//! SQL for the monitor and the notifier outbox: the monitor snapshot, alert
//! synchronisation (design section 9.3) and the delivery columns.
//!
//! Column ownership (section 5.2): the monitor side writes `kind` ..
//! `resolved_at` of `alerts` (through [`Store::sync_alerts`]); the notifier
//! side writes `notified_at`, `notify_attempts` and `last_notify_error`.
//!
//! The snapshot is read in one transaction as a set of candidate lists
//! (design section 9.1). Each list holds alert-capable rows only (SQL applies
//! the condition), newest first, capped at `SnapshotLimits::per_list`; a list
//! that has more rows than the cap is flagged `truncated`. The pure
//! `monitor::evaluate` applies the exact rules again and decides which alert
//! kinds are complete.

use std::collections::HashSet;

use rusqlite::{OptionalExtension, Row, params};

use super::{COVERAGE_MARGIN_SECS, HealthRow, Store, StoreError};
use crate::domain::{Bytes32, Domain, Mode};
use crate::matching::mode;
use crate::monitor::Severity;

/// Window of the time-bound checks (`latency_outlier`, `reorg_rollback`).
pub const RECENT_SECS: i64 = 24 * 3600;

/// Thresholds of one chain that `evaluate` needs and the database does not
/// hold. Built from config by `app`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainLimits {
    /// Chain.
    pub domain: Domain,
    /// Attestation SLA of Fast burns from this chain.
    pub sla_fast_secs: i64,
    /// Attestation SLA of Standard burns from this chain.
    pub sla_standard_secs: i64,
    /// Finality lag (heights) that raises `finality_stalled`.
    pub finality_lag_alert: u64,
}

/// Inputs of [`Store::monitor_snapshot`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotLimits {
    /// Rows per candidate list (`monitor.snapshot_limit`). The query reads
    /// `per_list + 1` rows to detect truncation.
    pub per_list: usize,
    /// Latencies kept per `(direction, mode)` as the outlier baseline.
    pub latency_window: usize,
    /// `monitor.unclaimed_after_secs`.
    pub unclaimed_after_secs: i64,
    /// `monitor.mint_without_burn_lookups`.
    pub mint_without_burn_lookups: u32,
    /// Per-chain thresholds; copied into the snapshot.
    pub chains: Vec<ChainLimits>,
}

impl Default for SnapshotLimits {
    fn default() -> Self {
        SnapshotLimits {
            per_list: 1000,
            latency_window: 200,
            unclaimed_after_secs: 3600,
            mint_without_burn_lookups: 3,
            chains: Vec::new(),
        }
    }
}

/// One candidate list of the snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidates<T> {
    /// The rows, newest first, at most `per_list`.
    pub rows: Vec<T>,
    /// The query found more than `per_list` rows; the oldest were dropped.
    pub truncated: bool,
}

impl<T> Default for Candidates<T> {
    fn default() -> Self {
        Candidates {
            rows: Vec::new(),
            truncated: false,
        }
    }
}

impl<T> Candidates<T> {
    /// A complete (not truncated) list.
    pub fn of(rows: Vec<T>) -> Self {
        Candidates {
            rows,
            truncated: false,
        }
    }
}

/// One `chain_state` row, reduced to what the checks use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainSnapshot {
    /// Chain.
    pub domain: Domain,
    /// Config name; the health row of its ingestor is `ingest:<name>`.
    pub name: String,
    /// Last finalized height read from the RPC.
    pub observed_finalized: Option<u64>,
    /// Last head height read from the RPC.
    pub observed_head: Option<u64>,
    /// When a tail scan last reached its target.
    pub caught_up_at: Option<i64>,
    /// Chain time at which the observed window starts (ADR 0013).
    pub start_time: i64,
}

/// A burn that Iris has been asked about and has not attested.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingBurnRow {
    /// Chain of the burn.
    pub source_domain: Domain,
    /// Burn transaction.
    pub tx_id: String,
    /// Event index inside the chain.
    pub event_index: u32,
    /// Chain time of the burn.
    pub block_time: i64,
    /// Finality the burner asked for; decides Fast or Standard.
    pub min_finality_threshold: u32,
    /// Last time Iris answered for this burn.
    pub last_polled_at: i64,
}

/// A burn that Iris attested and that has no receive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedBurnRow {
    /// Chain of the burn.
    pub source_domain: Domain,
    /// Chain of the mint.
    pub destination_domain: Domain,
    /// Nonce.
    pub nonce: Bytes32,
    /// First poll that saw `complete`.
    pub attested_at: i64,
    /// Chain time of the burn; the coverage rule compares it with the
    /// destination `start_time`.
    pub burn_time: i64,
}

/// A final receive with no burn and an alert-capable lookup verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrphanRow {
    /// Chain of the burn according to the receive.
    pub source_domain: Domain,
    /// Nonce.
    pub nonce: Bytes32,
    /// Receive transaction.
    pub receive_tx: String,
    /// Verdict (`SourceLookup` snake_case): `unknown_to_iris`,
    /// `source_not_found`, `iris_mismatch`, `double_mint`, `missed` or
    /// `unresolved`.
    pub source_lookup: String,
    /// Counted lookups done.
    pub lookup_count: u32,
    /// Source transaction Iris named, if any.
    pub iris_source_tx: Option<String>,
    /// Minted gross amount.
    pub amount: u64,
    /// Mint recipient.
    pub mint_recipient: Bytes32,
    /// For `double_mint`: the nonce under which we hold the same burn.
    pub other_nonce: Option<Bytes32>,
}

/// A final receive whose content disagrees with its burn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MismatchRow {
    /// Chain of the burn.
    pub source_domain: Domain,
    /// Nonce.
    pub nonce: Bytes32,
    /// Names of the fields that differ (design section 8).
    pub fields: Vec<String>,
}

/// More than one final receive for one `(source_domain, nonce)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateRow {
    /// Chain of the burn.
    pub source_domain: Domain,
    /// Nonce.
    pub nonce: Bytes32,
    /// Number of final receives.
    pub count: u32,
}

/// Latency of one completed transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatencySample {
    /// Chain of the burn.
    pub source_domain: Domain,
    /// Chain of the mint.
    pub destination_domain: Domain,
    /// Fast or Standard.
    pub mode: Mode,
    /// Nonce.
    pub nonce: Bytes32,
    /// Receive chain time minus burn chain time.
    pub latency_secs: i64,
    /// Receive chain time.
    pub receive_time: i64,
}

/// One row of `rollbacks`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackRow {
    /// Row id.
    pub id: i64,
    /// Chain.
    pub domain: Domain,
    /// `burn` or `receive`.
    pub event_type: String,
    /// Transaction of the deleted row.
    pub tx_id: String,
    /// Height of the deleted row.
    pub height: u64,
    /// `tail` or `final`.
    pub scope: String,
    /// When the rollback was detected.
    pub detected_at: i64,
}

/// Everything `evaluate` reads. Plain data: tests build it by hand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonitorSnapshot {
    /// Time of the snapshot (Unix seconds).
    pub now: i64,
    /// Thresholds that came with the request.
    pub limits: SnapshotLimits,
    /// All `chain_state` rows (a few; never truncated).
    pub chains: Vec<ChainSnapshot>,
    /// All `health` rows (a few; never truncated).
    pub health: Vec<HealthRow>,
    /// `delayed_burns`: pending burns whose last poll is past their SLA.
    pub delayed_burns: Candidates<PendingBurnRow>,
    /// `unclaimed_burns`: attested burns without a receive, past
    /// `unclaimed_after` of the destination `caught_up_at`, and inside the
    /// destination coverage window (ADR 0013).
    pub unclaimed_burns: Candidates<AttestedBurnRow>,
    /// `orphan_receives`: final receives without a burn and with an
    /// alert-capable verdict.
    pub orphan_receives: Candidates<OrphanRow>,
    /// `mismatched_pairs`: final receives that disagree with their burn.
    pub mismatched_pairs: Candidates<MismatchRow>,
    /// `duplicate_nonces`: nonces with several final receives.
    pub duplicate_nonces: Candidates<DuplicateRow>,
    /// `recent_completed`: final completions of the last 24 hours.
    pub recent_completed: Candidates<LatencySample>,
    /// Latest final latencies per `(direction, mode)`: the outlier baseline.
    /// Not a candidate list; bounded by `latency_window` per group.
    pub latency_baseline: Vec<LatencySample>,
    /// `recent_rollbacks`: rollbacks of the last 24 hours.
    pub recent_rollbacks: Candidates<RollbackRow>,
}

/// One active problem found by the monitor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlertCondition {
    /// Check name, for example `unclaimed`.
    pub kind: &'static str,
    /// What the problem is about; with `kind` it is the unique key.
    pub subject: String,
    /// Severity.
    pub severity: Severity,
    /// Human-readable text.
    pub message: String,
}

/// A stored alert row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    /// Row id.
    pub id: i64,
    /// Check name.
    pub kind: String,
    /// Subject.
    pub subject: String,
    /// Severity.
    pub severity: Severity,
    /// Human-readable text.
    pub message: String,
    /// First time the condition was seen.
    pub first_seen_at: i64,
    /// When the alert was last opened for notification.
    pub opened_at: i64,
    /// Last evaluation that saw the condition.
    pub last_seen_at: i64,
    /// Last successful delivery, if any.
    pub notified_at: Option<i64>,
    /// Failed delivery attempts.
    pub notify_attempts: u32,
    /// Error of the last failed attempt.
    pub last_notify_error: Option<String>,
}

/// What one [`Store::sync_alerts`] changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AlertSyncStats {
    /// New rows.
    pub inserted: usize,
    /// Open rows that stayed open.
    pub refreshed: usize,
    /// Resolved rows that became open again.
    pub reopened: usize,
    /// Re-opens that are due for a new notification (`opened_at` moved).
    pub renotified: usize,
    /// Open rows whose condition is gone.
    pub resolved: usize,
}

fn domain_at(r: &Row<'_>, idx: usize) -> rusqlite::Result<Domain> {
    Ok(Domain(r.get(idx)?))
}

fn bytes32_at(r: &Row<'_>, idx: usize) -> rusqlite::Result<Bytes32> {
    let blob: Vec<u8> = r.get(idx)?;
    <[u8; 32]>::try_from(blob).map(Bytes32).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            idx,
            rusqlite::types::Type::Blob,
            "expected 32 bytes".into(),
        )
    })
}

fn height_at(r: &Row<'_>, idx: usize) -> rusqlite::Result<Option<u64>> {
    Ok(r.get::<_, Option<i64>>(idx)?.map(|v| v as u64))
}

fn severity_from_db(s: &str, idx: usize) -> rusqlite::Result<Severity> {
    match s {
        "info" => Ok(Severity::Info),
        "warning" => Ok(Severity::Warning),
        "critical" => Ok(Severity::Critical),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            idx,
            rusqlite::types::Type::Text,
            "unknown severity".into(),
        )),
    }
}

fn alert_row(r: &Row<'_>) -> rusqlite::Result<Alert> {
    let severity: String = r.get(3)?;
    Ok(Alert {
        id: r.get(0)?,
        kind: r.get(1)?,
        subject: r.get(2)?,
        severity: severity_from_db(&severity, 3)?,
        message: r.get(4)?,
        first_seen_at: r.get(5)?,
        opened_at: r.get(6)?,
        last_seen_at: r.get(7)?,
        notified_at: r.get(8)?,
        notify_attempts: r.get(9)?,
        last_notify_error: r.get(10)?,
    })
}

const MISMATCH_SQL: &str = "
    SELECT source_domain, nonce, fields FROM (
        SELECT b.source_domain AS source_domain, b.nonce AS nonce, r.block_time AS t,
               TRIM(
                 CASE WHEN b.destination_domain <> r.domain THEN ' destination_domain' ELSE '' END ||
                 CASE WHEN b.sender <> r.sender THEN ' sender' ELSE '' END ||
                 CASE WHEN b.burn_token <> r.burn_token THEN ' burn_token' ELSE '' END ||
                 CASE WHEN b.mint_recipient <> r.mint_recipient THEN ' mint_recipient' ELSE '' END ||
                 CASE WHEN b.amount <> r.amount THEN ' amount' ELSE '' END ||
                 CASE WHEN b.depositor <> r.depositor THEN ' depositor' ELSE '' END ||
                 CASE WHEN b.max_fee <> r.max_fee THEN ' max_fee' ELSE '' END ||
                 CASE WHEN b.hook_data <> r.hook_data THEN ' hook_data' ELSE '' END ||
                 CASE WHEN b.fee_executed IS NOT NULL AND b.fee_executed <> r.fee_executed
                      THEN ' fee_executed' ELSE '' END ||
                 CASE WHEN r.fee_executed > b.max_fee THEN ' fee_exceeds_max_fee' ELSE '' END
               ) AS fields
        FROM receives r
        JOIN burns b ON b.source_domain = r.source_domain AND b.nonce = r.nonce
        WHERE r.finalized = 1
    )
    WHERE fields <> ''
    GROUP BY source_domain, nonce
    ORDER BY MAX(t) DESC, nonce
    LIMIT ?1";

/// SQL condition (on `burns`) of the `delayed_burns` list: the exact
/// attestation-delay rule, per source chain and mode. Thresholds are numbers
/// from config, so they are written into the text.
fn delayed_burns_sql(chains: &[ChainLimits]) -> String {
    let per_chain: Vec<String> = chains
        .iter()
        .map(|c| {
            format!(
                "(source_domain = {} AND last_polled_at - block_time >
                    CASE WHEN min_finality_threshold < 2000 THEN {} ELSE {} END)",
                c.domain.0, c.sla_fast_secs, c.sla_standard_secs
            )
        })
        .collect();
    let cond = if per_chain.is_empty() {
        "0".to_string()
    } else {
        per_chain.join(" OR ")
    };
    format!(
        "SELECT source_domain, tx_id, event_index, block_time, min_finality_threshold,
                last_polled_at
         FROM burns
         WHERE attestation_status <> 'complete' AND last_polled_at IS NOT NULL AND ({cond})
         ORDER BY block_time DESC, id DESC LIMIT ?1"
    )
}

/// Runs a list query with `LIMIT per_list + 1` and builds the [`Candidates`].
fn candidates<T>(
    tx: &rusqlite::Transaction<'_>,
    sql: &str,
    per_list: usize,
    extra: &[&dyn rusqlite::ToSql],
    map: impl FnMut(&Row<'_>) -> rusqlite::Result<T>,
) -> Result<Candidates<T>, StoreError> {
    let fetch = i64::try_from(per_list)
        .unwrap_or(i64::MAX - 1)
        .saturating_add(1);
    let mut all: Vec<&dyn rusqlite::ToSql> = vec![&fetch];
    all.extend_from_slice(extra);
    let mut rows = tx
        .prepare(sql)?
        .query_map(rusqlite::params_from_iter(all), map)?
        .collect::<Result<Vec<_>, _>>()?;
    let truncated = rows.len() > per_list;
    rows.truncate(per_list);
    Ok(Candidates { rows, truncated })
}

impl Store {
    /// Reads everything `evaluate` needs, in one read transaction: chain and
    /// health rows, the candidate lists of design section 9.1 (alert-capable
    /// rows, newest first, `per_list + 1` fetched to set `truncated`), and the
    /// latency baseline.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn monitor_snapshot(
        &self,
        now: i64,
        limits: &SnapshotLimits,
    ) -> Result<MonitorSnapshot, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let per = limits.per_list;

        let chains = tx
            .prepare(
                "SELECT domain, name, observed_finalized, observed_head, caught_up_at, start_time
                 FROM chain_state ORDER BY domain",
            )?
            .query_map([], |r| {
                Ok(ChainSnapshot {
                    domain: domain_at(r, 0)?,
                    name: r.get(1)?,
                    observed_finalized: height_at(r, 2)?,
                    observed_head: height_at(r, 3)?,
                    caught_up_at: r.get(4)?,
                    start_time: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let health = tx
            .prepare(
                "SELECT component, started_at, last_ok_at, last_error, last_error_at,
                        consecutive_failures
                 FROM health ORDER BY component",
            )?
            .query_map([], |r| {
                Ok(HealthRow {
                    component: r.get(0)?,
                    started_at: r.get(1)?,
                    last_ok_at: r.get(2)?,
                    last_error: r.get(3)?,
                    last_error_at: r.get(4)?,
                    consecutive_failures: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let delayed_burns = candidates(&tx, &delayed_burns_sql(&limits.chains), per, &[], |r| {
            Ok(PendingBurnRow {
                source_domain: domain_at(r, 0)?,
                tx_id: r.get(1)?,
                event_index: r.get(2)?,
                block_time: r.get(3)?,
                min_finality_threshold: r.get(4)?,
                last_polled_at: r.get(5)?,
            })
        })?;

        let unclaimed_burns = candidates(
            &tx,
            "SELECT b.source_domain, b.destination_domain, b.nonce, b.attested_at, b.block_time
             FROM burns b
             JOIN chain_state c ON c.domain = b.destination_domain
             WHERE b.attestation_status = 'complete' AND b.nonce IS NOT NULL
               AND b.attested_at IS NOT NULL AND c.caught_up_at IS NOT NULL
               AND b.attested_at < c.caught_up_at - ?2
               AND b.block_time >= c.start_time + ?3
               AND NOT EXISTS (SELECT 1 FROM receives r
                                WHERE r.source_domain = b.source_domain AND r.nonce = b.nonce)
             ORDER BY b.attested_at DESC, b.id DESC LIMIT ?1",
            per,
            &[&limits.unclaimed_after_secs, &COVERAGE_MARGIN_SECS],
            |r| {
                Ok(AttestedBurnRow {
                    source_domain: domain_at(r, 0)?,
                    destination_domain: domain_at(r, 1)?,
                    nonce: bytes32_at(r, 2)?,
                    attested_at: r.get(3)?,
                    burn_time: r.get(4)?,
                })
            },
        )?;

        let orphan_receives = candidates(
            &tx,
            "SELECT r.source_domain, r.nonce, r.tx_id, r.source_lookup, r.source_lookup_count,
                    r.iris_source_tx, r.amount, r.mint_recipient,
                    (SELECT o.nonce FROM burns o
                      WHERE o.source_domain = r.source_domain AND o.tx_id = r.iris_source_tx
                        AND o.nonce IS NOT NULL AND o.amount = r.amount
                        AND o.mint_recipient = r.mint_recipient
                      ORDER BY o.id LIMIT 1)
             FROM receives r
             WHERE r.finalized = 1
               AND (r.source_lookup IN ('iris_mismatch', 'double_mint', 'missed', 'unresolved')
                    OR (r.source_lookup IN ('unknown_to_iris', 'source_not_found')
                        AND r.source_lookup_count >= ?2))
               AND NOT EXISTS (SELECT 1 FROM burns b
                                WHERE b.source_domain = r.source_domain AND b.nonce = r.nonce)
             ORDER BY r.block_time DESC, r.id DESC LIMIT ?1",
            per,
            &[&limits.mint_without_burn_lookups],
            |r| {
                Ok(OrphanRow {
                    source_domain: domain_at(r, 0)?,
                    nonce: bytes32_at(r, 1)?,
                    receive_tx: r.get(2)?,
                    source_lookup: r.get(3)?,
                    lookup_count: r.get(4)?,
                    iris_source_tx: r.get(5)?,
                    amount: r.get::<_, i64>(6)? as u64,
                    mint_recipient: bytes32_at(r, 7)?,
                    other_nonce: r
                        .get::<_, Option<Vec<u8>>>(8)?
                        .and_then(|b| <[u8; 32]>::try_from(b).ok())
                        .map(Bytes32),
                })
            },
        )?;

        let mismatched_pairs = candidates(&tx, MISMATCH_SQL, per, &[], |r| {
            let fields: String = r.get(2)?;
            Ok(MismatchRow {
                source_domain: domain_at(r, 0)?,
                nonce: bytes32_at(r, 1)?,
                fields: fields.split_whitespace().map(str::to_string).collect(),
            })
        })?;

        let duplicate_nonces = candidates(
            &tx,
            "SELECT source_domain, nonce, COUNT(*) FROM receives WHERE finalized = 1
             GROUP BY source_domain, nonce HAVING COUNT(*) > 1
             ORDER BY MAX(block_time) DESC, nonce LIMIT ?1",
            per,
            &[],
            |r| {
                Ok(DuplicateRow {
                    source_domain: domain_at(r, 0)?,
                    nonce: bytes32_at(r, 1)?,
                    count: r.get(2)?,
                })
            },
        )?;

        let latency_row = |r: &Row<'_>| -> rusqlite::Result<LatencySample> {
            Ok(LatencySample {
                source_domain: domain_at(r, 0)?,
                destination_domain: domain_at(r, 1)?,
                mode: mode(r.get(2)?),
                nonce: bytes32_at(r, 3)?,
                latency_secs: r.get(4)?,
                receive_time: r.get(5)?,
            })
        };

        let recent_completed = candidates(
            &tx,
            "SELECT source_domain, destination_domain, min_finality_threshold, nonce,
                    latency_secs, receive_time
             FROM transfers
             WHERE state = 'completed' AND receive_finalized = 1
               AND latency_secs >= 0 AND nonce IS NOT NULL
               AND receive_time >= ?2 - ?3
             ORDER BY receive_time DESC, burn_id DESC LIMIT ?1",
            per,
            &[&now, &RECENT_SECS],
            latency_row,
        )?;

        let window = i64::try_from(limits.latency_window).unwrap_or(i64::MAX);
        let latency_baseline = tx
            .prepare(
                "SELECT source_domain, destination_domain, min_finality_threshold, nonce,
                        latency_secs, receive_time
                 FROM (
                    SELECT t.source_domain, t.destination_domain, t.min_finality_threshold,
                           t.nonce, t.latency_secs, t.receive_time,
                           ROW_NUMBER() OVER (
                               PARTITION BY t.source_domain, t.destination_domain,
                                            (t.min_finality_threshold < 2000)
                               ORDER BY t.receive_time DESC, t.burn_id DESC) AS rn
                    FROM transfers t
                    WHERE t.state = 'completed' AND t.receive_finalized = 1
                      AND t.latency_secs >= 0 AND t.nonce IS NOT NULL
                 )
                 WHERE rn <= ?1
                 ORDER BY receive_time DESC, nonce",
            )?
            .query_map(params![window], latency_row)?
            .collect::<Result<Vec<_>, _>>()?;

        let recent_rollbacks = candidates(
            &tx,
            "SELECT id, domain, event_type, tx_id, height, scope, detected_at
             FROM rollbacks WHERE detected_at >= ?2 - ?3
             ORDER BY id DESC LIMIT ?1",
            per,
            &[&now, &RECENT_SECS],
            |r| {
                Ok(RollbackRow {
                    id: r.get(0)?,
                    domain: domain_at(r, 1)?,
                    event_type: r.get(2)?,
                    tx_id: r.get(3)?,
                    height: r.get::<_, i64>(4)? as u64,
                    scope: r.get(5)?,
                    detected_at: r.get(6)?,
                })
            },
        )?;

        Ok(MonitorSnapshot {
            now,
            limits: limits.clone(),
            chains,
            health,
            delayed_burns,
            unclaimed_burns,
            orphan_receives,
            mismatched_pairs,
            duplicate_nonces,
            recent_completed,
            latency_baseline,
            recent_rollbacks,
        })
    }

    /// Makes the `alerts` table match `active`, in one transaction
    /// (design section 9.3).
    ///
    /// - No row for a condition: insert it (`first_seen_at = opened_at =
    ///   last_seen_at = now`).
    /// - Open row: refresh `last_seen_at`, `message`, `severity`.
    /// - Resolved row: re-open it. `opened_at` moves to `now` only if more than
    ///   `renotify_after_secs` passed since the last `opened_at`; otherwise the
    ///   re-open is silent, because the outbox compares `notified_at` with
    ///   `opened_at`.
    /// - Open row without a condition: set `resolved_at = now` only if its kind
    ///   is in `complete_kinds`. Otherwise its candidate list was truncated, a
    ///   missing row is no evidence, and the alert stays open.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn sync_alerts(
        &mut self,
        active: &[AlertCondition],
        complete_kinds: &[&str],
        now: i64,
        renotify_after_secs: i64,
    ) -> Result<AlertSyncStats, StoreError> {
        let tx = self.conn.transaction()?;
        let mut stats = AlertSyncStats::default();
        let mut seen: HashSet<(&str, &str)> = HashSet::new();
        for c in active {
            seen.insert((c.kind, c.subject.as_str()));
            let existing: Option<(i64, Option<i64>, i64)> = tx
                .query_row(
                    "SELECT id, resolved_at, opened_at FROM alerts WHERE kind = ?1 AND subject = ?2",
                    params![c.kind, c.subject],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            match existing {
                None => {
                    tx.execute(
                        "INSERT INTO alerts (kind, subject, severity, message, first_seen_at,
                                             opened_at, last_seen_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?5)",
                        params![c.kind, c.subject, c.severity.as_str(), c.message, now],
                    )?;
                    stats.inserted += 1;
                }
                Some((id, None, _)) => {
                    tx.execute(
                        "UPDATE alerts SET severity = ?2, message = ?3, last_seen_at = ?4
                         WHERE id = ?1",
                        params![id, c.severity.as_str(), c.message, now],
                    )?;
                    stats.refreshed += 1;
                }
                Some((id, Some(_), opened_at)) => {
                    let renotify = now - opened_at > renotify_after_secs;
                    tx.execute(
                        "UPDATE alerts SET severity = ?2, message = ?3, last_seen_at = ?4,
                                resolved_at = NULL, opened_at = CASE WHEN ?5 THEN ?4 ELSE opened_at END
                         WHERE id = ?1",
                        params![id, c.severity.as_str(), c.message, now, renotify],
                    )?;
                    stats.reopened += 1;
                    if renotify {
                        stats.renotified += 1;
                    }
                }
            }
        }
        let open: Vec<(i64, String, String)> = tx
            .prepare("SELECT id, kind, subject FROM alerts WHERE resolved_at IS NULL")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        for (id, kind, subject) in open {
            let active_now = seen.contains(&(kind.as_str(), subject.as_str()));
            if !active_now && complete_kinds.contains(&kind.as_str()) {
                tx.execute(
                    "UPDATE alerts SET resolved_at = ?2 WHERE id = ?1",
                    params![id, now],
                )?;
                stats.resolved += 1;
            }
        }
        tx.commit()?;
        Ok(stats)
    }

    /// Open alerts that still need a notification: `resolved_at IS NULL AND
    /// (notified_at IS NULL OR notified_at < opened_at)`, oldest id first.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn alert_outbox(&self, limit: usize) -> Result<Vec<Alert>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, subject, severity, message, first_seen_at, opened_at, last_seen_at,
                    notified_at, notify_attempts, last_notify_error
             FROM alerts
             WHERE resolved_at IS NULL AND (notified_at IS NULL OR notified_at < opened_at)
             ORDER BY id LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], alert_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// All alert rows, open and resolved, by id. For tests and diagnostics.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn all_alerts(&self) -> Result<Vec<Alert>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, subject, severity, message, first_seen_at, opened_at, last_seen_at,
                    notified_at, notify_attempts, last_notify_error
             FROM alerts ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], alert_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Records that the alert was delivered (or deliberately not sent) at
    /// `now`, and clears the last error. Does not touch `notify_attempts`.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn mark_alert_delivered(&mut self, alert_id: i64, now: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE alerts SET notified_at = ?2, last_notify_error = NULL WHERE id = ?1",
            params![alert_id, now],
        )?;
        Ok(())
    }

    /// Records a failed delivery: `notify_attempts` + 1 and the error text.
    /// `notified_at` stays, so the alert stays in the outbox.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn record_alert_failure(&mut self, alert_id: i64, error: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE alerts SET notify_attempts = notify_attempts + 1, last_notify_error = ?2
             WHERE id = ?1",
            params![alert_id, error],
        )?;
        Ok(())
    }
}
