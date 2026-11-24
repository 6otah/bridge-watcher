//! Monitor: pure rule evaluation ([`evaluate`]) and the loop that syncs the
//! results into the `alerts` table ([`Monitor`]).
//!
//! Principle (design section 9.1): absence is claimed only after looking. A
//! "missing" condition needs evidence that the relevant source was read after
//! the deadline: `last_polled_at` for Iris, `caught_up_at` of the destination
//! chain. `evaluate` is a pure function of the [`MonitorSnapshot`], so every
//! rule is tested with hand-built snapshots.
//!
//! Truncation (design sections 9.1 and 9.3): every candidate list of the
//! snapshot may be cut at `snapshot_limit`. [`evaluate`] reports which alert
//! kinds it saw completely, so `sync_alerts` resolves only those, and it
//! raises `monitor_truncated` for each cut list.
//!
//! Restart rule: `started_at` of a health row is the start of the current
//! process run, so `max(last_ok_at, started_at)` and `max(caught_up_at,
//! started_at)` give every component a full `stall_after` grace period after
//! a restart.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use crate::clock::unix_now;
use crate::config::MonitorConfig;
use crate::domain::{Bytes32, Domain, Mode};
use crate::matching::mode;
use crate::store::COVERAGE_MARGIN_SECS;
use crate::store::{
    AlertCondition, AlertSyncStats, ChainLimits, MonitorSnapshot, RECENT_SECS, SharedStore,
    SnapshotLimits, StoreError,
};

/// Alert severity. Ordered: `Info < Warning < Critical`.
///
/// Parsed from lowercase strings (`"info"`, `"warning"`, `"critical"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Logged only; sent only if `min_severity = "info"`.
    Info,
    /// Needs attention.
    Warning,
    /// Possible loss of funds or a broken invariant.
    Critical,
}

impl Severity {
    /// Lowercase name as stored in the `alerts.severity` column.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

/// Upper bound of a normal latency: `median + max(k * 1.4826 * MAD,
/// min_excess)`. Pure.
///
/// The MAD floor (`min_excess`) stops a set of equal samples from flagging
/// every slightly slower transfer. Returns `None` if there are fewer than
/// `min_samples` samples (and for an empty slice).
pub fn latency_upper_bound(
    samples: &[i64],
    k: f64,
    min_samples: usize,
    min_excess: i64,
) -> Option<i64> {
    if samples.is_empty() || samples.len() < min_samples {
        return None;
    }
    let median = |v: &mut Vec<i64>| -> i64 {
        v.sort_unstable();
        let n = v.len();
        if n % 2 == 1 {
            v[n / 2]
        } else {
            ((i128::from(v[n / 2 - 1]) + i128::from(v[n / 2])) / 2) as i64
        }
    };
    let med = median(&mut samples.to_vec());
    let mut deviations: Vec<i64> = samples
        .iter()
        .map(|s| i64::try_from(s.abs_diff(med)).unwrap_or(i64::MAX))
        .collect();
    let mad = median(&mut deviations);
    let scaled = (k * 1.4826 * mad as f64).ceil() as i64;
    Some(med.saturating_add(scaled.max(min_excess)))
}

/// Every alert kind the monitor can raise.
pub const ALL_KINDS: &[&str] = &[
    "attestation_delayed",
    "unclaimed",
    "mint_without_burn",
    "iris_mismatch",
    "double_mint",
    "ingestion_gap",
    "orphan_unresolved",
    "field_mismatch",
    "duplicate_receive",
    "latency_outlier",
    "component_stalled",
    "ingestion_lagging",
    "finality_stalled",
    "reorg_rollback",
    "monitor_truncated",
];

/// Result of [`evaluate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    /// Active problems, sorted by `(kind, subject)`, unique on that key.
    pub conditions: Vec<AlertCondition>,
    /// Kinds whose candidate lists were complete (not truncated). Only open
    /// alerts of these kinds may be resolved.
    pub complete_kinds: Vec<&'static str>,
}

fn nonce_subject(source: Domain, nonce: &Bytes32) -> String {
    format!("nonce:{source}:{nonce}")
}

fn direction(source: Domain, destination: Domain, m: Mode) -> String {
    format!("{source}->{destination} {m:?}")
}

/// Runs every check of design section 9.2 over `snapshot`. Pure: the same
/// snapshot gives the same evaluation. Conditions are sorted by
/// `(kind, subject)` and de-duplicated on that key.
///
/// A kind is in `complete_kinds` only if every list that feeds it is not
/// truncated. Each truncated list adds a `monitor_truncated` condition with
/// subject `list:<name>`.
pub fn evaluate(snapshot: &MonitorSnapshot, cfg: &MonitorConfig) -> Evaluation {
    use Severity::{Critical, Info, Warning};
    let now = snapshot.now;
    let mut out: Vec<AlertCondition> = Vec::new();
    let mut push = |kind: &'static str, subject: String, severity: Severity, message: String| {
        out.push(AlertCondition {
            kind,
            subject,
            severity,
            message,
        });
    };
    let limits_of = |d: Domain| snapshot.limits.chains.iter().find(|c| c.domain == d);

    for b in &snapshot.delayed_burns.rows {
        let Some(limits) = limits_of(b.source_domain) else {
            continue;
        };
        let m = mode(b.min_finality_threshold);
        let sla = match m {
            Mode::Fast => limits.sla_fast_secs,
            Mode::Standard => limits.sla_standard_secs,
        };
        let age = b.last_polled_at - b.block_time;
        if age > sla {
            push(
                "attestation_delayed",
                format!("burn:{}:{}:{}", b.source_domain, b.tx_id, b.event_index),
                Warning,
                format!(
                    "burn {} (domain {}, {m:?}) is not attested {age} s after the burn; SLA {sla} s",
                    b.tx_id, b.source_domain
                ),
            );
        }
    }

    for a in &snapshot.unclaimed_burns.rows {
        let Some(dest) = snapshot
            .chains
            .iter()
            .find(|c| c.domain == a.destination_domain)
        else {
            continue;
        };
        let Some(caught_up) = dest.caught_up_at else {
            continue;
        };
        // Coverage rule (ADR 0013): the receive may have happened before the
        // destination window began, so its absence proves nothing.
        if a.burn_time < dest.start_time + COVERAGE_MARGIN_SECS {
            continue;
        }
        let waited = caught_up - a.attested_at;
        if waited > cfg.unclaimed_after_secs {
            push(
                "unclaimed",
                nonce_subject(a.source_domain, &a.nonce),
                Warning,
                format!(
                    "attested burn {} from domain {} has no receive on domain {} after {waited} s",
                    a.nonce, a.source_domain, a.destination_domain
                ),
            );
        }
    }

    for o in &snapshot.orphan_receives.rows {
        let subject = nonce_subject(o.source_domain, &o.nonce);
        let via = o
            .iris_source_tx
            .as_deref()
            .map(|t| format!(" (source tx {t})"))
            .unwrap_or_default();
        match o.source_lookup.as_str() {
            "double_mint" => push(
                "double_mint",
                subject,
                Critical,
                format!(
                    "receive {} minted {} to {} under nonce {}, but the burn it equals is already attested under nonce {}{via}",
                    o.receive_tx,
                    o.amount,
                    o.mint_recipient,
                    o.nonce,
                    o.other_nonce
                        .map_or_else(|| "(unknown)".to_string(), |n| n.to_string())
                ),
            ),
            "iris_mismatch" => push(
                "iris_mismatch",
                subject,
                Critical,
                format!(
                    "receive {} minted {} to {} for nonce {}, but the source tx{via} has no burn equal to the attested message",
                    o.receive_tx, o.amount, o.mint_recipient, o.nonce
                ),
            ),
            "missed" => push(
                "ingestion_gap",
                subject,
                Warning,
                format!(
                    "receive {} has a source burn on domain {} in a range we scanned, but we do not hold it",
                    o.receive_tx, o.source_domain
                ),
            ),
            "unresolved" => push(
                "orphan_unresolved",
                subject,
                Warning,
                format!(
                    "receive {} for nonce {} could not be verified after {} lookups{via}",
                    o.receive_tx, o.nonce, o.lookup_count
                ),
            ),
            reason @ ("unknown_to_iris" | "source_not_found")
                if o.lookup_count >= cfg.mint_without_burn_lookups =>
            {
                let why = if reason == "unknown_to_iris" {
                    "Iris does not know the nonce"
                } else {
                    "the source tx is not on the source chain"
                };
                push(
                    "mint_without_burn",
                    subject,
                    Critical,
                    format!(
                        "receive {} minted for nonce {}: {why} ({} lookups){via}",
                        o.receive_tx, o.nonce, o.lookup_count
                    ),
                );
            }
            _ => {}
        }
    }

    for m in &snapshot.mismatched_pairs.rows {
        push(
            "field_mismatch",
            nonce_subject(m.source_domain, &m.nonce),
            Critical,
            format!(
                "receive and burn of {} differ in: {}",
                m.nonce,
                m.fields.join(", ")
            ),
        );
    }

    for d in &snapshot.duplicate_nonces.rows {
        push(
            "duplicate_receive",
            nonce_subject(d.source_domain, &d.nonce),
            Critical,
            format!("{} final receives for nonce {}", d.count, d.nonce),
        );
    }

    let mut groups: BTreeMap<(Domain, Domain, bool), Vec<i64>> = BTreeMap::new();
    for s in &snapshot.latency_baseline {
        groups
            .entry((s.source_domain, s.destination_domain, s.mode == Mode::Fast))
            .or_default()
            .push(s.latency_secs);
    }
    for s in &snapshot.recent_completed.rows {
        if s.receive_time < now - RECENT_SECS {
            continue;
        }
        let key = (s.source_domain, s.destination_domain, s.mode == Mode::Fast);
        let bound = groups.get(&key).and_then(|v| {
            latency_upper_bound(
                v,
                cfg.latency_mad_k,
                cfg.latency_min_samples,
                cfg.latency_min_excess_secs,
            )
        });
        if let Some(bound) = bound.filter(|b| s.latency_secs > *b) {
            push(
                "latency_outlier",
                nonce_subject(s.source_domain, &s.nonce),
                Info,
                format!(
                    "{} transfer took {} s; normal upper bound {bound} s",
                    direction(s.source_domain, s.destination_domain, s.mode),
                    s.latency_secs
                ),
            );
        }
    }

    for h in &snapshot.health {
        let base = h.last_ok_at.map_or(h.started_at, |ok| ok.max(h.started_at));
        let silent = now - base;
        if silent > cfg.stall_after_secs {
            push(
                "component_stalled",
                format!("component:{}", h.component),
                Warning,
                format!(
                    "{} made no progress for {silent} s{}",
                    h.component,
                    h.last_error
                        .as_deref()
                        .map(|e| format!("; last error: {e}"))
                        .unwrap_or_default()
                ),
            );
        }
    }

    for c in &snapshot.chains {
        let ingest = format!("ingest:{}", c.name);
        let started = snapshot
            .health
            .iter()
            .find(|h| h.component == ingest)
            .map(|h| h.started_at);
        if let Some(base) = c.caught_up_at.into_iter().chain(started).max() {
            let behind = now - base;
            if behind > cfg.stall_after_secs {
                push(
                    "ingestion_lagging",
                    format!("chain:{}", c.name),
                    Warning,
                    format!(
                        "chain {} has not caught up to its head for {behind} s",
                        c.name
                    ),
                );
            }
        }
        if let (Some(limits), Some(finalized), Some(head)) =
            (limits_of(c.domain), c.observed_finalized, c.observed_head)
        {
            let lag = head.saturating_sub(finalized);
            if lag > limits.finality_lag_alert {
                push(
                    "finality_stalled",
                    format!("chain:{}", c.name),
                    Warning,
                    format!(
                        "chain {}: head is {lag} heights above finalized (alert above {})",
                        c.name, limits.finality_lag_alert
                    ),
                );
            }
        }
    }

    for r in &snapshot.recent_rollbacks.rows {
        if r.detected_at >= now - RECENT_SECS {
            push(
                "reorg_rollback",
                format!("rollback:{}", r.id),
                Info,
                format!(
                    "{} {} at height {} on domain {} rolled back ({} scope)",
                    r.event_type, r.tx_id, r.height, r.domain, r.scope
                ),
            );
        }
    }

    let lists: [(&str, bool, &[&str]); 7] = [
        (
            "delayed_burns",
            snapshot.delayed_burns.truncated,
            &["attestation_delayed"],
        ),
        (
            "unclaimed_burns",
            snapshot.unclaimed_burns.truncated,
            &["unclaimed"],
        ),
        (
            "orphan_receives",
            snapshot.orphan_receives.truncated,
            &[
                "mint_without_burn",
                "iris_mismatch",
                "double_mint",
                "ingestion_gap",
                "orphan_unresolved",
            ],
        ),
        (
            "mismatched_pairs",
            snapshot.mismatched_pairs.truncated,
            &["field_mismatch"],
        ),
        (
            "duplicate_nonces",
            snapshot.duplicate_nonces.truncated,
            &["duplicate_receive"],
        ),
        (
            "recent_completed",
            snapshot.recent_completed.truncated,
            &["latency_outlier"],
        ),
        (
            "recent_rollbacks",
            snapshot.recent_rollbacks.truncated,
            &["reorg_rollback"],
        ),
    ];
    let mut incomplete: Vec<&str> = Vec::new();
    for (name, truncated, kinds) in lists {
        if truncated {
            incomplete.extend_from_slice(kinds);
            out.push(AlertCondition {
                kind: "monitor_truncated",
                subject: format!("list:{name}"),
                severity: Warning,
                message: format!(
                    "monitor list {name} reached snapshot_limit ({}); alerts of its kinds are not resolved until it shrinks",
                    snapshot.limits.per_list
                ),
            });
        }
    }
    let complete_kinds = ALL_KINDS
        .iter()
        .copied()
        .filter(|k| !incomplete.contains(k))
        .collect();

    out.sort_by(|a, b| (a.kind, &a.subject).cmp(&(b.kind, &b.subject)));
    out.dedup_by(|a, b| a.kind == b.kind && a.subject == b.subject);
    Evaluation {
        conditions: out,
        complete_kinds,
    }
}

/// Evaluates the rules on a timer and syncs the result into `alerts`.
pub struct Monitor {
    store: SharedStore,
    cfg: MonitorConfig,
    limits: SnapshotLimits,
    renotify_after_secs: i64,
}

impl Monitor {
    /// Creates a monitor. `chains` holds the per-chain thresholds that live in
    /// the chain config sections; a chain without an entry gets no SLA and no
    /// finality check. `renotify_after_secs` comes from `[alerts]`.
    pub fn new(
        store: SharedStore,
        cfg: MonitorConfig,
        chains: Vec<ChainLimits>,
        renotify_after_secs: i64,
    ) -> Monitor {
        let limits = SnapshotLimits {
            per_list: cfg.snapshot_limit,
            latency_window: cfg.latency_window,
            unclaimed_after_secs: cfg.unclaimed_after_secs,
            mint_without_burn_lookups: cfg.mint_without_burn_lookups,
            chains,
        };
        Monitor {
            store,
            cfg,
            limits,
            renotify_after_secs,
        }
    }

    /// One iteration: snapshot, evaluate, sync. `now` is Unix seconds.
    ///
    /// # Errors
    /// [`StoreError`]; the caller must stop the process.
    pub async fn tick(&self, now: i64) -> Result<AlertSyncStats, StoreError> {
        let (cfg, limits, renotify) = (
            self.cfg.clone(),
            self.limits.clone(),
            self.renotify_after_secs,
        );
        let (stats, active) = self
            .store
            .run(move |s| {
                let snapshot = s.monitor_snapshot(now, &limits)?;
                let eval = evaluate(&snapshot, &cfg);
                let stats = s.sync_alerts(&eval.conditions, &eval.complete_kinds, now, renotify)?;
                Ok((stats, eval.conditions.len()))
            })
            .await?;
        tracing::debug!(active, ?stats, "monitor tick");
        Ok(stats)
    }

    /// Runs ticks every `interval_secs` until `cancel` fires.
    ///
    /// # Errors
    /// The first [`StoreError`].
    pub async fn run(self, cancel: CancellationToken) -> Result<(), StoreError> {
        let interval = Duration::from_secs(self.cfg.interval_secs);
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                result = self.tick(unix_now()) => { result?; }
            }
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                () = tokio::time::sleep(interval) => {}
            }
        }
    }
}
