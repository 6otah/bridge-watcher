//! Read-only reports for the CLI: [`Store::status_report`] and
//! [`Store::list_transfers`]. Neither writes, so both work on a store opened
//! with [`Store::open_read_only`].

use rusqlite::{Row, params};

use super::{Store, StoreError};
use crate::domain::{Bytes32, Domain, Mode};
use crate::matching::mode;

/// State of a transfer, as computed by the `transfers` view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferState {
    /// Burn seen, attestation not complete.
    Burned,
    /// Attestation complete, no receive yet, and the destination window covers
    /// the time the receive would have happened.
    Attested,
    /// Attestation complete, no receive in the database, but the receive could
    /// have happened before the destination window began: its
    /// absence is not observable.
    PreWindow,
    /// Receive seen.
    Completed,
}

impl TransferState {
    /// Value used by the view (`burned`, `attested`, `pre_window`, `completed`).
    pub fn as_str(self) -> &'static str {
        match self {
            TransferState::Burned => "burned",
            TransferState::Attested => "attested",
            TransferState::PreWindow => "pre_window",
            TransferState::Completed => "completed",
        }
    }

    fn from_db(s: &str) -> Option<Self> {
        match s {
            "burned" => Some(TransferState::Burned),
            "attested" => Some(TransferState::Attested),
            "pre_window" => Some(TransferState::PreWindow),
            "completed" => Some(TransferState::Completed),
            _ => None,
        }
    }
}

/// One `health` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthRow {
    /// Loop name, for example `ingest:base`.
    pub component: String,
    /// When the row was created.
    pub started_at: i64,
    /// Last successful iteration.
    pub last_ok_at: Option<i64>,
    /// Last error text (already redacted).
    pub last_error: Option<String>,
    /// When the last error happened.
    pub last_error_at: Option<i64>,
    /// Failures since the last success.
    pub consecutive_failures: u32,
}

/// Status of one chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainStatus {
    /// Chain.
    pub domain: Domain,
    /// Config name.
    pub name: String,
    /// First height in scope.
    pub start_height: u64,
    /// Cursor.
    pub final_height: u64,
    /// Last finalized height read from the RPC.
    pub observed_finalized: Option<u64>,
    /// Last head height read from the RPC.
    pub observed_head: Option<u64>,
    /// Top of the last complete tail scan.
    pub scanned_head: Option<u64>,
    /// When a tail scan last reached its target.
    pub caught_up_at: Option<i64>,
    /// Last write to the row.
    pub updated_at: i64,
    /// `observed_finalized - final_height`: how far the cursor trails.
    pub cursor_lag: Option<u64>,
    /// Health row `ingest:<name>`, if any.
    pub health: Option<HealthRow>,
}

/// Open alerts by severity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AlertCounts {
    /// Open `info` alerts.
    pub info: u64,
    /// Open `warning` alerts.
    pub warning: u64,
    /// Open `critical` alerts.
    pub critical: u64,
}

/// Data for `bridge-watcher status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusReport {
    /// Time of the report.
    pub now: i64,
    /// One entry per chain, by domain.
    pub chains: Vec<ChainStatus>,
    /// All `health` rows.
    pub components: Vec<HealthRow>,
    /// Transfers in state `burned`.
    pub burned: u64,
    /// Transfers in state `attested`.
    pub attested: u64,
    /// Transfers in state `pre_window`.
    pub pre_window: u64,
    /// Transfers in state `completed`.
    pub completed: u64,
    /// Unresolved alerts.
    pub open_alerts: AlertCounts,
}

/// Filter of [`Store::list_transfers`].
#[derive(Clone, Copy, Debug)]
pub struct TransferFilter {
    /// Only this state; `None` for all.
    pub state: Option<TransferState>,
    /// Maximum number of rows.
    pub limit: usize,
}

/// One row of the `transfers` view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferRow {
    /// Burn row id.
    pub burn_id: i64,
    /// Receive row id, if received.
    pub receive_id: Option<i64>,
    /// Chain of the burn.
    pub source_domain: Domain,
    /// Chain of the mint.
    pub destination_domain: Domain,
    /// Nonce, once Iris attested.
    pub nonce: Option<Bytes32>,
    /// Burn transaction id.
    pub burn_tx: String,
    /// Burn chain time.
    pub burn_time: i64,
    /// Whether the burn row is final.
    pub burn_finalized: bool,
    /// Receive transaction id.
    pub receive_tx: Option<String>,
    /// Receive chain time.
    pub receive_time: Option<i64>,
    /// Whether the receive row is final.
    pub receive_finalized: Option<bool>,
    /// Gross amount in token base units (USDC has 6 decimals).
    pub amount: u64,
    /// Fee charged, from the receive.
    pub fee_executed: Option<u64>,
    /// Fast or Standard, from the burn.
    pub mode: Mode,
    /// Transfer state.
    pub state: TransferState,
    /// `receive_time - burn_time`, seconds.
    pub latency_secs: Option<i64>,
}

fn health_row(r: &Row<'_>) -> rusqlite::Result<HealthRow> {
    Ok(HealthRow {
        component: r.get(0)?,
        started_at: r.get(1)?,
        last_ok_at: r.get(2)?,
        last_error: r.get(3)?,
        last_error_at: r.get(4)?,
        consecutive_failures: r.get(5)?,
    })
}

fn bad_value(idx: usize, what: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        idx,
        rusqlite::types::Type::Blob,
        what.to_string().into(),
    )
}

fn nonce_at(r: &Row<'_>, idx: usize) -> rusqlite::Result<Option<Bytes32>> {
    let blob: Option<Vec<u8>> = r.get(idx)?;
    blob.map(|b| {
        <[u8; 32]>::try_from(b)
            .map(Bytes32)
            .map_err(|_| bad_value(idx, "nonce is not 32 bytes"))
    })
    .transpose()
}

fn transfer_row(r: &Row<'_>) -> rusqlite::Result<TransferRow> {
    let state: String = r.get(13)?;
    let threshold: u32 = r.get(12)?;
    Ok(TransferRow {
        burn_id: r.get(0)?,
        receive_id: r.get(1)?,
        source_domain: Domain(r.get(2)?),
        destination_domain: Domain(r.get(3)?),
        nonce: nonce_at(r, 4)?,
        burn_tx: r.get(5)?,
        burn_time: r.get(6)?,
        burn_finalized: r.get(7)?,
        receive_tx: r.get(8)?,
        receive_time: r.get(9)?,
        receive_finalized: r.get(10)?,
        amount: r.get::<_, i64>(11)? as u64,
        mode: mode(threshold),
        state: TransferState::from_db(&state).ok_or_else(|| bad_value(13, "unknown state"))?,
        fee_executed: r.get::<_, Option<i64>>(14)?.map(|v| v as u64),
        latency_secs: r.get(15)?,
    })
}

impl Store {
    /// Builds the data for `status`: cursors, health, transfer counts by
    /// state, and open alerts by severity, from one consistent snapshot.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn status_report(&self, now: i64) -> Result<StatusReport, StoreError> {
        // One read transaction: all statements see the same snapshot.
        let tx = self.conn.unchecked_transaction()?;
        let components = self
            .conn
            .prepare(
                "SELECT component, started_at, last_ok_at, last_error, last_error_at, consecutive_failures
                 FROM health ORDER BY component",
            )?
            .query_map([], health_row)?
            .collect::<Result<Vec<_>, _>>()?;

        let chains = self
            .conn
            .prepare(
                "SELECT domain, name, start_height, final_height, observed_finalized, observed_head,
                        scanned_head, caught_up_at, updated_at
                 FROM chain_state ORDER BY domain",
            )?
            .query_map([], |r| {
                let opt = |i: usize| -> rusqlite::Result<Option<u64>> {
                    Ok(r.get::<_, Option<i64>>(i)?.map(|v| v as u64))
                };
                let name: String = r.get(1)?;
                let final_height = r.get::<_, i64>(3)? as u64;
                let observed_finalized = opt(4)?;
                Ok(ChainStatus {
                    domain: Domain(r.get(0)?),
                    health: None,
                    start_height: r.get::<_, i64>(2)? as u64,
                    final_height,
                    observed_finalized,
                    observed_head: opt(5)?,
                    scanned_head: opt(6)?,
                    caught_up_at: r.get(7)?,
                    updated_at: r.get(8)?,
                    cursor_lag: observed_finalized.map(|f| f.saturating_sub(final_height)),
                    name,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let chains = chains
            .into_iter()
            .map(|mut c| {
                let key = format!("ingest:{}", c.name);
                c.health = components.iter().find(|h| h.component == key).cloned();
                c
            })
            .collect();

        let mut report = StatusReport {
            now,
            chains,
            components,
            burned: 0,
            attested: 0,
            pre_window: 0,
            completed: 0,
            open_alerts: AlertCounts::default(),
        };

        let mut stmt = self
            .conn
            .prepare("SELECT state, COUNT(*) FROM transfers GROUP BY state")?;
        let counts = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
        })?;
        for row in counts {
            let (state, n) = row?;
            match TransferState::from_db(&state) {
                Some(TransferState::Burned) => report.burned = n,
                Some(TransferState::Attested) => report.attested = n,
                Some(TransferState::PreWindow) => report.pre_window = n,
                Some(TransferState::Completed) => report.completed = n,
                None => {}
            }
        }

        let mut stmt = tx.prepare(
            "SELECT severity, COUNT(*) FROM alerts WHERE resolved_at IS NULL GROUP BY severity",
        )?;
        let alerts = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
        })?;
        for row in alerts {
            let (severity, n) = row?;
            match severity.as_str() {
                "info" => report.open_alerts.info = n,
                "warning" => report.open_alerts.warning = n,
                "critical" => report.open_alerts.critical = n,
                _ => {}
            }
        }
        Ok(report)
    }

    /// Lists transfers, newest burn first.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn list_transfers(&self, filter: &TransferFilter) -> Result<Vec<TransferRow>, StoreError> {
        let state = filter.state.map(TransferState::as_str);
        let limit = i64::try_from(filter.limit).unwrap_or(i64::MAX);
        let mut stmt = self.conn.prepare(
            "SELECT burn_id, receive_id, source_domain, destination_domain, nonce, burn_tx, burn_time,
                    burn_finalized, receive_tx, receive_time, receive_finalized, amount,
                    min_finality_threshold, state, fee_executed, latency_secs
             FROM transfers
             WHERE (?1 IS NULL OR state = ?1)
             ORDER BY burn_time DESC, burn_id DESC
             LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![state, limit], transfer_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}
