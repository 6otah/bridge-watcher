//! SQLite storage. All SQL of the program lives in this module.
//!
//! One [`Store`] owns one `rusqlite::Connection`. Its methods are synchronous
//! domain operations. [`SharedStore`] shares it between tokio tasks and runs
//! each call on the blocking pool.
//!
//! The schema (`schema.sql`) is applied when `PRAGMA user_version` is 0 and
//! then set to 1. Any other version is rejected. The invariants I1-I7 are
//! enforced by [`Store::apply_scan`] and by triggers that protect final rows.
//!
//! Rules for SQL in this module:
//! - Never use `OR REPLACE` or `REPLACE`. A replace deletes the conflicting
//!   row, and a final row must never be deleted (I3). `configure` also turns
//!   on `recursive_triggers`, so the protection triggers fire for REPLACE as a
//!   second line of defence.
//! - Write only your own columns, with targeted
//!   `UPDATE ... SET`.

mod alerts;
mod attest;
mod ingest;
mod read;

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OpenFlags};

pub use alerts::{
    Alert, AlertCondition, AlertSyncStats, AttestedBurnRow, Candidates, ChainLimits, ChainSnapshot,
    DuplicateRow, LatencySample, MismatchRow, MonitorSnapshot, OrphanRow, PendingBurnRow,
    RECENT_SECS, RollbackRow, SnapshotLimits,
};
pub use attest::{
    BurnPollUpdate, IrisObservation, NonceConflict, OrphanReceive, PendingBurn, PendingTx,
    SourceLookup, StoredBurn,
};
pub use ingest::{ApplyStats, ChainCursor, Scope};
pub use read::{
    AlertCounts, ChainStatus, HealthRow, StatusReport, TransferFilter, TransferRow, TransferState,
};

const SCHEMA: &str = include_str!("schema.sql");
const SCHEMA_VERSION: i64 = 2;

/// Slack, in seconds, for clock differences between chains in the coverage
/// rule: a missing receive is claimed only for a burn with
/// `block_time >= destination start_time + COVERAGE_MARGIN_SECS`. The
/// `transfers` view in `schema.sql` holds the same number as a literal; a test
/// keeps them equal.
pub const COVERAGE_MARGIN_SECS: i64 = 60;

/// Database failure. Every variant is fatal for the process: a restart
/// replays safely.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite or driver error, including a trigger abort.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// Another writer moved the cursor.
    #[error("cursor for domain {domain} moved: expected {expected}, found {found}")]
    CursorMoved {
        /// Chain.
        domain: u32,
        /// Cursor the caller scanned from.
        expected: u64,
        /// Cursor in the database.
        found: u64,
    },
    /// No `chain_state` row exists for the domain: `init_cursor` was not called.
    #[error("no cursor for domain {domain}; init_cursor was not called")]
    NoCursor {
        /// Chain.
        domain: u32,
    },
    /// A caller broke a documented precondition (a programming error).
    #[error("scope violation: {0}")]
    Scope(String),
    /// The file has a schema version this build does not know. There is no
    /// migration: delete the database file and start again.
    #[error(
        "database schema version {0} is not supported (this build needs version 2); delete the database file, there is no migration from version {0}"
    )]
    SchemaVersion(i64),
    /// The database and the configuration disagree.
    #[error("config does not match database: {0}")]
    ConfigMismatch(String),
    /// A closure panicked on the blocking pool, or the mutex is poisoned.
    #[error("store task panicked or mutex poisoned")]
    Panicked,
}

/// The database connection and the domain operations on it.
///
/// Operations are in `ingest.rs`, `read.rs` and (later phases) `attest.rs`
/// and `alerts.rs`.
pub struct Store {
    conn: Connection,
}

fn configure(conn: &Connection) -> Result<(), StoreError> {
    conn.busy_timeout(std::time::Duration::from_millis(5000))?;
    conn.pragma_update(None, "foreign_keys", true)?;
    // Without this, SQLite does not fire DELETE triggers for rows removed by
    // REPLACE conflict resolution, which would bypass the final-row triggers.
    conn.pragma_update(None, "recursive_triggers", true)?;
    Ok(())
}

impl Store {
    /// Opens or creates the database at `path`, enables WAL, and applies the
    /// schema when the file is new. The parent directory must exist.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`], or [`StoreError::SchemaVersion`] if the file has
    /// another schema version.
    pub fn open(path: &Path) -> Result<Store, StoreError> {
        let conn = Connection::open(path)?;
        configure(&conn)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::migrate(conn)
    }

    /// Opens a private in-memory database with the schema applied.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn open_in_memory() -> Result<Store, StoreError> {
        let conn = Connection::open_in_memory()?;
        configure(&conn)?;
        Self::migrate(conn)
    }

    /// Opens an existing database for reading only. Works while another
    /// process writes (WAL).
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] if the file is missing or unreadable;
    /// [`StoreError::SchemaVersion`] if it was never initialised.
    pub fn open_read_only(path: &Path) -> Result<Store, StoreError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure(&conn)?;
        let version = Self::user_version(&conn)?;
        if version != SCHEMA_VERSION {
            return Err(StoreError::SchemaVersion(version));
        }
        Ok(Store { conn })
    }

    fn user_version(conn: &Connection) -> Result<i64, StoreError> {
        Ok(conn.pragma_query_value(None, "user_version", |r| r.get(0))?)
    }

    fn migrate(mut conn: Connection) -> Result<Store, StoreError> {
        match Self::user_version(&conn)? {
            0 => {
                let tx = conn.transaction()?;
                tx.execute_batch(SCHEMA)?;
                tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                tx.commit()?;
            }
            SCHEMA_VERSION => {}
            other => return Err(StoreError::SchemaVersion(other)),
        }
        Ok(Store { conn })
    }
}

/// A [`Store`] shared between tokio tasks.
#[derive(Clone)]
pub struct SharedStore {
    inner: Arc<Mutex<Store>>,
}

impl SharedStore {
    /// Opens the database file. See [`Store::open`].
    ///
    /// # Errors
    /// Same as [`Store::open`].
    pub fn open(path: &Path) -> Result<SharedStore, StoreError> {
        Ok(Self::from_store(Store::open(path)?))
    }

    /// Wraps an already opened store.
    pub fn from_store(store: Store) -> SharedStore {
        SharedStore {
            inner: Arc::new(Mutex::new(store)),
        }
    }

    /// Runs `f` on the blocking pool while holding the only connection.
    ///
    /// The mutex guard never crosses an `.await`: it lives inside the blocking
    /// task, so futures that call `run` stay `Send`.
    ///
    /// # Errors
    /// Whatever `f` returns, or [`StoreError::Panicked`] if `f` panics or the
    /// mutex is poisoned.
    pub async fn run<R, F>(&self, f: F) -> Result<R, StoreError>
    where
        F: FnOnce(&mut Store) -> Result<R, StoreError> + Send + 'static,
        R: Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| StoreError::Panicked)?;
            f(&mut guard)
        })
        .await
        .map_err(|_| StoreError::Panicked)?
    }
}

/// Converts a height or amount to the `i64` that SQLite stores.
pub(crate) fn to_i64(v: u64, what: &str) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Scope(format!("{what} does not fit in i64: {v}")))
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::*;
    use crate::domain::{BurnBody, BurnMessage, ChainEvent, Domain, EventKind, EventLocation};
    use crate::domain::{Bytes32, ReceiveMessage};

    const BASE: Domain = Domain(6);

    fn location(tx: &str, height: u64) -> EventLocation {
        EventLocation {
            domain: BASE,
            tx_id: tx.to_string(),
            event_index: 0,
            height,
            block_hash: None,
            block_time: 1,
        }
    }

    fn burn(tx: &str, height: u64) -> ChainEvent {
        ChainEvent {
            at: location(tx, height),
            kind: EventKind::Burn(BurnMessage {
                source_domain: BASE,
                destination_domain: Domain(5),
                sender: Bytes32([1; 32]),
                recipient: Bytes32([2; 32]),
                destination_caller: Bytes32::ZERO,
                min_finality_threshold: 2000,
                burn_token: Bytes32([3; 32]),
                mint_recipient: Bytes32([4; 32]),
                amount: 1,
                depositor: Bytes32([5; 32]),
                max_fee: 0,
                hook_data: vec![],
            }),
        }
    }

    fn receive(tx: &str, height: u64) -> ChainEvent {
        ChainEvent {
            at: location(tx, height),
            kind: EventKind::Receive(ReceiveMessage {
                source_domain: Domain(5),
                nonce: Bytes32([9; 32]),
                sender: Bytes32([1; 32]),
                caller: Bytes32([6; 32]),
                finality_threshold_executed: 2000,
                body: BurnBody {
                    burn_token: Bytes32([3; 32]),
                    mint_recipient: Bytes32([4; 32]),
                    amount: 1,
                    depositor: Bytes32([5; 32]),
                    max_fee: 0,
                    fee_executed: 0,
                    expiration_block: 0,
                    hook_data: vec![],
                },
            }),
        }
    }

    fn assert_i3(res: rusqlite::Result<usize>) {
        let err = res
            .expect_err("the final-row trigger must abort")
            .to_string();
        assert!(err.contains("invariant I3"), "unexpected error: {err}");
    }

    /// REPLACE conflict resolution deletes rows without the DELETE trigger
    /// unless `recursive_triggers` is on. This runs on the connection that
    /// `Store` itself configures, because the pragma is per connection.
    #[test]
    fn store_replace_cannot_bypass_final_triggers() {
        let mut store = Store::open_in_memory().unwrap();
        store.init_cursor(BASE, "base", 100, 0, 0).unwrap();
        store
            .apply_scan(
                BASE,
                Scope::Final {
                    after: 100,
                    through: 110,
                },
                &[burn("0xa", 105), receive("0xr", 106)],
                0,
            )
            .unwrap();
        store
            .apply_scan(
                BASE,
                Scope::Tail {
                    after: 110,
                    through: 120,
                },
                &[burn("0xb", 115), receive("0xs", 116)],
                0,
            )
            .unwrap();
        let conn = &store.conn;

        // Same event key, other height: REPLACE would delete the final row.
        let replace_burn = "INSERT OR REPLACE INTO burns (source_domain, tx_id, event_index, height,
                block_time, finalized, destination_domain, sender, recipient, destination_caller,
                min_finality_threshold, burn_token, mint_recipient, amount, depositor, max_fee, hook_data)
            SELECT source_domain, tx_id, event_index, 999, block_time, 0, destination_domain, sender,
                recipient, destination_caller, min_finality_threshold, burn_token, mint_recipient,
                amount, depositor, max_fee, hook_data FROM burns WHERE tx_id = '0xa'";
        assert_i3(conn.execute(replace_burn, []));
        let replace_receive = "INSERT OR REPLACE INTO receives (domain, tx_id, event_index, height,
                block_time, finalized, source_domain, nonce, sender, caller,
                finality_threshold_executed, burn_token, mint_recipient, amount, depositor, max_fee,
                fee_executed, expiration_block, hook_data)
            SELECT domain, tx_id, event_index, 999, block_time, 0, source_domain, nonce, sender, caller,
                finality_threshold_executed, burn_token, mint_recipient, amount, depositor, max_fee,
                fee_executed, expiration_block, hook_data FROM receives WHERE tx_id = '0xr'";
        assert_i3(conn.execute(replace_receive, []));

        // UPDATE ... OR REPLACE onto the unique nonce index of a final row.
        conn.execute(
            "UPDATE burns SET nonce = ?1 WHERE tx_id = '0xa'",
            params![vec![1u8; 32]],
        )
        .unwrap();
        conn.execute(
            "UPDATE burns SET nonce = ?1 WHERE tx_id = '0xb'",
            params![vec![2u8; 32]],
        )
        .unwrap();
        let res = conn.execute(
            "UPDATE OR REPLACE burns SET nonce = ?1 WHERE tx_id = '0xb'",
            params![vec![1u8; 32]],
        );
        assert_i3(res);

        let (height, finalized): (i64, i64) = conn
            .query_row(
                "SELECT height, finalized FROM burns WHERE tx_id = '0xa'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((height, finalized), (105, 1));
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM receives WHERE tx_id = '0xr' AND finalized = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }
}
