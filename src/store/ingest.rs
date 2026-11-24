//! Store operations of the ingestors: cursors, heights, health and
//! [`Store::apply_scan`], which owns the finality invariants I1-I6.

use std::collections::HashSet;

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use super::{Store, StoreError, to_i64};
use crate::domain::{
    BurnMessage, ChainEvent, Domain, EventKind, EventLocation, Heights, ReceiveMessage,
};

/// The height range one scan covers.
///
/// - `Final { after, through }`: finalized data. `after` must equal the stored
///   cursor; the cursor moves to `through`.
/// - `Tail { after, through }`: unfinalized data above the cursor.
///
/// Both mean the half-open range `(after, through]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Finalized scan; moves the cursor.
    Final {
        /// Exclusive lower bound; the current cursor.
        after: u64,
        /// Inclusive upper bound; the new cursor.
        through: u64,
    },
    /// Unfinalized scan above the cursor.
    Tail {
        /// Exclusive lower bound; at or above the cursor.
        after: u64,
        /// Inclusive upper bound.
        through: u64,
    },
}

impl Scope {
    fn bounds(self) -> (u64, u64) {
        match self {
            Scope::Final { after, through } | Scope::Tail { after, through } => (after, through),
        }
    }

    fn is_final(self) -> bool {
        matches!(self, Scope::Final { .. })
    }

    fn name(self) -> &'static str {
        if self.is_final() { "final" } else { "tail" }
    }
}

/// What one [`Store::apply_scan`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApplyStats {
    /// Rows inserted or updated.
    pub upserted: usize,
    /// Unfinalized rows that became final.
    pub promoted: usize,
    /// Unfinalized rows deleted because the scan did not return them.
    pub rolled_back: usize,
    /// Events whose key matches a final row stored at another height. The
    /// final row is left unchanged.
    pub final_conflicts: usize,
}

/// Cursor and observed heights of one chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainCursor {
    /// Chain.
    pub domain: Domain,
    /// Config name of the chain.
    pub name: String,
    /// First height in scope; never changes.
    pub start_height: u64,
    /// Chain time at which the window starts: the time of the last block at or
    /// below `start_height - 1`. Written once with the cursor; never changes.
    pub start_time: i64,
    /// All events at heights up to this one are stored as final.
    pub final_height: u64,
    /// Top of the last complete tail scan.
    pub scanned_head: Option<u64>,
}

struct StoredRow {
    id: i64,
    tx_id: String,
    event_index: u32,
    height: i64,
    block_hash: Option<String>,
}

const UPSERT_BURN: &str = "
INSERT INTO burns (source_domain, tx_id, event_index, height, block_hash, block_time, finalized,
    destination_domain, sender, recipient, destination_caller, min_finality_threshold,
    burn_token, mint_recipient, amount, depositor, max_fee, hook_data)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
ON CONFLICT (source_domain, tx_id, event_index) DO UPDATE SET
    height = excluded.height, block_hash = excluded.block_hash, block_time = excluded.block_time,
    finalized = excluded.finalized, destination_domain = excluded.destination_domain,
    sender = excluded.sender, recipient = excluded.recipient,
    destination_caller = excluded.destination_caller,
    min_finality_threshold = excluded.min_finality_threshold,
    burn_token = excluded.burn_token, mint_recipient = excluded.mint_recipient,
    amount = excluded.amount, depositor = excluded.depositor, max_fee = excluded.max_fee,
    hook_data = excluded.hook_data
WHERE burns.finalized = 0";

const UPSERT_RECEIVE: &str = "
INSERT INTO receives (domain, tx_id, event_index, height, block_hash, block_time, finalized,
    source_domain, nonce, sender, caller, finality_threshold_executed, burn_token,
    mint_recipient, amount, depositor, max_fee, fee_executed, expiration_block, hook_data)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
ON CONFLICT (domain, tx_id, event_index) DO UPDATE SET
    height = excluded.height, block_hash = excluded.block_hash, block_time = excluded.block_time,
    finalized = excluded.finalized, source_domain = excluded.source_domain,
    nonce = excluded.nonce, sender = excluded.sender, caller = excluded.caller,
    finality_threshold_executed = excluded.finality_threshold_executed,
    burn_token = excluded.burn_token, mint_recipient = excluded.mint_recipient,
    amount = excluded.amount, depositor = excluded.depositor, max_fee = excluded.max_fee,
    fee_executed = excluded.fee_executed, expiration_block = excluded.expiration_block,
    hook_data = excluded.hook_data
WHERE receives.finalized = 0";

fn validate_events(
    domain: Domain,
    after: u64,
    through: u64,
    events: &[ChainEvent],
) -> Result<(), StoreError> {
    if after >= through {
        return Err(StoreError::Scope(format!(
            "empty scope: after {after} >= through {through}"
        )));
    }
    let mut keys = HashSet::new();
    for ev in events {
        if ev.at.domain != domain {
            return Err(StoreError::Scope(format!(
                "event {} has domain {}, scope has {}",
                ev.at.tx_id, ev.at.domain, domain
            )));
        }
        if ev.at.height <= after || ev.at.height > through {
            return Err(StoreError::Scope(format!(
                "event {}#{} at height {} is outside ({after}, {through}]",
                ev.at.tx_id, ev.at.event_index, ev.at.height
            )));
        }
        if !keys.insert((ev.at.tx_id.as_str(), ev.at.event_index)) {
            return Err(StoreError::Scope(format!(
                "duplicate event key {}#{}",
                ev.at.tx_id, ev.at.event_index
            )));
        }
    }
    Ok(())
}

fn existing_rows(
    tx: &Transaction<'_>,
    table: &str,
    domain_column: &str,
    domain: Domain,
    after: i64,
    through: i64,
) -> Result<Vec<StoredRow>, StoreError> {
    let sql = format!(
        "SELECT id, tx_id, event_index, height, block_hash FROM {table}
         WHERE {domain_column} = ?1 AND finalized = 0 AND height > ?2 AND height <= ?3"
    );
    let mut stmt = tx.prepare(&sql)?;
    let rows = stmt.query_map(params![domain.0, after, through], |r| {
        Ok(StoredRow {
            id: r.get(0)?,
            tx_id: r.get(1)?,
            event_index: r.get(2)?,
            height: r.get(3)?,
            block_hash: r.get(4)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// What [`upsert_event`] did with one event.
enum Upserted {
    /// Inserted or updated. `promoted` is true if an unfinalized row became final.
    Written { promoted: bool },
    /// A final row with the same key and height exists; nothing to do.
    AlreadyFinal,
    /// A final row with the same key exists at another height; it is kept.
    FinalConflict,
}

/// Writes one event unless a final row with the same key exists.
fn upsert_event(
    tx: &Transaction<'_>,
    ev: &ChainEvent,
    finalized: bool,
) -> Result<Upserted, StoreError> {
    let at = &ev.at;
    let height = to_i64(at.height, "height")?;
    let (table, domain_column) = match ev.kind {
        EventKind::Burn(_) => ("burns", "source_domain"),
        EventKind::Receive(_) => ("receives", "domain"),
    };
    let existing: Option<(i64, i64)> = tx
        .query_row(
            &format!(
                "SELECT finalized, height FROM {table}
                 WHERE {domain_column} = ?1 AND tx_id = ?2 AND event_index = ?3"
            ),
            params![at.domain.0, at.tx_id, at.event_index],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((1, stored_height)) = existing {
        return Ok(if stored_height == height {
            Upserted::AlreadyFinal
        } else {
            Upserted::FinalConflict
        });
    }
    match &ev.kind {
        EventKind::Burn(b) => upsert_burn(tx, at, b, finalized)?,
        EventKind::Receive(r) => upsert_receive(tx, at, r, finalized)?,
    }
    Ok(Upserted::Written {
        promoted: finalized && existing.is_some(),
    })
}

fn upsert_burn(
    tx: &Transaction<'_>,
    at: &EventLocation,
    b: &BurnMessage,
    finalized: bool,
) -> Result<(), StoreError> {
    tx.prepare_cached(UPSERT_BURN)?.execute(params![
        at.domain.0,
        at.tx_id,
        at.event_index,
        to_i64(at.height, "height")?,
        at.block_hash,
        at.block_time,
        finalized,
        b.destination_domain.0,
        &b.sender.0[..],
        &b.recipient.0[..],
        &b.destination_caller.0[..],
        b.min_finality_threshold,
        &b.burn_token.0[..],
        &b.mint_recipient.0[..],
        to_i64(b.amount, "amount")?,
        &b.depositor.0[..],
        to_i64(b.max_fee, "max_fee")?,
        b.hook_data,
    ])?;
    Ok(())
}

fn upsert_receive(
    tx: &Transaction<'_>,
    at: &EventLocation,
    r: &ReceiveMessage,
    finalized: bool,
) -> Result<(), StoreError> {
    let body = &r.body;
    tx.prepare_cached(UPSERT_RECEIVE)?.execute(params![
        at.domain.0,
        at.tx_id,
        at.event_index,
        to_i64(at.height, "height")?,
        at.block_hash,
        at.block_time,
        finalized,
        r.source_domain.0,
        &r.nonce.0[..],
        &r.sender.0[..],
        &r.caller.0[..],
        r.finality_threshold_executed,
        &body.burn_token.0[..],
        &body.mint_recipient.0[..],
        to_i64(body.amount, "amount")?,
        &body.depositor.0[..],
        to_i64(body.max_fee, "max_fee")?,
        to_i64(body.fee_executed, "fee_executed")?,
        to_i64(body.expiration_block, "expiration_block")?,
        body.hook_data,
    ])?;
    Ok(())
}

fn roll_back_stale(
    tx: &Transaction<'_>,
    table: &str,
    event_type: &str,
    domain: Domain,
    scope: &str,
    stale: &[&StoredRow],
    now: i64,
) -> Result<(), StoreError> {
    for row in stale {
        tx.execute(
            "INSERT INTO rollbacks (domain, event_type, tx_id, event_index, height, block_hash, scope, detected_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                domain.0,
                event_type,
                row.tx_id,
                row.event_index,
                row.height,
                row.block_hash,
                scope,
                now
            ],
        )?;
        tx.execute(
            &format!("DELETE FROM {table} WHERE id = ?1 AND finalized = 0"),
            params![row.id],
        )?;
        tracing::warn!(
            domain = domain.0,
            event_type,
            tx_id = %row.tx_id,
            event_index = row.event_index,
            height = row.height,
            scope,
            "rolled back unfinalized event"
        );
    }
    Ok(())
}

impl Store {
    /// Cursor row of `domain`, or `None` before [`Store::init_cursor`].
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn cursor(&self, domain: Domain) -> Result<Option<ChainCursor>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT name, start_height, final_height, scanned_head, start_time FROM chain_state WHERE domain = ?1",
                params![domain.0],
                |r| {
                    Ok(ChainCursor {
                        domain,
                        name: r.get(0)?,
                        start_height: r.get::<_, i64>(1)? as u64,
                        final_height: r.get::<_, i64>(2)? as u64,
                        scanned_head: r.get::<_, Option<i64>>(3)?.map(|v| v as u64),
                        start_time: r.get(4)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Creates the cursor on the first run: `final_height` as given,
    /// `start_height = final_height + 1`, and `start_time` (the chain time of
    /// the last block at or below `final_height`). All of them are written in
    /// one statement and never change. If the row exists, returns it
    /// unchanged and ignores the arguments.
    ///
    /// # Errors
    /// [`StoreError::ConfigMismatch`] if the stored row has another `name`;
    /// [`StoreError::Sqlite`].
    pub fn init_cursor(
        &mut self,
        domain: Domain,
        name: &str,
        final_height: u64,
        start_time: i64,
        now: i64,
    ) -> Result<ChainCursor, StoreError> {
        let start = to_i64(final_height, "final_height")?
            .checked_add(1)
            .ok_or_else(|| StoreError::Scope("final_height overflow".into()))?;
        self.conn.execute(
            "INSERT OR IGNORE INTO chain_state
                (domain, name, start_height, start_time, final_height, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![domain.0, name, start, start_time, start - 1, now],
        )?;
        let cursor = self
            .cursor(domain)?
            .ok_or(StoreError::NoCursor { domain: domain.0 })?;
        if cursor.name != name {
            return Err(StoreError::ConfigMismatch(format!(
                "domain {domain} is stored as '{}', config says '{name}'",
                cursor.name
            )));
        }
        Ok(cursor)
    }

    /// Records the heights read from the node.
    ///
    /// # Errors
    /// [`StoreError::NoCursor`] if the chain has no cursor; [`StoreError::Sqlite`].
    pub fn record_heights(
        &mut self,
        domain: Domain,
        observed: Heights,
        now: i64,
    ) -> Result<(), StoreError> {
        let changed = self.conn.execute(
            "UPDATE chain_state SET observed_finalized = ?2, observed_head = ?3, updated_at = ?4
             WHERE domain = ?1",
            params![
                domain.0,
                to_i64(observed.finalized, "finalized")?,
                to_i64(observed.head, "head")?,
                now
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::NoCursor { domain: domain.0 });
        }
        Ok(())
    }

    /// Applies one scan in one `BEGIN IMMEDIATE` transaction.
    ///
    /// Upserts the events with `finalized` set for `Scope::Final`, removes
    /// unfinalized rows of the scope that the scan did not return (each is
    /// logged in `rollbacks` first), and for `Scope::Final` moves the cursor
    /// from `after` to `through` (compare-and-swap).
    ///
    /// Final rows are never changed. An event whose key matches a final row at
    /// another height is counted in [`ApplyStats::final_conflicts`] and logged.
    ///
    /// # Errors
    /// [`StoreError::Scope`] if a precondition is broken (`after < through`;
    /// every event has this `domain` and a height in `(after, through]`; keys
    /// are unique; `Tail` has `after >= cursor`).
    /// [`StoreError::NoCursor`] if the chain has no cursor.
    /// [`StoreError::CursorMoved`] if `Final.after` is not the stored cursor.
    /// Nothing is written on error.
    pub fn apply_scan(
        &mut self,
        domain: Domain,
        scope: Scope,
        events: &[ChainEvent],
        now: i64,
    ) -> Result<ApplyStats, StoreError> {
        let (after, through) = scope.bounds();
        validate_events(domain, after, through, events)?;
        let (after_i, through_i) = (to_i64(after, "after")?, to_i64(through, "through")?);

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cursor: i64 = tx
            .query_row(
                "SELECT final_height FROM chain_state WHERE domain = ?1",
                params![domain.0],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(StoreError::NoCursor { domain: domain.0 })?;
        let cursor = cursor as u64;
        match scope {
            Scope::Final { after, .. } if after != cursor => {
                return Err(StoreError::CursorMoved {
                    domain: domain.0,
                    expected: after,
                    found: cursor,
                });
            }
            Scope::Tail { after, .. } if after < cursor => {
                return Err(StoreError::Scope(format!(
                    "tail scope after {after} is below cursor {cursor}"
                )));
            }
            _ => {}
        }

        let burns_before =
            existing_rows(&tx, "burns", "source_domain", domain, after_i, through_i)?;
        let receives_before = existing_rows(&tx, "receives", "domain", domain, after_i, through_i)?;

        let mut stats = ApplyStats::default();
        let mut burn_keys = HashSet::new();
        let mut receive_keys = HashSet::new();
        for ev in events {
            let keys = match ev.kind {
                EventKind::Burn(_) => &mut burn_keys,
                EventKind::Receive(_) => &mut receive_keys,
            };
            keys.insert((ev.at.tx_id.as_str(), ev.at.event_index));
            match upsert_event(&tx, ev, scope.is_final())? {
                Upserted::Written { promoted } => {
                    stats.upserted += 1;
                    stats.promoted += usize::from(promoted);
                }
                Upserted::AlreadyFinal => {}
                Upserted::FinalConflict => {
                    stats.final_conflicts += 1;
                    tracing::error!(
                        domain = domain.0,
                        tx_id = %ev.at.tx_id,
                        event_index = ev.at.event_index,
                        height = ev.at.height,
                        "event conflicts with a final row at another height; final row kept"
                    );
                }
            }
        }

        let stale_burns: Vec<&StoredRow> = burns_before
            .iter()
            .filter(|r| !burn_keys.contains(&(r.tx_id.as_str(), r.event_index)))
            .collect();
        let stale_receives: Vec<&StoredRow> = receives_before
            .iter()
            .filter(|r| !receive_keys.contains(&(r.tx_id.as_str(), r.event_index)))
            .collect();
        roll_back_stale(
            &tx,
            "burns",
            "burn",
            domain,
            scope.name(),
            &stale_burns,
            now,
        )?;
        roll_back_stale(
            &tx,
            "receives",
            "receive",
            domain,
            scope.name(),
            &stale_receives,
            now,
        )?;
        stats.rolled_back = stale_burns.len() + stale_receives.len();

        if scope.is_final() {
            let moved = tx.execute(
                "UPDATE chain_state SET final_height = ?2, updated_at = ?3
                 WHERE domain = ?1 AND final_height = ?4",
                params![domain.0, through_i, now, after_i],
            )?;
            if moved != 1 {
                return Err(StoreError::CursorMoved {
                    domain: domain.0,
                    expected: after,
                    found: cursor,
                });
            }
        } else {
            tx.execute(
                "UPDATE chain_state SET updated_at = ?2 WHERE domain = ?1",
                params![domain.0, now],
            )?;
        }
        tx.commit()?;
        Ok(stats)
    }

    /// Records that a tail scan reached `scanned_head` just now.
    ///
    /// # Errors
    /// [`StoreError::NoCursor`] if the chain has no cursor; [`StoreError::Sqlite`].
    pub fn mark_caught_up(
        &mut self,
        domain: Domain,
        scanned_head: u64,
        now: i64,
    ) -> Result<(), StoreError> {
        let changed = self.conn.execute(
            "UPDATE chain_state SET scanned_head = ?2, caught_up_at = ?3, updated_at = ?3
             WHERE domain = ?1",
            params![domain.0, to_i64(scanned_head, "scanned_head")?, now],
        )?;
        if changed == 0 {
            return Err(StoreError::NoCursor { domain: domain.0 });
        }
        Ok(())
    }

    /// Starts a process run: `health` then describes exactly `components`.
    ///
    /// In one transaction, upserts the row of each listed component with
    /// `started_at = now` and `consecutive_failures = 0`, and deletes the rows
    /// of all other components. `last_ok_at`, `last_error` and `last_error_at`
    /// of surviving rows are kept for diagnosis. Called once per process by
    /// `app`, after slow start-up work and before the loops spawn, so every
    /// loop gets a full `stall_after` grace period (section 9.2).
    ///
    /// # Errors
    /// [`StoreError::Sqlite`]. Nothing is written on error.
    pub fn start_components(&mut self, components: &[&str], now: i64) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for component in components {
            tx.execute(
                "INSERT INTO health (component, started_at, consecutive_failures)
                 VALUES (?1, ?2, 0)
                 ON CONFLICT (component) DO UPDATE SET
                    started_at = excluded.started_at, consecutive_failures = 0",
                params![component, now],
            )?;
        }
        let stored: Vec<String> = tx
            .prepare("SELECT component FROM health")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        for component in stored.iter().filter(|c| !components.contains(&c.as_str())) {
            tx.execute(
                "DELETE FROM health WHERE component = ?1",
                params![component],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Records the outcome of one loop iteration in the `health` row of
    /// `component`. `Ok` clears the failure counter; `Err(text)` stores the
    /// (already redacted) text and counts a failure.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn record_health(
        &mut self,
        component: &str,
        outcome: Result<(), &str>,
        now: i64,
    ) -> Result<(), StoreError> {
        match outcome {
            Ok(()) => self.conn.execute(
                "INSERT INTO health (component, started_at, last_ok_at, consecutive_failures)
                 VALUES (?1, ?2, ?2, 0)
                 ON CONFLICT (component) DO UPDATE SET
                    last_ok_at = excluded.last_ok_at, consecutive_failures = 0",
                params![component, now],
            )?,
            Err(error) => self.conn.execute(
                "INSERT INTO health (component, started_at, last_error, last_error_at, consecutive_failures)
                 VALUES (?1, ?2, ?3, ?2, 1)
                 ON CONFLICT (component) DO UPDATE SET
                    last_error = excluded.last_error, last_error_at = excluded.last_error_at,
                    consecutive_failures = consecutive_failures + 1",
                params![component, now, error],
            )?,
        };
        Ok(())
    }
}
