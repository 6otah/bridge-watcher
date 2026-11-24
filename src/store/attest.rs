//! SQL for the attestation resolver: the polling queue, the write-once nonce
//! rule, and the orphan-receive lookup queue.
//!
//! Column ownership (design section 5.2): this file writes only the
//! attestation columns of `burns` (`nonce` .. `poll_count`) and the lookup
//! columns of `receives` (`source_lookup` .. `iris_source_tx`). Every update
//! is a targeted `UPDATE ... WHERE id = ?`. `AUTOINCREMENT` ids are never
//! reused, so an update for a burn that a rollback deleted changes no row.

use rusqlite::{OptionalExtension, Row, params};

use super::{Store, StoreError};
use crate::domain::{BurnMessage, Bytes32, Domain};
use crate::matching::BurnSlot;

/// One stored burn of a source transaction, as the resolver needs it.
#[derive(Clone, Debug)]
pub struct PendingBurn {
    /// Row id, event index and stored nonce of the burn, plus its content.
    pub slot: BurnSlot,
    /// The burn is already attested (`attestation_status = 'complete'`).
    pub complete: bool,
    /// Polls so far; drives the backoff.
    pub poll_count: u32,
}

/// All burns of one source transaction, when at least one of them is due.
#[derive(Clone, Debug)]
pub struct PendingTx {
    /// Chain of the burns.
    pub source_domain: Domain,
    /// Transaction id as stored.
    pub tx_id: String,
    /// Every stored burn of the transaction (any status), by `event_index`.
    pub burns: Vec<PendingBurn>,
}

/// What Iris said about one burn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrisObservation {
    /// Nonce of the paired message.
    pub nonce: Bytes32,
    /// Attestation is ready and the status is `complete`.
    pub complete: bool,
    /// Fee Iris reports (`feeExecuted`).
    pub fee_executed: u64,
    /// Finality Iris reports (`finalityThresholdExecuted`).
    pub finality_threshold_executed: u32,
    /// Iris `delayReason`, if any.
    pub delay_reason: Option<String>,
    /// Iris `destinationMintTxHash`; informational only.
    pub iris_destination_tx: Option<String>,
}

/// One poll result for one burn.
#[derive(Clone, Debug)]
pub struct BurnPollUpdate {
    /// Burn row id.
    pub burn_id: i64,
    /// The paired Iris message, or `None` if Iris gave nothing for this burn.
    pub observation: Option<IrisObservation>,
    /// When to poll this burn again.
    pub next_poll_at: i64,
}

/// An observation that the write-once nonce rule refused. It is Iris data, not
/// a bug of ours, so it is a value and never a [`StoreError`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonceConflict {
    /// The burn that was not updated.
    pub burn_id: i64,
    /// The nonce that Iris reported.
    pub nonce: Bytes32,
    /// Id of another burn that holds `nonce`; `None` if this burn already
    /// holds a different nonce.
    pub held_by: Option<i64>,
}

/// A final receive with no burn of the same `(source_domain, nonce)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrphanReceive {
    /// Receive row id.
    pub id: i64,
    /// Chain of the burn, according to the receive.
    pub source_domain: Domain,
    /// Nonce of the receive.
    pub nonce: Bytes32,
    /// Counted lookups done so far.
    pub lookups_done: u32,
    /// Verdict of the last counted lookup, if any.
    pub last: Option<SourceLookup>,
}

/// A stored burn of a source transaction, with its finality.
#[derive(Clone, Debug)]
pub struct StoredBurn {
    /// Row id, content and stored nonce.
    pub slot: BurnSlot,
    /// The row came from a finalized scan.
    pub finalized: bool,
}

/// Verdict of one orphan lookup (design section 7.2). The column
/// `receives.source_lookup` stores it in snake_case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceLookup {
    /// Not terminal: Iris answered 404 for the nonce.
    UnknownToIris,
    /// Not terminal: Iris names no source tx, or the source chain does not
    /// know it.
    SourceNotFound,
    /// Not terminal: not decidable yet.
    Postponed,
    /// Terminal: the equal burn is below `start_height`.
    PreStart,
    /// Terminal: the equal burn is on chain, in our scanned range, and not
    /// stored.
    Missed,
    /// Terminal: the source tx has no burn equal to the attested message.
    IrisMismatch,
    /// Terminal: every equal on-chain burn is already stored, final and
    /// attested under another nonce, so this nonce is a second attestation of
    /// the same burn, and it was minted.
    DoubleMint,
    /// Terminal: still `Postponed` after the last allowed attempt, or the
    /// last attempt failed without a verdict.
    Unresolved,
}

impl SourceLookup {
    /// The value of the `source_lookup` column.
    pub fn as_str(self) -> &'static str {
        match self {
            SourceLookup::UnknownToIris => "unknown_to_iris",
            SourceLookup::SourceNotFound => "source_not_found",
            SourceLookup::Postponed => "postponed",
            SourceLookup::PreStart => "pre_start",
            SourceLookup::Missed => "missed",
            SourceLookup::IrisMismatch => "iris_mismatch",
            SourceLookup::DoubleMint => "double_mint",
            SourceLookup::Unresolved => "unresolved",
        }
    }

    /// Parses a column value.
    pub fn from_db(s: &str) -> Option<SourceLookup> {
        Some(match s {
            "unknown_to_iris" => SourceLookup::UnknownToIris,
            "source_not_found" => SourceLookup::SourceNotFound,
            "postponed" => SourceLookup::Postponed,
            "pre_start" => SourceLookup::PreStart,
            "missed" => SourceLookup::Missed,
            "iris_mismatch" => SourceLookup::IrisMismatch,
            "double_mint" => SourceLookup::DoubleMint,
            "unresolved" => SourceLookup::Unresolved,
            _ => return None,
        })
    }

    /// A terminal verdict leaves the orphan queue for good.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            SourceLookup::PreStart
                | SourceLookup::Missed
                | SourceLookup::IrisMismatch
                | SourceLookup::DoubleMint
                | SourceLookup::Unresolved
        )
    }
}

fn bytes32(r: &Row<'_>, idx: usize) -> rusqlite::Result<Bytes32> {
    let blob: Vec<u8> = r.get(idx)?;
    <[u8; 32]>::try_from(blob).map(Bytes32).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            idx,
            rusqlite::types::Type::Blob,
            "expected 32 bytes".into(),
        )
    })
}

fn pending_burn(r: &Row<'_>) -> rusqlite::Result<PendingBurn> {
    let nonce: Option<Vec<u8>> = r.get(13)?;
    let nonce = nonce
        .map(|b| {
            <[u8; 32]>::try_from(b).map(Bytes32).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    13,
                    rusqlite::types::Type::Blob,
                    "nonce is not 32 bytes".into(),
                )
            })
        })
        .transpose()?;
    let status: String = r.get(14)?;
    Ok(PendingBurn {
        slot: BurnSlot {
            id: r.get(0)?,
            message: BurnMessage {
                source_domain: Domain(r.get(1)?),
                destination_domain: Domain(r.get(2)?),
                sender: bytes32(r, 3)?,
                recipient: bytes32(r, 4)?,
                destination_caller: bytes32(r, 5)?,
                min_finality_threshold: r.get(6)?,
                burn_token: bytes32(r, 7)?,
                mint_recipient: bytes32(r, 8)?,
                amount: r.get::<_, i64>(9)? as u64,
                depositor: bytes32(r, 10)?,
                max_fee: r.get::<_, i64>(11)? as u64,
                hook_data: r.get(12)?,
            },
            nonce,
        },
        complete: status == "complete",
        poll_count: r.get(15)?,
    })
}

const BURNS_OF_TX_SQL: &str = "SELECT id, source_domain, destination_domain, sender, recipient,
        destination_caller, min_finality_threshold, burn_token, mint_recipient, amount, depositor,
        max_fee, hook_data, nonce, attestation_status, poll_count, finalized
     FROM burns WHERE source_domain = ?1 AND tx_id = ?2 ORDER BY event_index";

fn clamp_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

impl Store {
    /// Burns that need an Iris poll, grouped by source transaction.
    ///
    /// A transaction is returned when at least one of its burns has
    /// `attestation_status <> 'complete'` and `next_poll_at <= now`. Oldest
    /// burn first, at most `max_txs` transactions. Each transaction carries ALL
    /// its stored burns (any status) sorted by `event_index`, because the
    /// matching needs the held nonces of the whole transaction.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn attestation_queue(
        &self,
        now: i64,
        max_txs: usize,
    ) -> Result<Vec<PendingTx>, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let due: Vec<(i64, String)> = tx
            .prepare(
                "SELECT source_domain, tx_id FROM burns
                 WHERE attestation_status <> 'complete' AND next_poll_at <= ?1
                 GROUP BY source_domain, tx_id
                 ORDER BY MIN(block_time), MIN(id)
                 LIMIT ?2",
            )?
            .query_map(
                params![now, i64::try_from(max_txs).unwrap_or(i64::MAX)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?
            .collect::<Result<_, _>>()?;
        let mut stmt = tx.prepare(
            "SELECT id, source_domain, destination_domain, sender, recipient, destination_caller,
                    min_finality_threshold, burn_token, mint_recipient, amount, depositor,
                    max_fee, hook_data, nonce, attestation_status, poll_count
             FROM burns WHERE source_domain = ?1 AND tx_id = ?2 ORDER BY event_index",
        )?;
        let mut out = Vec::with_capacity(due.len());
        for (domain, tx_id) in due {
            let burns = stmt
                .query_map(params![domain, tx_id], pending_burn)?
                .collect::<Result<Vec<_>, _>>()?;
            out.push(PendingTx {
                source_domain: Domain(u32::try_from(domain).unwrap_or(u32::MAX)),
                tx_id,
                burns,
            });
        }
        Ok(out)
    }

    /// Applies Iris poll results in one transaction under the nonce
    /// write-once rule (design section 7.1).
    ///
    /// Per update: the poll bookkeeping (`last_polled_at`, `poll_count`,
    /// `next_poll_at`, `unseen` becomes `pending`) is always written. With an
    /// observation, the nonce, status and Iris columns are written only if the
    /// burn holds no nonce or the same nonce, and no other burn of the same
    /// source domain holds it. A refused observation is returned as a
    /// [`NonceConflict`]; nothing else changes for that burn. A burn that a
    /// rollback deleted is skipped silently.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`]. Iris data never causes an error.
    pub fn record_attestation_polls(
        &mut self,
        updates: &[BurnPollUpdate],
        now: i64,
    ) -> Result<Vec<NonceConflict>, StoreError> {
        let tx = self.conn.transaction()?;
        let mut conflicts = Vec::new();
        for u in updates {
            let polled = tx.execute(
                "UPDATE burns SET last_polled_at = ?2, poll_count = poll_count + 1, next_poll_at = ?3,
                        attestation_status = CASE attestation_status
                            WHEN 'unseen' THEN 'pending' ELSE attestation_status END
                 WHERE id = ?1",
                params![u.burn_id, now, u.next_poll_at],
            )?;
            if polled == 0 {
                continue;
            }
            let Some(obs) = &u.observation else { continue };
            let nonce = obs.nonce.0.to_vec();
            let applied = tx.execute(
                "UPDATE burns SET nonce = ?2,
                        attestation_status = CASE WHEN ?3 OR attestation_status = 'complete'
                            THEN 'complete' ELSE 'pending' END,
                        fee_executed = ?4, finality_threshold_executed = ?5,
                        delay_reason = ?6, iris_destination_tx = ?7,
                        attested_at = CASE WHEN ?3 THEN COALESCE(attested_at, ?8) ELSE attested_at END
                 WHERE id = ?1
                   AND (nonce IS NULL OR nonce = ?2)
                   AND NOT EXISTS (SELECT 1 FROM burns o
                                    WHERE o.source_domain = burns.source_domain
                                      AND o.nonce = ?2 AND o.id <> burns.id)",
                params![
                    u.burn_id,
                    nonce,
                    obs.complete,
                    clamp_i64(obs.fee_executed),
                    obs.finality_threshold_executed,
                    obs.delay_reason,
                    obs.iris_destination_tx,
                    now
                ],
            )?;
            if applied > 0 {
                continue;
            }
            let (own, domain): (Option<Vec<u8>>, i64) = tx.query_row(
                "SELECT nonce, source_domain FROM burns WHERE id = ?1",
                params![u.burn_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let held_by = if own.is_some_and(|n| n != nonce) {
                None
            } else {
                tx.query_row(
                    "SELECT id FROM burns WHERE source_domain = ?1 AND nonce = ?2 AND id <> ?3
                     LIMIT 1",
                    params![domain, nonce, u.burn_id],
                    |r| r.get(0),
                )
                .optional()?
            };
            conflicts.push(NonceConflict {
                burn_id: u.burn_id,
                nonce: obs.nonce,
                held_by,
            });
        }
        tx.commit()?;
        Ok(conflicts)
    }

    /// Postpones burns after a failed Iris call, without touching the poll
    /// bookkeeping: `last_polled_at` stays, because the monitor reads it as
    /// proof that Iris was asked.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn defer_attestation_polls(
        &mut self,
        burn_ids: &[i64],
        next_poll_at: i64,
    ) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        for id in burn_ids {
            tx.execute(
                "UPDATE burns SET next_poll_at = ?2 WHERE id = ?1",
                params![id, next_poll_at],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Final receives with no burn of the same `(source_domain, nonce)` that
    /// are due for a source lookup (design section 7.2).
    ///
    /// Due means: older than `grace_secs` (chain time against `now`), no final
    /// verdict yet (`source_lookup` is NULL or `unknown_to_iris`),
    /// `next_lookup_at <= now`, and fewer than `max_lookups` lookups. Oldest
    /// first.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn orphan_queue(
        &self,
        now: i64,
        grace_secs: i64,
        max_lookups: u32,
        limit: usize,
    ) -> Result<Vec<OrphanReceive>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT r.id, r.source_domain, r.nonce, r.source_lookup_count, r.source_lookup
             FROM receives r
             WHERE r.finalized = 1
               AND r.block_time < ?1 - ?2
               AND (r.source_lookup IS NULL
                    OR r.source_lookup IN ('unknown_to_iris', 'source_not_found', 'postponed'))
               AND r.next_lookup_at <= ?1
               AND r.source_lookup_count < ?3
               AND NOT EXISTS (SELECT 1 FROM burns b
                                WHERE b.source_domain = r.source_domain AND b.nonce = r.nonce)
             ORDER BY r.block_time, r.id
             LIMIT ?4",
        )?;
        let rows = stmt
            .query_map(
                params![
                    now,
                    grace_secs,
                    max_lookups,
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                |r| {
                    let last: Option<String> = r.get(4)?;
                    Ok(OrphanReceive {
                        id: r.get(0)?,
                        source_domain: Domain(r.get(1)?),
                        nonce: bytes32(r, 2)?,
                        lookups_done: r.get(3)?,
                        last: last.as_deref().and_then(SourceLookup::from_db),
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// All stored burns of one source transaction, by `event_index`, with
    /// their stored nonces and finality. Orphan verification compares them with the Iris
    /// message (design section 7.2).
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn burns_of_tx(
        &self,
        source_domain: Domain,
        tx_id: &str,
    ) -> Result<Vec<StoredBurn>, StoreError> {
        let mut stmt = self.conn.prepare(BURNS_OF_TX_SQL)?;
        let rows = stmt
            .query_map(params![source_domain.0, tx_id], |r| {
                Ok(StoredBurn {
                    slot: pending_burn(r)?.slot,
                    finalized: r.get(16)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Stores the result of one orphan lookup.
    ///
    /// Every call is one attempt: it adds one to `source_lookup_count`.
    /// `outcome = Some(v)` sets `source_lookup`; `outcome = None` (a failed
    /// attempt) keeps the stored verdict. `iris_source_tx`, if given, is
    /// stored for display. A receive deleted by a rollback is skipped
    /// silently.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`].
    pub fn record_source_lookup(
        &mut self,
        receive_id: i64,
        outcome: Option<SourceLookup>,
        iris_source_tx: Option<&str>,
        next_lookup_at: i64,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE receives SET
                    source_lookup = COALESCE(?2, source_lookup),
                    source_lookup_count = source_lookup_count + 1,
                    iris_source_tx = COALESCE(?3, iris_source_tx),
                    next_lookup_at = ?4
             WHERE id = ?1",
            params![
                receive_id,
                outcome.map(SourceLookup::as_str),
                iris_source_tx,
                next_lookup_at
            ],
        )?;
        Ok(())
    }
}
