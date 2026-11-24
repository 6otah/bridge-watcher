//! The attestation resolver: polls Iris for pending burns and classifies
//! orphan receives.
//!
//! Burn polling: each due source transaction is asked
//! from Iris once; the decoded messages are paired with the stored burns by
//! [`assign_iris_messages`] and the result is written in one store
//! transaction under the write-once nonce rule. Orphan verification: a final
//! receive without a burn is looked up in Iris by nonce, the source transaction
//! is read from its chain, and the pure [`classify_orphan`] decides whether an equal on-chain burn exists.
//!
//! Invariants:
//! - After HTTP 429 no Iris call is made until the lockout has passed.
//! - Iris data can never stop the process: a nonce conflict is logged and the
//!   burn stays not complete. Only [`StoreError`] is returned.
//! - `last_polled_at` moves only when Iris answered. A transport failure only
//!   postpones the next poll.
//! - Every orphan gets at most `orphan_max_lookups` attempts, spaced
//!   `orphan_retry_secs`. A failed attempt counts too, but it keeps the stored
//!   verdict; only an Iris 429 is not an attempt.

use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::clock::unix_now;
use crate::codec::decode_burn_message;
use crate::config::IrisConfig;
use crate::domain::{BurnMessage, Bytes32, IrisFields};
use crate::iris::{IrisApi, IrisError, IrisMessage, IrisQuery, IrisResponse};
use crate::matching::{IrisCandidate, assign_iris_messages};
use crate::source::{TxEvidence, TxInspector};
use crate::store::{
    BurnPollUpdate, ChainCursor, IrisObservation, NonceConflict, OrphanReceive, PendingTx,
    SharedStore, SourceLookup, StoreError,
};

/// Health component name of the resolver loop.
pub const COMPONENT: &str = "resolver";

/// Tuning of the [`Resolver`]. Built from `[iris]` with `From<&IrisConfig>`.
#[derive(Clone, Debug)]
pub struct ResolverConfig {
    /// Sleep between ticks.
    pub poll_interval: Duration,
    /// First retry delay of a pending burn.
    pub initial_backoff_secs: i64,
    /// Cap of the retry delay.
    pub max_backoff_secs: i64,
    /// Pause of all Iris calls after HTTP 429.
    pub lockout: Duration,
    /// Transactions polled per tick.
    pub max_txs_per_tick: usize,
    /// Age of a receive before its source lookup starts.
    pub orphan_grace_secs: i64,
    /// Attempts per orphan receive, failed ones included.
    pub orphan_max_lookups: u32,
    /// Orphan receives looked up per tick.
    pub orphan_batch: usize,
    /// Spacing between lookups of one orphan, also after an error.
    pub orphan_retry_secs: i64,
}

impl From<&IrisConfig> for ResolverConfig {
    fn from(c: &IrisConfig) -> Self {
        let secs = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
        ResolverConfig {
            poll_interval: Duration::from_secs(c.poll_interval_secs),
            initial_backoff_secs: secs(c.initial_backoff_secs),
            max_backoff_secs: secs(c.max_backoff_secs),
            lockout: Duration::from_secs(c.lockout_secs),
            max_txs_per_tick: c.max_txs_per_tick,
            orphan_grace_secs: c.orphan_grace_secs,
            orphan_max_lookups: c.orphan_max_lookups,
            orphan_batch: c.orphan_batch,
            orphan_retry_secs: secs(c.orphan_retry_secs),
        }
    }
}

/// What one [`Resolver::tick`] did.
#[derive(Debug, Default)]
pub struct ResolverReport {
    /// The tick did nothing because the Iris lockout is still running.
    pub paused: bool,
    /// Iris answered HTTP 429 during this tick.
    pub rate_limited: bool,
    /// Source transactions asked from Iris.
    pub txs_polled: usize,
    /// Burns that became complete.
    pub burns_attested: usize,
    /// Observations the write-once rule refused.
    pub conflicts: Vec<NonceConflict>,
    /// Orphan lookups that Iris answered and that ended in a verdict other
    /// than `postponed`.
    pub orphans_classified: usize,
    /// Failed Iris or source calls.
    pub errors: usize,
    /// Text for the `health` row; `Some` makes the tick count as a failure.
    pub error: Option<String>,
}

/// Polls Iris for pending burns and classifies orphan receives.
pub struct Resolver<I, T> {
    iris: I,
    inspector: T,
    store: SharedStore,
    cfg: ResolverConfig,
    paused_until: Option<Instant>,
}

/// A usable Iris message: ready, CCTP V2, decodable, non-zero nonce.
fn candidate(m: &IrisMessage) -> Option<(IrisCandidate, IrisFields)> {
    let bytes = m.message.as_ref()?;
    if m.cctp_version.is_some_and(|v| v != 2) {
        return None;
    }
    let (message, fields) = decode_burn_message(bytes).ok()?;
    if fields.nonce == Bytes32::ZERO {
        return None;
    }
    let nonce = fields.nonce;
    Some((IrisCandidate { message, nonce }, fields))
}

/// Canonical form of a transaction id that Iris reports: an EVM hash becomes
/// `0x` plus lowercase hex (stored ids are lowercase, and Iris may answer in
/// another case); a Solana base58 signature is case-sensitive and unchanged.
pub fn normalize_tx_id(tx: &str) -> String {
    match tx.strip_prefix("0x").or_else(|| tx.strip_prefix("0X")) {
        Some(hex) => format!("0x{}", hex.to_ascii_lowercase()),
        None => tx.to_string(),
    }
}

/// What Iris said for one nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum IrisNonceAnswer {
    /// HTTP 404.
    Unknown,
    /// Iris knows the nonce.
    Known {
        /// Source transaction Iris names, if any.
        source_tx: Option<String>,
        /// Source part of the message whose decoded nonce is the receive's
        /// nonce; `None` if no message decodes with it.
        message: Option<BurnMessage>,
    },
}

/// Our stored burns of the Iris source tx that equal the Iris message, by what
/// they mean for the minted nonce.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoredEqual {
    /// No nonce yet, or the receive's own nonce (any finality).
    pub free: u32,
    /// Final, attested under another nonce.
    pub other_final: u32,
    /// Not final, holding another nonce.
    pub other_unfinal: u32,
}

/// The decision table for one lookup. Pure.
///
/// `evidence` is the `inspect_tx` result for the Iris source tx (`None` if the
/// chain does not know it, or if it was not asked). `stored`: our stored
/// burns of that tx that equal the Iris message. `source` is the
/// cursor of the source chain. `lookups_done` counts the lookups before this
/// one. First matching row wins:
///
/// 1. Iris 404: `UnknownToIris`.
/// 2. Iris names no source tx: `SourceNotFound`.
/// 3. No decodable message with this nonce: `Postponed`.
/// 4. The chain does not know the tx: `SourceNotFound`.
/// 5. The tx has no burn equal to the message (`E = 0`): `IrisMismatch`,
///    whatever the start height. Row 5a, checked next: no free stored equal
///    burn, no unfinalized other-nonce holder, and `other_final >= E`, so every
///    equal on-chain burn is stored, final and attested under another nonce:
///    `DoubleMint`.
/// 6. Equal burn below `start_height`: `PreStart`.
/// 7. A stored equal burn is free or held by an unfinalized row: `Postponed`
///    (the burn side will match it, or finality will settle it).
/// 8. Equal burn within the scanned range, not stored: `Missed`.
/// 9. Equal burn above the scanned range: `Postponed`.
///
/// Rule E: a `Postponed` outcome on the last allowed attempt
/// (`lookups_done + 1 >= max_lookups`) becomes `Unresolved`.
pub fn classify_orphan(
    iris: &IrisNonceAnswer,
    evidence: Option<&TxEvidence>,
    stored: StoredEqual,
    source: &ChainCursor,
    lookups_done: u32,
    max_lookups: u32,
) -> SourceLookup {
    let outcome = match iris {
        IrisNonceAnswer::Unknown => SourceLookup::UnknownToIris,
        IrisNonceAnswer::Known {
            source_tx: None, ..
        } => SourceLookup::SourceNotFound,
        IrisNonceAnswer::Known { message: None, .. } => SourceLookup::Postponed,
        IrisNonceAnswer::Known {
            message: Some(message),
            ..
        } => match evidence {
            None => SourceLookup::SourceNotFound,
            Some(e) if !e.burns.contains(message) => SourceLookup::IrisMismatch,
            Some(e)
                if stored.free == 0
                    && stored.other_unfinal == 0
                    && usize::try_from(stored.other_final)
                        .is_ok_and(|n| n >= e.burns.iter().filter(|b| *b == message).count()) =>
            {
                SourceLookup::DoubleMint
            }
            Some(e) if e.height < source.start_height => SourceLookup::PreStart,
            Some(_) if stored.free > 0 || stored.other_unfinal > 0 => SourceLookup::Postponed,
            Some(e) => {
                let scanned = source.final_height.max(source.scanned_head.unwrap_or(0));
                if e.height <= scanned {
                    SourceLookup::Missed
                } else {
                    SourceLookup::Postponed
                }
            }
        },
    };
    if outcome == SourceLookup::Postponed && lookups_done.saturating_add(1) >= max_lookups {
        SourceLookup::Unresolved
    } else {
        outcome
    }
}

impl<I: IrisApi, T: TxInspector> Resolver<I, T> {
    /// Creates a resolver. It holds no state besides the lockout deadline.
    pub fn new(iris: I, inspector: T, store: SharedStore, cfg: ResolverConfig) -> Self {
        Resolver {
            iris,
            inspector,
            store,
            cfg,
            paused_until: None,
        }
    }

    /// True while the Iris lockout after an HTTP 429 is running.
    pub fn is_paused(&self) -> bool {
        self.paused_until.is_some_and(|t| Instant::now() < t)
    }

    /// `min(initial * 2^n, max)` seconds.
    fn backoff(&self, n: u32) -> i64 {
        let factor = 1i64.checked_shl(n.min(30)).unwrap_or(i64::MAX);
        self.cfg
            .initial_backoff_secs
            .saturating_mul(factor)
            .min(self.cfg.max_backoff_secs)
    }

    fn pause(&mut self, report: &mut ResolverReport) {
        self.paused_until = Some(Instant::now() + self.cfg.lockout);
        report.rate_limited = true;
        report.error = Some(format!(
            "Iris rate limit (HTTP 429): paused for {} s",
            self.cfg.lockout.as_secs()
        ));
        tracing::error!(
            lockout_secs = self.cfg.lockout.as_secs(),
            "Iris answered HTTP 429; pausing all Iris calls"
        );
    }

    /// One iteration: poll due burns, then look up orphan receives, then write
    /// the `health` row. `now` is Unix seconds.
    ///
    /// # Errors
    /// [`StoreError`] only. Iris and source failures are counted in the
    /// report and retried later.
    pub async fn tick(&mut self, now: i64) -> Result<ResolverReport, StoreError> {
        let mut report = ResolverReport::default();
        if self.is_paused() {
            report.paused = true;
            report.error = Some("Iris calls paused after HTTP 429".to_string());
        } else {
            self.paused_until = None;
            self.poll_burns(now, &mut report).await?;
            if !self.is_paused() {
                self.lookup_orphans(now, &mut report).await?;
            }
            if report.error.is_none() && report.errors > 0 && report.txs_polled == 0 {
                report.error = Some(format!("{} Iris or source calls failed", report.errors));
            }
        }
        let error = report.error.clone();
        self.store
            .run(move |s| s.record_health(COMPONENT, error.as_deref().map_or(Ok(()), Err), now))
            .await?;
        Ok(report)
    }

    /// Runs ticks until `cancel` fires.
    ///
    /// # Errors
    /// The first [`StoreError`]; the caller must stop the process.
    pub async fn run(mut self, cancel: CancellationToken) -> Result<(), StoreError> {
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                result = self.tick(unix_now()) => { result?; }
            }
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                () = tokio::time::sleep(self.cfg.poll_interval) => {}
            }
        }
    }

    async fn poll_burns(
        &mut self,
        now: i64,
        report: &mut ResolverReport,
    ) -> Result<(), StoreError> {
        let max = self.cfg.max_txs_per_tick;
        let queue = self
            .store
            .run(move |s| s.attestation_queue(now, max))
            .await?;
        let mut updates: Vec<BurnPollUpdate> = Vec::new();
        let mut deferred: Vec<(Vec<i64>, i64)> = Vec::new();
        for tx in queue {
            let answer = self
                .iris
                .get_messages(tx.source_domain, IrisQuery::TxId(tx.tx_id.clone()))
                .await;
            match answer {
                Err(IrisError::RateLimited) => {
                    self.pause(report);
                    break;
                }
                Err(IrisError::Transient(e)) => {
                    report.errors += 1;
                    tracing::warn!(tx = %tx.tx_id, error = %e, "Iris poll failed");
                    let next = now
                        + self.backoff(tx.burns.iter().map(|b| b.poll_count).max().unwrap_or(0));
                    let ids = tx
                        .burns
                        .iter()
                        .filter(|b| !b.complete)
                        .map(|b| b.slot.id)
                        .collect();
                    deferred.push((ids, next));
                }
                Ok(None) => {
                    report.txs_polled += 1;
                    for b in tx.burns.iter().filter(|b| !b.complete) {
                        updates.push(BurnPollUpdate {
                            burn_id: b.slot.id,
                            observation: None,
                            next_poll_at: now + self.backoff(b.poll_count),
                        });
                    }
                }
                Ok(Some(resp)) => {
                    report.txs_polled += 1;
                    self.pair_burns(&tx, &resp, now, &mut updates);
                }
            }
        }
        if updates.is_empty() && deferred.is_empty() {
            return Ok(());
        }
        let completed: Vec<i64> = updates
            .iter()
            .filter(|u| u.observation.as_ref().is_some_and(|o| o.complete))
            .map(|u| u.burn_id)
            .collect();
        let conflicts = self
            .store
            .run(move |s| {
                for (ids, next) in &deferred {
                    s.defer_attestation_polls(ids, *next)?;
                }
                s.record_attestation_polls(&updates, now)
            })
            .await?;
        for c in &conflicts {
            tracing::error!(
                burn_id = c.burn_id,
                nonce = %c.nonce,
                held_by = ?c.held_by,
                "Iris nonce conflict: observation not applied, burn stays not complete"
            );
        }
        report.burns_attested = completed
            .iter()
            .filter(|id| !conflicts.iter().any(|c| c.burn_id == **id))
            .count();
        report.conflicts = conflicts;
        Ok(())
    }

    /// Turns one Iris answer into poll updates for the not-complete burns of
    /// the transaction.
    fn pair_burns(
        &self,
        tx: &PendingTx,
        resp: &IrisResponse,
        now: i64,
        updates: &mut Vec<BurnPollUpdate>,
    ) {
        let decoded: Vec<Option<(IrisCandidate, IrisFields)>> =
            resp.messages.iter().map(candidate).collect();
        let cands: Vec<Option<IrisCandidate>> = decoded
            .iter()
            .map(|d| d.as_ref().map(|(c, _)| c.clone()))
            .collect();
        let slots: Vec<_> = tx.burns.iter().map(|b| b.slot.clone()).collect();
        let pairs = assign_iris_messages(&slots, &cands);
        for burn in tx.burns.iter().filter(|b| !b.complete) {
            let paired = pairs
                .iter()
                .find(|(id, _)| *id == burn.slot.id)
                .map(|(_, j)| *j);
            let observation = match paired {
                Some(j) => {
                    let (cand, fields) = decoded[j].as_ref().expect("paired message is usable");
                    let m = &resp.messages[j];
                    Some(IrisObservation {
                        nonce: cand.nonce,
                        complete: m.status == "complete" && m.attestation_ready,
                        fee_executed: fields.fee_executed,
                        finality_threshold_executed: fields.finality_threshold_executed,
                        delay_reason: m.delay_reason.clone(),
                        iris_destination_tx: m.destination_tx.clone(),
                    })
                }
                None => {
                    if let Some(n) = burn.slot.nonce {
                        tracing::warn!(
                            burn_id = burn.slot.id,
                            tx = %tx.tx_id,
                            nonce = %n,
                            "Iris did not confirm the stored nonce (missing, or other fields)"
                        );
                    }
                    None
                }
            };
            updates.push(BurnPollUpdate {
                burn_id: burn.slot.id,
                observation,
                next_poll_at: now + self.backoff(burn.poll_count),
            });
        }
    }

    async fn lookup_orphans(
        &mut self,
        now: i64,
        report: &mut ResolverReport,
    ) -> Result<(), StoreError> {
        let (grace, max_lookups, batch) = (
            self.cfg.orphan_grace_secs,
            self.cfg.orphan_max_lookups,
            self.cfg.orphan_batch,
        );
        let next = now + self.cfg.orphan_retry_secs;
        let queue = self
            .store
            .run(move |s| s.orphan_queue(now, grace, max_lookups, batch))
            .await?;
        for orphan in queue {
            let id = orphan.id;
            let answer = match self
                .iris
                .get_messages(orphan.source_domain, IrisQuery::Nonce(orphan.nonce))
                .await
            {
                Err(IrisError::RateLimited) => {
                    self.pause(report);
                    break;
                }
                Err(IrisError::Transient(e)) => {
                    tracing::warn!(nonce = %orphan.nonce, error = %e, "Iris orphan lookup failed");
                    self.failed_attempt(&orphan, next, report, e).await?;
                    continue;
                }
                Ok(None) => IrisNonceAnswer::Unknown,
                Ok(Some(resp)) => IrisNonceAnswer::Known {
                    source_tx: resp.source_tx.as_deref().map(normalize_tx_id),
                    message: message_with_nonce(&resp, orphan.nonce),
                },
            };
            let (evidence, stored) = match &answer {
                IrisNonceAnswer::Known {
                    source_tx: Some(tx),
                    message: Some(message),
                } => {
                    let evidence = match self.inspector.inspect_tx(orphan.source_domain, tx).await {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::warn!(tx = %tx, error = %e, "inspecting the source transaction failed");
                            self.failed_attempt(&orphan, next, report, e.to_string())
                                .await?;
                            continue;
                        }
                    };
                    let (domain, tx_owned, wanted) =
                        (orphan.source_domain, tx.clone(), message.clone());
                    let held = orphan.nonce;
                    let stored = self
                        .store
                        .run(move |s| {
                            let mut eq = StoredEqual::default();
                            for b in s
                                .burns_of_tx(domain, &tx_owned)?
                                .iter()
                                .filter(|b| b.slot.message == wanted)
                            {
                                match b.slot.nonce {
                                    None => eq.free += 1,
                                    Some(n) if n == held => eq.free += 1,
                                    Some(_) if b.finalized => eq.other_final += 1,
                                    Some(_) => eq.other_unfinal += 1,
                                }
                            }
                            Ok(eq)
                        })
                        .await?;
                    (evidence, stored)
                }
                _ => (None, StoredEqual::default()),
            };
            let domain = orphan.source_domain;
            let cursor = self
                .store
                .run(move |s| s.cursor(domain))
                .await?
                .unwrap_or_else(|| ChainCursor {
                    domain,
                    name: String::new(),
                    start_height: 0,
                    start_time: 0,
                    final_height: 0,
                    scanned_head: None,
                });
            let outcome = classify_orphan(
                &answer,
                evidence.as_ref(),
                stored,
                &cursor,
                orphan.lookups_done,
                self.cfg.orphan_max_lookups,
            );
            if outcome != SourceLookup::Postponed {
                report.orphans_classified += 1;
            }
            match outcome {
                SourceLookup::IrisMismatch => tracing::error!(
                    nonce = %orphan.nonce,
                    "minted message equals no burn of its source tx"
                ),
                SourceLookup::DoubleMint => tracing::error!(
                    nonce = %orphan.nonce,
                    "minted message equals a burn that is attested under another nonce"
                ),
                _ => {}
            }
            let iris_tx = match &answer {
                IrisNonceAnswer::Known { source_tx, .. } => source_tx.clone(),
                IrisNonceAnswer::Unknown => None,
            };
            self.store
                .run(move |s| s.record_source_lookup(id, Some(outcome), iris_tx.as_deref(), next))
                .await?;
        }
        Ok(())
    }
}

impl<I: IrisApi, T: TxInspector> Resolver<I, T> {
    /// Records a failed orphan attempt (Iris or source error). The attempt
    /// counts and is spaced like any other, but the stored verdict stays so a
    /// critical alert does not flap. If it was the last allowed attempt and no
    /// verdict was reached, the orphan becomes `unresolved`.
    async fn failed_attempt(
        &self,
        orphan: &OrphanReceive,
        next: i64,
        report: &mut ResolverReport,
        error: String,
    ) -> Result<(), StoreError> {
        report.errors += 1;
        let last_allowed = orphan.lookups_done.saturating_add(1) >= self.cfg.orphan_max_lookups;
        let verdict = (last_allowed && matches!(orphan.last, None | Some(SourceLookup::Postponed)))
            .then_some(SourceLookup::Unresolved);
        if verdict.is_some() {
            report.error.get_or_insert(error);
        }
        let id = orphan.id;
        self.store
            .run(move |s| s.record_source_lookup(id, verdict, None, next))
            .await
    }
}

/// The source part of the message of `resp` whose decoded nonce is `nonce`.
fn message_with_nonce(resp: &IrisResponse, nonce: Bytes32) -> Option<BurnMessage> {
    resp.messages.iter().find_map(|m| {
        let (message, fields) = decode_burn_message(m.message.as_ref()?).ok()?;
        (fields.nonce == nonce).then_some(message)
    })
}
