//! Solana chain source: JSON-RPC client, signature paging, batch planning and transaction decoding.
//!
//! Solana has no `eth_getLogs`. [`SolanaSource`] lists the signatures of the
//! CCTP MessageTransmitterV2 program, fetches the transactions of a batch of
//! whole slots, and decodes the Anchor `emit_cpi!` events found in their inner
//! instructions.
//!
//! - [`rpc`]: JSON-RPC client and serde types.
//! - [`plan`]: pure batch planning over whole slots.
//! - [`events_from_transaction`]: the event trust rules, pure.

pub mod plan;
pub mod rpc;

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::codec::{
    CodecError, DEPOSIT_FOR_BURN, DepositForBurnEvent, MESSAGE_RECEIVED, MessageReceivedEvent,
    split_event_ix,
};
use crate::config::SolanaConfig;
use crate::domain::{
    Bytes32, ChainEvent, Commitment, Counterparty, Domain, EventKind, EventLocation, Heights,
};
use crate::source::{ChainSource, ScanResult, SourceError, TxEvidence};
use plan::{SignatureInfo, plan_batch};
use rpc::{RpcClient, SolanaRpcApi, TransactionResult};

/// Entries requested per `getSignaturesForAddress` page (the node maximum).
pub const SIGNATURE_PAGE_LIMIT: usize = 1000;
/// Slots that `time_at_or_before` tries before it gives up.
const TIME_SEARCH_STEPS: u64 = 1000;
/// Entries of the tail cache at which it is emptied.
const TAIL_CACHE_MAX: usize = 4096;

/// Identity of the CCTP programs on Solana.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolanaIds {
    /// CCTP domain of Solana.
    pub domain: Domain,
    /// MessageTransmitterV2 program id; emits `MessageReceived`.
    pub message_transmitter: Bytes32,
    /// TokenMessengerMinterV2 program id; emits `DepositForBurn`.
    pub token_messenger_minter: Bytes32,
}

/// Resolves an account index of a transaction: static keys first, then the
/// loaded writable keys, then the loaded readonly keys (v0 layout). A
/// transaction without `loadedAddresses` (legacy, v1) has only static keys.
fn account_key(tx: &TransactionResult, index: usize) -> Option<&str> {
    let static_keys = tx.transaction.message.account_keys.as_slice();
    let loaded = tx.meta.as_ref().and_then(|m| m.loaded_addresses.as_ref());
    let (writable, readonly): (&[String], &[String]) = match loaded {
        Some(l) => (&l.writable, &l.readonly),
        None => (&[], &[]),
    };
    let mut rest = index;
    for list in [static_keys, writable, readonly] {
        if rest < list.len() {
            return Some(list[rest].as_str());
        }
        rest -= list.len();
    }
    None
}

/// Decodes all trusted CCTP events of one `getTransaction` result (json
/// encoding). Pure.
///
/// An instruction is a trusted event only if all of these hold:
/// - the transaction succeeded (`meta.err` is null);
/// - it is an inner instruction (only the program can sign for its event
///   authority, so a top-level instruction cannot be a real event);
/// - its program id, resolved through the static keys and `loadedAddresses`,
///   equals the CCTP program that emits that event: TokenMessengerMinterV2 for
///   `DepositForBurn`, MessageTransmitterV2 for `MessageReceived`. Other
///   programs, for example an aggregator, emit events with the same tag and are
///   skipped;
/// - its data starts with the Anchor event tag and the event discriminator;
/// - the Borsh payload decodes exactly (no trailing bytes).
///
/// A burn is kept if its destination domain is the counterparty. A receive is
/// kept if its source domain is the counterparty and its sender is the
/// counterparty token messenger. `event_index` is the position in the flattened
/// inner-instruction list. The height is `tx.slot`; `tx.block_time` must be
/// set.
///
/// # Errors
/// [`SourceError::Undecodable`] if a tagged instruction of a CCTP program with
/// a known discriminator does not decode. [`SourceError::Rpc`] if the response
/// is malformed: no `meta`, no signature, no block time, an unresolvable
/// program index, or instruction data that is not base58.
pub fn events_from_transaction(
    tx: &TransactionResult,
    ids: &SolanaIds,
    cp: Counterparty,
) -> Result<Vec<ChainEvent>, SourceError> {
    let malformed = |what: &str| SourceError::Rpc(format!("malformed transaction: {what}"));
    let meta = tx.meta.as_ref().ok_or_else(|| malformed("no meta"))?;
    if meta.err.is_some() {
        return Ok(Vec::new());
    }
    let tx_id = tx
        .transaction
        .signatures
        .first()
        .ok_or_else(|| malformed("no signature"))?;
    let undecodable = |e: CodecError| SourceError::Undecodable {
        tx_id: tx_id.clone(),
        reason: e.to_string(),
    };

    let mut events = Vec::new();
    let flat = meta
        .inner_instructions
        .iter()
        .flatten()
        .flat_map(|g| &g.instructions);
    for (position, ix) in flat.enumerate() {
        let event_index =
            u32::try_from(position).map_err(|_| malformed("too many instructions"))?;
        let data = bs58::decode(&ix.data)
            .into_vec()
            .map_err(|_| malformed("instruction data is not base58"))?;
        let Some((discriminator, payload)) = split_event_ix(&data) else {
            continue;
        };
        let program = account_key(tx, ix.program_id_index)
            .ok_or_else(|| malformed("program index out of range"))
            .and_then(|key| {
                Bytes32::from_base58(key).map_err(|_| malformed("account key is not a pubkey"))
            })?;
        let kind = if program == ids.token_messenger_minter && discriminator == DEPOSIT_FOR_BURN {
            let event = DepositForBurnEvent::decode(payload).map_err(undecodable)?;
            if event.destination_domain != cp.domain.0 {
                continue;
            }
            EventKind::Burn(
                event
                    .into_burn_message(ids.domain, ids.token_messenger_minter)
                    .map_err(undecodable)?,
            )
        } else if program == ids.message_transmitter && discriminator == MESSAGE_RECEIVED {
            let event = MessageReceivedEvent::decode(payload).map_err(undecodable)?;
            if event.source_domain != cp.domain.0 || Bytes32(event.sender) != cp.token_messenger {
                continue;
            }
            EventKind::Receive(event.into_receive_message().map_err(undecodable)?)
        } else {
            continue;
        };
        events.push(ChainEvent {
            at: EventLocation {
                domain: ids.domain,
                tx_id: tx_id.clone(),
                event_index,
                height: tx.slot,
                block_hash: None,
                block_time: tx.block_time.ok_or_else(|| malformed("no block time"))?,
            },
            kind,
        });
    }
    Ok(events)
}

/// Decoded events of one transaction, cached for tail scans.
struct CachedTx {
    slot: u64,
    events: Vec<ChainEvent>,
}

/// Reads CCTP events of Solana.
///
/// Invariants: a final scan fetches every transaction at `finalized`
/// commitment and never reads the tail cache; a batch always ends at a slot
/// boundary.
pub struct SolanaSource<R = RpcClient> {
    rpc: R,
    name: String,
    ids: SolanaIds,
    signature_address: String,
    cp: Counterparty,
    max_tx_fetch_per_scan: usize,
    final_margin: u64,
    /// Decoded confirmed transactions by signature, so that the tail rescan of
    /// every tick does not fetch them again. Used by confirmed scans only.
    tail_cache: Mutex<HashMap<String, CachedTx>>,
}

impl SolanaSource<RpcClient> {
    /// Builds the source for `cfg` against `rpc_url` (the config URL or the
    /// `BW_SOLANA_RPC_URL` override).
    ///
    /// # Errors
    /// [`SourceError::Rpc`] if the URL is invalid; see [`RpcClient::new`].
    pub fn new(
        cfg: &SolanaConfig,
        rpc_url: &str,
        counterparty: Counterparty,
    ) -> Result<Self, SourceError> {
        let rpc = RpcClient::new(rpc_url, cfg.requests_per_second)?;
        Ok(Self::with_rpc(rpc, cfg, counterparty))
    }
}

impl<R: SolanaRpcApi> SolanaSource<R> {
    /// Builds the source over any [`SolanaRpcApi`]; used by tests.
    pub fn with_rpc(rpc: R, cfg: &SolanaConfig, counterparty: Counterparty) -> Self {
        Self {
            rpc,
            name: cfg.name.clone(),
            ids: SolanaIds {
                domain: Domain(cfg.domain),
                message_transmitter: cfg.message_transmitter.0,
                token_messenger_minter: cfg.token_messenger_minter.0,
            },
            signature_address: cfg.signature_address().0.to_base58(),
            cp: counterparty,
            max_tx_fetch_per_scan: cfg.max_tx_fetch_per_scan,
            final_margin: cfg.final_margin,
            tail_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Lists the signatures of `(after, up_to]` in ascending slot order.
    ///
    /// Pages are newest first. Paging stops at a short page or at an entry at
    /// or below `after`. Finalized listings send `minContextSlot = up_to`, so a
    /// node that has not reached `up_to` answers `Lagging` instead of a short
    /// list (scan contract S2/S3).
    async fn list_signatures(
        &self,
        after: u64,
        up_to: u64,
        commitment: Commitment,
    ) -> Result<Vec<SignatureInfo>, SourceError> {
        let min_context_slot = (commitment == Commitment::Finalized).then_some(up_to);
        let mut list = Vec::new();
        let mut seen = HashSet::new();
        let mut before: Option<String> = None;
        loop {
            let page = self
                .rpc
                .get_signatures(
                    &self.signature_address,
                    before.as_deref(),
                    SIGNATURE_PAGE_LIMIT,
                    commitment,
                    min_context_slot,
                )
                .await?;
            let full = page.len() >= SIGNATURE_PAGE_LIMIT;
            let last = page.last().map(|e| (e.signature.clone(), e.slot));
            for entry in page {
                if entry.slot > after && entry.slot <= up_to && seen.insert(entry.signature.clone())
                {
                    list.push(SignatureInfo {
                        failed: entry.err.is_some(),
                        signature: entry.signature,
                        slot: entry.slot,
                    });
                }
            }
            let Some((last_signature, last_slot)) = last else {
                break;
            };
            if !full || last_slot <= after {
                break;
            }
            if before.as_deref() == Some(last_signature.as_str()) {
                return Err(SourceError::Rpc("signature paging did not advance".into()));
            }
            before = Some(last_signature);
        }
        list.sort_by_key(|s| s.slot);
        Ok(list)
    }

    fn cached(&self, signature: &str, slot: u64) -> Option<Vec<ChainEvent>> {
        let cache = self.tail_cache.lock().expect("tail cache lock");
        cache
            .get(signature)
            .filter(|c| c.slot == slot)
            .map(|c| c.events.clone())
    }

    fn cache(&self, signature: &str, slot: u64, events: Vec<ChainEvent>) {
        let mut cache = self.tail_cache.lock().expect("tail cache lock");
        if cache.len() >= TAIL_CACHE_MAX {
            cache.clear();
        }
        cache.insert(signature.to_string(), CachedTx { slot, events });
    }

    /// Drops cache entries that the moving tail has left behind.
    fn prune_cache(&self, after: u64) {
        self.tail_cache
            .lock()
            .expect("tail cache lock")
            .retain(|_, c| c.slot > after);
    }
}

impl<R: SolanaRpcApi> ChainSource for SolanaSource<R> {
    fn domain(&self) -> Domain {
        self.ids.domain
    }

    fn name(&self) -> &str {
        &self.name
    }

    /// Finalized slot minus `final_margin`, and the confirmed slot. The margin
    /// absorbs the few slots by which load-balanced nodes differ; correctness
    /// does not depend on it, `minContextSlot` still guards finalized scans.
    async fn heights(&self) -> Result<Heights, SourceError> {
        let finalized = self
            .rpc
            .get_slot(Commitment::Finalized)
            .await?
            .saturating_sub(self.final_margin);
        let head = self.rpc.get_slot(Commitment::Confirmed).await?;
        Ok(Heights { finalized, head })
    }

    /// Scans whole slots of `(after, up_to]`.
    ///
    /// A finalized scan fetches each transaction at `finalized`. If the node
    /// does not have one yet, the scan stops before that slot and reports the
    /// slots before it as complete. A confirmed scan skips a transaction that
    /// the node does not have, and serves repeated ones from the tail cache.
    ///
    /// # Errors
    /// [`SourceError::Lagging`] if the node has not reached `up_to` (finalized
    /// listing), if the first slot of the batch is not final on the node yet,
    /// or if a block time is unavailable. [`SourceError::Rpc`] for node errors
    /// and answers that break the scan contract. [`SourceError::Undecodable`]
    /// as in [`events_from_transaction`].
    async fn scan(
        &self,
        after: u64,
        up_to: u64,
        commitment: Commitment,
    ) -> Result<ScanResult, SourceError> {
        if after >= up_to {
            return Err(SourceError::Rpc(format!(
                "empty scan range ({after}, {up_to}]"
            )));
        }
        let list = self.list_signatures(after, up_to, commitment).await?;
        let batch = plan_batch(&list, up_to, self.max_tx_fetch_per_scan);
        let confirmed = commitment == Commitment::Confirmed;
        let mut complete_through = batch.complete_through;
        let mut events: Vec<ChainEvent> = Vec::new();

        for sig in batch.take.iter().filter(|s| !s.failed) {
            if confirmed && let Some(cached) = self.cached(&sig.signature, sig.slot) {
                events.extend(cached);
                continue;
            }
            let Some(mut tx) = self.rpc.get_transaction(&sig.signature, commitment).await? else {
                if confirmed {
                    continue;
                }
                events.retain(|e| e.at.height != sig.slot);
                complete_through = sig.slot - 1;
                if complete_through <= after {
                    return Err(SourceError::Lagging(format!(
                        "transaction {} at slot {} is not final on the node yet",
                        sig.signature, sig.slot
                    )));
                }
                break;
            };
            if tx.transaction.signatures.first() != Some(&sig.signature) {
                return Err(SourceError::Rpc(format!(
                    "transaction {} came back under another signature",
                    sig.signature
                )));
            }
            if tx.slot != sig.slot {
                if confirmed {
                    continue;
                }
                return Err(SourceError::Rpc(format!(
                    "transaction {} is in slot {}, the listing says {}",
                    sig.signature, tx.slot, sig.slot
                )));
            }
            if tx.block_time.is_none() {
                tx.block_time = self.rpc.get_block_time(tx.slot).await?;
                if tx.block_time.is_none() {
                    return Err(SourceError::Lagging(format!(
                        "block time of slot {} is not available",
                        tx.slot
                    )));
                }
            }
            let decoded = events_from_transaction(&tx, &self.ids, self.cp)?;
            if confirmed {
                self.cache(&sig.signature, sig.slot, decoded.clone());
            }
            events.extend(decoded);
        }
        if confirmed {
            self.prune_cache(after);
        }
        Ok(ScanResult {
            events,
            complete_through,
        })
    }

    /// Slot and burns of `tx_id` at finalized commitment, decoded with the
    /// ingestion rules (`events_from_transaction`). A text that is not a
    /// signature is unknown to the chain; a failed transaction has no burns.
    ///
    /// `getBlockTime` of `slot`, stepping down one slot at a time over skipped
    /// slots (no time) for at most 1000 slots. A block the node does not have
    /// yet is not a skipped slot: that answer is `Lagging`, so the start time
    /// is never taken from an older block.
    ///
    /// # Errors
    /// [`SourceError::Rpc`] for node errors; [`SourceError::Lagging`] if the
    /// node lacks a block or no slot in range has a block time.
    async fn time_at_or_before(&self, height: u64) -> Result<(u64, i64), SourceError> {
        for step in 0..TIME_SEARCH_STEPS {
            let Some(slot) = height.checked_sub(step) else {
                break;
            };
            if let Some(time) = self.rpc.get_block_time(slot).await? {
                return Ok((slot, time));
            }
        }
        Err(SourceError::Lagging(format!(
            "no block time at or below slot {height} within {TIME_SEARCH_STEPS} slots"
        )))
    }

    /// # Errors
    /// [`SourceError::Rpc`] for node errors; [`SourceError::Undecodable`] if a
    /// CCTP instruction of the tx does not decode.
    async fn inspect_tx(&self, tx_id: &str) -> Result<Option<TxEvidence>, SourceError> {
        if bs58::decode(tx_id)
            .into_vec()
            .map_or(true, |b| b.len() != 64)
        {
            return Ok(None);
        }
        let Some(tx) = self
            .rpc
            .get_transaction(tx_id, Commitment::Finalized)
            .await?
        else {
            return Ok(None);
        };
        let burns = events_from_transaction(&tx, &self.ids, self.cp)?
            .into_iter()
            .filter_map(|e| match e.kind {
                EventKind::Burn(b) => Some(b),
                EventKind::Receive(_) => None,
            })
            .collect();
        Ok(Some(TxEvidence {
            height: tx.slot,
            burns,
        }))
    }
}
