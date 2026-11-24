//! Solana source tests (`docs/ARCHITECTURE.md` sections 15.1 and 15.3): the
//! trust rules of `events_from_transaction` on the real fixtures, batch
//! planning, the request JSON, and the scan loop over a fake node.

mod common;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bridge_watcher::codec::{decode_burn_body, decode_burn_message, decode_header};
use bridge_watcher::config::SolanaConfig;
use bridge_watcher::domain::{Bytes32, ChainEvent, Commitment, Counterparty, Domain, EventKind};
use bridge_watcher::ingest::{IngestConfig, Ingestor};
use bridge_watcher::solana::plan::{SignatureInfo, plan_batch};
use bridge_watcher::solana::rpc::{
    SignatureEntry, SolanaRpcApi, TransactionResult, get_signatures_params, get_slot_params,
    get_transaction_params, request_body,
};
use bridge_watcher::solana::{
    SIGNATURE_PAGE_LIMIT, SolanaIds, SolanaSource, events_from_transaction,
};
use bridge_watcher::source::{ChainSource, SourceError};
use bridge_watcher::store::{SharedStore, Store};
use common::fixtures;
use serde_json::{Value, json};
use tempfile::TempDir;

const MINTER: &str = "CCTPV2vPZJS2u2BBsUoscuikbYjnpFmbFsvVuJdgUMQe";
const TRANSMITTER: &str = "CCTPV2Sm4AdWt5296sk4P66VBZ7bEhcARwFaaS9YPbeC";
const BURN_SIG: &str =
    "5hZceQXeq8yTugkfTLF9LXa9az3XXxEUbta6fUWhuEPuoogcgeS4dSgqMWDR5pPNq7dLYHtPPFrHtS87VpHdXWB2";
const RECEIVE_SIG: &str =
    "5SZfhkPdCW1iu1t3cBbbvHt4tpUGR7jKnKbXZUp7fp7Xd56wHeK5fB8XK9geuHQzna9S62nfJ54VGAmrowh6iRVX";
const BURN_SLOT: u64 = 473_327_426;
const RECEIVE_SLOT: u64 = 473_335_716;
const TOKEN_MESSENGER_EVM: &str = "28b5a0e9c621a5badaa536219b3a228c8168cf5d";
const NOW: i64 = 1_800_000_000;

fn ids() -> SolanaIds {
    SolanaIds {
        domain: Domain(5),
        message_transmitter: Bytes32::from_base58(TRANSMITTER).unwrap(),
        token_messenger_minter: Bytes32::from_base58(MINTER).unwrap(),
    }
}

fn counterparty() -> Counterparty {
    Counterparty {
        domain: Domain(6),
        token_messenger: Bytes32::from_evm_address(
            hex::decode(TOKEN_MESSENGER_EVM)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
    }
}

fn nonce(hex_str: &str) -> Bytes32 {
    Bytes32(
        hex::decode(hex_str.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn parse(v: Value) -> TransactionResult {
    serde_json::from_value(v).expect("fixture parses into TransactionResult")
}

fn burn_json() -> Value {
    fixtures::json("solana_burn_to_base.tx.json")
}

fn receive_json() -> Value {
    fixtures::json("solana_receive_from_base.tx.json")
}

fn events(v: Value) -> Result<Vec<ChainEvent>, SourceError> {
    events_from_transaction(&parse(v), &ids(), counterparty())
}

/// The `n`-th inner instruction of the flattened list.
fn inner_ix(tx: &mut Value, n: usize) -> &mut Value {
    let mut left = n;
    for group in tx["meta"]["innerInstructions"].as_array_mut().unwrap() {
        let list = group["instructions"].as_array_mut().unwrap();
        if left < list.len() {
            return &mut list[left];
        }
        left -= list.len();
    }
    panic!("no inner instruction {n}");
}

fn set_data(tx: &mut Value, n: usize, data: &[u8]) {
    inner_ix(tx, n)["data"] = json!(bs58::encode(data).into_string());
}

fn raw_data(tx: &mut Value, n: usize) -> Vec<u8> {
    bs58::decode(inner_ix(tx, n)["data"].as_str().unwrap())
        .into_vec()
        .unwrap()
}

// ---- events_from_transaction on the real fixtures (section 15.1, F8) ----

#[test]
fn solana_decodes_burn_fixture_v1_tx() {
    let tx = burn_json();
    assert_eq!(tx["version"], 1);
    let evs = events(tx).unwrap();
    assert_eq!(evs.len(), 1, "the aggregator event at index 10 is not ours");
    let ev = &evs[0];
    assert_eq!(ev.at.domain, Domain(5));
    assert_eq!(ev.at.tx_id, BURN_SIG);
    assert_eq!(ev.at.event_index, 9);
    assert_eq!(ev.at.height, BURN_SLOT);
    assert_eq!(ev.at.block_time, 1_795_519_649);
    assert_eq!(ev.at.block_hash, None);
    let EventKind::Burn(burn) = &ev.kind else {
        panic!("expected a burn");
    };
    assert_eq!(burn.source_domain, Domain(5));
    assert_eq!(burn.destination_domain, Domain(6));
    assert_eq!(burn.sender, ids().token_messenger_minter);
    assert_eq!(burn.amount, 21_000_000);
    assert_eq!(
        burn.depositor.to_base58(),
        "Bq3vfJV5KPerjc2eoa4PXQaJMvy6ACRQBRfwQ6wkanz7"
    );
    assert_eq!(burn.max_fee, 2100);
    assert_eq!(burn.min_finality_threshold, 1000);
    assert_eq!(burn.hook_data.len(), 32);
    // The same burn, as Circle's attestation service describes it.
    let (iris_burn, _) =
        decode_burn_message(&fixtures::iris_message("iris_solana_burn.json")).unwrap();
    assert_eq!(burn, &iris_burn);
}

#[test]
fn solana_ignores_aggregator_event_with_same_tag() {
    let mut tx = burn_json();
    // The aggregator (`pVs6...`) event sits at flattened index 10 and has the
    // CCTP tag; its program id is not a CCTP program.
    assert_eq!(
        &raw_data(&mut tx, 10)[..8],
        &bridge_watcher::codec::EVENT_IX_TAG
    );
    assert_eq!(events(tx.clone()).unwrap().len(), 1);

    // Even a perfect copy of the genuine burn event, emitted by the
    // aggregator, must not become a second burn.
    let genuine = raw_data(&mut tx, 9);
    set_data(&mut tx, 10, &genuine);
    let evs = events(tx).unwrap();
    assert_eq!(
        evs.iter().map(|e| e.at.event_index).collect::<Vec<_>>(),
        [9]
    );
}

#[test]
fn solana_decodes_receive_fixture_with_loaded_addresses() {
    let tx = receive_json();
    assert_eq!(tx["version"], 0);
    // MessageReceived (inner 4) has programIdIndex 3, a static key. The
    // MintAndWithdraw sibling (inner 3) uses key 17, which exists only in
    // `loadedAddresses.readonly`; it is tagged, so its program must resolve.
    assert_eq!(
        tx["transaction"]["message"]["accountKeys"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    let evs = events(tx.clone()).unwrap();
    assert_eq!(evs.len(), 1);
    let ev = &evs[0];
    assert_eq!(ev.at.tx_id, RECEIVE_SIG);
    assert_eq!(ev.at.event_index, 4);
    assert_eq!(ev.at.height, RECEIVE_SLOT);
    assert_eq!(ev.at.block_time, 1_795_521_438);
    let EventKind::Receive(rx) = &ev.kind else {
        panic!("expected a receive");
    };
    assert_eq!(rx.source_domain, Domain(6));
    assert_eq!(
        rx.nonce,
        nonce("0xdc9db8e758a6080cd494d37c7df9f4b80f3745b1957223ec728bb6759287833f")
    );
    assert_eq!(rx.sender, counterparty().token_messenger);
    assert_eq!(rx.finality_threshold_executed, 2000);
    assert_eq!(rx.body.amount, 5_196_725_157);
    // The body and nonce equal the Iris message of the same transfer.
    let iris = fixtures::iris_message("iris_base_burn.json");
    assert_eq!(rx.body, decode_burn_body(&iris[148..]).unwrap());
    assert_eq!(decode_header(&iris).unwrap().nonce, rx.nonce);
}

#[test]
fn solana_program_index_beyond_static_keys_needs_loaded_addresses() {
    let mut tx = receive_json();
    tx["meta"]
        .as_object_mut()
        .unwrap()
        .remove("loadedAddresses");
    let err = events(tx).unwrap_err();
    assert!(
        matches!(&err, SourceError::Rpc(m) if m.contains("program index out of range")),
        "{err:?}"
    );

    // A readonly list in another order moves key 17 to another program: the
    // sibling is then skipped, and the receive is still found.
    let mut tx = receive_json();
    let readonly = tx["meta"]["loadedAddresses"]["readonly"]
        .as_array_mut()
        .unwrap();
    readonly.reverse();
    assert_eq!(events(tx).unwrap().len(), 1);
}

#[test]
fn solana_tx_without_loaded_addresses_field() {
    let mut tx = burn_json();
    tx["meta"]
        .as_object_mut()
        .unwrap()
        .remove("loadedAddresses");
    let evs = events(tx).unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].at.event_index, 9);
    // `null` is the same as absent.
    let mut tx = burn_json();
    tx["meta"]["loadedAddresses"] = Value::Null;
    assert_eq!(events(tx).unwrap().len(), 1);
}

#[test]
fn solana_failed_tx_yields_no_events() {
    let mut tx = burn_json();
    tx["meta"]["err"] = json!({ "InstructionError": [0, { "Custom": 6001 }] });
    assert!(events(tx).unwrap().is_empty());
}

#[test]
fn solana_event_must_be_an_inner_instruction() {
    let mut tx = burn_json();
    let ix = inner_ix(&mut tx, 9).clone();
    tx["meta"]["innerInstructions"] = json!([]);
    tx["transaction"]["message"]["instructions"] = json!([ix]);
    assert!(events(tx.clone()).unwrap().is_empty());
    tx["meta"]["innerInstructions"] = Value::Null;
    assert!(events(tx).unwrap().is_empty());
}

#[test]
fn solana_undecodable_cctp_event_is_error() {
    for edit in [
        |d: &mut Vec<u8>| d.truncate(d.len() - 5),
        |d: &mut Vec<u8>| d.push(0),
        |d: &mut Vec<u8>| d.truncate(20),
    ] {
        let mut tx = burn_json();
        let mut data = raw_data(&mut tx, 9);
        edit(&mut data);
        set_data(&mut tx, 9, &data);
        let err = events(tx).unwrap_err();
        assert!(
            matches!(&err, SourceError::Undecodable { tx_id, .. } if tx_id == BURN_SIG),
            "{err:?}"
        );
    }
    let mut tx = receive_json();
    let mut data = raw_data(&mut tx, 4);
    data.push(7);
    set_data(&mut tx, 4, &data);
    assert!(matches!(
        events(tx).unwrap_err(),
        SourceError::Undecodable { .. }
    ));
}

#[test]
fn solana_ignores_other_domains_and_senders() {
    let tx = parse(burn_json());
    let other_domain = Counterparty {
        domain: Domain(7),
        ..counterparty()
    };
    assert!(
        events_from_transaction(&tx, &ids(), other_domain)
            .unwrap()
            .is_empty()
    );

    let rx = parse(receive_json());
    assert!(
        events_from_transaction(&rx, &ids(), other_domain)
            .unwrap()
            .is_empty()
    );
    let other_sender = Counterparty {
        token_messenger: Bytes32([9; 32]),
        ..counterparty()
    };
    assert!(
        events_from_transaction(&rx, &ids(), other_sender)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn solana_rejects_malformed_responses() {
    let mut tx = burn_json();
    tx["blockTime"] = Value::Null;
    assert!(matches!(events(tx).unwrap_err(), SourceError::Rpc(_)));

    let mut tx = burn_json();
    tx["meta"] = Value::Null;
    assert!(matches!(events(tx).unwrap_err(), SourceError::Rpc(_)));

    let mut tx = burn_json();
    tx["transaction"]["signatures"] = json!([]);
    assert!(matches!(events(tx).unwrap_err(), SourceError::Rpc(_)));

    let mut tx = burn_json();
    inner_ix(&mut tx, 9)["programIdIndex"] = json!(250);
    assert!(matches!(events(tx).unwrap_err(), SourceError::Rpc(_)));
}

// ---- plan_batch ----

fn sig(name: &str, slot: u64, failed: bool) -> SignatureInfo {
    SignatureInfo {
        signature: name.to_string(),
        slot,
        failed,
    }
}

#[test]
fn solana_plan_batch_never_splits_a_slot() {
    let sigs = [
        sig("a", 10, false),
        sig("b", 10, false),
        sig("c", 10, false),
        sig("d", 11, false),
    ];
    // The budget is below the size of the first slot: it is taken whole.
    let batch = plan_batch(&sigs, 20, 2);
    assert_eq!(batch.take.len(), 3);
    assert_eq!(batch.complete_through, 10);

    // The second slot does not fit; the batch ends before it.
    let sigs = [
        sig("a", 10, false),
        sig("b", 12, false),
        sig("c", 12, false),
    ];
    let batch = plan_batch(&sigs, 20, 2);
    assert_eq!(batch.take, sigs[..1]);
    assert_eq!(
        batch.complete_through, 11,
        "slot before the first one left out"
    );

    // Everything fits: complete through the end of the range.
    let batch = plan_batch(&sigs, 20, 3);
    assert_eq!(batch.take.len(), 3);
    assert_eq!(batch.complete_through, 20);
}

#[test]
fn solana_plan_batch_skips_failed_in_budget() {
    let sigs = [
        sig("f1", 10, true),
        sig("a", 10, false),
        sig("f2", 11, true),
        sig("f3", 11, true),
        sig("b", 12, false),
        sig("c", 13, false),
    ];
    let batch = plan_batch(&sigs, 20, 2);
    // Failed ones are taken but cost nothing: a, b fit, c does not.
    assert_eq!(batch.take.len(), 5);
    assert_eq!(batch.complete_through, 12);
}

#[test]
fn solana_plan_batch_of_an_empty_listing_covers_the_range() {
    let batch = plan_batch(&[], 50, 40);
    assert!(batch.take.is_empty());
    assert_eq!(batch.complete_through, 50);
}

// ---- request JSON ----

#[test]
fn solana_requests_send_version_and_min_context_slot() {
    let p = get_transaction_params("SIG", Commitment::Finalized);
    assert_eq!(
        p,
        json!(["SIG", {
            "encoding": "json",
            "commitment": "finalized",
            "maxSupportedTransactionVersion": 1
        }])
    );
    assert_eq!(
        get_transaction_params("SIG", Commitment::Confirmed)[1]["commitment"],
        "confirmed"
    );

    let p = get_signatures_params("ADDR", None, 1000, Commitment::Finalized, Some(777));
    assert_eq!(p[0], "ADDR");
    assert_eq!(p[1]["minContextSlot"], 777);
    assert_eq!(p[1]["commitment"], "finalized");
    assert_eq!(p[1]["limit"], 1000);
    assert!(p[1].get("before").is_none());

    let p = get_signatures_params("ADDR", Some("PREV"), 1000, Commitment::Confirmed, None);
    assert_eq!(p[1]["before"], "PREV");
    assert!(p[1].get("minContextSlot").is_none());

    assert_eq!(
        get_slot_params(Commitment::Confirmed)[0]["commitment"],
        "confirmed"
    );
    let body = request_body(7, "getSlot", &get_slot_params(Commitment::Finalized));
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 7);
    assert_eq!(body["method"], "getSlot");
}

#[test]
fn solana_response_types_accept_the_fixtures_and_missing_fields() {
    let tx = parse(burn_json());
    assert_eq!(tx.slot, BURN_SLOT);
    assert_eq!(tx.transaction.message.account_keys.len(), 32);
    let entry: SignatureEntry = serde_json::from_value(
        json!({ "signature": "S", "slot": 5, "err": null, "memo": null, "x": 1 }),
    )
    .unwrap();
    assert!(entry.err.is_none());
    let entry: SignatureEntry = serde_json::from_value(
        json!({ "signature": "S", "slot": 5, "err": { "InstructionError": [0, "X"] } }),
    )
    .unwrap();
    assert!(entry.err.is_some());
}

// ---- scan loop over a fake node ----

#[derive(Clone, Debug)]
struct SigCall {
    before: Option<String>,
    limit: usize,
    commitment: Commitment,
    min_context_slot: Option<u64>,
}

struct Entry {
    sig: String,
    slot: u64,
    err: bool,
}

#[derive(Default)]
struct Node {
    finalized: u64,
    confirmed: u64,
    entries: Vec<Entry>,
    txs: HashMap<String, TransactionResult>,
    not_final: HashSet<String>,
    block_times: HashMap<u64, i64>,
    sig_calls: Vec<SigCall>,
    tx_calls: Vec<(String, Commitment)>,
    time_calls: Vec<u64>,
    /// Slots for which `getBlockTime` says the block is not available (-32004).
    block_unavailable: HashSet<u64>,
}

#[derive(Clone, Default)]
struct FakeRpc(Arc<Mutex<Node>>);

impl FakeRpc {
    fn node(&self) -> MutexGuard<'_, Node> {
        self.0.lock().unwrap()
    }

    fn set_slots(&self, finalized: u64, confirmed: u64) {
        let mut n = self.node();
        n.finalized = finalized;
        n.confirmed = confirmed;
    }

    /// Lists and serves a transaction under `sig` at `slot`.
    fn add_tx(&self, sig: &str, slot: u64, mut tx: TransactionResult) {
        tx.slot = slot;
        tx.transaction.signatures = vec![sig.to_string()];
        let mut n = self.node();
        n.entries.push(Entry {
            sig: sig.to_string(),
            slot,
            err: false,
        });
        n.txs.insert(sig.to_string(), tx);
    }

    fn add_failed(&self, sig: &str, slot: u64) {
        self.node().entries.push(Entry {
            sig: sig.to_string(),
            slot,
            err: true,
        });
    }

    /// The signature leaves the listing and the node (a dropped fork).
    fn drop_sig(&self, sig: &str) {
        let mut n = self.node();
        n.entries.retain(|e| e.sig != sig);
        n.txs.remove(sig);
    }

    /// The node lists the signature but has no finalized copy yet.
    fn hide_from_finalized(&self, sig: &str) {
        self.node().not_final.insert(sig.to_string());
    }

    fn show_in_finalized(&self, sig: &str) {
        self.node().not_final.remove(sig);
    }

    /// The signature is included again in another slot.
    fn move_tx(&self, sig: &str, slot: u64) {
        let mut n = self.node();
        for e in n.entries.iter_mut().filter(|e| e.sig == sig) {
            e.slot = slot;
        }
        n.txs.get_mut(sig).unwrap().slot = slot;
    }

    fn tx_calls(&self) -> Vec<(String, Commitment)> {
        self.node().tx_calls.clone()
    }

    fn sig_calls(&self) -> Vec<SigCall> {
        self.node().sig_calls.clone()
    }
}

impl SolanaRpcApi for FakeRpc {
    async fn get_slot(&self, commitment: Commitment) -> Result<u64, SourceError> {
        let n = self.node();
        Ok(match commitment {
            Commitment::Finalized => n.finalized,
            Commitment::Confirmed => n.confirmed,
        })
    }

    async fn get_signatures(
        &self,
        _address: &str,
        before: Option<&str>,
        limit: usize,
        commitment: Commitment,
        min_context_slot: Option<u64>,
    ) -> Result<Vec<SignatureEntry>, SourceError> {
        let mut n = self.node();
        n.sig_calls.push(SigCall {
            before: before.map(str::to_string),
            limit,
            commitment,
            min_context_slot,
        });
        if let Some(min) = min_context_slot
            && n.finalized < min
        {
            return Err(SourceError::Lagging("minimum context slot".into()));
        }
        let visible = match commitment {
            Commitment::Finalized => n.finalized,
            Commitment::Confirmed => n.confirmed,
        };
        let mut list: Vec<&Entry> = n.entries.iter().filter(|e| e.slot <= visible).collect();
        list.sort_by_key(|e| std::cmp::Reverse(e.slot));
        let start = before.map_or(0, |b| {
            list.iter().position(|e| e.sig == b).expect("known cursor") + 1
        });
        Ok(list[start..]
            .iter()
            .take(limit)
            .map(|e| SignatureEntry {
                signature: e.sig.clone(),
                slot: e.slot,
                err: e.err.then(|| json!({ "InstructionError": [0, "Custom"] })),
            })
            .collect())
    }

    async fn get_transaction(
        &self,
        signature: &str,
        commitment: Commitment,
    ) -> Result<Option<TransactionResult>, SourceError> {
        let mut n = self.node();
        n.tx_calls.push((signature.to_string(), commitment));
        let Some(tx) = n.txs.get(signature) else {
            return Ok(None);
        };
        let visible = match commitment {
            Commitment::Finalized => n.finalized,
            Commitment::Confirmed => n.confirmed,
        };
        let hidden = commitment == Commitment::Finalized && n.not_final.contains(signature);
        Ok((tx.slot <= visible && !hidden).then(|| tx.clone()))
    }

    async fn get_block_time(&self, slot: u64) -> Result<Option<i64>, SourceError> {
        let mut n = self.node();
        n.time_calls.push(slot);
        if n.block_unavailable.contains(&slot) {
            return Err(SourceError::Lagging("block not available".into()));
        }
        Ok(n.block_times.get(&slot).copied())
    }
}

fn config() -> SolanaConfig {
    SolanaConfig {
        final_margin: 0,
        ..SolanaConfig::default()
    }
}

fn source(rpc: &FakeRpc, cfg: &SolanaConfig) -> SolanaSource<FakeRpc> {
    SolanaSource::with_rpc(rpc.clone(), cfg, counterparty())
}

fn burn_tx() -> TransactionResult {
    parse(burn_json())
}

fn receive_tx() -> TransactionResult {
    parse(receive_json())
}

#[tokio::test]
async fn solana_heights_subtract_the_final_margin() {
    let rpc = FakeRpc::default();
    rpc.set_slots(1000, 1040);
    let cfg = SolanaConfig {
        final_margin: 16,
        ..SolanaConfig::default()
    };
    let h = source(&rpc, &cfg).heights().await.unwrap();
    assert_eq!((h.finalized, h.head), (984, 1040));
}

#[tokio::test]
async fn solana_scan_decodes_events_and_sends_the_guards() {
    let rpc = FakeRpc::default();
    rpc.set_slots(2000, 2000);
    rpc.add_tx("burnA", 1005, burn_tx());
    rpc.add_tx("recvB", 1010, receive_tx());
    rpc.add_failed("failC", 1011);
    let src = source(&rpc, &config());

    let r = src.scan(1000, 1100, Commitment::Finalized).await.unwrap();
    assert_eq!(r.complete_through, 1100);
    let at: Vec<_> = r
        .events
        .iter()
        .map(|e| (e.at.tx_id.as_str(), e.at.height))
        .collect();
    assert_eq!(at, [("burnA", 1005), ("recvB", 1010)]);

    let calls = rpc.sig_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].min_context_slot,
        Some(1100),
        "finalized listing guard"
    );
    assert_eq!(calls[0].commitment, Commitment::Finalized);
    assert_eq!(calls[0].limit, SIGNATURE_PAGE_LIMIT);
    // The failed transaction is never fetched; the others at `finalized`.
    let fetched = rpc.tx_calls();
    assert_eq!(
        fetched,
        [
            ("burnA".to_string(), Commitment::Finalized),
            ("recvB".to_string(), Commitment::Finalized)
        ]
    );

    // A tail scan sends no minContextSlot.
    src.scan(1000, 1100, Commitment::Confirmed).await.unwrap();
    let calls = rpc.sig_calls();
    assert_eq!(calls[1].min_context_slot, None);
    assert_eq!(calls[1].commitment, Commitment::Confirmed);
}

#[tokio::test]
async fn solana_final_scan_lags_when_the_node_is_behind() {
    let rpc = FakeRpc::default();
    rpc.set_slots(1050, 1100);
    rpc.add_tx("burnA", 1005, burn_tx());
    let err = source(&rpc, &config())
        .scan(1000, 1100, Commitment::Finalized)
        .await
        .unwrap_err();
    assert!(matches!(err, SourceError::Lagging(_)), "{err:?}");
    assert!(rpc.tx_calls().is_empty());
}

#[tokio::test]
async fn solana_final_scan_stops_at_unfinalized_tx() {
    let rpc = FakeRpc::default();
    rpc.set_slots(1100, 1100);
    rpc.add_tx("burnA", 1005, burn_tx());
    rpc.add_tx("recvB", 1010, receive_tx());
    rpc.add_tx("recvC", 1010, receive_tx());
    rpc.add_tx("burnD", 1020, burn_tx());
    let src = source(&rpc, &config());

    // `recvC` shares slot 1010 with `recvB` and is not final yet: the whole
    // slot is dropped, even though `recvB` decoded.
    rpc.hide_from_finalized("recvC");
    let r = src.scan(1000, 1100, Commitment::Finalized).await.unwrap();
    assert_eq!(r.complete_through, 1009);
    let ids: Vec<_> = r.events.iter().map(|e| e.at.tx_id.as_str()).collect();
    assert_eq!(ids, ["burnA"]);

    // Not final at the first slot of the range: no progress is possible.
    rpc.hide_from_finalized("burnA");
    let err = src
        .scan(1004, 1100, Commitment::Finalized)
        .await
        .unwrap_err();
    assert!(matches!(err, SourceError::Lagging(_)), "{err:?}");

    // Once everything is final, the scan covers the range.
    rpc.show_in_finalized("burnA");
    rpc.show_in_finalized("recvC");
    let r = src.scan(1000, 1100, Commitment::Finalized).await.unwrap();
    assert_eq!(r.complete_through, 1100);
    assert_eq!(r.events.len(), 4);
}

#[tokio::test]
async fn solana_scan_budget_cuts_at_a_slot_boundary() {
    let rpc = FakeRpc::default();
    rpc.set_slots(1100, 1100);
    rpc.add_tx("a1", 1005, burn_tx());
    rpc.add_tx("a2", 1005, receive_tx());
    rpc.add_tx("b", 1020, burn_tx());
    let cfg = SolanaConfig {
        max_tx_fetch_per_scan: 1,
        ..config()
    };
    let src = source(&rpc, &cfg);
    let r = src.scan(1000, 1100, Commitment::Finalized).await.unwrap();
    assert_eq!(r.complete_through, 1019);
    assert_eq!(r.events.len(), 2, "the first slot is taken whole");
    assert!(r.events.iter().all(|e| e.at.height == 1005));

    let r = src.scan(1019, 1100, Commitment::Finalized).await.unwrap();
    assert_eq!(r.complete_through, 1100);
    assert_eq!(r.events.len(), 1);
}

#[tokio::test]
async fn solana_signature_listing_pages_until_the_cursor() {
    let rpc = FakeRpc::default();
    rpc.set_slots(5000, 5000);
    for slot in 951..=1000u64 {
        rpc.add_failed(&format!("old{slot}"), slot);
    }
    rpc.add_tx("burnA", 1005, burn_tx());
    for slot in 1006..=3305u64 {
        rpc.add_failed(&format!("fail{slot}"), slot);
    }
    let r = source(&rpc, &config())
        .scan(1000, 4000, Commitment::Finalized)
        .await
        .unwrap();
    assert_eq!(r.events.len(), 1);
    assert_eq!(r.events[0].at.tx_id, "burnA");
    assert_eq!(r.complete_through, 4000);
    let calls = rpc.sig_calls();
    assert_eq!(calls.len(), 3, "1000 + 1000 + a short page");
    assert_eq!(calls[0].before, None);
    assert_eq!(calls[1].before.as_deref(), Some("fail2306"));
    assert_eq!(calls[2].before.as_deref(), Some("fail1306"));
}

#[tokio::test]
async fn solana_block_time_falls_back_to_get_block_time() {
    let rpc = FakeRpc::default();
    rpc.set_slots(1100, 1100);
    let mut tx = burn_tx();
    tx.block_time = None;
    rpc.add_tx("burnA", 1005, tx);
    let src = source(&rpc, &config());

    // No time anywhere: the node is not ready.
    let err = src
        .scan(1000, 1100, Commitment::Finalized)
        .await
        .unwrap_err();
    assert!(matches!(err, SourceError::Lagging(_)), "{err:?}");

    rpc.node().block_times.insert(1005, 1_795_000_000);
    let r = src.scan(1000, 1100, Commitment::Finalized).await.unwrap();
    assert_eq!(r.events[0].at.block_time, 1_795_000_000);
}

#[tokio::test]
async fn solana_scan_rejects_a_transaction_in_another_slot() {
    let rpc = FakeRpc::default();
    rpc.set_slots(1100, 1100);
    rpc.add_tx("burnA", 1005, burn_tx());
    // The node serves the transaction from slot 1006 while listing slot 1005.
    rpc.node().txs.get_mut("burnA").unwrap().slot = 1006;
    let err = source(&rpc, &config())
        .scan(1000, 1100, Commitment::Finalized)
        .await
        .unwrap_err();
    assert!(matches!(err, SourceError::Rpc(_)), "{err:?}");
}

#[tokio::test]
async fn solana_inspect_tx_returns_the_finalized_slot_and_burns() {
    let rpc = FakeRpc::default();
    rpc.set_slots(2000, 2000);
    rpc.add_tx(BURN_SIG, 1005, burn_tx());
    let src = source(&rpc, &config());
    let ev = src.inspect_tx(BURN_SIG).await.unwrap().unwrap();
    assert_eq!(ev.height, 1005);
    assert_eq!(ev.burns.len(), 1);
    assert_eq!(ev.burns[0].amount, 21_000_000);
    assert_eq!(ev.burns[0].destination_domain, Domain(6));
    assert_eq!(
        rpc.tx_calls(),
        [(BURN_SIG.to_string(), Commitment::Finalized)]
    );
    // Unknown to the node, and not even a signature.
    assert_eq!(src.inspect_tx(RECEIVE_SIG).await.unwrap(), None);
    let calls = rpc.tx_calls().len();
    assert_eq!(src.inspect_tx("not a signature").await.unwrap(), None);
    assert_eq!(
        rpc.tx_calls().len(),
        calls,
        "no request for a bad signature"
    );
}

#[tokio::test]
async fn solana_inspect_tx_of_a_failed_tx_has_no_burns() {
    let rpc = FakeRpc::default();
    rpc.set_slots(2000, 2000);
    let mut tx = burn_json();
    tx["meta"]["err"] = json!({ "InstructionError": [0, { "Custom": 6001 }] });
    rpc.add_tx(BURN_SIG, 1005, parse(tx));
    let ev = source(&rpc, &config())
        .inspect_tx(BURN_SIG)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((ev.height, ev.burns.len()), (1005, 0));
}

// ---- ingestion with the Solana source (section 15.3) ----

struct Rig {
    _dir: TempDir,
    path: PathBuf,
    rpc: FakeRpc,
    ingestor: Ingestor<SolanaSource<FakeRpc>>,
}

const CURSOR: u64 = 473_327_400;

impl Rig {
    fn new(max_tx_fetch: usize) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("solana.db");
        let mut store = Store::open(&path).unwrap();
        store
            .init_cursor(Domain(5), "solana", CURSOR, 0, NOW)
            .unwrap();
        let rpc = FakeRpc::default();
        rpc.set_slots(CURSOR, CURSOR + 30);
        let cfg = SolanaConfig {
            max_tx_fetch_per_scan: max_tx_fetch,
            ..config()
        };
        let ingestor = Ingestor::new(
            Arc::new(source(&rpc, &cfg)),
            SharedStore::from_store(store),
            IngestConfig {
                poll_interval: Duration::from_millis(10),
                tail_max: 300,
                max_scans_per_tick: 10,
                max_backoff: Duration::from_millis(40),
            },
        );
        Rig {
            _dir: dir,
            path,
            rpc,
            ingestor,
        }
    }

    fn count(&self, sql: &str) -> i64 {
        let c = rusqlite::Connection::open(&self.path).unwrap();
        c.query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

#[tokio::test]
async fn solana_dropped_fork_rolls_back() {
    let rig = Rig::new(40);
    rig.rpc.add_tx(BURN_SIG, BURN_SLOT, burn_tx());
    let r = rig.ingestor.tick(NOW).await.unwrap();
    assert_eq!(r.stats.upserted, 1);
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM burns WHERE finalized = 0 AND source_domain = 5"),
        1
    );

    // The confirmed fork that held the signature is gone.
    rig.rpc.drop_sig(BURN_SIG);
    let r = rig.ingestor.tick(NOW).await.unwrap();
    assert_eq!(r.stats.rolled_back, 1);
    assert_eq!(rig.count("SELECT COUNT(*) FROM burns"), 0);
    assert_eq!(
        rig.count(&format!(
            "SELECT COUNT(*) FROM rollbacks WHERE scope = 'tail' AND height = {BURN_SLOT} AND tx_id = '{BURN_SIG}'"
        )),
        1
    );
}

#[tokio::test]
async fn solana_reinclusion_same_key_updates_slot() {
    let rig = Rig::new(40);
    rig.rpc.add_tx(BURN_SIG, BURN_SLOT, burn_tx());
    rig.ingestor.tick(NOW).await.unwrap();
    let id = rig.count("SELECT id FROM burns");

    rig.rpc.move_tx(BURN_SIG, BURN_SLOT + 3);
    let r = rig.ingestor.tick(NOW).await.unwrap();
    assert_eq!((r.stats.upserted, r.stats.rolled_back), (1, 0));
    assert_eq!(rig.count("SELECT COUNT(*) FROM rollbacks"), 0);
    assert_eq!(rig.count("SELECT COUNT(*) FROM burns"), 1);
    assert_eq!(rig.count("SELECT id FROM burns"), id, "same row");
    assert_eq!(
        rig.count(&format!(
            "SELECT COUNT(*) FROM burns WHERE height = {}",
            BURN_SLOT + 3
        )),
        1
    );
}

#[tokio::test]
async fn solana_tail_cache_serves_tail_scans_only() {
    let rig = Rig::new(40);
    rig.rpc.add_tx(BURN_SIG, BURN_SLOT, burn_tx());
    rig.ingestor.tick(NOW).await.unwrap();
    rig.ingestor.tick(NOW).await.unwrap();
    assert_eq!(
        rig.rpc.tx_calls(),
        [(BURN_SIG.to_string(), Commitment::Confirmed)],
        "the second tail scan does not fetch again"
    );

    // The slot becomes final: the cache must not serve a final row.
    rig.rpc.set_slots(CURSOR + 30, CURSOR + 30);
    let r = rig.ingestor.tick(NOW).await.unwrap();
    assert_eq!(r.stats.promoted, 1);
    assert_eq!(
        rig.rpc.tx_calls().last().unwrap(),
        &(BURN_SIG.to_string(), Commitment::Finalized)
    );
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM burns WHERE finalized = 1"),
        1
    );
}

#[tokio::test]
async fn solana_final_scan_holds_the_cursor_before_an_unfinalized_slot() {
    let rig = Rig::new(40);
    rig.rpc.set_slots(CURSOR + 30, CURSOR + 30);
    rig.rpc.add_tx(BURN_SIG, BURN_SLOT, burn_tx());
    rig.rpc.add_tx(RECEIVE_SIG, BURN_SLOT + 2, receive_tx());
    rig.rpc.hide_from_finalized(RECEIVE_SIG);

    // The first final scan commits up to the slot before the unfinalized one;
    // the second finds nothing final at its first slot and ends the tick.
    let err = rig.ingestor.tick(NOW).await.unwrap_err();
    assert!(matches!(
        err,
        bridge_watcher::ingest::TickError::Source(SourceError::Lagging(_))
    ));
    assert_eq!(
        rig.count("SELECT final_height FROM chain_state"),
        (BURN_SLOT + 1) as i64
    );
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM burns WHERE finalized = 1"),
        1
    );
    assert_eq!(rig.count("SELECT COUNT(*) FROM receives"), 0);

    rig.rpc.show_in_finalized(RECEIVE_SIG);
    let r = rig.ingestor.tick(NOW).await.unwrap();
    assert_eq!(r.final_through, CURSOR + 30);
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM receives WHERE finalized = 1"),
        1
    );
}

#[tokio::test]
async fn solana_scan_rejects_a_transaction_under_another_signature() {
    let rpc = FakeRpc::default();
    rpc.set_slots(1100, 1100);
    rpc.add_tx("sigA", 1005, burn_tx());
    rpc.add_tx("sigB", 1005, burn_tx());
    // The node answers the request for `sigB` with the transaction `sigA`:
    // both would yield the same event key.
    rpc.node()
        .txs
        .get_mut("sigB")
        .unwrap()
        .transaction
        .signatures = vec!["sigA".to_string()];
    let err = source(&rpc, &config())
        .scan(1000, 1100, Commitment::Finalized)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, SourceError::Rpc(m) if m.contains("another signature")),
        "{err:?}"
    );
}

#[tokio::test]
async fn solana_time_at_or_before_skips_skipped_slots() {
    let rpc = FakeRpc::default();
    let src = source(&rpc, &config());

    // Slots 5000 and 4999 were skipped; 4998 has a time.
    rpc.node().block_times.insert(4998, 1_795_000_000);
    assert_eq!(
        src.time_at_or_before(5000).await.unwrap(),
        (4998, 1_795_000_000)
    );
    assert_eq!(rpc.node().time_calls, [5000, 4999, 4998]);

    // A slot with a time answers for itself.
    rpc.node().block_times.insert(5000, 1_795_000_010);
    assert_eq!(
        src.time_at_or_before(5000).await.unwrap(),
        (5000, 1_795_000_010)
    );

    // The 1000th slot (offset 999) is still searched; offset 1000 is not.
    let far = FakeRpc::default();
    far.node().block_times.insert(4001, 42);
    assert_eq!(
        source(&far, &config())
            .time_at_or_before(5000)
            .await
            .unwrap(),
        (4001, 42)
    );
    let none = FakeRpc::default();
    none.node().block_times.insert(4000, 42);
    let err = source(&none, &config())
        .time_at_or_before(5000)
        .await
        .unwrap_err();
    assert!(matches!(err, SourceError::Lagging(_)), "{err:?}");
    assert_eq!(none.node().time_calls.len(), 1000);

    // The search stops at slot 0.
    let low = FakeRpc::default();
    let err = source(&low, &config())
        .time_at_or_before(3)
        .await
        .unwrap_err();
    assert!(matches!(err, SourceError::Lagging(_)));
    assert_eq!(low.node().time_calls, [3, 2, 1, 0]);
}

#[tokio::test]
async fn solana_time_at_or_before_lags_on_block_not_available() {
    let rpc = FakeRpc::default();
    // Slot 5000 was skipped (no time), 4999 is not on the node yet (-32004),
    // and 4998 has a time: the search must not jump over 4999.
    rpc.node().block_unavailable.insert(4999);
    rpc.node().block_times.insert(4998, 1_795_000_000);
    let err = source(&rpc, &config())
        .time_at_or_before(5000)
        .await
        .unwrap_err();
    assert!(matches!(err, SourceError::Lagging(_)), "{err:?}");
    assert_eq!(rpc.node().time_calls, [5000, 4999]);

    // Once the node has the block, the answer is that block's time.
    rpc.node().block_unavailable.clear();
    rpc.node().block_times.insert(4999, 1_795_000_005);
    assert_eq!(
        source(&rpc, &config())
            .time_at_or_before(5000)
            .await
            .unwrap(),
        (4999, 1_795_000_005)
    );
}
