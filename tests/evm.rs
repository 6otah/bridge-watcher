//! EVM source tests (`docs/ARCHITECTURE.md` section 15.1): `event_from_log` on
//! the real Base logs, and `EvmSource::scan` over a fake node.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use alloy::primitives::{Address, B256, Bytes};
use alloy::rpc::types::{BlockNumberOrTag, Filter, FilterBlockOption, Log};
use alloy::sol_types::SolEvent;
use bridge_watcher::codec::decode_burn_message;
use bridge_watcher::config::EvmConfig;
use bridge_watcher::domain::{Bytes32, Commitment, Counterparty, Domain, EventKind};
use bridge_watcher::evm::{
    BlockHeader, EvmIds, EvmRpc, EvmSource, TxReceipt, event_from_log, log_filter,
};
use bridge_watcher::source::{ChainSource, SourceError};
use common::fixtures::{self, MessageReceived, MessageSent};

const BURN_TX: &str = "0x90d79ce6d16f9d030f45f5ab1767e843e9cefc0d5afae43712b540d1686bab9d";
const RECEIVE_TX: &str = "0x449e3fe9e9504f335a32898084ce359e14b0d0a72e54f470a353f9e65fa4904b";
const BURN_BLOCK: u64 = 61_649_071;
const RECEIVE_BLOCK: u64 = 61_646_396;
const MINTER: &str = "CCTPV2vPZJS2u2BBsUoscuikbYjnpFmbFsvVuJdgUMQe";

fn cfg() -> EvmConfig {
    EvmConfig::default()
}

fn ids() -> EvmIds {
    let c = cfg();
    EvmIds {
        domain: Domain(c.domain),
        message_transmitter: c.message_transmitter.0,
        token_messenger: c.token_messenger.0,
    }
}

/// The Solana side of the pair: domain 5, TokenMessengerMinterV2.
fn counterparty() -> Counterparty {
    Counterparty {
        domain: Domain(5),
        token_messenger: Bytes32::from_base58(MINTER).unwrap(),
    }
}

fn evm_addr(hex_str: &str) -> Bytes32 {
    Bytes32::from_evm_address(hex::decode(hex_str).unwrap().try_into().unwrap())
}

fn decode(log: &Log) -> Result<Option<bridge_watcher::domain::ChainEvent>, SourceError> {
    event_from_log(log, &ids(), counterparty())
}

/// The burn log with its `MessageSent` message replaced.
fn burn_log_with(edit: impl FnOnce(&mut Vec<u8>)) -> Log {
    let mut log = fixtures::base_burn_log();
    let mut message = fixtures::message_sent_bytes(&log);
    edit(&mut message);
    let event = MessageSent {
        message: Bytes::from(message),
    };
    log.inner.data = event.encode_log_data();
    log
}

/// The receive log with its event fields edited.
fn receive_log_with(edit: impl FnOnce(&mut MessageReceived)) -> Log {
    let mut log = fixtures::base_receive_log();
    let mut event = fixtures::message_received(&log);
    edit(&mut event);
    log.inner.data = event.encode_log_data();
    log
}

#[test]
fn evm_event_from_log_burn_fixture() {
    let ev = decode(&fixtures::base_burn_log()).unwrap().unwrap();
    assert_eq!(ev.at.domain, Domain(6));
    assert_eq!(ev.at.tx_id, BURN_TX);
    assert_eq!(ev.at.event_index, 159);
    assert_eq!(ev.at.height, BURN_BLOCK);
    assert_eq!(ev.at.block_time, 1_795_520_189);
    assert_eq!(
        ev.at.block_hash.as_deref(),
        Some("0x7523765becd92e8cce43d2d3c378dddb29f190b00e81b75764b4c90724dd9775")
    );
    let EventKind::Burn(burn) = ev.kind else {
        panic!("expected a burn");
    };
    assert_eq!(burn.source_domain, Domain(6));
    assert_eq!(burn.destination_domain, Domain(5));
    assert_eq!(
        burn.sender,
        evm_addr("28b5a0e9c621a5badaa536219b3a228c8168cf5d")
    );
    assert_eq!(burn.amount, 5_196_725_157);
    assert_eq!(burn.min_finality_threshold, 2000);
    assert_eq!(
        burn.depositor,
        evm_addr("44b86c72cb96d9ff04e7b0b23124316bb884e35e")
    );
    // The same burn, as Circle's attestation service describes it.
    let (iris_burn, _) =
        decode_burn_message(&fixtures::iris_message("iris_base_burn.json")).unwrap();
    assert_eq!(burn, iris_burn);
}

#[test]
fn evm_event_from_log_receive_fixture() {
    let ev = decode(&fixtures::base_receive_log()).unwrap().unwrap();
    assert_eq!(ev.at.domain, Domain(6));
    assert_eq!(ev.at.tx_id, RECEIVE_TX);
    assert_eq!(ev.at.event_index, 6);
    assert_eq!(ev.at.height, RECEIVE_BLOCK);
    assert_eq!(ev.at.block_time, 1_795_519_654);
    let EventKind::Receive(rx) = ev.kind else {
        panic!("expected a receive");
    };
    assert_eq!(rx.source_domain, Domain(5));
    assert_eq!(
        rx.nonce,
        Bytes32(
            hex::decode("980e3ffa5313ffad7c20f89ae813d278a96a1c825f6feabcc3bd2d8f75ff7406")
                .unwrap()
                .try_into()
                .unwrap()
        )
    );
    assert_eq!(rx.finality_threshold_executed, 1000);
    assert_eq!(rx.sender, counterparty().token_messenger);
    assert_eq!(
        rx.caller,
        evm_addr("d5f73368ed244693d4116f1220e3959c2e5c6826")
    );
    assert_eq!(rx.body.amount, 21_000_000);
    assert_eq!(rx.body.fee_executed, 2100);
}

#[test]
fn evm_ignores_other_domains_and_senders() {
    let header = |m: &mut Vec<u8>| m[..4].copy_from_slice(&[0, 0, 0, 1]);
    assert!(decode(&burn_log_with(header)).unwrap().is_some());

    // Destination domain 7, source domain 7, and another message sender.
    for edit in [
        (|m: &mut Vec<u8>| m[8..12].copy_from_slice(&7u32.to_be_bytes())) as fn(&mut Vec<u8>),
        |m| m[4..8].copy_from_slice(&7u32.to_be_bytes()),
        |m| m[44..76].fill(0x11),
    ] {
        assert!(decode(&burn_log_with(edit)).unwrap().is_none());
    }

    // Receives: another source domain, another sender.
    assert!(
        decode(&receive_log_with(|e| e.sourceDomain = 7))
            .unwrap()
            .is_none()
    );
    assert!(
        decode(&receive_log_with(|e| e.sender = [0x22; 32].into()))
            .unwrap()
            .is_none()
    );
}

#[test]
fn evm_ignores_other_emitters_topics_and_removed_logs() {
    let mut log = fixtures::base_burn_log();
    log.removed = true;
    assert!(decode(&log).unwrap().is_none());

    let mut log = fixtures::base_burn_log();
    log.inner.address = Address::repeat_byte(0x42);
    assert!(decode(&log).unwrap().is_none());

    // Same emitter, unrelated event.
    let mut log = fixtures::base_burn_log();
    log.inner.data = alloy::primitives::LogData::new_unchecked(
        vec![B256::repeat_byte(0x33)],
        Bytes::from_static(&[1, 2, 3]),
    );
    assert!(decode(&log).unwrap().is_none());
}

#[test]
fn evm_undecodable_events_are_errors() {
    // A message from our token messenger to our counterparty whose body is cut.
    let log = burn_log_with(|m| m.truncate(160));
    let err = decode(&log).unwrap_err();
    assert!(
        matches!(&err, SourceError::Undecodable { tx_id, .. } if tx_id == BURN_TX),
        "{err:?}"
    );
    // A message too short for a header.
    let err = decode(&burn_log_with(|m| m.truncate(100))).unwrap_err();
    assert!(matches!(err, SourceError::Undecodable { .. }), "{err:?}");
    // A receive of the counterparty with a short body.
    let err = decode(&receive_log_with(|e| {
        e.messageBody = Bytes::from_static(&[1; 50])
    }))
    .unwrap_err();
    assert!(
        matches!(&err, SourceError::Undecodable { tx_id, .. } if tx_id == RECEIVE_TX),
        "{err:?}"
    );
    // An event whose data is not ABI-valid.
    let mut log = fixtures::base_burn_log();
    log.inner.data = alloy::primitives::LogData::new_unchecked(
        log.inner.data.topics().to_vec(),
        Bytes::from_static(&[1, 2, 3]),
    );
    assert!(matches!(
        decode(&log).unwrap_err(),
        SourceError::Undecodable { .. }
    ));
}

#[test]
fn evm_relevant_log_without_position_or_time_is_an_rpc_error() {
    let mut log = fixtures::base_burn_log();
    log.block_timestamp = None;
    assert!(matches!(decode(&log).unwrap_err(), SourceError::Rpc(_)));
    let mut log = fixtures::base_burn_log();
    log.log_index = None;
    assert!(matches!(decode(&log).unwrap_err(), SourceError::Rpc(_)));
    // An irrelevant log needs no position.
    let mut log = fixtures::base_burn_log();
    log.log_index = None;
    log.removed = true;
    assert!(decode(&log).unwrap().is_none());
}

#[test]
fn evm_log_filter_uses_numeric_bounds_and_both_topics() {
    let f = log_filter(&ids(), 101, 200);
    assert_eq!(
        f.block_option,
        FilterBlockOption::Range {
            from_block: Some(BlockNumberOrTag::Number(101)),
            to_block: Some(BlockNumberOrTag::Number(200)),
        }
    );
    assert!(
        f.address
            .contains(&Address::from(ids().message_transmitter))
    );
    assert_eq!(f.address.len(), 1);
    assert!(f.topics[0].contains(&MessageSent::SIGNATURE_HASH));
    assert!(f.topics[0].contains(&MessageReceived::SIGNATURE_HASH));
    assert_eq!(f.topics[0].len(), 2);
}

// ---- scan over a fake node ----

#[derive(Default)]
struct Node {
    finalized: Option<u64>,
    head: u64,
    logs: Vec<Log>,
    filters: Vec<Filter>,
    headers: HashMap<u64, BlockHeader>,
    header_calls: Vec<u64>,
    receipts: HashMap<B256, TxReceipt>,
    receipt_calls: usize,
}

#[derive(Clone, Default)]
struct FakeRpc(Arc<Mutex<Node>>);

impl FakeRpc {
    fn node(&self) -> MutexGuard<'_, Node> {
        self.0.lock().unwrap()
    }
}

impl EvmRpc for FakeRpc {
    async fn finalized_block(&self) -> Result<Option<u64>, SourceError> {
        Ok(self.node().finalized)
    }

    async fn block_number(&self) -> Result<u64, SourceError> {
        Ok(self.node().head)
    }

    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>, SourceError> {
        let mut n = self.node();
        n.filters.push(filter.clone());
        Ok(n.logs.clone())
    }

    async fn block_header(&self, number: u64) -> Result<Option<BlockHeader>, SourceError> {
        let mut n = self.node();
        n.header_calls.push(number);
        Ok(n.headers.get(&number).copied())
    }

    async fn tx_receipt(&self, hash: B256) -> Result<Option<TxReceipt>, SourceError> {
        let mut n = self.node();
        n.receipt_calls += 1;
        Ok(n.receipts.get(&hash).cloned())
    }
}

fn source(rpc: &FakeRpc, cfg: &EvmConfig) -> EvmSource<FakeRpc> {
    EvmSource::with_rpc(rpc.clone(), cfg, counterparty())
}

fn scan_args() -> (u64, u64) {
    (61_640_000, 61_650_000)
}

async fn scan(src: &EvmSource<FakeRpc>) -> Result<bridge_watcher::source::ScanResult, SourceError> {
    let (after, up_to) = scan_args();
    src.scan(after, up_to, Commitment::Finalized).await
}

#[tokio::test]
async fn evm_heights_read_finalized_and_head() {
    let rpc = FakeRpc::default();
    {
        let mut n = rpc.node();
        n.finalized = Some(900);
        n.head = 1000;
    }
    let h = source(&rpc, &cfg()).heights().await.unwrap();
    assert_eq!((h.finalized, h.head), (900, 1000));

    rpc.node().finalized = None;
    let err = source(&rpc, &cfg()).heights().await.unwrap_err();
    assert!(matches!(err, SourceError::Rpc(_)), "{err:?}");
}

#[tokio::test]
async fn evm_scan_returns_relevant_events_in_order() {
    let rpc = FakeRpc::default();
    let mut foreign = fixtures::base_burn_log();
    foreign.inner.address = Address::repeat_byte(7);
    rpc.node().logs = vec![
        fixtures::base_burn_log(),
        foreign,
        fixtures::base_receive_log(),
    ];
    let r = scan(&source(&rpc, &cfg())).await.unwrap();
    assert_eq!(r.complete_through, 61_650_000);
    let got: Vec<_> = r
        .events
        .iter()
        .map(|e| (e.at.height, e.at.event_index))
        .collect();
    assert_eq!(got, [(RECEIVE_BLOCK, 6), (BURN_BLOCK, 159)]);

    let n = rpc.node();
    assert_eq!(n.filters.len(), 1);
    assert_eq!(
        n.filters[0].block_option,
        FilterBlockOption::Range {
            from_block: Some(BlockNumberOrTag::Number(61_640_001)),
            to_block: Some(BlockNumberOrTag::Number(61_650_000)),
        }
    );
    assert!(n.header_calls.is_empty(), "logs carry blockTimestamp");
}

#[tokio::test]
async fn evm_scan_caps_the_range_at_max_log_range() {
    let rpc = FakeRpc::default();
    let cfg = EvmConfig {
        max_log_range: 1000,
        ..cfg()
    };
    let src = source(&rpc, &cfg);
    let r = src
        .scan(5000, 100_000, Commitment::Confirmed)
        .await
        .unwrap();
    assert_eq!(r.complete_through, 6000);
    assert!(r.events.is_empty());
    let n = rpc.node();
    assert_eq!(
        n.filters[0].block_option,
        FilterBlockOption::Range {
            from_block: Some(BlockNumberOrTag::Number(5001)),
            to_block: Some(BlockNumberOrTag::Number(6000)),
        }
    );
}

#[tokio::test]
async fn evm_scan_rejects_answers_that_break_the_range() {
    let rpc = FakeRpc::default();
    let src = source(&rpc, &cfg());

    // A log below and above the requested range.
    for block in [61_640_000, 61_650_001] {
        let mut log = fixtures::base_burn_log();
        log.block_number = Some(block);
        rpc.node().logs = vec![log];
        let err = scan(&src).await.unwrap_err();
        assert!(
            matches!(&err, SourceError::Rpc(m) if m.contains("outside")),
            "{err:?}"
        );
    }
    // A log without a block number.
    let mut log = fixtures::base_burn_log();
    log.block_number = None;
    rpc.node().logs = vec![log];
    assert!(matches!(scan(&src).await.unwrap_err(), SourceError::Rpc(_)));
    // The same event twice would be a scope violation in the store.
    rpc.node().logs = vec![fixtures::base_burn_log(), fixtures::base_burn_log()];
    let err = scan(&src).await.unwrap_err();
    assert!(
        matches!(&err, SourceError::Rpc(m) if m.contains("duplicate")),
        "{err:?}"
    );
    // An empty range is a caller bug.
    let err = src.scan(10, 10, Commitment::Finalized).await.unwrap_err();
    assert!(matches!(err, SourceError::Rpc(_)));
}

#[tokio::test]
async fn evm_scan_stops_on_an_undecodable_event() {
    let rpc = FakeRpc::default();
    rpc.node().logs = vec![burn_log_with(|m| m.truncate(160))];
    let err = scan(&source(&rpc, &cfg())).await.unwrap_err();
    assert!(matches!(err, SourceError::Undecodable { .. }), "{err:?}");
}

#[tokio::test]
async fn evm_block_time_comes_from_the_header_and_is_cached() {
    let rpc = FakeRpc::default();
    let hash: B256 = "0x7523765becd92e8cce43d2d3c378dddb29f190b00e81b75764b4c90724dd9775"
        .parse()
        .unwrap();
    let mut a = fixtures::base_burn_log();
    a.block_timestamp = None;
    let mut b = a.clone();
    b.log_index = Some(160);
    rpc.node().logs = vec![a, b];
    rpc.node().headers.insert(
        BURN_BLOCK,
        BlockHeader {
            hash,
            timestamp: 1_795_520_000,
        },
    );
    let src = source(&rpc, &cfg());

    let r = scan(&src).await.unwrap();
    assert_eq!(r.events.len(), 2);
    assert!(r.events.iter().all(|e| e.at.block_time == 1_795_520_000));
    assert_eq!(rpc.node().header_calls, [BURN_BLOCK], "one call per block");

    // A later scan of the same block hash uses the cache.
    scan(&src).await.unwrap();
    assert_eq!(rpc.node().header_calls.len(), 1);

    // A block that the node no longer has, or has with another hash.
    let fresh = source(&rpc, &cfg());
    rpc.node().headers.insert(
        BURN_BLOCK,
        BlockHeader {
            hash: B256::repeat_byte(1),
            timestamp: 5,
        },
    );
    let err = scan(&fresh).await.unwrap_err();
    assert!(
        matches!(&err, SourceError::Rpc(m) if m.contains("changed")),
        "{err:?}"
    );
    rpc.node().headers.clear();
    let err = scan(&fresh).await.unwrap_err();
    assert!(
        matches!(&err, SourceError::Rpc(m) if m.contains("not found")),
        "{err:?}"
    );
}

#[tokio::test]
async fn evm_inspect_tx_decodes_burns_from_the_receipt() {
    let rpc = FakeRpc::default();
    let hash: B256 = BURN_TX.parse().unwrap();
    let burn_log = fixtures::base_burn_log();
    let expected = decode_burn_message(&fixtures::message_sent_bytes(&burn_log))
        .unwrap()
        .0;
    // Other logs of the receipt (a receive of the pair, a foreign emitter)
    // are not burns.
    let mut foreign = fixtures::base_burn_log();
    foreign.inner.address = Address::repeat_byte(0x11);
    rpc.node().receipts.insert(
        hash,
        TxReceipt {
            block_number: BURN_BLOCK,
            logs: vec![fixtures::base_receive_log(), foreign, burn_log],
        },
    );
    let src = source(&rpc, &cfg());
    let ev = src.inspect_tx(BURN_TX).await.unwrap().unwrap();
    assert_eq!(ev.height, BURN_BLOCK);
    assert_eq!(ev.burns, vec![expected]);
}

#[tokio::test]
async fn evm_inspect_tx_without_burns_and_unknown_tx() {
    let rpc = FakeRpc::default();
    let hash: B256 = BURN_TX.parse().unwrap();
    // A reverted transaction has a receipt and no logs.
    rpc.node().receipts.insert(
        hash,
        TxReceipt {
            block_number: BURN_BLOCK,
            logs: vec![],
        },
    );
    let src = source(&rpc, &cfg());
    let ev = src.inspect_tx(BURN_TX).await.unwrap().unwrap();
    assert_eq!((ev.height, ev.burns.len()), (BURN_BLOCK, 0));
    assert_eq!(src.inspect_tx(RECEIVE_TX).await.unwrap(), None);
    let calls = rpc.node().receipt_calls;
    assert_eq!(src.inspect_tx("0x1234").await.unwrap(), None);
    assert_eq!(
        rpc.node().receipt_calls,
        calls,
        "a text that is not a hash needs no request"
    );
}

#[tokio::test]
async fn evm_inspect_tx_undecodable_burn_is_an_error() {
    let rpc = FakeRpc::default();
    let hash: B256 = BURN_TX.parse().unwrap();
    let broken = burn_log_with(|m| m.truncate(200));
    rpc.node().receipts.insert(
        hash,
        TxReceipt {
            block_number: BURN_BLOCK,
            logs: vec![broken],
        },
    );
    let err = source(&rpc, &cfg()).inspect_tx(BURN_TX).await.unwrap_err();
    assert!(matches!(err, SourceError::Undecodable { .. }), "{err:?}");
}

#[test]
fn evm_source_names_its_chain() {
    let src = source(&FakeRpc::default(), &cfg());
    assert_eq!(src.domain(), Domain(6));
    assert_eq!(src.name(), "base");
}

#[tokio::test]
async fn evm_time_at_or_before_reads_the_header() {
    let rpc = FakeRpc::default();
    rpc.node().headers.insert(
        777,
        BlockHeader {
            hash: B256::repeat_byte(3),
            timestamp: 1_795_000_777,
        },
    );
    let src = source(&rpc, &cfg());
    assert_eq!(
        src.time_at_or_before(777).await.unwrap(),
        (777, 1_795_000_777)
    );
    let err = src.time_at_or_before(778).await.unwrap_err();
    assert!(matches!(err, SourceError::Rpc(_)), "{err:?}");
}
