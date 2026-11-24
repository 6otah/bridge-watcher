//! Golden end-to-end tests.
//!
//! Real mainnet fixtures go through the real decoders (`event_from_log`,
//! `events_from_transaction`), the real ingestors and sources, the real
//! resolver and monitor, and a real SQLite file. Only the transports are fake:
//! the two JSON-RPC nodes and Iris.

mod common;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use alloy::primitives::B256;
use alloy::rpc::types::{BlockNumberOrTag, Filter, FilterBlockOption, Log};
use bridge_watcher::config::Config;
use bridge_watcher::domain::{Bytes32, Commitment, Counterparty, Domain, Mode};
use bridge_watcher::evm::{BlockHeader, EvmRpc, EvmSource, TxReceipt};
use bridge_watcher::ingest::{IngestConfig, Ingestor};
use bridge_watcher::iris::{IrisQuery, parse_response};
use bridge_watcher::monitor::Monitor;
use bridge_watcher::resolver::{Resolver, ResolverConfig};
use bridge_watcher::solana::SolanaSource;
use bridge_watcher::solana::rpc::{SignatureEntry, SolanaRpcApi, TransactionResult};
use bridge_watcher::source::{Chains, SourceError};
use bridge_watcher::store::{ChainLimits, SharedStore, TransferFilter, TransferRow, TransferState};
use common::fake_iris::{FakeIris, Reply};
use common::fixtures;
use rusqlite::Connection;
use tempfile::TempDir;

const BASE: Domain = Domain(6);
const SOLANA: Domain = Domain(5);

const BASE_BURN_TX: &str = "0x90d79ce6d16f9d030f45f5ab1767e843e9cefc0d5afae43712b540d1686bab9d";
const SOLANA_RECEIVE_SIG: &str =
    "5SZfhkPdCW1iu1t3cBbbvHt4tpUGR7jKnKbXZUp7fp7Xd56wHeK5fB8XK9geuHQzna9S62nfJ54VGAmrowh6iRVX";
const SOLANA_BURN_SIG: &str =
    "5hZceQXeq8yTugkfTLF9LXa9az3XXxEUbta6fUWhuEPuoogcgeS4dSgqMWDR5pPNq7dLYHtPPFrHtS87VpHdXWB2";
const BASE_RECEIVE_TX: &str = "0x449e3fe9e9504f335a32898084ce359e14b0d0a72e54f470a353f9e65fa4904b";
const NONCE_BASE_BURN: &str = "0xdc9db8e758a6080cd494d37c7df9f4b80f3745b1957223ec728bb6759287833f";
const NONCE_SOLANA_BURN: &str =
    "0x980e3ffa5313ffad7c20f89ae813d278a96a1c825f6feabcc3bd2d8f75ff7406";

// ---- fake nodes ----

#[derive(Default)]
struct BaseNode {
    finalized: u64,
    head: u64,
    logs: Vec<Log>,
    receipts: HashMap<B256, TxReceipt>,
}

#[derive(Clone, Default)]
struct BaseRpc(Arc<Mutex<BaseNode>>);

impl BaseRpc {
    fn node(&self) -> MutexGuard<'_, BaseNode> {
        self.0.lock().unwrap()
    }
}

impl EvmRpc for BaseRpc {
    async fn finalized_block(&self) -> Result<Option<u64>, SourceError> {
        Ok(Some(self.node().finalized))
    }

    async fn block_number(&self) -> Result<u64, SourceError> {
        Ok(self.node().head)
    }

    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>, SourceError> {
        let FilterBlockOption::Range {
            from_block: Some(BlockNumberOrTag::Number(from)),
            to_block: Some(BlockNumberOrTag::Number(to)),
        } = filter.block_option
        else {
            panic!("the source must ask for numeric bounds");
        };
        Ok(self
            .node()
            .logs
            .iter()
            .filter(|l| l.block_number.is_some_and(|n| (from..=to).contains(&n)))
            .cloned()
            .collect())
    }

    async fn block_header(&self, _number: u64) -> Result<Option<BlockHeader>, SourceError> {
        Ok(None)
    }

    async fn tx_receipt(&self, hash: B256) -> Result<Option<TxReceipt>, SourceError> {
        Ok(self.node().receipts.get(&hash).cloned())
    }
}

#[derive(Default)]
struct SolNode {
    finalized: u64,
    confirmed: u64,
    /// Signatures the node lists for the program address.
    listed: Vec<String>,
    /// Transactions the node can serve (listed or not).
    txs: HashMap<String, TransactionResult>,
}

#[derive(Clone, Default)]
struct SolRpc(Arc<Mutex<SolNode>>);

impl SolRpc {
    fn node(&self) -> MutexGuard<'_, SolNode> {
        self.0.lock().unwrap()
    }

    /// The node holds the transaction and lists it.
    fn add_listed(&self, tx: TransactionResult) {
        let sig = tx.transaction.signatures[0].clone();
        let mut n = self.node();
        n.listed.push(sig.clone());
        n.txs.insert(sig, tx);
    }

    /// The node can serve the transaction but its listing does not show it.
    fn add_unlisted(&self, tx: TransactionResult) {
        let sig = tx.transaction.signatures[0].clone();
        self.node().txs.insert(sig, tx);
    }
}

impl SolanaRpcApi for SolRpc {
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
        _before: Option<&str>,
        _limit: usize,
        commitment: Commitment,
        min_context_slot: Option<u64>,
    ) -> Result<Vec<SignatureEntry>, SourceError> {
        let n = self.node();
        if min_context_slot.is_some_and(|min| n.finalized < min) {
            return Err(SourceError::Lagging("minimum context slot".into()));
        }
        let visible = match commitment {
            Commitment::Finalized => n.finalized,
            Commitment::Confirmed => n.confirmed,
        };
        Ok(n.listed
            .iter()
            .map(|sig| (sig, n.txs[sig].slot))
            .filter(|(_, slot)| *slot <= visible)
            .map(|(sig, slot)| SignatureEntry {
                signature: sig.clone(),
                slot,
                err: None,
            })
            .collect())
    }

    async fn get_transaction(
        &self,
        signature: &str,
        commitment: Commitment,
    ) -> Result<Option<TransactionResult>, SourceError> {
        let n = self.node();
        let visible = match commitment {
            Commitment::Finalized => n.finalized,
            Commitment::Confirmed => n.confirmed,
        };
        Ok(n.txs.get(signature).filter(|t| t.slot <= visible).cloned())
    }

    async fn get_block_time(&self, _slot: u64) -> Result<Option<i64>, SourceError> {
        Ok(None)
    }
}

// ---- the world ----

type BaseSource = EvmSource<BaseRpc>;
type SolSource = SolanaSource<SolRpc>;

struct World {
    _dir: TempDir,
    path: PathBuf,
    store: SharedStore,
    base_rpc: BaseRpc,
    sol_rpc: SolRpc,
    iris: FakeIris,
    base: Ingestor<BaseSource>,
    solana: Ingestor<SolSource>,
    resolver: Resolver<FakeIris, Chains<BaseSource, SolSource>>,
    monitor: Monitor,
}

impl World {
    /// Both chains start at the given cursors (the first height of scope is
    /// the cursor + 1). The nodes' heights are set per scenario.
    fn new(base_cursor: u64, solana_cursor: u64) -> World {
        let config = Config::from_toml("").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("golden.db");
        let store = SharedStore::open(&path).unwrap();

        let base_rpc = BaseRpc::default();
        let sol_rpc = SolRpc::default();
        let base = Arc::new(EvmSource::with_rpc(
            base_rpc.clone(),
            &config.evm,
            Counterparty {
                domain: SOLANA,
                token_messenger: config.solana.token_messenger_minter.0,
            },
        ));
        let solana = Arc::new(SolanaSource::with_rpc(
            sol_rpc.clone(),
            &config.solana,
            Counterparty {
                domain: BASE,
                token_messenger: Bytes32::from_evm_address(config.evm.token_messenger.0),
            },
        ));

        let mut raw = bridge_watcher::store::Store::open(&path).unwrap();
        raw.init_cursor(BASE, "base", base_cursor, 0, 0).unwrap();
        raw.init_cursor(SOLANA, "solana", solana_cursor, 0, 0)
            .unwrap();
        drop(raw);

        let ingest_cfg = |tail_max| IngestConfig {
            poll_interval: std::time::Duration::from_secs(10),
            tail_max,
            max_scans_per_tick: 10,
            max_backoff: std::time::Duration::from_secs(300),
        };
        let iris = FakeIris::new();
        let secs = |v: u64| i64::try_from(v).unwrap();
        let limits = vec![
            ChainLimits {
                domain: BASE,
                sla_fast_secs: secs(config.evm.attestation_sla_fast_secs),
                sla_standard_secs: secs(config.evm.attestation_sla_standard_secs),
                finality_lag_alert: config.evm.finality_lag_alert,
            },
            ChainLimits {
                domain: SOLANA,
                sla_fast_secs: secs(config.solana.attestation_sla_fast_secs),
                sla_standard_secs: secs(config.solana.attestation_sla_standard_secs),
                finality_lag_alert: config.solana.finality_lag_alert,
            },
        ];
        World {
            base: Ingestor::new(
                Arc::clone(&base),
                store.clone(),
                ingest_cfg(config.evm.tail_max),
            ),
            solana: Ingestor::new(
                Arc::clone(&solana),
                store.clone(),
                ingest_cfg(config.solana.tail_max),
            ),
            resolver: Resolver::new(
                iris.clone(),
                Chains { a: base, b: solana },
                store.clone(),
                ResolverConfig::from(&config.iris),
            ),
            monitor: Monitor::new(
                store.clone(),
                config.monitor.clone(),
                limits,
                config.alerts.renotify_after_secs,
            ),
            _dir: dir,
            path,
            store,
            base_rpc,
            sol_rpc,
            iris,
        }
    }

    fn set_base_heights(&self, finalized: u64, head: u64) {
        let mut n = self.base_rpc.node();
        n.finalized = finalized;
        n.head = head;
    }

    /// `finalized` is the node's finalized slot; the ingestor sees 16 less.
    fn set_solana_slots(&self, finalized: u64, confirmed: u64) {
        let mut n = self.sol_rpc.node();
        n.finalized = finalized;
        n.confirmed = confirmed;
    }

    fn iris_by_tx(&self, domain: Domain, tx: &str, fixture: &str) {
        let response = parse_response(&fixtures::read(fixture)).unwrap();
        self.iris.set(
            domain,
            IrisQuery::TxId(tx.to_string()),
            Reply::Response(response),
        );
    }

    /// One pass of every task at wall-clock time `now`.
    async fn tick_all(&mut self, now: i64) {
        self.base.tick(now).await.unwrap();
        self.solana.tick(now).await.unwrap();
        self.resolver.tick(now).await.unwrap();
        self.monitor.tick(now).await.unwrap();
    }

    async fn transfers(&self) -> Vec<TransferRow> {
        self.store
            .run(|s| {
                s.list_transfers(&TransferFilter {
                    state: None,
                    limit: 10,
                })
            })
            .await
            .unwrap()
    }

    async fn open_alerts(&self) -> (u64, u64, u64) {
        let a = self
            .store
            .run(|s| s.status_report(0))
            .await
            .unwrap()
            .open_alerts;
        (a.critical, a.warning, a.info)
    }

    fn query_strings(&self, sql: &str) -> Vec<String> {
        let conn = Connection::open(&self.path).unwrap();
        let mut stmt = conn.prepare(sql).unwrap();
        stmt.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
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

fn solana_tx(name: &str) -> TransactionResult {
    serde_json::from_value(fixtures::json(name)).unwrap()
}

/// Base burn (block 61649071) and Solana receive (slot 473335716), both final.
fn base_to_solana() -> World {
    let w = World::new(61_649_000, 473_335_000);
    w.set_base_heights(61_649_100, 61_649_150);
    w.base_rpc.node().logs = vec![fixtures::base_burn_log()];
    w.set_solana_slots(473_335_816, 473_335_830);
    w.sol_rpc
        .add_listed(solana_tx("solana_receive_from_base.tx.json"));
    w.iris_by_tx(BASE, BASE_BURN_TX, "iris_base_burn.json");
    w
}

/// Solana burn (slot 473327426) and Base receive (block 61646396), both final.
fn solana_to_base() -> World {
    let w = World::new(61_646_000, 473_327_000);
    w.set_base_heights(61_646_500, 61_646_520);
    w.base_rpc.node().logs = vec![fixtures::base_receive_log()];
    w.set_solana_slots(473_327_816, 473_327_830);
    w.sol_rpc
        .add_listed(solana_tx("solana_burn_to_base.tx.json"));
    w.iris_by_tx(SOLANA, SOLANA_BURN_SIG, "iris_solana_burn.json");
    w
}

#[tokio::test]
async fn golden_base_to_solana_end_to_end() {
    let mut w = base_to_solana();
    w.tick_all(1_795_521_500).await;

    let rows = w.transfers().await;
    assert_eq!(rows.len(), 1);
    let t = &rows[0];
    assert_eq!(t.state, TransferState::Completed);
    assert_eq!((t.source_domain, t.destination_domain), (BASE, SOLANA));
    assert_eq!(t.nonce, Some(nonce(NONCE_BASE_BURN)));
    assert_eq!(t.burn_tx, BASE_BURN_TX);
    assert_eq!(t.receive_tx.as_deref(), Some(SOLANA_RECEIVE_SIG));
    assert_eq!(t.latency_secs, Some(1249));
    assert_eq!(t.mode, Mode::Standard);
    assert_eq!(t.amount, 5_196_725_157);
    assert!(t.burn_finalized && t.receive_finalized == Some(true));
    assert_eq!(w.open_alerts().await, (0, 0, 0));
    assert_eq!(w.iris.call_count(), 1, "one poll completed the burn");
}

#[tokio::test]
async fn golden_solana_to_base_end_to_end() {
    let mut w = solana_to_base();
    w.tick_all(1_795_519_700).await;

    let rows = w.transfers().await;
    assert_eq!(rows.len(), 1);
    let t = &rows[0];
    assert_eq!(t.state, TransferState::Completed);
    assert_eq!((t.source_domain, t.destination_domain), (SOLANA, BASE));
    assert_eq!(t.nonce, Some(nonce(NONCE_SOLANA_BURN)));
    assert_eq!(t.burn_tx, SOLANA_BURN_SIG);
    assert_eq!(t.receive_tx.as_deref(), Some(BASE_RECEIVE_TX));
    assert_eq!(t.latency_secs, Some(5));
    assert_eq!(t.mode, Mode::Fast);
    assert_eq!(t.amount, 21_000_000);
    // The fee Iris reports for the burn equals the fee the receive paid.
    assert_eq!(t.fee_executed, Some(2100));
    assert_eq!(
        w.query_strings("SELECT CAST(fee_executed AS TEXT) FROM burns"),
        ["2100"]
    );
    assert_eq!(w.open_alerts().await, (0, 0, 0));
}

#[tokio::test]
async fn golden_both_directions_in_one_database() {
    let mut w = World::new(61_646_000, 473_327_000);
    w.set_base_heights(61_649_100, 61_649_150);
    w.base_rpc.node().logs = vec![fixtures::base_burn_log(), fixtures::base_receive_log()];
    w.set_solana_slots(473_335_816, 473_335_830);
    w.sol_rpc
        .add_listed(solana_tx("solana_burn_to_base.tx.json"));
    w.sol_rpc
        .add_listed(solana_tx("solana_receive_from_base.tx.json"));
    w.iris_by_tx(BASE, BASE_BURN_TX, "iris_base_burn.json");
    w.iris_by_tx(SOLANA, SOLANA_BURN_SIG, "iris_solana_burn.json");
    w.tick_all(1_795_521_500).await;

    let rows = w.transfers().await;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|t| t.state == TransferState::Completed));
    let mut latencies: Vec<_> = rows.iter().map(|t| t.latency_secs.unwrap()).collect();
    latencies.sort_unstable();
    assert_eq!(latencies, [5, 1249]);
    assert_eq!(w.open_alerts().await, (0, 0, 0));

    // A second pass changes nothing: replay is idempotent.
    w.tick_all(1_795_521_510).await;
    assert_eq!(w.transfers().await, rows);
}

/// The Solana receive of the Base burn with the minted amount changed by one
/// base unit inside the `MessageReceived` event.
fn tampered_receive_tx() -> TransactionResult {
    let mut json = fixtures::json("solana_receive_from_base.tx.json");
    let event = &mut json["meta"]["innerInstructions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .flat_map(|g| g["instructions"].as_array_mut().unwrap().iter_mut())
        .nth(4)
        .unwrap()["data"];
    let mut data = bs58::decode(event.as_str().unwrap()).into_vec().unwrap();
    let (_, payload) = bridge_watcher::codec::split_event_ix(&data).unwrap();
    let body = bridge_watcher::codec::MessageReceivedEvent::decode(payload)
        .unwrap()
        .message_body;
    let at = data
        .windows(body.len())
        .position(|w| w == body.as_slice())
        .unwrap();
    // The amount is a big-endian u256 at body offset 68.
    data[at + 68 + 31] += 1;
    *event = serde_json::json!(bs58::encode(&data).into_string());
    serde_json::from_value(json).unwrap()
}

#[tokio::test]
async fn golden_field_tamper_raises_critical() {
    let mut w = base_to_solana();
    {
        let mut n = w.sol_rpc.node();
        n.txs
            .insert(SOLANA_RECEIVE_SIG.to_string(), tampered_receive_tx());
    }
    w.tick_all(1_795_521_500).await;

    let rows = w.transfers().await;
    assert_eq!(rows[0].state, TransferState::Completed);
    assert_eq!(rows[0].amount, 5_196_725_157, "the burn is unchanged");
    assert_eq!(w.open_alerts().await, (1, 0, 0));
    assert_eq!(
        w.query_strings("SELECT kind FROM alerts WHERE resolved_at IS NULL"),
        ["field_mismatch"]
    );
}

/// F-B end to end: Iris attests a message whose amount differs from the real
/// burn, and that amount is minted. The burn never gets a nonce; the minted
/// receive is an orphan, and the real burn tx on Base has no equal burn.
#[tokio::test]
async fn golden_iris_tamper_raises_iris_mismatch() {
    let mut w = base_to_solana();
    {
        let mut n = w.sol_rpc.node();
        n.txs
            .insert(SOLANA_RECEIVE_SIG.to_string(), tampered_receive_tx());
    }
    // The fake Base node serves the real burn receipt.
    w.base_rpc.node().receipts.insert(
        BASE_BURN_TX.parse().unwrap(),
        TxReceipt {
            block_number: 61_649_071,
            logs: vec![fixtures::base_burn_log()],
        },
    );
    // Iris answers with the amount changed by one base unit.
    let mut tampered = parse_response(&fixtures::read("iris_base_burn.json")).unwrap();
    let bytes = tampered.messages[0].message.as_mut().unwrap();
    bytes[148 + 68 + 31] += 1;
    w.iris.set(
        BASE,
        IrisQuery::TxId(BASE_BURN_TX.to_string()),
        Reply::Response(tampered.clone()),
    );
    w.iris.set(
        BASE,
        IrisQuery::Nonce(nonce(NONCE_BASE_BURN)),
        Reply::Response(tampered),
    );

    // More than the orphan grace after the receive.
    w.tick_all(1_795_521_438 + 1000).await;

    let rows = w.transfers().await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].state,
        TransferState::Burned,
        "the burn never matched"
    );
    assert_eq!(rows[0].nonce, None);
    assert_eq!(
        w.query_strings("SELECT source_lookup FROM receives"),
        ["iris_mismatch"]
    );
    assert_eq!(
        w.query_strings("SELECT kind FROM alerts WHERE resolved_at IS NULL"),
        ["iris_mismatch"]
    );
    assert_eq!(w.open_alerts().await, (1, 0, 0));
}

/// A Base receive of a Solana burn from before our first slot: Iris knows the
/// burn by nonce (`sourceTxHash`), the source chain read finds it below `start_height`,
/// so the receive is `pre_start` and nothing alerts.
#[tokio::test]
async fn golden_orphan_receive_before_start_is_pre_start() {
    let mut w = World::new(61_646_000, 473_327_500);
    w.set_base_heights(61_646_500, 61_646_520);
    w.base_rpc.node().logs = vec![fixtures::base_receive_log()];
    w.set_solana_slots(473_327_816, 473_327_830);
    w.sol_rpc
        .add_unlisted(solana_tx("solana_burn_to_base.tx.json"));
    let by_nonce = parse_response(&fixtures::read("iris_solana_by_nonce.json")).unwrap();
    assert_eq!(by_nonce.source_tx.as_deref(), Some(SOLANA_BURN_SIG));
    w.iris.set(
        SOLANA,
        IrisQuery::Nonce(nonce(NONCE_SOLANA_BURN)),
        Reply::Response(by_nonce),
    );

    // More than the orphan grace after the receive.
    w.tick_all(1_795_519_654 + 1000).await;

    assert!(w.transfers().await.is_empty());
    assert_eq!(
        w.query_strings("SELECT source_lookup FROM receives"),
        ["pre_start"]
    );
    assert_eq!(
        w.iris.calls(),
        [(SOLANA, IrisQuery::Nonce(nonce(NONCE_SOLANA_BURN)))]
    );
    assert_eq!(w.open_alerts().await, (0, 0, 0));
}

/// The same receive, but the burn lies inside the range we scanned and the
/// listing missed it: `missed`, which raises `ingestion_gap`.
#[tokio::test]
async fn golden_orphan_receive_in_scanned_range_is_a_gap() {
    let mut w = World::new(61_646_000, 473_327_000);
    w.set_base_heights(61_646_500, 61_646_520);
    w.base_rpc.node().logs = vec![fixtures::base_receive_log()];
    w.set_solana_slots(473_327_816, 473_327_830);
    w.sol_rpc
        .add_unlisted(solana_tx("solana_burn_to_base.tx.json"));
    w.iris.set(
        SOLANA,
        IrisQuery::Nonce(nonce(NONCE_SOLANA_BURN)),
        Reply::Response(parse_response(&fixtures::read("iris_solana_by_nonce.json")).unwrap()),
    );

    w.tick_all(1_795_519_654 + 1000).await;

    assert!(w.transfers().await.is_empty());
    assert_eq!(
        w.query_strings("SELECT source_lookup FROM receives"),
        ["missed"]
    );
    assert_eq!(
        w.query_strings("SELECT kind FROM alerts WHERE resolved_at IS NULL"),
        ["ingestion_gap"]
    );
    assert_eq!(w.open_alerts().await, (0, 1, 0));
}

#[test]
fn iris_parse_by_nonce_fixture() {
    let r = parse_response(&fixtures::read("iris_solana_by_nonce.json")).unwrap();
    // A nonce query also returns the burn transaction.
    assert_eq!(r.source_tx.as_deref(), Some(SOLANA_BURN_SIG));
    assert_eq!(r.messages.len(), 1);
    let m = &r.messages[0];
    assert_eq!(m.status, "complete");
    assert!(m.attestation_ready);
    assert_eq!(m.cctp_version, Some(2));
    assert_eq!(m.destination_tx.as_deref(), Some(BASE_RECEIVE_TX));
    let (burn, iris) =
        bridge_watcher::codec::decode_burn_message(m.message.as_ref().unwrap()).unwrap();
    assert_eq!(iris.nonce, nonce(NONCE_SOLANA_BURN));
    assert_eq!(burn.source_domain, SOLANA);
}
