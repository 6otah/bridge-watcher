//! Ingestion, reorg and restart tests
//! with the scripted `FakeChain` and a real SQLite file.

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bridge_watcher::domain::{Commitment, Domain};
use bridge_watcher::evm::EvmSource;
use bridge_watcher::ingest::{IngestConfig, Ingestor, TickError, TickReport, init_cursor};
use bridge_watcher::solana::SolanaSource;
use bridge_watcher::source::{ChainSource, SourceError};
use bridge_watcher::store::{SharedStore, StoreError};
use common::fake_chain::{FakeChain, ScanCall};
use common::{burn_event, receive_event};
use rusqlite::Connection;
use rusqlite::types::ValueRef;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

const BASE: Domain = Domain(6);
const NOW: i64 = 1_800_000_000;

fn cfg(max_scans_per_tick: u32, tail_max: u64) -> IngestConfig {
    IngestConfig {
        poll_interval: Duration::from_millis(10),
        tail_max,
        max_scans_per_tick,
        max_backoff: Duration::from_millis(40),
    }
}

/// A database file with a Base cursor and a fake chain.
struct Rig {
    _dir: TempDir,
    path: PathBuf,
    store: SharedStore,
    chain: FakeChain,
}

impl Rig {
    fn new(cursor: u64) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ingest.db");
        let mut store = bridge_watcher::store::Store::open(&path).unwrap();
        store.init_cursor(BASE, "base", cursor, 0, NOW).unwrap();
        Rig {
            _dir: dir,
            path,
            store: SharedStore::from_store(store),
            chain: FakeChain::new(6, "base"),
        }
    }

    fn ingestor(&self, cfg: IngestConfig) -> Ingestor<FakeChain> {
        Ingestor::new(Arc::new(self.chain.clone()), self.store.clone(), cfg)
    }

    /// Closes the store and opens the same file again, as a restart does.
    fn restart(&mut self) {
        self.store = SharedStore::open(&self.path).unwrap();
    }

    fn raw(&self) -> Connection {
        let c = Connection::open(&self.path).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c
    }

    fn count(&self, sql: &str) -> i64 {
        self.raw().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn cursor(&self) -> u64 {
        self.count("SELECT final_height FROM chain_state WHERE domain = 6") as u64
    }

    fn event_tables(&self) -> Vec<Vec<String>> {
        let conn = self.raw();
        ["burns", "receives", "rollbacks"]
            .iter()
            .flat_map(|t| dump(&conn, t))
            .collect()
    }

    fn state(&self) -> Vec<Vec<String>> {
        let conn = self.raw();
        ["chain_state", "burns", "receives", "rollbacks"]
            .iter()
            .flat_map(|t| {
                let mut rows = dump(&conn, t);
                rows.insert(0, vec![format!("table {t}")]);
                rows
            })
            .collect()
    }
}

fn dump(conn: &Connection, table: &str) -> Vec<Vec<String>> {
    let mut stmt = conn
        .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
        .unwrap();
    let n = stmt.column_count();
    stmt.query_map([], |r| {
        (0..n)
            .map(|i| {
                Ok(match r.get_ref(i)? {
                    ValueRef::Null => "NULL".to_string(),
                    ValueRef::Integer(v) => v.to_string(),
                    ValueRef::Real(v) => v.to_string(),
                    ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                    ValueRef::Blob(b) => hex::encode(b),
                })
            })
            .collect()
    })
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

async fn tick(ing: &Ingestor<FakeChain>) -> TickReport {
    ing.tick(NOW).await.unwrap()
}

#[tokio::test]
async fn evm_reorg_rolls_back_unfinalized_burn() {
    let rig = Rig::new(100);
    rig.chain.set_heights(100, 110);
    rig.chain.push(burn_event(6, "0xa", 0, 105, 7));
    let ing = rig.ingestor(cfg(10, 1000));

    let r1 = tick(&ing).await;
    assert!(r1.caught_up);
    assert_eq!(r1.stats.upserted, 1);
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM burns WHERE finalized = 0 AND height = 105"),
        1
    );

    rig.chain.drop_height(105);
    let r2 = tick(&ing).await;
    assert_eq!(r2.stats.rolled_back, 1);
    assert_eq!(rig.count("SELECT COUNT(*) FROM burns"), 0);
    assert_eq!(
        rig.count(
            "SELECT COUNT(*) FROM rollbacks WHERE tx_id = '0xa' AND scope = 'tail' AND height = 105"
        ),
        1
    );
    assert_eq!(rig.count("SELECT COUNT(*) FROM rollbacks"), 1);
}

#[tokio::test]
async fn reorg_reinclusion_moves_event() {
    let rig = Rig::new(100);
    rig.chain.set_heights(100, 110);
    rig.chain.push(burn_event(6, "0xa", 3, 105, 7));
    let ing = rig.ingestor(cfg(10, 1000));
    tick(&ing).await;

    rig.chain.drop_height(105);
    rig.chain.push(burn_event(6, "0xa", 1, 107, 7));
    let r = tick(&ing).await;
    assert_eq!((r.stats.upserted, r.stats.rolled_back), (1, 1));
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM rollbacks WHERE tx_id = '0xa' AND event_index = 3 AND height = 105"),
        1
    );
    assert_eq!(rig.count("SELECT COUNT(*) FROM burns"), 1);
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM burns WHERE tx_id = '0xa' AND event_index = 1 AND height = 107 AND finalized = 0"),
        1
    );
}

#[tokio::test]
async fn reorged_row_removed_at_finalization() {
    let rig = Rig::new(100);
    rig.chain.set_heights(100, 110);
    rig.chain.push(burn_event(6, "0xa", 0, 105, 7));
    let ing = rig.ingestor(cfg(10, 1000));
    tick(&ing).await;
    assert_eq!(rig.chain.scan_count(), 1);

    // The chain drops the row and the finalized height jumps past it.
    rig.chain.drop_height(105);
    rig.chain.set_heights(110, 110);
    let r = tick(&ing).await;
    assert_eq!(r.stats.rolled_back, 1);
    assert_eq!(rig.cursor(), 110);
    assert_eq!(
        rig.chain.calls()[1..],
        [ScanCall {
            after: 100,
            up_to: 110,
            commitment: Commitment::Finalized
        }],
        "only the finalize phase scans the range"
    );
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM rollbacks WHERE scope = 'final' AND height = 105"),
        1
    );
    assert_eq!(rig.count("SELECT COUNT(*) FROM burns"), 0);
}

#[tokio::test]
async fn heights_regression_is_clamped() {
    let rig = Rig::new(100);
    rig.chain.set_heights(120, 120);
    rig.chain.push(burn_event(6, "0xa", 0, 110, 7));
    let ing = rig.ingestor(cfg(10, 1000));
    tick(&ing).await;
    assert_eq!(rig.cursor(), 120);
    let before = rig.event_tables();
    let scans = rig.chain.scan_count();

    rig.chain.set_heights(90, 95);
    let r = tick(&ing).await;
    assert_eq!(r.final_through, 120);
    assert_eq!(rig.cursor(), 120);
    assert_eq!(rig.chain.scan_count(), scans, "nothing to scan");
    assert_eq!(rig.event_tables(), before);
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM burns WHERE finalized = 1"),
        1
    );
}

#[tokio::test]
async fn tail_waits_while_catching_up() {
    let rig = Rig::new(100);
    rig.chain.set_heights(1000, 1010);
    rig.chain.set_max_span(Some(100));
    let ing = rig.ingestor(cfg(3, 1000));

    for expected in [400, 700] {
        let r = tick(&ing).await;
        assert_eq!(r.final_through, expected);
        assert_eq!(r.tail_through, None);
        assert!(!r.caught_up);
        assert_eq!(
            rig.count("SELECT COUNT(*) FROM chain_state WHERE caught_up_at IS NULL"),
            1
        );
    }
    assert!(
        rig.chain
            .calls()
            .iter()
            .all(|c| c.commitment == Commitment::Finalized)
    );

    // The third tick reaches F and scans the tail in the same tick.
    let r = tick(&ing).await;
    assert_eq!(r.final_through, 1000);
    assert_eq!(r.tail_through, Some(1010));
    assert!(r.caught_up);
    assert_eq!(
        rig.chain.calls().last().unwrap(),
        &ScanCall {
            after: 1000,
            up_to: 1010,
            commitment: Commitment::Confirmed
        }
    );
    assert_eq!(
        rig.count("SELECT scanned_head FROM chain_state WHERE caught_up_at IS NOT NULL"),
        1010
    );
}

fn scripted_chain(rig: &Rig) {
    rig.chain.set_heights(140, 170);
    rig.chain.push(burn_event(6, "0xb1", 0, 105, 1));
    rig.chain.push(receive_event(6, "0xr1", 2, 112, 9, 2));
    rig.chain.push(burn_event(6, "0xb2", 0, 121, 3));
    rig.chain.push(burn_event(6, "0xb3", 1, 135, 4));
    rig.chain.push(burn_event(6, "0xb4", 0, 145, 5));
    rig.chain.push(receive_event(6, "0xr2", 0, 160, 8, 6));
}

#[tokio::test]
async fn partial_scan_results_advance_cursor_stepwise() {
    let reference = Rig::new(100);
    scripted_chain(&reference);
    let r = tick(&reference.ingestor(cfg(10, 1000))).await;
    assert!(r.caught_up);

    let rig = Rig::new(100);
    scripted_chain(&rig);
    rig.chain.set_max_span(Some(15));
    let r = tick(&rig.ingestor(cfg(10, 1000))).await;
    assert!(r.caught_up);
    let afters: Vec<(u64, Commitment)> = rig
        .chain
        .calls()
        .iter()
        .map(|c| (c.after, c.commitment))
        .collect();
    assert_eq!(
        afters,
        [
            (100, Commitment::Finalized),
            (115, Commitment::Finalized),
            (130, Commitment::Finalized),
            (140, Commitment::Confirmed),
            (155, Commitment::Confirmed),
        ]
    );
    assert_eq!(rig.state(), reference.state());
}

/// Fails scan `k` (a crash before commit `k`), restarts on the same file and
/// finishes. Returns the final database state.
async fn run_with_crash(k: Option<usize>, max_scans: u32) -> Vec<Vec<String>> {
    let mut rig = Rig::new(100);
    scripted_chain(&rig);
    rig.chain.set_max_span(Some(15));
    if let Some(k) = k {
        rig.chain.fail_on_scan(Some(k));
        let mut crashed = false;
        let ing = rig.ingestor(cfg(max_scans, 1000));
        for _ in 0..10 {
            match ing.tick(NOW).await {
                Err(TickError::Source(SourceError::Rpc(_))) => {
                    crashed = true;
                    break;
                }
                Ok(r) if r.caught_up => break,
                other => {
                    other.unwrap();
                }
            }
        }
        assert!(crashed, "scan {k} must fail");
        drop(ing);
        rig.restart();
        rig.chain.fail_on_scan(None);
    }
    let ing = rig.ingestor(cfg(max_scans, 1000));
    for _ in 0..10 {
        if tick(&ing).await.caught_up {
            return rig.state();
        }
    }
    panic!("did not catch up");
}

#[tokio::test]
async fn ingest_crash_at_every_commit_point_converges() {
    for max_scans in [100, 2] {
        let reference = run_with_crash(None, max_scans).await;
        // Five scans: three final, two tail.
        for k in 1..=5 {
            assert_eq!(
                run_with_crash(Some(k), max_scans).await,
                reference,
                "crash at scan {k}, max_scans_per_tick {max_scans}"
            );
        }
    }
}

#[tokio::test]
async fn restart_resumes_from_cursor() {
    let mut rig = Rig::new(100);
    rig.chain.set_heights(120, 120);
    rig.chain.push(burn_event(6, "0xa", 0, 110, 7));
    tick(&rig.ingestor(cfg(10, 1000))).await;
    assert_eq!(rig.cursor(), 120);

    rig.restart();
    rig.chain.set_heights(140, 140);
    let ing = rig.ingestor(cfg(10, 1000));
    tick(&ing).await;
    let calls = rig.chain.calls();
    assert_eq!(
        calls[1],
        ScanCall {
            after: 120,
            up_to: 140,
            commitment: Commitment::Finalized
        }
    );
    assert_eq!(rig.cursor(), 140);
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM burns WHERE finalized = 1"),
        1
    );
}

#[tokio::test]
async fn finality_stalled_caps_tail() {
    let rig = Rig::new(100);
    rig.chain.set_heights(100, 150);
    rig.chain.push(burn_event(6, "0xfar", 0, 130, 7));
    // Wide tail first: the row at 130 is stored unfinalized.
    tick(&rig.ingestor(cfg(10, 50))).await;
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM burns WHERE height = 130"),
        1
    );

    // Narrow tail: scans only (100, 120]; the row above stays untouched.
    rig.chain.drop_height(130);
    let r = tick(&rig.ingestor(cfg(10, 20))).await;
    assert_eq!(r.tail_through, Some(120));
    assert!(r.caught_up, "the capped target counts as reached");
    assert_eq!(
        *rig.chain.calls().last().unwrap(),
        ScanCall {
            after: 100,
            up_to: 120,
            commitment: Commitment::Confirmed
        }
    );
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM burns WHERE height = 130"),
        1
    );
    assert_eq!(rig.count("SELECT scanned_head FROM chain_state"), 120);
}

#[tokio::test]
async fn ingest_lagging_ends_tick_and_keeps_committed_work() {
    let rig = Rig::new(100);
    rig.chain.set_heights(130, 130);
    rig.chain.set_max_span(Some(10));
    rig.chain.lag_from_scan(Some(3));
    let ing = rig.ingestor(cfg(10, 1000));

    let err = ing.tick(NOW).await.unwrap_err();
    assert!(matches!(err, TickError::Source(SourceError::Lagging(_))));
    assert_eq!(rig.cursor(), 120, "two scans committed before the lag");

    rig.chain.lag_from_scan(None);
    let r = tick(&ing).await;
    assert!(r.caught_up);
    assert_eq!(rig.cursor(), 130);
}

#[tokio::test]
async fn ingest_tick_without_cursor_is_a_store_error() {
    let dir = tempfile::tempdir().unwrap();
    let store = SharedStore::open(&dir.path().join("x.db")).unwrap();
    let ing = Ingestor::new(Arc::new(FakeChain::new(6, "base")), store, cfg(1, 1));
    let err = ing.tick(NOW).await.unwrap_err();
    assert!(matches!(
        err,
        TickError::Store(StoreError::NoCursor { domain: 6 })
    ));
}

/// A source that breaks the scan contract must not reach the store.
#[tokio::test]
async fn ingest_rejects_scan_that_makes_no_progress() {
    let rig = Rig::new(100);
    rig.chain.set_heights(120, 120);
    rig.chain.set_max_span(Some(0));
    let err = rig.ingestor(cfg(10, 1)).tick(NOW).await.unwrap_err();
    assert!(matches!(err, TickError::Source(SourceError::Rpc(_))));
    assert_eq!(rig.cursor(), 100);
}

#[tokio::test]
async fn ingest_init_cursor_starts_at_finalized_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let store = SharedStore::open(&dir.path().join("x.db")).unwrap();
    let chain = FakeChain::new(6, "base");
    chain.set_heights(500, 510);
    let c = init_cursor(&chain, &store, None, NOW).await.unwrap();
    assert_eq!((c.start_height, c.final_height), (501, 500));
    assert_eq!(c.name, "base");
    assert_eq!(chain.scan_count(), 0);
}

#[tokio::test]
async fn ingest_init_cursor_backfills_from_start_height() {
    let dir = tempfile::tempdir().unwrap();
    let store = SharedStore::open(&dir.path().join("x.db")).unwrap();
    let chain = FakeChain::new(6, "base");
    chain.set_heights_failing(true);
    // A backfill start needs no node call.
    let c = init_cursor(&chain, &store, Some(400), NOW).await.unwrap();
    assert_eq!((c.start_height, c.final_height), (400, 399));
}

#[tokio::test]
async fn ingest_init_cursor_is_a_noop_on_later_runs() {
    let dir = tempfile::tempdir().unwrap();
    let store = SharedStore::open(&dir.path().join("x.db")).unwrap();
    let chain = FakeChain::new(6, "base");
    chain.set_heights(500, 510);
    init_cursor(&chain, &store, None, NOW).await.unwrap();

    // Another config value is ignored, and the node is not asked.
    chain.set_heights_failing(true);
    let c = init_cursor(&chain, &store, Some(10), NOW).await.unwrap();
    assert_eq!((c.start_height, c.final_height), (501, 500));

    let other = FakeChain::new(6, "renamed");
    let err = init_cursor(&other, &store, None, NOW).await.unwrap_err();
    assert!(matches!(
        err,
        TickError::Store(StoreError::ConfigMismatch(_))
    ));
}

async fn wait_for(mut cond: impl FnMut() -> bool) {
    for _ in 0..500 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not reached in 5 s");
}

fn health(rig: &Rig) -> Vec<String> {
    dump(&rig.raw(), "health")
        .into_iter()
        .next()
        .unwrap_or_default()
}

#[tokio::test]
async fn ingest_run_records_health_and_stops_on_cancel() {
    let rig = Rig::new(100);
    rig.chain.set_heights(110, 110);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(rig.ingestor(cfg(10, 10)).run(cancel.clone()));

    wait_for(|| health(&rig).get(2).is_some_and(|v| v != "NULL")).await;
    let row = health(&rig);
    assert_eq!(row[0], "ingest:base");
    assert_eq!((row[3].as_str(), row[5].as_str()), ("NULL", "0"));
    assert_eq!(rig.cursor(), 110);

    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn ingest_run_treats_lagging_as_healthy() {
    let rig = Rig::new(100);
    rig.chain.set_heights(110, 110);
    rig.chain.lag_from_scan(Some(1));
    let cancel = CancellationToken::new();
    let task = tokio::spawn(rig.ingestor(cfg(10, 10)).run(cancel.clone()));

    wait_for(|| rig.chain.scan_count() >= 3).await;
    let row = health(&rig);
    assert_eq!((row[3].as_str(), row[5].as_str()), ("NULL", "0"));
    assert_ne!(row[2], "NULL", "last_ok_at is set");
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn ingest_run_backs_off_on_source_errors_and_recovers() {
    let rig = Rig::new(100);
    rig.chain.set_heights(110, 110);
    rig.chain.set_heights_failing(true);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(rig.ingestor(cfg(10, 10)).run(cancel.clone()));

    wait_for(|| {
        health(&rig)
            .get(5)
            .is_some_and(|n| n.parse::<u32>().unwrap() >= 3)
    })
    .await;
    assert!(health(&rig)[3].contains("injected heights failure"));

    rig.chain.set_heights_failing(false);
    wait_for(|| health(&rig)[5] == "0").await;
    assert_eq!(rig.cursor(), 110);
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn ingest_run_returns_store_errors() {
    let dir = tempfile::tempdir().unwrap();
    let store = SharedStore::open(&dir.path().join("x.db")).unwrap();
    let ing = Ingestor::new(Arc::new(FakeChain::new(6, "base")), store, cfg(1, 1));
    let res = ing.run(CancellationToken::new()).await;
    assert!(matches!(res, Err(StoreError::NoCursor { domain: 6 })));
}

fn assert_send<T: Send>(_: &T) {}

fn run_future_is_send<S: ChainSource>(ingestor: Ingestor<S>) {
    assert_send(&ingestor.run(CancellationToken::new()));
}

/// Compile-time proof that `tokio::spawn(ingestor.run(..))` works for the
/// production sources. Never called; it only has to type-check.
#[allow(dead_code)]
fn concrete_run_futures_are_send(evm: Ingestor<EvmSource>, solana: Ingestor<SolanaSource>) {
    assert_send(&evm.run(CancellationToken::new()));
    assert_send(&solana.run(CancellationToken::new()));
}

#[test]
fn tasks_are_send() {
    let dir = tempfile::tempdir().unwrap();
    let store = SharedStore::open(&dir.path().join("x.db")).unwrap();
    let chain = Arc::new(FakeChain::new(6, "base"));
    run_future_is_send(Ingestor::new(chain, store, cfg(1, 1)));
}

#[tokio::test]
async fn init_cursor_records_start_time() {
    let dir = tempfile::tempdir().unwrap();
    let store = SharedStore::open(&dir.path().join("x.db")).unwrap();
    // FakeChain time is 1_700_000_000 + height.
    let chain = FakeChain::new(6, "base");
    chain.set_heights(500, 510);
    let c = init_cursor(&chain, &store, None, NOW).await.unwrap();
    assert_eq!((c.start_height, c.final_height), (501, 500));
    assert_eq!(c.start_time, 1_700_000_500, "time of the finalized block");

    // An explicit start h takes the time of block h - 1.
    let other = SharedStore::open(&dir.path().join("y.db")).unwrap();
    let c = init_cursor(&chain, &other, Some(400), NOW).await.unwrap();
    assert_eq!((c.start_height, c.final_height), (400, 399));
    assert_eq!(c.start_time, 1_700_000_399);

    // Written once: a later run with another start keeps it.
    let c = init_cursor(&chain, &other, Some(450), NOW).await.unwrap();
    assert_eq!((c.start_height, c.start_time), (400, 1_700_000_399));
}
