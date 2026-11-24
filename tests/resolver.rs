//! Iris parsing, the resolver and the attestation SQL
//! (including `store_nonce_is_write_once`). Offline: `FakeIris` and
//! `FakeInspector` script the network; the store is a real SQLite file.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use bridge_watcher::config::IrisConfig;
use bridge_watcher::domain::{BurnMessage, Bytes32, ChainEvent, Domain};
use bridge_watcher::iris::{IrisMessage, IrisQuery, IrisResponse, parse_response, request_url};
use bridge_watcher::resolver::{
    IrisNonceAnswer, Resolver, ResolverConfig, StoredEqual, classify_orphan,
};
use bridge_watcher::source::TxEvidence;
use bridge_watcher::store::{
    BurnPollUpdate, ChainCursor, IrisObservation, Scope, SharedStore, SnapshotLimits, SourceLookup,
    Store,
};
use common::fake_iris::{
    FakeInspector, FakeIris, Reply, encode_message, pending_message, ready_message, response,
};
use common::fixtures;
use common::{burn_event, burn_message, receive_event};
use rusqlite::Connection;
use tempfile::TempDir;

const BASE: Domain = Domain(6);
const SOLANA: Domain = Domain(5);
const NOW: i64 = 1_800_000_000;

struct Db {
    _dir: TempDir,
    path: PathBuf,
    store: SharedStore,
}

impl Db {
    /// Base cursor 100 (start 101) and Solana cursor 1000 (start 1001).
    fn new() -> Db {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let mut store = Store::open(&path).unwrap();
        store.init_cursor(BASE, "base", 100, 0, NOW).unwrap();
        store.init_cursor(SOLANA, "solana", 1000, 0, NOW).unwrap();
        Db {
            _dir: dir,
            path,
            store: SharedStore::from_store(store),
        }
    }

    fn raw(&self) -> Connection {
        let c = Connection::open(&self.path).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c
    }

    async fn base_tail(&self, events: Vec<ChainEvent>) {
        self.store
            .run(move |s| {
                s.apply_scan(
                    BASE,
                    Scope::Tail {
                        after: 100,
                        through: 200,
                    },
                    &events,
                    NOW,
                )
            })
            .await
            .unwrap();
    }

    async fn base_final(&self, events: Vec<ChainEvent>) {
        self.store
            .run(move |s| {
                s.apply_scan(
                    BASE,
                    Scope::Final {
                        after: 100,
                        through: 200,
                    },
                    &events,
                    NOW,
                )
            })
            .await
            .unwrap();
    }

    async fn solana_final(&self, events: Vec<ChainEvent>) {
        self.store
            .run(move |s| {
                s.apply_scan(
                    SOLANA,
                    Scope::Final {
                        after: 1000,
                        through: 1100,
                    },
                    &events,
                    NOW,
                )
            })
            .await
            .unwrap();
    }

    fn burn_id(&self, tx: &str, idx: u32) -> i64 {
        self.raw()
            .query_row(
                "SELECT id FROM burns WHERE tx_id = ?1 AND event_index = ?2",
                rusqlite::params![tx, idx],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn nonce(&self, tx: &str, idx: u32) -> Option<u8> {
        let blob: Option<Vec<u8>> = self
            .raw()
            .query_row(
                "SELECT nonce FROM burns WHERE tx_id = ?1 AND event_index = ?2",
                rusqlite::params![tx, idx],
                |r| r.get(0),
            )
            .unwrap();
        blob.map(|b| {
            assert!(b.iter().all(|x| *x == b[0]), "test nonces are uniform");
            b[0]
        })
    }

    fn status(&self, tx: &str, idx: u32) -> String {
        self.raw()
            .query_row(
                "SELECT attestation_status FROM burns WHERE tx_id = ?1 AND event_index = ?2",
                rusqlite::params![tx, idx],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// (poll_count, next_poll_at, last_polled_at)
    fn polls(&self, tx: &str, idx: u32) -> (i64, i64, Option<i64>) {
        self.raw()
            .query_row(
                "SELECT poll_count, next_poll_at, last_polled_at FROM burns
                 WHERE tx_id = ?1 AND event_index = ?2",
                rusqlite::params![tx, idx],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
    }

    fn iris_source_tx(&self, tx: &str) -> Option<String> {
        self.raw()
            .query_row(
                "SELECT iris_source_tx FROM receives WHERE tx_id = ?1",
                rusqlite::params![tx],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// (source_lookup, source_lookup_count, next_lookup_at)
    fn lookup(&self, tx: &str) -> (Option<String>, i64, i64) {
        self.raw()
            .query_row(
                "SELECT source_lookup, source_lookup_count, next_lookup_at FROM receives
                 WHERE tx_id = ?1",
                rusqlite::params![tx],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
    }
}

fn resolver(
    db: &Db,
    iris: &FakeIris,
    locator: &FakeInspector,
) -> Resolver<FakeIris, FakeInspector> {
    Resolver::new(
        iris.clone(),
        locator.clone(),
        db.store.clone(),
        ResolverConfig::from(&IrisConfig::default()),
    )
}

fn tx_query(tx: &str) -> IrisQuery {
    IrisQuery::TxId(tx.to_string())
}

fn script(iris: &FakeIris, tx: &str, reply: Reply) {
    iris.set(BASE, tx_query(tx), reply);
}

fn ok(tx: &str, messages: Vec<IrisMessage>) -> Reply {
    Reply::Response(response(tx, messages))
}

// ---------------------------------------------------------------------------
// Iris parsing and request building
// ---------------------------------------------------------------------------

#[test]
fn iris_parse_fixtures() {
    for (name, tx, nonce_hex, source_domain) in [
        (
            "iris_base_burn.json",
            "0x90d79ce6d16f9d030f45f5ab1767e843e9cefc0d5afae43712b540d1686bab9d",
            "dc9db8e758a6080cd494d37c7df9f4b80f3745b1957223ec728bb6759287833f",
            6,
        ),
        (
            "iris_solana_burn.json",
            "5hZceQXeq8yTugkfTLF9LXa9az3XXxEUbta6fUWhuEPuoogcgeS4dSgqMWDR5pPNq7dLYHtPPFrHtS87VpHdXWB2",
            "980e3ffa5313ffad7c20f89ae813d278a96a1c825f6feabcc3bd2d8f75ff7406",
            5,
        ),
    ] {
        let resp = parse_response(&fixtures::read(name)).unwrap();
        assert_eq!(resp.source_tx.as_deref(), Some(tx));
        assert_eq!(resp.messages.len(), 1);
        let m = &resp.messages[0];
        assert!(m.attestation_ready);
        assert_eq!(m.status, "complete");
        assert_eq!(m.cctp_version, Some(2));
        assert_eq!(m.delay_reason, None);
        assert!(m.destination_tx.is_some());
        let bytes = m.message.as_ref().expect("message is present");
        let (burn, iris) = bridge_watcher::codec::decode_burn_message(bytes).unwrap();
        assert_eq!(burn.source_domain, Domain(source_domain));
        assert_eq!(iris.nonce.to_hex(), format!("0x{nonce_hex}"));
    }
}

#[test]
fn iris_parse_not_ready_and_odd_messages() {
    let body = r#"{"messages":[
        {"message":"0x","attestation":"PENDING","status":"pending_confirmations","cctpVersion":2},
        {"message":"0x00","attestation":null,"status":"pending_confirmations","cctpVersion":"2","delayReason":"insufficient_fee"},
        {"message":"zz","attestation":"0x","cctpVersion":1}
    ]}"#;
    let resp = parse_response(body).unwrap();
    assert_eq!(resp.source_tx, None);
    assert_eq!(resp.messages.len(), 3);
    assert_eq!(resp.messages[0].message, None);
    assert!(!resp.messages[0].attestation_ready);
    assert_eq!(resp.messages[1].message, Some(vec![0]));
    assert!(!resp.messages[1].attestation_ready);
    assert_eq!(resp.messages[1].cctp_version, Some(2));
    assert_eq!(
        resp.messages[1].delay_reason.as_deref(),
        Some("insufficient_fee")
    );
    assert_eq!(
        resp.messages[2].message, None,
        "non-hex text is not a message"
    );
    assert_eq!(resp.messages[2].cctp_version, Some(1));
    assert_eq!(resp.messages[2].status, "unknown");
}

#[test]
fn iris_parse_rejects_non_json() {
    assert!(parse_response("<html>").is_err());
    assert!(parse_response("{}").unwrap().messages.is_empty());
}

#[test]
fn iris_request_url_shapes() {
    let n = Bytes32([0xab; 32]);
    assert_eq!(
        request_url("https://iris-api.circle.com/", BASE, &tx_query("0xdead")),
        "https://iris-api.circle.com/v2/messages/6?transactionHash=0xdead"
    );
    assert_eq!(
        request_url("https://iris-api.circle.com", SOLANA, &IrisQuery::Nonce(n)),
        format!(
            "https://iris-api.circle.com/v2/messages/5?nonce=0x{}",
            "ab".repeat(32)
        )
    );
}

// ---------------------------------------------------------------------------
// Store: write-once nonce
// ---------------------------------------------------------------------------

fn obs(nonce: u8, complete: bool) -> IrisObservation {
    IrisObservation {
        nonce: Bytes32([nonce; 32]),
        complete,
        fee_executed: 7,
        finality_threshold_executed: 2000,
        delay_reason: None,
        iris_destination_tx: None,
    }
}

fn upd(burn_id: i64, observation: Option<IrisObservation>, next: i64) -> BurnPollUpdate {
    BurnPollUpdate {
        burn_id,
        observation,
        next_poll_at: next,
    }
}

#[tokio::test]
async fn store_nonce_is_write_once() {
    let db = Db::new();
    db.base_tail(vec![
        burn_event(6, "0xa", 0, 110, 10),
        burn_event(6, "0xb", 0, 111, 20),
    ])
    .await;
    let (a, b) = (db.burn_id("0xa", 0), db.burn_id("0xb", 0));
    let mut s = Store::open(&db.path).unwrap();

    let none = s
        .record_attestation_polls(&[upd(a, Some(obs(1, false)), NOW + 10)], NOW)
        .unwrap();
    assert!(none.is_empty());
    assert_eq!(db.nonce("0xa", 0), Some(1));
    assert_eq!(db.status("0xa", 0), "pending");

    // Another nonce for a burn that holds one: refused, bookkeeping still runs.
    let conflicts = s
        .record_attestation_polls(&[upd(a, Some(obs(2, true)), NOW + 20)], NOW + 5)
        .unwrap();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].burn_id, a);
    assert_eq!(conflicts[0].nonce, Bytes32([2; 32]));
    assert_eq!(conflicts[0].held_by, None);
    assert_eq!(db.nonce("0xa", 0), Some(1));
    assert_eq!(db.status("0xa", 0), "pending", "status must not advance");
    assert_eq!(db.polls("0xa", 0), (2, NOW + 20, Some(NOW + 5)));

    // A nonce that another burn holds: refused with held_by.
    let conflicts = s
        .record_attestation_polls(&[upd(b, Some(obs(1, true)), NOW + 30)], NOW + 6)
        .unwrap();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].held_by, Some(a));
    assert_eq!(db.nonce("0xb", 0), None);
    assert_eq!(db.status("0xb", 0), "pending");

    // The same nonce again is accepted and may complete the burn.
    let conflicts = s
        .record_attestation_polls(&[upd(a, Some(obs(1, true)), NOW + 40)], NOW + 7)
        .unwrap();
    assert!(conflicts.is_empty());
    assert_eq!(db.status("0xa", 0), "complete");
    let attested: Option<i64> = db
        .raw()
        .query_row("SELECT attested_at FROM burns WHERE id = ?1", [a], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(attested, Some(NOW + 7));
}

#[tokio::test]
async fn store_defer_keeps_last_polled_at() {
    let db = Db::new();
    db.base_tail(vec![burn_event(6, "0xa", 0, 110, 10)]).await;
    let a = db.burn_id("0xa", 0);
    let mut s = Store::open(&db.path).unwrap();
    s.defer_attestation_polls(&[a], NOW + 99).unwrap();
    assert_eq!(db.polls("0xa", 0), (0, NOW + 99, None));
    assert_eq!(db.status("0xa", 0), "unseen");
}

#[tokio::test]
async fn resolver_ignores_vanished_burn() {
    let db = Db::new();
    db.base_tail(vec![burn_event(6, "0xa", 0, 110, 10)]).await;
    let old = db.burn_id("0xa", 0);
    let queue = db
        .store
        .run(|s| s.attestation_queue(NOW, 10))
        .await
        .unwrap();
    assert_eq!(queue.len(), 1);

    // A reorg removes the burn, and a new burn takes its place.
    db.base_tail(vec![]).await;
    db.base_tail(vec![burn_event(6, "0xc", 0, 112, 30)]).await;
    let fresh = db.burn_id("0xc", 0);
    assert_ne!(old, fresh, "ids are never reused");

    let conflicts = db
        .store
        .run(move |s| s.record_attestation_polls(&[upd(old, Some(obs(1, true)), NOW + 10)], NOW))
        .await
        .unwrap();
    assert!(conflicts.is_empty());
    assert_eq!(db.nonce("0xc", 0), None);
    assert_eq!(db.polls("0xc", 0), (0, 0, None));
}

// ---------------------------------------------------------------------------
// Resolver: burn polling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn iris_pending_message_keeps_burn_pending() {
    let db = Db::new();
    db.base_tail(vec![burn_event(6, "0xa", 0, 110, 10)]).await;
    let iris = FakeIris::new();
    script(&iris, "0xa", ok("0xa", vec![pending_message()]));
    let mut r = resolver(&db, &iris, &FakeInspector::new());
    let report = r.tick(NOW).await.unwrap();
    assert_eq!(report.txs_polled, 1);
    assert_eq!(db.nonce("0xa", 0), None);
    assert_eq!(db.status("0xa", 0), "pending");
    assert_eq!(db.polls("0xa", 0), (1, NOW + 10, Some(NOW)));
}

#[tokio::test]
async fn iris_404_backs_off() {
    let db = Db::new();
    db.base_tail(vec![burn_event(6, "0xa", 0, 110, 10)]).await;
    let iris = FakeIris::new();
    let mut r = resolver(&db, &iris, &FakeInspector::new());
    let mut now = NOW;
    let mut delays = Vec::new();
    for _ in 0..6 {
        r.tick(now).await.unwrap();
        let (_, next, _) = db.polls("0xa", 0);
        delays.push(next - now);
        now = next;
    }
    assert_eq!(delays, vec![10, 20, 40, 80, 120, 120]);
    assert_eq!(db.status("0xa", 0), "pending");
}

#[tokio::test]
async fn iris_maps_multiple_burns_in_one_tx_by_fields() {
    let db = Db::new();
    db.base_tail(vec![
        burn_event(6, "0xa", 1, 110, 10),
        burn_event(6, "0xa", 2, 110, 20),
        burn_event(6, "0xa", 3, 110, 30),
    ])
    .await;
    let mut other = burn_message(6, 99);
    other.destination_domain = Domain(7);
    let iris = FakeIris::new();
    script(
        &iris,
        "0xa",
        ok(
            "0xa",
            vec![
                ready_message(&burn_message(6, 30), 3),
                ready_message(&other, 9),
                ready_message(&burn_message(6, 10), 1),
                ready_message(&burn_message(6, 20), 2),
            ],
        ),
    );
    let mut r = resolver(&db, &iris, &FakeInspector::new());
    let report = r.tick(NOW).await.unwrap();
    assert_eq!(report.burns_attested, 3);
    assert_eq!(db.nonce("0xa", 1), Some(1));
    assert_eq!(db.nonce("0xa", 2), Some(2));
    assert_eq!(db.nonce("0xa", 3), Some(3));
    assert_eq!(db.status("0xa", 3), "complete");
}

#[tokio::test]
async fn iris_identical_burns_tie_break_by_order() {
    let db = Db::new();
    db.base_tail(vec![
        burn_event(6, "0xa", 1, 110, 10),
        burn_event(6, "0xa", 2, 110, 10),
    ])
    .await;
    let m = burn_message(6, 10);
    let iris = FakeIris::new();
    script(
        &iris,
        "0xa",
        ok("0xa", vec![ready_message(&m, 5), ready_message(&m, 6)]),
    );
    let mut r = resolver(&db, &iris, &FakeInspector::new());
    r.tick(NOW).await.unwrap();
    assert_eq!(db.nonce("0xa", 1), Some(5));
    assert_eq!(db.nonce("0xa", 2), Some(6));
}

/// The reviewer case: identical burns A and B, Iris readiness changes and the
/// message order may flip between polls. Each burn keeps its first nonce.
async fn identical_burns_two_polls(second_poll_reversed: bool) {
    let db = Db::new();
    db.base_tail(vec![
        burn_event(6, "0xa", 1, 110, 10),
        burn_event(6, "0xa", 2, 110, 10),
    ])
    .await;
    let m = burn_message(6, 10);
    let iris = FakeIris::new();
    let mut r = resolver(&db, &iris, &FakeInspector::new());

    // Poll 1: message 0 is not ready, message 1 is.
    script(
        &iris,
        "0xa",
        ok("0xa", vec![pending_message(), ready_message(&m, 6)]),
    );
    r.tick(NOW).await.unwrap();
    assert_eq!(
        db.nonce("0xa", 1),
        Some(6),
        "A takes the only ready message"
    );
    assert_eq!(db.nonce("0xa", 2), None);

    // Poll 2: both ready.
    let mut both = vec![ready_message(&m, 5), ready_message(&m, 6)];
    if second_poll_reversed {
        both.reverse();
    }
    script(&iris, "0xa", ok("0xa", both));
    let report = r.tick(NOW + 1000).await.unwrap();
    assert!(report.conflicts.is_empty());
    assert_eq!(db.nonce("0xa", 1), Some(6), "A keeps its nonce");
    assert_eq!(db.nonce("0xa", 2), Some(5), "B gets the other one");
    assert_eq!(db.status("0xa", 1), "complete");
    assert_eq!(db.status("0xa", 2), "complete");
}

#[tokio::test]
async fn iris_identical_burns_stable_across_polls() {
    identical_burns_two_polls(false).await;
    identical_burns_two_polls(true).await;
}

#[tokio::test]
async fn resolver_nonce_conflict_is_not_fatal() {
    let db = Db::new();
    db.base_tail(vec![
        burn_event(6, "0xa", 0, 110, 10),
        burn_event(6, "0xb", 0, 111, 20),
    ])
    .await;
    let iris = FakeIris::new();
    script(
        &iris,
        "0xa",
        ok("0xa", vec![ready_message(&burn_message(6, 10), 1)]),
    );
    // Iris wrongly gives burn B the nonce that burn A of another tx holds.
    script(
        &iris,
        "0xb",
        ok("0xb", vec![ready_message(&burn_message(6, 20), 1)]),
    );
    let mut r = resolver(&db, &iris, &FakeInspector::new());
    let report = r.tick(NOW).await.unwrap();
    assert_eq!(report.conflicts.len(), 1);
    assert_eq!(report.conflicts[0].burn_id, db.burn_id("0xb", 0));
    assert_eq!(report.conflicts[0].held_by, Some(db.burn_id("0xa", 0)));
    assert_eq!(report.burns_attested, 1);
    assert_eq!(db.status("0xa", 0), "complete");
    assert_ne!(db.status("0xb", 0), "complete");
    assert_eq!(db.nonce("0xb", 0), None);
    // The next tick works and keeps polling B.
    r.tick(NOW + 1000).await.unwrap();
}

#[tokio::test]
async fn resolver_stored_nonce_missing_keeps_nonce() {
    let db = Db::new();
    db.base_tail(vec![burn_event(6, "0xa", 0, 110, 10)]).await;
    let m = burn_message(6, 10);
    let iris = FakeIris::new();
    let mut pending = ready_message(&m, 1);
    pending.status = "pending_confirmations".to_string();
    pending.attestation_ready = false;
    script(&iris, "0xa", ok("0xa", vec![pending]));
    let mut r = resolver(&db, &iris, &FakeInspector::new());
    r.tick(NOW).await.unwrap();
    assert_eq!(db.nonce("0xa", 0), Some(1));
    assert_eq!(db.status("0xa", 0), "pending");

    // Iris now returns only another nonce with equal fields.
    script(&iris, "0xa", ok("0xa", vec![ready_message(&m, 2)]));
    let report = r.tick(NOW + 1000).await.unwrap();
    assert!(report.conflicts.is_empty());
    assert_eq!(db.nonce("0xa", 0), Some(1), "write-once");
    assert_eq!(db.status("0xa", 0), "pending");
    assert_eq!(db.polls("0xa", 0).0, 2);
}

#[tokio::test]
async fn resolver_duplicate_nonce_response_gives_the_nonce_to_one_burn() {
    let db = Db::new();
    db.base_tail(vec![
        burn_event(6, "0xa", 1, 110, 10),
        burn_event(6, "0xa", 2, 110, 10),
    ])
    .await;
    let m = burn_message(6, 10);
    let iris = FakeIris::new();
    // A malformed response: two messages, one nonce.
    script(
        &iris,
        "0xa",
        ok("0xa", vec![ready_message(&m, 7), ready_message(&m, 7)]),
    );
    let mut r = resolver(&db, &iris, &FakeInspector::new());
    let report = r.tick(NOW).await.unwrap();
    assert!(
        report.conflicts.is_empty(),
        "matching stops it before the store"
    );
    assert_eq!(db.nonce("0xa", 1), Some(7));
    assert_eq!(db.nonce("0xa", 2), None);
    assert_eq!(db.status("0xa", 1), "complete");
    assert_eq!(db.status("0xa", 2), "pending");
}

#[tokio::test]
async fn resolver_ignores_unusable_messages() {
    let db = Db::new();
    db.base_tail(vec![burn_event(6, "0xa", 0, 110, 10)]).await;
    let m = burn_message(6, 10);
    let mut v1 = ready_message(&m, 1);
    v1.cctp_version = Some(1);
    let mut zero_nonce = ready_message(&m, 0);
    zero_nonce.message = Some(encode_message(&m, Bytes32::ZERO, 2000, 0));
    let mut garbage = ready_message(&m, 3);
    garbage.message = Some(vec![1, 2, 3]);
    let iris = FakeIris::new();
    script(&iris, "0xa", ok("0xa", vec![v1, zero_nonce, garbage]));
    let mut r = resolver(&db, &iris, &FakeInspector::new());
    r.tick(NOW).await.unwrap();
    assert_eq!(db.nonce("0xa", 0), None);
    assert_eq!(db.status("0xa", 0), "pending");
}

#[tokio::test]
async fn resolver_transient_error_defers_without_polling() {
    let db = Db::new();
    db.base_tail(vec![burn_event(6, "0xa", 0, 110, 10)]).await;
    let iris = FakeIris::new();
    script(&iris, "0xa", Reply::Transient("boom".to_string()));
    let mut r = resolver(&db, &iris, &FakeInspector::new());
    let report = r.tick(NOW).await.unwrap();
    assert_eq!(report.errors, 1);
    assert!(report.error.is_some());
    assert_eq!(db.polls("0xa", 0), (0, NOW + 10, None));
    let (failures, error): (i64, Option<String>) = db
        .raw()
        .query_row(
            "SELECT consecutive_failures, last_error FROM health WHERE component = 'resolver'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(failures, 1);
    assert!(error.is_some());
    // Not due again right away.
    let again = r.tick(NOW + 1).await.unwrap();
    assert_eq!(again.txs_polled + again.errors, 0);
    assert_eq!(iris.call_count(), 1);
}

#[tokio::test(start_paused = true)]
async fn iris_429_pauses_all_calls_for_lockout() {
    let db = Db::new();
    db.base_tail(vec![burn_event(6, "0xa", 0, 110, 10)]).await;
    let iris = FakeIris::new();
    script(&iris, "0xa", Reply::RateLimited);
    let mut r = resolver(&db, &iris, &FakeInspector::new());

    let report = r.tick(NOW).await.unwrap();
    assert!(report.rate_limited);
    assert_eq!(iris.call_count(), 1);
    assert!(r.is_paused());
    assert_eq!(db.polls("0xa", 0), (0, 0, None), "a 429 polls nothing");

    tokio::time::advance(Duration::from_secs(5)).await;
    let report = r.tick(NOW + 5).await.unwrap();
    assert!(report.paused);
    tokio::time::advance(Duration::from_secs(300)).await;
    r.tick(NOW + 305).await.unwrap();
    assert_eq!(iris.call_count(), 1, "no call during the lockout");

    tokio::time::advance(Duration::from_secs(6)).await;
    assert!(!r.is_paused());
    script(&iris, "0xa", ok("0xa", vec![pending_message()]));
    r.tick(NOW + 311).await.unwrap();
    assert_eq!(iris.call_count(), 2);
}

#[tokio::test(start_paused = true)]
async fn iris_429_in_orphan_phase_pauses_burn_polling_too() {
    let db = Db::new();
    db.solana_final(vec![receive_event(5, "0xr", 0, 1010, 9, 10)])
        .await;
    db.base_tail(vec![burn_event(6, "0xa", 0, 110, 10)]).await;
    let iris = FakeIris::new();
    iris.set(BASE, nonce_query(), Reply::RateLimited);
    let mut r = resolver(&db, &iris, &FakeInspector::new());
    let report = r.tick(NOW).await.unwrap();
    assert!(report.rate_limited);
    let calls = iris.call_count();
    r.tick(NOW + 1).await.unwrap();
    assert_eq!(iris.call_count(), calls);
}

// ---------------------------------------------------------------------------
// classify_orphan: the decision table
// ---------------------------------------------------------------------------

fn cursor(start: u64, finalized: u64, scanned_head: Option<u64>) -> ChainCursor {
    ChainCursor {
        domain: BASE,
        name: "base".to_string(),
        start_height: start,
        start_time: 0,
        final_height: finalized,
        scanned_head,
    }
}

fn known(tx: Option<&str>, message: Option<BurnMessage>) -> IrisNonceAnswer {
    IrisNonceAnswer::Known {
        source_tx: tx.map(str::to_string),
        message,
    }
}

fn evidence(height: u64, burns: Vec<BurnMessage>) -> TxEvidence {
    TxEvidence { height, burns }
}

#[test]
fn classify_orphan_decision_table() {
    use SourceLookup::*;
    let m = burn_message(6, 10);
    let other = burn_message(6, 11);
    // Scanned range: start 101, finalized 200, tail scanned to 250.
    let src = cursor(101, 200, Some(250));
    let max = 6;
    let cs = |iris: &IrisNonceAnswer, ev: Option<&TxEvidence>, stored: StoredEqual, done: u32| {
        classify_orphan(iris, ev, stored, &src, done, max)
    };
    // `stored = true`: one stored equal burn that is free to take the nonce.
    let c = |iris: &IrisNonceAnswer, ev: Option<&TxEvidence>, stored: bool, done: u32| {
        let eq = StoredEqual {
            free: u32::from(stored),
            ..StoredEqual::default()
        };
        cs(iris, ev, eq, done)
    };
    let with_tx = known(Some("0xsrc"), Some(m.clone()));

    // 1. Iris 404.
    assert_eq!(c(&IrisNonceAnswer::Unknown, None, false, 0), UnknownToIris);
    // 2. Iris names no source tx (also when it has no message either).
    assert_eq!(
        c(&known(None, Some(m.clone())), None, false, 0),
        SourceNotFound
    );
    assert_eq!(c(&known(None, None), None, false, 0), SourceNotFound);
    // 3. No decodable message with this nonce.
    assert_eq!(c(&known(Some("0xsrc"), None), None, false, 0), Postponed);
    // 4. The chain does not know the tx.
    assert_eq!(c(&with_tx, None, false, 0), SourceNotFound);
    // 5. No equal burn: critical whatever the height, also below the start.
    for h in [50, 150, 900] {
        let ev = evidence(h, vec![other.clone()]);
        assert_eq!(c(&with_tx, Some(&ev), false, 0), IrisMismatch, "height {h}");
    }
    // 5. A failed source tx has no burns at all.
    assert_eq!(
        c(&with_tx, Some(&evidence(150, vec![])), false, 0),
        IrisMismatch
    );
    // 5. One equal burn among others is enough.
    let ev = evidence(150, vec![other.clone(), m.clone()]);
    assert_eq!(c(&with_tx, Some(&ev), false, 0), Missed);
    // 6. Equal burn below the start.
    let ev = evidence(100, vec![m.clone()]);
    assert_eq!(c(&with_tx, Some(&ev), false, 0), PreStart);
    assert_eq!(
        c(&with_tx, Some(&ev), true, 0),
        PreStart,
        "row 6 before row 7"
    );
    // 7. Equal burn is stored.
    let ev = evidence(150, vec![m.clone()]);
    assert_eq!(c(&with_tx, Some(&ev), true, 0), Postponed);
    // 8. Equal burn in the scanned range (cursor or scanned head), not stored.
    assert_eq!(c(&with_tx, Some(&ev), false, 0), Missed);
    let ev = evidence(250, vec![m.clone()]);
    assert_eq!(
        c(&with_tx, Some(&ev), false, 0),
        Missed,
        "scanned_head counts"
    );
    // 9. Above the scanned range.
    let ev = evidence(251, vec![m.clone()]);
    assert_eq!(c(&with_tx, Some(&ev), false, 0), Postponed);
    // 5a. Double mint: every equal on-chain burn is stored, final, and
    // attested under another nonce.
    let one = evidence(150, vec![m.clone()]);
    let holder = |free, other_final, other_unfinal| StoredEqual {
        free,
        other_final,
        other_unfinal,
    };
    assert_eq!(cs(&with_tx, Some(&one), holder(0, 1, 0), 0), DoubleMint);
    // 5a before 6: also below the start height.
    let below = evidence(100, vec![m.clone()]);
    assert_eq!(cs(&with_tx, Some(&below), holder(0, 1, 0), 0), DoubleMint);
    // An unfinalized holder only postpones (row 7).
    assert_eq!(cs(&with_tx, Some(&one), holder(0, 0, 1), 0), Postponed);
    assert_eq!(cs(&with_tx, Some(&one), holder(0, 1, 1), 0), Postponed);
    // A free stored burn can still take the nonce (row 7).
    assert_eq!(cs(&with_tx, Some(&one), holder(1, 1, 0), 0), Postponed);
    // E = 2 identical burns, one final holder, the other unstored: not a
    // double mint; row 8 (scanned) or row 9 (above the range).
    let two = evidence(150, vec![m.clone(), m.clone()]);
    assert_eq!(cs(&with_tx, Some(&two), holder(0, 1, 0), 0), Missed);
    let two_far = evidence(300, vec![m.clone(), m.clone()]);
    assert_eq!(cs(&with_tx, Some(&two_far), holder(0, 1, 0), 0), Postponed);
    // E = 2 and both stored with other nonces and final: double mint.
    assert_eq!(cs(&with_tx, Some(&two), holder(0, 2, 0), 0), DoubleMint);
    // Row 5 still wins when there is no equal burn on chain.
    let none = evidence(150, vec![other.clone()]);
    assert_eq!(cs(&with_tx, Some(&none), holder(0, 1, 0), 0), IrisMismatch);
    // E. Postponed on the last allowed lookup becomes unresolved; other
    // outcomes are untouched.
    assert_eq!(c(&with_tx, Some(&ev), false, 4), Postponed);
    assert_eq!(c(&with_tx, Some(&ev), false, 5), Unresolved);
    assert_eq!(c(&known(Some("0xsrc"), None), None, false, 5), Unresolved);
    assert_eq!(c(&IrisNonceAnswer::Unknown, None, false, 5), UnknownToIris);
    assert_eq!(c(&with_tx, None, false, 5), SourceNotFound);
    let ev = evidence(150, vec![]);
    assert_eq!(c(&with_tx, Some(&ev), false, 5), IrisMismatch);
}

// ---------------------------------------------------------------------------
// Resolver: orphan receives
// ---------------------------------------------------------------------------

/// A final Solana receive of a Base burn with nonce `[9; 32]` and amount 10,
/// old enough.
async fn orphan_db() -> (Db, FakeIris, FakeInspector) {
    let db = Db::new();
    db.solana_final(vec![receive_event(5, "0xr", 0, 1010, 9, 10)])
        .await;
    (db, FakeIris::new(), FakeInspector::new())
}

fn nonce_query() -> IrisQuery {
    IrisQuery::Nonce(Bytes32([9; 32]))
}

fn known_to_iris(iris: &FakeIris, source_tx: &str) {
    iris.set(
        BASE,
        nonce_query(),
        ok(source_tx, vec![ready_message(&burn_message(6, 10), 9)]),
    );
}

#[tokio::test]
async fn orphan_unknown_to_iris() {
    let (db, iris, inspector) = orphan_db().await;
    let mut r = resolver(&db, &iris, &inspector);
    let report = r.tick(NOW).await.unwrap();
    assert_eq!(report.orphans_classified, 1);
    assert_eq!(
        db.lookup("0xr"),
        (Some("unknown_to_iris".into()), 1, NOW + 600)
    );
    // Not due again before the retry time; then the count grows.
    r.tick(NOW + 599).await.unwrap();
    assert_eq!(db.lookup("0xr").1, 1);
    r.tick(NOW + 600).await.unwrap();
    assert_eq!(db.lookup("0xr").1, 2);
    assert_eq!(inspector.call_count(), 0, "nothing to inspect without Iris");
}

#[tokio::test]
async fn orphan_lookups_stop_at_the_maximum() {
    let (db, iris, inspector) = orphan_db().await;
    let mut r = resolver(&db, &iris, &inspector);
    for i in 0..10 {
        r.tick(NOW + i * 600).await.unwrap();
    }
    assert_eq!(db.lookup("0xr").1, 6);
    assert_eq!(iris.call_count(), 6);
}

#[tokio::test]
async fn orphan_pre_start() {
    let (db, iris, inspector) = orphan_db().await;
    known_to_iris(&iris, "0xsrc");
    inspector.insert(BASE, "0xsrc", 50, vec![burn_message(6, 10)]);
    let mut r = resolver(&db, &iris, &inspector);
    r.tick(NOW).await.unwrap();
    assert_eq!(db.lookup("0xr").0.as_deref(), Some("pre_start"));
    assert_eq!(db.iris_source_tx("0xr").as_deref(), Some("0xsrc"));
    // A verdict is final: no more lookups.
    let calls = iris.call_count();
    r.tick(NOW + 5000).await.unwrap();
    assert_eq!(iris.call_count(), calls);
}

#[tokio::test]
async fn orphan_missed() {
    let (db, iris, inspector) = orphan_db().await;
    db.base_final(vec![]).await;
    known_to_iris(&iris, "0xsrc");
    inspector.insert(BASE, "0xsrc", 150, vec![burn_message(6, 10)]);
    let mut r = resolver(&db, &iris, &inspector);
    r.tick(NOW).await.unwrap();
    assert_eq!(db.lookup("0xr").0.as_deref(), Some("missed"));
}

#[tokio::test]
async fn orphan_postponed_when_source_not_scanned() {
    let (db, iris, inspector) = orphan_db().await;
    known_to_iris(&iris, "0xsrc");
    inspector.insert(BASE, "0xsrc", 500, vec![burn_message(6, 10)]);
    let mut r = resolver(&db, &iris, &inspector);
    let report = r.tick(NOW).await.unwrap();
    assert_eq!(report.orphans_classified, 0);
    // Counted, retried after the spacing.
    assert_eq!(db.lookup("0xr"), (Some("postponed".into()), 1, NOW + 600));
    let calls = iris.call_count();
    r.tick(NOW + 599).await.unwrap();
    assert_eq!(iris.call_count(), calls);
    r.tick(NOW + 600).await.unwrap();
    assert_eq!(iris.call_count(), calls + 1);
}

#[tokio::test]
async fn orphan_postponed_while_the_equal_burn_is_stored() {
    let (db, iris, inspector) = orphan_db().await;
    db.base_final(vec![burn_event(6, "0xsrc", 0, 150, 10)])
        .await;
    known_to_iris(&iris, "0xsrc");
    inspector.insert(BASE, "0xsrc", 150, vec![burn_message(6, 10)]);
    let mut r = resolver(&db, &iris, &inspector);
    // The burn is stored but Iris has not attested it yet: not "missed".
    r.tick(NOW).await.unwrap();
    assert_eq!(db.lookup("0xr").0.as_deref(), Some("postponed"));
}

#[tokio::test]
async fn orphan_source_not_found() {
    // (a) Iris knows the nonce but names no source tx.
    let (db, iris, inspector) = orphan_db().await;
    iris.set(
        BASE,
        nonce_query(),
        Reply::Response(IrisResponse {
            source_tx: None,
            messages: vec![ready_message(&burn_message(6, 10), 9)],
        }),
    );
    let mut r = resolver(&db, &iris, &inspector);
    let report = r.tick(NOW).await.unwrap();
    assert_eq!(report.orphans_classified, 1);
    assert_eq!(
        db.lookup("0xr"),
        (Some("source_not_found".into()), 1, NOW + 600)
    );
    assert_eq!(inspector.call_count(), 0);

    // (b) Iris names a tx that the source chain does not know.
    let (db, iris, inspector) = orphan_db().await;
    known_to_iris(&iris, "0xghost");
    let mut r = resolver(&db, &iris, &inspector);
    r.tick(NOW).await.unwrap();
    assert_eq!(inspector.call_count(), 1);
    assert_eq!(
        db.lookup("0xr"),
        (Some("source_not_found".into()), 1, NOW + 600)
    );
    // Retried, and counted again.
    r.tick(NOW + 600).await.unwrap();
    assert_eq!(db.lookup("0xr").1, 2);
}

#[tokio::test]
async fn orphan_iris_mismatch_detected() {
    // F-B end to end: the burn on chain and in our store has amount 10; Iris
    // attests a message with amount 20 for the nonce, and 20 was minted.
    let db = Db::new();
    db.base_final(vec![burn_event(6, "0xsrc", 0, 150, 10)])
        .await;
    db.solana_final(vec![receive_event(5, "0xr", 0, 1010, 9, 20)])
        .await;
    let tampered = burn_message(6, 20);
    let iris = FakeIris::new();
    script(
        &iris,
        "0xsrc",
        ok("0xsrc", vec![ready_message(&tampered, 9)]),
    );
    iris.set(
        BASE,
        nonce_query(),
        ok("0xsrc", vec![ready_message(&tampered, 9)]),
    );
    let inspector = FakeInspector::new();
    inspector.insert(BASE, "0xsrc", 150, vec![burn_message(6, 10)]);
    let mut r = resolver(&db, &iris, &inspector);
    let report = r.tick(NOW).await.unwrap();
    // The burn never matches the tampered message ...
    assert_eq!(db.nonce("0xsrc", 0), None);
    assert_eq!(db.status("0xsrc", 0), "pending");
    // ... and the minted receive is flagged after one lookup.
    assert_eq!(report.orphans_classified, 1);
    assert_eq!(db.lookup("0xr").0.as_deref(), Some("iris_mismatch"));
    assert_eq!(db.lookup("0xr").1, 1);
    // Terminal: no further lookups.
    let calls = iris.call_count();
    r.tick(NOW + 5000).await.unwrap();
    assert_eq!(
        iris.call_count(),
        calls + 1,
        "only the burn poll runs again, not the orphan lookup"
    );
}

#[tokio::test]
async fn orphan_lookups_are_bounded() {
    let (db, iris, inspector) = orphan_db().await;
    known_to_iris(&iris, "0xsrc");
    // Above the scanned range for good: the verdict stays postponed.
    inspector.insert(BASE, "0xsrc", 500, vec![burn_message(6, 10)]);
    let mut r = resolver(&db, &iris, &inspector);
    for i in 0..12 {
        r.tick(NOW + i * 600).await.unwrap();
        // Ticks inside the spacing do nothing.
        r.tick(NOW + i * 600 + 599).await.unwrap();
    }
    assert_eq!(iris.call_count(), 6, "orphan_max_lookups Iris calls");
    assert_eq!(inspector.call_count(), 6, "and as many source reads");
    assert_eq!(
        db.lookup("0xr"),
        (Some("unresolved".into()), 6, NOW + 5 * 600 + 600)
    );
}

#[tokio::test]
async fn orphan_double_mint_detected() {
    // G1: a final burn is attested under nonce 7; a receive with nonce 9 and
    // equal content was minted; the source tx holds exactly that one burn.
    let db = Db::new();
    db.base_final(vec![burn_event(6, "0xsrc", 0, 150, 10)])
        .await;
    db.solana_final(vec![receive_event(5, "0xr", 0, 1010, 9, 10)])
        .await;
    let m = burn_message(6, 10);
    let iris = FakeIris::new();
    script(&iris, "0xsrc", ok("0xsrc", vec![ready_message(&m, 7)]));
    iris.set(BASE, nonce_query(), ok("0xsrc", vec![ready_message(&m, 9)]));
    let inspector = FakeInspector::new();
    inspector.insert(BASE, "0xsrc", 150, vec![m]);
    let mut r = resolver(&db, &iris, &inspector);
    let report = r.tick(NOW).await.unwrap();
    assert_eq!(db.nonce("0xsrc", 0), Some(7));
    assert_eq!(report.orphans_classified, 1);
    assert_eq!(db.lookup("0xr").0.as_deref(), Some("double_mint"));
    assert_eq!(db.lookup("0xr").1, 1);
    // Terminal: the orphan leaves the queue.
    let calls = iris.call_count();
    r.tick(NOW + 5000).await.unwrap();
    assert_eq!(iris.call_count(), calls, "no further orphan lookups");
    // The monitor reports it, naming both nonces.
    let snap = db
        .store
        .run(|s| s.monitor_snapshot(NOW + 5000, &SnapshotLimits::default()))
        .await
        .unwrap();
    let row = &snap.orphan_receives.rows[0];
    assert_eq!(row.other_nonce, Some(Bytes32([7; 32])));
}

#[tokio::test]
async fn orphan_double_mint_waits_for_an_unfinalized_holder() {
    // The stored equal burn is still unfinalized: finality may settle it.
    let db = Db::new();
    db.base_tail(vec![burn_event(6, "0xsrc", 0, 150, 10)]).await;
    db.solana_final(vec![receive_event(5, "0xr", 0, 1010, 9, 10)])
        .await;
    let m = burn_message(6, 10);
    let iris = FakeIris::new();
    script(&iris, "0xsrc", ok("0xsrc", vec![ready_message(&m, 7)]));
    iris.set(BASE, nonce_query(), ok("0xsrc", vec![ready_message(&m, 9)]));
    let inspector = FakeInspector::new();
    inspector.insert(BASE, "0xsrc", 150, vec![m]);
    let mut r = resolver(&db, &iris, &inspector);
    r.tick(NOW).await.unwrap();
    assert_eq!(db.lookup("0xr").0.as_deref(), Some("postponed"));
}

#[tokio::test]
async fn orphan_failed_attempt_counts_and_keeps_verdict() {
    // Iris fails after two unknown_to_iris lookups: the count grows, the
    // verdict stays, the attempt is spaced.
    let (db, iris, inspector) = orphan_db().await;
    let mut r = resolver(&db, &iris, &inspector);
    r.tick(NOW).await.unwrap();
    r.tick(NOW + 600).await.unwrap();
    assert_eq!(db.lookup("0xr").1, 2);
    iris.set(BASE, nonce_query(), Reply::Transient("boom".into()));
    let report = r.tick(NOW + 1200).await.unwrap();
    assert_eq!(report.errors, 1);
    assert_eq!(
        db.lookup("0xr"),
        (Some("unknown_to_iris".into()), 3, NOW + 1800)
    );
    let calls = iris.call_count();
    r.tick(NOW + 1799).await.unwrap();
    assert_eq!(iris.call_count(), calls, "spaced like any attempt");

    // The source chain read fails after two source_not_found lookups.
    let (db, iris, inspector) = orphan_db().await;
    known_to_iris(&iris, "0xsrc");
    let mut r = resolver(&db, &iris, &inspector);
    r.tick(NOW).await.unwrap();
    r.tick(NOW + 600).await.unwrap();
    assert_eq!(db.lookup("0xr").0.as_deref(), Some("source_not_found"));
    inspector.set_failing(true);
    r.tick(NOW + 1200).await.unwrap();
    assert_eq!(
        db.lookup("0xr"),
        (Some("source_not_found".into()), 3, NOW + 1800)
    );
}

#[tokio::test]
async fn orphan_iris_429_is_not_an_attempt() {
    let (db, iris, inspector) = orphan_db().await;
    iris.set(BASE, nonce_query(), Reply::RateLimited);
    let mut r = resolver(&db, &iris, &inspector);
    let report = r.tick(NOW).await.unwrap();
    assert!(report.rate_limited);
    assert_eq!(db.lookup("0xr"), (None, 0, 0));
}

#[tokio::test]
async fn orphan_persistent_errors_end_unresolved() {
    // Iris fails on every attempt: after 6 attempts the orphan is unresolved
    // and leaves the queue; nothing retries forever.
    let (db, iris, inspector) = orphan_db().await;
    iris.set(BASE, nonce_query(), Reply::Transient("boom".into()));
    let mut r = resolver(&db, &iris, &inspector);
    for i in 0..10 {
        r.tick(NOW + i * 600).await.unwrap();
    }
    assert_eq!(iris.call_count(), 6);
    assert_eq!(db.lookup("0xr").0.as_deref(), Some("unresolved"));
    assert_eq!(db.lookup("0xr").1, 6);

    // The same through a failing source read.
    let (db, iris, inspector) = orphan_db().await;
    known_to_iris(&iris, "0xsrc");
    inspector.insert(BASE, "0xsrc", 150, vec![burn_message(6, 10)]);
    inspector.set_failing(true);
    let mut r = resolver(&db, &iris, &inspector);
    for i in 0..10 {
        r.tick(NOW + i * 600).await.unwrap();
    }
    assert_eq!(inspector.call_count(), 6);
    assert_eq!(db.lookup("0xr").0.as_deref(), Some("unresolved"));
}

#[tokio::test]
async fn orphan_last_failed_attempt_keeps_an_alerting_verdict() {
    // A critical verdict is not replaced by unresolved on a failed last attempt.
    let (db, iris, inspector) = orphan_db().await;
    let mut r = resolver(&db, &iris, &inspector);
    for i in 0..5 {
        r.tick(NOW + i * 600).await.unwrap();
    }
    iris.set(BASE, nonce_query(), Reply::Transient("boom".into()));
    r.tick(NOW + 5 * 600).await.unwrap();
    assert_eq!(db.lookup("0xr").0.as_deref(), Some("unknown_to_iris"));
    assert_eq!(db.lookup("0xr").1, 6);
}

#[tokio::test]
async fn orphan_uses_the_message_with_the_receive_nonce() {
    let (db, iris, inspector) = orphan_db().await;
    db.base_final(vec![]).await;
    // Iris returns two messages; only the second carries nonce 9.
    iris.set(
        BASE,
        nonce_query(),
        ok(
            "0xsrc",
            vec![
                ready_message(&burn_message(6, 99), 8),
                ready_message(&burn_message(6, 10), 9),
            ],
        ),
    );
    inspector.insert(BASE, "0xsrc", 150, vec![burn_message(6, 10)]);
    let mut r = resolver(&db, &iris, &inspector);
    r.tick(NOW).await.unwrap();
    assert_eq!(db.lookup("0xr").0.as_deref(), Some("missed"));
}

#[tokio::test]
async fn orphan_without_a_decodable_message_is_postponed() {
    let (db, iris, inspector) = orphan_db().await;
    iris.set(BASE, nonce_query(), ok("0xsrc", vec![pending_message()]));
    let mut r = resolver(&db, &iris, &inspector);
    r.tick(NOW).await.unwrap();
    assert_eq!(db.lookup("0xr").0.as_deref(), Some("postponed"));
    assert_eq!(inspector.call_count(), 0);
}

#[tokio::test]
async fn orphan_batch_limits_the_lookups_per_tick() {
    let db = Db::new();
    let events: Vec<_> = (0..5u8)
        .map(|i| receive_event(5, &format!("0xr{i}"), 0, 1010 + u64::from(i), 20 + i, 10))
        .collect();
    db.solana_final(events).await;
    let iris = FakeIris::new();
    let mut cfg = ResolverConfig::from(&IrisConfig::default());
    cfg.orphan_batch = 2;
    let mut r = Resolver::new(iris.clone(), FakeInspector::new(), db.store.clone(), cfg);
    r.tick(NOW).await.unwrap();
    assert_eq!(iris.call_count(), 2);
    r.tick(NOW + 1).await.unwrap();
    assert_eq!(iris.call_count(), 4, "the next two are older than the rest");
}

#[tokio::test]
async fn orphan_receive_with_a_burn_is_not_an_orphan() {
    let db = Db::new();
    db.base_tail(vec![burn_event(6, "0xa", 0, 110, 10)]).await;
    db.solana_final(vec![receive_event(5, "0xr", 0, 1010, 9, 10)])
        .await;
    let mut s = Store::open(&db.path).unwrap();
    let a = db.burn_id("0xa", 0);
    s.record_attestation_polls(&[upd(a, Some(obs(9, true)), NOW)], NOW)
        .unwrap();
    assert!(s.orphan_queue(NOW, 600, 6, 10).unwrap().is_empty());
}

#[tokio::test]
async fn orphan_record_lookup_outcomes() {
    let (db, _, _) = orphan_db().await;
    let id: i64 = db
        .raw()
        .query_row("SELECT id FROM receives WHERE tx_id = '0xr'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let mut s = Store::open(&db.path).unwrap();
    // Every call is an attempt. A failed one (no verdict) keeps the stored
    // verdict and moves the next lookup time.
    s.record_source_lookup(id, None, None, 5).unwrap();
    assert_eq!(db.lookup("0xr"), (None, 1, 5));
    s.record_source_lookup(id, Some(SourceLookup::UnknownToIris), None, 6)
        .unwrap();
    assert_eq!(db.lookup("0xr"), (Some("unknown_to_iris".into()), 2, 6));
    s.record_source_lookup(id, None, None, 7).unwrap();
    assert_eq!(db.lookup("0xr"), (Some("unknown_to_iris".into()), 3, 7));
    s.record_source_lookup(id, Some(SourceLookup::Postponed), Some("0xsrc"), 8)
        .unwrap();
    assert_eq!(db.lookup("0xr"), (Some("postponed".into()), 4, 8));
    assert_eq!(db.iris_source_tx("0xr").as_deref(), Some("0xsrc"));
    // Terminal verdicts leave the queue.
    assert_eq!(s.orphan_queue(NOW, 600, 6, 10).unwrap().len(), 1);
    s.record_source_lookup(id, Some(SourceLookup::Missed), None, 9)
        .unwrap();
    assert!(s.orphan_queue(NOW, 600, 6, 10).unwrap().is_empty());
    // A vanished receive is skipped.
    s.record_source_lookup(id + 1000, Some(SourceLookup::Missed), None, 8)
        .unwrap();
}

#[tokio::test]
async fn store_burns_of_tx_lists_all_stored_burns_in_order() {
    let db = Db::new();
    db.base_tail(vec![
        burn_event(6, "0xa", 2, 110, 20),
        burn_event(6, "0xa", 1, 110, 10),
        burn_event(6, "0xb", 0, 111, 30),
    ])
    .await;
    let s = Store::open(&db.path).unwrap();
    let burns = s.burns_of_tx(BASE, "0xa").unwrap();
    let amounts: Vec<_> = burns.iter().map(|b| b.slot.message.amount).collect();
    assert_eq!(amounts, [10, 20]);
    assert!(s.burns_of_tx(BASE, "0xnone").unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Compile-time: the run future can be spawned
// ---------------------------------------------------------------------------

#[test]
fn resolver_run_future_is_send() {
    fn assert_send<T: Send>(_: &T) {}
    let db = Db::new();
    let r = resolver(&db, &FakeIris::new(), &FakeInspector::new());
    let fut = r.run(tokio_util::sync::CancellationToken::new());
    assert_send(&fut);
}

#[tokio::test]
async fn orphan_lookup_normalizes_the_evm_source_hash_case() {
    // Iris answers in checksum-style case; stored and inspected ids are lowercase.
    let (db, iris, inspector) = orphan_db().await;
    db.base_final(vec![]).await;
    known_to_iris(&iris, "0xAbCdEF0123");
    inspector.insert(BASE, "0xabcdef0123", 150, vec![burn_message(6, 10)]);
    let mut r = resolver(&db, &iris, &inspector);
    r.tick(NOW).await.unwrap();
    assert_eq!(db.lookup("0xr").0.as_deref(), Some("missed"));
}

#[test]
fn resolver_normalize_tx_id_lowercases_evm_hashes_only() {
    use bridge_watcher::resolver::normalize_tx_id;
    assert_eq!(normalize_tx_id("0xAB12Cd"), "0xab12cd");
    assert_eq!(normalize_tx_id("0XAB12"), "0xab12");
    let sol =
        "5hZceQXeq8yTugkfTLF9LXa9az3XXxEUbta6fUWhuEPuoogcgeS4dSgqMWDR5pPNq7dLYHtPPFrHtS87VpHdXWB2";
    assert_eq!(normalize_tx_id(sol), sol);
}
