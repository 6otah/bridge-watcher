//! Store invariants (`docs/ARCHITECTURE.md` section 15.2) on a real SQLite file.
//!
//! Raw SQL goes through a second connection to the same file, so the tests can
//! attack the schema the way a buggy writer would.

mod common;

use std::path::PathBuf;

use bridge_watcher::domain::{Domain, Heights, Mode};
use bridge_watcher::store::{
    ApplyStats, Scope, SharedStore, Store, StoreError, TransferFilter, TransferState,
};
use common::{burn_event, receive_event};
use rusqlite::Connection;
use rusqlite::types::ValueRef;
use tempfile::TempDir;

const BASE: Domain = Domain(6);
const SOLANA: Domain = Domain(5);
const NOW: i64 = 1_800_000_000;

struct Db {
    _dir: TempDir,
    path: PathBuf,
    store: Store,
}

impl Db {
    /// Base cursor at 100 (start_height 101).
    fn new() -> Db {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let mut store = Store::open(&path).unwrap();
        let c = store.init_cursor(BASE, "base", 100, 0, NOW).unwrap();
        assert_eq!((c.start_height, c.final_height), (101, 100));
        Db {
            _dir: dir,
            path,
            store,
        }
    }

    fn raw(&self) -> Connection {
        let c = Connection::open(&self.path).unwrap();
        c.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        c
    }

    fn count(&self, sql: &str) -> i64 {
        self.raw().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn cursor(&self, d: Domain) -> u64 {
        self.store.cursor(d).unwrap().unwrap().final_height
    }

    fn tail(
        &mut self,
        after: u64,
        through: u64,
        events: &[bridge_watcher::domain::ChainEvent],
    ) -> ApplyStats {
        self.store
            .apply_scan(BASE, Scope::Tail { after, through }, events, NOW)
            .unwrap()
    }

    fn fin(
        &mut self,
        after: u64,
        through: u64,
        events: &[bridge_watcher::domain::ChainEvent],
    ) -> ApplyStats {
        self.store
            .apply_scan(BASE, Scope::Final { after, through }, events, NOW)
            .unwrap()
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

fn assert_trigger_abort(res: rusqlite::Result<usize>) {
    let err = res.expect_err("trigger must abort").to_string();
    assert!(err.contains("invariant I3"), "unexpected error: {err}");
}

#[test]
fn store_final_rows_cannot_be_deleted() {
    let mut db = Db::new();
    db.fin(
        100,
        110,
        &[
            burn_event(6, "0xa", 0, 105, 1),
            receive_event(6, "0xr", 0, 106, 9, 1),
        ],
    );
    let raw = db.raw();
    assert_trigger_abort(raw.execute("DELETE FROM burns", []));
    assert_trigger_abort(raw.execute("DELETE FROM receives", []));
    assert_eq!(db.count("SELECT COUNT(*) FROM burns"), 1);
    assert_eq!(db.count("SELECT COUNT(*) FROM receives"), 1);
}

#[test]
fn store_final_rows_are_immutable() {
    let mut db = Db::new();
    db.fin(
        100,
        110,
        &[
            burn_event(6, "0xa", 0, 105, 1),
            receive_event(6, "0xr", 0, 106, 9, 1),
        ],
    );
    let raw = db.raw();
    for sql in [
        "UPDATE burns SET height = 1",
        "UPDATE burns SET amount = 2",
        "UPDATE burns SET finalized = 0",
        "UPDATE burns SET hook_data = x'00'",
        "UPDATE receives SET height = 1",
        "UPDATE receives SET amount = 2",
        "UPDATE receives SET finalized = 0",
        "UPDATE receives SET nonce = zeroblob(32)",
    ] {
        assert_trigger_abort(raw.execute(sql, []));
    }
    // The resolver columns of a final row stay writable.
    raw.execute(
        "UPDATE burns SET nonce = zeroblob(32), attestation_status = 'complete', fee_executed = 3",
        [],
    )
    .unwrap();
    raw.execute(
        "UPDATE receives SET source_lookup = 'missed', source_lookup_count = 1",
        [],
    )
    .unwrap();
}

#[test]
fn store_unfinalized_rows_are_not_protected() {
    let mut db = Db::new();
    db.tail(100, 120, &[burn_event(6, "0xa", 0, 105, 1)]);
    let raw = db.raw();
    raw.execute("UPDATE burns SET amount = 5", []).unwrap();
    raw.execute("DELETE FROM burns", []).unwrap();
}

#[test]
fn store_upsert_preserves_attestation_columns() {
    let mut db = Db::new();
    let ev = burn_event(6, "0xa", 0, 105, 7);
    db.tail(100, 120, std::slice::from_ref(&ev));
    db.raw()
        .execute(
            "UPDATE burns SET nonce = randomblob(32), attestation_status = 'complete',
                 fee_executed = 4, finality_threshold_executed = 2000, delay_reason = 'x',
                 iris_destination_tx = 'dest', attested_at = 5, last_polled_at = 6,
                 next_poll_at = 7, poll_count = 8",
            [],
        )
        .unwrap();
    let before = dump(&db.raw(), "burns");
    // Same tail applied again, then promoted to final: attestation stays.
    db.tail(100, 120, std::slice::from_ref(&ev));
    assert_eq!(dump(&db.raw(), "burns"), before);
    db.fin(100, 120, std::slice::from_ref(&ev));
    let after = dump(&db.raw(), "burns");
    let row = &after[0];
    let ci = |name: &str| -> usize {
        let raw = db.raw();
        let stmt = raw.prepare("SELECT * FROM burns").unwrap();
        stmt.column_names().position(|c| c == name).unwrap()
    };
    assert_eq!(row[ci("attestation_status")], "complete");
    assert_eq!(row[ci("fee_executed")], "4");
    assert_eq!(row[ci("poll_count")], "8");
    assert_eq!(row[ci("iris_destination_tx")], "dest");
    assert_eq!(row[ci("finalized")], "1");
}

#[test]
fn store_replay_is_idempotent() {
    let mut db = Db::new();
    let events = [
        burn_event(6, "0xa", 0, 105, 1),
        burn_event(6, "0xa", 1, 105, 2),
        receive_event(6, "0xr", 3, 110, 9, 5),
    ];
    let s1 = db.tail(100, 120, &events);
    assert_eq!(
        s1,
        ApplyStats {
            upserted: 3,
            ..Default::default()
        }
    );
    let dump1 = (dump(&db.raw(), "burns"), dump(&db.raw(), "receives"));
    let s2 = db.tail(100, 120, &events);
    assert_eq!(s2.upserted, 3);
    assert_eq!(s2.rolled_back, 0);
    let dump2 = (dump(&db.raw(), "burns"), dump(&db.raw(), "receives"));
    assert_eq!(dump1, dump2);

    // A Final scope over rows first stored by the tail promotes them in place.
    let ids_before: Vec<String> = dump2.0.iter().map(|r| r[0].clone()).collect();
    let s3 = db.fin(100, 120, &events);
    assert_eq!(s3.promoted, 3);
    assert_eq!(s3.upserted, 3);
    assert_eq!(db.cursor(BASE), 120);
    let burns = dump(&db.raw(), "burns");
    assert_eq!(burns.len(), 2);
    assert_eq!(
        burns.iter().map(|r| r[0].clone()).collect::<Vec<_>>(),
        ids_before
    );
    assert_eq!(
        db.count("SELECT COUNT(*) FROM burns WHERE finalized = 1"),
        2
    );
    assert_eq!(
        db.count("SELECT COUNT(*) FROM receives WHERE finalized = 1"),
        1
    );
    assert_eq!(db.count("SELECT COUNT(*) FROM rollbacks"), 0);
}

#[test]
fn store_cursor_compare_and_swap() {
    let mut db = Db::new();
    let err = db
        .store
        .apply_scan(
            BASE,
            Scope::Final {
                after: 90,
                through: 110,
            },
            &[],
            NOW,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        StoreError::CursorMoved {
            domain: 6,
            expected: 90,
            found: 100
        }
    ));
    assert_eq!(db.cursor(BASE), 100);

    db.fin(100, 110, &[]);
    assert_eq!(db.cursor(BASE), 110);
    // Replaying a finished scope is a stale writer.
    let err = db
        .store
        .apply_scan(
            BASE,
            Scope::Final {
                after: 100,
                through: 110,
            },
            &[],
            NOW,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        StoreError::CursorMoved {
            expected: 100,
            found: 110,
            ..
        }
    ));
}

#[test]
fn store_scope_preconditions() {
    let mut db = Db::new();
    let ok = burn_event(6, "0xa", 0, 105, 1);
    let cases: Vec<(Scope, Vec<_>)> = vec![
        // Event at or below `after`, and above `through`.
        (
            Scope::Tail {
                after: 100,
                through: 120,
            },
            vec![burn_event(6, "0xb", 0, 100, 1)],
        ),
        (
            Scope::Tail {
                after: 100,
                through: 120,
            },
            vec![burn_event(6, "0xb", 0, 121, 1)],
        ),
        // Wrong domain.
        (
            Scope::Tail {
                after: 100,
                through: 120,
            },
            vec![burn_event(5, "0xb", 0, 105, 1)],
        ),
        // Duplicate key.
        (
            Scope::Tail {
                after: 100,
                through: 120,
            },
            vec![ok.clone(), ok.clone()],
        ),
        // Empty or inverted scope.
        (
            Scope::Tail {
                after: 120,
                through: 120,
            },
            vec![],
        ),
        (
            Scope::Final {
                after: 100,
                through: 90,
            },
            vec![],
        ),
        // Tail below the cursor.
        (
            Scope::Tail {
                after: 99,
                through: 120,
            },
            vec![],
        ),
    ];
    for (scope, events) in cases {
        let err = db.store.apply_scan(BASE, scope, &events, NOW).unwrap_err();
        assert!(matches!(err, StoreError::Scope(_)), "{scope:?}: {err}");
    }
    // Nothing was written and the cursor did not move.
    assert_eq!(db.count("SELECT COUNT(*) FROM burns"), 0);
    assert_eq!(db.count("SELECT COUNT(*) FROM rollbacks"), 0);
    assert_eq!(db.cursor(BASE), 100);
}

#[test]
fn store_failed_scan_writes_nothing() {
    let mut db = Db::new();
    // The second event is invalid, so the first must not be stored either.
    let events = [
        burn_event(6, "0xa", 0, 105, 1),
        burn_event(6, "0xb", 0, 500, 1),
    ];
    assert!(
        db.store
            .apply_scan(
                BASE,
                Scope::Tail {
                    after: 100,
                    through: 120
                },
                &events,
                NOW
            )
            .is_err()
    );
    assert_eq!(db.count("SELECT COUNT(*) FROM burns"), 0);
    // An amount that cannot be stored aborts the whole transaction.
    let mut big = burn_event(6, "0xc", 0, 106, 1);
    if let bridge_watcher::domain::EventKind::Burn(b) = &mut big.kind {
        b.amount = u64::MAX;
    }
    let events = [burn_event(6, "0xa", 0, 105, 1), big];
    assert!(
        db.store
            .apply_scan(
                BASE,
                Scope::Final {
                    after: 100,
                    through: 120
                },
                &events,
                NOW
            )
            .is_err()
    );
    assert_eq!(db.count("SELECT COUNT(*) FROM burns"), 0);
    assert_eq!(db.cursor(BASE), 100);
}

#[test]
fn store_tail_scope_deletes_unseen_unfinalized_rows() {
    let mut db = Db::new();
    let a = burn_event(6, "0xa", 0, 105, 1);
    let b = burn_event(6, "0xb", 2, 110, 2);
    let r = receive_event(6, "0xr", 1, 111, 9, 3);
    db.tail(100, 120, &[a.clone(), b.clone(), r]);
    // The next scan of the same range returns only `b`.
    let stats = db.tail(100, 120, std::slice::from_ref(&b));
    assert_eq!(stats.rolled_back, 2);
    assert_eq!(db.count("SELECT COUNT(*) FROM burns"), 1);
    assert_eq!(db.count("SELECT COUNT(*) FROM receives"), 0);
    let rollbacks = dump(&db.raw(), "rollbacks");
    assert_eq!(rollbacks.len(), 2);
    // columns: id, domain, event_type, tx_id, event_index, height, block_hash, scope, detected_at
    assert_eq!(
        rollbacks[0][1..],
        [
            "6",
            "burn",
            "0xa",
            "0",
            "105",
            "0xhash105",
            "tail",
            "1800000000"
        ]
    );
    assert_eq!(rollbacks[1][2], "receive");
    assert_eq!(rollbacks[1][7], "tail");
}

#[test]
fn store_final_scope_deletes_unseen_unfinalized() {
    let mut db = Db::new();
    db.tail(
        100,
        120,
        &[
            burn_event(6, "0xa", 0, 105, 1),
            burn_event(6, "0xb", 0, 115, 2),
        ],
    );
    // The finalized scan of (100, 110] does not contain `a`: it was reorged out.
    let stats = db.fin(100, 110, &[]);
    assert_eq!(stats.rolled_back, 1);
    assert_eq!(db.cursor(BASE), 110);
    // `b` is above the new cursor and stays unfinalized (I2).
    assert_eq!(
        db.count("SELECT COUNT(*) FROM burns WHERE tx_id = '0xb' AND finalized = 0"),
        1
    );
    assert_eq!(
        db.count("SELECT COUNT(*) FROM burns WHERE tx_id = '0xa'"),
        0
    );
    let rollbacks = dump(&db.raw(), "rollbacks");
    assert_eq!(rollbacks.len(), 1);
    assert_eq!(rollbacks[0][7], "final");
    // I2: no unfinalized row at or below the cursor.
    assert_eq!(
        db.count("SELECT COUNT(*) FROM burns WHERE finalized = 0 AND height <= 110"),
        0
    );
}

#[test]
fn store_tail_scope_ignores_rows_outside_scope() {
    let mut db = Db::new();
    db.tail(
        100,
        140,
        &[
            burn_event(6, "0xa", 0, 105, 1),
            burn_event(6, "0xz", 0, 130, 2),
        ],
    );
    let stats = db.tail(100, 120, &[]);
    assert_eq!(stats.rolled_back, 1);
    assert_eq!(
        db.count("SELECT COUNT(*) FROM burns WHERE tx_id = '0xz'"),
        1
    );
}

#[test]
fn store_scope_ignores_other_chains() {
    let mut db = Db::new();
    db.store.init_cursor(SOLANA, "solana", 100, 0, NOW).unwrap();
    db.store
        .apply_scan(
            SOLANA,
            Scope::Tail {
                after: 100,
                through: 120,
            },
            &[burn_event(5, "sig", 0, 105, 1)],
            NOW,
        )
        .unwrap();
    // A Base scan over the same heights must not touch Solana rows.
    db.tail(100, 120, &[]);
    assert_eq!(
        db.count("SELECT COUNT(*) FROM burns WHERE source_domain = 5"),
        1
    );
}

#[test]
fn store_same_key_at_new_height_updates_row() {
    let mut db = Db::new();
    db.tail(100, 120, &[burn_event(6, "0xa", 3, 105, 1)]);
    let id: i64 = db.count("SELECT id FROM burns");
    // Re-included in a later block: same key, new height, no rollback.
    let stats = db.tail(100, 120, &[burn_event(6, "0xa", 3, 107, 1)]);
    assert_eq!(stats.rolled_back, 0);
    assert_eq!(db.count("SELECT height FROM burns"), 107);
    assert_eq!(db.count("SELECT id FROM burns"), id);
    assert_eq!(db.count("SELECT COUNT(*) FROM rollbacks"), 0);
}

#[test]
fn store_final_row_is_never_moved_by_a_conflicting_event() {
    let mut db = Db::new();
    db.fin(100, 120, &[burn_event(6, "0xa", 0, 105, 1)]);
    let before = dump(&db.raw(), "burns");
    let stats = db.fin(120, 130, &[burn_event(6, "0xa", 0, 125, 1)]);
    assert_eq!(stats.final_conflicts, 1);
    assert_eq!(stats.upserted, 0);
    assert_eq!(dump(&db.raw(), "burns"), before);
    assert_eq!(db.cursor(BASE), 130);
}

#[test]
fn store_vanished_id_update_is_noop() {
    let mut db = Db::new();
    db.tail(100, 120, &[burn_event(6, "0xa", 0, 105, 1)]);
    let old_id = db.count("SELECT id FROM burns");
    db.tail(100, 120, &[burn_event(6, "0xb", 0, 106, 2)]);
    assert_eq!(
        db.count("SELECT COUNT(*) FROM burns WHERE tx_id = '0xa'"),
        0
    );
    let new_id = db.count("SELECT id FROM burns");
    assert!(new_id > old_id, "ids must never be reused");
    let changed = db
        .raw()
        .execute(
            "UPDATE burns SET attestation_status = 'complete', nonce = zeroblob(32) WHERE id = ?1",
            [old_id],
        )
        .unwrap();
    assert_eq!(changed, 0);
    assert_eq!(
        db.count("SELECT COUNT(*) FROM burns WHERE nonce IS NOT NULL"),
        0
    );
}

#[test]
fn store_chain_state_bookkeeping() {
    let mut db = Db::new();
    db.store
        .record_heights(
            BASE,
            Heights {
                finalized: 130,
                head: 400,
            },
            NOW + 1,
        )
        .unwrap();
    db.store.mark_caught_up(BASE, 400, NOW + 2).unwrap();
    assert_eq!(db.count("SELECT observed_finalized FROM chain_state"), 130);
    assert_eq!(db.count("SELECT observed_head FROM chain_state"), 400);
    assert_eq!(db.count("SELECT scanned_head FROM chain_state"), 400);
    assert_eq!(db.count("SELECT caught_up_at FROM chain_state"), NOW + 2);
    assert_eq!(
        db.store.cursor(BASE).unwrap().unwrap().scanned_head,
        Some(400)
    );
    // No cursor, no bookkeeping.
    assert!(matches!(
        db.store.record_heights(
            SOLANA,
            Heights {
                finalized: 1,
                head: 2
            },
            NOW
        ),
        Err(StoreError::NoCursor { domain: 5 })
    ));
    assert!(matches!(
        db.store.mark_caught_up(SOLANA, 2, NOW),
        Err(StoreError::NoCursor { domain: 5 })
    ));
}

#[test]
fn store_init_cursor_is_idempotent() {
    let mut db = Db::new();
    let again = db.store.init_cursor(BASE, "base", 999, 0, NOW + 5).unwrap();
    assert_eq!((again.start_height, again.final_height), (101, 100));
    assert!(matches!(
        db.store.init_cursor(BASE, "other", 100, 0, NOW),
        Err(StoreError::ConfigMismatch(_))
    ));
    assert!(db.store.cursor(SOLANA).unwrap().is_none());
    // A backfill start of h gives final_height = h - 1.
    let c = db.store.init_cursor(SOLANA, "solana", 41, 0, NOW).unwrap();
    assert_eq!((c.start_height, c.final_height), (42, 41));
}

#[test]
fn store_record_health_counts_failures() {
    let mut db = Db::new();
    db.store.record_health("ingest:base", Ok(()), 10).unwrap();
    db.store
        .record_health("ingest:base", Err("boom"), 20)
        .unwrap();
    db.store
        .record_health("ingest:base", Err("boom2"), 30)
        .unwrap();
    let row = dump(&db.raw(), "health").remove(0).clone();
    // component, started_at, last_ok_at, last_error, last_error_at, consecutive_failures
    assert_eq!(row[1..], ["10", "10", "boom2", "30", "2"]);
    db.store.record_health("ingest:base", Ok(()), 40).unwrap();
    let row = dump(&db.raw(), "health").remove(0).clone();
    assert_eq!(row[1..], ["10", "40", "boom2", "30", "0"]);
}

#[test]
fn store_start_components_resets_run() {
    let mut db = Db::new();
    db.store.record_health("ingest:base", Ok(()), 10).unwrap();
    for t in 20..25 {
        db.store
            .record_health("ingest:base", Err("boom"), t)
            .unwrap();
    }
    db.store.record_health("old:gone", Ok(()), 10).unwrap();
    let row = dump(&db.raw(), "health").remove(0);
    // component, started_at, last_ok_at, last_error, last_error_at, consecutive_failures
    assert_eq!(row[1..], ["10", "10", "boom", "24", "5"]);

    db.store
        .start_components(&["ingest:base", "resolver"], 1000)
        .unwrap();
    let rows = dump(&db.raw(), "health");
    assert_eq!(rows.len(), 2, "the unlisted row is deleted: {rows:?}");
    assert_eq!(rows[0][0], "ingest:base");
    assert_eq!(rows[0][1..], ["1000", "10", "boom", "24", "0"]);
    assert_eq!(rows[1][0], "resolver");
    assert_eq!(rows[1][1..], ["1000", "NULL", "NULL", "NULL", "0"]);

    // A later record_health never changes started_at.
    db.store
        .record_health("ingest:base", Err("again"), 1100)
        .unwrap();
    db.store.record_health("resolver", Ok(()), 1200).unwrap();
    let rows = dump(&db.raw(), "health");
    assert_eq!(rows[0][1..], ["1000", "10", "again", "1100", "1"]);
    assert_eq!(rows[1][1..], ["1000", "1200", "NULL", "NULL", "0"]);

    // An empty list clears the table.
    db.store.start_components(&[], 2000).unwrap();
    assert!(dump(&db.raw(), "health").is_empty());
}

#[test]
fn store_rejects_old_schema_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.db");
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 1)
        .unwrap();
    let err = Store::open(&path).err().expect("version 1 is rejected");
    assert!(matches!(err, StoreError::SchemaVersion(1)), "{err:?}");
    let text = err.to_string();
    assert!(text.contains("delete the database file"), "{text}");
    assert!(text.contains("no migration from version 1"), "{text}");
    assert!(matches!(
        Store::open_read_only(&path),
        Err(StoreError::SchemaVersion(1))
    ));
    // A new file gets version 2.
    let fresh = dir.path().join("new.db");
    drop(Store::open(&fresh).unwrap());
    let v: i64 = Connection::open(&fresh)
        .unwrap()
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(v, 2);
}

#[test]
fn store_rejects_unknown_schema_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v7.db");
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 7)
        .unwrap();
    assert!(matches!(
        Store::open(&path),
        Err(StoreError::SchemaVersion(7))
    ));
    assert!(matches!(
        Store::open_read_only(&path),
        Err(StoreError::SchemaVersion(7))
    ));
}

#[test]
fn store_reopen_keeps_data_and_read_only_cannot_write() {
    let mut db = Db::new();
    db.fin(100, 110, &[burn_event(6, "0xa", 0, 105, 1)]);
    let path = db.path.clone();
    drop(db.store);
    let reopened = Store::open(&path).unwrap();
    assert_eq!(reopened.cursor(BASE).unwrap().unwrap().final_height, 110);
    let ro = Store::open_read_only(&path).unwrap();
    assert_eq!(
        ro.list_transfers(&TransferFilter {
            state: None,
            limit: 10
        })
        .unwrap()
        .len(),
        1
    );
    assert!(Store::open_read_only(&path.with_file_name("missing.db")).is_err());
}

#[test]
fn transfers_view_states() {
    let mut db = Db::new();
    db.store.init_cursor(SOLANA, "solana", 40, 0, NOW).unwrap();
    // Three Base burns: completed (nonce 9), attested (nonce 7), burned.
    db.tail(
        100,
        200,
        &[
            burn_event(6, "0xdone", 0, 105, 10),
            burn_event(6, "0xatt", 0, 110, 20),
            burn_event(6, "0xnew", 0, 115, 30),
        ],
    );
    db.store
        .apply_scan(
            SOLANA,
            Scope::Tail {
                after: 40,
                through: 300,
            },
            &[receive_event(5, "sigR", 0, 205, 9, 10)],
            NOW,
        )
        .unwrap();
    let raw = db.raw();
    raw.execute(
        "UPDATE burns SET nonce = x'0909090909090909090909090909090909090909090909090909090909090909',
            attestation_status = 'complete' WHERE tx_id = '0xdone'",
        [],
    )
    .unwrap();
    raw.execute(
        "UPDATE burns SET nonce = x'0707070707070707070707070707070707070707070707070707070707070707',
            attestation_status = 'complete' WHERE tx_id = '0xatt'",
        [],
    )
    .unwrap();

    let all = db
        .store
        .list_transfers(&TransferFilter {
            state: None,
            limit: 10,
        })
        .unwrap();
    // Newest burn first.
    assert_eq!(
        all.iter().map(|t| t.burn_tx.as_str()).collect::<Vec<_>>(),
        ["0xnew", "0xatt", "0xdone"]
    );
    let by_tx = |tx: &str| all.iter().find(|t| t.burn_tx == tx).unwrap();
    let done = by_tx("0xdone");
    assert_eq!(done.state, TransferState::Completed);
    assert_eq!(done.receive_tx.as_deref(), Some("sigR"));
    // Receive chain time 1_700_000_205, burn chain time 1_700_000_105.
    assert_eq!(done.latency_secs, Some(100));
    assert_eq!(done.amount, 10);
    assert_eq!(done.mode, Mode::Standard);
    assert!(!done.burn_finalized);
    assert_eq!(done.receive_finalized, Some(false));
    assert_eq!(by_tx("0xatt").state, TransferState::Attested);
    assert_eq!(by_tx("0xatt").latency_secs, None);
    assert_eq!(by_tx("0xnew").state, TransferState::Burned);
    assert!(by_tx("0xnew").nonce.is_none());

    let only = |s| {
        db.store
            .list_transfers(&TransferFilter {
                state: Some(s),
                limit: 10,
            })
            .unwrap()
    };
    assert_eq!(only(TransferState::Attested).len(), 1);
    assert_eq!(only(TransferState::Burned).len(), 1);
    assert_eq!(only(TransferState::Completed).len(), 1);
    assert_eq!(
        db.store
            .list_transfers(&TransferFilter {
                state: None,
                limit: 2
            })
            .unwrap()
            .len(),
        2
    );

    // A rollback of the receive un-matches the transfer (ADR 0008).
    db.store
        .apply_scan(
            SOLANA,
            Scope::Tail {
                after: 40,
                through: 300,
            },
            &[],
            NOW,
        )
        .unwrap();
    let after = db
        .store
        .list_transfers(&TransferFilter {
            state: None,
            limit: 10,
        })
        .unwrap();
    assert_eq!(
        after.iter().find(|t| t.burn_tx == "0xdone").unwrap().state,
        TransferState::Attested
    );
}

#[test]
fn store_status_report() {
    let mut db = Db::new();
    db.store
        .record_heights(
            BASE,
            Heights {
                finalized: 130,
                head: 400,
            },
            NOW,
        )
        .unwrap();
    db.store
        .record_health("ingest:base", Err("rpc down"), NOW)
        .unwrap();
    db.tail(100, 120, &[burn_event(6, "0xa", 0, 105, 1)]);
    db.raw()
        .execute_batch(
            "INSERT INTO alerts (kind, subject, severity, message, first_seen_at, opened_at, last_seen_at)
             VALUES ('k', 's1', 'warning', 'm', 1, 1, 1), ('k', 's2', 'critical', 'm', 1, 1, 1);
             INSERT INTO alerts (kind, subject, severity, message, first_seen_at, opened_at, last_seen_at, resolved_at)
             VALUES ('k', 's3', 'info', 'm', 1, 1, 1, 2);",
        )
        .unwrap();
    let report = db.store.status_report(NOW + 10).unwrap();
    assert_eq!(report.now, NOW + 10);
    assert_eq!(report.chains.len(), 1);
    let chain = &report.chains[0];
    assert_eq!((chain.name.as_str(), chain.domain), ("base", BASE));
    assert_eq!(chain.final_height, 100);
    assert_eq!(chain.cursor_lag, Some(30));
    assert_eq!(chain.observed_head, Some(400));
    assert_eq!(
        chain.health.as_ref().unwrap().last_error.as_deref(),
        Some("rpc down")
    );
    assert_eq!(
        (report.burned, report.attested, report.completed),
        (1, 0, 0)
    );
    assert_eq!(
        (
            report.open_alerts.info,
            report.open_alerts.warning,
            report.open_alerts.critical
        ),
        (0, 1, 1)
    );
}

#[tokio::test]
async fn store_shared_store_runs_on_blocking_pool() {
    let shared = SharedStore::from_store(Store::open_in_memory().unwrap());
    let cursor = shared
        .run(|s| s.init_cursor(BASE, "base", 5, 0, NOW))
        .await
        .unwrap();
    assert_eq!(cursor.final_height, 5);
    let clone = shared.clone();
    let got = clone.run(|s| s.cursor(BASE)).await.unwrap();
    assert_eq!(got.unwrap().start_height, 6);

    // A panic in a closure is reported as Panicked, never propagated.
    let err = shared
        .run(|_s| -> Result<(), StoreError> { panic!("boom") })
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Panicked));
    // The mutex is poisoned afterwards; later calls fail the same way.
    assert!(matches!(
        shared.run(|s| s.cursor(BASE)).await,
        Err(StoreError::Panicked)
    ));
}

#[test]
fn store_upsert_preserves_receive_lookup_columns() {
    let mut db = Db::new();
    let ev = receive_event(6, "0xr", 0, 105, 9, 5);
    db.tail(100, 120, std::slice::from_ref(&ev));
    db.raw()
        .execute(
            "UPDATE receives SET source_lookup = 'unknown_to_iris', source_lookup_count = 2,
                 next_lookup_at = 77, iris_source_tx = 'srctx'",
            [],
        )
        .unwrap();
    let before = dump(&db.raw(), "receives");
    db.tail(100, 120, std::slice::from_ref(&ev));
    assert_eq!(dump(&db.raw(), "receives"), before);
    // Promotion to final keeps them too.
    db.fin(100, 120, std::slice::from_ref(&ev));
    assert_eq!(db.count("SELECT source_lookup_count FROM receives"), 2);
    assert_eq!(db.count("SELECT next_lookup_at FROM receives"), 77);
    assert_eq!(db.count("SELECT finalized FROM receives"), 1);
    assert_eq!(
        db.raw()
            .query_row("SELECT iris_source_tx FROM receives", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        "srctx"
    );
}

#[test]
fn store_final_receive_is_never_moved_by_a_conflicting_event() {
    let mut db = Db::new();
    db.fin(100, 120, &[receive_event(6, "0xr", 0, 105, 9, 5)]);
    let before = dump(&db.raw(), "receives");
    let stats = db.fin(120, 130, &[receive_event(6, "0xr", 0, 125, 9, 5)]);
    assert_eq!(stats.final_conflicts, 1);
    assert_eq!(stats.upserted, 0);
    assert_eq!(dump(&db.raw(), "receives"), before);
}

#[test]
fn store_no_cursor_error() {
    let mut db = Db::new();
    for scope in [
        Scope::Tail {
            after: 0,
            through: 10,
        },
        Scope::Final {
            after: 0,
            through: 10,
        },
    ] {
        let err = db.store.apply_scan(SOLANA, scope, &[], NOW).unwrap_err();
        assert!(matches!(err, StoreError::NoCursor { domain: 5 }), "{err}");
    }
    assert_eq!(db.count("SELECT COUNT(*) FROM chain_state"), 1);
}

fn transfer_state(db: &Db, tx: &str) -> String {
    db.raw()
        .query_row(
            "SELECT state FROM transfers WHERE burn_tx = ?1",
            [tx],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn transfers_view_pre_window_state() {
    let mut db = Db::new();
    // Base burn at height 105 has block_time 1_700_000_105.
    let burn_time = 1_700_000_105i64;
    db.store
        .init_cursor(SOLANA, "solana", 40, burn_time - 59, NOW)
        .unwrap();
    db.tail(100, 200, &[burn_event(6, "0xb", 0, 105, 10)]);
    let raw = db.raw();
    raw.execute(
        "UPDATE burns SET nonce = x'0909090909090909090909090909090909090909090909090909090909090909',
            attestation_status = 'complete'",
        [],
    )
    .unwrap();
    // The destination window starts 59 s before the burn: inside the margin.
    assert_eq!(transfer_state(&db, "0xb"), "pre_window");
    // 60 s before the burn: covered, so the burn is simply attested.
    raw.execute(
        "UPDATE chain_state SET start_time = ?1 WHERE domain = 5",
        [burn_time - 60],
    )
    .unwrap();
    assert_eq!(transfer_state(&db, "0xb"), "attested");
    // A burn that is not attested yet is `burned`, whatever the window.
    raw.execute(
        "UPDATE chain_state SET start_time = ?1 WHERE domain = 5",
        [burn_time + 1000],
    )
    .unwrap();
    raw.execute("UPDATE burns SET attestation_status = 'pending'", [])
        .unwrap();
    assert_eq!(transfer_state(&db, "0xb"), "burned");
    raw.execute("UPDATE burns SET attestation_status = 'complete'", [])
        .unwrap();
    assert_eq!(transfer_state(&db, "0xb"), "pre_window");

    // A receive that shows up later inside the window completes it.
    db.store
        .apply_scan(
            SOLANA,
            Scope::Tail {
                after: 40,
                through: 300,
            },
            &[receive_event(5, "sigR", 0, 205, 9, 10)],
            NOW,
        )
        .unwrap();
    assert_eq!(transfer_state(&db, "0xb"), "completed");

    // The status report and the filter know the state.
    raw.execute("DELETE FROM receives WHERE tx_id = 'sigR'", [])
        .unwrap();
    assert_eq!(db.store.status_report(NOW).unwrap().pre_window, 1);
    let rows = db
        .store
        .list_transfers(&TransferFilter {
            state: Some(TransferState::PreWindow),
            limit: 10,
        })
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, TransferState::PreWindow);
}

#[test]
fn coverage_margin_matches_view_literal() {
    let schema = include_str!("../src/store/schema.sql");
    let needle = "b.block_time < d.start_time + ";
    let at = schema
        .find(needle)
        .expect("pre_window condition in the view");
    let literal: String = schema[at + needle.len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    assert_eq!(
        literal.parse::<i64>().unwrap(),
        bridge_watcher::store::COVERAGE_MARGIN_SECS
    );
}

#[test]
fn start_time_is_stable_across_restart() {
    let mut db = Db::new();
    let first = db
        .store
        .init_cursor(SOLANA, "solana", 500, 1_234, NOW)
        .unwrap();
    assert_eq!((first.start_height, first.start_time), (501, 1_234));

    // Same process: later values are ignored.
    let again = db
        .store
        .init_cursor(SOLANA, "solana", 900, 9_999, NOW + 1)
        .unwrap();
    assert_eq!((again.start_height, again.start_time), (501, 1_234));

    // After a restart (reopen the file), even another config start is ignored.
    let mut reopened = Store::open(&db.path).unwrap();
    let c = reopened
        .init_cursor(SOLANA, "solana", 1_000, 5_555, NOW + 2)
        .unwrap();
    assert_eq!((c.start_height, c.start_time), (501, 1_234));
    assert_eq!(reopened.cursor(SOLANA).unwrap().unwrap().start_time, 1_234);
}
