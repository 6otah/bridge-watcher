//! Monitor checks (design section 15.5). Most checks run through the pure
//! `evaluate` on hand-built snapshots; the SQL-filtered checks (mismatch,
//! duplicate, orphan, latency window) run on a real in-memory store.

mod common;

use bridge_watcher::config::MonitorConfig;
use bridge_watcher::domain::{Bytes32, ChainEvent, Domain, EventKind, Mode};
use bridge_watcher::monitor::{
    ALL_KINDS, Monitor, Severity, evaluate as evaluate_full, latency_upper_bound,
};
use bridge_watcher::store::{
    AlertCondition, AttestedBurnRow, BurnPollUpdate, Candidates, ChainLimits, ChainSnapshot,
    DuplicateRow, HealthRow, IrisObservation, LatencySample, MismatchRow, MonitorSnapshot,
    OrphanRow, PendingBurnRow, RollbackRow, Scope, SharedStore, SnapshotLimits, SourceLookup,
    Store,
};
use common::{burn_event, receive_event};

const BASE: Domain = Domain(6);
const SOLANA: Domain = Domain(5);
const NOW: i64 = 1_800_000_000;

fn cfg() -> MonitorConfig {
    MonitorConfig::default()
}

fn limits() -> SnapshotLimits {
    SnapshotLimits {
        chains: vec![
            ChainLimits {
                domain: BASE,
                sla_fast_secs: 300,
                sla_standard_secs: 3600,
                finality_lag_alert: 9000,
            },
            ChainLimits {
                domain: SOLANA,
                sla_fast_secs: 120,
                sla_standard_secs: 300,
                finality_lag_alert: 150,
            },
        ],
        ..SnapshotLimits::default()
    }
}

fn empty(now: i64) -> MonitorSnapshot {
    MonitorSnapshot {
        now,
        limits: limits(),
        chains: vec![],
        health: vec![],
        delayed_burns: Candidates::default(),
        unclaimed_burns: Candidates::default(),
        orphan_receives: Candidates::default(),
        mismatched_pairs: Candidates::default(),
        duplicate_nonces: Candidates::default(),
        recent_completed: Candidates::default(),
        latency_baseline: vec![],
        recent_rollbacks: Candidates::default(),
    }
}

/// Test helper: a completed transfer is both a candidate and a baseline
/// sample.
trait PushLat {
    fn push_lat(&mut self, sample: LatencySample);
}

impl PushLat for MonitorSnapshot {
    fn push_lat(&mut self, sample: LatencySample) {
        self.recent_completed.rows.push(sample.clone());
        self.latency_baseline.push(sample);
    }
}

/// The conditions of the full evaluation.
fn evaluate(s: &MonitorSnapshot, cfg: &MonitorConfig) -> Vec<AlertCondition> {
    evaluate_full(s, cfg).conditions
}

fn kinds(conds: &[AlertCondition]) -> Vec<&'static str> {
    conds.iter().map(|c| c.kind).collect()
}

fn nonce(b: u8) -> Bytes32 {
    Bytes32([b; 32])
}

fn pending(source: Domain, threshold: u32, block_time: i64, polled: i64) -> PendingBurnRow {
    PendingBurnRow {
        source_domain: source,
        tx_id: "0xburn".to_string(),
        event_index: 3,
        block_time,
        min_finality_threshold: threshold,
        last_polled_at: polled,
    }
}

fn chain(domain: Domain, name: &str) -> ChainSnapshot {
    ChainSnapshot {
        domain,
        name: name.to_string(),
        observed_finalized: Some(1000),
        observed_head: Some(1010),
        caught_up_at: Some(NOW),
        start_time: 0,
    }
}

fn health(component: &str, started_at: i64, last_ok_at: Option<i64>) -> HealthRow {
    HealthRow {
        component: component.to_string(),
        started_at,
        last_ok_at,
        last_error: None,
        last_error_at: None,
        consecutive_failures: 0,
    }
}

// ---------------------------------------------------------------------------
// latency_upper_bound
// ---------------------------------------------------------------------------

#[test]
fn latency_bound_is_median_plus_scaled_mad() {
    // median 1020, deviations 20,10,0,10,20 -> MAD 10 -> 6 * 1.4826 * 10 = 88.9 -> 89
    let s = [1000, 1010, 1020, 1030, 1040];
    assert_eq!(latency_upper_bound(&s, 6.0, 5, 0), Some(1020 + 89));
    // The floor wins when the scaled MAD is smaller.
    assert_eq!(latency_upper_bound(&s, 6.0, 5, 500), Some(1520));
}

#[test]
fn latency_bound_needs_enough_samples() {
    assert_eq!(latency_upper_bound(&[], 6.0, 0, 120), None);
    assert_eq!(latency_upper_bound(&[5; 19], 6.0, 20, 120), None);
    assert_eq!(latency_upper_bound(&[5; 20], 6.0, 20, 120), Some(125));
}

#[test]
fn latency_bound_even_count_uses_the_middle_pair() {
    assert_eq!(latency_upper_bound(&[10, 20, 30, 40], 0.0, 1, 0), Some(25));
}

#[test]
fn latency_bound_is_robust_to_an_outlier() {
    let mut s = vec![100; 30];
    s.push(1_000_000);
    assert_eq!(latency_upper_bound(&s, 6.0, 20, 120), Some(220));
}

// ---------------------------------------------------------------------------
// Pure checks
// ---------------------------------------------------------------------------

#[test]
fn check_attestation_delayed() {
    let mut s = empty(NOW);
    // Base Standard: SLA 3600.
    s.delayed_burns
        .rows
        .push(pending(BASE, 2000, 1000, 1000 + 3600));
    assert!(evaluate(&s, &cfg()).is_empty(), "equal to the SLA is fine");
    s.delayed_burns.rows[0].last_polled_at = 1000 + 3601;
    let c = evaluate(&s, &cfg());
    assert_eq!(kinds(&c), ["attestation_delayed"]);
    assert_eq!(c[0].subject, "burn:6:0xburn:3");
    assert_eq!(c[0].severity, Severity::Warning);

    // Base Fast: SLA 300.
    s.delayed_burns = Candidates::of(vec![pending(BASE, 1000, 1000, 1000 + 301)]);
    assert_eq!(kinds(&evaluate(&s, &cfg())), ["attestation_delayed"]);
    s.delayed_burns = Candidates::of(vec![pending(BASE, 1000, 1000, 1000 + 300)]);
    assert!(evaluate(&s, &cfg()).is_empty());

    // Solana: Standard 300, Fast 120.
    s.delayed_burns = Candidates::of(vec![pending(SOLANA, 2000, 1000, 1000 + 301)]);
    assert_eq!(kinds(&evaluate(&s, &cfg())), ["attestation_delayed"]);
    s.delayed_burns = Candidates::of(vec![pending(SOLANA, 1000, 1000, 1000 + 121)]);
    assert_eq!(kinds(&evaluate(&s, &cfg())), ["attestation_delayed"]);
    s.delayed_burns = Candidates::of(vec![pending(SOLANA, 1000, 1000, 1000 + 119)]);
    assert!(evaluate(&s, &cfg()).is_empty());

    // A chain without limits is not judged.
    s.limits.chains.clear();
    s.delayed_burns = Candidates::of(vec![pending(BASE, 2000, 0, 1_000_000)]);
    assert!(evaluate(&s, &cfg()).is_empty());
}

fn attested(attested_at: i64) -> AttestedBurnRow {
    AttestedBurnRow {
        source_domain: BASE,
        destination_domain: SOLANA,
        nonce: nonce(7),
        attested_at,
        burn_time: attested_at.max(1000),
    }
}

/// Only the `unclaimed` conditions; a stale `caught_up_at` also raises
/// `ingestion_lagging`, which is not under test here.
fn unclaimed(s: &MonitorSnapshot) -> Vec<AlertCondition> {
    evaluate(s, &cfg())
        .into_iter()
        .filter(|c| c.kind == "unclaimed")
        .collect()
}

#[test]
fn check_unclaimed() {
    let mut s = empty(NOW);
    let mut dest = chain(SOLANA, "solana");
    s.unclaimed_burns.rows.push(attested(10_000));
    dest.caught_up_at = Some(10_000 + 3600);
    s.chains = vec![dest.clone()];
    assert!(unclaimed(&s).is_empty(), "equal to the limit is fine");
    dest.caught_up_at = Some(10_000 + 3601);
    s.chains = vec![dest];
    let c = unclaimed(&s);
    assert_eq!(kinds(&c), ["unclaimed"]);
    assert_eq!(c[0].subject, format!("nonce:6:0x{}", "07".repeat(32)));
    assert_eq!(c[0].severity, Severity::Warning);
}

#[test]
fn check_unclaimed_suppressed_while_destination_lags() {
    let mut s = empty(NOW);
    s.unclaimed_burns.rows.push(attested(NOW - 7200));
    let mut dest = chain(SOLANA, "solana");
    // The destination was last caught up before the deadline: no evidence.
    dest.caught_up_at = Some(NOW - 7200 + 100);
    s.chains = vec![dest];
    assert!(unclaimed(&s).is_empty());
    // Never caught up: also no evidence.
    s.chains[0].caught_up_at = None;
    assert!(unclaimed(&s).is_empty());
    // No chain row at all.
    s.chains.clear();
    assert!(unclaimed(&s).is_empty());
}

fn orphan(lookup: &str, count: u32) -> OrphanRow {
    OrphanRow {
        source_domain: BASE,
        nonce: nonce(9),
        receive_tx: "0xrecv".to_string(),
        source_lookup: lookup.to_string(),
        lookup_count: count,
        iris_source_tx: Some("0xsrc".to_string()),
        amount: 21_000_000,
        mint_recipient: nonce(4),
        other_nonce: Some(nonce(7)),
    }
}

#[test]
fn check_mint_without_burn() {
    let mut s = empty(NOW);
    s.orphan_receives = Candidates::of(vec![orphan("unknown_to_iris", 2)]);
    assert!(evaluate(&s, &cfg()).is_empty());
    s.orphan_receives = Candidates::of(vec![orphan("unknown_to_iris", 3)]);
    let c = evaluate(&s, &cfg());
    assert_eq!(kinds(&c), ["mint_without_burn"]);
    assert_eq!(c[0].severity, Severity::Critical);
    assert!(c[0].subject.starts_with("nonce:6:0x"));
    // pre_start is expected and never alerts.
    s.orphan_receives = Candidates::of(vec![orphan("pre_start", 1)]);
    assert!(evaluate(&s, &cfg()).is_empty());
}

#[test]
fn check_mint_without_burn_source_not_found() {
    let mut s = empty(NOW);
    s.orphan_receives = Candidates::of(vec![orphan("source_not_found", 2)]);
    assert!(evaluate(&s, &cfg()).is_empty());
    s.orphan_receives = Candidates::of(vec![orphan("source_not_found", 3)]);
    let c = evaluate(&s, &cfg());
    assert_eq!(kinds(&c), ["mint_without_burn"]);
    assert_eq!(c[0].severity, Severity::Critical);
    assert!(
        c[0].message
            .contains("source tx is not on the source chain"),
        "{}",
        c[0].message
    );
    // The same orphan flips to the other reason: same subject, one alert row.
    s.orphan_receives = Candidates::of(vec![orphan("unknown_to_iris", 4)]);
    let d = evaluate(&s, &cfg());
    assert_eq!(d[0].subject, c[0].subject);
    assert!(d[0].message.contains("Iris does not know the nonce"));
    let mut store = Store::open_in_memory().unwrap();
    store.sync_alerts(&c, ALL_KINDS, NOW, 3600).unwrap();
    store.sync_alerts(&d, ALL_KINDS, NOW + 30, 3600).unwrap();
    assert_eq!(store.all_alerts().unwrap().len(), 1);
}

#[test]
fn check_iris_mismatch() {
    let mut s = empty(NOW);
    s.orphan_receives = Candidates::of(vec![orphan("iris_mismatch", 1)]);
    let c = evaluate(&s, &cfg());
    assert_eq!(kinds(&c), ["iris_mismatch"]);
    assert_eq!(c[0].severity, Severity::Critical);
    for part in ["0xsrc", "21000000", "0xrecv"] {
        assert!(c[0].message.contains(part), "{part} in {}", c[0].message);
    }
}

#[test]
fn check_iris_mismatch_resolves_when_a_matching_burn_appears() {
    let mut s = store();
    put_receives(&mut s, &[receive_event(5, "0xr", 0, 1010, 9, 100)]);
    let id = s.orphan_queue(i64::MAX, 0, 6, 10).unwrap()[0].id;
    s.record_source_lookup(id, Some(SourceLookup::IrisMismatch), Some("0xsrc"), 0)
        .unwrap();
    let run = |s: &mut Store, now: i64| {
        let snap = s.monitor_snapshot(now, &limits()).unwrap();
        let e = evaluate_full(&snap, &cfg());
        s.sync_alerts(&e.conditions, &e.complete_kinds, now, 3600)
            .unwrap();
    };
    run(&mut s, NOW);
    assert_eq!(s.alert_outbox(10).unwrap().len(), 1);
    // Our pipeline later pairs a burn with the nonce.
    put_burns(&mut s, &[burn_event(6, "0xsrc", 0, 110, 100)]);
    attest(&mut s, "0xsrc", 9, 0, NOW);
    run(&mut s, NOW + 30);
    assert!(s.alert_outbox(10).unwrap().is_empty(), "resolved");
}

#[test]
fn check_double_mint() {
    let mut s = empty(NOW);
    s.orphan_receives = Candidates::of(vec![orphan("double_mint", 1)]);
    let c = evaluate(&s, &cfg());
    assert_eq!(
        kinds(&c),
        ["double_mint"],
        "duplicate_receive does not fire"
    );
    assert_eq!(c[0].severity, Severity::Critical);
    assert!(c[0].subject.starts_with("nonce:6:0x"));
    for n in [nonce(9), nonce(7)] {
        assert!(
            c[0].message.contains(&n.to_string()),
            "{n} in {}",
            c[0].message
        );
    }
}

#[test]
fn check_orphan_unresolved() {
    let mut s = empty(NOW);
    s.orphan_receives = Candidates::of(vec![orphan("unresolved", 6)]);
    let c = evaluate(&s, &cfg());
    assert_eq!(kinds(&c), ["orphan_unresolved"]);
    assert_eq!(c[0].severity, Severity::Warning);
    // pre_start and postponed never alert.
    for verdict in ["pre_start", "postponed"] {
        s.orphan_receives = Candidates::of(vec![orphan(verdict, 6)]);
        assert!(evaluate(&s, &cfg()).is_empty(), "{verdict}");
    }
}

#[test]
fn check_ingestion_gap() {
    let mut s = empty(NOW);
    s.orphan_receives = Candidates::of(vec![orphan("missed", 1)]);
    let c = evaluate(&s, &cfg());
    assert_eq!(kinds(&c), ["ingestion_gap"]);
    assert_eq!(c[0].severity, Severity::Warning);
}

#[test]
fn check_duplicate_receive() {
    let mut s = empty(NOW);
    s.duplicate_nonces.rows.push(DuplicateRow {
        source_domain: BASE,
        nonce: nonce(4),
        count: 2,
    });
    let c = evaluate(&s, &cfg());
    assert_eq!(kinds(&c), ["duplicate_receive"]);
    assert_eq!(c[0].severity, Severity::Critical);
}

#[test]
fn check_field_mismatch_message_lists_fields() {
    let mut s = empty(NOW);
    s.mismatched_pairs.rows.push(MismatchRow {
        source_domain: BASE,
        nonce: nonce(4),
        fields: vec!["amount".into(), "sender".into()],
    });
    let c = evaluate(&s, &cfg());
    assert_eq!(kinds(&c), ["field_mismatch"]);
    assert_eq!(c[0].severity, Severity::Critical);
    assert!(c[0].message.contains("amount, sender"));
}

fn sample(i: u8, latency: i64, mode: Mode, receive_time: i64) -> LatencySample {
    LatencySample {
        source_domain: BASE,
        destination_domain: SOLANA,
        mode,
        nonce: nonce(i),
        latency_secs: latency,
        receive_time,
    }
}

#[test]
fn check_latency_outlier_median_mad() {
    let mut s = empty(NOW);
    // 24 normal samples around 1020 s and one slow transfer.
    for i in 0..24u8 {
        s.push_lat(sample(
            i,
            1000 + i64::from(i % 5) * 10,
            Mode::Standard,
            NOW - 100,
        ));
    }
    s.push_lat(sample(100, 5000, Mode::Standard, NOW - 50));
    let c = evaluate(&s, &cfg());
    assert_eq!(kinds(&c), ["latency_outlier"]);
    assert_eq!(c[0].severity, Severity::Info);
    assert_eq!(c[0].subject, format!("nonce:6:0x{}", "64".repeat(32)));

    // A transfer inside the normal band does not fire.
    s.recent_completed.rows.last_mut().unwrap().latency_secs = 1100;
    s.latency_baseline.last_mut().unwrap().latency_secs = 1100;
    assert!(evaluate(&s, &cfg()).is_empty());

    // Fewer than 20 samples: no judgement.
    let mut few = empty(NOW);
    for i in 0..19u8 {
        few.push_lat(sample(i, 1000, Mode::Standard, NOW - 10));
    }
    few.recent_completed.rows[0].latency_secs = 99_999;
    few.latency_baseline[0].latency_secs = 99_999;
    assert!(evaluate(&few, &cfg()).is_empty());

    // Old completions are not alerted, even when slow.
    let mut old = empty(NOW);
    for i in 0..24u8 {
        old.push_lat(sample(i, 1000, Mode::Standard, NOW - 100));
    }
    old.push_lat(sample(100, 9000, Mode::Standard, NOW - 90_000));
    assert!(evaluate(&old, &cfg()).is_empty());
}

#[test]
fn check_latency_outlier_all_equal_samples_use_min_excess() {
    let build = |slow: i64| {
        let mut s = empty(NOW);
        for i in 0..30u8 {
            s.push_lat(sample(i, 1000, Mode::Standard, NOW - 100));
        }
        s.push_lat(sample(200, slow, Mode::Standard, NOW - 10));
        s
    };
    assert!(evaluate(&build(1120), &cfg()).is_empty());
    assert_eq!(kinds(&evaluate(&build(1121), &cfg())), ["latency_outlier"]);
}

#[test]
fn check_latency_groups_do_not_mix_modes() {
    let mut s = empty(NOW);
    for i in 0..25u8 {
        s.push_lat(sample(i, 1000, Mode::Standard, NOW - 100));
    }
    // 20 s is normal for Fast and must not be judged against Standard.
    for i in 0..25u8 {
        s.push_lat(sample(100 + i, 20, Mode::Fast, NOW - 100));
    }
    assert!(evaluate(&s, &cfg()).is_empty());
}

#[test]
fn check_component_stalled() {
    let mut s = empty(NOW);
    s.health = vec![health("resolver", NOW - 5000, Some(NOW - 300))];
    assert!(evaluate(&s, &cfg()).is_empty());
    s.health[0].last_ok_at = Some(NOW - 301);
    let c = evaluate(&s, &cfg());
    assert_eq!(kinds(&c), ["component_stalled"]);
    assert_eq!(c[0].subject, "component:resolver");
    // Recovery resolves it.
    s.health[0].last_ok_at = Some(NOW);
    assert!(evaluate(&s, &cfg()).is_empty());
    // Never succeeded: counts from started_at.
    s.health = vec![health("notifier", NOW - 301, None)];
    assert_eq!(kinds(&evaluate(&s, &cfg())), ["component_stalled"]);
    s.health = vec![health("notifier", NOW - 300, None)];
    assert!(evaluate(&s, &cfg()).is_empty());
}

#[test]
fn check_ingestion_lagging() {
    let mut s = empty(NOW);
    let mut c = chain(BASE, "base");
    c.caught_up_at = Some(NOW - 300);
    s.chains = vec![c];
    s.health = vec![health("ingest:base", NOW - 9999, Some(NOW))];
    assert!(evaluate(&s, &cfg()).is_empty());
    s.chains[0].caught_up_at = Some(NOW - 301);
    let c = evaluate(&s, &cfg());
    assert_eq!(kinds(&c), ["ingestion_lagging"]);
    assert_eq!(c[0].subject, "chain:base");
    // Never caught up: counts from the health started_at.
    s.chains[0].caught_up_at = None;
    s.health[0].started_at = NOW - 301;
    assert_eq!(kinds(&evaluate(&s, &cfg())), ["ingestion_lagging"]);
    s.health[0].started_at = NOW - 100;
    assert!(evaluate(&s, &cfg()).is_empty());
    // Caught up again: resolves.
    s.chains[0].caught_up_at = Some(NOW);
    assert!(evaluate(&s, &cfg()).is_empty());
}

#[test]
fn check_finality_stalled() {
    let mut s = empty(NOW);
    let mut c = chain(BASE, "base");
    c.observed_finalized = Some(1_000_000);
    c.observed_head = Some(1_009_000);
    s.chains = vec![c];
    assert!(evaluate(&s, &cfg()).is_empty());
    s.chains[0].observed_head = Some(1_009_001);
    let c = evaluate(&s, &cfg());
    assert_eq!(kinds(&c), ["finality_stalled"]);
    assert_eq!(c[0].subject, "chain:base");
    // Recovery.
    s.chains[0].observed_finalized = Some(1_005_000);
    assert!(evaluate(&s, &cfg()).is_empty());
    // Missing heights or limits: no judgement.
    s.chains[0].observed_finalized = None;
    assert!(evaluate(&s, &cfg()).is_empty());
}

#[test]
fn check_no_stall_alert_right_after_restart() {
    let two_days = 2 * 24 * 3600;
    let started = NOW - 10;
    let mut s = empty(NOW);
    let mut c = chain(BASE, "base");
    c.caught_up_at = Some(NOW - two_days);
    s.chains = vec![c];
    s.health = vec![health("ingest:base", started, Some(NOW - two_days))];
    assert!(
        evaluate(&s, &cfg()).is_empty(),
        "the restart gives a full grace period"
    );

    let later = started + cfg().stall_after_secs + 1;
    s.now = later;
    let c = evaluate(&s, &cfg());
    assert_eq!(kinds(&c), ["component_stalled", "ingestion_lagging"]);
    // And exactly at the limit nothing fires yet.
    s.now = started + cfg().stall_after_secs;
    assert!(evaluate(&s, &cfg()).is_empty());
}

#[test]
fn check_reorg_rollback_info() {
    let mut s = empty(NOW);
    s.recent_rollbacks = Candidates::of(vec![RollbackRow {
        id: 7,
        domain: BASE,
        event_type: "burn".to_string(),
        tx_id: "0xgone".to_string(),
        height: 105,
        scope: "tail".to_string(),
        detected_at: NOW - 60,
    }]);
    let c = evaluate(&s, &cfg());
    assert_eq!(kinds(&c), ["reorg_rollback"]);
    assert_eq!(c[0].subject, "rollback:7");
    assert_eq!(c[0].severity, Severity::Info);
    s.recent_rollbacks.rows[0].detected_at = NOW - 90_000;
    assert!(evaluate(&s, &cfg()).is_empty());
}

#[test]
fn evaluate_is_sorted_and_deterministic() {
    let mut s = empty(NOW);
    s.orphan_receives = Candidates::of(vec![orphan("missed", 1), orphan("unknown_to_iris", 5)]);
    s.orphan_receives.rows[1].nonce = nonce(1);
    s.duplicate_nonces.rows.push(DuplicateRow {
        source_domain: BASE,
        nonce: nonce(2),
        count: 2,
    });
    s.health = vec![health("resolver", NOW - 9999, None)];
    let a = evaluate(&s, &cfg());
    let b = evaluate(&s, &cfg());
    assert_eq!(a, b);
    let keys: Vec<_> = a.iter().map(|c| (c.kind, c.subject.clone())).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
}

// ---------------------------------------------------------------------------
// SQL-filtered checks on a real store
// ---------------------------------------------------------------------------

fn store() -> Store {
    let mut s = Store::open_in_memory().unwrap();
    s.init_cursor(BASE, "base", 100, 0, NOW).unwrap();
    s.init_cursor(SOLANA, "solana", 1000, 0, NOW).unwrap();
    s
}

fn put_burns(s: &mut Store, events: &[ChainEvent]) {
    s.apply_scan(
        BASE,
        Scope::Tail {
            after: 100,
            through: 200,
        },
        events,
        NOW,
    )
    .unwrap();
}

fn put_receives(s: &mut Store, events: &[ChainEvent]) {
    s.apply_scan(
        SOLANA,
        Scope::Final {
            after: 1000,
            through: 1100,
        },
        events,
        NOW,
    )
    .unwrap();
}

fn attest(s: &mut Store, tx: &str, nonce_byte: u8, fee: u64, at: i64) {
    let id: i64 = s
        .attestation_queue(i64::MAX, 100)
        .unwrap()
        .into_iter()
        .find(|t| t.tx_id == tx)
        .unwrap()
        .burns[0]
        .slot
        .id;
    let conflicts = s
        .record_attestation_polls(
            &[BurnPollUpdate {
                burn_id: id,
                observation: Some(IrisObservation {
                    nonce: nonce(nonce_byte),
                    complete: true,
                    fee_executed: fee,
                    finality_threshold_executed: 2000,
                    delay_reason: None,
                    iris_destination_tx: None,
                }),
                next_poll_at: at + 10,
            }],
            at,
        )
        .unwrap();
    assert!(conflicts.is_empty());
}

fn mutate_receive(e: &mut ChainEvent, f: impl FnOnce(&mut bridge_watcher::domain::ReceiveMessage)) {
    match &mut e.kind {
        EventKind::Receive(r) => f(r),
        EventKind::Burn(_) => unreachable!(),
    }
}

fn mutate_burn(e: &mut ChainEvent, f: impl FnOnce(&mut bridge_watcher::domain::BurnMessage)) {
    match &mut e.kind {
        EventKind::Burn(b) => f(b),
        EventKind::Receive(_) => unreachable!(),
    }
}

#[test]
fn check_field_mismatch_each_field() {
    type Case = (
        &'static str,
        &'static str,
        fn(&mut ChainEvent, &mut ChainEvent),
        u64,
    );
    // (tx suffix, expected field, mutation of (burn event, receive event), Iris fee)
    let cases: Vec<Case> = vec![
        (
            "destination_domain",
            "destination_domain",
            |b, _| mutate_burn(b, |m| m.destination_domain = Domain(7)),
            0,
        ),
        (
            "sender",
            "sender",
            |_, r| mutate_receive(r, |m| m.sender = Bytes32([9; 32])),
            0,
        ),
        (
            "burn_token",
            "burn_token",
            |_, r| mutate_receive(r, |m| m.body.burn_token = Bytes32([9; 32])),
            0,
        ),
        (
            "mint_recipient",
            "mint_recipient",
            |_, r| mutate_receive(r, |m| m.body.mint_recipient = Bytes32([9; 32])),
            0,
        ),
        (
            "amount",
            "amount",
            |_, r| mutate_receive(r, |m| m.body.amount += 1),
            0,
        ),
        (
            "depositor",
            "depositor",
            |_, r| mutate_receive(r, |m| m.body.depositor = Bytes32([9; 32])),
            0,
        ),
        (
            "max_fee",
            "max_fee",
            |_, r| mutate_receive(r, |m| m.body.max_fee = 5),
            0,
        ),
        (
            "hook_data",
            "hook_data",
            |_, r| mutate_receive(r, |m| m.body.hook_data = vec![1]),
            0,
        ),
        // Iris says 1, the receive says 0 (max_fee 0 on both sides).
        ("fee_executed", "fee_executed", |_, _| {}, 1),
        // Iris and the receive agree on 5, but the burner allowed only 0.
        (
            "fee_exceeds_max_fee",
            "fee_exceeds_max_fee",
            |_, r| mutate_receive(r, |m| m.body.fee_executed = 5),
            5,
        ),
    ];
    let mut s = store();
    let mut burns = Vec::new();
    let mut receives = Vec::new();
    for (i, (name, _, mutate, _)) in cases.iter().enumerate() {
        let tx = format!("0x{name}");
        let n = u8::try_from(i + 1).unwrap();
        let mut b = burn_event(6, &tx, 0, 110 + i as u64, 100);
        let mut r = receive_event(5, &format!("0xr{name}"), 0, 1010 + i as u64, n, 100);
        mutate(&mut b, &mut r);
        burns.push(b);
        receives.push(r);
    }
    // A clean pair as control.
    burns.push(burn_event(6, "0xclean", 0, 150, 100));
    receives.push(receive_event(5, "0xrclean", 0, 1050, 99, 100));
    put_burns(&mut s, &burns);
    put_receives(&mut s, &receives);
    for (i, (name, _, _, fee)) in cases.iter().enumerate() {
        attest(
            &mut s,
            &format!("0x{name}"),
            u8::try_from(i + 1).unwrap(),
            *fee,
            NOW,
        );
    }
    attest(&mut s, "0xclean", 99, 0, NOW);

    let snap = s.monitor_snapshot(NOW, &limits()).unwrap();
    assert_eq!(
        snap.mismatched_pairs.rows.len(),
        cases.len(),
        "{:?}",
        snap.mismatched_pairs.rows
    );
    for (i, (name, expected, _, _)) in cases.iter().enumerate() {
        let n = u8::try_from(i + 1).unwrap();
        let row = snap
            .mismatched_pairs
            .rows
            .iter()
            .find(|m| m.nonce == nonce(n))
            .unwrap_or_else(|| panic!("no mismatch for {name}"));
        assert_eq!(row.fields, vec![(*expected).to_string()], "case {name}");
    }
    let conds = evaluate(&snap, &cfg());
    assert_eq!(conds.len(), cases.len());
    assert!(
        conds
            .iter()
            .all(|c| c.kind == "field_mismatch" && c.severity == Severity::Critical)
    );
}

#[test]
fn check_field_mismatch_ignores_unfinalized_receives_and_unknown_fee() {
    let mut s = store();
    let b = burn_event(6, "0xa", 0, 110, 100);
    let mut r = receive_event(5, "0xra", 0, 1010, 1, 100);
    mutate_receive(&mut r, |m| m.body.amount = 5);
    put_burns(&mut s, &[b]);
    // A tail (unfinalized) receive is not judged yet.
    s.apply_scan(
        SOLANA,
        Scope::Tail {
            after: 1000,
            through: 1100,
        },
        &[r],
        NOW,
    )
    .unwrap();
    attest(&mut s, "0xa", 1, 0, NOW);
    assert!(
        s.monitor_snapshot(NOW, &limits())
            .unwrap()
            .mismatched_pairs
            .rows
            .is_empty()
    );
}

#[test]
fn snapshot_duplicates_orphans_and_candidates() {
    let mut s = store();
    put_burns(
        &mut s,
        &[
            burn_event(6, "0xa", 0, 110, 100),
            burn_event(6, "0xb", 0, 111, 100),
        ],
    );
    attest(&mut s, "0xa", 1, 0, NOW);
    // Burn b is polled but pending; a has no receive; two receives share nonce 5.
    s.record_attestation_polls(
        &[BurnPollUpdate {
            burn_id: s.attestation_queue(i64::MAX, 10).unwrap()[0].burns[0]
                .slot
                .id,
            observation: None,
            next_poll_at: NOW,
        }],
        NOW + 1,
    )
    .unwrap();
    put_receives(
        &mut s,
        &[
            receive_event(5, "0xr1", 0, 1010, 5, 100),
            receive_event(5, "0xr2", 0, 1011, 5, 100),
            receive_event(5, "0xr3", 0, 1012, 6, 100),
        ],
    );
    // The destination chain was caught up long after the attestation.
    s.mark_caught_up(SOLANA, 1100, NOW + 5000).unwrap();
    let snap = s.monitor_snapshot(NOW + 5, &limits()).unwrap();
    assert_eq!(snap.unclaimed_burns.rows.len(), 1);
    assert_eq!(snap.unclaimed_burns.rows[0].nonce, nonce(1));
    assert_eq!(snap.delayed_burns.rows.len(), 1);
    assert_eq!(snap.delayed_burns.rows[0].tx_id, "0xb");
    assert_eq!(snap.delayed_burns.rows[0].last_polled_at, NOW + 1);
    assert_eq!(snap.duplicate_nonces.rows.len(), 1);
    assert_eq!(snap.duplicate_nonces.rows[0].nonce, nonce(5));
    assert_eq!(snap.duplicate_nonces.rows[0].count, 2);
    assert!(
        snap.orphan_receives.rows.is_empty(),
        "no alert-capable verdict yet"
    );
    assert!(!snap.delayed_burns.truncated && !snap.unclaimed_burns.truncated);
    assert_eq!(snap.chains.len(), 2);
}

#[test]
fn snapshot_latency_window_keeps_the_newest_per_group() {
    let mut s = store();
    let mut burns = Vec::new();
    let mut receives = Vec::new();
    for i in 0..6u64 {
        let tx = format!("0xb{i}");
        burns.push(burn_event(6, &tx, 0, 110 + i, 100));
        receives.push(receive_event(
            5,
            &format!("0xr{i}"),
            0,
            1010 + i * 10,
            i as u8 + 1,
            100,
        ));
    }
    put_burns(&mut s, &burns);
    put_receives(&mut s, &receives);
    for i in 0..6u64 {
        attest(&mut s, &format!("0xb{i}"), i as u8 + 1, 0, NOW);
    }
    let mut l = limits();
    l.latency_window = 4;
    let snap = s.monitor_snapshot(NOW, &l).unwrap();
    assert_eq!(snap.latency_baseline.len(), 4);
    let times: Vec<_> = snap
        .latency_baseline
        .iter()
        .map(|x| x.receive_time)
        .collect();
    let mut sorted = times.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(times, sorted, "newest first");
    assert!(
        snap.latency_baseline
            .iter()
            .all(|x| x.mode == Mode::Standard)
    );
}

#[test]
fn snapshot_rollbacks_are_limited_to_the_last_day() {
    let mut s = store();
    put_burns(&mut s, &[burn_event(6, "0xa", 0, 110, 100)]);
    s.apply_scan(
        BASE,
        Scope::Tail {
            after: 100,
            through: 200,
        },
        &[],
        NOW,
    )
    .unwrap();
    assert_eq!(
        s.monitor_snapshot(NOW + 100, &limits())
            .unwrap()
            .recent_rollbacks
            .rows
            .len(),
        1
    );
    assert!(
        s.monitor_snapshot(NOW + 100_000, &limits())
            .unwrap()
            .recent_rollbacks
            .rows
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Alert-capable candidate lists and truncation (design section 9.1)
// ---------------------------------------------------------------------------

fn nonce_u32(i: u32) -> Bytes32 {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&(i + 1).to_be_bytes());
    Bytes32(b)
}

/// A final receive on Solana with nonce `nonce_u32(i)` and a distinct tx.
fn receive_n(tx: &str, i: u32, height: u64) -> ChainEvent {
    let mut e = receive_event(5, tx, 0, height, 1, 100);
    mutate_receive(&mut e, |m| m.nonce = nonce_u32(i));
    e
}

fn mark_orphans(s: &mut Store, verdict: SourceLookup) {
    let queue = s.orphan_queue(i64::MAX, 0, 6, 100_000).unwrap();
    for o in &queue {
        s.record_source_lookup(o.id, Some(verdict), Some("0xsrc"), 0)
            .unwrap();
    }
}

fn put_receives_in(s: &mut Store, after: u64, events: &[ChainEvent]) {
    s.apply_scan(
        SOLANA,
        Scope::Final {
            after,
            through: after + 100,
        },
        events,
        NOW,
    )
    .unwrap();
}

#[test]
fn snapshot_selects_only_alert_capable_rows() {
    let mut s = store();
    // 2000 pre_start orphans: expected, never alert-capable.
    let orphans: Vec<_> = (0..2000u32)
        .map(|i| receive_n(&format!("0xp{i}"), i, 1010 + u64::from(i % 50)))
        .collect();
    put_receives_in(&mut s, 1000, &orphans);
    mark_orphans(&mut s, SourceLookup::PreStart);
    // 2000 claimed burns: attested, with a receive.
    let burns: Vec<ChainEvent> = (0..2000u32)
        .map(|i| burn_event(6, &format!("0xb{i}"), 0, 110 + u64::from(i % 50), 100))
        .collect();
    put_burns(&mut s, &burns);
    let updates: Vec<BurnPollUpdate> = s
        .attestation_queue(i64::MAX, 5000)
        .unwrap()
        .iter()
        .map(|t| {
            let i: u32 = t.tx_id.trim_start_matches("0xb").parse().unwrap();
            BurnPollUpdate {
                burn_id: t.burns[0].slot.id,
                observation: Some(IrisObservation {
                    nonce: nonce_u32(10_000 + i),
                    complete: true,
                    fee_executed: 0,
                    finality_threshold_executed: 2000,
                    delay_reason: None,
                    iris_destination_tx: None,
                }),
                next_poll_at: NOW,
            }
        })
        .collect();
    assert!(
        s.record_attestation_polls(&updates, NOW)
            .unwrap()
            .is_empty()
    );
    let claimed: Vec<_> = (0..2000u32)
        .map(|i| receive_n(&format!("0xc{i}"), 10_000 + i, 1110 + u64::from(i % 50)))
        .collect();
    put_receives_in(&mut s, 1100, &claimed);
    // One orphan with the iris_mismatch verdict.
    put_receives_in(&mut s, 1200, &[receive_n("0xm", 50_000, 1210)]);
    let queue = s.orphan_queue(i64::MAX, 0, 6, 100_000).unwrap();
    assert_eq!(queue.len(), 1, "the pre_start ones left the queue");
    s.record_source_lookup(
        queue[0].id,
        Some(SourceLookup::IrisMismatch),
        Some("0xsrc"),
        0,
    )
    .unwrap();

    let snap = s.monitor_snapshot(NOW, &limits()).unwrap();
    assert_eq!(snap.orphan_receives.rows.len(), 1);
    assert!(snap.unclaimed_burns.rows.is_empty() && snap.delayed_burns.rows.is_empty());
    for truncated in [
        snap.orphan_receives.truncated,
        snap.unclaimed_burns.truncated,
        snap.delayed_burns.truncated,
        snap.mismatched_pairs.truncated,
        snap.duplicate_nonces.truncated,
        snap.recent_completed.truncated,
        snap.recent_rollbacks.truncated,
    ] {
        assert!(!truncated);
    }
    let e = evaluate_full(&snap, &cfg());
    assert_eq!(kinds(&e.conditions), ["iris_mismatch"]);
    assert_eq!(e.complete_kinds.len(), ALL_KINDS.len());
}

#[test]
fn snapshot_truncation_flag() {
    let build = |n: u32| {
        let mut s = store();
        let events: Vec<ChainEvent> = (0..n)
            .map(|i| receive_n(&format!("0xr{i}"), i, 1010 + u64::from(i)))
            .collect();
        put_receives_in(&mut s, 1000, &events);
        mark_orphans(&mut s, SourceLookup::IrisMismatch);
        s
    };
    let mut l = limits();
    l.per_list = 3;

    // limit + 1 candidates: exactly `limit` rows, newest first, truncated.
    let snap = build(4).monitor_snapshot(NOW, &l).unwrap();
    assert_eq!(snap.orphan_receives.rows.len(), 3);
    assert!(snap.orphan_receives.truncated);
    let txs: Vec<_> = snap
        .orphan_receives
        .rows
        .iter()
        .map(|r| r.receive_tx.as_str())
        .collect();
    assert_eq!(txs, ["0xr3", "0xr2", "0xr1"], "the oldest row is dropped");

    // Exactly `limit` candidates: complete.
    let snap = build(3).monitor_snapshot(NOW, &l).unwrap();
    assert_eq!(snap.orphan_receives.rows.len(), 3);
    assert!(!snap.orphan_receives.truncated);
}

#[test]
fn truncated_kind_is_not_resolved() {
    let mut store = Store::open_in_memory().unwrap();
    let open: Vec<AlertCondition> = (0..3)
        .map(|i| AlertCondition {
            kind: "unclaimed",
            subject: format!("nonce:6:0x0{i}"),
            severity: Severity::Warning,
            message: "old".to_string(),
        })
        .collect();
    store.sync_alerts(&open, ALL_KINDS, NOW, 3600).unwrap();

    // The unclaimed list is truncated and the old burns fell out of it.
    let mut snap = empty(NOW + 60);
    snap.unclaimed_burns.truncated = true;
    let e = evaluate_full(&snap, &cfg());
    assert_eq!(kinds(&e.conditions), ["monitor_truncated"]);
    assert_eq!(e.conditions[0].subject, "list:unclaimed_burns");
    assert!(!e.complete_kinds.contains(&"unclaimed"));
    assert!(e.complete_kinds.contains(&"monitor_truncated"));
    assert!(e.complete_kinds.contains(&"field_mismatch"));
    let stats = store
        .sync_alerts(&e.conditions, &e.complete_kinds, NOW + 60, 3600)
        .unwrap();
    assert_eq!(stats.resolved, 0);
    let open_now: Vec<String> = store
        .alert_outbox(10)
        .unwrap()
        .into_iter()
        .map(|a| a.kind)
        .collect();
    assert_eq!(open_now.iter().filter(|k| *k == "unclaimed").count(), 3);

    // The list shrinks below the limit: normal resolution resumes.
    let snap = empty(NOW + 120);
    let e = evaluate_full(&snap, &cfg());
    assert!(e.conditions.is_empty());
    let stats = store
        .sync_alerts(&e.conditions, &e.complete_kinds, NOW + 120, 3600)
        .unwrap();
    assert_eq!(
        stats.resolved, 4,
        "3 unclaimed alerts and monitor_truncated"
    );
}

// ---------------------------------------------------------------------------
// Monitor loop
// ---------------------------------------------------------------------------

#[tokio::test]
async fn monitor_tick_opens_and_resolves_alerts() {
    let mut s = store();
    s.record_health("resolver", Err("never worked"), NOW - 1000)
        .unwrap();
    let shared = SharedStore::from_store(s);
    let m = Monitor::new(shared.clone(), cfg(), limits().chains, 3600);
    let stats = m.tick(NOW).await.unwrap();
    assert_eq!(stats.inserted, 1, "resolver never reported OK");
    let alerts = shared.run(|s| s.all_alerts()).await.unwrap();
    assert_eq!(alerts[0].kind, "component_stalled");
    assert_eq!(alerts[0].subject, "component:resolver");
    shared
        .run(|s| s.record_health("resolver", Ok(()), NOW + 10))
        .await
        .unwrap();
    let stats = m.tick(NOW + 20).await.unwrap();
    assert_eq!(stats.resolved, 1);
}

#[test]
fn monitor_run_future_is_send() {
    fn assert_send<T: Send>(_: &T) {}
    let m = Monitor::new(
        SharedStore::from_store(Store::open_in_memory().unwrap()),
        cfg(),
        vec![],
        3600,
    );
    assert_send(&m.run(tokio_util::sync::CancellationToken::new()));
}

// ---------------------------------------------------------------------------
// Coverage window (ADR 0013)
// ---------------------------------------------------------------------------

/// A store whose Solana window starts at `solana_start_time`, with one
/// attested Base burn (block time `1_700_000_110`) and no receive. The
/// destination was caught up long after the attestation.
fn store_with_window(solana_start_time: i64) -> Store {
    let mut s = Store::open_in_memory().unwrap();
    s.init_cursor(BASE, "base", 100, 0, NOW).unwrap();
    s.init_cursor(SOLANA, "solana", 1000, solana_start_time, NOW)
        .unwrap();
    put_burns(&mut s, &[burn_event(6, "0xa", 0, 110, 100)]);
    attest(&mut s, "0xa", 1, 0, NOW);
    s.mark_caught_up(SOLANA, 1100, NOW + 10_000).unwrap();
    s
}

const BURN_TIME: i64 = 1_700_000_110;

#[test]
fn check_unclaimed_skips_pre_window_burns() {
    // Pure rule: the burn is `margin - 1` seconds inside the window.
    let mut s = empty(NOW);
    let mut dest = chain(SOLANA, "solana");
    dest.caught_up_at = Some(NOW);
    let mut burn = attested(NOW - 7200);
    dest.start_time = BURN_TIME - 59;
    burn.burn_time = BURN_TIME;
    s.unclaimed_burns.rows.push(burn.clone());
    s.chains = vec![dest.clone()];
    assert!(unclaimed(&s).is_empty(), "burn time < start + 60");
    // At any later time too.
    s.now = NOW + 86_400;
    s.chains[0].caught_up_at = Some(NOW + 86_400);
    assert!(unclaimed(&s).is_empty());
    // Exactly the margin inside the window: claimed as before.
    s.chains[0].start_time = BURN_TIME - 60;
    assert_eq!(kinds(&unclaimed(&s)), ["unclaimed"]);

    // The candidate query applies the same rule (N7: never selected).
    for (start, selected) in [(BURN_TIME - 59, 0), (BURN_TIME - 60, 1)] {
        let snap = store_with_window(start)
            .monitor_snapshot(NOW + 10_000, &limits())
            .unwrap();
        assert_eq!(snap.unclaimed_burns.rows.len(), selected, "start {start}");
    }
}

/// Smoke-run regression: a Base to Solana Fast burn was minted seconds after
/// the burn, but the Solana window began later, so the receive is not in the
/// database. That must not become `unclaimed`.
#[test]
fn unclaimed_not_raised_when_receive_predates_window() {
    let mut s = store_with_window(BURN_TIME + 600);
    // Long after `unclaimed_after` and an hour more.
    let now = NOW + 10_000 + 3600;
    s.mark_caught_up(SOLANA, 1100, now).unwrap();
    let snap = s.monitor_snapshot(now, &limits()).unwrap();
    assert!(snap.unclaimed_burns.rows.is_empty());
    let e = evaluate(&snap, &cfg());
    assert!(e.iter().all(|c| c.kind != "unclaimed"), "{:?}", e);
    let rows = s
        .list_transfers(&bridge_watcher::store::TransferFilter {
            state: None,
            limit: 10,
        })
        .unwrap();
    assert_eq!(
        rows[0].state,
        bridge_watcher::store::TransferState::PreWindow
    );
}
