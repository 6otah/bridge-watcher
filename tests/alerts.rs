//! Alert lifecycle, outbox and notifier (design sections 9.3, 9.4 and 15.5).
//! The sink is `FakeSink`; the Telegram sink is tested through request
//! building and reply parsing only.

mod common;

use std::time::Duration;

use bridge_watcher::config::{AlertsConfig, MonitorConfig};
use bridge_watcher::monitor::{ALL_KINDS, Monitor, Severity};
use bridge_watcher::notify::{
    Notifier, NotifyConfig, SinkError, format_alert, parse_telegram_reply, telegram_payload,
};
use bridge_watcher::store::{AlertCondition, ChainLimits, SharedStore, Store};
use common::fake_sink::FakeSink;
use tempfile::TempDir;

const NOW: i64 = 1_800_000_000;
const HOUR: i64 = 3600;

fn cond(kind: &'static str, subject: &str, severity: Severity) -> AlertCondition {
    AlertCondition {
        kind,
        subject: subject.to_string(),
        severity,
        message: format!("{kind} on {subject}"),
    }
}

fn notifier(sink: &FakeSink, store: &SharedStore) -> Notifier<FakeSink> {
    Notifier::new(
        sink.clone(),
        store.clone(),
        NotifyConfig::from(&AlertsConfig::default()),
    )
}

fn open() -> SharedStore {
    SharedStore::from_store(Store::open_in_memory().unwrap())
}

async fn sync(store: &SharedStore, active: Vec<AlertCondition>, now: i64) {
    store
        .run(move |s| s.sync_alerts(&active, ALL_KINDS, now, HOUR))
        .await
        .unwrap();
}

async fn alerts(store: &SharedStore) -> Vec<bridge_watcher::store::Alert> {
    store.run(|s| s.all_alerts()).await.unwrap()
}

// ---------------------------------------------------------------------------
// sync_alerts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alerts_sync_lifecycle() {
    let store = open();
    let a = cond("unclaimed", "nonce:6:0xaa", Severity::Warning);
    sync(&store, vec![a.clone()], NOW).await;
    let rows = alerts(&store).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (
            rows[0].first_seen_at,
            rows[0].opened_at,
            rows[0].last_seen_at
        ),
        (NOW, NOW, NOW)
    );
    assert_eq!(rows[0].severity, Severity::Warning);

    // Still active: touched, message and severity refreshed, no new row.
    let mut b = a.clone();
    b.message = "new text".to_string();
    b.severity = Severity::Critical;
    sync(&store, vec![b], NOW + 30).await;
    let rows = alerts(&store).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].message, "new text");
    assert_eq!(rows[0].severity, Severity::Critical);
    assert_eq!((rows[0].first_seen_at, rows[0].opened_at), (NOW, NOW));
    assert_eq!(rows[0].last_seen_at, NOW + 30);

    // Gone: resolved, kept.
    let stats = store
        .run(|s| s.sync_alerts(&[], ALL_KINDS, NOW + 60, HOUR))
        .await
        .unwrap();
    assert_eq!(stats.resolved, 1);
    let open_count = store.run(|s| s.alert_outbox(10)).await.unwrap().len();
    assert_eq!(open_count, 0, "a resolved alert leaves the outbox");
    assert_eq!(alerts(&store).await.len(), 1);
}

#[tokio::test]
async fn alerts_key_is_kind_and_subject() {
    let store = open();
    sync(
        &store,
        vec![
            cond("unclaimed", "nonce:6:0x01", Severity::Warning),
            cond("unclaimed", "nonce:6:0x02", Severity::Warning),
            cond("field_mismatch", "nonce:6:0x01", Severity::Critical),
            cond("field_mismatch", "nonce:6:0x01", Severity::Critical),
        ],
        NOW,
    )
    .await;
    assert_eq!(alerts(&store).await.len(), 3);
}

#[tokio::test]
async fn alerts_resolve_and_reopen_throttled() {
    let store = open();
    let sink = FakeSink::new();
    let n = notifier(&sink, &store);
    let a = cond("unclaimed", "nonce:6:0xaa", Severity::Warning);

    sync(&store, vec![a.clone()], NOW).await;
    assert_eq!(n.tick(NOW + 1).await.unwrap(), 1);
    assert_eq!(sink.delivered().len(), 1);

    // Flap within the throttle window: silent.
    sync(&store, vec![], NOW + 60).await;
    sync(&store, vec![a.clone()], NOW + 120).await;
    assert_eq!(n.tick(NOW + 121).await.unwrap(), 0);
    assert_eq!(sink.delivered().len(), 1);
    let rows = alerts(&store).await;
    assert_eq!(rows[0].opened_at, NOW, "a silent re-open keeps opened_at");

    // Flap after the window: one more delivery.
    sync(&store, vec![], NOW + HOUR + 500).await;
    sync(&store, vec![a], NOW + HOUR + 600).await;
    assert_eq!(n.tick(NOW + HOUR + 601).await.unwrap(), 1);
    assert_eq!(sink.delivered().len(), 2);
    assert_eq!(alerts(&store).await[0].opened_at, NOW + HOUR + 600);
}

#[tokio::test]
async fn alerts_outbox_is_ordered_and_limited() {
    let store = open();
    let active: Vec<_> = (0..5)
        .map(|i| cond("unclaimed", &format!("nonce:6:0x0{i}"), Severity::Warning))
        .collect();
    sync(&store, active, NOW).await;
    let rows = store.run(|s| s.alert_outbox(3)).await.unwrap();
    assert_eq!(rows.len(), 3);
    assert!(rows.windows(2).all(|w| w[0].id < w[1].id));
}

// ---------------------------------------------------------------------------
// De-duplication across a restart
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alerts_dedup_across_restart() {
    let dir: TempDir = tempfile::tempdir().unwrap();
    let path = dir.path().join("alerts.db");
    let sink = FakeSink::new();
    let limits: Vec<ChainLimits> = vec![];

    {
        let mut s = Store::open(&path).unwrap();
        s.record_health("resolver", Err("never worked"), NOW - 1000)
            .unwrap();
        let store = SharedStore::from_store(s);
        let m = Monitor::new(
            store.clone(),
            MonitorConfig::default(),
            limits.clone(),
            HOUR,
        );
        m.tick(NOW).await.unwrap();
        assert_eq!(notifier(&sink, &store).tick(NOW + 1).await.unwrap(), 1);
    }

    // Restart: a new process opens the same file. The component is still
    // stalled, so the monitor sees the same condition.
    let store = SharedStore::open(&path).unwrap();
    let m = Monitor::new(store.clone(), MonitorConfig::default(), limits, HOUR);
    let stats = m.tick(NOW + 30).await.unwrap();
    assert_eq!((stats.inserted, stats.refreshed), (0, 1));
    assert_eq!(notifier(&sink, &store).tick(NOW + 31).await.unwrap(), 0);
    assert_eq!(alerts(&store).await.len(), 1);
    assert_eq!(sink.delivered().len(), 1, "the sink was called once");
    assert_eq!(sink.attempts(), 1);
}

// ---------------------------------------------------------------------------
// Notifier
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn notifier_marks_delivered_only_after_success() {
    let store = open();
    let sink = FakeSink::new();
    let n = notifier(&sink, &store);
    sync(
        &store,
        vec![cond("unclaimed", "nonce:6:0xaa", Severity::Warning)],
        NOW,
    )
    .await;

    sink.fail_next(1);
    assert_eq!(n.tick(NOW + 1).await.unwrap(), 0);
    let row = &alerts(&store).await[0];
    assert_eq!(row.notified_at, None);
    assert_eq!(row.notify_attempts, 1);
    assert_eq!(row.last_notify_error.as_deref(), Some("sink: sink down"));
    assert_eq!(store.run(|s| s.alert_outbox(10)).await.unwrap().len(), 1);

    // Backoff: no new attempt right away.
    assert_eq!(n.tick(NOW + 2).await.unwrap(), 0);
    assert_eq!(sink.attempts(), 1);

    tokio::time::advance(Duration::from_secs(6)).await;
    assert_eq!(n.tick(NOW + 8).await.unwrap(), 1);
    let row = &alerts(&store).await[0];
    assert_eq!(row.notified_at, Some(NOW + 8));
    assert_eq!(row.last_notify_error, None);
    assert!(store.run(|s| s.alert_outbox(10)).await.unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn notifier_respects_retry_after() {
    let store = open();
    let sink = FakeSink::new();
    let n = notifier(&sink, &store);
    sync(
        &store,
        vec![cond("unclaimed", "nonce:6:0xaa", Severity::Critical)],
        NOW,
    )
    .await;
    sink.retry_after_next(Duration::from_secs(60));
    n.tick(NOW + 1).await.unwrap();
    assert_eq!(sink.attempts(), 1);
    tokio::time::advance(Duration::from_secs(59)).await;
    n.tick(NOW + 60).await.unwrap();
    assert_eq!(sink.attempts(), 1, "still inside retry_after");
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(n.tick(NOW + 62).await.unwrap(), 1);
    assert_eq!(sink.attempts(), 2);
}

#[tokio::test(start_paused = true)]
async fn notifier_stops_the_round_on_failure_and_keeps_order() {
    let store = open();
    let sink = FakeSink::new();
    let n = notifier(&sink, &store);
    sync(
        &store,
        vec![
            cond("unclaimed", "nonce:6:0x01", Severity::Warning),
            cond("unclaimed", "nonce:6:0x02", Severity::Warning),
        ],
        NOW,
    )
    .await;
    sink.fail_next(1);
    assert_eq!(n.tick(NOW + 1).await.unwrap(), 0);
    assert_eq!(sink.attempts(), 1, "the second alert is not tried");
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(n.tick(NOW + 12).await.unwrap(), 2);
    let order: Vec<_> = sink.delivered().into_iter().map(|a| a.subject).collect();
    assert_eq!(order, ["nonce:6:0x01", "nonce:6:0x02"]);
}

#[tokio::test]
async fn notifier_below_min_severity_logs_only() {
    let store = open();
    let sink = FakeSink::new();
    let n = notifier(&sink, &store);
    sync(
        &store,
        vec![cond("latency_outlier", "nonce:6:0x01", Severity::Info)],
        NOW,
    )
    .await;
    assert_eq!(n.tick(NOW + 1).await.unwrap(), 1);
    assert_eq!(sink.attempts(), 0, "info is below the default threshold");
    assert_eq!(alerts(&store).await[0].notified_at, Some(NOW + 1));
}

#[tokio::test]
async fn notifier_min_severity_info_sends_everything() {
    let store = open();
    let sink = FakeSink::new();
    let mut cfg = NotifyConfig::from(&AlertsConfig::default());
    cfg.min_severity = Severity::Info;
    let n = Notifier::new(sink.clone(), store.clone(), cfg);
    sync(
        &store,
        vec![cond("latency_outlier", "nonce:6:0x01", Severity::Info)],
        NOW,
    )
    .await;
    n.tick(NOW + 1).await.unwrap();
    assert_eq!(sink.delivered().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn notifier_writes_its_health_row() {
    let store = open();
    let sink = FakeSink::new();
    let n = notifier(&sink, &store);
    n.tick(NOW).await.unwrap();
    let row = |store: &SharedStore| {
        let store = store.clone();
        async move {
            store
                .run(|s| Ok(s.status_report(NOW + 100)?.components))
                .await
                .unwrap()
        }
    };
    let h = row(&store).await;
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].component, "notifier");
    assert_eq!(h[0].last_ok_at, Some(NOW));

    sync(
        &store,
        vec![cond("unclaimed", "nonce:6:0x01", Severity::Warning)],
        NOW,
    )
    .await;
    sink.fail_next(1);
    n.tick(NOW + 5).await.unwrap();
    let h = row(&store).await;
    assert_eq!(h[0].consecutive_failures, 1);
    assert!(h[0].last_error.is_some());
}

#[test]
fn notifier_run_future_is_send() {
    fn assert_send<T: Send>(_: &T) {}
    let n = notifier(&FakeSink::new(), &open());
    assert_send(&n.run(tokio_util::sync::CancellationToken::new()));
}

// ---------------------------------------------------------------------------
// Formatting and the Telegram request/reply shapes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn format_alert_is_plain_text() {
    let store = open();
    sync(
        &store,
        vec![cond("field_mismatch", "nonce:6:0x01", Severity::Critical)],
        NOW,
    )
    .await;
    let alert = alerts(&store).await.remove(0);
    assert_eq!(
        format_alert(&alert),
        "[CRITICAL] field_mismatch\nnonce:6:0x01\nfield_mismatch on nonce:6:0x01"
    );
}

#[test]
fn telegram_payload_shape() {
    let p = telegram_payload("-100123", "hello");
    assert_eq!(p["chat_id"], "-100123");
    assert_eq!(p["text"], "hello");
    assert_eq!(p["disable_web_page_preview"], true);
    assert!(p.get("parse_mode").is_none(), "plain text only");
    let long = "x".repeat(10_000);
    assert_eq!(
        telegram_payload("1", &long)["text"].as_str().unwrap().len(),
        4000
    );
}

#[test]
fn telegram_reply_parsing() {
    let token = "123456:SECRET-TOKEN";
    assert!(parse_telegram_reply(200, r#"{"ok":true,"result":{}}"#, token).is_ok());

    match parse_telegram_reply(
        429,
        r#"{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 17","parameters":{"retry_after":17}}"#,
        token,
    ) {
        Err(SinkError::RetryAfter(d)) => assert_eq!(d, Duration::from_secs(17)),
        other => panic!("expected RetryAfter, got {other:?}"),
    }
    match parse_telegram_reply(429, "not json", token) {
        Err(SinkError::RetryAfter(d)) => assert_eq!(d, Duration::from_secs(30)),
        other => panic!("expected RetryAfter, got {other:?}"),
    }

    match parse_telegram_reply(
        401,
        r#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#,
        token,
    ) {
        Err(SinkError::Transient(t)) => assert_eq!(t, "telegram HTTP 401: Unauthorized"),
        other => panic!("expected Transient, got {other:?}"),
    }
    // HTTP 200 with ok=false is still a failure.
    assert!(matches!(
        parse_telegram_reply(200, r#"{"ok":false,"description":"bad"}"#, token),
        Err(SinkError::Transient(_))
    ));
}

#[test]
fn telegram_errors_never_contain_the_token() {
    let token = "123456:SECRET-TOKEN";
    let body = format!(r#"{{"ok":false,"description":"cannot reach bot{token}/sendMessage"}}"#);
    let err = parse_telegram_reply(502, &body, token).unwrap_err();
    assert!(!err.to_string().contains("SECRET-TOKEN"), "{err}");
}
