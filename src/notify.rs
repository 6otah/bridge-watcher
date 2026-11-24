//! Alert delivery: the [`AlertSink`] trait, the Telegram and log sinks, and the
//! outbox loop [`Notifier`].
//!
//! Delivery is at-least-once: an alert is marked delivered only
//! after the sink accepted it, so a crash between send and mark can repeat one
//! message.
//!
//! Secrets: the Telegram token sits in the request URL path. No code path logs
//! the URL, reqwest errors are stripped of it, and every error text is
//! scrubbed of the token before it leaves [`TelegramSink`].
//!
//! Telegram shapes (UNVERIFIED, U7; implemented from the public Bot API):
//! `POST /bot<token>/sendMessage` with JSON `{chat_id, text,
//! disable_web_page_preview}`; success is `{"ok": true, ...}`; a flood limit is
//! HTTP 429 with `{"ok": false, "parameters": {"retry_after": <secs>}}`.

use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::clock::unix_now;
use crate::config::{AlertsConfig, TelegramSecrets};
use crate::monitor::Severity;
use crate::ratelimit::RateLimiter;
use crate::store::{Alert, SharedStore, StoreError};

/// Health component name of the notifier loop.
pub const COMPONENT: &str = "notifier";

/// Telegram limits one message to 4096 characters; stay below it.
const MAX_TEXT_CHARS: usize = 4000;
/// Wait after a 429 without `retry_after`.
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(30);

/// A sink refused or failed to deliver an alert. Never fatal: the alert stays
/// in the outbox.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    /// Network error, HTTP error, or a rejected request. The text holds no
    /// secret.
    #[error("sink: {0}")]
    Transient(String),
    /// The service asks to wait before the next message.
    #[error("sink rate limited: retry after {0:?}")]
    RetryAfter(Duration),
}

/// Somewhere to send alerts.
pub trait AlertSink: Send + Sync + 'static {
    /// Delivers one alert. `Ok` means the sink accepted it.
    ///
    /// # Errors
    /// [`SinkError`]; the notifier keeps the alert and retries.
    fn deliver(&self, alert: &Alert) -> impl Future<Output = Result<(), SinkError>> + Send;
}

/// Plain-text form of an alert, with no markup, so no escaping is needed.
pub fn format_alert(alert: &Alert) -> String {
    format!(
        "[{}] {}\n{}\n{}",
        alert.severity.as_str().to_uppercase(),
        alert.kind,
        alert.subject,
        alert.message
    )
}

/// Sink for runs without Telegram. The [`Notifier`] already logs every alert,
/// so this sink only accepts.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogSink;

impl AlertSink for LogSink {
    async fn deliver(&self, alert: &Alert) -> Result<(), SinkError> {
        tracing::debug!(kind = %alert.kind, subject = %alert.subject, "alert accepted by log sink");
        Ok(())
    }
}

/// Request body of `sendMessage`. Pure.
pub fn telegram_payload(chat_id: &str, text: &str) -> Value {
    let text: String = text.chars().take(MAX_TEXT_CHARS).collect();
    json!({
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": true,
    })
}

/// Interprets a Telegram reply. Pure; `token` is scrubbed from error text.
///
/// # Errors
/// [`SinkError::RetryAfter`] on HTTP 429 (`parameters.retry_after`, or 30 s if
/// absent); [`SinkError::Transient`] on any other failure.
pub fn parse_telegram_reply(status: u16, body: &str, token: &str) -> Result<(), SinkError> {
    let value: Option<Value> = serde_json::from_str(body).ok();
    let ok = value
        .as_ref()
        .and_then(|v| v.get("ok"))
        .and_then(Value::as_bool);
    if (200..300).contains(&status) && ok != Some(false) {
        return Ok(());
    }
    if status == 429 {
        let secs = value
            .as_ref()
            .and_then(|v| v.pointer("/parameters/retry_after"))
            .and_then(Value::as_u64);
        return Err(SinkError::RetryAfter(
            secs.map_or(DEFAULT_RETRY_AFTER, Duration::from_secs),
        ));
    }
    let description = value
        .as_ref()
        .and_then(|v| v.get("description"))
        .and_then(Value::as_str)
        .unwrap_or("no description");
    Err(SinkError::Transient(scrub(
        &format!("telegram HTTP {status}: {description}"),
        token,
    )))
}

fn scrub(text: &str, token: &str) -> String {
    if token.is_empty() {
        text.to_string()
    } else {
        text.replace(token, "<redacted>")
    }
}

/// Sends alerts through the Telegram Bot API, at most one message per second.
pub struct TelegramSink {
    http: reqwest::Client,
    token: String,
    chat_id: String,
    limiter: RateLimiter,
}

impl std::fmt::Debug for TelegramSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramSink")
            .field("token", &"<redacted>")
            .field("chat_id", &"<redacted>")
            .finish()
    }
}

impl TelegramSink {
    /// Builds the sink from the environment secrets.
    ///
    /// # Errors
    /// [`SinkError::Transient`] if the HTTP client cannot be built.
    pub fn new(secrets: &TelegramSecrets) -> Result<TelegramSink, SinkError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| SinkError::Transient(e.without_url().to_string()))?;
        Ok(TelegramSink {
            http,
            token: secrets.bot_token.clone(),
            chat_id: secrets.chat_id.clone(),
            limiter: RateLimiter::new(1.0, 1),
        })
    }

    /// The request URL. It contains the token: never log it.
    fn endpoint(&self) -> String {
        format!("https://api.telegram.org/bot{}/sendMessage", self.token)
    }
}

impl AlertSink for TelegramSink {
    async fn deliver(&self, alert: &Alert) -> Result<(), SinkError> {
        self.limiter.acquire().await;
        let payload = telegram_payload(&self.chat_id, &format_alert(alert));
        let resp = self
            .http
            .post(self.endpoint())
            .json(&payload)
            .send()
            .await
            .map_err(|e| SinkError::Transient(scrub(&e.without_url().to_string(), &self.token)))?;
        let status = resp.status().as_u16();
        let body = resp
            .text()
            .await
            .map_err(|e| SinkError::Transient(scrub(&e.without_url().to_string(), &self.token)))?;
        parse_telegram_reply(status, &body, &self.token)
    }
}

/// Tuning of the [`Notifier`]. Built from `[alerts]` with
/// `From<&AlertsConfig>`.
#[derive(Clone, Debug)]
pub struct NotifyConfig {
    /// Alerts below this severity are logged and marked delivered, not sent.
    pub min_severity: Severity,
    /// Alerts read from the outbox per tick.
    pub batch: usize,
    /// Sleep between ticks.
    pub interval: Duration,
    /// Cap of the retry delay after a failed delivery.
    pub max_retry: Duration,
}

impl From<&AlertsConfig> for NotifyConfig {
    fn from(c: &AlertsConfig) -> Self {
        NotifyConfig {
            min_severity: c.min_severity,
            batch: 10,
            interval: Duration::from_secs(c.notify_interval_secs),
            max_retry: Duration::from_secs(300),
        }
    }
}

/// Reads the alert outbox and delivers through a sink.
pub struct Notifier<K> {
    sink: K,
    store: SharedStore,
    cfg: NotifyConfig,
    retry_not_before: Mutex<Option<Instant>>,
}

impl<K: AlertSink> Notifier<K> {
    /// Creates a notifier.
    pub fn new(sink: K, store: SharedStore, cfg: NotifyConfig) -> Notifier<K> {
        Notifier {
            sink,
            store,
            cfg,
            retry_not_before: Mutex::new(None),
        }
    }

    fn retry_delay(&self, error: &SinkError, attempts: u32) -> Duration {
        match error {
            SinkError::RetryAfter(d) => *d,
            SinkError::Transient(_) => {
                let secs = 5u64.saturating_mul(1u64 << attempts.min(16));
                Duration::from_secs(secs).min(self.cfg.max_retry)
            }
        }
    }

    /// One round: deliver the outbox in id order. Alerts below `min_severity`
    /// are logged and marked delivered without a send. On the first sink
    /// failure the round stops, the failure is stored, and no delivery is
    /// tried again until the retry delay has passed (tokio time). Writes the
    /// `notifier` health row. Returns the number of alerts marked delivered.
    ///
    /// # Errors
    /// [`StoreError`] only; sink failures are retried.
    pub async fn tick(&self, now: i64) -> Result<usize, StoreError> {
        let wait_until = *self
            .retry_not_before
            .lock()
            .map_err(|_| StoreError::Panicked)?;
        if wait_until.is_some_and(|t| Instant::now() < t) {
            return Ok(0);
        }
        let batch = self.cfg.batch;
        let outbox = self.store.run(move |s| s.alert_outbox(batch)).await?;
        let mut delivered = 0;
        let mut failure: Option<String> = None;
        for alert in outbox {
            if alert.notify_attempts == 0 {
                match alert.severity {
                    Severity::Info => {
                        tracing::info!(kind = %alert.kind, subject = %alert.subject, "{}", alert.message);
                    }
                    _ => {
                        tracing::warn!(kind = %alert.kind, subject = %alert.subject,
                            severity = alert.severity.as_str(), "{}", alert.message);
                    }
                }
            }
            if alert.severity >= self.cfg.min_severity
                && let Err(e) = self.sink.deliver(&alert).await
            {
                let delay = self.retry_delay(&e, alert.notify_attempts);
                *self
                    .retry_not_before
                    .lock()
                    .map_err(|_| StoreError::Panicked)? = Some(Instant::now() + delay);
                let (id, text) = (alert.id, e.to_string());
                failure = Some(text.clone());
                self.store
                    .run(move |s| s.record_alert_failure(id, &text))
                    .await?;
                tracing::warn!(alert_id = alert.id, error = %e, "alert delivery failed");
                break;
            }
            let id = alert.id;
            self.store
                .run(move |s| s.mark_alert_delivered(id, now))
                .await?;
            delivered += 1;
        }
        self.store
            .run(move |s| s.record_health(COMPONENT, failure.as_deref().map_or(Ok(()), Err), now))
            .await?;
        Ok(delivered)
    }

    /// Runs ticks every `interval` until `cancel` fires.
    ///
    /// # Errors
    /// The first [`StoreError`].
    pub async fn run(self, cancel: CancellationToken) -> Result<(), StoreError> {
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                result = self.tick(unix_now()) => { result?; }
            }
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                () = tokio::time::sleep(self.cfg.interval) => {}
            }
        }
    }
}
