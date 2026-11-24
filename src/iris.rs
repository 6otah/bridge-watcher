//! Circle Iris API: the [`IrisApi`] trait, the reqwest-based [`IrisClient`]
//! and the pure response parser [`parse_response`].
//!
//! Invariants:
//! - The client never exceeds the configured request rate (token bucket, far
//!   below the Iris limit of 40 req/s).
//! - HTTP 404 means "Iris does not know it" and is `Ok(None)`. HTTP 429 is
//!   [`IrisError::RateLimited`]; the caller must stop calling Iris for the
//!   lockout window. The client never retries a 429.
//! - Iris data is untrusted. The parser never fails on a single odd message:
//!   an unreadable `message` is reported as absent.
//!
//! Wire format (UNVERIFIED beyond the two mainnet fixtures, U6, U10): the
//! response is `{"messages": [...], "sourceTxHash": "..."}`; a message has
//! `message` (`"0x"` when not ready), `attestation` (hex or `"PENDING"`),
//! `status`, `cctpVersion`, `delayReason` and `destinationMintTxHash`.

use std::future::Future;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::config::IrisConfig;
use crate::domain::{Bytes32, Domain};
use crate::ratelimit::RateLimiter;

/// What to ask Iris for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IrisQuery {
    /// All messages of one source transaction (`?transactionHash=`).
    TxId(String),
    /// The message with one nonce (`?nonce=`).
    Nonce(Bytes32),
}

/// A parsed Iris answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrisResponse {
    /// Source transaction Iris reports (`sourceTxHash`), if present.
    pub source_tx: Option<String>,
    /// Messages in the order Iris returned them.
    pub messages: Vec<IrisMessage>,
}

/// One message of an [`IrisResponse`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrisMessage {
    /// Raw message bytes; `None` when Iris returns `"0x"` (not ready) or
    /// something that is not hex.
    pub message: Option<Vec<u8>>,
    /// The attestation is a hex signature (not `"PENDING"`, not null).
    pub attestation_ready: bool,
    /// `"complete"`, `"pending_confirmations"` or another Iris status.
    pub status: String,
    /// Why Iris delays the attestation, if it says so.
    pub delay_reason: Option<String>,
    /// CCTP version, if Iris states it.
    pub cctp_version: Option<u32>,
    /// `destinationMintTxHash`. Informational only; never used to match.
    pub destination_tx: Option<String>,
}

/// Failure of an Iris call.
#[derive(Debug, thiserror::Error)]
pub enum IrisError {
    /// HTTP 429. Iris locks the caller out for about 5 minutes after a breach.
    #[error("Iris rate limit (HTTP 429)")]
    RateLimited,
    /// Network error, HTTP 5xx or other status, or an unreadable body.
    #[error("iris: {0}")]
    Transient(String),
}

/// Read access to Iris.
pub trait IrisApi: Send + Sync + 'static {
    /// Fetches the messages of `query` for burns on `source`.
    ///
    /// `Ok(None)` means HTTP 404: Iris does not know the transaction or nonce.
    ///
    /// # Errors
    /// [`IrisError::RateLimited`] on HTTP 429; [`IrisError::Transient`] on any
    /// other failure.
    fn get_messages(
        &self,
        source: Domain,
        query: IrisQuery,
    ) -> impl Future<Output = Result<Option<IrisResponse>, IrisError>> + Send;
}

#[derive(Deserialize)]
struct RawResponse {
    #[serde(default)]
    messages: Vec<RawMessage>,
    #[serde(default, rename = "sourceTxHash")]
    source_tx: Option<String>,
}

#[derive(Deserialize)]
struct RawMessage {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    attestation: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default, rename = "cctpVersion")]
    cctp_version: Option<Value>,
    #[serde(default, rename = "delayReason")]
    delay_reason: Option<String>,
    #[serde(default, rename = "destinationMintTxHash")]
    destination_tx: Option<String>,
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    if digits.is_empty() {
        return None;
    }
    hex::decode(digits).ok()
}

fn parse_version(v: &Value) -> Option<u32> {
    match v {
        Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Parses the JSON body of a successful Iris answer.
///
/// `"0x"`, an empty string or non-hex text in `message` gives `None`. The
/// attestation counts as ready only when it is a non-empty hex string.
///
/// # Errors
/// [`IrisError::Transient`] if the body is not the expected JSON.
pub fn parse_response(json: &str) -> Result<IrisResponse, IrisError> {
    let raw: RawResponse =
        serde_json::from_str(json).map_err(|e| IrisError::Transient(format!("bad body: {e}")))?;
    let messages = raw
        .messages
        .into_iter()
        .map(|m| IrisMessage {
            message: m.message.as_deref().and_then(decode_hex),
            attestation_ready: m.attestation.as_deref().and_then(decode_hex).is_some(),
            status: m.status.unwrap_or_else(|| "unknown".to_string()),
            delay_reason: m.delay_reason,
            cctp_version: m.cctp_version.as_ref().and_then(parse_version),
            destination_tx: m.destination_tx,
        })
        .collect();
    Ok(IrisResponse {
        source_tx: raw.source_tx,
        messages,
    })
}

/// The URL of one request. Pure, so tests can check request building.
pub fn request_url(base_url: &str, source: Domain, query: &IrisQuery) -> String {
    let base = base_url.trim_end_matches('/');
    match query {
        IrisQuery::TxId(tx) => format!("{base}/v2/messages/{source}?transactionHash={tx}"),
        IrisQuery::Nonce(n) => format!("{base}/v2/messages/{source}?nonce={n}"),
    }
}

const ATTEMPT_WAITS: [Duration; 2] = [Duration::from_millis(500), Duration::from_secs(2)];

/// HTTP client for the Iris API.
///
/// Every request takes a token from one [`RateLimiter`]. Transport errors and
/// HTTP 5xx are retried up to 3 attempts in total (waits 0.5 s and 2 s); a 429
/// is never retried.
pub struct IrisClient {
    http: reqwest::Client,
    base_url: String,
    limiter: RateLimiter,
}

impl IrisClient {
    /// Builds a client from the `[iris]` config section.
    ///
    /// # Errors
    /// [`IrisError::Transient`] if the HTTP client cannot be built.
    pub fn new(cfg: &IrisConfig) -> Result<IrisClient, IrisError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(cfg.request_timeout_secs))
            .build()
            .map_err(|e| IrisError::Transient(e.without_url().to_string()))?;
        Ok(IrisClient {
            http,
            base_url: cfg.base_url.clone(),
            limiter: RateLimiter::new(cfg.requests_per_second, 1),
        })
    }

    async fn attempt(&self, url: &str) -> Result<Option<IrisResponse>, IrisError> {
        self.limiter.acquire().await;
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| IrisError::Transient(e.without_url().to_string()))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(IrisError::RateLimited);
        }
        if !status.is_success() {
            return Err(IrisError::Transient(format!("HTTP {status}")));
        }
        let body = resp
            .text()
            .await
            .map_err(|e| IrisError::Transient(e.without_url().to_string()))?;
        parse_response(&body).map(Some)
    }
}

impl IrisApi for IrisClient {
    async fn get_messages(
        &self,
        source: Domain,
        query: IrisQuery,
    ) -> Result<Option<IrisResponse>, IrisError> {
        let url = request_url(&self.base_url, source, &query);
        let mut waits = ATTEMPT_WAITS.iter();
        loop {
            match self.attempt(&url).await {
                Err(IrisError::Transient(e)) => match waits.next() {
                    Some(wait) => {
                        tracing::debug!(error = %e, "iris request failed, retrying");
                        tokio::time::sleep(*wait).await;
                    }
                    None => return Err(IrisError::Transient(e)),
                },
                other => return other,
            }
        }
    }
}
