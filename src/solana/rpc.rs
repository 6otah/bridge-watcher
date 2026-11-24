//! Solana JSON-RPC client and serde types (phase P5, ADR 0005).
//!
//! The client calls four methods: `getSlot`, `getSignaturesForAddress`,
//! `getTransaction` and `getBlockTime`. Response types hold only the fields the
//! watcher reads. Every optional field has a default and unknown fields are
//! ignored, because mainnet already has transaction version 1 and a response
//! can lack `meta.loadedAddresses`.
//!
//! [`SolanaRpcApi`] is the seam between the scan logic and the network.
//! [`RpcClient`] is the production implementation: it limits the request rate,
//! retries transient failures, and removes the RPC URL (a secret) from every
//! error text.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::config::scrub_url;
use crate::domain::Commitment;
use crate::ratelimit::RateLimiter;
use crate::source::SourceError;

/// JSON-RPC error code of a node that has not reached `minContextSlot`.
const CODE_MIN_CONTEXT_SLOT: i64 = -32016;
/// `getBlockTime` code for a slot that was skipped (it has no block).
const CODE_SLOT_SKIPPED: i64 = -32009;
/// `getBlockTime` code for a block the node does not have (yet): it may exist
/// on the chain, so this is a lag, not a skipped slot.
const CODE_BLOCK_NOT_AVAILABLE: i64 = -32004;
/// Longest `Retry-After` that the client honours.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);
/// Waits between the attempts of one request.
const RETRY_WAITS: [Duration; 2] = [Duration::from_millis(500), Duration::from_secs(2)];

/// One entry of `getSignaturesForAddress`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureEntry {
    /// Base58 signature.
    pub signature: String,
    /// Slot that holds the transaction.
    pub slot: u64,
    /// Transaction error; `None` for a successful transaction.
    #[serde(default)]
    pub err: Option<Value>,
}

/// Result of `getTransaction` with `encoding: "json"`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResult {
    /// Slot that holds the transaction.
    pub slot: u64,
    /// Unix seconds of the block; `None` if the node does not know it.
    #[serde(default)]
    pub block_time: Option<i64>,
    /// The transaction as sent.
    pub transaction: Transaction,
    /// Execution result; `None` only for very old transactions.
    #[serde(default)]
    pub meta: Option<Meta>,
}

/// The signed transaction.
#[derive(Clone, Debug, Deserialize)]
pub struct Transaction {
    /// Signatures; the first one identifies the transaction.
    #[serde(default)]
    pub signatures: Vec<String>,
    /// The message with the static account keys.
    pub message: Message,
}

/// Transaction message. Only the account keys are read.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    /// Static account keys (base58), in the runtime order.
    #[serde(default)]
    pub account_keys: Vec<String>,
}

/// Execution metadata.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    /// Execution error; `None` if the transaction succeeded.
    #[serde(default)]
    pub err: Option<Value>,
    /// Inner instructions, grouped by the top-level instruction that made
    /// them. Absent or null means none.
    #[serde(default)]
    pub inner_instructions: Option<Vec<InnerInstructions>>,
    /// Keys loaded from address lookup tables. Absent for legacy and some
    /// version 1 transactions.
    #[serde(default)]
    pub loaded_addresses: Option<LoadedAddresses>,
}

/// Inner instructions of one top-level instruction.
#[derive(Clone, Debug, Deserialize)]
pub struct InnerInstructions {
    /// The instructions, in execution order.
    #[serde(default)]
    pub instructions: Vec<InnerInstruction>,
}

/// One inner instruction. Accounts and stack height are not read.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InnerInstruction {
    /// Index of the program id in the full account key list.
    pub program_id_index: usize,
    /// Base58 instruction data.
    pub data: String,
}

/// Account keys that address lookup tables added to a v0 transaction.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct LoadedAddresses {
    /// Loaded writable keys; they follow the static keys.
    #[serde(default)]
    pub writable: Vec<String>,
    /// Loaded readonly keys; they follow the writable ones.
    #[serde(default)]
    pub readonly: Vec<String>,
}

/// Name of a commitment level in a request.
pub fn commitment_name(commitment: Commitment) -> &'static str {
    match commitment {
        Commitment::Finalized => "finalized",
        Commitment::Confirmed => "confirmed",
    }
}

/// JSON-RPC request body.
pub fn request_body(id: u64, method: &str, params: &Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

/// Params of `getSlot`.
pub fn get_slot_params(commitment: Commitment) -> Value {
    json!([{ "commitment": commitment_name(commitment) }])
}

/// Params of `getSignaturesForAddress`.
///
/// `min_context_slot` is sent only when given. Finalized scans give it so that
/// a lagging node fails instead of returning a short list.
pub fn get_signatures_params(
    address: &str,
    before: Option<&str>,
    limit: usize,
    commitment: Commitment,
    min_context_slot: Option<u64>,
) -> Value {
    let mut config = json!({ "limit": limit, "commitment": commitment_name(commitment) });
    if let Some(before) = before {
        config["before"] = json!(before);
    }
    if let Some(slot) = min_context_slot {
        config["minContextSlot"] = json!(slot);
    }
    json!([address, config])
}

/// Params of `getTransaction`: `json` encoding and
/// `maxSupportedTransactionVersion: 1`, without which a version 1
/// transaction is an error (ADR 0005).
pub fn get_transaction_params(signature: &str, commitment: Commitment) -> Value {
    json!([signature, {
        "encoding": "json",
        "commitment": commitment_name(commitment),
        "maxSupportedTransactionVersion": 1,
    }])
}

/// The node calls the Solana source needs. Errors must be redacted already.
pub trait SolanaRpcApi: Send + Sync + 'static {
    /// `getSlot` at `commitment`.
    fn get_slot(
        &self,
        commitment: Commitment,
    ) -> impl Future<Output = Result<u64, SourceError>> + Send;

    /// One page of `getSignaturesForAddress`, newest first.
    ///
    /// # Errors
    /// [`SourceError::Lagging`] if the node has not reached `min_context_slot`.
    fn get_signatures(
        &self,
        address: &str,
        before: Option<&str>,
        limit: usize,
        commitment: Commitment,
        min_context_slot: Option<u64>,
    ) -> impl Future<Output = Result<Vec<SignatureEntry>, SourceError>> + Send;

    /// `getTransaction`; `None` if the node does not have the transaction at
    /// `commitment`.
    fn get_transaction(
        &self,
        signature: &str,
        commitment: Commitment,
    ) -> impl Future<Output = Result<Option<TransactionResult>, SourceError>> + Send;

    /// `getBlockTime`. `None` if the slot has no block time: it was skipped
    /// (code -32009) or the answer is null.
    ///
    /// # Errors
    /// [`SourceError::Lagging`] if the node does not have the block (code
    /// -32004): the block may exist, so the caller must not treat the slot as
    /// skipped.
    fn get_block_time(
        &self,
        slot: u64,
    ) -> impl Future<Output = Result<Option<i64>, SourceError>> + Send;
}

/// JSON-RPC error object of a response.
#[derive(Debug, Deserialize)]
struct ErrorBody {
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(default)]
    result: Value,
    #[serde(default)]
    error: Option<ErrorBody>,
}

/// Failure of one HTTP exchange.
enum Failure {
    /// Worth another attempt; `wait` overrides the default pause.
    Transient {
        error: SourceError,
        wait: Option<Duration>,
    },
    /// Another attempt would fail the same way.
    Permanent(SourceError),
}

/// The one place that builds error texts: the RPC URL is removed from them.
fn failure(url: &str, method: &str, what: impl std::fmt::Display) -> SourceError {
    SourceError::Rpc(scrub_url(&format!("{method}: {what}"), url))
}

/// [`SolanaRpcApi`] over HTTP with reqwest.
///
/// The URL is a secret whatever its origin: it is kept only to send requests
/// and to scrub it from error texts, and it is never printed.
pub struct RpcClient {
    http: reqwest::Client,
    url: String,
    limiter: RateLimiter,
    next_id: AtomicU64,
}

impl RpcClient {
    /// Builds the client: connect timeout 10 s, request timeout 30 s.
    ///
    /// # Errors
    /// [`SourceError::Rpc`] if the URL does not parse or the HTTP client cannot
    /// be built. The message never contains the URL.
    pub fn new(rpc_url: &str, requests_per_second: f64) -> Result<Self, SourceError> {
        reqwest::Url::parse(rpc_url)
            .map_err(|_| SourceError::Rpc("invalid Solana RPC URL".into()))?;
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| SourceError::Rpc(scrub_url(&e.without_url().to_string(), rpc_url)))?;
        let burst = requests_per_second.ceil().max(1.0) as u32;
        Ok(Self {
            http,
            url: rpc_url.to_string(),
            limiter: RateLimiter::new(requests_per_second, burst),
            next_id: AtomicU64::new(1),
        })
    }

    fn fail(&self, method: &str, what: impl std::fmt::Display) -> SourceError {
        failure(&self.url, method, what)
    }

    async fn exchange(&self, method: &str, body: &Value) -> Result<Envelope, Failure> {
        let transient = |error, wait| Failure::Transient { error, wait };
        let resp = self
            .http
            .post(&self.url)
            .json(body)
            .send()
            .await
            .map_err(|e| transient(self.fail(method, e.without_url()), None))?;
        let status = resp.status();
        if status.is_server_error() || status.as_u16() == 429 {
            let wait = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(|s| Duration::from_secs(s).min(MAX_RETRY_AFTER));
            return Err(transient(self.fail(method, format!("HTTP {status}")), wait));
        }
        if !status.is_success() {
            return Err(Failure::Permanent(
                self.fail(method, format!("HTTP {status}")),
            ));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| transient(self.fail(method, e.without_url()), None))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Failure::Permanent(self.fail(method, format!("bad response: {e}"))))
    }

    /// Sends one request under the rate limit, with up to three attempts for
    /// transport errors, HTTP 5xx and 429. The outer error is a failed
    /// exchange, the inner one a JSON-RPC error object.
    async fn call_value(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Result<Value, ErrorBody>, SourceError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = request_body(id, method, &params);
        let mut attempt = 0;
        loop {
            self.limiter.acquire().await;
            match self.exchange(method, &body).await {
                Ok(env) => {
                    return Ok(match env.error {
                        Some(err) => Err(err),
                        None => Ok(env.result),
                    });
                }
                Err(Failure::Transient { error, wait }) if attempt < RETRY_WAITS.len() => {
                    tracing::debug!(%method, attempt, error = %error, "retrying request");
                    tokio::time::sleep(wait.unwrap_or(RETRY_WAITS[attempt])).await;
                    attempt += 1;
                }
                Err(Failure::Transient { error, .. } | Failure::Permanent(error)) => {
                    return Err(error);
                }
            }
        }
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, SourceError> {
        match self.call_value(method, params).await? {
            Ok(value) => serde_json::from_value(value)
                .map_err(|e| self.fail(method, format!("unexpected result shape: {e}"))),
            Err(ErrorBody { code, message }) if code == CODE_MIN_CONTEXT_SLOT => Err(
                SourceError::Lagging(scrub_url(&format!("{method}: {message}"), &self.url)),
            ),
            Err(ErrorBody { code, message }) => {
                Err(self.fail(method, format!("error {code}: {message}")))
            }
        }
    }
}

impl SolanaRpcApi for RpcClient {
    async fn get_slot(&self, commitment: Commitment) -> Result<u64, SourceError> {
        self.call("getSlot", get_slot_params(commitment)).await
    }

    async fn get_signatures(
        &self,
        address: &str,
        before: Option<&str>,
        limit: usize,
        commitment: Commitment,
        min_context_slot: Option<u64>,
    ) -> Result<Vec<SignatureEntry>, SourceError> {
        let params = get_signatures_params(address, before, limit, commitment, min_context_slot);
        self.call("getSignaturesForAddress", params).await
    }

    async fn get_transaction(
        &self,
        signature: &str,
        commitment: Commitment,
    ) -> Result<Option<TransactionResult>, SourceError> {
        self.call(
            "getTransaction",
            get_transaction_params(signature, commitment),
        )
        .await
    }

    async fn get_block_time(&self, slot: u64) -> Result<Option<i64>, SourceError> {
        match self.call_value("getBlockTime", json!([slot])).await? {
            Ok(value) => serde_json::from_value(value)
                .map_err(|e| self.fail("getBlockTime", format!("unexpected result shape: {e}"))),
            Err(ErrorBody { code, .. }) if code == CODE_SLOT_SKIPPED => Ok(None),
            Err(ErrorBody { code, message }) if code == CODE_BLOCK_NOT_AVAILABLE => Err(
                SourceError::Lagging(scrub_url(&format!("getBlockTime: {message}"), &self.url)),
            ),
            Err(ErrorBody { code, message }) => {
                Err(self.fail("getBlockTime", format!("error {code}: {message}")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_failure_text_never_holds_the_url() {
        let url = "https://solana.example.com/rpc/k3y-abcdef?api-key=zzzz9999";
        let SourceError::Rpc(text) = failure(
            url,
            "getSlot",
            format!("error sending request for url ({url}): timed out"),
        ) else {
            panic!("expected Rpc");
        };
        for secret in ["k3y-abcdef", "zzzz9999", "/rpc/"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        assert!(text.contains("timed out"));
    }
}
