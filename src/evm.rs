//! EVM chain source: alloy client, log filter and log decoding for Base.
//!
//! [`EvmSource`] reads `MessageSent` and `MessageReceived` logs of
//! MessageTransmitterV2 with `eth_getLogs` and turns the relevant ones into
//! [`ChainEvent`]s. The burn record is `MessageSent`, not `DepositForBurn`.
//!
//! What counts as relevant (S4 of the scan contract):
//! - a burn: the message `sender` is TokenMessengerV2 and the source domain is
//!   this chain, the destination domain is the counterparty;
//! - a receive: the `sourceDomain` is the counterparty and the `sender` is the
//!   counterparty token messenger.
//!
//! The node is reached through the small [`EvmRpc`] trait. [`AlloyRpc`] is the
//! production implementation: it limits the request rate, retries transport
//! errors, and removes the RPC URL (a secret) from every error text. Tests use
//! a fake [`EvmRpc`].

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};

use alloy::rpc::types::{BlockNumberOrTag, Filter, Log};
use alloy::sol_types::SolEvent;
use alloy::transports::RpcError;

use crate::codec::{ReceiveFields, decode_burn_message, decode_header, decode_receive};
use crate::config::{EvmConfig, scrub_url};
use crate::domain::{
    Bytes32, ChainEvent, Commitment, Counterparty, Domain, EventKind, EventLocation, Heights,
};
use crate::ratelimit::RateLimiter;
use crate::source::{ChainSource, ScanResult, SourceError, TxEvidence};

mod abi {
    alloy::sol! {
        event MessageSent(bytes message);
        event MessageReceived(
            address indexed caller,
            uint32 sourceDomain,
            bytes32 indexed nonce,
            bytes32 sender,
            uint32 indexed finalityThresholdExecuted,
            bytes messageBody
        );
    }
}

use abi::{MessageReceived, MessageSent};

/// Block-time cache size at which the cache is emptied.
const BLOCK_TIME_CACHE_MAX: usize = 4096;
/// Waits between the attempts of one request.
const RETRY_WAITS: [Duration; 2] = [Duration::from_millis(500), Duration::from_secs(2)];

/// Identity of the CCTP contracts on the EVM chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmIds {
    /// CCTP domain of this chain.
    pub domain: Domain,
    /// MessageTransmitterV2, the emitter of both events.
    pub message_transmitter: [u8; 20],
    /// TokenMessengerV2, the `sender` of burn messages.
    pub token_messenger: [u8; 20],
}

/// Header facts of one block that the source needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Block hash.
    pub hash: B256,
    /// Block timestamp, Unix seconds.
    pub timestamp: u64,
}

/// The node calls [`EvmSource`] needs. Errors must be redacted already.
pub trait EvmRpc: Send + Sync + 'static {
    /// Number of the `finalized` block, or `None` if the node has none.
    fn finalized_block(&self) -> impl Future<Output = Result<Option<u64>, SourceError>> + Send;
    /// Number of the latest block.
    fn block_number(&self) -> impl Future<Output = Result<u64, SourceError>> + Send;
    /// `eth_getLogs` with the given filter.
    fn get_logs(
        &self,
        filter: &Filter,
    ) -> impl Future<Output = Result<Vec<Log>, SourceError>> + Send;
    /// Header of block `number`, or `None` if the node does not have it.
    fn block_header(
        &self,
        number: u64,
    ) -> impl Future<Output = Result<Option<BlockHeader>, SourceError>> + Send;
    /// The receipt of `hash`, or `None` if there is none (unknown or pending
    /// transaction).
    fn tx_receipt(
        &self,
        hash: B256,
    ) -> impl Future<Output = Result<Option<TxReceipt>, SourceError>> + Send;
}

/// The parts of a transaction receipt that [`EvmSource::inspect_tx`] needs.
#[derive(Clone, Debug)]
pub struct TxReceipt {
    /// Block that holds the transaction.
    pub block_number: u64,
    /// Logs of the receipt. Empty for a reverted transaction.
    pub logs: Vec<Log>,
}

/// Longest `Retry-After` that the client honours.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Pause before the next attempt after `error`, or `None` if the request must
/// not be retried: attempts are used up, or the failure is not a transport
/// error (a JSON-RPC error answer would fail the same way), or it is marked
/// non-retryable. A server `Retry-After` replaces the default pause, capped at
/// 30 s.
fn retry_wait(error: &alloy::transports::TransportError, attempt: usize) -> Option<Duration> {
    use alloy::transports::TransportErrorKind::{HttpErrorWithRetryAfter, NonRetryable};
    let RpcError::Transport(kind) = error else {
        return None;
    };
    if attempt >= RETRY_WAITS.len() || matches!(kind, NonRetryable(_)) {
        return None;
    }
    Some(match kind {
        HttpErrorWithRetryAfter { retry_after, .. } => (*retry_after).min(MAX_RETRY_AFTER),
        _ => RETRY_WAITS[attempt],
    })
}

/// Maps an RPC failure to [`SourceError::Rpc`] with the URL removed.
fn rpc_error(url: &str, what: &str, err: &dyn std::fmt::Display) -> SourceError {
    SourceError::Rpc(scrub_url(&format!("{what}: {err}"), url))
}

/// [`EvmRpc`] over an alloy HTTP provider.
///
/// The URL is a secret whatever its origin: it is kept only to scrub it from
/// error texts, and it is never printed.
pub struct AlloyRpc {
    provider: RootProvider,
    url: String,
    limiter: RateLimiter,
}

impl AlloyRpc {
    /// Builds the client: connect timeout 10 s, request timeout 30 s.
    ///
    /// # Errors
    /// [`SourceError::Rpc`] if the URL does not parse or the HTTP client
    /// cannot be built. The message never contains the URL.
    pub fn new(rpc_url: &str, requests_per_second: f64) -> Result<Self, SourceError> {
        let parsed = reqwest::Url::parse(rpc_url)
            .map_err(|_| SourceError::Rpc("invalid EVM RPC URL".into()))?;
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| rpc_error(rpc_url, "http client", &e.without_url()))?;
        let burst = requests_per_second.ceil().max(1.0) as u32;
        Ok(Self {
            provider: ProviderBuilder::default().connect_reqwest(client, parsed),
            url: rpc_url.to_string(),
            limiter: RateLimiter::new(requests_per_second, burst),
        })
    }

    /// Runs `request` under the rate limit, up to three attempts for
    /// transport errors (including HTTP 5xx and 429).
    async fn call<T, Fut>(&self, what: &str, request: impl Fn() -> Fut) -> Result<T, SourceError>
    where
        Fut: Future<Output = Result<T, alloy::transports::TransportError>>,
    {
        let mut attempt = 0;
        loop {
            self.limiter.acquire().await;
            match request().await {
                Ok(v) => return Ok(v),
                Err(e) => match retry_wait(&e, attempt) {
                    Some(wait) => {
                        tokio::time::sleep(wait).await;
                        attempt += 1;
                    }
                    None => return Err(rpc_error(&self.url, what, &e)),
                },
            }
        }
    }
}

impl EvmRpc for AlloyRpc {
    async fn finalized_block(&self) -> Result<Option<u64>, SourceError> {
        let block = self
            .call("eth_getBlockByNumber(finalized)", || async {
                self.provider
                    .get_block_by_number(BlockNumberOrTag::Finalized)
                    .await
            })
            .await?;
        Ok(block.map(|b| b.header.number))
    }

    async fn block_number(&self) -> Result<u64, SourceError> {
        self.call("eth_blockNumber", || self.provider.get_block_number())
            .await
    }

    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>, SourceError> {
        self.call("eth_getLogs", || self.provider.get_logs(filter))
            .await
    }

    async fn block_header(&self, number: u64) -> Result<Option<BlockHeader>, SourceError> {
        let block = self
            .call("eth_getBlockByNumber", || async {
                self.provider
                    .get_block_by_number(BlockNumberOrTag::Number(number))
                    .await
            })
            .await?;
        Ok(block.map(|b| BlockHeader {
            hash: b.header.hash,
            timestamp: b.header.timestamp,
        }))
    }

    async fn tx_receipt(&self, hash: B256) -> Result<Option<TxReceipt>, SourceError> {
        let receipt = self
            .call("eth_getTransactionReceipt", || {
                self.provider.get_transaction_receipt(hash)
            })
            .await?;
        Ok(receipt.and_then(|r| {
            let block_number = r.block_number?;
            let logs = if r.status() {
                r.inner.logs().to_vec()
            } else {
                Vec::new()
            };
            Some(TxReceipt { block_number, logs })
        }))
    }
}

/// Reads CCTP events of one EVM chain.
///
/// Invariant: every returned event is a burn or receive of the configured
/// pair, lies in the scanned range, and has a block time.
pub struct EvmSource<R = AlloyRpc> {
    rpc: R,
    name: String,
    ids: EvmIds,
    cp: Counterparty,
    max_log_range: u64,
    /// Block times by block hash, for logs without `blockTimestamp`. Keyed by
    /// hash, so a reorged block cannot serve a stale time.
    block_times: Mutex<HashMap<B256, i64>>,
}

impl EvmSource<AlloyRpc> {
    /// Builds the source for `cfg` against `rpc_url` (the config URL or the
    /// `BW_EVM_RPC_URL` override).
    ///
    /// # Errors
    /// [`SourceError::Rpc`] if the URL is invalid; see [`AlloyRpc::new`].
    pub fn new(
        cfg: &EvmConfig,
        rpc_url: &str,
        counterparty: Counterparty,
    ) -> Result<Self, SourceError> {
        let rpc = AlloyRpc::new(rpc_url, cfg.requests_per_second)?;
        Ok(Self::with_rpc(rpc, cfg, counterparty))
    }
}

impl<R: EvmRpc> EvmSource<R> {
    /// Builds the source over any [`EvmRpc`]; used by tests.
    pub fn with_rpc(rpc: R, cfg: &EvmConfig, counterparty: Counterparty) -> Self {
        Self {
            rpc,
            name: cfg.name.clone(),
            ids: EvmIds {
                domain: Domain(cfg.domain),
                message_transmitter: cfg.message_transmitter.0,
                token_messenger: cfg.token_messenger.0,
            },
            cp: counterparty,
            max_log_range: cfg.max_log_range,
            block_times: Mutex::new(HashMap::new()),
        }
    }

    fn cached_time(&self, hash: &B256) -> Option<i64> {
        self.block_times
            .lock()
            .expect("block time cache lock")
            .get(hash)
            .copied()
    }

    fn cache_time(&self, hash: B256, time: i64) {
        let mut cache = self.block_times.lock().expect("block time cache lock");
        if cache.len() >= BLOCK_TIME_CACHE_MAX {
            cache.clear();
        }
        cache.insert(hash, time);
    }

    /// Block time of the log's block: the log's own `blockTimestamp` if the
    /// node sends it, else the cached or fetched header time.
    async fn block_time(&self, log: &Log, number: u64) -> Result<i64, SourceError> {
        if let Some(ts) = log.block_timestamp {
            return time_to_i64(ts);
        }
        let hash = log
            .block_hash
            .ok_or_else(|| SourceError::Rpc("log without block hash".into()))?;
        if let Some(t) = self.cached_time(&hash) {
            return Ok(t);
        }
        let header = self
            .rpc
            .block_header(number)
            .await?
            .ok_or_else(|| SourceError::Rpc(format!("block {number} not found")))?;
        if header.hash != hash {
            return Err(SourceError::Rpc(format!(
                "block {number} changed during the scan"
            )));
        }
        let time = time_to_i64(header.timestamp)?;
        self.cache_time(hash, time);
        Ok(time)
    }
}

fn time_to_i64(ts: u64) -> Result<i64, SourceError> {
    i64::try_from(ts).map_err(|_| SourceError::Rpc(format!("block timestamp {ts} out of range")))
}

/// The `eth_getLogs` filter of one scan: MessageTransmitterV2, both topics,
/// numeric bounds (never tags, so a moving `latest` cannot change the range).
pub fn log_filter(ids: &EvmIds, from_block: u64, to_block: u64) -> Filter {
    Filter::new()
        .address(Address::from(ids.message_transmitter))
        .event_signature(vec![
            MessageSent::SIGNATURE_HASH,
            MessageReceived::SIGNATURE_HASH,
        ])
        .from_block(from_block)
        .to_block(to_block)
}

/// Decodes the payload of a log of the right emitter and topic, without the
/// location. `None` if the log is not ours.
fn decode_kind(
    log: &Log,
    ids: &EvmIds,
    cp: Counterparty,
) -> Result<Option<EventKind>, SourceError> {
    if log.removed || log.address() != Address::from(ids.message_transmitter) {
        return Ok(None);
    }
    let Some(topic0) = log.topics().first() else {
        return Ok(None);
    };
    let undecodable = |reason: String| SourceError::Undecodable {
        tx_id: log
            .transaction_hash
            .map_or_else(|| "unknown".to_string(), |h| format!("{h:#x}")),
        reason,
    };
    if *topic0 == MessageSent::SIGNATURE_HASH {
        let ev = MessageSent::decode_raw_log(log.topics(), &log.data().data)
            .map_err(|e| undecodable(e.to_string()))?;
        let header = decode_header(&ev.message).map_err(|e| undecodable(e.to_string()))?;
        let ours = header.source_domain == ids.domain
            && header.destination_domain == cp.domain
            && header.sender == Bytes32::from_evm_address(ids.token_messenger);
        if !ours {
            return Ok(None);
        }
        let (burn, _) = decode_burn_message(&ev.message).map_err(|e| undecodable(e.to_string()))?;
        Ok(Some(EventKind::Burn(burn)))
    } else if *topic0 == MessageReceived::SIGNATURE_HASH {
        let ev = MessageReceived::decode_raw_log(log.topics(), &log.data().data)
            .map_err(|e| undecodable(e.to_string()))?;
        let source_domain = Domain(ev.sourceDomain);
        let sender = Bytes32(ev.sender.0);
        if source_domain != cp.domain || sender != cp.token_messenger {
            return Ok(None);
        }
        let receive = decode_receive(ReceiveFields {
            source_domain,
            nonce: Bytes32(ev.nonce.0),
            sender,
            caller: Bytes32::from_evm_address(ev.caller.into_array()),
            finality_threshold_executed: ev.finalityThresholdExecuted,
            message_body: &ev.messageBody,
        })
        .map_err(|e| undecodable(e.to_string()))?;
        Ok(Some(EventKind::Receive(receive)))
    } else {
        Ok(None)
    }
}

/// Location of a mined log. The log must carry block and log positions.
fn location(log: &Log, ids: &EvmIds, block_time: i64) -> Result<EventLocation, SourceError> {
    let missing = |what: &str| SourceError::Rpc(format!("log without {what}"));
    let tx = log
        .transaction_hash
        .ok_or_else(|| missing("transaction hash"))?;
    let index = log.log_index.ok_or_else(|| missing("log index"))?;
    Ok(EventLocation {
        domain: ids.domain,
        tx_id: format!("{tx:#x}"),
        event_index: u32::try_from(index)
            .map_err(|_| SourceError::Rpc(format!("log index {index} out of range")))?,
        height: log.block_number.ok_or_else(|| missing("block number"))?,
        block_hash: Some(format!(
            "{:#x}",
            log.block_hash.ok_or_else(|| missing("block hash"))?
        )),
        block_time,
    })
}

/// Turns one raw log into an event, or `None` if it is not ours.
///
/// Ignored: logs of another emitter, `removed` logs, other topics, burns that
/// are not from this chain's token messenger to the counterparty, and receives
/// that are not from the counterparty token messenger. The event key is
/// `(domain, transaction hash, logIndex)`.
///
/// The block time is the log's `blockTimestamp`; a log without it must be
/// completed by the caller first, as [`EvmSource::scan`] does.
///
/// # Errors
/// [`SourceError::Undecodable`] if a log of the right emitter and topic does
/// not decode. [`SourceError::Rpc`] if a relevant log lacks its position or
/// its block time.
pub fn event_from_log(
    log: &Log,
    ids: &EvmIds,
    cp: Counterparty,
) -> Result<Option<ChainEvent>, SourceError> {
    let Some(kind) = decode_kind(log, ids, cp)? else {
        return Ok(None);
    };
    let ts = log
        .block_timestamp
        .ok_or_else(|| SourceError::Rpc("log without block timestamp".into()))?;
    Ok(Some(ChainEvent {
        at: location(log, ids, time_to_i64(ts)?)?,
        kind,
    }))
}

impl<R: EvmRpc> ChainSource for EvmSource<R> {
    fn domain(&self) -> Domain {
        self.ids.domain
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn heights(&self) -> Result<Heights, SourceError> {
        let finalized = self
            .rpc
            .finalized_block()
            .await?
            .ok_or_else(|| SourceError::Rpc("node returned no finalized block".into()))?;
        let head = self.rpc.block_number().await?;
        Ok(Heights { finalized, head })
    }

    /// One `eth_getLogs` over `(after, min(up_to, after + max_log_range)]`.
    ///
    /// # Errors
    /// [`SourceError::Rpc`] for node errors and for an answer that breaks the
    /// scan contract: a log outside the range, a duplicate event key, or a
    /// block whose hash changed between `getLogs` and the header call.
    /// [`SourceError::Undecodable`] as in [`event_from_log`].
    async fn scan(
        &self,
        after: u64,
        up_to: u64,
        _commitment: Commitment,
    ) -> Result<ScanResult, SourceError> {
        if after >= up_to {
            return Err(SourceError::Rpc(format!(
                "empty scan range ({after}, {up_to}]"
            )));
        }
        let to = up_to.min(after.saturating_add(self.max_log_range));
        let logs = self
            .rpc
            .get_logs(&log_filter(&self.ids, after + 1, to))
            .await?;
        let mut events = Vec::new();
        let mut keys = HashSet::new();
        for log in &logs {
            let number = log
                .block_number
                .ok_or_else(|| SourceError::Rpc("log without block number".into()))?;
            if number <= after || number > to {
                return Err(SourceError::Rpc(format!(
                    "log in block {number} is outside ({after}, {to}]"
                )));
            }
            let Some(kind) = decode_kind(log, &self.ids, self.cp)? else {
                continue;
            };
            let at = location(log, &self.ids, self.block_time(log, number).await?)?;
            if !keys.insert((at.tx_id.clone(), at.event_index)) {
                return Err(SourceError::Rpc(format!(
                    "duplicate log {}#{}",
                    at.tx_id, at.event_index
                )));
            }
            events.push(ChainEvent { at, kind });
        }
        events.sort_by_key(|e| (e.at.height, e.at.event_index));
        Ok(ScanResult {
            events,
            complete_through: to,
        })
    }

    /// Block number and burns of the receipt of `tx_id`. A text that is not a
    /// transaction hash is unknown to the chain. Burns are decoded from the
    /// receipt logs with the ingestion rules (`decode_kind`); a reverted
    /// transaction has no logs, so no burns.
    ///
    /// Header timestamp of block `height` (every EVM height has a block).
    ///
    /// # Errors
    /// [`SourceError::Rpc`] for node errors, a missing block, or a timestamp
    /// out of range.
    async fn time_at_or_before(&self, height: u64) -> Result<(u64, i64), SourceError> {
        let header = self
            .rpc
            .block_header(height)
            .await?
            .ok_or_else(|| SourceError::Rpc(format!("block {height} not found")))?;
        Ok((height, time_to_i64(header.timestamp)?))
    }

    /// # Errors
    /// [`SourceError::Rpc`] for node errors; [`SourceError::Undecodable`] if a
    /// CCTP log of the receipt does not decode.
    async fn inspect_tx(&self, tx_id: &str) -> Result<Option<TxEvidence>, SourceError> {
        let Ok(hash) = tx_id.parse::<B256>() else {
            return Ok(None);
        };
        let Some(receipt) = self.rpc.tx_receipt(hash).await? else {
            return Ok(None);
        };
        let mut burns = Vec::new();
        for log in &receipt.logs {
            if let Some(EventKind::Burn(burn)) = decode_kind(log, &self.ids, self.cp)? {
                burns.push(burn);
            }
        }
        Ok(Some(TxEvidence {
            height: receipt.block_number,
            burns,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_wait_honours_retry_after_up_to_30_seconds() {
        use alloy::transports::{HttpError, TransportErrorKind};
        let limited = |secs: u64| {
            RpcError::Transport(TransportErrorKind::HttpErrorWithRetryAfter {
                error: HttpError {
                    status: 429,
                    body: String::new(),
                },
                retry_after: Duration::from_secs(secs),
            })
        };
        assert_eq!(retry_wait(&limited(7), 0), Some(Duration::from_secs(7)));
        assert_eq!(retry_wait(&limited(600), 1), Some(MAX_RETRY_AFTER));
        assert_eq!(retry_wait(&limited(7), 2), None, "three attempts only");

        let plain = TransportErrorKind::custom_str("connection reset");
        assert_eq!(retry_wait(&plain, 0), Some(RETRY_WAITS[0]));
        assert_eq!(retry_wait(&plain, 1), Some(RETRY_WAITS[1]));
        let fatal = TransportErrorKind::non_retryable_str("bad request");
        assert_eq!(retry_wait(&fatal, 0), None);
    }

    #[test]
    fn rpc_error_scrubs_the_url_in_every_form() {
        let url = "https://base-mainnet.example.com/v2/s3cr3t-key-123?token=abcdef12";
        let err = alloy::transports::TransportErrorKind::custom_str(&format!(
            "error sending request for url ({url}): connection refused"
        ));
        let SourceError::Rpc(text) = rpc_error(url, "eth_getLogs", &err) else {
            panic!("expected Rpc");
        };
        assert!(text.starts_with("eth_getLogs: "));
        for secret in ["s3cr3t-key-123", "abcdef12", "/v2/"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        assert!(text.contains("connection refused"));
    }
}
