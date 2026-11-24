//! Configuration: TOML file, validation, defaults, environment secrets and URL
//! redaction.
//!
//! Invariants:
//! - Secrets never come from TOML. Every struct uses `deny_unknown_fields`, so
//!   a secret key placed in the file fails to parse.
//! - Secrets never reach logs: [`Secrets`] prints `<redacted>` in `Debug`, and
//!   [`redact_url`] / [`scrub_url`] strip RPC URLs from text.
//! - Every field has a default (the mainnet values of
//!   `config/bridge-watcher.example.toml`), so a partial file is valid.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde::de::{self, Deserializer};

use crate::domain::Bytes32;
use crate::monitor::Severity;

/// Configuration failure. The process exits with code 2.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read config {path}: {source}")]
    Io {
        /// File path.
        path: PathBuf,
        /// Cause.
        source: std::io::Error,
    },
    /// The TOML is malformed, has an unknown key, or a value of the wrong type.
    #[error("invalid config: {0}")]
    Parse(String),
    /// A value is out of range or inconsistent.
    #[error("invalid config: {0}")]
    Invalid(String),
    /// Environment variables are inconsistent.
    #[error("invalid environment: {0}")]
    Env(String),
}

/// 20-byte EVM address, parsed from `0x` + 40 hex characters (any case).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmAddress(pub [u8; 20]);

impl<'de> Deserialize<'de> for EvmAddress {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let h = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .ok_or_else(|| de::Error::custom(format!("EVM address must start with 0x: {s}")))?;
        let bytes =
            hex::decode(h).map_err(|e| de::Error::custom(format!("bad EVM address {s}: {e}")))?;
        let arr: [u8; 20] = bytes
            .try_into()
            .map_err(|_| de::Error::custom(format!("EVM address must be 20 bytes: {s}")))?;
        Ok(EvmAddress(arr))
    }
}

/// Solana public key, parsed from base58.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pubkey(pub Bytes32);

impl<'de> Deserialize<'de> for Pubkey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Bytes32::from_base58(&s)
            .map(Pubkey)
            .map_err(|_| de::Error::custom(format!("bad Solana public key: {s}")))
    }
}

/// An RPC URL. It may carry an API key in its path, query or userinfo, so
/// whichever URL a client uses (TOML or environment) is a secret: `Debug`
/// prints [`redact_url`], and the text is available only through `as_str`.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct SecretUrl(String);

impl SecretUrl {
    /// Wraps a URL.
    pub fn new(url: impl Into<String>) -> Self {
        SecretUrl(url.into())
    }

    /// The full URL. Never log it; log [`redact_url`] of it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&redact_url(&self.0))
    }
}

/// `[database]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DatabaseConfig {
    /// SQLite file path. The directory must exist.
    pub path: PathBuf,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("data/bridge-watcher.db"),
        }
    }
}

/// `[evm]`: the EVM chain of the pair (Base).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EvmConfig {
    /// Name used in logs and as the `chain_state.name` value.
    pub name: String,
    /// CCTP domain id.
    pub domain: u32,
    /// Default RPC URL. `BW_EVM_RPC_URL` overrides it.
    pub rpc_url: SecretUrl,
    /// MessageTransmitterV2 address.
    pub message_transmitter: EvmAddress,
    /// TokenMessengerV2 address.
    pub token_messenger: EvmAddress,
    /// First block to ingest on the first run; absent means the current
    /// finalized block (no backfill). Ignored after the first run.
    pub start_height: Option<u64>,
    /// Seconds between ingestor ticks.
    pub poll_interval_secs: u64,
    /// RPC request budget.
    pub requests_per_second: f64,
    /// Maximum block range of one `eth_getLogs` call.
    pub max_log_range: u64,
    /// Blocks above finalized that the tail scan covers.
    pub tail_max: u64,
    /// Scans per phase per tick.
    pub max_scans_per_tick: u32,
    /// `finality_stalled` threshold in blocks.
    pub finality_lag_alert: u64,
    /// Fast attestation SLA in seconds.
    pub attestation_sla_fast_secs: u64,
    /// Standard attestation SLA in seconds.
    pub attestation_sla_standard_secs: u64,
}

impl Default for EvmConfig {
    fn default() -> Self {
        Self {
            name: "base".into(),
            domain: 6,
            rpc_url: SecretUrl::new("https://base-rpc.publicnode.com"),
            message_transmitter: EvmAddress(
                hex::decode("81D40F21F12A8F0E3252Bccb954D722d4c464B64")
                    .expect("valid hex")
                    .try_into()
                    .expect("20 bytes"),
            ),
            token_messenger: EvmAddress(
                hex::decode("28b5a0e9C621a5BadaA536219b3a228C8168cf5d")
                    .expect("valid hex")
                    .try_into()
                    .expect("20 bytes"),
            ),
            start_height: None,
            poll_interval_secs: 10,
            requests_per_second: 10.0,
            max_log_range: 10_000,
            tail_max: 10_000,
            max_scans_per_tick: 10,
            finality_lag_alert: 9_000,
            attestation_sla_fast_secs: 300,
            attestation_sla_standard_secs: 3600,
        }
    }
}

/// `[solana]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SolanaConfig {
    /// Name used in logs and as the `chain_state.name` value.
    pub name: String,
    /// CCTP domain id.
    pub domain: u32,
    /// Default RPC URL. `BW_SOLANA_RPC_URL` overrides it.
    pub rpc_url: SecretUrl,
    /// MessageTransmitterV2 program id.
    pub message_transmitter: Pubkey,
    /// TokenMessengerMinterV2 program id.
    pub token_messenger_minter: Pubkey,
    /// Address passed to `getSignaturesForAddress`; defaults to
    /// `message_transmitter`. Use [`SolanaConfig::signature_address`].
    pub signature_address: Option<Pubkey>,
    /// First slot to ingest on the first run; absent means the current
    /// finalized slot (no backfill). Ignored after the first run.
    pub start_height: Option<u64>,
    /// Seconds between ingestor ticks.
    pub poll_interval_secs: u64,
    /// RPC request budget.
    pub requests_per_second: f64,
    /// Maximum transactions fetched by one scan.
    pub max_tx_fetch_per_scan: usize,
    /// Slots subtracted from the finalized slot.
    pub final_margin: u64,
    /// Slots above finalized that the tail scan covers.
    pub tail_max: u64,
    /// Scans per phase per tick.
    pub max_scans_per_tick: u32,
    /// `finality_stalled` threshold in slots.
    pub finality_lag_alert: u64,
    /// Fast attestation SLA in seconds.
    pub attestation_sla_fast_secs: u64,
    /// Standard attestation SLA in seconds.
    pub attestation_sla_standard_secs: u64,
}

impl SolanaConfig {
    /// The address whose signatures are listed.
    pub fn signature_address(&self) -> Pubkey {
        self.signature_address.unwrap_or(self.message_transmitter)
    }
}

fn pubkey(s: &str) -> Pubkey {
    Pubkey(Bytes32::from_base58(s).expect("valid built-in pubkey"))
}

impl Default for SolanaConfig {
    fn default() -> Self {
        Self {
            name: "solana".into(),
            domain: 5,
            rpc_url: SecretUrl::new("https://api.mainnet-beta.solana.com"),
            message_transmitter: pubkey("CCTPV2Sm4AdWt5296sk4P66VBZ7bEhcARwFaaS9YPbeC"),
            token_messenger_minter: pubkey("CCTPV2vPZJS2u2BBsUoscuikbYjnpFmbFsvVuJdgUMQe"),
            signature_address: None,
            start_height: None,
            poll_interval_secs: 10,
            requests_per_second: 4.0,
            max_tx_fetch_per_scan: 40,
            final_margin: 16,
            tail_max: 300,
            max_scans_per_tick: 10,
            finality_lag_alert: 150,
            attestation_sla_fast_secs: 120,
            attestation_sla_standard_secs: 300,
        }
    }
}

/// `[iris]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct IrisConfig {
    /// API base URL.
    pub base_url: String,
    /// Client rate limit; validation rejects values above 10.
    pub requests_per_second: f64,
    /// Seconds between resolver ticks.
    pub poll_interval_secs: u64,
    /// First retry delay for a pending burn.
    pub initial_backoff_secs: u64,
    /// Cap of the retry delay.
    pub max_backoff_secs: u64,
    /// Pause after HTTP 429.
    pub lockout_secs: u64,
    /// Transactions polled per tick.
    pub max_txs_per_tick: usize,
    /// Age of an orphan receive before the source lookup starts.
    pub orphan_grace_secs: i64,
    /// Lookups per orphan receive.
    pub orphan_max_lookups: u32,
    /// HTTP timeout.
    pub request_timeout_secs: u64,
}

impl Default for IrisConfig {
    fn default() -> Self {
        Self {
            base_url: "https://iris-api.circle.com".into(),
            requests_per_second: 2.0,
            poll_interval_secs: 5,
            initial_backoff_secs: 10,
            max_backoff_secs: 120,
            lockout_secs: 310,
            max_txs_per_tick: 20,
            orphan_grace_secs: 600,
            orphan_max_lookups: 6,
            request_timeout_secs: 15,
        }
    }
}

/// `[monitor]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MonitorConfig {
    /// Seconds between monitor ticks.
    pub interval_secs: u64,
    /// Attested but unclaimed after this many seconds raises `unclaimed`.
    pub unclaimed_after_secs: i64,
    /// Lookups that found nothing before `mint_without_burn` fires.
    pub mint_without_burn_lookups: u32,
    /// A component silent for this long raises `component_stalled`.
    pub stall_after_secs: i64,
    /// Latencies sampled per direction and mode.
    pub latency_window: usize,
    /// Minimum samples for the outlier check.
    pub latency_min_samples: usize,
    /// MAD multiplier of the outlier bound.
    pub latency_mad_k: f64,
    /// Minimum excess over the median in seconds.
    pub latency_min_excess_secs: i64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            interval_secs: 30,
            unclaimed_after_secs: 3600,
            mint_without_burn_lookups: 3,
            stall_after_secs: 300,
            latency_window: 200,
            latency_min_samples: 20,
            latency_mad_k: 6.0,
            latency_min_excess_secs: 120,
        }
    }
}

/// `[alerts]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AlertsConfig {
    /// Alerts below this severity are logged only.
    pub min_severity: Severity,
    /// A resolved alert re-notifies only after this many seconds.
    pub renotify_after_secs: i64,
    /// Seconds between notifier ticks.
    pub notify_interval_secs: u64,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            min_severity: Severity::Warning,
            renotify_after_secs: 3600,
            notify_interval_secs: 5,
        }
    }
}

/// Whole configuration file.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// `[database]`
    pub database: DatabaseConfig,
    /// `[evm]`
    pub evm: EvmConfig,
    /// `[solana]`
    pub solana: SolanaConfig,
    /// `[iris]`
    pub iris: IrisConfig,
    /// `[monitor]`
    pub monitor: MonitorConfig,
    /// `[alerts]`
    pub alerts: AlertsConfig,
}

/// Builds a parse error from the message and the position only. The TOML
/// error's own `Display` quotes the source line, which could echo a secret that
/// was put into the file by mistake.
fn parse_error(text: &str, e: &toml::de::Error) -> ConfigError {
    let at = e
        .span()
        .map(|span| {
            let before = &text[..span.start.min(text.len())];
            let line = before.matches('\n').count() + 1;
            let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
            format!(" at line {line}, column {col}")
        })
        .unwrap_or_default();
    ConfigError::Parse(format!("{}{at}", e.message()))
}

fn is_http_url(s: &str) -> bool {
    reqwest::Url::parse(s)
        .map(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
        .unwrap_or(false)
}

fn require(ok: bool, what: &str) -> Result<(), ConfigError> {
    if ok {
        Ok(())
    } else {
        Err(ConfigError::Invalid(what.to_string()))
    }
}

impl Config {
    /// Reads, parses and validates the file at `path`.
    ///
    /// # Errors
    /// [`ConfigError::Io`], [`ConfigError::Parse`] (including unknown keys) or
    /// [`ConfigError::Invalid`].
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml(&text)
    }

    /// Parses and validates TOML text.
    ///
    /// # Errors
    /// [`ConfigError::Parse`] or [`ConfigError::Invalid`].
    pub fn from_toml(text: &str) -> Result<Config, ConfigError> {
        let cfg: Config = toml::from_str(text).map_err(|e| parse_error(text, &e))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Checks cross-field rules: distinct domains, positive intervals and
    /// limits, `iris.requests_per_second <= 10`, `tail_max >= 1`,
    /// `max_log_range >= 1`, `start_height >= 1`.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] naming the first violated rule.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let (e, s, i, m, a) = (
            &self.evm,
            &self.solana,
            &self.iris,
            &self.monitor,
            &self.alerts,
        );
        require(
            e.domain != s.domain,
            "evm.domain and solana.domain must differ",
        )?;
        require(
            !e.name.is_empty() && !s.name.is_empty(),
            "chain names must not be empty",
        )?;
        require(e.name != s.name, "evm.name and solana.name must differ")?;
        require(
            e.poll_interval_secs > 0 && s.poll_interval_secs > 0,
            "poll_interval_secs must be positive",
        )?;
        let rate_ok = |r: f64| r.is_finite() && r > 0.0;
        require(
            rate_ok(e.requests_per_second) && rate_ok(s.requests_per_second),
            "requests_per_second must be positive",
        )?;
        require(
            rate_ok(i.requests_per_second) && i.requests_per_second <= 10.0,
            "iris.requests_per_second must be in (0, 10]",
        )?;
        require(
            e.tail_max >= 1 && s.tail_max >= 1,
            "tail_max must be at least 1",
        )?;
        require(e.max_log_range >= 1, "evm.max_log_range must be at least 1")?;
        require(
            e.max_scans_per_tick >= 1 && s.max_scans_per_tick >= 1,
            "max_scans_per_tick must be at least 1",
        )?;
        require(
            s.max_tx_fetch_per_scan >= 1,
            "solana.max_tx_fetch_per_scan must be at least 1",
        )?;
        require(
            e.start_height != Some(0) && s.start_height != Some(0),
            "start_height must be at least 1",
        )?;
        require(
            i.poll_interval_secs > 0
                && i.initial_backoff_secs > 0
                && i.max_backoff_secs >= i.initial_backoff_secs
                && i.lockout_secs > 0
                && i.request_timeout_secs > 0
                && i.max_txs_per_tick >= 1,
            "iris intervals must be positive and max_backoff_secs >= initial_backoff_secs",
        )?;
        require(
            m.interval_secs > 0
                && m.stall_after_secs > 0
                && m.unclaimed_after_secs > 0
                && m.latency_window >= 1
                && m.latency_min_samples >= 1
                && m.latency_mad_k.is_finite()
                && m.latency_mad_k >= 0.0,
            "monitor intervals and windows must be positive",
        )?;
        require(
            a.notify_interval_secs > 0 && a.renotify_after_secs > 0,
            "alerts intervals must be positive",
        )?;
        require(
            is_http_url(e.rpc_url.as_str()) && is_http_url(s.rpc_url.as_str()),
            "rpc_url must be an http(s) URL",
        )?;
        require(
            is_http_url(&i.base_url),
            "iris.base_url must be an http(s) URL",
        )?;
        require(
            e.attestation_sla_fast_secs > 0
                && e.attestation_sla_standard_secs > 0
                && s.attestation_sla_fast_secs > 0
                && s.attestation_sla_standard_secs > 0,
            "attestation_sla_*_secs must be positive",
        )?;
        require(
            e.finality_lag_alert > 0 && s.finality_lag_alert > 0,
            "finality_lag_alert must be positive",
        )?;
        require(
            m.mint_without_burn_lookups >= 1 && i.orphan_max_lookups >= m.mint_without_burn_lookups,
            "need iris.orphan_max_lookups >= monitor.mint_without_burn_lookups >= 1",
        )?;
        require(
            m.latency_min_samples <= m.latency_window && m.latency_min_excess_secs >= 0,
            "monitor.latency_min_samples must not exceed latency_window",
        )?;
        require(
            i.orphan_grace_secs >= 0,
            "iris.orphan_grace_secs must not be negative",
        )?;
        Ok(())
    }
}

/// Telegram credentials. Both values come from the environment.
#[derive(Clone)]
pub struct TelegramSecrets {
    /// Bot token. It sits in the request URL path: never log that URL.
    pub bot_token: String,
    /// Target chat id.
    pub chat_id: String,
}

impl fmt::Debug for TelegramSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelegramSecrets")
            .field("bot_token", &"<redacted>")
            .field("chat_id", &"<redacted>")
            .finish()
    }
}

/// Secrets and overrides read from the environment.
#[derive(Clone, Default)]
pub struct Secrets {
    /// `BW_EVM_RPC_URL`: overrides `evm.rpc_url`; may hold an API key.
    pub evm_rpc_url: Option<String>,
    /// `BW_SOLANA_RPC_URL`: overrides `solana.rpc_url`; may hold an API key.
    pub solana_rpc_url: Option<String>,
    /// `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`, both or neither.
    pub telegram: Option<TelegramSecrets>,
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mark = |present: bool| if present { "<redacted>" } else { "<unset>" };
        f.debug_struct("Secrets")
            .field("evm_rpc_url", &mark(self.evm_rpc_url.is_some()))
            .field("solana_rpc_url", &mark(self.solana_rpc_url.is_some()))
            .field("telegram", &mark(self.telegram.is_some()))
            .finish()
    }
}

impl Secrets {
    /// Reads the process environment. Empty values count as unset.
    ///
    /// # Errors
    /// [`ConfigError::Env`] if only one Telegram variable is set.
    pub fn from_env() -> Result<Secrets, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Same as [`Secrets::from_env`] with an injected lookup, for tests.
    ///
    /// # Errors
    /// [`ConfigError::Env`] if only one Telegram variable is set.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Secrets, ConfigError> {
        let get = |name: &str| get(name).filter(|v| !v.trim().is_empty());
        let telegram = match (get("TELEGRAM_BOT_TOKEN"), get("TELEGRAM_CHAT_ID")) {
            (Some(bot_token), Some(chat_id)) => Some(TelegramSecrets { bot_token, chat_id }),
            (None, None) => None,
            _ => {
                return Err(ConfigError::Env(
                    "set both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, or neither".into(),
                ));
            }
        };
        Ok(Secrets {
            evm_rpc_url: get("BW_EVM_RPC_URL"),
            solana_rpc_url: get("BW_SOLANA_RPC_URL"),
            telegram,
        })
    }
}

/// Reduces a URL to `scheme://host/<redacted>`. Path, query, credentials and
/// port are dropped because RPC providers put API keys there. Text that is
/// not a URL becomes `<redacted>`.
pub fn redact_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(u) => match u.host_str() {
            Some(host) => format!("{}://{}/<redacted>", u.scheme(), host),
            None => "<redacted>".to_string(),
        },
        Err(_) => "<redacted>".to_string(),
    }
}

/// Removes an RPC URL from `text`.
///
/// Replaces the URL as written, its normalized form (lowercase host, added
/// `/`, default port dropped), and, on their own, its secret parts: path,
/// query, user name and password. HTTP clients quote either form in errors.
pub fn scrub_url(text: &str, url: &str) -> String {
    if url.is_empty() {
        return text.to_string();
    }
    let redacted = redact_url(url);
    let mut whole = vec![url.to_string()];
    let mut parts: Vec<String> = Vec::new();
    if let Ok(u) = reqwest::Url::parse(url) {
        whole.push(u.as_str().to_string());
        if u.path().len() > 1 {
            parts.push(u.path().to_string());
        }
        if let Some(q) = u.query().filter(|q| !q.is_empty()) {
            parts.push(q.to_string());
        }
        if !u.username().is_empty() {
            parts.push(u.username().to_string());
        }
        if let Some(pw) = u.password().filter(|p| !p.is_empty()) {
            parts.push(pw.to_string());
        }
    }
    whole.sort_by_key(|n| std::cmp::Reverse(n.len()));
    parts.retain(|p| p.len() >= 4);
    parts.sort_by_key(|n| std::cmp::Reverse(n.len()));
    let mut out = text.to_string();
    for needle in &whole {
        out = out.replace(needle.as_str(), &redacted);
    }
    for needle in &parts {
        out = out.replace(needle.as_str(), "<redacted>");
    }
    out
}
