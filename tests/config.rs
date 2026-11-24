//! Configuration, secrets, redaction and rate limiter tests.

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use bridge_watcher::config::{
    Config, ConfigError, Secrets, TelegramSecrets, redact_url, scrub_url,
};
use bridge_watcher::monitor::Severity;
use bridge_watcher::ratelimit::RateLimiter;
use tokio::time::Instant;

fn example_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("config/bridge-watcher.example.toml")
}

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |name| map.get(name).cloned()
}

#[test]
fn config_example_parses() {
    let cfg = Config::load(&example_path()).unwrap();
    assert_eq!(cfg.evm.domain, 6);
    assert_eq!(cfg.solana.domain, 5);
    assert_eq!(cfg.evm.rpc_url.as_str(), "https://base-rpc.publicnode.com");
    assert_eq!(
        cfg.solana.rpc_url.as_str(),
        "https://api.mainnet-beta.solana.com"
    );
    assert_eq!(cfg.evm.start_height, None);
    assert_eq!(cfg.solana.start_height, None);
    assert_eq!(cfg.alerts.min_severity, Severity::Warning);
    assert_eq!(cfg.monitor.unclaimed_after_secs, 3600);
    assert_eq!(cfg.evm.attestation_sla_standard_secs, 3600);
    assert_eq!(
        cfg.solana.signature_address(),
        cfg.solana.message_transmitter
    );
    assert_eq!(
        hex::encode(cfg.evm.message_transmitter.0),
        "81d40f21f12a8f0e3252bccb954d722d4c464b64"
    );
    assert_eq!(
        cfg.solana.token_messenger_minter.0.to_base58(),
        "CCTPV2vPZJS2u2BBsUoscuikbYjnpFmbFsvVuJdgUMQe"
    );
}

#[test]
fn config_example_equals_defaults() {
    let example = Config::load(&example_path()).unwrap();
    let mut default = Config::from_toml("").unwrap();
    // The example spells out the default of signature_address.
    default.solana.signature_address = Some(default.solana.message_transmitter);
    assert_eq!(example.evm.rpc_url, default.evm.rpc_url);
    assert_eq!(example.solana.rpc_url, default.solana.rpc_url);
    assert_eq!(format!("{example:?}"), format!("{default:?}"));
}

#[test]
fn config_start_height_is_optional_and_parsed() {
    let cfg = Config::from_toml("[evm]\nstart_height = 100\n[solana]\nstart_height = 7\n").unwrap();
    assert_eq!(cfg.evm.start_height, Some(100));
    assert_eq!(cfg.solana.start_height, Some(7));
    let zero = Config::from_toml("[evm]\nstart_height = 0\n");
    assert!(matches!(zero, Err(ConfigError::Invalid(_))));
}

#[test]
fn config_rejects_secret_keys_in_toml() {
    for text in [
        "[alerts]
telegram_bot_token = \"123456:SECRETVALUE\"
",
        "telegram_bot_token = \"123456:SECRETVALUE\"
",
        "[evm]
api_key = \"SECRETVALUE\"
",
        "[evm]
start = \"SECRETVALUE\"
",
    ] {
        let err = Config::from_toml(text).expect_err(text);
        assert!(matches!(err, ConfigError::Parse(_)), "accepted: {text}");
        let shown = format!("{err} {err:?}");
        assert!(
            !shown.contains("SECRETVALUE"),
            "error echoes the secret: {shown}"
        );
        assert!(shown.contains("line"), "error has no position: {shown}");
    }
}

#[test]
fn config_rpc_url_is_secret_in_debug() {
    let cfg = Config::from_toml(
        "[evm]
rpc_url = \"https://base.example/v2/SECRETKEY\"
",
    )
    .unwrap();
    assert_eq!(
        cfg.evm.rpc_url.as_str(),
        "https://base.example/v2/SECRETKEY"
    );
    assert!(!format!("{cfg:?}").contains("SECRETKEY"));
    assert!(format!("{cfg:?}").contains("https://base.example/<redacted>"));
}

#[test]
fn config_rejects_iris_rate_above_cap() {
    let ok = Config::from_toml("[iris]\nrequests_per_second = 10\n");
    assert!(ok.is_ok());
    for rate in ["20", "10.5", "0", "-1"] {
        let text = format!("[iris]\nrequests_per_second = {rate}\n");
        assert!(
            matches!(Config::from_toml(&text), Err(ConfigError::Invalid(_))),
            "accepted rate {rate}"
        );
    }
}

#[test]
fn config_rejects_invalid_values() {
    for text in [
        "[evm]\ndomain = 5\n",
        "[evm]\ntail_max = 0\n",
        "[solana]\ntail_max = 0\n",
        "[evm]\nmax_log_range = 0\n",
        "[evm]\npoll_interval_secs = 0\n",
        "[solana]\nmax_tx_fetch_per_scan = 0\n",
        "[iris]\ninitial_backoff_secs = 500\n",
        "[evm]\nmessage_transmitter = \"0x1234\"\n",
        "[evm]\nmessage_transmitter = \"81D40F21F12A8F0E3252Bccb954D722d4c464B64\"\n",
        "[solana]\nmessage_transmitter = \"not-a-key\"\n",
        "[alerts]\nmin_severity = \"loud\"\n",
    ] {
        assert!(Config::from_toml(text).is_err(), "accepted: {text}");
    }
}

#[test]
fn config_load_reports_missing_file() {
    let err = Config::load(Path::new("does/not/exist.toml")).unwrap_err();
    assert!(matches!(err, ConfigError::Io { .. }));
}

#[test]
fn config_telegram_env_pair() {
    let both = Secrets::from_lookup(env(&[
        ("TELEGRAM_BOT_TOKEN", "123:abc"),
        ("TELEGRAM_CHAT_ID", "42"),
    ]))
    .unwrap();
    assert!(both.telegram.is_some());

    let none = Secrets::from_lookup(env(&[])).unwrap();
    assert!(none.telegram.is_none());

    // Empty values (as in .env.example) count as unset.
    let empty = Secrets::from_lookup(env(&[
        ("TELEGRAM_BOT_TOKEN", ""),
        ("TELEGRAM_CHAT_ID", ""),
        ("BW_EVM_RPC_URL", ""),
    ]))
    .unwrap();
    assert!(empty.telegram.is_none() && empty.evm_rpc_url.is_none());

    for pairs in [
        &[("TELEGRAM_BOT_TOKEN", "123:abc")][..],
        &[("TELEGRAM_CHAT_ID", "42")][..],
    ] {
        let err = Secrets::from_lookup(env(pairs)).unwrap_err();
        assert!(matches!(err, ConfigError::Env(_)));
    }
}

#[test]
fn config_rpc_env_overrides_are_read() {
    let s = Secrets::from_lookup(env(&[
        ("BW_EVM_RPC_URL", "https://base.example/v2/KEY1"),
        ("BW_SOLANA_RPC_URL", "https://sol.example/?api-key=KEY2"),
    ]))
    .unwrap();
    assert_eq!(
        s.evm_rpc_url.as_deref(),
        Some("https://base.example/v2/KEY1")
    );
    assert_eq!(
        s.solana_rpc_url.as_deref(),
        Some("https://sol.example/?api-key=KEY2")
    );
}

#[test]
fn redaction_hides_secrets() {
    assert_eq!(
        redact_url("https://base-mainnet.g.alchemy.com/v2/SECRETKEY"),
        "https://base-mainnet.g.alchemy.com/<redacted>"
    );
    assert_eq!(
        redact_url("https://user:pass@sol.example:8899/path?api-key=SECRETKEY#frag"),
        "https://sol.example/<redacted>"
    );
    assert_eq!(redact_url("not a url SECRETKEY"), "<redacted>");

    let secrets = Secrets {
        evm_rpc_url: Some("https://base.example/v2/SECRETKEY".into()),
        solana_rpc_url: Some("https://sol.example/?api-key=SECRETKEY".into()),
        telegram: Some(TelegramSecrets {
            bot_token: "SECRETTOKEN".into(),
            chat_id: "SECRETCHAT".into(),
        }),
    };
    let shown = format!("{secrets:?} {:?}", secrets.telegram);
    assert!(!shown.contains("SECRETKEY"));
    assert!(!shown.contains("SECRETTOKEN"));
    assert!(!shown.contains("SECRETCHAT"));
    assert!(shown.contains("<redacted>"));

    let url = "https://base.example/v2/SECRETKEY";
    let err = format!("error sending request for url ({url}): connection refused");
    let clean = scrub_url(&err, url);
    assert!(!clean.contains("SECRETKEY"));
    assert!(clean.contains("https://base.example/<redacted>"));
    assert_eq!(scrub_url("no url here", url), "no url here");

    // HTTP clients quote the normalized form: lowercase host, default port
    // dropped, "/" added.
    let url = "HTTPS://Base.Example:443/v2/SECRETKEY?k=SECRETQUERY";
    let normalized = "https://base.example/v2/SECRETKEY?k=SECRETQUERY";
    for text in [
        format!("error for url ({normalized}): timeout"),
        format!("error for url ({url}): timeout"),
        "bad path /v2/SECRETKEY in response".to_string(),
        "bad query k=SECRETQUERY in response".to_string(),
    ] {
        let clean = scrub_url(&text, url);
        assert!(
            !clean.contains("SECRETKEY") && !clean.contains("SECRETQUERY"),
            "not scrubbed: {clean}"
        );
    }
    let with_userinfo = "https://user1:SECRETPASS@sol.example/";
    let clean = scrub_url(&format!("failed: {with_userinfo}"), with_userinfo);
    assert!(!clean.contains("SECRETPASS") && !clean.contains("user1"));
}

#[tokio::test(start_paused = true)]
async fn rate_limiter_enforces_rate() {
    let limiter = RateLimiter::new(2.0, 2);
    let start = Instant::now();
    for _ in 0..10 {
        limiter.acquire().await;
    }
    let elapsed = start.elapsed();
    // 2 immediate (burst), then 8 more at 2 per second = 4 s.
    assert!(elapsed >= Duration::from_secs(4), "elapsed {elapsed:?}");
    assert!(elapsed < Duration::from_millis(4100), "elapsed {elapsed:?}");
}

#[tokio::test(start_paused = true)]
async fn rate_limiter_burst_is_immediate_and_refills() {
    let limiter = RateLimiter::new(1.0, 3);
    let start = Instant::now();
    for _ in 0..3 {
        limiter.acquire().await;
    }
    assert_eq!(start.elapsed(), Duration::ZERO);
    tokio::time::sleep(Duration::from_secs(10)).await;
    // The bucket refills only up to the burst size.
    let t = Instant::now();
    for _ in 0..4 {
        limiter.acquire().await;
    }
    assert!(t.elapsed() >= Duration::from_secs(1));
    assert!(t.elapsed() < Duration::from_millis(1100));
}
