//! Process wiring: builds clients, initialises cursors, spawns the background tasks and handles shutdown.
//!
//! [`run`] follows the startup order:
//! resolve the RPC URLs, open the store, build the clients, write the first-run
//! cursors, start the health run, spawn the five tasks. The first task that
//! returns a store error (or panics) cancels all the others and becomes the
//! error of [`run`]. The tasks share nothing but the store and the two chain
//! sources.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::clock::unix_now;
use crate::config::{Config, ConfigError, SecretUrl, Secrets, redact_url};
use crate::domain::{Bytes32, Counterparty, Domain};
use crate::evm::EvmSource;
use crate::ingest::{IngestConfig, Ingestor, TickError, init_cursor};
use crate::iris::IrisClient;
use crate::monitor::Monitor;
use crate::notify::{self, LogSink, Notifier, NotifyConfig, TelegramSink};
use crate::resolver::{self, Resolver, ResolverConfig};
use crate::solana::SolanaSource;
use crate::source::Chains;
use crate::store::{ChainLimits, SharedStore, StoreError};

/// Cap of the ingestors' backoff after failed ticks.
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// Time the tasks get to stop after the shutdown signal.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

/// Names of the `health` rows of one run, in one place so that
/// `Store::start_components` and every loop's `record_health` agree:
/// `ingest:<evm name>`, `ingest:<solana name>`, `resolver`, `notifier`. The
/// monitor has no row: it is the component that raises the stall alerts.
pub fn health_components(cfg: &Config) -> Vec<String> {
    vec![
        format!("ingest:{}", cfg.evm.name),
        format!("ingest:{}", cfg.solana.name),
        resolver::COMPONENT.to_string(),
        notify::COMPONENT.to_string(),
    ]
}

/// The URL a chain client uses: the environment override if set, else the
/// config value. The override is checked as an http(s) URL with a host.
///
/// # Errors
/// [`ConfigError::Env`] if the override is not such a URL. The message names
/// the variable and never echoes the value, which may hold an API key.
pub fn resolve_rpc_url(
    configured: &SecretUrl,
    override_url: Option<&str>,
    variable: &str,
) -> Result<SecretUrl, ConfigError> {
    let Some(url) = override_url else {
        return Ok(configured.clone());
    };
    let ok = reqwest::Url::parse(url)
        .map(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
        .unwrap_or(false);
    if ok {
        Ok(SecretUrl::new(url))
    } else {
        Err(ConfigError::Env(format!(
            "{variable} must be an http(s) URL with a host"
        )))
    }
}

/// The chain thresholds that the monitor needs and the database does not hold.
fn chain_limits(cfg: &Config) -> Vec<ChainLimits> {
    let secs = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
    vec![
        ChainLimits {
            domain: Domain(cfg.evm.domain),
            sla_fast_secs: secs(cfg.evm.attestation_sla_fast_secs),
            sla_standard_secs: secs(cfg.evm.attestation_sla_standard_secs),
            finality_lag_alert: cfg.evm.finality_lag_alert,
        },
        ChainLimits {
            domain: Domain(cfg.solana.domain),
            sla_fast_secs: secs(cfg.solana.attestation_sla_fast_secs),
            sla_standard_secs: secs(cfg.solana.attestation_sla_standard_secs),
            finality_lag_alert: cfg.solana.finality_lag_alert,
        },
    ]
}

type TaskResult = (&'static str, Result<(), StoreError>);

/// Remembers the first failure; later ones are only logged.
fn record(first: &mut Option<anyhow::Error>, joined: Result<TaskResult, tokio::task::JoinError>) {
    let failure = match joined {
        Ok((_, Ok(()))) => return,
        Ok((name, Err(e))) => anyhow!("{name} stopped: {e}"),
        Err(e) => anyhow!("a task panicked: {e}"),
    };
    if first.is_some() {
        tracing::error!(error = %failure, "another task failed during shutdown");
    } else {
        *first = Some(failure);
    }
}

fn ingest_config(poll_interval_secs: u64, tail_max: u64, max_scans_per_tick: u32) -> IngestConfig {
    IngestConfig {
        poll_interval: Duration::from_secs(poll_interval_secs),
        tail_max,
        max_scans_per_tick,
        max_backoff: MAX_BACKOFF,
    }
}

/// `init_cursor` that survives a node that cannot answer at start-up: a
/// [`SourceError`](crate::source::SourceError) (a failed call, a lagging node)
/// is logged and retried with the ingest backoff. Returns `Ok(None)` if
/// `shutdown` fires first.
///
/// # Errors
/// Only a store error, which is fatal.
async fn init_cursor_retrying<S: crate::source::ChainSource>(
    source: &S,
    store: &SharedStore,
    start_height: Option<u64>,
    poll_interval: Duration,
    shutdown: &CancellationToken,
) -> anyhow::Result<Option<crate::store::ChainCursor>> {
    let mut failures: u32 = 0;
    loop {
        let attempt = tokio::select! {
            () = shutdown.cancelled() => return Ok(None),
            attempt = init_cursor(source, store, start_height, unix_now()) => attempt,
        };
        match attempt {
            Ok(cursor) => return Ok(Some(cursor)),
            Err(TickError::Store(e)) => return Err(e.into()),
            Err(TickError::Source(e)) => {
                failures = failures.saturating_add(1);
                let wait = crate::ingest::backoff(poll_interval, MAX_BACKOFF, failures);
                tracing::warn!(
                    chain = source.name(), error = %e, retry_in_secs = wait.as_secs(),
                    "cannot read the start position; retrying"
                );
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(None),
                    () = tokio::time::sleep(wait) => {}
                }
            }
        }
    }
}

/// Runs the watcher until `shutdown` is cancelled or a task fails.
///
/// Startup: resolve the RPC URLs (an environment override must be
/// a valid http(s) URL); create the database's parent directory and open the
/// store; build the clients; `init_cursor` for both chains (first run only);
/// `Store::start_components` with [`health_components`]; spawn two ingestors,
/// the resolver, the monitor and the notifier. The notifier uses Telegram if
/// both secrets are set, else only the log.
///
/// # Errors
/// [`ConfigError`] (as the `anyhow` source) for an invalid RPC override.
/// Any other error is fatal: store failure, a client that cannot be built, a
/// first run that cannot read the finalized height, or a task that stopped
/// with a store error or panicked. A failing task cancels the others, which get
/// 15 s to stop. Clean cancellation returns `Ok(())`.
pub async fn run(
    config: Config,
    secrets: Secrets,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let evm_url = resolve_rpc_url(
        &config.evm.rpc_url,
        secrets.evm_rpc_url.as_deref(),
        "BW_EVM_RPC_URL",
    )?;
    let solana_url = resolve_rpc_url(
        &config.solana.rpc_url,
        secrets.solana_rpc_url.as_deref(),
        "BW_SOLANA_RPC_URL",
    )?;

    let db_path = &config.database.path;
    if let Some(dir) = db_path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create database directory {}", dir.display()))?;
    }
    let store = SharedStore::open(db_path).context("cannot open the database")?;

    let evm_peer = Counterparty {
        domain: Domain(config.solana.domain),
        token_messenger: config.solana.token_messenger_minter.0,
    };
    let solana_peer = Counterparty {
        domain: Domain(config.evm.domain),
        token_messenger: Bytes32::from_evm_address(config.evm.token_messenger.0),
    };
    let evm =
        Arc::new(EvmSource::new(&config.evm, evm_url.as_str(), evm_peer).context("EVM client")?);
    let solana = Arc::new(
        SolanaSource::new(&config.solana, solana_url.as_str(), solana_peer)
            .context("Solana client")?,
    );
    let iris = IrisClient::new(&config.iris).map_err(|e| anyhow!("Iris client: {e}"))?;
    tracing::info!(
        evm = %redact_url(evm_url.as_str()),
        solana = %redact_url(solana_url.as_str()),
        database = %db_path.display(),
        telegram = secrets.telegram.is_some(),
        "starting"
    );

    let Some(evm_cursor) = init_cursor_retrying(
        &*evm,
        &store,
        config.evm.start_height,
        Duration::from_secs(config.evm.poll_interval_secs),
        &shutdown,
    )
    .await
    .context("EVM cursor")?
    else {
        return Ok(());
    };
    let Some(solana_cursor) = init_cursor_retrying(
        &*solana,
        &store,
        config.solana.start_height,
        Duration::from_secs(config.solana.poll_interval_secs),
        &shutdown,
    )
    .await
    .context("Solana cursor")?
    else {
        return Ok(());
    };
    for c in [&evm_cursor, &solana_cursor] {
        tracing::info!(
            chain = %c.name, start = c.start_height, cursor = c.final_height,
            "cursor ready"
        );
    }

    let components = health_components(&config);
    store
        .run(move |s| {
            let names: Vec<&str> = components.iter().map(String::as_str).collect();
            s.start_components(&names, unix_now())
        })
        .await
        .context("cannot start the health run")?;

    let monitor = Monitor::new(
        store.clone(),
        config.monitor.clone(),
        chain_limits(&config),
        config.alerts.renotify_after_secs,
    );
    let resolver = Resolver::new(
        iris,
        Chains {
            a: Arc::clone(&evm),
            b: Arc::clone(&solana),
        },
        store.clone(),
        ResolverConfig::from(&config.iris),
    );
    let notify_cfg = NotifyConfig::from(&config.alerts);
    let evm_ingestor = Ingestor::new(
        Arc::clone(&evm),
        store.clone(),
        ingest_config(
            config.evm.poll_interval_secs,
            config.evm.tail_max,
            config.evm.max_scans_per_tick,
        ),
    );
    let solana_ingestor = Ingestor::new(
        Arc::clone(&solana),
        store.clone(),
        ingest_config(
            config.solana.poll_interval_secs,
            config.solana.tail_max,
            config.solana.max_scans_per_tick,
        ),
    );

    let mut tasks: JoinSet<TaskResult> = JoinSet::new();
    let c = shutdown.clone();
    tasks.spawn(async move { ("evm ingestor", evm_ingestor.run(c).await) });
    let c = shutdown.clone();
    tasks.spawn(async move { ("solana ingestor", solana_ingestor.run(c).await) });
    let c = shutdown.clone();
    tasks.spawn(async move { ("resolver", resolver.run(c).await) });
    let c = shutdown.clone();
    tasks.spawn(async move { ("monitor", monitor.run(c).await) });
    let c = shutdown.clone();
    match &secrets.telegram {
        Some(t) => {
            let sink = TelegramSink::new(t).map_err(|e| anyhow!("Telegram sink: {e}"))?;
            let notifier = Notifier::new(sink, store.clone(), notify_cfg);
            tasks.spawn(async move { ("notifier", notifier.run(c).await) });
        }
        None => {
            let notifier = Notifier::new(LogSink, store.clone(), notify_cfg);
            tasks.spawn(async move { ("notifier", notifier.run(c).await) });
        }
    }

    let mut first: Option<anyhow::Error> = None;
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            joined = tasks.join_next() => match joined {
                None => break,
                Some(joined) => {
                    let failed = !matches!(joined, Ok((_, Ok(()))));
                    record(&mut first, joined);
                    if failed {
                        break;
                    }
                }
            },
        }
    }
    shutdown.cancel();
    let drain = async {
        while let Some(joined) = tasks.join_next().await {
            record(&mut first, joined);
        }
    };
    if tokio::time::timeout(SHUTDOWN_GRACE, drain).await.is_err() {
        tracing::error!("tasks did not stop within the grace period");
    }
    match first {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_override_must_be_an_http_url_and_is_never_echoed() {
        let configured = SecretUrl::new("https://configured.example/");
        let kept = resolve_rpc_url(&configured, None, "BW_X").unwrap();
        assert_eq!(kept.as_str(), "https://configured.example/");
        let set = resolve_rpc_url(&configured, Some("https://rpc.example/v2/KEY"), "BW_X").unwrap();
        assert_eq!(set.as_str(), "https://rpc.example/v2/KEY");
        for bad in [
            "ftp://rpc.example/KEY-1234",
            "rpc.example/KEY-1234",
            "https://:99/KEY-1234",
            "KEY-1234",
        ] {
            let err = resolve_rpc_url(&configured, Some(bad), "BW_X").unwrap_err();
            assert!(matches!(err, ConfigError::Env(_)));
            assert!(!err.to_string().contains("KEY-1234"), "{err}");
            assert!(err.to_string().contains("BW_X"));
        }
    }

    #[test]
    fn health_components_match_the_loops() {
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(
            health_components(&cfg),
            ["ingest:base", "ingest:solana", "resolver", "notifier"]
        );
    }
}
