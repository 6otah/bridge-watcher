//! Command-line entry point: `run`, `status` and `transfers`.
//!
//! Exit codes: 0 on success or a clean stop, 1 on a fatal runtime error, 2 on
//! a configuration or environment error.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bridge_watcher::clock::unix_now;
use bridge_watcher::config::{Config, ConfigError, Secrets};
use bridge_watcher::store::{Store, TransferFilter, TransferState};
use bridge_watcher::{app, cli};
use clap::{Parser, Subcommand, ValueEnum};
use tokio_util::sync::CancellationToken;

/// Read-only watcher for CCTP V2 USDC transfers between Solana and Base.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Path of the TOML config file.
    #[arg(
        long,
        global = true,
        env = "BW_CONFIG",
        default_value = "bridge-watcher.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start all background tasks.
    Run,
    /// Print chain cursors, transfer counts and open alerts.
    Status,
    /// List transfers, newest first.
    Transfers {
        /// Only transfers in this state.
        #[arg(long, value_enum)]
        state: Option<StateArg>,
        /// Maximum number of rows.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum StateArg {
    Burned,
    Attested,
    #[value(name = "pre_window")]
    PreWindow,
    Completed,
}

impl From<StateArg> for TransferState {
    fn from(s: StateArg) -> Self {
        match s {
            StateArg::Burned => TransferState::Burned,
            StateArg::Attested => TransferState::Attested,
            StateArg::PreWindow => TransferState::PreWindow,
            StateArg::Completed => TransferState::Completed,
        }
    }
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();
}

/// Opens the database read-only, or reports that there is none yet.
fn open_for_reading(path: &Path) -> Result<Option<Store>, ExitCode> {
    if !path.exists() {
        println!(
            "No database at {} yet. Start `bridge-watcher run` first.",
            path.display()
        );
        return Ok(None);
    }
    Store::open_read_only(path).map(Some).map_err(|e| {
        eprintln!("error: cannot read {}: {e}", path.display());
        ExitCode::FAILURE
    })
}

fn report_io<T>(r: std::io::Result<T>) -> ExitCode {
    match r {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    // The config path may come from `.env`, so load it before parsing.
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();
    let config = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    match cli.command {
        Command::Run => {
            init_logging();
            let secrets = match Secrets::from_env() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let shutdown = CancellationToken::new();
            let on_signal = shutdown.clone();
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    tracing::info!("Ctrl-C received; stopping");
                    on_signal.cancel();
                }
            });
            match app::run(config, secrets, shutdown).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) if e.downcast_ref::<ConfigError>().is_some() => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
                Err(e) => {
                    eprintln!("error: {e:#}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Status => match open_for_reading(&config.database.path) {
            Ok(None) => ExitCode::SUCCESS,
            Ok(Some(store)) => match store.status_report(unix_now()) {
                Ok(report) => report_io(cli::print_status(&report, &mut std::io::stdout())),
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            },
            Err(code) => code,
        },
        Command::Transfers { state, limit } => match open_for_reading(&config.database.path) {
            Ok(None) => ExitCode::SUCCESS,
            Ok(Some(store)) => {
                let filter = TransferFilter {
                    state: state.map(Into::into),
                    limit,
                };
                match store.list_transfers(&filter) {
                    Ok(rows) => {
                        let mut out = std::io::stdout().lock();
                        let r = cli::print_transfers(&rows, &mut out).and_then(|()| out.flush());
                        report_io(r)
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        ExitCode::FAILURE
                    }
                }
            }
            Err(code) => code,
        },
    }
}
