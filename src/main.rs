//! Command-line entry point. Stub: `run`, `status` and `transfers` are wired
//! in phase P8; for now the binary only parses arguments and loads the config.

use std::path::PathBuf;
use std::process::ExitCode;

use bridge_watcher::config::Config;
use clap::{Parser, Subcommand, ValueEnum};

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
    Completed,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Err(e) = Config::load(&cli.config) {
        eprintln!("error: {e}");
        return ExitCode::from(2);
    }
    eprintln!("error: command {:?} is not implemented yet", cli.command);
    ExitCode::FAILURE
}
