//! `status` and `transfers` output (`docs/ARCHITECTURE.md` section 15.7) and
//! the binary's exit codes. Offline: the binary is only run for commands that
//! read a local database.

use std::path::Path;
use std::process::{Command, Output};

use bridge_watcher::cli::{print_status, print_transfers};
use bridge_watcher::domain::{Bytes32, Domain, Mode};
use bridge_watcher::store::{
    AlertCounts, ChainStatus, HealthRow, StatusReport, Store, TransferRow, TransferState,
};

const NOW: i64 = 1_795_521_500;

fn text(f: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>) -> String {
    let mut out = Vec::new();
    f(&mut out).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn cli_status_on_empty_db() {
    let store = Store::open_in_memory().unwrap();
    let report = store.status_report(1_800_000_000).unwrap();
    assert_eq!(
        text(|o| print_status(&report, o)),
        "bridge-watcher status at 2027-01-15 08:00:00 UTC\n\
         \n\
         Chains\n\
         \x20 none yet (start `bridge-watcher run` first)\n\
         \n\
         Transfers    burned 0   attested 0   pre_window 0   completed 0\n\
         Open alerts  critical 0   warning 0   info 0\n"
    );
}

fn health(component: &str, ok: Option<i64>, error: Option<&str>, failures: u32) -> HealthRow {
    HealthRow {
        component: component.to_string(),
        started_at: NOW - 600,
        last_ok_at: ok,
        last_error: error.map(str::to_string),
        last_error_at: error.map(|_| NOW - 20),
        consecutive_failures: failures,
    }
}

#[test]
fn cli_status_shows_chains_components_and_alerts() {
    let base_health = health("ingest:base", Some(NOW - 4), None, 0);
    let report = StatusReport {
        now: NOW,
        chains: vec![
            ChainStatus {
                domain: Domain(5),
                name: "solana".into(),
                start_height: 473_300_001,
                final_height: 473_335_800,
                observed_finalized: Some(473_335_816),
                observed_head: Some(473_335_900),
                scanned_head: None,
                caught_up_at: None,
                updated_at: NOW,
                cursor_lag: Some(16),
                health: Some(health(
                    "ingest:solana",
                    Some(NOW - 3000),
                    Some("rpc: HTTP 503"),
                    4,
                )),
            },
            ChainStatus {
                domain: Domain(6),
                name: "base".into(),
                start_height: 61_640_001,
                final_height: 61_649_100,
                observed_finalized: Some(61_649_100),
                observed_head: Some(61_654_500),
                scanned_head: Some(61_654_500),
                caught_up_at: Some(NOW - 12),
                updated_at: NOW,
                cursor_lag: Some(0),
                health: Some(base_health.clone()),
            },
        ],
        components: vec![
            base_health,
            health("notifier", Some(NOW - 2), None, 0),
            health("resolver", None, None, 0),
        ],
        burned: 1,
        attested: 2,
        pre_window: 4,
        completed: 30,
        open_alerts: AlertCounts {
            info: 3,
            warning: 1,
            critical: 0,
        },
    };
    let got = text(|o| print_status(&report, o));
    let expected = "bridge-watcher status at 2026-11-24 11:58:20 UTC

Chains
  solana (domain 5)
    cursor      473335800 (first height 473300001)
    finalized   473335816 (cursor lag 16)
    head        473335900
    scanned to  -
    caught up   never
    ingestor    failing: rpc: HTTP 503 (4 in a row, last 20 s ago)
  base (domain 6)
    cursor      61649100 (first height 61640001)
    finalized   61649100 (cursor lag 0)
    head        61654500
    scanned to  61654500
    caught up   2026-11-24 11:58:08 UTC (12 s ago)
    ingestor    ok, last ok 4 s ago

Components
  notifier    ok, last ok 2 s ago
  resolver    started 10 min ago, no success yet

Transfers    burned 1   attested 2   pre_window 4   completed 30
Open alerts  critical 0   warning 1   info 3
";
    assert_eq!(got, expected);
}

fn row(state: TransferState, burn_tx: &str, receive: Option<(&str, i64)>) -> TransferRow {
    TransferRow {
        burn_id: 1,
        receive_id: receive.map(|_| 1),
        source_domain: Domain(6),
        destination_domain: Domain(5),
        nonce: Some(Bytes32([0xdc; 32])),
        burn_tx: burn_tx.to_string(),
        burn_time: 1_795_520_189,
        burn_finalized: true,
        receive_tx: receive.map(|(t, _)| t.to_string()),
        receive_time: receive.map(|(_, t)| t),
        receive_finalized: receive.map(|_| true),
        amount: 5_196_725_157,
        fee_executed: None,
        mode: Mode::Standard,
        state,
        latency_secs: receive.map(|(_, t)| t - 1_795_520_189),
    }
}

#[test]
fn cli_transfers_output() {
    let burn_sig =
        "5hZceQXeq8yTugkfTLF9LXa9az3XXxEUbta6fUWhuEPuoogcgeS4dSgqMWDR5pPNq7dLYHtPPFrHtS87VpHdXWB2"
            .to_string();
    let evm_tx = "0x90d79ce6d16f9d030f45f5ab1767e843e9cefc0d5afae43712b540d1686bab9d".to_string();
    let receive_sig =
        "5SZfhkPdCW1iu1t3cBbbvHt4tpUGR7jKnKbXZUp7fp7Xd56wHeK5fB8XK9geuHQzna9S62nfJ54VGAmrowh6iRVX"
            .to_string();
    let mut fast = row(TransferState::Burned, &burn_sig, None);
    fast.source_domain = Domain(5);
    fast.destination_domain = Domain(6);
    fast.mode = Mode::Fast;
    fast.amount = 21_000_000;
    fast.nonce = None;
    let done = row(
        TransferState::Completed,
        &evm_tx,
        Some((&receive_sig, 1_795_521_438)),
    );
    let got = text(|o| print_transfers(&[fast, done], o));
    // The exact column widths are an implementation detail; check the content
    // and the alignment instead of one frozen string.
    let lines: Vec<&str> = got.lines().collect();
    assert_eq!(lines.len(), 3, "{got}");
    let header = lines[0];
    for needle in [
        "STATE",
        "DIRECTION",
        "MODE",
        "USDC",
        "BURN TX",
        "RECEIVE TX",
        "NONCE",
        "LATENCY",
    ] {
        assert!(header.contains(needle), "{header}");
    }
    let col = |needle: &str| header.find(needle).unwrap();
    assert!(lines[1].starts_with("burned"));
    assert_eq!(
        &lines[1][col("DIRECTION")..col("DIRECTION") + 12],
        "solana->base"
    );
    let short = |tx: &str| format!("{}..{}", &tx[..10], &tx[tx.len() - 6..]);
    assert!(lines[1].contains("21.000000"));
    assert!(lines[1].contains(&short(&burn_sig)));
    assert!(lines[2].starts_with("completed"));
    assert_eq!(
        &lines[2][col("DIRECTION")..col("DIRECTION") + 12],
        "base->solana"
    );
    assert!(lines[2].contains("5196.725157"));
    assert!(lines[2].contains(&short(&evm_tx)));
    assert!(lines[2].contains(&short(&receive_sig)));
    assert!(lines[2].contains("0xdcdcdcdc.."));
    assert!(lines[2].ends_with("1249s"));
    assert_eq!(&lines[2][col("MODE")..col("MODE") + 8], "standard");
}

#[test]
fn cli_transfers_empty() {
    assert_eq!(text(|o| print_transfers(&[], o)), "No transfers.\n");
}

// ---- the binary ----

fn config_for(dir: &Path) -> std::path::PathBuf {
    let db = dir.join("watcher.db");
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        format!(
            "[database]\npath = \"{}\"\n",
            db.to_string_lossy().replace('\\', "/")
        ),
    )
    .unwrap();
    path
}

fn run(args: &[&str], config: Option<&Path>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bridge-watcher"));
    cmd.env_remove("BW_CONFIG");
    if let Some(c) = config {
        cmd.arg("--config").arg(c);
    }
    cmd.args(args).output().unwrap()
}

#[test]
fn cli_help_lists_the_commands() {
    let out = run(&["--help"], None);
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout).unwrap();
    for word in ["run", "status", "transfers", "--config"] {
        assert!(help.contains(word), "{help}");
    }
}

#[test]
fn cli_binary_status_and_transfers_on_an_empty_database() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path());
    Store::open(&dir.path().join("watcher.db")).unwrap();

    let out = run(&["status"], Some(&config));
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("none yet"), "{stdout}");
    assert!(stdout.contains("Transfers    burned 0   attested 0   pre_window 0   completed 0"));

    let out = run(&["transfers", "--state", "pre_window"], Some(&config));
    assert!(out.status.success(), "{out:?}");

    let out = run(
        &["transfers", "--state", "completed", "--limit", "5"],
        Some(&config),
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "No transfers.\n");
}

#[test]
fn cli_binary_without_a_database_says_so_and_does_not_create_one() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path());
    let out = run(&["status"], Some(&config));
    assert!(out.status.success());
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .contains("No database")
    );
    assert!(!dir.path().join("watcher.db").exists());
}

#[test]
fn cli_binary_config_errors_exit_with_code_2() {
    let dir = tempfile::tempdir().unwrap();
    let missing = run(&["status"], Some(&dir.path().join("none.toml")));
    assert_eq!(missing.status.code(), Some(2));

    let bad = dir.path().join("bad.toml");
    std::fs::write(&bad, "telegram_bot_token = \"123:secret\"\n").unwrap();
    let out = run(&["status"], Some(&bad));
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(!stderr.contains("123:secret"), "{stderr}");
}
