//! Read-only output for the status and transfers commands.
//!
//! Both functions are pure over the report types of `store::read` and write
//! plain text, so the output is stable and testable. Times are UTC. Nothing
//! here touches the database.

use std::io::{self, Write};

use crate::domain::{Bytes32, Domain, Mode};
use crate::store::{HealthRow, StatusReport, TransferRow};

/// `YYYY-MM-DD HH:MM:SS UTC` for Unix seconds.
pub fn format_time(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    // Civil-from-days (proleptic Gregorian calendar).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// `"12 s ago"`, `"3 min ago"`, `"2 h ago"`, `"4 d ago"`.
fn ago(now: i64, then: i64) -> String {
    let d = (now - then).max(0);
    match d {
        0..=119 => format!("{d} s ago"),
        120..=7199 => format!("{} min ago", d / 60),
        7200..=172_799 => format!("{} h ago", d / 3600),
        _ => format!("{} d ago", d / 86_400),
    }
}

fn when(now: i64, ts: Option<i64>) -> String {
    ts.map_or_else(
        || "never".to_string(),
        |t| format!("{} ({})", format_time(t), ago(now, t)),
    )
}

fn opt(v: Option<u64>) -> String {
    v.map_or_else(|| "-".to_string(), |v| v.to_string())
}

fn health_line(now: i64, h: &HealthRow) -> String {
    match (&h.last_error, h.consecutive_failures) {
        (Some(e), n) if n > 0 => format!(
            "failing: {e} ({n} in a row, last {})",
            ago(now, h.last_error_at.unwrap_or(h.started_at))
        ),
        _ => match h.last_ok_at {
            Some(t) => format!("ok, last ok {}", ago(now, t)),
            None => format!("started {}, no success yet", ago(now, h.started_at)),
        },
    }
}

/// Prints cursors, observed heights, component health, transfer counts and
/// open alerts.
///
/// # Errors
/// Any error of `out`.
pub fn print_status(report: &StatusReport, out: &mut impl Write) -> io::Result<()> {
    let now = report.now;
    writeln!(out, "bridge-watcher status at {}", format_time(now))?;
    writeln!(out)?;
    writeln!(out, "Chains")?;
    if report.chains.is_empty() {
        writeln!(out, "  none yet (start `bridge-watcher run` first)")?;
    }
    for c in &report.chains {
        writeln!(out, "  {} (domain {})", c.name, c.domain)?;
        writeln!(
            out,
            "    cursor      {} (first height {})",
            c.final_height, c.start_height
        )?;
        writeln!(
            out,
            "    finalized   {} (cursor lag {})",
            opt(c.observed_finalized),
            opt(c.cursor_lag)
        )?;
        writeln!(out, "    head        {}", opt(c.observed_head))?;
        writeln!(out, "    scanned to  {}", opt(c.scanned_head))?;
        writeln!(out, "    caught up   {}", when(now, c.caught_up_at))?;
        let ingestor = c
            .health
            .as_ref()
            .map_or_else(|| "no health row".to_string(), |h| health_line(now, h));
        writeln!(out, "    ingestor    {ingestor}")?;
    }
    let others: Vec<_> = report
        .components
        .iter()
        .filter(|h| !h.component.starts_with("ingest:"))
        .collect();
    if !others.is_empty() {
        writeln!(out)?;
        writeln!(out, "Components")?;
        for h in others {
            writeln!(out, "  {:<10}  {}", h.component, health_line(now, h))?;
        }
    }
    writeln!(out)?;
    writeln!(
        out,
        "Transfers    burned {}   attested {}   pre_window {}   completed {}",
        report.burned, report.attested, report.pre_window, report.completed
    )?;
    let a = report.open_alerts;
    writeln!(
        out,
        "Open alerts  critical {}   warning {}   info {}",
        a.critical, a.warning, a.info
    )
}

fn chain_label(d: Domain) -> String {
    match d.0 {
        5 => "solana".to_string(),
        6 => "base".to_string(),
        n => format!("domain{n}"),
    }
}

/// `amount` base units of USDC (6 decimals) as `21.000000`.
fn usdc(amount: u64) -> String {
    format!("{}.{:06}", amount / 1_000_000, amount % 1_000_000)
}

/// First 10 and last 6 characters of a long id.
fn short(id: &str) -> String {
    if id.len() > 18 {
        format!("{}..{}", &id[..10], &id[id.len() - 6..])
    } else {
        id.to_string()
    }
}

fn short_nonce(n: Option<Bytes32>) -> String {
    n.map_or_else(|| "-".to_string(), |n| format!("{}..", &n.to_hex()[..10]))
}

/// Prints transfers as an aligned table, in the order given (newest first).
/// USDC amounts are for display only.
///
/// # Errors
/// Any error of `out`.
pub fn print_transfers(rows: &[TransferRow], out: &mut impl Write) -> io::Result<()> {
    if rows.is_empty() {
        return writeln!(out, "No transfers.");
    }
    let header = [
        "STATE",
        "DIRECTION",
        "MODE",
        "USDC",
        "BURN TX",
        "RECEIVE TX",
        "NONCE",
        "LATENCY",
    ];
    let table: Vec<[String; 8]> = rows
        .iter()
        .map(|r| {
            [
                r.state.as_str().to_string(),
                format!(
                    "{}->{}",
                    chain_label(r.source_domain),
                    chain_label(r.destination_domain)
                ),
                match r.mode {
                    Mode::Fast => "fast",
                    Mode::Standard => "standard",
                }
                .to_string(),
                usdc(r.amount),
                short(&r.burn_tx),
                r.receive_tx.as_deref().map_or_else(|| "-".into(), short),
                short_nonce(r.nonce),
                r.latency_secs
                    .map_or_else(|| "-".to_string(), |s| format!("{s}s")),
            ]
        })
        .collect();
    let widths: Vec<usize> = (0..8)
        .map(|i| {
            table
                .iter()
                .map(|r| r[i].len())
                .chain([header[i].len()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let line = |cells: &[&str], out: &mut dyn Write| -> io::Result<()> {
        let text: Vec<String> = cells
            .iter()
            .zip(&widths)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect();
        writeln!(out, "{}", text.join("  ").trim_end())
    };
    line(&header, out)?;
    for row in &table {
        let cells: Vec<&str> = row.iter().map(String::as_str).collect();
        line(&cells, out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_time_is_utc_calendar_time() {
        assert_eq!(format_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_time(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(format_time(1_800_000_000), "2027-01-15 08:00:00 UTC");
    }

    #[test]
    fn usdc_shows_six_decimals() {
        assert_eq!(usdc(21_000_000), "21.000000");
        assert_eq!(usdc(5_196_725_157), "5196.725157");
        assert_eq!(usdc(5), "0.000005");
    }
}
