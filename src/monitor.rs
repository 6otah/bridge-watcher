//! Monitor: pure rule evaluation and the alert-sync loop (phase P7).
//!
//! Only [`Severity`] exists so far, because `config` needs it. The rest is a
//! stub: implemented in a later phase of `docs/ARCHITECTURE.md` §17.

use serde::Deserialize;

/// Alert severity. Ordered: `Info < Warning < Critical`.
///
/// Parsed from lowercase strings (`"info"`, `"warning"`, `"critical"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Logged only; sent only if `min_severity = "info"`.
    Info,
    /// Needs attention.
    Warning,
    /// Possible loss of funds or a broken invariant.
    Critical,
}

impl Severity {
    /// Lowercase name as stored in the `alerts.severity` column.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}
