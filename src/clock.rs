//! Wall-clock time for the background loops.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix time in seconds. Saturates instead of failing: a clock before
/// 1970 gives 0.
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}
