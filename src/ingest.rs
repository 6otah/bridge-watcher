//! Chain-agnostic ingestor tick: finalize, then scan the unfinalized tail (phase P3).
//!
//! One [`Ingestor`] drives one [`ChainSource`] and one chain's rows in the
//! store. Each tick reads the heights, finalizes `(cursor, F]` with
//! finalized-commitment scans, and, only when the cursor has reached `F`,
//! re-derives the unfinalized tail `(F, T]` (`docs/ARCHITECTURE.md` section
//! 6.6). There is no reorg detector: a reorg is a different scan result for
//! the same range, and `Store::apply_scan` deletes what the new result no
//! longer holds.
//!
//! Failure policy (section 12): [`SourceError::Lagging`] ends the tick early
//! and is healthy; other source errors back off; store errors are fatal and
//! returned from [`Ingestor::run`].

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::clock::unix_now;
use crate::domain::Commitment;
use crate::source::{ChainSource, SourceError};
use crate::store::{ApplyStats, ChainCursor, Scope, SharedStore, StoreError};

/// Tuning of one [`Ingestor`]. Built from the chain's config section by `app`.
#[derive(Clone, Debug)]
pub struct IngestConfig {
    /// Sleep between successful ticks.
    pub poll_interval: Duration,
    /// Maximum number of heights above finalized that the tail scan covers.
    pub tail_max: u64,
    /// Maximum scans per phase (finalize, tail) per tick.
    pub max_scans_per_tick: u32,
    /// Cap of the exponential backoff after failed ticks.
    pub max_backoff: Duration,
}

/// Outcome of one successful [`Ingestor::tick`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TickReport {
    /// Cursor (`final_height`) at the end of the tick.
    pub final_through: u64,
    /// Top of the tail scanned in this tick; `None` if the tail phase did not
    /// run because the cursor had not reached the finalized height.
    pub tail_through: Option<u64>,
    /// The tail scan reached its target, so `caught_up_at` was written.
    pub caught_up: bool,
    /// Sum of the stats of all scans of the tick.
    pub stats: ApplyStats,
}

/// Failure of one tick.
#[derive(Debug, thiserror::Error)]
pub enum TickError {
    /// The chain source failed. Committed work of the tick stays valid.
    #[error(transparent)]
    Source(#[from] SourceError),
    /// The store failed. Fatal for the process.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Ingests one chain into the store.
///
/// Invariants: the cursor only moves forward, inside `apply_scan`, together
/// with the rows of the scanned range; the tail is scanned only when the
/// cursor equals the finalized height.
pub struct Ingestor<S> {
    source: Arc<S>,
    store: SharedStore,
    cfg: IngestConfig,
}

/// Sleep after `failures` consecutive failed ticks: `interval * 2^failures`,
/// capped at `max`.
pub(crate) fn backoff(interval: Duration, max: Duration, failures: u32) -> Duration {
    interval.saturating_mul(1u32 << failures.min(16)).min(max)
}

fn add_stats(total: &mut ApplyStats, s: ApplyStats) {
    total.upserted += s.upserted;
    total.promoted += s.promoted;
    total.rolled_back += s.rolled_back;
    total.final_conflicts += s.final_conflicts;
}

impl<S: ChainSource> Ingestor<S> {
    /// Creates an ingestor. The cursor row must exist: call [`init_cursor`]
    /// first.
    pub fn new(source: Arc<S>, store: SharedStore, cfg: IngestConfig) -> Self {
        Self { source, store, cfg }
    }

    /// Name of the `health` row of this loop: `ingest:<chain name>`.
    pub fn component(&self) -> String {
        format!("ingest:{}", self.source.name())
    }

    /// Rejects a scan result that breaks `after < complete_through <= up_to`,
    /// so that a faulty source cannot reach the store as a scope violation.
    fn check_progress(&self, after: u64, up_to: u64, through: u64) -> Result<u64, SourceError> {
        if through > after && through <= up_to {
            Ok(through)
        } else {
            Err(SourceError::Rpc(format!(
                "{}: scan of ({after}, {up_to}] returned complete_through {through}",
                self.source.name()
            )))
        }
    }

    /// Runs one tick (section 6.6) at wall-clock time `now`.
    ///
    /// Phase A scans `(cursor, F]` at finalized commitment, at most
    /// `max_scans_per_tick` times; every scan commits on its own. Phase B
    /// runs only if the cursor reached `F`: it scans `(F, min(L, F +
    /// tail_max)]` at confirmed commitment the same way and calls
    /// `mark_caught_up` when the whole range is covered. `F` never falls below
    /// the stored cursor, so a regressing node cannot move anything backwards.
    ///
    /// # Errors
    /// [`TickError::Source`] with the error of the source, including
    /// [`SourceError::Lagging`]; work committed before the error stays valid.
    /// [`TickError::Store`] for any store error, including
    /// [`StoreError::NoCursor`] if [`init_cursor`] was not called.
    pub async fn tick(&self, now: i64) -> Result<TickReport, TickError> {
        let domain = self.source.domain();
        let cursor = self
            .store
            .run(move |s| s.cursor(domain))
            .await?
            .ok_or(StoreError::NoCursor { domain: domain.0 })?;
        let observed = self.source.heights().await?;
        self.store
            .run(move |s| s.record_heights(domain, observed, now))
            .await?;

        let mut final_height = cursor.final_height;
        let finalized = observed.finalized.max(final_height);
        let head = observed.head.max(finalized);
        let mut stats = ApplyStats::default();

        let mut scans = 0;
        while final_height < finalized && scans < self.cfg.max_scans_per_tick {
            let result = self
                .source
                .scan(final_height, finalized, Commitment::Finalized)
                .await?;
            let through = self.check_progress(final_height, finalized, result.complete_through)?;
            let after = final_height;
            let applied = self
                .store
                .run(move |s| {
                    s.apply_scan(domain, Scope::Final { after, through }, &result.events, now)
                })
                .await?;
            add_stats(&mut stats, applied);
            final_height = through;
            scans += 1;
        }
        if final_height < finalized {
            return Ok(TickReport {
                final_through: final_height,
                tail_through: None,
                caught_up: false,
                stats,
            });
        }

        let target = head.min(finalized.saturating_add(self.cfg.tail_max));
        let mut after = finalized;
        let mut tail_scans = 0;
        while after < target && tail_scans < self.cfg.max_scans_per_tick {
            let result = self
                .source
                .scan(after, target, Commitment::Confirmed)
                .await?;
            let through = self.check_progress(after, target, result.complete_through)?;
            let from = after;
            let applied = self
                .store
                .run(move |s| {
                    s.apply_scan(
                        domain,
                        Scope::Tail {
                            after: from,
                            through,
                        },
                        &result.events,
                        now,
                    )
                })
                .await?;
            add_stats(&mut stats, applied);
            after = through;
            tail_scans += 1;
        }
        let caught_up = after == target;
        if caught_up {
            self.store
                .run(move |s| s.mark_caught_up(domain, target, now))
                .await?;
        }
        Ok(TickReport {
            final_through: final_height,
            tail_through: Some(after),
            caught_up,
            stats,
        })
    }

    /// Ticks until `cancel` is cancelled.
    ///
    /// After a successful tick, and after [`SourceError::Lagging`] (expected
    /// with load-balanced nodes), it records the health row `ingest:<name>` as
    /// OK and sleeps `poll_interval`. After any other source error it records
    /// the error text and sleeps `poll_interval * 2^failures`, capped at
    /// `max_backoff`. Dropping a tick on cancellation is safe: every store
    /// call either commits or rolls back.
    ///
    /// # Errors
    /// Returns `Err` only for a [`StoreError`], which is fatal (ADR 0010).
    /// Cancellation returns `Ok(())`.
    pub async fn run(self, cancel: CancellationToken) -> Result<(), StoreError> {
        let component = self.component();
        let mut failures: u32 = 0;
        loop {
            let now = unix_now();
            let outcome = tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                outcome = self.tick(now) => outcome,
            };
            let delay = match outcome {
                Ok(report) => {
                    tracing::debug!(chain = %component, ?report, "tick done");
                    failures = 0;
                    self.record(&component, None, now).await?;
                    self.cfg.poll_interval
                }
                Err(TickError::Source(SourceError::Lagging(why))) => {
                    tracing::debug!(chain = %component, %why, "node lagging; tick ended early");
                    failures = 0;
                    self.record(&component, None, now).await?;
                    self.cfg.poll_interval
                }
                Err(TickError::Source(err)) => {
                    failures = failures.saturating_add(1);
                    let text = err.to_string();
                    tracing::warn!(chain = %component, error = %text, failures, "tick failed");
                    self.record(&component, Some(text), now).await?;
                    backoff(self.cfg.poll_interval, self.cfg.max_backoff, failures)
                }
                Err(TickError::Store(err)) => return Err(err),
            };
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                () = tokio::time::sleep(delay) => {}
            }
        }
    }

    /// Writes the health row: OK if `error` is `None`.
    async fn record(
        &self,
        component: &str,
        error: Option<String>,
        now: i64,
    ) -> Result<(), StoreError> {
        let component = component.to_string();
        self.store
            .run(move |s| {
                let outcome = match &error {
                    None => Ok(()),
                    Some(text) => Err(text.as_str()),
                };
                s.record_health(&component, outcome, now)
            })
            .await
    }
}

/// Writes the initial cursor of a chain on the first run. Later runs do not
/// touch the stored cursor and do not call the node.
///
/// - `start_height = None`: start at the current finalized height `F`, so
///   `final_height = F` and `start_height = F + 1` (no backfill).
/// - `start_height = Some(h)`: backfill from `h`: `final_height = h - 1`.
///
/// The first run also records `start_time`, the chain time of the last block at
/// or below `final_height` (`ChainSource::time_at_or_before`), in the same
/// store call as the cursor. It never changes (ADR 0013).
///
/// If a cursor exists and `start_height` is `Some` with another value, the
/// stored value wins and a warning is logged.
///
/// # Errors
/// [`TickError::Source`] if the first run cannot read the finalized height or
/// the start time.
/// [`TickError::Store`] with [`StoreError::ConfigMismatch`] if the stored
/// chain name differs from the source's name.
pub async fn init_cursor<S: ChainSource>(
    source: &S,
    store: &SharedStore,
    start_height: Option<u64>,
    now: i64,
) -> Result<ChainCursor, TickError> {
    let domain = source.domain();
    let name = source.name().to_string();
    if let Some(existing) = store.run(move |s| s.cursor(domain)).await? {
        if let Some(h) = start_height.filter(|h| *h != existing.start_height) {
            tracing::warn!(
                chain = %name,
                configured = h,
                stored = existing.start_height,
                "configured start_height differs from the stored one; the stored value wins"
            );
        }
        let (final_height, start_time) = (existing.final_height, existing.start_time);
        return Ok(store
            .run(move |s| s.init_cursor(domain, &name, final_height, start_time, now))
            .await?);
    }
    let final_height = match start_height {
        Some(h) => h.saturating_sub(1),
        None => source.heights().await?.finalized,
    };
    let (_, start_time) = source.time_at_or_before(final_height).await?;
    Ok(store
        .run(move |s| s.init_cursor(domain, &name, final_height, start_time, now))
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_is_capped() {
        let (i, max) = (Duration::from_secs(10), Duration::from_secs(300));
        let secs = |f| backoff(i, max, f).as_secs();
        assert_eq!([secs(1), secs(2), secs(3), secs(4)], [20, 40, 80, 160]);
        assert_eq!([secs(5), secs(6), secs(1000)], [300, 300, 300]);
    }
}
