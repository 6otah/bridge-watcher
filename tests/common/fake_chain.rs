//! Scripted fake chain for ingestion tests (phase P3).
//!
//! [`FakeChain`] implements `ChainSource` over a table `height -> events`.
//! Tests change the table between ticks to simulate reorgs, make it fail on
//! the n-th scan to simulate a crash, or cap the span of each scan to force
//! partial results. Clones share one state, so a test keeps a handle while the
//! ingestor owns another.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use bridge_watcher::domain::{ChainEvent, Commitment, Domain, EventKind, Heights};
use bridge_watcher::source::{ChainSource, ScanResult, SourceError, TxEvidence};

/// One call of `ChainSource::scan`, as the ingestor made it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanCall {
    pub after: u64,
    pub up_to: u64,
    pub commitment: Commitment,
}

#[derive(Default)]
struct State {
    finalized: u64,
    head: u64,
    events: BTreeMap<u64, Vec<ChainEvent>>,
    calls: Vec<ScanCall>,
    fail_scan: Option<usize>,
    max_span: Option<u64>,
    lag_from: Option<usize>,
    heights_fail: bool,
}

#[derive(Clone)]
pub struct FakeChain {
    domain: Domain,
    name: String,
    state: Arc<Mutex<State>>,
}

impl FakeChain {
    pub fn new(domain: u32, name: &str) -> FakeChain {
        FakeChain {
            domain: Domain(domain),
            name: name.to_string(),
            state: Arc::default(),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    pub fn set_heights(&self, finalized: u64, head: u64) {
        let mut s = self.state();
        s.finalized = finalized;
        s.head = head;
    }

    /// Adds an event at `ev.at.height`.
    pub fn push(&self, ev: ChainEvent) {
        self.state()
            .events
            .entry(ev.at.height)
            .or_default()
            .push(ev);
    }

    /// Removes every event at `height` (the chain no longer holds it).
    pub fn drop_height(&self, height: u64) {
        self.state().events.remove(&height);
    }

    /// Removes every event.
    pub fn clear(&self) {
        self.state().events.clear();
    }

    /// The n-th `scan` call (1-based, counted over the life of the fake)
    /// fails with `SourceError::Rpc`. `None` disables the failure.
    pub fn fail_on_scan(&self, n: Option<usize>) {
        self.state().fail_scan = n;
    }

    /// Each scan covers at most `span` heights, so `complete_through < up_to`.
    pub fn set_max_span(&self, span: Option<u64>) {
        self.state().max_span = span;
    }

    /// From the n-th `scan` call on (1-based), `scan` returns
    /// `SourceError::Lagging`. `None` disables the lag.
    pub fn lag_from_scan(&self, n: Option<usize>) {
        self.state().lag_from = n;
    }

    /// `heights` returns `SourceError::Rpc` while set.
    pub fn set_heights_failing(&self, failing: bool) {
        self.state().heights_fail = failing;
    }

    pub fn calls(&self) -> Vec<ScanCall> {
        self.state().calls.clone()
    }

    pub fn scan_count(&self) -> usize {
        self.state().calls.len()
    }
}

impl ChainSource for FakeChain {
    fn domain(&self) -> Domain {
        self.domain
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn heights(&self) -> Result<Heights, SourceError> {
        let s = self.state();
        if s.heights_fail {
            return Err(SourceError::Rpc("injected heights failure".into()));
        }
        Ok(Heights {
            finalized: s.finalized,
            head: s.head,
        })
    }

    async fn scan(
        &self,
        after: u64,
        up_to: u64,
        commitment: Commitment,
    ) -> Result<ScanResult, SourceError> {
        let mut s = self.state();
        s.calls.push(ScanCall {
            after,
            up_to,
            commitment,
        });
        let n = s.calls.len();
        if s.fail_scan == Some(n) {
            return Err(SourceError::Rpc(format!("injected failure at scan {n}")));
        }
        if s.lag_from.is_some_and(|from| n >= from) {
            return Err(SourceError::Lagging("injected lag".into()));
        }
        let to = s.max_span.map_or(up_to, |span| up_to.min(after + span));
        let events = s
            .events
            .range(after + 1..=to)
            .flat_map(|(_, evs)| evs.iter().cloned())
            .collect();
        Ok(ScanResult {
            events,
            complete_through: to,
        })
    }

    /// Chain time grows with the height: `1_700_000_000 + height`, the same
    /// formula the event helpers in `common` use for `block_time`.
    async fn time_at_or_before(&self, height: u64) -> Result<(u64, i64), SourceError> {
        Ok((height, 1_700_000_000 + height as i64))
    }

    async fn inspect_tx(&self, tx_id: &str) -> Result<Option<TxEvidence>, SourceError> {
        let s = self.state();
        let Some((height, _)) = s
            .events
            .iter()
            .find(|(_, evs)| evs.iter().any(|e| e.at.tx_id == tx_id))
        else {
            return Ok(None);
        };
        let burns = s.events[height]
            .iter()
            .filter(|e| e.at.tx_id == tx_id)
            .filter_map(|e| match &e.kind {
                EventKind::Burn(b) => Some(b.clone()),
                EventKind::Receive(_) => None,
            })
            .collect();
        Ok(Some(TxEvidence {
            height: *height,
            burns,
        }))
    }
}
