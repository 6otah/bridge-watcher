//! Recording fake alert sink.
//!
//! `FakeSink` is cheap to clone; clones share one record, so a test keeps a
//! handle after it moves a clone into the `Notifier`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_watcher::notify::{AlertSink, SinkError};
use bridge_watcher::store::Alert;

#[derive(Default)]
struct State {
    delivered: Vec<Alert>,
    attempts: usize,
    failures: Vec<SinkError>,
}

/// Accepts alerts and records them. Can be told to fail the next deliveries.
#[derive(Clone, Default)]
pub struct FakeSink {
    state: Arc<Mutex<State>>,
}

impl FakeSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// The next `n` deliveries fail with a transient error.
    pub fn fail_next(&self, n: usize) {
        let mut s = self.state.lock().unwrap();
        for _ in 0..n {
            s.failures
                .push(SinkError::Transient("sink down".to_string()));
        }
    }

    /// The next delivery fails with a rate-limit answer.
    pub fn retry_after_next(&self, d: Duration) {
        self.state
            .lock()
            .unwrap()
            .failures
            .push(SinkError::RetryAfter(d));
    }

    /// Alerts the sink accepted, in order.
    pub fn delivered(&self) -> Vec<Alert> {
        self.state.lock().unwrap().delivered.clone()
    }

    /// Delivery calls, successful or not.
    pub fn attempts(&self) -> usize {
        self.state.lock().unwrap().attempts
    }
}

impl AlertSink for FakeSink {
    async fn deliver(&self, alert: &Alert) -> Result<(), SinkError> {
        let mut s = self.state.lock().unwrap();
        s.attempts += 1;
        if !s.failures.is_empty() {
            return Err(s.failures.remove(0));
        }
        s.delivered.push(alert.clone());
        Ok(())
    }
}
