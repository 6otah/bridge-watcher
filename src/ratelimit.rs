//! Token-bucket rate limiter.
//!
//! Invariant: after the initial burst, at most `rate` acquisitions complete per
//! second, however many tasks share the limiter. Time comes from
//! `tokio::time`, so tests can pause and advance it.

use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

struct State {
    tokens: f64,
    last: Instant,
}

/// Token bucket shared by all users of one external host.
pub struct RateLimiter {
    per_second: f64,
    burst: f64,
    state: Mutex<State>,
}

impl RateLimiter {
    /// Creates a limiter with a full bucket of `burst` tokens that refills at
    /// `per_second` tokens per second.
    ///
    /// # Panics
    /// If `per_second` is not a positive finite number or `burst` is 0.
    /// `config` validation rejects such values before they reach this point.
    pub fn new(per_second: f64, burst: u32) -> Self {
        assert!(
            per_second.is_finite() && per_second > 0.0,
            "rate must be positive and finite"
        );
        assert!(burst >= 1, "burst must be at least 1");
        Self {
            per_second,
            burst: f64::from(burst),
            state: Mutex::new(State {
                tokens: f64::from(burst),
                last: Instant::now(),
            }),
        }
    }

    /// Waits until one token is available, then takes it.
    ///
    /// Waiters are served in lock order. Dropping the future before it
    /// completes takes no token.
    pub async fn acquire(&self) {
        let mut st = self.state.lock().await;
        loop {
            let now = Instant::now();
            let elapsed = now.duration_since(st.last).as_secs_f64();
            st.tokens = (st.tokens + elapsed * self.per_second).min(self.burst);
            st.last = now;
            if st.tokens >= 1.0 {
                st.tokens -= 1.0;
                return;
            }
            let wait = (1.0 - st.tokens) / self.per_second;
            tokio::time::sleep(Duration::from_secs_f64(wait)).await;
        }
    }
}
