//! Per-key token-bucket limiter used to cap the message rate of a single
//! inbound client IP. Port of the Go `internal/ratelimit` package.
//!
//! A self-contained token bucket (no external crate) refills continuously at
//! `rps` tokens/second up to `burst`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Bucket {
    tokens: f64,
    updated: Instant,
    seen: Instant,
}

/// Holds one token bucket per key, created on first use and evicted when idle.
pub struct Limiter {
    rps: f64,
    burst: f64,
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
    buckets: Mutex<HashMap<String, Bucket>>,
    max_keys: usize,
}

/// Default cap on tracked keys (bounds memory under many distinct clients).
pub const DEFAULT_MAX_KEYS: usize = 100_000;

impl Limiter {
    /// Returns a limiter allowing `rps` tokens/sec with the given `burst`, or
    /// `None` when `rps <= 0` (disabled).
    pub fn new(rps: f64, burst: i64) -> Option<Self> {
        if rps <= 0.0 {
            return None;
        }
        let burst = if burst <= 0 { 1 } else { burst };
        Some(Limiter {
            rps,
            burst: burst as f64,
            clock: Box::new(Instant::now),
            buckets: Mutex::new(HashMap::new()),
            max_keys: DEFAULT_MAX_KEYS,
        })
    }

    /// Caps the number of tracked keys (0 -> [`DEFAULT_MAX_KEYS`]).
    pub fn with_max_keys(mut self, max: usize) -> Self {
        self.max_keys = if max == 0 { DEFAULT_MAX_KEYS } else { max };
        self
    }

    pub fn with_clock(mut self, clock: Box<dyn Fn() -> Instant + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// Reports whether an event for `key` may proceed now, consuming a token.
    pub fn allow(&self, key: &str) -> bool {
        let now = (self.clock)();
        let mut buckets = self.buckets.lock().unwrap();
        if buckets.len() >= self.max_keys && !buckets.contains_key(key) {
            // A fully refilled bucket is indistinguishable from a fresh one, so
            // dropping those loses no state.
            let (rps, burst) = (self.rps, self.burst);
            buckets.retain(|_, b| {
                b.tokens + now.duration_since(b.updated).as_secs_f64() * rps < burst
            });
            if buckets.len() >= self.max_keys {
                // Still full of active clients: allow without tracking rather
                // than growing without bound.
                return true;
            }
        }
        let b = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: self.burst,
            updated: now,
            seen: now,
        });
        // Refill based on elapsed time.
        let elapsed = now.duration_since(b.updated).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.rps).min(self.burst);
        b.updated = now;
        b.seen = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Evicts buckets idle for longer than `idle`.
    pub fn sweep(&self, idle: Duration) {
        let now = (self.clock)();
        let mut buckets = self.buckets.lock().unwrap();
        buckets.retain(|_, b| now.duration_since(b.seen) <= idle);
    }

    pub fn len(&self) -> usize {
        self.buckets.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Convenience: `allow` on an `Option<Limiter>` treats `None` as "always allow"
/// (disabled), mirroring the Go nil-receiver behaviour.
pub fn allow(limiter: &Option<Limiter>, key: &str) -> bool {
    match limiter {
        Some(l) => l.allow(key),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    fn clock() -> (Arc<AtomicU64>, Box<dyn Fn() -> Instant + Send + Sync>) {
        let base = Instant::now();
        let off = Arc::new(AtomicU64::new(0));
        let o = off.clone();
        (
            off.clone(),
            Box::new(move || base + Duration::from_nanos(o.load(Ordering::SeqCst))),
        )
    }

    #[test]
    fn burst_then_deny() {
        // Negligible refill within the test, burst 2: two allowed, third denied.
        let (_off, f) = clock();
        let l = Limiter::new(0.0001, 2).unwrap().with_clock(f);
        assert!(l.allow("1.2.3.4"));
        assert!(l.allow("1.2.3.4"));
        assert!(!l.allow("1.2.3.4"), "third over burst denied");
        assert!(l.allow("5.6.7.8"), "distinct key has its own budget");
    }

    #[test]
    fn disabled_always_allows() {
        assert!(Limiter::new(0.0, 5).is_none());
        let none: Option<Limiter> = None;
        assert!(allow(&none, "x"));
    }

    #[test]
    fn sweep_evicts() {
        let (off, f) = clock();
        let l = Limiter::new(1.0, 1).unwrap().with_clock(f);
        l.allow("1.2.3.4");
        assert_eq!(l.len(), 1);
        off.store(2 * 3600 * 1_000_000_000, Ordering::SeqCst); // +2h
        l.sweep(Duration::from_secs(3600));
        assert_eq!(l.len(), 0);
    }

    #[test]
    fn bounded_keys() {
        let (off, f) = clock();
        let l = Limiter::new(1.0, 1).unwrap().with_clock(f).with_max_keys(2);
        assert!(l.allow("a"));
        assert!(l.allow("b"));
        assert!(l.allow("c"), "full: allowed untracked");
        assert_eq!(l.len(), 2);
        off.store(5_000_000_000, Ordering::SeqCst); // +5s: a, b refilled
        assert!(l.allow("c"));
        assert_eq!(l.len(), 1, "refilled buckets evicted, c tracked");
    }
}
