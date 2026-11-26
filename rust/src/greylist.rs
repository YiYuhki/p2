//! SMTP greylisting: the first delivery attempt for an unseen
//! (client IP, sender, recipient) triplet is deferred, and the triplet is
//! accepted only when it is retried after a short delay. Legitimate MTAs retry
//! and succeed; much spamware does not retry at all.
//!
//! State is kept in memory (per-instance, reset on restart). Port of the Go
//! `internal/greylist` package.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Entry {
    first: Instant,
    last: Instant,
    passed: bool,
}

/// Tracks triplets. Construct with [`Greylist::new`].
pub struct Greylist {
    delay: Duration,
    expiry: Duration,
    // `now` is injectable for tests; it maps a logical clock to Instant-like
    // ordering via a base Instant plus elapsed nanoseconds.
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
    seen: Mutex<HashMap<String, Entry>>,
    max_entries: usize,
}

/// Default cap on tracked triplets (bounds memory under a flood of unique
/// senders/recipients).
pub const DEFAULT_MAX_ENTRIES: usize = 1_000_000;
/// Longest sender/recipient stored in a key (RFC 5321 paths are <= 256).
const MAX_PART_LEN: usize = 320;

impl Greylist {
    /// `delay` is the minimum wait before a retry is accepted (<=0 -> 1m);
    /// `expiry` is how long state is retained (<=0 -> 36h).
    pub fn new(delay: Duration, expiry: Duration) -> Self {
        let delay = if delay.is_zero() {
            Duration::from_secs(60)
        } else {
            delay
        };
        let expiry = if expiry.is_zero() {
            Duration::from_secs(36 * 3600)
        } else {
            expiry
        };
        Greylist {
            delay,
            expiry,
            clock: Box::new(Instant::now),
            seen: Mutex::new(HashMap::new()),
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }

    /// Caps the number of tracked triplets (0 -> [`DEFAULT_MAX_ENTRIES`]).
    /// When full, unseen triplets are allowed through without being stored
    /// (fail open) until [`Greylist::sweep`] frees space.
    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = if max == 0 { DEFAULT_MAX_ENTRIES } else { max };
        self
    }

    /// Replace the clock (tests only).
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> Instant + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    fn key(ip: &str, from: &str, to: &str) -> String {
        format!("{}\0{}\0{}", truncate(ip), truncate(from), truncate(to)).to_lowercase()
    }

    /// Records a delivery attempt and reports whether it may proceed now. The
    /// first attempt (and any retry sooner than `delay`) returns false — the
    /// caller should defer with a 4xx. Once the delay has elapsed the triplet
    /// passes and keeps passing until it expires.
    pub fn allow(&self, ip: &str, from: &str, to: &str) -> bool {
        let now = (self.clock)();
        let k = Self::key(ip, from, to);
        let mut seen = self.seen.lock().unwrap();
        let full = seen.len() >= self.max_entries;
        match seen.get_mut(&k) {
            None if full => true,
            None => {
                seen.insert(
                    k,
                    Entry {
                        first: now,
                        last: now,
                        passed: false,
                    },
                );
                false
            }
            Some(e) if e.passed => {
                e.last = now;
                true
            }
            Some(e) if now.duration_since(e.first) >= self.delay => {
                e.passed = true;
                e.last = now;
                true
            }
            Some(_) => false,
        }
    }

    /// Drops entries that have aged out (idle longer than `expiry`).
    pub fn sweep(&self) {
        let now = (self.clock)();
        let mut seen = self.seen.lock().unwrap();
        seen.retain(|_, e| {
            let reference = if e.passed { e.last } else { e.first };
            now.duration_since(reference) <= self.expiry
        });
    }

    /// Number of tracked triplets (tests/metrics).
    pub fn len(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Truncates to at most [`MAX_PART_LEN`] bytes on a char boundary.
fn truncate(s: &str) -> &str {
    if s.len() <= MAX_PART_LEN {
        return s;
    }
    let mut end = MAX_PART_LEN;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    // A controllable clock built on a base Instant + an atomic nanosecond offset.
    fn clock() -> (Arc<AtomicU64>, Box<dyn Fn() -> Instant + Send + Sync>) {
        let base = Instant::now();
        let off = Arc::new(AtomicU64::new(0));
        let o = off.clone();
        let f = Box::new(move || base + Duration::from_nanos(o.load(Ordering::SeqCst)));
        (off, f)
    }

    #[test]
    fn defer_then_allow_after_delay() {
        let (off, f) = clock();
        let g = Greylist::new(Duration::from_secs(60), Duration::from_secs(3600)).with_clock(f);
        assert!(!g.allow("192.0.2.1", "a@ext", "b@us"), "first deferred");
        off.store(30_000_000_000, Ordering::SeqCst); // +30s
        assert!(
            !g.allow("192.0.2.1", "a@ext", "b@us"),
            "retry within delay deferred"
        );
        off.store(61_000_000_000, Ordering::SeqCst); // +61s
        assert!(
            g.allow("192.0.2.1", "a@ext", "b@us"),
            "retry after delay passes"
        );
        assert!(
            g.allow("192.0.2.1", "a@ext", "b@us"),
            "passed keeps passing"
        );
    }

    #[test]
    fn triplets_independent() {
        let (_off, f) = clock();
        let g = Greylist::new(Duration::from_secs(60), Duration::from_secs(3600)).with_clock(f);
        g.allow("192.0.2.1", "a@ext", "b@us");
        assert!(
            !g.allow("192.0.2.1", "a@ext", "c@us"),
            "different rcpt is its own triplet"
        );
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn sweep_expires() {
        let (off, f) = clock();
        let g = Greylist::new(Duration::from_secs(60), Duration::from_secs(3600)).with_clock(f);
        g.allow("192.0.2.1", "a@ext", "b@us");
        off.store(2 * 3600 * 1_000_000_000, Ordering::SeqCst); // +2h
        g.sweep();
        assert_eq!(g.len(), 0);
    }

    #[test]
    fn bounded_entries_fail_open() {
        let (_off, f) = clock();
        let g = Greylist::new(Duration::from_secs(60), Duration::from_secs(3600))
            .with_clock(f)
            .with_max_entries(2);
        assert!(!g.allow("192.0.2.1", "a@ext", "b@us"));
        assert!(!g.allow("192.0.2.1", "a@ext", "c@us"));
        assert!(g.allow("192.0.2.1", "a@ext", "d@us"), "full: allowed");
        assert_eq!(g.len(), 2, "not stored when full");
        assert!(
            !g.allow("192.0.2.1", "a@ext", "b@us"),
            "known still deferred"
        );
    }

    #[test]
    fn long_keys_truncated() {
        let (_off, f) = clock();
        let g = Greylist::new(Duration::from_secs(60), Duration::from_secs(3600)).with_clock(f);
        let long = "é".repeat(10_000);
        g.allow("192.0.2.1", &long, &long);
        let seen = g.seen.lock().unwrap();
        assert!(seen.keys().all(|k| k.len() <= 3 * MAX_PART_LEN + 2));
    }
}
