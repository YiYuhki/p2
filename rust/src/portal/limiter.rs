//! Token-lookup throttling for the portal. Port of the Go `portal/ratelimit.go`
//! `ipLimiter`, built on the crate's token bucket (`crate::ratelimit::Limiter`).
//!
//! Two independent budgets are kept:
//!
//! - a general per-IP budget charged on every lookup (page loads, polling);
//! - an enumeration budget charged only when a lookup misses (unknown or
//!   malformed token), enforced both per IP and globally so that token guessing
//!   spread over many source IPs is still capped in aggregate.
//!
//! Wrong OTP codes are charged to the per-IP miss budget only (never the
//! global one), so a lookup flood cannot lock legitimate users out of login.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::proxy::bucket_key;
use crate::ratelimit::Limiter;

/// Idle per-IP buckets are evicted after this long.
const IDLE: Duration = Duration::from_secs(10 * 60);

/// Per-generation cap on tracked miss buckets (see [`GenMap`]).
const MAX_FAIL_KEYS: usize = 50_000;

/// A bounded map with O(1) amortised eviction: entries live in a "current"
/// generation; once it is older than `period` or holds `cap` entries it
/// becomes the "previous" generation and the old previous one is dropped
/// wholesale. Lookups consult both generations (promoting hits), so an entry
/// survives at least one full `period` unless more than `cap` other keys are
/// written in the meantime. No request ever scans the map.
pub(crate) struct GenMap<V> {
    cur: HashMap<String, V>,
    prev: HashMap<String, V>,
    rotated: Instant,
    period: Duration,
    cap: usize,
}

impl<V> GenMap<V> {
    pub(crate) fn new(period: Duration, cap: usize) -> Self {
        GenMap {
            cur: HashMap::new(),
            prev: HashMap::new(),
            rotated: Instant::now(),
            period,
            cap: cap.max(1),
        }
    }

    fn maybe_rotate(&mut self, now: Instant) {
        if now.duration_since(self.rotated) >= self.period || self.cur.len() >= self.cap {
            self.prev = std::mem::take(&mut self.cur);
            self.rotated = now;
        }
    }

    /// The entry for `key` (promoted into the current generation), if any.
    pub(crate) fn get_mut(&mut self, key: &str, now: Instant) -> Option<&mut V> {
        if !self.cur.contains_key(key) {
            let v = self.prev.remove(key)?;
            self.maybe_rotate(now);
            self.cur.insert(key.to_string(), v);
        }
        self.cur.get_mut(key)
    }

    /// The entry for `key`, inserting `init()` when absent.
    pub(crate) fn entry(&mut self, key: &str, now: Instant, init: impl FnOnce() -> V) -> &mut V {
        if !self.cur.contains_key(key) {
            let v = self.prev.remove(key).unwrap_or_else(init);
            self.maybe_rotate(now);
            self.cur.insert(key.to_string(), v);
        }
        self.cur.get_mut(key).expect("just inserted")
    }

    pub(crate) fn remove(&mut self, key: &str) {
        self.cur.remove(key);
        self.prev.remove(key);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.cur.len() + self.prev.len()
    }
}

/// Per-key token buckets (refill `rps`, capacity `burst`) that, unlike
/// [`Limiter`], can refund a token, and that never scan the map.
struct FailBuckets {
    rps: f64,
    burst: f64,
    m: Mutex<GenMap<(f64, Instant)>>,
}

impl FailBuckets {
    fn new(rps: f64, burst: i64, cap: usize) -> Self {
        FailBuckets {
            rps,
            burst: burst.max(1) as f64,
            m: Mutex::new(GenMap::new(IDLE, cap)),
        }
    }

    fn with<R>(&self, key: &str, f: impl FnOnce(&mut f64) -> R) -> R {
        let now = Instant::now();
        let mut m = self.m.lock().unwrap();
        let burst = self.burst;
        let b = m.entry(key, now, || (burst, now));
        b.0 = (b.0 + now.duration_since(b.1).as_secs_f64() * self.rps).min(burst);
        b.1 = now;
        f(&mut b.0)
    }

    /// Consumes a token; false when none is left.
    fn take(&self, key: &str) -> bool {
        self.with(key, |t| {
            if *t >= 1.0 {
                *t -= 1.0;
                true
            } else {
                false
            }
        })
    }

    /// Returns a token taken by [`FailBuckets::take`].
    fn refund(&self, key: &str) {
        let burst = self.burst;
        self.with(key, |t| *t = (*t + 1.0).min(burst));
    }
}

pub(crate) struct IpLimiter {
    general: Option<Limiter>,
    fails: FailBuckets,
    global: Limiter,
    last_sweep: AtomicU64,
}

fn epoch() -> Instant {
    static E: OnceLock<Instant> = OnceLock::new();
    *E.get_or_init(Instant::now)
}

/// A per-IP OTP guess reserved by [`IpLimiter::reserve_guess`]. Call
/// [`OtpCharge::refund`] when the code was correct; dropping it keeps the
/// charge.
pub(crate) struct OtpCharge<'a> {
    l: &'a IpLimiter,
    key: String,
}

impl OtpCharge<'_> {
    pub(crate) fn refund(self) {
        self.l.fails.refund(&self.key);
    }
}

impl IpLimiter {
    /// `rps <= 0` disables the general budget. Non-positive enumeration values
    /// fall back to the Go defaults (per-IP burst 10 refilling at 1/s, global
    /// 20/s with a burst of 40).
    pub(crate) fn new(
        rps: f64,
        burst: i64,
        fail_burst: i64,
        global_fail_rps: f64,
        global_fail_burst: i64,
    ) -> Self {
        let fail_burst = if fail_burst <= 0 { 10 } else { fail_burst };
        let global_fail_rps = if global_fail_rps <= 0.0 {
            20.0
        } else {
            global_fail_rps
        };
        let global_fail_burst = if global_fail_burst <= 0 {
            (2.0 * global_fail_rps) as i64
        } else {
            global_fail_burst
        };
        IpLimiter {
            general: Limiter::new(rps, burst),
            fails: FailBuckets::new(1.0, fail_burst, MAX_FAIL_KEYS),
            global: Limiter::new(global_fail_rps, global_fail_burst).expect("positive rate"),
            last_sweep: AtomicU64::new(0),
        }
    }

    fn maybe_sweep(&self) {
        let now = epoch().elapsed().as_secs();
        let last = self.last_sweep.load(Ordering::Relaxed);
        if now.saturating_sub(last) > 60
            && self
                .last_sweep
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            if let Some(g) = &self.general {
                g.sweep(IDLE);
            }
        }
    }

    /// General per-IP throttle: may a lookup from `ip` proceed at all?
    pub(crate) fn allow(&self, ip: &str) -> bool {
        self.maybe_sweep();
        match &self.general {
            Some(l) => l.allow(&bucket_key(ip)),
            None => true,
        }
    }

    /// Charged when a token lookup misses. Returns false once the per-IP or
    /// global miss allowance is exhausted (the caller then answers 429, not
    /// 404). Only misses the per-IP budget allowed draw on the global budget,
    /// so one source cannot drain it for everyone.
    pub(crate) fn allow_fail(&self, ip: &str) -> bool {
        self.fails.take(&bucket_key(ip)) && self.global.allow("")
    }

    /// Reserves one OTP guess against the client's per-IP (/64) miss budget
    /// only. OTP guesses never touch the global lookup-miss budget, so a token
    /// enumeration flood elsewhere cannot block legitimate logins. Returns
    /// None when the client's budget is already exhausted.
    pub(crate) fn reserve_guess(&self, ip: &str) -> Option<OtpCharge<'_>> {
        let key = bucket_key(ip);
        self.fails.take(&key).then_some(OtpCharge { l: self, key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_fail_per_ip() {
        let l = IpLimiter::new(1000.0, 1000, 3, 1000.0, 2000);
        let ok = (0..10).filter(|_| l.allow_fail("10.0.0.1")).count();
        assert_eq!(ok, 3, "per-IP miss budget");
        assert!(l.allow_fail("10.0.0.2"), "second IP has its own budget");
    }

    #[test]
    fn allow_fail_global() {
        let l = IpLimiter::new(1000.0, 1000, 1000, 1.0, 5);
        let ok = (0..50)
            .filter(|i| l.allow_fail(&format!("172.16.0.{i}")))
            .count();
        assert_eq!(ok, 5, "distributed guessing must be capped");
    }

    #[test]
    fn denied_misses_do_not_drain_global() {
        let l = IpLimiter::new(1000.0, 1000, 2, 0.001, 5);
        for _ in 0..50 {
            l.allow_fail("10.0.0.1");
        }
        let ok = (0..4)
            .filter(|i| l.allow_fail(&format!("10.0.1.{i}")))
            .count();
        assert_eq!(ok, 3, "one IP spends only its per-IP share of global");
    }

    #[test]
    fn otp_guess_reserve_refund_and_no_global() {
        let l = IpLimiter::new(1000.0, 1000, 2, 0.001, 1);
        // Drain the global miss budget from elsewhere.
        assert!(l.allow_fail("10.9.9.9"));
        assert!(!l.allow_fail("10.9.9.8"));
        // OTP guesses are still allowed (per-IP budget only)...
        let c = l.reserve_guess("10.0.0.1").expect("first guess");
        c.refund(); // correct code: not charged
        assert!(l.reserve_guess("10.0.0.1").is_some());
        assert!(l.reserve_guess("10.0.0.1").is_some());
        // ...until wrong guesses spend the per-IP budget.
        assert!(l.reserve_guess("10.0.0.1").is_none());
        assert!(l.reserve_guess("10.0.0.2").is_some(), "other IP");
    }

    #[test]
    fn genmap_bounded() {
        let mut m: GenMap<u32> = GenMap::new(Duration::from_secs(3600), 10);
        let now = Instant::now();
        for i in 0..1000 {
            *m.entry(&format!("k{i}"), now, || 0) += 1;
        }
        assert!(m.len() <= 20, "len {}", m.len());
        *m.entry("hot", now, || 0) += 1;
        for i in 0..9 {
            m.entry(&format!("x{i}"), now, || 0);
        }
        assert_eq!(
            m.get_mut("hot", now).copied(),
            Some(1),
            "survives one rotation"
        );
        m.remove("hot");
        assert!(m.get_mut("hot", now).is_none());
    }

    #[test]
    fn ipv6_shares_a_64_bucket() {
        let l = IpLimiter::new(1000.0, 1000, 3, 1000.0, 2000);
        let ok = (0..10)
            .filter(|i| l.allow_fail(&format!("2001:db8:0:1::{i:x}")))
            .count();
        assert_eq!(ok, 3, "addresses in one /64 share the miss budget");
        assert!(l.allow_fail("2001:db8:0:2::1"), "other /64");
    }

    #[test]
    fn general_disabled_when_rps_zero() {
        let l = IpLimiter::new(0.0, 0, 0, 0.0, 0);
        assert!((0..100).all(|_| l.allow("1.2.3.4")));
    }
}
