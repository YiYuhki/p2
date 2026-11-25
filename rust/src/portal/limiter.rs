//! Token-lookup throttling for the portal. Port of the Go `portal/ratelimit.go`
//! `ipLimiter`, built on the crate's token bucket (`crate::ratelimit::Limiter`).
//!
//! Two independent budgets are kept:
//!
//! - a general per-IP budget charged on every lookup (page loads, polling);
//! - an enumeration budget charged only when a lookup misses (unknown or
//!   malformed token), enforced both per IP and globally so that token guessing
//!   spread over many source IPs is still capped in aggregate.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::ratelimit::Limiter;

/// Idle per-IP buckets are evicted after this long.
const IDLE: Duration = Duration::from_secs(10 * 60);

pub(crate) struct IpLimiter {
    general: Option<Limiter>,
    fails: Limiter,
    global: Limiter,
    last_sweep: AtomicU64,
}

fn epoch() -> Instant {
    static E: OnceLock<Instant> = OnceLock::new();
    *E.get_or_init(Instant::now)
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
            fails: Limiter::new(1.0, fail_burst).expect("positive rate"),
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
            self.fails.sweep(IDLE);
        }
    }

    /// General per-IP throttle: may a lookup from `ip` proceed at all?
    pub(crate) fn allow(&self, ip: &str) -> bool {
        self.maybe_sweep();
        match &self.general {
            Some(l) => l.allow(ip),
            None => true,
        }
    }

    /// Charged when a lookup misses. Returns false once the per-IP or global
    /// miss allowance is exhausted (the caller then answers 429, not 404).
    pub(crate) fn allow_fail(&self, ip: &str) -> bool {
        let per_ip = self.fails.allow(ip);
        // Always consume from the global budget so a spread-out attack is
        // capped even when no single IP exceeds its own allowance.
        let glob = self.global.allow("");
        per_ip && glob
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
    fn general_disabled_when_rps_zero() {
        let l = IpLimiter::new(0.0, 0, 0, 0.0, 0);
        assert!((0..100).all(|_| l.allow("1.2.3.4")));
    }
}
