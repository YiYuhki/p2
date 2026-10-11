// Package ratelimit provides a per-key token-bucket limiter used to cap the
// message rate of a single inbound client IP, so one source cannot flood the
// gateway even while staying under the per-IP connection limit.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter holds one token bucket per key (client IP), created on first use and
// evicted when idle. The zero value is not usable; call New.
type Limiter struct {
	rps   rate.Limit
	burst int
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// New returns a Limiter allowing rps tokens/sec with the given burst, or nil
// when rps <= 0 (disabled), so callers need not check whether it is configured.
func New(rps float64, burst int) *Limiter {
	if rps <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = 1
	}
	return &Limiter{rps: rate.Limit(rps), burst: burst, now: time.Now, buckets: make(map[string]*bucket)}
}

// Allow reports whether an event for key may proceed now, consuming a token. A
// nil Limiter always allows (disabled).
func (l *Limiter) Allow(key string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{lim: rate.NewLimiter(l.rps, l.burst)}
		l.buckets[key] = b
	}
	b.seen = l.now()
	lim := b.lim
	l.mu.Unlock()
	return lim.Allow()
}

// Sweep evicts buckets idle for longer than idle, bounding memory under a
// churn of distinct client IPs. Call it periodically.
func (l *Limiter) Sweep(idle time.Duration) {
	if l == nil {
		return
	}
	cutoff := l.now().Add(-idle)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.seen.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

// Len reports the number of tracked keys (for tests/metrics).
func (l *Limiter) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
