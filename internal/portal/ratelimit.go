package portal

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipLimiter throttles token lookups per client IP to make token guessing
// and scraping impractical.
type ipLimiter struct {
	mu         sync.Mutex
	m          map[string]*limiterEntry
	rps        rate.Limit
	burst      int
	trustProxy bool
	lastSweep  time.Time
}

type limiterEntry struct {
	l    *rate.Limiter
	seen time.Time
}

func newIPLimiter(rps float64, burst int, trustProxy bool) *ipLimiter {
	return &ipLimiter{m: map[string]*limiterEntry{}, rps: rate.Limit(rps), burst: burst, trustProxy: trustProxy}
}

func (l *ipLimiter) clientIP(r *http.Request) string {
	if l.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (l *ipLimiter) Allow(r *http.Request) bool {
	if l.rps <= 0 {
		return true
	}
	ip := l.clientIP(r)
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) > time.Minute {
		for k, e := range l.m {
			if now.Sub(e.seen) > 10*time.Minute {
				delete(l.m, k)
			}
		}
		l.lastSweep = now
	}
	e, ok := l.m[ip]
	if !ok {
		e = &limiterEntry{l: rate.NewLimiter(l.rps, l.burst)}
		l.m[ip] = e
	}
	e.seen = now
	return e.l.Allow()
}
