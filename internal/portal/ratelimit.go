package portal

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipLimiter throttles token lookups per client IP to make token guessing
// and scraping impractical.
//
// It keeps two independent budgets:
//
//   - a general per-IP budget charged on every lookup, which caps ordinary
//     traffic (page loads, status polling) from a single client;
//   - an enumeration budget charged only when a lookup fails (unknown or
//     malformed token). Legitimate users follow real links and practically
//     never miss, so a burst of failures is the signature of token guessing.
//     The failure budget is enforced both per-IP and globally, so a
//     distributed guessing attack spread across many source IPs is still
//     capped in aggregate.
type ipLimiter struct {
	mu        sync.Mutex
	m         map[string]*limiterEntry // general per-IP
	fails     map[string]*limiterEntry // per-IP failed-lookup budget
	global    *rate.Limiter            // aggregate failed-lookup budget
	rps       rate.Limit
	burst     int
	failRPS   rate.Limit
	failBurst int
	trusted   []netip.Prefix // proxies whose X-Forwarded-For is honoured
	lastSweep time.Time
}

type limiterEntry struct {
	l    *rate.Limiter
	seen time.Time
}

// newIPLimiterFull configures the general and the enumeration (failed-lookup)
// budgets. failBurst is the per-IP allowance of consecutive misses;
// globalFailRPS caps the aggregate miss rate across all clients. Non-positive
// values fall back to safe defaults. X-Forwarded-For is honoured only for
// requests whose peer is in xffFrom (the trusted reverse proxies); nil
// ignores the header entirely.
func newIPLimiterFull(rps float64, burst int, failBurst int, globalFailRPS float64, globalFailBurst int, xffFrom []netip.Prefix) *ipLimiter {
	if failBurst <= 0 {
		failBurst = 10
	}
	if globalFailRPS <= 0 {
		globalFailRPS = 20
	}
	if globalFailBurst <= 0 {
		globalFailBurst = 2 * int(globalFailRPS)
	}
	return &ipLimiter{
		m:         map[string]*limiterEntry{},
		fails:     map[string]*limiterEntry{},
		global:    rate.NewLimiter(rate.Limit(globalFailRPS), globalFailBurst),
		rps:       rate.Limit(rps),
		burst:     burst,
		failRPS:   1, // one sustained retry per second per IP after the burst
		failBurst: failBurst,
		trusted:   xffFrom,
	}
}

func (l *ipLimiter) clientIP(r *http.Request) string {
	return clientIP(r, l.trusted)
}

// peerAddr returns the address of the directly connected peer.
func peerAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func inPrefixes(a netip.Addr, list []netip.Prefix) bool {
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// fromTrustedProxy reports whether the request came directly from one of the
// trusted reverse proxies.
func fromTrustedProxy(r *http.Request, trusted []netip.Prefix) bool {
	a, ok := peerAddr(r)
	return ok && inPrefixes(a, trusted)
}

// clientIP returns the client address used for rate limiting. The
// X-Forwarded-For chain is only consulted when the peer is a trusted proxy,
// and then walked from the right (entries appended by our own proxies),
// skipping trusted hops: the first untrusted address is the client. The
// leftmost entries are client-controlled and are never used on their own.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	peer, ok := peerAddr(r)
	if !ok {
		return r.RemoteAddr
	}
	if len(trusted) == 0 || !inPrefixes(peer, trusted) {
		return peer.String()
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // garbage: keep the last hop we could vouch for
		}
		client = a.Unmap()
		if !inPrefixes(client, trusted) {
			break
		}
	}
	return client.String()
}

// sweep drops idle per-IP entries. Caller holds l.mu.
func (l *ipLimiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) <= time.Minute {
		return
	}
	for k, e := range l.m {
		if now.Sub(e.seen) > 10*time.Minute {
			delete(l.m, k)
		}
	}
	for k, e := range l.fails {
		if now.Sub(e.seen) > 10*time.Minute {
			delete(l.fails, k)
		}
	}
	l.lastSweep = now
}

// Allow reports whether a lookup from this request may proceed at all
// (general per-IP throttle).
func (l *ipLimiter) Allow(r *http.Request) bool {
	if l.rps <= 0 {
		return true
	}
	ip := l.clientIP(r)
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(now)
	e, ok := l.m[ip]
	if !ok {
		e = &limiterEntry{l: rate.NewLimiter(l.rps, l.burst)}
		l.m[ip] = e
	}
	e.seen = now
	return e.l.Allow()
}

// AllowFail is charged when a lookup misses (unknown or malformed token). It
// returns false once the client's per-IP miss allowance or the global miss
// allowance is exhausted, at which point the caller should throttle (429)
// instead of returning the ordinary not-found response. This slows token
// enumeration, including attacks distributed across many source IPs, without
// affecting legitimate users (who follow valid links and rarely miss).
func (l *ipLimiter) AllowFail(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	e, ok := l.fails[ip]
	if !ok {
		e = &limiterEntry{l: rate.NewLimiter(l.failRPS, l.failBurst)}
		l.fails[ip] = e
	}
	e.seen = now
	perIP := e.l.Allow()
	l.mu.Unlock()
	// Always consume from the global budget so that a spread-out attack is
	// still capped even when no single IP exceeds its own allowance.
	glob := l.global.Allow()
	return perIP && glob
}
