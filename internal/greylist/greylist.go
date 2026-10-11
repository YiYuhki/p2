// Package greylist implements SMTP greylisting: the first delivery attempt for
// an unseen (client IP, sender, recipient) triplet is deferred with a temporary
// failure, and the triplet is accepted only when it is retried after a short
// delay. Legitimate MTAs retry and succeed; much spamware does not retry at
// all, so it never gets through.
//
// State is kept in memory, so it is per-instance and reset on restart (a
// restart just re-defers in-flight triplets, which legitimate senders retry).
package greylist

import (
	"strings"
	"sync"
	"time"
)

type entry struct {
	first  time.Time // when the triplet was first seen
	last   time.Time // most recent attempt (passed entries only, for expiry)
	passed bool
}

// Greylist tracks triplets. The zero value is not usable; call New.
type Greylist struct {
	delay  time.Duration
	expiry time.Duration
	now    func() time.Time

	mu   sync.Mutex
	seen map[string]entry
}

// New returns a Greylist. delay is the minimum wait before a retry is accepted
// (default 1m); expiry is how long state is retained (default 36h).
func New(delay, expiry time.Duration) *Greylist {
	if delay <= 0 {
		delay = time.Minute
	}
	if expiry <= 0 {
		expiry = 36 * time.Hour
	}
	return &Greylist{delay: delay, expiry: expiry, now: time.Now, seen: make(map[string]entry)}
}

func key(ip, from, to string) string {
	return strings.ToLower(ip + "\x00" + from + "\x00" + to)
}

// Allow records a delivery attempt for the triplet and reports whether it may
// proceed now. The first attempt (and any retry sooner than delay) returns
// false — the caller should defer with a 4xx. Once the delay has elapsed the
// triplet passes and keeps passing until it expires.
func (g *Greylist) Allow(ip, from, to string) bool {
	now := g.now()
	k := key(ip, from, to)
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.seen[k]
	if !ok {
		g.seen[k] = entry{first: now, last: now}
		return false
	}
	if e.passed {
		e.last = now
		g.seen[k] = e
		return true
	}
	if now.Sub(e.first) >= g.delay {
		g.seen[k] = entry{first: e.first, last: now, passed: true}
		return true
	}
	// Still within the delay window; keep deferring without resetting first.
	return false
}

// Sweep drops entries that have aged out: a passed triplet idle for longer than
// expiry, or a never-retried triplet older than expiry. Call it periodically.
func (g *Greylist) Sweep() {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, e := range g.seen {
		ref := e.first
		if e.passed {
			ref = e.last
		}
		if now.Sub(ref) > g.expiry {
			delete(g.seen, k)
		}
	}
}

// Len reports the number of tracked triplets (for tests/metrics).
func (g *Greylist) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}
