package ratelimit

import (
	"testing"
	"time"
)

func TestBurstThenDeny(t *testing.T) {
	// 0 rps refill within the test window, burst 2: first two allowed, third denied.
	l := New(0.0001, 2)
	if !l.Allow("1.2.3.4") || !l.Allow("1.2.3.4") {
		t.Fatal("first two within burst should be allowed")
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("third over burst should be denied")
	}
	// A different key has its own bucket.
	if !l.Allow("5.6.7.8") {
		t.Fatal("distinct key should have its own budget")
	}
}

func TestNilAlwaysAllows(t *testing.T) {
	if New(0, 5) != nil {
		t.Fatal("rps<=0 should disable")
	}
	var l *Limiter
	if !l.Allow("x") {
		t.Fatal("nil limiter must allow")
	}
}

func TestSweepEvicts(t *testing.T) {
	now := time.Now()
	l := New(1, 1)
	l.now = func() time.Time { return now }
	l.Allow("1.2.3.4")
	if l.Len() != 1 {
		t.Fatalf("want 1 bucket, got %d", l.Len())
	}
	now = now.Add(2 * time.Hour)
	l.Sweep(time.Hour)
	if l.Len() != 0 {
		t.Fatalf("idle bucket should be evicted, len=%d", l.Len())
	}
}
