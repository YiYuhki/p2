package greylist

import (
	"testing"
	"time"
)

func TestDeferThenAllowAfterDelay(t *testing.T) {
	now := time.Now()
	g := New(time.Minute, time.Hour)
	g.now = func() time.Time { return now }

	// First attempt is deferred.
	if g.Allow("192.0.2.1", "a@ext", "b@us") {
		t.Fatal("first attempt should be deferred")
	}
	// A retry too soon is still deferred.
	now = now.Add(30 * time.Second)
	if g.Allow("192.0.2.1", "a@ext", "b@us") {
		t.Fatal("retry within delay should be deferred")
	}
	// A retry after the delay passes.
	now = now.Add(31 * time.Second) // 61s total >= 1m
	if !g.Allow("192.0.2.1", "a@ext", "b@us") {
		t.Fatal("retry after delay should pass")
	}
	// Once passed, subsequent attempts pass immediately.
	if !g.Allow("192.0.2.1", "a@ext", "b@us") {
		t.Fatal("passed triplet should keep passing")
	}
}

func TestTripletsAreIndependent(t *testing.T) {
	now := time.Now()
	g := New(time.Minute, time.Hour)
	g.now = func() time.Time { return now }
	g.Allow("192.0.2.1", "a@ext", "b@us") // defer triplet 1
	// A different recipient is a different triplet: also deferred, not allowed
	// by triplet 1's prior sighting.
	if g.Allow("192.0.2.1", "a@ext", "c@us") {
		t.Fatal("different recipient must be its own triplet")
	}
	if g.Len() != 2 {
		t.Fatalf("want 2 triplets, got %d", g.Len())
	}
}

func TestSweepExpires(t *testing.T) {
	now := time.Now()
	g := New(time.Minute, time.Hour)
	g.now = func() time.Time { return now }
	g.Allow("192.0.2.1", "a@ext", "b@us")
	now = now.Add(2 * time.Hour)
	g.Sweep()
	if g.Len() != 0 {
		t.Fatalf("expired triplet should be swept, len=%d", g.Len())
	}
}
