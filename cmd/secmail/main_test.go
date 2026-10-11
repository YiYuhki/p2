package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestValidateConfig(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	os.WriteFile(good, []byte("upstream:\n  addr: 127.0.0.1:25\nsmtp:\n  accepted_domains:\n    - example.com\ninternal_api:\n  token: 0123456789abcdef0123\n"), 0o600)
	if err := validateConfig([]string{"-config", good}); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := filepath.Join(dir, "bad.yaml")
	// Missing accepted_domains (open-relay protection) must fail validation.
	os.WriteFile(bad, []byte("upstream:\n  addr: 127.0.0.1:25\n"), 0o600)
	if err := validateConfig([]string{"-config", bad}); err == nil {
		t.Fatal("invalid config accepted")
	}
	if err := validateConfig([]string{"-config", filepath.Join(dir, "nope.yaml")}); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestWaitReadySucceedsAfterRetries(t *testing.T) {
	calls := 0
	err := waitReady(context.Background(), quietLog(), "dep", 10*time.Second, func(context.Context) error {
		calls++
		if calls < 3 {
			return errors.New("not up")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("want success, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}

func TestWaitReadyTimesOut(t *testing.T) {
	start := time.Now()
	err := waitReady(context.Background(), quietLog(), "dep", 1500*time.Millisecond, func(context.Context) error {
		return errors.New("down")
	})
	if err == nil {
		t.Fatal("want timeout error")
	}
	if time.Since(start) < time.Second {
		t.Fatalf("should have retried up to the timeout, elapsed %v", time.Since(start))
	}
}

func TestWaitReadyCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := waitReady(ctx, quietLog(), "dep", time.Minute, func(context.Context) error {
		calls++
		cancel()
		return errors.New("down")
	})
	if err == nil {
		t.Fatal("want cancellation error")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (cancel stops retries)", calls)
	}
}
