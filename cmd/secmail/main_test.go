package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yiyuhki/p2/internal/dnsbl"
)

type blResolver struct{ hit string }

func (r blResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if host == r.hit {
		return []string{"127.0.0.2"}, nil
	}
	return nil, errors.New("no such host")
}

func TestDNSBLGate(t *testing.T) {
	// 192.0.2.66 -> 66.2.0.192.bl.example
	bl := dnsbl.New([]string{"bl.example"}, time.Second, blResolver{hit: "66.2.0.192.bl.example"}, quietLog())
	g := dnsblGate{bl: bl}
	if serr := g.Gate(context.Background(), netip.MustParseAddr("192.0.2.66")); serr == nil || serr.Code != 554 {
		t.Fatalf("listed IP should be refused 554, got %v", serr)
	}
	if serr := g.Gate(context.Background(), netip.MustParseAddr("192.0.2.67")); serr != nil {
		t.Fatalf("unlisted IP should pass, got %v", serr)
	}
}

func TestCertExpiry(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	want := time.Now().Add(42 * 24 * time.Hour).UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     want,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "cert.pem")
	os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)

	got, err := certExpiry(f)
	if err != nil {
		t.Fatalf("certExpiry: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("expiry = %v, want %v", got, want)
	}
	if _, err := certExpiry(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("missing file should error")
	}
}

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
