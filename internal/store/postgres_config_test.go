package store

import (
	"testing"
	"time"
)

func TestPoolConfigAppliesOptions(t *testing.T) {
	cfg, err := poolConfig(PGOptions{
		DSN:             "postgres://u:p@localhost:5432/db",
		MaxConns:        20,
		MinConns:        3,
		MaxConnLifetime: 30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConns != 20 {
		t.Errorf("MaxConns = %d, want 20", cfg.MaxConns)
	}
	if cfg.MinConns != 3 {
		t.Errorf("MinConns = %d, want 3", cfg.MinConns)
	}
	if cfg.MaxConnLifetime != 30*time.Minute {
		t.Errorf("MaxConnLifetime = %v, want 30m", cfg.MaxConnLifetime)
	}
}

func TestPoolConfigZeroKeepsDefaults(t *testing.T) {
	cfg, err := poolConfig(PGOptions{DSN: "postgres://u:p@localhost:5432/db"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConns <= 0 {
		t.Errorf("zero MaxConns should keep pgx default, got %d", cfg.MaxConns)
	}
}

func TestPoolConfigBadDSN(t *testing.T) {
	if _, err := poolConfig(PGOptions{DSN: "://not a dsn"}); err == nil {
		t.Fatal("expected error for malformed DSN")
	}
}
