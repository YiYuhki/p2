package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yiyuhki/p2/internal/model"
)

// conformance runs the same behavioural checks against every Store.
func conformance(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	msg := &model.Message{ID: uuid.NewString(), MessageID: "<x@y>", MailFrom: "a@ext.org",
		RcptTo: []string{"u1@example.com", "u2@example.com"}, Subject: "s", ReceivedAt: now, AttachmentCount: 2}
	mk := func(sha string, exp time.Time) *model.Attachment {
		return &model.Attachment{ID: uuid.NewString(), MessageID: msg.ID, Filename: "f", ContentType: "application/pdf",
			Size: 3, SHA256: sha, StorageKey: "k/" + uuid.NewString(), TokenHash: uuid.NewString() + uuid.NewString()[:28],
			Status: model.StatusPending, Attempts: 1, CreatedAt: now, UpdatedAt: now, QueuedAt: now, ExpiresAt: exp}
	}
	sha := uuid.NewString() + uuid.NewString()[:28]
	a1 := mk(sha, now.Add(time.Hour))
	a2 := mk(uuid.NewString()+uuid.NewString()[:28], now.Add(-time.Minute))
	if err := s.CreateMessage(ctx, msg, []*model.Attachment{a1, a2}); err != nil {
		t.Fatal(err)
	}

	m, err := s.GetMessage(ctx, msg.ID)
	if err != nil || len(m.RcptTo) != 2 || m.RcptTo[1] != "u2@example.com" {
		t.Fatalf("GetMessage: %+v %v", m, err)
	}
	got, err := s.GetAttachmentByTokenHash(ctx, a1.TokenHash)
	if err != nil || got.ID != a1.ID || got.Status != model.StatusPending {
		t.Fatalf("by token: %+v %v", got, err)
	}
	if _, err := s.GetAttachment(ctx, uuid.NewString()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}

	if _, err := s.FindReusableVerdict(ctx, sha, now.Add(-time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatal("no verdict yet")
	}
	detail := json.RawMessage(`{"yara":["r1"]}`)
	if err := s.SetVerdict(ctx, a1.ID, model.StatusMalicious, "T", detail, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetVerdict(ctx, a1.ID, model.StatusClean, "", nil, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
	if err := s.SetVerdict(ctx, uuid.NewString(), model.StatusClean, "", nil, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	r, err := s.FindReusableVerdict(ctx, sha, now.Add(-time.Hour))
	if err != nil || r.ID != a1.ID || r.ThreatName != "T" {
		t.Fatalf("reuse: %+v %v", r, err)
	}
	var d map[string]any
	if json.Unmarshal(r.VerdictDetail, &d); d["yara"] == nil {
		t.Fatalf("detail not stored: %s", r.VerdictDetail)
	}

	stale, err := s.ListStalePending(ctx, now.Add(time.Second), 100)
	if err != nil || !containsID(stale, a2.ID) || containsID(stale, a1.ID) {
		t.Fatalf("stale: %v", err)
	}
	if err := s.MarkRequeued(ctx, a2.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	g2, _ := s.GetAttachment(ctx, a2.ID)
	if g2.Attempts != 2 || !g2.QueuedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("requeue: %+v", g2)
	}

	ev := model.DownloadEvent{AttachmentID: a1.ID, User: "u1@example.com", RemoteIP: "10.0.0.1", UserAgent: "ua", At: now}
	if err := s.RecordDownload(ctx, ev); err != nil {
		t.Fatal(err)
	}
	g1, _ := s.GetAttachment(ctx, a1.ID)
	if g1.DownloadCount != 1 || g1.LastDownloadedAt == nil {
		t.Fatalf("download: %+v", g1)
	}

	exp, err := s.ListExpired(ctx, now, 100)
	if err != nil || !containsID(exp, a2.ID) || containsID(exp, a1.ID) {
		t.Fatalf("expired: %v", err)
	}
	if err := s.MarkExpired(ctx, a2.ID, now); err != nil {
		t.Fatal(err)
	}
	exp, _ = s.ListExpired(ctx, now, 100)
	if containsID(exp, a2.ID) {
		t.Fatal("expired twice")
	}
}

func containsID(list []*model.Attachment, id string) bool {
	for _, a := range list {
		if a.ID == id {
			return true
		}
	}
	return false
}

func TestMemoryConformance(t *testing.T) { conformance(t, NewMemory()) }

// TestPostgresConformance runs against a real database when
// SECMAIL_TEST_PG_DSN is set, e.g.
// postgres://postgres@127.0.0.1:5432/secmail_test?sslmode=disable
func TestPostgresConformance(t *testing.T) {
	dsn := os.Getenv("SECMAIL_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("SECMAIL_TEST_PG_DSN not set")
	}
	ctx := context.Background()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	// Second start must find migrations already applied.
	p, err = NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("re-running migrations: %v", err)
	}
	defer p.Close()
	conformance(t, p)

	var n int
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM download_events WHERE username='u1@example.com'`).Scan(&n); err != nil || n == 0 {
		t.Fatalf("download event not persisted: %d %v", n, err)
	}
}
