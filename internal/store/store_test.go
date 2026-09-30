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

func holdConformance(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	mk := func(exp time.Time) *model.Hold {
		return &model.Hold{ID: uuid.NewString(), TokenHash: uuid.NewString() + uuid.NewString()[:28],
			MailFrom: "a@example.com", RcptTo: []string{"x@ext.org"}, Subject: "s", StorageKey: "holds/k",
			Size: 10, Findings: json.RawMessage(`{"findings":[]}`), Status: model.HoldHeld,
			CreatedAt: now, ExpiresAt: exp}
	}
	h1, h2 := mk(now.Add(time.Hour)), mk(now.Add(-time.Minute))
	for _, h := range []*model.Hold{h1, h2} {
		if err := s.CreateHold(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	g, err := s.GetHoldByTokenHash(ctx, h1.TokenHash)
	if err != nil || g.ID != h1.ID || g.RcptTo[0] != "x@ext.org" || g.Status != model.HoldHeld {
		t.Fatalf("hold by token: %+v %v", g, err)
	}
	held, _ := s.ListHolds(ctx, model.HoldHeld, 100, Page{})
	if len(held) < 2 {
		t.Fatalf("list held: %d", len(held))
	}
	exp, _ := s.ListExpiredHolds(ctx, now, 100)
	found := false
	for _, h := range exp {
		found = found || h.ID == h2.ID
		if h.ID == h1.ID {
			t.Fatal("unexpired hold listed")
		}
	}
	if !found {
		t.Fatal("expired hold not listed")
	}
	if err := s.DecideHold(ctx, h1.ID, model.HoldReleased, "sec@example.com", "ok", now); err != nil {
		t.Fatal(err)
	}
	if err := s.DecideHold(ctx, h1.ID, model.HoldRejected, "x", "", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("double decision: %v", err)
	}
	g, _ = s.GetHold(ctx, h1.ID)
	if g.Status != model.HoldReleased || g.DecidedBy != "sec@example.com" || g.DecidedAt == nil {
		t.Fatalf("decided: %+v", g)
	}
	ev := &model.DLPEvent{ID: uuid.NewString(), MailFrom: "a@example.com", RcptTo: []string{"x@ext.org"},
		Action: "hold", Severity: "high", Findings: json.RawMessage(`{}`), HoldID: h1.ID, At: now}
	if err := s.RecordDLPEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	evs, err := s.ListDLPEvents(ctx, 10, Page{})
	if err != nil || len(evs) == 0 || evs[0].ID != ev.ID || evs[0].HoldID != h1.ID {
		t.Fatalf("events: %+v %v", evs, err)
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

func TestMemoryConformance(t *testing.T) {
	m := NewMemory()
	conformance(t, m)
	holdConformance(t, m)
	paginationConformance(t, m)
}

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
	holdConformance(t, p)
	paginationConformance(t, p)

	var n int
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM download_events WHERE username='u1@example.com'`).Scan(&n); err != nil || n == 0 {
		t.Fatalf("download event not persisted: %d %v", n, err)
	}
}

func TestHoldAndEventPagination(t *testing.T) { paginationConformance(t, NewMemory()) }

func paginationConformance(t *testing.T, s Store) {
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Insert 5 holds and 5 events with a unique marker so the assertions are
	// robust to rows a prior conformance step left in a shared store.
	mine := map[string]bool{}
	for i := 0; i < 5; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		hid, eid := uuid.NewString(), uuid.NewString()
		mine[hid], mine[eid] = true, true
		if err := s.CreateHold(ctx, &model.Hold{ID: hid, TokenHash: "page-" + hid, Status: model.HoldHeld, MailFrom: "a@ex.org",
			RcptTo: []string{"x@ext.org"}, Findings: json.RawMessage(`{}`), CreatedAt: at, ExpiresAt: at.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordDLPEvent(ctx, &model.DLPEvent{ID: eid, MailFrom: "a@ex.org", RcptTo: []string{"x@ext.org"},
			Action: "notify", Severity: "low", Findings: json.RawMessage(`{}`), At: at}); err != nil {
			t.Fatal(err)
		}
	}

	// walk pages the full list and returns every id seen; it fails on any
	// cross-page repeat or non-monotonic (time DESC) ordering.
	walk := func(next func(Page) (ids []string, times []time.Time, more bool)) []string {
		var all []string
		var last time.Time
		first := true
		seen := map[string]bool{}
		page := Page{}
		for {
			ids, times, ok := next(page)
			for i, id := range ids {
				if seen[id] {
					t.Fatalf("id %s repeated across pages", id)
				}
				seen[id] = true
				if !first && times[i].After(last) {
					t.Fatal("pagination not monotonically newest-first")
				}
				first, last = false, times[i]
				all = append(all, id)
			}
			if !ok {
				return all
			}
			li := len(ids) - 1
			page = Page{Before: times[li], BeforeID: ids[li]}
		}
	}

	got := walk(func(p Page) ([]string, []time.Time, bool) {
		hs, err := s.ListHolds(ctx, model.HoldHeld, 2, p)
		if err != nil {
			t.Fatal(err)
		}
		ids, ts := make([]string, len(hs)), make([]time.Time, len(hs))
		for i, h := range hs {
			ids[i], ts[i] = h.ID, h.CreatedAt
		}
		return ids, ts, len(hs) == 2
	})
	assertAllPresent(t, "holds", got, mine)

	got = walk(func(p Page) ([]string, []time.Time, bool) {
		evs, err := s.ListDLPEvents(ctx, 2, p)
		if err != nil {
			t.Fatal(err)
		}
		ids, ts := make([]string, len(evs)), make([]time.Time, len(evs))
		for i, e := range evs {
			ids[i], ts[i] = e.ID, e.At
		}
		return ids, ts, len(evs) == 2
	})
	assertAllPresent(t, "events", got, mine)
}

func assertAllPresent(t *testing.T, what string, got []string, mine map[string]bool) {
	t.Helper()
	n := 0
	for _, id := range got {
		if mine[id] {
			n++
		}
	}
	if n != 5 {
		t.Fatalf("%s: paged %d of my 5 marked rows", what, n)
	}
}
