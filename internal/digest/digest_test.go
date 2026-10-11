package digest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/store"
)

type capSender struct {
	from string
	to   []string
	msg  []byte
	sent int
}

func (c *capSender) Send(_ context.Context, from string, to []string, msg []byte) error {
	c.from, c.to, c.msg = from, to, msg
	c.sent++
	return nil
}

type fakeStore struct{ holds []*model.Hold }

func (f *fakeStore) ListHolds(_ context.Context, status model.HoldStatus, limit int, page store.Page) ([]*model.Hold, error) {
	if page.Set() {
		return nil, nil // single page for the test
	}
	var out []*model.Hold
	for _, h := range f.holds {
		if h.Status == status {
			out = append(out, h)
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func TestDigestSendsSummary(t *testing.T) {
	st := &fakeStore{holds: []*model.Hold{
		{ID: "11111111-aaaa", MailFrom: "kim@example.com", RcptTo: []string{"p@ext.org"}, Subject: "명단",
			Status: model.HoldHeld, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
			Findings: []byte(`{"findings":[{"severity":"high"},{"severity":"low"}]}`)},
	}}
	snd := &capSender{}
	m := New(st, snd, "dlp@example.com", "보안메일", []string{"sec@example.com"}, time.UTC)
	if err := m.Send(context.Background()); err != nil {
		t.Fatal(err)
	}
	if snd.sent != 1 {
		t.Fatalf("want 1 send, got %d", snd.sent)
	}
	body := string(snd.msg)
	if !strings.Contains(body, "dlp@example.com") || !strings.Contains(body, "sec@example.com") {
		t.Fatalf("envelope headers missing:\n%s", body)
	}
}

func TestDigestSkipsWhenEmpty(t *testing.T) {
	snd := &capSender{}
	m := New(&fakeStore{}, snd, "dlp@example.com", "보안메일", []string{"sec@example.com"}, time.UTC)
	if err := m.Send(context.Background()); err != nil {
		t.Fatal(err)
	}
	if snd.sent != 0 {
		t.Fatal("no held mail should send no digest")
	}
}

func TestDigestDisabledWithoutRecipients(t *testing.T) {
	snd := &capSender{}
	if New(&fakeStore{}, snd, "dlp@example.com", "", nil, time.UTC) != nil {
		t.Fatal("no recipients should disable")
	}
	if New(&fakeStore{}, nil, "dlp@example.com", "", []string{"x@y"}, time.UTC) != nil {
		t.Fatal("no sender should disable")
	}
	var m *Mailer
	if err := m.Send(context.Background()); err != nil {
		t.Fatalf("nil mailer Send: %v", err)
	}
}

func TestSummarize(t *testing.T) {
	sev, n := summarize([]byte(`{"findings":[{"severity":"low"},{"severity":"high"},{"severity":"medium"}]}`))
	if sev != "high" || n != 3 {
		t.Fatalf("summarize = %s %d, want high 3", sev, n)
	}
	if sev, n := summarize(nil); sev != "-" || n != 0 {
		t.Fatalf("empty summarize = %s %d", sev, n)
	}
}
