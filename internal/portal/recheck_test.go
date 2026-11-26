package portal

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
	"github.com/yiyuhki/p2/internal/token"
)

// hookTickets runs onRedeem when a ticket is redeemed, simulating a verdict
// change that lands between the page load and the transfer.
type hookTickets struct {
	Tickets
	onRedeem func()
}

func (h hookTickets) Redeem(ctx context.Context, t string) (string, error) {
	id, err := h.Tickets.Redeem(ctx, t)
	h.onRedeem()
	return id, err
}

func TestFileRechecksFreshVerdict(t *testing.T) {
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	obj.Put(context.Background(), "k1", strings.NewReader("file-bytes"), 10)
	tok := token.New()
	now := time.Now()
	a := &model.Attachment{
		ID: "00000000-0000-0000-0000-0000000000aa", MessageID: "m", Filename: "f.pdf",
		Size: 10, StorageKey: "k1", TokenHash: token.Hash(tok), Status: model.StatusClean,
		CreatedAt: now, QueuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	st.CreateMessage(context.Background(), &model.Message{ID: "m"}, []*model.Attachment{a})
	tk := hookTickets{Tickets: NewMemoryTickets(), onRedeem: func() {
		st.MarkExpired(context.Background(), a.ID, time.Now())
	}}
	p := New(st, obj, tk, Options{TicketTTL: time.Minute, RateLimitRPS: 1000, RateLimitBurst: 1000},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	base := srv.URL + "/d/" + tok
	r := post(t, base+"/download")
	loc := r.Header.Get("Location")
	if !strings.Contains(loc, "/file?t=") {
		t.Fatalf("no ticket issued: %d %q", r.StatusCode, loc)
	}
	resp, body := get(t, srv.URL+loc)
	if resp.StatusCode == http.StatusOK && body == "file-bytes" {
		t.Fatal("file served although the attachment changed state after the page load")
	}
}
