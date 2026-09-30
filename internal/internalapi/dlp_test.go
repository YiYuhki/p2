package internalapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
)

type reviewer struct{ st *store.Memory }

func (r reviewer) Release(ctx context.Context, id, by string) error {
	return r.st.DecideHold(ctx, id, model.HoldReleased, by, "", time.Now())
}
func (r reviewer) Reject(ctx context.Context, id, by, reason string) error {
	return r.st.DecideHold(ctx, id, model.HoldRejected, by, reason, time.Now())
}

func TestDLPAdminAPI(t *testing.T) {
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	id := "00000000-0000-0000-0000-00000000abcd"
	st.CreateHold(context.Background(), &model.Hold{ID: id, TokenHash: "t", MailFrom: "kim@example.com",
		RcptTo: []string{"p@ext.org"}, Findings: json.RawMessage(`{"findings":[]}`), Status: model.HoldHeld,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	st.RecordDLPEvent(context.Background(), &model.DLPEvent{ID: "e1", Action: "hold", Findings: json.RawMessage(`{}`), At: time.Now()})

	api := New(st, obj, nil, secret, slog.New(slog.NewTextHandler(io.Discard, nil)))
	const admin = "admin-token-0123456789"
	api.EnableDLPAdmin(admin, reviewer{st})
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	base := srv.URL + "/internal/v1/dlp"

	// The analyzer token must not grant admin access.
	if code, _ := do(t, "GET", base+"/holds", secret, ""); code != 401 {
		t.Fatalf("analyzer token accepted for admin API: %d", code)
	}
	code, body := do(t, "GET", base+"/holds?status=held", admin, "")
	if code != 200 || !strings.Contains(body, id) {
		t.Fatalf("list: %d %s", code, body)
	}
	if code, body = do(t, "GET", base+"/events", admin, ""); code != 200 || !strings.Contains(body, `"action":"hold"`) {
		t.Fatalf("events: %d %s", code, body)
	}
	if code, _ = do(t, "POST", base+"/holds/"+id+"/reject", admin, `{"by":"sec","reason":"no"}`); code != 200 {
		t.Fatalf("reject: %d", code)
	}
	if code, _ = do(t, "POST", base+"/holds/"+id+"/release", admin, `{}`); code != 409 {
		t.Fatalf("release after reject: %d", code)
	}
	if code, _ = do(t, "GET", base+"/holds/nope", admin, ""); code != 404 {
		t.Fatalf("bad id: %d", code)
	}
}
