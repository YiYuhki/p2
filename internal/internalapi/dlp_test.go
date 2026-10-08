package internalapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yiyuhki/p2/internal/config"
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

func TestMetricsAndReadyz(t *testing.T) {
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	api := New(st, obj, nil, secret, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	// /metrics and /readyz are unauthenticated (probed by orchestrators).
	code, body := do(t, "GET", srv.URL+"/metrics", "", "")
	if code != 200 || !strings.Contains(body, "secmail_dlp_scan_seconds") {
		t.Fatalf("metrics: %d, body has secmail_=%v", code, strings.Contains(body, "secmail_"))
	}
	code, body = do(t, "GET", srv.URL+"/readyz", "", "")
	if code != 200 || !strings.Contains(body, `"database":"ok"`) || !strings.Contains(body, `"storage":"ok"`) {
		t.Fatalf("readyz healthy: %d %s", code, body)
	}
}

func TestReadyzReportsFailure(t *testing.T) {
	obj, _ := storage.NewFS(t.TempDir())
	api := New(failingStore{store.NewMemory()}, obj, nil, secret, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	code, body := do(t, "GET", srv.URL+"/readyz", "", "")
	if code != 503 || !strings.Contains(body, `"database":"fail"`) {
		t.Fatalf("readyz should report db failure: %d %s", code, body)
	}
}

type failingStore struct{ store.Store }

func (failingStore) Ping(context.Context) error { return context.DeadlineExceeded }

func TestDLPHoldsPaginationCursor(t *testing.T) {
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	base0 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	ids := map[string]bool{}
	for i := 0; i < 3; i++ {
		id := "00000000-0000-0000-0000-00000000000" + string(rune('a'+i))
		ids[id] = true
		st.CreateHold(context.Background(), &model.Hold{ID: id, Status: model.HoldHeld,
			Findings: json.RawMessage(`{}`), CreatedAt: base0.Add(time.Duration(i) * time.Minute),
			ExpiresAt: base0.Add(time.Hour)})
	}
	api := New(st, obj, nil, secret, slog.New(slog.NewTextHandler(io.Discard, nil)))
	const admin = "admin-token-0123456789"
	api.EnableDLPAdmin(admin, reviewer{st})
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	get := func(url string) (int, string, []holdJSON) {
		t.Helper()
		req, _ := httpNewGet(url, admin)
		resp, err := httpDo(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var hs []holdJSON
		json.Unmarshal(b, &hs)
		return resp.StatusCode, resp.Header.Get("X-Next-Cursor"), hs
	}

	code, cursor, page1 := get(srv.URL + "/internal/v1/dlp/holds?status=held&limit=2")
	if code != 200 || len(page1) != 2 || cursor == "" {
		t.Fatalf("page1: code=%d n=%d cursor=%q", code, len(page1), cursor)
	}
	_, cursor2, page2 := get(srv.URL + "/internal/v1/dlp/holds?status=held&limit=2&cursor=" + cursor)
	if len(page2) != 1 {
		t.Fatalf("page2 should have the last hold, got %d", len(page2))
	}
	if cursor2 != "" {
		t.Fatalf("no more pages expected, got cursor %q", cursor2)
	}
	all := map[string]bool{page1[0].ID: true, page1[1].ID: true, page2[0].ID: true}
	if len(all) != 3 {
		t.Fatalf("pages overlapped: %v", all)
	}
	for id := range ids {
		if !all[id] {
			t.Fatalf("hold %s missing across pages", id)
		}
	}
}

func httpNewGet(url, bearer string) (*http.Request, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err == nil && bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return req, err
}

func httpDo(req *http.Request) (*http.Response, error) { return http.DefaultClient.Do(req) }

func TestDLPEventsFilteredPaginationKeepsFilter(t *testing.T) {
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	base0 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	// 3 block + 3 notify events, interleaved in time.
	for i := 0; i < 6; i++ {
		action := "block"
		if i%2 == 1 {
			action = "notify"
		}
		st.RecordDLPEvent(context.Background(), &model.DLPEvent{ID: uuid.NewString(), MailFrom: "a@ex.org",
			RcptTo: []string{"x@ext.org"}, Action: action, Severity: "high", Findings: json.RawMessage(`{}`),
			At: base0.Add(time.Duration(i) * time.Minute)})
	}
	api := New(st, obj, nil, secret, slog.New(slog.NewTextHandler(io.Discard, nil)))
	const admin = "admin-token-0123456789"
	api.EnableDLPAdmin(admin, reviewer{st})
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	get := func(url string) (string, int) {
		req, _ := httpNewGet(url, admin)
		resp, err := httpDo(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var evs []struct {
			Action string `json:"action"`
		}
		json.Unmarshal(b, &evs)
		for _, e := range evs {
			if e.Action != "block" {
				t.Fatalf("filtered page leaked a %q event", e.Action)
			}
		}
		return resp.Header.Get("X-Next-Cursor"), len(evs)
	}

	// limit=2 over 3 block events: page 1 (2) + page 2 via cursor alone (1).
	cursor, n1 := get(srv.URL + "/internal/v1/dlp/events?action=block&limit=2")
	if n1 != 2 || cursor == "" {
		t.Fatalf("page1: n=%d cursor=%q", n1, cursor)
	}
	// Deliberately omit action= on page 2 — the cursor must carry it.
	_, n2 := get(srv.URL + "/internal/v1/dlp/events?limit=2&cursor=" + cursor)
	if n2 != 1 {
		t.Fatalf("page2 should have the last block event only, got %d", n2)
	}
}

func TestDLPRuleTestEndpoint(t *testing.T) {
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	api := New(st, obj, nil, secret, slog.New(slog.NewTextHandler(io.Discard, nil)))
	const admin = "admin-token-0123456789"
	api.EnableDLPAdmin(admin, reviewer{st})
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	base := srv.URL + "/internal/v1/dlp/rules/test"

	code, body := do(t, "POST", base, admin, `{"pattern":"ORD-[0-9]{6}","text":"ORD-123456 and ORD-654321"}`)
	if code != 200 || !strings.Contains(body, `"count":2`) {
		t.Fatalf("rule test: %d %s", code, body)
	}
	if strings.Contains(body, "123456") {
		t.Fatalf("matches not masked: %s", body)
	}
	if code, _ := do(t, "POST", base, admin, `{"pattern":"(","text":"x"}`); code != 400 {
		t.Fatalf("bad regex should 400, got %d", code)
	}
	if code, _ := do(t, "POST", base, secret, `{"pattern":"x","text":"x"}`); code != 401 {
		t.Fatalf("analyzer token must not reach admin endpoint: %d", code)
	}
}

type polReviewer struct{ reviewer }

func (polReviewer) Policy() (config.DLPActions, []string, []string, bool, bool) {
	return config.DLPActions{High: "block", Medium: "notify", Low: "allow"},
		[]string{"payroll@example.com"}, []string{"partner.example"}, true, false
}

func TestDLPPolicyEndpoint(t *testing.T) {
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	api := New(st, obj, nil, secret, slog.New(slog.NewTextHandler(io.Discard, nil)))
	const admin = "admin-token-0123456789"
	api.EnableDLPAdmin(admin, polReviewer{reviewer{st}})
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	code, body := do(t, "GET", srv.URL+"/internal/v1/dlp/policy", admin, "")
	if code != 200 || !strings.Contains(body, "payroll@example.com") || !strings.Contains(body, `"dry_run":true`) {
		t.Fatalf("policy endpoint: %d %s", code, body)
	}
}
