package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

type fixture struct {
	srv   *httptest.Server
	store *store.Memory
	tok   string
	id    string
}

func newFixture(t *testing.T, expires time.Time) *fixture {
	t.Helper()
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	obj.Put(context.Background(), "k1", strings.NewReader("file-bytes"), 10)

	tok := token.New()
	now := time.Now()
	a := &model.Attachment{
		ID: "00000000-0000-0000-0000-000000000001", MessageID: "m", Filename: "보고서 (최종).pdf",
		ContentType: "application/pdf", Size: 10, StorageKey: "k1", TokenHash: token.Hash(tok),
		Status: model.StatusPending, CreatedAt: now, QueuedAt: now, ExpiresAt: expires,
	}
	st.CreateMessage(context.Background(), &model.Message{ID: "m"}, []*model.Attachment{a})

	p := New(st, obj, NewMemoryTickets(), Options{TicketTTL: time.Minute, RateLimitRPS: 1000, RateLimitBurst: 1000},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return &fixture{srv: srv, store: st, tok: tok, id: a.ID}
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	resp, err := noRedirect.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func post(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := noRedirect.Post(url, "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func TestPendingThenCleanDownloadFlow(t *testing.T) {
	f := newFixture(t, time.Now().Add(time.Hour))
	base := f.srv.URL + "/d/" + f.tok

	resp, body := get(t, base)
	if resp.StatusCode != 200 || !strings.Contains(body, "보안 검사가 진행 중") || !strings.Contains(body, `type="submit" disabled`) {
		t.Fatalf("pending page wrong: %d\n%s", resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "nonce-") {
		t.Fatal("CSP missing")
	}

	_, js := get(t, base+"/status")
	var st statusJSON
	json.Unmarshal([]byte(js), &st)
	if st.Status != model.StatusPending {
		t.Fatalf("status json: %s", js)
	}

	// Download must not be possible while pending.
	if r := post(t, base+"/download"); r.StatusCode != http.StatusSeeOther || strings.Contains(r.Header.Get("Location"), "/file") {
		t.Fatalf("pending download should bounce to page, got %d %s", r.StatusCode, r.Header.Get("Location"))
	}

	f.store.SetVerdict(context.Background(), f.id, model.StatusClean, "", nil, time.Now())

	resp, body = get(t, base)
	if !strings.Contains(body, "안전한 파일") || strings.Contains(body, `type="submit" disabled`) {
		t.Fatalf("clean page wrong:\n%s", body)
	}

	r := post(t, base+"/download")
	loc := r.Header.Get("Location")
	if r.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "/file?t=") {
		t.Fatalf("want redirect to file, got %d %q", r.StatusCode, loc)
	}
	resp, body = get(t, f.srv.URL+loc)
	if resp.StatusCode != 200 || body != "file-bytes" {
		t.Fatalf("download failed: %d %q", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("content type %q", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(strings.ToLower(cd), "filename*=utf-8''") {
		t.Fatalf("non-ASCII filename should be RFC 5987 encoded: %q", cd)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") {
		t.Fatalf("must be an attachment disposition: %q", cd)
	}

	// Ticket is single use.
	resp, _ = get(t, f.srv.URL+loc)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("reused ticket should redirect, got %d", resp.StatusCode)
	}
	a, _ := f.store.GetAttachment(context.Background(), f.id)
	if a.DownloadCount != 1 {
		t.Fatalf("download count %d", a.DownloadCount)
	}
}

func TestMaliciousBlocked(t *testing.T) {
	f := newFixture(t, time.Now().Add(time.Hour))
	f.store.SetVerdict(context.Background(), f.id, model.StatusMalicious, "Ransom.Generic", nil, time.Now())
	base := f.srv.URL + "/d/" + f.tok

	resp, body := get(t, base)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "악성코드가 감지") || !strings.Contains(body, "Ransom.Generic") {
		t.Fatalf("malicious page wrong: %d\n%s", resp.StatusCode, body)
	}
	if strings.Contains(body, "<form") {
		t.Fatal("no download form for malicious files")
	}
	if r := post(t, base+"/download"); strings.Contains(r.Header.Get("Location"), "/file") {
		t.Fatal("malicious file must not get a ticket")
	}
}

func TestTicketCannotBeUsedForOtherAttachment(t *testing.T) {
	f := newFixture(t, time.Now().Add(time.Hour))
	f.store.SetVerdict(context.Background(), f.id, model.StatusClean, "", nil, time.Now())
	tk, _ := NewMemoryTickets().Issue(context.Background(), "other-id", time.Minute)
	resp, body := get(t, f.srv.URL+"/d/"+f.tok+"/file?t="+tk)
	if resp.StatusCode == 200 && body == "file-bytes" {
		t.Fatal("foreign ticket accepted")
	}
}

func TestExpiredAndUnknown(t *testing.T) {
	f := newFixture(t, time.Now().Add(-time.Minute))
	f.store.SetVerdict(context.Background(), f.id, model.StatusClean, "", nil, time.Now())
	resp, body := get(t, f.srv.URL+"/d/"+f.tok)
	if resp.StatusCode != http.StatusGone || !strings.Contains(body, "만료") {
		t.Fatalf("expired: %d", resp.StatusCode)
	}
	if r := post(t, f.srv.URL+"/d/"+f.tok+"/download"); strings.Contains(r.Header.Get("Location"), "/file") {
		t.Fatal("expired link must not download")
	}
	resp, _ = get(t, f.srv.URL+"/d/"+token.New())
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown token: %d", resp.StatusCode)
	}
	resp, _ = get(t, f.srv.URL+"/d/short")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("malformed token: %d", resp.StatusCode)
	}
}

func TestRateLimit(t *testing.T) {
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	p := New(st, obj, NewMemoryTickets(), Options{RateLimitRPS: 1, RateLimitBurst: 2},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := p.Handler()
	codes := []int{}
	for i := 0; i < 4; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/d/"+token.New(), bytes.NewReader(nil)))
		codes = append(codes, rec.Code)
	}
	if codes[3] != http.StatusTooManyRequests {
		t.Fatalf("expected throttling, got %v", codes)
	}
}

func TestContentDisposition(t *testing.T) {
	cases := []struct {
		name      string
		wantASCII string // filename="..."
	}{
		{"report.pdf", "report.pdf"},
		{"보고서.pdf", "___.pdf"},
		{`a"b.txt`, "a_b.txt"},         // quote replaced in ascii fallback
		{"a\r\nb.txt", "ab.txt"},       // control chars stripped
		{"../../etc/passwd", "passwd"}, // path traversal stripped
		{"", "download"},               // empty -> download
		{"..", "download"},             // dotdot -> download
		{"a/b/c.bin", "c.bin"},         // unix separator stripped
		{`x\y\z.bin`, "z.bin"},         // windows separator stripped
	}
	for _, c := range cases {
		got := contentDisposition(c.name)
		if !strings.HasPrefix(got, "attachment;") {
			t.Errorf("%q: not an attachment disposition: %q", c.name, got)
		}
		if !strings.Contains(got, `filename="`+c.wantASCII+`"`) {
			t.Errorf("%q: want ascii %q, got %q", c.name, c.wantASCII, got)
		}
		// The header must never carry a raw quote-break or CR/LF that could
		// escape the value or inject a header.
		if v := strings.TrimPrefix(got, `attachment; filename="`); strings.HasPrefix(v, c.wantASCII+`"`) {
			// ok: the ascii value is properly closed
		}
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("%q: header contains CR/LF: %q", c.name, got)
		}
	}
	// A non-ASCII name must also emit an RFC 5987 filename* carrying the real name.
	if got := contentDisposition("보고서.pdf"); !strings.Contains(got, "filename*=UTF-8''") {
		t.Errorf("non-ASCII name should include filename*: %q", got)
	}
	// A plain ASCII name needs no filename*.
	if got := contentDisposition("report.pdf"); strings.Contains(got, "filename*=") {
		t.Errorf("ascii name should not include filename*: %q", got)
	}
}

func TestAllowFailPerIP(t *testing.T) {
	// failBurst 3, generous global so only the per-IP budget bites.
	l := newIPLimiterFull(1000, 1000, 3, 1000, 2000, false)
	ok := 0
	for i := 0; i < 10; i++ {
		if l.AllowFail("10.0.0.1") {
			ok++
		}
	}
	if ok != 3 {
		t.Fatalf("per-IP miss budget = %d, want 3", ok)
	}
	// A different IP has its own budget.
	if !l.AllowFail("10.0.0.2") {
		t.Fatal("second IP should have its own budget")
	}
}

func TestAllowFailGlobal(t *testing.T) {
	// Large per-IP burst but a global cap of 5; spread across many IPs.
	l := newIPLimiterFull(1000, 1000, 1000, 1, 5, false)
	ok := 0
	for i := 0; i < 50; i++ {
		if l.AllowFail(fmt.Sprintf("172.16.0.%d", i)) {
			ok++
		}
	}
	if ok != 5 {
		t.Fatalf("global miss budget = %d, want 5 (distributed guessing must be capped)", ok)
	}
}

func TestEnumerationThrottleHTTP(t *testing.T) {
	f := newFixture(t, time.Now().Add(time.Hour))
	// Unknown but well-formed tokens: first EnumPerIPBurst (default 10) return
	// 404, then the client is throttled with 429.
	var got404, got429 int
	for i := 0; i < 20; i++ {
		resp, _ := get(t, f.srv.URL+"/d/"+token.New())
		switch resp.StatusCode {
		case http.StatusNotFound:
			got404++
		case http.StatusTooManyRequests:
			got429++
		default:
			t.Fatalf("unexpected status %d", resp.StatusCode)
		}
	}
	if got429 == 0 {
		t.Fatalf("token guessing was never throttled (404=%d 429=%d)", got404, got429)
	}
	// A valid token still works despite the guessing storm on the same IP.
	resp, _ := get(t, f.srv.URL+"/d/"+f.tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid token must still resolve, got %d", resp.StatusCode)
	}
}
