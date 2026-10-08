package portal

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
)

func adminFixture(t *testing.T, auth AuthOptions) (string, *fakeReviewer, *fakeMailer, []string) {
	t.Helper()
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	findings, _ := json.Marshal(map[string]any{"findings": []map[string]any{
		{"name": "주민등록번호", "severity": "high", "location": "첨부 a.xlsx", "count": 3, "samples": []string{"900101-1******"}},
		{"name": "여권", "severity": "medium", "location": "본문", "count": 1, "samples": []string{"M12****78"}},
	}})
	var ids []string
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		id := "00000000-0000-0000-0000-00000000000" + string(rune('a'+i))
		ids = append(ids, id)
		st.CreateHold(context.Background(), &model.Hold{ID: id, TokenHash: "tok" + id,
			MailFrom: "kim@example.com", RcptTo: []string{"p@ext.org"}, Subject: "고객 명단", Findings: findings,
			Status: model.HoldHeld, CreatedAt: base.Add(time.Duration(i) * time.Minute), ExpiresAt: base.Add(time.Hour)})
	}
	rv := &fakeReviewer{st: st}
	m := &fakeMailer{codes: map[string]string{}}
	auth.SessionSecret = []byte("0123456789abcdef0123456789abcdef")
	auth.SessionTTL, auth.OTPTTL, auth.OTPMaxAttempts, auth.OTPResendAfter = time.Hour, time.Minute, 3, time.Minute
	p := New(st, obj, NewMemoryTickets(), Options{RateLimitRPS: 1000, RateLimitBurst: 1000, Auth: auth,
		Codes: NewMemoryCodes(), Mailer: m, Holds: rv, DLPAdmins: []string{"Sec@Example.com"}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return srv.URL, rv, m, ids
}

func TestAdminDashboardDisabledWithoutAuth(t *testing.T) {
	url0, _, _, _ := adminFixture(t, AuthOptions{Mode: "none"})
	c := browser(t)
	if _, body := fetch(t, c, "GET", url0+"/dlp/admin", nil); !strings.Contains(body, "수신자 인증이 설정된") {
		t.Fatalf("none mode should show the disabled notice:\n%s", body)
	}
	if resp, _ := fetch(t, c, "GET", url0+"/dlp/admin/holds", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("holds API should 404 in none mode, got %d", resp.StatusCode)
	}
}

type holdsResp struct {
	Holds []adminHoldJSON `json:"holds"`
	Next  string          `json:"next"`
}

func adminLogin(t *testing.T, c *http.Client, base, email string, m *fakeMailer) {
	t.Helper()
	fetch(t, c, "POST", base+"/dlp/admin/auth", url.Values{"email": {email}})
	code := m.code(email)
	if code == "" {
		t.Fatalf("no OTP code for %s", email)
	}
	fetch(t, c, "POST", base+"/dlp/admin/auth", url.Values{"email": {email}, "code": {code}})
}

func TestAdminDashboardListAndDecide(t *testing.T) {
	base, rv, m, ids := adminFixture(t, AuthOptions{Mode: "otp"})
	c := browser(t)

	// Unauthenticated holds API is challenged.
	if resp, _ := fetch(t, c, "GET", base+"/dlp/admin/holds", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth holds API should 401, got %d", resp.StatusCode)
	}
	adminLogin(t, c, base, "sec@example.com", m)

	// The dashboard shell renders for the logged-in admin.
	if resp, body := fetch(t, c, "GET", base+"/dlp/admin", nil); resp.StatusCode != 200 ||
		!strings.Contains(body, "발송 보류 관리") || !strings.Contains(body, `id="hrows"`) ||
		!strings.Contains(body, "sec@example.com") {
		t.Fatalf("dashboard shell: %d\n%s", resp.StatusCode, body)
	}

	// List HELD holds — newest first, with severity summary.
	resp, body := fetch(t, c, "GET", base+"/dlp/admin/holds?status=HELD", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list: %d", resp.StatusCode)
	}
	var hr holdsResp
	if err := json.Unmarshal([]byte(body), &hr); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	if len(hr.Holds) != 3 {
		t.Fatalf("want 3 held, got %d", len(hr.Holds))
	}
	if hr.Holds[0].Severity != "high" || hr.Holds[0].Findings != 2 {
		t.Fatalf("severity summary wrong: %+v", hr.Holds[0])
	}

	// Release one by id.
	resp, body = fetch(t, c, "POST", base+"/dlp/admin/holds/"+ids[0]+"/release", url.Values{})
	if resp.StatusCode != 200 || !strings.Contains(body, "RELEASED") {
		t.Fatalf("release: %d %s", resp.StatusCode, body)
	}
	if len(rv.released) != 1 || rv.released[0] != "sec@example.com" {
		t.Fatalf("release not recorded by admin: %v", rv.released)
	}
	// Second decision on the same hold conflicts.
	if resp, _ = fetch(t, c, "POST", base+"/dlp/admin/holds/"+ids[0]+"/reject", url.Values{"reason": {"x"}}); resp.StatusCode != http.StatusConflict {
		t.Fatalf("double decide should 409, got %d", resp.StatusCode)
	}
	// Reject another with a reason.
	fetch(t, c, "POST", base+"/dlp/admin/holds/"+ids[1]+"/reject", url.Values{"reason": {"마스킹 필요"}})
	if len(rv.rejected) != 1 || rv.rejected[0] != "마스킹 필요" {
		t.Fatalf("reject reason not recorded: %v", rv.rejected)
	}
}

func TestAdminDashboardNonAdminForbidden(t *testing.T) {
	base, _, m, _ := adminFixture(t, AuthOptions{Mode: "otp"})
	c := browser(t)
	// kim is a sender, not a DLP admin: no code is ever sent, so they cannot log in.
	fetch(t, c, "POST", base+"/dlp/admin/auth", url.Values{"email": {"kim@example.com"}})
	if m.code("kim@example.com") != "" {
		t.Fatal("OTP code sent to non-admin")
	}
	// Without a valid session the holds API stays challenged.
	if resp, _ := fetch(t, c, "GET", base+"/dlp/admin/holds", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-admin holds API should 401, got %d", resp.StatusCode)
	}
}

func TestAdminEventsAndExport(t *testing.T) {
	base, rv, m, _ := adminFixture(t, AuthOptions{Mode: "otp"})
	// Seed a couple of audit events.
	rv.st.RecordDLPEvent(context.Background(), &model.DLPEvent{ID: "ev-a", MailFrom: "kim@example.com",
		RcptTo: []string{"p@ext.org"}, Subject: "유출 의심", Action: "block", Severity: "high",
		Findings: []byte(`{}`), At: time.Now()})
	rv.st.RecordDLPEvent(context.Background(), &model.DLPEvent{ID: "ev-b", MailFrom: "lee@example.com",
		RcptTo: []string{"q@ext.org"}, Subject: "알림건", Action: "notify", Severity: "medium",
		Findings: []byte(`{}`), At: time.Now()})
	c := browser(t)
	adminLogin(t, c, base, "sec@example.com", m)

	// Events JSON, filtered to block.
	resp, body := fetch(t, c, "GET", base+"/dlp/admin/events?action=block", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `"action":"block"`) || strings.Contains(body, "notify") {
		t.Fatalf("events filter: %d %s", resp.StatusCode, body)
	}

	// CSV export (events).
	resp, body = fetch(t, c, "GET", base+"/dlp/admin/export?kind=events", nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") {
		t.Fatalf("events csv content-type: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(body, "id,at,action,severity") || !strings.Contains(body, "ev-a") || !strings.Contains(body, "ev-b") {
		t.Fatalf("events csv body:\n%s", body)
	}

	// CSV export (holds) includes the seeded held hold.
	resp, body = fetch(t, c, "GET", base+"/dlp/admin/export?kind=holds", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "mail_from") || !strings.Contains(body, "kim@example.com") {
		t.Fatalf("holds csv: %d\n%s", resp.StatusCode, body)
	}
	if resp, _ := fetch(t, c, "GET", base+"/dlp/admin/export?kind=bogus", nil); resp.StatusCode != 400 {
		t.Fatalf("bad kind should 400, got %d", resp.StatusCode)
	}
}
