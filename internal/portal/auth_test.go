package portal

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
	"github.com/yiyuhki/p2/internal/token"
)

type fakeMailer struct {
	mu    sync.Mutex
	codes map[string]string
}

func (m *fakeMailer) SendCode(_ context.Context, to, code string, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[to] = code
	return nil
}

func (m *fakeMailer) code(to string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.codes[to]
}

type authFixture struct {
	srv    *httptest.Server
	store  *store.Memory
	mailer *fakeMailer
	base   string
	id     string
}

func newAuthFixture(t *testing.T, auth AuthOptions) *authFixture {
	t.Helper()
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	obj.Put(context.Background(), "k", strings.NewReader("secret-bytes"), 12)
	tok := token.New()
	now := time.Now()
	a := &model.Attachment{
		ID: "00000000-0000-0000-0000-00000000000a", MessageID: "msg1", Filename: "plan.xlsx",
		Size: 12, StorageKey: "k", TokenHash: token.Hash(tok), Status: model.StatusClean,
		CreatedAt: now, QueuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	st.CreateMessage(context.Background(),
		&model.Message{ID: "msg1", RcptTo: []string{"Alice@Example.com", "bob@example.com"}},
		[]*model.Attachment{a})

	if auth.SessionTTL == 0 {
		auth.SessionTTL = time.Hour
	}
	auth.SessionSecret = []byte("0123456789abcdef0123456789abcdef")
	auth.OTPTTL, auth.OTPMaxAttempts, auth.OTPResendAfter = 10*time.Minute, 3, time.Minute
	auth.AcceptedDomains = []string{"example.com"}
	m := &fakeMailer{codes: map[string]string{}}
	p := New(st, obj, NewMemoryTickets(), Options{
		TicketTTL: time.Minute, RateLimitRPS: 1000, RateLimitBurst: 1000,
		Auth: auth, Codes: NewMemoryCodes(), Mailer: m,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return &authFixture{srv: srv, store: st, mailer: m, base: srv.URL + "/d/" + tok, id: a.ID}
}

func browser(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func fetch(t *testing.T, c *http.Client, method, u string, form url.Values) (*http.Response, string) {
	t.Helper()
	var req *http.Request
	if form != nil {
		req, _ = http.NewRequest(method, u, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, _ = http.NewRequest(method, u, nil)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestOTPLoginFlow(t *testing.T) {
	f := newAuthFixture(t, AuthOptions{Mode: "otp"})
	c := browser(t)

	resp, body := fetch(t, c, "GET", f.base, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "수신자 본인 확인") || strings.Contains(body, "plan.xlsx") {
		t.Fatalf("expected login page without file details:\n%s", body)
	}
	if resp, _ := fetch(t, c, "GET", f.base+"/status", nil); resp.StatusCode != 401 {
		t.Fatalf("status must require auth, got %d", resp.StatusCode)
	}
	// Download without session is refused.
	if _, body := fetch(t, c, "POST", f.base+"/download", url.Values{}); strings.Contains(body, "secret-bytes") {
		t.Fatal("download without auth")
	}

	// Request a code (case-insensitive recipient match).
	_, body = fetch(t, c, "POST", f.base+"/auth", url.Values{"email": {"ALICE@example.com"}})
	if !strings.Contains(body, "인증 코드를 입력") {
		t.Fatalf("code page expected:\n%s", body)
	}
	code := f.mailer.code("alice@example.com")
	if len(code) != 6 {
		t.Fatalf("code not mailed: %q", code)
	}

	// Wrong code.
	_, body = fetch(t, c, "POST", f.base+"/auth", url.Values{"email": {"alice@example.com"}, "code": {"000000x"}})
	if !strings.Contains(body, "올바르지 않거나") {
		t.Fatal("wrong code should fail")
	}
	// Right code -> session -> page shows file + user.
	resp, body = fetch(t, c, "POST", f.base+"/auth", url.Values{"email": {"alice@example.com"}, "code": {code}})
	if resp.StatusCode != 200 || !strings.Contains(body, "안전한 파일") || !strings.Contains(body, "alice@example.com") {
		t.Fatalf("login failed: %d\n%s", resp.StatusCode, body)
	}
	// Code is single use.
	_, body = fetch(t, c, "POST", f.base+"/auth", url.Values{"email": {"alice@example.com"}, "code": {code}})
	if !strings.Contains(body, "올바르지 않거나") {
		t.Fatal("code must be single-use")
	}

	resp, body = fetch(t, c, "POST", f.base+"/download", url.Values{})
	if resp.StatusCode != 200 || body != "secret-bytes" {
		t.Fatalf("download after login failed: %d %q", resp.StatusCode, body)
	}
	if len(f.store.Downloads) != 1 || f.store.Downloads[0].User != "alice@example.com" {
		t.Fatalf("audit event missing user: %+v", f.store.Downloads)
	}

	// Logout clears the session.
	fetch(t, c, "POST", f.base+"/logout", url.Values{})
	if _, body := fetch(t, c, "GET", f.base, nil); !strings.Contains(body, "수신자 본인 확인") {
		t.Fatal("logout did not clear session")
	}
}

func TestOTPNonRecipientGetsNoCode(t *testing.T) {
	f := newAuthFixture(t, AuthOptions{Mode: "otp"})
	c := browser(t)
	_, body := fetch(t, c, "POST", f.base+"/auth", url.Values{"email": {"mallory@evil.com"}})
	if !strings.Contains(body, "수신자라면 인증 코드가 발송") {
		t.Fatal("response must not reveal recipient list")
	}
	if f.mailer.code("mallory@evil.com") != "" {
		t.Fatal("code sent to non-recipient")
	}
}

func TestOTPBruteForceLimit(t *testing.T) {
	f := newAuthFixture(t, AuthOptions{Mode: "otp"})
	c := browser(t)
	fetch(t, c, "POST", f.base+"/auth", url.Values{"email": {"bob@example.com"}})
	code := f.mailer.code("bob@example.com")
	for i := 0; i < 3; i++ {
		fetch(t, c, "POST", f.base+"/auth", url.Values{"email": {"bob@example.com"}, "code": {"999999"}})
	}
	_, body := fetch(t, c, "POST", f.base+"/auth", url.Values{"email": {"bob@example.com"}, "code": {code}})
	if !strings.Contains(body, "올바르지 않거나") {
		t.Fatal("code must be destroyed after max attempts")
	}
}

func TestSessionForOtherRecipientForbidden(t *testing.T) {
	f := newAuthFixture(t, AuthOptions{Mode: "otp"})
	p := &Server{opts: Options{Auth: AuthOptions{SessionSecret: []byte("0123456789abcdef0123456789abcdef")}}, now: time.Now}
	c := browser(t)
	u, _ := url.Parse(f.srv.URL)
	c.Jar.SetCookies(u, []*http.Cookie{{Name: sessionCookie, Value: p.signSession("carol@example.com", time.Now().Add(time.Hour)), Path: "/"}})
	resp, body := fetch(t, c, "GET", f.base, nil)
	if resp.StatusCode != 403 || !strings.Contains(body, "권한이 없습니다") {
		t.Fatalf("non-recipient session: %d", resp.StatusCode)
	}

	// Tampered cookie is ignored -> login page.
	c.Jar.SetCookies(u, []*http.Cookie{{Name: sessionCookie, Value: p.signSession("alice@example.com", time.Now().Add(time.Hour)) + "x", Path: "/"}})
	if _, body := fetch(t, c, "GET", f.base, nil); !strings.Contains(body, "수신자 본인 확인") {
		t.Fatal("tampered cookie accepted")
	}
	// Expired cookie is ignored.
	c.Jar.SetCookies(u, []*http.Cookie{{Name: sessionCookie, Value: p.signSession("alice@example.com", time.Now().Add(-time.Minute)), Path: "/"}})
	if _, body := fetch(t, c, "GET", f.base, nil); !strings.Contains(body, "수신자 본인 확인") {
		t.Fatal("expired cookie accepted")
	}
}

func TestDomainUsersAllowed(t *testing.T) {
	f := newAuthFixture(t, AuthOptions{Mode: "header", TrustedHeader: "X-Auth-Request-Email", AllowDomainUsers: true})
	req, _ := http.NewRequest("GET", f.base, nil)
	req.Header.Set("X-Auth-Request-Email", "carol@example.com")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("domain user should be allowed, got %d", resp.StatusCode)
	}
}

func TestHeaderMode(t *testing.T) {
	f := newAuthFixture(t, AuthOptions{Mode: "header", TrustedHeader: "X-Auth-Request-Email"})
	get := func(email string) int {
		req, _ := http.NewRequest("GET", f.base, nil)
		if email != "" {
			req.Header.Set("X-Auth-Request-Email", email)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(""); code != 401 {
		t.Fatalf("no header: %d", code)
	}
	if code := get("bob@example.com"); code != 200 {
		t.Fatalf("recipient: %d", code)
	}
	if code := get("carol@example.com"); code != 403 {
		t.Fatalf("non-recipient: %d", code)
	}
	// OTP endpoints are disabled in header mode.
	resp, _ := http.PostForm(f.base+"/auth", url.Values{"email": {"bob@example.com"}})
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("auth endpoint in header mode: %d", resp.StatusCode)
	}
}

func TestCrossOriginPostRejected(t *testing.T) {
	f := newAuthFixture(t, AuthOptions{Mode: "none"})
	req, _ := http.NewRequest("POST", f.base+"/download", nil)
	req.Header.Set("Origin", "https://evil.example.net")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-origin POST: %d", resp.StatusCode)
	}
	for _, h := range []map[string]string{
		{"Origin": f.srv.URL},
		{"Origin": "null", "Sec-Fetch-Site": "same-origin"}, // Chrome form post
	} {
		req, _ = http.NewRequest("POST", f.base+"/download", nil)
		for k, v := range h {
			req.Header.Set(k, v)
		}
		resp, _ = noRedirect.Do(req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("same-origin POST %v: %d", h, resp.StatusCode)
		}
	}
	for _, h := range []map[string]string{
		{"Sec-Fetch-Site": "cross-site"},
		{"Origin": "null"},
	} {
		req, _ = http.NewRequest("POST", f.base+"/download", nil)
		for k, v := range h {
			req.Header.Set(k, v)
		}
		resp, _ = noRedirect.Do(req)
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("cross-site POST %v: %d", h, resp.StatusCode)
		}
	}
}

func TestCodeMessage(t *testing.T) {
	msg := string(BuildCodeMessage("no-reply@example.com", "a@example.com", "123456", 10*time.Minute, time.Now()))
	for _, want := range []string{"To: <a@example.com>", "Auto-Submitted: auto-generated", "Content-Transfer-Encoding: base64"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q", want)
		}
	}
}
