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
	"github.com/yiyuhki/p2/internal/token"
)

type fakeReviewer struct {
	st       *store.Memory
	released []string
	rejected []string
}

func (f *fakeReviewer) Release(ctx context.Context, id, by string) error {
	if err := f.st.DecideHold(ctx, id, model.HoldReleased, by, "", time.Now()); err != nil {
		return err
	}
	f.released = append(f.released, by)
	return nil
}

func (f *fakeReviewer) Reject(ctx context.Context, id, by, reason string) error {
	if err := f.st.DecideHold(ctx, id, model.HoldRejected, by, reason, time.Now()); err != nil {
		return err
	}
	f.rejected = append(f.rejected, reason)
	return nil
}

func holdFixture(t *testing.T, auth AuthOptions) (string, *fakeReviewer, *fakeMailer) {
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	tok := token.New()
	findings, _ := json.Marshal(map[string]any{"findings": []map[string]any{{
		"name": "주민등록번호/외국인등록번호", "severity": "high", "location": "첨부 고객.xlsx", "count": 12,
		"samples": []string{"900101-1******"}}}})
	st.CreateHold(context.Background(), &model.Hold{ID: "00000000-0000-0000-0000-0000000000h1", TokenHash: token.Hash(tok),
		MailFrom: "kim@example.com", RcptTo: []string{"p@ext.org"}, Subject: "고객 명단", Findings: findings,
		Status: model.HoldHeld, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	rv := &fakeReviewer{st: st}
	m := &fakeMailer{codes: map[string]string{}}
	auth.SessionSecret = []byte("0123456789abcdef0123456789abcdef")
	auth.SessionTTL, auth.OTPTTL, auth.OTPMaxAttempts, auth.OTPResendAfter = time.Hour, time.Minute, 3, time.Minute
	p := New(st, obj, NewMemoryTickets(), Options{RateLimitRPS: 1000, RateLimitBurst: 1000, Auth: auth,
		Codes: NewMemoryCodes(), Mailer: m, Holds: rv, DLPAdmins: []string{"Sec@Example.com"}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return srv.URL + "/dlp/" + tok, rv, m
}

func TestHoldReviewNoAuth(t *testing.T) {
	base, rv, _ := holdFixture(t, AuthOptions{Mode: "none"})
	c := browser(t)
	resp, body := fetch(t, c, "GET", base, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "검토 대기") || !strings.Contains(body, "900101-1******") ||
		!strings.Contains(body, "첨부 고객.xlsx") {
		t.Fatalf("review page: %d\n%s", resp.StatusCode, body)
	}
	_, body = fetch(t, c, "POST", base+"/reject", url.Values{"reason": {"마스킹 필요"}})
	if !strings.Contains(body, "반려되었습니다") || len(rv.rejected) != 1 || rv.rejected[0] != "마스킹 필요" {
		t.Fatalf("reject: %v\n%s", rv.rejected, body)
	}
	resp, body = fetch(t, c, "POST", base+"/release", url.Values{})
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "이미 처리된") {
		t.Fatalf("decided hold must not be released: %d", resp.StatusCode)
	}
}

func TestHoldReviewRequiresAdminOTP(t *testing.T) {
	base, rv, m := holdFixture(t, AuthOptions{Mode: "otp"})
	c := browser(t)
	if _, body := fetch(t, c, "GET", base, nil); !strings.Contains(body, "본인 확인") || strings.Contains(body, "고객 명단") {
		t.Fatal("review page must require login and hide details")
	}
	// The sender is not an admin: no code is sent.
	fetch(t, c, "POST", base+"/auth", url.Values{"email": {"kim@example.com"}})
	if m.code("kim@example.com") != "" {
		t.Fatal("code sent to non-admin")
	}
	fetch(t, c, "POST", base+"/auth", url.Values{"email": {"sec@example.com"}})
	code := m.code("sec@example.com")
	_, body := fetch(t, c, "POST", base+"/auth", url.Values{"email": {"sec@example.com"}, "code": {code}})
	if !strings.Contains(body, "승인 후 발송") {
		t.Fatalf("admin should see review page:\n%s", body)
	}
	_, body = fetch(t, c, "POST", base+"/release", url.Values{})
	if !strings.Contains(body, "승인되어") || len(rv.released) != 1 || rv.released[0] != "sec@example.com" {
		t.Fatalf("release: %v", rv.released)
	}
}
