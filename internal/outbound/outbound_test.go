package outbound

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/yiyuhki/p2/internal/config"
	"github.com/yiyuhki/p2/internal/dlp"
	"github.com/yiyuhki/p2/internal/gateway"
	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/smtpclient"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
)

// ---- fake next hop MTA ----

type sink struct {
	mu   sync.Mutex
	msgs []string
	rcpt [][]string
}

type sinkSession struct {
	s  *sink
	to []string
}

func (k *sink) NewSession(*smtp.Conn) (smtp.Session, error) { return &sinkSession{s: k}, nil }
func (x *sinkSession) Reset()                               { x.to = nil }
func (x *sinkSession) Logout() error                        { return nil }
func (x *sinkSession) Mail(string, *smtp.MailOptions) error { return nil }
func (x *sinkSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	x.to = append(x.to, to)
	return nil
}
func (x *sinkSession) Data(r io.Reader) error {
	b, _ := io.ReadAll(r)
	x.s.mu.Lock()
	x.s.msgs = append(x.s.msgs, string(b))
	x.s.rcpt = append(x.s.rcpt, x.to)
	x.s.mu.Unlock()
	return nil
}
func (k *sink) count() int { k.mu.Lock(); defer k.mu.Unlock(); return len(k.msgs) }

func listen(t *testing.T, be smtp.Backend) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(be)
	srv.Domain = "localhost"
	srv.AllowInsecureAuth = true
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return l.Addr().String()
}

// ---- fake notifier ----

type mailbox struct {
	mu   sync.Mutex
	mail []struct {
		to   []string
		body string
	}
}

func (m *mailbox) Send(_ context.Context, _ string, to []string, msg []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// decode the base64 body for assertions
	parts := strings.SplitN(string(msg), "\r\n\r\n", 2)
	body, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(parts[1], "\r\n", ""))
	m.mail = append(m.mail, struct {
		to   []string
		body string
	}{to, parts[0] + "\n" + string(body)})
	return nil
}

func (m *mailbox) waitFor(t *testing.T, to, contains string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		for _, x := range m.mail {
			if strings.Contains(strings.Join(x.to, ","), to) && strings.Contains(x.body, contains) {
				m.mu.Unlock()
				return x.body
			}
		}
		m.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no notice to %s containing %q", to, contains)
	return ""
}

// ---- harness ----

type env struct {
	addr  string
	next  *sink
	box   *mailbox
	store *store.Memory
	svc   *Service
}

func setup(t *testing.T, mutate func(*Options)) *env {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	next := &sink{}
	nextAddr := listen(t, next)
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	sc, err := dlp.NewScanner(dlp.Options{ScanAttachments: true})
	if err != nil {
		t.Fatal(err)
	}
	box := &mailbox{}
	opts := Options{
		Actions: config.DLPActions{High: config.ActionHold, Medium: config.ActionNotify,
			Low: config.ActionAllow, Uninspectable: config.ActionNotify},
		NotifySender: true, Admins: []string{"sec@example.com"}, NotifyFrom: "dlp@example.com",
		HoldTTL: time.Hour, PublicBaseURL: "https://sec.example.com", OwnDomains: []string{"example.com"},
		NextHop: smtpclient.Options{Addr: nextAddr, Timeout: 5 * time.Second},
	}
	if mutate != nil {
		mutate(&opts)
	}
	svc := New(sc, st, obj, box, opts, log)
	be := gateway.NewBackend(svc, gateway.BackendOptions{
		Name: "outbound", SenderDomains: []string{"example.com"},
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Upstream:       opts.NextHop,
	}, log)
	return &env{addr: listen(t, be), next: next, box: box, store: st, svc: svc}
}

func (e *env) send(from string, to []string, msg string) error {
	c, err := smtp.Dial(e.addr)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.SendMail(from, to, strings.NewReader(strings.ReplaceAll(msg, "\n", "\r\n")))
}

func mail(subject, body string) string {
	return "From: kim@example.com\nTo: partner@ext.org\nSubject: " + subject +
		"\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n" + body + "\n"
}

func withAttachment(name string, data []byte) string {
	return "From: kim@example.com\nTo: partner@ext.org\nSubject: files\nMIME-Version: 1.0\n" +
		"Content-Type: multipart/mixed; boundary=X\n\n--X\nContent-Type: text/plain\n\nsee attached\n" +
		"--X\nContent-Type: application/octet-stream; name=" + name + "\nContent-Disposition: attachment; filename=" + name +
		"\nContent-Transfer-Encoding: base64\n\n" + base64.StdEncoding.EncodeToString(data) + "\n--X--\n"
}

func TestCleanMailRelayedUntouched(t *testing.T) {
	e := setup(t, nil)
	msg := mail("hello", "회의 자료 공유드립니다.")
	if err := e.send("kim@example.com", []string{"partner@ext.org"}, msg); err != nil {
		t.Fatal(err)
	}
	if e.next.count() != 1 || !strings.Contains(e.next.msgs[0], "회의 자료") {
		t.Fatal("clean mail not relayed")
	}
	if strings.Contains(e.next.msgs[0], "X-SecMail") {
		t.Fatal("outbound mail must not carry internal DLP headers")
	}
}

func TestMediumFindingNotifiesAndDelivers(t *testing.T) {
	e := setup(t, nil)
	// JWT is medium severity -> notify.
	msg := mail("token", "토큰 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
	if err := e.send("kim@example.com", []string{"partner@ext.org"}, msg); err != nil {
		t.Fatal(err)
	}
	if e.next.count() != 1 {
		t.Fatal("notify action must still deliver")
	}
	body := e.box.waitFor(t, "kim@example.com", "정상적으로 발송")
	if !strings.Contains(body, "JWT") || !strings.Contains(body, "외부로 전달되었습니다. 즉시 폐기") {
		t.Fatalf("sender notice: %s", body)
	}
	e.box.waitFor(t, "sec@example.com", "JWT")
}

func TestHighFindingHeldThenReleased(t *testing.T) {
	e := setup(t, nil)
	msg := mail("고객 정보", "고객 주민번호 900101-1234567 입니다.")
	if err := e.send("kim@example.com", []string{"partner@ext.org"}, msg); err != nil {
		t.Fatalf("held mail should be accepted (250): %v", err)
	}
	if e.next.count() != 0 {
		t.Fatal("held mail was relayed")
	}
	holds, _ := e.store.ListHolds(context.Background(), model.HoldHeld, 10)
	if len(holds) != 1 {
		t.Fatalf("holds: %d", len(holds))
	}
	admin := e.box.waitFor(t, "sec@example.com", "https://sec.example.com/dlp/")
	if strings.Contains(admin, "1234567") {
		t.Fatal("notice leaked unmasked value")
	}
	e.box.waitFor(t, "kim@example.com", "보류")

	if err := e.svc.Release(context.Background(), holds[0].ID, "sec@example.com"); err != nil {
		t.Fatal(err)
	}
	if e.next.count() != 1 || e.next.rcpt[0][0] != "partner@ext.org" || !strings.Contains(e.next.msgs[0], "Subject:") {
		t.Fatalf("released mail not delivered: %+v", e.next.rcpt)
	}
	if err := e.svc.Release(context.Background(), holds[0].ID, "x"); !errors.Is(err, ErrNotHeld) {
		t.Fatalf("double release: %v", err)
	}
	e.box.waitFor(t, "kim@example.com", "승인하여 메일이 발송")
	evs, _ := e.store.ListDLPEvents(context.Background(), 10)
	if len(evs) != 1 || evs[0].Action != "hold" || evs[0].HoldID != holds[0].ID {
		t.Fatalf("audit event: %+v", evs)
	}
}

func TestReleaseFailureReopensHold(t *testing.T) {
	e := setup(t, nil)
	e.send("kim@example.com", []string{"partner@ext.org"}, mail("x", "AKIAIOSFODNN7EXAMPLE"))
	holds, _ := e.store.ListHolds(context.Background(), model.HoldHeld, 10)
	e.svc.relay = func(string, []string, []byte) error { return errors.New("next hop down") }
	if err := e.svc.Release(context.Background(), holds[0].ID, "sec"); err == nil {
		t.Fatal("expected relay error")
	}
	h, _ := e.store.GetHold(context.Background(), holds[0].ID)
	if h.Status != model.HoldHeld {
		t.Fatalf("hold should be reopened, got %s", h.Status)
	}
}

func TestRejectAndExpiry(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	e.send("kim@example.com", []string{"partner@ext.org"}, mail("a", "-----BEGIN RSA PRIVATE KEY-----"))
	e.send("kim@example.com", []string{"partner@ext.org"}, mail("b", "카드 4111-1111-1111-1111"))
	holds, _ := e.store.ListHolds(ctx, model.HoldHeld, 10)
	if len(holds) != 2 {
		t.Fatalf("holds %d", len(holds))
	}
	if err := e.svc.Reject(ctx, holds[0].ID, "sec@example.com", "마스킹 후 재발송"); err != nil {
		t.Fatal(err)
	}
	e.box.waitFor(t, "kim@example.com", "마스킹 후 재발송")

	e.svc.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	e.svc.SweepOnce(ctx)
	h, _ := e.store.GetHold(ctx, holds[1].ID)
	if h.Status != model.HoldExpired {
		t.Fatalf("want EXPIRED, got %s", h.Status)
	}
	e.box.waitFor(t, "kim@example.com", "검토 기한 내에 승인되지 않아")
	if e.next.count() != 0 {
		t.Fatal("rejected/expired mail was sent")
	}
}

func TestBlockPolicy(t *testing.T) {
	e := setup(t, func(o *Options) { o.Actions.High = config.ActionBlock })
	err := e.send("kim@example.com", []string{"partner@ext.org"}, mail("keys", "ghp_"+strings.Repeat("a1B", 12)))
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 550 || !strings.Contains(se.Message, "github_token") {
		t.Fatalf("want 550 DLP block, got %v", err)
	}
	e.box.waitFor(t, "kim@example.com", "차단")
}

func TestAttachmentsAndUninspectable(t *testing.T) {
	e := setup(t, nil)
	// CSV with bulk phone numbers (medium) -> notify.
	var rows []string
	for i := 0; i < 8; i++ {
		rows = append(rows, "고객,010-5555-"+strings.Repeat(string(rune('0'+i)), 4))
	}
	if err := e.send("kim@example.com", []string{"partner@ext.org"}, withAttachment("list.csv", []byte(strings.Join(rows, "\n")))); err != nil {
		t.Fatal(err)
	}
	e.box.waitFor(t, "kim@example.com", "첨부 list.csv")

	// Encrypted zip entry -> encrypted (falls back to uninspectable=notify).
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "a.xlsx", Flags: 1})
	w.Write([]byte("x"))
	zw.Close()
	if err := e.send("kim@example.com", []string{"partner@ext.org"}, withAttachment("secret.zip", buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	e.box.waitFor(t, "kim@example.com", "암호가 걸린 첨부파일")
	if e.next.count() != 2 {
		t.Fatalf("notify-level mail must be delivered, got %d", e.next.count())
	}
}

func TestExemptions(t *testing.T) {
	e := setup(t, func(o *Options) {
		o.ExemptRecipientDomains = []string{"payroll-partner.com"}
		o.ExemptSenders = []string{"hr-bot@example.com"}
	})
	if err := e.send("kim@example.com", []string{"a@payroll-partner.com"}, mail("급여", "900101-1234567")); err != nil {
		t.Fatal(err)
	}
	if err := e.send("hr-bot@example.com", []string{"x@ext.org"}, mail("급여", "900101-1234567")); err != nil {
		t.Fatal(err)
	}
	if e.next.count() != 2 {
		t.Fatalf("exempt mail should be delivered: %d", e.next.count())
	}
	evs, _ := e.store.ListDLPEvents(context.Background(), 10)
	if len(evs) != 1 || evs[0].Action != "allow" {
		t.Fatalf("exempt recipient should be logged as allow: %+v", evs)
	}
	// Mixed recipients: one non-exempt recipient -> policy applies.
	e.send("kim@example.com", []string{"a@payroll-partner.com", "b@ext.org"}, mail("급여", "900101-1234567"))
	if e.next.count() != 2 {
		t.Fatal("mixed recipients must not be exempt")
	}
}

func TestRelayProtection(t *testing.T) {
	e := setup(t, nil)
	err := e.send("someone@other.org", []string{"x@ext.org"}, mail("x", "hi"))
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 550 {
		t.Fatalf("foreign sender must be refused: %v", err)
	}

	// A client outside allowed_clients cannot relay at all.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	be := gateway.NewBackend(e.svc, gateway.BackendOptions{Name: "outbound",
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("10.9.9.9/32")}}, log)
	addr := listen(t, be)
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Hello("x"); err == nil {
		t.Fatal("unauthorised client accepted")
	}
}

func TestInternalMailSkippedUnlessConfigured(t *testing.T) {
	e := setup(t, nil)
	if err := e.send("kim@example.com", []string{"lee@example.com"}, mail("사내", "900101-1234567")); err != nil {
		t.Fatal(err)
	}
	if e.next.count() != 1 {
		t.Fatal("internal mail should pass without DLP")
	}
	e2 := setup(t, func(o *Options) { o.ScanInternal = true })
	e2.send("kim@example.com", []string{"lee@example.com"}, mail("사내", "900101-1234567"))
	if e2.next.count() != 0 {
		t.Fatal("scan_internal should apply the policy to internal mail")
	}
}

func TestEncryptedAttachmentPolicy(t *testing.T) {
	if _, err := exec.LookPath("7z"); err != nil {
		t.Skip("7z not installed")
	}
	dlp.SetArchiveTools("", 2)
	enc, err := os.ReadFile("../dlp/testdata/rrn-enc.7z")
	if err != nil {
		t.Fatal(err)
	}
	// Default (encrypted -> hold via setup's action set below).
	e := setup(t, func(o *Options) { o.Actions.Encrypted = config.ActionHold })
	if err := e.send("kim@example.com", []string{"partner@ext.org"}, withAttachment("secret.7z", enc)); err != nil {
		t.Fatalf("held mail should be accepted: %v", err)
	}
	if e.next.count() != 0 {
		t.Fatal("encrypted attachment must be held, not relayed")
	}
	holds, _ := e.store.ListHolds(context.Background(), model.HoldHeld, 10)
	if len(holds) != 1 {
		t.Fatalf("expected one hold, got %d", len(holds))
	}
	e.box.waitFor(t, "kim@example.com", "암호가 걸린 첨부파일")

	// Block policy: sender is refused at SMTP time.
	e2 := setup(t, func(o *Options) { o.Actions.Encrypted = config.ActionBlock })
	err = e2.send("kim@example.com", []string{"partner@ext.org"}, withAttachment("secret.7z", enc))
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 550 || !strings.Contains(se.Message, "encrypted") {
		t.Fatalf("want 550 with encrypted, got %v", err)
	}
}
