package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-smtp"

	"github.com/yiyuhki/p2/internal/dkimutil"
	"github.com/yiyuhki/p2/internal/mimeproc"
	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/queue"
	"github.com/yiyuhki/p2/internal/service"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
)

// ---- fake upstream MTA ----

type delivered struct {
	from string
	to   []string
	data []byte
}

type upstream struct {
	mu   sync.Mutex
	msgs []delivered
}

type upSession struct {
	u    *upstream
	from string
	to   []string
}

func (u *upstream) NewSession(*smtp.Conn) (smtp.Session, error) { return &upSession{u: u}, nil }
func (s *upSession) Reset()                                     { s.from, s.to = "", nil }
func (s *upSession) Logout() error                              { return nil }
func (s *upSession) Mail(f string, _ *smtp.MailOptions) error   { s.from = f; return nil }
func (s *upSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	if strings.HasPrefix(to, "nouser@") {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "No such user"}
	}
	s.to = append(s.to, to)
	return nil
}
func (s *upSession) Data(r io.Reader) error {
	b, _ := io.ReadAll(r)
	s.u.mu.Lock()
	s.u.msgs = append(s.u.msgs, delivered{s.from, s.to, b})
	s.u.mu.Unlock()
	return nil
}

func (u *upstream) last(t *testing.T) delivered {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.msgs) == 0 {
		t.Fatal("upstream received nothing")
	}
	return u.msgs[len(u.msgs)-1]
}

func serve(t *testing.T, be smtp.Backend) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(be)
	srv.Domain = "localhost"
	srv.AllowInsecureAuth = true
	srv.MaxMessageBytes = 10 << 20
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return l.Addr().String()
}

// ---- harness ----

type harness struct {
	addr  string
	up    *upstream
	store *store.Memory
	queue *queue.Memory
	pub   *rsa.PublicKey
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	log := slog.New(slog.NewTextHandler(testWriter{t}, nil))
	up := &upstream{}
	upAddr := serve(t, up)

	st := store.NewMemory()
	obj, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	q := queue.NewMemory()
	svc := service.New(st, obj, q, service.Options{
		PublicBaseURL: "https://sec-mail.example.com", LinkTTL: 14 * 24 * time.Hour,
		AnalysisTimeout: time.Minute, MaxAttempts: 3,
	}, log)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	proc := NewProcessor(svc, ProcessorOptions{
		Hostname: "gw.example.com", GatewayID: "test-gw", LinkTTL: 14 * 24 * time.Hour,
		Rewrite: mimeproc.Options{KeepInlineImages: true}, StripOrigDKIM: true,
		Signer: dkimutil.NewSigner("example.com", "sel", key),
	}, log)
	be := NewBackend(proc, BackendOptions{
		RecipientDomains: []string{"example.com"},
		Upstream:         UpstreamOptions{Addr: upAddr, Timeout: 5 * time.Second},
	}, log)
	return &harness{addr: serve(t, be), up: up, store: st, queue: q, pub: &key.PublicKey}
}

func (h *harness) send(from string, to []string, msg string) error {
	c, err := smtp.Dial(h.addr)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.SendMail(from, to, strings.NewReader(strings.ReplaceAll(msg, "\n", "\r\n")))
}

const mailWithAttachment = `From: sender@ext.org
To: user@example.com
Subject: invoice
Message-ID: <abc@ext.org>
X-SecMail-Processed: spoofed
DKIM-Signature: v=1; a=rsa-sha256; d=ext.org; s=s; h=from; bh=x; b=y
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="B"

--B
Content-Type: text/plain; charset=utf-8

Please see the invoice.
--B
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcfsj6IK
--B--
`

func TestEndToEndAttachmentRewritten(t *testing.T) {
	h := newHarness(t)
	if err := h.send("sender@ext.org", []string{"user@example.com"}, mailWithAttachment); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := h.up.last(t)
	out := string(got.data)

	if got.from != "sender@ext.org" || len(got.to) != 1 || got.to[0] != "user@example.com" {
		t.Fatalf("envelope not preserved: %+v", got)
	}
	if strings.Contains(out, "JVBERi0xLjQKJcfsj6IK") {
		t.Fatal("attachment content leaked to upstream")
	}
	if !strings.Contains(out, "https://sec-mail.example.com/d/") {
		t.Fatal("download link missing")
	}
	if strings.Contains(out, "spoofed") {
		t.Fatal("sender-supplied X-SecMail header must be stripped")
	}
	parsed, err := mimeproc.Parse(got.data)
	if err != nil {
		t.Fatal(err)
	}
	if v := parsed.Header.Get("X-SecMail-Processed"); !strings.HasPrefix(v, "test-gw; attachments=1; id=") {
		t.Fatalf("processed header wrong: %q", v)
	}
	if !strings.Contains(parsed.Header.Get("X-SecMail-Original-DKIM-Signature"), "d=ext.org") {
		t.Fatal("original DKIM signature should be preserved under a new name")
	}
	if n := len(parsed.Header.Values("DKIM-Signature")); n != 1 {
		t.Fatalf("want only the gateway DKIM signature, got %d", n)
	}

	// Gateway DKIM signature must verify.
	pubDER, _ := x509.MarshalPKIXPublicKey(h.pub)
	vs, err := dkim.VerifyWithOptions(bytes.NewReader(got.data), &dkim.VerifyOptions{
		LookupTXT: func(d string) ([]string, error) {
			if d != "sel._domainkey.example.com" {
				return nil, errors.New("unexpected lookup " + d)
			}
			return []string{"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pubDER)}, nil
		},
	})
	if err != nil || len(vs) != 1 || vs[0].Err != nil {
		t.Fatalf("gateway DKIM signature invalid: %v %+v", err, vs)
	}

	jobs := h.queue.Snapshot()
	if len(jobs) != 1 || jobs[0].Filename != "invoice.pdf" {
		t.Fatalf("expected 1 analysis job, got %+v", jobs)
	}
	a, err := h.store.GetAttachment(context.Background(), jobs[0].AttachmentID)
	if err != nil || a.Status != model.StatusPending || a.Size != 15 {
		t.Fatalf("attachment record: %+v %v", a, err)
	}
}

func TestRelayDenied(t *testing.T) {
	h := newHarness(t)
	err := h.send("a@ext.org", []string{"victim@elsewhere.com"}, "Subject: x\n\nhi\n")
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 550 {
		t.Fatalf("want 550 relay denied, got %v", err)
	}
}

func TestUpstreamRecipientRejectionIsForwarded(t *testing.T) {
	h := newHarness(t)
	err := h.send("a@ext.org", []string{"nouser@example.com"}, "Subject: x\n\nhi\n")
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 550 || !strings.Contains(se.Message, "No such user") {
		t.Fatalf("want upstream 550 forwarded, got %v", err)
	}
}

func TestPlainMailPassesUnchangedBody(t *testing.T) {
	h := newHarness(t)
	msg := "From: a@ext.org\nTo: u@example.com\nSubject: hi\n\nJust text.\n"
	if err := h.send("a@ext.org", []string{"u@example.com"}, msg); err != nil {
		t.Fatal(err)
	}
	out := string(h.up.last(t).data)
	if !strings.Contains(out, "Just text.") || !strings.Contains(out, "attachments=0") ||
		strings.Contains(out, "Original-Dkim") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	if len(h.queue.Snapshot()) != 0 {
		t.Fatal("no jobs expected")
	}
}

func TestUnparsableMessageQuarantinedWhole(t *testing.T) {
	h := newHarness(t)
	// multipart without a closing/opening boundary that matches.
	msg := "From: a@ext.org\nTo: u@example.com\nSubject: broken\nContent-Type: multipart/mixed; boundary=\"NOPE\"\n\nno parts here\n"
	if err := h.send("a@ext.org", []string{"u@example.com"}, msg); err != nil {
		t.Fatal(err)
	}
	out := string(h.up.last(t).data)
	if !strings.Contains(out, "Subject: broken") || !strings.Contains(out, "/d/") {
		t.Fatalf("fallback message wrong:\n%s", out)
	}
	jobs := h.queue.Snapshot()
	if len(jobs) != 1 || jobs[0].Filename != "original-message.eml" {
		t.Fatalf("want whole message quarantined, got %+v", jobs)
	}
}

func TestBannerHTMLEscapesFilename(t *testing.T) {
	b := buildBanner([]service.Link{{Filename: `<script>x</script>.pdf`, Size: 2048, URL: "https://s/d/t"}},
		time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), "")
	if strings.Contains(b.HTML, "<script>") {
		t.Fatal("filename not escaped in HTML banner")
	}
	if !strings.Contains(b.Text, "2.0 KB") {
		t.Fatalf("size missing: %s", b.Text)
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}
