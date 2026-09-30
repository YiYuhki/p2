// Package gateway implements the inbound SMTP proxy.
//
// Transactions are proxied in lock-step ("before-queue" filtering): MAIL and
// RCPT are forwarded to the upstream mail server immediately, so its
// per-recipient answers reach the sender, and the rewritten message is
// relayed during DATA. The sender only receives 250 once the upstream server
// has accepted the rewritten message, so the gateway needs no local spool.
package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/yiyuhki/p2/internal/smtpclient"
)

// UpstreamOptions configures the connection to the real mail server.
type UpstreamOptions = smtpclient.Options

type BackendOptions struct {
	AcceptedDomains []string
	Upstream        UpstreamOptions
}

type Backend struct {
	proc *Processor
	opts BackendOptions
	log  *slog.Logger
}

func NewBackend(proc *Processor, opts BackendOptions, log *slog.Logger) *Backend {
	return &Backend{proc: proc, opts: opts, log: log}
}

func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	s := &session{b: b, conn: c}
	if c != nil && c.Conn() != nil {
		s.remote = c.Conn().RemoteAddr().String()
	}
	return s, nil
}

type session struct {
	b      *Backend
	conn   *smtp.Conn
	remote string

	up   *smtp.Client
	from string
	rcpt []string
}

var (
	errRelayDenied = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1},
		Message: "Relaying denied"}
	errUpstreamUnavailable = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 1},
		Message: "Upstream mail server unavailable, please retry"}
	errNoMail = &smtp.SMTPError{Code: 503, EnhancedCode: smtp.EnhancedCode{5, 5, 1},
		Message: "Need MAIL command"}
)

func (s *session) dialUpstream() (*smtp.Client, error) {
	o := s.b.opts.Upstream
	if o.HeloName == "" {
		o.HeloName = s.b.proc.opts.Hostname
	}
	return smtpclient.Dial(o)
}

func (s *session) Mail(from string, opts *smtp.MailOptions) error {
	s.resetState()
	if s.up == nil {
		up, err := s.dialUpstream()
		if err != nil {
			s.b.log.Error("upstream dial failed", "addr", s.b.opts.Upstream.Addr, "err", err)
			return errUpstreamUnavailable
		}
		s.up = up
	}
	var upOpts *smtp.MailOptions
	if opts != nil {
		upOpts = &smtp.MailOptions{Body: opts.Body, UTF8: opts.UTF8}
		if upOpts.Body == smtp.BodyBinaryMIME {
			upOpts.Body = smtp.Body8BitMIME // we never emit BINARYMIME
		}
	}
	if err := s.up.Mail(from, upOpts); err != nil {
		return s.upstreamErr(err)
	}
	s.from = from
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.up == nil {
		return errNoMail
	}
	if !s.accepted(to) {
		return errRelayDenied
	}
	if err := s.up.Rcpt(to, nil); err != nil {
		return s.upstreamErr(err)
	}
	s.rcpt = append(s.rcpt, to)
	return nil
}

func (s *session) accepted(addr string) bool {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 {
		return false
	}
	domain := strings.ToLower(addr[at+1:])
	for _, d := range s.b.opts.AcceptedDomains {
		if domain == d || (strings.HasPrefix(d, ".") && strings.HasSuffix(domain, d)) {
			return true
		}
	}
	return false
}

func (s *session) Data(r io.Reader) error {
	if s.up == nil || len(s.rcpt) == 0 {
		return &smtp.SMTPError{Code: 503, EnhancedCode: smtp.EnhancedCode{5, 5, 1}, Message: "Need RCPT command"}
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		// Size limit exceeded or connection dropped. The upstream
		// transaction must be aborted.
		s.abortUpstream()
		return err
	}
	env := Envelope{MailFrom: s.from, RcptTo: append([]string(nil), s.rcpt...), RemoteAddr: s.remote}
	if s.conn != nil {
		env.Helo = s.conn.Hostname()
		_, env.TLS = s.conn.TLSConnectionState()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := s.b.proc.Process(ctx, env, raw)
	if err != nil {
		s.abortUpstream()
		return err
	}

	w, err := s.up.Data()
	if err != nil {
		return s.upstreamErr(err)
	}
	if _, err := io.Copy(w, bytes.NewReader(out)); err != nil {
		w.Close()
		return s.upstreamErr(err)
	}
	if err := w.Close(); err != nil {
		return s.upstreamErr(err)
	}
	s.b.log.Info("relayed", "from", s.from, "rcpt", s.rcpt, "in_bytes", len(raw), "out_bytes", len(out))
	s.resetState()
	return nil
}

// upstreamErr forwards upstream SMTP replies verbatim and maps transport
// errors to a temporary failure. On transport errors the connection is
// dropped so the next transaction redials.
func (s *session) upstreamErr(err error) error {
	var se *smtp.SMTPError
	if errors.As(err, &se) {
		return se
	}
	s.b.log.Warn("upstream error", "err", err)
	s.closeUpstream()
	return errUpstreamUnavailable
}

func (s *session) abortUpstream() {
	if s.up == nil {
		return
	}
	if err := s.up.Reset(); err != nil {
		s.closeUpstream()
	}
}

func (s *session) resetState() {
	s.from = ""
	s.rcpt = nil
}

func (s *session) Reset() {
	if s.from != "" || len(s.rcpt) > 0 {
		s.abortUpstream()
	}
	s.resetState()
}

func (s *session) closeUpstream() {
	if s.up != nil {
		s.up.Close()
		s.up = nil
	}
}

func (s *session) Logout() error {
	if s.up != nil {
		s.up.Quit()
		s.up = nil
	}
	return nil
}

func newQueueID() string {
	var b [8]byte
	rand.Read(b[:])
	return strings.ToUpper(hex.EncodeToString(b[:]))
}
