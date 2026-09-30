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
	"net/netip"
	"strings"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/yiyuhki/p2/internal/metrics"
	"github.com/yiyuhki/p2/internal/smtpclient"
)

// UpstreamOptions configures the connection to the real mail server.
type UpstreamOptions = smtpclient.Options

// MessageProcessor transforms (inbound) or inspects (outbound) a message
// before it is relayed. Returning ErrHeld accepts the message without
// relaying it; returning an *smtp.SMTPError sends that reply to the client.
type MessageProcessor interface {
	Process(ctx context.Context, env Envelope, raw []byte) ([]byte, error)
}

// ErrHeld means the processor kept the message (e.g. DLP hold): the client
// gets 250 but nothing is relayed now.
var ErrHeld = errors.New("message held")

type BackendOptions struct {
	// RecipientDomains restricts RCPT TO (inbound: our domains). Empty = any.
	RecipientDomains []string
	// SenderDomains restricts MAIL FROM (outbound: our domains). Empty = any.
	SenderDomains []string
	// AllowedClients restricts connecting IPs (outbound: internal servers).
	AllowedClients []netip.Prefix
	Upstream       UpstreamOptions
	// Name labels log lines ("inbound" / "outbound").
	Name string
}

type Backend struct {
	proc MessageProcessor
	opts BackendOptions
	log  *slog.Logger
}

func NewBackend(proc MessageProcessor, opts BackendOptions, log *slog.Logger) *Backend {
	if opts.Name == "" {
		opts.Name = "inbound"
	}
	return &Backend{proc: proc, opts: opts, log: log.With("direction", opts.Name)}
}

var errClientDenied = &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 7, 1},
	Message: "Access denied"}

func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	s := &session{b: b, conn: c}
	if c != nil && c.Conn() != nil {
		s.remote = c.Conn().RemoteAddr().String()
	}
	if len(b.opts.AllowedClients) > 0 && !b.clientAllowed(s.remote) {
		b.log.Warn("connection from unauthorised client refused", "remote", s.remote)
		return nil, errClientDenied
	}
	return s, nil
}

func (b *Backend) clientAllowed(remote string) bool {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	for _, p := range b.opts.AllowedClients {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ParsePrefixes accepts CIDRs or single IPs.
func ParsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, v := range list {
		if !strings.Contains(v, "/") {
			a, err := netip.ParseAddr(v)
			if err != nil {
				return nil, err
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
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
	return smtpclient.Dial(s.b.opts.Upstream)
}

var errSenderDenied = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1},
	Message: "Sender domain not allowed"}

func (s *session) Mail(from string, opts *smtp.MailOptions) error {
	s.resetState()
	// Null sender (bounces) is allowed; otherwise enforce SenderDomains.
	if from != "" && len(s.b.opts.SenderDomains) > 0 && !domainIn(from, s.b.opts.SenderDomains) {
		return errSenderDenied
	}
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
	if len(s.b.opts.RecipientDomains) > 0 && !domainIn(to, s.b.opts.RecipientDomains) {
		return errRelayDenied
	}
	if err := s.up.Rcpt(to, nil); err != nil {
		return s.upstreamErr(err)
	}
	s.rcpt = append(s.rcpt, to)
	return nil
}

func domainIn(addr string, domains []string) bool {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 {
		return false
	}
	domain := strings.ToLower(addr[at+1:])
	for _, d := range domains {
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
	if errors.Is(err, ErrHeld) {
		s.abortUpstream()
		s.b.log.Info("message held, not relayed", "from", s.from, "rcpt", s.rcpt)
		s.resetState()
		return nil
	}
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
	if s.b.opts.Name == "inbound" {
		metrics.InboundMessages.WithLabelValues("relayed").Inc()
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
