package gateway

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/emersion/go-message/textproto"
	"github.com/emersion/go-smtp"

	"github.com/yiyuhki/p2/internal/dkimutil"
	"github.com/yiyuhki/p2/internal/mimeproc"
	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/service"
	"github.com/yiyuhki/p2/internal/spfutil"
)

// Quarantiner is implemented by service.Service.
type Quarantiner interface {
	Quarantine(ctx context.Context, msg *model.Message, extracted []*mimeproc.Extracted) ([]service.Link, error)
}

type ProcessorOptions struct {
	Hostname      string
	GatewayID     string
	Rewrite       mimeproc.Options
	LinkTTL       time.Duration
	Location      *time.Location
	VerifyDKIM    bool
	VerifySPF     bool
	StripOrigDKIM bool
	Signer        *dkimutil.Signer // nil disables re-signing
	// LookupTXT overrides DNS for DKIM verification (tests).
	LookupTXT func(string) ([]string, error)
	// SPF is the SPF checker; nil disables SPF even when VerifySPF is set.
	SPF *spfutil.Checker
}

// Processor turns an inbound message into the message relayed upstream.
type Processor struct {
	q    Quarantiner
	opts ProcessorOptions
	log  *slog.Logger
	now  func() time.Time
}

func NewProcessor(q Quarantiner, opts ProcessorOptions, log *slog.Logger) *Processor {
	if opts.Location == nil {
		opts.Location = time.Local
	}
	return &Processor{q: q, opts: opts, log: log, now: time.Now}
}

// Envelope is the SMTP transaction metadata.
type Envelope struct {
	MailFrom   string
	RcptTo     []string
	RemoteAddr string
	Helo       string
	TLS        bool
}

var (
	errTempFail = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0},
		Message: "Temporary failure while securing attachments, please retry"}
	errEncrypted = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1},
		Message: "Encrypted messages are not accepted by policy"}
	errMalformed = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 6, 0},
		Message: "Malformed message"}
)

// Process returns the rewritten message or an *smtp.SMTPError.
func (p *Processor) Process(ctx context.Context, env Envelope, raw []byte) ([]byte, error) {
	queueID := newQueueID()
	log := p.log.With("queue_id", queueID, "from", env.MailFrom, "rcpt", env.RcptTo)

	authResults := p.authenticate(ctx, env, raw)

	root, err := mimeproc.Parse(raw)
	if err != nil {
		// Fail closed: anything we cannot parse is quarantined as a whole.
		log.Warn("unparsable MIME structure, quarantining entire message", "err", err)
		root, err = p.wholeMessageFallback(raw)
		if err != nil {
			return nil, errMalformed
		}
		return p.finish(ctx, log, env, queueID, root, []*mimeproc.Extracted{{
			Filename: "original-message.eml", ContentType: "message/rfc822", Data: raw,
		}}, "원본 메일의 구조를 해석할 수 없어 메일 전체를 첨부파일로 보관했습니다.", authResults, true)
	}

	stripGatewayHeaders(&root.Header)

	res, err := mimeproc.Extract(root, p.opts.Rewrite)
	if errors.Is(err, mimeproc.ErrEncrypted) {
		log.Info("rejected encrypted message by policy")
		return nil, errEncrypted
	}
	if err != nil {
		log.Error("extract failed", "err", err)
		return nil, errTempFail
	}
	if res.Skipped != "" {
		log.Info("message passed through without inspection", "reason", res.Skipped)
		root.Header.Add("X-SecMail-Notice", "not-inspected; reason="+res.Skipped)
	}
	notice := ""
	if res.SignatureRemoved {
		notice = "첨부파일 분리로 인해 원본 메일의 전자서명(S/MIME/PGP)이 제거되었습니다."
		root.Header.Add("X-SecMail-Notice", "signature-removed")
	}
	return p.finish(ctx, log, env, queueID, root, res.Attachments, notice, authResults, len(res.Attachments) > 0)
}

func (p *Processor) finish(ctx context.Context, log *slog.Logger, env Envelope, queueID string, root *mimeproc.Part,
	atts []*mimeproc.Extracted, notice, authResults string, modified bool) ([]byte, error) {

	// RFC 8601 §5: strip any inbound Authentication-Results that claim this
	// gateway's identity, so a sender cannot forge results downstream filters
	// would trust as ours. Done unconditionally, even when we do not verify.
	stripSpoofedAuthResults(&root.Header, p.opts.Hostname)

	msgID := ""
	if len(atts) > 0 {
		meta := &model.Message{
			MessageID:  strings.TrimSpace(root.Header.Get("Message-Id")),
			MailFrom:   env.MailFrom,
			RcptTo:     env.RcptTo,
			Subject:    mimeproc.DecodeHeader(root.Header.Get("Subject")),
			RemoteAddr: env.RemoteAddr,
		}
		links, err := p.q.Quarantine(ctx, meta, atts)
		if err != nil {
			log.Error("quarantine failed", "err", err)
			return nil, errTempFail
		}
		msgID = meta.ID
		expires := p.now().Add(p.opts.LinkTTL).In(p.opts.Location)
		mimeproc.InsertBanner(root, buildBanner(links, expires, notice))
		log.Info("attachments quarantined", "message", msgID, "count", len(links))
	}

	if modified && p.opts.StripOrigDKIM {
		renameHeader(&root.Header, "Dkim-Signature", "X-SecMail-Original-DKIM-Signature")
	}
	processed := fmt.Sprintf("%s; attachments=%d", p.opts.GatewayID, len(atts))
	if msgID != "" {
		processed += "; id=" + msgID
	}
	root.Header.Add("X-SecMail-Processed", processed)
	if authResults != "" {
		root.Header.Add("Authentication-Results", p.opts.Hostname+"; "+authResults)
	}
	root.Header.Add("Received", p.received(env, queueID))

	out, err := root.Bytes()
	if err != nil {
		log.Error("serialise failed", "err", err)
		return nil, errTempFail
	}
	if p.opts.Signer != nil {
		signed, err := p.opts.Signer.Sign(out)
		if err != nil {
			log.Error("dkim sign failed", "err", err)
			return nil, errTempFail
		}
		out = signed
	}
	return out, nil
}

// authenticate runs the enabled inbound checks against the original message and
// returns their combined RFC 8601 method list (e.g. "spf=pass smtp.mailfrom=…;
// dkim=pass header.d=…"), or "" when nothing is enabled.
func (p *Processor) authenticate(ctx context.Context, env Envelope, raw []byte) string {
	var methods []string
	if p.opts.VerifySPF && p.opts.SPF != nil {
		methods = append(methods, p.opts.SPF.Check(ctx, env.RemoteAddr, env.Helo, env.MailFrom))
	}
	if p.opts.VerifyDKIM {
		methods = append(methods, dkimutil.Verify(raw, p.opts.LookupTXT))
	}
	return strings.Join(methods, "; ")
}

func (p *Processor) received(env Envelope, queueID string) string {
	proto := "ESMTP"
	if env.TLS {
		proto = "ESMTPS"
	}
	helo := sanitizeHeaderValue(env.Helo)
	return fmt.Sprintf("from %s (%s) by %s (secmail) with %s id %s; %s",
		helo, sanitizeHeaderValue(env.RemoteAddr), p.opts.Hostname, proto, queueID,
		p.now().Format(time.RFC1123Z))
}

// wholeMessageFallback builds a fresh message that keeps the original
// top-level headers but carries no content except the banner.
func (p *Processor) wholeMessageFallback(raw []byte) (*mimeproc.Part, error) {
	h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil || h.Len() == 0 {
		return nil, fmt.Errorf("unreadable header: %v", err)
	}
	root := &mimeproc.Part{Header: h}
	fields := root.Header.Fields()
	for fields.Next() {
		if strings.HasPrefix(strings.ToLower(fields.Key()), "content-") {
			fields.Del()
		}
	}
	stripGatewayHeaders(&root.Header)
	root.Header.Set("Content-Type", "multipart/mixed; boundary="+mimeproc.NewBoundary())
	if !root.Header.Has("Mime-Version") {
		root.Header.Set("MIME-Version", "1.0")
	}
	return root, nil
}

// stripGatewayHeaders removes X-SecMail-* headers supplied by the sender so
// they cannot spoof a "processed" marker.
func stripGatewayHeaders(h *textproto.Header) {
	fields := h.Fields()
	for fields.Next() {
		if strings.HasPrefix(strings.ToLower(fields.Key()), "x-secmail-") {
			fields.Del()
		}
	}
}

// stripSpoofedAuthResults removes Authentication-Results header fields whose
// authserv-id matches this gateway (RFC 8601 §5). Fields authored by other
// (trusted upstream) authserv-ids are left in place.
func stripSpoofedAuthResults(h *textproto.Header, authservID string) {
	id := strings.ToLower(strings.TrimSpace(authservID))
	if id == "" {
		return
	}
	fields := h.Fields()
	for fields.Next() {
		if strings.EqualFold(fields.Key(), "Authentication-Results") && authResultsID(fields.Value()) == id {
			fields.Del()
		}
	}
}

// authResultsID returns the lower-cased authserv-id of an Authentication-Results
// value: the first token, before any version number or the first ';'.
func authResultsID(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexAny(v, " \t"); i >= 0 { // drop optional version token
		v = v[:i]
	}
	return strings.ToLower(strings.TrimSpace(v))
}

func renameHeader(h *textproto.Header, from, to string) {
	vals := h.Values(from)
	if len(vals) == 0 {
		return
	}
	h.Del(from)
	for _, v := range vals {
		h.Add(to, v)
	}
}

func sanitizeHeaderValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
