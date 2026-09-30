// Package outbound applies the DLP policy to mail leaving the organisation:
// it scans each message, records an audit event and then allows, notifies,
// holds (for administrator review) or blocks it.
package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/google/uuid"

	"github.com/yiyuhki/p2/internal/config"
	"github.com/yiyuhki/p2/internal/dlp"
	"github.com/yiyuhki/p2/internal/gateway"
	"github.com/yiyuhki/p2/internal/metrics"
	"github.com/yiyuhki/p2/internal/mimeproc"
	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/notify"
	"github.com/yiyuhki/p2/internal/smtpclient"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
	"github.com/yiyuhki/p2/internal/token"
)

type Options struct {
	Actions                config.DLPActions
	NotifySender           bool
	Admins                 []string
	NotifyFrom             string
	HoldTTL                time.Duration
	PublicBaseURL          string   // for review links
	OwnDomains             []string // only senders in these domains get notices
	ExemptSenders          []string
	ExemptRecipientDomains []string
	ScanInternal           bool
	NextHop                smtpclient.Options // relay target when a hold is released
	Location               *time.Location
}

// Relayer delivers a released message (smtpclient.Send in production).
type Relayer func(from string, to []string, msg []byte) error

type Service struct {
	scanner  *dlp.Scanner
	store    store.Store
	storage  storage.Storage
	notifier notify.Sender
	relay    Relayer
	opts     Options
	log      *slog.Logger
	now      func() time.Time
}

func New(sc *dlp.Scanner, st store.Store, obj storage.Storage, n notify.Sender, opts Options, log *slog.Logger) *Service {
	if opts.Location == nil {
		opts.Location = time.Local
	}
	s := &Service{scanner: sc, store: st, storage: obj, notifier: n, opts: opts,
		log: log.With("component", "dlp"), now: time.Now}
	s.relay = func(from string, to []string, msg []byte) error {
		return smtpclient.Send(opts.NextHop, from, to, msg)
	}
	return s
}

var actionRank = map[string]int{config.ActionAllow: 0, config.ActionNotify: 1, config.ActionHold: 2, config.ActionBlock: 3}

func stricter(a, b string) string {
	if actionRank[b] > actionRank[a] {
		return b
	}
	return a
}

// Decide maps a report to the configured action.
func (s *Service) Decide(rep *dlp.Report) string {
	act := config.ActionAllow
	for _, f := range rep.Findings {
		switch f.Sev() {
		case dlp.SeverityHigh:
			act = stricter(act, s.opts.Actions.High)
		case dlp.SeverityMedium:
			act = stricter(act, s.opts.Actions.Medium)
		case dlp.SeverityLow:
			act = stricter(act, s.opts.Actions.Low)
		}
	}
	if len(rep.Uninspectable) > 0 {
		act = stricter(act, s.opts.Actions.Uninspectable)
	}
	if rep.HasEncrypted() {
		enc := s.opts.Actions.Encrypted
		if enc == "" {
			enc = s.opts.Actions.Uninspectable
		}
		act = stricter(act, enc)
	}
	return act
}

func addrIn(addr string, list []string) bool {
	addr = strings.ToLower(addr)
	for _, a := range list {
		if strings.ToLower(a) == addr {
			return true
		}
	}
	return false
}

func domainOf(addr string) string {
	return strings.ToLower(addr[strings.LastIndexByte(addr, '@')+1:])
}

func domainMatch(addr string, domains []string) bool {
	d := domainOf(addr)
	for _, x := range domains {
		x = strings.ToLower(x)
		if d == x || (strings.HasPrefix(x, ".") && strings.HasSuffix(d, x)) {
			return true
		}
	}
	return false
}

var errBlocked = func(rep *dlp.Report) error {
	seen := map[string]bool{}
	var ids []string
	for _, f := range rep.Findings {
		if !seen[f.Detector] {
			seen[f.Detector] = true
			ids = append(ids, f.Detector)
		}
	}
	if len(rep.Uninspectable) > 0 {
		ids = append(ids, "uninspectable")
	}
	if rep.HasEncrypted() {
		ids = append(ids, "encrypted")
	}
	return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1},
		Message: "Message blocked by data loss prevention policy (" + strings.Join(ids, ", ") + ")"}
}

var errTemp = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0},
	Message: "Temporary failure in content inspection, please retry"}

// Process implements gateway.MessageProcessor for the outbound listener.
func (s *Service) Process(ctx context.Context, env gateway.Envelope, raw []byte) ([]byte, error) {
	if addrIn(env.MailFrom, s.opts.ExemptSenders) {
		return raw, nil
	}
	if !s.opts.ScanInternal && len(env.RcptTo) > 0 {
		internal := true
		for _, r := range env.RcptTo {
			internal = internal && domainMatch(r, s.opts.OwnDomains)
		}
		if internal {
			return raw, nil
		}
	}
	scanStart := s.now()
	rep := s.scanner.ScanMessage(ctx, raw)
	metrics.DLPScanSeconds.Observe(s.now().Sub(scanStart).Seconds())
	if len(rep.Findings) == 0 && len(rep.Uninspectable) == 0 && !rep.HasEncrypted() {
		metrics.OutboundMessages.WithLabelValues("allow").Inc()
		return raw, nil
	}
	for _, f := range rep.Findings {
		if f.Detector == "pii_combination" {
			continue // derived escalation, not newly matched values
		}
		metrics.DLPFindings.WithLabelValues(f.Sev().String()).Add(float64(f.Count))
	}
	action := s.Decide(rep)
	exempt := len(s.opts.ExemptRecipientDomains) > 0
	for _, r := range env.RcptTo {
		exempt = exempt && domainMatch(r, s.opts.ExemptRecipientDomains)
	}
	if exempt {
		action = config.ActionAllow
		metrics.OutboundMessages.WithLabelValues("exempt").Inc()
	} else {
		metrics.OutboundMessages.WithLabelValues(action).Inc()
	}

	subject := subjectOf(raw)
	findings, _ := json.Marshal(rep)
	ev := &model.DLPEvent{ID: uuid.NewString(), MailFrom: env.MailFrom, RcptTo: env.RcptTo, Subject: subject,
		Action: action, Severity: rep.MaxSeverity().String(), Findings: findings, At: s.now().UTC()}
	log := s.log.With("from", env.MailFrom, "rcpt", env.RcptTo, "action", action, "findings", rep.Summary())

	var hold *model.Hold
	var reviewURL string
	if action == config.ActionHold {
		var err error
		hold, reviewURL, err = s.createHold(ctx, env, subject, raw, findings)
		if err != nil {
			log.Error("create hold failed", "err", err)
			return nil, errTemp
		}
		ev.HoldID = hold.ID
	}
	if err := s.store.RecordDLPEvent(ctx, ev); err != nil {
		// Audit only; the decision itself does not depend on it.
		log.Error("record dlp event", "err", err)
	}
	log.Info("outbound message inspected", "severity", ev.Severity, "exempt_recipients", exempt)

	if action != config.ActionAllow {
		n := notice{env: env, subject: subject, rep: rep, action: action, reviewURL: reviewURL}
		if hold != nil {
			n.holdExpires = hold.ExpiresAt
		}
		go s.sendNotices(context.WithoutCancel(ctx), n)
	}
	switch action {
	case config.ActionHold:
		return nil, gateway.ErrHeld
	case config.ActionBlock:
		return nil, errBlocked(rep)
	}
	return raw, nil
}

func subjectOf(raw []byte) string {
	if root, err := mimeproc.Parse(raw); err == nil {
		return mimeproc.DecodeHeader(root.Header.Get("Subject"))
	}
	return ""
}

func (s *Service) createHold(ctx context.Context, env gateway.Envelope, subject string, raw, findings []byte) (*model.Hold, string, error) {
	now := s.now().UTC()
	tok := token.New()
	h := &model.Hold{
		ID: uuid.NewString(), TokenHash: token.Hash(tok), MailFrom: env.MailFrom, RcptTo: env.RcptTo,
		Subject: subject, Size: int64(len(raw)), Findings: findings, Status: model.HoldHeld,
		CreatedAt: now, ExpiresAt: now.Add(s.opts.HoldTTL),
	}
	h.StorageKey = fmt.Sprintf("holds/%s/%s.eml", now.Format("2006/01/02"), h.ID)
	if err := s.storage.Put(ctx, h.StorageKey, bytes.NewReader(raw), h.Size); err != nil {
		return nil, "", err
	}
	if err := s.store.CreateHold(ctx, h); err != nil {
		s.storage.Delete(context.WithoutCancel(ctx), h.StorageKey)
		return nil, "", err
	}
	metrics.Holds.WithLabelValues("created").Inc()
	return h, s.opts.PublicBaseURL + "/dlp/" + tok, nil
}

// ErrNotHeld is returned when a hold was already decided (wraps store.ErrConflict).
var ErrNotHeld = fmt.Errorf("hold is no longer pending: %w", store.ErrConflict)

// Release relays a held message to the next hop.
func (s *Service) Release(ctx context.Context, id, by string) error {
	h, err := s.store.GetHold(ctx, id)
	if err != nil {
		return err
	}
	if h.Status != model.HoldHeld {
		return ErrNotHeld
	}
	// Claim first so that concurrent approvals cannot send twice.
	if err := s.store.DecideHold(ctx, id, model.HoldReleased, by, "", s.now().UTC()); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return ErrNotHeld
		}
		return err
	}
	raw, err := s.load(ctx, h)
	if err == nil {
		err = s.relay(h.MailFrom, h.RcptTo, raw)
	}
	if err != nil {
		if rerr := s.store.ReopenHold(ctx, id); rerr != nil {
			s.log.Error("reopen hold after failed release", "hold", id, "err", rerr)
		}
		return fmt.Errorf("relay held message: %w", err)
	}
	s.storage.Delete(ctx, h.StorageKey) // keep only masked findings after delivery
	metrics.Holds.WithLabelValues("released").Inc()
	s.log.Info("hold released", "hold", id, "by", by)
	go s.sendDecisionNotice(context.WithoutCancel(ctx), h, model.HoldReleased, by, "")
	return nil
}

// Reject discards a held message.
func (s *Service) Reject(ctx context.Context, id, by, reason string) error {
	return s.finish(ctx, id, model.HoldRejected, by, reason)
}

func (s *Service) finish(ctx context.Context, id string, st model.HoldStatus, by, reason string) error {
	h, err := s.store.GetHold(ctx, id)
	if err != nil {
		return err
	}
	if err := s.store.DecideHold(ctx, id, st, by, reason, s.now().UTC()); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return ErrNotHeld
		}
		return err
	}
	s.storage.Delete(ctx, h.StorageKey)
	metrics.Holds.WithLabelValues(strings.ToLower(string(st))).Inc()
	s.log.Info("hold closed", "hold", id, "status", st, "by", by)
	go s.sendDecisionNotice(context.WithoutCancel(ctx), h, st, by, reason)
	return nil
}

func (s *Service) load(ctx context.Context, h *model.Hold) ([]byte, error) {
	r, err := s.storage.Get(ctx, h.StorageKey)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var b bytes.Buffer
	_, err = b.ReadFrom(r)
	return b.Bytes(), err
}

// Janitor expires undecided holds (not sent: fail closed).
func (s *Service) Janitor(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.SweepOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) SweepOnce(ctx context.Context) {
	hs, err := s.store.ListExpiredHolds(ctx, s.now().UTC(), 200)
	if err != nil {
		s.log.Error("list expired holds", "err", err)
		return
	}
	for _, h := range hs {
		if err := s.finish(ctx, h.ID, model.HoldExpired, "system", "검토 기한 만료"); err != nil && !errors.Is(err, ErrNotHeld) {
			s.log.Error("expire hold", "hold", h.ID, "err", err)
		}
	}
}
