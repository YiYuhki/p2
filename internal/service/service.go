// Package service contains the attachment lifecycle: quarantine on ingest,
// verdict application and the background janitor.
package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/yiyuhki/p2/internal/metrics"
	"github.com/yiyuhki/p2/internal/mimeproc"
	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/notify"
	"github.com/yiyuhki/p2/internal/queue"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
	"github.com/yiyuhki/p2/internal/token"
	"github.com/yiyuhki/p2/internal/webhook"
)

type Options struct {
	PublicBaseURL      string        // e.g. https://sec-mail.example.com
	InternalBaseURL    string        // e.g. http://secmail-internal:8081 (optional)
	LinkTTL            time.Duration // download link lifetime
	AnalysisTimeout    time.Duration
	MaxAttempts        int
	VerdictReuseWindow time.Duration
	// AuditRetention, when > 0, makes the janitor delete dlp_events and
	// download_events older than this. 0 keeps the audit log forever.
	AuditRetention time.Duration
	// BlockedExtensions are file extensions (without dot) that are refused up
	// front: the attachment is marked blocked without waiting for the analyzer,
	// so the portal never releases it. Matched on the final extension, so
	// "invoice.pdf.exe" is caught.
	BlockedExtensions []string
	// Webhook, when set, receives a JSON event when a verdict is MALICIOUS.
	Webhook *webhook.Notifier
	// NotifyRecipients emails the message recipients when an attachment verdict
	// completes (CLEAN or MALICIOUS). Needs Notifier and NotifyFrom.
	NotifyRecipients bool
	Notifier         notify.Sender
	NotifyFrom       string
}

type Service struct {
	store      store.Store
	storage    storage.Storage
	queue      queue.Queue
	opts       Options
	blockedExt atomic.Pointer[map[string]bool] // hot-swappable
	log        *slog.Logger
	now        func() time.Time
}

func New(st store.Store, obj storage.Storage, q queue.Queue, opts Options, log *slog.Logger) *Service {
	s := &Service{store: st, storage: obj, queue: q, opts: opts, log: log, now: time.Now}
	s.SetBlockedExtensions(opts.BlockedExtensions)
	return s
}

// SetBlockedExtensions hot-swaps the blocked file-extension set (SIGHUP reload).
func (s *Service) SetBlockedExtensions(exts []string) {
	m := map[string]bool{}
	for _, e := range exts {
		if e = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(e), ".")); e != "" {
			m[e] = true
		}
	}
	s.blockedExt.Store(&m)
}

// fileExt returns the lower-cased extension of name without the dot ("" if none).
// Trailing dots and whitespace are stripped first so a name like "evil.exe."
// (which Windows and many mail clients save/execute as "evil.exe") is classified
// by its real final extension and cannot slip past the blocked-extension gate.
func fileExt(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimRight(name, ". ")
	if i := strings.LastIndexByte(name, '.'); i >= 0 && i < len(name)-1 {
		return name[i+1:]
	}
	return ""
}

// Link is the per-attachment information rendered into the mail banner.
type Link struct {
	AttachmentID string
	Filename     string
	Size         int64
	URL          string
	Status       model.Status
}

// Quarantine stores the extracted attachments, records them and queues them
// for analysis. It returns one Link per attachment, in order.
//
// Storage or database failures are returned so that the SMTP layer answers
// with a temporary error and the sender retries; a queue failure is only
// logged because the janitor re-queues PENDING items after AnalysisTimeout.
func (s *Service) Quarantine(ctx context.Context, msg *model.Message, extracted []*mimeproc.Extracted) ([]Link, error) {
	now := s.now().UTC()
	msg.ID = uuid.NewString()
	msg.ReceivedAt = now
	msg.AttachmentCount = len(extracted)

	atts := make([]*model.Attachment, 0, len(extracted))
	links := make([]Link, 0, len(extracted))
	blocked := map[string]bool{}
	var stored []string
	cleanup := func() {
		for _, k := range stored {
			if err := s.storage.Delete(context.WithoutCancel(ctx), k); err != nil {
				s.log.Warn("cleanup: delete object", "key", k, "err", err)
			}
		}
	}

	for _, e := range extracted {
		sum := sha256.Sum256(e.Data)
		a := &model.Attachment{
			ID:          uuid.NewString(),
			MessageID:   msg.ID,
			Filename:    e.Filename,
			ContentType: e.ContentType,
			Size:        int64(len(e.Data)),
			SHA256:      hex.EncodeToString(sum[:]),
			Status:      model.StatusPending,
			Attempts:    1,
			CreatedAt:   now,
			UpdatedAt:   now,
			QueuedAt:    now,
			ExpiresAt:   now.Add(s.opts.LinkTTL),
		}
		a.StorageKey = fmt.Sprintf("attachments/%s/%s", now.Format("2006/01/02"), a.ID)
		tok := token.New()
		a.TokenHash = token.Hash(tok)

		if ext := fileExt(e.Filename); ext != "" && (*s.blockedExt.Load())[ext] {
			// Refused by file-type policy: block without analysis.
			a.Status, a.ThreatName, a.AnalyzedAt = model.StatusMalicious, "차단된 파일 형식 (."+ext+")", &now
			a.VerdictDetail = json.RawMessage(`{"reason":"blocked_extension","ext":"` + ext + `"}`)
			blocked[a.ID] = true
		} else if s.opts.VerdictReuseWindow > 0 {
			prev, err := s.store.FindReusableVerdict(ctx, a.SHA256, now.Add(-s.opts.VerdictReuseWindow))
			if err == nil {
				a.Status, a.ThreatName, a.AnalyzedAt = prev.Status, prev.ThreatName, &now
				a.VerdictDetail = reusedDetail(prev)
			} else if !errors.Is(err, store.ErrNotFound) {
				s.log.Warn("verdict reuse lookup failed", "err", err)
			}
		}

		if err := s.storage.Put(ctx, a.StorageKey, bytes.NewReader(e.Data), a.Size); err != nil {
			cleanup()
			return nil, fmt.Errorf("store attachment: %w", err)
		}
		stored = append(stored, a.StorageKey)
		atts = append(atts, a)
		links = append(links, Link{
			AttachmentID: a.ID,
			Filename:     a.Filename,
			Size:         a.Size,
			URL:          s.opts.PublicBaseURL + "/d/" + tok,
			Status:       a.Status,
		})
	}

	if err := s.store.CreateMessage(ctx, msg, atts); err != nil {
		cleanup()
		return nil, fmt.Errorf("record message: %w", err)
	}

	for _, a := range atts {
		if blocked[a.ID] {
			metrics.Attachments.WithLabelValues("blocked").Inc()
			s.log.Info("attachment blocked by file-type policy", "attachment", a.ID, "filename", a.Filename, "threat", a.ThreatName)
			continue
		}
		if a.Status != model.StatusPending {
			metrics.Attachments.WithLabelValues("reused-" + strings.ToLower(string(a.Status))).Inc()
			s.log.Info("verdict reused", "attachment", a.ID, "sha256", a.SHA256, "status", a.Status)
			continue
		}
		metrics.Attachments.WithLabelValues("pending").Inc()
		if err := s.queue.Enqueue(ctx, s.job(a), queue.PriorityHigh); err != nil {
			s.log.Error("enqueue failed; janitor will retry", "attachment", a.ID, "err", err)
		}
	}
	return links, nil
}

func reusedDetail(prev *model.Attachment) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"reused_from": prev.ID,
		"original":    prev.VerdictDetail,
	})
	return b
}

func (s *Service) job(a *model.Attachment) model.Job {
	j := model.Job{
		Version:      1,
		AttachmentID: a.ID,
		MessageID:    a.MessageID,
		Filename:     a.Filename,
		ContentType:  a.ContentType,
		Size:         a.Size,
		SHA256:       a.SHA256,
		Storage:      model.JobObject{Type: s.storage.Type(), Bucket: s.storage.Bucket(), Key: a.StorageKey},
		Attempt:      a.Attempts,
		EnqueuedAt:   s.now().UTC(),
	}
	if base := s.opts.InternalBaseURL; base != "" {
		j.ContentURL = base + "/internal/v1/attachments/" + a.ID + "/content"
		j.VerdictURL = base + "/internal/v1/attachments/" + a.ID + "/verdict"
	}
	return j
}

var ErrInvalidVerdict = errors.New("invalid verdict")

// maxDetailBytes bounds the analyzer-supplied detail blob so a buggy or hostile
// analyzer cannot bloat the database with one verdict.
const maxDetailBytes = 64 << 10

// ApplyVerdict records an analyzer result. Duplicate results for an already
// decided attachment return store.ErrConflict.
func (s *Service) ApplyVerdict(ctx context.Context, v model.Verdict) error {
	if _, err := uuid.Parse(v.AttachmentID); err != nil {
		return fmt.Errorf("%w: bad attachment_id", ErrInvalidVerdict)
	}
	if !v.Status.Final() {
		return fmt.Errorf("%w: status must be CLEAN, MALICIOUS or ERROR", ErrInvalidVerdict)
	}
	if len(v.Detail) > maxDetailBytes {
		return fmt.Errorf("%w: detail exceeds %d bytes", ErrInvalidVerdict, maxDetailBytes)
	}
	if len(v.Detail) > 0 && !json.Valid(v.Detail) {
		return fmt.Errorf("%w: detail is not valid JSON", ErrInvalidVerdict)
	}
	v.ThreatName = sanitizeThreatName(v.ThreatName)
	err := s.store.SetVerdict(ctx, v.AttachmentID, v.Status, v.ThreatName, v.Detail, s.now().UTC())
	if err == nil {
		metrics.Verdicts.WithLabelValues(strings.ToLower(string(v.Status))).Inc()
		s.log.Info("verdict applied", "attachment", v.AttachmentID, "status", v.Status, "threat", v.ThreatName)
		s.afterVerdict(ctx, v)
	}
	return err
}

// afterVerdict fires the security webhook (MALICIOUS) and the recipient
// completion notice (CLEAN/MALICIOUS), both enriched with the message envelope
// from a single best-effort lookup. It only runs on the first (PENDING→final)
// transition, so recipients are never notified twice.
func (s *Service) afterVerdict(ctx context.Context, v model.Verdict) {
	notifyRcpt := s.opts.NotifyRecipients && s.opts.Notifier != nil &&
		(v.Status == model.StatusClean || v.Status == model.StatusMalicious)
	if s.opts.Webhook == nil && !notifyRcpt {
		return
	}
	var mailFrom, subject, filename string
	var rcpt []string
	if a, err := s.store.GetAttachment(ctx, v.AttachmentID); err == nil {
		filename = a.Filename
		if m, err := s.store.GetMessage(ctx, a.MessageID); err == nil {
			mailFrom, rcpt, subject = m.MailFrom, m.RcptTo, m.Subject
		}
	}
	if s.opts.Webhook != nil && v.Status == model.StatusMalicious {
		s.opts.Webhook.Send(webhook.Event{
			Type: "inbound_verdict", At: s.now().UTC(), Status: string(v.Status),
			Threat: v.ThreatName, Attachment: v.AttachmentID,
			MailFrom: mailFrom, RcptTo: rcpt, Subject: subject,
		})
	}
	if notifyRcpt && len(rcpt) > 0 {
		body := verdictBody(v.Status, filename, subject, v.ThreatName)
		msg := notify.Build(s.opts.NotifyFrom, "보안 메일 게이트웨이", rcpt, verdictSubject(v.Status), body, s.now())
		go func() {
			if err := s.opts.Notifier.Send(context.WithoutCancel(ctx), s.opts.NotifyFrom, rcpt, msg); err != nil {
				s.log.Warn("verdict notice send failed", "attachment", v.AttachmentID, "err", err)
			}
		}()
	}
}

func verdictSubject(st model.Status) string {
	if st == model.StatusMalicious {
		return "[보안] 첨부파일이 차단되었습니다"
	}
	return "[보안] 첨부파일 검사 완료"
}

func verdictBody(st model.Status, filename, subject, threat string) string {
	if st == model.StatusMalicious {
		return fmt.Sprintf("받으신 메일(%q)의 첨부파일 '%s'이(가) 보안 검사에서 위협(%s)으로 판정되어 차단되었습니다.\n"+
			"해당 파일은 내려받을 수 없습니다. 문의는 보안 담당자에게 연락하세요.", subject, filename, threat)
	}
	return fmt.Sprintf("받으신 메일(%q)의 첨부파일 '%s'이(가) 보안 검사를 통과했습니다.\n"+
		"원본 메일 본문의 다운로드 링크에서 파일을 받으실 수 있습니다.", subject, filename)
}

// sanitizeThreatName strips control characters (the name is surfaced in the
// download page and logs) and truncates to 256 bytes on a UTF-8 boundary so a
// multi-byte rune is never cut in half.
func sanitizeThreatName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 256 {
		s = s[:256]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// ResultHandler adapts ApplyVerdict for the queue consumer. It classifies
// permanent failures — a malformed payload, an unknown attachment, or a
// duplicate for an already-decided attachment — so the consumer dead-letters or
// drops them instead of re-delivering, while transient (database/storage)
// failures are returned for retry.
func (s *Service) ResultHandler() queue.ResultHandler {
	return func(ctx context.Context, v model.Verdict) error {
		err := s.ApplyVerdict(ctx, v)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, store.ErrConflict):
			// Idempotent duplicate: the attachment already has a final verdict.
			s.log.Info("verdict ignored (already decided)", "attachment", v.AttachmentID)
			return nil
		case errors.Is(err, ErrInvalidVerdict), errors.Is(err, store.ErrNotFound):
			return queue.Permanent(err)
		default:
			return err // transient — let the consumer retry
		}
	}
}

// Janitor re-queues stalled analyses and removes expired attachments.
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
	now := s.now().UTC()
	stale, err := s.store.ListStalePending(ctx, now.Add(-s.opts.AnalysisTimeout), 500)
	if err != nil {
		s.log.Error("janitor: list stale", "err", err)
	}
	for _, a := range stale {
		if a.Attempts >= s.opts.MaxAttempts {
			detail, _ := json.Marshal(map[string]any{"reason": "analysis timeout", "attempts": a.Attempts})
			err := s.store.SetVerdict(ctx, a.ID, model.StatusError, "", detail, now)
			if err != nil && !errors.Is(err, store.ErrConflict) {
				s.log.Error("janitor: mark error", "attachment", a.ID, "err", err)
			} else {
				s.log.Warn("janitor: analysis gave up", "attachment", a.ID, "attempts", a.Attempts)
			}
			continue
		}
		if err := s.store.MarkRequeued(ctx, a.ID, now); err != nil {
			s.log.Error("janitor: requeue", "attachment", a.ID, "err", err)
			continue
		}
		a.Attempts++
		if err := s.queue.Enqueue(ctx, s.job(a), queue.PriorityNormal); err != nil {
			s.log.Error("janitor: enqueue", "attachment", a.ID, "err", err)
		}
	}

	expired, err := s.store.ListExpired(ctx, now, 500)
	if err != nil {
		s.log.Error("janitor: list expired", "err", err)
	}
	for _, a := range expired {
		if err := s.storage.Delete(ctx, a.StorageKey); err != nil {
			s.log.Error("janitor: delete object", "attachment", a.ID, "err", err)
			continue
		}
		if err := s.store.MarkExpired(ctx, a.ID, now); err != nil {
			s.log.Error("janitor: mark expired", "attachment", a.ID, "err", err)
		}
	}

	if s.opts.AuditRetention > 0 {
		if n, err := s.store.PruneAuditEvents(ctx, now.Add(-s.opts.AuditRetention)); err != nil {
			s.log.Error("janitor: prune audit events", "err", err)
		} else if n > 0 {
			s.log.Info("janitor: pruned audit events", "rows", n, "older_than", s.opts.AuditRetention)
		}
	}
}
