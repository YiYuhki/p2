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
	"time"

	"github.com/google/uuid"

	"github.com/yiyuhki/p2/internal/metrics"
	"github.com/yiyuhki/p2/internal/mimeproc"
	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/queue"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
	"github.com/yiyuhki/p2/internal/token"
)

type Options struct {
	PublicBaseURL      string        // e.g. https://sec-mail.example.com
	InternalBaseURL    string        // e.g. http://secmail-internal:8081 (optional)
	LinkTTL            time.Duration // download link lifetime
	AnalysisTimeout    time.Duration
	MaxAttempts        int
	VerdictReuseWindow time.Duration
}

type Service struct {
	store   store.Store
	storage storage.Storage
	queue   queue.Queue
	opts    Options
	log     *slog.Logger
	now     func() time.Time
}

func New(st store.Store, obj storage.Storage, q queue.Queue, opts Options, log *slog.Logger) *Service {
	return &Service{store: st, storage: obj, queue: q, opts: opts, log: log, now: time.Now}
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

		if s.opts.VerdictReuseWindow > 0 {
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

// ApplyVerdict records an analyzer result. Duplicate results for an already
// decided attachment return store.ErrConflict.
func (s *Service) ApplyVerdict(ctx context.Context, v model.Verdict) error {
	if _, err := uuid.Parse(v.AttachmentID); err != nil {
		return fmt.Errorf("%w: bad attachment_id", ErrInvalidVerdict)
	}
	if !v.Status.Final() {
		return fmt.Errorf("%w: status must be CLEAN, MALICIOUS or ERROR", ErrInvalidVerdict)
	}
	if len(v.Detail) > 0 && !json.Valid(v.Detail) {
		return fmt.Errorf("%w: detail is not valid JSON", ErrInvalidVerdict)
	}
	if len(v.ThreatName) > 256 {
		v.ThreatName = v.ThreatName[:256]
	}
	err := s.store.SetVerdict(ctx, v.AttachmentID, v.Status, v.ThreatName, v.Detail, s.now().UTC())
	if err == nil {
		metrics.Verdicts.WithLabelValues(strings.ToLower(string(v.Status))).Inc()
		s.log.Info("verdict applied", "attachment", v.AttachmentID, "status", v.Status, "threat", v.ThreatName)
	}
	return err
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
}
