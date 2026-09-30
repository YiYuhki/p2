package store

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/yiyuhki/p2/internal/model"
)

// Memory is an in-process Store for development and tests.
type Memory struct {
	mu       sync.Mutex
	messages map[string]*model.Message
	atts     map[string]*model.Attachment
	byToken  map[string]string
	// Downloads is the audit log (exported for tests).
	Downloads []model.DownloadEvent
	holds     map[string]*model.Hold
	dlpEvents []*model.DLPEvent
}

func NewMemory() *Memory {
	return &Memory{
		messages: map[string]*model.Message{},
		atts:     map[string]*model.Attachment{},
		byToken:  map[string]string{},
	}
}

func clone(a *model.Attachment) *model.Attachment {
	c := *a
	return &c
}

func (s *Memory) CreateMessage(_ context.Context, m *model.Message, atts []*model.Attachment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	mc := *m
	s.messages[m.ID] = &mc
	for _, a := range atts {
		s.atts[a.ID] = clone(a)
		s.byToken[a.TokenHash] = a.ID
	}
	return nil
}

func (s *Memory) GetMessage(_ context.Context, id string) (*model.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.messages[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *m
	c.RcptTo = append([]string(nil), m.RcptTo...)
	return &c, nil
}

func (s *Memory) GetAttachment(_ context.Context, id string) (*model.Attachment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.atts[id]
	if !ok {
		return nil, ErrNotFound
	}
	return clone(a), nil
}

func (s *Memory) GetAttachmentByTokenHash(ctx context.Context, h string) (*model.Attachment, error) {
	s.mu.Lock()
	id, ok := s.byToken[h]
	s.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	return s.GetAttachment(ctx, id)
}

func (s *Memory) SetVerdict(_ context.Context, id string, st model.Status, threat string, detail json.RawMessage, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.atts[id]
	if !ok {
		return ErrNotFound
	}
	if a.Status != model.StatusPending {
		return ErrConflict
	}
	a.Status, a.ThreatName, a.VerdictDetail = st, threat, detail
	a.AnalyzedAt, a.UpdatedAt = &at, at
	return nil
}

func (s *Memory) FindReusableVerdict(_ context.Context, sha string, since time.Time) (*model.Attachment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best *model.Attachment
	for _, a := range s.atts {
		if a.SHA256 != sha || a.AnalyzedAt == nil || a.AnalyzedAt.Before(since) {
			continue
		}
		if a.Status != model.StatusClean && a.Status != model.StatusMalicious {
			continue
		}
		if best == nil || a.AnalyzedAt.After(*best.AnalyzedAt) {
			best = a
		}
	}
	if best == nil {
		return nil, ErrNotFound
	}
	return clone(best), nil
}

func (s *Memory) MarkRequeued(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.atts[id]
	if !ok {
		return ErrNotFound
	}
	a.Attempts++
	a.QueuedAt, a.UpdatedAt = at, at
	return nil
}

func (s *Memory) RecordDownload(_ context.Context, ev model.DownloadEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.atts[ev.AttachmentID]
	if !ok {
		return ErrNotFound
	}
	a.DownloadCount++
	at := ev.At
	a.LastDownloadedAt = &at
	s.Downloads = append(s.Downloads, ev)
	return nil
}

func (s *Memory) list(limit int, keep func(*model.Attachment) bool) []*model.Attachment {
	var out []*model.Attachment
	for _, a := range s.atts {
		if keep(a) {
			out = append(out, clone(a))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *Memory) ListStalePending(_ context.Context, olderThan time.Time, limit int) ([]*model.Attachment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.list(limit, func(a *model.Attachment) bool {
		return a.Status == model.StatusPending && a.QueuedAt.Before(olderThan)
	}), nil
}

func (s *Memory) ListExpired(_ context.Context, now time.Time, limit int) ([]*model.Attachment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.list(limit, func(a *model.Attachment) bool {
		return a.Status != model.StatusExpired && a.ExpiresAt.Before(now)
	}), nil
}

func (s *Memory) MarkExpired(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.atts[id]
	if !ok {
		return ErrNotFound
	}
	a.Status, a.UpdatedAt = model.StatusExpired, at
	return nil
}

func (s *Memory) Close() {}
