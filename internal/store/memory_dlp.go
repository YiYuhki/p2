package store

import (
	"context"
	"sort"
	"time"

	"github.com/yiyuhki/p2/internal/model"
)

func cloneHold(h *model.Hold) *model.Hold {
	c := *h
	c.RcptTo = append([]string(nil), h.RcptTo...)
	return &c
}

func (s *Memory) CreateHold(_ context.Context, h *model.Hold) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.holds == nil {
		s.holds = map[string]*model.Hold{}
	}
	s.holds[h.ID] = cloneHold(h)
	return nil
}

func (s *Memory) GetHold(_ context.Context, id string) (*model.Hold, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.holds[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneHold(h), nil
}

func (s *Memory) GetHoldByTokenHash(_ context.Context, th string) (*model.Hold, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.holds {
		if h.TokenHash == th {
			return cloneHold(h), nil
		}
	}
	return nil, ErrNotFound
}

func (s *Memory) holdList(limit int, keep func(*model.Hold) bool) []*model.Hold {
	var out []*model.Hold
	for _, h := range s.holds {
		if keep(h) {
			out = append(out, cloneHold(h))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *Memory) ListHolds(_ context.Context, st model.HoldStatus, limit int) ([]*model.Hold, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.holdList(limit, func(h *model.Hold) bool { return st == "" || h.Status == st }), nil
}

func (s *Memory) DecideHold(_ context.Context, id string, st model.HoldStatus, by, reason string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.holds[id]
	if !ok {
		return ErrNotFound
	}
	if h.Status != model.HoldHeld {
		return ErrConflict
	}
	h.Status, h.DecidedBy, h.Reason, h.DecidedAt = st, by, reason, &at
	return nil
}

func (s *Memory) ListExpiredHolds(_ context.Context, now time.Time, limit int) ([]*model.Hold, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.holdList(limit, func(h *model.Hold) bool { return h.Status == model.HoldHeld && h.ExpiresAt.Before(now) }), nil
}

func (s *Memory) RecordDLPEvent(_ context.Context, ev *model.DLPEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *ev
	s.dlpEvents = append(s.dlpEvents, &c)
	return nil
}

func (s *Memory) ListDLPEvents(_ context.Context, limit int) ([]*model.DLPEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*model.DLPEvent
	for i := len(s.dlpEvents) - 1; i >= 0 && len(out) < limit; i-- {
		c := *s.dlpEvents[i]
		out = append(out, &c)
	}
	return out, nil
}

func (s *Memory) ReopenHold(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.holds[id]
	if !ok {
		return ErrNotFound
	}
	if h.Status != model.HoldReleased {
		return ErrConflict
	}
	h.Status, h.DecidedBy, h.Reason, h.DecidedAt = model.HoldHeld, "", "", nil
	return nil
}
