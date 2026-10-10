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
	sort.Slice(out, func(i, j int) bool { return beforeKey(out[i].CreatedAt, out[i].ID, out[j].CreatedAt, out[j].ID) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// beforeKey orders by (time DESC, id DESC): row (ai,aid) sorts before (bi,bid).
func beforeKey(at time.Time, aid string, bt time.Time, bid string) bool {
	if at.Equal(bt) {
		return aid > bid
	}
	return at.After(bt)
}

// afterCursor reports whether (t,id) is strictly older than the cursor under
// the (time DESC, id DESC) ordering, i.e. it belongs on a later page.
func afterCursor(t time.Time, id string, page Page) bool {
	if !page.Set() {
		return true
	}
	if t.Equal(page.Before) {
		return id < page.BeforeID
	}
	return t.Before(page.Before)
}

func (s *Memory) ListHolds(_ context.Context, st model.HoldStatus, limit int, page Page) ([]*model.Hold, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.holdList(limit, func(h *model.Hold) bool {
		return (st == "" || h.Status == st) && afterCursor(h.CreatedAt, h.ID, page)
	}), nil
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

func (s *Memory) PruneAuditEvents(_ context.Context, cutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	de := s.dlpEvents[:0]
	for _, e := range s.dlpEvents {
		if e.At.Before(cutoff) {
			n++
		} else {
			de = append(de, e)
		}
	}
	s.dlpEvents = de
	dl := s.Downloads[:0]
	for _, e := range s.Downloads {
		if e.At.Before(cutoff) {
			n++
		} else {
			dl = append(dl, e)
		}
	}
	s.Downloads = dl
	return n, nil
}

func (s *Memory) ListDLPEvents(_ context.Context, f EventFilter, limit int, page Page) ([]*model.DLPEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []*model.DLPEvent
	for _, e := range s.dlpEvents {
		if (f.Action == "" || e.Action == f.Action) && (f.Severity == "" || e.Severity == f.Severity) &&
			afterCursor(e.At, e.ID, page) {
			c := *e
			all = append(all, &c)
		}
	}
	sort.Slice(all, func(i, j int) bool { return beforeKey(all[i].At, all[i].ID, all[j].At, all[j].ID) })
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
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
