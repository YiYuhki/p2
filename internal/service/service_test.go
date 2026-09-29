package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/yiyuhki/p2/internal/mimeproc"
	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/queue"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newSvc(t *testing.T) (*Service, *store.Memory, *queue.Memory, *storage.FS, *clock) {
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	q := queue.NewMemory()
	s := New(st, obj, q, Options{
		PublicBaseURL: "https://p", InternalBaseURL: "http://i", LinkTTL: 24 * time.Hour,
		AnalysisTimeout: time.Minute, MaxAttempts: 2, VerdictReuseWindow: time.Hour,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s.now = c.now
	return s, st, q, obj, c
}

func quarantine(t *testing.T, s *Service, data string) Link {
	links, err := s.Quarantine(context.Background(), &model.Message{}, []*mimeproc.Extracted{
		{Filename: "a.bin", ContentType: "application/octet-stream", Data: []byte(data)},
	})
	if err != nil || len(links) != 1 {
		t.Fatal(err)
	}
	return links[0]
}

func TestQuarantineStoresAndQueues(t *testing.T) {
	s, st, q, obj, _ := newSvc(t)
	l := quarantine(t, s, "payload")
	a, err := st.GetAttachment(context.Background(), l.AttachmentID)
	if err != nil || a.Status != model.StatusPending {
		t.Fatal(err, a)
	}
	r, err := obj.Get(context.Background(), a.StorageKey)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if string(b) != "payload" {
		t.Fatalf("stored %q", b)
	}
	jobs := q.Snapshot()
	if len(jobs) != 1 || jobs[0].ContentURL != "http://i/internal/v1/attachments/"+a.ID+"/content" {
		t.Fatalf("job %+v", jobs)
	}
}

func TestApplyVerdictAndConflict(t *testing.T) {
	s, st, _, _, _ := newSvc(t)
	l := quarantine(t, s, "x")
	ctx := context.Background()
	if err := s.ApplyVerdict(ctx, model.Verdict{AttachmentID: l.AttachmentID, Status: model.StatusPending}); !errors.Is(err, ErrInvalidVerdict) {
		t.Fatalf("PENDING must be rejected: %v", err)
	}
	if err := s.ApplyVerdict(ctx, model.Verdict{AttachmentID: l.AttachmentID, Status: model.StatusMalicious, ThreatName: "T"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyVerdict(ctx, model.Verdict{AttachmentID: l.AttachmentID, Status: model.StatusClean}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second verdict must conflict: %v", err)
	}
	a, _ := st.GetAttachment(ctx, l.AttachmentID)
	if a.Status != model.StatusMalicious || a.ThreatName != "T" {
		t.Fatalf("%+v", a)
	}
}

func TestVerdictReuse(t *testing.T) {
	s, st, q, _, _ := newSvc(t)
	l := quarantine(t, s, "same")
	s.ApplyVerdict(context.Background(), model.Verdict{AttachmentID: l.AttachmentID, Status: model.StatusMalicious, ThreatName: "X"})
	l2 := quarantine(t, s, "same")
	if l2.Status != model.StatusMalicious {
		t.Fatalf("verdict not reused: %s", l2.Status)
	}
	a, _ := st.GetAttachment(context.Background(), l2.AttachmentID)
	if a.ThreatName != "X" || len(q.Snapshot()) != 1 {
		t.Fatal("reused verdict should not queue a new job")
	}
}

func TestJanitorRequeueThenError(t *testing.T) {
	s, st, q, _, c := newSvc(t)
	l := quarantine(t, s, "slow")
	ctx := context.Background()

	c.t = c.t.Add(2 * time.Minute)
	s.SweepOnce(ctx)
	if n := len(q.Snapshot()); n != 2 {
		t.Fatalf("want requeue, jobs=%d", n)
	}
	if q.Snapshot()[1].Attempt != 2 {
		t.Fatalf("attempt not incremented: %+v", q.Snapshot()[1])
	}

	c.t = c.t.Add(2 * time.Minute)
	s.SweepOnce(ctx)
	a, _ := st.GetAttachment(ctx, l.AttachmentID)
	if a.Status != model.StatusError {
		t.Fatalf("want ERROR after max attempts, got %s", a.Status)
	}
}

func TestJanitorExpiry(t *testing.T) {
	s, st, _, obj, c := newSvc(t)
	l := quarantine(t, s, "old")
	ctx := context.Background()
	s.ApplyVerdict(ctx, model.Verdict{AttachmentID: l.AttachmentID, Status: model.StatusClean})
	c.t = c.t.Add(25 * time.Hour)
	s.SweepOnce(ctx)
	a, _ := st.GetAttachment(ctx, l.AttachmentID)
	if a.Status != model.StatusExpired {
		t.Fatalf("want EXPIRED, got %s", a.Status)
	}
	if _, err := obj.Get(ctx, a.StorageKey); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("object should be deleted")
	}
}
