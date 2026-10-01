package queue

import (
	"context"
	"testing"
	"time"

	"github.com/yiyuhki/p2/internal/model"
)

// A job enqueued while an in-process consumer is running is delivered to it.
func TestMemoryConsumeJobs(t *testing.T) {
	q := NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan string, 1)
	go q.ConsumeJobs(ctx, func(_ context.Context, j model.Job) error {
		got <- j.AttachmentID
		return nil
	})
	// Give the consumer a moment to start waiting on the channel.
	time.Sleep(10 * time.Millisecond)

	if err := q.Enqueue(ctx, model.Job{AttachmentID: "job-1"}, PriorityHigh); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	select {
	case id := <-got:
		if id != "job-1" {
			t.Fatalf("got %q, want job-1", id)
		}
	case <-time.After(time.Second):
		t.Fatal("job was not delivered to the consumer")
	}
}

// Enqueue never blocks when no consumer is running, and the job is still
// recorded for Snapshot (dev convenience).
func TestMemoryEnqueueWithoutConsumer(t *testing.T) {
	q := NewMemory()
	for i := 0; i < 5; i++ {
		if err := q.Enqueue(context.Background(), model.Job{AttachmentID: "x"}, PriorityNormal); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}
	if n := len(q.Snapshot()); n != 5 {
		t.Fatalf("Snapshot has %d jobs, want 5", n)
	}
}
