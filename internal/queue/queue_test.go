package queue

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/yiyuhki/p2/internal/model"
)

// TestRedisQueue runs when SECMAIL_TEST_REDIS (host:port) is set.
func TestRedisQueue(t *testing.T) {
	addr := os.Getenv("SECMAIL_TEST_REDIS")
	if addr == "" {
		t.Skip("SECMAIL_TEST_REDIS not set")
	}
	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	defer rdb.Close()
	prefix := "test-" + uuid.NewString()[:8]
	q := NewRedis(rdb, prefix, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rdb.Del(ctx, q.JobsKey(PriorityHigh), q.JobsKey(PriorityNormal), q.ResultsKey(), q.ResultsKey()+":dead")

	q.Enqueue(ctx, model.Job{AttachmentID: "normal-1"}, PriorityNormal)
	q.Enqueue(ctx, model.Job{AttachmentID: "high-1"}, PriorityHigh)
	q.Enqueue(ctx, model.Job{AttachmentID: "high-2"}, PriorityHigh)

	// An analyzer draining with BRPOP high normal must see high first, FIFO.
	var order []string
	for i := 0; i < 3; i++ {
		res, err := rdb.BRPop(ctx, time.Second, q.JobsKey(PriorityHigh), q.JobsKey(PriorityNormal)).Result()
		if err != nil {
			t.Fatal(err)
		}
		var j model.Job
		json.Unmarshal([]byte(res[1]), &j)
		order = append(order, j.AttachmentID)
	}
	if order[0] != "high-1" || order[1] != "high-2" || order[2] != "normal-1" {
		t.Fatalf("priority order wrong: %v", order)
	}

	// Results: valid verdict delivered, garbage goes to the dead list.
	rdb.LPush(ctx, q.ResultsKey(), `not json`)
	b, _ := json.Marshal(model.Verdict{AttachmentID: "a1", Status: model.StatusClean})
	rdb.LPush(ctx, q.ResultsKey(), b)

	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	got := make(chan model.Verdict, 1)
	go q.ConsumeResults(cctx, func(_ context.Context, v model.Verdict) error { got <- v; cancel(); return nil })
	select {
	case v := <-got:
		if v.AttachmentID != "a1" || v.Status != model.StatusClean {
			t.Fatalf("verdict %+v", v)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("verdict not consumed")
	}
	if n, _ := rdb.LLen(ctx, q.ResultsKey()+":dead").Result(); n != 1 {
		t.Fatalf("dead letter count %d", n)
	}
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestDeliverWithRetry(t *testing.T) {
	old := retryBackoff
	retryBackoff = func(int) time.Duration { return time.Millisecond }
	defer func() { retryBackoff = old }()

	v := model.Verdict{AttachmentID: "a1"}

	t.Run("success on first try", func(t *testing.T) {
		calls, dead := 0, 0
		deliverWithRetry(context.Background(),
			func(context.Context, model.Verdict) error { calls++; return nil },
			v, quietLog(), func() { dead++ })
		if calls != 1 || dead != 0 {
			t.Fatalf("calls=%d dead=%d, want 1/0", calls, dead)
		}
	})

	t.Run("permanent dead-letters without retry", func(t *testing.T) {
		calls, dead := 0, 0
		deliverWithRetry(context.Background(),
			func(context.Context, model.Verdict) error { calls++; return Permanent(errors.New("bad")) },
			v, quietLog(), func() { dead++ })
		if calls != 1 || dead != 1 {
			t.Fatalf("calls=%d dead=%d, want 1/1", calls, dead)
		}
	})

	t.Run("transient retried then dropped, never dead-lettered", func(t *testing.T) {
		calls, dead := 0, 0
		deliverWithRetry(context.Background(),
			func(context.Context, model.Verdict) error { calls++; return errors.New("db down") },
			v, quietLog(), func() { dead++ })
		if calls != maxDeliverTries || dead != 0 {
			t.Fatalf("calls=%d dead=%d, want %d/0", calls, dead, maxDeliverTries)
		}
	})

	t.Run("transient then success", func(t *testing.T) {
		calls, dead := 0, 0
		deliverWithRetry(context.Background(),
			func(context.Context, model.Verdict) error {
				calls++
				if calls < 2 {
					return errors.New("blip")
				}
				return nil
			}, v, quietLog(), func() { dead++ })
		if calls != 2 || dead != 0 {
			t.Fatalf("calls=%d dead=%d, want 2/0", calls, dead)
		}
	})

	t.Run("context cancel stops retries", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		deliverWithRetry(ctx,
			func(context.Context, model.Verdict) error { calls++; cancel(); return errors.New("x") },
			v, quietLog(), func() {})
		if calls != 1 {
			t.Fatalf("calls=%d, want 1 (cancel should stop)", calls)
		}
	})
}
