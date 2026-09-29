// Package queue publishes analysis jobs to, and consumes verdicts from, the
// external analysis engine.
//
// Redis layout (prefix defaults to "secmail"):
//
//	<prefix>:jobs:high     LIST  new mail attachments (LPUSH / consumer BRPOP)
//	<prefix>:jobs:normal   LIST  retries / rescans
//	<prefix>:results       LIST  verdicts pushed by the analyzer (LPUSH)
//	<prefix>:results:dead  LIST  undecodable verdict payloads
//
// A consumer that runs `BRPOP <prefix>:jobs:high <prefix>:jobs:normal 0`
// automatically drains high priority first.
package queue

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/yiyuhki/p2/internal/model"
)

type Priority int

const (
	PriorityHigh Priority = iota
	PriorityNormal
)

// ResultHandler applies a verdict. Returning an error only logs; the verdict
// is not re-delivered (the stale-job sweep will re-queue if needed).
type ResultHandler func(ctx context.Context, v model.Verdict) error

type Queue interface {
	Enqueue(ctx context.Context, job model.Job, p Priority) error
	// ConsumeResults blocks until ctx is cancelled.
	ConsumeResults(ctx context.Context, h ResultHandler) error
}

// ---- Redis ----

type Redis struct {
	rdb    *redis.Client
	prefix string
	log    *slog.Logger
}

func NewRedis(rdb *redis.Client, prefix string, log *slog.Logger) *Redis {
	if prefix == "" {
		prefix = "secmail"
	}
	return &Redis{rdb: rdb, prefix: prefix, log: log}
}

func (q *Redis) JobsKey(p Priority) string {
	if p == PriorityHigh {
		return q.prefix + ":jobs:high"
	}
	return q.prefix + ":jobs:normal"
}

func (q *Redis) ResultsKey() string { return q.prefix + ":results" }

func (q *Redis) Enqueue(ctx context.Context, job model.Job, p Priority) error {
	b, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return q.rdb.LPush(ctx, q.JobsKey(p), b).Err()
}

func (q *Redis) ConsumeResults(ctx context.Context, h ResultHandler) error {
	key := q.ResultsKey()
	for {
		res, err := q.rdb.BRPop(ctx, 5*time.Second, key).Result()
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, redis.Nil) {
			continue
		}
		if err != nil {
			q.log.Error("results: brpop failed", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
			}
			continue
		}
		payload := res[1]
		var v model.Verdict
		if err := json.Unmarshal([]byte(payload), &v); err != nil || v.AttachmentID == "" {
			q.log.Warn("results: undecodable verdict, moved to dead list", "err", err)
			q.rdb.LPush(ctx, key+":dead", payload)
			continue
		}
		if err := h(ctx, v); err != nil {
			q.log.Warn("results: apply verdict failed", "attachment", v.AttachmentID, "err", err)
		}
	}
}

// ---- Memory (dev / tests) ----

type Memory struct {
	mu      sync.Mutex
	Jobs    []model.Job
	results chan model.Verdict
}

func NewMemory() *Memory { return &Memory{results: make(chan model.Verdict, 64)} }

func (q *Memory) Enqueue(_ context.Context, job model.Job, _ Priority) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.Jobs = append(q.Jobs, job)
	return nil
}

func (q *Memory) Snapshot() []model.Job {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]model.Job(nil), q.Jobs...)
}

// PushResult simulates an analyzer reply.
func (q *Memory) PushResult(v model.Verdict) { q.results <- v }

func (q *Memory) ConsumeResults(ctx context.Context, h ResultHandler) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case v := <-q.results:
			_ = h(ctx, v)
		}
	}
}
