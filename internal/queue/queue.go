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

// ResultHandler applies a verdict. A nil error consumes the verdict; a
// PermanentError dead-letters it; any other error is treated as transient and
// the consumer retries a few times before falling back to the stale-job sweep.
type ResultHandler func(ctx context.Context, v model.Verdict) error

// JobHandler analyzes one job. It is used by an in-process analyzer; the
// standalone external worker consumes the Redis job queues on its own. A job
// whose handler returns an error (or is never delivered) is left for the
// stale-job sweep to re-enqueue, so a transient failure is not a lost job.
type JobHandler func(ctx context.Context, job model.Job) error

// PermanentError marks a verdict that must not be retried (malformed payload,
// unknown attachment, or a duplicate for an already-decided attachment).
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return "permanent: " + e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent wraps err so the results consumer dead-letters it instead of
// retrying.
func Permanent(err error) error { return &PermanentError{Err: err} }

type Queue interface {
	Enqueue(ctx context.Context, job model.Job, p Priority) error
	// ConsumeJobs blocks until ctx is cancelled, invoking h for each job
	// (high priority first). It lets secmail analyze attachments in-process;
	// the external worker consumes the Redis job lists directly instead.
	ConsumeJobs(ctx context.Context, h JobHandler) error
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

func (q *Redis) ConsumeJobs(ctx context.Context, h JobHandler) error {
	high, normal := q.JobsKey(PriorityHigh), q.JobsKey(PriorityNormal)
	for {
		// BRPOP drains high before normal, so waiting users are served first.
		res, err := q.rdb.BRPop(ctx, 5*time.Second, high, normal).Result()
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, redis.Nil) {
			continue
		}
		if err != nil {
			q.log.Error("jobs: brpop failed", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
			}
			continue
		}
		var job model.Job
		if err := json.Unmarshal([]byte(res[1]), &job); err != nil {
			q.log.Warn("jobs: undecodable job, dropped", "err", err)
			continue
		}
		if err := h(ctx, job); err != nil {
			// The attachment stays PENDING; the stale-job sweep re-enqueues it.
			q.log.Warn("jobs: handler failed; stale-job sweep will re-queue",
				"attachment", job.AttachmentID, "err", err)
		}
	}
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
		q.deliver(ctx, h, v, payload, key)
	}
}

// deliver applies one verdict, dead-lettering permanent failures.
func (q *Redis) deliver(ctx context.Context, h ResultHandler, v model.Verdict, payload, key string) {
	deliverWithRetry(ctx, h, v, q.log, func() { q.rdb.LPush(ctx, key+":dead", payload) })
}

// maxDeliverTries bounds transient retries of a consumed verdict.
const maxDeliverTries = 4

// retryBackoff is the delay before the next transient retry; a package variable
// so tests can shrink it. Exponential, capped at 4s (1s, 2s, 4s, ...).
var retryBackoff = func(attempt int) time.Duration {
	d := time.Second << (attempt - 1)
	if d > 4*time.Second {
		d = 4 * time.Second
	}
	return d
}

// deliverWithRetry applies a verdict, retrying transient failures with backoff
// so a brief database/storage blip does not discard a finished verdict (which
// would otherwise force a full re-analysis via the stale-job sweep). Permanent
// failures invoke deadLetter; if transient failures persist past
// maxDeliverTries the verdict is dropped and the stale-job sweep re-queues the
// job.
func deliverWithRetry(ctx context.Context, h ResultHandler, v model.Verdict, log *slog.Logger, deadLetter func()) {
	for attempt := 1; ; attempt++ {
		err := h(ctx, v)
		if err == nil {
			return
		}
		var perm *PermanentError
		if errors.As(err, &perm) {
			log.Warn("results: permanent verdict error, dead-lettering",
				"attachment", v.AttachmentID, "err", perm.Err)
			deadLetter()
			return
		}
		if attempt >= maxDeliverTries {
			log.Error("results: apply verdict failed after retries; stale-job sweep will re-queue",
				"attachment", v.AttachmentID, "attempts", attempt, "err", err)
			return
		}
		log.Warn("results: apply verdict failed, retrying",
			"attachment", v.AttachmentID, "attempt", attempt, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryBackoff(attempt)):
		}
	}
}

// ---- Memory (dev / tests) ----

type Memory struct {
	mu      sync.Mutex
	Jobs    []model.Job
	jobs    chan model.Job
	results chan model.Verdict
}

func NewMemory() *Memory {
	return &Memory{jobs: make(chan model.Job, 1024), results: make(chan model.Verdict, 64)}
}

func (q *Memory) Enqueue(_ context.Context, job model.Job, _ Priority) error {
	q.mu.Lock()
	q.Jobs = append(q.Jobs, job)
	q.mu.Unlock()
	// Deliver to an in-process consumer if one is running; never block the
	// enqueuer when none is (the job is still recorded in Jobs/Snapshot).
	select {
	case q.jobs <- job:
	default:
	}
	return nil
}

// ConsumeJobs delivers enqueued jobs to h in FIFO order (priority is not
// distinguished in the dev/in-memory queue).
func (q *Memory) ConsumeJobs(ctx context.Context, h JobHandler) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case job := <-q.jobs:
			_ = h(ctx, job)
		}
	}
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
