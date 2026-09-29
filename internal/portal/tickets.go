package portal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Tickets are single-use, short-lived download authorisations. They are
// issued only by POST so that link scanners / mail preview bots that follow
// GET links cannot consume or trigger downloads.
type Tickets interface {
	Issue(ctx context.Context, attachmentID string, ttl time.Duration) (string, error)
	// Redeem consumes the ticket and returns the attachment it was issued for.
	Redeem(ctx context.Context, ticket string) (string, error)
}

var ErrTicketInvalid = errors.New("ticket invalid or already used")

func newTicket() string {
	var b [24]byte
	rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

type RedisTickets struct {
	rdb    *redis.Client
	prefix string
}

func NewRedisTickets(rdb *redis.Client, prefix string) *RedisTickets {
	return &RedisTickets{rdb: rdb, prefix: prefix + ":ticket:"}
}

func (t *RedisTickets) Issue(ctx context.Context, id string, ttl time.Duration) (string, error) {
	tk := newTicket()
	return tk, t.rdb.Set(ctx, t.prefix+tk, id, ttl).Err()
}

func (t *RedisTickets) Redeem(ctx context.Context, tk string) (string, error) {
	id, err := t.rdb.GetDel(ctx, t.prefix+tk).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrTicketInvalid
	}
	return id, err
}

type MemoryTickets struct {
	mu sync.Mutex
	m  map[string]memTicket
}

type memTicket struct {
	id  string
	exp time.Time
}

func NewMemoryTickets() *MemoryTickets { return &MemoryTickets{m: map[string]memTicket{}} }

func (t *MemoryTickets) Issue(_ context.Context, id string, ttl time.Duration) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for k, v := range t.m {
		if now.After(v.exp) {
			delete(t.m, k)
		}
	}
	tk := newTicket()
	t.m[tk] = memTicket{id: id, exp: now.Add(ttl)}
	return tk, nil
}

func (t *MemoryTickets) Redeem(_ context.Context, tk string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.m[tk]
	delete(t.m, tk)
	if !ok || time.Now().After(v.exp) {
		return "", ErrTicketInvalid
	}
	return v.id, nil
}
