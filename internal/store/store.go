// Package store persists message and attachment metadata.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/yiyuhki/p2/internal/model"
)

var (
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when a verdict targets an attachment that is no
	// longer PENDING (duplicate or late analyzer result).
	ErrConflict = errors.New("store: state conflict")
)

type Store interface {
	// CreateMessage atomically inserts a message and its attachments.
	CreateMessage(ctx context.Context, m *model.Message, atts []*model.Attachment) error
	Ping(ctx context.Context) error
	GetMessage(ctx context.Context, id string) (*model.Message, error)
	GetAttachment(ctx context.Context, id string) (*model.Attachment, error)
	GetAttachmentByTokenHash(ctx context.Context, tokenHash string) (*model.Attachment, error)
	// SetVerdict moves a PENDING attachment to a final status.
	SetVerdict(ctx context.Context, id string, status model.Status, threat string, detail json.RawMessage, at time.Time) error
	// FindReusableVerdict returns the most recent final verdict for sha256
	// analyzed after since (CLEAN or MALICIOUS only).
	FindReusableVerdict(ctx context.Context, sha256 string, since time.Time) (*model.Attachment, error)
	// MarkRequeued increments Attempts and resets QueuedAt.
	MarkRequeued(ctx context.Context, id string, at time.Time) error
	// RecordDownload increments the counter and appends an audit event.
	RecordDownload(ctx context.Context, ev model.DownloadEvent) error
	// ListStalePending returns PENDING attachments queued before olderThan.
	ListStalePending(ctx context.Context, olderThan time.Time, limit int) ([]*model.Attachment, error)
	// ListExpired returns non-EXPIRED attachments whose ExpiresAt < now.
	ListExpired(ctx context.Context, now time.Time, limit int) ([]*model.Attachment, error)
	MarkExpired(ctx context.Context, id string, at time.Time) error

	// Outbound DLP.
	CreateHold(ctx context.Context, h *model.Hold) error
	GetHold(ctx context.Context, id string) (*model.Hold, error)
	GetHoldByTokenHash(ctx context.Context, tokenHash string) (*model.Hold, error)
	ListHolds(ctx context.Context, status model.HoldStatus, limit int, page Page) ([]*model.Hold, error)
	// DecideHold moves a HELD hold to status; ErrConflict if already decided.
	DecideHold(ctx context.Context, id string, status model.HoldStatus, by, reason string, at time.Time) error
	// ReopenHold returns a RELEASED hold to HELD (used when relaying failed
	// after the hold was claimed).
	ReopenHold(ctx context.Context, id string) error
	// ListExpiredHolds returns HELD holds whose ExpiresAt < now.
	ListExpiredHolds(ctx context.Context, now time.Time, limit int) ([]*model.Hold, error)
	RecordDLPEvent(ctx context.Context, ev *model.DLPEvent) error
	ListDLPEvents(ctx context.Context, filter EventFilter, limit int, page Page) ([]*model.DLPEvent, error)
	Close()
}

// EventFilter narrows a DLP event listing. Empty fields match anything.
type EventFilter struct {
	Action   string // allow | notify | hold | block | exempt
	Severity string // high | medium | low | uninspectable | encrypted
}

// Page is a keyset pagination cursor for the admin list endpoints. Rows are
// ordered (time DESC, id DESC); a set cursor returns only rows strictly before
// this position. The zero value starts from the newest row.
type Page struct {
	Before   time.Time
	BeforeID string
}

// Set reports whether the cursor points past the first page.
func (p Page) Set() bool { return !p.Before.IsZero() }
