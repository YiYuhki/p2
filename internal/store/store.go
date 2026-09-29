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
	GetAttachment(ctx context.Context, id string) (*model.Attachment, error)
	GetAttachmentByTokenHash(ctx context.Context, tokenHash string) (*model.Attachment, error)
	// SetVerdict moves a PENDING attachment to a final status.
	SetVerdict(ctx context.Context, id string, status model.Status, threat string, detail json.RawMessage, at time.Time) error
	// FindReusableVerdict returns the most recent final verdict for sha256
	// analyzed after since (CLEAN or MALICIOUS only).
	FindReusableVerdict(ctx context.Context, sha256 string, since time.Time) (*model.Attachment, error)
	// MarkRequeued increments Attempts and resets QueuedAt.
	MarkRequeued(ctx context.Context, id string, at time.Time) error
	RecordDownload(ctx context.Context, id string, at time.Time) error
	// ListStalePending returns PENDING attachments queued before olderThan.
	ListStalePending(ctx context.Context, olderThan time.Time, limit int) ([]*model.Attachment, error)
	// ListExpired returns non-EXPIRED attachments whose ExpiresAt < now.
	ListExpired(ctx context.Context, now time.Time, limit int) ([]*model.Attachment, error)
	MarkExpired(ctx context.Context, id string, at time.Time) error
	Close()
}
