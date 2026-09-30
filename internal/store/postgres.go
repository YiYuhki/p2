package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yiyuhki/p2/internal/model"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Postgres struct {
	pool *pgxpool.Pool
}

// PGOptions configures the connection pool and startup behaviour. Zero values
// keep pgx defaults, except ReadyTimeout (0 = ping once, no retry).
type PGOptions struct {
	DSN               string
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	// ReadyTimeout bounds how long Open retries the initial connection while
	// the database is still starting up. 0 means a single attempt.
	ReadyTimeout time.Duration
	Log          *slog.Logger
}

// NewPostgres opens a pool with default tuning (convenience for tests).
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	return Open(ctx, PGOptions{DSN: dsn})
}

// Open builds a tuned connection pool, waits (with backoff) for the database to
// accept connections, then applies migrations.
func Open(ctx context.Context, opts PGOptions) (*Postgres, error) {
	cfg, err := poolConfig(opts)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pingWithRetry(ctx, pool, opts.ReadyTimeout, opts.Log); err != nil {
		pool.Close()
		return nil, err
	}
	p := &Postgres{pool: pool}
	if err := p.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return p, nil
}

// poolConfig parses the DSN and overlays the non-zero tuning options.
func poolConfig(opts PGOptions) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse dsn: %w", err)
	}
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	if opts.MinConns > 0 {
		cfg.MinConns = opts.MinConns
	}
	if opts.MaxConnLifetime > 0 {
		cfg.MaxConnLifetime = opts.MaxConnLifetime
	}
	if opts.MaxConnIdleTime > 0 {
		cfg.MaxConnIdleTime = opts.MaxConnIdleTime
	}
	if opts.HealthCheckPeriod > 0 {
		cfg.HealthCheckPeriod = opts.HealthCheckPeriod
	}
	return cfg, nil
}

// pingWithRetry pings until success or the timeout elapses, backing off
// exponentially (1s→5s). A zero timeout pings once.
func pingWithRetry(ctx context.Context, pool *pgxpool.Pool, timeout time.Duration, log *slog.Logger) error {
	if timeout <= 0 {
		if err := pool.Ping(ctx); err != nil {
			return fmt.Errorf("postgres: ping: %w", err)
		}
		return nil
	}
	deadline := time.Now().Add(timeout)
	delay := time.Second
	for attempt := 1; ; attempt++ {
		err := pool.Ping(ctx)
		if err == nil {
			if attempt > 1 && log != nil {
				log.Info("postgres ready", "attempts", attempt)
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("postgres: not ready after %s: %w", timeout, err)
		}
		if log != nil {
			log.Warn("postgres not ready, retrying", "attempt", attempt, "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < 5*time.Second {
			delay *= 2
		}
	}
}

// migrate applies embedded migrations in lexical order, serialised across
// replicas with an advisory lock.
func (p *Postgres) migrate(ctx context.Context) error {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	const lockID = 0x5ec3a11
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockID); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, lockID)

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)`, name).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sqlText, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlText)); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(name) VALUES ($1)`, name); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (p *Postgres) Close() { p.pool.Close() }

func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

func (p *Postgres) CreateMessage(ctx context.Context, m *model.Message, atts []*model.Attachment) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO mail_messages
			(id, message_id, mail_from, rcpt_to, subject, remote_addr, received_at, attachment_count)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			m.ID, m.MessageID, m.MailFrom, m.RcptTo, m.Subject, m.RemoteAddr, m.ReceivedAt, m.AttachmentCount)
		if err != nil {
			return err
		}
		for _, a := range atts {
			_, err := tx.Exec(ctx, `INSERT INTO attachments
				(id, message_id, filename, content_type, size, sha256, storage_key, token_hash,
				 status, threat_name, verdict_detail, attempts, created_at, updated_at, queued_at,
				 analyzed_at, expires_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
				a.ID, a.MessageID, a.Filename, a.ContentType, a.Size, a.SHA256, a.StorageKey, a.TokenHash,
				string(a.Status), a.ThreatName, nullJSON(a.VerdictDetail), a.Attempts, a.CreatedAt, a.UpdatedAt,
				a.QueuedAt, a.AnalyzedAt, a.ExpiresAt)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func nullJSON(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return []byte(b)
}

const attachmentCols = `id, message_id, filename, content_type, size, sha256, storage_key, token_hash,
	status, threat_name, verdict_detail, attempts, created_at, updated_at, queued_at, analyzed_at,
	expires_at, download_count, last_downloaded_at`

func scanAttachment(row pgx.Row) (*model.Attachment, error) {
	var a model.Attachment
	var status string
	var detail []byte
	err := row.Scan(&a.ID, &a.MessageID, &a.Filename, &a.ContentType, &a.Size, &a.SHA256, &a.StorageKey,
		&a.TokenHash, &status, &a.ThreatName, &detail, &a.Attempts, &a.CreatedAt, &a.UpdatedAt,
		&a.QueuedAt, &a.AnalyzedAt, &a.ExpiresAt, &a.DownloadCount, &a.LastDownloadedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.Status = model.Status(status)
	if len(detail) > 0 {
		a.VerdictDetail = detail
	}
	return &a, nil
}

func (p *Postgres) queryAttachments(ctx context.Context, sql string, args ...any) ([]*model.Attachment, error) {
	rows, err := p.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Attachment
	for rows.Next() {
		a, err := scanAttachment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *Postgres) GetAttachment(ctx context.Context, id string) (*model.Attachment, error) {
	return scanAttachment(p.pool.QueryRow(ctx, `SELECT `+attachmentCols+` FROM attachments WHERE id=$1`, id))
}

func (p *Postgres) GetAttachmentByTokenHash(ctx context.Context, h string) (*model.Attachment, error) {
	return scanAttachment(p.pool.QueryRow(ctx, `SELECT `+attachmentCols+` FROM attachments WHERE token_hash=$1`, h))
}

func (p *Postgres) SetVerdict(ctx context.Context, id string, st model.Status, threat string, detail json.RawMessage, at time.Time) error {
	tag, err := p.pool.Exec(ctx, `UPDATE attachments
		SET status=$2, threat_name=$3, verdict_detail=$4, analyzed_at=$5, updated_at=$5
		WHERE id=$1 AND status='PENDING'`, id, string(st), threat, nullJSON(detail), at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if _, err := p.GetAttachment(ctx, id); err != nil {
			return err
		}
		return ErrConflict
	}
	return nil
}

func (p *Postgres) FindReusableVerdict(ctx context.Context, sha string, since time.Time) (*model.Attachment, error) {
	return scanAttachment(p.pool.QueryRow(ctx, `SELECT `+attachmentCols+` FROM attachments
		WHERE sha256=$1 AND analyzed_at >= $2 AND status IN ('CLEAN','MALICIOUS')
		ORDER BY analyzed_at DESC LIMIT 1`, sha, since))
}

func (p *Postgres) MarkRequeued(ctx context.Context, id string, at time.Time) error {
	_, err := p.pool.Exec(ctx, `UPDATE attachments SET attempts=attempts+1, queued_at=$2, updated_at=$2
		WHERE id=$1 AND status='PENDING'`, id, at)
	return err
}

func (p *Postgres) RecordDownload(ctx context.Context, ev model.DownloadEvent) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE attachments SET download_count=download_count+1, last_downloaded_at=$2
			WHERE id=$1`, ev.AttachmentID, ev.At)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx, `INSERT INTO download_events (attachment_id, username, remote_ip, user_agent, at)
			VALUES ($1,$2,$3,$4,$5)`, ev.AttachmentID, ev.User, ev.RemoteIP, ev.UserAgent, ev.At)
		return err
	})
}

func (p *Postgres) GetMessage(ctx context.Context, id string) (*model.Message, error) {
	var m model.Message
	err := p.pool.QueryRow(ctx, `SELECT id, message_id, mail_from, rcpt_to, subject, remote_addr,
		received_at, attachment_count FROM mail_messages WHERE id=$1`, id).Scan(
		&m.ID, &m.MessageID, &m.MailFrom, &m.RcptTo, &m.Subject, &m.RemoteAddr, &m.ReceivedAt, &m.AttachmentCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (p *Postgres) ListStalePending(ctx context.Context, olderThan time.Time, limit int) ([]*model.Attachment, error) {
	return p.queryAttachments(ctx, `SELECT `+attachmentCols+` FROM attachments
		WHERE status='PENDING' AND queued_at < $1 ORDER BY queued_at LIMIT $2`, olderThan, limit)
}

func (p *Postgres) ListExpired(ctx context.Context, now time.Time, limit int) ([]*model.Attachment, error) {
	return p.queryAttachments(ctx, `SELECT `+attachmentCols+` FROM attachments
		WHERE status<>'EXPIRED' AND expires_at < $1 ORDER BY expires_at LIMIT $2`, now, limit)
}

func (p *Postgres) MarkExpired(ctx context.Context, id string, at time.Time) error {
	_, err := p.pool.Exec(ctx, `UPDATE attachments SET status='EXPIRED', updated_at=$2 WHERE id=$1`, id, at)
	return err
}
