package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yiyuhki/p2/internal/model"
)

const holdCols = `id, token_hash, mail_from, rcpt_to, subject, storage_key, size, findings, status,
	created_at, expires_at, decided_at, decided_by, reason`

func scanHold(row pgx.Row) (*model.Hold, error) {
	var h model.Hold
	var st string
	var findings []byte
	err := row.Scan(&h.ID, &h.TokenHash, &h.MailFrom, &h.RcptTo, &h.Subject, &h.StorageKey, &h.Size,
		&findings, &st, &h.CreatedAt, &h.ExpiresAt, &h.DecidedAt, &h.DecidedBy, &h.Reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	h.Status, h.Findings = model.HoldStatus(st), findings
	return &h, nil
}

func (p *Postgres) queryHolds(ctx context.Context, sql string, args ...any) ([]*model.Hold, error) {
	rows, err := p.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Hold
	for rows.Next() {
		h, err := scanHold(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (p *Postgres) CreateHold(ctx context.Context, h *model.Hold) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO dlp_holds (`+holdCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		h.ID, h.TokenHash, h.MailFrom, h.RcptTo, h.Subject, h.StorageKey, h.Size, []byte(h.Findings),
		string(h.Status), h.CreatedAt, h.ExpiresAt, h.DecidedAt, h.DecidedBy, h.Reason)
	return err
}

func (p *Postgres) GetHold(ctx context.Context, id string) (*model.Hold, error) {
	return scanHold(p.pool.QueryRow(ctx, `SELECT `+holdCols+` FROM dlp_holds WHERE id=$1`, id))
}

func (p *Postgres) GetHoldByTokenHash(ctx context.Context, th string) (*model.Hold, error) {
	return scanHold(p.pool.QueryRow(ctx, `SELECT `+holdCols+` FROM dlp_holds WHERE token_hash=$1`, th))
}

func (p *Postgres) ListHolds(ctx context.Context, st model.HoldStatus, limit int, page Page) ([]*model.Hold, error) {
	if page.Set() {
		return p.queryHolds(ctx, `SELECT `+holdCols+` FROM dlp_holds
			WHERE ($1 = '' OR status = $1)
			  AND (created_at < $3 OR (created_at = $3 AND id < $4))
			ORDER BY created_at DESC, id DESC LIMIT $2`, string(st), limit, page.Before, page.BeforeID)
	}
	return p.queryHolds(ctx, `SELECT `+holdCols+` FROM dlp_holds
		WHERE ($1 = '' OR status = $1) ORDER BY created_at DESC, id DESC LIMIT $2`, string(st), limit)
}

func (p *Postgres) DecideHold(ctx context.Context, id string, st model.HoldStatus, by, reason string, at time.Time) error {
	tag, err := p.pool.Exec(ctx, `UPDATE dlp_holds SET status=$2, decided_by=$3, reason=$4, decided_at=$5
		WHERE id=$1 AND status='HELD'`, id, string(st), by, reason, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if _, err := p.GetHold(ctx, id); err != nil {
			return err
		}
		return ErrConflict
	}
	return nil
}

func (p *Postgres) ListExpiredHolds(ctx context.Context, now time.Time, limit int) ([]*model.Hold, error) {
	return p.queryHolds(ctx, `SELECT `+holdCols+` FROM dlp_holds
		WHERE status='HELD' AND expires_at < $1 ORDER BY expires_at LIMIT $2`, now, limit)
}

func (p *Postgres) RecordDLPEvent(ctx context.Context, ev *model.DLPEvent) error {
	var hold any
	if ev.HoldID != "" {
		hold = ev.HoldID
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO dlp_events
		(id, mail_from, rcpt_to, subject, action, severity, findings, hold_id, at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		ev.ID, ev.MailFrom, ev.RcptTo, ev.Subject, ev.Action, ev.Severity, []byte(ev.Findings), hold, ev.At)
	return err
}

func (p *Postgres) ListDLPEvents(ctx context.Context, limit int, page Page) ([]*model.DLPEvent, error) {
	const cols = `id, mail_from, rcpt_to, subject, action, severity, findings, COALESCE(hold_id::text, ''), at`
	var rows pgx.Rows
	var err error
	if page.Set() {
		rows, err = p.pool.Query(ctx, `SELECT `+cols+` FROM dlp_events
			WHERE (at < $2 OR (at = $2 AND id < $3))
			ORDER BY at DESC, id DESC LIMIT $1`, limit, page.Before, page.BeforeID)
	} else {
		rows, err = p.pool.Query(ctx, `SELECT `+cols+` FROM dlp_events
			ORDER BY at DESC, id DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.DLPEvent
	for rows.Next() {
		var e model.DLPEvent
		var f []byte
		if err := rows.Scan(&e.ID, &e.MailFrom, &e.RcptTo, &e.Subject, &e.Action, &e.Severity, &f, &e.HoldID, &e.At); err != nil {
			return nil, err
		}
		e.Findings = f
		out = append(out, &e)
	}
	return out, rows.Err()
}

func (p *Postgres) ReopenHold(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE dlp_holds SET status='HELD', decided_by='', reason='', decided_at=NULL
		WHERE id=$1 AND status='RELEASED'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}
