CREATE TABLE IF NOT EXISTS dlp_holds (
    id          UUID PRIMARY KEY,
    token_hash  CHAR(64)    NOT NULL UNIQUE,
    mail_from   TEXT        NOT NULL DEFAULT '',
    rcpt_to     TEXT[]      NOT NULL DEFAULT '{}',
    subject     TEXT        NOT NULL DEFAULT '',
    storage_key TEXT        NOT NULL,
    size        BIGINT      NOT NULL,
    findings    JSONB       NOT NULL,
    status      TEXT        NOT NULL CHECK (status IN ('HELD','RELEASED','REJECTED','EXPIRED')),
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    decided_at  TIMESTAMPTZ,
    decided_by  TEXT        NOT NULL DEFAULT '',
    reason      TEXT        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS dlp_holds_status_idx ON dlp_holds (status, created_at DESC);
CREATE INDEX IF NOT EXISTS dlp_holds_expiry_idx ON dlp_holds (expires_at) WHERE status = 'HELD';

CREATE TABLE IF NOT EXISTS dlp_events (
    id        UUID PRIMARY KEY,
    mail_from TEXT        NOT NULL DEFAULT '',
    rcpt_to   TEXT[]      NOT NULL DEFAULT '{}',
    subject   TEXT        NOT NULL DEFAULT '',
    action    TEXT        NOT NULL,
    severity  TEXT        NOT NULL,
    findings  JSONB       NOT NULL,
    hold_id   UUID,
    at        TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS dlp_events_at_idx ON dlp_events (at DESC);
CREATE INDEX IF NOT EXISTS dlp_events_sender_idx ON dlp_events (mail_from, at DESC);
