CREATE TABLE IF NOT EXISTS mail_messages (
    id               UUID PRIMARY KEY,
    message_id       TEXT        NOT NULL DEFAULT '',
    mail_from        TEXT        NOT NULL DEFAULT '',
    rcpt_to          TEXT[]      NOT NULL DEFAULT '{}',
    subject          TEXT        NOT NULL DEFAULT '',
    remote_addr      TEXT        NOT NULL DEFAULT '',
    received_at      TIMESTAMPTZ NOT NULL,
    attachment_count INT         NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS attachments (
    id                 UUID PRIMARY KEY,
    message_id         UUID        NOT NULL REFERENCES mail_messages(id) ON DELETE CASCADE,
    filename           TEXT        NOT NULL,
    content_type       TEXT        NOT NULL,
    size               BIGINT      NOT NULL,
    sha256             CHAR(64)    NOT NULL,
    storage_key        TEXT        NOT NULL,
    token_hash         CHAR(64)    NOT NULL UNIQUE,
    status             TEXT        NOT NULL CHECK (status IN ('PENDING','CLEAN','MALICIOUS','ERROR','EXPIRED')),
    threat_name        TEXT        NOT NULL DEFAULT '',
    verdict_detail     JSONB,
    attempts           INT         NOT NULL DEFAULT 1,
    created_at         TIMESTAMPTZ NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL,
    queued_at          TIMESTAMPTZ NOT NULL,
    analyzed_at        TIMESTAMPTZ,
    expires_at         TIMESTAMPTZ NOT NULL,
    download_count     INT         NOT NULL DEFAULT 0,
    last_downloaded_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS attachments_sha256_idx  ON attachments (sha256, analyzed_at DESC);
CREATE INDEX IF NOT EXISTS attachments_pending_idx ON attachments (queued_at) WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS attachments_expiry_idx  ON attachments (expires_at) WHERE status <> 'EXPIRED';
CREATE INDEX IF NOT EXISTS attachments_message_idx ON attachments (message_id);
