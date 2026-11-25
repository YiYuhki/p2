CREATE TABLE IF NOT EXISTS download_events (
    id            BIGSERIAL PRIMARY KEY,
    attachment_id UUID        NOT NULL REFERENCES attachments(id) ON DELETE CASCADE,
    username      TEXT        NOT NULL DEFAULT '',
    remote_ip     TEXT        NOT NULL DEFAULT '',
    user_agent    TEXT        NOT NULL DEFAULT '',
    at            TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS download_events_attachment_idx ON download_events (attachment_id, at DESC);
