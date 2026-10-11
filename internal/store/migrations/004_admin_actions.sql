-- Append-only audit trail of privileged admin-dashboard / admin-API actions
-- (hold release/reject, CSV export, login) so they are attributable after the
-- fact, independent of the hold's own decided_by.
CREATE TABLE IF NOT EXISTS admin_actions (
    id      TEXT        PRIMARY KEY,
    at      TIMESTAMPTZ NOT NULL,
    actor   TEXT        NOT NULL,
    action  TEXT        NOT NULL,
    target  TEXT        NOT NULL DEFAULT '',
    detail  TEXT        NOT NULL DEFAULT '',
    source  TEXT        NOT NULL DEFAULT '',
    result  TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS admin_actions_at_idx ON admin_actions (at DESC, id DESC);
