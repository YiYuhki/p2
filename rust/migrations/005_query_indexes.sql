-- Indexes matching the keyset listings and retention sweeps in store/postgres.rs.

-- list_holds without a status filter: ORDER BY created_at DESC, id DESC.
CREATE INDEX IF NOT EXISTS dlp_holds_created_idx ON dlp_holds (created_at DESC, id DESC);
-- list_holds with a status filter (tie-break on id for the keyset cursor).
CREATE INDEX IF NOT EXISTS dlp_holds_status_created_id_idx ON dlp_holds (status, created_at DESC, id DESC);

-- prune_audit_events: DELETE FROM download_events WHERE at < $1.
CREATE INDEX IF NOT EXISTS download_events_at_idx ON download_events (at);

-- list_dlp_events: ORDER BY at DESC, id DESC, optionally filtered by action
-- and/or severity.
CREATE INDEX IF NOT EXISTS dlp_events_at_id_idx ON dlp_events (at DESC, id DESC);
CREATE INDEX IF NOT EXISTS dlp_events_action_at_idx ON dlp_events (action, at DESC, id DESC);
CREATE INDEX IF NOT EXISTS dlp_events_severity_at_idx ON dlp_events (severity, at DESC, id DESC);
