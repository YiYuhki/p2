//! PostgreSQL [`Store`](super::Store) implementation. Port of the Go
//! `internal/store` Postgres (`postgres.go`, `postgres_dlp.go`).
//!
//! Schema migrations are embedded from `rust/migrations/*.sql` and applied in
//! lexical order, tracked in `schema_migrations` and serialised across
//! replicas with a Postgres advisory lock (same lock id as the Go service, so
//! mixed deployments cannot race each other).
//!
//! UUID columns are bound as text and cast server-side (`$1::text::uuid`) and
//! read back as text (`id::text`), so the model can keep plain `String` ids.
//! Lookups by an id that is not a valid UUID report [`StoreError::NotFound`],
//! like the in-memory store does for an unknown id.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use serde_json::Value as Json;
use tokio_postgres::types::ToSql;
use tokio_postgres::{NoTls, Row};

use super::{EventFilter, Page, Result, Store, StoreError};
use crate::model::{
    AdminAction, Attachment, DlpEvent, DownloadEvent, Hold, HoldStatus, Message, Status,
};

/// Embedded migrations, in the order they must be applied.
const MIGRATIONS: &[(&str, &str)] = &[
    (
        "migrations/001_init.sql",
        include_str!("../../migrations/001_init.sql"),
    ),
    (
        "migrations/002_download_events.sql",
        include_str!("../../migrations/002_download_events.sql"),
    ),
    (
        "migrations/003_dlp.sql",
        include_str!("../../migrations/003_dlp.sql"),
    ),
    (
        "migrations/004_admin_actions.sql",
        include_str!("../../migrations/004_admin_actions.sql"),
    ),
    (
        "migrations/005_query_indexes.sql",
        include_str!("../../migrations/005_query_indexes.sql"),
    ),
];

/// Advisory lock id serialising migrations (matches the Go service).
const MIGRATION_LOCK_ID: i64 = 0x5ec3a11;

const ATTACHMENT_COLS: &str = "id::text, message_id::text, filename, content_type, size, \
     sha256::text, storage_key, token_hash::text, status, threat_name, verdict_detail, attempts, \
     created_at, updated_at, queued_at, analyzed_at, expires_at, download_count, last_downloaded_at";

const HOLD_COLS: &str = "id::text, token_hash::text, mail_from, rcpt_to, subject, storage_key, \
     size, NULLIF(findings, 'null'::jsonb), status, created_at, expires_at, decided_at, \
     decided_by, reason";

const DLP_EVENT_COLS: &str = "id::text, mail_from, rcpt_to, subject, action, severity, \
     NULLIF(findings, 'null'::jsonb), COALESCE(hold_id::text, ''), at";

const ADMIN_ACTION_COLS: &str = "id, at, actor, action, target, detail, source, result";

/// PostgreSQL-backed store over a `deadpool_postgres` connection pool.
pub struct Postgres {
    pool: Pool,
}

impl Postgres {
    /// Builds a pool of at most `max_conns` connections (0 keeps the pool
    /// default), checks connectivity and applies pending migrations.
    pub async fn connect(dsn: &str, max_conns: usize) -> std::result::Result<Self, String> {
        let mut cfg: tokio_postgres::Config = dsn
            .parse()
            .map_err(|e| format!("postgres: parse dsn: {e}"))?;
        // A hung database must fail calls, not stall mail processing: bound
        // connecting and every statement unless the DSN says otherwise.
        if cfg.get_connect_timeout().is_none() {
            cfg.connect_timeout(std::time::Duration::from_secs(10));
        }
        if cfg.get_options().is_none() {
            cfg.options("-c statement_timeout=30000");
        }
        let mgr = Manager::from_config(
            cfg,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let mut builder = Pool::builder(mgr)
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .wait_timeout(Some(std::time::Duration::from_secs(15)))
            .create_timeout(Some(std::time::Duration::from_secs(15)));
        if max_conns > 0 {
            builder = builder.max_size(max_conns);
        }
        let pool = builder
            .build()
            .map_err(|e| format!("postgres: build pool: {e}"))?;
        let p = Postgres { pool };
        p.ping().await.map_err(|e| format!("postgres: ping: {e}"))?;
        p.migrate()
            .await
            .map_err(|e| format!("postgres: migrate: {e}"))?;
        Ok(p)
    }

    /// Applies embedded migrations in lexical order under an advisory lock.
    async fn migrate(&self) -> Result<()> {
        let mut client = self.pool.get().await.map_err(other)?;
        // Waiting for another replica's migration and building indexes on
        // large tables can legitimately exceed the per-statement timeout.
        client
            .batch_execute("SET statement_timeout = 0")
            .await
            .map_err(other)?;
        let res = async {
            client
                .execute("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK_ID])
                .await
                .map_err(other)?;
            let res = apply_migrations(&mut client).await;
            let unlock = client
                .execute("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK_ID])
                .await
                .map_err(other);
            res.and(unlock.map(|_| ()))
        }
        .await;
        // The pooled connection is reused: restore the session default.
        let reset = client
            .batch_execute("RESET statement_timeout")
            .await
            .map_err(other);
        res.and(reset)
    }

    async fn query(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<Row>> {
        let client = self.pool.get().await.map_err(other)?;
        client.query(sql, params).await.map_err(other)
    }

    async fn query_opt(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Option<Row>> {
        let client = self.pool.get().await.map_err(other)?;
        client.query_opt(sql, params).await.map_err(other)
    }

    async fn execute(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<u64> {
        let client = self.pool.get().await.map_err(other)?;
        client.execute(sql, params).await.map_err(other)
    }

    /// Reports whether a row with this UUID id exists in `table`.
    async fn exists(&self, table: &str, id: &str) -> Result<bool> {
        let sql = format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id = $1::text::uuid)");
        let row = self
            .query_opt(&sql, &[&id])
            .await?
            .ok_or_else(|| StoreError::Other("exists: no row".into()))?;
        Ok(row.get(0))
    }

    async fn one_attachment(
        &self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Attachment> {
        match self.query_opt(sql, params).await? {
            Some(r) => scan_attachment(&r),
            None => Err(StoreError::NotFound),
        }
    }

    async fn attachments(
        &self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Attachment>> {
        self.query(sql, params)
            .await?
            .iter()
            .map(scan_attachment)
            .collect()
    }

    async fn one_hold(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Hold> {
        match self.query_opt(sql, params).await? {
            Some(r) => scan_hold(&r),
            None => Err(StoreError::NotFound),
        }
    }

    async fn holds(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<Hold>> {
        self.query(sql, params)
            .await?
            .iter()
            .map(scan_hold)
            .collect()
    }
}

async fn apply_migrations(client: &mut deadpool_postgres::Client) -> Result<()> {
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        )
        .await
        .map_err(other)?;
    let mut migrations: Vec<&(&str, &str)> = MIGRATIONS.iter().collect();
    migrations.sort_by_key(|(name, _)| *name);
    for (name, sql) in migrations {
        let row = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name = $1)",
                &[name],
            )
            .await
            .map_err(other)?;
        if row.get::<_, bool>(0) {
            continue;
        }
        let tx = client.transaction().await.map_err(other)?;
        tx.batch_execute(sql)
            .await
            .map_err(|e| StoreError::Other(format!("migration {name}: {e}")))?;
        tx.execute("INSERT INTO schema_migrations(name) VALUES ($1)", &[name])
            .await
            .map_err(other)?;
        tx.commit().await.map_err(other)?;
    }
    Ok(())
}

/// Maps a unique-key violation on insert to `Conflict` (duplicate id).
fn insert_err(e: tokio_postgres::Error) -> StoreError {
    if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
        StoreError::Conflict
    } else {
        other(e)
    }
}

fn other(e: impl std::fmt::Display) -> StoreError {
    StoreError::Other(e.to_string())
}

fn valid_uuid(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok()
}

fn limit_param(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}

fn parse_status(s: &str) -> Result<Status> {
    Ok(match s {
        "PENDING" => Status::Pending,
        "CLEAN" => Status::Clean,
        "MALICIOUS" => Status::Malicious,
        "ERROR" => Status::Error,
        "EXPIRED" => Status::Expired,
        _ => {
            return Err(StoreError::Other(format!(
                "unknown attachment status {s:?}"
            )))
        }
    })
}

fn parse_hold_status(s: &str) -> Result<HoldStatus> {
    Ok(match s {
        "HELD" => HoldStatus::Held,
        "RELEASED" => HoldStatus::Released,
        "REJECTED" => HoldStatus::Rejected,
        "EXPIRED" => HoldStatus::Expired,
        _ => return Err(StoreError::Other(format!("unknown hold status {s:?}"))),
    })
}

fn scan_attachment(r: &Row) -> Result<Attachment> {
    let status: String = r.try_get(8).map_err(other)?;
    Ok(Attachment {
        id: r.try_get(0).map_err(other)?,
        message_id: r.try_get(1).map_err(other)?,
        filename: r.try_get(2).map_err(other)?,
        content_type: r.try_get(3).map_err(other)?,
        size: r.try_get(4).map_err(other)?,
        sha256: r.try_get(5).map_err(other)?,
        storage_key: r.try_get(6).map_err(other)?,
        token_hash: r.try_get(7).map_err(other)?,
        status: parse_status(&status)?,
        threat_name: r.try_get(9).map_err(other)?,
        verdict_detail: r.try_get(10).map_err(other)?,
        attempts: r.try_get(11).map_err(other)?,
        created_at: r.try_get(12).map_err(other)?,
        updated_at: r.try_get(13).map_err(other)?,
        queued_at: r.try_get(14).map_err(other)?,
        analyzed_at: r.try_get(15).map_err(other)?,
        expires_at: r.try_get(16).map_err(other)?,
        download_count: r.try_get(17).map_err(other)?,
        last_downloaded_at: r.try_get(18).map_err(other)?,
    })
}

fn scan_hold(r: &Row) -> Result<Hold> {
    let status: String = r.try_get(8).map_err(other)?;
    Ok(Hold {
        id: r.try_get(0).map_err(other)?,
        token_hash: r.try_get(1).map_err(other)?,
        mail_from: r.try_get(2).map_err(other)?,
        rcpt_to: r.try_get(3).map_err(other)?,
        subject: r.try_get(4).map_err(other)?,
        storage_key: r.try_get(5).map_err(other)?,
        size: r.try_get(6).map_err(other)?,
        findings: r.try_get(7).map_err(other)?,
        status: parse_hold_status(&status)?,
        created_at: r.try_get(9).map_err(other)?,
        expires_at: r.try_get(10).map_err(other)?,
        decided_at: r.try_get(11).map_err(other)?,
        decided_by: r.try_get(12).map_err(other)?,
        reason: r.try_get(13).map_err(other)?,
    })
}

fn scan_dlp_event(r: &Row) -> Result<DlpEvent> {
    Ok(DlpEvent {
        id: r.try_get(0).map_err(other)?,
        mail_from: r.try_get(1).map_err(other)?,
        rcpt_to: r.try_get(2).map_err(other)?,
        subject: r.try_get(3).map_err(other)?,
        action: r.try_get(4).map_err(other)?,
        severity: r.try_get(5).map_err(other)?,
        findings: r.try_get(6).map_err(other)?,
        hold_id: r.try_get(7).map_err(other)?,
        at: r.try_get(8).map_err(other)?,
    })
}

fn scan_admin_action(r: &Row) -> Result<AdminAction> {
    Ok(AdminAction {
        id: r.try_get(0).map_err(other)?,
        at: r.try_get(1).map_err(other)?,
        actor: r.try_get(2).map_err(other)?,
        action: r.try_get(3).map_err(other)?,
        target: r.try_get(4).map_err(other)?,
        detail: r.try_get(5).map_err(other)?,
        source: r.try_get(6).map_err(other)?,
        result: r.try_get(7).map_err(other)?,
    })
}

/// Dynamic SQL parameter list with `$n` placeholder allocation.
#[derive(Default)]
struct Args {
    vals: Vec<Box<dyn ToSql + Sync + Send>>,
}

impl Args {
    fn push(&mut self, v: impl ToSql + Sync + Send + 'static) -> String {
        self.vals.push(Box::new(v));
        format!("${}", self.vals.len())
    }

    fn refs(&self) -> Vec<&(dyn ToSql + Sync)> {
        self.vals
            .iter()
            .map(|b| b.as_ref() as &(dyn ToSql + Sync))
            .collect()
    }

    /// Adds the keyset condition "strictly after the cursor" for (time DESC,
    /// id DESC) ordering. Ids are compared as text, which for canonical UUIDs
    /// matches UUID ordering and never fails on a malformed cursor id.
    fn keyset(&mut self, page: &Page, time_col: &str) -> Option<String> {
        let before = page.before?;
        let bt = self.push(before);
        let bid = self.push(page.before_id.clone());
        Some(format!(
            "({time_col} < {bt} OR ({time_col} = {bt} AND id::text < {bid}::text))"
        ))
    }
}

fn where_clause(conds: &[String]) -> String {
    if conds.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conds.join(" AND "))
    }
}

#[async_trait]
impl Store for Postgres {
    async fn ping(&self) -> Result<()> {
        let client = self.pool.get().await.map_err(other)?;
        client.simple_query("SELECT 1").await.map_err(other)?;
        Ok(())
    }

    async fn create_message(&self, m: &Message, atts: &[Attachment]) -> Result<()> {
        let mut client = self.pool.get().await.map_err(other)?;
        let tx = client.transaction().await.map_err(other)?;
        let count = i32::try_from(m.attachment_count)
            .map_err(|_| StoreError::Other("attachment_count out of range".into()))?;
        tx.execute(
            "INSERT INTO mail_messages
                (id, message_id, mail_from, rcpt_to, subject, remote_addr, received_at, attachment_count)
             VALUES ($1::text::uuid, $2, $3, $4, $5, $6, COALESCE($7, now()), $8)",
            &[
                &m.id,
                &m.message_id,
                &m.mail_from,
                &m.rcpt_to,
                &m.subject,
                &m.remote_addr,
                &m.received_at,
                &count,
            ],
        )
        .await
        .map_err(insert_err)?;
        for a in atts {
            tx.execute(
                "INSERT INTO attachments
                    (id, message_id, filename, content_type, size, sha256, storage_key, token_hash,
                     status, threat_name, verdict_detail, attempts, created_at, updated_at, queued_at,
                     analyzed_at, expires_at, download_count, last_downloaded_at)
                 VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                         $13, $14, $15, $16, $17, $18, $19)",
                &[
                    &a.id,
                    &a.message_id,
                    &a.filename,
                    &a.content_type,
                    &a.size,
                    &a.sha256,
                    &a.storage_key,
                    &a.token_hash,
                    &a.status.as_str(),
                    &a.threat_name,
                    &a.verdict_detail,
                    &a.attempts,
                    &a.created_at,
                    &a.updated_at,
                    &a.queued_at,
                    &a.analyzed_at,
                    &a.expires_at,
                    &a.download_count,
                    &a.last_downloaded_at,
                ],
            )
            .await
            .map_err(insert_err)?;
        }
        tx.commit().await.map_err(other)
    }

    async fn get_message(&self, id: &str) -> Result<Message> {
        if !valid_uuid(id) {
            return Err(StoreError::NotFound);
        }
        let row = self
            .query_opt(
                "SELECT id::text, message_id, mail_from, rcpt_to, subject, remote_addr,
                        received_at, attachment_count::bigint
                 FROM mail_messages WHERE id = $1::text::uuid",
                &[&id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        Ok(Message {
            id: row.try_get(0).map_err(other)?,
            message_id: row.try_get(1).map_err(other)?,
            mail_from: row.try_get(2).map_err(other)?,
            rcpt_to: row.try_get(3).map_err(other)?,
            subject: row.try_get(4).map_err(other)?,
            remote_addr: row.try_get(5).map_err(other)?,
            received_at: row.try_get(6).map_err(other)?,
            attachment_count: row.try_get(7).map_err(other)?,
        })
    }

    async fn get_attachment(&self, id: &str) -> Result<Attachment> {
        if !valid_uuid(id) {
            return Err(StoreError::NotFound);
        }
        let sql = format!("SELECT {ATTACHMENT_COLS} FROM attachments WHERE id = $1::text::uuid");
        self.one_attachment(&sql, &[&id]).await
    }

    async fn get_attachment_by_token_hash(&self, h: &str) -> Result<Attachment> {
        let sql = format!("SELECT {ATTACHMENT_COLS} FROM attachments WHERE token_hash = $1");
        self.one_attachment(&sql, &[&h]).await
    }

    async fn set_verdict(
        &self,
        id: &str,
        status: Status,
        threat: &str,
        detail: Option<Json>,
        at: DateTime<Utc>,
    ) -> Result<()> {
        if !valid_uuid(id) {
            return Err(StoreError::NotFound);
        }
        let n = self
            .execute(
                "UPDATE attachments
                 SET status = $2, threat_name = $3, verdict_detail = $4,
                     analyzed_at = $5, updated_at = $5
                 WHERE id = $1::text::uuid AND status = 'PENDING'",
                &[&id, &status.as_str(), &threat, &detail, &at],
            )
            .await?;
        if n == 0 {
            if !self.exists("attachments", id).await? {
                return Err(StoreError::NotFound);
            }
            return Err(StoreError::Conflict);
        }
        Ok(())
    }

    async fn find_reusable_verdict(
        &self,
        sha256: &str,
        since: DateTime<Utc>,
    ) -> Result<Attachment> {
        let sql = format!(
            "SELECT {ATTACHMENT_COLS} FROM attachments
             WHERE sha256 = $1 AND analyzed_at >= $2 AND status IN ('CLEAN', 'MALICIOUS')
             ORDER BY analyzed_at DESC LIMIT 1"
        );
        self.one_attachment(&sql, &[&sha256, &since]).await
    }

    async fn mark_requeued(&self, id: &str, at: DateTime<Utc>) -> Result<()> {
        if !valid_uuid(id) {
            return Err(StoreError::NotFound);
        }
        // As in the Go store, only a still-pending attachment is requeued; a
        // verdict that landed meanwhile is left untouched.
        let n = self
            .execute(
                "UPDATE attachments SET attempts = attempts + 1, queued_at = $2, updated_at = $2
                 WHERE id = $1::text::uuid AND status = 'PENDING'",
                &[&id, &at],
            )
            .await?;
        if n == 0 {
            if !self.exists("attachments", id).await? {
                return Err(StoreError::NotFound);
            }
            return Err(StoreError::Conflict);
        }
        Ok(())
    }

    async fn record_download(&self, ev: DownloadEvent) -> Result<()> {
        if !valid_uuid(&ev.attachment_id) {
            return Err(StoreError::NotFound);
        }
        let mut client = self.pool.get().await.map_err(other)?;
        let tx = client.transaction().await.map_err(other)?;
        let n = tx
            .execute(
                "UPDATE attachments SET download_count = download_count + 1, last_downloaded_at = $2
                 WHERE id = $1::text::uuid",
                &[&ev.attachment_id, &ev.at],
            )
            .await
            .map_err(other)?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        tx.execute(
            "INSERT INTO download_events (attachment_id, username, remote_ip, user_agent, at)
             VALUES ($1::text::uuid, $2, $3, $4, $5)",
            &[
                &ev.attachment_id,
                &ev.user,
                &ev.remote_ip,
                &ev.user_agent,
                &ev.at,
            ],
        )
        .await
        .map_err(other)?;
        tx.commit().await.map_err(other)
    }

    async fn list_stale_pending(
        &self,
        older_than: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<Attachment>> {
        let sql = format!(
            "SELECT {ATTACHMENT_COLS} FROM attachments
             WHERE status = 'PENDING' AND queued_at < $1 ORDER BY queued_at LIMIT $2"
        );
        self.attachments(&sql, &[&older_than, &limit_param(limit)])
            .await
    }

    async fn list_expired(&self, now: DateTime<Utc>, limit: usize) -> Result<Vec<Attachment>> {
        let sql = format!(
            "SELECT {ATTACHMENT_COLS} FROM attachments
             WHERE status <> 'EXPIRED' AND expires_at < $1 ORDER BY expires_at LIMIT $2"
        );
        self.attachments(&sql, &[&now, &limit_param(limit)]).await
    }

    async fn mark_expired(&self, id: &str, at: DateTime<Utc>) -> Result<()> {
        if !valid_uuid(id) {
            return Err(StoreError::NotFound);
        }
        let n = self
            .execute(
                "UPDATE attachments SET status = 'EXPIRED', updated_at = $2
                 WHERE id = $1::text::uuid",
                &[&id, &at],
            )
            .await?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn create_hold(&self, h: &Hold) -> Result<()> {
        self.execute(
            "INSERT INTO dlp_holds
                (id, token_hash, mail_from, rcpt_to, subject, storage_key, size, findings, status,
                 created_at, expires_at, decided_at, decided_by, reason)
             VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, COALESCE($8, 'null'::jsonb), $9,
                     $10, $11, $12, $13, $14)",
            &[
                &h.id,
                &h.token_hash,
                &h.mail_from,
                &h.rcpt_to,
                &h.subject,
                &h.storage_key,
                &h.size,
                &h.findings,
                &h.status.as_str(),
                &h.created_at,
                &h.expires_at,
                &h.decided_at,
                &h.decided_by,
                &h.reason,
            ],
        )
        .await?;
        Ok(())
    }

    async fn get_hold(&self, id: &str) -> Result<Hold> {
        if !valid_uuid(id) {
            return Err(StoreError::NotFound);
        }
        let sql = format!("SELECT {HOLD_COLS} FROM dlp_holds WHERE id = $1::text::uuid");
        self.one_hold(&sql, &[&id]).await
    }

    async fn get_hold_by_token_hash(&self, th: &str) -> Result<Hold> {
        let sql = format!("SELECT {HOLD_COLS} FROM dlp_holds WHERE token_hash = $1");
        self.one_hold(&sql, &[&th]).await
    }

    async fn list_holds(
        &self,
        status: Option<HoldStatus>,
        limit: usize,
        page: Page,
    ) -> Result<Vec<Hold>> {
        let mut args = Args::default();
        let mut conds = Vec::new();
        if let Some(s) = status {
            conds.push(format!("status = {}", args.push(s.as_str())));
        }
        if let Some(c) = args.keyset(&page, "created_at") {
            conds.push(c);
        }
        let lim = args.push(limit_param(limit));
        let sql = format!(
            "SELECT {HOLD_COLS} FROM dlp_holds{} ORDER BY created_at DESC, id DESC LIMIT {lim}",
            where_clause(&conds)
        );
        self.holds(&sql, &args.refs()).await
    }

    async fn decide_hold(
        &self,
        id: &str,
        status: HoldStatus,
        by: &str,
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<()> {
        if !valid_uuid(id) {
            return Err(StoreError::NotFound);
        }
        let n = self
            .execute(
                "UPDATE dlp_holds SET status = $2, decided_by = $3, reason = $4, decided_at = $5
                 WHERE id = $1::text::uuid AND status = 'HELD'
                   AND ($2 <> 'RELEASED' OR expires_at > $5)",
                &[&id, &status.as_str(), &by, &reason, &at],
            )
            .await?;
        if n == 0 {
            if !self.exists("dlp_holds", id).await? {
                return Err(StoreError::NotFound);
            }
            return Err(StoreError::Conflict);
        }
        Ok(())
    }

    async fn reopen_hold(&self, id: &str) -> Result<()> {
        if !valid_uuid(id) {
            return Err(StoreError::NotFound);
        }
        let n = self
            .execute(
                "UPDATE dlp_holds
                 SET status = 'HELD', decided_by = '', reason = '', decided_at = NULL
                 WHERE id = $1::text::uuid AND status = 'RELEASED'",
                &[&id],
            )
            .await?;
        if n == 0 {
            if !self.exists("dlp_holds", id).await? {
                return Err(StoreError::NotFound);
            }
            return Err(StoreError::Conflict);
        }
        Ok(())
    }

    async fn set_hold_reason(&self, id: &str, reason: &str) -> Result<()> {
        if !valid_uuid(id) {
            return Err(StoreError::NotFound);
        }
        let n = self
            .execute(
                "UPDATE dlp_holds SET reason = $2 WHERE id = $1::text::uuid AND status <> 'HELD'",
                &[&id, &reason],
            )
            .await?;
        if n == 0 {
            if !self.exists("dlp_holds", id).await? {
                return Err(StoreError::NotFound);
            }
            return Err(StoreError::Conflict);
        }
        Ok(())
    }

    async fn list_expired_holds(&self, now: DateTime<Utc>, limit: usize) -> Result<Vec<Hold>> {
        let sql = format!(
            "SELECT {HOLD_COLS} FROM dlp_holds
             WHERE status = 'HELD' AND expires_at < $1 ORDER BY expires_at LIMIT $2"
        );
        self.holds(&sql, &[&now, &limit_param(limit)]).await
    }

    async fn record_dlp_event(&self, ev: &DlpEvent) -> Result<()> {
        self.execute(
            "INSERT INTO dlp_events
                (id, mail_from, rcpt_to, subject, action, severity, findings, hold_id, at)
             VALUES ($1::text::uuid, $2, $3, $4, $5, $6, COALESCE($7, 'null'::jsonb),
                     NULLIF($8::text, '')::uuid, $9)",
            &[
                &ev.id,
                &ev.mail_from,
                &ev.rcpt_to,
                &ev.subject,
                &ev.action,
                &ev.severity,
                &ev.findings,
                &ev.hold_id,
                &ev.at,
            ],
        )
        .await?;
        Ok(())
    }

    async fn list_dlp_events(
        &self,
        filter: EventFilter,
        limit: usize,
        page: Page,
    ) -> Result<Vec<DlpEvent>> {
        let mut args = Args::default();
        let mut conds = Vec::new();
        if !filter.action.is_empty() {
            conds.push(format!("action = {}", args.push(filter.action)));
        }
        if !filter.severity.is_empty() {
            conds.push(format!("severity = {}", args.push(filter.severity)));
        }
        if let Some(c) = args.keyset(&page, "at") {
            conds.push(c);
        }
        let lim = args.push(limit_param(limit));
        let sql = format!(
            "SELECT {DLP_EVENT_COLS} FROM dlp_events{} ORDER BY at DESC, id DESC LIMIT {lim}",
            where_clause(&conds)
        );
        self.query(&sql, &args.refs())
            .await?
            .iter()
            .map(scan_dlp_event)
            .collect()
    }

    async fn prune_audit_events(&self, cutoff: DateTime<Utc>) -> Result<i64> {
        // Batched so a large backlog makes progress within the statement
        // timeout instead of one huge DELETE that is cancelled every sweep.
        const BATCH: i64 = 10_000;
        let mut total: u64 = 0;
        for table in ["dlp_events", "download_events"] {
            let sql = format!(
                "DELETE FROM {table} WHERE ctid IN \
                 (SELECT ctid FROM {table} WHERE at < $1 LIMIT $2)"
            );
            loop {
                let n = self.execute(&sql, &[&cutoff, &BATCH]).await?;
                total += n;
                if n < BATCH as u64 {
                    break;
                }
            }
        }
        Ok(i64::try_from(total).unwrap_or(i64::MAX))
    }

    async fn record_admin_action(&self, a: AdminAction) -> Result<()> {
        self.execute(
            "INSERT INTO admin_actions (id, at, actor, action, target, detail, source, result)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &a.id, &a.at, &a.actor, &a.action, &a.target, &a.detail, &a.source, &a.result,
            ],
        )
        .await?;
        Ok(())
    }

    async fn list_admin_actions(&self, limit: usize, page: Page) -> Result<Vec<AdminAction>> {
        let mut args = Args::default();
        let mut conds = Vec::new();
        if let Some(c) = args.keyset(&page, "at") {
            conds.push(c);
        }
        let lim = args.push(limit_param(limit));
        let sql = format!(
            "SELECT {ADMIN_ACTION_COLS} FROM admin_actions{} ORDER BY at DESC, id DESC LIMIT {lim}",
            where_clause(&conds)
        );
        self.query(&sql, &args.refs())
            .await?
            .iter()
            .map(scan_admin_action)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    //! Integration tests against a real PostgreSQL. Set `SECMAIL_TEST_PG` to a
    //! key/value DSN (e.g. `host=127.0.0.1 user=postgres password=postgres
    //! dbname=secmail_test`); tests are skipped when it is unset. Each test
    //! runs in its own freshly created schema (dropped afterwards), so tests
    //! can run concurrently.

    use super::*;
    use chrono::Duration;
    use serde_json::json;

    struct TestDb {
        store: Postgres,
        dsn: String,
        schema: String,
    }

    impl TestDb {
        async fn new() -> Option<TestDb> {
            let dsn = std::env::var("SECMAIL_TEST_PG").ok()?;
            let schema = format!("t_{}", uuid::Uuid::new_v4().simple());
            let (client, conn) = tokio_postgres::connect(&dsn, NoTls).await.expect("connect");
            tokio::spawn(conn);
            client
                .batch_execute(&format!("CREATE SCHEMA {schema}"))
                .await
                .expect("create schema");
            let scoped = format!("{dsn} options='-c search_path={schema}'");
            let store = Postgres::connect(&scoped, 4).await.expect("connect store");
            Some(TestDb { store, dsn, schema })
        }

        async fn drop(self) {
            let TestDb { store, dsn, schema } = self;
            store.pool.close();
            let (client, conn) = tokio_postgres::connect(&dsn, NoTls).await.expect("connect");
            tokio::spawn(conn);
            client
                .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
                .await
                .expect("drop schema");
        }
    }

    fn id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn message(id: &str) -> Message {
        Message {
            id: id.into(),
            message_id: "<m@x>".into(),
            mail_from: "a@x".into(),
            rcpt_to: vec!["b@y".into(), "c@y".into()],
            subject: "hi".into(),
            remote_addr: "1.2.3.4".into(),
            received_at: Some(Utc::now()),
            attachment_count: 1,
        }
    }

    fn att(id: &str, msg: &str, sha: &str, status: Status) -> Attachment {
        let now = Utc::now();
        Attachment {
            id: id.into(),
            message_id: msg.into(),
            filename: "a.pdf".into(),
            content_type: "application/pdf".into(),
            size: 10,
            sha256: sha.into(),
            storage_key: "k".into(),
            token_hash: format!("tok-{id}"),
            status,
            threat_name: String::new(),
            verdict_detail: None,
            attempts: 1,
            created_at: now,
            updated_at: now,
            queued_at: now,
            analyzed_at: None,
            expires_at: now + Duration::hours(1),
            download_count: 0,
            last_downloaded_at: None,
        }
    }

    fn hold(id: &str, created_at: DateTime<Utc>) -> Hold {
        Hold {
            id: id.into(),
            token_hash: format!("th-{id}"),
            mail_from: "a@x".into(),
            rcpt_to: vec!["b@y".into()],
            subject: "s".into(),
            storage_key: "k".into(),
            size: 1,
            findings: Some(json!([{"detector": "iban"}])),
            status: HoldStatus::Held,
            created_at,
            expires_at: created_at + Duration::hours(3),
            decided_at: None,
            decided_by: String::new(),
            reason: String::new(),
        }
    }

    #[tokio::test]
    async fn migrations_are_idempotent() {
        let Some(db) = TestDb::new().await else {
            return;
        };
        db.store.migrate().await.unwrap();
        db.store.ping().await.unwrap();
        let rows = db
            .store
            .query("SELECT count(*) FROM schema_migrations", &[])
            .await
            .unwrap();
        assert_eq!(rows[0].get::<_, i64>(0), MIGRATIONS.len() as i64);
        db.drop().await;
    }

    #[tokio::test]
    async fn verdict_lifecycle() {
        let Some(db) = TestDb::new().await else {
            return;
        };
        let s = &db.store;
        let (mid, aid) = (id(), id());
        s.create_message(
            &message(&mid),
            &[att(&aid, &mid, "deadbeef", Status::Pending)],
        )
        .await
        .unwrap();

        // Duplicate ids are a conflict (and the transaction inserts nothing).
        let other_att = id();
        assert_eq!(
            s.create_message(
                &message(&mid),
                &[att(&other_att, &mid, "x", Status::Pending)]
            )
            .await,
            Err(StoreError::Conflict)
        );
        assert_eq!(
            s.get_attachment(&other_att).await.err(),
            Some(StoreError::NotFound)
        );

        let m = s.get_message(&mid).await.unwrap();
        assert_eq!(m.rcpt_to, vec!["b@y".to_string(), "c@y".to_string()]);
        assert_eq!(m.attachment_count, 1);

        let a = s.get_attachment(&aid).await.unwrap();
        assert_eq!(a.status, Status::Pending);
        assert_eq!(a.sha256, "deadbeef");
        assert_eq!(a.message_id, mid);

        // by token hash
        assert_eq!(
            s.get_attachment_by_token_hash(&format!("tok-{aid}"))
                .await
                .unwrap()
                .id,
            aid
        );
        assert_eq!(
            s.get_attachment_by_token_hash("nope").await.err(),
            Some(StoreError::NotFound)
        );

        // requeue bumps attempts while pending
        s.mark_requeued(&aid, Utc::now()).await.unwrap();
        assert_eq!(s.get_attachment(&aid).await.unwrap().attempts, 2);

        // set verdict
        let detail = json!({"engine": "x", "score": 0});
        s.set_verdict(&aid, Status::Clean, "", Some(detail.clone()), Utc::now())
            .await
            .unwrap();
        let a = s.get_attachment(&aid).await.unwrap();
        assert_eq!(a.status, Status::Clean);
        assert_eq!(a.verdict_detail, Some(detail));
        // A verdict landed: requeue is a conflict and leaves attempts alone.
        assert_eq!(
            s.mark_requeued(&aid, Utc::now()).await,
            Err(StoreError::Conflict)
        );
        assert_eq!(s.get_attachment(&aid).await.unwrap().attempts, 2);
        assert!(a.analyzed_at.is_some());

        // second verdict conflicts (not pending any more)
        assert_eq!(
            s.set_verdict(&aid, Status::Malicious, "x", None, Utc::now())
                .await,
            Err(StoreError::Conflict)
        );
        assert_eq!(
            s.set_verdict(&id(), Status::Clean, "", None, Utc::now())
                .await,
            Err(StoreError::NotFound)
        );
        assert_eq!(
            s.get_attachment("missing").await.err(),
            Some(StoreError::NotFound)
        );
        assert_eq!(
            s.get_attachment(&id()).await.err(),
            Some(StoreError::NotFound)
        );

        // expiry sweep
        let later = Utc::now() + Duration::hours(2);
        let exp = s.list_expired(later, 10).await.unwrap();
        assert_eq!(exp.len(), 1);
        s.mark_expired(&aid, later).await.unwrap();
        assert!(s.list_expired(later, 10).await.unwrap().is_empty());
        assert_eq!(
            s.get_attachment(&aid).await.unwrap().status,
            Status::Expired
        );
        db.drop().await;
    }

    #[tokio::test]
    async fn reusable_verdict_and_stale_pending() {
        let Some(db) = TestDb::new().await else {
            return;
        };
        let s = &db.store;
        let mid = id();
        let (old, newer, err, pending) = (id(), id(), id(), id());
        s.create_message(
            &message(&mid),
            &[
                att(&old, &mid, "abc", Status::Pending),
                att(&newer, &mid, "abc", Status::Pending),
                att(&err, &mid, "abc", Status::Pending),
                att(&pending, &mid, "abc", Status::Pending),
            ],
        )
        .await
        .unwrap();
        let now = Utc::now();
        s.set_verdict(
            &old,
            Status::Malicious,
            "eicar",
            None,
            now - Duration::hours(3),
        )
        .await
        .unwrap();
        s.set_verdict(&newer, Status::Clean, "", None, now - Duration::hours(1))
            .await
            .unwrap();
        s.set_verdict(&err, Status::Error, "", None, now)
            .await
            .unwrap();

        // newest CLEAN/MALICIOUS within the window; ERROR is ignored
        let r = s
            .find_reusable_verdict("abc", now - Duration::hours(6))
            .await
            .unwrap();
        assert_eq!(r.id, newer);
        // window excludes the newer one too
        assert_eq!(
            s.find_reusable_verdict("abc", now - Duration::minutes(30))
                .await
                .err(),
            Some(StoreError::NotFound)
        );
        assert_eq!(
            s.find_reusable_verdict("other", now - Duration::hours(6))
                .await
                .err(),
            Some(StoreError::NotFound)
        );

        let stale = s
            .list_stale_pending(Utc::now() + Duration::minutes(1), 10)
            .await
            .unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].id, pending);
        db.drop().await;
    }

    #[tokio::test]
    async fn download_increments_count() {
        let Some(db) = TestDb::new().await else {
            return;
        };
        let s = &db.store;
        let (mid, aid) = (id(), id());
        s.create_message(&message(&mid), &[att(&aid, &mid, "x", Status::Clean)])
            .await
            .unwrap();
        for _ in 0..2 {
            s.record_download(DownloadEvent {
                attachment_id: aid.clone(),
                user: "bob".into(),
                remote_ip: "10.0.0.1".into(),
                user_agent: "ua".into(),
                at: Utc::now(),
            })
            .await
            .unwrap();
        }
        let a = s.get_attachment(&aid).await.unwrap();
        assert_eq!(a.download_count, 2);
        assert!(a.last_downloaded_at.is_some());
        assert_eq!(
            s.record_download(DownloadEvent {
                attachment_id: id(),
                user: String::new(),
                remote_ip: String::new(),
                user_agent: String::new(),
                at: Utc::now(),
            })
            .await,
            Err(StoreError::NotFound)
        );
        // download events are pruned with the audit trail
        let n = s
            .prune_audit_events(Utc::now() + Duration::minutes(1))
            .await
            .unwrap();
        assert_eq!(n, 2);
        db.drop().await;
    }

    #[tokio::test]
    async fn hold_decision_and_keyset() {
        let Some(db) = TestDb::new().await else {
            return;
        };
        let s = &db.store;
        let base = Utc::now() - Duration::hours(2);
        let ids: Vec<String> = (0..3).map(|_| id()).collect();
        for (i, hid) in ids.iter().enumerate() {
            s.create_hold(&hold(hid, base + Duration::minutes(i as i64)))
                .await
                .unwrap();
        }
        // a hold without findings round-trips as None
        let bare = id();
        let mut h = hold(&bare, base - Duration::minutes(10));
        h.findings = None;
        s.create_hold(&h).await.unwrap();
        assert_eq!(s.get_hold(&bare).await.unwrap().findings, None);

        let held = s
            .list_holds(Some(HoldStatus::Held), 50, Page::default())
            .await
            .unwrap();
        assert_eq!(held.len(), 4);
        assert_eq!(held[0].id, ids[2]); // newest first
        assert_eq!(held[0].findings, Some(json!([{"detector": "iban"}])));

        assert_eq!(
            s.get_hold_by_token_hash(&format!("th-{}", ids[0]))
                .await
                .unwrap()
                .id,
            ids[0]
        );

        // decide one
        s.decide_hold(&ids[1], HoldStatus::Rejected, "sec", "no", Utc::now())
            .await
            .unwrap();
        assert_eq!(
            s.decide_hold(&ids[1], HoldStatus::Released, "x", "", Utc::now())
                .await,
            Err(StoreError::Conflict)
        );
        assert_eq!(
            s.decide_hold(&id(), HoldStatus::Released, "x", "", Utc::now())
                .await,
            Err(StoreError::NotFound)
        );
        s.set_hold_reason(&ids[1], "updated").await.unwrap();
        assert_eq!(
            s.set_hold_reason(&ids[2], "x").await,
            Err(StoreError::Conflict),
            "still HELD"
        );
        // An overdue hold cannot be released (but can be rejected).
        let late = id();
        let mut lh = hold(&late, Utc::now() - Duration::hours(5));
        lh.expires_at = Utc::now() - Duration::seconds(1);
        s.create_hold(&lh).await.unwrap();
        assert_eq!(
            s.decide_hold(&late, HoldStatus::Released, "x", "", Utc::now())
                .await,
            Err(StoreError::Conflict)
        );
        s.decide_hold(&late, HoldStatus::Rejected, "x", "", Utc::now())
            .await
            .unwrap();
        let h1 = s.get_hold(&ids[1]).await.unwrap();
        assert_eq!(h1.status, HoldStatus::Rejected);
        assert_eq!(h1.decided_by, "sec");
        assert!(h1.decided_at.is_some());

        // status filter
        let rejected = s
            .list_holds(Some(HoldStatus::Rejected), 50, Page::default())
            .await
            .unwrap();
        assert_eq!(rejected.len(), 2); // ids[1] and the overdue hold
        assert_eq!(
            s.list_holds(Some(HoldStatus::Held), 50, Page::default())
                .await
                .unwrap()
                .len(),
            3
        );

        // reopen: only RELEASED -> HELD
        assert_eq!(s.reopen_hold(&ids[1]).await, Err(StoreError::Conflict));
        s.decide_hold(&ids[0], HoldStatus::Released, "sec", "ok", Utc::now())
            .await
            .unwrap();
        s.reopen_hold(&ids[0]).await.unwrap();
        let h0 = s.get_hold(&ids[0]).await.unwrap();
        assert_eq!(h0.status, HoldStatus::Held);
        assert!(h0.decided_at.is_none());
        assert!(h0.decided_by.is_empty() && h0.reason.is_empty());
        assert_eq!(s.reopen_hold(&id()).await, Err(StoreError::NotFound));

        // keyset paging: first page of 2, then the rest
        let page1 = s.list_holds(None, 2, Page::default()).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].id, ids[2]);
        assert_eq!(page1[1].id, ids[1]);
        let last = &page1[1];
        let page2 = s
            .list_holds(
                None,
                2,
                Page {
                    before: Some(last.created_at),
                    before_id: last.id.clone(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            page2.iter().map(|h| h.id.as_str()).collect::<Vec<_>>(),
            vec![ids[0].as_str(), bare.as_str()]
        );

        // expired sweep: only HELD holds past expiry
        let exp = s
            .list_expired_holds(Utc::now() + Duration::hours(2), 10)
            .await
            .unwrap();
        assert_eq!(exp.len(), 3);
        db.drop().await;
    }

    #[tokio::test]
    async fn dlp_events_filter_prune_and_paging() {
        let Some(db) = TestDb::new().await else {
            return;
        };
        let s = &db.store;
        let old = Utc::now() - Duration::hours(48);
        let recent = Utc::now();
        let hold_id = id();
        let ev = |eid: &str, action: &str, sev: &str, at, hold: &str| DlpEvent {
            id: eid.into(),
            mail_from: "a".into(),
            rcpt_to: vec!["r@x".into()],
            subject: "s".into(),
            action: action.into(),
            severity: sev.into(),
            findings: Some(json!({"n": 1})),
            hold_id: hold.into(),
            at,
        };
        let (e1, e2, e3) = (id(), id(), id());
        s.record_dlp_event(&ev(&e1, "block", "high", old, ""))
            .await
            .unwrap();
        s.record_dlp_event(&ev(&e2, "notify", "low", recent, ""))
            .await
            .unwrap();
        s.record_dlp_event(&ev(&e3, "hold", "high", recent, &hold_id))
            .await
            .unwrap();

        let blocked = s
            .list_dlp_events(
                EventFilter {
                    action: "block".into(),
                    ..Default::default()
                },
                50,
                Page::default(),
            )
            .await
            .unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].id, e1);
        assert_eq!(blocked[0].hold_id, "");

        let high = s
            .list_dlp_events(
                EventFilter {
                    severity: "high".into(),
                    ..Default::default()
                },
                50,
                Page::default(),
            )
            .await
            .unwrap();
        assert_eq!(high.len(), 2);
        assert_eq!(high[0].id, e3);
        assert_eq!(high[0].hold_id, hold_id);
        assert_eq!(high[0].findings, Some(json!({"n": 1})));

        // keyset paging over all events (e2/e3 share a timestamp: id DESC)
        let all = s
            .list_dlp_events(EventFilter::default(), 50, Page::default())
            .await
            .unwrap();
        assert_eq!(all.len(), 3);
        let p1 = s
            .list_dlp_events(EventFilter::default(), 1, Page::default())
            .await
            .unwrap();
        let p2 = s
            .list_dlp_events(
                EventFilter::default(),
                5,
                Page {
                    before: Some(p1[0].at),
                    before_id: p1[0].id.clone(),
                },
            )
            .await
            .unwrap();
        let mut seen: Vec<String> = p1.iter().chain(p2.iter()).map(|e| e.id.clone()).collect();
        assert_eq!(seen, all.iter().map(|e| e.id.clone()).collect::<Vec<_>>());
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 3);

        // prune events older than 24h -> drops e1
        let n = s
            .prune_audit_events(Utc::now() - Duration::hours(24))
            .await
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            s.list_dlp_events(EventFilter::default(), 50, Page::default())
                .await
                .unwrap()
                .len(),
            2
        );
        db.drop().await;
    }

    #[tokio::test]
    async fn admin_actions_record_and_list() {
        let Some(db) = TestDb::new().await else {
            return;
        };
        let s = &db.store;
        let base = Utc::now();
        for i in 0..3i64 {
            s.record_admin_action(AdminAction {
                id: format!("x{i}"),
                at: base + Duration::seconds(i),
                actor: "admin".into(),
                action: "release".into(),
                target: format!("h{i}"),
                detail: String::new(),
                source: "portal".into(),
                result: "ok".into(),
            })
            .await
            .unwrap();
        }
        let all = s.list_admin_actions(50, Page::default()).await.unwrap();
        assert_eq!(
            all.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            vec!["x2", "x1", "x0"]
        );
        assert_eq!(all[0].target, "h2");
        let rest = s
            .list_admin_actions(
                50,
                Page {
                    before: Some(all[0].at),
                    before_id: all[0].id.clone(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            rest.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            vec!["x1", "x0"]
        );
        db.drop().await;
    }
}
