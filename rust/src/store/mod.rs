//! Persistence interface for the gateway. Port of the Go `internal/store`.
//! `Store` is the async trait implemented by the in-memory store (here) and,
//! later, the Postgres store. Keyset pagination orders by (time DESC, id DESC).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value as Json;

use crate::model::{
    AdminAction, Attachment, DlpEvent, DownloadEvent, Hold, HoldStatus, Message, Status,
};

pub mod memory;
pub mod postgres;
pub use memory::Memory;

/// Store error.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    NotFound,
    Conflict,
    Other(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NotFound => write!(f, "store: not found"),
            StoreError::Conflict => write!(f, "store: state conflict"),
            StoreError::Other(e) => write!(f, "store: {e}"),
        }
    }
}
impl std::error::Error for StoreError {}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Narrows a DLP event listing. Empty fields match anything.
#[derive(Clone, Debug, Default)]
pub struct EventFilter {
    pub action: String,
    pub severity: String,
}

/// Keyset pagination cursor. Rows are ordered (time DESC, id DESC); a set cursor
/// returns only rows strictly before this position.
#[derive(Clone, Debug, Default)]
pub struct Page {
    pub before: Option<DateTime<Utc>>,
    pub before_id: String,
}

impl Page {
    pub fn set(&self) -> bool {
        self.before.is_some()
    }
}

/// The persistence interface.
#[async_trait]
pub trait Store: Send + Sync {
    async fn ping(&self) -> Result<()>;

    /// Inserts a message and its attachments atomically. A duplicate message
    /// or attachment id is a `Conflict` and inserts nothing.
    async fn create_message(&self, m: &Message, atts: &[Attachment]) -> Result<()>;
    async fn get_message(&self, id: &str) -> Result<Message>;
    async fn get_attachment(&self, id: &str) -> Result<Attachment>;
    async fn get_attachment_by_token_hash(&self, h: &str) -> Result<Attachment>;
    async fn set_verdict(
        &self,
        id: &str,
        status: Status,
        threat: &str,
        detail: Option<Json>,
        at: DateTime<Utc>,
    ) -> Result<()>;
    async fn find_reusable_verdict(&self, sha256: &str, since: DateTime<Utc>)
        -> Result<Attachment>;
    /// Bumps attempts/queued_at of a still-PENDING attachment. `Conflict` when
    /// a verdict landed meanwhile (the caller must not enqueue it again).
    async fn mark_requeued(&self, id: &str, at: DateTime<Utc>) -> Result<()>;
    async fn record_download(&self, ev: DownloadEvent) -> Result<()>;
    /// PENDING attachments queued before `older_than`, oldest `queued_at` first.
    async fn list_stale_pending(
        &self,
        older_than: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<Attachment>>;
    /// Non-EXPIRED attachments past `expires_at`, oldest `expires_at` first.
    async fn list_expired(&self, now: DateTime<Utc>, limit: usize) -> Result<Vec<Attachment>>;
    async fn mark_expired(&self, id: &str, at: DateTime<Utc>) -> Result<()>;

    async fn create_hold(&self, h: &Hold) -> Result<()>;
    async fn get_hold(&self, id: &str) -> Result<Hold>;
    async fn get_hold_by_token_hash(&self, th: &str) -> Result<Hold>;
    async fn list_holds(
        &self,
        status: Option<HoldStatus>,
        limit: usize,
        page: Page,
    ) -> Result<Vec<Hold>>;
    /// Moves a HELD hold to `status`. `Conflict` when it is no longer HELD, or
    /// (for RELEASED) when it is already past `expires_at`.
    async fn decide_hold(
        &self,
        id: &str,
        status: HoldStatus,
        by: &str,
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<()>;
    async fn reopen_hold(&self, id: &str) -> Result<()>;
    /// Overwrites the decision reason of an already-decided hold (e.g. to flag
    /// a release whose relay outcome is unknown).
    async fn set_hold_reason(&self, id: &str, reason: &str) -> Result<()>;
    async fn list_expired_holds(&self, now: DateTime<Utc>, limit: usize) -> Result<Vec<Hold>>;

    async fn record_dlp_event(&self, ev: &DlpEvent) -> Result<()>;
    async fn list_dlp_events(
        &self,
        filter: EventFilter,
        limit: usize,
        page: Page,
    ) -> Result<Vec<DlpEvent>>;
    async fn prune_audit_events(&self, cutoff: DateTime<Utc>) -> Result<i64>;

    async fn record_admin_action(&self, a: AdminAction) -> Result<()>;
    async fn list_admin_actions(&self, limit: usize, page: Page) -> Result<Vec<AdminAction>>;
}

/// Orders by (time DESC, id DESC): row (a) sorts before (b).
pub(crate) fn before_key(
    at: DateTime<Utc>,
    aid: &str,
    bt: DateTime<Utc>,
    bid: &str,
) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    if at == bt {
        bid.cmp(aid) // id DESC
    } else if at > bt {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// Reports whether (t,id) belongs on a page strictly after `page`.
pub(crate) fn after_cursor(t: DateTime<Utc>, id: &str, page: &Page) -> bool {
    match page.before {
        None => true,
        Some(b) if t == b => id < page.before_id.as_str(),
        Some(b) => t < b,
    }
}
