//! In-memory [`Store`] implementation. Port of the Go `internal/store` Memory.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value as Json;

use super::{after_cursor, before_key, EventFilter, Page, Result, Store, StoreError};
use crate::model::{AdminAction, Attachment, DlpEvent, DownloadEvent, Hold, HoldStatus, Message, Status};

#[derive(Default)]
struct Inner {
    messages: HashMap<String, Message>,
    atts: HashMap<String, Attachment>,
    by_token: HashMap<String, String>,
    downloads: Vec<DownloadEvent>,
    holds: HashMap<String, Hold>,
    dlp_events: Vec<DlpEvent>,
    admin_actions: Vec<AdminAction>,
}

/// Thread-safe in-memory store.
#[derive(Default)]
pub struct Memory {
    inner: Mutex<Inner>,
}

impl Memory {
    pub fn new() -> Self {
        Memory::default()
    }

    /// Number of recorded download events (tests).
    pub fn download_count(&self) -> usize {
        self.inner.lock().unwrap().downloads.len()
    }
}

#[async_trait]
impl Store for Memory {
    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn create_message(&self, m: &Message, atts: &[Attachment]) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.messages.insert(m.id.clone(), m.clone());
        for a in atts {
            g.by_token.insert(a.token_hash.clone(), a.id.clone());
            g.atts.insert(a.id.clone(), a.clone());
        }
        Ok(())
    }

    async fn get_message(&self, id: &str) -> Result<Message> {
        self.inner.lock().unwrap().messages.get(id).cloned().ok_or(StoreError::NotFound)
    }

    async fn get_attachment(&self, id: &str) -> Result<Attachment> {
        self.inner.lock().unwrap().atts.get(id).cloned().ok_or(StoreError::NotFound)
    }

    async fn get_attachment_by_token_hash(&self, h: &str) -> Result<Attachment> {
        let g = self.inner.lock().unwrap();
        let id = g.by_token.get(h).ok_or(StoreError::NotFound)?;
        g.atts.get(id).cloned().ok_or(StoreError::NotFound)
    }

    async fn set_verdict(
        &self,
        id: &str,
        status: Status,
        threat: &str,
        detail: Option<Json>,
        at: DateTime<Utc>,
    ) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let a = g.atts.get_mut(id).ok_or(StoreError::NotFound)?;
        if a.status != Status::Pending {
            return Err(StoreError::Conflict);
        }
        a.status = status;
        a.threat_name = threat.to_string();
        a.verdict_detail = detail;
        a.analyzed_at = Some(at);
        a.updated_at = at;
        Ok(())
    }

    async fn find_reusable_verdict(&self, sha256: &str, since: DateTime<Utc>) -> Result<Attachment> {
        let g = self.inner.lock().unwrap();
        let mut best: Option<&Attachment> = None;
        for a in g.atts.values() {
            let analyzed = match a.analyzed_at {
                Some(t) if t >= since => t,
                _ => continue,
            };
            if a.sha256 != sha256 {
                continue;
            }
            if a.status != Status::Clean && a.status != Status::Malicious {
                continue;
            }
            if best.map(|b| analyzed > b.analyzed_at.unwrap()).unwrap_or(true) {
                best = Some(a);
            }
        }
        best.cloned().ok_or(StoreError::NotFound)
    }

    async fn mark_requeued(&self, id: &str, at: DateTime<Utc>) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let a = g.atts.get_mut(id).ok_or(StoreError::NotFound)?;
        a.attempts += 1;
        a.queued_at = at;
        a.updated_at = at;
        Ok(())
    }

    async fn record_download(&self, ev: DownloadEvent) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let a = g.atts.get_mut(&ev.attachment_id).ok_or(StoreError::NotFound)?;
        a.download_count += 1;
        a.last_downloaded_at = Some(ev.at);
        g.downloads.push(ev);
        Ok(())
    }

    async fn list_stale_pending(&self, older_than: DateTime<Utc>, limit: usize) -> Result<Vec<Attachment>> {
        let g = self.inner.lock().unwrap();
        Ok(att_list(&g, limit, |a| a.status == Status::Pending && a.queued_at < older_than))
    }

    async fn list_expired(&self, now: DateTime<Utc>, limit: usize) -> Result<Vec<Attachment>> {
        let g = self.inner.lock().unwrap();
        Ok(att_list(&g, limit, |a| a.status != Status::Expired && a.expires_at < now))
    }

    async fn mark_expired(&self, id: &str, at: DateTime<Utc>) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let a = g.atts.get_mut(id).ok_or(StoreError::NotFound)?;
        a.status = Status::Expired;
        a.updated_at = at;
        Ok(())
    }

    async fn create_hold(&self, h: &Hold) -> Result<()> {
        self.inner.lock().unwrap().holds.insert(h.id.clone(), h.clone());
        Ok(())
    }

    async fn get_hold(&self, id: &str) -> Result<Hold> {
        self.inner.lock().unwrap().holds.get(id).cloned().ok_or(StoreError::NotFound)
    }

    async fn get_hold_by_token_hash(&self, th: &str) -> Result<Hold> {
        let g = self.inner.lock().unwrap();
        g.holds.values().find(|h| h.token_hash == th).cloned().ok_or(StoreError::NotFound)
    }

    async fn list_holds(&self, status: Option<HoldStatus>, limit: usize, page: Page) -> Result<Vec<Hold>> {
        let g = self.inner.lock().unwrap();
        Ok(hold_list(&g, limit, |h| {
            status.map(|s| h.status == s).unwrap_or(true) && after_cursor(h.created_at, &h.id, &page)
        }))
    }

    async fn decide_hold(
        &self,
        id: &str,
        status: HoldStatus,
        by: &str,
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let h = g.holds.get_mut(id).ok_or(StoreError::NotFound)?;
        if h.status != HoldStatus::Held {
            return Err(StoreError::Conflict);
        }
        h.status = status;
        h.decided_by = by.to_string();
        h.reason = reason.to_string();
        h.decided_at = Some(at);
        Ok(())
    }

    async fn reopen_hold(&self, id: &str) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let h = g.holds.get_mut(id).ok_or(StoreError::NotFound)?;
        if h.status != HoldStatus::Released {
            return Err(StoreError::Conflict);
        }
        h.status = HoldStatus::Held;
        h.decided_by.clear();
        h.reason.clear();
        h.decided_at = None;
        Ok(())
    }

    async fn list_expired_holds(&self, now: DateTime<Utc>, limit: usize) -> Result<Vec<Hold>> {
        let g = self.inner.lock().unwrap();
        Ok(hold_list(&g, limit, |h| h.status == HoldStatus::Held && h.expires_at < now))
    }

    async fn record_dlp_event(&self, ev: &DlpEvent) -> Result<()> {
        self.inner.lock().unwrap().dlp_events.push(ev.clone());
        Ok(())
    }

    async fn list_dlp_events(&self, filter: EventFilter, limit: usize, page: Page) -> Result<Vec<DlpEvent>> {
        let g = self.inner.lock().unwrap();
        let mut all: Vec<DlpEvent> = g
            .dlp_events
            .iter()
            .filter(|e| {
                (filter.action.is_empty() || e.action == filter.action)
                    && (filter.severity.is_empty() || e.severity == filter.severity)
                    && after_cursor(e.at, &e.id, &page)
            })
            .cloned()
            .collect();
        all.sort_by(|a, b| before_key(a.at, &a.id, b.at, &b.id));
        all.truncate(limit);
        Ok(all)
    }

    async fn prune_audit_events(&self, cutoff: DateTime<Utc>) -> Result<i64> {
        let mut g = self.inner.lock().unwrap();
        let before = g.dlp_events.len() + g.downloads.len();
        g.dlp_events.retain(|e| e.at >= cutoff);
        g.downloads.retain(|e| e.at >= cutoff);
        let after = g.dlp_events.len() + g.downloads.len();
        Ok((before - after) as i64)
    }

    async fn record_admin_action(&self, a: AdminAction) -> Result<()> {
        self.inner.lock().unwrap().admin_actions.push(a);
        Ok(())
    }

    async fn list_admin_actions(&self, limit: usize, page: Page) -> Result<Vec<AdminAction>> {
        let g = self.inner.lock().unwrap();
        let mut all: Vec<AdminAction> = g
            .admin_actions
            .iter()
            .filter(|a| after_cursor(a.at, &a.id, &page))
            .cloned()
            .collect();
        all.sort_by(|a, b| before_key(a.at, &a.id, b.at, &b.id));
        all.truncate(limit);
        Ok(all)
    }
}

fn att_list(g: &Inner, limit: usize, keep: impl Fn(&Attachment) -> bool) -> Vec<Attachment> {
    let mut out: Vec<Attachment> = g.atts.values().filter(|a| keep(a)).cloned().collect();
    out.sort_by_key(|a| a.created_at);
    out.truncate(limit);
    out
}

fn hold_list(g: &Inner, limit: usize, keep: impl Fn(&Hold) -> bool) -> Vec<Hold> {
    let mut out: Vec<Hold> = g.holds.values().filter(|h| keep(h)).cloned().collect();
    out.sort_by(|a, b| before_key(a.created_at, &a.id, b.created_at, &b.id));
    out.truncate(limit);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn att(id: &str, status: Status) -> Attachment {
        let now = Utc::now();
        Attachment {
            id: id.into(),
            message_id: "m1".into(),
            filename: "a.pdf".into(),
            content_type: "application/pdf".into(),
            size: 10,
            sha256: "deadbeef".into(),
            storage_key: "k".into(),
            token_hash: format!("tok-{id}"),
            status,
            threat_name: String::new(),
            verdict_detail: None,
            attempts: 0,
            created_at: now,
            updated_at: now,
            queued_at: now,
            analyzed_at: None,
            expires_at: now + Duration::hours(1),
            download_count: 0,
            last_downloaded_at: None,
        }
    }

    #[tokio::test]
    async fn verdict_lifecycle() {
        let s = Memory::new();
        let m = Message { id: "m1".into(), ..Default::default() };
        s.create_message(&m, &[att("a1", Status::Pending)]).await.unwrap();
        assert_eq!(s.get_attachment("a1").await.unwrap().status, Status::Pending);
        // by token
        assert_eq!(s.get_attachment_by_token_hash("tok-a1").await.unwrap().id, "a1");
        // set verdict
        s.set_verdict("a1", Status::Clean, "", None, Utc::now()).await.unwrap();
        assert_eq!(s.get_attachment("a1").await.unwrap().status, Status::Clean);
        // second verdict conflicts (not pending any more)
        assert_eq!(s.set_verdict("a1", Status::Malicious, "x", None, Utc::now()).await, Err(StoreError::Conflict));
        assert_eq!(s.get_attachment("missing").await.err(), Some(StoreError::NotFound));
    }

    #[tokio::test]
    async fn hold_decision_and_keyset() {
        let s = Memory::new();
        let base = Utc::now();
        for i in 0..3u32 {
            let h = Hold {
                id: format!("h{i}"),
                token_hash: format!("t{i}"),
                mail_from: "a@x".into(),
                rcpt_to: vec!["b@y".into()],
                subject: "s".into(),
                storage_key: "k".into(),
                size: 1,
                findings: None,
                status: HoldStatus::Held,
                created_at: base + Duration::minutes(i as i64),
                expires_at: base + Duration::hours(1),
                decided_at: None,
                decided_by: String::new(),
                reason: String::new(),
            };
            s.create_hold(&h).await.unwrap();
        }
        let held = s.list_holds(Some(HoldStatus::Held), 50, Page::default()).await.unwrap();
        assert_eq!(held.len(), 3);
        // newest first
        assert_eq!(held[0].id, "h2");
        // decide one
        s.decide_hold("h1", HoldStatus::Rejected, "sec", "no", Utc::now()).await.unwrap();
        assert_eq!(s.decide_hold("h1", HoldStatus::Released, "x", "", Utc::now()).await, Err(StoreError::Conflict));
        assert_eq!(s.get_hold("h1").await.unwrap().status, HoldStatus::Rejected);
        // keyset paging: first page of 2, then the rest
        let page1 = s.list_holds(None, 2, Page::default()).await.unwrap();
        assert_eq!(page1.len(), 2);
        let last = &page1[1];
        let page2 = s
            .list_holds(None, 2, Page { before: Some(last.created_at), before_id: last.id.clone() })
            .await
            .unwrap();
        assert_eq!(page2.len(), 1);
        assert_eq!(page2[0].id, "h0");
    }

    #[tokio::test]
    async fn dlp_events_filter_prune_and_admin() {
        let s = Memory::new();
        let old = Utc::now() - Duration::hours(48);
        let recent = Utc::now();
        s.record_dlp_event(&DlpEvent {
            id: "e1".into(), mail_from: "a".into(), rcpt_to: vec![], subject: "s".into(),
            action: "block".into(), severity: "high".into(), findings: None, hold_id: String::new(), at: old,
        }).await.unwrap();
        s.record_dlp_event(&DlpEvent {
            id: "e2".into(), mail_from: "a".into(), rcpt_to: vec![], subject: "s".into(),
            action: "notify".into(), severity: "low".into(), findings: None, hold_id: String::new(), at: recent,
        }).await.unwrap();
        let blocked = s.list_dlp_events(EventFilter { action: "block".into(), ..Default::default() }, 50, Page::default()).await.unwrap();
        assert_eq!(blocked.len(), 1);
        // prune events older than 24h -> drops e1
        let n = s.prune_audit_events(Utc::now() - Duration::hours(24)).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(s.list_dlp_events(EventFilter::default(), 50, Page::default()).await.unwrap().len(), 1);
        // admin actions
        s.record_admin_action(AdminAction {
            id: "x1".into(), at: Utc::now(), actor: "admin".into(), action: "release".into(),
            target: "h0".into(), detail: String::new(), source: "portal".into(), result: "ok".into(),
        }).await.unwrap();
        assert_eq!(s.list_admin_actions(50, Page::default()).await.unwrap().len(), 1);
    }
}
