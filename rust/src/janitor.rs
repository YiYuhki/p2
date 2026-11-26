//! Background workers and adapters that tie the services together. Port of the
//! Go `Service.ResultHandler`/`ApplyVerdict`, `Service.Janitor`/`SweepOnce`,
//! the outbound hold janitor, `notify.SMTPSender`, and the release path of the
//! DLP review (a released hold is relayed to the outbound next hop).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use chrono::{DateTime, Utc};

use crate::metrics::Metrics;
use crate::model::{Attachment, HoldStatus, Job, JobObject, Status, Verdict};
use crate::queue::{HandlerError, Priority, Queue, ResultHandler};
use crate::smtpclient::Options as SmtpOptions;
use crate::storage::Storage;
use crate::store::{Store, StoreError};

const MAX_DETAIL_BYTES: usize = 64 << 10;

/// Strips control characters and truncates to 256 bytes on a char boundary.
pub fn sanitize_threat_name(s: &str) -> String {
    let mut out: String = s.chars().filter(|&c| !(c < ' ' || c == '\u{7f}')).collect();
    if out.len() > 256 {
        let mut i = 256;
        while !out.is_char_boundary(i) {
            i -= 1;
        }
        out.truncate(i);
    }
    out
}

/// Sends a plain UTF-8 notice mail via the upstream relay.
pub struct SmtpMailer {
    opts: SmtpOptions,
    from: String,
    display_name: String,
}

impl SmtpMailer {
    pub fn new(opts: SmtpOptions, from: &str, display_name: &str) -> Self {
        SmtpMailer {
            opts,
            from: from.to_string(),
            display_name: display_name.to_string(),
        }
    }

    /// Builds the RFC 5322 message (base64 UTF-8 body, RFC 2047 subject).
    pub fn build(&self, to: &[String], subject: &str, body: &str, now: DateTime<Utc>) -> Vec<u8> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let enc = |s: &str| format!("=?UTF-8?B?{}?=", b64.encode(s));
        let domain = self
            .from
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or("localhost");
        let from = if self.display_name.is_empty() {
            format!("<{}>", self.from)
        } else {
            format!("{} <{}>", enc(&self.display_name), self.from)
        };
        let body = b64.encode(body.replace("\r\n", "\n").replace('\n', "\r\n"));
        let wrapped: Vec<&str> = body
            .as_bytes()
            .chunks(76)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "From: {from}\r\nTo: {}\r\nSubject: {}\r\nDate: {}\r\nMessage-ID: <{}@{domain}>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\nAuto-Submitted: auto-generated\r\n\r\n{}\r\n",
            to.join(", "),
            enc(subject),
            now.format("%a, %d %b %Y %H:%M:%S +0000"),
            uuid::Uuid::new_v4(),
            wrapped.join("\r\n")
        )
        .into_bytes()
    }

    pub async fn send_to(&self, to: &[String], subject: &str, body: &str) -> Result<(), String> {
        if self.from.is_empty() {
            return Err("mailer: no sender address configured".into());
        }
        let msg = self.build(to, subject, body, Utc::now());
        crate::smtpclient::send(&self.opts, &self.from, to, &msg)
            .await
            .map_err(|e| e.to_string())
    }
}

#[async_trait]
impl crate::portal::Mailer for SmtpMailer {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        self.send_to(&[to.to_string()], subject, body).await
    }
}

/// Applies analyzer verdicts (queue consumer), optionally notifying the
/// original recipients once a final CLEAN/MALICIOUS verdict lands.
pub struct VerdictHandler {
    store: Arc<dyn Store>,
    metrics: Arc<Metrics>,
    notifier: Option<Arc<SmtpMailer>>,
}

impl VerdictHandler {
    pub fn new(store: Arc<dyn Store>, metrics: Arc<Metrics>) -> Self {
        VerdictHandler {
            store,
            metrics,
            notifier: None,
        }
    }

    pub fn with_notifier(mut self, n: Arc<SmtpMailer>) -> Self {
        self.notifier = Some(n);
        self
    }

    /// Attaches a notifier built by `make` when `enabled`.
    pub fn with_notifier_opt(self, enabled: bool, make: impl FnOnce() -> Arc<SmtpMailer>) -> Self {
        if enabled {
            self.with_notifier(make())
        } else {
            self
        }
    }

    /// Validates and records a verdict.
    pub async fn apply(&self, v: &Verdict) -> Result<(), HandlerError> {
        if uuid::Uuid::parse_str(&v.attachment_id).is_err() {
            return Err(HandlerError::Permanent("bad attachment_id".into()));
        }
        if !matches!(v.status, Status::Clean | Status::Malicious | Status::Error) {
            return Err(HandlerError::Permanent(
                "status must be CLEAN, MALICIOUS or ERROR".into(),
            ));
        }
        if let Some(d) = &v.detail {
            if serde_json::to_vec(d).map(|b| b.len()).unwrap_or(0) > MAX_DETAIL_BYTES {
                return Err(HandlerError::Permanent("detail too large".into()));
            }
        }
        let threat = sanitize_threat_name(&v.threat_name);
        match self
            .store
            .set_verdict(
                &v.attachment_id,
                v.status,
                &threat,
                v.detail.clone(),
                Utc::now(),
            )
            .await
        {
            Ok(()) => {
                let label = format!("{:?}", v.status).to_lowercase();
                self.metrics.verdicts.with_label_values(&[&label]).inc();
                self.after_verdict(v, &threat).await;
                Ok(())
            }
            Err(StoreError::Conflict) => Ok(()), // idempotent duplicate
            Err(StoreError::NotFound) => Err(HandlerError::Permanent("unknown attachment".into())),
            Err(e) => Err(HandlerError::Transient(e.to_string())),
        }
    }

    async fn after_verdict(&self, v: &Verdict, threat: &str) {
        let notify =
            self.notifier.is_some() && matches!(v.status, Status::Clean | Status::Malicious);
        if !notify {
            return;
        }
        let (mut filename, mut subject, mut rcpt) = (String::new(), String::new(), Vec::new());
        if let Ok(a) = self.store.get_attachment(&v.attachment_id).await {
            filename = a.filename;
            if let Ok(m) = self.store.get_message(&a.message_id).await {
                subject = m.subject;
                rcpt = m.rcpt_to;
            }
        }
        if let (true, Some(n)) = (notify && !rcpt.is_empty(), &self.notifier) {
            let (subj, body) = if v.status == Status::Malicious {
                (
                    "[보안] 첨부파일이 차단되었습니다".to_string(),
                    format!("받으신 메일({subject:?})의 첨부파일 '{filename}'이(가) 보안 검사에서 위협({threat})으로 판정되어 차단되었습니다.\n해당 파일은 내려받을 수 없습니다. 문의는 보안 담당자에게 연락하세요."),
                )
            } else {
                (
                    "[보안] 첨부파일 검사 완료".to_string(),
                    format!("받으신 메일({subject:?})의 첨부파일 '{filename}'이(가) 보안 검사를 통과했습니다.\n원본 메일 본문의 다운로드 링크에서 파일을 받으실 수 있습니다."),
                )
            };
            let n = n.clone();
            tokio::spawn(async move {
                if let Err(e) = n.send_to(&rcpt, &subj, &body).await {
                    eprintln!("verdict notice send failed: {e}");
                }
            });
        }
    }
}

#[async_trait]
impl ResultHandler for VerdictHandler {
    async fn handle(&self, v: &Verdict) -> Result<(), HandlerError> {
        self.apply(v).await
    }
}

/// Periodic maintenance: re-queue stalled analyses (giving up after
/// `max_attempts`), delete expired attachments, expire undecided DLP holds and
/// prune old audit events.
pub struct Janitor {
    pub store: Arc<dyn Store>,
    pub storage: Arc<dyn Storage>,
    pub queue: Arc<dyn Queue>,
    pub analysis_timeout: Duration,
    pub max_attempts: i32,
    pub audit_retention: Option<Duration>,
}

/// Rebuilds the analysis job for an attachment.
pub fn job_for(a: &Attachment, storage: &dyn Storage) -> Job {
    Job {
        version: 1,
        attachment_id: a.id.clone(),
        message_id: a.message_id.clone(),
        filename: a.filename.clone(),
        content_type: a.content_type.clone(),
        size: a.size,
        sha256: a.sha256.clone(),
        storage: JobObject {
            kind: storage.kind().to_string(),
            bucket: storage.bucket().to_string(),
            key: a.storage_key.clone(),
        },
        content_url: String::new(),
        verdict_url: String::new(),
        attempt: a.attempts,
        enqueued_at: Utc::now(),
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepStats {
    pub requeued: usize,
    pub gave_up: usize,
    pub expired: usize,
    pub holds_expired: usize,
    pub pruned: i64,
}

impl Janitor {
    pub async fn sweep_once(&self, now: DateTime<Utc>) -> SweepStats {
        let mut st = SweepStats::default();
        let timeout = chrono::Duration::from_std(self.analysis_timeout)
            .unwrap_or(chrono::Duration::minutes(10));
        if let Ok(stale) = self.store.list_stale_pending(now - timeout, 500).await {
            for mut a in stale {
                if a.attempts >= self.max_attempts {
                    let detail =
                        serde_json::json!({"reason": "analysis timeout", "attempts": a.attempts});
                    match self
                        .store
                        .set_verdict(&a.id, Status::Error, "", Some(detail), now)
                        .await
                    {
                        Ok(()) | Err(StoreError::Conflict) => st.gave_up += 1,
                        Err(e) => eprintln!("janitor: mark error {}: {e}", a.id),
                    }
                    continue;
                }
                match self.store.mark_requeued(&a.id, now).await {
                    Ok(()) => {}
                    // A verdict landed since the listing: nothing to re-queue.
                    Err(StoreError::Conflict) => continue,
                    Err(e) => {
                        eprintln!("janitor: requeue {}: {e}", a.id);
                        continue;
                    }
                }
                a.attempts += 1;
                match self
                    .queue
                    .enqueue(job_for(&a, self.storage.as_ref()), Priority::Normal)
                    .await
                {
                    Ok(()) => st.requeued += 1,
                    Err(e) => eprintln!("janitor: enqueue {}: {e}", a.id),
                }
            }
        }
        if let Ok(expired) = self.store.list_expired(now, 500).await {
            for a in expired {
                if let Err(e) = self.storage.delete(&a.storage_key).await {
                    eprintln!("janitor: delete object {}: {e}", a.id);
                    continue;
                }
                if self.store.mark_expired(&a.id, now).await.is_ok() {
                    st.expired += 1;
                }
            }
        }
        if let Ok(holds) = self.store.list_expired_holds(now, 500).await {
            for h in holds {
                if self
                    .store
                    .decide_hold(&h.id, HoldStatus::Expired, "system", "hold expired", now)
                    .await
                    .is_ok()
                {
                    let _ = self.storage.delete(&h.storage_key).await;
                    st.holds_expired += 1;
                }
            }
        }
        if let Some(r) = self.audit_retention.filter(|d| !d.is_zero()) {
            let cutoff = now - chrono::Duration::from_std(r).unwrap_or(chrono::Duration::days(365));
            match self.store.prune_audit_events(cutoff).await {
                Ok(n) => st.pruned = n,
                Err(e) => eprintln!("janitor: prune audit events: {e}"),
            }
        }
        st
    }

    /// Sweeps every `interval` until `shutdown` turns true.
    pub async fn run(self, interval: Duration, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let interval = if interval.is_zero() {
            Duration::from_secs(60)
        } else {
            interval
        };
        loop {
            self.sweep_once(Utc::now()).await;
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                r = shutdown.changed() => { if r.is_err() || *shutdown.borrow() { return; } }
            }
        }
    }
}

/// Reason recorded on a RELEASED hold whose relay may or may not have landed.
pub const RELAY_UNKNOWN: &str = "relay result unknown";

/// Outcome of relaying one message.
#[derive(Debug)]
pub enum RelayOutcome {
    Delivered,
    /// Failed before the next hop could have accepted the message.
    NotSent(String),
    /// Failed during or after DATA without a definite SMTP rejection: the
    /// next hop may have accepted (and will deliver) the message.
    Unknown(String),
}

/// Relays a message, classifying failures by whether the message may have
/// been accepted. QUIT errors are ignored (the message was already accepted).
pub async fn relay(opts: &SmtpOptions, from: &str, to: &[String], msg: &[u8]) -> RelayOutcome {
    use crate::smtpclient::{Client, Error};
    let mut c = match Client::dial(opts).await {
        Ok(c) => c,
        Err(e) => return RelayOutcome::NotSent(e.to_string()),
    };
    if let Err(e) = c.mail(from).await {
        return RelayOutcome::NotSent(e.to_string());
    }
    for t in to {
        if let Err(e) = c.rcpt(t).await {
            return RelayOutcome::NotSent(e.to_string());
        }
    }
    match c.data(msg).await {
        Ok(()) => {
            let _ = c.quit().await;
            RelayOutcome::Delivered
        }
        // An SMTP reply code (DATA refused, or the final reply after the
        // message was a 4xx/5xx) is a definite "not accepted".
        Err(e @ Error::Smtp { .. }) => RelayOutcome::NotSent(e.to_string()),
        // A transport error mid-DATA (or while waiting for the final reply)
        // leaves the outcome unknown.
        Err(e @ Error::Transport(_)) => RelayOutcome::Unknown(e.to_string()),
    }
}

/// DLP review decisions that relay a released hold to the outbound next hop.
pub struct RelayHoldReviewer {
    store: Arc<dyn Store>,
    storage: Arc<dyn Storage>,
    next_hop: SmtpOptions,
}

impl RelayHoldReviewer {
    pub fn new(store: Arc<dyn Store>, storage: Arc<dyn Storage>, next_hop: SmtpOptions) -> Self {
        RelayHoldReviewer {
            store,
            storage,
            next_hop,
        }
    }
}

#[async_trait]
impl crate::portal::HoldReviewer for RelayHoldReviewer {
    async fn release(&self, id: &str, by: &str) -> Result<(), StoreError> {
        let h = self.store.get_hold(id).await?;
        if h.status != HoldStatus::Held {
            return Err(StoreError::Conflict);
        }
        let raw = self
            .storage
            .get(&h.storage_key)
            .await
            .map_err(|e| StoreError::Other(format!("load held message: {e}")))?;
        // Claim first so two reviewers cannot both relay; undo on failure.
        self.store
            .decide_hold(id, HoldStatus::Released, by, "", Utc::now())
            .await?;
        match relay(&self.next_hop, &h.mail_from, &h.rcpt_to, &raw).await {
            RelayOutcome::Delivered => {
                let _ = self.storage.delete(&h.storage_key).await;
                Ok(())
            }
            RelayOutcome::NotSent(e) => {
                let _ = self.store.reopen_hold(id).await;
                Err(StoreError::Other(format!("relay released message: {e}")))
            }
            RelayOutcome::Unknown(e) => {
                // The message may already have been accepted: never reopen
                // (a second release would duplicate it). Keep RELEASED, flag
                // it, and keep the stored copy for manual follow-up.
                eprintln!("janitor: relay result unknown for hold {id}: {e}");
                let _ = self.store.set_hold_reason(id, RELAY_UNKNOWN).await;
                Err(StoreError::Other(format!("{RELAY_UNKNOWN}: {e}")))
            }
        }
    }

    async fn reject(&self, id: &str, by: &str, reason: &str) -> Result<(), StoreError> {
        let h = self.store.get_hold(id).await?;
        self.store
            .decide_hold(id, HoldStatus::Rejected, by, reason, Utc::now())
            .await?;
        let _ = self.storage.delete(&h.storage_key).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Hold;
    use crate::portal::HoldReviewer;
    use crate::storage::Fs;
    use crate::store::Memory;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    async fn deps() -> (Arc<Memory>, Arc<dyn Storage>, Arc<crate::queue::Memory>) {
        let dir = std::env::temp_dir().join(format!("secmail-jan-{}", uuid::Uuid::new_v4()));
        (
            Arc::new(Memory::new()),
            Arc::new(Fs::new(dir.to_str().unwrap()).await.unwrap()),
            Arc::new(crate::queue::Memory::new()),
        )
    }

    fn att(id: &str, created: DateTime<Utc>, attempts: i32, expires: DateTime<Utc>) -> Attachment {
        Attachment {
            id: id.into(),
            message_id: "m1".into(),
            filename: "a.pdf".into(),
            content_type: "application/pdf".into(),
            size: 3,
            sha256: "x".into(),
            storage_key: format!("k/{id}"),
            token_hash: format!("t{id}"),
            status: Status::Pending,
            threat_name: String::new(),
            verdict_detail: None,
            attempts,
            created_at: created,
            updated_at: created,
            queued_at: created,
            analyzed_at: None,
            expires_at: expires,
            download_count: 0,
            last_downloaded_at: None,
        }
    }

    fn msg() -> crate::model::Message {
        crate::model::Message {
            id: "m1".into(),
            message_id: String::new(),
            mail_from: "a@x.org".into(),
            rcpt_to: vec!["b@corp.test".into()],
            subject: "s".into(),
            remote_addr: String::new(),
            received_at: None,
            attachment_count: 2,
        }
    }

    #[tokio::test]
    async fn verdict_handler_classifies() {
        let (store, _s, _q) = deps().await;
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        store
            .create_message(&msg(), &[att(&id, now, 1, now + chrono::Duration::days(1))])
            .await
            .unwrap();
        let h = VerdictHandler::new(store.clone(), Arc::new(Metrics::new()));
        let v = |s: Status| Verdict {
            attachment_id: id.clone(),
            status: s,
            threat_name: "Eicar\u{7}".into(),
            detail: None,
        };
        assert!(matches!(
            h.apply(&v(Status::Pending)).await,
            Err(HandlerError::Permanent(_))
        ));
        h.apply(&v(Status::Malicious)).await.unwrap();
        assert_eq!(
            store.get_attachment(&id).await.unwrap().threat_name,
            "Eicar"
        );
        h.apply(&v(Status::Clean)).await.unwrap(); // duplicate → ignored
        assert_eq!(
            store.get_attachment(&id).await.unwrap().status,
            Status::Malicious
        );
        let unknown = Verdict {
            attachment_id: uuid::Uuid::new_v4().to_string(),
            status: Status::Clean,
            threat_name: String::new(),
            detail: None,
        };
        assert!(matches!(
            h.apply(&unknown).await,
            Err(HandlerError::Permanent(_))
        ));
    }

    #[tokio::test]
    async fn sweep_requeues_gives_up_and_expires() {
        let (store, storage, queue) = deps().await;
        let now = Utc::now();
        let old = now - chrono::Duration::hours(1);
        let far = now + chrono::Duration::days(1);
        store
            .create_message(
                &msg(),
                &[
                    att("a1", old, 1, far),
                    att("a2", old, 3, far),
                    att("a3", old, 1, now - chrono::Duration::seconds(1)),
                ],
            )
            .await
            .unwrap();
        storage.put("k/a3", b"zzz").await.unwrap();
        let j = Janitor {
            store: store.clone(),
            storage: storage.clone(),
            queue: queue.clone(),
            analysis_timeout: Duration::from_secs(600),
            max_attempts: 3,
            audit_retention: None,
        };
        let st = j.sweep_once(now).await;
        assert_eq!(st.gave_up, 1);
        assert_eq!(
            store.get_attachment("a2").await.unwrap().status,
            Status::Error
        );
        assert!(st.requeued >= 1);
        assert!(queue
            .snapshot()
            .iter()
            .any(|j| j.attachment_id == "a1" && j.attempt == 2));
        assert_eq!(st.expired, 1);
        assert!(storage.get("k/a3").await.is_err());
    }

    /// Minimal SMTP sink recording the DATA payload.
    async fn sink() -> (String, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut c = BufReader::new(s);
            c.write_all(b"220 sink\r\n").await.unwrap();
            let mut tx = Some(tx);
            loop {
                let mut line = String::new();
                if c.read_line(&mut line).await.unwrap_or(0) == 0 {
                    break;
                }
                let up = line.to_ascii_uppercase();
                if up.starts_with("DATA") {
                    c.write_all(b"354 go\r\n").await.unwrap();
                    let d = crate::smtpclient::read_data(&mut c, 0).await.unwrap();
                    if let Some(t) = tx.take() {
                        let _ = t.send(d);
                    }
                    c.write_all(b"250 ok\r\n").await.unwrap();
                } else if up.starts_with("QUIT") {
                    c.write_all(b"221 bye\r\n").await.unwrap();
                    break;
                } else {
                    c.write_all(b"250 ok\r\n").await.unwrap();
                }
            }
        });
        (addr, rx)
    }

    fn hold(id: &str) -> Hold {
        let now = Utc::now();
        Hold {
            id: id.into(),
            token_hash: format!("th{id}"),
            mail_from: "alice@corp.test".into(),
            rcpt_to: vec!["ext@partner.example".into()],
            subject: "q".into(),
            storage_key: format!("holds/{id}"),
            size: 10,
            findings: None,
            status: HoldStatus::Held,
            created_at: now,
            expires_at: now + chrono::Duration::days(1),
            decided_at: None,
            decided_by: String::new(),
            reason: String::new(),
        }
    }

    #[tokio::test]
    async fn release_relays_and_failure_reopens() {
        let (store, storage, _q) = deps().await;
        store.create_hold(&hold("h1")).await.unwrap();
        storage
            .put("holds/h1", b"Subject: q\r\n\r\nbody\r\n")
            .await
            .unwrap();
        let (addr, rx) = sink().await;
        let r = RelayHoldReviewer::new(
            store.clone(),
            storage.clone(),
            SmtpOptions {
                addr,
                ..Default::default()
            },
        );
        r.release("h1", "admin@corp.test").await.unwrap();
        assert_eq!(rx.await.unwrap(), b"Subject: q\r\n\r\nbody\r\n");
        assert_eq!(
            store.get_hold("h1").await.unwrap().status,
            HoldStatus::Released
        );
        assert_eq!(r.release("h1", "x").await, Err(StoreError::Conflict));

        // Unreachable next hop: the hold goes back to HELD.
        store.create_hold(&hold("h2")).await.unwrap();
        storage.put("holds/h2", b"x\r\n").await.unwrap();
        let r = RelayHoldReviewer::new(
            store.clone(),
            storage.clone(),
            SmtpOptions {
                addr: "127.0.0.1:1".into(),
                timeout: Duration::from_secs(2),
                ..Default::default()
            },
        );
        assert!(r.release("h2", "admin").await.is_err());
        assert_eq!(store.get_hold("h2").await.unwrap().status, HoldStatus::Held);
        r.reject("h2", "admin", "pii").await.unwrap();
        assert_eq!(
            store.get_hold("h2").await.unwrap().status,
            HoldStatus::Rejected
        );
    }

    /// SMTP sink whose behaviour after the message body is scripted:
    /// `after_data` is the reply to the end of DATA (None: drop the
    /// connection without replying); QUIT is never answered.
    async fn scripted_sink(after_data: Option<&'static str>) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut c = BufReader::new(s);
            c.write_all(b"220 sink\r\n").await.unwrap();
            loop {
                let mut line = String::new();
                if c.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let up = line.to_ascii_uppercase();
                if up.starts_with("DATA") {
                    c.write_all(b"354 go\r\n").await.unwrap();
                    crate::smtpclient::read_data(&mut c, 0).await.unwrap();
                    match after_data {
                        Some(r) => c.write_all(r.as_bytes()).await.unwrap(),
                        None => return, // accepted? nobody knows
                    }
                } else if up.starts_with("QUIT") {
                    return; // drop without 221
                } else {
                    c.write_all(b"250 ok\r\n").await.unwrap();
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn release_outcomes_after_data() {
        let (store, storage, _q) = deps().await;
        let reviewer = |addr: String| {
            RelayHoldReviewer::new(
                store.clone(),
                storage.clone(),
                SmtpOptions {
                    addr,
                    timeout: Duration::from_secs(5),
                    ..Default::default()
                },
            )
        };
        // QUIT error after an accepted message: success.
        store.create_hold(&hold("q1")).await.unwrap();
        storage.put("holds/q1", b"x\r\n").await.unwrap();
        reviewer(scripted_sink(Some("250 queued\r\n")).await)
            .release("q1", "admin")
            .await
            .unwrap();
        assert_eq!(
            store.get_hold("q1").await.unwrap().status,
            HoldStatus::Released
        );
        assert!(storage.get("holds/q1").await.is_err(), "copy deleted");

        // Definite rejection of the message: reopened.
        store.create_hold(&hold("q2")).await.unwrap();
        storage.put("holds/q2", b"x\r\n").await.unwrap();
        assert!(reviewer(scripted_sink(Some("554 no\r\n")).await)
            .release("q2", "admin")
            .await
            .is_err());
        assert_eq!(store.get_hold("q2").await.unwrap().status, HoldStatus::Held);

        // Connection lost after the body: maybe sent -> stays RELEASED.
        store.create_hold(&hold("q3")).await.unwrap();
        storage.put("holds/q3", b"x\r\n").await.unwrap();
        assert!(reviewer(scripted_sink(None).await)
            .release("q3", "admin")
            .await
            .is_err());
        let h = store.get_hold("q3").await.unwrap();
        assert_eq!(h.status, HoldStatus::Released);
        assert_eq!(h.reason, RELAY_UNKNOWN);
        assert!(storage.get("holds/q3").await.is_ok(), "copy kept");
    }

    #[tokio::test]
    async fn sweep_skips_requeue_when_verdict_landed() {
        let (store, storage, queue) = deps().await;
        let now = Utc::now();
        let old = now - chrono::Duration::hours(1);
        store
            .create_message(
                &msg(),
                &[att("r1", old, 1, now + chrono::Duration::days(1))],
            )
            .await
            .unwrap();
        store
            .set_verdict("r1", Status::Clean, "", None, now)
            .await
            .unwrap();
        assert_eq!(
            store.mark_requeued("r1", now).await,
            Err(StoreError::Conflict)
        );
        let j = Janitor {
            store: store.clone(),
            storage,
            queue: queue.clone(),
            analysis_timeout: Duration::from_secs(600),
            max_attempts: 3,
            audit_retention: None,
        };
        let st = j.sweep_once(now).await;
        assert_eq!(st.requeued, 0);
        assert!(queue.snapshot().is_empty());
    }

    #[tokio::test]
    async fn mailer_builds_and_sends() {
        let (addr, rx) = sink().await;
        let m = SmtpMailer::new(
            SmtpOptions {
                addr,
                ..Default::default()
            },
            "noreply@corp.test",
            "보안메일",
        );
        m.send_to(&["u@corp.test".into()], "인증 코드", "코드: 123456")
            .await
            .unwrap();
        let raw = rx.await.unwrap();
        let p = mailparse::parse_mail(&raw).unwrap();
        use mailparse::MailHeaderMap;
        assert_eq!(p.headers.get_first_value("Subject").unwrap(), "인증 코드");
        assert!(p.get_body().unwrap().contains("123456"));
        assert_eq!(sanitize_threat_name(&"가".repeat(200)).len(), 255);
    }
}
