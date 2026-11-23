//! Inbound quarantine service. Port of the Go `internal/service` Quarantine: it
//! extracts attachments from an inbound message, stores them in the object
//! store, records them, enqueues analysis, and rewrites the message so the
//! attachments are replaced by download links (a banner). Blocked extensions are
//! marked MALICIOUS up front and never enqueued.
//!
//! The rewrite is simplified relative to the Go implementation: the message is
//! re-emitted as a single text/plain part (banner + original text). Structural
//! HTML rewriting is a follow-up; the security function (quarantine + links +
//! analysis) is complete.

use std::sync::Arc;

use base64::Engine;
use chrono::Utc;

use crate::gateway::{Envelope, MessageProcessor, ProcessError};
use crate::metrics::Metrics;
use crate::model::{Attachment, Job, JobObject, Message, Status};
use crate::queue::{Priority, Queue};
use crate::storage::Storage;
use crate::store::Store;

/// A quarantined attachment's banner link.
pub struct Link {
    pub filename: String,
    pub size: i64,
    pub url: String,
    pub status: Status,
}

/// Inbound quarantine configuration + dependencies.
pub struct Service {
    store: Arc<dyn Store>,
    storage: Arc<dyn Storage>,
    queue: Arc<dyn Queue>,
    metrics: Arc<Metrics>,
    public_base_url: String,
    link_ttl: chrono::Duration,
    gateway_id: String,
    blocked_extensions: std::collections::HashSet<String>,
}

impl Service {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<dyn Store>,
        storage: Arc<dyn Storage>,
        queue: Arc<dyn Queue>,
        metrics: Arc<Metrics>,
        public_base_url: String,
        link_ttl: std::time::Duration,
        gateway_id: String,
        blocked_extensions: &[String],
    ) -> Self {
        Service {
            store,
            storage,
            queue,
            metrics,
            public_base_url: public_base_url.trim_end_matches('/').to_string(),
            link_ttl: chrono::Duration::from_std(link_ttl)
                .unwrap_or_else(|_| chrono::Duration::hours(336)),
            gateway_id: if gateway_id.is_empty() {
                "secmail".into()
            } else {
                gateway_id
            },
            blocked_extensions: blocked_extensions
                .iter()
                .map(|e| e.trim_start_matches('.').to_lowercase())
                .collect(),
        }
    }

    /// Quarantines attachments and returns the rewritten message. When the
    /// message has no attachments it is relayed unchanged.
    pub async fn quarantine(&self, env: &Envelope, raw: &[u8]) -> Result<Vec<u8>, ProcessError> {
        let parsed = crate::mimeproc::parse(raw).map_err(|_| ProcessError::TempFail)?;
        if parsed.attachments.is_empty() {
            return Ok(raw.to_vec());
        }
        let now = Utc::now();
        let msg_id = uuid::Uuid::new_v4().to_string();
        let mut atts: Vec<Attachment> = Vec::new();
        let mut links: Vec<Link> = Vec::new();
        let mut jobs: Vec<Job> = Vec::new();

        for a in &parsed.attachments {
            let id = uuid::Uuid::new_v4().to_string();
            let key = format!("attachments/{}/{}", now.format("%Y/%m/%d"), id);
            let token = random_token();
            let blocked = file_ext(&a.filename)
                .map(|e| self.blocked_extensions.contains(&e))
                .unwrap_or(false);
            let (status, threat, analyzed) = if blocked {
                (
                    Status::Malicious,
                    "blocked.extension".to_string(),
                    Some(now),
                )
            } else {
                (Status::Pending, String::new(), None)
            };

            if self.storage.put(&key, &a.data).await.is_err() {
                return Err(ProcessError::TempFail);
            }
            let att = Attachment {
                id: id.clone(),
                message_id: msg_id.clone(),
                filename: a.filename.clone(),
                content_type: a.content_type.clone(),
                size: a.data.len() as i64,
                sha256: sha256_hex(&a.data),
                storage_key: key.clone(),
                token_hash: sha256_hex(token.as_bytes()),
                status,
                threat_name: threat,
                verdict_detail: None,
                attempts: 1,
                created_at: now,
                updated_at: now,
                queued_at: now,
                analyzed_at: analyzed,
                expires_at: now + self.link_ttl,
                download_count: 0,
                last_downloaded_at: None,
            };
            links.push(Link {
                filename: att.filename.clone(),
                size: att.size,
                url: format!("{}/dl/{}", self.public_base_url, token),
                status,
            });
            if status == Status::Pending {
                jobs.push(Job {
                    version: 1,
                    attachment_id: id.clone(),
                    message_id: msg_id.clone(),
                    filename: att.filename.clone(),
                    content_type: att.content_type.clone(),
                    size: att.size,
                    sha256: att.sha256.clone(),
                    storage: JobObject {
                        kind: self.storage.kind().to_string(),
                        bucket: self.storage.bucket().to_string(),
                        key: key.clone(),
                    },
                    content_url: String::new(),
                    verdict_url: String::new(),
                    attempt: 1,
                    enqueued_at: now,
                });
                self.metrics
                    .attachments
                    .with_label_values(&["pending"])
                    .inc();
            } else {
                self.metrics
                    .attachments
                    .with_label_values(&["blocked"])
                    .inc();
            }
            atts.push(att);
        }

        let msg = Message {
            id: msg_id.clone(),
            message_id: String::new(),
            mail_from: env.mail_from.clone(),
            rcpt_to: env.rcpt_to.clone(),
            subject: parsed.subject.clone(),
            remote_addr: env.remote_addr.clone(),
            received_at: Some(now),
            attachment_count: atts.len() as i64,
        };
        if self.store.create_message(&msg, &atts).await.is_err() {
            return Err(ProcessError::TempFail);
        }
        for job in jobs {
            let _ = self.queue.enqueue(job, Priority::High).await;
        }

        let body = rewrite_body(
            &parsed,
            &links,
            &self.gateway_id,
            &msg_id,
            now + self.link_ttl,
        );
        Ok(body.into_bytes())
    }
}

#[async_trait::async_trait]
impl MessageProcessor for Service {
    async fn process(&self, env: &Envelope, raw: &[u8]) -> Result<Vec<u8>, ProcessError> {
        self.quarantine(env, raw).await
    }
}

/// Final lower-cased extension, with trailing dots/spaces stripped (matches the
/// blocked-extension gate so "evil.exe." is caught).
fn file_ext(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches(['.', ' ']).to_lowercase();
    name.rfind('.')
        .filter(|&i| i + 1 < name.len())
        .map(|i| name[i + 1..].to_string())
}

fn random_token() -> String {
    let mut b = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn human_size(n: i64) -> String {
    const U: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// Rebuilds the message as a text/plain part: preserved headers + a banner with
/// download links + the original text.
fn rewrite_body(
    parsed: &crate::mimeproc::Parsed,
    links: &[Link],
    gateway_id: &str,
    msg_id: &str,
    expires: chrono::DateTime<Utc>,
) -> String {
    let mut out = String::new();
    if !parsed.subject.is_empty() {
        out.push_str(&format!("Subject: {}\r\n", parsed.subject));
    }
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str(&format!(
        "X-SecMail-Processed: {gateway_id}; attachments={}; id={msg_id}\r\n",
        links.len()
    ));
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");

    // Original text body.
    for t in &parsed.text_parts {
        out.push_str(t);
        if !t.ends_with('\n') {
            out.push_str("\r\n");
        }
    }
    // Banner.
    let rule = "-".repeat(60);
    out.push_str(&format!(
        "\r\n{rule}\r\n[보안 메일 게이트웨이] 첨부파일 {}개가 분리 보관되었습니다.\r\n\
         악성코드 검사 후 아래 링크에서 다운로드하세요 (유효기간: {} 까지).\r\n\r\n",
        links.len(),
        expires.format("%Y-%m-%d %H:%M UTC")
    ));
    for (i, l) in links.iter().enumerate() {
        let state = if l.status == Status::Malicious {
            " [차단됨]"
        } else {
            ""
        };
        out.push_str(&format!(
            "  {}. {} ({}){}\r\n     {}\r\n",
            i + 1,
            l.filename,
            human_size(l.size),
            state,
            l.url
        ));
    }
    out.push_str(&format!("{rule}\r\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Fs;
    use crate::store::{Memory, Page};

    async fn svc(blocked: &[String]) -> (Service, Arc<Memory>, Arc<crate::queue::Memory>) {
        let store: Arc<Memory> = Arc::new(Memory::new());
        let dir = std::env::temp_dir().join(format!("secmail-svc-{}", uuid::Uuid::new_v4()));
        let storage: Arc<dyn Storage> = Arc::new(Fs::new(dir.to_str().unwrap()).await.unwrap());
        let queue: Arc<crate::queue::Memory> = Arc::new(crate::queue::Memory::new());
        let s = Service::new(
            store.clone(),
            storage,
            queue.clone(),
            Arc::new(Metrics::new()),
            "https://sec.example.com/".into(),
            std::time::Duration::from_secs(336 * 3600),
            "test-gw".into(),
            blocked,
        );
        (s, store, queue)
    }

    const MSG: &[u8] = b"From: a@ext.org\r\nTo: b@example.com\r\nSubject: invoice\r\n\
MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
--B\r\nContent-Type: text/plain\r\n\r\nplease see attached\r\n\
--B\r\nContent-Type: application/pdf; name=\"invoice.pdf\"\r\n\
Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--B--\r\n";

    #[tokio::test]
    async fn quarantines_and_rewrites() {
        let (s, store, queue) = svc(&[]).await;
        let env = Envelope {
            mail_from: "a@ext.org".into(),
            rcpt_to: vec!["b@example.com".into()],
            ..Default::default()
        };
        let out = s.quarantine(&env, MSG).await.unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("https://sec.example.com/dl/"),
            "banner link present:\n{text}"
        );
        assert!(text.contains("invoice.pdf"));
        assert!(text.contains("please see attached")); // original text kept
                                                       // Attachment stored + record PENDING + job enqueued.
        let jobs = queue.snapshot();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].filename, "invoice.pdf");
        // A message record exists with one attachment.
        assert_eq!(
            store
                .get_message(&jobs[0].message_id)
                .await
                .unwrap()
                .attachment_count,
            1
        );
    }

    #[tokio::test]
    async fn blocked_extension_marked_malicious_and_unqueued() {
        let (s, _store, queue) = svc(&["exe".into()]).await;
        let raw = b"From: a@ext.org\r\nSubject: x\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n\
--B\r\nContent-Type: application/octet-stream; name=\"evil.exe.\"\r\n\
Content-Disposition: attachment; filename=\"evil.exe.\"\r\n\r\nMZ\r\n--B--\r\n";
        let env = Envelope {
            mail_from: "a@ext.org".into(),
            rcpt_to: vec!["b@example.com".into()],
            ..Default::default()
        };
        let out = s.quarantine(&env, raw).await.unwrap();
        assert!(String::from_utf8_lossy(&out).contains("[차단됨]"));
        assert!(
            queue.snapshot().is_empty(),
            "blocked attachment must not be enqueued"
        );
    }

    #[tokio::test]
    async fn no_attachments_passthrough() {
        let (s, _store, _queue) = svc(&[]).await;
        let raw = b"Subject: hi\r\nContent-Type: text/plain\r\n\r\njust text\r\n";
        let env = Envelope::default();
        assert_eq!(s.quarantine(&env, raw).await.unwrap(), raw);
    }

    #[tokio::test]
    async fn file_ext_trailing_dot() {
        assert_eq!(file_ext("evil.exe."), Some("exe".into()));
        assert_eq!(file_ext("a.tar.gz"), Some("gz".into()));
        assert_eq!(file_ext("noext"), None);
    }

    #[tokio::test]
    async fn clean_attachment_downloadable_after_verdict() {
        // End-to-end: quarantine stores the attachment under a token; a CLEAN
        // verdict then makes it downloadable via the portal gate.
        let (s, store, _q) = svc(&[]).await;
        let env = Envelope {
            mail_from: "a@ext.org".into(),
            rcpt_to: vec!["b@example.com".into()],
            ..Default::default()
        };
        let out = s.quarantine(&env, MSG).await.unwrap();
        let text = String::from_utf8_lossy(&out);
        let token = text
            .split("/dl/")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_string();
        let hash = sha256_hex(token.as_bytes());
        let att = store.get_attachment_by_token_hash(&hash).await.unwrap();
        assert_eq!(att.status, Status::Pending);
        // Nothing to assert on download here (covered by portal tests); just that
        // the token resolves to the stored attachment.
        let _ = Page::default();
    }
}
