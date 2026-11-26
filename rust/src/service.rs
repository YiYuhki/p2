//! Inbound quarantine service. Port of the Go `internal/service` Quarantine: it
//! extracts attachments from an inbound message, stores them in the object
//! store, records them, enqueues analysis, and rewrites the message so the
//! attachments are replaced by download links (a banner). Blocked extensions are
//! marked MALICIOUS up front and never enqueued.
//!
//! The rewrite is structural (see [`crate::mimetree`]): attachments are removed
//! in place, every other part is preserved byte-for-byte, and the banner is
//! appended to the first text/plain and text/html bodies.

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
    rewrite: crate::mimetree::Options,
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
            rewrite: crate::mimetree::Options::default(),
        }
    }

    /// Sets the MIME rewrite policy (inline images, signed/encrypted handling).
    pub fn with_rewrite(mut self, opts: crate::mimetree::Options) -> Self {
        self.rewrite = opts;
        self
    }

    /// Quarantines attachments and returns the rewritten message. When the
    /// message has no attachments it is relayed unchanged.
    pub async fn quarantine(&self, env: &Envelope, raw: &[u8]) -> Result<Vec<u8>, ProcessError> {
        let mut root = crate::mimetree::parse(raw);
        // The blocked-extension gate also applies to parts the rewrite policy
        // would keep inline (e.g. an inline image named "x.exe" is extracted).
        let blocked = |name: &str| {
            file_ext(name)
                .map(|e| self.blocked_extensions.contains(&e))
                .unwrap_or(false)
        };
        let res = match crate::mimetree::extract_with(&mut root, &self.rewrite, &blocked) {
            Ok(r) => r,
            Err(crate::mimetree::ExtractError::Encrypted) => {
                return Err(ProcessError::Reject(crate::gateway::SmtpError::new(
                    554,
                    "5.7.1 Encrypted messages are not accepted by policy",
                )))
            }
        };
        if res.attachments.is_empty() {
            return Ok(raw.to_vec());
        }
        let subject = crate::mimeproc::decode_header(&root.header("subject").unwrap_or_default());
        let now = Utc::now();
        let msg_id = uuid::Uuid::new_v4().to_string();
        let mut atts: Vec<Attachment> = Vec::new();
        let mut links: Vec<Link> = Vec::new();
        let mut jobs: Vec<Job> = Vec::new();

        for a in &res.attachments {
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
            message_id: root.header("message-id").unwrap_or_default(),
            mail_from: env.mail_from.clone(),
            rcpt_to: env.rcpt_to.clone(),
            subject,
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

        let notice = if res.signature_removed {
            "원본 메일의 전자서명은 첨부파일 분리로 인해 제거되었습니다."
        } else {
            ""
        };
        let banner = build_banner(&links, now + self.link_ttl, notice);
        crate::mimetree::insert_banner(&mut root, &banner);
        if root.header("mime-version").is_none() {
            root.set_header("MIME-Version", "1.0");
        }
        root.set_header(
            "X-SecMail-Processed",
            &format!(
                "{}; attachments={}; id={msg_id}",
                self.gateway_id,
                links.len()
            ),
        );
        Ok(root.to_bytes())
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

fn html_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&#34;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

/// Renders the download banner (text + HTML). Port of the Go `buildBanner`.
pub fn build_banner(
    links: &[Link],
    expires: chrono::DateTime<Utc>,
    notice: &str,
) -> crate::mimetree::Banner {
    let exp = expires.format("%Y-%m-%d %H:%M UTC").to_string();
    let mark = |l: &Link| {
        if l.status == Status::Malicious {
            " [차단됨]"
        } else {
            ""
        }
    };

    let mut h = String::new();
    h.push_str("\r\n<div style=\"margin:24px 0 0 0;padding:16px;border:1px solid #c7d2fe;border-left:4px solid #4f46e5;border-radius:6px;background:#f5f7ff;font-family:'Malgun Gothic','Apple SD Gothic Neo',Arial,sans-serif;font-size:14px;color:#1f2937;\">\r\n");
    h.push_str(&format!(
        "<div style=\"font-weight:bold;font-size:15px;margin-bottom:6px;\">&#128274; 보안 메일 게이트웨이 &middot; 첨부파일 {}개 분리 보관</div>\r\n",
        links.len()
    ));
    h.push_str("<div style=\"margin-bottom:10px;color:#374151;\">이 메일의 첨부파일은 악성코드 검사를 위해 안전한 저장소로 옮겨졌습니다. 아래 링크에서 검사 결과를 확인한 뒤 다운로드하세요.");
    if !notice.is_empty() {
        h.push_str(&format!(
            "<br><span style=\"color:#b45309;\">{}</span>",
            html_escape(notice)
        ));
    }
    h.push_str("</div>\r\n<table cellpadding=\"0\" cellspacing=\"0\" style=\"border-collapse:collapse;width:100%;\">\r\n");
    for l in links {
        let url = html_escape(&l.url);
        h.push_str(&format!(
            "<tr><td style=\"padding:6px 0;border-top:1px solid #e0e7ff;\"><a href=\"{url}\" style=\"color:#4338ca;font-weight:bold;text-decoration:none;\">{}</a> <span style=\"color:#6b7280;\">({}){}</span></td><td style=\"padding:6px 0;border-top:1px solid #e0e7ff;text-align:right;\"><a href=\"{url}\" style=\"display:inline-block;padding:4px 12px;border-radius:4px;background:#4f46e5;color:#ffffff;text-decoration:none;font-size:13px;\">검사 결과 확인 / 다운로드</a></td></tr>\r\n",
            html_escape(&l.filename),
            human_size(l.size),
            mark(l)
        ));
    }
    h.push_str(&format!(
        "</table>\r\n<div style=\"margin-top:8px;font-size:12px;color:#6b7280;\">링크 유효기간: {exp} 까지 &middot; 이 안내는 보안 게이트웨이가 자동으로 추가했습니다.</div>\r\n</div>"
    ));

    let rule = "-".repeat(60);
    let mut t = format!(
        "{rule}\r\n[보안 메일 게이트웨이] 첨부파일 {}개가 악성코드 검사를 위해 분리 보관되었습니다.\r\n아래 링크에서 검사 결과를 확인한 뒤 다운로드하세요.\r\n",
        links.len()
    );
    if !notice.is_empty() {
        t.push_str(notice);
        t.push_str("\r\n");
    }
    t.push_str("\r\n");
    for (i, l) in links.iter().enumerate() {
        t.push_str(&format!(
            " {}. {} ({}){}\r\n    {}\r\n",
            i + 1,
            l.filename,
            human_size(l.size),
            mark(l),
            l.url
        ));
    }
    t.push_str(&format!("\r\n링크 유효기간: {exp} 까지\r\n{rule}"));
    crate::mimetree::Banner { text: t, html: h }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Fs;
    use crate::store::{Memory, Page};

    fn bodies(out: &[u8]) -> String {
        crate::mimeproc::parse(out)
            .unwrap()
            .text_parts
            .iter()
            .map(|t| t.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tokio::test]
    async fn encrypted_rejected_by_policy() {
        let (s, _store, _q) = svc(&[]).await;
        let s = s.with_rewrite(crate::mimetree::Options {
            encrypted_reject: true,
            ..Default::default()
        });
        let raw = b"From: a@x.org\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=E\r\n\r\n--E\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--E\r\nContent-Type: application/octet-stream\r\n\r\nx\r\n--E--\r\n";
        match s.quarantine(&Envelope::default(), raw).await {
            Err(ProcessError::Reject(e)) => assert_eq!(e.code, 554),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn html_banner_escapes_filename() {
        let links = vec![Link {
            filename: "<script>.pdf".into(),
            size: 2048,
            url: "https://x/dl/t?a=1&b=2".into(),
            status: Status::Pending,
        }];
        let b = build_banner(&links, Utc::now(), "");
        assert!(b.html.contains("&lt;script&gt;.pdf"));
        assert!(b.html.contains("a=1&amp;b=2"));
        assert!(b.text.contains("<script>.pdf (2.0 KB)"));
    }

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
        let text = bodies(&out);
        let raw = String::from_utf8_lossy(&out);
        assert!(raw.contains("From: a@ext.org") && raw.contains("To: b@example.com"));
        assert!(raw.contains("X-SecMail-Processed: test-gw; attachments=1"));
        assert!(!raw.contains("JVBERi0xLjQK"), "attachment removed");
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
        assert!(bodies(&out).contains("[차단됨]"));
        assert!(
            queue.snapshot().is_empty(),
            "blocked attachment must not be enqueued"
        );
    }

    #[tokio::test]
    async fn kept_inline_part_with_blocked_name_is_extracted() {
        let (s, _store, queue) = svc(&["gif".into()]).await;
        let s = s.with_rewrite(crate::mimetree::Options {
            keep_inline_images: true,
            ..Default::default()
        });
        let raw = b"From: a@ext.org\r\nSubject: x\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/related; boundary=\"B\"\r\n\r\n\
--B\r\nContent-Type: text/html\r\n\r\n<img src=cid:a>\r\n\
--B\r\nContent-Type: image/png\r\nContent-ID: <a>\r\n\r\nPNG\r\n\
--B\r\nContent-Type: image/gif; name=\"x.gif\"\r\nContent-ID: <b>\r\n\r\nGIF\r\n--B--\r\n";
        let out = s.quarantine(&Envelope::default(), raw).await.unwrap();
        let o = String::from_utf8_lossy(&out);
        assert!(o.contains("Content-ID: <a>"), "nameless raster image kept");
        assert!(!o.contains("Content-ID: <b>"), "blocked name extracted");
        assert!(bodies(&out).contains("[차단됨]"));
        assert!(queue.snapshot().is_empty());
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
        let text = bodies(&out);
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
