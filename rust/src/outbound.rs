//! Outbound Data Loss Prevention. Port of the Go `internal/outbound` decision
//! core: scan an outgoing message, map findings to an action (allow/notify/
//! hold/block) and apply it as the SMTP proxy's MessageProcessor — relaying,
//! holding for review, or blocking.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;

use crate::config::{ACTION_ALLOW, ACTION_BLOCK, ACTION_HOLD, ACTION_NOTIFY};
use crate::dlp::{Report, Scanner, Severity};
use crate::gateway::{Envelope, MessageProcessor, ProcessError, SmtpError};
use crate::model::{DlpEvent, Hold, HoldStatus};
use crate::storage::Storage;
use crate::store::Store;

/// Per-severity dispositions and exemptions (the tunable DLP policy).
#[derive(Clone)]
pub struct Policy {
    pub high: String,
    pub medium: String,
    pub low: String,
    pub uninspectable: String,
    pub encrypted: String,
    pub exempt_senders: Vec<String>,
    pub exempt_recipient_domains: Vec<String>,
    pub dry_run: bool,
}

fn action_rank(a: &str) -> u8 {
    match a {
        ACTION_NOTIFY => 1,
        ACTION_HOLD => 2,
        ACTION_BLOCK => 3,
        _ => 0, // allow / unknown
    }
}

fn stricter<'a>(a: &'a str, b: &'a str) -> &'a str {
    if action_rank(b) > action_rank(a) {
        b
    } else {
        a
    }
}

/// Maps a scan report to an action under `policy`.
pub fn decide(report: &Report, policy: &Policy) -> String {
    let mut act = ACTION_ALLOW;
    for f in &report.findings {
        match f.sev() {
            Severity::High => act = stricter(act, &policy.high),
            Severity::Medium => act = stricter(act, &policy.medium),
            Severity::Low => act = stricter(act, &policy.low),
            Severity::None => {}
        }
    }
    if !report.uninspectable.is_empty() {
        act = stricter(act, &policy.uninspectable);
    }
    if report.has_encrypted() {
        let enc = if policy.encrypted.is_empty() {
            &policy.uninspectable
        } else {
            &policy.encrypted
        };
        act = stricter(act, enc);
    }
    act.to_string()
}

/// The outbound DLP service, used as the outbound SMTP proxy's processor.
pub struct Service {
    scanner: Arc<Scanner>,
    store: Arc<dyn Store>,
    storage: Arc<dyn Storage>,
    policy: Policy,
    hold_ttl: chrono::Duration,
}

impl Service {
    pub fn new(
        scanner: Arc<Scanner>,
        store: Arc<dyn Store>,
        storage: Arc<dyn Storage>,
        policy: Policy,
        hold_ttl: std::time::Duration,
    ) -> Self {
        Service {
            scanner,
            store,
            storage,
            policy,
            hold_ttl: chrono::Duration::from_std(hold_ttl)
                .unwrap_or_else(|_| chrono::Duration::hours(72)),
        }
    }

    fn exempt(&self, env: &Envelope) -> bool {
        let from = env.mail_from.to_lowercase();
        if self
            .policy
            .exempt_senders
            .iter()
            .any(|s| s.to_lowercase() == from)
        {
            return true;
        }
        // Exempt only when *every* recipient is in an exempt domain.
        if self.policy.exempt_recipient_domains.is_empty() {
            return false;
        }
        !env.rcpt_to.is_empty()
            && env.rcpt_to.iter().all(|r| {
                let dom = r.rsplit('@').next().unwrap_or("").to_lowercase();
                self.policy.exempt_recipient_domains.iter().any(|d| {
                    let d = d.to_lowercase();
                    dom == d || (d.starts_with('.') && dom.ends_with(&d))
                })
            })
    }

    async fn record_event(&self, env: &Envelope, action: &str, report: &Report) {
        let findings = serde_json::to_value(report).ok();
        let _ = self
            .store
            .record_dlp_event(&DlpEvent {
                id: uuid::Uuid::new_v4().to_string(),
                mail_from: env.mail_from.clone(),
                rcpt_to: env.rcpt_to.clone(),
                subject: subject_of(report),
                action: action.to_string(),
                severity: report.max_severity().as_str().to_string(),
                findings,
                hold_id: String::new(),
                at: Utc::now(),
            })
            .await;
    }

    async fn create_hold(
        &self,
        env: &Envelope,
        report: &Report,
        raw: &[u8],
    ) -> Result<(), ProcessError> {
        let id = uuid::Uuid::new_v4().to_string();
        let key = format!("holds/{id}");
        self.storage
            .put(&key, raw)
            .await
            .map_err(|_| ProcessError::TempFail)?;
        let token = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        self.store
            .create_hold(&Hold {
                id,
                token_hash: sha256_hex(token.as_bytes()),
                mail_from: env.mail_from.clone(),
                rcpt_to: env.rcpt_to.clone(),
                subject: subject_of(report),
                storage_key: key,
                size: raw.len() as i64,
                findings: serde_json::to_value(report).ok(),
                status: HoldStatus::Held,
                created_at: now,
                expires_at: now + self.hold_ttl,
                decided_at: None,
                decided_by: String::new(),
                reason: String::new(),
            })
            .await
            .map_err(|_| ProcessError::TempFail)
    }
}

fn subject_of(_report: &Report) -> String {
    String::new() // subject is taken from the message in the full wiring
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[async_trait]
impl MessageProcessor for Service {
    async fn process(&self, env: &Envelope, raw: &[u8]) -> Result<Vec<u8>, ProcessError> {
        if self.exempt(env) {
            let empty = Report::default();
            self.record_event(env, "exempt", &empty).await;
            return Ok(raw.to_vec());
        }
        let report = self.scanner.scan_message(raw);
        let action = decide(&report, &self.policy);
        self.record_event(env, &action, &report).await;

        if self.policy.dry_run {
            return Ok(raw.to_vec());
        }
        match action.as_str() {
            ACTION_BLOCK => Err(ProcessError::Reject(SmtpError::new(
                550,
                "Message blocked by data-loss-prevention policy",
            ))),
            ACTION_HOLD => {
                self.create_hold(env, &report, raw).await?;
                Err(ProcessError::Held)
            }
            // allow / notify -> relay (recipient notice is sent in the full wiring)
            _ => Ok(raw.to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlp::Options as DlpOptions;
    use crate::storage::Fs;
    use crate::store::{Memory, Page};

    fn policy(high: &str) -> Policy {
        Policy {
            high: high.into(),
            medium: ACTION_NOTIFY.into(),
            low: ACTION_ALLOW.into(),
            uninspectable: ACTION_NOTIFY.into(),
            encrypted: ACTION_HOLD.into(),
            exempt_senders: vec![],
            exempt_recipient_domains: vec![],
            dry_run: false,
        }
    }

    async fn service(high: &str) -> (Arc<Service>, Arc<Memory>) {
        let scanner = Arc::new(
            Scanner::new(DlpOptions {
                combine_pii: true,
                ..Default::default()
            })
            .unwrap(),
        );
        let store: Arc<Memory> = Arc::new(Memory::new());
        let dir = std::env::temp_dir().join(format!("secmail-out-{}", uuid::Uuid::new_v4()));
        let storage: Arc<dyn Storage> = Arc::new(Fs::new(dir.to_str().unwrap()).await.unwrap());
        let svc = Arc::new(Service::new(
            scanner,
            store.clone() as Arc<dyn Store>,
            storage,
            policy(high),
            std::time::Duration::from_secs(72 * 3600),
        ));
        (svc, store)
    }

    fn env() -> Envelope {
        Envelope {
            mail_from: "staff@corp.com".into(),
            rcpt_to: vec!["ext@partner.com".into()],
            ..Default::default()
        }
    }

    const RRN_MSG: &[u8] =
        b"Subject: x\r\nContent-Type: text/plain\r\n\r\n\xEC\xA3\xBC\xEB\xAF\xBC 900101-1234567\r\n";

    #[tokio::test]
    async fn high_finding_holds() {
        let (svc, store) = service(ACTION_HOLD).await;
        let r = svc.process(&env(), RRN_MSG).await;
        assert!(matches!(r, Err(ProcessError::Held)));
        let holds = store
            .list_holds(Some(HoldStatus::Held), 10, Page::default())
            .await
            .unwrap();
        assert_eq!(holds.len(), 1);
        assert_eq!(holds[0].mail_from, "staff@corp.com");
    }

    #[tokio::test]
    async fn block_action_rejects() {
        let (svc, _store) = service(ACTION_BLOCK).await;
        let r = svc.process(&env(), RRN_MSG).await;
        match r {
            Err(ProcessError::Reject(e)) => assert_eq!(e.code, 550),
            other => panic!("want reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn clean_message_relays() {
        let (svc, store) = service(ACTION_HOLD).await;
        let out = svc
            .process(
                &env(),
                b"Subject: hi\r\nContent-Type: text/plain\r\n\r\nhello team\r\n",
            )
            .await
            .unwrap();
        assert_eq!(
            out,
            b"Subject: hi\r\nContent-Type: text/plain\r\n\r\nhello team\r\n"
        );
        // An allow event is still recorded.
        let evs = store
            .list_dlp_events(Default::default(), 10, Page::default())
            .await
            .unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].action, "allow");
    }

    #[tokio::test]
    async fn exempt_sender_relays() {
        let (svc_arc, _store) = service(ACTION_HOLD).await;
        // Rebuild with an exempt sender.
        let scanner = Arc::new(Scanner::new(DlpOptions::default()).unwrap());
        let store: Arc<Memory> = Arc::new(Memory::new());
        let dir = std::env::temp_dir().join(format!("secmail-out-{}", uuid::Uuid::new_v4()));
        let storage: Arc<dyn Storage> = Arc::new(Fs::new(dir.to_str().unwrap()).await.unwrap());
        let mut p = policy(ACTION_HOLD);
        p.exempt_senders = vec!["staff@corp.com".into()];
        let svc = Service::new(
            scanner,
            store as Arc<dyn Store>,
            storage,
            p,
            std::time::Duration::from_secs(1),
        );
        let r = svc.process(&env(), RRN_MSG).await;
        assert!(r.is_ok(), "exempt sender should relay despite RRN");
        let _ = svc_arc;
    }

    #[tokio::test]
    async fn dry_run_relays_but_records() {
        let scanner = Arc::new(
            Scanner::new(DlpOptions {
                combine_pii: true,
                ..Default::default()
            })
            .unwrap(),
        );
        let store: Arc<Memory> = Arc::new(Memory::new());
        let dir = std::env::temp_dir().join(format!("secmail-out-{}", uuid::Uuid::new_v4()));
        let storage: Arc<dyn Storage> = Arc::new(Fs::new(dir.to_str().unwrap()).await.unwrap());
        let mut p = policy(ACTION_HOLD);
        p.dry_run = true;
        let svc = Service::new(
            scanner,
            store.clone() as Arc<dyn Store>,
            storage,
            p,
            std::time::Duration::from_secs(1),
        );
        let r = svc.process(&env(), RRN_MSG).await;
        assert!(r.is_ok(), "dry-run relays");
        // No hold created, but the (would-be hold) event is recorded.
        assert!(store
            .list_holds(None, 10, Page::default())
            .await
            .unwrap()
            .is_empty());
        let evs = store
            .list_dlp_events(Default::default(), 10, Page::default())
            .await
            .unwrap();
        assert_eq!(evs[0].action, "hold");
    }

    #[test]
    fn decide_stricter() {
        let s = Scanner::new(DlpOptions {
            combine_pii: true,
            ..Default::default()
        })
        .unwrap();
        // A high-severity RRN under a "hold" policy -> hold.
        let rep = s.scan_text_report("본문", "주민등록번호 900101-1234567");
        assert_eq!(decide(&rep, &policy(ACTION_HOLD)), "hold");
        // No findings -> allow.
        assert_eq!(decide(&Report::default(), &policy(ACTION_HOLD)), "allow");
    }
}
