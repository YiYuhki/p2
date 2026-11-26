//! Posts security events (DLP decisions, malware verdicts) to an external
//! endpoint (SIEM/chat-ops) as JSON, with HMAC-SHA256 signing, bounded retries
//! and a dead-letter sink. Port of the Go `internal/webhook`.
//!
//! Signing: when a secret is configured each attempt carries
//! `X-Secmail-Timestamp: <unix seconds>` and
//! `X-Secmail-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">`, so a
//! receiver can reject stale or replayed deliveries (check the timestamp is
//! within a few minutes, then verify the MAC over `timestamp + "." + body`).
//!
//! The HTTP transport is behind the [`Transport`] trait so the retry/backoff/DLQ
//! logic is testable without a network; the real reqwest-backed transport lands
//! with the async I/O layer.

use std::time::Duration;

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::Sha256;

/// JSON payload delivered to the webhook. Unset fields are omitted.
#[derive(Clone, Debug, Serialize, Default)]
pub struct Event {
    #[serde(rename = "type")]
    pub kind: String,
    pub at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub action: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub severity: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mail_from: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rcpt_to: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subject: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub threat: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub attachment: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hold_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub summary: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub dry_run: bool,
}

/// One delivery attempt's outcome.
pub enum PostOutcome {
    /// 2xx — delivered.
    Ok,
    /// Network error or 429/5xx — caller backs off and retries.
    Retryable(String),
    /// 4xx (other than 429) — will never succeed.
    Terminal(String),
}

/// Header carrying the signing timestamp (unix seconds).
pub const TIMESTAMP_HEADER: &str = "X-Secmail-Timestamp";
/// Header carrying the HMAC signature.
pub const SIGNATURE_HEADER: &str = "X-Secmail-Signature";

/// The signing headers of one delivery attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// Value of [`TIMESTAMP_HEADER`].
    pub timestamp: String,
    /// Value of [`SIGNATURE_HEADER`] (`sha256=<hex>`).
    pub signature: String,
}

/// HTTP transport for a single POST attempt.
pub trait Transport: Send + Sync {
    /// Posts `body` to `url`. With `signature`, sends its timestamp and
    /// signature as the [`TIMESTAMP_HEADER`] / [`SIGNATURE_HEADER`] headers.
    fn post(&self, url: &str, body: &[u8], signature: Option<&Signature>) -> PostOutcome;
}

/// Receives an event that could not be delivered after every attempt.
pub trait DeadLetter: Send + Sync {
    fn fail(&self, event: &Event, body: &[u8], last_err: &str);
}

/// Posts events to a configured URL. Construct with [`Notifier::new`]; a
/// disabled notifier (empty URL) is represented as `None`.
pub struct Notifier {
    url: String,
    secret: Vec<u8>,
    retries: u32,
    backoff: Duration,
    transport: Box<dyn Transport>,
    dlq: Option<Box<dyn DeadLetter>>,
    sleep: Box<dyn Fn(Duration) + Send + Sync>,
}

/// Tuning options (zero values give fire-and-forget: one attempt, no DLQ).
pub struct Options {
    pub retries: u32,
    pub backoff: Duration,
    pub dlq: Option<Box<dyn DeadLetter>>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            retries: 0,
            backoff: Duration::from_secs(1),
            dlq: None,
        }
    }
}

impl Notifier {
    /// Returns a Notifier, or `None` when `url` is empty (disabled).
    pub fn new(
        url: &str,
        secret: &str,
        transport: Box<dyn Transport>,
        opts: Options,
    ) -> Option<Self> {
        if url.is_empty() {
            return None;
        }
        let backoff = if opts.backoff.is_zero() {
            Duration::from_secs(1)
        } else {
            opts.backoff
        };
        Some(Notifier {
            url: url.to_string(),
            secret: secret.as_bytes().to_vec(),
            retries: opts.retries,
            backoff,
            transport,
            dlq: opts.dlq,
            sleep: Box::new(std::thread::sleep),
        })
    }

    #[cfg(test)]
    pub fn with_sleep(mut self, sleep: Box<dyn Fn(Duration) + Send + Sync>) -> Self {
        self.sleep = sleep;
        self
    }

    /// Delivers `event`, attempting up to `1 + retries` times with exponential
    /// backoff; on final failure it hands the event to the dead-letter sink.
    pub fn deliver(&self, mut event: Event) {
        if event.at.is_none() {
            event.at = Some(Utc::now());
        }
        let body = match serde_json::to_vec(&event) {
            Ok(b) => b,
            Err(_) => return,
        };
        let mut delay = self.backoff;
        let mut last_err = String::new();
        for attempt in 0..=self.retries {
            if attempt > 0 {
                (self.sleep)(delay);
                delay *= 2;
            }
            // Signed per attempt so a retry carries a fresh timestamp.
            let sig = if self.secret.is_empty() {
                None
            } else {
                let ts = Utc::now().timestamp();
                Some(Signature {
                    timestamp: ts.to_string(),
                    signature: sign(&self.secret, ts, &body),
                })
            };
            match self.transport.post(&self.url, &body, sig.as_ref()) {
                PostOutcome::Ok => return,
                PostOutcome::Terminal(e) => {
                    last_err = e;
                    break;
                }
                PostOutcome::Retryable(e) => {
                    last_err = e;
                }
            }
        }
        if let Some(dlq) = &self.dlq {
            dlq.fail(&event, &body, &last_err);
        }
    }
}

/// Computes the `sha256=<hex>` HMAC signature over `"<timestamp>.<body>"`.
pub fn sign(secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(7 + tag.len() * 2);
    hex.push_str("sha256=");
    for b in tag {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// Appends one JSON line per permanently-failed event to a file.
pub struct FileDeadLetter {
    path: std::path::PathBuf,
    lock: std::sync::Mutex<()>,
}

impl FileDeadLetter {
    /// Returns a sink writing to `path`, or `None` when `path` is empty.
    pub fn new(path: &str) -> Option<Self> {
        if path.is_empty() {
            return None;
        }
        Some(FileDeadLetter {
            path: path.into(),
            lock: std::sync::Mutex::new(()),
        })
    }
}

impl DeadLetter for FileDeadLetter {
    fn fail(&self, event: &Event, _body: &[u8], last_err: &str) {
        use std::io::Write;
        #[derive(Serialize)]
        struct Record<'a> {
            failed_at: DateTime<Utc>,
            last_err: &'a str,
            event: &'a Event,
        }
        let line = match serde_json::to_string(&Record {
            failed_at: Utc::now(),
            last_err,
            event,
        }) {
            Ok(l) => l,
            Err(_) => return,
        };
        let _g = self.lock.lock().unwrap();
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(f, "{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    struct Seq {
        // Outcomes to return per call (then repeat the last).
        outcomes: Vec<u16>, // status codes; 0 = network error
        hits: Arc<AtomicU32>,
    }
    impl Transport for Seq {
        fn post(&self, _url: &str, _body: &[u8], _sig: Option<&Signature>) -> PostOutcome {
            let i = self.hits.fetch_add(1, Ordering::SeqCst) as usize;
            let code = *self
                .outcomes
                .get(i)
                .unwrap_or(self.outcomes.last().unwrap());
            classify(code)
        }
    }
    fn classify(code: u16) -> PostOutcome {
        match code {
            0 => PostOutcome::Retryable("network".into()),
            200..=299 => PostOutcome::Ok,
            429 | 500..=599 => PostOutcome::Retryable(format!("status {code}")),
            _ => PostOutcome::Terminal(format!("status {code}")),
        }
    }

    struct CapDlq {
        n: Arc<AtomicU32>,
    }
    impl DeadLetter for CapDlq {
        fn fail(&self, _e: &Event, _b: &[u8], _err: &str) {
            self.n.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn retry_then_succeed() {
        let hits = Arc::new(AtomicU32::new(0));
        let t = Seq {
            outcomes: vec![503, 503, 200],
            hits: hits.clone(),
        };
        let n = Notifier::new(
            "http://x",
            "",
            Box::new(t),
            Options {
                retries: 3,
                ..Default::default()
            },
        )
        .unwrap()
        .with_sleep(Box::new(|_| {}));
        n.deliver(Event {
            kind: "t".into(),
            ..Default::default()
        });
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn exhausted_goes_to_dead_letter() {
        let hits = Arc::new(AtomicU32::new(0));
        let dn = Arc::new(AtomicU32::new(0));
        let t = Seq {
            outcomes: vec![502],
            hits: hits.clone(),
        };
        let n = Notifier::new(
            "http://x",
            "",
            Box::new(t),
            Options {
                retries: 2,
                dlq: Some(Box::new(CapDlq { n: dn.clone() })),
                ..Default::default()
            },
        )
        .unwrap()
        .with_sleep(Box::new(|_| {}));
        n.deliver(Event {
            kind: "t".into(),
            action: "block".into(),
            ..Default::default()
        });
        assert_eq!(hits.load(Ordering::SeqCst), 3); // 1 + 2 retries
        assert_eq!(dn.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn client_error_not_retried_but_dead_lettered() {
        let hits = Arc::new(AtomicU32::new(0));
        let dn = Arc::new(AtomicU32::new(0));
        let t = Seq {
            outcomes: vec![400],
            hits: hits.clone(),
        };
        let n = Notifier::new(
            "http://x",
            "",
            Box::new(t),
            Options {
                retries: 5,
                dlq: Some(Box::new(CapDlq { n: dn.clone() })),
                ..Default::default()
            },
        )
        .unwrap()
        .with_sleep(Box::new(|_| {}));
        n.deliver(Event {
            kind: "t".into(),
            ..Default::default()
        });
        assert_eq!(hits.load(Ordering::SeqCst), 1, "4xx is terminal");
        assert_eq!(dn.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn signature_is_hmac_over_timestamp_and_body() {
        let body = b"{\"type\":\"t\"}";
        let s = sign(b"s3cr3t", 1_700_000_000, body);
        assert!(s.starts_with("sha256="));
        assert_eq!(s, sign(b"s3cr3t", 1_700_000_000, body));
        // Known value: HMAC-SHA256("s3cr3t", "1700000000." + body).
        let mut m = Hmac::<Sha256>::new_from_slice(b"s3cr3t").unwrap();
        m.update(b"1700000000.{\"type\":\"t\"}");
        let want: String = m
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(s, format!("sha256={want}"));
        // A different timestamp (replay with a new time) changes the MAC.
        assert_ne!(s, sign(b"s3cr3t", 1_700_000_001, body));
    }

    #[test]
    fn deliveries_carry_timestamp_and_signature() {
        struct Cap(std::sync::Mutex<Vec<(Vec<u8>, Option<Signature>)>>);
        impl Transport for Arc<Cap> {
            fn post(&self, _u: &str, b: &[u8], s: Option<&Signature>) -> PostOutcome {
                self.0.lock().unwrap().push((b.to_vec(), s.cloned()));
                PostOutcome::Ok
            }
        }
        let cap = Arc::new(Cap(Default::default()));
        let n =
            Notifier::new("http://x", "k3y", Box::new(cap.clone()), Options::default()).unwrap();
        n.deliver(Event {
            kind: "t".into(),
            ..Default::default()
        });
        let got = cap.0.lock().unwrap();
        let (body, sig) = &got[0];
        let sig = sig.as_ref().expect("signed");
        let ts: i64 = sig.timestamp.parse().unwrap();
        assert!((Utc::now().timestamp() - ts).abs() < 60);
        assert_eq!(sig.signature, sign(b"k3y", ts, body));
        // Unsigned without a secret.
        let cap2 = Arc::new(Cap(Default::default()));
        Notifier::new("http://x", "", Box::new(cap2.clone()), Options::default())
            .unwrap()
            .deliver(Event::default());
        assert!(cap2.0.lock().unwrap()[0].1.is_none());
    }

    #[test]
    fn disabled_without_url() {
        struct Nop;
        impl Transport for Nop {
            fn post(&self, _u: &str, _b: &[u8], _s: Option<&Signature>) -> PostOutcome {
                PostOutcome::Ok
            }
        }
        assert!(Notifier::new("", "", Box::new(Nop), Options::default()).is_none());
    }

    #[test]
    fn file_dead_letter_appends() {
        assert!(FileDeadLetter::new("").is_none());
        let dir = std::env::temp_dir().join(format!("secmail-dlq-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dlq.jsonl");
        let f = FileDeadLetter::new(path.to_str().unwrap()).unwrap();
        f.fail(
            &Event {
                kind: "dlp_outbound".into(),
                action: "block".into(),
                ..Default::default()
            },
            b"",
            "status 502",
        );
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"action\":\"block\"") && content.contains("status 502"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
