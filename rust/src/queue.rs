//! Publishes analysis jobs to, and consumes verdicts from, the external
//! analysis engine. Port of the Go `internal/queue`. The in-memory queue (dev/
//! tests) and the verdict retry/dead-letter logic are ported here; the Redis
//! transport lands with the Redis wiring.

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::model::{Job, Verdict};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Priority {
    High,
    Normal,
}

/// A verdict-application error. `Permanent` is dead-lettered; `Transient` is
/// retried a few times before the stale-job sweep re-queues the work.
#[derive(Debug)]
pub enum HandlerError {
    Permanent(String),
    Transient(String),
}

/// Applies a verdict.
#[async_trait]
pub trait ResultHandler: Send + Sync {
    async fn handle(&self, v: &Verdict) -> Result<(), HandlerError>;
}

/// Analyzes one job (in-process analyzer).
#[async_trait]
pub trait JobHandler: Send + Sync {
    async fn handle(&self, job: &Job) -> Result<(), String>;
}

/// The publish/consume interface.
#[async_trait]
pub trait Queue: Send + Sync {
    async fn enqueue(&self, job: Job, priority: Priority) -> Result<(), String>;
}

const MAX_DELIVER_TRIES: u32 = 4;

/// Exponential backoff for a transient retry (1s, 2s, 4s, capped at 4s).
pub fn retry_backoff(attempt: u32) -> Duration {
    let d = Duration::from_secs(1) * (1 << (attempt - 1));
    d.min(Duration::from_secs(4))
}

/// Applies a verdict, retrying transient failures with backoff. Permanent
/// failures invoke `dead_letter`; transient failures past the try limit drop
/// the verdict (the stale-job sweep re-queues the job). `sleep` is injectable.
pub async fn deliver_with_retry<H, D, S, F>(handler: &H, v: &Verdict, dead_letter: D, sleep: S)
where
    H: ResultHandler,
    D: Fn(),
    S: Fn(Duration) -> F,
    F: std::future::Future<Output = ()>,
{
    let mut attempt = 1u32;
    loop {
        match handler.handle(v).await {
            Ok(()) => return,
            Err(HandlerError::Permanent(_)) => {
                dead_letter();
                return;
            }
            Err(HandlerError::Transient(_)) => {
                if attempt >= MAX_DELIVER_TRIES {
                    return;
                }
                sleep(retry_backoff(attempt)).await;
                attempt += 1;
            }
        }
    }
}

/// In-memory queue for development and tests.
pub struct Memory {
    jobs_log: Mutex<Vec<Job>>,
    jobs_tx: mpsc::UnboundedSender<Job>,
    jobs_rx: Mutex<Option<mpsc::UnboundedReceiver<Job>>>,
    results_tx: mpsc::UnboundedSender<Verdict>,
    results_rx: Mutex<Option<mpsc::UnboundedReceiver<Verdict>>>,
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

impl Memory {
    pub fn new() -> Self {
        let (jobs_tx, jobs_rx) = mpsc::unbounded_channel();
        let (results_tx, results_rx) = mpsc::unbounded_channel();
        Memory {
            jobs_log: Mutex::new(Vec::new()),
            jobs_tx,
            jobs_rx: Mutex::new(Some(jobs_rx)),
            results_tx,
            results_rx: Mutex::new(Some(results_rx)),
        }
    }

    /// All enqueued jobs so far (tests).
    pub fn snapshot(&self) -> Vec<Job> {
        self.jobs_log.lock().unwrap().clone()
    }

    /// Simulates an analyzer reply.
    pub fn push_result(&self, v: Verdict) {
        let _ = self.results_tx.send(v);
    }

    /// Consumes verdicts until the results channel closes, applying each with
    /// retry/dead-letter. Takes the receiver (single consumer).
    pub async fn consume_results<H: ResultHandler>(&self, handler: &H) {
        let mut rx = self
            .results_rx
            .lock()
            .unwrap()
            .take()
            .expect("results already consumed");
        while let Some(v) = rx.recv().await {
            deliver_with_retry(handler, &v, || {}, |_d| async {}).await;
        }
    }

    /// Consumes jobs until the jobs channel closes (in-process analyzer).
    pub async fn consume_jobs<H: JobHandler>(&self, handler: &H) {
        let mut rx = self
            .jobs_rx
            .lock()
            .unwrap()
            .take()
            .expect("jobs already consumed");
        while let Some(job) = rx.recv().await {
            let _ = handler.handle(&job).await;
        }
    }
}

#[async_trait]
impl Queue for Memory {
    async fn enqueue(&self, job: Job, _priority: Priority) -> Result<(), String> {
        self.jobs_log.lock().unwrap().push(job.clone());
        let _ = self.jobs_tx.send(job);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{JobObject, Status};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    fn job(id: &str) -> Job {
        Job {
            version: 1,
            attachment_id: id.into(),
            message_id: "m1".into(),
            filename: "a.pdf".into(),
            content_type: "application/pdf".into(),
            size: 10,
            sha256: "x".into(),
            storage: JobObject {
                kind: "fs".into(),
                bucket: String::new(),
                key: "k".into(),
            },
            content_url: String::new(),
            verdict_url: String::new(),
            attempt: 0,
            enqueued_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn enqueue_records_and_snapshots() {
        let q = Memory::new();
        q.enqueue(job("a1"), Priority::High).await.unwrap();
        q.enqueue(job("a2"), Priority::Normal).await.unwrap();
        let snap = q.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].attachment_id, "a1");
    }

    struct CountHandler {
        calls: Arc<AtomicU32>,
        // Return outcome per call index: Ok=0, Transient=1, Permanent=2.
        plan: Vec<u8>,
    }
    #[async_trait]
    impl ResultHandler for CountHandler {
        async fn handle(&self, _v: &Verdict) -> Result<(), HandlerError> {
            let i = self.calls.fetch_add(1, Ordering::SeqCst) as usize;
            match self.plan.get(i).copied().unwrap_or(0) {
                1 => Err(HandlerError::Transient("t".into())),
                2 => Err(HandlerError::Permanent("p".into())),
                _ => Ok(()),
            }
        }
    }

    #[tokio::test]
    async fn retry_then_succeed() {
        let calls = Arc::new(AtomicU32::new(0));
        let h = CountHandler {
            calls: calls.clone(),
            plan: vec![1, 1, 0],
        };
        let v = Verdict {
            attachment_id: "a".into(),
            status: Status::Clean,
            threat_name: String::new(),
            detail: None,
        };
        let dead = Arc::new(AtomicU32::new(0));
        let d = dead.clone();
        deliver_with_retry(
            &h,
            &v,
            || {
                d.fetch_add(1, Ordering::SeqCst);
            },
            |_| async {},
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(dead.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn permanent_dead_letters() {
        let calls = Arc::new(AtomicU32::new(0));
        let h = CountHandler {
            calls: calls.clone(),
            plan: vec![2],
        };
        let v = Verdict {
            attachment_id: "a".into(),
            status: Status::Error,
            threat_name: String::new(),
            detail: None,
        };
        let dead = Arc::new(AtomicU32::new(0));
        let d = dead.clone();
        deliver_with_retry(
            &h,
            &v,
            || {
                d.fetch_add(1, Ordering::SeqCst);
            },
            |_| async {},
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(dead.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn transient_exhausts_without_dead_letter() {
        let calls = Arc::new(AtomicU32::new(0));
        let h = CountHandler {
            calls: calls.clone(),
            plan: vec![1, 1, 1, 1, 1],
        };
        let v = Verdict {
            attachment_id: "a".into(),
            status: Status::Clean,
            threat_name: String::new(),
            detail: None,
        };
        let dead = Arc::new(AtomicU32::new(0));
        let d = dead.clone();
        deliver_with_retry(
            &h,
            &v,
            || {
                d.fetch_add(1, Ordering::SeqCst);
            },
            |_| async {},
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 4); // MAX_DELIVER_TRIES
        assert_eq!(dead.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn consume_results_drains() {
        let q = Memory::new();
        let calls = Arc::new(AtomicU32::new(0));
        let h = CountHandler {
            calls: calls.clone(),
            plan: vec![],
        };
        q.push_result(Verdict {
            attachment_id: "a".into(),
            status: Status::Clean,
            threat_name: String::new(),
            detail: None,
        });
        q.push_result(Verdict {
            attachment_id: "b".into(),
            status: Status::Malicious,
            threat_name: "x".into(),
            detail: None,
        });
        // The queue holds its own sender, so the consumer never ends on its own;
        // a short timeout bounds the drain and both queued verdicts are applied.
        let _ = tokio::time::timeout(Duration::from_millis(50), q.consume_results(&h)).await;
        assert!(calls.load(Ordering::SeqCst) >= 2);
    }
}
