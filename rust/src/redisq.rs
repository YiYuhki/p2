//! Redis-backed analysis queue (port of the Go `internal/queue` Redis).
//!
//! Redis layout (prefix defaults to "secmail"):
//!
//! ```text
//! <prefix>:jobs:high     LIST  new mail attachments (LPUSH / consumer BRPOP)
//! <prefix>:jobs:normal   LIST  retries / rescans
//! <prefix>:results       LIST  verdicts pushed by the analyzer (LPUSH)
//! <prefix>:results:dead  LIST  undecodable / permanently-failed verdicts
//! ```
//!
//! A consumer that runs `BRPOP <prefix>:jobs:high <prefix>:jobs:normal <t>`
//! automatically drains high priority first.
//!
//! Blocking `BRPOP`s run on a connection dedicated to each consumer loop, so
//! they never stall `enqueue` / dead-letter pushes on the shared command
//! connection. A short BRPOP timeout lets the loops observe shutdown without
//! cancelling an in-flight pop (which could lose an already-popped item).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use tokio::sync::watch;

use crate::model::{Job, Verdict};
use crate::queue::{deliver_with_retry, JobHandler, Priority, Queue, ResultHandler};

const DEFAULT_PREFIX: &str = "secmail";
/// BRPOP timeout in seconds; bounds how long a loop takes to notice shutdown.
const BRPOP_TIMEOUT_SECS: f64 = 1.0;
/// Pause after a Redis error before retrying.
const ERROR_BACKOFF: Duration = Duration::from_secs(2);

/// Redis-backed [`Queue`] plus the job / verdict consumers.
pub struct RedisQueue {
    client: redis::Client,
    /// Shared connection for non-blocking commands (LPUSH etc.). Replaced
    /// after the underlying socket drops.
    conn: Mutex<MultiplexedConnection>,
    prefix: String,
}

impl RedisQueue {
    /// Opens `url` and establishes the shared command connection. An empty
    /// `prefix` falls back to "secmail".
    pub async fn connect(url: &str, prefix: &str) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| format!("redis: open {url}: {e}"))?;
        let conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("redis: connect: {e}"))?;
        let prefix = if prefix.is_empty() {
            DEFAULT_PREFIX
        } else {
            prefix
        };
        Ok(RedisQueue {
            client,
            conn: Mutex::new(conn),
            prefix: prefix.to_string(),
        })
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn jobs_key(&self, p: Priority) -> String {
        match p {
            Priority::High => format!("{}:jobs:high", self.prefix),
            Priority::Normal => format!("{}:jobs:normal", self.prefix),
        }
    }

    pub fn results_key(&self) -> String {
        format!("{}:results", self.prefix)
    }

    pub fn dead_key(&self) -> String {
        format!("{}:results:dead", self.prefix)
    }

    /// Verdicts taken by a consumer but not yet fully handled. A verdict is
    /// moved here atomically (BLMOVE) and removed once applied or
    /// dead-lettered, so a crash mid-handling does not lose it.
    pub fn processing_key(&self) -> String {
        format!("{}:results:processing", self.prefix)
    }

    /// Moves verdicts left in the processing list (by a consumer that died
    /// mid-handling) back to the consuming end of the results list, oldest
    /// first. Applying a verdict twice is harmless (duplicates are ignored).
    pub async fn recover_results(&self) -> redis::RedisResult<usize> {
        let mut conn = self.cmd_conn();
        let (src, dst) = (self.processing_key(), self.results_key());
        let mut n = 0;
        loop {
            let moved: Option<String> = redis::cmd("LMOVE")
                .arg(&src)
                .arg(&dst)
                .arg("LEFT")
                .arg("RIGHT")
                .query_async(&mut conn)
                .await?;
            if moved.is_none() {
                return Ok(n);
            }
            n += 1;
        }
    }

    /// Removes a handled verdict from the processing list.
    async fn ack_result(&self, payload: &str) {
        let mut conn = self.cmd_conn();
        if let Err(e) = conn
            .lrem::<_, _, ()>(self.processing_key(), 1, payload)
            .await
        {
            eprintln!("redisq: results: ack failed (will be re-applied on restart): {e}");
        }
    }

    /// BLMOVE results -> processing on the dedicated blocking connection.
    async fn take_result(
        &self,
        blocking: &mut Option<MultiplexedConnection>,
    ) -> redis::RedisResult<Option<String>> {
        if blocking.is_none() {
            *blocking = Some(self.client.get_multiplexed_async_connection().await?);
        }
        let conn = blocking.as_mut().expect("blocking connection set");
        let res = conn
            .blmove(
                self.results_key(),
                self.processing_key(),
                redis::Direction::Right,
                redis::Direction::Left,
                BRPOP_TIMEOUT_SECS,
            )
            .await;
        if res.is_err() {
            *blocking = None;
        }
        res
    }

    fn cmd_conn(&self) -> MultiplexedConnection {
        self.conn.lock().unwrap().clone()
    }

    /// Re-establishes the shared command connection after it dropped.
    async fn reconnect_cmd(&self) {
        match self.client.get_multiplexed_async_connection().await {
            Ok(c) => *self.conn.lock().unwrap() = c,
            Err(e) => eprintln!("redisq: reconnect failed: {e}"),
        }
    }

    /// LPUSH on the shared connection, reconnecting once if it dropped.
    async fn lpush(&self, key: &str, value: &str) -> redis::RedisResult<()> {
        let mut conn = self.cmd_conn();
        match conn.lpush::<_, _, ()>(key, value).await {
            Err(e) if e.is_connection_dropped() || e.is_unrecoverable_error() => {
                self.reconnect_cmd().await;
                let mut conn = self.cmd_conn();
                conn.lpush::<_, _, ()>(key, value).await
            }
            r => r,
        }
    }

    async fn dead_letter(&self, payload: &str) {
        if let Err(e) = self.lpush(&self.dead_key(), payload).await {
            eprintln!("redisq: results: dead-letter push failed: {e}");
        }
    }

    /// BRPOP on a dedicated connection (opened lazily, dropped on error so the
    /// next call reconnects). `Ok(None)` is a timeout.
    async fn brpop(
        &self,
        blocking: &mut Option<MultiplexedConnection>,
        keys: &[String],
    ) -> redis::RedisResult<Option<[String; 2]>> {
        if blocking.is_none() {
            *blocking = Some(self.client.get_multiplexed_async_connection().await?);
        }
        let conn = blocking.as_mut().expect("blocking connection set");
        let res = conn.brpop(keys, BRPOP_TIMEOUT_SECS).await;
        if res.is_err() {
            *blocking = None;
        }
        res
    }

    /// Consumes verdicts until `shutdown` turns true (or its sender drops),
    /// applying each with retry; undecodable and permanently-failed verdicts
    /// are pushed to `<prefix>:results:dead`. Each verdict is moved to
    /// `<prefix>:results:processing` while it is handled and removed after,
    /// and verdicts found there at startup are re-queued first.
    pub async fn consume_results<H: ResultHandler>(
        &self,
        handler: &H,
        mut shutdown: watch::Receiver<bool>,
    ) {
        match self.recover_results().await {
            Ok(0) => {}
            Ok(n) => eprintln!("redisq: results: recovered {n} unacknowledged verdict(s)"),
            Err(e) => eprintln!("redisq: results: recovery failed: {e}"),
        }
        let mut blocking = None;
        while !stopping(&shutdown) {
            let payload = match self.take_result(&mut blocking).await {
                Ok(Some(payload)) => payload,
                Ok(None) => continue,
                Err(e) => {
                    eprintln!("redisq: results: blmove failed: {e}");
                    backoff(&mut shutdown).await;
                    continue;
                }
            };
            self.handle_result(handler, &payload).await;
            self.ack_result(&payload).await;
        }
    }

    async fn handle_result<H: ResultHandler>(&self, handler: &H, payload: &str) {
        let v: Verdict = match serde_json::from_str::<Verdict>(payload) {
            Ok(v) if !v.attachment_id.is_empty() => v,
            Ok(_) => {
                eprintln!("redisq: results: verdict without attachment_id, moved to dead list");
                self.dead_letter(payload).await;
                return;
            }
            Err(e) => {
                eprintln!("redisq: results: undecodable verdict, moved to dead list: {e}");
                self.dead_letter(payload).await;
                return;
            }
        };
        // deliver_with_retry's dead-letter hook is synchronous: record the
        // decision and do the async push afterwards.
        let dead = AtomicBool::new(false);
        deliver_with_retry(
            handler,
            &v,
            || dead.store(true, Ordering::SeqCst),
            tokio::time::sleep,
        )
        .await;
        if dead.load(Ordering::SeqCst) {
            eprintln!(
                "redisq: results: permanent verdict error, dead-lettering attachment {}",
                v.attachment_id
            );
            self.dead_letter(payload).await;
        }
    }

    /// Consumes jobs (high priority first) until `shutdown` turns true (or its
    /// sender drops). Handler failures are logged; the stale-job sweep
    /// re-queues the attachment.
    pub async fn consume_jobs<H: JobHandler>(
        &self,
        handler: &H,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let keys = [
            self.jobs_key(Priority::High),
            self.jobs_key(Priority::Normal),
        ];
        let mut blocking = None;
        while !stopping(&shutdown) {
            let payload = match self.brpop(&mut blocking, &keys).await {
                Ok(Some([_, payload])) => payload,
                Ok(None) => continue,
                Err(e) => {
                    eprintln!("redisq: jobs: brpop failed: {e}");
                    backoff(&mut shutdown).await;
                    continue;
                }
            };
            let job: Job = match serde_json::from_str(&payload) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("redisq: jobs: undecodable job, dropped: {e}");
                    continue;
                }
            };
            if let Err(e) = handler.handle(&job).await {
                eprintln!(
                    "redisq: jobs: handler failed for attachment {}; stale-job sweep will re-queue: {e}",
                    job.attachment_id
                );
            }
        }
    }
}

#[async_trait]
impl Queue for RedisQueue {
    async fn enqueue(&self, job: Job, priority: Priority) -> Result<(), String> {
        let body = serde_json::to_string(&job).map_err(|e| format!("redisq: encode job: {e}"))?;
        self.lpush(&self.jobs_key(priority), &body)
            .await
            .map_err(|e| format!("redisq: enqueue: {e}"))
    }
}

/// True once shutdown was requested or the shutdown sender is gone.
fn stopping(rx: &watch::Receiver<bool>) -> bool {
    *rx.borrow() || rx.has_changed().is_err()
}

/// Waits out the error backoff, returning early on a shutdown signal.
async fn backoff(rx: &mut watch::Receiver<bool>) {
    tokio::select! {
        _ = tokio::time::sleep(ERROR_BACKOFF) => {}
        _ = rx.changed() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{JobObject, Status};
    use crate::queue::HandlerError;
    use std::sync::Arc;

    async fn setup() -> Option<RedisQueue> {
        let url = std::env::var("SECMAIL_TEST_REDIS").ok()?;
        let prefix = format!("secmail-test-{}", uuid::Uuid::new_v4());
        Some(RedisQueue::connect(&url, &prefix).await.expect("connect"))
    }

    async fn cleanup(q: &RedisQueue) {
        let mut c = q.cmd_conn();
        let keys = [
            q.jobs_key(Priority::High),
            q.jobs_key(Priority::Normal),
            q.results_key(),
            q.dead_key(),
            q.processing_key(),
        ];
        let _: () = c.del(&keys).await.unwrap();
    }

    async fn lrange(q: &RedisQueue, key: &str) -> Vec<String> {
        q.cmd_conn().lrange(key, 0, -1).await.unwrap()
    }

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

    fn verdict(id: &str) -> Verdict {
        Verdict {
            attachment_id: id.into(),
            status: Status::Malicious,
            threat_name: "Eicar".into(),
            detail: None,
        }
    }

    struct Jobs {
        seen: Mutex<Vec<String>>,
        stop_after: usize,
        tx: watch::Sender<bool>,
    }
    #[async_trait]
    impl JobHandler for Jobs {
        async fn handle(&self, job: &Job) -> Result<(), String> {
            let mut s = self.seen.lock().unwrap();
            s.push(job.attachment_id.clone());
            if s.len() >= self.stop_after {
                let _ = self.tx.send(true);
            }
            Err("ignored: logged only".into())
        }
    }

    /// Records verdicts; fails permanently for ids starting with "perm".
    struct Results {
        seen: Mutex<Vec<(String, Status)>>,
        stop_after: usize,
        tx: watch::Sender<bool>,
    }
    #[async_trait]
    impl ResultHandler for Results {
        async fn handle(&self, v: &Verdict) -> Result<(), HandlerError> {
            let mut s = self.seen.lock().unwrap();
            s.push((v.attachment_id.clone(), v.status));
            if s.len() >= self.stop_after {
                let _ = self.tx.send(true);
            }
            if v.attachment_id.starts_with("perm") {
                return Err(HandlerError::Permanent("unknown attachment".into()));
            }
            Ok(())
        }
    }

    fn assert_send<T: Send>(_: &T) {}

    #[tokio::test]
    async fn keys_and_default_prefix() {
        let Some(q) = setup().await else { return };
        assert!(q.jobs_key(Priority::High).ends_with(":jobs:high"));
        assert!(q.jobs_key(Priority::Normal).ends_with(":jobs:normal"));
        assert_eq!(q.results_key(), format!("{}:results", q.prefix()));
        let url = std::env::var("SECMAIL_TEST_REDIS").unwrap();
        let d = RedisQueue::connect(&url, "").await.unwrap();
        assert_eq!(d.jobs_key(Priority::High), "secmail:jobs:high");
        assert_eq!(d.results_key(), "secmail:results");
        assert_eq!(d.dead_key(), "secmail:results:dead");
    }

    #[tokio::test]
    async fn connect_bad_url_errors() {
        assert!(RedisQueue::connect("not a url", "x").await.is_err());
    }

    #[tokio::test]
    async fn enqueue_lands_on_priority_list() {
        let Some(q) = setup().await else { return };
        q.enqueue(job("h1"), Priority::High).await.unwrap();
        q.enqueue(job("n1"), Priority::Normal).await.unwrap();
        q.enqueue(job("n2"), Priority::Normal).await.unwrap();

        let high = lrange(&q, &q.jobs_key(Priority::High)).await;
        let normal = lrange(&q, &q.jobs_key(Priority::Normal)).await;
        assert_eq!(high.len(), 1);
        assert_eq!(normal.len(), 2);
        let j: Job = serde_json::from_str(&high[0]).unwrap();
        assert_eq!(j.attachment_id, "h1");
        // LPUSH: newest at the head, so BRPOP yields FIFO.
        let n: Job = serde_json::from_str(&normal[1]).unwrap();
        assert_eq!(n.attachment_id, "n1");
        let raw: serde_json::Value = serde_json::from_str(&high[0]).unwrap();
        assert_eq!(raw["storage"]["type"], "fs");
        cleanup(&q).await;
    }

    #[tokio::test]
    async fn consume_jobs_drains_high_first() {
        let Some(q) = setup().await else { return };
        q.enqueue(job("n1"), Priority::Normal).await.unwrap();
        q.enqueue(job("n2"), Priority::Normal).await.unwrap();
        q.enqueue(job("h1"), Priority::High).await.unwrap();
        q.enqueue(job("h2"), Priority::High).await.unwrap();
        // An undecodable job is dropped, not fatal.
        let _: () = q
            .cmd_conn()
            .lpush(q.jobs_key(Priority::Normal), "{bad")
            .await
            .unwrap();

        let (tx, rx) = watch::channel(false);
        let h = Jobs {
            seen: Mutex::new(Vec::new()),
            stop_after: 4,
            tx,
        };
        let fut = q.consume_jobs(&h, rx);
        assert_send(&fut);
        tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .expect("consume_jobs stops after shutdown");
        assert_eq!(*h.seen.lock().unwrap(), vec!["h1", "h2", "n1", "n2"]);
        cleanup(&q).await;
    }

    #[tokio::test]
    async fn consume_results_applies_and_dead_letters() {
        let Some(q) = setup().await else { return };
        let mut c = q.cmd_conn();
        let rk = q.results_key();
        let good = serde_json::to_string(&verdict("a1")).unwrap();
        let perm = serde_json::to_string(&verdict("perm1")).unwrap();
        let _: () = c.lpush(&rk, &good).await.unwrap();
        let _: () = c.lpush(&rk, "not json").await.unwrap();
        let _: () = c
            .lpush(&rk, r#"{"attachment_id":"","status":"CLEAN"}"#)
            .await
            .unwrap();
        let _: () = c.lpush(&rk, &perm).await.unwrap();

        let (tx, rx) = watch::channel(false);
        let h = Results {
            seen: Mutex::new(Vec::new()),
            stop_after: 2,
            tx,
        };
        let fut = q.consume_results(&h, rx);
        assert_send(&fut);
        tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .expect("consume_results stops after shutdown");

        let seen = h.seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![
                ("a1".to_string(), Status::Malicious),
                ("perm1".to_string(), Status::Malicious)
            ]
        );
        // Dead list (LPUSH, newest first): perm verdict, empty id, garbage.
        let dead = lrange(&q, &q.dead_key()).await;
        assert_eq!(
            dead,
            vec![
                perm,
                r#"{"attachment_id":"","status":"CLEAN"}"#.to_string(),
                "not json".to_string()
            ]
        );
        assert!(lrange(&q, &rk).await.is_empty());
        assert!(
            lrange(&q, &q.processing_key()).await.is_empty(),
            "handled verdicts are acknowledged"
        );
        cleanup(&q).await;
    }

    #[tokio::test]
    async fn unacknowledged_verdicts_are_recovered_on_startup() {
        let Some(q) = setup().await else { return };
        let mut c = q.cmd_conn();
        // A previous consumer took v1 then v2 (BLMOVE pushes to the head)
        // and died before acknowledging; v3 is still queued.
        let (v1, v2, v3) = (
            serde_json::to_string(&verdict("r1")).unwrap(),
            serde_json::to_string(&verdict("r2")).unwrap(),
            serde_json::to_string(&verdict("r3")).unwrap(),
        );
        let _: () = c.lpush(q.processing_key(), &v1).await.unwrap();
        let _: () = c.lpush(q.processing_key(), &v2).await.unwrap();
        let _: () = c.lpush(q.results_key(), &v3).await.unwrap();

        let (tx, rx) = watch::channel(false);
        let h = Results {
            seen: Mutex::new(Vec::new()),
            stop_after: 3,
            tx,
        };
        tokio::time::timeout(Duration::from_secs(10), q.consume_results(&h, rx))
            .await
            .expect("stops");
        let ids: Vec<String> = h
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|(i, _)| i.clone())
            .collect();
        assert_eq!(ids, ["r1", "r2", "r3"], "recovered first, oldest first");
        assert!(lrange(&q, &q.processing_key()).await.is_empty());
        assert!(lrange(&q, &q.results_key()).await.is_empty());
        cleanup(&q).await;
    }

    #[tokio::test]
    async fn shutdown_stops_idle_loops() {
        let Some(q) = setup().await else { return };
        let q = Arc::new(q);
        let (tx, rx) = watch::channel(false);
        let (jtx, _) = watch::channel(false);
        let (rtx, _) = watch::channel(false);
        let jh = Jobs {
            seen: Mutex::new(Vec::new()),
            stop_after: usize::MAX,
            tx: jtx,
        };
        let rh = Results {
            seen: Mutex::new(Vec::new()),
            stop_after: usize::MAX,
            tx: rtx,
        };
        let (q1, q2) = (q.clone(), q.clone());
        let (rx1, rx2) = (rx.clone(), rx);
        let j = tokio::spawn(async move { q1.consume_jobs(&jh, rx1).await });
        let r = tokio::spawn(async move { q2.consume_results(&rh, rx2).await });
        // While the consumers sit in BRPOP, the shared connection still works.
        tokio::time::sleep(Duration::from_millis(200)).await;
        tokio::time::timeout(
            Duration::from_secs(1),
            q.enqueue(job("x"), Priority::Normal),
        )
        .await
        .expect("enqueue not blocked by BRPOP")
        .unwrap();
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            j.await.unwrap();
            r.await.unwrap();
        })
        .await
        .expect("loops stop on shutdown");
        cleanup(&q).await;
    }

    #[tokio::test]
    async fn dropped_shutdown_sender_stops_loop() {
        let Some(q) = setup().await else { return };
        let (tx, rx) = watch::channel(false);
        let (htx, _) = watch::channel(false);
        let h = Jobs {
            seen: Mutex::new(Vec::new()),
            stop_after: usize::MAX,
            tx: htx,
        };
        drop(tx);
        tokio::time::timeout(Duration::from_secs(3), q.consume_jobs(&h, rx))
            .await
            .expect("loop stops when the sender is gone");
        cleanup(&q).await;
    }
}
