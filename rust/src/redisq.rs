//! Redis-backed analysis queue (port of the Go `internal/queue` Redis).
//!
//! Redis layout (prefix defaults to "secmail"):
//!
//! ```text
//! <prefix>:jobs:high     LIST  new mail attachments (LPUSH / consumer BRPOP)
//! <prefix>:jobs:normal   LIST  retries / rescans
//! <prefix>:results       LIST  verdicts pushed by the analyzer (LPUSH)
//! <prefix>:results:dead  LIST  undecodable / permanently-failed verdicts
//! <prefix>:results:consumers          SET     ids of verdict consumers
//! <prefix>:results:processing:<id>    LIST    verdicts consumer <id> is handling
//! <prefix>:results:alive:<id>         STRING  consumer <id>'s heartbeat (TTL)
//! ```
//!
//! Every verdict consumer (one per process) has its own processing list and
//! keeps a heartbeat key alive while it runs. Recovery (at startup and then
//! periodically) only re-queues the processing lists of consumers whose
//! heartbeat has expired, never the in-flight verdicts of live replicas. The
//! pre-heartbeat shared `<prefix>:results:processing` list is drained once on
//! startup (upgrade path).
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
/// Lifetime of a consumer's heartbeat key; a consumer silent for this long is
/// presumed dead and its processing list is re-queued.
const HEARTBEAT_TTL_SECS: u64 = 30;
/// How often a running consumer refreshes its heartbeat.
const HEARTBEAT_EVERY: Duration = Duration::from_secs(10);
/// How often a running consumer looks for dead consumers' processing lists.
const RECOVER_EVERY: Duration = Duration::from_secs(60);

/// Redis-backed [`Queue`] plus the job / verdict consumers.
pub struct RedisQueue {
    client: redis::Client,
    /// Shared connection for non-blocking commands (LPUSH etc.). Replaced
    /// after the underlying socket drops.
    conn: Mutex<MultiplexedConnection>,
    prefix: String,
    /// This process's verdict-consumer id (names its processing list).
    consumer_id: String,
    /// When the heartbeat last succeeded. Verdicts are only taken while it
    /// is fresh, so a consumer that cannot prove it is alive never holds
    /// verdicts other replicas would recover and apply concurrently.
    last_beat: Mutex<Option<tokio::time::Instant>>,
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
            consumer_id: uuid::Uuid::new_v4().to_string(),
            last_beat: Mutex::new(None),
        })
    }

    /// This process's verdict-consumer id.
    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
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

    /// Verdicts taken by this consumer but not yet fully handled. A verdict is
    /// moved here atomically (BLMOVE) and removed once applied or
    /// dead-lettered, so a crash mid-handling does not lose it.
    pub fn processing_key(&self) -> String {
        self.processing_key_for(&self.consumer_id)
    }

    fn processing_key_for(&self, id: &str) -> String {
        format!("{}:results:processing:{id}", self.prefix)
    }

    /// Set of registered verdict-consumer ids.
    pub fn consumers_key(&self) -> String {
        format!("{}:results:consumers", self.prefix)
    }

    fn heartbeat_key_for(&self, id: &str) -> String {
        format!("{}:results:alive:{id}", self.prefix)
    }

    /// Registers this consumer and (re)arms its heartbeat key, reconnecting
    /// the command connection once if it dropped.
    async fn heartbeat(&self) -> redis::RedisResult<()> {
        let r = match self.heartbeat_once().await {
            Err(_) => {
                self.reconnect_cmd().await;
                self.heartbeat_once().await
            }
            ok => ok,
        };
        if r.is_ok() {
            *self.last_beat.lock().unwrap() = Some(tokio::time::Instant::now());
        }
        r
    }

    /// True while the last successful heartbeat is younger than half its TTL.
    fn beat_fresh(&self) -> bool {
        self.last_beat
            .lock()
            .unwrap()
            .map(|t| t.elapsed() < Duration::from_secs(HEARTBEAT_TTL_SECS / 2))
            .unwrap_or(false)
    }

    async fn heartbeat_once(&self) -> redis::RedisResult<()> {
        let mut conn = self.cmd_conn();
        redis::pipe()
            .atomic()
            .sadd(self.consumers_key(), &self.consumer_id)
            .ignore()
            .set_ex(
                self.heartbeat_key_for(&self.consumer_id),
                1,
                HEARTBEAT_TTL_SECS,
            )
            .ignore()
            .query_async::<()>(&mut conn)
            .await
    }

    /// Drops the heartbeat on a clean shutdown. The consumer stays registered
    /// when its processing list is not empty (a failed ack), so the next
    /// recovery re-queues what is left.
    async fn deregister(&self) {
        let mut conn = self.cmd_conn();
        let hb = self.heartbeat_key_for(&self.consumer_id);
        if let Err(e) = conn.del::<_, ()>(&hb).await {
            eprintln!("redisq: results: drop heartbeat: {e}");
            return;
        }
        match conn.llen::<_, usize>(self.processing_key()).await {
            Ok(0) => {
                let _ = conn
                    .srem::<_, _, ()>(self.consumers_key(), &self.consumer_id)
                    .await;
            }
            Ok(_) => {}
            Err(e) => eprintln!("redisq: results: deregister: {e}"),
        }
    }

    /// Moves every entry of `src` back to the consuming end of the results
    /// list, oldest first.
    async fn drain(
        &self,
        conn: &mut MultiplexedConnection,
        src: &str,
    ) -> redis::RedisResult<usize> {
        let dst = self.results_key();
        let mut n = 0;
        loop {
            let moved: Option<String> = redis::cmd("LMOVE")
                .arg(src)
                .arg(&dst)
                .arg("LEFT")
                .arg("RIGHT")
                .query_async(conn)
                .await?;
            if moved.is_none() {
                return Ok(n);
            }
            n += 1;
        }
    }

    /// Re-queues verdicts left in the processing lists of consumers that died
    /// mid-handling (their heartbeat expired), oldest first. Live consumers'
    /// lists, including other replicas' in-flight verdicts, are left alone.
    /// Applying a verdict twice is harmless (duplicates are ignored).
    async fn recover_dead(&self) -> redis::RedisResult<usize> {
        let mut conn = self.cmd_conn();
        let ids: Vec<String> = conn.smembers(self.consumers_key()).await?;
        let mut n = 0;
        for id in ids {
            if id == self.consumer_id {
                continue;
            }
            let alive: bool = conn.exists(self.heartbeat_key_for(&id)).await?;
            if alive {
                continue;
            }
            let src = self.processing_key_for(&id);
            n += self.drain(&mut conn, &src).await?;
            // Forget the consumer once its list is empty. Should it turn out
            // to be alive after all, its next heartbeat registers it again.
            let left: usize = conn.llen(&src).await?;
            if left == 0 {
                conn.srem::<_, _, ()>(self.consumers_key(), &id).await?;
            }
        }
        Ok(n)
    }

    /// Startup recovery: registers this consumer and re-queues dead
    /// consumers' processing lists.
    pub async fn recover_results(&self) -> redis::RedisResult<usize> {
        self.heartbeat().await?;
        self.recover_dead().await
    }

    /// Removes a handled verdict from the processing list.
    async fn ack_result(&self, payload: &str) {
        let key = self.processing_key();
        let mut conn = self.cmd_conn();
        let mut r = conn.lrem::<_, _, ()>(&key, 1, payload).await;
        if r.is_err() {
            self.reconnect_cmd().await;
            let mut conn = self.cmd_conn();
            r = conn.lrem::<_, _, ()>(&key, 1, payload).await;
        }
        if let Err(e) = r {
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
    /// are pushed to `<prefix>:results:dead`. Each verdict is moved to this
    /// consumer's `<prefix>:results:processing:<id>` list while it is handled
    /// and removed after; the processing lists of dead consumers (expired
    /// heartbeat) are re-queued at startup and periodically after.
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
        let work = async {
            let mut blocking = None;
            let mut last_recover = tokio::time::Instant::now();
            while !stopping(&shutdown) {
                if last_recover.elapsed() >= RECOVER_EVERY {
                    last_recover = tokio::time::Instant::now();
                    match self.recover_dead().await {
                        Ok(0) => {}
                        Ok(n) => {
                            eprintln!("redisq: results: recovered {n} verdict(s) of dead consumers")
                        }
                        Err(e) => eprintln!("redisq: results: recovery failed: {e}"),
                    }
                }
                if !self.beat_fresh() {
                    // Prove liveness before taking work; otherwise another
                    // replica could recover what we hold and apply it too.
                    if let Err(e) = self.heartbeat().await {
                        eprintln!("redisq: results: heartbeat failed, pausing: {e}");
                        backoff(&mut shutdown).await;
                        continue;
                    }
                }
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
        };
        // The heartbeat runs beside the loop (not between verdicts) so a
        // verdict whose handling retries for a long time is not mistaken for
        // the work of a dead consumer.
        let beat = async {
            loop {
                tokio::time::sleep(HEARTBEAT_EVERY).await;
                if let Err(e) = self.heartbeat().await {
                    eprintln!("redisq: results: heartbeat failed: {e}");
                }
            }
        };
        tokio::select! {
            _ = work => {}
            _ = beat => {}
        }
        self.deregister().await;
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
        let keys: Vec<String> = c.keys(format!("{}:*", q.prefix())).await.unwrap();
        if !keys.is_empty() {
            let _: () = c.del(&keys).await.unwrap();
        }
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
        // A previous consumer ("dead": registered, heartbeat expired) took v1
        // then v2 (BLMOVE pushes to the head) and died before acknowledging;
        // v3 is still queued.
        let (v1, v2, v3) = (
            serde_json::to_string(&verdict("r1")).unwrap(),
            serde_json::to_string(&verdict("r2")).unwrap(),
            serde_json::to_string(&verdict("r3")).unwrap(),
        );
        let _: () = c.sadd(q.consumers_key(), "dead").await.unwrap();
        let _: () = c.lpush(q.processing_key_for("dead"), &v1).await.unwrap();
        let _: () = c.lpush(q.processing_key_for("dead"), &v2).await.unwrap();
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
        assert!(lrange(&q, &q.processing_key_for("dead")).await.is_empty());
        assert!(lrange(&q, &q.results_key()).await.is_empty());
        let members: Vec<String> = c.smembers(q.consumers_key()).await.unwrap();
        assert!(
            members.is_empty(),
            "dead consumer forgotten, self deregistered on shutdown: {members:?}"
        );
        let hb: bool = c
            .exists(q.heartbeat_key_for(q.consumer_id()))
            .await
            .unwrap();
        assert!(!hb, "heartbeat dropped on clean shutdown");
        cleanup(&q).await;
    }

    /// Review round 2: startup recovery used to move every entry of one
    /// shared processing list back, including the in-flight verdicts of live
    /// replicas (applied twice, concurrently). Only consumers whose heartbeat
    /// expired are recovered now.
    #[tokio::test]
    async fn recovery_skips_live_replicas() {
        let Some(q) = setup().await else { return };
        let url = std::env::var("SECMAIL_TEST_REDIS").unwrap();
        let live = RedisQueue::connect(&url, q.prefix()).await.unwrap();
        assert_ne!(live.consumer_id(), q.consumer_id());
        let mut c = q.cmd_conn();
        let inflight = serde_json::to_string(&verdict("live1")).unwrap();
        let dead = serde_json::to_string(&verdict("dead1")).unwrap();
        // A live replica (fresh heartbeat) is handling `inflight`.
        live.heartbeat().await.unwrap();
        let _: () = c.lpush(live.processing_key(), &inflight).await.unwrap();
        // A dead one left `dead` behind.
        let _: () = c.sadd(q.consumers_key(), "gone").await.unwrap();
        let _: () = c.lpush(q.processing_key_for("gone"), &dead).await.unwrap();

        assert_eq!(q.recover_results().await.unwrap(), 1);
        assert_eq!(
            lrange(&q, &live.processing_key()).await,
            vec![inflight.clone()]
        );
        let mut queued = lrange(&q, &q.results_key()).await;
        queued.sort();
        assert_eq!(queued, vec![dead]);
        let mut members: Vec<String> = c.smembers(q.consumers_key()).await.unwrap();
        members.sort();
        let mut want = vec![live.consumer_id().to_string(), q.consumer_id().to_string()];
        want.sort();
        assert_eq!(
            members, want,
            "dead consumer forgotten, both live registered"
        );

        // Once the live replica's heartbeat lapses its list is recovered too.
        let _: () = c
            .del(live.heartbeat_key_for(live.consumer_id()))
            .await
            .unwrap();
        assert_eq!(q.recover_dead().await.unwrap(), 1);
        assert!(lrange(&q, &live.processing_key()).await.is_empty());
        let hb_ttl: i64 = c.ttl(q.heartbeat_key_for(q.consumer_id())).await.unwrap();
        assert!(
            hb_ttl > 0 && hb_ttl <= HEARTBEAT_TTL_SECS as i64,
            "ttl {hb_ttl}"
        );
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
