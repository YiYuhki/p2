//! The inbound SMTP proxy. Port of the Go `internal/gateway` server: a before-
//! queue, lock-step proxy — MAIL and RCPT are forwarded to the upstream mail
//! server immediately, and the (possibly rewritten) message is relayed during
//! DATA, so the gateway needs no local spool.
//!
//! Hardening: optional client allow-list (outbound listener open-relay
//! protection), global and per-IP connection caps, idle and whole-session
//! timeouts, bounded command lines, a recipient cap, a cap on concurrent DATA
//! phases, strict RFC 5321 path parsing and in-sync draining of oversize
//! messages.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Instant};

use crate::tls::BoxIo;

use crate::smtpclient::{self, Client, DataError, LineRead, Options as UpstreamOptions};

/// Default idle timeout waiting for a client command or DATA bytes.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Default timeout for writing one reply to the client.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(60);
/// Default limit on the whole SMTP session (slow-loris defense).
pub const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Default cap on concurrent connections per listener.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;
/// Default cap on concurrent connections per client IP (IPv6: per /64).
pub const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 50;
/// Default cap on recipients per transaction.
pub const DEFAULT_MAX_RECIPIENTS: usize = 100;
/// Default cap on a command line, including CRLF.
pub const DEFAULT_MAX_LINE_LENGTH: usize = 2048;
/// Default cap on concurrent DATA phases (messages buffered in memory).
pub const DEFAULT_MAX_CONCURRENT_DATA: usize = 32;
/// Limit on one DATA phase (client upload).
pub const DEFAULT_DATA_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Concurrent DATA phases from one client IP (or IPv6 /64).
pub const DEFAULT_MAX_DATA_PER_IP: usize = 8;
/// Limit on processing one message (quarantine, auth, signing).
pub const DEFAULT_PROCESS_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// How long DATA waits for a free slot before answering 451.
const DATA_SLOT_WAIT: Duration = Duration::from_secs(30);
/// Protocol errors tolerated before the session is dropped.
const MAX_ERRORS: u32 = 20;

/// SMTP error reply.
#[derive(Clone, Debug)]
pub struct SmtpError {
    pub code: u16,
    pub message: String,
}

impl SmtpError {
    pub fn new(code: u16, message: &str) -> Self {
        SmtpError {
            code,
            message: message.to_string(),
        }
    }
}

/// The message envelope handed to the processor.
#[derive(Clone, Debug, Default)]
pub struct Envelope {
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    pub remote_addr: String,
    pub helo: String,
    pub tls: bool,
}

/// Outcome of processing a message before relay.
#[derive(Debug)]
pub enum ProcessError {
    /// The processor kept the message (DLP hold): client gets 250, nothing relayed.
    Held,
    /// Reply with this SMTP error to the client.
    Reject(SmtpError),
    /// Transient failure: the client should retry (451).
    TempFail,
}

/// Transforms (inbound) or inspects (outbound) a message before it is relayed.
#[async_trait]
pub trait MessageProcessor: Send + Sync {
    async fn process(&self, env: &Envelope, raw: &[u8]) -> Result<Vec<u8>, ProcessError>;
}

/// Consulted at connection time (DNSBL). A `Some` rejects the connection.
#[async_trait]
pub trait ConnGate: Send + Sync {
    async fn gate(&self, ip: IpAddr) -> Option<SmtpError>;
}

/// Defers the first delivery of each unseen triplet (greylisting).
pub trait Greylister: Send + Sync {
    fn allow(&self, ip: &str, from: &str, to: &str) -> bool;
}

/// Caps the per-client-IP message rate.
pub trait RateLimiter: Send + Sync {
    fn allow(&self, key: &str) -> bool;
}

impl Greylister for crate::greylist::Greylist {
    fn allow(&self, ip: &str, from: &str, to: &str) -> bool {
        crate::greylist::Greylist::allow(self, ip, from, to)
    }
}
impl RateLimiter for crate::ratelimit::Limiter {
    fn allow(&self, key: &str) -> bool {
        crate::ratelimit::Limiter::allow(self, key)
    }
}

/// Backend configuration. Zero numeric/duration limits select the
/// `DEFAULT_*` constants of this module.
#[derive(Default)]
pub struct BackendOptions {
    pub recipient_domains: Vec<String>,
    pub sender_domains: Vec<String>,
    pub upstream: UpstreamOptions,
    pub name: String,
    pub hostname: String,
    /// Maximum message size in bytes (0 = unlimited).
    pub max_message_bytes: usize,
    pub conn_gate: Option<Arc<dyn ConnGate>>,
    pub greylist: Option<Arc<dyn Greylister>>,
    pub rate_limit: Option<Arc<dyn RateLimiter>>,
    /// Offer STARTTLS with this server configuration.
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// Refuse MAIL until the client has negotiated TLS.
    pub require_tls: bool,
    /// When non-empty, only peers inside these IPs/CIDRs may connect; others
    /// get 554 and are disconnected. Invalid entries are ignored (logged), and
    /// a non-empty list with no valid entry rejects everyone (fail closed).
    pub allowed_clients: Vec<String>,
    /// Idle timeout per client read (0 -> [`DEFAULT_READ_TIMEOUT`]).
    pub read_timeout: Duration,
    /// Timeout per client write (0 -> [`DEFAULT_WRITE_TIMEOUT`]).
    pub write_timeout: Duration,
    /// Limit on the whole session (0 -> [`DEFAULT_SESSION_TIMEOUT`]).
    pub session_timeout: Duration,
    /// Concurrent connections (0 -> [`DEFAULT_MAX_CONNECTIONS`]).
    pub max_connections: usize,
    /// Concurrent connections per IP / IPv6 /64
    /// (0 -> [`DEFAULT_MAX_CONNECTIONS_PER_IP`]).
    pub max_connections_per_ip: usize,
    /// Recipients per transaction (0 -> [`DEFAULT_MAX_RECIPIENTS`]).
    pub max_recipients: usize,
    /// Command line length incl. CRLF (0 -> [`DEFAULT_MAX_LINE_LENGTH`]).
    pub max_line_length: usize,
    /// Concurrent DATA phases (0 -> [`DEFAULT_MAX_CONCURRENT_DATA`]).
    pub max_concurrent_data: usize,
    /// Limit on one DATA upload (0 -> [`DEFAULT_DATA_TIMEOUT`]).
    pub data_timeout: Duration,
    /// Concurrent DATA phases per client IP (0 -> [`DEFAULT_MAX_DATA_PER_IP`]).
    pub max_data_per_ip: usize,
    /// Limit on processing one message (0 -> [`DEFAULT_PROCESS_TIMEOUT`]).
    pub process_timeout: Duration,
}

/// An IP network (address + prefix length) from `allowed_clients`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Parses "192.0.2.7", "192.0.2.0/24", "2001:db8::/32" or "[::1]".
    pub fn parse(s: &str) -> Result<IpNet, String> {
        let s = s.trim();
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let a = a.trim_start_matches('[').trim_end_matches(']');
        let addr: IpAddr = a.parse().map_err(|_| format!("invalid IP/CIDR {s:?}"))?;
        let addr = addr.to_canonical();
        let max: u8 = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            None => max,
            Some(p) => {
                let mut n: u8 = p.parse().map_err(|_| format!("invalid prefix in {s:?}"))?;
                // An IPv4-mapped IPv6 CIDR (::ffff:a.b.c.d/120) maps onto IPv4.
                if addr.is_ipv4() && a.contains(':') {
                    n = n
                        .checked_sub(96)
                        .ok_or_else(|| format!("invalid prefix in {s:?}"))?;
                }
                if n > max {
                    return Err(format!("invalid prefix in {s:?}"));
                }
                n
            }
        };
        Ok(IpNet { addr, prefix })
    }

    /// Whether `ip` lies inside the network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(n) & mask == u32::from(i) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(i) & mask
            }
            _ => false,
        }
    }
}

/// The key connection caps, rate limits and greylisting use for a client:
/// the address itself for IPv4, its /64 for IPv6 (one end site).
fn ip_bucket(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        v4 => v4,
    }
}

fn ip_key(ip: IpAddr) -> String {
    match ip_bucket(ip) {
        IpAddr::V6(v6) => format!("{v6}/64"),
        v4 => v4.to_string(),
    }
}

type ConnCounts = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// Takes one slot for `ip` (bucketed) from `counts` unless `max` are in use.
fn take_slot(counts: &ConnCounts, max: usize, ip: IpAddr) -> Option<IpSlot> {
    let key = ip_bucket(ip);
    let mut m = counts.lock().unwrap_or_else(|e| e.into_inner());
    let c = m.entry(key).or_insert(0);
    if *c >= max {
        if *c == 0 {
            m.remove(&key);
        }
        return None;
    }
    *c += 1;
    Some(IpSlot {
        counts: counts.clone(),
        key,
    })
}

/// Holds one per-IP connection slot; releases it on drop.
struct IpSlot {
    counts: ConnCounts,
    key: IpAddr,
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut m = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = m.get_mut(&self.key) {
            *c -= 1;
            if *c == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// Effective limits after applying defaults.
#[derive(Clone, Copy)]
struct Limits {
    read: Duration,
    write: Duration,
    session: Duration,
    max_recipients: usize,
    max_line: usize,
    data: Duration,
    process: Duration,
}

/// The inbound/outbound backend.
pub struct Backend {
    proc: Arc<dyn MessageProcessor>,
    opts: BackendOptions,
    /// `None` = any client may connect.
    allowed: Option<Vec<IpNet>>,
    limits: Limits,
    conn_sem: Arc<Semaphore>,
    data_sem: Arc<Semaphore>,
    per_ip: ConnCounts,
    max_per_ip: usize,
    data_per_ip: ConnCounts,
    max_data_per_ip: usize,
}

fn or_default<T: PartialEq + Default>(v: T, d: T) -> T {
    if v == T::default() {
        d
    } else {
        v
    }
}

impl Backend {
    pub fn new(proc: Arc<dyn MessageProcessor>, mut opts: BackendOptions) -> Self {
        if opts.name.is_empty() {
            opts.name = "inbound".into();
        }
        if opts.hostname.is_empty() {
            opts.hostname = "localhost".into();
        }
        let allowed = if opts.allowed_clients.is_empty() {
            None
        } else {
            let mut nets = Vec::new();
            for c in &opts.allowed_clients {
                match IpNet::parse(c) {
                    Ok(n) => nets.push(n),
                    Err(e) => eprintln!("smtp {}: allowed_clients: {e} (ignored)", opts.name),
                }
            }
            Some(nets)
        };
        let limits = Limits {
            read: or_default(opts.read_timeout, DEFAULT_READ_TIMEOUT),
            write: or_default(opts.write_timeout, DEFAULT_WRITE_TIMEOUT),
            session: or_default(opts.session_timeout, DEFAULT_SESSION_TIMEOUT),
            max_recipients: or_default(opts.max_recipients, DEFAULT_MAX_RECIPIENTS),
            max_line: or_default(opts.max_line_length, DEFAULT_MAX_LINE_LENGTH),
            data: or_default(opts.data_timeout, DEFAULT_DATA_TIMEOUT),
            process: or_default(opts.process_timeout, DEFAULT_PROCESS_TIMEOUT),
        };
        let max_data_per_ip = or_default(opts.max_data_per_ip, DEFAULT_MAX_DATA_PER_IP);
        let max_conn = or_default(opts.max_connections, DEFAULT_MAX_CONNECTIONS);
        let max_data = or_default(opts.max_concurrent_data, DEFAULT_MAX_CONCURRENT_DATA);
        let max_per_ip = or_default(opts.max_connections_per_ip, DEFAULT_MAX_CONNECTIONS_PER_IP);
        Backend {
            proc,
            opts,
            allowed,
            limits,
            conn_sem: Arc::new(Semaphore::new(max_conn)),
            data_sem: Arc::new(Semaphore::new(max_data)),
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip,
            data_per_ip: Arc::new(Mutex::new(HashMap::new())),
            max_data_per_ip,
        }
    }

    /// Serves the SMTP proxy on `listener`. Accept errors (e.g. EMFILE) are
    /// logged and retried after a short pause; this never returns normally.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("smtp {}: accept: {e}", self.opts.name);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let backend = self.clone();
            tokio::spawn(async move {
                backend.handle_conn(stream, peer).await;
            });
        }
    }

    fn client_allowed(&self, ip: IpAddr) -> bool {
        match &self.allowed {
            None => true,
            Some(nets) => nets.iter().any(|n| n.contains(ip)),
        }
    }

    fn ip_slot(&self, ip: IpAddr) -> Option<IpSlot> {
        take_slot(&self.per_ip, self.max_per_ip, ip)
    }

    /// Writes one reply and closes, bounded by the write timeout.
    async fn refuse(&self, mut stream: TcpStream, code: u16, msg: &str) {
        let line = format!("{code} {msg}\r\n");
        let _ = timeout(self.limits.write.min(Duration::from_secs(10)), async {
            stream.write_all(line.as_bytes()).await?;
            stream.shutdown().await
        })
        .await;
    }

    /// Applies the connection-level policy (allow-list, caps) and runs the
    /// session under the overall deadline.
    async fn handle_conn(&self, stream: TcpStream, peer: SocketAddr) {
        let ip = peer.ip().to_canonical();
        if !self.client_allowed(ip) {
            self.refuse(
                stream,
                554,
                "5.7.1 Client host not authorized to use this server",
            )
            .await;
            return;
        }
        let _permit = match self.conn_sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                self.refuse(stream, 421, "4.3.2 Too many connections, try again later")
                    .await;
                return;
            }
        };
        let _slot = match self.ip_slot(ip) {
            Some(s) => s,
            None => {
                self.refuse(stream, 421, "4.7.0 Too many connections from your host")
                    .await;
                return;
            }
        };
        let _ = stream.set_nodelay(true);
        let deadline = Instant::now() + self.limits.session;
        // Hard backstop in case a step outside the client I/O wrappers stalls.
        let backstop = self.limits.session + self.limits.read + self.limits.write;
        let _ = timeout(backstop, self.handle(stream, peer, ip, deadline)).await;
    }

    async fn handle(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        ip: IpAddr,
        deadline: Instant,
    ) -> std::io::Result<()> {
        let remote = peer.to_string();
        let key = ip_key(ip);
        let lim = self.limits;
        let mut conn = Conn {
            io: BufReader::new(Box::new(stream)),
            write_to: lim.write,
        };
        let mut tls_on = false;

        // Connection gate (DNSBL).
        if let Some(gate) = &self.opts.conn_gate {
            if let Some(err) = gate.gate(ip).await {
                conn.reply(err.code, &err.message).await?;
                return Ok(());
            }
        }

        conn.reply(220, &format!("{} ESMTP secmail", self.opts.hostname))
            .await?;

        let mut txn = Txn::default();
        let mut helo = String::new();
        let mut errors = 0u32;
        let mut buf = Vec::with_capacity(256);

        loop {
            if errors >= MAX_ERRORS {
                conn.reply(421, "4.7.0 Too many errors, closing connection")
                    .await?;
                break;
            }
            // Read one command line, bounded in size and time.
            let now = Instant::now();
            if now >= deadline {
                conn.reply(421, "4.4.2 Session time limit exceeded, closing connection")
                    .await?;
                break;
            }
            let wait = lim.read.min(deadline - now);
            let r = match timeout(
                wait,
                smtpclient::read_line_limited(&mut conn.io, &mut buf, lim.max_line),
            )
            .await
            {
                Ok(r) => r?,
                Err(_) => {
                    let msg = if Instant::now() >= deadline {
                        "4.4.2 Session time limit exceeded, closing connection"
                    } else {
                        "4.4.2 Idle timeout, closing connection"
                    };
                    conn.reply(421, msg).await?;
                    break;
                }
            };
            match r {
                LineRead::Eof => break,
                LineRead::TooLong => {
                    errors += 1;
                    conn.reply(500, "5.5.2 Line too long").await?;
                    continue;
                }
                LineRead::Line => {}
            }
            let line = String::from_utf8_lossy(&buf);
            let line = line.trim_end_matches(['\r', '\n']);
            let (cmd, arg) = split_cmd(line);
            match cmd.as_str() {
                "HELO" | "EHLO" => {
                    if arg.is_empty() || arg.bytes().any(|b| b < 0x20 || b == 0x7f) {
                        errors += 1;
                        conn.reply(501, &format!("5.5.4 Syntax: {cmd} hostname"))
                            .await?;
                        continue;
                    }
                    // RFC 5321 §4.1.4: HELO/EHLO resets the transaction.
                    txn.abort().await;
                    helo = arg.to_string();
                    if cmd == "HELO" {
                        conn.reply(250, &format!("{} greets {arg}", self.opts.hostname))
                            .await?;
                    } else {
                        let mut lines = vec![
                            format!("{} greets {arg}", self.opts.hostname),
                            "8BITMIME".to_string(),
                            "ENHANCEDSTATUSCODES".to_string(),
                        ];
                        if self.opts.max_message_bytes > 0 {
                            lines.push(format!("SIZE {}", self.opts.max_message_bytes));
                        }
                        if self.opts.tls.is_some() && !tls_on {
                            lines.push("STARTTLS".to_string());
                        }
                        conn.reply_multi(250, &lines).await?;
                    }
                }
                "STARTTLS" => {
                    let cfg = match (&self.opts.tls, tls_on) {
                        (Some(c), false) => c.clone(),
                        (_, true) => {
                            errors += 1;
                            conn.reply(503, "5.5.1 TLS already active").await?;
                            continue;
                        }
                        (None, _) => {
                            errors += 1;
                            conn.reply(502, "5.5.1 Command not implemented").await?;
                            continue;
                        }
                    };
                    if !arg.is_empty() {
                        errors += 1;
                        conn.reply(501, "5.5.4 Syntax: STARTTLS").await?;
                        continue;
                    }
                    conn.reply(220, "2.0.0 Ready to start TLS").await?;
                    // into_inner drops any pipelined plaintext (command injection).
                    let io = conn.take_io().into_inner();
                    let wait = lim
                        .read
                        .min(deadline.saturating_duration_since(Instant::now()));
                    let tls = match timeout(wait, crate::tls::accept(io, cfg)).await {
                        Ok(r) => r?,
                        Err(_) => return Ok(()),
                    };
                    conn.io = BufReader::new(tls);
                    tls_on = true;
                    // RFC 3207 §4.2: discard all prior session state.
                    helo.clear();
                    txn.abort().await;
                    if let Some(mut c) = txn.up.take() {
                        let _ = c.quit().await;
                    }
                }
                "MAIL" => {
                    // A new MAIL starts over: close any open upstream transaction
                    // first so a rejected MAIL can never leave the previous one
                    // usable.
                    txn.abort().await;
                    if self.opts.require_tls && !tls_on {
                        conn.reply(530, "5.7.0 Must issue a STARTTLS command first")
                            .await?;
                        continue;
                    }
                    let (addr, params) = match parse_path(arg, "FROM") {
                        Ok(v) => v,
                        Err(e) => {
                            errors += 1;
                            conn.reply(501, &format!("5.5.4 {e}")).await?;
                            continue;
                        }
                    };
                    let mut bad_param = None;
                    for (k, v) in &params {
                        match (k.as_str(), v) {
                            ("SIZE", Some(v)) => match v.parse::<u64>() {
                                Ok(n) => {
                                    let max = self.opts.max_message_bytes as u64;
                                    if max > 0 && n > max {
                                        bad_param = Some((
                                            552,
                                            "5.3.4 Message size exceeds fixed maximum message size",
                                        ));
                                    }
                                }
                                Err(_) => bad_param = Some((501, "5.5.4 Invalid SIZE parameter")),
                            },
                            ("BODY", Some(v))
                                if v.eq_ignore_ascii_case("7BIT")
                                    || v.eq_ignore_ascii_case("8BITMIME") => {}
                            _ => bad_param = Some((555, "5.5.4 Unsupported MAIL parameter")),
                        }
                        if bad_param.is_some() {
                            break;
                        }
                    }
                    if let Some((code, msg)) = bad_param {
                        conn.reply(code, msg).await?;
                        continue;
                    }
                    if self
                        .opts
                        .rate_limit
                        .as_ref()
                        .map(|r| !r.allow(&key))
                        .unwrap_or(false)
                    {
                        conn.reply(451, "4.7.1 Message rate limit exceeded, please slow down")
                            .await?;
                        continue;
                    }
                    if !self.opts.sender_domains.is_empty() {
                        if addr.is_empty() {
                            conn.reply(550, "5.7.1 Null sender not allowed").await?;
                            continue;
                        }
                        if !domain_in(&addr, &self.opts.sender_domains) {
                            conn.reply(550, "5.7.1 Sender domain not allowed").await?;
                            continue;
                        }
                    }
                    if txn.up.is_none() {
                        match Client::dial(&self.opts.upstream).await {
                            Ok(c) => txn.up = Some(c),
                            Err(_) => {
                                conn.reply(
                                    451,
                                    "4.4.1 Upstream mail server unavailable, please retry",
                                )
                                .await?;
                                continue;
                            }
                        }
                    }
                    let res = match txn.up.as_mut() {
                        Some(c) => c.mail(&addr).await,
                        None => continue,
                    };
                    match res {
                        Ok(()) => {
                            txn.from = addr;
                            txn.mail_ok = true;
                            txn.open = true;
                            conn.reply(250, "2.1.0 OK").await?;
                        }
                        Err(e) => conn.upstream_err(e, &mut txn.up).await?,
                    }
                }
                "RCPT" => {
                    if !txn.mail_ok || txn.up.is_none() {
                        errors += 1;
                        conn.reply(503, "5.5.1 Need MAIL command").await?;
                        continue;
                    }
                    let addr = match parse_path(arg, "TO") {
                        Ok((a, p)) if p.is_empty() && !a.is_empty() => a,
                        Ok((a, _)) if a.is_empty() => {
                            errors += 1;
                            conn.reply(501, "5.1.3 Bad recipient address syntax")
                                .await?;
                            continue;
                        }
                        Ok(_) => {
                            conn.reply(555, "5.5.4 Unsupported RCPT parameter").await?;
                            continue;
                        }
                        Err(e) => {
                            errors += 1;
                            conn.reply(501, &format!("5.5.4 {e}")).await?;
                            continue;
                        }
                    };
                    if txn.rcpt.len() >= lim.max_recipients {
                        errors += 1;
                        conn.reply(452, "4.5.3 Too many recipients").await?;
                        continue;
                    }
                    if !self.opts.recipient_domains.is_empty()
                        && !domain_in(&addr, &self.opts.recipient_domains)
                    {
                        errors += 1;
                        conn.reply(550, "5.7.1 Relaying denied").await?;
                        continue;
                    }
                    if let Some(gl) = &self.opts.greylist {
                        let sender = if txn.from.is_empty() {
                            "<>"
                        } else {
                            txn.from.as_str()
                        };
                        if !gl.allow(&key, sender, &addr) {
                            errors += 1;
                            conn.reply(451, "4.7.1 Greylisted, please retry shortly")
                                .await?;
                            continue;
                        }
                    }
                    let res = match txn.up.as_mut() {
                        Some(c) => c.rcpt(&addr).await,
                        None => continue,
                    };
                    match res {
                        Ok(()) => {
                            txn.rcpt.push(addr);
                            conn.reply(250, "2.1.5 OK").await?;
                        }
                        Err(e) => {
                            let transport = matches!(e, smtpclient::Error::Transport(_));
                            conn.upstream_err(e, &mut txn.up).await?;
                            if transport {
                                txn.clear();
                            }
                        }
                    }
                }
                "DATA" => {
                    if !txn.mail_ok || txn.up.is_none() || txn.rcpt.is_empty() {
                        errors += 1;
                        conn.reply(503, "5.5.1 Need RCPT command").await?;
                        continue;
                    }
                    let _data_slot = match take_slot(&self.data_per_ip, self.max_data_per_ip, ip) {
                        Some(s) => s,
                        None => {
                            txn.abort().await;
                            conn.reply(451, "4.7.0 Too many concurrent messages from your host")
                                .await?;
                            continue;
                        }
                    };
                    let _data_permit = match timeout(
                        DATA_SLOT_WAIT,
                        self.data_sem.clone().acquire_owned(),
                    )
                    .await
                    {
                        Ok(Ok(p)) => p,
                        _ => {
                            txn.abort().await;
                            conn.reply(451, "4.3.2 System busy, please retry").await?;
                            continue;
                        }
                    };
                    conn.reply(354, "Start mail input; end with <CRLF>.<CRLF>")
                        .await?;
                    let remaining = deadline
                        .saturating_duration_since(Instant::now())
                        .min(lim.data);
                    let read = timeout(
                        remaining,
                        smtpclient::read_data_timeout(
                            &mut conn.io,
                            self.opts.max_message_bytes,
                            Some(lim.read),
                        ),
                    )
                    .await;
                    let raw = match read {
                        Ok(Ok(b)) => b,
                        Ok(Err(DataError::TooLarge)) => {
                            // The rest of the message was drained, so the
                            // session is still in sync.
                            txn.abort().await;
                            conn.reply(552, "5.3.4 Message too big").await?;
                            continue;
                        }
                        Ok(Err(DataError::Timeout)) => {
                            txn.abort().await;
                            conn.reply(421, "4.4.2 Idle timeout, closing connection")
                                .await?;
                            break;
                        }
                        Err(_) => {
                            txn.abort().await;
                            conn.reply(
                                421,
                                "4.4.2 Session time limit exceeded, closing connection",
                            )
                            .await?;
                            break;
                        }
                        Ok(Err(DataError::Io(_))) => {
                            // Stream position unknown: never answer 552 and carry on.
                            txn.abort().await;
                            let _ = conn.reply(451, "4.3.0 Error reading message").await;
                            break;
                        }
                    };
                    let env = Envelope {
                        mail_from: txn.from.clone(),
                        rcpt_to: txn.rcpt.clone(),
                        remote_addr: remote.clone(),
                        helo: helo.clone(),
                        tls: tls_on,
                    };
                    let outcome = match timeout(lim.process, self.proc.process(&env, &raw)).await {
                        Ok(o) => o,
                        Err(_) => {
                            eprintln!("smtp {}: message processing timed out", self.opts.name);
                            Err(ProcessError::TempFail)
                        }
                    };
                    drop(raw);
                    match outcome {
                        Ok(out) => {
                            let res = match txn.up.as_mut() {
                                Some(c) => c.data(&out).await,
                                None => Err(smtpclient::Error::Transport("no upstream".into())),
                            };
                            match res {
                                Ok(()) => {
                                    txn.open = false;
                                    conn.reply(250, "2.0.0 OK: queued").await?
                                }
                                Err(e) => {
                                    // An SMTP-level rejection leaves the upstream
                                    // transaction open: RSET it so the session
                                    // stays in sync.
                                    let smtp = matches!(e, smtpclient::Error::Smtp { .. });
                                    conn.upstream_err(e, &mut txn.up).await?;
                                    if smtp {
                                        txn.abort().await;
                                    }
                                }
                            }
                        }
                        Err(ProcessError::Held) => {
                            txn.abort().await;
                            conn.reply(250, "2.0.0 OK: accepted").await?;
                        }
                        Err(ProcessError::Reject(err)) => {
                            txn.abort().await;
                            conn.reply(err.code, &err.message).await?;
                        }
                        Err(ProcessError::TempFail) => {
                            txn.abort().await;
                            conn.reply(451, "4.3.0 Temporary processing failure, please retry")
                                .await?;
                        }
                    }
                    // The upstream transaction is finished (or was reset).
                    txn.clear();
                }
                "RSET" => {
                    txn.abort().await;
                    conn.reply(250, "2.0.0 OK").await?;
                }
                "NOOP" => conn.reply(250, "2.0.0 OK").await?,
                "QUIT" => {
                    if let Some(mut c) = txn.up.take() {
                        let _ = c.quit().await;
                    }
                    conn.reply(221, "2.0.0 Bye").await?;
                    break;
                }
                _ => {
                    errors += 1;
                    conn.reply(502, "5.5.1 Command not implemented").await?;
                }
            }
        }
        Ok(())
    }
}

/// Per-session transaction state, mirrored on the upstream connection.
#[derive(Default)]
struct Txn {
    up: Option<Client>,
    from: String,
    rcpt: Vec<String>,
    /// MAIL was accepted locally and upstream (RCPT/DATA allowed).
    mail_ok: bool,
    /// An upstream transaction may be open (needs RSET before reuse).
    open: bool,
}

impl Txn {
    fn clear(&mut self) {
        self.from.clear();
        self.rcpt.clear();
        self.mail_ok = false;
    }

    /// Clears local state and RSETs the upstream if a transaction is open there.
    async fn abort(&mut self) {
        if self.open {
            self.open = false;
            if let Some(c) = self.up.as_mut() {
                if c.reset().await.is_err() {
                    // Upstream state unknown: drop it; the next MAIL redials.
                    self.up = None;
                }
            }
        }
        self.clear();
    }
}

/// The client connection with write timeouts applied to every reply.
struct Conn {
    io: BufReader<BoxIo>,
    write_to: Duration,
}

impl Conn {
    fn take_io(&mut self) -> BufReader<BoxIo> {
        std::mem::replace(
            &mut self.io,
            BufReader::new(Box::new(tokio::io::join(
                tokio::io::empty(),
                tokio::io::sink(),
            ))),
        )
    }

    async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        timeout(self.write_to, async {
            self.io.write_all(data).await?;
            self.io.flush().await
        })
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "write timed out"))?
    }

    async fn reply(&mut self, code: u16, message: &str) -> std::io::Result<()> {
        self.write(format!("{code} {message}\r\n").as_bytes()).await
    }

    async fn reply_multi(&mut self, code: u16, lines: &[String]) -> std::io::Result<()> {
        let mut out = String::new();
        for (i, l) in lines.iter().enumerate() {
            let sep = if i + 1 == lines.len() { ' ' } else { '-' };
            out.push_str(&format!("{code}{sep}{l}\r\n"));
        }
        self.write(out.as_bytes()).await
    }

    async fn upstream_err(
        &mut self,
        e: smtpclient::Error,
        up: &mut Option<Client>,
    ) -> std::io::Result<()> {
        match e {
            smtpclient::Error::Smtp { code, message } => {
                // Relay the upstream text, minus anything that could break
                // our reply framing.
                let clean: String = message
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(512)
                    .collect();
                self.reply(code, &clean).await
            }
            smtpclient::Error::Transport(_) => {
                *up = None;
                self.reply(451, "4.4.1 Upstream mail server unavailable, please retry")
                    .await
            }
        }
    }
}

fn split_cmd(line: &str) -> (String, &str) {
    let line = line.trim_start();
    match line.find(' ') {
        Some(i) => (line[..i].to_ascii_uppercase(), line[i + 1..].trim_start()),
        None => (line.to_ascii_uppercase(), ""),
    }
}

/// ESMTP parameters after the path: (UPPERCASE keyword, value).
type Params = Vec<(String, Option<String>)>;

/// Strictly parses a `FROM:<path> [params]` / `TO:<path> [params]` argument
/// (RFC 5321 §4.1.2). Returns the address ("" for the null path `<>`) and
/// the ESMTP parameters. The angle brackets are mandatory; control
/// characters, spaces and stray `<`/`>` inside the path are rejected, so
/// e.g. `TO:victim@evil.com>@example.com` cannot pass the relay check.
fn parse_path(arg: &str, kw: &str) -> Result<(String, Params), &'static str> {
    const SYNTAX: &str = "Syntax error in mailbox address";
    let head = arg
        .get(..kw.len())
        .filter(|h| h.eq_ignore_ascii_case(kw))
        .ok_or(SYNTAX)?;
    let rest = arg[head.len()..].strip_prefix(':').ok_or(SYNTAX)?;
    // Tolerate "FROM: <a@b>" (common, though not RFC-conformant).
    let rest = rest.trim_start_matches(' ');
    let rest = rest.strip_prefix('<').ok_or(SYNTAX)?;
    let close = rest.find('>').ok_or(SYNTAX)?;
    let inner = &rest[..close];
    let after = &rest[close + 1..];
    if !after.is_empty() && !after.starts_with(' ') {
        return Err(SYNTAX);
    }
    if inner.len() > 256 {
        return Err("Path too long");
    }
    if inner
        .bytes()
        .any(|b| b <= b' ' || b == 0x7f || b == b'<' || b == b'>')
    {
        return Err(SYNTAX);
    }
    // Strip an obsolete source route ("@a,@b:user@host").
    let addr = if inner.starts_with('@') {
        match inner.find(':') {
            Some(i) => &inner[i + 1..],
            None => return Err(SYNTAX),
        }
    } else {
        inner
    };
    if !addr.is_empty() && !valid_mailbox(addr) {
        return Err(SYNTAX);
    }
    let mut params = Vec::new();
    for p in after.split(' ').filter(|p| !p.is_empty()) {
        let (k, v) = match p.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (p, None),
        };
        let kb = k.as_bytes();
        if kb.is_empty()
            || !kb[0].is_ascii_alphanumeric()
            || !kb.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err("Syntax error in parameters");
        }
        if let Some(v) = v {
            if v.is_empty() || !v.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'=') {
                return Err("Syntax error in parameters");
            }
        }
        params.push((k.to_ascii_uppercase(), v.map(str::to_string)));
    }
    Ok((addr.to_string(), params))
}

/// `local@domain` (or the bare `postmaster` recipient).
fn valid_mailbox(addr: &str) -> bool {
    if addr.eq_ignore_ascii_case("postmaster") {
        return true;
    }
    // SMTPUTF8 is not offered, so addresses must be ASCII; '%' and '!' are
    // source-routing hacks some upstreams still honour (relay bypass).
    if !addr.is_ascii() {
        return false;
    }
    let Some((local, domain)) = addr.rsplit_once('@') else {
        return false;
    };
    if local.contains(['%', '!']) {
        return false;
    }
    if local.is_empty() || local.len() > 64 || domain.is_empty() || domain.len() > 255 {
        return false;
    }
    let quoted = local.len() >= 2 && local.starts_with('"') && local.ends_with('"');
    if !quoted && (local.contains('@') || local.contains('"')) {
        return false;
    }
    if let Some(lit) = domain.strip_prefix('[') {
        return lit.ends_with(']') && lit.len() > 1;
    }
    !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

fn domain_in(addr: &str, domains: &[String]) -> bool {
    let at = match addr.rfind('@') {
        Some(i) => i,
        None => return false,
    };
    let domain = addr[at + 1..].to_ascii_lowercase();
    if !domain.is_ascii() {
        return false;
    }
    domains
        .iter()
        .any(|d| domain == *d || (d.starts_with('.') && domain.ends_with(d.as_str())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncBufReadExt;

    fn path(arg: &str, kw: &str) -> Option<String> {
        parse_path(arg, kw).ok().map(|(a, _)| a)
    }

    #[test]
    fn parse_path_and_domain() {
        assert_eq!(path("FROM:<a@ext.org>", "FROM").unwrap(), "a@ext.org");
        assert_eq!(path("from: <a@ext.org>", "FROM").unwrap(), "a@ext.org");
        let (a, p) = parse_path("TO:<b@example.com> NOTIFY=NEVER", "TO").unwrap();
        assert_eq!(a, "b@example.com");
        assert_eq!(p, vec![("NOTIFY".to_string(), Some("NEVER".to_string()))]);
        let (a, p) = parse_path("FROM:<> SIZE=10 BODY=8BITMIME", "FROM").unwrap();
        assert_eq!(a, "");
        assert_eq!(p.len(), 2);
        assert_eq!(
            path("TO:<@relay.example:u@example.com>", "TO").unwrap(),
            "u@example.com"
        );
        assert_eq!(path("TO:<Postmaster>", "TO").unwrap(), "Postmaster");
        assert!(domain_in("x@example.com", &["example.com".into()]));
        assert!(domain_in("x@mail.example.com", &[".example.com".into()]));
        assert!(!domain_in("x@evil.com", &["example.com".into()]));
    }

    #[test]
    fn parse_path_rejects_malformed() {
        for bad in [
            "TO:victim@evil.com>@example.com",
            "TO:<victim@evil.com>@example.com",
            "TO:<user%evil.com@example.com>",
            "TO:<evil.com!user@example.com>",
            "TO:<ceo@exampl\u{212A}.com>",
            "TO:<u@\u{0435}xample.com>",
            "TO:victim@example.com",
            "TO:<victim@evil.com",
            "TO:<a b@example.com>",
            "TO:<a\tb@example.com>",
            "TO:<a\rb@example.com>",
            "TO:<a<b@example.com>",
            "TO:<a@evil.com@example.com>",
            "TO:<a@>",
            "TO:<@example.com>",
            "TO:<noat>",
            "TO:<a@exa mple.com>",
            "TO:<a@example..com>",
            "TO:<a@example.com> =x",
            "TO:<a@example.com> X=",
            "FROM:<a@example.com>",
            "TO<a@example.com>",
            "TÖ:<a@example.com>",
            "é",
            "",
        ] {
            assert!(parse_path(bad, "TO").is_err(), "accepted {bad:?}");
        }
        let long = format!("TO:<{}@example.com>", "a".repeat(300));
        assert!(parse_path(&long, "TO").is_err());
    }

    #[test]
    fn ipnet_parse_contains() {
        let n = IpNet::parse("192.0.2.0/24").unwrap();
        assert!(n.contains("192.0.2.77".parse().unwrap()));
        assert!(n.contains("::ffff:192.0.2.1".parse().unwrap()));
        assert!(!n.contains("192.0.3.1".parse().unwrap()));
        let h = IpNet::parse("10.0.0.5").unwrap();
        assert!(h.contains("10.0.0.5".parse().unwrap()));
        assert!(!h.contains("10.0.0.6".parse().unwrap()));
        let v6 = IpNet::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        assert!(!v6.contains("192.0.2.1".parse().unwrap()));
        let all = IpNet::parse("0.0.0.0/0").unwrap();
        assert!(all.contains("203.0.113.9".parse().unwrap()));
        for bad in ["", "x", "10.0.0.0/33", "::/129", "10.0.0.0/a"] {
            assert!(IpNet::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ipv6_bucket_is_slash64() {
        let a = ip_bucket("2001:db8:1:2:aaaa::1".parse().unwrap());
        let b = ip_bucket("2001:db8:1:2:bbbb::2".parse().unwrap());
        assert_eq!(a, b);
        assert_eq!(
            ip_key("2001:db8:1:2::9".parse().unwrap()),
            "2001:db8:1:2::/64"
        );
        assert_eq!(ip_key("::ffff:192.0.2.1".parse().unwrap()), "192.0.2.1");
    }

    // ---- end-to-end helpers ----

    #[derive(Default)]
    struct Upstream {
        cmds: Mutex<Vec<String>>,
        data: Mutex<Vec<Vec<u8>>>,
    }

    /// A fake upstream SMTP sink (accepts any number of connections) that
    /// records commands and relayed messages.
    async fn fake_upstream() -> (String, Arc<Upstream>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let rec = Arc::new(Upstream::default());
        let r2 = rec.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = l.accept().await {
                let rec = r2.clone();
                tokio::spawn(async move {
                    let (r, mut w) = tokio::io::split(stream);
                    let mut reader = BufReader::new(r);
                    let _ = w.write_all(b"220 fake ESMTP\r\n").await;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                            break;
                        }
                        let up = line.trim_end().to_uppercase();
                        rec.cmds.lock().unwrap().push(up.clone());
                        if up == "DATA" {
                            let _ = w.write_all(b"354 go\r\n").await;
                            let data = smtpclient::read_data(&mut reader, 0)
                                .await
                                .unwrap_or_default();
                            rec.data.lock().unwrap().push(data);
                            let _ = w.write_all(b"250 queued\r\n").await;
                        } else if up == "QUIT" {
                            let _ = w.write_all(b"221 bye\r\n").await;
                            break;
                        } else {
                            let _ = w.write_all(b"250 ok\r\n").await;
                        }
                    }
                });
            }
        });
        (addr, rec)
    }

    struct Passthrough;
    #[async_trait]
    impl MessageProcessor for Passthrough {
        async fn process(&self, _e: &Envelope, raw: &[u8]) -> Result<Vec<u8>, ProcessError> {
            Ok(raw.to_vec())
        }
    }

    fn upstream_opts(addr: String) -> UpstreamOptions {
        UpstreamOptions {
            addr,
            helo_name: "gw".into(),
            timeout: Duration::from_secs(5),
            ..Default::default()
        }
    }

    async fn start(opts: BackendOptions) -> String {
        let backend = Arc::new(Backend::new(Arc::new(Passthrough), opts));
        let gw = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = gw.local_addr().unwrap().to_string();
        tokio::spawn(backend.serve(gw));
        addr
    }

    type Reader = BufReader<tokio::io::ReadHalf<TcpStream>>;
    type Writer = tokio::io::WriteHalf<TcpStream>;

    async fn connect(addr: &str) -> (Reader, Writer) {
        let stream = TcpStream::connect(addr).await.unwrap();
        let (r, w) = tokio::io::split(stream);
        (BufReader::new(r), w)
    }

    /// Reads one (multi-line) reply; `None` on EOF.
    async fn try_reply(reader: &mut Reader) -> Option<(u16, String)> {
        let mut all = String::new();
        loop {
            let mut line = String::new();
            let n = timeout(Duration::from_secs(10), reader.read_line(&mut line))
                .await
                .expect("reply timed out")
                .unwrap_or(0);
            if n == 0 {
                return None;
            }
            let l = line.trim_end();
            all.push_str(l.get(4..).unwrap_or(""));
            all.push('\n');
            if l.as_bytes().get(3) != Some(&b'-') {
                return Some((l[..3].parse().unwrap(), all.trim().to_string()));
            }
        }
    }

    async fn read_reply(reader: &mut Reader) -> (u16, String) {
        try_reply(reader).await.expect("unexpected EOF")
    }

    async fn cmd(r: &mut Reader, w: &mut Writer, line: &str) -> u16 {
        w.write_all(line.as_bytes()).await.unwrap();
        w.write_all(b"\r\n").await.unwrap();
        read_reply(r).await.0
    }

    async fn session(addr: &str) -> (Reader, Writer) {
        let (mut r, mut w) = connect(addr).await;
        assert_eq!(read_reply(&mut r).await.0, 220);
        assert_eq!(cmd(&mut r, &mut w, "EHLO client").await, 250);
        (r, w)
    }

    fn inbound(up: String) -> BackendOptions {
        BackendOptions {
            recipient_domains: vec!["example.com".into()],
            upstream: upstream_opts(up),
            hostname: "gw.example.com".into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn end_to_end_relay() {
        let (up, rec) = fake_upstream().await;
        let addr = start(inbound(up)).await;
        let (mut r, mut w) = session(&addr).await;
        assert_eq!(cmd(&mut r, &mut w, "MAIL FROM:<a@ext.org>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "RCPT TO:<user@example.com>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "DATA").await, 354);
        w.write_all(b"Subject: hi\r\n\r\nbody line\r\n.\r\n")
            .await
            .unwrap();
        assert_eq!(read_reply(&mut r).await.0, 250);
        assert_eq!(cmd(&mut r, &mut w, "QUIT").await, 221);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let got = rec.data.lock().unwrap().concat();
        let got = String::from_utf8_lossy(&got);
        assert!(got.contains("Subject: hi"), "upstream got:\n{got}");
        assert!(got.contains("body line"));
    }

    #[tokio::test]
    async fn relay_denied_for_foreign_domain() {
        let (up, _rec) = fake_upstream().await;
        let addr = start(inbound(up)).await;
        let (mut r, mut w) = session(&addr).await;
        assert_eq!(cmd(&mut r, &mut w, "MAIL FROM:<a@ext.org>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "RCPT TO:<user@foreign.net>").await, 550);
    }

    #[tokio::test]
    async fn malformed_rcpt_path_rejected() {
        let (up, rec) = fake_upstream().await;
        let addr = start(inbound(up)).await;
        let (mut r, mut w) = session(&addr).await;
        assert_eq!(cmd(&mut r, &mut w, "MAIL FROM:<a@ext.org>").await, 250);
        for bad in [
            "RCPT TO:victim@evil.com>@example.com",
            "RCPT TO:<victim@evil.com>@example.com",
            "RCPT TO:<victim@evil.com@example.com>",
        ] {
            assert_eq!(cmd(&mut r, &mut w, bad).await, 501, "{bad}");
        }
        assert_eq!(cmd(&mut r, &mut w, "MAIL FROM:a@ext.org").await, 501);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !rec.cmds
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.starts_with("RCPT")),
            "nothing relayed upstream"
        );
    }

    #[tokio::test]
    async fn open_relay_client_not_allowed() {
        let (up, rec) = fake_upstream().await;
        let addr = start(BackendOptions {
            sender_domains: vec!["example.com".into()],
            allowed_clients: vec!["192.0.2.0/24".into(), "2001:db8::/32".into()],
            upstream: upstream_opts(up),
            ..Default::default()
        })
        .await;
        let (mut r, _w) = connect(&addr).await;
        assert_eq!(read_reply(&mut r).await.0, 554);
        assert!(try_reply(&mut r).await.is_none(), "connection closed");
        assert!(rec.cmds.lock().unwrap().is_empty());

        // A list with only invalid entries fails closed.
        let (up, _rec) = fake_upstream().await;
        let addr = start(BackendOptions {
            allowed_clients: vec!["not-an-ip".into()],
            upstream: upstream_opts(up),
            ..Default::default()
        })
        .await;
        let (mut r, _w) = connect(&addr).await;
        assert_eq!(read_reply(&mut r).await.0, 554);
    }

    #[tokio::test]
    async fn outbound_allowed_client_and_null_sender() {
        let (up, _rec) = fake_upstream().await;
        let addr = start(BackendOptions {
            sender_domains: vec!["example.com".into()],
            allowed_clients: vec!["127.0.0.0/8".into()],
            upstream: upstream_opts(up),
            name: "outbound".into(),
            ..Default::default()
        })
        .await;
        let (mut r, mut w) = session(&addr).await;
        assert_eq!(cmd(&mut r, &mut w, "MAIL FROM:<>").await, 550);
        assert_eq!(cmd(&mut r, &mut w, "MAIL FROM:<a@evil.org>").await, 550);
        assert_eq!(cmd(&mut r, &mut w, "MAIL FROM:<a@example.com>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "RCPT TO:<x@anywhere.net>").await, 250);
    }

    #[tokio::test]
    async fn rejected_mail_resets_upstream_and_blocks_rcpt() {
        let (up, rec) = fake_upstream().await;
        let mut o = inbound(up);
        o.sender_domains = vec!["ext.org".into()];
        let addr = start(o).await;
        let (mut r, mut w) = session(&addr).await;
        assert_eq!(cmd(&mut r, &mut w, "MAIL FROM:<a@ext.org>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "MAIL FROM:<a@bad.org>").await, 550);
        assert_eq!(cmd(&mut r, &mut w, "RCPT TO:<u@example.com>").await, 503);
        assert_eq!(cmd(&mut r, &mut w, "DATA").await, 503);
        let cmds = rec.cmds.lock().unwrap().clone();
        let mail = cmds.iter().position(|c| c.starts_with("MAIL")).unwrap();
        assert_eq!(
            cmds.get(mail + 1).map(String::as_str),
            Some("RSET"),
            "{cmds:?}"
        );
        assert!(!cmds.iter().any(|c| c.starts_with("RCPT")));
    }

    #[tokio::test]
    async fn ehlo_resets_transaction() {
        let (up, rec) = fake_upstream().await;
        let addr = start(inbound(up)).await;
        let (mut r, mut w) = session(&addr).await;
        assert_eq!(cmd(&mut r, &mut w, "MAIL FROM:<a@ext.org>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "EHLO again").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "RCPT TO:<u@example.com>").await, 503);
        assert_eq!(cmd(&mut r, &mut w, "HELO again").await, 250);
        assert!(rec.cmds.lock().unwrap().iter().any(|c| c == "RSET"));
    }

    #[tokio::test]
    async fn overlong_line_rejected_and_discarded() {
        let (up, _rec) = fake_upstream().await;
        let mut o = inbound(up);
        o.max_line_length = 64;
        let addr = start(o).await;
        let (mut r, mut w) = session(&addr).await;
        // The tail of the long line must not be parsed as a command.
        let long = format!("NOOP {}QUIT", "x".repeat(200));
        assert_eq!(cmd(&mut r, &mut w, &long).await, 500);
        assert_eq!(cmd(&mut r, &mut w, "NOOP").await, 250);
    }

    #[tokio::test]
    async fn oversize_data_drained_no_smuggling() {
        let (up, rec) = fake_upstream().await;
        let mut o = inbound(up);
        o.max_message_bytes = 100;
        let addr = start(o).await;
        let (mut r, mut w) = session(&addr).await;
        assert_eq!(cmd(&mut r, &mut w, "MAIL FROM:<a@ext.org>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "RCPT TO:<u@example.com>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "DATA").await, 354);
        let mut body = Vec::new();
        for _ in 0..50 {
            body.extend_from_slice(b"filler filler filler filler filler\r\n");
        }
        // Lines that would be commands if the gateway desynchronised.
        body.extend_from_slice(b"RSET\r\nMAIL FROM:<x@evil.org>\r\nRCPT TO:<v@example.com>\r\n");
        body.extend_from_slice(b".\r\n");
        w.write_all(&body).await.unwrap();
        // Exactly one reply for the whole message: 552.
        assert_eq!(read_reply(&mut r).await.0, 552);
        assert_eq!(cmd(&mut r, &mut w, "NOOP").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "RCPT TO:<u@example.com>").await, 503);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let cmds = rec.cmds.lock().unwrap().clone();
        assert!(!cmds.iter().any(|c| c.contains("EVIL")), "{cmds:?}");
        assert!(!cmds.iter().any(|c| c == "DATA"));
        assert!(cmds.iter().any(|c| c == "RSET"));
    }

    #[tokio::test]
    async fn size_param_and_max_recipients() {
        let (up, _rec) = fake_upstream().await;
        let mut o = inbound(up);
        o.max_message_bytes = 1000;
        o.max_recipients = 2;
        let addr = start(o).await;
        let (mut r, mut w) = session(&addr).await;
        assert_eq!(
            cmd(&mut r, &mut w, "MAIL FROM:<a@ext.org> SIZE=5000").await,
            552
        );
        assert_eq!(
            cmd(&mut r, &mut w, "MAIL FROM:<a@ext.org> SIZE=abc").await,
            501
        );
        assert_eq!(
            cmd(&mut r, &mut w, "MAIL FROM:<a@ext.org> FOO=1").await,
            555
        );
        assert_eq!(
            cmd(&mut r, &mut w, "MAIL FROM:<a@ext.org> SIZE=500").await,
            250
        );
        assert_eq!(cmd(&mut r, &mut w, "RCPT TO:<a@example.com>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "RCPT TO:<b@example.com>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "RCPT TO:<c@example.com>").await, 452);
    }

    #[tokio::test]
    async fn per_ip_connection_cap() {
        let (up, _rec) = fake_upstream().await;
        let mut o = inbound(up);
        o.max_connections_per_ip = 1;
        let addr = start(o).await;
        let (mut r1, w1) = connect(&addr).await;
        assert_eq!(read_reply(&mut r1).await.0, 220);
        let (mut r2, _w2) = connect(&addr).await;
        assert_eq!(read_reply(&mut r2).await.0, 421);
        assert!(try_reply(&mut r2).await.is_none());
        drop((r1, w1));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (mut r3, _w3) = connect(&addr).await;
        assert_eq!(read_reply(&mut r3).await.0, 220, "slot released on close");
    }

    #[tokio::test]
    async fn global_connection_cap() {
        let (up, _rec) = fake_upstream().await;
        let mut o = inbound(up);
        o.max_connections = 1;
        let addr = start(o).await;
        let (mut r1, _w1) = connect(&addr).await;
        assert_eq!(read_reply(&mut r1).await.0, 220);
        let (mut r2, _w2) = connect(&addr).await;
        assert_eq!(read_reply(&mut r2).await.0, 421);
    }

    #[tokio::test]
    async fn idle_timeout_closes() {
        let (up, _rec) = fake_upstream().await;
        let mut o = inbound(up);
        o.read_timeout = Duration::from_millis(200);
        let addr = start(o).await;
        let (mut r, mut w) = connect(&addr).await;
        assert_eq!(read_reply(&mut r).await.0, 220);
        // A partial line does not reset the idle timer forever.
        w.write_all(b"NOO").await.unwrap();
        let (code, msg) = read_reply(&mut r).await;
        assert_eq!(code, 421, "{msg}");
        assert!(msg.contains("Idle"));
        assert!(try_reply(&mut r).await.is_none());
    }

    #[tokio::test]
    async fn idle_timeout_in_data() {
        let (up, rec) = fake_upstream().await;
        let mut o = inbound(up);
        o.read_timeout = Duration::from_millis(200);
        let addr = start(o).await;
        let (mut r, mut w) = session(&addr).await;
        assert_eq!(cmd(&mut r, &mut w, "MAIL FROM:<a@ext.org>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "RCPT TO:<u@example.com>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "DATA").await, 354);
        w.write_all(b"Subject: x\r\n").await.unwrap();
        assert_eq!(read_reply(&mut r).await.0, 421);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!rec.cmds.lock().unwrap().iter().any(|c| c == "DATA"));
    }

    #[tokio::test]
    async fn session_deadline() {
        let (up, _rec) = fake_upstream().await;
        let mut o = inbound(up);
        o.session_timeout = Duration::from_millis(300);
        let addr = start(o).await;
        let (mut r, mut w) = session(&addr).await;
        let mut last = 0;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            w.write_all(b"NOOP\r\n").await.unwrap();
            last = read_reply(&mut r).await.0;
            if last != 250 {
                break;
            }
        }
        assert_eq!(last, 421);
    }

    #[tokio::test]
    async fn eof_mid_data_does_not_relay() {
        let (up, rec) = fake_upstream().await;
        let addr = start(inbound(up)).await;
        let (mut r, mut w) = session(&addr).await;
        assert_eq!(cmd(&mut r, &mut w, "MAIL FROM:<a@ext.org>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "RCPT TO:<u@example.com>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "DATA").await, 354);
        w.write_all(b"partial\r\n").await.unwrap();
        w.shutdown().await.unwrap();
        // 451 (not 552) and the session ends.
        assert_eq!(read_reply(&mut r).await.0, 451);
        assert!(try_reply(&mut r).await.is_none());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!rec.cmds.lock().unwrap().iter().any(|c| c == "DATA"));
    }

    struct RecordingGreylist(Mutex<Vec<(String, String, String)>>);
    impl Greylister for RecordingGreylist {
        fn allow(&self, ip: &str, from: &str, to: &str) -> bool {
            self.0
                .lock()
                .unwrap()
                .push((ip.into(), from.into(), to.into()));
            false
        }
    }

    #[tokio::test]
    async fn null_sender_is_greylisted() {
        let (up, _rec) = fake_upstream().await;
        let gl = Arc::new(RecordingGreylist(Mutex::new(Vec::new())));
        let mut o = inbound(up);
        o.greylist = Some(gl.clone());
        let addr = start(o).await;
        let (mut r, mut w) = session(&addr).await;
        assert_eq!(cmd(&mut r, &mut w, "MAIL FROM:<>").await, 250);
        assert_eq!(cmd(&mut r, &mut w, "RCPT TO:<u@example.com>").await, 451);
        let calls = gl.0.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![("127.0.0.1".into(), "<>".into(), "u@example.com".into())]
        );
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;

    struct Echo;
    #[async_trait]
    impl MessageProcessor for Echo {
        async fn process(&self, _e: &Envelope, raw: &[u8]) -> Result<Vec<u8>, ProcessError> {
            Ok(raw.to_vec())
        }
    }

    #[tokio::test]
    async fn starttls_client_and_server() {
        let cfg = crate::tls::server_config_from_pem(
            include_bytes!("../testdata/tls-cert.pem"),
            include_bytes!("../testdata/tls-key.pem"),
        )
        .unwrap();
        let be = Arc::new(Backend::new(
            Arc::new(Echo),
            BackendOptions {
                tls: Some(cfg),
                require_tls: true,
                upstream: UpstreamOptions {
                    addr: "127.0.0.1:1".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
        ));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(be.serve(l));

        // Plain session: MAIL refused until STARTTLS.
        let mut plain = Client::dial(&UpstreamOptions {
            addr: addr.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
        assert!(!plain.is_tls());
        match plain.mail("a@example.com").await {
            Err(smtpclient::Error::Smtp { code, .. }) => assert_eq!(code, 530),
            other => panic!("unexpected {other:?}"),
        }

        // STARTTLS session (self-signed → insecure_skip_verify).
        let mut c = Client::dial(&UpstreamOptions {
            addr: addr.clone(),
            starttls: true,
            require_tls: true,
            insecure_skip_verify: true,
            ..Default::default()
        })
        .await
        .unwrap();
        assert!(c.is_tls());
        // Past the TLS gate the (unreachable) upstream yields a 451.
        match c.mail("a@example.com").await {
            Err(smtpclient::Error::Smtp { code, .. }) => assert_eq!(code, 451),
            other => panic!("unexpected {other:?}"),
        }
        c.quit().await.unwrap();

        // Verified mode rejects the self-signed certificate.
        assert!(Client::dial(&UpstreamOptions {
            addr,
            starttls: true,
            ..Default::default()
        })
        .await
        .is_err());
    }
}

#[cfg(test)]
mod r2_tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    /// Upstream that tracks transaction state like a real MTA and rejects DATA.
    async fn strict_upstream() -> (String, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let log = log2.clone();
                tokio::spawn(async move {
                    let (r, mut w) = tokio::io::split(s);
                    let mut r = BufReader::new(r);
                    let _ = w.write_all(b"220 up\r\n").await;
                    let mut in_txn = false;
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                            break;
                        }
                        let up = line.trim_end().to_uppercase();
                        let reply: &[u8] = if up.starts_with("MAIL") {
                            if in_txn {
                                b"503 5.5.1 nested MAIL\r\n"
                            } else {
                                in_txn = true;
                                b"250 ok\r\n"
                            }
                        } else if up == "DATA" {
                            b"554 5.7.1 no DATA for you\r\n"
                        } else if up == "RSET" {
                            in_txn = false;
                            b"250 ok\r\n"
                        } else {
                            b"250 ok\r\n"
                        };
                        log.lock()
                            .unwrap()
                            .push(format!("{up} -> {}", String::from_utf8_lossy(reply).trim()));
                        let _ = w.write_all(reply).await;
                    }
                });
            }
        });
        (addr, log)
    }

    struct Pass;
    #[async_trait]
    impl MessageProcessor for Pass {
        async fn process(&self, _e: &Envelope, raw: &[u8]) -> Result<Vec<u8>, ProcessError> {
            Ok(raw.to_vec())
        }
    }

    async fn line(r: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> String {
        let mut all = String::new();
        loop {
            let mut l = String::new();
            r.read_line(&mut l).await.unwrap();
            all.push_str(&l);
            if l.as_bytes().get(3) != Some(&b'-') {
                return all;
            }
        }
    }

    #[tokio::test]
    async fn upstream_data_reject_keeps_session_in_sync() {
        let (up, log) = strict_upstream().await;
        let backend = Arc::new(Backend::new(
            Arc::new(Pass),
            BackendOptions {
                recipient_domains: vec!["example.com".into()],
                upstream: crate::smtpclient::Options {
                    addr: up,
                    timeout: Duration::from_secs(5),
                    ..Default::default()
                },
                ..Default::default()
            },
        ));
        let gw = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = gw.local_addr().unwrap();
        tokio::spawn(backend.serve(gw));
        let (r, mut w) = tokio::io::split(TcpStream::connect(addr).await.unwrap());
        let mut r = BufReader::new(r);
        line(&mut r).await;
        let mut send = |s: &'static str| {
            let s = s.to_string();
            async move { s }
        };
        let _ = &mut send;
        for c in [
            "EHLO c",
            "MAIL FROM:<a@x.org>",
            "RCPT TO:<u@example.com>",
            "DATA",
        ] {
            w.write_all(format!("{c}\r\n").as_bytes()).await.unwrap();
            let rep = line(&mut r).await;
            eprintln!("{c} => {rep}");
        }
        w.write_all(b"Subject: x\r\n\r\nhi\r\n.\r\n").await.unwrap();
        eprintln!("body => {}", line(&mut r).await);
        for c in ["RSET", "MAIL FROM:<b@x.org>"] {
            w.write_all(format!("{c}\r\n").as_bytes()).await.unwrap();
            let rep = line(&mut r).await;
            eprintln!("{c} => {rep}");
            if c.starts_with("MAIL") {
                eprintln!("upstream log: {:?}", log.lock().unwrap());
                assert!(rep.starts_with("250"), "second MAIL failed: {rep}");
            }
        }
    }

    #[tokio::test]
    async fn greylist_not_exhausted_by_one_session() {
        let (up, _log) = strict_upstream().await;
        let gl = Arc::new(
            crate::greylist::Greylist::new(Duration::from_secs(3600), Duration::ZERO)
                .with_max_entries(500),
        );
        let backend = Arc::new(Backend::new(
            Arc::new(Pass),
            BackendOptions {
                recipient_domains: vec!["example.com".into()],
                upstream: crate::smtpclient::Options {
                    addr: up,
                    timeout: Duration::from_secs(5),
                    ..Default::default()
                },
                greylist: Some(gl.clone()),
                ..Default::default()
            },
        ));
        let gw = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = gw.local_addr().unwrap();
        tokio::spawn(backend.serve(gw));
        let (r, mut w) = tokio::io::split(TcpStream::connect(addr).await.unwrap());
        let mut r = BufReader::new(r);
        line(&mut r).await;
        w.write_all(b"EHLO c\r\nMAIL FROM:<a@x.org>\r\n")
            .await
            .unwrap();
        line(&mut r).await;
        line(&mut r).await;
        let mut replies = Vec::new();
        for i in 0..600 {
            if w.write_all(format!("RCPT TO:<u{i}@example.com>\r\n").as_bytes())
                .await
                .is_err()
            {
                break;
            }
            let mut l = String::new();
            if r.read_line(&mut l).await.unwrap_or(0) == 0 {
                break;
            }
            let closing = l.starts_with("421");
            replies.push(l);
            if closing {
                break;
            }
        }
        assert!(
            replies
                .last()
                .map(|l| l.starts_with("421"))
                .unwrap_or(false),
            "session cut off after repeated greylist deferrals"
        );
        assert!(
            gl.len() <= 25,
            "one session stored only a few triplets: {}",
            gl.len()
        );
        // A never-seen triplet from another client is still greylisted.
        assert!(!gl.allow("203.0.113.9", "spam@bad.example", "ceo@example.com"));
    }
}
