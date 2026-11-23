//! The inbound SMTP proxy. Port of the Go `internal/gateway` server: a before-
//! queue, lock-step proxy — MAIL and RCPT are forwarded to the upstream mail
//! server immediately, and the (possibly rewritten) message is relayed during
//! DATA, so the gateway needs no local spool.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::smtpclient::{self, Client, Options as UpstreamOptions};

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

/// Backend configuration.
#[derive(Default)]
pub struct BackendOptions {
    pub recipient_domains: Vec<String>,
    pub sender_domains: Vec<String>,
    pub upstream: UpstreamOptions,
    pub name: String,
    pub hostname: String,
    pub max_message_bytes: usize,
    pub conn_gate: Option<Arc<dyn ConnGate>>,
    pub greylist: Option<Arc<dyn Greylister>>,
    pub rate_limit: Option<Arc<dyn RateLimiter>>,
}

/// The inbound/outbound backend.
pub struct Backend {
    proc: Arc<dyn MessageProcessor>,
    opts: BackendOptions,
}

impl Backend {
    pub fn new(proc: Arc<dyn MessageProcessor>, mut opts: BackendOptions) -> Self {
        if opts.name.is_empty() {
            opts.name = "inbound".into();
        }
        if opts.hostname.is_empty() {
            opts.hostname = "localhost".into();
        }
        Backend { proc, opts }
    }

    /// Serves the SMTP proxy on `listener` until it errors.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (stream, peer) = listener.accept().await?;
            let backend = self.clone();
            tokio::spawn(async move {
                if let Err(e) = backend.handle(stream, peer.to_string()).await {
                    let _ = e; // per-connection errors are not fatal
                }
            });
        }
    }

    async fn handle(&self, stream: TcpStream, remote: String) -> std::io::Result<()> {
        let (r, mut w) = tokio::io::split(stream);
        let mut reader = BufReader::new(r);

        // Connection gate (DNSBL).
        if let Some(gate) = &self.opts.conn_gate {
            if let Ok(ip) = host_only(&remote).parse::<IpAddr>() {
                if let Some(err) = gate.gate(ip).await {
                    reply(&mut w, err.code, &err.message).await?;
                    return Ok(());
                }
            }
        }

        reply(
            &mut w,
            220,
            &format!("{} ESMTP secmail", self.opts.hostname),
        )
        .await?;

        let mut up: Option<Client> = None;
        let mut from = String::new();
        let mut rcpt: Vec<String> = Vec::new();
        let mut helo = String::new();

        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break;
            }
            let line = line.trim_end().to_string();
            let (cmd, arg) = split_cmd(&line);
            match cmd.as_str() {
                "EHLO" | "HELO" => {
                    helo = arg.to_string();
                    reply(&mut w, 250, &format!("{} greets {arg}", self.opts.hostname)).await?;
                }
                "MAIL" => {
                    from = String::new();
                    rcpt.clear();
                    let addr = parse_path(arg);
                    if self
                        .opts
                        .rate_limit
                        .as_ref()
                        .map(|r| !r.allow(&host_only(&remote)))
                        .unwrap_or(false)
                    {
                        reply(&mut w, 451, "Message rate limit exceeded, please slow down").await?;
                        continue;
                    }
                    if !addr.is_empty()
                        && !self.opts.sender_domains.is_empty()
                        && !domain_in(&addr, &self.opts.sender_domains)
                    {
                        reply(&mut w, 550, "Sender domain not allowed").await?;
                        continue;
                    }
                    if up.is_none() {
                        match Client::dial(&self.opts.upstream).await {
                            Ok(c) => up = Some(c),
                            Err(_) => {
                                reply(
                                    &mut w,
                                    451,
                                    "Upstream mail server unavailable, please retry",
                                )
                                .await?;
                                continue;
                            }
                        }
                    }
                    match up.as_mut().unwrap().mail(&addr).await {
                        Ok(()) => {
                            from = addr;
                            reply(&mut w, 250, "OK").await?;
                        }
                        Err(e) => {
                            emit_upstream_err(&mut w, e, &mut up).await?;
                        }
                    }
                }
                "RCPT" => {
                    if up.is_none() {
                        reply(&mut w, 503, "Need MAIL command").await?;
                        continue;
                    }
                    let addr = parse_path(arg);
                    if !self.opts.recipient_domains.is_empty()
                        && !domain_in(&addr, &self.opts.recipient_domains)
                    {
                        reply(&mut w, 550, "Relaying denied").await?;
                        continue;
                    }
                    if !from.is_empty() {
                        if let Some(gl) = &self.opts.greylist {
                            if !gl.allow(&host_only(&remote), &from, &addr) {
                                reply(&mut w, 451, "Greylisted, please retry shortly").await?;
                                continue;
                            }
                        }
                    }
                    match up.as_mut().unwrap().rcpt(&addr).await {
                        Ok(()) => {
                            rcpt.push(addr);
                            reply(&mut w, 250, "OK").await?;
                        }
                        Err(e) => {
                            emit_upstream_err(&mut w, e, &mut up).await?;
                        }
                    }
                }
                "DATA" => {
                    if up.is_none() || rcpt.is_empty() {
                        reply(&mut w, 503, "Need RCPT command").await?;
                        continue;
                    }
                    reply(&mut w, 354, "Start mail input; end with <CRLF>.<CRLF>").await?;
                    let raw = match smtpclient::read_data(&mut reader, self.opts.max_message_bytes)
                        .await
                    {
                        Ok(b) => b,
                        Err(_) => {
                            if let Some(c) = up.as_mut() {
                                let _ = c.reset().await;
                            }
                            reply(&mut w, 552, "Message too large or read error").await?;
                            continue;
                        }
                    };
                    let env = Envelope {
                        mail_from: from.clone(),
                        rcpt_to: rcpt.clone(),
                        remote_addr: remote.clone(),
                        helo: helo.clone(),
                        tls: false,
                    };
                    match self.proc.process(&env, &raw).await {
                        Ok(out) => {
                            let c = up.as_mut().unwrap();
                            match c.data(&out).await {
                                Ok(()) => {
                                    reply(&mut w, 250, "OK: queued").await?;
                                }
                                Err(e) => {
                                    emit_upstream_err(&mut w, e, &mut up).await?;
                                }
                            }
                        }
                        Err(ProcessError::Held) => {
                            if let Some(c) = up.as_mut() {
                                let _ = c.reset().await;
                            }
                            reply(&mut w, 250, "OK: accepted").await?;
                        }
                        Err(ProcessError::Reject(err)) => {
                            if let Some(c) = up.as_mut() {
                                let _ = c.reset().await;
                            }
                            reply(&mut w, err.code, &err.message).await?;
                        }
                        Err(ProcessError::TempFail) => {
                            if let Some(c) = up.as_mut() {
                                let _ = c.reset().await;
                            }
                            reply(&mut w, 451, "Temporary processing failure, please retry")
                                .await?;
                        }
                    }
                    from.clear();
                    rcpt.clear();
                }
                "RSET" => {
                    from.clear();
                    rcpt.clear();
                    if let Some(c) = up.as_mut() {
                        let _ = c.reset().await;
                    }
                    reply(&mut w, 250, "OK").await?;
                }
                "NOOP" => reply(&mut w, 250, "OK").await?,
                "QUIT" => {
                    if let Some(mut c) = up.take() {
                        let _ = c.quit().await;
                    }
                    reply(&mut w, 221, "Bye").await?;
                    break;
                }
                "" => {}
                _ => reply(&mut w, 502, "Command not implemented").await?,
            }
        }
        Ok(())
    }
}

async fn emit_upstream_err<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    e: smtpclient::Error,
    up: &mut Option<Client>,
) -> std::io::Result<()> {
    match e {
        smtpclient::Error::Smtp { code, message } => reply(w, code, &message).await,
        smtpclient::Error::Transport(_) => {
            *up = None;
            reply(w, 451, "Upstream mail server unavailable, please retry").await
        }
    }
}

async fn reply<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    code: u16,
    message: &str,
) -> std::io::Result<()> {
    w.write_all(format!("{code} {message}\r\n").as_bytes())
        .await?;
    w.flush().await
}

fn split_cmd(line: &str) -> (String, &str) {
    let line = line.trim_start();
    match line.find(' ') {
        Some(i) => (line[..i].to_uppercase(), line[i + 1..].trim_start()),
        None => (line.to_uppercase(), ""),
    }
}

/// Extracts the address from a `FROM:<addr>` / `TO:<addr>` argument.
fn parse_path(arg: &str) -> String {
    let after = match arg.find(':') {
        Some(i) => &arg[i + 1..],
        None => arg,
    };
    let after = after.trim();
    let inner = after
        .strip_prefix('<')
        .and_then(|s| s.find('>').map(|j| &s[..j]))
        .unwrap_or(after);
    inner.trim().to_string()
}

fn domain_in(addr: &str, domains: &[String]) -> bool {
    let at = match addr.rfind('@') {
        Some(i) => i,
        None => return false,
    };
    let domain = addr[at + 1..].to_lowercase();
    domains
        .iter()
        .any(|d| domain == *d || (d.starts_with('.') && domain.ends_with(d.as_str())))
}

fn host_only(remote: &str) -> String {
    match remote.rfind(':') {
        Some(i) => remote[..i]
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string(),
        None => remote.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn parse_path_and_domain() {
        assert_eq!(parse_path("FROM:<a@ext.org>"), "a@ext.org");
        assert_eq!(parse_path("TO:<b@example.com> SIZE=10"), "b@example.com");
        assert_eq!(parse_path("FROM:<>"), "");
        assert!(domain_in("x@example.com", &["example.com".into()]));
        assert!(domain_in("x@mail.example.com", &[".example.com".into()]));
        assert!(!domain_in("x@evil.com", &["example.com".into()]));
    }

    // A minimal fake upstream SMTP sink that captures the relayed message.
    async fn fake_upstream(captured: Arc<Mutex<Vec<u8>>>) -> String {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((stream, _)) = l.accept().await {
                let (r, mut w) = tokio::io::split(stream);
                let mut reader = BufReader::new(r);
                let _ = w.write_all(b"220 fake ESMTP\r\n").await;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        break;
                    }
                    let up = line.trim_end().to_uppercase();
                    if up.starts_with("EHLO")
                        || up.starts_with("HELO")
                        || up.starts_with("MAIL")
                        || up.starts_with("RCPT")
                        || up == "RSET"
                    {
                        let _ = w.write_all(b"250 ok\r\n").await;
                    } else if up == "DATA" {
                        let _ = w.write_all(b"354 go\r\n").await;
                        let data = smtpclient::read_data(&mut reader, 0)
                            .await
                            .unwrap_or_default();
                        *captured.lock().unwrap() = data;
                        let _ = w.write_all(b"250 queued\r\n").await;
                    } else if up == "QUIT" {
                        let _ = w.write_all(b"221 bye\r\n").await;
                        break;
                    } else {
                        let _ = w.write_all(b"250 ok\r\n").await;
                    }
                }
            }
        });
        addr
    }

    struct Passthrough;
    #[async_trait]
    impl MessageProcessor for Passthrough {
        async fn process(&self, _e: &Envelope, raw: &[u8]) -> Result<Vec<u8>, ProcessError> {
            Ok(raw.to_vec())
        }
    }

    async fn read_reply(reader: &mut (impl AsyncBufReadExt + Unpin)) -> (u16, String) {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let line = line.trim_end();
        (line[..3].parse().unwrap(), line[3..].trim().to_string())
    }

    #[tokio::test]
    async fn end_to_end_relay() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let up_addr = fake_upstream(captured.clone()).await;

        let backend = Arc::new(Backend::new(
            Arc::new(Passthrough),
            BackendOptions {
                recipient_domains: vec!["example.com".into()],
                upstream: UpstreamOptions {
                    addr: up_addr,
                    helo_name: "gw".into(),
                    timeout: std::time::Duration::from_secs(5),
                },
                hostname: "gw.example.com".into(),
                ..Default::default()
            },
        ));
        let gw = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw.local_addr().unwrap().to_string();
        tokio::spawn(backend.serve(gw));

        // Client dialogue against the gateway.
        let stream = TcpStream::connect(&gw_addr).await.unwrap();
        let (r, mut w) = tokio::io::split(stream);
        let mut reader = BufReader::new(r);
        assert_eq!(read_reply(&mut reader).await.0, 220);
        w.write_all(b"EHLO client\r\n").await.unwrap();
        assert_eq!(read_reply(&mut reader).await.0, 250);
        w.write_all(b"MAIL FROM:<a@ext.org>\r\n").await.unwrap();
        assert_eq!(read_reply(&mut reader).await.0, 250);
        w.write_all(b"RCPT TO:<user@example.com>\r\n")
            .await
            .unwrap();
        assert_eq!(read_reply(&mut reader).await.0, 250);
        w.write_all(b"DATA\r\n").await.unwrap();
        assert_eq!(read_reply(&mut reader).await.0, 354);
        w.write_all(b"Subject: hi\r\n\r\nbody line\r\n.\r\n")
            .await
            .unwrap();
        assert_eq!(read_reply(&mut reader).await.0, 250);
        w.write_all(b"QUIT\r\n").await.unwrap();

        // Give the upstream a moment to capture.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let got = captured.lock().unwrap().clone();
        let got = String::from_utf8_lossy(&got);
        assert!(got.contains("Subject: hi"), "upstream got:\n{got}");
        assert!(got.contains("body line"));
    }

    #[tokio::test]
    async fn relay_denied_for_foreign_domain() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let up_addr = fake_upstream(captured.clone()).await;
        let backend = Arc::new(Backend::new(
            Arc::new(Passthrough),
            BackendOptions {
                recipient_domains: vec!["example.com".into()],
                upstream: UpstreamOptions {
                    addr: up_addr,
                    helo_name: "gw".into(),
                    timeout: std::time::Duration::from_secs(5),
                },
                hostname: "gw".into(),
                ..Default::default()
            },
        ));
        let gw = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw.local_addr().unwrap().to_string();
        tokio::spawn(backend.serve(gw));

        let stream = TcpStream::connect(&gw_addr).await.unwrap();
        let (r, mut w) = tokio::io::split(stream);
        let mut reader = BufReader::new(r);
        let _ = read_reply(&mut reader).await;
        w.write_all(b"EHLO c\r\n").await.unwrap();
        let _ = read_reply(&mut reader).await;
        w.write_all(b"MAIL FROM:<a@ext.org>\r\n").await.unwrap();
        let _ = read_reply(&mut reader).await;
        w.write_all(b"RCPT TO:<user@foreign.net>\r\n")
            .await
            .unwrap();
        assert_eq!(read_reply(&mut reader).await.0, 550);
    }
}
