//! Minimal async SMTP client used to relay to the upstream (internal) mail
//! server. Port of the Go `internal/smtpclient` (plaintext + the EHLO/MAIL/RCPT/
//! DATA dialog) with opportunistic or required STARTTLS via tokio-rustls.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::tls::BoxIo;
use tokio::time::timeout;

/// Connection options.
#[derive(Clone, Debug)]
pub struct Options {
    pub addr: String,
    pub helo_name: String,
    pub timeout: Duration,
    /// Upgrade with STARTTLS when the server offers it.
    pub starttls: bool,
    /// Fail the connection unless STARTTLS succeeds.
    pub require_tls: bool,
    /// Skip certificate verification (private-CA internal upstreams).
    pub insecure_skip_verify: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            addr: String::new(),
            helo_name: "localhost".into(),
            timeout: Duration::from_secs(60),
            starttls: false,
            require_tls: false,
            insecure_skip_verify: false,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// Transport failure (connect/read/write) — the caller maps this to a 4xx.
    Transport(String),
    /// The upstream replied with an SMTP error code; relayed verbatim.
    Smtp { code: u16, message: String },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Transport(e) => write!(f, "smtpclient: {e}"),
            Error::Smtp { code, message } => write!(f, "{code} {message}"),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

/// A live SMTP session with the upstream.
pub struct Client {
    conn: BufReader<BoxIo>,
    timeout: Duration,
    helo: String,
    /// EHLO keywords (uppercase) advertised by the server.
    ext: Vec<String>,
    tls: bool,
}

impl Client {
    /// Connects, reads the greeting and sends EHLO (falling back to HELO).
    pub async fn dial(opts: &Options) -> Result<Client> {
        let to = if opts.timeout.is_zero() {
            Duration::from_secs(60)
        } else {
            opts.timeout
        };
        let helo = if opts.helo_name.is_empty() {
            "localhost".to_string()
        } else {
            opts.helo_name.clone()
        };
        let stream = timeout(to, TcpStream::connect(&opts.addr))
            .await
            .map_err(|_| Error::Transport("connect timed out".into()))?
            .map_err(|e| Error::Transport(e.to_string()))?;
        let mut c = Client {
            conn: BufReader::new(Box::new(stream) as BoxIo),
            timeout: to,
            helo,
            ext: Vec::new(),
            tls: false,
        };
        let (code, _) = c.read_reply().await?;
        if code != 220 {
            return Err(Error::Transport(format!("unexpected greeting {code}")));
        }
        c.ehlo().await?;
        if opts.starttls || opts.require_tls {
            if c.has_ext("STARTTLS") {
                c.starttls(host_of(&opts.addr), opts.insecure_skip_verify)
                    .await?;
            } else if opts.require_tls {
                let _ = c.quit().await;
                return Err(Error::Transport(
                    "upstream does not offer STARTTLS (require_tls)".into(),
                ));
            }
        }
        Ok(c)
    }

    /// Whether the session is TLS-protected.
    pub fn is_tls(&self) -> bool {
        self.tls
    }

    fn has_ext(&self, kw: &str) -> bool {
        self.ext.iter().any(|e| e == kw)
    }

    async fn starttls(&mut self, host: &str, insecure: bool) -> Result<()> {
        self.cmd("STARTTLS", 220).await?;
        let conn = std::mem::replace(
            &mut self.conn,
            BufReader::new(
                Box::new(tokio::io::join(tokio::io::empty(), tokio::io::sink())) as BoxIo,
            ),
        );
        let io = conn.into_inner();
        let tls = timeout(self.timeout, crate::tls::connect(io, host, insecure))
            .await
            .map_err(|_| Error::Transport("tls handshake timed out".into()))?
            .map_err(Error::Transport)?;
        self.conn = BufReader::new(tls);
        self.tls = true;
        self.ext.clear();
        self.ehlo().await
    }

    async fn ehlo(&mut self) -> Result<()> {
        let helo = self.helo.clone();
        self.write_line(&format!("EHLO {helo}")).await?;
        let (code, lines) = self.read_reply_lines().await?;
        if code == 250 {
            self.ext = lines
                .iter()
                .skip(1)
                .filter_map(|l| l.split_whitespace().next())
                .map(|k| k.to_ascii_uppercase())
                .collect();
            return Ok(());
        }
        // Fall back to HELO.
        self.write_line(&format!("HELO {helo}")).await?;
        let (code, msg) = self.read_reply().await?;
        if code == 250 {
            Ok(())
        } else {
            Err(Error::Smtp { code, message: msg })
        }
    }

    pub async fn mail(&mut self, from: &str) -> Result<()> {
        self.cmd(&format!("MAIL FROM:<{from}>"), 250).await
    }

    pub async fn rcpt(&mut self, to: &str) -> Result<()> {
        self.cmd(&format!("RCPT TO:<{to}>"), 250).await
    }

    /// Sends DATA, the dot-stuffed message, and the terminating "." line.
    pub async fn data(&mut self, msg: &[u8]) -> Result<()> {
        self.write_line("DATA").await?;
        let (code, m) = self.read_reply().await?;
        if code != 354 {
            return Err(Error::Smtp { code, message: m });
        }
        let stuffed = dot_stuff(msg);
        self.write_all(&stuffed).await?;
        let end: &[u8] = if stuffed.is_empty() || stuffed.ends_with(b"\r\n") {
            b".\r\n"
        } else {
            b"\r\n.\r\n"
        };
        self.write_all(end).await?;
        let (code, m) = self.read_reply().await?;
        if (200..300).contains(&code) {
            Ok(())
        } else {
            Err(Error::Smtp { code, message: m })
        }
    }

    pub async fn reset(&mut self) -> Result<()> {
        self.cmd("RSET", 250).await
    }

    pub async fn quit(&mut self) -> Result<()> {
        self.write_line("QUIT").await?;
        let _ = self.read_reply().await;
        Ok(())
    }

    async fn cmd(&mut self, line: &str, want: u16) -> Result<()> {
        self.write_line(line).await?;
        let (code, msg) = self.read_reply().await?;
        if code == want || (want == 250 && code == 251) {
            Ok(())
        } else {
            Err(Error::Smtp { code, message: msg })
        }
    }

    async fn write_line(&mut self, line: &str) -> Result<()> {
        self.write_all(line.as_bytes()).await?;
        self.write_all(b"\r\n").await
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        timeout(self.timeout, async {
            self.conn.write_all(data).await?;
            self.conn.flush().await
        })
        .await
        .map_err(|_| Error::Transport("write timed out".into()))?
        .map_err(|e| Error::Transport(e.to_string()))
    }

    /// Reads a (possibly multi-line) SMTP reply and returns (code, last text).
    async fn read_reply(&mut self) -> Result<(u16, String)> {
        let (code, mut lines) = self.read_reply_lines().await?;
        Ok((code, lines.pop().unwrap_or_default()))
    }

    /// Reads a multi-line reply, returning the code and each line's text.
    async fn read_reply_lines(&mut self) -> Result<(u16, Vec<String>)> {
        let mut out = Vec::new();
        loop {
            let mut line = String::new();
            let n = timeout(self.timeout, self.conn.read_line(&mut line))
                .await
                .map_err(|_| Error::Transport("read timed out".into()))?
                .map_err(|e| Error::Transport(e.to_string()))?;
            if n == 0 {
                return Err(Error::Transport("connection closed".into()));
            }
            let line = line.trim_end();
            if line.len() < 3 {
                return Err(Error::Transport(format!("short reply {line:?}")));
            }
            let code: u16 = line[..3]
                .parse()
                .map_err(|_| Error::Transport(format!("bad code {line:?}")))?;
            // A hyphen after the code means more lines follow.
            let more = line.as_bytes().get(3) == Some(&b'-');
            out.push(line.get(4..).unwrap_or("").trim().to_string());
            if !more {
                return Ok((code, out));
            }
        }
    }
}

/// Dot-stuffs a message per RFC 5321 §4.5.2 (a line starting with "." gets an
/// extra "."), normalizing bare LF to CRLF. Byte-exact for 8-bit content.
fn dot_stuff(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 64);
    let mut bol = true;
    let mut prev = 0u8;
    for &b in msg {
        if bol && b == b'.' {
            out.push(b'.');
        }
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        bol = b == b'\n';
        prev = b;
    }
    out
}

/// The host part of "host:port" (for TLS server-name verification).
fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    }
}

/// Connects, sends one message and quits.
pub async fn send(opts: &Options, from: &str, to: &[String], msg: &[u8]) -> Result<()> {
    let mut c = Client::dial(opts).await?;
    c.mail(from).await?;
    for t in to {
        c.rcpt(t).await?;
    }
    c.data(msg).await?;
    c.quit().await
}

/// Reads a full message body from a reader (used by the server DATA phase),
/// un-stuffing dots and stopping at the "\r\n.\r\n" terminator. Returns the
/// message bytes, erroring past `max_bytes`.
pub async fn read_data<R: AsyncReadExt + Unpin>(
    r: &mut R,
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = r.read(&mut byte).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof in DATA",
            ));
        }
        buf.push(byte[0]);
        if buf == b".\r\n" {
            return Ok(Vec::new()); // empty message
        }
        if buf.ends_with(b"\r\n.\r\n") {
            buf.truncate(buf.len() - 3); // drop ".\r\n", keep trailing CRLF
            break;
        }
        if max_bytes != 0 && buf.len() > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
    }
    Ok(un_dot_stuff(&buf))
}

fn un_dot_stuff(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len());
    let mut bol = true;
    for &b in msg {
        if bol && b == b'.' {
            bol = false;
            continue;
        }
        out.push(b);
        bol = b == b'\n';
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_stuffing_roundtrip() {
        let msg = b"Subject: x\r\n\r\n.hidden\r\nnormal\r\n..two\r\n";
        let stuffed = dot_stuff(msg);
        assert!(String::from_utf8_lossy(&stuffed).contains("..hidden"));
        let back = un_dot_stuff(&stuffed);
        assert_eq!(back, msg);
    }
}
