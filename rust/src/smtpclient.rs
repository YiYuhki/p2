//! Minimal async SMTP client used to relay to the upstream (internal) mail
//! server. Port of the Go `internal/smtpclient` (plaintext + the EHLO/MAIL/RCPT/
//! DATA dialog). STARTTLS is a follow-up (tokio-rustls).

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Connection options.
#[derive(Clone, Debug)]
pub struct Options {
    pub addr: String,
    pub helo_name: String,
    pub timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            addr: String::new(),
            helo_name: "localhost".into(),
            timeout: Duration::from_secs(60),
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
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: tokio::io::WriteHalf<TcpStream>,
    timeout: Duration,
    helo: String,
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
        let (r, w) = tokio::io::split(stream);
        let mut c = Client {
            reader: BufReader::new(r),
            writer: w,
            timeout: to,
            helo,
        };
        let (code, _) = c.read_reply().await?;
        if code != 220 {
            return Err(Error::Transport(format!("unexpected greeting {code}")));
        }
        c.ehlo().await?;
        Ok(c)
    }

    async fn ehlo(&mut self) -> Result<()> {
        let helo = self.helo.clone();
        self.write_line(&format!("EHLO {helo}")).await?;
        let (code, _) = self.read_reply().await?;
        if code == 250 {
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
        self.write_all(b"\r\n.\r\n").await?;
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
        timeout(self.timeout, self.writer.write_all(data))
            .await
            .map_err(|_| Error::Transport("write timed out".into()))?
            .map_err(|e| Error::Transport(e.to_string()))
    }

    /// Reads a (possibly multi-line) SMTP reply and returns (code, last text).
    async fn read_reply(&mut self) -> Result<(u16, String)> {
        loop {
            let mut line = String::new();
            let n = timeout(self.timeout, self.reader.read_line(&mut line))
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
            if !more {
                return Ok((code, line[3..].trim_start().to_string()));
            }
        }
    }
}

/// Dot-stuffs a message body per RFC 5321 §4.5.2 (a line starting with "." gets
/// an extra ".").
fn dot_stuff(msg: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(msg);
    let normalized = text.replace("\r\n", "\n");
    let mut out = String::with_capacity(msg.len());
    for (i, line) in normalized.split('\n').enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
    }
    out.into_bytes()
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
    let text = String::from_utf8_lossy(msg);
    let normalized = text.replace("\r\n", "\n");
    let mut out = String::with_capacity(msg.len());
    for (i, line) in normalized.split('\n').enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        if let Some(stripped) = line.strip_prefix('.') {
            out.push_str(stripped);
        } else {
            out.push_str(line);
        }
    }
    out.into_bytes()
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
