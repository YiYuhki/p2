//! Minimal async SMTP client used to relay to the upstream (internal) mail
//! server. Port of the Go `internal/smtpclient` (plaintext + the EHLO/MAIL/RCPT/
//! DATA dialog) with opportunistic or required STARTTLS via tokio-rustls.

use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
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
        // Dot-stuff in bounded chunks instead of copying the whole message.
        const CHUNK: usize = 64 * 1024;
        let mut st = StuffState::default();
        let mut buf = Vec::with_capacity(CHUNK + 1024);
        for piece in msg.chunks(CHUNK) {
            buf.clear();
            st.stuff_into(piece, &mut buf);
            self.write_all(&buf).await?;
        }
        let end: &[u8] = if msg.is_empty() || st.ends_crlf() {
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
    /// Lines are read as bytes with a length cap and the code is parsed from
    /// the first three bytes, so arbitrary (non-UTF-8, multibyte) input cannot
    /// panic the parser.
    async fn read_reply_lines(&mut self) -> Result<(u16, Vec<String>)> {
        let mut out = Vec::new();
        let mut line = Vec::new();
        loop {
            if out.len() >= MAX_REPLY_LINES {
                return Err(Error::Transport("reply has too many lines".into()));
            }
            let r = timeout(
                self.timeout,
                read_line_limited(&mut self.conn, &mut line, MAX_REPLY_LINE),
            )
            .await
            .map_err(|_| Error::Transport("read timed out".into()))?
            .map_err(|e| Error::Transport(e.to_string()))?;
            match r {
                LineRead::Eof => return Err(Error::Transport("connection closed".into())),
                LineRead::TooLong => return Err(Error::Transport("reply line too long".into())),
                LineRead::Line => {}
            }
            let (code, more, text) = parse_reply_line(&line)?;
            out.push(text);
            if !more {
                return Ok((code, out));
            }
        }
    }
}

/// Maximum length of one upstream reply line (RFC 5321 says 512; be lenient).
const MAX_REPLY_LINE: usize = 64 * 1024;
/// Maximum number of lines in one upstream reply.
const MAX_REPLY_LINES: usize = 1000;

/// Parses one reply line into (code, continuation?, text), working on bytes.
fn parse_reply_line(line: &[u8]) -> Result<(u16, bool, String)> {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    let line = &line[..end];
    if line.len() < 3 || !line[..3].iter().all(u8::is_ascii_digit) {
        return Err(Error::Transport(format!(
            "bad reply line {:?}",
            String::from_utf8_lossy(line)
        )));
    }
    let code = line[..3]
        .iter()
        .fold(0u16, |acc, d| acc * 10 + u16::from(d - b'0'));
    // A hyphen after the code means more lines follow.
    let more = line.get(3) == Some(&b'-');
    let text = String::from_utf8_lossy(line.get(4..).unwrap_or(&[]))
        .trim()
        .to_string();
    Ok((code, more, text))
}

/// Result of [`read_line_limited`].
#[derive(Debug, PartialEq, Eq)]
pub enum LineRead {
    /// A complete line (including its terminating LF) was read into the buffer.
    Line,
    /// The line exceeded the cap. The rest of the line (through its LF) was
    /// consumed and discarded; the buffer holds only a prefix.
    TooLong,
    /// The peer closed the connection before a complete line arrived.
    Eof,
}

/// Reads one LF-terminated line into `buf` (cleared first), storing at most
/// `max` bytes. An overlong line is consumed through its end and reported as
/// [`LineRead::TooLong`], so the stream stays in sync without unbounded
/// buffering.
pub async fn read_line_limited<R: AsyncBufRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<LineRead> {
    buf.clear();
    let mut too_long = false;
    loop {
        let avail = r.fill_buf().await?;
        if avail.is_empty() {
            return Ok(LineRead::Eof);
        }
        let (n, done) = match avail.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (avail.len(), false),
        };
        if !too_long {
            let room = max.saturating_sub(buf.len());
            if n > room {
                buf.extend_from_slice(&avail[..room]);
                too_long = true;
            } else {
                buf.extend_from_slice(&avail[..n]);
            }
        }
        r.consume(n);
        if done {
            return Ok(if too_long {
                LineRead::TooLong
            } else {
                LineRead::Line
            });
        }
    }
}

/// Dot-stuffs a message per RFC 5321 §4.5.2 (a line starting with "." gets an
/// extra "."), normalizing bare LF to CRLF. Byte-exact for 8-bit content.
#[cfg(test)]
fn dot_stuff(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 64);
    StuffState::default().stuff_into(msg, &mut out);
    out
}

/// Incremental dot-stuffing (and bare-LF -> CRLF) across chunk boundaries.
struct StuffState {
    bol: bool,
    prev: u8,
    last2: [u8; 2],
}

impl Default for StuffState {
    fn default() -> Self {
        StuffState {
            bol: true,
            prev: 0,
            last2: [0, 0],
        }
    }
}

impl StuffState {
    fn stuff_into(&mut self, msg: &[u8], out: &mut Vec<u8>) {
        for &b in msg {
            if self.bol && b == b'.' {
                out.push(b'.');
            }
            if b == b'\n' && self.prev != b'\r' {
                out.push(b'\r');
                self.last2 = [self.last2[1], b'\r'];
            }
            out.push(b);
            self.last2 = [self.last2[1], b];
            self.bol = b == b'\n';
            self.prev = b;
        }
    }

    fn ends_crlf(&self) -> bool {
        self.last2 == *b"\r\n"
    }
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

/// Why [`read_data`] failed.
#[derive(Debug)]
pub enum DataError {
    /// The message exceeded the size limit. The rest of it was read and
    /// discarded through the terminating "." line, so the session is still in
    /// sync and the caller may reply 552 and carry on.
    TooLarge,
    /// No data arrived within the idle timeout (stream position unknown).
    Timeout,
    /// The client is too slow (below [`MIN_DATA_RATE`] after the grace
    /// period); the caller should reply 421 and close (stream position
    /// unknown).
    Abort(&'static str),
    /// Transport error or premature EOF (stream position unknown).
    Io(std::io::Error),
}

impl std::fmt::Display for DataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataError::TooLarge => write!(f, "message too large"),
            DataError::Timeout => write!(f, "timed out reading message"),
            DataError::Abort(m) => write!(f, "aborted: {m}"),
            DataError::Io(e) => write!(f, "reading message: {e}"),
        }
    }
}

impl std::error::Error for DataError {}

/// Reads a full message body from a reader (used by the server DATA phase),
/// un-stuffing dots and stopping at the "\r\n.\r\n" terminator. Past
/// `max_bytes` (0 = unlimited) the remainder is drained and discarded through
/// the terminator and [`DataError::TooLarge`] is returned.
pub async fn read_data<R: AsyncBufRead + Unpin>(
    r: &mut R,
    max_bytes: usize,
) -> std::result::Result<Vec<u8>, DataError> {
    read_data_timeout(r, max_bytes, None).await
}

/// Like [`read_data`], with an idle timeout applied to every read.
/// Minimum average upload rate (bytes/second) enforced after
/// [`MIN_RATE_GRACE`], so slow-drip clients cannot hold DATA slots.
pub const MIN_DATA_RATE: f64 = 256.0;
/// Time before the minimum rate is enforced.
pub const MIN_RATE_GRACE: Duration = Duration::from_secs(60);

pub async fn read_data_timeout<R: AsyncBufRead + Unpin>(
    r: &mut R,
    max_bytes: usize,
    idle: Option<Duration>,
) -> std::result::Result<Vec<u8>, DataError> {
    let mut out: Vec<u8> = Vec::new();
    // The current line: fully buffered while within the limit, otherwise only
    // its first few bytes (enough to recognise the "." terminator).
    let mut cur: Vec<u8> = Vec::new();
    let mut cur_len = 0usize;
    // The last byte of the current line seen so far.
    let mut last = 0u8;
    // Whether the current line starts right after a CRLF (or at the start).
    let mut bol = true;
    let mut too_large = false;
    let started = std::time::Instant::now();
    let mut total: usize = 0;
    loop {
        let avail = match idle {
            Some(d) => timeout(d, r.fill_buf())
                .await
                .map_err(|_| DataError::Timeout)?,
            None => r.fill_buf().await,
        }
        .map_err(DataError::Io)?;
        if avail.is_empty() {
            return Err(DataError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof in DATA",
            )));
        }
        let (n, done) = match avail.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (avail.len(), false),
        };
        // The byte before the newline, when this chunk ends the line.
        let before_last = if n >= 2 { avail[n - 2] } else { last };
        last = avail[n - 1];
        if too_large {
            let keep = n.min(4usize.saturating_sub(cur.len()));
            cur.extend_from_slice(&avail[..keep]);
        } else {
            cur.extend_from_slice(&avail[..n]);
        }
        cur_len += n;
        total += n;
        r.consume(n);
        let elapsed = started.elapsed();
        if elapsed > MIN_RATE_GRACE && (total as f64) / elapsed.as_secs_f64() < MIN_DATA_RATE {
            return Err(DataError::Abort(
                "4.4.2 Transfer too slow, closing connection",
            ));
        }

        if !too_large && max_bytes != 0 && out.len() + cur_len > max_bytes {
            too_large = true;
            out = Vec::new();
            cur.truncate(4);
        }
        if !done {
            continue;
        }
        if bol && cur_len == 3 && cur == b".\r\n" {
            return if too_large {
                Err(DataError::TooLarge)
            } else {
                Ok(out)
            };
        }
        if !too_large {
            // RFC 5321 §4.5.2: drop the leading dot of a line that follows CRLF.
            let start = usize::from(bol && cur.first() == Some(&b'.'));
            out.extend_from_slice(&cur[start..]);
        }
        bol = before_last == b'\r';
        cur.clear();
        cur_len = 0;
        last = 0;
    }
}

/// Reverses [`dot_stuff`]: drops the leading dot of each line that follows a
/// CRLF (or starts the message). A dot after a bare LF is content.
#[cfg(test)]
fn un_dot_stuff(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len());
    let mut bol = true;
    let mut prev = 0u8;
    for &b in msg {
        if bol && b == b'.' {
            bol = false;
            prev = b;
            continue;
        }
        out.push(b);
        bol = b == b'\n' && prev == b'\r';
        prev = b;
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

    #[test]
    fn chunked_stuffing_matches_whole() {
        let msg = b"a\r\n.b\n.c\r\nd.\r\n..e\r\n.";
        let whole = dot_stuff(msg);
        for split in 0..msg.len() {
            let mut st = StuffState::default();
            let mut out = Vec::new();
            st.stuff_into(&msg[..split], &mut out);
            st.stuff_into(&msg[split..], &mut out);
            assert_eq!(out, whole, "split at {split}");
        }
        let mut st = StuffState::default();
        st.stuff_into(b"x\n", &mut Vec::new());
        assert!(st.ends_crlf(), "bare LF counted as CRLF ending");
    }

    #[test]
    fn un_dot_stuff_only_after_crlf() {
        assert_eq!(un_dot_stuff(b"a\n.b\r\n..c\r\n"), b"a\n.b\r\n.c\r\n");
    }

    #[test]
    fn reply_line_multibyte_no_panic() {
        // "é" is two bytes: slicing a &str at 3 would panic mid-character.
        assert!(parse_reply_line("2é0 ok\r\n".as_bytes()).is_err());
        assert!(parse_reply_line("éé ok".as_bytes()).is_err());
        assert!(parse_reply_line(b"\xff\xfe\xfd").is_err());
        assert!(parse_reply_line(b"25").is_err());
        let (c, more, t) = parse_reply_line("250-héllo\r\n".as_bytes()).unwrap();
        assert_eq!((c, more, t.as_str()), (250, true, "héllo"));
        let (c, more, _) = parse_reply_line(b"550 no\r\n").unwrap();
        assert_eq!((c, more), (550, false));
    }

    #[tokio::test]
    async fn client_multibyte_greeting_is_error_not_panic() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let _ = s.write_all("2é0 hi\r\n".as_bytes()).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let r = Client::dial(&Options {
            addr,
            timeout: Duration::from_secs(5),
            ..Default::default()
        })
        .await;
        assert!(matches!(r, Err(Error::Transport(_))));
    }

    #[tokio::test]
    async fn line_limited_discards_overlong() {
        let mut input: &[u8] = b"short\r\nxxxxxxxxxxxxxxxxxxxx\r\nnext\r\npartial";
        let mut buf = Vec::new();
        assert_eq!(
            read_line_limited(&mut input, &mut buf, 10).await.unwrap(),
            LineRead::Line
        );
        assert_eq!(buf, b"short\r\n");
        assert_eq!(
            read_line_limited(&mut input, &mut buf, 10).await.unwrap(),
            LineRead::TooLong
        );
        assert_eq!(buf.len(), 10);
        assert_eq!(
            read_line_limited(&mut input, &mut buf, 10).await.unwrap(),
            LineRead::Line
        );
        assert_eq!(buf, b"next\r\n");
        assert_eq!(
            read_line_limited(&mut input, &mut buf, 10).await.unwrap(),
            LineRead::Eof
        );
    }

    #[tokio::test]
    async fn read_data_unstuffs_and_stops() {
        let mut input: &[u8] = b"a\r\n..b\r\nc\n.d\r\n.\r\nAFTER\r\n";
        let got = read_data(&mut input, 0).await.unwrap();
        assert_eq!(got, b"a\r\n.b\r\nc\n.d\r\n");
        assert_eq!(input, b"AFTER\r\n");

        let mut empty: &[u8] = b".\r\nX";
        assert!(read_data(&mut empty, 0).await.unwrap().is_empty());

        // ".\r\n" after a bare LF is not the terminator.
        let mut bare: &[u8] = b"a\n.\r\nb\r\n.\r\n";
        assert_eq!(read_data(&mut bare, 0).await.unwrap(), b"a\n.\r\nb\r\n");
    }

    #[tokio::test]
    async fn read_data_too_large_drains_to_terminator() {
        let mut msg = Vec::new();
        for _ in 0..1000 {
            msg.extend_from_slice(b"0123456789012345678901234567890123456789\r\n");
        }
        // A line that would look like a command must not escape the drain.
        msg.extend_from_slice(b"RCPT TO:<x@evil.example>\r\n.\r\nNEXT\r\n");
        let mut input: &[u8] = &msg;
        let r = read_data(&mut input, 100).await;
        assert!(matches!(r, Err(DataError::TooLarge)), "{r:?}");
        assert_eq!(input, b"NEXT\r\n");
    }

    #[tokio::test]
    async fn read_data_eof_is_io() {
        let mut input: &[u8] = b"abc\r\n";
        assert!(matches!(
            read_data(&mut input, 0).await,
            Err(DataError::Io(_))
        ));
    }

    #[tokio::test]
    async fn read_data_idle_timeout() {
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(b"partial").await.unwrap();
        let mut r = BufReader::new(b);
        let res = read_data_timeout(&mut r, 0, Some(Duration::from_millis(50))).await;
        assert!(matches!(res, Err(DataError::Timeout)));
        drop(a);
    }
}
