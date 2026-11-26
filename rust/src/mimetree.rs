//! Structural MIME rewriting. Port of the Go `internal/mimeproc` Part tree,
//! `Extract` and `InsertBanner`: the message is parsed into a tree of raw-byte
//! parts so that every part the gateway does not touch is re-serialized
//! byte-for-byte, attachments are removed in place (multipart/signed wrappers
//! are unwrapped when their content changes), and the download banner is
//! appended to the first text/plain and text/html bodies (quoted-printable,
//! UTF-8), or added as a new multipart/alternative part when neither exists.
//!
//! This is the gateway's single MIME parser: quarantine *and* the DLP scanner
//! ([`crate::mimeproc::parse`]) both walk this tree, so what is inspected is
//! exactly the structure recipients are given. `mailparse` is only ever run on
//! single, non-multipart leaves (with a synthesized Content-Type), so its
//! unbounded multipart recursion can never be reached with attacker input.
//!
//! Hostile input is bounded: at most [`MAX_PARTS`] entities per message and
//! [`MAX_FIELDS`] header fields per entity are parsed, nesting stops at
//! [`MAX_DEPTH`], and entities with conflicting duplicate Content-* headers
//! are opaque ([`Opaque`]); every opaque entity is extracted whole and
//! reported as uninspectable. A missing Content-Type means text/plain
//! (message/rfc822 inside multipart/digest), RFC 2045 §5.2.
//!
//! Round-trip guarantee: for CRLF input, `parse(x).to_bytes() == x` — header
//! lines without a colon, delimiter transport padding, the preamble's line
//! break, a missing close delimiter and a missing header/body separator are all
//! preserved.

use std::cell::OnceCell;
use std::collections::BTreeMap;

use mailparse::{parse_content_disposition, parse_content_type, DispositionType};

/// Maximum multipart nesting the tree descends into. A multipart nested deeper
/// stays an opaque leaf ([`Part::is_truncated`]) and is treated as an
/// uninspectable attachment.
pub const MAX_DEPTH: usize = 32;

/// Maximum number of MIME entities parsed per message (across the whole
/// tree). Once exhausted, the rest of a multipart body is kept as one opaque,
/// uninspectable entity (extracted whole), so a body of millions of
/// delimiter lines cannot exhaust memory.
pub const MAX_PARTS: usize = 2000;

/// Maximum header fields parsed per entity. Further header lines are kept
/// verbatim (and never matched by a lookup); when they include a Content-*
/// field the entity is opaque, since recipients may honour it.
pub const MAX_FIELDS: usize = 1000;

/// Most parameters accepted in one Content-* field (more is ambiguous).
const MAX_PARAMS: usize = 64;

/// Longest raw filename value decoded (its tail: the base name/extension).
const MAX_RAW_NAME: usize = 8 * 1024;

/// Why an entity could not be parsed into an inspectable structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opaque {
    /// A multipart nested deeper than [`MAX_DEPTH`].
    Depth,
    /// The per-message entity budget ([`MAX_PARTS`]) was exhausted.
    Parts,
    /// Conflicting duplicate Content-Type / Content-Disposition /
    /// Content-Transfer-Encoding fields or duplicate parameters: different
    /// clients would interpret the entity differently.
    Ambiguous,
    /// A Content-* field beyond the [`MAX_FIELDS`] header limit.
    Headers,
}

#[derive(Clone, Debug)]
struct Field {
    /// Lowercase field name ("" for a header line without a colon, which is
    /// kept verbatim but never matches a lookup).
    name: String,
    /// Full raw field bytes including folding and the trailing CRLF (the last
    /// field of a header block without a separator may lack the CRLF).
    raw: Vec<u8>,
}

impl Field {
    fn value(&self) -> String {
        let c = self
            .raw
            .iter()
            .position(|&b| b == b':')
            .map(|i| i + 1)
            .unwrap_or(self.raw.len());
        let v: Vec<u8> = self.raw[c..]
            .iter()
            .copied()
            .filter(|&b| b != b'\r' && b != b'\n')
            .collect();
        String::from_utf8_lossy(&v).trim().to_string()
    }
}

/// One MIME entity.
#[derive(Clone, Debug)]
pub struct Part {
    fields: Vec<Field>,
    /// The header block was terminated by an empty line.
    has_sep: bool,
    body: Vec<u8>,
    /// Bytes before the first delimiter; `Some(p)` means `p` + CRLF precede it,
    /// `None` that the delimiter starts the body.
    preamble: Option<Vec<u8>>,
    children: Vec<Part>,
    /// Bytes after the closing delimiter line's "--" (starts with its CRLF).
    epilogue: Vec<u8>,
    boundary: Option<String>,
    /// The multipart had no close delimiter (the last child runs to the end).
    open_ended: bool,
    /// Bytes after "--boundary" on the delimiter line that opened this part,
    /// through its line break (`None` for parts the gateway created: CRLF).
    delim_tail: Option<Vec<u8>>,
    /// This (empty) child was followed directly by the next delimiter line,
    /// with no CRLF of its own.
    no_tail_crlf: bool,
    /// Why the entity is opaque (not parsed / not trustworthy), if it is.
    opaque: Option<Opaque>,
    /// Raw bytes only (no header parse): `body` is written verbatim.
    verbatim: bool,
    /// A child of multipart/digest (default type message/rfc822).
    digest_child: bool,
    /// Cached [`Part::filename`] (reset whenever a field changes).
    fname: OnceCell<String>,
}

impl Default for Part {
    fn default() -> Self {
        Part {
            fields: Vec::new(),
            has_sep: true,
            body: Vec::new(),
            preamble: None,
            children: Vec::new(),
            epilogue: Vec::new(),
            boundary: None,
            open_ended: false,
            delim_tail: None,
            no_tail_crlf: false,
            opaque: None,
            verbatim: false,
            digest_child: false,
            fname: OnceCell::new(),
        }
    }
}

/// Normalizes bare LF and bare CR line breaks to CRLF (what [`parse`] does
/// before parsing).
pub fn crlf(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + msg.len() / 40);
    let n = msg.len();
    for i in 0..n {
        let b = msg[i];
        if (b == b'\n' && (i == 0 || msg[i - 1] != b'\r'))
            || (b == b'\r' && (i + 1 >= n || msg[i + 1] != b'\n'))
        {
            out.extend_from_slice(b"\r\n");
        } else {
            out.push(b);
        }
    }
    out
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.len() > h.len() {
        return None;
    }
    h.windows(n.len()).position(|w| w == n)
}

/// Parses a raw message (bare LFs / CRs are normalized to CRLF).
pub fn parse(raw: &[u8]) -> Part {
    let mut budget = MAX_PARTS;
    parse_part(&crlf(raw), 0, false, &mut budget)
}

/// An opaque entity holding `raw` verbatim.
fn verbatim_part(raw: &[u8], why: Opaque) -> Part {
    Part {
        body: raw.to_vec(),
        has_sep: false,
        opaque: Some(why),
        verbatim: true,
        ..Default::default()
    }
}

fn parse_part(raw: &[u8], depth: usize, digest_child: bool, budget: &mut usize) -> Part {
    if *budget == 0 {
        return verbatim_part(raw, Opaque::Parts);
    }
    *budget -= 1;
    let (head, body, has_sep): (&[u8], &[u8], bool) = if raw.starts_with(b"\r\n") {
        (&[], &raw[2..], true)
    } else {
        match find(raw, b"\r\n\r\n") {
            Some(i) => (&raw[..i + 2], &raw[i + 4..], true),
            None => (raw, &[], false),
        }
    };
    let mut fields: Vec<Field> = Vec::new();
    let mut opaque = None;
    let mut start = 0;
    while start < head.len() {
        let end = find(&head[start..], b"\r\n")
            .map(|i| start + i + 2)
            .unwrap_or(head.len());
        let line = &head[start..end];
        if (line[0] == b' ' || line[0] == b'\t') && !fields.is_empty() {
            fields.last_mut().unwrap().raw.extend_from_slice(line);
        } else if fields.len() >= MAX_FIELDS {
            // Keep the rest verbatim; hidden Content-* fields make it opaque.
            let rest = &head[start..];
            let content = rest
                .split(|&b| b == b'\n')
                .any(|l| l.len() >= 8 && l[..8].eq_ignore_ascii_case(b"content-"));
            if content {
                opaque = Some(Opaque::Headers);
            }
            fields.push(Field {
                name: if content {
                    "content-x-overflow".into()
                } else {
                    String::new()
                },
                raw: rest.to_vec(),
            });
            break;
        } else {
            let name = match line.iter().position(|&b| b == b':') {
                Some(c) => String::from_utf8_lossy(&line[..c])
                    .trim()
                    .to_ascii_lowercase(),
                None => String::new(),
            };
            fields.push(Field {
                name,
                raw: line.to_vec(),
            });
        }
        start = end;
    }
    let mut p = Part {
        fields,
        has_sep,
        digest_child,
        opaque,
        ..Default::default()
    };
    if p.opaque.is_none() && p.ambiguous_content_headers() {
        p.opaque = Some(Opaque::Ambiguous);
    }
    if p.opaque.is_some() {
        p.body = body.to_vec();
        return p;
    }
    let (mt, params) = p.media_type();
    if mt.starts_with("multipart/") {
        if let Some(b) = params.get("boundary").filter(|b| !b.is_empty()) {
            if depth >= MAX_DEPTH {
                p.opaque = Some(Opaque::Depth);
            } else if let Some(sp) = split_multipart(body, b, *budget) {
                let digest = mt == "multipart/digest";
                p.preamble = sp.preamble.map(|(s, e)| body[s..e].to_vec());
                match sp.epilogue {
                    Some(s) => p.epilogue = body[s..].to_vec(),
                    None => p.open_ended = true,
                }
                p.children = sp
                    .kids
                    .iter()
                    .map(|k| {
                        let piece = &body[k.start..k.end];
                        let mut c = if k.rest {
                            verbatim_part(piece, Opaque::Parts)
                        } else {
                            parse_part(piece, depth + 1, digest, budget)
                        };
                        c.delim_tail = Some(body[k.tail.0..k.tail.1].to_vec());
                        c.no_tail_crlf = k.no_crlf;
                        c
                    })
                    .collect();
                p.boundary = Some(b.clone());
                return p;
            }
        }
    }
    p.body = body.to_vec();
    p
}

/// One child entity of a multipart body, as byte ranges into that body.
struct Kid {
    start: usize,
    end: usize,
    /// Range of the opening delimiter line after "--boundary" (padding + CRLF).
    tail: (usize, usize),
    no_crlf: bool,
    /// The entity budget ran out: this "child" is the whole remainder of the
    /// body (further delimiters included), kept verbatim.
    rest: bool,
}

struct Split {
    preamble: Option<(usize, usize)>,
    kids: Vec<Kid>,
    /// Start of the bytes after the close delimiter's "--"; None when missing.
    epilogue: Option<usize>,
}

/// Splits a multipart body into preamble, children and epilogue (as ranges, so
/// nested bodies are not copied at every level). None when the opening
/// delimiter is missing. Delimiters must match exactly (RFC 2046 §5.1.1):
/// "--boundary", optionally "--", then only transport padding. At most
/// `max_kids` children are split off; the remainder becomes one `rest` kid.
fn split_multipart(body: &[u8], boundary: &str, max_kids: usize) -> Option<Split> {
    let delim = format!("--{boundary}");
    let d = delim.as_bytes();
    let mut kids: Vec<Kid> = Vec::new();
    let mut preamble: Option<(usize, usize)> = None;
    let mut cur: Option<(usize, (usize, usize))> = None;
    let mut seen_first = false;
    let mut pos = 0;
    while pos <= body.len() {
        let end = find(&body[pos..], b"\r\n")
            .map(|i| pos + i)
            .unwrap_or(body.len());
        let line_end = if end < body.len() { end + 2 } else { end };
        let line = &body[pos..end];
        let is_delim = line.starts_with(d) && {
            let rest = &line[d.len()..];
            let rest = rest.strip_prefix(b"--").unwrap_or(rest);
            rest.iter().all(|&b| b == b' ' || b == b'\t')
        };
        if is_delim {
            match cur.take() {
                Some((s, tail)) => {
                    // Content ends before the CRLF that precedes this delimiter.
                    let (e, no_crlf) = if pos >= s + 2 {
                        (pos - 2, false)
                    } else {
                        (s, true)
                    };
                    kids.push(Kid {
                        start: s,
                        end: e,
                        tail,
                        no_crlf,
                        rest: false,
                    });
                }
                None if !seen_first => {
                    preamble = if pos == 0 { None } else { Some((0, pos - 2)) };
                }
                None => {}
            }
            seen_first = true;
            if line[d.len()..].starts_with(b"--") {
                return Some(Split {
                    preamble,
                    kids,
                    epilogue: Some(pos + d.len() + 2),
                });
            }
            if kids.len() >= max_kids {
                // Budget exhausted: everything after this delimiter line is
                // one opaque remainder (written back verbatim).
                kids.push(Kid {
                    start: line_end,
                    end: body.len(),
                    tail: (pos + d.len(), line_end),
                    no_crlf: false,
                    rest: true,
                });
                return Some(Split {
                    preamble,
                    kids,
                    epilogue: None,
                });
            }
            cur = Some((line_end, (pos + d.len(), line_end)));
        }
        if end >= body.len() {
            break;
        }
        pos = end + 2;
    }
    // Missing close delimiter: the last child runs to the end of the body.
    let (s, tail) = cur?;
    kids.push(Kid {
        start: s,
        end: body.len(),
        tail,
        no_crlf: false,
        rest: false,
    });
    Some(Split {
        preamble,
        kids,
        epilogue: None,
    })
}

impl Part {
    /// Serializes the part (headers, blank line, body or children).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 512);
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        if self.verbatim {
            out.extend_from_slice(&self.body);
            return;
        }
        let sep = self.has_sep || !self.body.is_empty() || self.boundary.is_some();
        let n = self.fields.len();
        for (i, f) in self.fields.iter().enumerate() {
            out.extend_from_slice(&f.raw);
            if !f.raw.ends_with(b"\r\n") && (i + 1 < n || sep) {
                out.extend_from_slice(b"\r\n");
            }
        }
        if sep {
            out.extend_from_slice(b"\r\n");
        }
        match &self.boundary {
            Some(b) => {
                if let Some(p) = &self.preamble {
                    out.extend_from_slice(p);
                    out.extend_from_slice(b"\r\n");
                }
                let n = self.children.len();
                for (i, c) in self.children.iter().enumerate() {
                    out.extend_from_slice(b"--");
                    out.extend_from_slice(b.as_bytes());
                    match &c.delim_tail {
                        Some(t) => out.extend_from_slice(t),
                        None => out.extend_from_slice(b"\r\n"),
                    }
                    let before = out.len();
                    c.write(out);
                    let last = i + 1 == n;
                    let empty_tight = c.no_tail_crlf && out.len() == before;
                    if !(last && self.open_ended) && !empty_tight {
                        out.extend_from_slice(b"\r\n");
                    }
                }
                if !self.open_ended {
                    out.extend_from_slice(b"--");
                    out.extend_from_slice(b.as_bytes());
                    out.extend_from_slice(b"--");
                    out.extend_from_slice(&self.epilogue);
                }
            }
            None => out.extend_from_slice(&self.body),
        }
    }

    pub fn is_multipart(&self) -> bool {
        self.boundary.is_some()
    }

    /// An entity left unparsed / untrusted (too deep, over the entity budget,
    /// ambiguous Content-* headers): treated as an uninspectable attachment.
    pub fn is_truncated(&self) -> bool {
        self.opaque.is_some()
    }

    /// Why the entity is opaque, if it is.
    pub fn opaque(&self) -> Option<Opaque> {
        self.opaque
    }

    /// Child entities of a multipart (empty for leaves).
    pub fn children(&self) -> &[Part] {
        &self.children
    }

    /// First value of a header (unfolded), if present.
    pub fn header(&self, name: &str) -> Option<String> {
        let n = name.to_ascii_lowercase();
        self.fields.iter().find(|f| f.name == n).map(Field::value)
    }

    /// Every value of a header (unfolded), in order.
    pub fn headers(&self, name: &str) -> Vec<String> {
        let n = name.to_ascii_lowercase();
        self.fields
            .iter()
            .filter(|f| f.name == n)
            .map(Field::value)
            .collect()
    }

    /// The raw header block (every field as received, folding included).
    pub fn raw_headers(&self) -> Vec<u8> {
        self.fields.iter().flat_map(|f| f.raw.clone()).collect()
    }

    fn touch(&mut self) {
        self.fname = OnceCell::new();
    }

    /// Replaces every instance of `name` with a single field appended last.
    pub fn set_header(&mut self, name: &str, value: &str) {
        let n = name.to_ascii_lowercase();
        self.fields.retain(|f| f.name != n);
        self.add_header(name, value);
    }

    pub fn add_header(&mut self, name: &str, value: &str) {
        self.touch();
        self.fields.push(Field {
            name: name.to_ascii_lowercase(),
            raw: format!("{name}: {value}\r\n").into_bytes(),
        });
    }

    /// Prepends a header field (used for trace/marker headers on the root).
    pub fn prepend_header(&mut self, name: &str, value: &str) {
        self.touch();
        self.fields.insert(
            0,
            Field {
                name: name.to_ascii_lowercase(),
                raw: format!("{name}: {value}\r\n").into_bytes(),
            },
        );
    }

    /// Removes every header field for which `f(lowercase_name, value)` is true.
    pub fn remove_headers(&mut self, f: impl Fn(&str, &str) -> bool) {
        self.touch();
        self.fields
            .retain(|fl| fl.name.is_empty() || !f(&fl.name, &fl.value()));
    }

    /// Renames every instance of header `from` to `to`, keeping values and
    /// positions.
    pub fn rename_header(&mut self, from: &str, to: &str) {
        self.touch();
        let n = from.to_ascii_lowercase();
        for fl in self.fields.iter_mut().filter(|f| f.name == n) {
            let c = fl.raw.iter().position(|&b| b == b':').unwrap_or(0);
            let mut raw = to.as_bytes().to_vec();
            raw.extend_from_slice(&fl.raw[c..]);
            fl.raw = raw;
            fl.name = to.to_ascii_lowercase();
        }
    }

    fn clear_content_headers(&mut self) {
        self.touch();
        self.fields.retain(|f| !f.name.starts_with("content-"));
    }

    /// Conflicting duplicate Content-Type / Content-Disposition /
    /// Content-Transfer-Encoding fields, or a duplicated parameter in one:
    /// the first instance (what this parser uses) may not be what a
    /// recipient's client uses.
    fn ambiguous_content_headers(&self) -> bool {
        for name in [
            "content-type",
            "content-disposition",
            "content-transfer-encoding",
        ] {
            // Any difference at all between instances (beyond surrounding
            // whitespace / line folding) is a conflict: parameter values such
            // as boundary, name and filename are case- and quote-sensitive,
            // so no normalization is safe.
            let vals: Vec<String> = self
                .fields
                .iter()
                .filter(|f| f.name == name)
                .map(Field::value)
                .collect();
            if vals.windows(2).any(|w| w[0] != w[1]) {
                return true;
            }
            if let Some(v) = vals.first() {
                // Parameter names are case-insensitive (and may be quoted
                // or padded): compare them normalized.
                let v: String = v
                    .chars()
                    .filter(|c| !c.is_whitespace() && *c != '"')
                    .collect::<String>()
                    .to_ascii_lowercase();
                // Parameters are split exactly as mailparse splits them.
                // Absurdly many parameters: refuse rather than parse them.
                if v.matches(';').count() > MAX_PARAMS {
                    return true;
                }
                let mut seen: Vec<&str> = Vec::new();
                for kv in v.split(';').skip(1) {
                    if let Some((k, _)) = kv.split_once('=') {
                        if seen.contains(&k) {
                            return true;
                        }
                        seen.push(k);
                    }
                }
                // RFC 2231: `name` together with `name*` / `name*N[*]` is
                // ambiguous when the two decode to different extensions
                // (clients prefer the starred form; this parser and mailparse
                // may use the plain one). Same-name pairs, which some mailers
                // send for non-ASCII names, are fine.
                if let Some(raw) = self
                    .fields
                    .iter()
                    .find(|f| f.name == name)
                    .map(Field::value)
                {
                    if rfc2231_pairs(&raw)
                        .iter()
                        .any(|(plain, starred)| name_ext(plain) != name_ext(starred))
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Lowercase media type and its parameters. A missing (or empty)
    /// Content-Type defaults to text/plain; charset=us-ascii (message/rfc822
    /// in a multipart/digest), RFC 2045 §5.2 / RFC 2046 §5.1.5. A present but
    /// syntactically invalid one is treated as application/octet-stream, so
    /// it is never trusted as displayable text.
    pub fn media_type(&self) -> (String, BTreeMap<String, String>) {
        let raw = self.header("content-type").unwrap_or_default();
        if raw.trim().is_empty() {
            let mut params = BTreeMap::new();
            if self.digest_child {
                return ("message/rfc822".into(), params);
            }
            params.insert("charset".into(), "us-ascii".into());
            return ("text/plain".into(), params);
        }
        let ct = parse_content_type(&raw);
        let mut params: BTreeMap<String, String> = ct.params.into_iter().collect();
        let mt = ct.mimetype.trim().to_ascii_lowercase();
        if !valid_media_type(&mt) {
            return ("application/octet-stream".into(), params);
        }
        params.entry("charset".into()).or_insert(ct.charset);
        (mt, params)
    }

    /// Lowercase disposition type ("" when absent) and its parameters.
    pub fn disposition(&self) -> (String, BTreeMap<String, String>) {
        match self.header("content-disposition") {
            None => (String::new(), BTreeMap::new()),
            Some(v) => {
                let d = parse_content_disposition(&v);
                let kind = match d.disposition {
                    DispositionType::Inline => "inline".to_string(),
                    DispositionType::Attachment => "attachment".to_string(),
                    DispositionType::FormData => "form-data".to_string(),
                    DispositionType::Extension(e) => e.to_ascii_lowercase(),
                };
                (kind, d.params.into_iter().collect())
            }
        }
    }

    /// Decoded (RFC 2231/2047) filename, unsanitized, or "". Only the tail of
    /// an overlong raw value is decoded (it holds the base name and
    /// extension), and the result is cached.
    pub fn filename(&self) -> String {
        self.fname
            .get_or_init(|| {
                let (_, dp) = self.disposition();
                let raw = match dp.get("filename") {
                    Some(n) => n.clone(),
                    None => self.media_type().1.remove("name").unwrap_or_default(),
                };
                crate::mimeproc::decode_header(tail_str(&raw, MAX_RAW_NAME))
            })
            .clone()
    }

    /// Every decoded name the entity carries: the Content-Disposition
    /// filename and the Content-Type name (clients differ in which one they
    /// show and save under), without empty or repeated ones.
    pub fn names(&self) -> Vec<String> {
        let mut out = vec![self.filename()];
        // Both forms of an RFC 2231 plain+starred pair (clients show the
        // starred one).
        for name in ["content-disposition", "content-type"] {
            if let Some(raw) = self
                .fields
                .iter()
                .find(|f| f.name == name)
                .map(Field::value)
            {
                for (p, st) in rfc2231_pairs(&raw) {
                    for n in [p, st] {
                        if !n.is_empty() && !out.contains(&n) {
                            out.push(n);
                        }
                    }
                }
            }
        }
        if self.disposition().1.contains_key("filename") {
            if let Some(n) = self.media_type().1.remove("name") {
                let n = crate::mimeproc::decode_header(tail_str(&n, MAX_RAW_NAME));
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
        out.retain(|n| !n.is_empty());
        out
    }

    /// Sanitized [`Part::names`] (non-empty only).
    fn safe_names(&self) -> Vec<String> {
        self.names()
            .iter()
            .map(|n| crate::mimeproc::sanitize_filename(n))
            .filter(|n| !n.is_empty())
            .collect()
    }

    /// The lowercase Content-Transfer-Encoding ("" when absent).
    fn cte(&self) -> String {
        self.header("content-transfer-encoding")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
    }

    /// uuencode used as a transfer encoding (not a registered CTE, but
    /// decoded by common clients).
    fn is_uuencoded_cte(&self) -> bool {
        matches!(
            self.cte().as_str(),
            "x-uuencode" | "uuencode" | "x-uue" | "uue"
        )
    }

    /// Body with the transfer encoding removed. Multipart (and opaque)
    /// entities are returned raw: `mailparse` is never run on them.
    pub fn decode_body(&self) -> Vec<u8> {
        if self.is_uuencoded_cte() && self.opaque.is_none() && !self.is_multipart() {
            // One entity, one attachment: no block limit needed here.
            let (_, blocks, _) = split_uuencode(&self.body, usize::MAX);
            if !blocks.is_empty() {
                return blocks.into_iter().flat_map(|b| b.data).collect();
            }
        }
        let Some(lb) = self.leaf_bytes() else {
            return self.body.clone();
        };
        match mailparse::parse_mail(&lb) {
            Ok(m) => m.get_body_raw().unwrap_or_else(|_| self.body.clone()),
            Err(_) => self.body.clone(),
        }
    }

    /// Body decoded to UTF-8 text using the declared charset (None for
    /// multiparts or an undecodable body).
    pub fn text(&self) -> Option<String> {
        mailparse::parse_mail(&self.leaf_bytes()?)
            .ok()?
            .get_body()
            .ok()
    }

    /// A self-contained single-part entity for `mailparse`: a synthesized,
    /// non-multipart Content-Type plus the first Content-Transfer-Encoding.
    /// None for multiparts, so `mailparse`'s multipart recursion is unreachable.
    fn leaf_bytes(&self) -> Option<Vec<u8>> {
        let (mt, params) = self.media_type();
        if self.opaque.is_some() || self.is_multipart() || mt.starts_with("multipart/") {
            return None;
        }
        let mut out = Vec::with_capacity(self.body.len() + 128);
        if mt != "message/rfc822" || self.header("content-type").is_some() {
            out.extend_from_slice(
                format!("Content-Type: {}\r\n", format_media_type(&mt, &params)).as_bytes(),
            );
        }
        if let Some(cte) = self.header("content-transfer-encoding") {
            out.extend_from_slice(format!("Content-Transfer-Encoding: {cte}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        Some(out)
    }

    fn make_multipart_mixed(&mut self) {
        self.clear_content_headers();
        let b = new_boundary();
        self.set_header(
            "Content-Type",
            &format!("multipart/mixed; boundary=\"{b}\""),
        );
        self.boundary = Some(b);
        self.has_sep = true;
        self.opaque = None;
        self.verbatim = false;
        self.open_ended = false;
        self.body.clear();
        self.children.clear();
        self.preamble = None;
        self.epilogue = b"\r\n".to_vec();
    }

    /// Makes self carry src's content while keeping self's non-content headers
    /// (and its own position in the parent).
    fn replace_content(&mut self, src: Part) {
        self.clear_content_headers();
        for f in src
            .fields
            .into_iter()
            .filter(|f| f.name.starts_with("content-"))
        {
            self.fields.push(f);
        }
        self.has_sep = true;
        self.body = src.body;
        self.children = src.children;
        self.preamble = src.preamble;
        self.epilogue = src.epilogue;
        self.boundary = src.boundary;
        self.open_ended = src.open_ended;
        self.opaque = src.opaque;
        self.digest_child = src.digest_child;
    }
}

/// The last `max` bytes of `s` (snapped to a char boundary).
/// Lowercased extension of a sanitized file name ("" when none).
fn name_ext(n: &str) -> String {
    let n = crate::mimeproc::sanitize_filename(n).to_lowercase();
    n.rsplit_once('.')
        .map(|(_, e)| e.to_string())
        .unwrap_or_default()
}

/// For each parameter given both plain (`x=`) and in RFC 2231 form (`x*=` or
/// `x*N[*]=`), the (decoded plain, decoded starred) values. Parsed from the
/// raw header value (case and quotes preserved).
fn rfc2231_pairs(raw: &str) -> Vec<(String, String)> {
    let raw = tail_str(raw, MAX_RAW_NAME * 4);
    // Quote-aware split on ';'.
    let mut params: Vec<(String, String)> = Vec::new();
    let mut cur = String::new();
    let mut inq = false;
    let mut esc = false;
    let mut segs: Vec<String> = Vec::new();
    for c in raw.chars() {
        if esc {
            cur.push(c);
            esc = false;
            continue;
        }
        match c {
            '\\' if inq => esc = true,
            '"' => inq = !inq,
            ';' if !inq => segs.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
        if segs.len() > MAX_PARAMS + 1 {
            return Vec::new();
        }
    }
    segs.push(cur);
    for seg in segs.into_iter().skip(1) {
        if let Some((k, v)) = seg.split_once('=') {
            params.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let mut out = Vec::new();
    for (k, plain) in params.iter().filter(|(k, _)| !k.contains('*')) {
        let prefix = format!("{k}*");
        let mut parts: Vec<(u32, bool, &str)> = params
            .iter()
            .filter_map(|(pk, pv)| {
                let rest = pk.strip_prefix(&prefix)?;
                if rest.is_empty() {
                    return Some((0, true, pv.as_str()));
                }
                let (num, enc) = match rest.strip_suffix('*') {
                    Some(n) => (n, true),
                    None => (rest, false),
                };
                num.parse::<u32>().ok().map(|n| (n, enc, pv.as_str()))
            })
            .collect();
        if parts.is_empty() {
            continue;
        }
        parts.sort_by_key(|p| p.0);
        let mut charset = String::from("us-ascii");
        let mut bytes: Vec<u8> = Vec::new();
        for (i, (_, enc, v)) in parts.iter().enumerate() {
            if *enc {
                let mut v = *v;
                if i == 0 {
                    // charset'language'value
                    let mut it = v.splitn(3, '\'');
                    if let (Some(cs), Some(_), Some(rest)) = (it.next(), it.next(), it.next()) {
                        if !cs.is_empty() {
                            charset = cs.to_string();
                        }
                        v = rest;
                    }
                }
                let b = v.as_bytes();
                let mut j = 0;
                while j < b.len() {
                    if b[j] == b'%' && j + 2 < b.len() {
                        let h = std::str::from_utf8(&b[j + 1..j + 3]).ok();
                        if let Some(x) = h.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                            bytes.push(x);
                            j += 3;
                            continue;
                        }
                    }
                    bytes.push(b[j]);
                    j += 1;
                }
            } else {
                bytes.extend_from_slice(v.as_bytes());
            }
        }
        let starred = crate::mimeproc::decode_charset(&charset, &bytes);
        out.push((crate::mimeproc::decode_header(plain), starred));
    }
    out
}

fn tail_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut i = s.len() - max;
    while !s.is_char_boundary(i) {
        i += 1;
    }
    &s[i..]
}

/// "type/subtype" made of RFC 2045 tokens.
fn valid_media_type(mt: &str) -> bool {
    let tok = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| (33..=126).contains(&b) && !b"()<>@,;:\\\"/[]?=".contains(&b))
    };
    match mt.split_once('/') {
        Some((t, s)) => tok(t) && tok(s),
        None => false,
    }
}

/// One uuencoded file found in a text body.
pub(crate) struct UuBlock {
    pub(crate) name: String,
    pub(crate) data: Vec<u8>,
}

/// Finds uuencoded blocks ("begin <mode> <name>" … "end") in `data`; returns
/// the text with the blocks removed, the decoded files (at most `max`) and,
/// when there are more, the raw remainder of `data` from the first block
/// beyond `max` onwards (undecoded). A block without its "end" line runs to
/// the end of the text.
pub(crate) fn split_uuencode(data: &[u8], max: usize) -> (Vec<u8>, Vec<UuBlock>, Option<Vec<u8>>) {
    let mut rest: Vec<u8> = Vec::new();
    let mut blocks: Vec<UuBlock> = Vec::new();
    if !data.windows(6).any(|w| w == b"begin ") {
        return (data.to_vec(), blocks, None);
    }
    let mut cur: Option<UuBlock> = None;
    let mut done = false; // data lines ended (zero-length line seen)
    let mut off = 0;
    let lines: Vec<&[u8]> = data.split_inclusive(|&b| b == b'\n').collect();
    for (li, &line) in lines.iter().enumerate() {
        let start = off;
        off += line.len();
        let t = trim_eol(line);
        match cur.as_mut() {
            None => {
                // A short (1-2 digit) mode is only a uuencode header when a
                // well-formed data line follows, so prose such as
                // "begin 1 month later" is left alone.
                let begin = uu_begin(t).filter(|_| {
                    uu_mode_len(t) >= 3
                        || lines
                            .get(li + 1)
                            .map(|n| uu_data_line(trim_eol(n)))
                            .unwrap_or(false)
                });
                if let Some(name) = begin {
                    if blocks.len() >= max {
                        return (rest, blocks, Some(data[start..].to_vec()));
                    }
                    cur = Some(UuBlock {
                        name,
                        data: Vec::new(),
                    });
                    done = false;
                } else {
                    rest.extend_from_slice(line);
                }
            }
            Some(b) => {
                if t.trim_ascii() == b"end" {
                    blocks.push(cur.take().unwrap());
                } else if !done {
                    done = !uu_line(t, &mut b.data);
                }
            }
        }
    }
    if let Some(b) = cur {
        blocks.push(b);
    }
    (rest, blocks, None)
}

/// Digits in the mode field of a "begin" line (0 if not one).
fn uu_mode_len(t: &[u8]) -> usize {
    t.trim_ascii_start()
        .strip_prefix(b"begin ")
        .map(|r| {
            r.trim_ascii_start()
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .count()
        })
        .unwrap_or(0)
}

/// A uuencoded data line: its length character matches its length.
fn uu_data_line(t: &[u8]) -> bool {
    let Some(&first) = t.first() else {
        return false;
    };
    let n = (first.wrapping_sub(b' ') & 63) as usize;
    if n == 0 || n > 45 {
        return false;
    }
    // Lenient like client decoders (short lines are padded; MTAs may strip
    // trailing spaces). Prose is excluded by the character range: lowercase
    // letters are outside ' '..='`'.
    let want = 1 + n.div_ceil(3) * 4;
    (2..=want + 2).contains(&t.len()) && t.iter().all(|&b| (b' '..=b'`').contains(&b))
}

fn trim_eol(l: &[u8]) -> &[u8] {
    let l = l.strip_suffix(b"\n").unwrap_or(l);
    l.strip_suffix(b"\r").unwrap_or(l)
}

/// "begin 644 name" → name. Lenient like the decoders clients use: leading
/// whitespace and an octal mode of three to six digits are accepted.
/// Embedded binary encodings other than uuencode that mail clients render as
/// attachments (yEnc, BinHex 4.0). Not decoded here: a text part carrying one
/// is extracted whole.
pub(crate) fn has_other_binary_encoding(data: &[u8]) -> bool {
    data.split(|&b| b == b'\n').any(|line| {
        let t = line.trim_ascii_start();
        (t.starts_with(b"=ybegin ") && t.windows(5).any(|w| w == b"name="))
            || t.starts_with(b"(This file must be converted with BinHex")
    })
}

fn uu_begin(t: &[u8]) -> Option<String> {
    let r = t.trim_ascii_start().strip_prefix(b"begin ")?;
    let r = r.trim_ascii_start();
    let sp = r.iter().position(|&b| b == b' ' || b == b'\t')?;
    let (mode, name) = (&r[..sp], &r[sp + 1..]);
    // Clients (e.g. Thunderbird) accept any 1+ digit mode.
    if !(1..=6).contains(&mode.len()) || !mode.iter().all(|b| (b'0'..=b'7').contains(b)) {
        return None;
    }
    let name = String::from_utf8_lossy(name).trim().to_string();
    (!name.is_empty()).then_some(name)
}

/// Decodes one uuencoded line into `out`; false at the terminating
/// zero-length line.
fn uu_line(t: &[u8], out: &mut Vec<u8>) -> bool {
    let Some(&first) = t.first() else {
        return true;
    };
    let n = (first.wrapping_sub(b' ') & 63) as usize;
    if n == 0 {
        return false;
    }
    let v = |c: u8| c.wrapping_sub(b' ') & 63;
    let mut got = 0;
    for ch in t[1..].chunks(4) {
        if got >= n {
            break;
        }
        let c: Vec<u8> = (0..4).map(|i| v(*ch.get(i).unwrap_or(&b'`'))).collect();
        let bytes = [
            (c[0] << 2) | (c[1] >> 4),
            (c[1] << 4) | (c[2] >> 2),
            (c[2] << 6) | c[3],
        ];
        for &b in bytes.iter().take(n - got) {
            out.push(b);
            got += 1;
        }
    }
    true
}

pub fn new_boundary() -> String {
    let mut b = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    format!(
        "secmail-{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

// ---------------------------------------------------------------------------
// Extraction

/// Rewrite policy (mirrors config.rewrite).
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub keep_inline_images: bool,
    /// Leave (well-formed) multipart/signed messages untouched.
    pub signed_passthrough: bool,
    /// Reject encrypted messages instead of passing them through.
    pub encrypted_reject: bool,
}

/// An attachment removed from the tree.
#[derive(Clone, Debug)]
pub struct Extracted {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

/// What `extract` did.
#[derive(Debug, Default)]
pub struct ExtractResult {
    pub attachments: Vec<Extracted>,
    /// A multipart/signed wrapper was dropped because its content changed.
    pub signature_removed: bool,
    /// "signed" / "encrypted" when policy left the message untouched.
    pub skipped: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExtractError {
    Encrypted,
}

fn is_signature_type(mt: &str) -> bool {
    matches!(
        mt,
        "application/pgp-signature"
            | "application/pkcs7-signature"
            | "application/x-pkcs7-signature"
    )
}

/// Largest detached signature kept in a multipart/signed.
const MAX_SIGNATURE: usize = 64 * 1024;

/// A detached signature part that may stay in place: a signature media type,
/// nameless or conventionally named (smime.p7s, signature.asc, *.sig — both
/// the Content-Type name and the Content-Disposition filename), not blocked,
/// small, and actually shaped like a signature (an ASCII-armored PGP
/// signature, or a DER SEQUENCE for S/MIME). Anything else in the signature
/// slot is extracted.
fn signature_ok(p: &Part, blocked: &dyn Fn(&str) -> bool) -> bool {
    let mt = p.media_type().0;
    if p.is_multipart() || p.opaque.is_some() || !is_signature_type(&mt) {
        return false;
    }
    let names_ok = p.safe_names().iter().all(|n| {
        let name = n.to_ascii_lowercase();
        (name == "smime.p7s"
            || name == "signature.asc"
            || (name.ends_with(".sig") && name.len() > 4))
            && !blocked(n)
            && !blocked(&name)
    });
    if !names_ok {
        return false;
    }
    let body = p.decode_body();
    if body.len() >= MAX_SIGNATURE {
        return false;
    }
    if mt == "application/pgp-signature" {
        body.trim_ascii_start()
            .starts_with(b"-----BEGIN PGP SIGNATURE-----")
            && body.is_ascii()
    } else {
        body.first() == Some(&0x30)
    }
}

/// True only for content that is genuinely opaque ciphertext:
///
/// - PGP/MIME (RFC 3156): multipart/encrypted with
///   protocol="application/pgp-encrypted", exactly an application/pgp-encrypted
///   control part containing "Version: 1" and an application/octet-stream part
///   whose (decoded) body is an ASCII-armored "-----BEGIN PGP MESSAGE-----";
/// - S/MIME enveloped-data / authEnveloped-data whose decoded body is a DER
///   SEQUENCE (0x30) and whose filename, if any, is smime.p7m.
///
/// Anything else claiming to be "encrypted" (pkcs7 signed-data, a text part in
/// a multipart/encrypted, a named executable) is inspected / extracted
/// normally.
pub fn is_opaque_encrypted(p: &Part) -> bool {
    if p.opaque.is_some() {
        return false;
    }
    let (mt, params) = p.media_type();
    match mt.as_str() {
        "multipart/encrypted" => {
            let proto = params
                .get("protocol")
                .map(|s| s.trim().to_ascii_lowercase())
                .unwrap_or_default();
            if proto != "application/pgp-encrypted"
                || p.children.len() != 2
                || !p
                    .children
                    .iter()
                    .all(|c| !c.is_multipart() && c.opaque.is_none())
            {
                return false;
            }
            let (ctl, data) = (&p.children[0], &p.children[1]);
            ctl.media_type().0 == "application/pgp-encrypted"
                && String::from_utf8_lossy(&ctl.decode_body()).contains("Version: 1")
                && data.media_type().0 == "application/octet-stream"
                && data
                    .decode_body()
                    .trim_ascii_start()
                    .starts_with(b"-----BEGIN PGP MESSAGE-----")
        }
        "application/pkcs7-mime" | "application/x-pkcs7-mime" => {
            let enveloped = params
                .get("smime-type")
                .map(|s| {
                    let s = s.trim().to_ascii_lowercase();
                    s == "enveloped-data" || s == "authenveloped-data"
                })
                .unwrap_or(false);
            let names_ok = p
                .safe_names()
                .iter()
                .all(|n| n.eq_ignore_ascii_case("smime.p7m"));
            !p.is_multipart() && enveloped && names_ok && p.decode_body().first() == Some(&0x30)
        }
        _ => false,
    }
}

/// Any entity in the tree carries a blocked name (Content-Disposition
/// filename or Content-Type name), or a text leaf embeds a uuencoded file
/// with a blocked name.
fn any_blocked_name(p: &Part, blocked: &dyn Fn(&str) -> bool) -> bool {
    if p.safe_names().iter().any(|n| blocked(n)) {
        return true;
    }
    if !p.is_multipart() && p.opaque.is_none() && p.media_type().0 == "text/plain" {
        let body = p.decode_body();
        if has_other_binary_encoding(&body) {
            return true;
        }
        let (_, blocks, rest) = split_uuencode(&body, MAX_PARTS);
        if rest.is_some()
            || blocks.iter().any(|b| {
                let n = crate::mimeproc::sanitize_filename(&b.name);
                n.is_empty() || blocked(&n)
            })
        {
            return true;
        }
    }
    p.children.iter().any(|c| any_blocked_name(c, blocked))
}

/// A multipart/signed with exactly the content part and one acceptable
/// signature part.
fn is_well_formed_signed(p: &Part, blocked: &dyn Fn(&str) -> bool) -> bool {
    p.children.len() == 2 && signature_ok(&p.children[1], blocked)
}

/// Most attachments extracted from one message. Once reached, everything
/// further is gathered into one last, uninspectable blob
/// ([`OVERFLOW_NAME`]), so a hostile message can never turn into an
/// unbounded number of stored objects, rows and jobs.
pub const MAX_ATTACHMENTS: usize = 500;

/// Name of the blob holding everything beyond [`MAX_ATTACHMENTS`] (and
/// uuencoded files beyond the entity budget).
pub const OVERFLOW_NAME: &str = "remaining-attachments.bin";

struct Ctx<'a> {
    opts: &'a Options,
    blocked: &'a dyn Fn(&str) -> bool,
    res: ExtractResult,
    /// Entities left in the per-message budget ([`MAX_PARTS`], shared by MIME
    /// entities and uuencoded files).
    budget: usize,
    /// Content beyond [`MAX_ATTACHMENTS`] (one uninspectable blob).
    overflow: Option<Vec<u8>>,
}

impl Ctx<'_> {
    /// Records an extracted attachment, or appends it to the overflow blob
    /// once [`MAX_ATTACHMENTS`] - 1 are recorded.
    fn push(&mut self, e: Extracted) {
        if self.overflow.is_none() && self.res.attachments.len() + 1 < MAX_ATTACHMENTS {
            self.res.attachments.push(e);
            return;
        }
        let o = self.overflow.get_or_insert_with(Vec::new);
        o.extend_from_slice(
            format!(
                "\r\n----- {} ({}, {} bytes) -----\r\n",
                e.filename,
                e.content_type,
                e.data.len()
            )
            .as_bytes(),
        );
        o.extend_from_slice(&e.data);
    }

    /// Appends raw, undecoded content (uuencoded text beyond the budget) to
    /// the overflow blob.
    fn push_raw(&mut self, data: Vec<u8>) {
        match self.overflow.as_mut() {
            None => self.overflow = Some(data),
            Some(o) => {
                o.extend_from_slice(b"\r\n----- uuencoded remainder -----\r\n");
                o.extend_from_slice(&data);
            }
        }
    }

    fn finish(mut self) -> ExtractResult {
        if let Some(data) = self.overflow.take() {
            self.res.attachments.push(Extracted {
                filename: OVERFLOW_NAME.into(),
                content_type: "application/octet-stream".into(),
                data,
            });
        }
        self.res
    }
}

/// Number of entities in a tree.
fn count_parts(p: &Part) -> usize {
    1 + p.children.iter().map(count_parts).sum::<usize>()
}

/// Removes attachment parts from `root` in place.
pub fn extract(root: &mut Part, opts: &Options) -> Result<ExtractResult, ExtractError> {
    extract_with(root, opts, &|_| false)
}

/// Like [`extract`]; `blocked(sanitized_name)` reports a blocked file
/// extension, and a part the policy would otherwise keep (an inline image, a
/// passed-through encrypted or signed message) is extracted when its name is
/// blocked.
pub fn extract_with(
    root: &mut Part,
    opts: &Options,
    blocked: &dyn Fn(&str) -> bool,
) -> Result<ExtractResult, ExtractError> {
    let mut ctx = Ctx {
        opts,
        blocked,
        res: ExtractResult::default(),
        budget: MAX_PARTS.saturating_sub(count_parts(root)),
        overflow: None,
    };
    if is_opaque_encrypted(root) && !any_blocked_name(root, blocked) {
        if opts.encrypted_reject {
            return Err(ExtractError::Encrypted);
        }
        ctx.res.skipped = "encrypted".into();
        return Ok(ctx.finish());
    }
    let (mt, _) = root.media_type();
    if mt == "multipart/signed"
        && root.opaque.is_none()
        && opts.signed_passthrough
        && is_well_formed_signed(root, blocked)
        && !any_blocked_name(root, blocked)
    {
        ctx.res.skipped = "signed".into();
        return Ok(ctx.finish());
    }
    if !root.is_multipart() {
        if is_attachment(root, &ctx) {
            ctx.push(extract_leaf(root));
            root.make_multipart_mixed();
        } else {
            extract_uuencoded(root, &mut ctx);
        }
        return Ok(ctx.finish());
    }
    walk(root, &mut ctx)?;
    if root.is_multipart() && root.children.is_empty() {
        root.make_multipart_mixed();
    }
    Ok(ctx.finish())
}

fn walk(p: &mut Part, ctx: &mut Ctx) -> Result<bool, ExtractError> {
    let (mt, _) = p.media_type();
    if mt == "multipart/signed" {
        if p.children.is_empty() {
            return Ok(false);
        }
        let mut kids = std::mem::take(&mut p.children);
        // Keep only the content part and one acceptable signature part; every
        // other child (a smuggled third part, a non-signature or suspicious
        // second part) is removed.
        let keep_n = if kids.len() >= 2 && signature_ok(&kids[1], ctx.blocked) {
            2
        } else {
            1
        };
        let mut changed = false;
        for extra in kids.drain(keep_n..) {
            ctx.push(extract_whole(&extra));
            changed = true;
        }
        let content = kids.remove(0);
        let (kept, sub) = process_child(content, ctx)?;
        if !sub && !changed {
            p.children = kept.into_iter().chain(kids).collect();
            return Ok(false);
        }
        ctx.res.signature_removed = true;
        match kept {
            Some(c) if !(c.is_multipart() && c.children.is_empty()) => p.replace_content(c),
            _ => p.children.clear(),
        }
        p.open_ended = false;
        return Ok(true);
    }

    let mut changed = false;
    let kids = std::mem::take(&mut p.children);
    for c in kids {
        let (kept, ch) = process_child(c, ctx)?;
        changed |= ch;
        if let Some(k) = kept {
            p.children.push(k);
        }
    }
    if changed {
        p.open_ended = false;
    }
    Ok(changed)
}

/// Processes one child: returns the part to keep (if any) and whether anything
/// was removed.
fn process_child(c: Part, ctx: &mut Ctx) -> Result<(Option<Part>, bool), ExtractError> {
    if is_opaque_encrypted(&c) {
        // A nested encrypted container cannot be inspected: extract it whole.
        if ctx.opts.encrypted_reject {
            return Err(ExtractError::Encrypted);
        }
        ctx.push(extract_whole(&c));
        return Ok((None, true));
    }
    if c.is_multipart() {
        let mut c = c;
        let ch = walk(&mut c, ctx)?;
        if ch && c.is_multipart() && c.children.is_empty() {
            return Ok((None, true)); // drop now-empty container
        }
        return Ok((Some(c), ch));
    }
    if is_attachment(&c, ctx) {
        ctx.push(extract_leaf(&c));
        return Ok((None, true));
    }
    let mut c = c;
    let ch = extract_uuencoded(&mut c, ctx);
    Ok((Some(c), ch))
}

/// Moves uuencoded files embedded in a kept text/plain body out into
/// attachments (clients render them as attachments). Returns true when the
/// body changed.
fn extract_uuencoded(p: &mut Part, ctx: &mut Ctx) -> bool {
    if p.is_multipart() || p.opaque.is_some() || p.media_type().0 != "text/plain" {
        return false;
    }
    let data = p.decode_body();
    if has_other_binary_encoding(&data) {
        // yEnc / BinHex: move the whole text out as one opaque attachment.
        ctx.budget = ctx.budget.saturating_sub(1);
        ctx.push_raw(data);
        p.set_header("Content-Transfer-Encoding", "7bit");
        p.body = Vec::new();
        return true;
    }
    let max = ctx.budget.min(MAX_ATTACHMENTS);
    let (rest, blocks, remainder) = split_uuencode(&data, max);
    if blocks.is_empty() && remainder.is_none() {
        return false;
    }
    ctx.budget = ctx.budget.saturating_sub(blocks.len());
    for b in blocks {
        let mut name = crate::mimeproc::sanitize_filename(&b.name);
        if name.is_empty() {
            name = "attachment.bin".into();
        }
        ctx.push(Extracted {
            filename: name,
            content_type: "application/octet-stream".into(),
            data: b.data,
        });
    }
    if let Some(r) = remainder {
        // Beyond the budget: the rest of the text, undecoded, as one blob.
        ctx.push_raw(r);
    }
    if matches!(p.cte().as_str(), "" | "7bit" | "8bit" | "binary") {
        p.body = rest;
    } else {
        p.set_header("Content-Transfer-Encoding", "quoted-printable");
        p.body = encode_qp(&rest);
    }
    true
}

fn is_raster_image(mt: &str) -> bool {
    matches!(
        mt,
        "image/png"
            | "image/jpeg"
            | "image/jpg"
            | "image/pjpeg"
            | "image/gif"
            | "image/webp"
            | "image/bmp"
            | "image/x-ms-bmp"
    )
}

/// The decoded content starts with the magic bytes of the declared raster
/// type.
fn raster_magic_ok(mt: &str, data: &[u8]) -> bool {
    match mt {
        "image/png" => data.starts_with(b"\x89PNG"),
        "image/jpeg" | "image/jpg" | "image/pjpeg" => data.starts_with(b"\xFF\xD8\xFF"),
        "image/gif" => data.starts_with(b"GIF8"),
        "image/webp" => data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP",
        "image/bmp" | "image/x-ms-bmp" => data.starts_with(b"BM"),
        _ => false,
    }
}

fn has_raster_ext(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"]
        .iter()
        .any(|e| n.ends_with(e))
}

/// message/* types that are reports or headers only (no attachments of their
/// own) and stay inline.
fn is_report_message(mt: &str) -> bool {
    matches!(
        mt,
        "message/delivery-status"
            | "message/disposition-notification"
            | "message/rfc822-headers"
            | "message/global-delivery-status"
            | "message/global-disposition-notification"
            | "message/global-headers"
    )
}

fn is_attachment(p: &Part, ctx: &Ctx) -> bool {
    let (mt, _) = p.media_type();
    if p.opaque.is_some() || mt.starts_with("multipart/") {
        return true; // opaque, or an unsplit multipart (no boundary)
    }
    if p.is_uuencoded_cte() {
        return true;
    }
    let (disp, _) = p.disposition();
    if disp == "attachment" {
        return true;
    }
    // A headers-only report type that carries a body after its header block
    // (an embedded message in disguise) is extracted like a message.
    let headers_with_body = || {
        if !mt.ends_with("-headers") {
            return false;
        }
        let b = crlf(&p.decode_body());
        let b = b.trim_ascii_start();
        match b.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(i) => !b[i + 4..].trim_ascii().is_empty(),
            None => false,
        }
    };
    if mt.starts_with("message/") && (!is_report_message(&mt) || headers_with_body()) {
        return true; // forwarded mails / news may carry their own attachments
    }
    let name = p.filename();
    if ctx.opts.keep_inline_images && is_raster_image(&mt) && p.header("content-id").is_some() {
        // Every name (CD filename and CT name) must be a raster name.
        if p.safe_names()
            .iter()
            .all(|n| has_raster_ext(n) && !(ctx.blocked)(n))
            && raster_magic_ok(&mt, &p.decode_body())
        {
            return false;
        }
    }
    if !name.is_empty() {
        return true;
    }
    if mt.starts_with("text/") || mt.starts_with("message/") {
        return false;
    }
    true // nameless non-text leaves (signature parts outside multipart/signed too)
}

fn extract_leaf(p: &Part) -> Extracted {
    let (mt, _) = p.media_type();
    let whole = p.opaque.is_some() || p.is_multipart() || mt.starts_with("multipart/");
    let mut name = p.filename();
    if name.is_empty() {
        name = if p.opaque.is_some() {
            "uninspectable.eml".into()
        } else if mt.starts_with("message/") || whole {
            "forwarded-message.eml".into()
        } else {
            format!("attachment{}", ext_for(&mt))
        };
    }
    let data = if whole { p.to_bytes() } else { p.decode_body() };
    let content_type = if p.opaque.is_some() {
        "message/rfc822".into()
    } else {
        mt
    };
    Extracted {
        filename: crate::mimeproc::sanitize_filename(&name),
        content_type,
        data,
    }
}

/// Extracts a whole entity (leaf or container) as one attachment.
fn extract_whole(p: &Part) -> Extracted {
    if !p.is_multipart() {
        return extract_leaf(p);
    }
    let (mt, _) = p.media_type();
    let mut name = p.filename();
    if name.is_empty() {
        name = "attachment.eml".into();
    }
    Extracted {
        filename: crate::mimeproc::sanitize_filename(&name),
        content_type: mt,
        data: p.to_bytes(),
    }
}

fn ext_for(mt: &str) -> &'static str {
    match mt {
        "application/pdf" => ".pdf",
        "application/zip" => ".zip",
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/gif" => ".gif",
        "text/calendar" => ".ics",
        "application/msword" => ".doc",
        "application/pkcs7-mime" | "application/x-pkcs7-mime" => ".p7m",
        _ => ".bin",
    }
}

// ---------------------------------------------------------------------------
// Banner

/// Text and HTML renderings of the download banner.
#[derive(Clone, Debug, Default)]
pub struct Banner {
    pub text: String,
    pub html: String,
}

/// Appends the banner to the first text/plain and first text/html body
/// parts; if neither can be modified, adds a new banner part.
pub fn insert_banner(root: &mut Part, b: &Banner) {
    let mut plain: Option<Vec<usize>> = None;
    let mut html: Option<Vec<usize>> = None;
    find_bodies(root, &mut Vec::new(), &mut plain, &mut html);
    let ok_plain = plain
        .map(|path| append_to_text(node_mut(root, &path), &b.text, false))
        .unwrap_or(false);
    let ok_html = html
        .map(|path| append_to_text(node_mut(root, &path), &b.html, true))
        .unwrap_or(false);
    if !(ok_plain || ok_html) {
        add_banner_part(root, b);
    }
}

fn node_mut<'a>(root: &'a mut Part, path: &[usize]) -> &'a mut Part {
    let mut n = root;
    for &i in path {
        n = &mut n.children[i];
    }
    n
}

fn find_bodies(
    p: &Part,
    path: &mut Vec<usize>,
    plain: &mut Option<Vec<usize>>,
    html: &mut Option<Vec<usize>>,
) {
    let (mt, _) = p.media_type();
    if p.is_multipart() {
        if mt == "multipart/signed" || mt == "multipart/encrypted" {
            return;
        }
        for (i, c) in p.children.iter().enumerate() {
            path.push(i);
            find_bodies(c, path, plain, html);
            path.pop();
        }
        return;
    }
    if p.disposition().0 == "attachment" {
        return;
    }
    match mt.as_str() {
        "text/plain" if plain.is_none() => *plain = Some(path.clone()),
        "text/html" if html.is_none() => *html = Some(path.clone()),
        _ => {}
    }
}

fn append_to_text(p: &mut Part, banner: &str, is_html: bool) -> bool {
    let (mt, mut params) = p.media_type();
    let Some(text) = p.text() else {
        return false;
    };
    let text = if is_html {
        insert_before_body_end(&text, banner)
    } else {
        format!(
            "{}\r\n\r\n{}\r\n",
            text.trim_end_matches(['\r', '\n']),
            banner
        )
    };
    params.insert("charset".into(), "utf-8".into());
    params.remove("format"); // appending breaks format=flowed / delsp
    params.remove("delsp");
    p.set_header("Content-Type", &format_media_type(&mt, &params));
    p.set_header("Content-Transfer-Encoding", "quoted-printable");
    p.body = encode_qp(text.as_bytes());
    p.has_sep = true;
    true
}

fn format_media_type(mt: &str, params: &BTreeMap<String, String>) -> String {
    let mut s = mt.to_string();
    for (k, v) in params {
        if v.is_empty() {
            continue;
        }
        let esc = v.replace('\\', "\\\\").replace('"', "\\\"");
        s.push_str(&format!("; {k}=\"{esc}\""));
    }
    s
}

fn insert_before_body_end(html: &str, banner: &str) -> String {
    match html.to_ascii_lowercase().rfind("</body>") {
        Some(i) => format!("{}{}{}", &html[..i], banner, &html[i..]),
        None => format!("{html}{banner}"),
    }
}

/// Quoted-printable encoding (RFC 2045 §6.7) with CRLF hard breaks and
/// soft breaks keeping lines within 76 characters.
pub fn encode_qp(b: &[u8]) -> Vec<u8> {
    let text = crlf(b);
    let mut out = Vec::with_capacity(text.len() * 11 / 10);
    let lines: Vec<&[u8]> = text.split(|&c| c == b'\n').collect();
    for (li, raw_line) in lines.iter().enumerate() {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let mut col = 0;
        for (i, &c) in line.iter().enumerate() {
            let last = i + 1 == line.len();
            let enc = !(c == b' ' || c == b'\t' || (33..=126).contains(&c) && c != b'=')
                || ((c == b' ' || c == b'\t') && last);
            let tok: Vec<u8> = if enc {
                format!("={c:02X}").into_bytes()
            } else {
                vec![c]
            };
            if col + tok.len() > 75 {
                out.extend_from_slice(b"=\r\n");
                col = 0;
            }
            out.extend_from_slice(&tok);
            col += tok.len();
        }
        if li + 1 < lines.len() {
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

fn leaf(ct: &str, body: &str) -> Part {
    let mut p = Part::default();
    p.add_header("Content-Type", ct);
    p.add_header("Content-Transfer-Encoding", "quoted-printable");
    p.body = encode_qp(body.as_bytes());
    p
}

fn add_banner_part(root: &mut Part, b: &Banner) {
    let ab = new_boundary();
    let mut alt = Part::default();
    alt.add_header(
        "Content-Type",
        &format!("multipart/alternative; boundary=\"{ab}\""),
    );
    alt.boundary = Some(ab);
    alt.children = vec![
        leaf("text/plain; charset=utf-8", &format!("{}\r\n", b.text)),
        leaf(
            "text/html; charset=utf-8",
            &format!("<html><body>{}</body></html>\r\n", b.html),
        ),
    ];
    let (mt, _) = root.media_type();
    if mt == "multipart/mixed" && root.is_multipart() {
        root.children.insert(0, alt);
        return;
    }
    // Wrap the existing content into a new multipart/mixed root.
    let mut inner = Part {
        body: std::mem::take(&mut root.body),
        children: std::mem::take(&mut root.children),
        preamble: root.preamble.take(),
        epilogue: std::mem::take(&mut root.epilogue),
        boundary: root.boundary.take(),
        open_ended: root.open_ended,
        opaque: root.opaque,
        verbatim: root.verbatim,
        fields: root
            .fields
            .iter()
            .filter(|f| f.name.starts_with("content-"))
            .cloned()
            .collect(),
        ..Default::default()
    };
    if inner.fields.is_empty() {
        inner.add_header("Content-Type", "text/plain; charset=us-ascii");
    }
    root.make_multipart_mixed();
    root.children = vec![alt, inner];
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const MIXED: &str = "From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"XX\"\r\n\r\npreamble\r\n--XX\r\nContent-Type: multipart/alternative; boundary=\"YY\"\r\n\r\n--YY\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nCaf=E9 menu\r\n--YY\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><p>Hello</p></body></html>\r\n--YY--\r\n--XX\r\nContent-Type: application/pdf; name=\"report.pdf\"\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--XX\r\nContent-Type: image/png\r\nContent-ID: <logo>\r\nContent-Disposition: inline\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0K\r\n--XX--\r\n";

    fn banner() -> Banner {
        Banner {
            text: "BANNER-TEXT https://gw/dl/t".into(),
            html: "<div>BANNER-HTML</div>".into(),
        }
    }

    #[test]
    fn roundtrip_is_byte_exact() {
        let p = parse(MIXED.as_bytes());
        assert_eq!(p.to_bytes(), MIXED.as_bytes());
    }

    #[test]
    fn extracts_and_banners_preserving_structure() {
        let mut p = parse(MIXED.as_bytes());
        let r = extract(
            &mut p,
            &Options {
                keep_inline_images: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(r.attachments.len(), 1);
        assert_eq!(r.attachments[0].filename, "report.pdf");
        assert_eq!(r.attachments[0].data, b"%PDF-1.4\n");
        insert_banner(&mut p, &banner());
        let out = p.to_bytes();
        let s = String::from_utf8_lossy(&out);
        // Original envelope headers survive.
        for h in [
            "From: a@example.com",
            "To: b@example.com",
            "Date: Mon",
            "Subject: hi",
        ] {
            assert!(s.contains(h), "{h} missing");
        }
        assert!(!s.contains("report.pdf"));
        assert!(s.contains("Content-ID: <logo>"), "inline image kept");
        // Both bodies carry the banner; text re-encoded as UTF-8.
        let m = mailparse::parse_mail(&out).unwrap();
        let alt = &m.subparts[0];
        let plain = alt.subparts[0].get_body().unwrap();
        assert!(plain.contains("Café menu"));
        assert!(plain.contains("BANNER-TEXT https://gw/dl/t"));
        let html = alt.subparts[1].get_body().unwrap();
        assert!(html.contains("<p>Hello</p><div>BANNER-HTML</div></body>"));
    }

    #[test]
    fn inline_image_dropped_by_default() {
        let mut p = parse(MIXED.as_bytes());
        let r = extract(&mut p, &Options::default()).unwrap();
        assert_eq!(r.attachments.len(), 2);
        assert_eq!(r.attachments[1].filename, "attachment.png");
    }

    #[test]
    fn single_part_attachment_becomes_banner_message() {
        let raw = b"From: a@x.com\r\nSubject: s\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"a.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\nAAEC\r\n";
        let mut p = parse(raw);
        let r = extract(&mut p, &Options::default()).unwrap();
        assert_eq!(r.attachments[0].data, vec![0, 1, 2]);
        insert_banner(&mut p, &banner());
        let out = p.to_bytes();
        let m = mailparse::parse_mail(&out).unwrap();
        assert_eq!(m.ctype.mimetype, "multipart/mixed");
        assert_eq!(
            m.headers.iter().filter(|h| h.get_key() == "From").count(),
            1
        );
        let alt = &m.subparts[0];
        assert_eq!(alt.ctype.mimetype, "multipart/alternative");
        assert!(alt.subparts[0].get_body().unwrap().contains("BANNER-TEXT"));
    }

    #[test]
    fn plain_message_wrapped_when_no_text_body() {
        let raw = b"From: a@x.com\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0K\r\n";
        let mut p = parse(raw);
        insert_banner(&mut p, &banner()); // no extraction: wraps the content
        let out = p.to_bytes();
        let m = mailparse::parse_mail(&out).unwrap();
        assert_eq!(m.subparts.len(), 2);
        assert_eq!(m.subparts[1].ctype.mimetype, "image/png");
    }

    #[test]
    fn signed_wrapper_unwrapped_when_modified() {
        let raw = "From: a@x.com\r\nContent-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=\"S\"\r\n\r\n--S\r\nContent-Type: multipart/mixed; boundary=\"M\"\r\n\r\n--M\r\nContent-Type: text/plain\r\n\r\nbody\r\n--M\r\nContent-Type: application/zip; name=\"z.zip\"\r\nContent-Transfer-Encoding: base64\r\n\r\nUEsDBA==\r\n--M--\r\n--S\r\nContent-Type: application/pgp-signature\r\n\r\n-----BEGIN PGP SIGNATURE-----\r\nSIG\r\n--S--\r\n";
        let mut p = parse(raw.as_bytes());
        let r = extract(&mut p, &Options::default()).unwrap();
        assert!(r.signature_removed);
        assert_eq!(r.attachments.len(), 1);
        let s = String::from_utf8(p.to_bytes()).unwrap();
        assert!(!s.contains("multipart/signed"));
        assert!(!s.contains("SIG"));
        assert!(s.contains("From: a@x.com"));

        let mut p = parse(raw.as_bytes());
        let r = extract(
            &mut p,
            &Options {
                signed_passthrough: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(r.skipped, "signed");
        assert_eq!(p.to_bytes(), raw.as_bytes());
    }

    #[test]
    fn encrypted_policy() {
        let raw = b"From: a@x.com\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data\r\nContent-Transfer-Encoding: base64\r\n\r\nMIAG\r\n";
        let mut p = parse(raw);
        assert_eq!(
            extract(
                &mut p,
                &Options {
                    encrypted_reject: true,
                    ..Default::default()
                }
            )
            .unwrap_err(),
            ExtractError::Encrypted
        );
        assert_eq!(
            extract(&mut p, &Options::default()).unwrap().skipped,
            "encrypted"
        );
    }

    #[test]
    fn qp_encoding() {
        assert_eq!(encode_qp(b"a=b \r\nc\t"), b"a=3Db=20\r\nc=09");
        let long = "x".repeat(200);
        let enc = encode_qp(long.as_bytes());
        assert!(enc.split(|&c| c == b'\n').all(|l| l.len() <= 77));
        let m = format!(
            "Content-Transfer-Encoding: quoted-printable\r\n\r\n{}",
            String::from_utf8(encode_qp("한글 é".as_bytes())).unwrap()
        );
        assert_eq!(
            mailparse::parse_mail(m.as_bytes())
                .unwrap()
                .get_body_raw()
                .unwrap(),
            "한글 é".as_bytes()
        );
    }

    fn names(raw: &[u8], o: &Options) -> (Vec<String>, String) {
        let mut p = parse(raw);
        let r = extract(&mut p, o).unwrap();
        (
            r.attachments.iter().map(|a| a.filename.clone()).collect(),
            String::from_utf8_lossy(&p.to_bytes()).into_owned(),
        )
    }

    #[test]
    fn signed_extra_child_is_extracted() {
        let raw = b"From: a@x\r\nContent-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=S\r\n\r\n--S\r\nContent-Type: text/plain\r\n\r\nhi\r\n--S\r\nContent-Type: application/pgp-signature\r\n\r\n-----BEGIN PGP SIGNATURE-----\r\nSIG\r\n--S\r\nContent-Type: application/x-msdownload; name=\"evil.exe\"\r\nContent-Disposition: attachment; filename=\"evil.exe\"\r\n\r\nMZ\r\n--S--\r\n";
        let (n, out) = names(raw, &Options::default());
        assert_eq!(n, vec!["evil.exe".to_string()]);
        assert!(!out.contains("evil.exe") && !out.contains("MZ"));
        assert!(out.contains("hi"));
        // Even under signed passthrough a malformed signed message is processed.
        let (n, out) = names(
            raw,
            &Options {
                signed_passthrough: true,
                ..Default::default()
            },
        );
        assert_eq!(n, vec!["evil.exe".to_string()]);
        assert!(!out.contains("evil.exe"));
        // A non-signature second child is not trusted as "the signature".
        let raw2 = b"From: a@x\r\nContent-Type: multipart/signed; boundary=S\r\n\r\n--S\r\nContent-Type: text/plain\r\n\r\nhi\r\n--S\r\nContent-Type: application/octet-stream\r\n\r\nMZ\r\n--S--\r\n";
        let (n, out) = names(raw2, &Options::default());
        assert_eq!(n.len(), 1);
        assert!(!out.contains("MZ"));
    }

    #[test]
    fn inline_image_with_bad_name_is_extracted() {
        let keep = Options {
            keep_inline_images: true,
            ..Default::default()
        };
        let mkb = |ct: &str, cd: &str, b64: &str| {
            format!("From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: {ct}\r\nContent-ID: <x>\r\nContent-Disposition: {cd}\r\nContent-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--B--\r\n")
        };
        // Real magic bytes for the declared type.
        let mk = |ct: &str, cd: &str| {
            let b64 = if ct.starts_with("image/gif") {
                "R0lGODlh"
            } else if ct.starts_with("image/png") {
                "iVBORw0K"
            } else {
                "TVo="
            };
            mkb(ct, cd, b64)
        };
        // Content that is not the declared raster type is never kept.
        let raw = mkb("image/png", "inline", "TVo=");
        assert_eq!(names(raw.as_bytes(), &keep).0.len(), 1);
        let raw = mk(
            "image/png; name=\"evil.exe\"",
            "inline; filename=\"evil.exe\"",
        );
        let (n, out) = names(raw.as_bytes(), &keep);
        assert_eq!(n, vec!["evil.exe".to_string()]);
        assert!(!out.contains("evil.exe"));
        // SVG (scriptable) is never kept inline.
        let raw = mk("image/svg+xml", "inline");
        assert_eq!(names(raw.as_bytes(), &keep).0.len(), 1);
        // A raster image with a raster name (or none) is kept.
        let raw = mk("image/png; name=\"logo.png\"", "inline");
        assert!(names(raw.as_bytes(), &keep).0.is_empty());
        let raw = mk("image/gif", "inline");
        assert!(names(raw.as_bytes(), &keep).0.is_empty());
        // ...unless the blocked-extension gate says otherwise.
        let mut p = parse(mk("image/png; name=\"logo.png\"", "inline").as_bytes());
        let r = extract_with(&mut p, &keep, &|n: &str| n.ends_with(".png")).unwrap();
        assert_eq!(r.attachments.len(), 1);
    }

    #[test]
    fn only_enveloped_pkcs7_is_opaque() {
        let raw = b"From: a@x\r\nContent-Type: application/pkcs7-mime; smime-type=signed-data; name=smime.p7m\r\nContent-Transfer-Encoding: base64\r\n\r\nMIAG\r\n";
        let mut p = parse(raw);
        let r = extract(
            &mut p,
            &Options {
                encrypted_reject: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(r.skipped, "");
        assert_eq!(r.attachments.len(), 1);
        assert_eq!(r.attachments[0].filename, "smime.p7m");

        // A one-part "multipart/encrypted" is walked, not trusted.
        let raw2 = b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: multipart/encrypted; boundary=E\r\n\r\n--E\r\nContent-Type: application/x-msdownload; name=\"evil.exe\"\r\nContent-Disposition: attachment; filename=\"evil.exe\"\r\n\r\nMZ\r\n--E--\r\n--B--\r\n";
        let (n, out) = names(raw2, &Options::default());
        assert_eq!(n, vec!["evil.exe".to_string()]);
        assert!(!out.contains("evil.exe"));
    }

    const PGP_ENC: &str = "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=E\r\n\r\n--E\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--E\r\nContent-Type: application/octet-stream\r\n\r\n-----BEGIN PGP MESSAGE-----\r\n--E--\r\n";

    #[test]
    fn nested_encrypted_container_is_extracted_or_rejected() {
        let raw = format!("From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\n{PGP_ENC}--B--\r\n");
        let (n, out) = names(raw.as_bytes(), &Options::default());
        assert_eq!(n, vec!["attachment.eml".to_string()]);
        assert!(!out.contains("PGP MESSAGE"));
        let mut p = parse(raw.as_bytes());
        let reject = Options {
            encrypted_reject: true,
            ..Default::default()
        };
        assert_eq!(
            extract(&mut p, &reject).unwrap_err(),
            ExtractError::Encrypted
        );
        // A well-formed top-level PGP/MIME message is opaque: policy applies.
        let top = format!("From: a@x\r\n{PGP_ENC}");
        let mut p = parse(top.as_bytes());
        assert_eq!(
            extract(&mut p, &Options::default()).unwrap().skipped,
            "encrypted"
        );
        assert_eq!(p.to_bytes(), top.as_bytes());
    }

    /// Builds a message nested `n` multiparts deep.
    pub(crate) fn deep_message(n: usize) -> Vec<u8> {
        let mut raw = String::from("From: a@x\r\n");
        for i in 0..n {
            raw.push_str(&format!(
                "Content-Type: multipart/mixed; boundary=b{i}\r\n\r\n--b{i}\r\n"
            ));
        }
        raw.push_str("Content-Type: text/plain\r\n\r\nx\r\n");
        raw.into_bytes()
    }

    #[test]
    fn deep_nesting_does_not_overflow_the_stack() {
        let raw = deep_message(50_000);
        let h = std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || {
                let mut p = parse(&raw);
                let r = extract(&mut p, &Options::default()).unwrap();
                insert_banner(&mut p, &banner());
                let _ = p.to_bytes();
                r.attachments.len()
            })
            .unwrap();
        // The over-deep remainder is quarantined as one opaque attachment.
        assert_eq!(h.join().expect("no stack overflow"), 1);
    }

    #[test]
    fn untouched_messages_round_trip_byte_exact() {
        let cases: &[&[u8]] = &[
            MIXED.as_bytes(),
            b"Subject: a\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nx\r\n--B--\r\n",
            b"Subject: a\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B  \r\nContent-Type: text/plain\r\n\r\nx\r\n--B--\t\r\nepilogue\r\n",
            b"Subject: a\r\nbogus line\r\nX: y\r\n\r\nbody\r\n",
            b"Subject: a\r\nX: y\r\n",
            b"Subject: a\r\nX: y",
            b"\r\nbody only\r\n",
            b"",
            b" leading continuation\r\nSubject: a\r\n\r\nb",
            b"Subject: a\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n--B\r\nContent-Type: text/plain\r\n\r\nx\r\n--B--",
            b"Subject: a\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\npre\r\n--B\r\n\r\nno headers\r\n--B\r\nContent-Type: text/plain\r\n\r\nunterminated",
            b"Subject: a\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: multipart/alternative; boundary=C\r\n\r\n--C\r\n\r\nx\r\n--C--\r\n--B",
            b"Subject: a\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B--\r\n",
            b"Subject: a\r\nContent-Type: text/plain\r\n\r\n\xc7\xd1\xb1\xdb 8-bit\r\n\r\n",
        ];
        for (i, c) in cases.iter().enumerate() {
            let out = parse(c).to_bytes();
            assert_eq!(
                String::from_utf8_lossy(&out),
                String::from_utf8_lossy(c),
                "case {i}"
            );
            assert_eq!(out, *c, "case {i}");
        }
        let deep = deep_message(40);
        assert_eq!(parse(&deep).to_bytes(), deep);
    }
}

/// Round-2 review regressions (MIME bypasses, plain mail, DoS bounds).
#[cfg(test)]
mod r2_tests {
    use super::*;

    fn exe(n: &str) -> bool {
        n.to_ascii_lowercase().ends_with(".exe")
    }

    /// (attachment names, skipped, serialized output)
    fn run(raw: &[u8], o: &Options) -> (Vec<String>, String, String) {
        let mut root = parse(raw);
        let r = extract_with(&mut root, o, &exe).unwrap();
        (
            r.attachments.iter().map(|a| a.filename.clone()).collect(),
            r.skipped,
            String::from_utf8_lossy(&root.to_bytes()).into_owned(),
        )
    }

    #[test]
    fn bypasses_are_extracted() {
        let d = Options {
            keep_inline_images: true,
            ..Default::default()
        };
        let sp = Options {
            keep_inline_images: true,
            signed_passthrough: true,
            ..Default::default()
        };
        let cases: &[(&str, &[u8], &Options)] = &[
            ("pgp-encrypted-root", b"From: a@x\r\nContent-Type: multipart/encrypted; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B\r\nContent-Type: application/octet-stream; name=evil.exe\r\nContent-Disposition: attachment; filename=evil.exe\r\n\r\nMZ\r\n--B--\r\n", &d),
            ("pgp-proto-but-named-exe", b"From: a@x\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=B\r\n\r\n--B\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--B\r\nContent-Type: application/octet-stream; name=evil.exe\r\n\r\n-----BEGIN PGP MESSAGE-----\r\n--B--\r\n", &d),
            ("smime-env-root", b"From: a@x\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=evil.exe\r\nContent-Disposition: attachment; filename=evil.exe\r\n\r\nMZ\r\n", &d),
            ("signed-sigpart", b"From: a@x\r\nContent-Type: multipart/signed; boundary=B; protocol=\"application/pkcs7-signature\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B\r\nContent-Type: application/pkcs7-signature; name=evil.exe\r\nContent-Disposition: attachment; filename=evil.exe\r\n\r\nMZ\r\n--B--\r\n", &d),
            ("signed-sigpart-nested", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=A\r\n\r\n--A\r\nContent-Type: multipart/signed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B\r\nContent-Type: application/pgp-signature; name=evil.exe\r\n\r\nMZ\r\n--B--\r\n--A--\r\n", &d),
            ("signed-passthrough-content", b"From: a@x\r\nContent-Type: multipart/signed; boundary=B\r\n\r\n--B\r\nContent-Type: multipart/mixed; boundary=C\r\n\r\n--C\r\nContent-Type: text/plain\r\n\r\nhi\r\n--C\r\nContent-Type: application/octet-stream; name=evil.exe\r\n\r\nMZ\r\n--C--\r\n--B\r\nContent-Type: application/pgp-signature\r\n\r\nx\r\n--B--\r\n", &sp),
            ("uuencode-nonmime", b"From: a@x\r\nSubject: s\r\n\r\nsee attached\r\n\r\nbegin 644 evil.exe\r\n#35H*\r\n`\r\nend\r\n", &d),
            ("dup-ct-first-text", b"From: a@x\r\nContent-Type: text/plain\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: application/octet-stream; name=evil.exe\r\n\r\nMZ\r\n--B--\r\n", &d),
            ("dup-boundary-param", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=A; boundary=B\r\n\r\n--A\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: application/octet-stream; name=evil.exe\r\n\r\nMZ\r\n--A--\r\n", &d),
            ("ct-ws-case", b"From: a@x\r\nCONTENT-TYPE :  MultiPart/Mixed ;\r\n Boundary = \"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: application/octet-stream; name=evil.exe\r\n\r\nMZ\r\n--B--\r\n", &d),
            ("cr-only", b"From: a@x\rContent-Type: multipart/mixed; boundary=B\r\r--B\rContent-Type: text/plain\r\rhi\r--B\rContent-Type: application/octet-stream; name=evil.exe\r\rMZ\r--B--\r", &d),
            ("inline-svg-name-png", b"From: a@x\r\nContent-Type: multipart/related; boundary=B\r\n\r\n--B\r\nContent-Type: text/html\r\n\r\n<img src=cid:x>\r\n--B\r\nContent-Type: image/png; name=evil.png\r\nContent-ID: <x>\r\nContent-Disposition: inline; filename=evil.exe\r\n\r\nMZ\r\n--B--\r\n", &d),
            ("inline-image-nameless-octet", b"From: a@x\r\nContent-Type: multipart/related; boundary=B\r\n\r\n--B\r\nContent-Type: text/html\r\n\r\n<img src=cid:x>\r\n--B\r\nContent-Type: image/png\r\nContent-ID: <x>\r\nContent-Description: evil\r\n\r\nMZ\r\n--B--\r\n", &d),
            ("disp-attachment-case", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: text/x-vbscript\r\nContent-Disposition: ATTACHMENT\r\n\r\nevil\r\n--B--\r\n", &d),
            ("filename-star", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: text/plain\r\nContent-Disposition: inline; filename*=UTF-8''evil.exe\r\n\r\nevil\r\n--B--\r\n", &d),
            ("filename-cont", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: text/plain\r\nContent-Disposition: inline; filename*0=\"ev\"; filename*1=\"il.exe\"\r\n\r\nevil\r\n--B--\r\n", &d),
            ("ct-name-star-only", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: text/plain; name*=UTF-8''evil.exe\r\n\r\nevil\r\n--B--\r\n", &d),
            ("message-news", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: message/news\r\n\r\nContent-Type: application/octet-stream; name=evil.exe\r\n\r\nMZ\r\n--B--\r\n", &d),
            ("dup-ct-conflict-leaf", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: text/plain\r\nContent-Type: application/x-msdownload; name=evil.exe\r\n\r\nMZ\r\n--B--\r\n", &d),
            ("dup-cd-conflict-leaf", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: text/plain\r\nContent-Disposition: inline\r\nContent-Disposition: attachment; filename=evil.exe\r\n\r\nMZ\r\n--B--\r\n", &d),
            ("ct-in-folded-name", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: text/plain\r\nContent-Disposition: inline; filename=\"=?utf-8?q?evil=2Eexe?=\"\r\n\r\nMZ\r\n--B--\r\n", &d),
            ("bad-ct-syntax", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: application/octet-stream name=evil.exe\r\n\r\nMZ\r\n--B--\r\n", &d),
            ("text-ct-garbage", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: text\r\nContent-Disposition: inline\r\n\r\nMZ evil\r\n--B--\r\n", &d),
        ];
        for (label, raw, o) in cases {
            let (names, skipped, out) = run(raw, o);
            assert!(!names.is_empty(), "{label}: nothing extracted");
            assert_eq!(skipped, "", "{label}: passed through");
            assert!(
                !out.contains("evil") && !out.contains("MZ"),
                "{label}: payload left in the relayed message:\n{out}"
            );
        }
    }

    #[test]
    fn opaque_encryption_requires_real_ciphertext() {
        let d = Options::default();
        // Well-formed PGP/MIME and S/MIME enveloped-data pass through.
        let pgp = b"From: a@x\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=E\r\n\r\n--E\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--E\r\nContent-Type: application/octet-stream; name=encrypted.asc\r\n\r\n-----BEGIN PGP MESSAGE-----\r\nhQEMA\r\n-----END PGP MESSAGE-----\r\n--E--\r\n";
        let (n, s, out) = run(pgp, &d);
        assert!(n.is_empty() && s == "encrypted");
        assert_eq!(out.as_bytes(), pgp);
        let smime = b"From: a@x\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m\r\nContent-Transfer-Encoding: base64\r\n\r\nMIAGCSqGSIb3DQEHA6CAMIACAQAx\r\n";
        assert_eq!(run(smime, &d).1, "encrypted");
        // Not a DER SEQUENCE, or the wrong name: inspected normally.
        let fake = b"From: a@x\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data\r\n\r\nMZ\r\n";
        assert_eq!(run(fake, &d).0.len(), 1);
        let named = b"From: a@x\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=report.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nMIAGCSqGSIb3DQEHA6CAMIACAQAx\r\n";
        assert_eq!(run(named, &d).0, vec!["report.pdf".to_string()]);
        // PGP without the armored message or the control part.
        let pgp_bad = String::from_utf8_lossy(pgp).replace("-----BEGIN PGP MESSAGE-----", "MZ");
        assert_eq!(run(pgp_bad.as_bytes(), &d).1, "");
        let pgp_noproto =
            String::from_utf8_lossy(pgp).replace("protocol=\"application/pgp-encrypted\"; ", "");
        assert_eq!(run(pgp_noproto.as_bytes(), &d).1, "");
    }

    #[test]
    fn signature_part_kept_only_when_plausible() {
        let mk = |sig_ct: &str, body: &str| {
            format!("From: a@x\r\nContent-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=S\r\n\r\n--S\r\nContent-Type: text/plain\r\n\r\nhi\r\n--S\r\nContent-Type: {sig_ct}\r\n\r\n{body}\r\n--S--\r\n")
        };
        let d = Options::default();
        let pgp_sig = "-----BEGIN PGP SIGNATURE-----\r\nSIG\r\n-----END PGP SIGNATURE-----";
        let der_sig = "MIAGCSqGSIb3DQEHAqCAMIACAQEx";
        for (ok, body) in [
            ("application/pgp-signature", pgp_sig),
            ("application/pgp-signature; name=signature.asc", pgp_sig),
            (
                "application/pkcs7-signature; name=smime.p7s\r\nContent-Transfer-Encoding: base64",
                der_sig,
            ),
            (
                "application/pkcs7-signature; name=\"mail.sig\"\r\nContent-Transfer-Encoding: base64",
                der_sig,
            ),
        ] {
            let raw = mk(ok, body);
            let (n, _, out) = run(raw.as_bytes(), &d);
            assert!(n.is_empty(), "{ok}");
            assert_eq!(out, raw, "{ok}: untouched");
        }
        for bad in [
            "application/pgp-signature; name=readme.txt",
            "application/pkcs7-signature; name=evil.exe",
            "application/octet-stream",
        ] {
            let (n, _, out) = run(mk(bad, "SIG").as_bytes(), &d);
            assert_eq!(n.len(), 1, "{bad}");
            assert!(
                !out.contains("SIG") && !out.contains("multipart/signed"),
                "{bad}"
            );
        }
        // Oversized signature.
        let big = "A".repeat(70 * 1024);
        assert_eq!(
            run(mk("application/pgp-signature", &big).as_bytes(), &d)
                .0
                .len(),
            1
        );
    }

    #[test]
    fn plain_messages_default_to_text_plain() {
        let plain = b"From: a@x\r\nSubject: s\r\n\r\nhello\r\n";
        let root = parse(plain);
        assert_eq!(root.media_type().0, "text/plain");
        assert_eq!(root.media_type().1["charset"], "us-ascii");
        let (n, _, out) = run(plain, &Options::default());
        assert!(n.is_empty());
        assert_eq!(out.as_bytes(), plain);
        // A child without Content-Type is text/plain too (body kept)...
        let mixed = b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n\r\nbody text\r\n--B--\r\n";
        let (n, _, out) = run(mixed, &Options::default());
        assert!(n.is_empty());
        assert_eq!(out.as_bytes(), mixed);
        // ...except in a multipart/digest, where it is message/rfc822.
        let digest = parse(b"Content-Type: multipart/digest; boundary=B\r\n\r\n--B\r\n\r\nSubject: x\r\n\r\ny\r\n--B--\r\n");
        assert_eq!(digest.children()[0].media_type().0, "message/rfc822");
        // uuencoded files in plain text become attachments.
        for raw in [
            &b"From: a@x\r\nSubject: s\r\n\r\nsee\r\n\r\nbegin 644 evil.exe\r\n#35H*\r\n`\r\nend\r\n"[..],
            b"From: a@x\r\nMIME-Version: 1.0\r\n\r\nbegin 644 evil.exe\r\n#35H*\r\n`\r\nend\r\n",
        ] {
            let mut root = parse(raw);
            let r = extract(&mut root, &Options::default()).unwrap();
            assert_eq!(r.attachments.len(), 1);
            assert_eq!(r.attachments[0].filename, "evil.exe");
            assert_eq!(r.attachments[0].data, b"MZ\n");
            assert!(!String::from_utf8_lossy(&root.to_bytes()).contains("begin 644"));
        }
    }

    #[test]
    fn part_and_field_caps() {
        let mut e = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n".to_vec();
        while e.len() < 2 << 20 {
            e.extend_from_slice(b"--B\r\n");
        }
        let p = parse(&e);
        assert!(p.children().len() <= MAX_PARTS + 1);
        assert_eq!(p.children().last().unwrap().opaque(), Some(Opaque::Parts));
        assert_eq!(p.to_bytes(), e, "byte-exact with the opaque remainder");
        let mut q = p.clone();
        let r = extract(&mut q, &Options::default()).unwrap();
        assert!(r
            .attachments
            .iter()
            .any(|a| a.filename == "uninspectable.eml"));
        // Nested: the budget is shared across the tree.
        let mut inner = b"Content-Type: multipart/mixed; boundary=C\r\n\r\n".to_vec();
        for _ in 0..1500 {
            inner.extend_from_slice(b"--C\r\n\r\nx\r\n");
        }
        inner.extend_from_slice(b"--C--");
        let mut outer = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n".to_vec();
        for _ in 0..3 {
            outer.extend_from_slice(b"--B\r\n");
            outer.extend_from_slice(&inner);
            outer.extend_from_slice(b"\r\n");
        }
        outer.extend_from_slice(b"--B--\r\n");
        let p = parse(&outer);
        fn count(p: &Part) -> usize {
            1 + p.children().iter().map(count).sum::<usize>()
        }
        assert!(count(&p) <= 2 * MAX_PARTS + 2);
        assert_eq!(p.to_bytes(), outer);
        // Content-* fields hidden beyond the header-field cap: opaque.
        let mut h = Vec::new();
        for _ in 0..MAX_FIELDS + 5 {
            h.extend_from_slice(b"X-A: b\r\n");
        }
        let mut hidden = h.clone();
        hidden.extend_from_slice(
            b"Content-Type: application/x-msdownload; name=evil.exe\r\n\r\nMZ\r\n",
        );
        let p = parse(&hidden);
        assert_eq!(p.opaque(), Some(Opaque::Headers));
        assert_eq!(p.to_bytes(), hidden);
        let (n, _, out) = run(&hidden, &Options::default());
        assert_eq!(n.len(), 1);
        assert!(!out.contains("evil"));
        let mut benign = h;
        benign.extend_from_slice(b"\r\nhello\r\n");
        assert_eq!(parse(&benign).opaque(), None);
        assert_eq!(parse(&benign).to_bytes(), benign);
    }

    #[test]
    fn message_subtypes() {
        let mk = |mt: &str| {
            format!("From: a@x\r\nContent-Type: multipart/report; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: {mt}\r\n\r\nX: y\r\n--B--\r\n")
        };
        for keep in [
            "message/delivery-status",
            "message/disposition-notification",
            "message/rfc822-headers",
        ] {
            assert!(
                run(mk(keep).as_bytes(), &Options::default()).0.is_empty(),
                "{keep}"
            );
        }
        for ext in ["message/news", "message/global", "message/x-custom"] {
            assert_eq!(
                run(mk(ext).as_bytes(), &Options::default()).0.len(),
                1,
                "{ext}"
            );
        }
    }

    #[test]
    fn encoded_word_names_decode_in_linear_time() {
        for n in [35_000usize, 140_000] {
            let raw = format!(
                "Content-Type: application/x; name=\"{}.exe\"\r\n\r\nx",
                "=?utf-8?q?a?= ".repeat(n)
            );
            let p = parse(raw.as_bytes());
            let t = std::time::Instant::now();
            let f = p.filename();
            assert!(f.ends_with("a .exe") && f.len() < 9000, "{f}");
            let _ = p.filename(); // cached
            assert!(
                t.elapsed() < std::time::Duration::from_secs(2),
                "{:?}",
                t.elapsed()
            );
        }
    }

    const SEEDS: &[&[u8]] = &[
        b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\npre\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B \r\nContent-Type: multipart/alternative; boundary=\"C\"\r\n\r\n--C\r\nContent-Type: text/html\r\n\r\n<p>x</p>\r\n--C--\r\n--B\r\nContent-Type: application/pdf; name=a.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0x\r\n--B--\r\nepi\r\n",
        b"From: a@x\r\nContent-Type: multipart/signed; boundary=S; protocol=x\r\n\r\n--S\r\nContent-Type: multipart/mixed; boundary=M\r\n\r\n--M\r\nContent-Type: text/plain\r\n\r\nt\r\n--M\r\nContent-Type: image/png\r\nContent-ID: <a>\r\n\r\nPNG\r\n--M--\r\n--S\r\nContent-Type: application/pkcs7-signature\r\n\r\nsig\r\n--S--\r\n",
        b"Subject: x\r\nContent-Type: message/rfc822\r\n\r\nContent-Type: multipart/mixed; boundary=Q\r\n\r\n--Q\r\n\r\nbody\r\n--Q\r\nContent-Disposition: attachment; filename*=UTF-8''%E2%80%AEexe.pdf\r\n\r\nx\r\n--Q",
        b"Content-Type: multipart/encrypted; boundary=E\r\n\r\n--E\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--E\r\nContent-Type: application/octet-stream\r\n\r\n-----BEGIN PGP\r\n--E--\r\n",
        b"From: a@x\r\nSubject: =?utf-8?b?7ZWc6riA?=\r\n\r\ntext\r\nbegin 644 a.exe\r\n#35H*\r\n`\r\nend\r\n",
        b"Content-Type: multipart/digest; boundary=D\r\n\r\n--D\r\n\r\nSubject: a\r\n\r\nb\r\n--D\r\nContent-Type: text/plain\r\nContent-Type: text/html\r\n\r\nc\r\n--D--\r\n",
    ];
    const TOKENS: &[&[u8]] = &[
        b"\r\n",
        b"\r",
        b"\n",
        b"--",
        b"--B",
        b"--B--",
        b"--C",
        b"--M--",
        b"--S",
        b"--Q",
        b"--D",
        b"\r\n\r\n",
        b":",
        b";",
        b"\"",
        b"=",
        b" ",
        b"\t",
        b"Content-Type: multipart/mixed; boundary=B\r\n",
        b"Content-Type: text/plain; charset=utf-16\r\n",
        b"Content-Transfer-Encoding: base64\r\n",
        b"Content-Transfer-Encoding: quoted-printable\r\n",
        b"Content-Transfer-Encoding: x-uuencode\r\n",
        b"=?utf-8?b?",
        b"=?euc-kr?q?",
        b"?=",
        b"=\r\n",
        b"\xff",
        b"\xe2\x80",
        b"filename*0*=",
        b"name=\"",
        b"Content-Disposition: attachment\r\n",
        b"multipart/",
        b"message/rfc822",
        b"</body>",
        b"&#",
        b"<",
        b"begin 644 x\r\n",
        b"end\r\n",
        b"<span hidden>",
    ];

    fn mutate(r: &mut rand::rngs::StdRng, v: &mut Vec<u8>) {
        use rand::Rng;
        for _ in 0..r.gen_range(1..8) {
            let pos = if v.is_empty() {
                0
            } else {
                r.gen_range(0..=v.len())
            };
            match r.gen_range(0..5) {
                0 if !v.is_empty() && pos < v.len() => {
                    v.remove(pos);
                }
                1 => {
                    let t = TOKENS[r.gen_range(0..TOKENS.len())];
                    v.splice(pos..pos, t.iter().copied());
                }
                2 if pos < v.len() => v[pos] = r.gen(),
                3 if !v.is_empty() => {
                    let a = r.gen_range(0..v.len());
                    let b = (a + r.gen_range(0..40)).min(v.len());
                    let s: Vec<u8> = v[a..b].to_vec();
                    v.splice(pos..pos, s);
                }
                _ => {
                    if pos < v.len() {
                        v.truncate(pos.max(1));
                    }
                }
            }
        }
    }

    /// Every line break is CRLF (no bare CR or LF).
    fn strict_crlf(v: &[u8]) -> bool {
        v.iter().enumerate().all(|(i, &b)| match b {
            b'\n' => i > 0 && v[i - 1] == b'\r',
            b'\r' => v.get(i + 1) == Some(&b'\n'),
            _ => true,
        })
    }

    /// Random and mutated messages: no panics anywhere in parse / extract /
    /// banner / DLP, and CRLF input round-trips byte for byte.
    #[test]
    fn fuzz_no_panics_and_exact_round_trip() {
        use rand::{Rng, SeedableRng};
        let iters: usize = std::env::var("R2_ITERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3000);
        let mut r = rand::rngs::StdRng::seed_from_u64(42);
        let s = crate::dlp::Scanner::new(Default::default()).unwrap();
        for i in 0..iters {
            let mut v: Vec<u8> = if i % 10 == 0 {
                (0..r.gen_range(0..200)).map(|_| r.gen()).collect()
            } else {
                SEEDS[r.gen_range(0..SEEDS.len())].to_vec()
            };
            mutate(&mut r, &mut v);
            let p = parse(&v);
            if strict_crlf(&v) {
                assert_eq!(
                    p.to_bytes(),
                    v,
                    "round trip of {:?}",
                    String::from_utf8_lossy(&v)
                );
            }
            for o in [
                Options::default(),
                Options {
                    keep_inline_images: true,
                    signed_passthrough: true,
                    ..Default::default()
                },
            ] {
                let mut q = p.clone();
                let _ = extract_with(&mut q, &o, &exe);
                insert_banner(
                    &mut q,
                    &Banner {
                        text: "t".into(),
                        html: "<b>h</b>".into(),
                    },
                );
                let out = q.to_bytes();
                if strict_crlf(&v) {
                    assert_eq!(parse(&out).to_bytes(), out, "re-parse of rewritten output");
                }
            }
            let _ = crate::mimeproc::parse(&v);
            let _ = s.scan_message(&v);
        }
    }

    fn timed(label: &str, raw: &[u8]) {
        let st = std::time::Instant::now();
        let mut p = parse(raw);
        let _ = extract_with(
            &mut p,
            &Options {
                keep_inline_images: true,
                ..Default::default()
            },
            &|_| false,
        );
        insert_banner(
            &mut p,
            &Banner {
                text: "t".into(),
                html: "h".into(),
            },
        );
        let _ = p.to_bytes();
        let mime = st.elapsed();
        let s = crate::dlp::Scanner::new(Default::default()).unwrap();
        let st = std::time::Instant::now();
        let _ = s.scan_message(raw);
        let dlp = st.elapsed();
        eprintln!(
            "R2PERF {label} ({} KB): mime {mime:?} dlp {dlp:?}",
            raw.len() / 1024
        );
        let lim = std::time::Duration::from_secs(2);
        assert!(
            mime < lim && dlp < lim,
            "{label}: mime {mime:?} dlp {dlp:?}"
        );
    }

    /// DoS bounds (release builds only: debug timings are meaningless).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "timing test: run with --release")]
    fn dos_inputs_are_bounded() {
        let mut e = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n".to_vec();
        while e.len() < 20 << 20 {
            e.extend_from_slice(b"--B\r\n");
        }
        timed("20MB of delimiters", &e);
        let mut b4b = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n".to_vec();
        for _ in 0..100_000 {
            b4b.extend_from_slice(b"--B\r\n\r\nx\r\n");
        }
        timed("100k text parts", &b4b);
        let mut b9 = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Disposition: attachment; filename=\"".to_vec();
        b9.extend(b"=?utf-8?q?a?= ".repeat(150_000));
        b9.extend_from_slice(b".exe\"\r\n\r\nx\r\n--B--\r\n");
        timed("2MB encoded-words filename", &b9);
        let mut subj = b"Subject: ".to_vec();
        for _ in 0..150_000 {
            subj.extend_from_slice(b"=?utf-8?q?a?=\r\n ");
        }
        subj.extend_from_slice(b"x\r\nContent-Type: text/plain\r\n\r\nhi\r\n");
        timed("2MB folded encoded-word subject", &subj);
        let mut b6 = b"Content-Type: multipart/mixed; boundary=B".to_vec();
        for i in 0..50_000 {
            b6.extend_from_slice(format!("; p{i}=v").as_bytes());
        }
        b6.extend_from_slice(b"\r\n\r\n--B\r\n\r\nx\r\n--B--\r\n");
        timed("CT 50k params", &b6);
        let mut b7 = Vec::new();
        for _ in 0..100_000 {
            b7.extend_from_slice(b"X-A: b\r\n");
        }
        b7.extend_from_slice(b"Content-Type: text/plain\r\n\r\nx\r\n");
        timed("100k headers", &b7);
        let mut b8 = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Disposition: attachment; filename=\"".to_vec();
        b8.extend(std::iter::repeat(b'a').take(1 << 20));
        b8.extend_from_slice(b".exe\"\r\n\r\nx\r\n--B--\r\n");
        timed("1MB filename", &b8);
        let mut d = Vec::new();
        for i in 0..31 {
            d.extend_from_slice(
                format!("Content-Type: multipart/mixed; boundary=b{i}\r\n\r\n--b{i}\r\n")
                    .as_bytes(),
            );
        }
        d.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
        while d.len() < 20 << 20 {
            d.extend_from_slice(b"\r\n");
        }
        timed("31 levels 20MB of CRLF", &d);
        let mut f = b"Content-Type: text/plain\r\n\r\n".to_vec();
        while f.len() < 10 << 20 {
            f.extend_from_slice(b"1 ");
        }
        timed("10MB '1 ' digits", &f);
        let mut g = b"Content-Type: text/plain\r\n\r\n".to_vec();
        let line = b"lorem ipsum 010-1234-5678 dolor 1234567890123 sit\r\n";
        while g.len() < 20 << 20 {
            g.extend_from_slice(line);
        }
        timed("20MB text", &g);
        let mut h = b"Content-Type: text/html\r\n\r\n".to_vec();
        while h.len() < 10 << 20 {
            h.extend_from_slice(b"<span hidden><a href=\"x\">1234567890-</a>&#49;");
        }
        timed("10MB nested hidden html", &h);
    }
}

/// Round-3 review regressions.
#[cfg(test)]
mod r3_tests {
    use super::*;

    fn exe(n: &str) -> bool {
        let n = n.to_ascii_lowercase();
        n.ends_with(".exe") || n.ends_with(".bat")
    }

    fn run(raw: &[u8], o: &Options) -> (Vec<String>, String, String) {
        let mut root = parse(raw);
        let r = extract_with(&mut root, o, &exe).unwrap();
        (
            r.attachments.iter().map(|a| a.filename.clone()).collect(),
            r.skipped,
            String::from_utf8_lossy(&root.to_bytes()).into_owned(),
        )
    }

    #[test]
    fn escapes_are_extracted() {
        let o = Options {
            keep_inline_images: true,
            ..Default::default()
        };
        let sp = Options {
            keep_inline_images: true,
            signed_passthrough: true,
            ..Default::default()
        };
        let cases: &[(&str, &[u8], &Options)] = &[
            ("boundary-case", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=ab\r\nContent-Type: multipart/mixed; boundary=AB\r\n\r\n--ab\r\nContent-Type: text/plain\r\n\r\nhi\r\n--AB\r\nContent-Type: application/octet-stream; name=evil.exe\r\n\r\nMZ\r\n--AB--\r\n--ab--\r\n", &o),
            ("boundary-ws", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=\"a b\"\r\nContent-Type: multipart/mixed; boundary=ab\r\n\r\n--a b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--ab\r\nContent-Type: application/octet-stream; name=evil.exe\r\n\r\nMZ\r\n--ab--\r\n--a b--\r\n", &o),
            ("sig-ct-name-mismatch", b"From: a@x\r\nContent-Type: multipart/mixed; boundary=A\r\n\r\n--A\r\nContent-Type: multipart/signed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B\r\nContent-Type: application/pgp-signature; name=evil.exe\r\nContent-Disposition: attachment; filename=signature.asc\r\n\r\nMZ\r\n--B--\r\n--A--\r\n", &o),
            ("sig-ct-name-mismatch-armored", b"From: a@x\r\nContent-Type: multipart/signed; boundary=B; protocol=\"application/pgp-signature\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B\r\nContent-Type: application/pgp-signature; name=evil.exe\r\nContent-Disposition: attachment; filename=signature.asc\r\n\r\n-----BEGIN PGP SIGNATURE-----\r\nMZ\r\n--B--\r\n", &sp),
            ("pgp-ct-name-mismatch", b"From: a@x\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=B\r\n\r\n--B\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--B\r\nContent-Type: application/octet-stream; name=evil.bat\r\nContent-Disposition: attachment; filename=msg.asc\r\n\r\n-----BEGIN PGP MESSAGE-----\r\ncalc.exe\r\n--B--\r\n", &o),
            ("smime-ct-name-mismatch", b"From: a@x\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=evil.exe\r\nContent-Disposition: attachment; filename=smime.p7m\r\nContent-Transfer-Encoding: base64\r\n\r\nME1a\r\n", &o),
            ("inline-image-ct-name", b"From: a@x\r\nContent-Type: multipart/related; boundary=B\r\n\r\n--B\r\nContent-Type: text/html\r\n\r\n<img src=cid:x>\r\n--B\r\nContent-Type: image/png; name=evil.exe\r\nContent-ID: <x>\r\nContent-Disposition: inline; filename=logo.png\r\n\r\n\x89PNG MZ\r\n--B--\r\n", &o),
            ("uu-5digit-mode", b"From: a@x\r\nSubject: s\r\n\r\nsee\r\nbegin 100644 evil.exe\r\n#35H*\r\n`\r\nend\r\n", &o),
            ("uu-in-qp", b"From: a@x\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nsee\r\nbegin=20644 evil.exe\r\n#35H*\r\n`\r\nend\r\n", &o),
            ("uu-leading-space", b"From: a@x\r\nSubject: s\r\n\r\nsee\r\n begin 644 evil.exe\r\n#35H*\r\n`\r\nend\r\n", &o),
            ("utf7-name", b"From: a@x\r\nContent-Type: multipart/related; boundary=B\r\n\r\n--B\r\nContent-Type: text/html\r\n\r\n<img src=cid:x>\r\n--B\r\nContent-Type: image/png; name=\"=?utf-7?Q?a+AC4-exe?=\"\r\nContent-ID: <x>\r\n\r\n\x89PNG MZ\r\n--B--\r\n", &o),
            ("signed-uuencode", b"From: a@x\r\nContent-Type: multipart/signed; boundary=B; protocol=\"application/pgp-signature\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nsee\r\nbegin 644 evil.exe\r\n#35H*\r\n`\r\nend\r\n--B\r\nContent-Type: application/pgp-signature\r\n\r\n-----BEGIN PGP SIGNATURE-----\r\n--B--\r\n", &sp),
            ("report-headers-with-body", b"From: a@x\r\nContent-Type: multipart/report; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nbounce\r\n--B\r\nContent-Type: message/rfc822-headers\r\n\r\nContent-Type: multipart/mixed; boundary=C\r\n\r\n--C\r\nContent-Type: application/octet-stream; name=evil.exe\r\nContent-Transfer-Encoding: base64\r\n\r\nTVo=\r\n--C--\r\n--B--\r\n", &o),
        ];
        for (label, raw, o) in cases {
            let (names, skipped, out) = run(raw, o);
            assert!(!names.is_empty(), "{label}: nothing extracted");
            assert_eq!(skipped, "", "{label}: passed through");
            for leak in ["evil", "MZ", "TVo=", "#35H*"] {
                assert!(!out.contains(leak), "{label}: {leak} left in:\n{out}");
            }
        }
    }

    #[test]
    fn utf7_encoded_words_decode() {
        assert_eq!(
            crate::mimeproc::decode_header("=?utf-7?Q?a+AC4-exe?="),
            "a.exe"
        );
        assert_eq!(
            crate::mimeproc::decode_utf7(b"Hi Mom -+Jjo--!"),
            "Hi Mom -\u{263A}-!"
        );
        assert_eq!(crate::mimeproc::decode_utf7(b"1 +- 1"), "1 + 1");
        assert_eq!(
            crate::mimeproc::decode_utf7(b"+1VyuAA-"),
            "\u{D55C}\u{AE00}"
        );
        // Malformed runs never panic.
        let _ = crate::mimeproc::decode_utf7(b"+////////+\xff+2D3cAA");
    }

    #[test]
    fn short_mode_with_short_data_line_still_uuencode() {
        let raw = b"From: a@b.c\r\nContent-Type: text/plain\r\n\r\nhi\r\nbegin 7 evil.exe\r\nM3$%&\r\n`\r\nend\r\n";
        let mut p = parse(raw);
        let r = extract(&mut p, &Options::default()).unwrap();
        assert_eq!(r.attachments.len(), 1);
    }

    #[test]
    fn begin_in_prose_is_not_uuencode() {
        let raw = b"From: a@b.c\r\nContent-Type: text/plain\r\n\r\nbegin 1 month later we ship.\r\nThanks, Kim\r\n";
        let mut p = parse(raw);
        let r = extract(&mut p, &Options::default()).unwrap();
        assert!(r.attachments.is_empty());
        assert_eq!(p.to_bytes(), raw);
    }

    #[test]
    fn short_mode_uuencode_and_yenc_binhex_extracted() {
        let opts = Options::default();
        for body in [
            "hi\r\nbegin 7 evil.exe\r\n#35H*\r\n`\r\nend\r\n",
            "hi\r\n=ybegin line=128 size=2 name=evil.exe\r\nxx\r\n=yend size=2\r\n",
            "(This file must be converted with BinHex 4.0)\r\n:abc:\r\n",
        ] {
            let raw = format!("From: a@b.c\r\nContent-Type: text/plain\r\n\r\n{body}");
            let mut p = parse(raw.as_bytes());
            let r = extract(&mut p, &opts).unwrap();
            assert_eq!(r.attachments.len(), 1, "{body:?}");
            assert!(
                !String::from_utf8_lossy(&p.to_bytes()).contains("evil.exe")
                    || body.starts_with("(This")
            );
        }
    }

    #[test]
    fn rfc2231_plain_and_starred_param_is_ambiguous() {
        let img = b"Content-Type: image/png; name=logo.png; name*=utf-8''evil.exe\r\nContent-ID: <x>\r\n\r\niVBORw0K\r\n";
        assert_eq!(parse(img).opaque(), Some(Opaque::Ambiguous));
        let cd = b"Content-Type: application/pgp-signature\r\nContent-Disposition: inline; filename=s.asc; filename*0*=utf-8''run.bat\r\n\r\nx\r\n";
        assert_eq!(parse(cd).opaque(), Some(Opaque::Ambiguous));
        // The same name in both forms (non-ASCII names) is fine.
        let same = b"Content-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"=?UTF-8?B?67O06rOg7IScLnBkZg==?=\"; filename*=UTF-8''%EB%B3%B4%EA%B3%A0%EC%84%9C.pdf\r\n\r\nx\r\n";
        assert_eq!(parse(same).opaque(), None);
        // Continuations alone are fine.
        let ok = b"Content-Type: application/pdf; name*0=a; name*1=b.pdf\r\n\r\nx\r\n";
        assert_eq!(parse(ok).opaque(), None);
    }

    #[test]
    fn duplicate_content_headers_compare_raw_values() {
        // Identical duplicates (modulo surrounding whitespace) stay parsed.
        let same = b"From: a@x\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Type:  text/plain; charset=utf-8 \r\n\r\nhi\r\n";
        assert!(parse(same).opaque().is_none());
        for v in [
            "text/plain; charset=UTF-8",
            "text/plain; charset=\"utf-8\"",
            "text/plain;charset=utf-8",
            "TEXT/plain; charset=utf-8",
        ] {
            let raw = format!("From: a@x\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Type: {v}\r\n\r\nhi\r\n");
            assert_eq!(
                parse(raw.as_bytes()).opaque(),
                Some(Opaque::Ambiguous),
                "{v}"
            );
        }
        let cd = b"From: a@x\r\nContent-Disposition: attachment; filename=a.txt\r\nContent-Disposition: attachment; filename=A.txt\r\n\r\nhi\r\n";
        assert_eq!(parse(cd).opaque(), Some(Opaque::Ambiguous));
        // Duplicate parameter names are still caught case-insensitively.
        let dp =
            b"From: a@x\r\nContent-Type: multipart/mixed; boundary=A; BOUNDARY=B\r\n\r\n--A--\r\n";
        assert_eq!(parse(dp).opaque(), Some(Opaque::Ambiguous));
    }

    #[test]
    fn plausible_signed_and_encrypted_still_pass() {
        let sp = Options {
            signed_passthrough: true,
            ..Default::default()
        };
        let pgp = b"From: a@x\r\nContent-Type: multipart/signed; boundary=B; protocol=\"application/pgp-signature\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B\r\nContent-Type: application/pgp-signature; name=signature.asc\r\nContent-Disposition: attachment; filename=signature.asc\r\n\r\n-----BEGIN PGP SIGNATURE-----\r\niQEz\r\n-----END PGP SIGNATURE-----\r\n--B--\r\n";
        let (n, s, out) = run(pgp, &sp);
        assert!(n.is_empty() && s == "signed");
        assert_eq!(out.as_bytes(), pgp);
        let smime = b"From: a@x\r\nContent-Type: multipart/signed; boundary=B; protocol=\"application/pkcs7-signature\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B\r\nContent-Type: application/pkcs7-signature; name=smime.p7s\r\nContent-Disposition: attachment; filename=smime.p7s\r\nContent-Transfer-Encoding: base64\r\n\r\nMIAGCSqGSIb3DQEHAqCAMIACAQEx\r\n--B--\r\n";
        assert_eq!(run(smime, &sp).1, "signed");
        // A text body with a harmless uuencoded file still passes.
        let ok_uu = String::from_utf8_lossy(pgp).replace(
            "hello\r\n",
            "see\r\nbegin 644 notes.txt\r\n#35H*\r\n`\r\nend\r\n",
        );
        assert_eq!(run(ok_uu.as_bytes(), &sp).1, "signed");
        // A non-armored signature body is not kept.
        let fake = String::from_utf8_lossy(pgp).replace("-----BEGIN PGP SIGNATURE-----", "MZ");
        let (n, s, _) = run(fake.as_bytes(), &sp);
        assert_eq!((n.len(), s.as_str()), (1, ""));
        // S/MIME enveloped-data with both names smime.p7m stays encrypted.
        let env = b"From: a@x\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m\r\nContent-Disposition: attachment; filename=smime.p7m\r\nContent-Transfer-Encoding: base64\r\n\r\nMIAGCSqGSIb3DQEHA6CAMIACAQAx\r\n";
        assert_eq!(run(env, &Options::default()).1, "encrypted");
    }

    #[test]
    fn uuencode_extraction_is_bounded() {
        let raw = format!(
            "From: a@x\r\nSubject: s\r\n\r\n{}",
            "begin 644 a\r\n#35H*\r\nend\r\n".repeat(400_000)
        );
        let mut root = parse(raw.as_bytes());
        let r = extract_with(&mut root, &Options::default(), &|_: &str| false).unwrap();
        assert!(
            r.attachments.len() <= MAX_ATTACHMENTS,
            "{}",
            r.attachments.len()
        );
        let last = r.attachments.last().unwrap();
        assert_eq!(last.filename, OVERFLOW_NAME);
        assert!(last.data.len() > 1_000_000);
        assert!(!String::from_utf8_lossy(&root.to_bytes()).contains("begin 644"));
        // Shared with MIME entities: many parts plus many uuencoded blocks.
        let mut m = String::from("From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n");
        for _ in 0..1500 {
            m.push_str("--B\r\nContent-Type: application/octet-stream; name=a.bin\r\n\r\nx\r\n");
        }
        m.push_str("--B\r\nContent-Type: text/plain\r\n\r\n");
        m.push_str(&"begin 644 b\r\n#35H*\r\nend\r\n".repeat(5000));
        m.push_str("--B--\r\n");
        let mut root = parse(m.as_bytes());
        let r = extract_with(&mut root, &Options::default(), &|_: &str| false).unwrap();
        assert_eq!(r.attachments.len(), MAX_ATTACHMENTS);
        assert_eq!(r.attachments.last().unwrap().filename, OVERFLOW_NAME);
        // The DLP view is bounded too.
        let p = crate::mimeproc::parse(raw.as_bytes()).unwrap();
        assert!(p.attachments.len() <= MAX_ATTACHMENTS + 1);
        assert!(!p.uninspectable.is_empty());
    }
}
