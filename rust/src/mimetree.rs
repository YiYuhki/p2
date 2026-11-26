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
//! Round-trip guarantee: for CRLF input, `parse(x).to_bytes() == x` — header
//! lines without a colon, delimiter transport padding, the preamble's line
//! break, a missing close delimiter and a missing header/body separator are all
//! preserved.

use std::collections::BTreeMap;

use mailparse::{parse_content_disposition, parse_content_type, DispositionType};

/// Maximum multipart nesting the tree descends into. A multipart nested deeper
/// stays an opaque leaf ([`Part::is_truncated`]) and is treated as an
/// uninspectable attachment.
pub const MAX_DEPTH: usize = 32;

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
    /// A multipart left unsplit because the nesting limit was reached.
    truncated: bool,
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
            truncated: false,
        }
    }
}

fn crlf(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + msg.len() / 40);
    let mut prev = 0u8;
    for &b in msg {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.len() > h.len() {
        return None;
    }
    h.windows(n.len()).position(|w| w == n)
}

/// Parses a raw message (bare LFs are normalized to CRLF).
pub fn parse(raw: &[u8]) -> Part {
    parse_part(&crlf(raw), 0)
}

fn parse_part(raw: &[u8], depth: usize) -> Part {
    let (head, body, has_sep): (&[u8], &[u8], bool) = if raw.starts_with(b"\r\n") {
        (&[], &raw[2..], true)
    } else {
        match find(raw, b"\r\n\r\n") {
            Some(i) => (&raw[..i + 2], &raw[i + 4..], true),
            None => (raw, &[], false),
        }
    };
    let mut fields: Vec<Field> = Vec::new();
    let mut start = 0;
    while start < head.len() {
        let end = find(&head[start..], b"\r\n")
            .map(|i| start + i + 2)
            .unwrap_or(head.len());
        let line = &head[start..end];
        if (line[0] == b' ' || line[0] == b'\t') && !fields.is_empty() {
            fields.last_mut().unwrap().raw.extend_from_slice(line);
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
        ..Default::default()
    };
    let (mt, params) = p.media_type();
    if mt.starts_with("multipart/") {
        if let Some(b) = params.get("boundary").filter(|b| !b.is_empty()) {
            if depth >= MAX_DEPTH {
                p.truncated = true;
            } else if let Some(sp) = split_multipart(body, b) {
                p.preamble = sp.preamble.map(|(s, e)| body[s..e].to_vec());
                match sp.epilogue {
                    Some(s) => p.epilogue = body[s..].to_vec(),
                    None => p.open_ended = true,
                }
                p.children = sp
                    .kids
                    .iter()
                    .map(|k| {
                        let mut c = parse_part(&body[k.start..k.end], depth + 1);
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
/// "--boundary", optionally "--", then only transport padding.
fn split_multipart(body: &[u8], boundary: &str) -> Option<Split> {
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

    /// A multipart nested deeper than [`MAX_DEPTH`], left unparsed.
    pub fn is_truncated(&self) -> bool {
        self.truncated
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

    /// Replaces every instance of `name` with a single field appended last.
    pub fn set_header(&mut self, name: &str, value: &str) {
        let n = name.to_ascii_lowercase();
        self.fields.retain(|f| f.name != n);
        self.add_header(name, value);
    }

    pub fn add_header(&mut self, name: &str, value: &str) {
        self.fields.push(Field {
            name: name.to_ascii_lowercase(),
            raw: format!("{name}: {value}\r\n").into_bytes(),
        });
    }

    /// Prepends a header field (used for trace/marker headers on the root).
    pub fn prepend_header(&mut self, name: &str, value: &str) {
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
        self.fields
            .retain(|fl| fl.name.is_empty() || !f(&fl.name, &fl.value()));
    }

    /// Renames every instance of header `from` to `to`, keeping values and
    /// positions.
    pub fn rename_header(&mut self, from: &str, to: &str) {
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
        self.fields.retain(|f| !f.name.starts_with("content-"));
    }

    /// Lowercase media type and its parameters (defaults to text/plain).
    pub fn media_type(&self) -> (String, BTreeMap<String, String>) {
        let ct = parse_content_type(&self.header("content-type").unwrap_or_default());
        let mut params: BTreeMap<String, String> = ct.params.into_iter().collect();
        if self.header("content-type").is_some() {
            params.entry("charset".into()).or_insert(ct.charset);
        }
        (ct.mimetype.to_ascii_lowercase(), params)
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

    /// Decoded (RFC 2231/2047) filename, unsanitized, or "".
    pub fn filename(&self) -> String {
        let (_, dp) = self.disposition();
        let (_, cp) = self.media_type();
        let raw = dp
            .get("filename")
            .or_else(|| cp.get("name"))
            .cloned()
            .unwrap_or_default();
        crate::mimeproc::decode_header(&raw)
    }

    /// Body with the transfer encoding removed. Multipart (and truncated)
    /// entities are returned raw: `mailparse` is never run on them.
    pub fn decode_body(&self) -> Vec<u8> {
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
        if self.truncated || self.is_multipart() || mt.starts_with("multipart/") {
            return None;
        }
        let mut out = Vec::with_capacity(self.body.len() + 128);
        if self.header("content-type").is_some() {
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
        self.truncated = false;
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
        self.truncated = src.truncated;
    }
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

/// True only for content that is genuinely opaque ciphertext: S/MIME
/// enveloped-data / authEnveloped-data, or a well-formed PGP/MIME
/// multipart/encrypted (exactly a control part and an application/octet-stream
/// part). Anything else claiming to be "encrypted" (e.g. pkcs7 signed-data,
/// which carries readable content) is inspected / extracted normally.
pub fn is_opaque_encrypted(p: &Part) -> bool {
    let (mt, params) = p.media_type();
    match mt.as_str() {
        "multipart/encrypted" => {
            p.children.len() == 2
                && p.children.iter().all(|c| !c.is_multipart() && !c.truncated)
                && p.children[1].media_type().0 == "application/octet-stream"
        }
        "application/pkcs7-mime" | "application/x-pkcs7-mime" => {
            !p.is_multipart()
                && params
                    .get("smime-type")
                    .map(|s| {
                        let s = s.to_ascii_lowercase();
                        s == "enveloped-data" || s == "authenveloped-data"
                    })
                    .unwrap_or(false)
        }
        _ => false,
    }
}

/// A multipart/signed with exactly the content part and one signature part.
fn is_well_formed_signed(p: &Part) -> bool {
    p.children.len() == 2 && is_signature_type(&p.children[1].media_type().0)
}

struct Ctx<'a> {
    opts: &'a Options,
    blocked: &'a dyn Fn(&str) -> bool,
    res: ExtractResult,
}

/// Removes attachment parts from `root` in place.
pub fn extract(root: &mut Part, opts: &Options) -> Result<ExtractResult, ExtractError> {
    extract_with(root, opts, &|_| false)
}

/// Like [`extract`]; `blocked(sanitized_name)` reports a blocked file
/// extension, and a part the policy would otherwise keep inline (an inline
/// image) is extracted when its name is blocked.
pub fn extract_with(
    root: &mut Part,
    opts: &Options,
    blocked: &dyn Fn(&str) -> bool,
) -> Result<ExtractResult, ExtractError> {
    let mut ctx = Ctx {
        opts,
        blocked,
        res: ExtractResult::default(),
    };
    if is_opaque_encrypted(root) {
        if opts.encrypted_reject {
            return Err(ExtractError::Encrypted);
        }
        ctx.res.skipped = "encrypted".into();
        return Ok(ctx.res);
    }
    let (mt, _) = root.media_type();
    if mt == "multipart/signed" && opts.signed_passthrough && is_well_formed_signed(root) {
        ctx.res.skipped = "signed".into();
        return Ok(ctx.res);
    }
    if !root.is_multipart() {
        if is_attachment(root, &ctx) {
            ctx.res.attachments.push(extract_leaf(root));
            root.make_multipart_mixed();
        }
        return Ok(ctx.res);
    }
    walk(root, &mut ctx)?;
    if root.is_multipart() && root.children.is_empty() {
        root.make_multipart_mixed();
    }
    Ok(ctx.res)
}

fn walk(p: &mut Part, ctx: &mut Ctx) -> Result<bool, ExtractError> {
    let (mt, _) = p.media_type();
    if mt == "multipart/signed" {
        if p.children.is_empty() {
            return Ok(false);
        }
        let mut kids = std::mem::take(&mut p.children);
        // Keep only the content part and one signature part; every other child
        // (a smuggled third part, or a non-signature second part) is removed.
        let keep_n = if kids.len() >= 2 && is_signature_type(&kids[1].media_type().0) {
            2
        } else {
            1
        };
        let mut changed = false;
        for extra in kids.drain(keep_n..) {
            ctx.res.attachments.push(extract_whole(&extra));
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
        ctx.res.attachments.push(extract_whole(&c));
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
        ctx.res.attachments.push(extract_leaf(&c));
        return Ok((None, true));
    }
    Ok((Some(c), false))
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

fn has_raster_ext(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"]
        .iter()
        .any(|e| n.ends_with(e))
}

fn is_attachment(p: &Part, ctx: &Ctx) -> bool {
    let (mt, _) = p.media_type();
    if p.truncated || mt.starts_with("multipart/") {
        return true; // an unsplit multipart (too deep / no boundary)
    }
    let (disp, _) = p.disposition();
    if disp == "attachment" {
        return true;
    }
    if matches!(
        mt.as_str(),
        "message/rfc822" | "message/global" | "message/partial" | "message/external-body"
    ) {
        return true; // forwarded mails may carry their own attachments
    }
    let name = p.filename();
    if ctx.opts.keep_inline_images && is_raster_image(&mt) && p.header("content-id").is_some() {
        let safe = crate::mimeproc::sanitize_filename(&name);
        if (safe.is_empty() || has_raster_ext(&safe)) && !(ctx.blocked)(&safe) {
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
    let whole = p.truncated || p.is_multipart() || mt.starts_with("multipart/");
    let mut name = p.filename();
    if name.is_empty() {
        name = if mt.starts_with("message/") || whole {
            "forwarded-message.eml".into()
        } else {
            format!("attachment{}", ext_for(&mt))
        };
    }
    let data = if whole { p.to_bytes() } else { p.decode_body() };
    Extracted {
        filename: crate::mimeproc::sanitize_filename(&name),
        content_type: mt,
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
        truncated: root.truncated,
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
        let raw = "From: a@x.com\r\nContent-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=\"S\"\r\n\r\n--S\r\nContent-Type: multipart/mixed; boundary=\"M\"\r\n\r\n--M\r\nContent-Type: text/plain\r\n\r\nbody\r\n--M\r\nContent-Type: application/zip; name=\"z.zip\"\r\nContent-Transfer-Encoding: base64\r\n\r\nUEsDBA==\r\n--M--\r\n--S\r\nContent-Type: application/pgp-signature\r\n\r\nSIG\r\n--S--\r\n";
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
        let raw = b"From: a@x.com\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data\r\n\r\nMIAG\r\n";
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
        let raw = b"From: a@x\r\nContent-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=S\r\n\r\n--S\r\nContent-Type: text/plain\r\n\r\nhi\r\n--S\r\nContent-Type: application/pgp-signature\r\n\r\nSIG\r\n--S\r\nContent-Type: application/x-msdownload; name=\"evil.exe\"\r\nContent-Disposition: attachment; filename=\"evil.exe\"\r\n\r\nMZ\r\n--S--\r\n";
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
        let mk = |ct: &str, cd: &str| {
            format!("From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: {ct}\r\nContent-ID: <x>\r\nContent-Disposition: {cd}\r\n\r\nMZ\r\n--B--\r\n")
        };
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
