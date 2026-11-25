//! Structural MIME rewriting. Port of the Go `internal/mimeproc` Part tree,
//! `Extract` and `InsertBanner`: the message is parsed into a tree of raw-byte
//! parts so that every part the gateway does not touch is re-serialized
//! byte-for-byte, attachments are removed in place (multipart/signed wrappers
//! are unwrapped when their content changes), and the download banner is
//! appended to the first text/plain and text/html bodies (quoted-printable,
//! UTF-8), or added as a new multipart/alternative part when neither exists.

use std::collections::BTreeMap;

use mailparse::{parse_content_disposition, parse_content_type, DispositionType};

const MAX_DEPTH: usize = 32;

#[derive(Clone, Debug)]
struct Field {
    /// Lowercase field name.
    name: String,
    /// Full raw field bytes including folding and the trailing CRLF.
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
#[derive(Clone, Debug, Default)]
pub struct Part {
    fields: Vec<Field>,
    body: Vec<u8>,
    preamble: Vec<u8>,
    children: Vec<Part>,
    /// Bytes after the closing delimiter line's "--" (starts with its CRLF).
    epilogue: Vec<u8>,
    boundary: Option<String>,
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
    let (head, body): (&[u8], &[u8]) = if raw.starts_with(b"\r\n") {
        (&[], &raw[2..])
    } else {
        match find(raw, b"\r\n\r\n") {
            Some(i) => (&raw[..i + 2], &raw[i + 4..]),
            None => (raw, &[]),
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
        } else if let Some(c) = line.iter().position(|&b| b == b':') {
            let mut raw = line.to_vec();
            if !raw.ends_with(b"\r\n") {
                raw.extend_from_slice(b"\r\n");
            }
            fields.push(Field {
                name: String::from_utf8_lossy(&line[..c])
                    .trim()
                    .to_ascii_lowercase(),
                raw,
            });
        }
        start = end;
    }
    let mut p = Part {
        fields,
        body: body.to_vec(),
        ..Default::default()
    };
    let (mt, params) = p.media_type();
    if mt.starts_with("multipart/") && depth < MAX_DEPTH {
        if let Some(b) = params.get("boundary").filter(|b| !b.is_empty()) {
            if let Some((pre, kids, epi)) = split_multipart(body, b) {
                p.preamble = pre;
                p.epilogue = epi;
                p.children = kids.iter().map(|k| parse_part(k, depth + 1)).collect();
                p.boundary = Some(b.clone());
                p.body.clear();
            }
        }
    }
    p
}

/// Splits a multipart body into (preamble, child entities, epilogue). None
/// when the opening delimiter is missing.
type Split = (Vec<u8>, Vec<Vec<u8>>, Vec<u8>);
fn split_multipart(body: &[u8], boundary: &str) -> Option<Split> {
    let delim = format!("--{boundary}");
    let d = delim.as_bytes();
    // Collect line starts.
    let mut kids = Vec::new();
    let mut preamble: Option<Vec<u8>> = None;
    let mut cur_start: Option<usize> = None;
    let mut pos = 0;
    while pos <= body.len() {
        let end = find(&body[pos..], b"\r\n")
            .map(|i| pos + i)
            .unwrap_or(body.len());
        let line = &body[pos..end];
        let is_delim = line.starts_with(d) && {
            let rest = &line[d.len()..];
            let rest = if rest.starts_with(b"--") {
                &rest[2..]
            } else {
                rest
            };
            rest.iter().all(|&b| b == b' ' || b == b'\t')
        };
        if is_delim {
            // Content ends before the CRLF that precedes this delimiter.
            let content_end = pos.saturating_sub(2);
            match cur_start {
                None => preamble = Some(body[..content_end.min(body.len())].to_vec()),
                Some(s) => kids.push(body[s..content_end.max(s)].to_vec()),
            }
            if pos == 0 {
                preamble = Some(Vec::new());
            }
            if line[d.len()..].starts_with(b"--") {
                let epi = body[pos + d.len() + 2..].to_vec();
                return Some((preamble.unwrap_or_default(), kids, epi));
            }
            cur_start = Some((end + 2).min(body.len()));
        }
        if end >= body.len() {
            break;
        }
        pos = end + 2;
    }
    // Missing close delimiter: keep what we have.
    let s = cur_start?;
    kids.push(body[s..].to_vec());
    Some((preamble.unwrap_or_default(), kids, b"\r\n".to_vec()))
}

impl Part {
    /// Serializes the part (headers, blank line, body or children).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 512);
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        for f in &self.fields {
            out.extend_from_slice(&f.raw);
        }
        out.extend_from_slice(b"\r\n");
        match &self.boundary {
            Some(b) => {
                if !self.preamble.is_empty() {
                    out.extend_from_slice(&self.preamble);
                    out.extend_from_slice(b"\r\n");
                }
                for c in &self.children {
                    out.extend_from_slice(format!("--{b}\r\n").as_bytes());
                    c.write(out);
                    out.extend_from_slice(b"\r\n");
                }
                out.extend_from_slice(format!("--{b}--").as_bytes());
                out.extend_from_slice(&self.epilogue);
            }
            None => out.extend_from_slice(&self.body),
        }
    }

    pub fn is_multipart(&self) -> bool {
        self.boundary.is_some()
    }

    /// First value of a header (unfolded), if present.
    pub fn header(&self, name: &str) -> Option<String> {
        let n = name.to_ascii_lowercase();
        self.fields.iter().find(|f| f.name == n).map(Field::value)
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

    fn disposition(&self) -> (String, BTreeMap<String, String>) {
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

    /// Body with the transfer encoding removed.
    pub fn decode_body(&self) -> Vec<u8> {
        match mailparse::parse_mail(&self.leaf_bytes()) {
            Ok(m) => m.get_body_raw().unwrap_or_else(|_| self.body.clone()),
            Err(_) => self.body.clone(),
        }
    }

    /// Body decoded to UTF-8 text using the declared charset.
    fn text(&self) -> Option<String> {
        mailparse::parse_mail(&self.leaf_bytes())
            .ok()?
            .get_body()
            .ok()
    }

    fn leaf_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for f in self
            .fields
            .iter()
            .filter(|f| f.name.starts_with("content-"))
        {
            out.extend_from_slice(&f.raw);
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    fn make_multipart_mixed(&mut self) {
        self.clear_content_headers();
        let b = new_boundary();
        self.set_header(
            "Content-Type",
            &format!("multipart/mixed; boundary=\"{b}\""),
        );
        self.boundary = Some(b);
        self.body.clear();
        self.preamble.clear();
        self.epilogue = b"\r\n".to_vec();
    }

    /// Makes self carry src's content while keeping self's non-content headers.
    fn replace_content(&mut self, src: Part) {
        self.clear_content_headers();
        for f in src
            .fields
            .into_iter()
            .filter(|f| f.name.starts_with("content-"))
        {
            self.fields.push(f);
        }
        self.body = src.body;
        self.children = src.children;
        self.preamble = src.preamble;
        self.epilogue = src.epilogue;
        self.boundary = src.boundary;
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
    /// Leave multipart/signed messages untouched.
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

fn is_encrypted(mt: &str) -> bool {
    matches!(
        mt,
        "multipart/encrypted" | "application/pkcs7-mime" | "application/x-pkcs7-mime"
    )
}

/// Removes attachment parts from `root` in place.
pub fn extract(root: &mut Part, opts: &Options) -> Result<ExtractResult, ExtractError> {
    let mut res = ExtractResult::default();
    let (mt, _) = root.media_type();
    if is_encrypted(&mt) {
        if opts.encrypted_reject {
            return Err(ExtractError::Encrypted);
        }
        res.skipped = "encrypted".into();
        return Ok(res);
    }
    if mt == "multipart/signed" && opts.signed_passthrough {
        res.skipped = "signed".into();
        return Ok(res);
    }
    if !root.is_multipart() {
        if is_attachment(root, opts) {
            res.attachments.push(extract_leaf(root));
            root.make_multipart_mixed();
        }
        return Ok(res);
    }
    walk(root, opts, &mut res);
    if root.is_multipart() && root.children.is_empty() {
        root.make_multipart_mixed();
    }
    Ok(res)
}

fn walk(p: &mut Part, opts: &Options, res: &mut ExtractResult) -> bool {
    let (mt, _) = p.media_type();
    if mt == "multipart/signed" {
        if p.children.is_empty() {
            return false;
        }
        let mut content = Some(p.children[0].clone());
        let mut sub = false;
        if let Some(c) = content.as_mut() {
            if c.is_multipart() {
                sub = walk(c, opts, res);
            } else if is_attachment(c, opts) {
                res.attachments.push(extract_leaf(c));
                content = None;
                sub = true;
            }
        }
        if !sub {
            return false;
        }
        res.signature_removed = true;
        match content {
            Some(c) if !(c.is_multipart() && c.children.is_empty()) => p.replace_content(c),
            _ => p.children.clear(),
        }
        return true;
    }

    let mut changed = false;
    let kids = std::mem::take(&mut p.children);
    for mut c in kids {
        if c.is_multipart() {
            let (cmt, _) = c.media_type();
            if is_encrypted(&cmt) {
                p.children.push(c);
                continue;
            }
            if walk(&mut c, opts, res) {
                changed = true;
            }
            if c.is_multipart() && c.children.is_empty() {
                continue; // drop now-empty container
            }
            p.children.push(c);
            continue;
        }
        if is_attachment(&c, opts) {
            res.attachments.push(extract_leaf(&c));
            changed = true;
            continue;
        }
        p.children.push(c);
    }
    changed
}

fn is_attachment(p: &Part, opts: &Options) -> bool {
    let (mt, _) = p.media_type();
    let (disp, _) = p.disposition();
    if disp == "attachment" {
        return true;
    }
    if mt == "message/rfc822" || mt == "message/global" {
        return true; // forwarded mails may carry their own attachments
    }
    if matches!(
        mt.as_str(),
        "application/pgp-signature"
            | "application/pkcs7-signature"
            | "application/x-pkcs7-signature"
    ) {
        return false;
    }
    if opts.keep_inline_images && mt.starts_with("image/") && p.header("content-id").is_some() {
        return false;
    }
    if !p.filename().is_empty() {
        return true;
    }
    if mt.starts_with("text/") || mt.starts_with("message/") {
        return false;
    }
    true // nameless non-text leaves
}

fn extract_leaf(p: &Part) -> Extracted {
    let (mt, _) = p.media_type();
    let mut name = p.filename();
    if name.is_empty() {
        name = if mt.starts_with("message/") {
            "forwarded-message.eml".into()
        } else {
            format!("attachment{}", ext_for(&mt))
        };
    }
    let data = if mt.starts_with("message/") && p.is_multipart() {
        p.to_bytes()
    } else {
        p.decode_body()
    };
    Extracted {
        filename: crate::mimeproc::sanitize_filename(&name),
        content_type: mt,
        data,
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
        if mt == "multipart/signed" || is_encrypted(&mt) {
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
        preamble: std::mem::take(&mut root.preamble),
        epilogue: std::mem::take(&mut root.epilogue),
        boundary: root.boundary.take(),
        fields: root
            .fields
            .iter()
            .filter(|f| f.name.starts_with("content-"))
            .cloned()
            .collect(),
    };
    if inner.fields.is_empty() {
        inner.add_header("Content-Type", "text/plain; charset=us-ascii");
    }
    root.make_multipart_mixed();
    root.children = vec![alt, inner];
}

#[cfg(test)]
mod tests {
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
}
