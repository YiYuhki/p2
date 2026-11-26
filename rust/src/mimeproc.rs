//! MIME parsing and filename sanitization. Port of the Go `internal/mimeproc`
//! parsing/extraction surface used by the DLP scanner. Structure comes from
//! [`crate::mimetree`] (the same parser the quarantine rewrite uses, so DLP
//! inspects exactly what recipients receive); `mailparse` only decodes single
//! leaves (transfer encodings). RFC 2047 header decoding and charset
//! decoding are done here in linear time ([`decode_header`], [`decode_text`]).

use base64::Engine;

use crate::mimetree::{self, Opaque, Part};

/// Maximum depth of message/rfc822 messages embedded in each other that is
/// unpacked for inspection; deeper ones are reported as uninspectable.
const MAX_EMBEDDED: usize = 8;

/// Longest raw Subject value decoded (its head).
pub const MAX_RAW_SUBJECT: usize = 8 * 1024;

/// An attachment extracted from a message.
#[derive(Clone, Debug)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    /// Declared charset (lowercase), if any.
    pub charset: Option<String>,
    pub data: Vec<u8>,
}

/// A decoded text body (or text-like part) to inspect.
#[derive(Clone, Debug)]
pub struct TextPart {
    /// Where it was found, e.g. "본문" or "첨부 메일 본문".
    pub location: String,
    pub text: String,
    /// HTML markup (tags/entities must be normalized before matching).
    pub html: bool,
}

/// The pieces of a parsed message the DLP scanner and quarantine need.
#[derive(Clone, Debug, Default)]
pub struct Parsed {
    pub subject: String,
    /// Decoded text bodies and text-like leaves (JSON, XML, CSV, ...),
    /// including those of embedded message/rfc822 parts.
    pub text_parts: Vec<TextPart>,
    /// Named parts and nameless binary leaves.
    pub attachments: Vec<Attachment>,
    /// Parts that could not be inspected (with a reason).
    pub uninspectable: Vec<String>,
    /// Opaque encrypted parts.
    pub encrypted: Vec<String>,
}

/// The first `max` bytes of `s` (snapped to a char boundary).
pub fn head_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut i = max;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

/// Decoded Subject of an entity (only its first [`MAX_RAW_SUBJECT`] bytes).
pub fn subject_of(p: &Part) -> String {
    decode_header(head_str(
        &p.header("subject").unwrap_or_default(),
        MAX_RAW_SUBJECT,
    ))
}

/// Parses a raw message, decoding headers/bodies and collecting the subject,
/// every text-like leaf and every other leaf as an attachment. Every leaf ends
/// up in exactly one of `text_parts`, `attachments`, `uninspectable` or
/// `encrypted`. Never fails (kept as a Result for API stability).
pub fn parse(raw: &[u8]) -> Result<Parsed, String> {
    let root = mimetree::parse(raw);
    let mut out = Parsed {
        subject: subject_of(&root),
        ..Default::default()
    };
    walk(&root, 0, "", &mut out);
    Ok(out)
}

fn opaque_reason(o: Opaque) -> String {
    match o {
        Opaque::Depth => format!(
            "MIME 중첩이 {}단계를 초과하여 검사할 수 없는 파트",
            mimetree::MAX_DEPTH
        ),
        Opaque::Parts => format!(
            "MIME 파트 수가 {}개를 초과하여 나머지를 검사할 수 없음",
            mimetree::MAX_PARTS
        ),
        Opaque::Ambiguous => "Content-* 헤더가 중복·충돌하여 해석이 모호한 파트".into(),
        Opaque::Headers => format!(
            "헤더 필드가 {}개를 초과하여 검사할 수 없는 파트",
            mimetree::MAX_FIELDS
        ),
    }
}

fn walk(part: &Part, msg_depth: usize, prefix: &str, out: &mut Parsed) {
    let (mt, params) = part.media_type();
    if let Some(o) = part.opaque() {
        out.uninspectable
            .push(format!("{prefix}{}", opaque_reason(o)));
        return;
    }
    if mimetree::is_opaque_encrypted(part) {
        out.encrypted.push(format!("{prefix}암호화된 파트 ({mt})"));
        return;
    }
    if part.is_multipart() {
        for sub in part.children() {
            walk(sub, msg_depth, prefix, out);
        }
        return;
    }
    if mt == "message/rfc822" || mt == "message/global" {
        if msg_depth >= MAX_EMBEDDED {
            out.uninspectable
                .push(format!("{prefix}첨부 메일 중첩이 너무 깊어 검사할 수 없음"));
            return;
        }
        let inner = mimetree::parse(&part.decode_body());
        let p = format!("{prefix}첨부 메일 ");
        let subject = subject_of(&inner);
        if !subject.is_empty() {
            out.text_parts.push(TextPart {
                location: format!("{p}제목"),
                text: subject,
                html: false,
            });
        }
        walk(&inner, msg_depth + 1, &p, out);
        return;
    }
    let charset = params
        .get("charset")
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty());
    // A part with a filename (or an "attachment" disposition) is an attachment.
    let (disp, _) = part.disposition();
    let raw_name = part.filename();
    if disp == "attachment" || !raw_name.is_empty() {
        let mut name = sanitize_filename(&raw_name);
        if name.is_empty() {
            name = "attachment".into();
        }
        out.attachments.push(Attachment {
            filename: format!("{prefix}{name}"),
            content_type: mt,
            charset,
            data: part.decode_body(),
        });
        return;
    }
    if is_text_like(&mt) {
        let mut body = part.decode_body();
        let mut stripped = false;
        if mt == "text/plain" {
            // uuencoded files inside the text are attachments to recipients.
            let (rest, blocks) = mimetree::split_uuencode(&body);
            for b in blocks {
                let mut name = sanitize_filename(&b.name);
                if name.is_empty() {
                    name = "attachment".into();
                }
                out.attachments.push(Attachment {
                    filename: format!("{prefix}{name}"),
                    content_type: "application/octet-stream".into(),
                    charset: None,
                    data: b.data,
                });
            }
            stripped = body.len() != rest.len();
            body = rest;
        }
        let text = match decode_text(&body, charset.as_deref()) {
            Decoded::Text(t) => t,
            // A charset encoding_rs does not know (e.g. UTF-7): mailparse's
            // charset support, then the heuristic text.
            Decoded::UnknownCharset(t) | Decoded::Lossy(t) if stripped => t,
            Decoded::UnknownCharset(t) | Decoded::Lossy(t) => part.text().unwrap_or(t),
        };
        out.text_parts.push(TextPart {
            location: format!("{prefix}본문"),
            text,
            html: mt == "text/html" || mt == "application/xhtml+xml",
        });
        return;
    }
    // Nameless non-text leaf (application/octet-stream, image/*, ...): goes
    // down the attachment path so it is scanned or reported, never skipped.
    out.attachments.push(Attachment {
        filename: format!("{prefix}(이름 없는 {mt} 파트)"),
        content_type: mt,
        charset,
        data: part.decode_body(),
    });
}

/// Media types whose content is text and is scanned as such.
pub fn is_text_like(mt: &str) -> bool {
    if mt.starts_with("text/") || mt.starts_with("multipart/") {
        return true; // a multipart without a usable boundary: scan the raw body
    }
    if mt.starts_with("message/") {
        return !matches!(mt, "message/partial" | "message/external-body");
    }
    if mt.ends_with("+json") || mt.ends_with("+xml") {
        return true;
    }
    matches!(
        mt,
        "application/json"
            | "application/xml"
            | "application/csv"
            | "application/x-csv"
            | "application/javascript"
            | "application/x-javascript"
            | "application/ecmascript"
            | "application/yaml"
            | "application/x-yaml"
            | "application/x-sh"
            | "application/sql"
            | "application/x-sql"
            | "application/rtf"
            | "application/x-www-form-urlencoded"
            | "application/x-ndjson"
    )
}

/// Result of [`decode_text`].
#[derive(Debug, PartialEq, Eq)]
pub enum Decoded {
    /// Decoded with confidence (BOM, declared charset, valid UTF-8, UTF-16
    /// by NUL density, or error-free EUC-KR/CP949).
    Text(String),
    /// The declared charset is unknown; best-effort heuristic text.
    UnknownCharset(String),
    /// Last resort: lossy UTF-8 with NULs removed (likely binary).
    Lossy(String),
}

impl Decoded {
    pub fn into_string(self) -> String {
        match self {
            Decoded::Text(s) | Decoded::UnknownCharset(s) | Decoded::Lossy(s) => s,
        }
    }
}

/// Decodes text content: a BOM (UTF-8, UTF-16LE/BE) wins, then the declared
/// charset, then valid UTF-8, UTF-16 detected by NUL density, EUC-KR/CP949,
/// and finally lossy UTF-8 with NULs stripped.
pub fn decode_text(data: &[u8], charset: Option<&str>) -> Decoded {
    use encoding_rs::{Encoding, UTF_8};
    if let Some((enc, bom)) = Encoding::for_bom(data) {
        return Decoded::Text(enc.decode_without_bom_handling(&data[bom..]).0.into_owned());
    }
    let mut unknown = false;
    if let Some(cs) = charset {
        let cs = cs.trim().trim_matches('"').to_ascii_lowercase();
        let ascii = matches!(
            cs.as_str(),
            "us-ascii" | "ascii" | "us_ascii" | "ansi_x3.4-1968"
        );
        if cs == "utf-16" {
            if let Some(enc) = utf16_guess(data) {
                return Decoded::Text(enc.decode_without_bom_handling(data).0.into_owned());
            }
        } else if !ascii {
            match Encoding::for_label(cs.as_bytes()) {
                // Declared UTF-8 that is not: fall through to the heuristics.
                Some(enc) if enc == UTF_8 => {}
                Some(enc) => {
                    let (t, had_errors) = enc.decode_without_bom_handling(data);
                    if !had_errors || utf16_guess(data).is_none() {
                        return Decoded::Text(t.into_owned());
                    }
                }
                None => unknown = true,
            }
        }
    }
    match heuristic_text(data) {
        Decoded::Text(t) | Decoded::UnknownCharset(t) | Decoded::Lossy(t) if unknown => {
            Decoded::UnknownCharset(t)
        }
        d => d,
    }
}

/// Undeclared charset: valid UTF-8, UTF-16 by NUL density, EUC-KR/CP949,
/// else lossy UTF-8 without NULs.
fn heuristic_text(data: &[u8]) -> Decoded {
    let utf16 = utf16_guess(data);
    if let (Ok(s), None) = (std::str::from_utf8(data), utf16) {
        return Decoded::Text(s.to_string());
    }
    if let Some(enc) = utf16 {
        return Decoded::Text(enc.decode_without_bom_handling(data).0.into_owned());
    }
    let (t, had_errors) = encoding_rs::EUC_KR.decode_without_bom_handling(data);
    if !had_errors {
        return Decoded::Text(t.into_owned());
    }
    Decoded::Lossy(
        String::from_utf8_lossy(data)
            .chars()
            .filter(|&c| c != '\0')
            .collect(),
    )
}

/// UTF-16 without a BOM, recognized by NULs concentrated on odd (LE) or even
/// (BE) byte positions of the first 64 KiB.
fn utf16_guess(data: &[u8]) -> Option<&'static encoding_rs::Encoding> {
    let s = &data[..data.len().min(64 * 1024)];
    if s.len() < 4 {
        return None;
    }
    let (mut even, mut odd) = (0usize, 0usize);
    for (i, &b) in s.iter().enumerate() {
        if b == 0 {
            if i % 2 == 0 {
                even += 1;
            } else {
                odd += 1;
            }
        }
    }
    let half = s.len() / 2;
    if odd * 10 >= half * 3 && even * 10 < half {
        Some(encoding_rs::UTF_16LE)
    } else if even * 10 >= half * 3 && odd * 10 < half {
        Some(encoding_rs::UTF_16BE)
    } else {
        None
    }
}

/// Decodes RFC 2047 encoded words in a header value, in linear time.
/// Whitespace between adjacent encoded words is dropped; adjacent words in
/// the same charset are decoded together (a multi-byte character may be
/// split across words). Unknown charsets decode as lossy UTF-8; malformed
/// words are kept verbatim.
pub fn decode_header(v: &str) -> String {
    if !v.contains("=?") {
        return v.to_string();
    }
    let b = v.as_bytes();
    let mut out = String::with_capacity(v.len());
    // Pending run of adjacent encoded words: (charset, decoded bytes).
    let mut run: Option<(String, Vec<u8>)> = None;
    let mut lit = 0; // start of pending literal text
    let mut i = 0;
    let flush = |out: &mut String, run: &mut Option<(String, Vec<u8>)>| {
        if let Some((cs, bytes)) = run.take() {
            out.push_str(&decode_charset(&cs, &bytes));
        }
    };
    while i + 1 < b.len() {
        if !(b[i] == b'=' && b[i + 1] == b'?') {
            i += 1;
            continue;
        }
        match parse_encoded_word(b, i) {
            Some((cs, bytes, end)) => {
                let between = &v[lit..i];
                let adjacent = run.is_some() && between.bytes().all(|c| c == b' ' || c == b'\t');
                if adjacent {
                    let r = run.as_mut().unwrap();
                    if r.0.eq_ignore_ascii_case(&cs) {
                        r.1.extend_from_slice(&bytes);
                    } else {
                        flush(&mut out, &mut run);
                        run = Some((cs, bytes));
                    }
                } else {
                    flush(&mut out, &mut run);
                    out.push_str(between);
                    run = Some((cs, bytes));
                }
                i = end;
                lit = end;
            }
            None => i += 2,
        }
    }
    flush(&mut out, &mut run);
    out.push_str(&v[lit..]);
    out
}

/// Parses "=?charset?B|Q?text?=" at `s`; returns (charset, bytes, end).
/// Scans stop at the first '?' or whitespace, so a failed attempt never
/// re-reads more than it skips (linear overall).
fn parse_encoded_word(b: &[u8], s: usize) -> Option<(String, Vec<u8>, usize)> {
    let mut i = s + 2;
    let cs_start = i;
    while i < b.len() && b[i] != b'?' {
        if b[i].is_ascii_whitespace() || i - cs_start > 64 {
            return None;
        }
        i += 1;
    }
    if i >= b.len() || i == cs_start {
        return None;
    }
    let charset = String::from_utf8_lossy(&b[cs_start..i]).into_owned();
    // RFC 2231 language suffix: "utf-8*ko".
    let charset = charset.split('*').next().unwrap_or("").to_string();
    let enc = *b.get(i + 1)?;
    if b.get(i + 2) != Some(&b'?') {
        return None;
    }
    i += 3;
    let t_start = i;
    while i < b.len() && b[i] != b'?' {
        if b[i] == b' ' || b[i] == b'\t' {
            return None;
        }
        i += 1;
    }
    if b.get(i + 1) != Some(&b'=') {
        return None;
    }
    let text = &b[t_start..i];
    let bytes = match enc {
        b'B' | b'b' => {
            let t: Vec<u8> = text.iter().copied().filter(|&c| c != b'=').collect();
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(&t)
                .ok()?
        }
        b'Q' | b'q' => {
            let mut o = Vec::with_capacity(text.len());
            let mut k = 0;
            while k < text.len() {
                match text[k] {
                    b'_' => o.push(b' '),
                    b'=' if k + 2 < text.len() => match (hex(text[k + 1]), hex(text[k + 2])) {
                        (Some(h), Some(l)) => {
                            o.push(h << 4 | l);
                            k += 2;
                        }
                        _ => o.push(b'='),
                    },
                    c => o.push(c),
                }
                k += 1;
            }
            o
        }
        _ => return None,
    };
    Some((charset, bytes, i + 2))
}

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// Decodes bytes in a named charset (lossy UTF-8 when unknown).
pub fn decode_charset(cs: &str, bytes: &[u8]) -> String {
    match encoding_rs::Encoding::for_label(cs.trim().as_bytes()) {
        Some(enc) => enc.decode_without_bom_handling(bytes).0.into_owned(),
        None => String::from_utf8_lossy(bytes).into_owned(),
    }
}
/// Unicode format characters (general category Cf): invisible characters
/// such as zero-width spaces/joiners, the soft hyphen, BOM, bidi embeddings,
/// overrides and isolates, and tag characters.
pub fn is_format_char(c: char) -> bool {
    matches!(c as u32,
        0x00AD
        | 0x0600..=0x0605
        | 0x061C
        | 0x06DD
        | 0x070F
        | 0x0890..=0x0891
        | 0x08E2
        | 0x180E
        | 0x200B..=0x200F
        | 0x202A..=0x202E
        | 0x2060..=0x2064
        | 0x2066..=0x206F
        | 0xFEFF
        | 0xFFF9..=0xFFFB
        | 0x110BD
        | 0x110CD
        | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A
        | 0xE0001
        | 0xE0020..=0xE007F)
}

/// Longest raw name inspected: anything before the last 8 KiB cannot be part
/// of the base name or extension the gate needs.
pub(crate) const MAX_RAW_NAME: usize = 8 * 1024;
/// Longest sanitized name, in characters.
const MAX_NAME_CHARS: usize = 200;

/// Strips directories, control and format characters (incl. every bidi
/// control such as RLO/LRI and zero-width characters), Windows-reserved
/// characters and trailing dots/spaces so the name is safe to show and to use
/// in Content-Disposition, and the blocked-extension gate sees the name the OS
/// resolves. Windows device names (CON, NUL, COM1, ...) are prefixed with "_".
/// Port of the Go `SanitizeFilename` (with the trailing-dot normalization).
/// Runs in linear time.
pub fn sanitize_filename(name: &str) -> String {
    // Only the tail can hold the base name; cap the work on hostile input.
    let name = if name.len() > MAX_RAW_NAME {
        let mut i = name.len() - MAX_RAW_NAME;
        while !name.is_char_boundary(i) {
            i += 1;
        }
        &name[i..]
    } else {
        name
    };
    // path.Base, for both separators.
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let s: String = base
        .chars()
        .filter(|&c| {
            !(c.is_control()
                || is_format_char(c)
                || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'))
        })
        .collect();
    let mut s = s
        .trim()
        .trim_start_matches('.')
        .trim_end_matches([' ', '.'])
        .to_string();
    if s.is_empty() {
        return String::new();
    }
    // Truncate an overlong name once, keeping a short extension.
    if s.chars().count() > MAX_NAME_CHARS {
        let ext = path_ext(&s);
        let ext = if ext.chars().count() > 20 { "" } else { ext };
        let stem = &s[..s.len() - ext.len()];
        let keep = MAX_NAME_CHARS - ext.chars().count();
        let cut = stem
            .char_indices()
            .nth(keep)
            .map(|(i, _)| i)
            .unwrap_or(stem.len());
        let stem = stem[..cut].trim_end_matches([' ', '.']);
        s = format!("{stem}{ext}");
    }
    if is_windows_device_name(&s) {
        s.insert(0, '_');
    }
    s
}

/// CON, PRN, AUX, NUL, COM1-9, LPT1-9 (case-insensitive), with or without an
/// extension ("nul.txt" is the NUL device on Windows too).
fn is_windows_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end();
    let u = stem.to_ascii_uppercase();
    match u.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" => true,
        _ => {
            let b = u.as_bytes();
            b.len() == 4
                && (u.starts_with("COM") || u.starts_with("LPT"))
                && (b'1'..=b'9').contains(&b[3])
        }
    }
}

fn path_ext(name: &str) -> &str {
    match name.rfind('.') {
        Some(i) => &name[i..],
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename(r"C:\Users\x\evil.exe"), "evil.exe");
        assert_eq!(sanitize_filename("...hidden"), "hidden");
        assert_eq!(sanitize_filename("evil.exe."), "evil.exe");
        assert_eq!(sanitize_filename("evil.exe. "), "evil.exe");
        assert_eq!(sanitize_filename("report.pdf..."), "report.pdf");
        assert_eq!(sanitize_filename("quote\".pdf"), "quote.pdf");
        assert_eq!(sanitize_filename("a\u{202E}gpj.exe"), "agpj.exe");
    }

    #[test]
    fn parse_multipart_with_attachment() {
        let raw = b"From: a@ext.org\r\nTo: b@example.com\r\nSubject: =?utf-8?B?7ZWc6riA?=\r\n\
MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
--B\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
please see the attachment 900101-1234567\r\n\
--B\r\nContent-Type: application/pdf; name=\"invoice.pdf.\"\r\n\
Content-Disposition: attachment; filename=\"invoice.pdf.\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
JVBERi0xLjQK\r\n--B--\r\n";
        let p = parse(raw).unwrap();
        assert_eq!(p.subject, "한글"); // RFC 2047 decoded
        assert!(p
            .text_parts
            .iter()
            .any(|t| t.text.contains("900101-1234567")));
        assert_eq!(p.attachments.len(), 1);
        assert_eq!(p.attachments[0].filename, "invoice.pdf"); // trailing dot stripped
        assert_eq!(p.attachments[0].content_type, "application/pdf");
        assert!(p.attachments[0].data.starts_with(b"%PDF")); // base64 decoded
    }

    #[test]
    fn parse_singlepart_text() {
        let raw =
            b"Subject: hi\r\nContent-Type: text/plain\r\n\r\nsecret AKIAIOSFODNN7EXAMPLE here\r\n";
        let p = parse(raw).unwrap();
        assert_eq!(p.subject, "hi");
        assert_eq!(p.text_parts.len(), 1);
        assert!(p.text_parts[0].text.contains("AKIA"));
        assert!(p.attachments.is_empty());
    }

    #[test]
    fn sanitize_is_linear_and_keeps_extension() {
        let name = "a".repeat(40_000) + ".pdf";
        let t = std::time::Instant::now();
        let out = sanitize_filename(&name);
        assert!(t.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(out.chars().count(), 200);
        assert!(out.ends_with(".pdf"));
        let huge = "가".repeat(2_000_000) + ".exe";
        let out = sanitize_filename(&huge);
        assert!(out.ends_with(".exe") && out.chars().count() == 200);
    }

    #[test]
    fn sanitize_strips_bidi_reserved_and_device_names() {
        for bidi in [
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}',
            '\u{2068}', '\u{2069}', '\u{200E}', '\u{200F}', '\u{061C}', '\u{200B}', '\u{FEFF}',
        ] {
            assert_eq!(sanitize_filename(&format!("a{bidi}gpj.exe")), "agpj.exe");
        }
        assert_eq!(sanitize_filename("a<b>c:d\"e|f?g*.txt"), "abcdefg.txt");
        assert_eq!(sanitize_filename("x\u{1}y\u{7f}.txt"), "xy.txt");
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename("nul.txt"), "_nul.txt");
        assert_eq!(sanitize_filename("Com1.exe"), "_Com1.exe");
        assert_eq!(sanitize_filename("lpt9"), "_lpt9");
        assert_eq!(sanitize_filename("console.txt"), "console.txt");
        assert_eq!(sanitize_filename("com10.txt"), "com10.txt");
    }

    #[test]
    fn every_leaf_is_classified() {
        let raw = b"From: a@x\r\nSubject: s\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n\
--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n\
--B\r\nContent-Type: application/json\r\n\r\n{\"rrn\":\"900101-1234567\"}\r\n\
--B\r\nContent-Type: application/octet-stream\r\n\r\n\x00\x01binary\r\n\
--B\r\nContent-Type: message/rfc822\r\n\r\nSubject: inner\r\nContent-Type: text/html\r\n\r\n<p>x</p>\r\n\
--B\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data\r\nContent-Transfer-Encoding: base64\r\n\r\nMIAG\r\n--B--\r\n";
        let p = parse(raw).unwrap();
        assert!(p
            .text_parts
            .iter()
            .any(|t| t.text.contains("900101-1234567")));
        assert!(p
            .text_parts
            .iter()
            .any(|t| t.location == "첨부 메일 제목" && t.text == "inner"));
        assert!(p
            .text_parts
            .iter()
            .any(|t| t.html && t.location == "첨부 메일 본문"));
        assert_eq!(p.attachments.len(), 1);
        assert_eq!(p.attachments[0].content_type, "application/octet-stream");
        assert_eq!(p.encrypted.len(), 1);
    }

    #[test]
    fn deep_nesting_is_uninspectable_not_a_crash() {
        let raw = crate::mimetree::tests::deep_message(50_000);
        let h = std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || parse(&raw).unwrap())
            .unwrap();
        let p = h.join().expect("no stack overflow");
        assert_eq!(p.uninspectable.len(), 1);
    }

    #[test]
    fn decode_header_rfc2047() {
        assert_eq!(decode_header("=?utf-8?B?7ZWc6riA?="), "한글");
        assert_eq!(decode_header("=?utf-8?q?a?= =?utf-8?q?b?="), "ab");
        assert_eq!(decode_header("x =?utf-8?q?a_b?= y"), "x a b y");
        assert_eq!(decode_header("=?UTF-8?Q?=EC=9D=B4?="), "이");
        // A character split across adjacent words.
        assert_eq!(decode_header("=?utf-8?B?7ZU=?= =?utf-8?B?nA==?="), "한");
        assert_eq!(decode_header("=?euc-kr?B?x9Gx2w==?="), "한글");
        assert_eq!(decode_header("=?utf-8*ko?q?x?="), "x");
        for keep in ["=?utf-8?x?abc?=", "=?", "a=?b", "=?utf-8?q?a b?=", "plain"] {
            assert_eq!(decode_header(keep), keep);
        }
    }

    #[test]
    fn decode_header_is_linear() {
        for v in [
            "=?utf-8?q?a?= ".repeat(150_000),
            "=?a?b?".repeat(300_000),
            "=?".repeat(1_000_000),
            format!("=?utf-8?q?{}", "a".repeat(2_000_000)),
        ] {
            let t = std::time::Instant::now();
            let _ = decode_header(&v);
            assert!(
                t.elapsed() < std::time::Duration::from_secs(2),
                "{:?}",
                t.elapsed()
            );
        }
        // Subjects are decoded from their first 8 KiB only.
        let raw = format!("Subject: {}\r\n\r\nx", "=?utf-8?q?a?= ".repeat(150_000));
        let p = parse(raw.as_bytes()).unwrap();
        assert!(p.subject.len() <= MAX_RAW_SUBJECT);
    }

    #[test]
    fn delimiter_prefix_is_not_a_boundary() {
        // "--Bx" is not a delimiter for boundary "B": the PII stays in the text
        // part, exactly as the quarantine parser (and recipients) see it.
        let raw = b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n--Bx\r\nContent-Type: image/png; name=a.png\r\n\r\nrrn 900101-1234567\r\n--B--\r\n";
        let p = parse(raw).unwrap();
        assert!(p.attachments.is_empty());
        assert!(p.text_parts[0].text.contains("900101-1234567"));
    }
}
