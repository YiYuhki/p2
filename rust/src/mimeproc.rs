//! MIME parsing and filename sanitization. Port of the Go `internal/mimeproc`
//! parsing/extraction surface used by the DLP scanner. Structure comes from
//! [`crate::mimetree`] (the same parser the quarantine rewrite uses, so DLP
//! inspects exactly what recipients receive); `mailparse` only decodes single
//! leaves (RFC 2047 headers, transfer encodings, charsets).

use mailparse::{parse_mail, MailHeaderMap};

use crate::mimetree::{self, Part};

/// Maximum depth of message/rfc822 messages embedded in each other that is
/// unpacked for inspection; deeper ones are reported as uninspectable.
const MAX_EMBEDDED: usize = 8;

/// An attachment extracted from a message.
#[derive(Clone, Debug)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
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

/// Parses a raw message, decoding headers/bodies and collecting the subject,
/// every text-like leaf and every other leaf as an attachment. Every leaf ends
/// up in exactly one of `text_parts`, `attachments`, `uninspectable` or
/// `encrypted`. Never fails (kept as a Result for API stability).
pub fn parse(raw: &[u8]) -> Result<Parsed, String> {
    let root = mimetree::parse(raw);
    let mut out = Parsed {
        subject: decode_header(&root.header("subject").unwrap_or_default()),
        ..Default::default()
    };
    walk(&root, 0, "", &mut out);
    Ok(out)
}

fn walk(part: &Part, msg_depth: usize, prefix: &str, out: &mut Parsed) {
    let (mt, _) = part.media_type();
    if part.is_truncated() {
        out.uninspectable.push(format!(
            "{prefix}MIME 중첩이 {}단계를 초과하여 검사할 수 없는 파트",
            mimetree::MAX_DEPTH
        ));
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
        let subject = decode_header(&inner.header("subject").unwrap_or_default());
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
            data: part.decode_body(),
        });
        return;
    }
    if is_text_like(&mt) {
        let text = part
            .text()
            .unwrap_or_else(|| String::from_utf8_lossy(&part.decode_body()).into_owned());
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
        data: part.decode_body(),
    });
}

/// Media types whose content is text and is scanned as such.
fn is_text_like(mt: &str) -> bool {
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

/// Decodes an RFC 2047 encoded-word header value.
pub fn decode_header(v: &str) -> String {
    // mailparse exposes header decoding via a parsed header; wrap the value.
    let synthetic = format!("X: {v}\r\n\r\n");
    match parse_mail(synthetic.as_bytes()) {
        Ok(m) => m
            .headers
            .get_first_value("X")
            .unwrap_or_else(|| v.to_string()),
        Err(_) => v.to_string(),
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
const MAX_RAW_NAME: usize = 8 * 1024;
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
--B\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data\r\n\r\nMIAG\r\n--B--\r\n";
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
    fn delimiter_prefix_is_not_a_boundary() {
        // "--Bx" is not a delimiter for boundary "B": the PII stays in the text
        // part, exactly as the quarantine parser (and recipients) see it.
        let raw = b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n--Bx\r\nContent-Type: image/png; name=a.png\r\n\r\nrrn 900101-1234567\r\n--B--\r\n";
        let p = parse(raw).unwrap();
        assert!(p.attachments.is_empty());
        assert!(p.text_parts[0].text.contains("900101-1234567"));
    }
}
