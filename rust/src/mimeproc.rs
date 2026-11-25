//! MIME parsing and filename sanitization. Port of the Go `internal/mimeproc`
//! parsing/extraction surface, built on the `mailparse` crate (RFC 2047 header
//! decoding and transfer-encoding handled by the crate). Message *rewriting*
//! (banner insertion, attachment stripping, re-serialization) lives in `mimetree`.

use mailparse::{parse_mail, MailHeaderMap, ParsedMail};

/// An attachment extracted from a message.
#[derive(Clone, Debug)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

/// The pieces of a parsed message the DLP scanner and quarantine need.
#[derive(Clone, Debug, Default)]
pub struct Parsed {
    pub subject: String,
    /// Decoded text/plain and text/html part bodies.
    pub text_parts: Vec<String>,
    pub attachments: Vec<Attachment>,
}

/// Parses a raw RFC 5322 message, decoding headers/bodies and collecting the
/// subject, text parts and attachments.
pub fn parse(raw: &[u8]) -> Result<Parsed, String> {
    let mail = parse_mail(raw).map_err(|e| e.to_string())?;
    let mut out = Parsed {
        subject: mail.headers.get_first_value("Subject").unwrap_or_default(),
        ..Default::default()
    };
    walk(&mail, &mut out);
    Ok(out)
}

fn walk(part: &ParsedMail, out: &mut Parsed) {
    let mimetype = part.ctype.mimetype.to_lowercase();
    if mimetype.starts_with("multipart/") {
        for sub in &part.subparts {
            walk(sub, out);
        }
        return;
    }
    // A part with a filename (or an "attachment" disposition) is an attachment.
    let disp = part.get_content_disposition();
    let is_attachment = disp.disposition == mailparse::DispositionType::Attachment
        || disp.params.contains_key("filename")
        || part.ctype.params.contains_key("name");
    if is_attachment {
        let raw_name = disp
            .params
            .get("filename")
            .or_else(|| part.ctype.params.get("name"))
            .cloned()
            .unwrap_or_default();
        out.attachments.push(Attachment {
            filename: sanitize_filename(&raw_name),
            content_type: part.ctype.mimetype.clone(),
            data: part.get_body_raw().unwrap_or_default(),
        });
        return;
    }
    if mimetype.starts_with("text/") {
        if let Ok(body) = part.get_body() {
            out.text_parts.push(body);
        }
    }
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

/// Strips directories, control characters, RLO/LRO overrides and trailing
/// dots/spaces so the name is safe to show and to use in Content-Disposition,
/// and the blocked-extension gate sees the name the OS resolves. Port of the Go
/// `SanitizeFilename` (with the trailing-dot normalization).
pub fn sanitize_filename(name: &str) -> String {
    let name = name.replace('\\', "/");
    // path.Base
    let base = name.rsplit('/').next().unwrap_or(&name);
    let mut s: String = base
        .chars()
        .filter(|&c| {
            !(c.is_control() || c == '"' || c == '/' || c == '\u{202E}' || c == '\u{202D}')
        })
        .collect();
    s = s.trim().to_string();
    s = s.trim_start_matches('.').to_string();
    s = s.trim_end_matches([' ', '.']).to_string();
    if s.is_empty() || s == "." {
        return String::new();
    }
    // Truncate overlong names, keeping a short extension.
    while s.chars().count() > 200 {
        let ext = path_ext(&s);
        let ext = if ext.len() > 20 { "" } else { ext };
        let stem: String = {
            let without = s.strip_suffix(ext).unwrap_or(&s);
            let mut chars: Vec<char> = without.chars().collect();
            chars.pop();
            chars.into_iter().collect()
        };
        s = format!("{stem}{ext}");
    }
    s
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
        assert!(p.text_parts.iter().any(|t| t.contains("900101-1234567")));
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
        assert!(p.text_parts[0].contains("AKIA"));
        assert!(p.attachments.is_empty());
    }
}
