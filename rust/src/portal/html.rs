//! Minimal, injection-safe HTML templating for the portal pages.
//!
//! Templates are embedded with `include_str!` and carry `{{name}}` placeholders.
//! Values are [`Html`] fragments: either escaped user data ([`esc`]) or markup
//! assembled in code from escaped parts. Substitution is a single pass over the
//! template, so an inserted value is never re-scanned for placeholders.

use std::fmt::Write as _;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;

pub(crate) const STYLES: &str = include_str!("templates/styles.css");
pub(crate) const PAGE: &str = include_str!("templates/page.html");
pub(crate) const DLP: &str = include_str!("templates/dlp.html");
pub(crate) const DLP_ADMIN: &str = include_str!("templates/dlp_admin.html");
pub(crate) const DLP_ADMIN_APP: &str = include_str!("templates/dlp_admin_app.html");

/// A fragment of trusted HTML.
#[derive(Clone, Debug, Default)]
pub(crate) struct Html(String);

impl Html {
    /// Markup written by this crate (never user data).
    pub(crate) fn raw(s: impl Into<String>) -> Html {
        Html(s.into())
    }

    pub(crate) fn push_raw(&mut self, s: &str) {
        self.0.push_str(s);
    }

    pub(crate) fn push_esc(&mut self, s: &str) {
        self.0.push_str(&html_escape(s));
    }

    pub(crate) fn into_string(self) -> String {
        self.0
    }
}

/// Escapes text for an HTML text node or a quoted attribute value.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escaped user data as an HTML fragment.
pub(crate) fn esc(s: &str) -> Html {
    Html(html_escape(s))
}

/// Encodes `s` as a JavaScript string literal that is safe inside a <script>
/// element (no `<`, `>`, `&` or line separators survive literally).
pub(crate) fn js_string(s: &str) -> Html {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '<' | '>' | '&' | '\'' | '\u{2028}' | '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    Html(out)
}

/// Substitutes `{{name}}` placeholders in `tpl` (single pass). Unknown
/// placeholders render as empty.
pub(crate) fn fill(tpl: &str, vars: &[(&str, Html)]) -> String {
    let mut out = String::with_capacity(tpl.len() + 1024);
    let mut rest = tpl;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        match after.find("}}") {
            Some(j) => {
                let key = after[..j].trim();
                if let Some((_, v)) = vars.iter().find(|(k, _)| *k == key) {
                    out.push_str(&v.0);
                }
                rest = &after[j + 2..];
            }
            None => {
                out.push_str("{{");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// A fresh random CSP nonce.
pub(crate) fn nonce() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// CSP for a page with a nonce'd style and script.
pub(crate) fn csp_with_script(nonce: &str) -> String {
    format!(
        "default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; \
         connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
}

/// CSP for a page with a nonce'd style and no script.
pub(crate) fn csp_style_only(nonce: &str) -> String {
    format!(
        "default-src 'none'; style-src 'nonce-{nonce}'; form-action 'self'; \
         frame-ancestors 'none'; base-uri 'none'"
    )
}

/// An HTML response with the given CSP.
pub(crate) fn html_response(code: StatusCode, csp: &str, body: String) -> Response {
    let mut resp = (code, body).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    if let Ok(v) = HeaderValue::from_str(csp) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    resp
}

/// Human-readable byte size (1024-based), as the Go `humanSize`.
pub(crate) fn human_size(n: i64) -> String {
    const UNIT: i64 = 1024;
    if n < UNIT {
        return format!("{n} B");
    }
    let (mut div, mut exp) = (UNIT, 0usize);
    let mut m = n / UNIT;
    while m >= UNIT {
        div *= UNIT;
        exp += 1;
        m /= UNIT;
    }
    let unit = b"KMGTPE"[exp] as char;
    format!("{:.1} {unit}B", n as f64 / div as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_and_fill() {
        assert_eq!(
            html_escape(r#"<a href="x">'&'</a>"#),
            "&lt;a href=&#34;x&#34;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
        // An inserted value containing a placeholder is not re-expanded.
        let out = fill(
            "<p>{{a}}|{{b}}|{{missing}}</p>",
            &[("a", esc("{{b}}<x>")), ("b", Html::raw("<i>ok</i>"))],
        );
        assert_eq!(out, "<p>{{b}}&lt;x&gt;|<i>ok</i>|</p>");
        assert_eq!(fill("x {{ unterminated", &[]), "x {{ unterminated");
    }

    #[test]
    fn js_string_is_script_safe() {
        let s = js_string("</script><b>\"x\"\n").into_string();
        assert!(!s.contains('<') && !s.contains('\n'));
        assert!(s.starts_with('"') && s.ends_with('"'));
    }

    #[test]
    fn sizes() {
        assert_eq!(human_size(10), "10 B");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MB");
    }
}
