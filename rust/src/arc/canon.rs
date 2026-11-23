//! Relaxed header/body canonicalization per RFC 6376 §3.4.2 / §3.4.4, shared by
//! the ARC-Message-Signature and ARC-Seal. Port of the Go `internal/arc` canon.

/// Relaxed canonical form of one header as "name:value" WITHOUT a trailing CRLF.
pub fn relaxed_header(name: &str, value: &str) -> String {
    let n = name.trim().to_lowercase();
    let v = collapse_wsp(&unfold(value));
    let v = v.trim();
    format!("{}:{}", n, v)
}

/// Relaxed canonical body: WSP runs collapsed to a single space, trailing line
/// WSP removed, trailing empty lines removed, and a single trailing CRLF (an
/// all-empty body canonicalizes to the empty string).
pub fn relaxed_body(body: &str) -> String {
    let body = body.replace("\r\n", "\n");
    let mut out: Vec<String> = body
        .split('\n')
        .map(|ln| collapse_wsp(ln).trim_end_matches([' ', '\t']).to_string())
        .collect();
    while out.last().map(|s| s.is_empty()).unwrap_or(false) {
        out.pop();
    }
    if out.is_empty() {
        return String::new();
    }
    let mut s = out.join("\r\n");
    s.push_str("\r\n");
    s
}

fn unfold(s: &str) -> String {
    s.replace("\r\n", "").replace('\n', "")
}

/// Reduces every run of spaces/tabs to a single space.
fn collapse_wsp(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_wsp = false;
    for c in s.chars() {
        if c == ' ' || c == '\t' {
            if !in_wsp {
                out.push(' ');
                in_wsp = true;
            }
        } else {
            in_wsp = false;
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relaxed_canonicalization_rfc6376() {
        // RFC 6376 §3.4.5 worked example.
        assert_eq!(relaxed_header("A", " X"), "a:X");
        assert_eq!(relaxed_header("B", " Y\r\n\tZ  "), "b:Y Z");
        assert_eq!(relaxed_body(" C \r\nD \t E\r\n\r\n\r\n"), " C\r\nD E\r\n");
        assert_eq!(relaxed_body(""), "");
    }
}
