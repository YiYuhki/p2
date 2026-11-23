//! Helpers shared by the Authentication-Results producers (SPF/DKIM/DMARC), so
//! the header-injection guard stays identical. Port of the Go `internal/authres`.

/// Strips characters that could break out of an Authentication-Results method
/// value or inject an additional method: `;` (method separator), whitespace
/// (property separator) and control characters.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|&r| {
            let u = r as u32;
            !(r == ';' || r == ' ' || r == '\t' || u < 0x20 || u == 0x7f)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_injection_chars() {
        assert_eq!(sanitize("example.com"), "example.com");
        assert_eq!(sanitize("evil.com; spf=pass"), "evil.comspf=pass");
        assert_eq!(sanitize("a b\tc\u{7f}d"), "abcd");
    }
}
