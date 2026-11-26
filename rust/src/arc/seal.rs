//! ARC (RFC 8617) sealing. Port of the Go `internal/arc` sealer: builds a fresh
//! i=1, cv=none ARC set (ARC-Authentication-Results, ARC-Message-Signature,
//! ARC-Seal) and signs it with the gateway RSA key (RSA-SHA256), reusing the
//! shared relaxed canonicalization.

use base64::Engine;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, PrivateKey};
use sha2::{Digest, Sha256};

use super::canon::{relaxed_body, relaxed_header};

/// Header set the ARC-Message-Signature covers when present (mirrors the Go
/// `amsHeaders`).
const AMS_HEADERS: &[&str] = &[
    "From",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
    "Authentication-Results",
];

/// Adds an ARC set to a message with the gateway's signing key.
pub struct Sealer {
    domain: String,
    selector: String,
    authserv: String,
    key: PrivateKey,
    now: Box<dyn Fn() -> i64 + Send + Sync>,
}

impl Sealer {
    /// Returns a Sealer, or `None` when any required field is empty (disabled).
    pub fn new(domain: &str, selector: &str, authserv: &str, key: PrivateKey) -> Option<Self> {
        if domain.is_empty() || selector.is_empty() {
            return None;
        }
        let authserv = if authserv.is_empty() {
            domain
        } else {
            authserv
        };
        Some(Sealer {
            domain: domain.to_string(),
            selector: selector.to_string(),
            authserv: authserv.to_string(),
            key,
            now: Box::new(|| chrono::Utc::now().timestamp()),
        })
    }

    /// Loads a PEM private key (PKCS#1 or PKCS#8 RSA) and builds a Sealer.
    pub fn load(domain: &str, selector: &str, authserv: &str, pem: &str) -> Result<Self, String> {
        let key = PrivateKey::from_pkcs1_pem(pem)
            .or_else(|_| PrivateKey::from_pkcs8_pem(pem))
            .map_err(|e| format!("arc: parse key: {e}"))?;
        Self::new(domain, selector, authserv, key)
            .ok_or_else(|| "arc: domain and selector are required".to_string())
    }

    #[cfg(test)]
    pub fn with_now(mut self, now: Box<dyn Fn() -> i64 + Send + Sync>) -> Self {
        self.now = now;
        self
    }

    /// Prepends a fresh ARC set (i=1, cv=none) to `raw`. `auth_results` is the
    /// RFC 8601 method list without the leading authserv-id.
    pub fn seal(&self, raw: &[u8], auth_results: &str) -> Result<Vec<u8>, String> {
        let raw = String::from_utf8_lossy(raw).into_owned();
        let (headers, body) = split(&raw).ok_or("arc: message has no header/body separator")?;
        let t = (self.now)();

        let auth_results = if auth_results.is_empty() {
            "none"
        } else {
            auth_results
        };
        let aar = format!("i=1; {}; {}", self.authserv, auth_results);

        let bh = b64(&sha256(relaxed_body(&body).as_bytes()));
        let present = select_headers(&headers, AMS_HEADERS);
        let hlist: Vec<String> = present.iter().map(|h| h.name.clone()).collect();
        let ams_tags = format!(
            "i=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={}; t={}; bh={}; h={}; b=",
            self.domain,
            self.selector,
            t,
            bh,
            hlist.join(":")
        );
        let ams_sig = self.sign(&ams_signing_input(&present, &ams_tags))?;
        let ams_full = format!("{ams_tags}{ams_sig}");

        let as_tags = format!(
            "i=1; a=rsa-sha256; cv=none; d={}; s={}; t={}; b=",
            self.domain, self.selector, t
        );
        let as_sig = self.sign(&seal_signing_input(&aar, &ams_full, &as_tags))?;
        let as_full = format!("{as_tags}{as_sig}");

        let mut out = String::new();
        out.push_str(&fold("ARC-Seal", &as_full));
        out.push_str(&fold("ARC-Message-Signature", &ams_full));
        out.push_str(&fold("ARC-Authentication-Results", &aar));
        out.push_str(&headers);
        out.push_str("\r\n");
        out.push_str(&body);
        Ok(out.into_bytes())
    }

    fn sign(&self, input: &str) -> Result<String, String> {
        let digest = sha256(input.as_bytes());
        let sig = self
            .key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .map_err(|e| format!("arc: sign: {e}"))?;
        Ok(b64(&sig))
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

struct Header {
    name: String,
    value: String,
}

/// Builds the data the ARC-Message-Signature signs.
fn ams_signing_input(present: &[Header], ams_tags: &str) -> String {
    let mut b = String::new();
    for h in present {
        b.push_str(&relaxed_header(&h.name, &h.value));
        b.push_str("\r\n");
    }
    b.push_str(&relaxed_header("ARC-Message-Signature", ams_tags));
    b
}

/// Builds the data the ARC-Seal signs (AAR, AMS-with-real-b, AS-with-empty-b).
fn seal_signing_input(aar: &str, ams_full: &str, as_tags: &str) -> String {
    let mut b = String::new();
    b.push_str(&relaxed_header("ARC-Authentication-Results", aar));
    b.push_str("\r\n");
    b.push_str(&relaxed_header("ARC-Message-Signature", ams_full));
    b.push_str("\r\n");
    b.push_str(&relaxed_header("ARC-Seal", as_tags));
    b
}

/// Separates `raw` into the header block (through the last header's CRLF) and
/// the body (after the blank line).
fn split(raw: &str) -> Option<(String, String)> {
    let normalized = raw.replace("\r\n", "\n");
    let i = normalized.find("\n\n")?;
    let h = &normalized[..i + 1];
    let b = &normalized[i + 2..];
    Some((to_crlf(h), to_crlf(b)))
}

fn to_crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

/// For each wanted name (case-insensitive, in order), the first matching header.
fn select_headers(block: &str, want: &[&str]) -> Vec<Header> {
    let parsed = parse_headers(block);
    let mut out = Vec::new();
    for w in want {
        if let Some(h) = parsed.iter().find(|h| h.name.eq_ignore_ascii_case(w)) {
            out.push(Header {
                name: h.name.clone(),
                value: h.value.clone(),
            });
        }
    }
    out
}

/// Splits a header block into ordered name/value pairs, joining folded lines.
fn parse_headers(block: &str) -> Vec<Header> {
    let mut out: Vec<Header> = Vec::new();
    for ln in block.replace("\r\n", "\n").split('\n') {
        if ln.is_empty() {
            continue;
        }
        if ln.starts_with(' ') || ln.starts_with('\t') {
            if let Some(last) = out.last_mut() {
                last.value.push_str("\r\n");
                last.value.push_str(ln);
            }
            continue;
        }
        if let Some(c) = ln.find(':') {
            out.push(Header {
                name: ln[..c].to_string(),
                value: ln[c + 1..]
                    .strip_prefix(' ')
                    .unwrap_or(&ln[c + 1..])
                    .to_string(),
            });
        }
    }
    out
}

/// Emits "Name: value\r\n", wrapping the long value at ~78 columns on spaces.
fn fold(name: &str, value: &str) -> String {
    let line = format!("{name}: {value}");
    let mut b = String::new();
    const LIMIT: usize = 78;
    let mut col = 0usize;
    for field in line.split(' ') {
        if col > 0 && col + 1 + field.len() > LIMIT {
            b.push_str("\r\n ");
            col = 1;
        } else if col > 0 {
            b.push(' ');
            col += 1;
        }
        b.push_str(field);
        col += field.len();
    }
    b.push_str("\r\n");
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;
    use rsa::PublicKey;

    fn parse_tags(v: &str) -> std::collections::HashMap<String, String> {
        let v: String = v.replace("\r\n", "").replace('\n', "");
        let mut m = std::collections::HashMap::new();
        for part in v.split(';') {
            let part = part.trim();
            if let Some(eq) = part.find('=') {
                m.insert(
                    part[..eq].trim().to_string(),
                    part[eq + 1..].trim().to_string(),
                );
            }
        }
        m
    }

    fn empty_b(tags: &str) -> String {
        match tags.rfind("b=") {
            Some(i) => format!("{}b=", &tags[..i]),
            None => tags.to_string(),
        }
    }

    fn header_block(msg: &str) -> String {
        let n = msg.replace("\r\n", "\n");
        match n.find("\n\n") {
            Some(i) => to_crlf(&n[..i + 1]),
            None => msg.to_string(),
        }
    }

    fn collapse(v: &str) -> String {
        // relaxed-ish collapse for reading emitted values back as tag strings.
        let v = v.replace("\r\n", "").replace('\n', "");
        let mut out = String::new();
        let mut in_wsp = false;
        for c in v.chars() {
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

    fn verify(pk: &PublicKey, input: &str, sig_b64: &str) -> bool {
        let sig = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .unwrap();
        let vk = VerifyingKey::<Sha256>::new(pk.clone());
        let signature = rsa::pkcs1v15::Signature::try_from(sig.as_slice()).unwrap();
        vk.verify(input.as_bytes(), &signature).is_ok()
    }

    #[test]
    fn seal_round_trip() {
        let key = PrivateKey::new(&mut getrandom::SysRng, 2048).unwrap();
        let pk = PublicKey::from(&key);
        let s = Sealer::new("gw.example.com", "arc1", "gw.example.com", key)
            .unwrap()
            .with_now(Box::new(|| 1_700_000_000));

        let raw = "From: sender@ext.org\r\nTo: user@example.com\r\nSubject: hi\r\n\
             Date: Mon, 01 Jan 2026 00:00:00 +0000\r\nAuthentication-Results: gw.example.com; spf=pass\r\n\
             \r\nhello body\r\n";
        let sealed = s.seal(raw.as_bytes(), "spf=pass; dkim=fail").unwrap();
        let out = String::from_utf8(sealed).unwrap();

        assert!(out.starts_with("ARC-Seal:"), "ARC-Seal outermost");
        for h in [
            "ARC-Seal:",
            "ARC-Message-Signature:",
            "ARC-Authentication-Results:",
        ] {
            assert!(out.contains(h), "missing {h}");
        }

        let block = header_block(&out);
        let parsed = parse_headers(&block);
        let get = |name: &str| -> String {
            parsed
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(name))
                .map(|h| collapse(&h.value))
                .unwrap_or_default()
        };
        let aar = get("ARC-Authentication-Results");
        let ams = get("ARC-Message-Signature");
        let as_ = get("ARC-Seal");
        assert!(aar.contains("i=1;") && aar.contains("spf=pass; dkim=fail"));

        let ams_tags = parse_tags(&ams);
        assert!(!ams_tags.contains_key("cv"), "AMS has no cv");
        let (_h, body) = split(&out).unwrap();
        assert_eq!(ams_tags["bh"], b64(&sha256(relaxed_body(&body).as_bytes())));

        // Verify AMS signature.
        let present = select_headers(&block, &ams_tags["h"].split(':').collect::<Vec<_>>());
        let ams_input = ams_signing_input(&present, &empty_b(&ams));
        assert!(verify(&pk, &ams_input, &ams_tags["b"]), "AMS verifies");

        // Verify ARC-Seal signature.
        let as_tags = parse_tags(&as_);
        assert_eq!(as_tags["cv"], "none");
        let seal_input = seal_signing_input(&aar, &ams, &empty_b(&as_));
        assert!(verify(&pk, &seal_input, &as_tags["b"]), "ARC-Seal verifies");
    }

    #[test]
    fn disabled_when_missing_fields() {
        let key = PrivateKey::new(&mut getrandom::SysRng, 2048).unwrap();
        assert!(Sealer::new("", "s", "a", key).is_none());
    }
}
