//! DKIM (RFC 6376) verification and signing. Port of the Go `internal/dkimutil`:
//! verifies inbound signatures (rsa-sha256, simple/relaxed canonicalization,
//! TXT key lookup) before the gateway modifies the message, and re-signs the
//! rewritten message with the gateway key. Canonicalization works on raw bytes
//! so 8-bit content hashes exactly as transmitted.

use base64::Engine;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Pkcs1v15Sign, PrivateKey, PublicKey};
use sha2::{Digest, Sha256};

use crate::authres::sanitize;
use crate::dns::{DnsError, Resolver};

const MAX_VERIFICATIONS: usize = 5;

/// Headers recommended by RFC 6376 §5.4.1 plus the gateway's own marker.
const SIGNED_HEADERS: &[&str] = &[
    "From",
    "Reply-To",
    "Subject",
    "Date",
    "To",
    "Cc",
    "Message-ID",
    "In-Reply-To",
    "References",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
    "X-SecMail-Processed",
];

/// Per-signature outcome: the result and the signing domain (d=).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Result {
    /// pass | fail | temperror | permerror
    pub value: String,
    /// header.d ("" when the signature could not be parsed)
    pub domain: String,
}

/// Renders the RFC 8601 method list ("dkim=pass header.d=...").
pub fn auth_results(rs: &[Result]) -> String {
    if rs.is_empty() {
        return "dkim=none".into();
    }
    rs.iter()
        .map(|r| {
            if r.domain.is_empty() {
                format!("dkim={}", r.value)
            } else {
                format!("dkim={} header.d={}", r.value, sanitize(&r.domain))
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

// ---------------------------------------------------------------------------
// Message parsing

/// A raw header field: full bytes (including folding and the final CRLF) and
/// the lowercase field name.
pub(crate) struct Field {
    pub(crate) raw: Vec<u8>,
    pub(crate) name: String,
}

/// Normalizes bare LF to CRLF.
pub(crate) fn crlf(msg: &[u8]) -> Vec<u8> {
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

/// Splits a CRLF message into header fields and body.
pub(crate) fn split(msg: &[u8]) -> (Vec<Field>, &[u8]) {
    let (head, body) = match find(msg, b"\r\n\r\n") {
        Some(i) => (&msg[..i + 2], &msg[i + 4..]),
        None => (msg, &b""[..]),
    };
    let mut fields: Vec<Field> = Vec::new();
    let mut start = 0;
    while start < head.len() {
        let end = match find(&head[start..], b"\r\n") {
            Some(i) => start + i + 2,
            None => head.len(),
        };
        let line = &head[start..end];
        if (line[0] == b' ' || line[0] == b'\t') && !fields.is_empty() {
            fields.last_mut().unwrap().raw.extend_from_slice(line);
        } else if let Some(c) = line.iter().position(|&b| b == b':') {
            fields.push(Field {
                raw: line.to_vec(),
                name: String::from_utf8_lossy(&line[..c])
                    .trim()
                    .to_ascii_lowercase(),
            });
        }
        start = end;
    }
    (fields, body)
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

// ---------------------------------------------------------------------------
// Canonicalization

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Canon {
    Simple,
    Relaxed,
}

/// Canonicalizes one raw header field. Simple keeps it verbatim (with CRLF);
/// relaxed lowercases the name, unfolds, collapses WSP and trims, then CRLF.
pub(crate) fn canon_header(raw: &[u8], c: Canon) -> Vec<u8> {
    if c == Canon::Simple {
        return raw.to_vec();
    }
    let colon = raw.iter().position(|&b| b == b':').unwrap_or(raw.len());
    let name = String::from_utf8_lossy(&raw[..colon])
        .trim()
        .to_ascii_lowercase();
    let value = if colon < raw.len() {
        &raw[colon + 1..]
    } else {
        &[][..]
    };
    let mut v: Vec<u8> = Vec::with_capacity(value.len());
    let mut wsp = false;
    for &b in value {
        match b {
            b'\r' | b'\n' => {}
            b' ' | b'\t' => wsp = true,
            _ => {
                if wsp && !v.is_empty() {
                    v.push(b' ');
                }
                wsp = false;
                v.push(b);
            }
        }
    }
    let mut out = name.into_bytes();
    out.push(b':');
    out.extend_from_slice(&v);
    out.extend_from_slice(b"\r\n");
    out
}

/// Canonicalizes a CRLF body.
pub(crate) fn canon_body(body: &[u8], c: Canon) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let (line, next) = match find(rest, b"\r\n") {
            Some(i) => (&rest[..i], &rest[i + 2..]),
            None => (rest, &b""[..]),
        };
        lines.push(match c {
            Canon::Simple => line.to_vec(),
            Canon::Relaxed => {
                let mut l: Vec<u8> = Vec::with_capacity(line.len());
                let mut wsp = false;
                for &b in line {
                    if is_wsp(b) {
                        wsp = true;
                    } else {
                        if wsp {
                            l.push(b' ');
                        }
                        wsp = false;
                        l.push(b);
                    }
                }
                l
            }
        });
        rest = next;
    }
    while lines.last().map(|l| l.is_empty()).unwrap_or(false) {
        lines.pop();
    }
    let mut out = Vec::with_capacity(body.len() + 2);
    if lines.is_empty() {
        if c == Canon::Simple {
            out.extend_from_slice(b"\r\n");
        }
        return out;
    }
    for l in lines {
        out.extend_from_slice(&l);
        out.extend_from_slice(b"\r\n");
    }
    out
}

// ---------------------------------------------------------------------------
// Tag lists

fn parse_tags(value: &str) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    for part in value.split(';') {
        let p = part.trim_matches(|c: char| c.is_ascii_whitespace());
        if p.is_empty() {
            continue;
        }
        let (k, v) = p.split_once('=')?;
        let k = k.trim().to_string();
        if k.is_empty() || out.iter().any(|(e, _): &(String, String)| *e == k) {
            return None; // duplicate tags are invalid (RFC 6376 §3.2)
        }
        out.push((k, v.trim().to_string()));
    }
    Some(out)
}

fn tag<'a>(tags: &'a [(String, String)], k: &str) -> Option<&'a str> {
    tags.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

fn strip_fws(s: &str) -> String {
    s.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}

/// Returns the raw DKIM-Signature field with the b= tag value removed.
fn without_b(raw: &[u8]) -> Vec<u8> {
    let colon = raw
        .iter()
        .position(|&b| b == b':')
        .map(|i| i + 1)
        .unwrap_or(0);
    let mut out = raw[..colon].to_vec();
    let value = &raw[colon..];
    let mut i = 0;
    let mut seg_start = 0;
    while i <= value.len() {
        if i == value.len() || value[i] == b';' {
            let seg = &value[seg_start..i];
            let eq = seg.iter().position(|&b| b == b'=');
            let is_b = eq
                .map(|e| {
                    let name: Vec<u8> = seg[..e]
                        .iter()
                        .copied()
                        .filter(|b| !b.is_ascii_whitespace())
                        .collect();
                    name == b"b"
                })
                .unwrap_or(false);
            if is_b {
                let e = eq.unwrap();
                out.extend_from_slice(&seg[..e + 1]);
                // Keep a trailing CRLF if the b= tag ended the field.
                if seg.ends_with(b"\r\n") {
                    out.extend_from_slice(b"\r\n");
                }
            } else {
                out.extend_from_slice(seg);
            }
            if i < value.len() {
                out.push(b';');
            }
            seg_start = i + 1;
        }
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Verification

enum Fail {
    Perm,
    Temp,
    Bad,
}

impl Fail {
    fn value(&self) -> &'static str {
        match self {
            Fail::Perm => "permerror",
            Fail::Temp => "temperror",
            Fail::Bad => "fail",
        }
    }
}

/// Minimum accepted RSA modulus (RFC 8301 §3.2: keys < 1024 bits must not be
/// considered valid).
const MIN_KEY_BITS: u32 = 1024;

/// A signature whose cheap checks and body hash succeeded; only the key lookup
/// and header-hash verification remain.
struct Pending {
    sig_idx: usize,
    selector: String,
    h: Vec<String>,
    hc: Canon,
    b: Vec<u8>,
}

struct PreparedSig {
    domain: String,
    stage: std::result::Result<Pending, Fail>,
}

/// DKIM signatures parsed and body-hashed: the CPU-bound part of verification
/// (proportional to the message size), done synchronously so callers can run
/// it on a blocking thread. Finish with [`verify_prepared`].
pub struct Prepared {
    fields: Vec<Field>,
    sigs: Vec<PreparedSig>,
}

/// Parses and body-hashes up to five DKIM signatures (no I/O).
pub fn prepare(msg: &[u8]) -> Prepared {
    let msg = crlf(msg);
    let (fields, body) = split(&msg);
    let sigs = fields
        .iter()
        .enumerate()
        .filter(|(_, f)| f.name == "dkim-signature")
        .take(MAX_VERIFICATIONS)
        .map(|(idx, f)| prepare_one(idx, f, body))
        .collect();
    Prepared { fields, sigs }
}

/// Verifies up to five DKIM signatures. An empty vector means the message
/// carried no signatures.
pub async fn verify<R: Resolver + ?Sized>(msg: &[u8], resolver: &R) -> Vec<Result> {
    verify_prepared(&prepare(msg), resolver).await
}

/// Completes verification of [`prepare`]d signatures (key lookups).
pub async fn verify_prepared<R: Resolver + ?Sized>(p: &Prepared, resolver: &R) -> Vec<Result> {
    let mut out = Vec::new();
    for s in &p.sigs {
        let res = match &s.stage {
            Err(f) => Err(f.value()),
            Ok(pending) => finish_one(&p.fields, pending, &s.domain, resolver)
                .await
                .map_err(|f| f.value()),
        };
        out.push(Result {
            value: res.err().unwrap_or("pass").into(),
            domain: s.domain.clone(),
        });
    }
    out
}

fn prepare_one(sig_idx: usize, sig: &Field, body: &[u8]) -> PreparedSig {
    let colon = sig.raw.iter().position(|&b| b == b':').unwrap_or(0);
    let value = String::from_utf8_lossy(&sig.raw[colon + 1..]).into_owned();
    let tags = match parse_tags(&value) {
        Some(t) => t,
        None => {
            return PreparedSig {
                domain: String::new(),
                stage: Err(Fail::Perm),
            }
        }
    };
    let domain = tag(&tags, "d")
        .map(|d| d.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let stage = (|| {
        if tag(&tags, "v") != Some("1") {
            return Err(Fail::Perm);
        }
        let alg = tag(&tags, "a").ok_or(Fail::Perm)?.to_ascii_lowercase();
        if alg != "rsa-sha256" {
            return Err(Fail::Perm);
        }
        let selector = tag(&tags, "s").ok_or(Fail::Perm)?.trim();
        if domain.is_empty() || selector.is_empty() {
            return Err(Fail::Perm);
        }
        let b = base64::engine::general_purpose::STANDARD
            .decode(strip_fws(tag(&tags, "b").ok_or(Fail::Perm)?))
            .map_err(|_| Fail::Perm)?;
        let bh = base64::engine::general_purpose::STANDARD
            .decode(strip_fws(tag(&tags, "bh").ok_or(Fail::Perm)?))
            .map_err(|_| Fail::Perm)?;
        let h: Vec<String> = strip_fws(tag(&tags, "h").ok_or(Fail::Perm)?)
            .split(':')
            .map(|s| s.to_ascii_lowercase())
            .collect();
        if !h.iter().any(|n| n == "from") {
            return Err(Fail::Perm);
        }
        let (hc, bc) = match tag(&tags, "c").map(|c| c.trim().to_ascii_lowercase()) {
            None => (Canon::Simple, Canon::Simple),
            Some(c) => {
                let (a, b) = c.split_once('/').unwrap_or((c.as_str(), "simple"));
                (parse_canon(a)?, parse_canon(b)?)
            }
        };
        if let Some(i) = tag(&tags, "i") {
            let idom = i
                .rsplit_once('@')
                .map(|(_, d)| d)
                .unwrap_or("")
                .to_ascii_lowercase();
            if idom != domain && !idom.ends_with(&format!(".{domain}")) {
                return Err(Fail::Perm);
            }
        }
        if let Some(x) = tag(&tags, "x") {
            let x: i64 = x.trim().parse().map_err(|_| Fail::Perm)?;
            if x < chrono::Utc::now().timestamp() {
                return Err(Fail::Perm); // signature expired
            }
        }

        // Body hash.
        let cb = canon_body(body, bc);
        if let Some(l) = tag(&tags, "l") {
            let l: usize = l.trim().parse().map_err(|_| Fail::Perm)?;
            if l > cb.len() {
                return Err(Fail::Perm);
            }
            // l= lets anyone append unsigned content (RFC 6376 §8.2) — e.g. a
            // phishing body after a signed newsletter. A signature that does
            // not cover the whole body is treated as failing.
            if l < cb.len() {
                return Err(Fail::Bad);
            }
        }
        if Sha256::digest(&cb).as_slice() != bh.as_slice() {
            return Err(Fail::Bad);
        }
        Ok(Pending {
            sig_idx,
            selector: selector.to_string(),
            h,
            hc,
            b,
        })
    })();
    PreparedSig { domain, stage }
}

async fn finish_one<R: Resolver + ?Sized>(
    fields: &[Field],
    p: &Pending,
    domain: &str,
    resolver: &R,
) -> std::result::Result<(), Fail> {
    let key = lookup_key(resolver, &p.selector, domain).await?;

    // Header hash: each h= name picks the next unused instance bottom-up.
    let mut used = vec![false; fields.len()];
    used[p.sig_idx] = true;
    let mut data: Vec<u8> = Vec::new();
    for name in &p.h {
        if let Some(i) = (0..fields.len())
            .rev()
            .find(|&i| !used[i] && fields[i].name == *name)
        {
            used[i] = true;
            data.extend_from_slice(&canon_header(&fields[i].raw, p.hc));
        }
    }
    let mut own = canon_header(&without_b(&fields[p.sig_idx].raw), p.hc);
    if own.ends_with(b"\r\n") {
        own.truncate(own.len() - 2);
    }
    data.extend_from_slice(&own);
    let digest = Sha256::digest(&data);
    key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &p.b)
        .map_err(|_| Fail::Bad)
}

fn parse_canon(s: &str) -> std::result::Result<Canon, Fail> {
    match s {
        "simple" => Ok(Canon::Simple),
        "relaxed" => Ok(Canon::Relaxed),
        _ => Err(Fail::Perm),
    }
}

async fn lookup_key<R: Resolver + ?Sized>(
    r: &R,
    selector: &str,
    domain: &str,
) -> std::result::Result<PublicKey, Fail> {
    let txts = match r.txt(&format!("{selector}._domainkey.{domain}")).await {
        Ok(t) => t,
        Err(DnsError::NotFound) => return Err(Fail::Perm),
        Err(DnsError::Temp(_)) => return Err(Fail::Temp),
    };
    let rec = txts.first().ok_or(Fail::Perm)?;
    let tags = parse_tags(rec).ok_or(Fail::Perm)?;
    if let Some(v) = tag(&tags, "v") {
        if v != "DKIM1" {
            return Err(Fail::Perm);
        }
    }
    if let Some(k) = tag(&tags, "k") {
        if !k.eq_ignore_ascii_case("rsa") {
            return Err(Fail::Perm);
        }
    }
    let p = strip_fws(tag(&tags, "p").ok_or(Fail::Perm)?);
    if p.is_empty() {
        return Err(Fail::Perm); // revoked key
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(p)
        .map_err(|_| Fail::Perm)?;
    let key = PublicKey::from_public_key_der(&der)
        .or_else(|_| PublicKey::from_pkcs1_der(&der))
        .map_err(|_| Fail::Perm)?;
    if rsa::traits::PublicKeyParts::n(&key).bit_width() < MIN_KEY_BITS {
        return Err(Fail::Perm); // weak key
    }
    Ok(key)
}

// ---------------------------------------------------------------------------
// Signing

/// Signs outgoing (rewritten) messages with relaxed/relaxed rsa-sha256.
pub struct Signer {
    domain: String,
    selector: String,
    key: PrivateKey,
    now: fn() -> i64,
}

impl Signer {
    pub fn new(domain: &str, selector: &str, key: PrivateKey) -> Self {
        Signer {
            domain: domain.into(),
            selector: selector.into(),
            key,
            now: || chrono::Utc::now().timestamp(),
        }
    }

    /// Loads a PEM private key (PKCS#1 or PKCS#8 RSA).
    pub fn load(domain: &str, selector: &str, pem: &str) -> std::result::Result<Self, String> {
        if domain.is_empty() || selector.is_empty() {
            return Err("dkim: domain and selector are required".into());
        }
        let key = PrivateKey::from_pkcs1_pem(pem)
            .or_else(|_| PrivateKey::from_pkcs8_pem(pem))
            .map_err(|e| format!("dkim: parse key: {e}"))?;
        Ok(Self::new(domain, selector, key))
    }

    /// Returns `msg` with a DKIM-Signature header prepended.
    pub fn sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, String> {
        let msg = crlf(msg);
        let (fields, body) = split(&msg);
        let bh = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(canon_body(body, Canon::Relaxed)));

        // Signed header list: present headers, bottom-up instance selection.
        let mut used = vec![false; fields.len()];
        let mut names: Vec<String> = Vec::new();
        let mut data: Vec<u8> = Vec::new();
        for want in SIGNED_HEADERS {
            let lw = want.to_ascii_lowercase();
            if let Some(i) = (0..fields.len())
                .rev()
                .find(|&i| !used[i] && fields[i].name == lw)
            {
                used[i] = true;
                names.push(want.to_string());
                data.extend_from_slice(&canon_header(&fields[i].raw, Canon::Relaxed));
            }
        }
        if !names.iter().any(|n| n.eq_ignore_ascii_case("from")) {
            return Err("dkim: message has no From header".into());
        }
        let t = (self.now)();
        let x = t + 30 * 24 * 3600;
        let head = format!(
            "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={};\r\n\tt={}; x={}; h={};\r\n\tbh={};\r\n\tb=",
            self.domain,
            self.selector,
            t,
            x,
            names.join(":"),
            bh
        );
        let mut own = canon_header(format!("{head}\r\n").as_bytes(), Canon::Relaxed);
        own.truncate(own.len() - 2);
        data.extend_from_slice(&own);
        let sig = self
            .key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&data))
            .map_err(|e| format!("dkim: sign: {e}"))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(sig);
        let mut header = head;
        for (i, chunk) in b64.as_bytes().chunks(72).enumerate() {
            if i > 0 {
                header.push_str("\r\n\t");
            }
            header.push_str(std::str::from_utf8(chunk).unwrap());
        }
        header.push_str("\r\n");
        let mut out = header.into_bytes();
        out.extend_from_slice(&msg);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Static;
    use rsa::pkcs8::EncodePublicKey;

    fn key() -> PrivateKey {
        PrivateKey::new(&mut getrandom::SysRng, 1024).unwrap()
    }

    fn txt_for(k: &PrivateKey) -> String {
        let der = k.to_public_key().to_public_key_der().unwrap();
        format!(
            "v=DKIM1; k=rsa; p={}",
            base64::engine::general_purpose::STANDARD.encode(der.as_bytes())
        )
    }

    const MSG: &[u8] = b"From: Alice <alice@example.com>\r\nTo: bob@example.net\r\nSubject:  Hello   there\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nHi Bob,  \r\nthis is a test.\r\n\r\n\r\n";

    #[tokio::test]
    async fn sign_verify_roundtrip() {
        let k = key();
        let r = Static::default().with_txt("sel._domainkey.example.com", &[&txt_for(&k)]);
        let s = Signer::new("example.com", "sel", k);
        let signed = s.sign(MSG).unwrap();
        let res = verify(&signed, &r).await;
        assert_eq!(
            res,
            vec![Result {
                value: "pass".into(),
                domain: "example.com".into()
            }]
        );
        assert_eq!(auth_results(&res), "dkim=pass header.d=example.com");

        // Relaxed canonicalization tolerates whitespace changes and LF endings.
        let lf = String::from_utf8(signed.clone())
            .unwrap()
            .replace("Subject:  Hello   there", "Subject: Hello there")
            .replace("\r\n", "\n");
        assert_eq!(verify(lf.as_bytes(), &r).await[0].value, "pass");

        // A body change breaks the body hash.
        let tampered = String::from_utf8(signed.clone())
            .unwrap()
            .replace("a test", "a tesT");
        assert_eq!(verify(tampered.as_bytes(), &r).await[0].value, "fail");

        // A signed header change breaks the signature.
        let tampered = String::from_utf8(signed)
            .unwrap()
            .replace("To: bob", "To: eve");
        assert_eq!(verify(tampered.as_bytes(), &r).await[0].value, "fail");
    }

    #[tokio::test]
    async fn missing_key_and_temp() {
        let k = key();
        let signed = Signer::new("example.com", "sel", k).sign(MSG).unwrap();
        assert_eq!(
            verify(&signed, &Static::default()).await[0].value,
            "permerror"
        );
        let r = Static::default().with_temp("sel._domainkey.example.com");
        assert_eq!(verify(&signed, &r).await[0].value, "temperror");
        assert!(verify(MSG, &r).await.is_empty());
        assert_eq!(auth_results(&[]), "dkim=none");
    }

    #[test]
    fn canonicalization() {
        assert_eq!(canon_body(b"", Canon::Simple), b"\r\n");
        assert_eq!(canon_body(b"", Canon::Relaxed), b"");
        assert_eq!(canon_body(b"a  b \t\r\n\r\n", Canon::Relaxed), b"a b\r\n");
        assert_eq!(canon_body(b"a  b \r\n\r\n", Canon::Simple), b"a  b \r\n");
        assert_eq!(
            canon_header(b"SubJect:\t Hi \r\n  there \r\n", Canon::Relaxed),
            b"subject:Hi there\r\n"
        );
        assert_eq!(
            without_b(b"DKIM-Signature: a=1; bh=xyz; b=ab\r\n cd\r\n"),
            b"DKIM-Signature: a=1; bh=xyz; b=\r\n"
        );
    }

    /// RFC 6376 Appendix A-style simple/simple signature produced by a third
    /// party implementation must verify too: emulate by signing with
    /// simple canonicalization manually.
    #[tokio::test]
    async fn verifies_simple_canonicalization() {
        let k = key();
        let r = Static::default().with_txt("s1._domainkey.example.org", &[&txt_for(&k)]);
        let body = b"Hello\r\n\r\n";
        let bh = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(canon_body(body, Canon::Simple)));
        let from = b"From: joe@example.org\r\n";
        let head =
            format!("DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=s1; h=from; bh={bh}; b=");
        let mut data = from.to_vec();
        data.extend_from_slice(head.as_bytes());
        let sig = k
            .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&data))
            .unwrap();
        let msg = format!(
            "{head}{}\r\nFrom: joe@example.org\r\n\r\nHello\r\n\r\n",
            base64::engine::general_purpose::STANDARD.encode(sig)
        );
        assert_eq!(verify(msg.as_bytes(), &r).await[0].value, "pass");
        // Simple header canon is whitespace-sensitive.
        let msg2 = msg.replace("From: joe", "From:  joe");
        assert_eq!(verify(msg2.as_bytes(), &r).await[0].value, "fail");
    }

    #[tokio::test]
    async fn weak_keys_are_rejected() {
        // A 512-bit RSA public key (RFC 8301: < 1024 bits must not verify).
        const WEAK: &str = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANbA+GHz2t4epOPS8NUqaizBBpTOXJp6jVL2ZjDGOUggJl+bkmTcgR0Umc+dOZhB5/Go/AyGBmfifhI31leyqoMCAwEAAQ==";
        let r = Static::default().with_txt(
            "sel._domainkey.example.com",
            &[&format!("v=DKIM1; k=rsa; p={WEAK}")],
        );
        let signed = Signer::new("example.com", "sel", key()).sign(MSG).unwrap();
        assert_eq!(verify(&signed, &r).await[0].value, "permerror");
    }

    /// Signs `body` with simple/simple and the given l= over its canonical
    /// form truncated to `l` bytes.
    fn sign_with_l(k: &PrivateKey, body: &[u8], l: usize) -> String {
        let mut cb = canon_body(body, Canon::Simple);
        cb.truncate(l);
        let bh = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&cb));
        let head = format!(
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=s1; h=from; l={l}; bh={bh}; b="
        );
        let mut data = b"From: joe@example.org\r\n".to_vec();
        data.extend_from_slice(head.as_bytes());
        let sig = k
            .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&data))
            .unwrap();
        format!(
            "{head}{}\r\nFrom: joe@example.org\r\n\r\n{}",
            base64::engine::general_purpose::STANDARD.encode(sig),
            String::from_utf8_lossy(body)
        )
    }

    #[tokio::test]
    async fn partial_body_length_fails() {
        let k = key();
        let r = Static::default().with_txt("s1._domainkey.example.org", &[&txt_for(&k)]);
        let body = b"Signed newsletter\r\n";
        // l= covering the whole body verifies.
        let full = sign_with_l(&k, body, body.len());
        assert_eq!(verify(full.as_bytes(), &r).await[0].value, "pass");
        // Content appended after the signed prefix: fail, not pass.
        let appended = format!("{full}Click http://phish.example/\r\n");
        assert_eq!(verify(appended.as_bytes(), &r).await[0].value, "fail");
    }

    #[tokio::test]
    async fn prepare_then_verify_matches_verify() {
        let k = key();
        let r = Static::default().with_txt("sel._domainkey.example.com", &[&txt_for(&k)]);
        let signed = Signer::new("example.com", "sel", k).sign(MSG).unwrap();
        let p = std::thread::spawn(move || prepare(&signed)).join().unwrap();
        assert_eq!(verify_prepared(&p, &r).await[0].value, "pass");
    }
}
