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

/// Canonicalizes a CRLF body in one pass with no per-line allocation:
/// trailing empty lines are counted and only emitted when content follows.
pub(crate) fn canon_body(body: &[u8], c: Canon) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 2);
    let mut pending_empty = 0usize;
    let mut rest = body;
    while !rest.is_empty() {
        let (line, next) = match find(rest, b"\r\n") {
            Some(i) => (&rest[..i], &rest[i + 2..]),
            None => (rest, &b""[..]),
        };
        rest = next;
        let empty = match c {
            Canon::Simple => line.is_empty(),
            Canon::Relaxed => line.iter().all(|&b| is_wsp(b)),
        };
        if empty {
            pending_empty += 1;
            continue;
        }
        for _ in 0..pending_empty {
            out.extend_from_slice(b"\r\n");
        }
        pending_empty = 0;
        match c {
            Canon::Simple => out.extend_from_slice(line),
            Canon::Relaxed => {
                let mut wsp = false;
                for &b in line {
                    if is_wsp(b) {
                        wsp = true;
                    } else {
                        if wsp {
                            out.push(b' ');
                        }
                        wsp = false;
                        out.push(b);
                    }
                }
            }
        }
        out.extend_from_slice(b"\r\n");
    }
    if out.is_empty() && c == Canon::Simple {
        out.extend_from_slice(b"\r\n");
    }
    out
}
// ---------------------------------------------------------------------------
// Tag lists

/// Most tags accepted in one tag list (DKIM-Signature, ARC-*, key record);
/// real ones carry about a dozen. More is a permanent error.
pub(crate) const MAX_TAGS: usize = 64;

/// Longest tag list parsed, in bytes; longer is a permanent error.
pub(crate) const MAX_TAG_LIST: usize = 16 * 1024;

/// Parses a tag=value list. None (a permanent error) for a malformed list,
/// a duplicate tag (RFC 6376 §3.2), more than [`MAX_TAGS`] tags or more
/// than [`MAX_TAG_LIST`] bytes. Linear in the input.
pub(crate) fn parse_tags(value: &str) -> Option<Vec<(String, String)>> {
    if value.len() > MAX_TAG_LIST {
        return None;
    }
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for part in value.split(';') {
        let p = part.trim_matches(|c: char| c.is_ascii_whitespace());
        if p.is_empty() {
            continue;
        }
        if out.len() >= MAX_TAGS {
            return None;
        }
        let (k, v) = p.split_once('=')?;
        let k = k.trim().to_string();
        if k.is_empty() || !seen.insert(k.clone()) {
            return None; // duplicate tags are invalid (RFC 6376 §3.2)
        }
        out.push((k, v.trim().to_string()));
    }
    Some(out)
}

pub(crate) fn tag<'a>(tags: &'a [(String, String)], k: &str) -> Option<&'a str> {
    tags.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

pub(crate) fn strip_fws(s: &str) -> String {
    s.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}

/// Returns the raw DKIM-Signature field with the b= tag value removed.
pub(crate) fn without_b(raw: &[u8]) -> Vec<u8> {
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

pub(crate) enum Fail {
    Perm,
    Temp,
    Bad,
}

impl Fail {
    pub(crate) fn value(&self) -> &'static str {
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

/// Most entries accepted in a signature's h= list (more is a permerror): the
/// header hash is built before any key is fetched, so its cost must be
/// bounded independently of the attacker's DNS.
pub(crate) const MAX_H: usize = 64;

/// A signature whose cheap checks, body hash and header hash are done; only
/// the key lookup and the RSA verification remain.
struct Pending {
    selector: String,
    /// SHA-256 of the canonicalized signed headers + signature field.
    digest: Vec<u8>,
    b: Vec<u8>,
}

struct PreparedSig {
    domain: String,
    stage: std::result::Result<Pending, Fail>,
}

/// DKIM signatures parsed, body-hashed and header-hashed: all the CPU-bound
/// work of verification (proportional to the message size), done
/// synchronously so callers can run it on a blocking thread. Finish with
/// [`verify_prepared`] (key lookups + one RSA verification per signature).
pub struct Prepared {
    sigs: Vec<PreparedSig>,
}

/// Lowercase field name → field indices (top to bottom), built once per
/// message so h= selection is linear.
pub(crate) fn name_index(fields: &[Field]) -> std::collections::HashMap<&str, Vec<usize>> {
    let mut m: std::collections::HashMap<&str, Vec<usize>> = std::collections::HashMap::new();
    for (i, f) in fields.iter().enumerate() {
        m.entry(f.name.as_str()).or_default().push(i);
    }
    m
}

/// Canonicalized signed headers for an h= list: each name picks the next
/// unused instance bottom-up (`skip` — the signature itself — is never
/// picked). Linear in |h| + |fields|.
pub(crate) fn signed_headers(
    fields: &[Field],
    index: &std::collections::HashMap<&str, Vec<usize>>,
    h: &[String],
    skip: usize,
    c: Canon,
) -> Vec<u8> {
    let mut cursor: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    let mut data = Vec::new();
    for name in h {
        let Some(list) = index.get(name.as_str()) else {
            continue;
        };
        let pos = cursor.entry(name.as_str()).or_insert(list.len());
        while *pos > 0 {
            *pos -= 1;
            let i = list[*pos];
            if i != skip {
                data.extend_from_slice(&canon_header(&fields[i].raw, c));
                break;
            }
        }
    }
    data
}

/// Canonicalized bodies, computed at most once per canonicalization.
#[derive(Default)]
pub(crate) struct BodyCache {
    simple: Option<Vec<u8>>,
    relaxed: Option<Vec<u8>>,
}

impl BodyCache {
    pub(crate) fn get(&mut self, body: &[u8], c: Canon) -> &[u8] {
        let slot = match c {
            Canon::Simple => &mut self.simple,
            Canon::Relaxed => &mut self.relaxed,
        };
        slot.get_or_insert_with(|| canon_body(body, c))
    }
}

/// Parses, body-hashes and header-hashes up to five DKIM signatures (no I/O).
pub fn prepare(msg: &[u8]) -> Prepared {
    let msg = crlf(msg);
    let (fields, body) = split(&msg);
    let index = name_index(&fields);
    let mut cache = BodyCache::default();
    let sigs = fields
        .iter()
        .enumerate()
        .filter(|(_, f)| f.name == "dkim-signature")
        .take(MAX_VERIFICATIONS)
        .map(|(idx, f)| prepare_one(idx, f, &fields, &index, body, &mut cache))
        .collect();
    Prepared { sigs }
}

/// Verifies up to five DKIM signatures. An empty vector means the message
/// carried no signatures. The CPU-bound part runs on the blocking pool when
/// called inside a multi-threaded Tokio runtime.
pub async fn verify<R: Resolver + ?Sized>(msg: &[u8], resolver: &R) -> Vec<Result> {
    let prepared = match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            let owned = msg.to_vec();
            match tokio::task::spawn_blocking(move || prepare(&owned)).await {
                Ok(p) => p,
                Err(_) => prepare(msg),
            }
        }
        _ => prepare(msg),
    };
    verify_prepared(&prepared, resolver).await
}

/// Completes verification of [`prepare`]d signatures (key lookups).
pub async fn verify_prepared<R: Resolver + ?Sized>(p: &Prepared, resolver: &R) -> Vec<Result> {
    let mut out = Vec::new();
    for s in &p.sigs {
        let res = match &s.stage {
            Err(f) => Err(f.value()),
            Ok(pending) => finish_one(pending, &s.domain, resolver)
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

fn prepare_one(
    sig_idx: usize,
    sig: &Field,
    fields: &[Field],
    index: &std::collections::HashMap<&str, Vec<usize>>,
    body: &[u8],
    cache: &mut BodyCache,
) -> PreparedSig {
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
        let h = parse_h(tag(&tags, "h").ok_or(Fail::Perm)?)?;
        if !h.iter().any(|n| n == "from") {
            return Err(Fail::Perm);
        }
        let b = base64::engine::general_purpose::STANDARD
            .decode(strip_fws(tag(&tags, "b").ok_or(Fail::Perm)?))
            .map_err(|_| Fail::Perm)?;
        let bh = base64::engine::general_purpose::STANDARD
            .decode(strip_fws(tag(&tags, "bh").ok_or(Fail::Perm)?))
            .map_err(|_| Fail::Perm)?;
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

        // Body hash (canonical bodies are shared between signatures).
        let cb = cache.get(body, bc);
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
        if Sha256::digest(cb).as_slice() != bh.as_slice() {
            return Err(Fail::Bad);
        }

        // Header hash: each h= name picks the next unused instance bottom-up.
        let mut data = signed_headers(fields, index, &h, sig_idx, hc);
        let mut own = canon_header(&without_b(&sig.raw), hc);
        if own.ends_with(b"\r\n") {
            own.truncate(own.len() - 2);
        }
        data.extend_from_slice(&own);
        Ok(Pending {
            selector: selector.to_string(),
            digest: Sha256::digest(&data).to_vec(),
            b,
        })
    })();
    PreparedSig { domain, stage }
}

/// Parses an h= list (lowercased); more than [`MAX_H`] entries is a
/// permerror.
pub(crate) fn parse_h(v: &str) -> std::result::Result<Vec<String>, Fail> {
    let v = strip_fws(v);
    if v.split(':').nth(MAX_H).is_some() {
        return Err(Fail::Perm);
    }
    Ok(v.split(':').map(|s| s.to_ascii_lowercase()).collect())
}

async fn finish_one<R: Resolver + ?Sized>(
    p: &Pending,
    domain: &str,
    resolver: &R,
) -> std::result::Result<(), Fail> {
    let key = lookup_key(resolver, &p.selector, domain).await?;
    verify_digest(&key, &p.digest, &p.b)
}

/// RSA-SHA256 PKCS#1 v1.5 verification of a precomputed digest.
pub(crate) fn verify_digest(
    key: &PublicKey,
    digest: &[u8],
    sig: &[u8],
) -> std::result::Result<(), Fail> {
    key.verify(Pkcs1v15Sign::new::<Sha256>(), digest, sig)
        .map_err(|_| Fail::Bad)
}
pub(crate) fn parse_canon(s: &str) -> std::result::Result<Canon, Fail> {
    match s {
        "simple" => Ok(Canon::Simple),
        "relaxed" => Ok(Canon::Relaxed),
        _ => Err(Fail::Perm),
    }
}

pub(crate) async fn lookup_key<R: Resolver + ?Sized>(
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

/// Round-2 review regressions: h= / header-field CPU DoS.
#[cfg(test)]
mod r2_tests {
    use super::*;
    use crate::dns::Static;
    use rsa::pkcs8::EncodePublicKey;

    fn keyed() -> (PrivateKey, Static) {
        let k = PrivateKey::new(&mut getrandom::SysRng, 1024).unwrap();
        let der = k.to_public_key().to_public_key_der().unwrap();
        let txt = format!(
            "v=DKIM1; k=rsa; p={}",
            base64::engine::general_purpose::STANDARD.encode(der.as_bytes())
        );
        let r = Static::default().with_txt("s1._domainkey.attacker.net", &[&txt]);
        (k, r)
    }

    /// Signs `fields` + body with simple/simple over the given h= list.
    fn sign(k: &PrivateKey, h: &[&str], fields: &str, body: &str) -> String {
        let bh = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(canon_body(body.as_bytes(), Canon::Simple)));
        let head = format!(
            "DKIM-Signature: v=1; a=rsa-sha256; d=attacker.net; s=s1; h={}; bh={bh}; b=",
            h.join(":")
        );
        let msg = crlf(format!("{head}\r\n{fields}\r\n{body}").as_bytes());
        let (fl, _) = split(&msg);
        let idx = name_index(&fl);
        let hs: Vec<String> = h.iter().map(|s| s.to_ascii_lowercase()).collect();
        let mut data = signed_headers(&fl, &idx, &hs, 0, Canon::Simple);
        data.extend_from_slice(head.as_bytes());
        let sig = k
            .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&data))
            .unwrap();
        format!(
            "{head}{}\r\n{fields}\r\n{body}",
            base64::engine::general_purpose::STANDARD.encode(sig)
        )
    }

    #[tokio::test]
    async fn huge_h_lists_are_refused_quickly() {
        let (_k, r) = keyed();
        for (nh, nf) in [(20_000usize, 20_000usize), (40_000, 40_000)] {
            let bh = base64::engine::general_purpose::STANDARD
                .encode(Sha256::digest(canon_body(b"hi\r\n", Canon::Simple)));
            let mut msg = format!(
                "DKIM-Signature: v=1; a=rsa-sha256; d=attacker.net; s=s1; h=from{}; bh={bh}; b=AAAA\r\n",
                ":x".repeat(nh)
            );
            for _ in 0..nf {
                msg.push_str("Y: z\r\n");
            }
            msg.push_str("From: a@attacker.net\r\n\r\nhi\r\n");
            let t = std::time::Instant::now();
            let res = verify(msg.as_bytes(), &r).await;
            eprintln!(
                "R2PERF dkim h={nh} fields={nf} ({} KB): {:?}",
                msg.len() / 1024,
                t.elapsed()
            );
            assert_eq!(res[0].value, "permerror");
            assert!(
                t.elapsed() < std::time::Duration::from_secs(2),
                "{:?}",
                t.elapsed()
            );
        }
    }

    #[tokio::test]
    async fn many_fields_and_max_h_stay_linear() {
        let (k, r) = keyed();
        // 64 h= entries over 100k header fields, five signatures: verifies,
        // and quickly.
        let mut fields = String::new();
        for _ in 0..100_000 {
            fields.push_str("X: z\r\n");
        }
        fields.push_str("From: a@attacker.net\r\n");
        let mut h = vec!["from"];
        h.extend(std::iter::repeat("x").take(63));
        let one = sign(&k, &h, &fields, "hi\r\n");
        let t = std::time::Instant::now();
        let res = verify(one.as_bytes(), &r).await;
        assert_eq!(res[0].value, "pass");
        let el = t.elapsed();
        eprintln!("R2PERF dkim 64 h= over 100k fields: {el:?}");
        assert!(el < std::time::Duration::from_secs(5), "{el:?}");
        // 65 entries: permerror.
        h.push("x");
        let two = sign(&k, &h, "From: a@attacker.net\r\n", "hi\r\n");
        assert_eq!(verify(two.as_bytes(), &r).await[0].value, "permerror");
    }

    #[tokio::test]
    async fn header_selection_is_bottom_up_and_skips_missing() {
        let (k, r) = keyed();
        // h= names a header twice and one that is absent (null string).
        let fields = "Subject: top\r\nFrom: a@attacker.net\r\nSubject: bottom\r\n";
        let m = sign(
            &k,
            &["from", "subject", "subject", "subject", "to"],
            fields,
            "b\r\n",
        );
        assert_eq!(verify(m.as_bytes(), &r).await[0].value, "pass");
        // Adding a To afterwards breaks it (it was signed as absent).
        let added = m.replace("\r\n\r\nb\r\n", "\r\nTo: x@y\r\n\r\nb\r\n");
        assert_eq!(verify(added.as_bytes(), &r).await[0].value, "fail");
        let swapped = m.replace("Subject: top", "Subject: TOP");
        assert_eq!(verify(swapped.as_bytes(), &r).await[0].value, "fail");
    }

    #[test]
    fn canon_body_matches_reference() {
        for (body, s, rl) in [
            (&b""[..], &b"\r\n"[..], &b""[..]),
            (b"\r\n\r\n", b"\r\n", b""),
            (
                b"a\r\n\r\n \r\nb  \t\r\n\r\n",
                b"a\r\n\r\n \r\nb  \t\r\n",
                b"a\r\n\r\n\r\nb\r\n",
            ),
            (b"x", b"x\r\n", b"x\r\n"),
            (b" \t \r\n", b" \t \r\n", b""),
        ] {
            assert_eq!(canon_body(body, Canon::Simple), s);
            assert_eq!(canon_body(body, Canon::Relaxed), rl);
        }
    }
}

/// Round-3 review regressions: bounded tag-list parsing.
#[cfg(test)]
mod r3_tests {
    use super::*;

    #[test]
    fn tag_lists_are_bounded() {
        let ok = (0..MAX_TAGS)
            .map(|k| format!("t{k}=x"))
            .collect::<Vec<_>>()
            .join("; ");
        assert_eq!(parse_tags(&ok).unwrap().len(), MAX_TAGS);
        assert!(parse_tags(&format!("{ok}; extra=1")).is_none());
        assert!(parse_tags("a=1; b=2; a=3").is_none());
        assert!(parse_tags(&format!("a={}", "x".repeat(MAX_TAG_LIST))).is_none());
    }

    #[tokio::test]
    async fn huge_signature_is_a_quick_permerror() {
        let mut v =
            String::from("DKIM-Signature: v=1; a=rsa-sha256; d=x; s=y; h=from; bh=AAAA; b=AAAA");
        for k in 0..60_000 {
            v.push_str(&format!("; t{k}=x"));
        }
        let msg = format!("{v}\r\nFrom: a@x\r\n\r\nb\r\n");
        let t = std::time::Instant::now();
        let p = prepare(msg.as_bytes());
        assert!(
            t.elapsed() < std::time::Duration::from_millis(500),
            "{:?}",
            t.elapsed()
        );
        let r = verify_prepared(&p, &crate::dns::Static::default()).await;
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].value, "permerror");
    }
}
