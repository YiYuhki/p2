//! ARC (RFC 8617) sealing. Port of the Go `internal/arc` sealer: builds the
//! next ARC set (ARC-Authentication-Results, ARC-Message-Signature, ARC-Seal)
//! and signs it with the gateway RSA key (RSA-SHA256).
//!
//! Canonicalization works on the raw bytes (the DKIM relaxed canonicalization
//! in [`crate::dkim`]), so 8-bit content is hashed and relayed exactly as
//! received. Header instances are selected bottom-up as a verifier does.
//!
//! The chain validation status is never assumed: [`Sealer::seal_with_chain`]
//! validates the existing sets ([`super::validate`]) and seals i=n+1 with
//! cv=none (no chain), cv=pass (every seal and the newest AMS verified) or
//! cv=fail. [`Sealer::seal`], for callers without a resolver, asserts
//! cv=fail whenever ARC headers are present. A cv=pass seal covers every
//! earlier set; a cv=fail seal covers only its own set (the earlier ones may
//! be malformed, and validators stop at a failed chain anyway). More than 50
//! sets cannot be extended: an error is returned and the message is relayed
//! unsealed.

use base64::Engine;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, PrivateKey};
use sha2::{Digest, Sha256};

use super::validate::{self, ChainStatus, Cv, MAX_INSTANCES};
use crate::dkim::{canon_body, canon_header, crlf, split, Canon, Field};
use crate::dns::Resolver;

/// Header set the ARC-Message-Signature covers when present (mirrors the Go
/// `amsHeaders`). Authentication-Results is deliberately absent: RFC 8617
/// §4.1.2 — the AMS must not sign it (the AAR carries the results).
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

    /// Prepends the next ARC set to `raw` without validating the existing
    /// chain (no resolver): cv=none when there is none, otherwise cv=fail.
    /// `auth_results` is the RFC 8601 method list without the leading
    /// authserv-id. Fails (leaving the caller to relay unsealed) when the
    /// message has no header/body separator or already has 50 sets.
    pub fn seal(&self, raw: &[u8], auth_results: &str) -> Result<Vec<u8>, String> {
        let status = if validate::has_arc_headers(raw) {
            ChainStatus {
                cv: Cv::Fail,
                instances: validate::highest_instance(raw),
            }
        } else {
            ChainStatus::NONE
        };
        self.seal_with(raw, auth_results, &status)
    }

    /// Validates the existing chain with `resolver` and seals i=n+1. The
    /// hashing runs inline; callers on an async runtime should prefer
    /// validating with [`validate::prepare`] on a blocking thread and then
    /// calling [`Sealer::seal_with`].
    pub async fn seal_with_chain<R: Resolver + ?Sized>(
        &self,
        raw: &[u8],
        auth_results: &str,
        resolver: &R,
    ) -> Result<Vec<u8>, String> {
        let status = validate::validate(raw, resolver).await;
        self.seal_with(raw, auth_results, &status)
    }

    /// Prepends ARC set i=`status.instances`+1 asserting `status.cv`.
    pub fn seal_with(
        &self,
        raw: &[u8],
        auth_results: &str,
        status: &ChainStatus,
    ) -> Result<Vec<u8>, String> {
        let msg = crlf(raw);
        if !(msg.starts_with(b"\r\n") || msg.windows(4).any(|w| w == b"\r\n\r\n")) {
            return Err("arc: message has no header/body separator".into());
        }
        let (fields, body) = split(&msg);
        let has_arc = fields.iter().any(|f| {
            matches!(
                f.name.as_str(),
                "arc-seal" | "arc-message-signature" | "arc-authentication-results"
            )
        });
        let mut cv = status.cv;
        if cv == Cv::None && has_arc {
            cv = Cv::Fail; // never claim "no chain" over existing ARC headers
        }
        let i = status.instances + 1;
        if i > MAX_INSTANCES {
            return Err("arc: chain already has 50 sets; not sealed".into());
        }
        // A passing chain is covered by the new seal (RFC 8617 §5.1.1).
        let mut prior: Vec<u8> = Vec::new();
        if cv == Cv::Pass {
            let sets = validate::sets(&fields)
                .filter(|s| s.len() == status.instances)
                .ok_or("arc: chain changed since validation; not sealed")?;
            for s in sets {
                for idx in s {
                    prior.extend_from_slice(&canon_header(&fields[idx].raw, Canon::Relaxed));
                }
            }
        }
        let t = (self.now)();

        let auth_results = if auth_results.is_empty() {
            "none"
        } else {
            auth_results
        };
        let aar = format!("i={i}; {}; {}", self.authserv, auth_results);

        let bh = b64(&Sha256::digest(canon_body(body, Canon::Relaxed)));
        let (names, mut ams_input) = select_headers(&fields, AMS_HEADERS);
        let ams_tags = format!(
            "i={i}; a=rsa-sha256; c=relaxed/relaxed; d={}; s={}; t={}; bh={}; h={}; b=",
            self.domain,
            self.selector,
            t,
            bh,
            names.join(":")
        );
        ams_input.extend_from_slice(&canon_last("ARC-Message-Signature", &ams_tags));
        let ams_full = format!("{ams_tags}{}", self.sign(&ams_input)?);

        let as_tags = format!(
            "i={i}; a=rsa-sha256; cv={}; d={}; s={}; t={}; b=",
            cv.as_str(),
            self.domain,
            self.selector,
            t
        );
        let mut seal_input = prior;
        seal_input.extend_from_slice(&seal_signing_input(&aar, &ams_full, &as_tags));
        let as_full = format!("{as_tags}{}", self.sign(&seal_input)?);

        let mut out = Vec::with_capacity(msg.len() + 2048);
        out.extend_from_slice(fold("ARC-Seal", &as_full).as_bytes());
        out.extend_from_slice(fold("ARC-Message-Signature", &ams_full).as_bytes());
        out.extend_from_slice(fold("ARC-Authentication-Results", &aar).as_bytes());
        out.extend_from_slice(&msg);
        Ok(out)
    }

    fn sign(&self, input: &[u8]) -> Result<String, String> {
        let digest = Sha256::digest(input);
        let sig = self
            .key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .map_err(|e| format!("arc: sign: {e}"))?;
        Ok(b64(&sig))
    }
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// For each wanted name (case-insensitive, in order), the bottom-most unused
/// instance — the one a verifier picks for that h= entry. Returns the h= names
/// and the canonicalized headers.
fn select_headers(fields: &[Field], want: &[&str]) -> (Vec<String>, Vec<u8>) {
    let mut used = vec![false; fields.len()];
    let mut names = Vec::new();
    let mut data = Vec::new();
    for w in want {
        let lw = w.to_ascii_lowercase();
        if let Some(i) = (0..fields.len())
            .rev()
            .find(|&i| !used[i] && fields[i].name == lw)
        {
            used[i] = true;
            names.push(w.to_string());
            data.extend_from_slice(&canon_header(&fields[i].raw, Canon::Relaxed));
        }
    }
    (names, data)
}

/// Relaxed canonical form of a header being signed, without the final CRLF.
fn canon_last(name: &str, value: &str) -> Vec<u8> {
    let mut c = canon_header(format!("{name}: {value}\r\n").as_bytes(), Canon::Relaxed);
    c.truncate(c.len() - 2);
    c
}

/// Builds the data the ARC-Seal signs (AAR, AMS-with-real-b, AS-with-empty-b).
fn seal_signing_input(aar: &str, ams_full: &str, as_tags: &str) -> Vec<u8> {
    let mut b = canon_header(
        format!("ARC-Authentication-Results: {aar}\r\n").as_bytes(),
        Canon::Relaxed,
    );
    b.extend_from_slice(&canon_header(
        format!("ARC-Message-Signature: {ams_full}\r\n").as_bytes(),
        Canon::Relaxed,
    ));
    b.extend_from_slice(&canon_last("ARC-Seal", as_tags));
    b
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
        let v: String = v.replace("\r\n", "");
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

    fn value(f: &Field) -> String {
        let c = f.raw.iter().position(|&b| b == b':').unwrap();
        String::from_utf8_lossy(&f.raw[c + 1..])
            .replace("\r\n", "")
            .trim()
            .to_string()
    }

    fn verify(pk: &PublicKey, input: &[u8], sig_b64: &str) -> bool {
        let sig = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .unwrap();
        let vk = VerifyingKey::<Sha256>::new(pk.clone());
        let signature = rsa::pkcs1v15::Signature::try_from(sig.as_slice()).unwrap();
        vk.verify(input, &signature).is_ok()
    }

    /// Verifies the AMS and AS of a sealed message the way a receiver does
    /// (bottom-up header selection over the raw bytes).
    fn verify_sealed(pk: &PublicKey, out: &[u8]) -> (bool, bool, Vec<String>) {
        let (fields, body) = split(out);
        let get = |n: &str| value(fields.iter().find(|f| f.name == n).unwrap());
        let (aar, ams, as_) = (
            get("arc-authentication-results"),
            get("arc-message-signature"),
            get("arc-seal"),
        );
        let ams_tags = parse_tags(&ams);
        assert_eq!(
            ams_tags["bh"],
            b64(&Sha256::digest(canon_body(body, Canon::Relaxed)))
        );
        let h: Vec<String> = ams_tags["h"].split(':').map(String::from).collect();
        let hs: Vec<&str> = h.iter().map(|s| s.as_str()).collect();
        // Exclude our own ARC headers (never in h=) and select like a verifier.
        let (_, mut input) = select_headers(&fields, &hs);
        input.extend_from_slice(&canon_last("ARC-Message-Signature", &empty_b(&ams)));
        let ams_ok = verify(pk, &input, &ams_tags["b"]);
        let as_tags = parse_tags(&as_);
        assert_eq!(as_tags["cv"], "none");
        let seal_ok = verify(
            pk,
            &seal_signing_input(&aar, &ams, &empty_b(&as_)),
            &as_tags["b"],
        );
        (ams_ok, seal_ok, h)
    }

    fn sealer() -> (Sealer, PublicKey) {
        let key = PrivateKey::new(&mut getrandom::SysRng, 1024).unwrap();
        let pk = PublicKey::from(&key);
        let s = Sealer::new("gw.example.com", "arc1", "gw.example.com", key)
            .unwrap()
            .with_now(Box::new(|| 1_700_000_000));
        (s, pk)
    }

    #[test]
    fn seal_round_trip() {
        let (s, pk) = sealer();
        let raw = "From: sender@ext.org\r\nTo: user@example.com\r\nSubject: hi\r\n\
             Date: Mon, 01 Jan 2026 00:00:00 +0000\r\nAuthentication-Results: gw.example.com; spf=pass\r\n\
             \r\nhello body\r\n";
        let out = s.seal(raw.as_bytes(), "spf=pass; dkim=fail").unwrap();
        let text = String::from_utf8(out.clone()).unwrap();
        assert!(text.starts_with("ARC-Seal:"), "ARC-Seal outermost");
        assert!(text.ends_with(raw), "original message unchanged");
        let (ams_ok, seal_ok, h) = verify_sealed(&pk, &out);
        assert!(ams_ok, "AMS verifies");
        assert!(seal_ok, "ARC-Seal verifies");
        // RFC 8617 §4.1.2: the AMS must not cover Authentication-Results.
        assert!(!h
            .iter()
            .any(|n| n.eq_ignore_ascii_case("authentication-results")));
        assert!(h.iter().any(|n| n == "From"));
        let aar = parse_tags(&value(
            split(&out)
                .0
                .iter()
                .find(|f| f.name == "arc-authentication-results")
                .unwrap(),
        ));
        assert_eq!(aar["i"], "1");
    }

    #[test]
    fn eight_bit_body_is_preserved_and_verifies() {
        let (s, pk) = sealer();
        let raw = b"From: a@x\r\nContent-Type: text/plain; charset=euc-kr\r\nContent-Transfer-Encoding: 8bit\r\n\r\n\xc7\xd1\xb1\xdb\r\n";
        let out = s.seal(raw, "spf=pass").unwrap();
        assert!(out.ends_with(raw));
        let (ams_ok, seal_ok, _) = verify_sealed(&pk, &out);
        assert!(ams_ok && seal_ok);
    }

    #[test]
    fn duplicate_headers_select_bottom_most() {
        let (s, pk) = sealer();
        let raw = b"Subject: top\r\nFrom: a@x\r\nSubject: bottom\r\n\r\nb\r\n";
        let out = s.seal(raw, "spf=pass").unwrap();
        let (ams_ok, _, _) = verify_sealed(&pk, &out);
        assert!(ams_ok);
        // The signature covers the bottom-most Subject: changing it breaks it.
        let tampered = String::from_utf8(out)
            .unwrap()
            .replace("Subject: bottom", "Subject: BOTTOM");
        assert!(!verify_sealed(&pk, tampered.as_bytes()).0);
    }

    #[test]
    fn existing_chain_is_never_skipped() {
        let (s, _) = sealer();
        // Without a resolver an existing (here: forged) chain is cv=fail and
        // the next instance is sealed — a fake ARC-Seal no longer suppresses
        // sealing.
        let raw = b"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=a.example; s=s; b=x\r\nFrom: a@x\r\n\r\nb\r\n";
        let out = String::from_utf8(s.seal(raw, "spf=pass").unwrap()).unwrap();
        assert!(
            out.starts_with("ARC-Seal: i=2; a=rsa-sha256; cv=fail;"),
            "{out}"
        );
        assert!(out.contains("ARC-Authentication-Results: i=2; gw.example.com; spf=pass"));
        assert!(s.seal(b"From: a@x\r\n", "spf=pass").is_err());
        // 50 sets cannot be extended.
        let raw = b"ARC-Seal: i=50; a=rsa-sha256; cv=pass; d=a.example; s=s; b=x\r\nFrom: a@x\r\n\r\nb\r\n";
        assert!(s.seal(raw, "spf=pass").is_err());
    }

    fn resolver_for(pk: &PublicKey) -> crate::dns::Static {
        use rsa::pkcs8::EncodePublicKey;
        let der = pk.to_public_key_der().unwrap();
        crate::dns::Static::default().with_txt(
            "arc1._domainkey.gw.example.com",
            &[&format!("v=DKIM1; k=rsa; p={}", b64(der.as_bytes()))],
        )
    }

    #[tokio::test]
    async fn chain_is_validated_and_extended() {
        use super::validate::{validate, ChainStatus, Cv};
        let (s, pk) = sealer();
        let r = resolver_for(&pk);
        let raw = b"From: sender@ext.org\r\nTo: user@example.com\r\nSubject: hi\r\n\r\nhello\r\n";
        assert_eq!(validate(raw, &r).await, ChainStatus::NONE);
        // Hop 1, then hop 2 validating hop 1.
        let one = s.seal_with_chain(raw, "spf=pass", &r).await.unwrap();
        assert_eq!(
            validate(&one, &r).await,
            ChainStatus {
                cv: Cv::Pass,
                instances: 1
            }
        );
        let mut relayed = b"Received: from hop1\r\n".to_vec();
        relayed.extend_from_slice(&one);
        let two = s.seal_with_chain(&relayed, "arc=pass", &r).await.unwrap();
        let text = String::from_utf8_lossy(&two);
        assert!(
            text.starts_with("ARC-Seal: i=2; a=rsa-sha256; cv=pass;"),
            "{text}"
        );
        assert_eq!(
            validate(&two, &r).await,
            ChainStatus {
                cv: Cv::Pass,
                instances: 2
            }
        );
        // A body change breaks the newest AMS: the chain fails, and the next
        // seal records cv=fail.
        let tampered = String::from_utf8_lossy(&two).replace("hello", "HELLO");
        let st = validate(tampered.as_bytes(), &r).await;
        assert_eq!(st.cv, Cv::Fail);
        let three = s.seal_with(tampered.as_bytes(), "arc=fail", &st).unwrap();
        assert!(
            String::from_utf8_lossy(&three).starts_with("ARC-Seal: i=3; a=rsa-sha256; cv=fail;")
        );
        assert_eq!(validate(&three, &r).await.cv, Cv::Fail);
        // A tampered earlier seal fails too.
        let forged = String::from_utf8_lossy(&two).replacen("spf=pass", "spf=fail", 1);
        assert_eq!(validate(forged.as_bytes(), &r).await.cv, Cv::Fail);
        // Unknown key / missing set / duplicate set.
        assert_eq!(
            validate(&two, &crate::dns::Static::default()).await.cv,
            Cv::Fail
        );
        let gap = String::from_utf8_lossy(&two).replacen("ARC-Seal: i=2", "ARC-Seal: i=3", 1);
        assert_eq!(validate(gap.as_bytes(), &r).await.cv, Cv::Fail);
        let fake = b"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=gw.example.com; s=arc1; b=AAAA\r\nARC-Message-Signature: i=1; a=rsa-sha256; d=gw.example.com; s=arc1; h=from; bh=AAAA; b=AAAA\r\nARC-Authentication-Results: i=1; x; spf=pass\r\nFrom: a@x\r\n\r\nb\r\n";
        assert_eq!(validate(fake, &r).await.cv, Cv::Fail);
        // >50 instances is a failed chain.
        let many =
            b"ARC-Seal: i=51; a=rsa-sha256; cv=pass; d=a; s=s; b=x\r\nFrom: a@x\r\n\r\nb\r\n";
        assert_eq!(validate(many, &r).await.cv, Cv::Fail);
    }

    #[test]
    fn disabled_when_missing_fields() {
        let key = PrivateKey::new(&mut getrandom::SysRng, 1024).unwrap();
        assert!(Sealer::new("", "s", "a", key).is_none());
    }
}
