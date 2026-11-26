//! ARC chain validation (RFC 8617 §5.2): decides the chain validation status
//! (cv) the gateway asserts when it adds its own ARC set.
//!
//! The CPU-bound part ([`prepare`]: parsing, body/header hashing) is
//! synchronous so callers can run it on a blocking thread; [`verify`] then
//! only fetches keys (with the DKIM key lookup) and checks RSA signatures.

use base64::Engine;
use sha2::{Digest, Sha256};

use crate::dkim::{
    canon_header, crlf, lookup_key, name_index, parse_canon, parse_h, parse_tags, signed_headers,
    split, strip_fws, tag, verify_digest, without_b, BodyCache, Canon, Field,
};
use crate::dns::Resolver;

/// Highest ARC instance allowed (RFC 8617 §4.2.1).
pub const MAX_INSTANCES: usize = 50;

/// Most distinct signing keys fetched per chain (bounds DNS work).
const MAX_KEYS: usize = 16;

/// Overall deadline for a chain's key lookups (they run concurrently); a
/// chain whose keys are not all known by then fails.
pub const KEY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// Chain validation status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cv {
    None,
    Pass,
    Fail,
}

impl Cv {
    pub fn as_str(self) -> &'static str {
        match self {
            Cv::None => "none",
            Cv::Pass => "pass",
            Cv::Fail => "fail",
        }
    }
}

/// The outcome of validating a message's existing ARC sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainStatus {
    pub cv: Cv,
    /// Highest instance number present (0 without ARC headers); the next
    /// set is `instances + 1`.
    pub instances: usize,
}

impl ChainStatus {
    pub const NONE: ChainStatus = ChainStatus {
        cv: Cv::None,
        instances: 0,
    };
}

/// One signature to check once its key is known.
struct SigCheck {
    domain: String,
    selector: String,
    digest: Vec<u8>,
    b: Vec<u8>,
}

/// A parsed chain: either already decided, or signatures left to verify
/// (the latest ARC-Message-Signature first, then every ARC-Seal from the
/// newest down).
pub struct Prepared {
    instances: usize,
    decided: Option<Cv>,
    checks: Vec<SigCheck>,
}

impl Prepared {
    /// The status when no keys can be fetched (no resolver): an existing
    /// chain cannot be shown to pass, so it is a failure.
    pub fn unverified(&self) -> ChainStatus {
        ChainStatus {
            cv: self.decided.unwrap_or(Cv::Fail),
            instances: self.instances,
        }
    }
}

fn is_arc(name: &str) -> bool {
    matches!(
        name,
        "arc-seal" | "arc-message-signature" | "arc-authentication-results"
    )
}

fn value_of(f: &Field) -> String {
    let c = f.raw.iter().position(|&b| b == b':').unwrap_or(0);
    String::from_utf8_lossy(&f.raw[c + 1..]).into_owned()
}

/// The i= instance of an ARC header (the AAR's value starts with "i=N;").
fn instance(f: &Field) -> Option<usize> {
    let v = value_of(f);
    let i = if f.name == "arc-authentication-results" {
        let first = v.split(';').next()?;
        let (k, n) = first.split_once('=')?;
        if k.trim() != "i" {
            return None;
        }
        strip_fws(n)
    } else {
        strip_fws(tag(&parse_tags(&v)?, "i")?)
    };
    let n: usize = i.parse().ok()?;
    (n >= 1).then_some(n)
}

/// Highest instance number among the message's ARC headers (0 if none).
pub fn highest_instance(raw: &[u8]) -> usize {
    let msg = crlf(raw);
    let (fields, _) = split(&msg);
    fields
        .iter()
        .filter(|f| is_arc(&f.name))
        .filter_map(instance)
        .max()
        .unwrap_or(0)
}

/// The message carries any ARC header.
pub fn has_arc_headers(raw: &[u8]) -> bool {
    let msg = crlf(raw);
    let (fields, _) = split(&msg);
    fields.iter().any(|f| is_arc(&f.name))
}

/// ARC sets i=1..n as indices of (AAR, AMS, AS), or None when the structure
/// is invalid (gaps, duplicates, unparseable instance numbers, n > 50).
pub(crate) fn sets(fields: &[Field]) -> Option<Vec<[usize; 3]>> {
    let mut found: Vec<[Option<usize>; 3]> = Vec::new();
    for (idx, f) in fields.iter().enumerate() {
        let k = match f.name.as_str() {
            "arc-authentication-results" => 0,
            "arc-message-signature" => 1,
            "arc-seal" => 2,
            _ => continue,
        };
        let i = instance(f)?;
        if i > MAX_INSTANCES {
            return None;
        }
        if found.len() < i {
            found.resize(i, [None; 3]);
        }
        if found[i - 1][k].replace(idx).is_some() {
            return None; // duplicate
        }
    }
    found
        .into_iter()
        .map(|s| Some([s[0]?, s[1]?, s[2]?]))
        .collect()
}

/// Parses the chain and computes every hash (no I/O).
pub fn prepare(raw: &[u8]) -> Prepared {
    let msg = crlf(raw);
    let (fields, body) = split(&msg);
    let instances = fields
        .iter()
        .filter(|f| is_arc(&f.name))
        .filter_map(instance)
        .max()
        .unwrap_or(0);
    let decided = |cv| Prepared {
        instances,
        decided: Some(cv),
        checks: Vec::new(),
    };
    if !fields.iter().any(|f| is_arc(&f.name)) {
        return decided(Cv::None);
    }
    let Some(sets) = sets(&fields) else {
        return decided(Cv::Fail);
    };
    match prepare_checks(&fields, body, &sets) {
        Some(checks) => Prepared {
            instances,
            decided: None,
            checks,
        },
        None => decided(Cv::Fail),
    }
}

fn prepare_checks(fields: &[Field], body: &[u8], sets: &[[usize; 3]]) -> Option<Vec<SigCheck>> {
    let n = sets.len();
    let mut checks = Vec::new();
    // ARC-Seal tags and the cv sequence (§5.2 steps 2-3).
    let mut seal_tags = Vec::with_capacity(n);
    for (k, s) in sets.iter().enumerate() {
        let tags = parse_tags(&value_of(&fields[s[2]]))?;
        let cv = tag(&tags, "cv")?.trim().to_ascii_lowercase();
        let want = if k == 0 { "none" } else { "pass" };
        if cv != want || tag(&tags, "h").is_some() {
            return None; // a recorded failure, or an invalid chain
        }
        if !tag(&tags, "a")?.trim().eq_ignore_ascii_case("rsa-sha256") {
            return None;
        }
        seal_tags.push(tags);
    }

    // The newest ARC-Message-Signature (§5.2 step 5).
    let ams = &fields[sets[n - 1][1]];
    let tags = parse_tags(&value_of(ams))?;
    if !tag(&tags, "a")?.trim().eq_ignore_ascii_case("rsa-sha256") {
        return None;
    }
    let h = parse_h(tag(&tags, "h")?).ok()?;
    let (hc, bc) = match tag(&tags, "c").map(|c| c.trim().to_ascii_lowercase()) {
        None => (Canon::Simple, Canon::Simple),
        Some(c) => {
            let (a, b) = c.split_once('/').unwrap_or((c.as_str(), "simple"));
            (parse_canon(a).ok()?, parse_canon(b).ok()?)
        }
    };
    let bh = b64d(tag(&tags, "bh")?)?;
    let mut cache = BodyCache::default();
    if Sha256::digest(cache.get(body, bc)).as_slice() != bh.as_slice() {
        return None;
    }
    let index = name_index(fields);
    let mut data = signed_headers(fields, &index, &h, sets[n - 1][1], hc);
    data.extend_from_slice(&canon_last(&without_b(&ams.raw), hc));
    checks.push(SigCheck {
        domain: tag(&tags, "d")?.trim().to_ascii_lowercase(),
        selector: tag(&tags, "s")?.trim().to_string(),
        digest: Sha256::digest(&data).to_vec(),
        b: b64d(tag(&tags, "b")?)?,
    });

    // Every ARC-Seal, newest first (§5.2 step 6): each signs sets 1..=i.
    let mut prefix = Sha256::new();
    let mut seal_checks = Vec::with_capacity(n);
    for (k, s) in sets.iter().enumerate() {
        prefix.update(canon_header(&fields[s[0]].raw, Canon::Relaxed));
        prefix.update(canon_header(&fields[s[1]].raw, Canon::Relaxed));
        let mut input = prefix.clone();
        input.update(canon_last(&without_b(&fields[s[2]].raw), Canon::Relaxed));
        let tags = &seal_tags[k];
        seal_checks.push(SigCheck {
            domain: tag(tags, "d")?.trim().to_ascii_lowercase(),
            selector: tag(tags, "s")?.trim().to_string(),
            digest: input.finalize().to_vec(),
            b: b64d(tag(tags, "b")?)?,
        });
        prefix.update(canon_header(&fields[s[2]].raw, Canon::Relaxed));
    }
    seal_checks.reverse();
    checks.extend(seal_checks);
    Some(checks)
}

fn b64d(v: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(strip_fws(v))
        .ok()
}

/// Canonical form of a header being verified, without its final CRLF.
fn canon_last(raw: &[u8], c: Canon) -> Vec<u8> {
    let mut v = canon_header(raw, c);
    if v.ends_with(b"\r\n") {
        v.truncate(v.len() - 2);
    }
    v
}

/// Fetches the keys and verifies the prepared signatures. The distinct
/// (selector, domain) keys — at most [`MAX_KEYS`], more fails the chain —
/// are looked up concurrently under one [`KEY_DEADLINE`].
pub async fn verify<R: Resolver + ?Sized>(p: &Prepared, resolver: &R) -> ChainStatus {
    verify_within(p, resolver, KEY_DEADLINE).await
}

async fn verify_within<R: Resolver + ?Sized>(
    p: &Prepared,
    resolver: &R,
    deadline: std::time::Duration,
) -> ChainStatus {
    let instances = p.instances;
    if let Some(cv) = p.decided {
        return ChainStatus { cv, instances };
    }
    let fail = ChainStatus {
        cv: Cv::Fail,
        instances,
    };
    let mut ids: Vec<(&str, &str)> = Vec::new();
    for c in &p.checks {
        let id = (c.selector.as_str(), c.domain.as_str());
        if !ids.contains(&id) {
            if ids.len() >= MAX_KEYS {
                return fail;
            }
            ids.push(id);
        }
    }
    let lookups = futures_util::future::join_all(
        ids.iter()
            .map(|(sel, dom)| async move { lookup_key(resolver, sel, dom).await.ok() }),
    );
    let Ok(keys) = tokio::time::timeout(deadline, lookups).await else {
        return fail;
    };
    for c in &p.checks {
        let id = (c.selector.as_str(), c.domain.as_str());
        let key = ids
            .iter()
            .position(|k| *k == id)
            .and_then(|i| keys[i].as_ref());
        let ok = key
            .map(|k| verify_digest(k, &c.digest, &c.b).is_ok())
            .unwrap_or(false);
        if !ok {
            return fail;
        }
    }
    ChainStatus {
        cv: Cv::Pass,
        instances,
    }
}

/// Validates the message's ARC chain ([`prepare`] + [`verify`]).
pub async fn validate<R: Resolver + ?Sized>(raw: &[u8], resolver: &R) -> ChainStatus {
    verify(&prepare(raw), resolver).await
}

/// Round-3 review regressions: bounded tag parsing, concurrent key lookups.
#[cfg(test)]
mod r3_tests {
    use super::*;
    use crate::arc::seal::Sealer;
    use crate::dns::{Result as DnsResult, Static};
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    /// A resolver that answers from `Static` after a delay.
    struct Slow(Static, Duration);

    #[async_trait::async_trait]
    impl Resolver for Slow {
        async fn txt(&self, name: &str) -> DnsResult<Vec<String>> {
            tokio::time::sleep(self.1).await;
            self.0.txt(name).await
        }
        async fn ip(&self, name: &str) -> DnsResult<Vec<IpAddr>> {
            self.0.ip(name).await
        }
        async fn mx(&self, name: &str) -> DnsResult<Vec<String>> {
            self.0.mx(name).await
        }
    }

    /// A message carrying a valid 4-set chain, each set under its own key.
    async fn chain() -> (Vec<u8>, Static) {
        use base64::Engine;
        use rsa::pkcs8::EncodePublicKey;
        let mut r = Static::default();
        let mut msg = b"From: a@x\r\nSubject: s\r\n\r\nbody\r\n".to_vec();
        for i in 1..=4 {
            let key = rsa::PrivateKey::new(&mut getrandom::SysRng, 1024).unwrap();
            let txt = format!(
                "v=DKIM1; k=rsa; p={}",
                base64::engine::general_purpose::STANDARD
                    .encode(key.to_public_key().to_public_key_der().unwrap().as_bytes())
            );
            let sel = format!("s{i}");
            r = r.with_txt(&format!("{sel}._domainkey.hop{i}.test"), &[&txt]);
            let sealer = Sealer::new(&format!("hop{i}.test"), &sel, "gw", key).unwrap();
            let status = prepare(&msg);
            let status = verify(&status, &r).await;
            assert_eq!(status.instances, i - 1);
            msg = sealer.seal_with(&msg, "spf=pass", &status).unwrap();
        }
        (msg, r)
    }

    #[tokio::test]
    async fn key_lookups_run_concurrently_under_one_deadline() {
        let (msg, r) = chain().await;
        let p = prepare(&msg);
        assert_eq!(
            verify(&p, &r).await,
            ChainStatus {
                cv: Cv::Pass,
                instances: 4
            }
        );
        let slow = Slow(r, Duration::from_millis(400));
        let t = Instant::now();
        assert_eq!(verify(&p, &slow).await.cv, Cv::Pass);
        // Four distinct keys at 400 ms each: sequential would take 1.6 s.
        assert!(
            t.elapsed() < Duration::from_millis(1200),
            "{:?}",
            t.elapsed()
        );
        // Past the deadline the chain fails.
        let t = Instant::now();
        let st = verify_within(&p, &slow, Duration::from_millis(50)).await;
        assert_eq!(st.cv, Cv::Fail);
        assert!(t.elapsed() < Duration::from_millis(300));
    }

    #[test]
    fn huge_tag_lists_are_rejected_quickly() {
        for n in [100usize, 60_000] {
            let mut v = String::from("ARC-Seal: i=1; cv=none");
            for k in 0..n {
                v.push_str(&format!("; t{k}=x"));
            }
            let msg = format!("{v}\r\nFrom: a@x\r\n\r\nb\r\n");
            let t = Instant::now();
            let st = prepare(msg.as_bytes()).unverified();
            assert_eq!(st.cv, Cv::Fail);
            assert!(
                t.elapsed() < Duration::from_millis(500),
                "{n}: {:?}",
                t.elapsed()
            );
        }
    }
}
