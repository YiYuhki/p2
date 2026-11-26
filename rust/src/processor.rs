//! The inbound message processor wired into the SMTP proxy. Port of the Go
//! `internal/gateway` Processor:
//!
//! 1. SPF / DKIM / DMARC run against the *original* bytes; an unambiguous DMARC
//!    fail under `p=reject` is rejected when enforcement is on.
//! 2. Gateway marker headers and Authentication-Results claiming this gateway's
//!    authserv-id are stripped (RFC 8601 §5) so senders cannot forge them.
//! 3. Attachments are quarantined and replaced by download links.
//! 4. Authentication-Results and Received are added, the message is ARC-sealed
//!    with the real results, then optionally DKIM-signed by the gateway.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::arc::Sealer;
use crate::dns::Resolver;
use crate::gateway::{Envelope, MessageProcessor, ProcessError, SmtpError};
use crate::metrics::Metrics;
use crate::service::Service;

/// Inbound authentication settings.
#[derive(Clone, Default)]
pub struct AuthOptions {
    pub spf: Option<Arc<dyn crate::spf::Check>>,
    /// DKIM verification resolver (None disables DKIM verification).
    pub dkim: Option<Arc<dyn Resolver>>,
    pub dmarc: Option<Arc<crate::dmarc::Evaluator<Arc<dyn Resolver>>>>,
    /// Reject `p=reject` DMARC failures.
    pub enforce_dmarc: bool,
}

/// Inbound processor options.
#[derive(Clone, Default)]
pub struct Options {
    /// authserv-id for Authentication-Results and the Received "by" host.
    pub hostname: String,
    pub auth: AuthOptions,
    /// Rename the original DKIM-Signature headers once the message changed.
    pub strip_original_dkim: bool,
    pub signer: Option<Arc<crate::dkim::Signer>>,
    pub metrics: Option<Arc<Metrics>>,
}

/// Inbound processor.
pub struct InboundProcessor {
    service: Option<Arc<Service>>,
    arc: Option<Arc<Sealer>>,
    opts: Options,
}

struct AuthOutcome {
    results: String,
    dmarc_rejects: bool,
}

impl InboundProcessor {
    pub fn new(service: Option<Arc<Service>>, arc: Option<Arc<Sealer>>) -> Self {
        Self::with_options(service, arc, Options::default())
    }

    pub fn with_options(
        service: Option<Arc<Service>>,
        arc: Option<Arc<Sealer>>,
        mut opts: Options,
    ) -> Self {
        if opts.hostname.is_empty() {
            opts.hostname = "localhost".into();
        }
        InboundProcessor { service, arc, opts }
    }

    async fn authenticate(&self, env: &Envelope, raw: &[u8]) -> AuthOutcome {
        let a = &self.opts.auth;
        let mut methods: Vec<String> = Vec::new();
        let mut spf: Option<crate::spf::Result> = None;
        let mut dkim: Vec<crate::dkim::Result> = Vec::new();

        if let Some(checker) = &a.spf {
            let r = match host_ip(&env.remote_addr) {
                Some(ip) => checker.check(ip, &env.helo, &env.mail_from).await,
                None => crate::spf::Result {
                    value: "none".into(),
                    ident: String::new(),
                    domain: String::new(),
                },
            };
            methods.push(r.auth_results());
            spf = Some(r);
        }
        if let Some(res) = &a.dkim {
            // Canonicalizing and hashing a (up to 50 MB) body is CPU-bound:
            // keep it off the async workers; only the key lookups are async.
            let owned = raw.to_vec();
            let prepared = tokio::task::spawn_blocking(move || crate::dkim::prepare(&owned))
                .await
                .unwrap_or_else(|_| crate::dkim::prepare(raw));
            dkim = crate::dkim::verify_prepared(&prepared, res.as_ref()).await;
            methods.push(crate::dkim::auth_results(&dkim));
        }
        let mut rejects = false;
        if let Some(ev) = &a.dmarc {
            if spf.is_some() || a.dkim.is_some() {
                let sigs: Vec<crate::dmarc::Signature> = dkim
                    .iter()
                    .map(|r| crate::dmarc::Signature {
                        result: r.value.clone(),
                        domain: r.domain.clone(),
                    })
                    .collect();
                let (sv, sd) = spf
                    .as_ref()
                    .map(|s| (s.value.as_str(), s.domain.as_str()))
                    .unwrap_or(("", ""));
                // Every distinct From domain is evaluated (RFC 7489 §6.6.1): a
                // From listing several domains must not dodge the policy of
                // any of them. Absurdly many domains are refused outright.
                let domains = from_header_domains(raw);
                if domains.len() > MAX_FROM_DOMAINS {
                    methods.push("dmarc=permerror (too many From domains)".into());
                    rejects = a.enforce_dmarc;
                } else {
                    let targets = if domains.is_empty() {
                        vec![String::new()]
                    } else {
                        domains
                    };
                    for from in targets {
                        let res = ev.evaluate(&from, sv, sd, &sigs).await;
                        methods.push(res.auth_results.clone());
                        // Only an unambiguous fail under p=reject is enforced, so
                        // a temperror or quarantine policy never bounces
                        // legitimate mail.
                        rejects |=
                            a.enforce_dmarc && res.verdict == "fail" && res.policy == "reject";
                    }
                }
            }
        }
        let results = methods.join("; ");
        if let Some(m) = &self.opts.metrics {
            record_auth_metrics(m, &results);
        }
        AuthOutcome {
            results,
            dmarc_rejects: rejects,
        }
    }

    fn received(&self, env: &Envelope) -> String {
        let ip = host_ip(&env.remote_addr)
            .map(|i| i.to_string())
            .unwrap_or_default();
        let helo = sanitize_header_value(if env.helo.is_empty() {
            "unknown"
        } else {
            &env.helo
        });
        let proto = if env.tls { "ESMTPS" } else { "ESMTP" };
        format!(
            "from {helo} ([{ip}]) by {} (secmail) with {proto}; {}",
            self.opts.hostname,
            chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000")
        )
    }
}

#[async_trait]
impl MessageProcessor for InboundProcessor {
    async fn process(&self, env: &Envelope, raw: &[u8]) -> Result<Vec<u8>, ProcessError> {
        let auth = self.authenticate(env, raw).await;
        if auth.dmarc_rejects {
            return Err(ProcessError::Reject(SmtpError::new(
                550,
                "5.7.1 Message rejected due to DMARC policy",
            )));
        }

        // Strip forged gateway markers / Authentication-Results claiming our
        // authserv-id before anything else reads the headers.
        let id = self.opts.hostname.to_ascii_lowercase();
        let mut pre = crate::mimetree::parse(raw);
        pre.remove_headers(|name, value| {
            name.starts_with("x-secmail-")
                || (name == "authentication-results" && auth_results_id(value) == id)
        });
        let cleaned = pre.to_bytes();
        drop(pre);

        // Quarantine; `modified` tells whether the body changed.
        let (body, modified) = match &self.service {
            Some(s) => {
                let q = s.quarantine(env, &cleaned).await?;
                let m = q != cleaned;
                drop(cleaned);
                (q, m)
            }
            None => (cleaned, false),
        };
        let body = if modified && self.opts.strip_original_dkim {
            let mut root = crate::mimetree::parse(&body);
            root.rename_header("DKIM-Signature", "X-SecMail-Original-DKIM-Signature");
            root.to_bytes()
        } else {
            body
        };

        // Prepend trace headers as raw bytes (no re-parse of the message).
        let mut head = String::new();
        head.push_str(&fold_header("Received", &self.received(env)));
        if !auth.results.is_empty() {
            head.push_str(&fold_header(
                "Authentication-Results",
                &format!("{}; {}", self.opts.hostname, auth.results),
            ));
        }
        let mut out = Vec::with_capacity(head.len() + body.len());
        out.extend_from_slice(head.as_bytes());
        out.extend_from_slice(&body);
        drop(body);

        // ARC-seal before DKIM signing so the seal covers our results. ARC is
        // advisory: a sealing error leaves the message unsealed. Both hash the
        // whole message (CPU-bound), so they run on the blocking pool.
        if let Some(sealer) = &self.arc {
            let ar = if auth.results.is_empty() {
                "none".to_string()
            } else {
                auth.results.clone()
            };
            let sealer = sealer.clone();
            let (input, sealed) = tokio::task::spawn_blocking(move || {
                let r = sealer.seal(&out, &ar);
                (out, r)
            })
            .await
            .map_err(|_| ProcessError::TempFail)?;
            out = sealed.unwrap_or(input);
        }
        if let Some(signer) = &self.opts.signer {
            let signer = signer.clone();
            out = tokio::task::spawn_blocking(move || signer.sign(&out))
                .await
                .map_err(|_| ProcessError::TempFail)?
                .map_err(|_| ProcessError::TempFail)?;
        }
        Ok(out)
    }
}

/// "Name: value\r\n", folded at whitespace only when a line nears the
/// RFC 5322 998-octet limit.
fn fold_header(name: &str, value: &str) -> String {
    let mut out = format!("{name}:");
    let mut col = out.len();
    for word in value.split(' ').filter(|w| !w.is_empty()) {
        if col + 1 + word.len() > 900 && col > name.len() + 1 {
            out.push_str("\r\n\t");
            col = 1;
        } else {
            out.push(' ');
            col += 1;
        }
        out.push_str(word);
        col += word.len();
    }
    out.push_str("\r\n");
    out
}

/// Increments inbound_auth{method,result} for each "method=result" entry.
fn record_auth_metrics(m: &Metrics, results: &str) {
    for part in results.split(';') {
        let tok = part.split_whitespace().next().unwrap_or("");
        if let Some((method, result)) = tok.split_once('=') {
            if matches!(method, "spf" | "dkim" | "dmarc") {
                m.inbound_auth.with_label_values(&[method, result]).inc();
            }
        }
    }
}

fn host_ip(remote: &str) -> Option<IpAddr> {
    let r = remote.trim();
    if let Ok(sa) = r.parse::<std::net::SocketAddr>() {
        return Some(sa.ip());
    }
    r.trim_matches(|c| c == '[' || c == ']').parse().ok()
}

/// The authserv-id of an Authentication-Results value (first token, before
/// any version number or ';'), lowercased.
fn auth_results_id(v: &str) -> String {
    let v = v.trim();
    let v = v.split(';').next().unwrap_or("");
    let v = v.split([' ', '\t']).next().unwrap_or("");
    v.trim().to_ascii_lowercase()
}

fn sanitize_header_value(s: &str) -> String {
    s.chars().filter(|&c| !(c < ' ' || c == '\u{7f}')).collect()
}

/// Most distinct From domains evaluated; more is treated as a DMARC failure.
const MAX_FROM_DOMAINS: usize = 5;

/// Distinct domains (lowercased, in order) of every address in every From
/// header. An empty vector when no domain could be found.
fn from_header_domains(raw: &[u8]) -> Vec<String> {
    let root = crate::mimetree::parse(raw);
    let domain_of = |a: &str| {
        a.rsplit_once('@')
            .map(|(_, d)| {
                d.trim()
                    .trim_end_matches(['>', '.'])
                    .trim()
                    .to_ascii_lowercase()
            })
            .unwrap_or_default()
    };
    let mut out: Vec<String> = Vec::new();
    let mut push = |d: String| {
        if !d.is_empty() && !out.contains(&d) {
            out.push(d);
        }
    };
    for value in root.headers("from") {
        let from = crate::mimeproc::decode_header(&value);
        let mut found = false;
        if let Ok(list) = mailparse::addrparse(&from) {
            for a in list.iter() {
                match a {
                    mailparse::MailAddr::Single(s) => {
                        found = true;
                        push(domain_of(&s.addr));
                    }
                    mailparse::MailAddr::Group(g) => {
                        for s in &g.addrs {
                            found = true;
                            push(domain_of(&s.addr));
                        }
                    }
                }
            }
        }
        if !found {
            // Fallback for a malformed header: the text after each '@'.
            for (i, _) in from.match_indices('@') {
                let d = from[i + 1..]
                    .split(['>', ' ', '\t', ')', ',', ';'])
                    .next()
                    .unwrap_or("")
                    .trim_matches(|c| c == '.' || c == '<' || c == '>')
                    .to_ascii_lowercase();
                push(d);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Static;
    use std::time::Duration;

    const MSG: &[u8] = b"From: Alice <alice@example.com>\r\nTo: bob@corp.test\r\nSubject: hi\r\nAuthentication-Results: gw.corp.test; spf=pass (forged)\r\nAuthentication-Results: other.example; dkim=pass\r\nX-SecMail-Processed: forged\r\n\r\nhello\r\n";

    fn env() -> Envelope {
        Envelope {
            mail_from: "alice@example.com".into(),
            rcpt_to: vec!["bob@corp.test".into()],
            remote_addr: "192.0.2.10:52000".into(),
            helo: "mx.example.com".into(),
            tls: true,
        }
    }

    fn auth(resolver: Static, enforce: bool) -> AuthOptions {
        let r: Arc<dyn Resolver> = Arc::new(resolver);
        AuthOptions {
            spf: Some(Arc::new(crate::spf::Checker::new(
                r.clone(),
                Duration::from_secs(2),
            ))),
            dkim: Some(r.clone()),
            dmarc: Some(Arc::new(crate::dmarc::Evaluator::new(
                r,
                Duration::from_secs(2),
            ))),
            enforce_dmarc: enforce,
        }
    }

    #[tokio::test]
    async fn adds_headers_and_strips_forgeries() {
        let r = Static::default()
            .with_txt("example.com", &["v=spf1 ip4:192.0.2.0/24 -all"])
            .with_txt("_dmarc.example.com", &["v=DMARC1; p=reject"]);
        let m = Arc::new(Metrics::new());
        let p = InboundProcessor::with_options(
            None,
            None,
            Options {
                hostname: "gw.corp.test".into(),
                auth: auth(r, true),
                metrics: Some(m.clone()),
                ..Default::default()
            },
        );
        let out = String::from_utf8(p.process(&env(), MSG).await.unwrap()).unwrap();
        assert!(out.starts_with(
            "Received: from mx.example.com ([192.0.2.10]) by gw.corp.test (secmail) with ESMTPS;"
        ));
        assert!(out.contains(
            "Authentication-Results: gw.corp.test; spf=pass smtp.mailfrom=example.com; dkim=none; dmarc=pass header.from=example.com\r\n"
        ));
        assert!(!out.contains("(forged)"));
        assert!(!out.contains("X-SecMail-Processed: forged"));
        assert!(out.contains("Authentication-Results: other.example; dkim=pass"));
        assert!(out.ends_with("\r\n\r\nhello\r\n"));
        assert_eq!(
            m.inbound_auth.with_label_values(&["dmarc", "pass"]).get(),
            1
        );
    }

    #[tokio::test]
    async fn dmarc_reject_enforced() {
        let r = Static::default()
            .with_txt("example.com", &["v=spf1 -all"])
            .with_txt("_dmarc.example.com", &["v=DMARC1; p=reject"]);
        let p = InboundProcessor::with_options(
            None,
            None,
            Options {
                hostname: "gw.corp.test".into(),
                auth: auth(r.clone(), true),
                ..Default::default()
            },
        );
        match p.process(&env(), MSG).await {
            Err(ProcessError::Reject(e)) => assert_eq!(e.code, 550),
            other => panic!("expected reject, got {:?}", other.map(|_| ())),
        }
        // Not enforced → delivered with dmarc=fail recorded.
        let p = InboundProcessor::with_options(
            None,
            None,
            Options {
                hostname: "gw.corp.test".into(),
                auth: auth(r, false),
                ..Default::default()
            },
        );
        let out = String::from_utf8(p.process(&env(), MSG).await.unwrap()).unwrap();
        assert!(out.contains(
            "spf=fail smtp.mailfrom=example.com; dkim=none; dmarc=fail header.from=example.com"
        ));
    }

    #[tokio::test]
    async fn gateway_dkim_signature_verifies_downstream() {
        let key = rsa::PrivateKey::new(&mut getrandom::SysRng, 1024).unwrap();
        use base64::Engine;
        use rsa::pkcs8::EncodePublicKey;
        let txt = format!(
            "v=DKIM1; k=rsa; p={}",
            base64::engine::general_purpose::STANDARD
                .encode(key.to_public_key().to_public_key_der().unwrap().as_bytes())
        );
        let p = InboundProcessor::with_options(
            None,
            None,
            Options {
                hostname: "gw.corp.test".into(),
                signer: Some(Arc::new(crate::dkim::Signer::new("corp.test", "gw", key))),
                ..Default::default()
            },
        );
        let out = p.process(&env(), MSG).await.unwrap();
        let r = Static::default().with_txt("gw._domainkey.corp.test", &[&txt]);
        let v = crate::dkim::verify(&out, &r).await;
        assert_eq!(v[0].value, "pass");
        assert_eq!(v[0].domain, "corp.test");
    }

    #[test]
    fn from_domains() {
        assert_eq!(
            from_header_domains(b"From: A <a@Example.COM>\r\n\r\n"),
            vec!["example.com"]
        );
        assert_eq!(
            from_header_domains(b"From: a@x.com, b@y.com\r\n\r\n"),
            vec!["x.com", "y.com"]
        );
        assert_eq!(
            from_header_domains(b"From: a@x.com, b@x.com\r\n\r\n"),
            vec!["x.com"]
        );
        assert_eq!(
            from_header_domains(b"From: a@x.com\r\nFrom: b@victim.com\r\n\r\n"),
            vec!["x.com", "victim.com"]
        );
        assert!(from_header_domains(b"Subject: none\r\n\r\n").is_empty());
        assert_eq!(auth_results_id("GW.corp.test 1; spf=pass"), "gw.corp.test");
    }

    #[tokio::test]
    async fn multi_domain_from_cannot_dodge_dmarc_reject() {
        let r = Static::default()
            .with_txt("attacker.net", &["v=spf1 ip4:192.0.2.0/24 -all"])
            .with_txt("_dmarc.attacker.net", &["v=DMARC1; p=none"])
            .with_txt("_dmarc.victim.com", &["v=DMARC1; p=reject"]);
        let p = InboundProcessor::with_options(
            None,
            None,
            Options {
                hostname: "gw.corp.test".into(),
                auth: auth(r, true),
                ..Default::default()
            },
        );
        let mut e = env();
        e.mail_from = "x@attacker.net".into();
        let msg = b"From: x@attacker.net, ceo@victim.com\r\nSubject: pay\r\n\r\nhi\r\n";
        match p.process(&e, msg).await {
            Err(ProcessError::Reject(e)) => assert_eq!(e.code, 550),
            other => panic!("expected reject, got {:?}", other.map(|_| ())),
        }
        // Too many From domains is refused under enforcement.
        let many = b"From: a@a.com, b@b.com, c@c.com, d@d.com, e@e.com, f@f.com\r\n\r\nhi\r\n";
        assert!(matches!(
            p.process(&e, many).await,
            Err(ProcessError::Reject(_))
        ));
    }

    #[tokio::test]
    async fn arc_sealed_and_signed_output_verifies() {
        use base64::Engine;
        use rsa::pkcs8::EncodePublicKey;
        let key = rsa::PrivateKey::new(&mut getrandom::SysRng, 1024).unwrap();
        let txt = format!(
            "v=DKIM1; k=rsa; p={}",
            base64::engine::general_purpose::STANDARD
                .encode(key.to_public_key().to_public_key_der().unwrap().as_bytes())
        );
        let arc_key = rsa::PrivateKey::new(&mut getrandom::SysRng, 1024).unwrap();
        let sealer = Sealer::new("corp.test", "arc", "gw.corp.test", arc_key).unwrap();
        let p = InboundProcessor::with_options(
            None,
            Some(Arc::new(sealer)),
            Options {
                hostname: "gw.corp.test".into(),
                signer: Some(Arc::new(crate::dkim::Signer::new("corp.test", "gw", key))),
                ..Default::default()
            },
        );
        let out = p.process(&env(), MSG).await.unwrap();
        assert!(String::from_utf8_lossy(&out).contains("ARC-Seal: i=1;"));
        let r = Static::default().with_txt("gw._domainkey.corp.test", &[&txt]);
        assert_eq!(crate::dkim::verify(&out, &r).await[0].value, "pass");
    }
}
