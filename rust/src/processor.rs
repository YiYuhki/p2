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
            dkim = crate::dkim::verify(raw, res.as_ref()).await;
            methods.push(crate::dkim::auth_results(&dkim));
        }
        let mut rejects = false;
        if let Some(ev) = &a.dmarc {
            if spf.is_some() || a.dkim.is_some() {
                let from = from_header_domain(raw);
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
                let res = ev.evaluate(&from, sv, sd, &sigs).await;
                methods.push(res.auth_results.clone());
                // Only an unambiguous fail under p=reject is enforced, so a
                // temperror or quarantine policy never bounces legitimate mail.
                rejects = a.enforce_dmarc && res.verdict == "fail" && res.policy == "reject";
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

        let quarantined = match &self.service {
            Some(s) => s.quarantine(env, &cleaned).await?,
            None => cleaned.clone(),
        };
        let modified = quarantined != cleaned;

        let mut root = crate::mimetree::parse(&quarantined);
        if modified && self.opts.strip_original_dkim {
            root.rename_header("DKIM-Signature", "X-SecMail-Original-DKIM-Signature");
        }
        if !auth.results.is_empty() {
            root.prepend_header(
                "Authentication-Results",
                &format!("{}; {}", self.opts.hostname, auth.results),
            );
        }
        root.prepend_header("Received", &self.received(env));
        let mut out = root.to_bytes();

        // ARC-seal before DKIM signing so the seal covers our results. ARC is
        // advisory: a sealing error leaves the message unsealed.
        if let Some(sealer) = &self.arc {
            let ar = if auth.results.is_empty() {
                "none"
            } else {
                auth.results.as_str()
            };
            if let Ok(sealed) = sealer.seal(&out, ar) {
                out = sealed;
            }
        }
        if let Some(signer) = &self.opts.signer {
            out = signer.sign(&out).map_err(|_| ProcessError::TempFail)?;
        }
        Ok(out)
    }
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

/// Domain of the first From address; "" when the From carries addresses from
/// several domains (ambiguous — DMARC then reports none).
fn from_header_domain(raw: &[u8]) -> String {
    let root = crate::mimetree::parse(raw);
    let from = crate::mimeproc::decode_header(&root.header("from").unwrap_or_default());
    let domain_of = |a: &str| {
        a.rsplit_once('@')
            .map(|(_, d)| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .unwrap_or_default()
    };
    if let Ok(list) = mailparse::addrparse(&from) {
        let mut addrs: Vec<String> = Vec::new();
        for a in list.iter() {
            match a {
                mailparse::MailAddr::Single(s) => addrs.push(s.addr.clone()),
                mailparse::MailAddr::Group(g) => {
                    addrs.extend(g.addrs.iter().map(|s| s.addr.clone()))
                }
            }
        }
        if let Some(first) = addrs.first() {
            let d = domain_of(first);
            if addrs.iter().skip(1).any(|a| domain_of(a) != d) {
                return String::new();
            }
            return d;
        }
    }
    // Fallback for a malformed header: the text after the first '@'.
    match from.split_once('@') {
        Some((_, rest)) => rest
            .split(['>', ' ', '\t', ')', ',', ';'])
            .next()
            .unwrap_or("")
            .trim_matches(|c| c == '.' || c == '<' || c == '>')
            .to_ascii_lowercase(),
        None => String::new(),
    }
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
            from_header_domain(b"From: A <a@Example.COM>\r\n\r\n"),
            "example.com"
        );
        assert_eq!(from_header_domain(b"From: a@x.com, b@y.com\r\n\r\n"), "");
        assert_eq!(
            from_header_domain(b"From: a@x.com, b@x.com\r\n\r\n"),
            "x.com"
        );
        assert_eq!(auth_results_id("GW.corp.test 1; spf=pass"), "gw.corp.test");
    }
}
