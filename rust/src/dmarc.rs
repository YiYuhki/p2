//! DMARC (RFC 7489) evaluation. Port of the Go `internal/dmarc`: fetches the
//! `_dmarc` policy (falling back to the organizational domain), checks DKIM and
//! SPF identifier alignment, and reports the verdict plus the published policy.

use crate::authres::sanitize;
use crate::dns::{org_domain, DnsError, Resolver};

/// One DKIM signature outcome as DMARC sees it.
#[derive(Clone, Debug, Default)]
pub struct Signature {
    pub result: String,
    pub domain: String,
}

/// DMARC outcome.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Result {
    /// RFC 8601 fragment, e.g. "dmarc=fail header.from=ex.org".
    pub auth_results: String,
    /// pass | fail | none | temperror
    pub verdict: String,
    /// none | quarantine | reject ("" when no policy was found)
    pub policy: String,
}

/// Evaluates DMARC with an injectable resolver.
pub struct Evaluator<R: Resolver> {
    resolver: R,
    timeout: std::time::Duration,
}

impl<R: Resolver> Evaluator<R> {
    pub fn new(resolver: R, timeout: std::time::Duration) -> Self {
        let timeout = if timeout.is_zero() {
            std::time::Duration::from_secs(5)
        } else {
            timeout
        };
        Evaluator { resolver, timeout }
    }

    /// Computes the verdict for `from_domain` given the SPF result/domain and
    /// the DKIM signature outcomes.
    pub async fn evaluate(
        &self,
        from_domain: &str,
        spf_result: &str,
        spf_domain: &str,
        dkim: &[Signature],
    ) -> Result {
        let from = sanitize(from_domain.trim()).to_ascii_lowercase();
        if from.is_empty() {
            return mk("dmarc=none".into(), "none", "");
        }
        let frag = |v: &str| format!("dmarc={v} header.from={from}");

        let lookup = tokio::time::timeout(self.timeout, self.lookup_policy(&from)).await;
        let rec = match lookup {
            Err(_) | Ok(Lookup::Temp) => return mk(frag("temperror"), "temperror", ""),
            Ok(Lookup::None) => return mk(frag("none"), "none", ""),
            Ok(Lookup::Found(r)) => r,
        };
        let (adkim, aspf) = alignment_modes(&rec);
        let policy = policy_of(&rec);

        if dkim
            .iter()
            .any(|s| s.result.eq_ignore_ascii_case("pass") && aligned(&s.domain, &from, adkim))
        {
            return mk(frag("pass"), "pass", policy);
        }
        if spf_result.eq_ignore_ascii_case("pass") && aligned(spf_domain, &from, aspf) {
            return mk(frag("pass"), "pass", policy);
        }
        // Nothing aligned. A transient underlying error → temperror (retry), not
        // a hard fail of legitimate mail.
        if is_temp(spf_result) || dkim.iter().any(|s| is_temp(&s.result)) {
            return mk(frag("temperror"), "temperror", policy);
        }
        mk(frag("fail"), "fail", policy)
    }

    async fn lookup_policy(&self, domain: &str) -> Lookup {
        match self.fetch(domain).await {
            Lookup::None => {}
            other => return other,
        }
        let org = org_domain(domain);
        if !org.is_empty() && org != domain {
            return self.fetch(&org).await;
        }
        Lookup::None
    }

    async fn fetch(&self, domain: &str) -> Lookup {
        match self.resolver.txt(&format!("_dmarc.{domain}")).await {
            Err(DnsError::NotFound) => Lookup::None,
            Err(DnsError::Temp(_)) => Lookup::Temp,
            Ok(txts) => {
                let recs: Vec<&String> = txts
                    .iter()
                    .filter(|t| t.trim().to_ascii_lowercase().starts_with("v=dmarc1"))
                    .collect();
                // RFC 7489 §6.6.3: more than one record → no discoverable policy.
                if recs.len() == 1 {
                    Lookup::Found(recs[0].clone())
                } else {
                    Lookup::None
                }
            }
        }
    }
}

enum Lookup {
    Found(String),
    None,
    Temp,
}

fn mk(ar: String, verdict: &str, policy: &str) -> Result {
    Result {
        auth_results: ar,
        verdict: verdict.into(),
        policy: policy.into(),
    }
}

fn is_temp(r: &str) -> bool {
    r.eq_ignore_ascii_case("temperror")
}

fn tags(rec: &str) -> impl Iterator<Item = (String, String)> + '_ {
    rec.split(';').filter_map(|t| {
        let (k, v) = t.trim().split_once('=')?;
        Some((k.trim().to_ascii_lowercase(), v.trim().to_ascii_lowercase()))
    })
}

/// Parses p= (none|quarantine|reject); unknown/absent → none.
fn policy_of(rec: &str) -> &'static str {
    for (k, v) in tags(rec) {
        if k == "p" {
            match v.as_str() {
                "quarantine" => return "quarantine",
                "reject" => return "reject",
                _ => {}
            }
        }
    }
    "none"
}

/// adkim/aspf alignment modes; `true` = strict. Both default to relaxed.
fn alignment_modes(rec: &str) -> (bool, bool) {
    let (mut d, mut s) = (false, false);
    for (k, v) in tags(rec) {
        match k.as_str() {
            "adkim" => d = v == "s",
            "aspf" => s = v == "s",
            _ => {}
        }
    }
    (d, s)
}

fn aligned(auth_domain: &str, from: &str, strict: bool) -> bool {
    let a = auth_domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if a.is_empty() {
        return false;
    }
    if a.eq_ignore_ascii_case(from) {
        return true;
    }
    if strict {
        return false;
    }
    let of = org_domain(from);
    !of.is_empty() && org_domain(&a) == of
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Static;
    use std::time::Duration;

    fn sig(r: &str, d: &str) -> Signature {
        Signature {
            result: r.into(),
            domain: d.into(),
        }
    }

    fn ev(r: Static) -> Evaluator<Static> {
        Evaluator::new(r, Duration::from_secs(1))
    }

    #[tokio::test]
    async fn pass_via_relaxed_dkim() {
        let e = ev(Static::default().with_txt("_dmarc.example.com", &["v=DMARC1; p=reject"]));
        let r = e
            .evaluate(
                "example.com",
                "fail",
                "",
                &[sig("pass", "mail.example.com")],
            )
            .await;
        assert_eq!(r.verdict, "pass");
        assert_eq!(r.policy, "reject");
        assert_eq!(r.auth_results, "dmarc=pass header.from=example.com");
    }

    #[tokio::test]
    async fn strict_dkim_fails_subdomain() {
        let e =
            ev(Static::default()
                .with_txt("_dmarc.example.com", &["v=DMARC1; p=quarantine; adkim=s"]));
        let r = e
            .evaluate(
                "example.com",
                "none",
                "",
                &[sig("pass", "mail.example.com")],
            )
            .await;
        assert_eq!(r.verdict, "fail");
        assert_eq!(r.policy, "quarantine");
    }

    #[tokio::test]
    async fn spf_alignment_and_org_fallback() {
        let e = ev(Static::default().with_txt("_dmarc.example.com", &["v=DMARC1; p=none"]));
        let r = e
            .evaluate("news.example.com", "pass", "bounce.example.com", &[])
            .await;
        assert_eq!(r.verdict, "pass");
        assert_eq!(r.policy, "none");
    }

    #[tokio::test]
    async fn none_temp_and_multiple() {
        let e = ev(Static::default());
        assert_eq!(
            e.evaluate("example.org", "pass", "example.org", &[])
                .await
                .verdict,
            "none"
        );
        assert_eq!(
            e.evaluate("", "pass", "", &[]).await.auth_results,
            "dmarc=none"
        );

        let e = ev(Static::default().with_temp("_dmarc.example.org"));
        assert_eq!(
            e.evaluate("example.org", "pass", "x.net", &[])
                .await
                .verdict,
            "temperror"
        );

        let e = ev(Static::default().with_txt(
            "_dmarc.example.org",
            &["v=DMARC1; p=reject", "v=DMARC1; p=none"],
        ));
        assert_eq!(
            e.evaluate("example.org", "fail", "", &[]).await.verdict,
            "none"
        );

        let e = ev(Static::default().with_txt("_dmarc.example.org", &["v=DMARC1; p=reject"]));
        let r = e
            .evaluate("example.org", "temperror", "example.org", &[])
            .await;
        assert_eq!(r.verdict, "temperror");
        assert_eq!(r.policy, "reject");
    }
}
