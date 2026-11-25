//! SPF (RFC 7208) evaluation with an injectable async resolver. Port of the Go
//! `internal/spfutil` wrapper plus a native `check_host()` implementation
//! (ip4/ip6/a/mx/ptr-as-neutral/include/exists/redirect/all, macros, the
//! 10-DNS-mechanism limit and the 2-void-lookup limit).

use std::net::IpAddr;

use async_trait::async_trait;

use crate::authres::sanitize;
use crate::dns::{DnsError, Resolver};

/// SPF result values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    None,
    Neutral,
    Pass,
    Fail,
    SoftFail,
    TempError,
    PermError,
}

impl Value {
    pub fn as_str(self) -> &'static str {
        match self {
            Value::None => "none",
            Value::Neutral => "neutral",
            Value::Pass => "pass",
            Value::Fail => "fail",
            Value::SoftFail => "softfail",
            Value::TempError => "temperror",
            Value::PermError => "permerror",
        }
    }
}

/// A structured SPF outcome. `ident` is the property name ("smtp.mailfrom" or
/// "smtp.helo") and `domain` the domain actually evaluated (for DMARC).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Result {
    pub value: String,
    pub ident: String,
    pub domain: String,
}

impl Result {
    fn none() -> Self {
        Result {
            value: "none".into(),
            ident: String::new(),
            domain: String::new(),
        }
    }

    /// RFC 8601 method fragment, e.g. "spf=pass smtp.mailfrom=example.com".
    pub fn auth_results(&self) -> String {
        if self.ident.is_empty() || self.domain.is_empty() {
            format!("spf={}", self.value)
        } else {
            format!("spf={} {}={}", self.value, self.ident, self.domain)
        }
    }
}

/// Evaluates SPF for connections.
pub struct Checker<R: Resolver> {
    resolver: R,
    timeout: std::time::Duration,
}

const MAX_DNS_MECHS: u32 = 10;
const MAX_VOID: u32 = 2;
const MAX_MX_PTR: usize = 10;

struct Ctx<'a> {
    ip: IpAddr,
    sender: &'a str,
    helo: &'a str,
    lookups: u32,
    voids: u32,
}

#[derive(Debug)]
enum Abort {
    Temp,
    Perm,
}

type Eval<T> = std::result::Result<T, Abort>;

impl<R: Resolver> Checker<R> {
    pub fn new(resolver: R, timeout: std::time::Duration) -> Self {
        let timeout = if timeout.is_zero() {
            std::time::Duration::from_secs(10)
        } else {
            timeout
        };
        Checker { resolver, timeout }
    }

    /// Evaluates SPF for the client IP, HELO and MAIL FROM. Without a usable
    /// MAIL FROM domain the HELO identity is checked (RFC 7208 §2.4).
    pub async fn check(&self, remote_ip: IpAddr, helo: &str, mail_from: &str) -> Result {
        let helo = sanitize(helo.trim());
        let (sender, ident, domain) = match domain_of(mail_from) {
            Some(d) => (
                mail_from
                    .trim()
                    .trim_matches(|c| c == '<' || c == '>')
                    .to_string(),
                "smtp.mailfrom",
                d,
            ),
            None if !helo.is_empty() => (format!("postmaster@{helo}"), "smtp.helo", helo.clone()),
            None => return Result::none(),
        };
        let v = match tokio::time::timeout(
            self.timeout,
            self.check_host(remote_ip, &domain, &sender, &helo),
        )
        .await
        {
            Ok(v) => v,
            Err(_) => Value::TempError,
        };
        Result {
            value: v.as_str().into(),
            ident: ident.into(),
            domain,
        }
    }

    /// RFC 7208 check_host().
    pub async fn check_host(&self, ip: IpAddr, domain: &str, sender: &str, helo: &str) -> Value {
        let mut cx = Ctx {
            ip,
            sender,
            helo,
            lookups: 0,
            voids: 0,
        };
        match self.eval(&mut cx, domain, 0).await {
            Ok(v) => v,
            Err(Abort::Temp) => Value::TempError,
            Err(Abort::Perm) => Value::PermError,
        }
    }

    fn eval<'a>(
        &'a self,
        cx: &'a mut Ctx<'_>,
        domain: &'a str,
        depth: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Eval<Value>> + Send + 'a>>
    where
        R: 'a,
    {
        Box::pin(async move {
            if depth > MAX_DNS_MECHS {
                return Err(Abort::Perm);
            }
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            if !valid_domain(&domain) {
                return Ok(Value::None);
            }
            let txts = match self.resolver.txt(&domain).await {
                Ok(t) => t,
                Err(DnsError::NotFound) => return Ok(Value::None),
                Err(DnsError::Temp(_)) => return Err(Abort::Temp),
            };
            let recs: Vec<&String> = txts.iter().filter(|t| is_spf(t)).collect();
            let rec = match recs.len() {
                0 => return Ok(Value::None),
                1 => recs[0].clone(),
                _ => return Err(Abort::Perm),
            };

            let mut redirect: Option<String> = None;
            for term in rec.split_ascii_whitespace().skip(1) {
                let lower = term.to_ascii_lowercase();
                // Modifiers.
                if let Some((name, val)) = term.split_once('=') {
                    if name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
                        && !name.is_empty()
                        && !name.contains(':')
                    {
                        if name.eq_ignore_ascii_case("redirect") {
                            if redirect.is_some() {
                                return Err(Abort::Perm);
                            }
                            redirect = Some(val.to_string());
                        }
                        continue; // exp= and unknown modifiers are ignored
                    }
                }
                let (qual, mech) = match lower.chars().next() {
                    Some(c @ ('+' | '-' | '~' | '?')) => (c, &term[1..]),
                    _ => ('+', term),
                };
                if self.matches(cx, &domain, mech, depth).await? {
                    return Ok(match qual {
                        '-' => Value::Fail,
                        '~' => Value::SoftFail,
                        '?' => Value::Neutral,
                        _ => Value::Pass,
                    });
                }
            }
            if let Some(r) = redirect {
                bump(cx)?;
                let target = self.expand(cx, &r, &domain)?;
                return match self.eval(cx, &target, depth + 1).await? {
                    Value::None => Err(Abort::Perm),
                    v => Ok(v),
                };
            }
            Ok(Value::Neutral)
        })
    }

    async fn matches(&self, cx: &mut Ctx<'_>, domain: &str, mech: &str, depth: u32) -> Eval<bool> {
        let (name, arg) = match mech.find([':', '/']) {
            Some(i) => (&mech[..i], &mech[i..]),
            None => (mech, ""),
        };
        let name = name.to_ascii_lowercase();
        match name.as_str() {
            "all" if arg.is_empty() => Ok(true),
            "ip4" | "ip6" => {
                let spec = arg.strip_prefix(':').ok_or(Abort::Perm)?;
                let (addr, len) = match spec.split_once('/') {
                    Some((a, l)) => (a, Some(l.parse::<u8>().map_err(|_| Abort::Perm)?)),
                    None => (spec, None),
                };
                let net: IpAddr = addr.parse().map_err(|_| Abort::Perm)?;
                if (name == "ip4") != net.is_ipv4() {
                    return Err(Abort::Perm);
                }
                let max = if net.is_ipv4() { 32 } else { 128 };
                let len = len.unwrap_or(max);
                if len > max {
                    return Err(Abort::Perm);
                }
                Ok(in_cidr(cx.ip, net, len))
            }
            "a" | "mx" => {
                bump(cx)?;
                let (target, v4, v6) = self.domain_cidr(cx, arg, domain)?;
                let hosts = if name == "a" {
                    vec![target]
                } else {
                    match self.resolver.mx(&target).await {
                        Ok(h) => {
                            if h.len() > MAX_MX_PTR {
                                return Err(Abort::Perm);
                            }
                            h
                        }
                        Err(DnsError::NotFound) => {
                            void(cx)?;
                            vec![]
                        }
                        Err(DnsError::Temp(_)) => return Err(Abort::Temp),
                    }
                };
                for h in hosts {
                    match self.resolver.ip(&h).await {
                        Ok(ips) => {
                            for a in ips {
                                let len = if a.is_ipv4() { v4 } else { v6 };
                                if in_cidr(cx.ip, a, len) {
                                    return Ok(true);
                                }
                            }
                        }
                        Err(DnsError::NotFound) => {
                            if name == "a" {
                                void(cx)?;
                            }
                        }
                        Err(DnsError::Temp(_)) => return Err(Abort::Temp),
                    }
                }
                Ok(false)
            }
            "ptr" => {
                // Deprecated (RFC 7208 §5.5); counted but never matches.
                bump(cx)?;
                Ok(false)
            }
            "exists" => {
                bump(cx)?;
                let spec = arg.strip_prefix(':').ok_or(Abort::Perm)?;
                let target = self.expand(cx, spec, domain)?;
                match self.resolver.ip(&target).await {
                    Ok(ips) => Ok(ips.iter().any(|i| i.is_ipv4())),
                    Err(DnsError::NotFound) => {
                        void(cx)?;
                        Ok(false)
                    }
                    Err(DnsError::Temp(_)) => Err(Abort::Temp),
                }
            }
            "include" => {
                bump(cx)?;
                let spec = arg.strip_prefix(':').ok_or(Abort::Perm)?;
                let target = self.expand(cx, spec, domain)?;
                match self.eval(cx, &target, depth + 1).await {
                    Ok(Value::Pass) => Ok(true),
                    Ok(Value::Fail | Value::SoftFail | Value::Neutral) => Ok(false),
                    Ok(Value::None | Value::PermError) | Err(Abort::Perm) => Err(Abort::Perm),
                    Ok(Value::TempError) | Err(Abort::Temp) => Err(Abort::Temp),
                }
            }
            _ => Err(Abort::Perm),
        }
    }

    /// Parses `[:domain-spec][/v4cidr][//v6cidr]` for a/mx.
    fn domain_cidr(&self, cx: &Ctx<'_>, arg: &str, domain: &str) -> Eval<(String, u8, u8)> {
        let (spec, cidr) = match arg.find('/') {
            Some(i) => (&arg[..i], &arg[i..]),
            None => (arg, ""),
        };
        let target = match spec.strip_prefix(':') {
            Some(s) => self.expand(cx, s, domain)?,
            None if spec.is_empty() => domain.to_string(),
            None => return Err(Abort::Perm),
        };
        let (mut v4, mut v6) = (32u8, 128u8);
        if !cidr.is_empty() {
            let (a, b) = match cidr.split_once("//") {
                Some((a, b)) => (a, Some(b)),
                None => (cidr, None),
            };
            if let Some(a) = a.strip_prefix('/') {
                v4 = a.parse().map_err(|_| Abort::Perm)?;
            } else if !a.is_empty() {
                return Err(Abort::Perm);
            }
            if let Some(b) = b {
                v6 = b.parse().map_err(|_| Abort::Perm)?;
            }
            if v4 > 32 || v6 > 128 {
                return Err(Abort::Perm);
            }
        }
        Ok((target, v4, v6))
    }

    /// Expands RFC 7208 §7 macros (s l o d i h v and the literal escapes).
    fn expand(&self, cx: &Ctx<'_>, spec: &str, domain: &str) -> Eval<String> {
        let mut out = String::new();
        let mut it = spec.chars().peekable();
        let (local, sdom) = match cx.sender.rsplit_once('@') {
            Some((l, d)) => (if l.is_empty() { "postmaster" } else { l }, d),
            None => ("postmaster", cx.sender),
        };
        while let Some(c) = it.next() {
            if c != '%' {
                out.push(c);
                continue;
            }
            match it.next() {
                Some('%') => out.push('%'),
                Some('_') => out.push(' '),
                Some('-') => out.push_str("%20"),
                Some('{') => {
                    let mut body = String::new();
                    loop {
                        match it.next() {
                            Some('}') => break,
                            Some(ch) => body.push(ch),
                            None => return Err(Abort::Perm),
                        }
                    }
                    let mut bc = body.chars();
                    let letter = bc.next().ok_or(Abort::Perm)?.to_ascii_lowercase();
                    let rest: String = bc.collect();
                    let val = match letter {
                        's' => cx.sender.to_string(),
                        'l' => local.to_string(),
                        'o' => sdom.to_string(),
                        'd' => domain.to_string(),
                        'i' => match cx.ip {
                            IpAddr::V4(v) => v.to_string(),
                            IpAddr::V6(_) => {
                                let r = crate::dnsbl::reverse(cx.ip).unwrap_or_default();
                                r.split('.').rev().collect::<Vec<_>>().join(".")
                            }
                        },
                        'h' => cx.helo.to_string(),
                        'v' => if cx.ip.is_ipv4() { "in-addr" } else { "ip6" }.to_string(),
                        'p' => "unknown".to_string(),
                        _ => return Err(Abort::Perm),
                    };
                    out.push_str(&transform(&val, &rest)?);
                }
                _ => return Err(Abort::Perm),
            }
        }
        Ok(out)
    }
}

/// Applies a macro transformer: `[digits][r][delimiters]`.
fn transform(val: &str, spec: &str) -> Eval<String> {
    let digits: String = spec.chars().take_while(|c| c.is_ascii_digit()).collect();
    let mut rest = &spec[digits.len()..];
    let reverse = rest.starts_with(['r', 'R']);
    if reverse {
        rest = &rest[1..];
    }
    let delims: Vec<char> = if rest.is_empty() {
        vec!['.']
    } else {
        rest.chars().collect()
    };
    if rest.chars().any(|c| !".-+,/_=".contains(c)) {
        return Err(Abort::Perm);
    }
    let mut parts: Vec<&str> = val.split(|c| delims.contains(&c)).collect();
    if reverse {
        parts.reverse();
    }
    if !digits.is_empty() {
        let n: usize = digits.parse().map_err(|_| Abort::Perm)?;
        if n == 0 {
            return Err(Abort::Perm);
        }
        if parts.len() > n {
            parts = parts.split_off(parts.len() - n);
        }
    }
    Ok(parts.join("."))
}

fn bump(cx: &mut Ctx<'_>) -> Eval<()> {
    cx.lookups += 1;
    if cx.lookups > MAX_DNS_MECHS {
        Err(Abort::Perm)
    } else {
        Ok(())
    }
}

fn void(cx: &mut Ctx<'_>) -> Eval<()> {
    cx.voids += 1;
    if cx.voids > MAX_VOID {
        Err(Abort::Perm)
    } else {
        Ok(())
    }
}

fn is_spf(t: &str) -> bool {
    let l = t.trim().to_ascii_lowercase();
    l == "v=spf1" || l.starts_with("v=spf1 ")
}

fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|l| !l.is_empty() && l.len() <= 63)
}

fn in_cidr(ip: IpAddr, net: IpAddr, len: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if len == 0 {
                0
            } else {
                u32::MAX << (32 - len as u32)
            };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            // IPv4-mapped client addresses compare as IPv4 elsewhere.
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len as u32)
            };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V4(_)) => match a.to_ipv4_mapped() {
            Some(v4) => in_cidr(IpAddr::V4(v4), net, len),
            None => false,
        },
        _ => false,
    }
}

/// Sanitised domain part of a MAIL FROM address, or None without one.
fn domain_of(addr: &str) -> Option<String> {
    let a = addr.trim().trim_matches(|c| c == '<' || c == '>');
    let (_, d) = a.rsplit_once('@')?;
    let d = sanitize(d);
    if d.is_empty() {
        None
    } else {
        Some(d)
    }
}

/// Object-safe SPF checking for the inbound processor.
#[async_trait]
pub trait Check: Send + Sync {
    async fn check(&self, ip: IpAddr, helo: &str, mail_from: &str) -> Result;
}

#[async_trait]
impl<R: Resolver> Check for Checker<R> {
    async fn check(&self, ip: IpAddr, helo: &str, mail_from: &str) -> Result {
        Checker::check(self, ip, helo, mail_from).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Static;
    use std::time::Duration;

    fn ck(r: Static) -> Checker<Static> {
        Checker::new(r, Duration::from_secs(2))
    }

    async fn host(c: &Checker<Static>, ip: &str, d: &str) -> Value {
        c.check_host(ip.parse().unwrap(), d, &format!("user@{d}"), "mx.test")
            .await
    }

    #[tokio::test]
    async fn ip_mechanisms_and_qualifiers() {
        let c = ck(Static::default().with_txt(
            "example.com",
            &["v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 ~all"],
        ));
        assert_eq!(host(&c, "192.0.2.77", "example.com").await, Value::Pass);
        assert_eq!(host(&c, "2001:db8::5", "example.com").await, Value::Pass);
        assert_eq!(
            host(&c, "198.51.100.1", "example.com").await,
            Value::SoftFail
        );
        assert_eq!(host(&c, "1.1.1.1", "nospf.example").await, Value::None);
    }

    #[tokio::test]
    async fn a_mx_include_redirect() {
        let c = ck(Static::default()
            .with_txt(
                "example.com",
                &["v=spf1 a mx/24 include:_spf.partner.net -all"],
            )
            .with_ip("example.com", &["203.0.113.10"])
            .with_mx("example.com", &["mx1.example.com"])
            .with_ip("mx1.example.com", &["198.51.100.20"])
            .with_txt("_spf.partner.net", &["v=spf1 ip4:100.64.0.1 -all"])
            .with_txt("sub.example.com", &["v=spf1 redirect=example.com"]));
        assert_eq!(host(&c, "203.0.113.10", "example.com").await, Value::Pass);
        assert_eq!(host(&c, "198.51.100.99", "example.com").await, Value::Pass);
        assert_eq!(host(&c, "100.64.0.1", "example.com").await, Value::Pass);
        assert_eq!(host(&c, "9.9.9.9", "example.com").await, Value::Fail);
        assert_eq!(host(&c, "100.64.0.1", "sub.example.com").await, Value::Pass);
    }

    #[tokio::test]
    async fn errors() {
        let c = ck(Static::default()
            .with_txt("two.example", &["v=spf1 -all", "v=spf1 +all"])
            .with_txt("badinc.example", &["v=spf1 include:missing.example -all"])
            .with_txt("tmp.example", &["v=spf1 include:servfail.example -all"])
            .with_temp("servfail.example")
            .with_txt("loop.example", &["v=spf1 include:loop.example"])
            .with_txt("bogus.example", &["v=spf1 foo:bar"]));
        assert_eq!(host(&c, "1.2.3.4", "two.example").await, Value::PermError);
        assert_eq!(
            host(&c, "1.2.3.4", "badinc.example").await,
            Value::PermError
        );
        assert_eq!(host(&c, "1.2.3.4", "tmp.example").await, Value::TempError);
        assert_eq!(host(&c, "1.2.3.4", "loop.example").await, Value::PermError);
        assert_eq!(host(&c, "1.2.3.4", "bogus.example").await, Value::PermError);
    }

    #[tokio::test]
    async fn macros_exists() {
        let c = ck(Static::default()
            .with_txt(
                "example.com",
                &["v=spf1 exists:%{ir}.%{l1r-}.allow.%{d} -all"],
            )
            .with_ip("4.3.2.1.user.allow.example.com", &["127.0.0.2"]));
        assert_eq!(host(&c, "1.2.3.4", "example.com").await, Value::Pass);
        assert_eq!(host(&c, "1.2.3.5", "example.com").await, Value::Fail);
    }

    #[tokio::test]
    async fn check_identity_selection() {
        let c = ck(Static::default()
            .with_txt("example.com", &["v=spf1 ip4:192.0.2.1 -all"])
            .with_txt("mx.example.net", &["v=spf1 ip4:192.0.2.1 -all"]));
        let r = c
            .check("192.0.2.1".parse().unwrap(), "x", "<a@example.com>")
            .await;
        assert_eq!(r.auth_results(), "spf=pass smtp.mailfrom=example.com");
        let r = c
            .check("192.0.2.1".parse().unwrap(), "mx.example.net", "<>")
            .await;
        assert_eq!(r.auth_results(), "spf=pass smtp.helo=mx.example.net");
        let r = c.check("192.0.2.1".parse().unwrap(), "", "").await;
        assert_eq!(r.auth_results(), "spf=none");
    }
}
