//! Async DNS abstraction shared by the SPF, DKIM and DMARC verifiers. The real
//! implementation uses hickory-resolver (system configuration); tests use the
//! in-memory [`Static`] resolver.

use std::collections::HashMap;
use std::net::IpAddr;

use async_trait::async_trait;

/// DNS lookup outcome classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsError {
    /// NXDOMAIN or an empty answer.
    NotFound,
    /// A transient failure (timeout, SERVFAIL, network).
    Temp(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::NotFound => write!(f, "dns: not found"),
            DnsError::Temp(e) => write!(f, "dns: {e}"),
        }
    }
}
impl std::error::Error for DnsError {}

pub type Result<T> = std::result::Result<T, DnsError>;

/// The DNS surface the authentication verifiers need.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// TXT records, each with its character-strings concatenated.
    async fn txt(&self, name: &str) -> Result<Vec<String>>;
    /// A and AAAA addresses.
    async fn ip(&self, name: &str) -> Result<Vec<IpAddr>>;
    /// MX exchange host names (preference order).
    async fn mx(&self, name: &str) -> Result<Vec<String>>;
}

fn fqdn(name: &str) -> String {
    let n = name.trim();
    if n.ends_with('.') {
        n.to_string()
    } else {
        format!("{n}.")
    }
}

/// hickory-resolver backed implementation using the system configuration
/// (falling back to the library defaults when /etc/resolv.conf is unusable).
pub struct Hickory {
    inner: hickory_resolver::TokioResolver,
}

impl Hickory {
    pub fn new() -> Self {
        let builder = match hickory_resolver::TokioResolver::builder_tokio() {
            Ok(b) => b,
            Err(_) => hickory_resolver::TokioResolver::builder_with_config(
                hickory_resolver::config::ResolverConfig::default(),
                hickory_resolver::name_server::TokioConnectionProvider::default(),
            ),
        };
        Hickory {
            inner: builder.build(),
        }
    }
}

impl Default for Hickory {
    fn default() -> Self {
        Self::new()
    }
}

fn classify(e: hickory_resolver::ResolveError) -> DnsError {
    if e.is_nx_domain() || e.is_no_records_found() {
        DnsError::NotFound
    } else {
        DnsError::Temp(e.to_string())
    }
}

#[async_trait]
impl Resolver for Hickory {
    async fn txt(&self, name: &str) -> Result<Vec<String>> {
        let l = self.inner.txt_lookup(fqdn(name)).await.map_err(classify)?;
        Ok(l.iter()
            .map(|t| {
                t.txt_data()
                    .iter()
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect::<String>()
            })
            .collect())
    }

    async fn ip(&self, name: &str) -> Result<Vec<IpAddr>> {
        let l = self.inner.lookup_ip(fqdn(name)).await.map_err(classify)?;
        Ok(l.iter().collect())
    }

    async fn mx(&self, name: &str) -> Result<Vec<String>> {
        let l = self.inner.mx_lookup(fqdn(name)).await.map_err(classify)?;
        let mut v: Vec<(u16, String)> = l
            .iter()
            .map(|m| {
                (
                    m.preference(),
                    m.exchange().to_utf8().trim_end_matches('.').to_string(),
                )
            })
            .collect();
        v.sort();
        Ok(v.into_iter().map(|(_, h)| h).collect())
    }
}

/// In-memory resolver for tests and static configurations. Names are matched
/// case-insensitively without a trailing dot. Names listed in `temp` fail with
/// a temporary error.
#[derive(Clone, Debug, Default)]
pub struct Static {
    pub txt: HashMap<String, Vec<String>>,
    pub ip: HashMap<String, Vec<IpAddr>>,
    pub mx: HashMap<String, Vec<String>>,
    pub temp: Vec<String>,
}

impl Static {
    fn key(name: &str) -> String {
        name.trim().trim_end_matches('.').to_ascii_lowercase()
    }
    fn check_temp(&self, k: &str) -> Result<()> {
        if self.temp.iter().any(|t| Self::key(t) == k) {
            return Err(DnsError::Temp("servfail".into()));
        }
        Ok(())
    }
    pub fn with_txt(mut self, name: &str, recs: &[&str]) -> Self {
        self.txt.insert(
            Self::key(name),
            recs.iter().map(|s| s.to_string()).collect(),
        );
        self
    }
    pub fn with_ip(mut self, name: &str, ips: &[&str]) -> Self {
        self.ip.insert(
            Self::key(name),
            ips.iter().map(|s| s.parse().expect("ip")).collect(),
        );
        self
    }
    pub fn with_mx(mut self, name: &str, hosts: &[&str]) -> Self {
        self.mx.insert(
            Self::key(name),
            hosts.iter().map(|s| s.to_string()).collect(),
        );
        self
    }
    pub fn with_temp(mut self, name: &str) -> Self {
        self.temp.push(name.to_string());
        self
    }
}

fn found<T: Clone>(m: &HashMap<String, Vec<T>>, k: &str) -> Result<Vec<T>> {
    match m.get(k) {
        Some(v) if !v.is_empty() => Ok(v.clone()),
        _ => Err(DnsError::NotFound),
    }
}

#[async_trait]
impl Resolver for Static {
    async fn txt(&self, name: &str) -> Result<Vec<String>> {
        let k = Self::key(name);
        self.check_temp(&k)?;
        found(&self.txt, &k)
    }
    async fn ip(&self, name: &str) -> Result<Vec<IpAddr>> {
        let k = Self::key(name);
        self.check_temp(&k)?;
        found(&self.ip, &k)
    }
    async fn mx(&self, name: &str) -> Result<Vec<String>> {
        let k = Self::key(name);
        self.check_temp(&k)?;
        found(&self.mx, &k)
    }
}

/// The organizational (registrable) domain per the Public Suffix List, or ""
/// when the name is itself a public suffix or invalid.
pub fn org_domain(domain: &str) -> String {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    psl::domain_str(&d).map(str::to_string).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_domains() {
        assert_eq!(org_domain("mail.example.com"), "example.com");
        assert_eq!(org_domain("a.b.example.co.uk."), "example.co.uk");
        assert_eq!(org_domain("com"), "");
    }

    #[tokio::test]
    async fn static_resolver() {
        let r = Static::default()
            .with_txt("Example.com.", &["v=spf1 -all"])
            .with_temp("bad.example");
        assert_eq!(r.txt("example.com").await.unwrap(), vec!["v=spf1 -all"]);
        assert_eq!(r.txt("none.example").await, Err(DnsError::NotFound));
        assert!(matches!(r.txt("bad.example").await, Err(DnsError::Temp(_))));
    }
}
