//! Checks a connecting client IP against DNS block lists (RBLs). Port of the Go
//! `internal/dnsbl` package.
//!
//! [`AsyncChecker`] is the production checker: it queries every zone through
//! the shared async [`crate::dns::Resolver`] with a per-lookup timeout and
//! implements [`crate::gateway::ConnGate`] directly. The blocking [`Checker`]
//! over the [`Resolver`] trait is kept for callers that need a synchronous
//! lookup. Both only count answers that are real listings (see
//! [`is_listing_answer`]), not DNSBL error codes or hijacked NXDOMAINs.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

/// Default per-lookup timeout for [`AsyncChecker`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Looks up A records for a host (blocking). Tests inject a fake.
pub trait Resolver {
    /// Returns the A records for `host`, or an error. A "not found" (NXDOMAIN)
    /// should be returned as `Ok(empty)` or an error — either is treated as
    /// "not listed".
    fn lookup_host(&self, host: &str) -> Result<Vec<String>, String>;
}

/// A resolver backed by the system resolver via `ToSocketAddrs`. Blocking —
/// call from a blocking context (e.g. `spawn_blocking`). Prefer
/// [`AsyncChecker`].
pub struct StdResolver;

impl Resolver for StdResolver {
    fn lookup_host(&self, host: &str) -> Result<Vec<String>, String> {
        use std::net::ToSocketAddrs;
        match (host, 0u16).to_socket_addrs() {
            Ok(addrs) => Ok(addrs.map(|a| a.ip().to_string()).collect()),
            Err(e) => Err(e.to_string()),
        }
    }
}

fn clean_zones(zones: &[String]) -> Vec<String> {
    zones
        .iter()
        .map(|z| z.trim().trim_end_matches('.').to_string())
        .filter(|z| !z.is_empty())
        .collect()
}

/// Whether a DNSBL A-record answer means "listed": an address in 127.0.0.0/8
/// at or above 127.0.0.2, excluding 127.255.255.0/24 (the range Spamhaus and
/// others use for query errors such as "public resolver blocked"). Anything
/// else (e.g. an ISP resolver's NXDOMAIN-hijack address, or 127.0.0.1) is
/// ignored.
pub fn is_listing_answer(ip: IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => return false,
        },
    };
    let o = v4.octets();
    o[0] == 127 && v4 >= Ipv4Addr::new(127, 0, 0, 2) && !(o[1] == 255 && o[2] == 255)
}

/// Queries one or more DNSBL zones with a blocking resolver.
pub struct Checker<R: Resolver> {
    zones: Vec<String>,
    resolver: R,
}

impl<R: Resolver> Checker<R> {
    /// Returns a checker, or `None` when no zones are configured (disabled).
    pub fn new(zones: &[String], resolver: R) -> Option<Self> {
        let clean = clean_zones(zones);
        if clean.is_empty() {
            return None;
        }
        Some(Checker {
            zones: clean,
            resolver,
        })
    }

    /// Reports whether `ip` is on any configured DNSBL, returning the first zone
    /// that lists it. Loopback/private/link-local addresses are never queried.
    pub fn listed(&self, ip: IpAddr) -> Option<String> {
        let prefix = query_prefix(ip)?;
        for zone in &self.zones {
            let query = format!("{}.{}", prefix, zone);
            if let Ok(addrs) = self.resolver.lookup_host(&query) {
                if addrs
                    .iter()
                    .filter_map(|a| a.parse::<IpAddr>().ok())
                    .any(is_listing_answer)
                {
                    return Some(zone.clone());
                }
            }
        }
        None
    }
}

/// Queries DNSBL zones through the async resolver, concurrently, each lookup
/// bounded by a timeout. A timed-out or failed lookup counts as "not listed".
pub struct AsyncChecker {
    zones: Vec<String>,
    resolver: Arc<dyn crate::dns::Resolver>,
    timeout: Duration,
}

impl AsyncChecker {
    /// Returns a checker, or `None` when no zones are configured (disabled).
    /// `timeout` bounds each lookup (zero -> [`DEFAULT_TIMEOUT`]).
    pub fn new(
        zones: &[String],
        resolver: Arc<dyn crate::dns::Resolver>,
        timeout: Duration,
    ) -> Option<Self> {
        let clean = clean_zones(zones);
        if clean.is_empty() {
            return None;
        }
        Some(AsyncChecker {
            zones: clean,
            resolver,
            timeout: if timeout.is_zero() {
                DEFAULT_TIMEOUT
            } else {
                timeout
            },
        })
    }

    /// Reports whether `ip` is on any configured DNSBL, returning the first
    /// (in configuration order) zone that lists it.
    pub async fn listed(&self, ip: IpAddr) -> Option<String> {
        let prefix = query_prefix(ip)?;
        let mut set = tokio::task::JoinSet::new();
        for (i, zone) in self.zones.iter().enumerate() {
            let query = format!("{prefix}.{zone}");
            let resolver = self.resolver.clone();
            let to = self.timeout;
            set.spawn(async move {
                let hit = match tokio::time::timeout(to, resolver.ip(&query)).await {
                    Ok(Ok(addrs)) => addrs.into_iter().any(is_listing_answer),
                    _ => false,
                };
                (i, hit)
            });
        }
        let mut first: Option<usize> = None;
        while let Some(res) = set.join_next().await {
            if let Ok((i, true)) = res {
                first = Some(first.map_or(i, |f| f.min(i)));
            }
        }
        first.map(|i| self.zones[i].clone())
    }
}

#[async_trait]
impl crate::gateway::ConnGate for AsyncChecker {
    async fn gate(&self, ip: IpAddr) -> Option<crate::gateway::SmtpError> {
        let zone = self.listed(ip).await?;
        Some(crate::gateway::SmtpError::new(
            554,
            &format!("Client host [{ip}] blocked by {zone}"),
        ))
    }
}

/// The reversed query prefix for `ip`, or `None` for addresses that are never
/// queried (loopback/private/link-local/unspecified).
fn query_prefix(ip: IpAddr) -> Option<String> {
    let ip = ip.to_canonical();
    if is_skippable(ip) {
        return None;
    }
    reverse(ip)
}

fn is_skippable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || is_v6_local(v6),
    }
}

fn is_v6_local(v6: std::net::Ipv6Addr) -> bool {
    let seg = v6.segments();
    // fe80::/10 link-local, fc00::/7 unique-local.
    (seg[0] & 0xffc0) == 0xfe80 || (seg[0] & 0xfe00) == 0xfc00
}

/// Builds the reversed-label query prefix: dotted-reversed octets for IPv4,
/// reversed nibbles for IPv6.
pub fn reverse(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0]))
        }
        IpAddr::V6(v6) => {
            let b = v6.octets();
            let mut parts: Vec<String> = Vec::with_capacity(32);
            for byte in b.iter().rev() {
                parts.push(format!("{:x}", byte & 0x0f));
                parts.push(format!("{:x}", byte >> 4));
            }
            Some(parts.join("."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fake {
        listed: HashMap<String, Vec<String>>,
    }
    impl Resolver for Fake {
        fn lookup_host(&self, host: &str) -> Result<Vec<String>, String> {
            match self.listed.get(host) {
                Some(a) => Ok(a.clone()),
                None => Err("no such host".into()),
            }
        }
    }

    #[test]
    fn listed_ipv4() {
        let mut m = HashMap::new();
        m.insert(
            "1.2.0.192.zen.example".to_string(),
            vec!["127.0.0.2".to_string()],
        );
        let c = Checker::new(
            &["zen.example".to_string(), "bl.example".to_string()],
            Fake { listed: m },
        )
        .unwrap();
        assert_eq!(
            c.listed("192.0.2.1".parse().unwrap()),
            Some("zen.example".to_string())
        );
        assert_eq!(c.listed("198.51.100.9".parse().unwrap()), None);
    }

    #[test]
    fn error_codes_not_listed() {
        let mut m = HashMap::new();
        m.insert(
            "1.2.0.192.zen.example".to_string(),
            vec!["127.255.255.254".to_string()],
        );
        m.insert(
            "2.2.0.192.zen.example".to_string(),
            vec!["198.51.100.1".to_string()],
        );
        let c = Checker::new(&["zen.example".to_string()], Fake { listed: m }).unwrap();
        assert_eq!(c.listed("192.0.2.1".parse().unwrap()), None);
        assert_eq!(c.listed("192.0.2.2".parse().unwrap()), None);
    }

    #[test]
    fn listing_answer_range() {
        for (ip, want) in [
            ("127.0.0.2", true),
            ("127.0.0.11", true),
            ("127.0.1.2", true),
            ("127.0.0.255", true),
            ("127.0.0.1", false),
            ("127.0.0.0", false),
            ("127.255.255.252", false),
            ("127.255.255.254", false),
            ("10.0.0.2", false),
            ("::1", false),
        ] {
            assert_eq!(is_listing_answer(ip.parse().unwrap()), want, "{ip}");
        }
    }

    #[test]
    fn private_and_loopback_skipped() {
        let c = Checker::new(
            &["zen.example".to_string()],
            Fake {
                listed: HashMap::new(),
            },
        )
        .unwrap();
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.5", "::ffff:10.0.0.1"] {
            assert_eq!(c.listed(ip.parse().unwrap()), None);
        }
    }

    #[test]
    fn disabled_without_zones() {
        assert!(Checker::new(
            &[],
            Fake {
                listed: HashMap::new()
            }
        )
        .is_none());
        assert!(AsyncChecker::new(
            &[" ".into()],
            Arc::new(crate::dns::Static::default()),
            Duration::ZERO
        )
        .is_none());
    }

    #[test]
    fn reverse_ipv6() {
        let got = reverse("2001:db8::1".parse().unwrap()).unwrap();
        assert_eq!(
            got,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
        );
    }

    #[tokio::test]
    async fn async_listed_and_gate() {
        use crate::gateway::ConnGate;
        let r = crate::dns::Static::default()
            .with_ip("1.2.0.192.bl.example", &["127.0.0.4"])
            .with_ip("1.2.0.192.zen.example", &["127.255.255.254"])
            .with_temp("2.2.0.192.zen.example");
        let c = AsyncChecker::new(
            &["zen.example".into(), "bl.example".into()],
            Arc::new(r),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            c.listed("192.0.2.1".parse().unwrap()).await,
            Some("bl.example".into())
        );
        assert_eq!(c.listed("192.0.2.2".parse().unwrap()).await, None);
        assert_eq!(c.listed("10.0.0.1".parse().unwrap()).await, None);
        let e = c.gate("192.0.2.1".parse().unwrap()).await.unwrap();
        assert_eq!(e.code, 554);
        assert!(c.gate("192.0.2.9".parse().unwrap()).await.is_none());
    }

    struct Slow;
    #[async_trait]
    impl crate::dns::Resolver for Slow {
        async fn txt(&self, _: &str) -> crate::dns::Result<Vec<String>> {
            Err(crate::dns::DnsError::NotFound)
        }
        async fn ip(&self, _: &str) -> crate::dns::Result<Vec<IpAddr>> {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(vec!["127.0.0.2".parse().unwrap()])
        }
        async fn mx(&self, _: &str) -> crate::dns::Result<Vec<String>> {
            Err(crate::dns::DnsError::NotFound)
        }
    }

    #[tokio::test]
    async fn async_lookup_timeout() {
        let c = AsyncChecker::new(
            &["zen.example".into()],
            Arc::new(Slow),
            Duration::from_millis(50),
        )
        .unwrap();
        let start = std::time::Instant::now();
        assert_eq!(c.listed("192.0.2.1".parse().unwrap()).await, None);
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
