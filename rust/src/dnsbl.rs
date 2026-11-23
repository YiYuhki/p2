//! Checks a connecting client IP against DNS block lists (RBLs). Port of the Go
//! `internal/dnsbl` package. The DNS lookup is behind a [`Resolver`] trait so
//! the reversal/zone logic is testable without real DNS.

use std::net::IpAddr;

/// Looks up A records for a host. The real implementation uses the system
/// resolver; tests inject a fake.
pub trait Resolver {
    /// Returns the A records for `host`, or an error. A "not found" (NXDOMAIN)
    /// should be returned as `Ok(empty)` or an error — either is treated as
    /// "not listed".
    fn lookup_host(&self, host: &str) -> Result<Vec<String>, String>;
}

/// A resolver backed by the system resolver via `ToSocketAddrs` (A/AAAA
/// lookups, which is what A-record DNSBLs need). Blocking — call from a blocking
/// context (e.g. `spawn_blocking`).
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

/// Queries one or more DNSBL zones.
pub struct Checker<R: Resolver> {
    zones: Vec<String>,
    resolver: R,
}

impl<R: Resolver> Checker<R> {
    /// Returns a checker, or `None` when no zones are configured (disabled).
    pub fn new(zones: &[String], resolver: R) -> Option<Self> {
        let clean: Vec<String> = zones
            .iter()
            .map(|z| z.trim().trim_end_matches('.').to_string())
            .filter(|z| !z.is_empty())
            .collect();
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
        if is_skippable(ip) {
            return None;
        }
        let prefix = reverse(ip)?;
        for zone in &self.zones {
            let query = format!("{}.{}", prefix, zone);
            match self.resolver.lookup_host(&query) {
                Ok(addrs) if !addrs.is_empty() => return Some(zone.clone()),
                _ => {}
            }
        }
        None
    }
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
    fn private_and_loopback_skipped() {
        let c = Checker::new(
            &["zen.example".to_string()],
            Fake {
                listed: HashMap::new(),
            },
        )
        .unwrap();
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.5"] {
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
    }

    #[test]
    fn reverse_ipv6() {
        let got = reverse("2001:db8::1".parse().unwrap()).unwrap();
        assert_eq!(
            got,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
        );
    }
}
