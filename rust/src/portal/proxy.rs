//! Client-address resolution behind reverse proxies.
//!
//! `X-Forwarded-For` is only honoured when the TCP peer is a configured
//! trusted proxy. The header is then walked right to left (each proxy appends
//! the address it received the request from) and the first address that is
//! not itself a trusted proxy is the client. Entries to the left of that are
//! client-controlled and never used.

use std::net::IpAddr;

/// An IP network (address + prefix length).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    addr: IpAddr,
    len: u8,
}

impl Net {
    /// Parses `ip` or `ip/len` (IPv4 or IPv6).
    pub fn parse(s: &str) -> Result<Net, String> {
        let s = s.trim();
        let (ip, len) = match s.split_once('/') {
            Some((ip, len)) => (ip, Some(len)),
            None => (s, None),
        };
        let addr: IpAddr = ip
            .trim()
            .parse()
            .map_err(|_| format!("invalid IP address {ip:?}"))?;
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = match len {
            None => max,
            Some(l) => l
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|l| *l <= max)
                .ok_or_else(|| format!("invalid prefix length in {s:?}"))?,
        };
        Ok(Net { addr, len })
    }

    /// Reports whether `ip` lies in this network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.len)
                };
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.len)
                };
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

/// Parses a list of trusted proxies.
pub fn parse_nets(list: &[String]) -> Result<Vec<Net>, String> {
    list.iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| Net::parse(s))
        .collect()
}

fn trusted(nets: &[Net], ip: IpAddr) -> bool {
    nets.iter().any(|n| n.contains(ip))
}

/// Parses one X-Forwarded-For element (tolerates `[v6]:port` and `v4:port`).
fn parse_hop(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip.to_canonical());
    }
    if let Some(rest) = s.strip_prefix('[') {
        return rest
            .split(']')
            .next()?
            .parse::<IpAddr>()
            .ok()
            .map(|ip| ip.to_canonical());
    }
    let (ip, _port) = s.rsplit_once(':')?;
    ip.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
}

/// Resolves the client address of a request.
///
/// `peer` is the TCP peer; `xff` are the X-Forwarded-For header values in
/// order. Forwarded headers are ignored unless `use_xff` is set and the peer
/// is in `nets`.
pub fn client_ip(
    peer: Option<IpAddr>,
    xff: &[&str],
    use_xff: bool,
    nets: &[Net],
) -> Option<IpAddr> {
    let peer = peer.map(|p| p.to_canonical())?;
    if !use_xff || !trusted(nets, peer) {
        return Some(peer);
    }
    let hops: Vec<&str> = xff
        .iter()
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .collect();
    let mut client = peer;
    for hop in hops.iter().rev() {
        match parse_hop(hop) {
            // Garbage in the chain: stop at the last address we can vouch for.
            None => break,
            Some(ip) => {
                client = ip;
                if !trusted(nets, ip) {
                    break;
                }
            }
        }
    }
    Some(client)
}

/// Reports whether `peer` is a trusted proxy.
pub fn is_trusted(peer: Option<IpAddr>, nets: &[Net]) -> bool {
    peer.map(|p| trusted(nets, p)).unwrap_or(false)
}

/// The rate-limiter bucket for an address: IPv6 clients are grouped by their
/// /64 (one subscriber typically controls a whole /64), IPv4 by address.
pub fn bucket_key(ip: &str) -> String {
    match ip.parse::<IpAddr>().map(|ip| ip.to_canonical()) {
        Ok(IpAddr::V6(v6)) => {
            let net = u128::from(v6) & (u128::MAX << 64);
            format!("{}/64", std::net::Ipv6Addr::from(net))
        }
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Err(_) => ip.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn nets_parse_and_match() {
        let n = Net::parse("10.0.0.0/8").unwrap();
        assert!(n.contains("10.1.2.3".parse().unwrap()));
        assert!(!n.contains("11.0.0.1".parse().unwrap()));
        assert!(n.contains("::ffff:10.0.0.1".parse().unwrap()), "v4-mapped");
        let h = Net::parse("192.0.2.7").unwrap();
        assert!(h.contains("192.0.2.7".parse().unwrap()));
        assert!(!h.contains("192.0.2.8".parse().unwrap()));
        let v6 = Net::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::5".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        assert!(Net::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
        for bad in ["", "x", "10.0.0.0/33", "::/129", "10.0.0.0/-1"] {
            assert!(Net::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn xff_only_from_trusted_peer_rightmost_untrusted() {
        let nets = parse_nets(&["127.0.0.1".into(), "10.0.0.0/8".into()]).unwrap();
        // Untrusted peer: header ignored.
        assert_eq!(
            client_ip(ip("203.0.113.9"), &["1.2.3.4"], true, &nets),
            ip("203.0.113.9")
        );
        // Disabled: header ignored.
        assert_eq!(
            client_ip(ip("127.0.0.1"), &["1.2.3.4"], false, &nets),
            ip("127.0.0.1")
        );
        // Spoofed leftmost entries are skipped; rightmost untrusted wins.
        assert_eq!(
            client_ip(
                ip("127.0.0.1"),
                &["6.6.6.6, 7.7.7.7", "198.51.100.4, 10.1.1.1"],
                true,
                &nets
            ),
            ip("198.51.100.4")
        );
        // Garbage stops the walk at the last trusted hop.
        assert_eq!(
            client_ip(ip("127.0.0.1"), &["junk, 10.2.2.2"], true, &nets),
            ip("10.2.2.2")
        );
        // Ports and brackets are tolerated.
        assert_eq!(
            client_ip(ip("127.0.0.1"), &["[2001:db8::1]:443"], true, &nets),
            ip("2001:db8::1")
        );
        assert_eq!(
            client_ip(ip("127.0.0.1"), &["198.51.100.4:5555"], true, &nets),
            ip("198.51.100.4")
        );
        // No header: the peer.
        assert_eq!(
            client_ip(ip("127.0.0.1"), &[], true, &nets),
            ip("127.0.0.1")
        );
        assert!(is_trusted(ip("10.9.9.9"), &nets));
        assert!(!is_trusted(ip("11.9.9.9"), &nets));
        assert!(!is_trusted(None, &nets));
    }

    #[test]
    fn ipv6_buckets_by_64() {
        assert_eq!(bucket_key("2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64");
        assert_eq!(
            bucket_key("2001:db8:1:2:ffff::9"),
            bucket_key("2001:db8:1:2::1")
        );
        assert_ne!(bucket_key("2001:db8:1:3::1"), bucket_key("2001:db8:1:2::1"));
        assert_eq!(bucket_key("::ffff:192.0.2.1"), "192.0.2.1");
        assert_eq!(bucket_key("192.0.2.1"), "192.0.2.1");
        assert_eq!(bucket_key("unknown"), "unknown");
    }
}
