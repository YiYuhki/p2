// Package dnsbl checks a connecting client IP against DNS block lists (RBLs).
// A DNSBL publishes listed addresses as A records under a zone: the client's
// IP is reversed and prefixed to the zone (1.2.0.192.zen.spamhaus.org for
// 192.0.2.1) and any returned A record (conventionally 127.0.0.x) means the
// address is listed.
package dnsbl

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Resolver looks up A records for a host. *net.Resolver satisfies it.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Checker queries one or more DNSBL zones.
type Checker struct {
	zones    []string
	resolver Resolver
	timeout  time.Duration
	log      *slog.Logger
}

// New returns a Checker, or nil when no zones are configured (disabled).
func New(zones []string, timeout time.Duration, resolver Resolver, log *slog.Logger) *Checker {
	clean := make([]string, 0, len(zones))
	for _, z := range zones {
		z = strings.TrimSpace(strings.TrimSuffix(z, "."))
		if z != "" {
			clean = append(clean, z)
		}
	}
	if len(clean) == 0 {
		return nil
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Checker{zones: clean, resolver: resolver, timeout: timeout, log: log}
}

// Listed reports whether ip is on any configured DNSBL, returning the first
// zone that lists it. A nil Checker reports not listed, so callers need not
// check whether the feature is enabled. Loopback and private addresses are
// never queried (they are never meaningfully listed and would leak internal
// topology to the DNSBL operator).
func (c *Checker) Listed(ctx context.Context, ip netip.Addr) (bool, string) {
	if c == nil || !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return false, ""
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	prefix := reverse(ip)
	if prefix == "" {
		return false, ""
	}
	for _, zone := range c.zones {
		addrs, err := c.resolver.LookupHost(ctx, prefix+"."+zone)
		if err != nil {
			// NXDOMAIN (the common "not listed" answer) arrives as an error;
			// only log a genuine resolver failure at debug level.
			if !isNotFound(err) && c.log != nil {
				c.log.Debug("dnsbl lookup error", "zone", zone, "err", err)
			}
			continue
		}
		if len(addrs) > 0 {
			return true, zone
		}
	}
	return false, ""
}

func isNotFound(err error) bool {
	var d *net.DNSError
	return strings.Contains(err.Error(), "no such host") ||
		(asDNSError(err, &d) && d.IsNotFound)
}

func asDNSError(err error, target **net.DNSError) bool {
	if e, ok := err.(*net.DNSError); ok {
		*target = e
		return true
	}
	return false
}

// reverse builds the reversed-label query prefix for ip: dotted-reversed octets
// for IPv4, reversed nibbles for IPv6. Returns "" for an unexpected form.
func reverse(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is4() {
		b := ip.As4()
		return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." +
			strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0]))
	}
	if ip.Is6() {
		b := ip.As16()
		const hex = "0123456789abcdef"
		var sb strings.Builder
		for i := len(b) - 1; i >= 0; i-- {
			sb.WriteByte(hex[b[i]&0x0f])
			sb.WriteByte('.')
			sb.WriteByte(hex[b[i]>>4])
			if i > 0 {
				sb.WriteByte('.')
			}
		}
		return sb.String()
	}
	return ""
}
