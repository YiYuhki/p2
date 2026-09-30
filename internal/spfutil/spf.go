// Package spfutil checks the SPF status of an inbound connection and renders it
// as an RFC 8601 Authentication-Results method result. It complements DKIM
// verification so that downstream DMARC evaluation has both inputs.
package spfutil

import (
	"context"
	"net"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
)

// Resolver is the DNS surface SPF needs; *net.Resolver satisfies it, and tests
// can supply a fake.
type Resolver = spf.DNSResolver

// Checker evaluates SPF for a connection.
type Checker struct {
	resolver Resolver
	timeout  time.Duration
}

// New returns a Checker. A nil resolver uses the system resolver; a zero
// timeout defaults to 10s (SPF may perform several DNS lookups).
func New(resolver Resolver, timeout time.Duration) *Checker {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Checker{resolver: resolver, timeout: timeout}
}

// Check evaluates SPF for the given client IP, HELO name and MAIL FROM, and
// returns an Authentication-Results method result such as
// "spf=pass smtp.mailfrom=example.com". A nil/empty MAIL FROM (bounce) is
// checked against the HELO identity per RFC 7208 §2.4.
func (c *Checker) Check(ctx context.Context, remoteAddr, helo, mailFrom string) string {
	ip := parseIP(remoteAddr)
	if ip == nil {
		return "spf=none"
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	opts := []spf.Option{spf.WithContext(ctx)}
	if c.resolver != nil {
		opts = append(opts, spf.WithResolver(c.resolver))
	}

	sender := mailFrom
	idKey, idVal := "smtp.mailfrom", domainOf(mailFrom)
	if sender == "" {
		// Null return-path: authenticate the HELO identity instead.
		sender = "postmaster@" + helo
		idKey, idVal = "smtp.helo", sanitize(helo)
	}

	res, _ := spf.CheckHostWithSender(ip, helo, sender, opts...)
	out := "spf=" + string(res)
	if idVal != "" {
		out += " " + idKey + "=" + idVal
	}
	return out
}

func parseIP(remoteAddr string) net.IP {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	return net.ParseIP(strings.TrimSpace(host))
}

func domainOf(addr string) string {
	addr = strings.TrimSpace(addr)
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		addr = addr[i+1:]
	}
	return sanitize(strings.TrimSuffix(addr, ">"))
}

// sanitize strips characters that could break out of the header field value.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ';' || r == ' ' || r == '\t' || r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
