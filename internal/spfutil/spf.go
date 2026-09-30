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

	"github.com/yiyuhki/p2/internal/authres"
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
// "spf=pass smtp.mailfrom=example.com". When MAIL FROM carries no usable domain
// (a null return-path bounce, or a bare address), SPF is evaluated against the
// HELO identity per RFC 7208 §2.4; if neither yields an identity the result is
// "spf=none". The reported identity always matches the domain actually checked.
func (c *Checker) Check(ctx context.Context, remoteAddr, helo, mailFrom string) string {
	ip := parseIP(remoteAddr)
	if ip == nil {
		return "spf=none"
	}
	helo = authres.Sanitize(helo)

	var sender, idKey, idVal string
	if d := domainOf(mailFrom); d != "" {
		sender = strings.Trim(strings.TrimSpace(mailFrom), "<>")
		idKey, idVal = "smtp.mailfrom", d
	} else if helo != "" {
		sender, idKey, idVal = "postmaster@"+helo, "smtp.helo", helo
	} else {
		return "spf=none" // nothing to authenticate
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	opts := []spf.Option{spf.WithContext(ctx)}
	if c.resolver != nil {
		opts = append(opts, spf.WithResolver(c.resolver))
	}

	res, _ := spf.CheckHostWithSender(ip, helo, sender, opts...)
	return "spf=" + string(res) + " " + idKey + "=" + idVal
}

func parseIP(remoteAddr string) net.IP {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	return net.ParseIP(strings.TrimSpace(host))
}

// domainOf returns the sanitised domain part of a MAIL FROM address, or "" when
// there is no '@' or the domain is empty.
func domainOf(addr string) string {
	addr = strings.Trim(strings.TrimSpace(addr), "<>")
	i := strings.LastIndexByte(addr, '@')
	if i < 0 || i == len(addr)-1 {
		return ""
	}
	return authres.Sanitize(addr[i+1:])
}
