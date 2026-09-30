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

// Result is a structured SPF outcome. Ident is the property name
// ("smtp.mailfrom" or "smtp.helo") and Domain the domain actually evaluated —
// what DMARC needs for alignment.
type Result struct {
	Value  string // pass/fail/softfail/neutral/none/temperror/permerror
	Ident  string // smtp.mailfrom | smtp.helo | ""
	Domain string // the evaluated domain, or ""
}

// AuthResults renders the RFC 8601 method fragment, e.g.
// "spf=pass smtp.mailfrom=example.com".
func (r Result) AuthResults() string {
	if r.Ident == "" || r.Domain == "" {
		return "spf=" + r.Value
	}
	return "spf=" + r.Value + " " + r.Ident + "=" + r.Domain
}

// Check evaluates SPF and returns the rendered Authentication-Results fragment.
func (c *Checker) Check(ctx context.Context, remoteAddr, helo, mailFrom string) string {
	return c.CheckResult(ctx, remoteAddr, helo, mailFrom).AuthResults()
}

// CheckResult evaluates SPF for the given client IP, HELO name and MAIL FROM.
// When MAIL FROM carries no usable domain (a null return-path bounce, or a bare
// address), SPF is evaluated against the HELO identity per RFC 7208 §2.4; if
// neither yields an identity the result is "none". The reported identity always
// matches the domain actually checked.
func (c *Checker) CheckResult(ctx context.Context, remoteAddr, helo, mailFrom string) Result {
	ip := parseIP(remoteAddr)
	if ip == nil {
		return Result{Value: "none"}
	}
	helo = authres.Sanitize(helo)

	var sender string
	res := Result{}
	if d := domainOf(mailFrom); d != "" {
		sender = strings.Trim(strings.TrimSpace(mailFrom), "<>")
		res.Ident, res.Domain = "smtp.mailfrom", d
	} else if helo != "" {
		sender, res.Ident, res.Domain = "postmaster@"+helo, "smtp.helo", helo
	} else {
		return Result{Value: "none"} // nothing to authenticate
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	opts := []spf.Option{spf.WithContext(ctx)}
	if c.resolver != nil {
		opts = append(opts, spf.WithResolver(c.resolver))
	}

	r, _ := spf.CheckHostWithSender(ip, helo, sender, opts...)
	res.Value = string(r)
	return res
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
