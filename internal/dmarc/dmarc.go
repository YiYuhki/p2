// Package dmarc evaluates DMARC (RFC 7489) alignment from already-computed SPF
// and DKIM results and renders an RFC 8601 "dmarc=" method result. It is
// evaluation-only: it never rejects mail, leaving enforcement to policy.
package dmarc

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/yiyuhki/p2/internal/authres"
)

// Resolver is the DNS surface DMARC needs (TXT lookups). *net.Resolver fits.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Signature is a DKIM outcome DMARC evaluates for alignment.
type Signature struct {
	Result string // pass/fail/...
	Domain string // header.d
}

// Evaluator holds the resolver and DNS timeout.
type Evaluator struct {
	resolver Resolver
	timeout  time.Duration
}

// New returns an Evaluator. A nil resolver uses the system resolver; a zero
// timeout defaults to 5s.
func New(resolver Resolver, timeout time.Duration) *Evaluator {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Evaluator{resolver: resolver, timeout: timeout}
}

// Evaluate computes the DMARC result for the From-header domain given the SPF
// result (and the domain SPF authenticated) and the DKIM signatures. It returns
// an RFC 8601 fragment: "dmarc=pass|fail|none|temperror header.from=<domain>".
func (e *Evaluator) Evaluate(ctx context.Context, fromDomain, spfResult, spfDomain string, dkim []Signature) string {
	fromDomain = strings.ToLower(authres.Sanitize(strings.TrimSpace(fromDomain)))
	if fromDomain == "" {
		return "dmarc=none"
	}

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	rec, temp, found := e.lookupPolicy(ctx, fromDomain)
	if temp {
		return "dmarc=temperror header.from=" + fromDomain
	}
	if !found {
		return "dmarc=none header.from=" + fromDomain
	}
	adkim, aspf := alignmentModes(rec)

	// DKIM-authenticated identifier alignment: a passing signature whose d=
	// aligns with the From domain.
	for _, s := range dkim {
		if strings.EqualFold(s.Result, "pass") && aligned(s.Domain, fromDomain, adkim) {
			return "dmarc=pass header.from=" + fromDomain
		}
	}
	// SPF-authenticated identifier alignment: a pass whose MAIL FROM domain
	// aligns with the From domain.
	if strings.EqualFold(spfResult, "pass") && aligned(spfDomain, fromDomain, aspf) {
		return "dmarc=pass header.from=" + fromDomain
	}
	return "dmarc=fail header.from=" + fromDomain
}

// lookupPolicy fetches the DMARC record for the domain, falling back to its
// organizational domain (RFC 7489 §6.6.3). Returns (record, tempError, found).
func (e *Evaluator) lookupPolicy(ctx context.Context, domain string) (string, bool, bool) {
	if rec, temp, ok := e.fetch(ctx, domain); ok || temp {
		return rec, temp, ok
	}
	org := orgDomain(domain)
	if org != "" && org != domain {
		return e.fetch(ctx, org)
	}
	return "", false, false
}

func (e *Evaluator) fetch(ctx context.Context, domain string) (string, bool, bool) {
	txts, err := e.resolver.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return "", false, false // NXDOMAIN / no record
		}
		return "", true, false // temporary DNS failure
	}
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
			return t, false, true
		}
	}
	return "", false, false
}

// alignmentModes parses adkim/aspf tags; both default to relaxed ("r").
func alignmentModes(rec string) (adkim, aspf string) {
	adkim, aspf = "r", "r"
	for _, tag := range strings.Split(rec, ";") {
		kv := strings.SplitN(strings.TrimSpace(tag), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.ToLower(strings.TrimSpace(kv[1]))
		switch k {
		case "adkim":
			if v == "s" {
				adkim = "s"
			}
		case "aspf":
			if v == "s" {
				aspf = "s"
			}
		}
	}
	return adkim, aspf
}

// aligned reports whether authDomain aligns with fromDomain under the mode
// ("s" strict = exact match; "r" relaxed = same organizational domain).
func aligned(authDomain, fromDomain, mode string) bool {
	authDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(authDomain), "."))
	if authDomain == "" {
		return false
	}
	if strings.EqualFold(authDomain, fromDomain) {
		return true
	}
	if mode == "s" {
		return false
	}
	return orgDomain(authDomain) == orgDomain(fromDomain) && orgDomain(fromDomain) != ""
}

func orgDomain(domain string) string {
	d, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(domain, "."))
	if err != nil {
		return ""
	}
	return strings.ToLower(d)
}
