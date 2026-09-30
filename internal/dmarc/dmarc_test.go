package dmarc

import (
	"context"
	"net"
	"strings"
	"testing"
)

type fakeResolver struct{ txt map[string][]string }

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	name = strings.TrimSuffix(name, ".")
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "nx", Name: name, IsNotFound: true}
}

func eval(t *testing.T, txt map[string][]string, from, spfRes, spfDom string, dkim []Signature) string {
	t.Helper()
	e := New(fakeResolver{txt: txt}, 0)
	return e.Evaluate(context.Background(), from, spfRes, spfDom, dkim)
}

func TestDMARCNoRecord(t *testing.T) {
	got := eval(t, map[string][]string{}, "example.com", "pass", "example.com", nil)
	if got != "dmarc=none header.from=example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestDMARCPassViaSPFRelaxed(t *testing.T) {
	txt := map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}}
	// SPF pass on a subdomain aligns under relaxed (same org domain).
	got := eval(t, txt, "example.com", "pass", "mail.example.com", nil)
	if got != "dmarc=pass header.from=example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestDMARCStrictSPFRejectsSubdomain(t *testing.T) {
	txt := map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; aspf=s"}}
	got := eval(t, txt, "example.com", "pass", "mail.example.com", nil)
	if got != "dmarc=fail header.from=example.com" {
		t.Fatalf("strict aspf should fail subdomain, got %q", got)
	}
}

func TestDMARCPassViaDKIM(t *testing.T) {
	txt := map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=quarantine"}}
	got := eval(t, txt, "example.com", "fail", "evil.org", []Signature{{Result: "pass", Domain: "example.com"}})
	if got != "dmarc=pass header.from=example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestDMARCFailUnaligned(t *testing.T) {
	txt := map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}}
	got := eval(t, txt, "example.com", "pass", "evil.org", []Signature{{Result: "pass", Domain: "evil.org"}})
	if got != "dmarc=fail header.from=example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestDMARCOrgDomainFallback(t *testing.T) {
	// Policy published at the org domain applies to a subdomain From.
	txt := map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}}
	got := eval(t, txt, "sub.example.com", "pass", "sub.example.com", nil)
	if got != "dmarc=pass header.from=sub.example.com" {
		t.Fatalf("org-domain policy should apply to subdomain, got %q", got)
	}
}

func TestDMARCTempError(t *testing.T) {
	e := New(errResolver{}, 0)
	got := e.Evaluate(context.Background(), "example.com", "pass", "example.com", nil)
	if got != "dmarc=temperror header.from=example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestDMARCNoFromDomain(t *testing.T) {
	got := eval(t, map[string][]string{}, "", "pass", "example.com", nil)
	if got != "dmarc=none" {
		t.Fatalf("got %q", got)
	}
}

type errResolver struct{}

func (errResolver) LookupTXT(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{Err: "server misbehaving", IsTemporary: true}
}

func TestDMARCMultipleRecordsIsNone(t *testing.T) {
	txt := map[string][]string{"_dmarc.example.com": {
		"v=DMARC1; p=reject", "v=DMARC1; p=none",
	}}
	got := eval(t, txt, "example.com", "pass", "example.com", nil)
	if got != "dmarc=none header.from=example.com" {
		t.Fatalf("multiple DMARC records must be treated as none, got %q", got)
	}
}

func TestDMARCTempErrorFromUnderlying(t *testing.T) {
	txt := map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}}
	// No pass; DKIM had a transient temperror -> DMARC temperror, not fail.
	got := eval(t, txt, "example.com", "none", "", []Signature{{Result: "temperror", Domain: "example.com"}})
	if got != "dmarc=temperror header.from=example.com" {
		t.Fatalf("got %q", got)
	}
}
