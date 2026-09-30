package spfutil

import (
	"context"
	"net"
	"strings"
	"testing"
)

// fakeResolver serves canned TXT/MX/IP answers for SPF evaluation.
type fakeResolver struct {
	txt map[string][]string
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	name = strings.TrimSuffix(name, ".")
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}
func (f fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error) { return nil, nil }
func (f fakeResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, nil
}
func (f fakeResolver) LookupAddr(context.Context, string) ([]string, error) { return nil, nil }

func TestSPFPass(t *testing.T) {
	r := fakeResolver{txt: map[string][]string{
		"example.com": {"v=spf1 ip4:203.0.113.0/24 -all"},
	}}
	c := New(r, 0)
	got := c.Check(context.Background(), "203.0.113.9:2500", "mail.example.com", "user@example.com")
	if got != "spf=pass smtp.mailfrom=example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestSPFFail(t *testing.T) {
	r := fakeResolver{txt: map[string][]string{
		"example.com": {"v=spf1 ip4:198.51.100.0/24 -all"},
	}}
	c := New(r, 0)
	got := c.Check(context.Background(), "203.0.113.9:2500", "mail.example.com", "user@example.com")
	if got != "spf=fail smtp.mailfrom=example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestSPFNoRecord(t *testing.T) {
	c := New(fakeResolver{txt: map[string][]string{}}, 0)
	got := c.Check(context.Background(), "203.0.113.9:2500", "mail.example.com", "user@example.com")
	if !strings.HasPrefix(got, "spf=none") {
		t.Fatalf("no SPF record should be spf=none, got %q", got)
	}
}

func TestSPFNullSenderUsesHelo(t *testing.T) {
	r := fakeResolver{txt: map[string][]string{
		"mail.example.com": {"v=spf1 ip4:203.0.113.9 -all"},
	}}
	c := New(r, 0)
	got := c.Check(context.Background(), "203.0.113.9:25", "mail.example.com", "")
	if got != "spf=pass smtp.helo=mail.example.com" {
		t.Fatalf("null return-path should authenticate HELO, got %q", got)
	}
}

func TestSPFBadIP(t *testing.T) {
	c := New(fakeResolver{}, 0)
	if got := c.Check(context.Background(), "not-an-ip", "h", "user@example.com"); got != "spf=none" {
		t.Fatalf("unpar?able IP should be spf=none, got %q", got)
	}
}

func TestSanitizeInjection(t *testing.T) {
	if got := domainOf("user@evil.com; spf=pass"); strings.ContainsAny(got, "; ") {
		t.Fatalf("domain not sanitised: %q", got)
	}
}
