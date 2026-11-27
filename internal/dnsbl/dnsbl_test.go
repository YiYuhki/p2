package dnsbl

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

type fakeResolver struct {
	listed map[string][]string // query host -> A records
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if a, ok := f.listed[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestListedIPv4(t *testing.T) {
	// 192.0.2.1 listed on zen -> query 1.2.0.192.zen.example
	r := fakeResolver{listed: map[string][]string{"1.2.0.192.zen.example": {"127.0.0.2"}}}
	c := New([]string{"zen.example", "bl.example"}, time.Second, r, nil)
	listed, zone := c.Listed(context.Background(), netip.MustParseAddr("192.0.2.1"))
	if !listed || zone != "zen.example" {
		t.Fatalf("listed=%v zone=%q, want true zen.example", listed, zone)
	}
	// A different IP is not listed anywhere.
	if l, _ := c.Listed(context.Background(), netip.MustParseAddr("198.51.100.9")); l {
		t.Fatal("unlisted IP reported as listed")
	}
}

func TestPrivateAndLoopbackSkipped(t *testing.T) {
	// A resolver that would list everything; private/loopback must never be queried.
	r := fakeResolver{listed: map[string][]string{}}
	c := New([]string{"zen.example"}, time.Second, r, nil)
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.0.5"} {
		if l, _ := c.Listed(context.Background(), netip.MustParseAddr(ip)); l {
			t.Fatalf("%s should be skipped", ip)
		}
	}
}

func TestNilCheckerDisabled(t *testing.T) {
	if New(nil, 0, nil, nil) != nil {
		t.Fatal("no zones should disable")
	}
	var c *Checker
	if l, _ := c.Listed(context.Background(), netip.MustParseAddr("192.0.2.1")); l {
		t.Fatal("nil checker must report not listed")
	}
}

func TestResolverErrorIsNotListed(t *testing.T) {
	c := New([]string{"zen.example"}, time.Second, errResolver{}, nil)
	if l, _ := c.Listed(context.Background(), netip.MustParseAddr("192.0.2.1")); l {
		t.Fatal("a resolver failure must not count as listed")
	}
}

type errResolver struct{}

func (errResolver) LookupHost(context.Context, string) ([]string, error) {
	return nil, errors.New("server misbehaving")
}

func TestReverseIPv6(t *testing.T) {
	got := reverse(netip.MustParseAddr("2001:db8::1"))
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
	if got != want {
		t.Fatalf("reverse(2001:db8::1) = %q, want %q", got, want)
	}
}
