package portal

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/yiyuhki/p2/internal/config"
)

func TestClientIPTrustedProxies(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	cases := []struct {
		peer string
		xff  []string
		want string
	}{
		// Untrusted peer: XFF ignored entirely.
		{"203.0.113.5:1234", []string{"1.2.3.4"}, "203.0.113.5"},
		// Trusted proxy: rightmost untrusted hop, not the spoofable leftmost.
		{"10.0.0.1:1234", []string{"6.6.6.6, 198.51.100.7"}, "198.51.100.7"},
		// Chained trusted proxies are skipped.
		{"10.0.0.1:1234", []string{"6.6.6.6, 198.51.100.7, 10.0.0.2"}, "198.51.100.7"},
		// Multiple header lines are one list.
		{"10.0.0.1:1234", []string{"6.6.6.6", "198.51.100.8"}, "198.51.100.8"},
		// No XFF from a trusted proxy: the proxy itself.
		{"10.0.0.1:1234", nil, "10.0.0.1"},
		// Garbage stops the walk at the last address we could vouch for.
		{"10.0.0.1:1234", []string{"198.51.100.9, junk, 10.0.0.3"}, "10.0.0.3"},
		{"[::ffff:203.0.113.6]:1", []string{"1.2.3.4"}, "203.0.113.6"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.peer
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := clientIP(r, trusted); got != c.want {
			t.Errorf("peer %s xff %q: got %s, want %s", c.peer, c.xff, got, c.want)
		}
	}
	// Without a trusted list XFF is never used.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientIP(r, nil); got != "10.0.0.1" {
		t.Errorf("no trusted proxies: got %s", got)
	}
}

func TestHeaderAuthOnlyFromTrustedProxy(t *testing.T) {
	s := &Server{opts: Options{
		Auth:           AuthOptions{Mode: config.AuthHeader, TrustedHeader: "X-Auth-Request-Email"},
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
	}}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Auth-Request-Email", "bob@example.com")
	r.RemoteAddr = "203.0.113.5:999"
	if u := s.currentUser(r); u != "" {
		t.Fatalf("forged header from untrusted peer accepted: %q", u)
	}
	r.RemoteAddr = "10.0.0.1:999"
	if u := s.currentUser(r); u != "bob@example.com" {
		t.Fatalf("header from trusted proxy rejected: %q", u)
	}
}
