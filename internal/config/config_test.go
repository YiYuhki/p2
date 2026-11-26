package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePrefixesUnmapsIPv4Mapped(t *testing.T) {
	got, err := ParsePrefixes([]string{"::ffff:10.1.2.3/120", "::ffff:192.0.2.7/128", "::ffff:198.51.100.9", "10.0.0.0/8", "2001:db8::/32", "::ffff:0:0/95"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.1.2.0/24", "192.0.2.7/32", "198.51.100.9/32", "10.0.0.0/8", "2001:db8::/32", "::fffe:0:0/95"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("%d: got %s, want %s", i, got[i], want[i])
		}
	}
}

func TestExampleConfigLoads(t *testing.T) {
	t.Setenv("SECMAIL_INTERNAL_TOKEN", "0123456789abcdef0123")
	t.Setenv("SECMAIL_SESSION_SECRET", strings.Repeat("s", 32))
	for _, f := range []string{"../../config.example.yaml", "../../deploy/config.docker.yaml"} {
		cfg, err := Load(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if cfg.Portal.Auth.Mode != AuthOTP {
			t.Errorf("%s: auth mode %q", f, cfg.Portal.Auth.Mode)
		}
	}
}

func TestValidation(t *testing.T) {
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "c.yaml")
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	base := "upstream: {addr: 'mx:25'}\nsmtp: {accepted_domains: [Example.COM]}\ninternal_api: {listen: ''}\n"
	cfg, err := Load(write(base))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SMTP.AcceptedDomains[0] != "example.com" {
		t.Fatal("domains should be normalised")
	}
	bad := map[string]string{
		"no upstream":        "smtp: {accepted_domains: [a.com]}\ninternal_api: {listen: ''}\n",
		"open relay":         "upstream: {addr: 'mx:25'}\ninternal_api: {listen: ''}\n",
		"short secret":       base + "portal: {auth: {mode: otp, session_secret: short, otp_from: a@b.c}}\n",
		"otp without from":   base + "portal: {auth: {mode: otp, session_secret: " + strings.Repeat("x", 32) + "}}\n",
		"header w/o name":    base + "portal: {auth: {mode: header}}\n",
		"header w/o proxies": base + "portal: {auth: {mode: header, trusted_header: X-Email}}\n",
		"xff w/o proxies":    base + "portal: {trust_proxy_headers: true}\n",
		"bad proxy cidr":     base + "portal: {trusted_proxies: [not-an-ip]}\n",
		"unknown auth mode":  base + "portal: {auth: {mode: magic}}\n",
		"weak api token":     "upstream: {addr: 'mx:25'}\nsmtp: {accepted_domains: [a.com]}\ninternal_api: {listen: ':8081', token: x}\n",
		"bad encrypted action": base + "outbound: {enabled: true, allowed_clients: [10.0.0.1]}\n" +
			"dlp: {notify_from: a@b.c, admins: [s@b.c], actions: {high: hold, medium: notify, low: allow, uninspectable: notify, encrypted: magic}}\n",
	}
	for name, body := range bad {
		if _, err := Load(write(body)); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestEncryptedActionDefaultsToUninspectable(t *testing.T) {
	body := "upstream: {addr: 'mx:25'}\nsmtp: {accepted_domains: [a.com]}\ninternal_api: {listen: ''}\n" +
		"outbound: {enabled: true, allowed_clients: [10.0.0.1], next_hop: {addr: 'mx:26'}}\n" +
		"dlp: {notify_from: a@b.c, actions: {high: notify, medium: notify, low: allow, uninspectable: block, encrypted: ''}}\n"
	p := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(p, []byte(body), 0o600)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DLP.Actions.Encrypted != ActionBlock {
		t.Fatalf("encrypted should default to uninspectable (block), got %q", cfg.DLP.Actions.Encrypted)
	}
}
