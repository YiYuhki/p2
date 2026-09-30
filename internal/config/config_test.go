package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
		"no upstream":       "smtp: {accepted_domains: [a.com]}\ninternal_api: {listen: ''}\n",
		"open relay":        "upstream: {addr: 'mx:25'}\ninternal_api: {listen: ''}\n",
		"short secret":      base + "portal: {auth: {mode: otp, session_secret: short, otp_from: a@b.c}}\n",
		"otp without from":  base + "portal: {auth: {mode: otp, session_secret: " + strings.Repeat("x", 32) + "}}\n",
		"header w/o name":   base + "portal: {auth: {mode: header}}\n",
		"unknown auth mode": base + "portal: {auth: {mode: magic}}\n",
		"weak api token":    "upstream: {addr: 'mx:25'}\nsmtp: {accepted_domains: [a.com]}\ninternal_api: {listen: ':8081', token: x}\n",
	}
	for name, body := range bad {
		if _, err := Load(write(body)); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}
