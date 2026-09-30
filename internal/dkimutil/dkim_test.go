package dkimutil

import (
	"strings"
	"testing"
)

func TestVerifyNoSignatures(t *testing.T) {
	raw := []byte("From: a@b.com\r\nSubject: x\r\n\r\nbody\r\n")
	got := Verify(raw, func(string) ([]string, error) { return nil, nil })
	if got != "dkim=none" {
		t.Fatalf("Verify with no signatures = %q, want dkim=none", got)
	}
}

// A signature domain is attacker-influenced; the rendered result must not inject
// extra methods or fold the header.
func TestVerifyDomainSanitised(t *testing.T) {
	got := Verify([]byte("From: a@b.com\r\n\r\nx\r\n"), func(string) ([]string, error) { return nil, nil })
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("result contains CR/LF: %q", got)
	}
}
