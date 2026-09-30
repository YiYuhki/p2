package dkimutil

import "testing"

func TestSanitizeBlocksHeaderInjection(t *testing.T) {
	// A signature domain is attacker-influenced; it must not be able to inject
	// extra Authentication-Results methods or fold the header.
	cases := map[string]string{
		"good.com":                       "good.com",
		"evil.com; dkim=pass header.d=x": "evil.com dkim=pass header.d=x", // ';' removed
		"a\r\nb":                         "ab",
		"a\tb":                           "ab", // control chars (incl. tab) removed
		"x\x00y":                         "xy",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVerifyNoSignatures(t *testing.T) {
	raw := []byte("From: a@b.com\r\nSubject: x\r\n\r\nbody\r\n")
	got := Verify(raw, func(string) ([]string, error) { return nil, nil })
	if got != "dkim=none" {
		t.Fatalf("Verify with no signatures = %q, want dkim=none", got)
	}
}
