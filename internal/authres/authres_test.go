package authres

import (
	"strings"
	"testing"
)

func TestSanitizeBlocksHeaderInjection(t *testing.T) {
	cases := map[string]string{
		"good.com":                       "good.com",
		"evil.com; dkim=pass header.d=x": "evil.comdkim=passheader.d=x", // ';' + spaces removed
		"a\r\nb":                         "ab",
		"a\tb":                           "ab",
		"x\x00y":                         "xy",
		"has space":                      "hasspace",
	}
	for in, want := range cases {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
	// Property: output never contains a separator that could inject a method.
	for _, in := range []string{"a;b c\td\re\nf\x00g\x7fh"} {
		if strings.ContainsAny(Sanitize(in), "; \t\r\n") {
			t.Errorf("Sanitize left a separator in %q -> %q", in, Sanitize(in))
		}
	}
}
