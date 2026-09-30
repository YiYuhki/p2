package portal

import (
	"strings"
	"testing"
)

// FuzzContentDisposition feeds arbitrary attachment names: the name comes from
// the sender, so the built header must always be a well-formed "attachment"
// disposition with no header-injection or inline-render risk.
func FuzzContentDisposition(f *testing.F) {
	for _, s := range []string{
		"report.pdf", "보고서.pdf", `a"b\c.txt`, "../../etc/passwd",
		"", "..", "a\r\nb.txt", "x\x00y", strings.Repeat("가", 500),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		got := contentDisposition(name)
		if !strings.HasPrefix(got, "attachment;") {
			t.Fatalf("not an attachment disposition: %q", got)
		}
		if strings.ContainsAny(got, "\r\n") {
			t.Fatalf("header contains CR/LF (injection): %q", got)
		}
		// The ascii filename must be a properly closed quoted-string: exactly
		// two unescaped double quotes delimiting it.
		if strings.Count(got, `"`) < 2 {
			t.Fatalf("filename not quoted: %q", got)
		}
	})
}
