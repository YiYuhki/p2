// Package authres holds helpers shared by the Authentication-Results producers
// (SPF and DKIM), so the header-injection guard stays identical across them.
package authres

import "strings"

// Sanitize strips characters that could break out of an Authentication-Results
// method value or inject an additional method: ';' (method separator),
// whitespace (property separator), and control characters. Domains and identity
// values never legitimately contain these.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ';' || r == ' ' || r == '\t' || r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
