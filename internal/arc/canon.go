package arc

import "strings"

// relaxed header/body canonicalization per RFC 6376 §3.4.2 / §3.4.4, shared by
// the ARC-Message-Signature and ARC-Seal (RFC 8617 reuses DKIM canonicalization).

// relaxedHeader returns the relaxed canonical form of one header as
// "name:value" WITHOUT a trailing CRLF. The caller appends CRLF between lines.
func relaxedHeader(name, value string) string {
	// Field name: lower-cased.
	n := strings.ToLower(strings.TrimSpace(name))
	// Value: unfold (drop CRLF), collapse WSP runs to a single space, trim ends.
	v := unfold(value)
	v = collapseWSP(v)
	v = strings.TrimSpace(v)
	return n + ":" + v
}

// relaxedBody returns the relaxed canonical body: WSP runs collapsed to a single
// space, trailing line WSP removed, trailing empty lines removed, and a single
// trailing CRLF (an all-empty body canonicalizes to the empty string).
func relaxedBody(body string) string {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	lines := strings.Split(body, "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		ln = collapseWSP(ln)
		ln = strings.TrimRight(ln, " \t")
		out = append(out, ln)
	}
	// Drop trailing empty lines.
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\r\n") + "\r\n"
}

// unfold removes the CRLF of folded header continuation lines, leaving the WSP
// that followed it (which collapseWSP then reduces).
func unfold(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "")
	s = strings.ReplaceAll(s, "\n", "")
	return s
}

// collapseWSP reduces every run of spaces/tabs to a single space.
func collapseWSP(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inWSP := false
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if !inWSP {
				b.WriteByte(' ')
				inWSP = true
			}
			continue
		}
		inWSP = false
		b.WriteByte(s[i])
	}
	return b.String()
}
