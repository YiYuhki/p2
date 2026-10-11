// Package arc implements ARC (Authenticated Received Chain, RFC 8617) sealing
// for the gateway. Because the gateway rewrites inbound mail (inserting a
// banner, rewriting attachments), it breaks the original DKIM/SPF alignment; an
// ARC seal lets a downstream, ARC-aware receiver see the authentication results
// the gateway observed and trust that the gateway — not a later hop — vouched
// for them.
//
// Only the sealing side (adding a fresh i=1 … or i=N+1 set) is implemented; the
// gateway does not currently consume inbound ARC chains, so a received chain is
// always sealed with cv=none (no prior chain) in this version.
package arc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// LoadSealer reads a PEM private key (PKCS#1 or PKCS#8 RSA) and returns a
// Sealer, or an error. A nil-returning New (empty domain/selector) surfaces as
// an error here so misconfiguration is caught at startup.
func LoadSealer(domain, selector, authServ, keyFile string) (*Sealer, error) {
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("arc: no PEM block in key file")
	}
	key, err := parseKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("arc: %s: %w", keyFile, err)
	}
	s := New(domain, selector, authServ, key)
	if s == nil {
		return nil, errors.New("arc: domain and selector are required")
	}
	return s, nil
}

func parseKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	switch k := k.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	}
	return nil, fmt.Errorf("unsupported key type %T", k)
}

// Sealer adds an ARC set to a message using the gateway's signing key.
type Sealer struct {
	domain   string
	selector string
	authServ string // authserv-id used in the ARC-Authentication-Results
	key      crypto.Signer
	now      func() time.Time
}

// New returns a Sealer, or nil when any required field is empty (disabled), so
// callers need not check.
func New(domain, selector, authServ string, key crypto.Signer) *Sealer {
	if domain == "" || selector == "" || key == nil {
		return nil
	}
	if authServ == "" {
		authServ = domain
	}
	return &Sealer{domain: domain, selector: selector, authServ: authServ, key: key, now: time.Now}
}

// amsHeaders is the header set the ARC-Message-Signature covers when present,
// mirroring the gateway's DKIM selection plus the Authentication-Results it adds.
var amsHeaders = []string{
	"From", "To", "Cc", "Subject", "Date", "Message-ID", "In-Reply-To", "References",
	"MIME-Version", "Content-Type", "Content-Transfer-Encoding", "Authentication-Results",
}

// Seal prepends a fresh ARC set (ARC-Authentication-Results, ARC-Message-
// Signature, ARC-Seal; instance i=1, cv=none) to raw and returns the result. A
// nil Sealer returns raw unchanged. authResults is the RFC 8601 method list the
// gateway produced (without the leading authserv-id), e.g. "spf=pass; dkim=fail".
func (s *Sealer) Seal(raw []byte, authResults string) ([]byte, error) {
	if s == nil {
		return raw, nil
	}
	headers, body, ok := split(string(raw))
	if !ok {
		return nil, fmt.Errorf("arc: message has no header/body separator")
	}
	t := s.now().Unix()

	// ---- ARC-Authentication-Results (i=1) ----
	if authResults == "" {
		authResults = "none"
	}
	aar := fmt.Sprintf("i=1; %s; %s", s.authServ, authResults)

	// ---- ARC-Message-Signature (i=1) ----
	bh := base64.StdEncoding.EncodeToString(sha256Sum(relaxedBody(body)))
	present := selectHeaders(headers, amsHeaders)
	hlist := make([]string, len(present))
	for i, h := range present {
		hlist[i] = h.name
	}
	amsTags := fmt.Sprintf("i=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; t=%d; bh=%s; h=%s; b=",
		s.domain, s.selector, t, bh, strings.Join(hlist, ":"))
	amsSig, err := s.sign(amsSigningInput(present, amsTags))
	if err != nil {
		return nil, err
	}
	amsFull := amsTags + amsSig

	// ---- ARC-Seal (i=1) ----
	asTags := fmt.Sprintf("i=1; a=rsa-sha256; cv=none; d=%s; s=%s; t=%d; b=", s.domain, s.selector, t)
	asSig, err := s.sign(sealSigningInput(aar, amsFull, asTags))
	if err != nil {
		return nil, err
	}
	asFull := asTags + asSig

	// Prepend the set, ARC-Seal outermost (topmost), then AMS, then AAR.
	var out strings.Builder
	out.WriteString(fold("ARC-Seal", asFull))
	out.WriteString(fold("ARC-Message-Signature", amsFull))
	out.WriteString(fold("ARC-Authentication-Results", aar))
	out.WriteString(headers)
	out.WriteString("\r\n")
	out.WriteString(body)
	return []byte(out.String()), nil
}

func (s *Sealer) sign(input string) (string, error) {
	sum := sha256.Sum256([]byte(input))
	sig, err := s.key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("arc: sign: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// amsSigningInput builds the data the ARC-Message-Signature signs: each covered
// header (relaxed, CRLF-terminated) in order, then the AMS header itself
// (relaxed, b= empty, no trailing CRLF).
func amsSigningInput(present []header, amsTags string) string {
	var b strings.Builder
	for _, h := range present {
		b.WriteString(relaxedHeader(h.name, h.value))
		b.WriteString("\r\n")
	}
	b.WriteString(relaxedHeader("ARC-Message-Signature", amsTags))
	return b.String()
}

// sealSigningInput builds the data the ARC-Seal signs: the ARC set in instance
// order (AAR, AMS, AS), each relaxed; the AS has b= empty and no trailing CRLF.
func sealSigningInput(aar, amsFull, asTags string) string {
	var b strings.Builder
	b.WriteString(relaxedHeader("ARC-Authentication-Results", aar))
	b.WriteString("\r\n")
	b.WriteString(relaxedHeader("ARC-Message-Signature", amsFull))
	b.WriteString("\r\n")
	b.WriteString(relaxedHeader("ARC-Seal", asTags))
	return b.String()
}

func sha256Sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

type header struct{ name, value string }

// split separates raw into the header block (through the last header's CRLF,
// including it) and the body (after the blank line).
func split(raw string) (headers, body string, ok bool) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	i := strings.Index(raw, "\n\n")
	if i < 0 {
		return "", "", false
	}
	h := raw[:i+1] // header lines including the final LF
	b := raw[i+2:] // body after the blank line
	return toCRLF(h), toCRLF(b), true
}

func toCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// selectHeaders returns, for each wanted name (case-insensitive, in order), the
// first matching header found in the block; names not present are skipped.
func selectHeaders(block string, want []string) []header {
	parsed := parseHeaders(block)
	var out []header
	for _, w := range want {
		for _, h := range parsed {
			if strings.EqualFold(h.name, w) {
				out = append(out, h)
				break
			}
		}
	}
	return out
}

// parseHeaders splits a header block into ordered name/value pairs, joining
// folded continuation lines.
func parseHeaders(block string) []header {
	lines := strings.Split(strings.ReplaceAll(block, "\r\n", "\n"), "\n")
	var out []header
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		if ln[0] == ' ' || ln[0] == '\t' {
			if len(out) > 0 {
				out[len(out)-1].value += "\r\n" + ln
			}
			continue
		}
		c := strings.IndexByte(ln, ':')
		if c < 0 {
			continue
		}
		out = append(out, header{name: ln[:c], value: strings.TrimPrefix(ln[c+1:], " ")})
	}
	return out
}

// fold emits a header "Name: value\r\n", wrapping the long base64/tag value at
// ~78 columns on whitespace so the line stays within SMTP limits.
func fold(name, value string) string {
	line := name + ": " + value
	var b strings.Builder
	const limit = 78
	col := 0
	for _, field := range strings.Split(line, " ") {
		if col > 0 && col+1+len(field) > limit {
			b.WriteString("\r\n ")
			col = 1
		} else if col > 0 {
			b.WriteByte(' ')
			col++
		}
		b.WriteString(field)
		col += len(field)
	}
	b.WriteString("\r\n")
	return b.String()
}
