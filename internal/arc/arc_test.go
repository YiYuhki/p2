package arc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestRelaxedCanonicalizationRFC6376(t *testing.T) {
	// RFC 6376 §3.4.5 worked example.
	if got := relaxedHeader("A", " X"); got != "a:X" {
		t.Errorf("header A: got %q", got)
	}
	if got := relaxedHeader("B", " Y\r\n\tZ  "); got != "b:Y Z" {
		t.Errorf("header B: got %q", got)
	}
	if got := relaxedBody(" C \r\nD \t E\r\n\r\n\r\n"); got != " C\r\nD E\r\n" {
		t.Errorf("body: got %q", got)
	}
	if got := relaxedBody(""); got != "" {
		t.Errorf("empty body: got %q", got)
	}
}

func parseTags(v string) map[string]string {
	v = collapseWSP(strings.ReplaceAll(strings.ReplaceAll(v, "\r\n", ""), "\n", ""))
	m := map[string]string{}
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		m[strings.TrimSpace(part[:eq])] = strings.TrimSpace(part[eq+1:])
	}
	return m
}

// emptyB replaces the final "b=..." tag value with empty, preserving order.
func emptyB(tags string) string {
	i := strings.LastIndex(tags, "b=")
	if i < 0 {
		return tags
	}
	return tags[:i] + "b="
}

func TestSealRoundTrip(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := New("gw.example.com", "arc1", "gw.example.com", key)
	s.now = func() time.Time { return time.Unix(1700000000, 0) }

	raw := "From: sender@ext.org\r\nTo: user@example.com\r\nSubject: hi\r\n" +
		"Date: Mon, 01 Jan 2026 00:00:00 +0000\r\nAuthentication-Results: gw.example.com; spf=pass\r\n" +
		"\r\nhello body\r\n"
	sealed, err := s.Seal([]byte(raw), "spf=pass; dkim=fail")
	if err != nil {
		t.Fatal(err)
	}
	out := string(sealed)
	// Structure: the three ARC headers are present, seal outermost.
	if !strings.HasPrefix(out, "ARC-Seal:") {
		t.Fatalf("ARC-Seal should be the first (outermost) header:\n%s", out[:120])
	}
	for _, h := range []string{"ARC-Seal:", "ARC-Message-Signature:", "ARC-Authentication-Results:"} {
		if !strings.Contains(out, h) {
			t.Fatalf("missing %s", h)
		}
	}

	parsed := parseHeaders(headerBlock(out))
	get := func(name string) string {
		for _, h := range parsed {
			if strings.EqualFold(h.name, name) {
				return collapseWSP(strings.ReplaceAll(strings.ReplaceAll(h.value, "\r\n", ""), "\n", ""))
			}
		}
		return ""
	}
	aar := get("ARC-Authentication-Results")
	ams := get("ARC-Message-Signature")
	as := get("ARC-Seal")
	if !strings.Contains(aar, "i=1;") || !strings.Contains(aar, "spf=pass; dkim=fail") {
		t.Fatalf("AAR unexpected: %q", aar)
	}

	amsTags := parseTags(ams)
	if amsTags["cv"] != "" { // AMS has no cv
		t.Fatal("AMS should not carry cv")
	}
	// Body hash must match the relaxed body.
	_, body, _ := split(out)
	wantBH := base64.StdEncoding.EncodeToString(sha256Sum(relaxedBody(body)))
	if amsTags["bh"] != wantBH {
		t.Fatalf("bh mismatch:\n got %s\nwant %s", amsTags["bh"], wantBH)
	}

	// Verify the ARC-Message-Signature RSA signature.
	present := selectHeaders(headerBlock(out), strings.Split(amsTags["h"], ":"))
	amsInput := amsSigningInput(present, emptyB(ams))
	if err := verify(&key.PublicKey, amsInput, amsTags["b"]); err != nil {
		t.Fatalf("AMS signature does not verify: %v", err)
	}

	// Verify the ARC-Seal signature (signs AAR, AMS-with-real-b, AS-with-empty-b).
	asTags := parseTags(as)
	if asTags["cv"] != "none" {
		t.Fatalf("cv = %q, want none", asTags["cv"])
	}
	sealInput := sealSigningInput(aar, ams, emptyB(as))
	if err := verify(&key.PublicKey, sealInput, asTags["b"]); err != nil {
		t.Fatalf("ARC-Seal signature does not verify: %v", err)
	}
}

func TestNilSealerPassthrough(t *testing.T) {
	if New("", "s", "a", nil) != nil {
		t.Fatal("missing fields should disable")
	}
	var s *Sealer
	out, err := s.Seal([]byte("x"), "")
	if err != nil || string(out) != "x" {
		t.Fatalf("nil sealer should pass through: %v %q", err, out)
	}
}

// selectHeaders needs the covered header names in the h= order; the names in
// the test message are known, so this also exercises ordering.
func headerBlock(msg string) string {
	i := strings.Index(strings.ReplaceAll(msg, "\r\n", "\n"), "\n\n")
	if i < 0 {
		return msg
	}
	return toCRLF(strings.ReplaceAll(msg, "\r\n", "\n")[:i+1])
}

func verify(pub *rsa.PublicKey, input, sigB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(input))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig)
}
