// Package dkimutil verifies inbound DKIM signatures before the message is
// modified and re-signs the rewritten message with the gateway's key.
package dkimutil

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/yiyuhki/p2/internal/authres"
)

// Signer signs outgoing (rewritten) messages.
type Signer struct {
	domain   string
	selector string
	key      crypto.Signer
}

func LoadSigner(domain, selector, keyFile string) (*Signer, error) {
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := parseKey(raw)
	if err != nil {
		return nil, fmt.Errorf("dkim: %s: %w", keyFile, err)
	}
	return &Signer{domain: domain, selector: selector, key: key}, nil
}

func NewSigner(domain, selector string, key crypto.Signer) *Signer {
	return &Signer{domain: domain, selector: selector, key: key}
}

func parseKey(raw []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
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

// Headers recommended by RFC 6376 §5.4.1 plus the gateway's own markers.
var signedHeaders = []string{
	"From", "Reply-To", "Subject", "Date", "To", "Cc", "Message-ID",
	"In-Reply-To", "References", "MIME-Version", "Content-Type",
	"Content-Transfer-Encoding", "X-SecMail-Processed",
}

// Sign returns msg with a DKIM-Signature header prepended.
func (s *Signer) Sign(msg []byte) ([]byte, error) {
	var out bytes.Buffer
	err := dkim.Sign(&out, bytes.NewReader(msg), &dkim.SignOptions{
		Domain:                 s.domain,
		Selector:               s.selector,
		Signer:                 s.key,
		Hash:                   crypto.SHA256,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             signedHeaders,
		Expiration:             time.Now().Add(30 * 24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Verify checks the original DKIM signatures and renders the result as an
// RFC 8601 Authentication-Results method list ("dkim=pass header.d=...").
func Verify(msg []byte, lookup func(string) ([]string, error)) string {
	opts := &dkim.VerifyOptions{MaxVerifications: 5, LookupTXT: lookup}
	vs, err := dkim.VerifyWithOptions(bytes.NewReader(msg), opts)
	if err != nil && len(vs) == 0 {
		return "dkim=temperror"
	}
	if len(vs) == 0 {
		return "dkim=none"
	}
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		res := "pass"
		switch {
		case v.Err == nil:
		case dkim.IsTempFail(v.Err):
			res = "temperror"
		case dkim.IsPermFail(v.Err):
			res = "permerror"
		default:
			res = "fail"
		}
		parts = append(parts, fmt.Sprintf("dkim=%s header.d=%s", res, authres.Sanitize(v.Domain)))
	}
	return strings.Join(parts, "; ")
}
