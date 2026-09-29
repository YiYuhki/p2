// Package token generates unguessable download tokens.
//
// The raw token only ever appears in the mail link; the database stores its
// SHA-256 hash so a database leak does not expose working links.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// New returns a 256-bit random URL-safe token.
func New() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// Hash returns the hex SHA-256 of a token, used as the lookup key.
func Hash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// WellFormed rejects obviously invalid tokens before touching the database.
func WellFormed(tok string) bool {
	if len(tok) != 43 {
		return false
	}
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
