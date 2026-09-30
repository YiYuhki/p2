package mimeproc

import (
	"strings"
	"testing"
)

// FuzzParse feeds arbitrary bytes to the MIME parser: the gateway parses
// attacker-controlled mail, so Parse (and a follow-up serialise) must never
// panic, whatever the input.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"",
		"From: a@b\r\n\r\nbody",
		"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nhi\r\n--x--\r\n",
		"Content-Type: multipart/mixed; boundary=\"\"\r\n\r\n----\r\n",
		"Content-Transfer-Encoding: base64\r\n\r\n!!!!notbase64!!!!",
		"Subject: =?utf-8?B?bad==?=\r\n\r\n",
		strings.Repeat("A:", 1000),
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		root, err := Parse(raw)
		if err != nil {
			return // rejecting malformed input is fine; it must not panic
		}
		// A successfully parsed message must be re-serialisable without panic.
		if _, err := root.Bytes(); err != nil {
			return
		}
	})
}
