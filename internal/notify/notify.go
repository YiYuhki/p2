// Package notify builds and sends the gateway's own notification mails
// (one-time codes, DLP notices). They are delivered straight to the internal
// mail server, never through the gateway listeners.
package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"mime"
	"strings"
	"time"

	"github.com/yiyuhki/p2/internal/smtpclient"
)

// Sender delivers a finished RFC 5322 message.
type Sender interface {
	Send(ctx context.Context, from string, to []string, msg []byte) error
}

type SMTPSender struct{ opts smtpclient.Options }

func NewSMTPSender(opts smtpclient.Options) *SMTPSender { return &SMTPSender{opts: opts} }

func (s *SMTPSender) Send(_ context.Context, from string, to []string, msg []byte) error {
	return smtpclient.Send(s.opts, from, to, msg)
}

// Build renders a UTF-8 plain-text message.
func Build(from, fromName string, to []string, subject, body string, now time.Time) []byte {
	var id [12]byte
	rand.Read(id[:])
	domain := from[strings.LastIndexByte(from, '@')+1:]
	var b bytes.Buffer
	if fromName != "" {
		fmt.Fprintf(&b, "From: %s <%s>\r\n", mime.BEncoding.Encode("utf-8", fromName), from)
	} else {
		fmt.Fprintf(&b, "From: <%s>\r\n", from)
	}
	quoted := make([]string, len(to))
	for i, t := range to {
		quoted[i] = "<" + t + ">"
	}
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(quoted, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.BEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id[:]), domain)
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.Bytes()
}
