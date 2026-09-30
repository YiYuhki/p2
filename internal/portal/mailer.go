package portal

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

// Mailer delivers one-time codes to recipients.
type Mailer interface {
	SendCode(ctx context.Context, to, code string, ttl time.Duration) error
}

// SMTPMailer sends codes straight to the internal mail server (not through
// the gateway itself).
type SMTPMailer struct {
	opts smtpclient.Options
	from string
}

func NewSMTPMailer(opts smtpclient.Options, from string) *SMTPMailer {
	return &SMTPMailer{opts: opts, from: from}
}

func (m *SMTPMailer) SendCode(_ context.Context, to, code string, ttl time.Duration) error {
	return smtpclient.Send(m.opts, m.from, []string{to}, BuildCodeMessage(m.from, to, code, ttl, time.Now()))
}

// BuildCodeMessage renders the RFC 5322 message carrying the code.
func BuildCodeMessage(from, to, code string, ttl time.Duration, now time.Time) []byte {
	var id [12]byte
	rand.Read(id[:])
	domain := from[strings.LastIndexByte(from, '@')+1:]
	body := fmt.Sprintf("보안 첨부파일 다운로드 인증 코드입니다.\r\n\r\n"+
		"    인증 코드: %s\r\n\r\n"+
		"유효시간: %d분\r\n"+
		"본인이 요청하지 않았다면 이 메일을 무시하세요. 코드를 다른 사람에게 알려주지 마세요.\r\n",
		code, int(ttl.Minutes()))

	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s <%s>\r\n", mime.BEncoding.Encode("utf-8", "보안 메일 게이트웨이"), from)
	fmt.Fprintf(&b, "To: <%s>\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.BEncoding.Encode("utf-8", "[보안 메일] 첨부파일 다운로드 인증 코드 "+code))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id[:]), domain)
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.Bytes()
}
