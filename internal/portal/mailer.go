package portal

import (
	"context"
	"fmt"
	"time"

	"github.com/yiyuhki/p2/internal/notify"
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
	body := fmt.Sprintf("보안 첨부파일 다운로드 인증 코드입니다.\n\n"+
		"    인증 코드: %s\n\n"+
		"유효시간: %d분\n"+
		"본인이 요청하지 않았다면 이 메일을 무시하세요. 코드를 다른 사람에게 알려주지 마세요.\n",
		code, int(ttl.Minutes()))
	return notify.Build(from, "보안 메일 게이트웨이", []string{to}, "[보안 메일] 첨부파일 다운로드 인증 코드 "+code, body, now)
}
