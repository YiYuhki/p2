package outbound

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yiyuhki/p2/internal/config"
	"github.com/yiyuhki/p2/internal/dlp"
	"github.com/yiyuhki/p2/internal/gateway"
	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/notify"

	"time"
)

type notice struct {
	env         gateway.Envelope
	subject     string
	rep         *dlp.Report
	action      string
	reviewURL   string
	holdExpires time.Time
}

func (s *Service) fmtTime(t time.Time) string {
	return t.In(s.opts.Location).Format("2006-01-02 15:04 MST")
}

// FindingsText renders findings as an indented list (masked samples only).
func FindingsText(rep *dlp.Report) string {
	var b strings.Builder
	for _, f := range rep.Findings {
		fmt.Fprintf(&b, "  - %s %d건 · 위치: %s", f.Name, f.Count, f.Location)
		if len(f.Samples) > 0 {
			fmt.Fprintf(&b, " · 예: %s", strings.Join(f.Samples, ", "))
		}
		b.WriteString("\n")
	}
	for _, u := range rep.Uninspectable {
		fmt.Fprintf(&b, "  - 검사 불가: %s\n", u)
	}
	return b.String()
}

func hasSecrets(rep *dlp.Report) bool {
	for _, f := range rep.Findings {
		if f.Category == dlp.CategorySecret {
			return true
		}
	}
	return false
}

func (s *Service) header(n notice) string {
	return fmt.Sprintf("제목: %s\n발신: %s\n수신: %s\n시각: %s\n",
		n.subject, n.env.MailFrom, strings.Join(n.env.RcptTo, ", "), s.fmtTime(s.now()))
}

func (s *Service) sendNotices(ctx context.Context, n notice) {
	var status string
	switch n.action {
	case config.ActionNotify:
		status = "메일은 정상적으로 발송되었습니다."
	case config.ActionHold:
		status = fmt.Sprintf("메일 발송이 보류되었습니다. 보안 담당자가 승인하면 자동으로 발송되며, %s까지 승인되지 않으면 발송되지 않습니다.",
			s.fmtTime(n.holdExpires))
	case config.ActionBlock:
		status = "보안 정책에 따라 메일 발송이 차단되었습니다. 수신자에게 전달되지 않았습니다."
	}
	advice := "개인정보는 꼭 필요한 경우에만 마스킹·암호화하여 승인된 방법으로 전달하세요.\n"
	if hasSecrets(n.rep) {
		if n.action == config.ActionNotify {
			advice += "API 키·비밀번호·개인키 등 인증정보가 외부로 전달되었습니다. 즉시 폐기(재발급)하세요.\n"
		} else {
			advice += "API 키·비밀번호·개인키 등 인증정보는 메일로 보내지 마세요. 승인된 비밀정보 공유 수단을 이용하세요.\n"
		}
	}
	findings := FindingsText(n.rep)

	if s.opts.NotifySender && n.env.MailFrom != "" && domainMatch(n.env.MailFrom, s.opts.OwnDomains) {
		body := "보낸 메일에서 민감정보가 발견되었습니다.\n\n" + s.header(n) + "\n조치: " + status +
			"\n\n발견 내역:\n" + findings + "\n" + advice +
			"\n오탐이라고 판단되면 보안 담당자에게 문의하세요.\n"
		s.send(ctx, []string{n.env.MailFrom}, "[보안 알림] 발송 메일 민감정보 탐지: "+n.subject, body)
	}
	if len(s.opts.Admins) > 0 {
		body := "외부 발송 메일에서 민감정보가 탐지되었습니다.\n\n" + s.header(n) +
			"조치: " + n.action + "\n\n발견 내역:\n" + findings
		if n.reviewURL != "" {
			body += fmt.Sprintf("\n검토(승인/반려): %s\n기한: %s (기한이 지나면 발송되지 않습니다)\n",
				n.reviewURL, s.fmtTime(n.holdExpires))
		}
		s.send(ctx, s.opts.Admins, fmt.Sprintf("[DLP %s] %s → %s", strings.ToUpper(n.action), n.env.MailFrom, n.subject), body)
	}
}

func (s *Service) sendDecisionNotice(ctx context.Context, h *model.Hold, st model.HoldStatus, by, reason string) {
	if !s.opts.NotifySender || !domainMatch(h.MailFrom, s.opts.OwnDomains) {
		return
	}
	var what string
	switch st {
	case model.HoldReleased:
		what = "보안 담당자가 승인하여 메일이 발송되었습니다."
	case model.HoldRejected:
		what = "보안 담당자가 발송을 반려했습니다. 메일은 전달되지 않았습니다."
	case model.HoldExpired:
		what = "검토 기한 내에 승인되지 않아 메일이 발송되지 않았습니다. 필요하면 민감정보를 제거한 뒤 다시 보내세요."
	}
	body := fmt.Sprintf("보류되었던 메일의 처리 결과를 알려드립니다.\n\n제목: %s\n수신: %s\n결과: %s\n",
		h.Subject, strings.Join(h.RcptTo, ", "), what)
	if reason != "" && st != model.HoldExpired {
		body += "사유: " + reason + "\n"
	}
	var rep dlp.Report
	if json.Unmarshal(h.Findings, &rep) == nil {
		body += "\n발견 내역:\n" + FindingsText(&rep)
	}
	s.send(ctx, []string{h.MailFrom}, "[보안 알림] 보류 메일 처리 결과: "+h.Subject, body)
}

func (s *Service) send(ctx context.Context, to []string, subject, body string) {
	if s.notifier == nil || s.opts.NotifyFrom == "" {
		return
	}
	msg := notify.Build(s.opts.NotifyFrom, "보안 메일 게이트웨이", to, subject, body, s.now())
	if err := s.notifier.Send(ctx, s.opts.NotifyFrom, to, msg); err != nil {
		s.log.Error("send notice failed", "to", to, "err", err)
	}
}
