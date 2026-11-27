// Package digest builds and sends a periodic summary of mail currently held by
// outbound DLP, so reviewers get a scheduled reminder of the backlog instead of
// having to poll the dashboard.
package digest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/notify"
	"github.com/yiyuhki/p2/internal/store"
)

// HoldLister is the slice of the store the digest needs.
type HoldLister interface {
	ListHolds(ctx context.Context, status model.HoldStatus, limit int, page store.Page) ([]*model.Hold, error)
}

// Mailer renders and sends the held-mail digest.
type Mailer struct {
	store    HoldLister
	sender   notify.Sender
	from     string
	fromName string
	to       []string
	loc      *time.Location
	now      func() time.Time
}

// New returns a Mailer, or nil when it cannot run (no sender or no recipients),
// so the caller need not check.
func New(st HoldLister, sender notify.Sender, from, fromName string, to []string, loc *time.Location) *Mailer {
	if sender == nil || from == "" || len(to) == 0 {
		return nil
	}
	if loc == nil {
		loc = time.UTC
	}
	return &Mailer{store: st, sender: sender, from: from, fromName: fromName, to: to, loc: loc, now: time.Now}
}

const maxDigestRows = 200

// Send lists currently-held mail and, when there is any, emails a summary to
// the configured recipients. A digest with nothing held is not sent (no noise).
// A nil Mailer is a no-op.
func (m *Mailer) Send(ctx context.Context) error {
	if m == nil {
		return nil
	}
	var (
		held []*model.Hold
		page store.Page
	)
	for len(held) < maxDigestRows {
		batch, err := m.store.ListHolds(ctx, model.HoldHeld, 100, page)
		if err != nil {
			return err
		}
		held = append(held, batch...)
		if len(batch) < 100 {
			break
		}
		last := batch[len(batch)-1]
		page = store.Page{Before: last.CreatedAt, BeforeID: last.ID}
	}
	if len(held) == 0 {
		return nil
	}
	subject, body := m.render(held)
	return m.sender.Send(ctx, m.from, m.to, notify.Build(m.from, m.fromName, m.to, subject, body, m.now()))
}

func (m *Mailer) render(held []*model.Hold) (subject, body string) {
	n := len(held)
	truncated := false
	if n >= maxDigestRows {
		truncated = true
	}
	subject = fmt.Sprintf("[보안메일] 발송 보류 메일 %d건 검토 대기", n)
	var b strings.Builder
	fmt.Fprintf(&b, "발송이 보류된 메일이 %d건 있습니다. 포털 관리자 대시보드에서 승인 또는 반려해 주세요.\n\n", n)
	for _, h := range held {
		sev, cnt := summarize(h.Findings)
		fmt.Fprintf(&b, "- %s\n  발신: %s\n  수신: %s\n  제목: %s\n  접수: %s  만료: %s  탐지: %s (%d건)\n\n",
			shortID(h.ID), h.MailFrom, strings.Join(h.RcptTo, ", "), h.Subject,
			h.CreatedAt.In(m.loc).Format("2006-01-02 15:04"),
			h.ExpiresAt.In(m.loc).Format("2006-01-02 15:04"), sev, cnt)
	}
	if truncated {
		fmt.Fprintf(&b, "...이 외에도 더 있을 수 있습니다. 대시보드에서 전체 목록을 확인하세요.\n")
	}
	return subject, b.String()
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// summarize returns the top severity and finding count from a hold's findings
// blob ({"findings":[{"severity":...}]}).
func summarize(raw []byte) (string, int) {
	var rep struct {
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &rep) != nil || len(rep.Findings) == 0 {
		return "-", 0
	}
	rank := map[string]int{"high": 3, "medium": 2, "low": 1}
	top := ""
	for _, f := range rep.Findings {
		if rank[f.Severity] > rank[top] {
			top = f.Severity
		}
	}
	if top == "" {
		top = "-"
	}
	return top, len(rep.Findings)
}
