package gateway

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/yiyuhki/p2/internal/mimeproc"
	"github.com/yiyuhki/p2/internal/service"
)

type bannerData struct {
	Count   int
	Expires string
	Links   []bannerLink
	Notice  string
}

type bannerLink struct {
	Index    int
	Filename string
	Size     string
	URL      template.URL
	RawURL   string
}

var htmlBanner = template.Must(template.New("banner").Parse(`
<div style="margin:24px 0 0 0;padding:16px;border:1px solid #c7d2fe;border-left:4px solid #4f46e5;border-radius:6px;background:#f5f7ff;font-family:'Malgun Gothic','Apple SD Gothic Neo',Arial,sans-serif;font-size:14px;color:#1f2937;">
<div style="font-weight:bold;font-size:15px;margin-bottom:6px;">&#128274; 보안 메일 게이트웨이 &middot; 첨부파일 {{.Count}}개 분리 보관</div>
<div style="margin-bottom:10px;color:#374151;">이 메일의 첨부파일은 악성코드 검사를 위해 안전한 저장소로 옮겨졌습니다. 아래 링크에서 검사 결과를 확인한 뒤 다운로드하세요.{{if .Notice}}<br><span style="color:#b45309;">{{.Notice}}</span>{{end}}</div>
<table cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%;">
{{range .Links}}<tr><td style="padding:6px 0;border-top:1px solid #e0e7ff;"><a href="{{.URL}}" style="color:#4338ca;font-weight:bold;text-decoration:none;">{{.Filename}}</a> <span style="color:#6b7280;">({{.Size}})</span></td><td style="padding:6px 0;border-top:1px solid #e0e7ff;text-align:right;"><a href="{{.URL}}" style="display:inline-block;padding:4px 12px;border-radius:4px;background:#4f46e5;color:#ffffff;text-decoration:none;font-size:13px;">검사 결과 확인 / 다운로드</a></td></tr>
{{end}}</table>
<div style="margin-top:8px;font-size:12px;color:#6b7280;">링크 유효기간: {{.Expires}} 까지 &middot; 이 안내는 보안 게이트웨이가 자동으로 추가했습니다.</div>
</div>`))

func buildBanner(links []service.Link, expires time.Time, notice string) mimeproc.Banner {
	d := bannerData{
		Count:   len(links),
		Expires: expires.Format("2006-01-02 15:04 MST"),
		Notice:  notice,
	}
	for i, l := range links {
		d.Links = append(d.Links, bannerLink{
			Index:    i + 1,
			Filename: l.Filename,
			Size:     humanSize(l.Size),
			URL:      template.URL(l.URL),
			RawURL:   l.URL,
		})
	}
	var h bytes.Buffer
	if err := htmlBanner.Execute(&h, d); err != nil {
		panic(err) // template is static; only fails on programmer error
	}

	var t strings.Builder
	rule := strings.Repeat("-", 60)
	t.WriteString(rule + "\r\n")
	fmt.Fprintf(&t, "[보안 메일 게이트웨이] 첨부파일 %d개가 악성코드 검사를 위해 분리 보관되었습니다.\r\n", d.Count)
	t.WriteString("아래 링크에서 검사 결과를 확인한 뒤 다운로드하세요.\r\n")
	if notice != "" {
		t.WriteString(notice + "\r\n")
	}
	t.WriteString("\r\n")
	for _, l := range d.Links {
		fmt.Fprintf(&t, " %d. %s (%s)\r\n    %s\r\n", l.Index, l.Filename, l.Size, l.RawURL)
	}
	fmt.Fprintf(&t, "\r\n링크 유효기간: %s 까지\r\n", d.Expires)
	t.WriteString(rule)
	return mimeproc.Banner{Text: t.String(), HTML: h.String()}
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
