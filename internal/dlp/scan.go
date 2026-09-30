package dlp

import (
	"context"
	"errors"
	"fmt"
	"html"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/yiyuhki/p2/internal/mimeproc"
)

// Rule is a user-defined detector from the configuration.
type Rule struct {
	ID       string   `yaml:"id"`
	Name     string   `yaml:"name"`
	Pattern  string   `yaml:"pattern"`
	Severity string   `yaml:"severity"`
	Category string   `yaml:"category"`
	MinCount int      `yaml:"min_count"`
	Context  []string `yaml:"context"`
}

type Options struct {
	// Disabled lists built-in detector IDs to turn off.
	Disabled []string
	// MinCounts overrides a detector's bulk threshold.
	MinCounts map[string]int
	Rules     []Rule
	// ScanAttachments enables attachment text extraction.
	ScanAttachments bool
	Limits          Limits
	// OCR, when OCR.Engine is set, reads text in images (image
	// attachments, inline images, pictures in documents, scanned PDFs).
	OCR OCROptions
}

type Scanner struct {
	detectors []*Detector
	opts      Options
}

func NewScanner(opts Options) (*Scanner, error) {
	off := map[string]bool{}
	for _, id := range opts.Disabled {
		off[id] = true
	}
	var ds []*Detector
	for _, d := range Builtin() {
		if off[d.ID] {
			continue
		}
		if n, ok := opts.MinCounts[d.ID]; ok {
			d.MinCount = n
		}
		ds = append(ds, d)
	}
	for _, r := range opts.Rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("dlp rule %q: %w", r.ID, err)
		}
		if re.NumSubexp() > 1 {
			return nil, fmt.Errorf("dlp rule %q: at most one capture group allowed", r.ID)
		}
		sev, ok := ParseSeverity(r.Severity)
		if !ok {
			return nil, fmt.Errorf("dlp rule %q: severity must be low, medium or high", r.ID)
		}
		cat := r.Category
		if cat == "" {
			cat = CategoryPII
		}
		name := r.Name
		if name == "" {
			name = r.ID
		}
		var ctx []string
		for _, c := range r.Context {
			ctx = append(ctx, strings.ToLower(c))
		}
		ds = append(ds, &Detector{ID: r.ID, Name: name, Category: cat, Severity: sev, Re: re,
			MinCount: r.MinCount, Context: ctx, Mask: maskMiddle(2, 2)})
	}
	if opts.Limits.MaxDepth == 0 {
		opts.Limits = DefaultLimits()
	}
	if opts.OCR.Engine != nil {
		opts.OCR.defaults()
	}
	return &Scanner{detectors: ds, opts: opts}, nil
}

// Finding aggregates matches of one detector in one location.
type Finding struct {
	Detector string   `json:"detector"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Location string   `json:"location"`
	Count    int      `json:"count"`   // distinct values
	Samples  []string `json:"samples"` // masked, at most 3
	sev      Severity
}

func (f Finding) Sev() Severity {
	if f.sev != SeverityNone {
		return f.sev
	}
	s, _ := ParseSeverity(f.Severity)
	return s
}

type Report struct {
	Findings []Finding `json:"findings"`
	// Uninspectable lists parts that could not be scanned (encrypted
	// archives or documents, parse failures).
	Uninspectable []string `json:"uninspectable,omitempty"`
}

func (r *Report) MaxSeverity() Severity {
	m := SeverityNone
	for _, f := range r.Findings {
		if s := f.Sev(); s > m {
			m = s
		}
	}
	return m
}

// Summary is a short one-line description, e.g. "주민등록번호 3건, AWS Access Key 1건".
func (r *Report) Summary() string {
	tot := map[string]int{}
	var names []string
	for _, f := range r.Findings {
		if _, ok := tot[f.Name]; !ok {
			names = append(names, f.Name)
		}
		tot[f.Name] += f.Count
	}
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s %d건", n, tot[n]))
	}
	return strings.Join(parts, ", ")
}

// ScanText runs every detector over one piece of text.
func (s *Scanner) ScanText(loc, text string) []Finding {
	var out []Finding
	lower := asciiLower(text) // same byte offsets as text
	var numTokens [][2]int
	numDone := false
	for _, d := range s.detectors {
		var windows [][2]int
		switch {
		case d.Digits:
			if !numDone {
				numTokens, numDone = numberTokens(text), true
			}
			windows = numTokens
		case len(d.Hints) > 0 || len(d.HintsFold) > 0:
			back, ahead := d.Back, d.Ahead
			if ahead == 0 {
				ahead = 512
				if back == 0 {
					back = 32
				}
			}
			windows = hintWindows(text, lower, d.Hints, d.HintsFold, back, ahead)
		default:
			windows = [][2]int{{0, len(text)}}
		}
		if len(windows) == 0 {
			continue
		}
		seen := map[string]bool{}
		var samples []string
		for _, w := range windows {
			seg := text[w[0]:w[1]]
			for _, m := range d.Re.FindAllStringSubmatchIndex(seg, -1) {
				start, end := m[0], m[1]
				if len(m) >= 4 && m[2] >= 0 {
					start, end = m[2], m[3]
				}
				v := seg[start:end]
				start, end = start+w[0], end+w[0]
				if seen[v] || (d.Validate != nil && !d.Validate(v)) {
					continue
				}
				if len(d.Context) > 0 && (d.NeedsContext == nil || d.NeedsContext(v)) &&
					!hasContext(lower, start, end, d.Context) {
					continue
				}
				seen[v] = true
				if len(samples) < 3 {
					samples = append(samples, d.Mask(v))
				}
			}
		}
		n := len(seen)
		if n >= max(d.MinCount, 1) {
			out = append(out, Finding{Detector: d.ID, Name: d.Name, Category: d.Category,
				Severity: d.Severity.String(), sev: d.Severity, Location: loc, Count: n, Samples: samples})
		}
	}
	return out
}

// asciiLower lower-cases ASCII letters only, preserving byte offsets.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// hintWindows returns merged [start,end) byte ranges around every hint
// occurrence. Window edges are moved to UTF-8 boundaries.
func hintWindows(text, lower string, hints, fold []string, back, ahead int) [][2]int {
	var pos []int
	find := func(hay, needle string) {
		for i := 0; ; {
			j := strings.Index(hay[i:], needle)
			if j < 0 {
				return
			}
			pos = append(pos, i+j)
			i += j + len(needle)
		}
	}
	for _, h := range hints {
		find(text, h)
	}
	for _, h := range fold {
		find(lower, h)
	}
	if len(pos) == 0 {
		return nil
	}
	sort.Ints(pos)
	var out [][2]int
	for _, p := range pos {
		lo, hi := max(0, p-back), min(len(text), p+ahead)
		for lo > 0 && !utf8.RuneStart(text[lo]) {
			lo--
		}
		for hi < len(text) && !utf8.RuneStart(text[hi]) {
			hi++
		}
		if n := len(out); n > 0 && lo <= out[n-1][1] {
			out[n-1][1] = max(out[n-1][1], hi)
			continue
		}
		out = append(out, [2]int{lo, hi})
	}
	return out
}

// numberTokens finds runs of digits joined by single '-', ' ' or '.'
// separators that contain at least 10 digits, padded by one byte on each
// side so the detectors' non-digit guards still see the neighbours.
func numberTokens(text string) [][2]int {
	var out [][2]int
	n := len(text)
	for i := 0; i < n; {
		if text[i] < '0' || text[i] > '9' {
			i++
			continue
		}
		start, digitsN, j := i, 0, i
		for j < n {
			c := text[j]
			if c >= '0' && c <= '9' {
				digitsN++
				j++
				continue
			}
			if (c == '-' || c == ' ' || c == '.') && j+1 < n && text[j+1] >= '0' && text[j+1] <= '9' {
				j++
				continue
			}
			break
		}
		if digitsN >= 10 {
			lo, hi := max(0, start-1), min(n, j+1)
			for hi < n && !utf8.RuneStart(text[hi]) {
				hi++
			}
			out = append(out, [2]int{lo, hi})
		}
		i = j
	}
	return out
}

func hasContext(lower string, start, end int, kws []string) bool {
	lo, hi := max(0, start-contextWindow), min(len(lower), end+contextWindow)
	win := lower[lo:hi]
	for _, k := range kws {
		if strings.Contains(win, k) {
			return true
		}
	}
	return false
}

// ScanMessage scans subject, bodies and (optionally) attachments and images.
func (s *Scanner) ScanMessage(ctx context.Context, raw []byte) *Report {
	rep := &Report{}
	root, err := mimeproc.Parse(raw)
	if err != nil {
		rep.Uninspectable = append(rep.Uninspectable, "메일 구조 해석 실패: 원문 전체를 텍스트로 검사")
		rep.Findings = append(rep.Findings, s.ScanText("메일 원문", decodeText(raw))...)
		return rep
	}
	var images []Image
	s.scanEntity(rep, root, "", 0, &images)
	s.ocrImages(ctx, rep, images)
	sort.SliceStable(rep.Findings, func(i, j int) bool { return rep.Findings[i].Sev() > rep.Findings[j].Sev() })
	return rep
}

func (s *Scanner) scanEntity(rep *Report, root *mimeproc.Part, prefix string, depth int, images *[]Image) {
	if subj := root.Header.Get("Subject"); subj != "" {
		rep.Findings = append(rep.Findings, s.ScanText(prefix+"제목", mimeproc.DecodeHeader(subj))...)
	}
	bodyN := 0
	var walk func(p *mimeproc.Part)
	walk = func(p *mimeproc.Part) {
		if p.IsMultipart() {
			for _, c := range p.Children {
				walk(c)
			}
			return
		}
		mt, params := p.MediaType()
		name := p.Filename()
		isBody := name == "" && p.Disposition() != "attachment" && (mt == "text/plain" || mt == "text/html")
		switch {
		case isBody:
			b, err := mimeproc.ToUTF8(params["charset"], p.DecodeBody())
			if err != nil {
				b = []byte(decodeText(p.DecodeBody()))
			}
			text := string(b)
			if mt == "text/html" {
				text = htmlToText(text)
			}
			bodyN++
			rep.Findings = append(rep.Findings, s.ScanText(prefix+"본문", text)...)
		case strings.HasPrefix(mt, "message/"):
			if depth >= 3 || !s.opts.ScanAttachments {
				return
			}
			label := name
			if label == "" {
				label = "첨부된 메일"
			}
			inner, err := mimeproc.Parse(p.DecodeBody())
			if err != nil {
				rep.Uninspectable = append(rep.Uninspectable, prefix+label+": 해석 실패")
				return
			}
			s.scanEntity(rep, inner, prefix+"첨부 "+label+" > ", depth+1, images)
		default:
			if !s.opts.ScanAttachments {
				return
			}
			if strings.HasPrefix(mt, "video/") || strings.HasPrefix(mt, "audio/") {
				return
			}
			if strings.HasPrefix(mt, "image/") && s.opts.OCR.Engine == nil {
				return
			}
			loc := prefix + "첨부 " + name
			switch {
			case name == "" && strings.HasPrefix(mt, "image/"):
				loc = prefix + "본문 삽입 이미지"
			case name == "":
				loc = prefix + "첨부 (이름 없음)"
			}
			ex := Extract(loc, name, p.DecodeBody(), s.opts.Limits)
			for _, t := range ex.Texts {
				rep.Findings = append(rep.Findings, s.ScanText(t.Location, t.Content)...)
			}
			rep.Uninspectable = append(rep.Uninspectable, ex.Problems...)
			*images = append(*images, ex.Images...)
		}
	}
	walk(root)
	// Bodies may appear twice (text + html alternative): merge duplicates.
	if bodyN > 1 {
		rep.Findings = mergeSameLocation(rep.Findings, prefix+"본문")
	}
}

func mergeSameLocation(fs []Finding, loc string) []Finding {
	idx := map[string]int{}
	out := fs[:0]
	for _, f := range fs {
		if f.Location != loc {
			out = append(out, f)
			continue
		}
		if i, ok := idx[f.Detector]; ok {
			if f.Count > out[i].Count {
				out[i] = f
			}
			continue
		}
		idx[f.Detector] = len(out)
		out = append(out, f)
	}
	return out
}

var (
	reScriptStyle = regexp.MustCompile(`(?is)<(script|style)[^>]*>.*?</(script|style)>`)
	reBlockTag    = regexp.MustCompile(`(?i)<(br|/p|/div|/tr|/li|/h[1-6])[^>]*>`)
	reCellTag     = regexp.MustCompile(`(?i)</t[dh]>`)
	reTag         = regexp.MustCompile(`<[^>]*>`)
)

func htmlToText(s string) string {
	s = reScriptStyle.ReplaceAllString(s, " ")
	s = reBlockTag.ReplaceAllString(s, "\n")
	s = reCellTag.ReplaceAllString(s, "\t")
	s = reTag.ReplaceAllString(s, "")
	return html.UnescapeString(s)
}

// ocrImages OCRs distinct, reasonably sized images within the configured
// limits and scans the recognised text. Anything skipped because of limits
// or errors is reported as uninspectable.
func (s *Scanner) ocrImages(ctx context.Context, rep *Report, images []Image) {
	o := s.opts.OCR
	if o.Engine == nil || len(images) == 0 {
		return
	}
	seen := map[[32]byte]bool{}
	var todo []Image
	for _, im := range images {
		k := imageKey(im.Data)
		if seen[k] { // signature logos, repeated screenshots
			continue
		}
		seen[k] = true
		w, h, err := imageSize(im.Data)
		if err != nil {
			rep.Uninspectable = append(rep.Uninspectable, im.Location+": 이미지 해석 실패")
			continue
		}
		if w*h < o.MinPixels || w < 40 || h < 16 {
			continue // icons, bullets, spacer images
		}
		if w*h > o.MaxPixels {
			rep.Uninspectable = append(rep.Uninspectable, im.Location+": 이미지가 너무 큼 (OCR 생략)")
			continue
		}
		todo = append(todo, im)
	}
	if len(todo) > o.MaxImages {
		rep.Uninspectable = append(rep.Uninspectable,
			fmt.Sprintf("이미지 %d개 중 %d개만 OCR 검사 (한도 초과)", len(todo), o.MaxImages))
		todo = todo[:o.MaxImages]
	}
	if len(todo) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, o.TotalTimeout)
	defer cancel()
	type result struct {
		text string
		err  error
	}
	results := make([]result, len(todo))
	sem := make(chan struct{}, o.Concurrency)
	var wg sync.WaitGroup
	for i, im := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i].err = ctx.Err()
				return
			}
			defer func() { <-sem }()
			ictx, icancel := context.WithTimeout(ctx, o.Timeout)
			defer icancel()
			results[i].text, results[i].err = o.Engine.Recognize(ictx, im.Data)
		}()
	}
	wg.Wait()

	for i, r := range results {
		loc := todo[i].Location + " (OCR)"
		if r.err != nil {
			why := "OCR 실패"
			if errors.Is(r.err, context.DeadlineExceeded) || errors.Is(r.err, context.Canceled) {
				why = "OCR 시간 한도 초과"
			}
			rep.Uninspectable = append(rep.Uninspectable, todo[i].Location+": "+why)
			continue
		}
		rep.Findings = append(rep.Findings, s.ScanText(loc, NormalizeOCR(r.text))...)
	}
}
