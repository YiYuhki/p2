// Package dlp finds personal data and credentials in outgoing mail bodies
// and attachments (Data Loss Prevention).
package dlp

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Severity int

const (
	SeverityNone Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	}
	return "none"
}

func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(s) {
	case "low":
		return SeverityLow, true
	case "medium":
		return SeverityMedium, true
	case "high":
		return SeverityHigh, true
	}
	return SeverityNone, false
}

const (
	CategoryPII    = "pii"
	CategorySecret = "secret"
)

// Detector finds one kind of sensitive value.
type Detector struct {
	ID       string
	Name     string // shown to users (Korean)
	Category string
	Severity Severity
	// Re must contain exactly one capture group holding the value, or none
	// (then the whole match is the value).
	Re *regexp.Regexp
	// Validate filters false positives (checksums, dates, entropy...).
	Validate func(value string) bool
	// Context, if set, requires one of these keywords (lower-case) within
	// ContextWindow bytes of the match.
	Context []string
	// MinCount is the number of distinct values needed in one location
	// before the detector reports (bulk detection, e.g. phone lists).
	MinCount int
	Mask     func(string) string
	// NeedsContext, if set, makes Context mandatory only for values it
	// returns true for (e.g. card numbers written without separators).
	NeedsContext func(value string) bool

	// Pre-filters so that regexes only run near plausible matches:
	//   Digits    - run on number-like tokens (>= 10 digits) only
	//   Hints     - case-sensitive literals that every match contains
	//   HintsFold - lower-case literals searched case-insensitively
	// Detectors without any pre-filter scan the whole text.
	Digits    bool
	Hints     []string
	HintsFold []string
	// Back/Ahead size the window around a hint (defaults 32 / 512 bytes).
	Back, Ahead int
}

const contextWindow = 60

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ---- validators ----

// validRRN checks a Korean resident / alien registration number
// (주민등록번호 / 외국인등록번호). Since Oct 2020 the last digits are random,
// so the checksum cannot be required; the birth date and gender digit are
// always checked. Without a hyphen the checksum must also match to avoid
// flagging arbitrary 13-digit numbers.
func validRRN(v string) bool {
	d := digits(v)
	if len(d) != 13 {
		return false
	}
	g := d[6]
	var century int
	switch g {
	case '1', '2', '5', '6':
		century = 1900
	case '3', '4', '7', '8':
		century = 2000
	default:
		return false
	}
	yy, _ := strconv.Atoi(d[0:2])
	mm, _ := strconv.Atoi(d[2:4])
	dd, _ := strconv.Atoi(d[4:6])
	t := time.Date(century+yy, time.Month(mm), dd, 0, 0, 0, 0, time.UTC)
	if t.Month() != time.Month(mm) || t.Day() != dd || t.After(time.Now()) {
		return false
	}
	if strings.Contains(v, "-") {
		return true
	}
	return rrnChecksum(d)
}

func rrnChecksum(d string) bool {
	w := []int{2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5}
	sum := 0
	for i, m := range w {
		sum += int(d[i]-'0') * m
	}
	check := (11 - sum%11) % 10
	return check == int(d[12]-'0')
}

func luhn(d string) bool {
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// validBizReg checks a Korean business registration number (사업자등록번호,
// 10 digits, DDD-DD-DDDDD) via its official check digit.
func validBizReg(v string) bool {
	d := digits(v)
	if len(d) != 10 || d == "0000000000" {
		return false
	}
	w := []int{1, 3, 7, 1, 3, 7, 1, 3, 5}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * w[i]
	}
	sum += int(d[8]-'0') * 5 / 10
	check := (10 - sum%10) % 10
	return check == int(d[9]-'0')
}

// validCorpReg checks a Korean corporate registration number (법인등록번호,
// 13 digits, DDDDDD-DDDDDDD) via its check digit.
func validCorpReg(v string) bool {
	d := digits(v)
	if len(d) != 13 {
		return false
	}
	sum := 0
	for i := 0; i < 12; i++ {
		w := 1
		if i%2 == 1 {
			w = 2
		}
		sum += int(d[i]-'0') * w
	}
	check := (10 - sum%10) % 10
	return check == int(d[12]-'0')
}

// validIBAN checks an International Bank Account Number via the ISO 7064
// mod-97 rule.
func validIBAN(v string) bool {
	s := strings.ToUpper(strings.ReplaceAll(v, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearranged := s[4:] + s[:4]
	rem := 0
	for _, c := range rearranged {
		var n int
		switch {
		case c >= '0' && c <= '9':
			n = int(c - '0')
		case c >= 'A' && c <= 'Z':
			n = int(c-'A') + 10
		default:
			return false
		}
		if n < 10 {
			rem = (rem*10 + n) % 97
		} else {
			rem = (rem*100 + n) % 97
		}
	}
	return rem == 1
}

func validCard(v string) bool {
	d := digits(v)
	// 14+ digits: a 13-digit number is far more likely a resident number.
	if len(d) < 14 || len(d) > 19 || !luhn(d) {
		return false
	}
	// Issuer prefixes: Visa, Mastercard, Amex, JCB, Discover, UnionPay,
	// Korean domestic (9xxx).
	p2, _ := strconv.Atoi(d[:2])
	p4, _ := strconv.Atoi(d[:4])
	switch {
	case d[0] == '4':
	case d[0] == '9' && len(d) == 16:
	case p2 >= 51 && p2 <= 55, p4 >= 2221 && p4 <= 2720:
	case p2 == 34 || p2 == 37 || p2 == 35 || p2 == 62 || p2 == 65 || p4 == 6011:
	default:
		return false
	}
	// Reject trivially repetitive numbers (0000..., 4111 1111 ... is a
	// well-known test number but still a PAN format; keep it).
	return strings.Trim(d, d[:1]) != ""
}

// entropy returns the Shannon entropy in bits per character.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	e := 0.0
	for _, c := range freq {
		p := c / n
		e -= p * math.Log2(p)
	}
	return e
}

var placeholders = []string{"xxxx", "****", "....", "your", "example", "sample", "changeme",
	"password", "secret", "dummy", "test1234", "<", "${", "{{", "%s", "redacted", "masked", "none", "null"}

func validGenericSecret(v string) bool {
	lv := strings.ToLower(v)
	for _, p := range placeholders {
		if strings.Contains(lv, p) {
			return false
		}
	}
	return entropy(v) >= 3.0
}

// validDBURL rejects connection strings whose password is a placeholder
// (documentation examples such as postgres://user:password@localhost).
func validDBURL(v string) bool {
	at := strings.LastIndexByte(v, '@')
	scheme := strings.Index(v, "://")
	if at < 0 || scheme < 0 || at < scheme {
		return false
	}
	cred := v[scheme+3 : at]
	c := strings.IndexByte(cred, ':')
	if c < 0 {
		return false
	}
	pw := strings.ToLower(cred[c+1:])
	switch pw {
	case "pass", "pw", "pwd", "user", "username", "root", "admin", "postgres", "mysql", "guest", "123456", "1234":
		return false
	}
	for _, p := range placeholders {
		if strings.Contains(pw, p) {
			return false
		}
	}
	return len(pw) >= 4
}

// ---- maskers ----

func maskMiddle(keepStart, keepEnd int) func(string) string {
	return func(v string) string {
		r := []rune(v)
		if len(r) <= keepStart+keepEnd {
			return strings.Repeat("*", len(r))
		}
		return string(r[:keepStart]) + strings.Repeat("*", len(r)-keepStart-keepEnd) + string(r[len(r)-keepEnd:])
	}
}

func maskRRN(v string) string {
	d := digits(v)
	return d[:6] + "-" + d[6:7] + "******"
}

func maskCard(v string) string {
	d := digits(v)
	return strings.Repeat("*", len(d)-4) + d[len(d)-4:]
}

func maskPhone(v string) string {
	d := digits(v)
	return d[:3] + "-****-" + d[len(d)-4:]
}

func maskEmail(v string) string {
	at := strings.LastIndexByte(v, '@')
	if at <= 0 {
		return maskMiddle(1, 0)(v)
	}
	return v[:1] + strings.Repeat("*", at-1) + v[at:]
}

// ---- built-in detectors ----

// Non-digit / non-alnum guards emulate \b around numbers (RE2 has no
// look-around).
const (
	nd  = `(?:^|[^0-9])`
	ndE = `(?:[^0-9]|$)`
	na  = `(?:^|[^A-Za-z0-9_])`
	naE = `(?:[^A-Za-z0-9_]|$)`
)

func Builtin() []*Detector {
	return []*Detector{
		// --- personal information ---
		{ID: "kr_rrn", Name: "주민등록번호/외국인등록번호", Category: CategoryPII, Severity: SeverityHigh, Digits: true,
			Re: regexp.MustCompile(nd + `(\d{6}[- ]?[1-8]\d{6})` + ndE), Validate: validRRN, Mask: maskRRN},
		{ID: "credit_card", Name: "신용카드번호", Category: CategoryPII, Severity: SeverityHigh, Digits: true,
			Context:      []string{"카드", "card", "신용", "체크", "결제", "visa", "master", "amex", "비자", "마스터", "pan"},
			NeedsContext: func(v string) bool { return v == digits(v) }, // contiguous digits need context
			Re:           regexp.MustCompile(nd + `(\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{2,7}|3[47]\d{2}[- ]?\d{6}[- ]?\d{5})` + ndE),
			Validate:     validCard, Mask: maskCard},
		{ID: "kr_passport", Name: "여권번호", Category: CategoryPII, Severity: SeverityMedium,
			HintsFold: []string{"여권", "passport"}, Back: 200, Ahead: 200,
			Re:      regexp.MustCompile(na + `([MSRGDmsrgd]\d{8}|[MSRGD]\d{3}[A-Z]\d{4})` + naE),
			Context: []string{"여권", "passport"}, Mask: maskMiddle(2, 2)},
		{ID: "kr_driver_license", Name: "운전면허번호", Category: CategoryPII, Severity: SeverityMedium, Digits: true,
			Re:   regexp.MustCompile(nd + `((?:1[1-9]|2[0-8])-\d{2}-\d{6}-\d{2})` + ndE),
			Mask: maskMiddle(5, 2)},
		{ID: "kr_biz_reg", Name: "사업자등록번호", Category: CategoryPII, Severity: SeverityMedium, Digits: true,
			Re:       regexp.MustCompile(nd + `(\d{3}-\d{2}-\d{5})` + ndE),
			Validate: validBizReg, Mask: maskMiddle(3, 2)},
		{ID: "kr_corp_reg", Name: "법인등록번호", Category: CategoryPII, Severity: SeverityMedium, Digits: true,
			Re:       regexp.MustCompile(nd + `(\d{6}-\d{7})` + ndE),
			Validate: validCorpReg, Mask: maskMiddle(6, 2)},
		{ID: "bank_account", Name: "계좌번호", Category: CategoryPII, Severity: SeverityMedium, Digits: true,
			Re: regexp.MustCompile(nd + `(\d{2,6}-\d{2,6}-\d{2,7}(?:-\d{1,7})?)` + ndE),
			Context: []string{"계좌", "예금주", "입금", "송금", "account", "은행", "bank", "농협", "국민",
				"신한", "우리", "하나", "기업", "카카오뱅크", "토스", "새마을", "우체국", "수협", "대출"},
			Validate: func(v string) bool { d := digits(v); return len(d) >= 10 && len(d) <= 16 },
			Mask:     maskMiddle(3, 3)},
		{ID: "iban", Name: "IBAN(해외계좌)", Category: CategoryPII, Severity: SeverityMedium,
			Re:       regexp.MustCompile(na + `([A-Z]{2}\d{2}[A-Z0-9]{11,30})` + naE),
			Validate: validIBAN, Mask: maskMiddle(4, 2)},
		{ID: "kr_mobile", Name: "휴대전화번호(대량)", Category: CategoryPII, Severity: SeverityMedium, MinCount: 5, Digits: true,
			Re:   regexp.MustCompile(nd + `(01[016789][- .]?\d{3,4}[- .]?\d{4})` + ndE),
			Mask: maskPhone},
		{ID: "email_address", Name: "이메일 주소(대량)", Category: CategoryPII, Severity: SeverityLow, MinCount: 20,
			Hints: []string{"@"}, Back: 64, Ahead: 256,
			Re:   regexp.MustCompile(`[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`),
			Mask: maskEmail},

		// --- credentials / secrets ---
		{ID: "private_key", Name: "개인키(Private Key)", Category: CategorySecret, Severity: SeverityHigh,
			Hints: []string{"-----BEGIN "},
			Re:    regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`),
			Mask:  func(v string) string { return v }},
		{ID: "aws_access_key", Name: "AWS Access Key", Category: CategorySecret, Severity: SeverityHigh,
			Hints: []string{"AKIA", "ASIA"},
			Re:    regexp.MustCompile(na + `((?:AKIA|ASIA)[0-9A-Z]{16})` + naE), Mask: maskMiddle(4, 2)},
		{ID: "aws_secret_key", Name: "AWS Secret Key", Category: CategorySecret, Severity: SeverityHigh,
			HintsFold: []string{"aws"}, Back: 0, Ahead: 160,
			Re:       regexp.MustCompile(`(?i)aws.{0,20}(?:secret|private).{0,20}?[=:"'\s]\s*["']?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|$)`),
			Validate: func(v string) bool { return entropy(v) >= 3.5 }, Mask: maskMiddle(4, 2)},
		{ID: "github_token", Name: "GitHub 토큰", Category: CategorySecret, Severity: SeverityHigh,
			Hints: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
			Re:    regexp.MustCompile(na + `((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})` + naE),
			Mask:  maskMiddle(6, 2)},
		{ID: "gitlab_token", Name: "GitLab 토큰", Category: CategorySecret, Severity: SeverityHigh,
			Hints: []string{"glpat-"},
			Re:    regexp.MustCompile(na + `(glpat-[A-Za-z0-9_-]{20,})`), Mask: maskMiddle(8, 2)},
		{ID: "slack_token", Name: "Slack 토큰", Category: CategorySecret, Severity: SeverityHigh,
			Hints: []string{"xox"},
			Re:    regexp.MustCompile(na + `(xox[baprs]-[A-Za-z0-9-]{10,})`), Mask: maskMiddle(5, 2)},
		{ID: "slack_webhook", Name: "Slack Webhook URL", Category: CategorySecret, Severity: SeverityHigh,
			Hints: []string{"hooks.slack.com"}, Back: 16,
			Re:   regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`),
			Mask: maskMiddle(34, 2)},
		{ID: "google_api_key", Name: "Google API Key", Category: CategorySecret, Severity: SeverityHigh,
			Hints: []string{"AIza"},
			Re:    regexp.MustCompile(na + `(AIza[0-9A-Za-z_-]{35})` + naE), Mask: maskMiddle(6, 2)},
		{ID: "stripe_key", Name: "Stripe Secret Key", Category: CategorySecret, Severity: SeverityHigh,
			Hints: []string{"_live_"},
			Re:    regexp.MustCompile(na + `((?:sk|rk)_live_[0-9a-zA-Z]{24,})`), Mask: maskMiddle(8, 2)},
		{ID: "anthropic_key", Name: "Anthropic API Key", Category: CategorySecret, Severity: SeverityHigh,
			Hints: []string{"sk-ant-"},
			Re:    regexp.MustCompile(na + `(sk-ant-[A-Za-z0-9_-]{32,})`), Mask: maskMiddle(10, 2)},
		{ID: "openai_key", Name: "OpenAI API Key", Category: CategorySecret, Severity: SeverityHigh,
			Hints: []string{"sk-"},
			Re:    regexp.MustCompile(na + `(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{48})` + naE),
			Mask:  maskMiddle(8, 2)},
		{ID: "db_connection", Name: "DB 접속정보(계정 포함)", Category: CategorySecret, Severity: SeverityHigh,
			HintsFold: []string{"postgres://", "postgresql://", "mysql://", "mariadb://", "mongodb://",
				"mongodb+srv://", "redis://", "rediss://", "amqp://", "amqps://", "mssql://", "sqlserver://"},
			Back: 1, Ahead: 256, Validate: validDBURL,
			Re: regexp.MustCompile(`((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)://[^\s:/@"'<>]+:[^\s@/"'<>]+@[^\s/"'<>]+)`),
			Mask: func(v string) string {
				at := strings.LastIndexByte(v, '@')
				c := strings.LastIndex(v[:at], ":")
				return v[:c+1] + "****" + v[at:]
			}},
		{ID: "azure_storage_key", Name: "Azure Storage Key", Category: CategorySecret, Severity: SeverityHigh,
			Hints: []string{"AccountKey="}, Back: 0,
			Re: regexp.MustCompile(`AccountKey=([A-Za-z0-9+/=]{80,})`), Mask: maskMiddle(4, 2)},
		{ID: "jwt", Name: "JWT 토큰", Category: CategorySecret, Severity: SeverityMedium,
			Hints: []string{"eyJ"}, Ahead: 8192,
			Re:   regexp.MustCompile(na + `(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`),
			Mask: maskMiddle(10, 0)},
		{ID: "generic_secret", Name: "비밀번호/시크릿 값", Category: CategorySecret, Severity: SeverityMedium,
			HintsFold: []string{"password", "passwd", "pwd", "secret", "api_key", "api-key", "apikey", "access_token",
				"access-token", "auth_token", "auth-token", "client_secret", "client-secret", "비밀번호", "패스워드", "암호"},
			Back: 1, Ahead: 128,
			Re:       regexp.MustCompile(`(?i)(?:\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\b|비밀번호|패스워드|암호)["']?\s*[:=：]\s*["']?([^\s"'<>,;]{8,64})`),
			Validate: validGenericSecret, Mask: maskMiddle(2, 0)},
	}
}
