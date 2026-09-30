package dlp

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

func newScanner(t *testing.T) *Scanner {
	s, err := NewScanner(Options{ScanAttachments: true})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ids(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.Detector] = f
	}
	return m
}

func validRRNDigits(prefix12 string) string {
	w := []int{2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5}
	sum := 0
	for i, m := range w {
		sum += int(prefix12[i]-'0') * m
	}
	return prefix12 + fmt.Sprint((11-sum%11)%10)
}

func TestDetectorsPositive(t *testing.T) {
	s := newScanner(t)
	rrnNoHyphen := validRRNDigits("850315123456")
	text := strings.Join([]string{
		"주민번호: 900101-1234567",
		"번호 " + rrnNoHyphen,
		"카드 4111-1111-1111-1111 결제",
		"여권번호 M12345678",
		"면허 11-22-123456-78",
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"aws_secret_access_key = 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",
		"token ghp_" + strings.Repeat("aB3", 12),
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"DATABASE_URL=postgres://admin:S3cr3tPw@db.internal:5432/app",
		"password: Xk9$mQ2!vLp",
		"key=AIza" + strings.Repeat("Zx9_", 8) + "abc",
		"slack https://hooks.slack.com/services/T0001/B0002/abcdefXYZ123",
		"sk-ant-api03-" + strings.Repeat("Ab1-", 12),
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
	}, "\n")
	got := ids(s.ScanText("본문", text))
	for _, want := range []string{"kr_rrn", "credit_card", "kr_passport", "kr_driver_license", "aws_access_key",
		"aws_secret_key", "github_token", "private_key", "db_connection", "generic_secret", "google_api_key",
		"slack_webhook", "anthropic_key", "jwt"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing detection %s", want)
		}
	}
	if got["kr_rrn"].Count != 2 {
		t.Errorf("rrn count %d", got["kr_rrn"].Count)
	}
	if s := got["kr_rrn"].Samples[0]; s != "900101-1******" {
		t.Errorf("rrn mask %q", s)
	}
	if s := got["credit_card"].Samples[0]; !strings.HasSuffix(s, "1111") || strings.Contains(s, "4111") {
		t.Errorf("card mask %q", s)
	}
	if strings.Contains(got["db_connection"].Samples[0], "S3cr3tPw") {
		t.Error("db password not masked")
	}
}

func TestDetectorsNegative(t *testing.T) {
	s := newScanner(t)
	text := strings.Join([]string{
		"주문번호 991332-1234567",              // month 13
		"주문번호 9001011234560 9001011234561", // no hyphen, bad checksum (at most one can pass)
		"카드 4111-1111-1111-1112",           // Luhn fail
		"M12345678",                        // passport-like without context
		"문의 010-1234-5678, 010-9876-5432",  // below bulk threshold
		"password: ********",
		"password: your_password_here",
		"api_key=${API_KEY}",
		"mysql://localhost:3306/db",
		"postgres://username:password@localhost:5432/mydb",
		"redis://user:${REDIS_PASSWORD}@cache:6379",
		"전화 02-123-4567",
	}, "\n")
	got := ids(s.ScanText("본문", text))
	for _, bad := range []string{"credit_card", "kr_passport", "kr_mobile", "generic_secret", "db_connection"} {
		if f, ok := got[bad]; ok {
			t.Errorf("false positive %s: %+v", bad, f)
		}
	}
	if f, ok := got["kr_rrn"]; ok && f.Count > 1 {
		t.Errorf("rrn false positives: %+v", f)
	}
}

func TestBulkPhoneThreshold(t *testing.T) {
	s := newScanner(t)
	var rows []string
	for i := 0; i < 6; i++ {
		rows = append(rows, fmt.Sprintf("고객%d,010-%04d-%04d", i, 1000+i, 2000+i))
	}
	got := ids(s.ScanText("첨부 list.csv", strings.Join(rows, "\n")))
	if got["kr_mobile"].Count != 6 {
		t.Fatalf("bulk phones: %+v", got["kr_mobile"])
	}
	s2, _ := NewScanner(Options{MinCounts: map[string]int{"kr_mobile": 10}})
	if _, ok := ids(s2.ScanText("x", strings.Join(rows, "\n")))["kr_mobile"]; ok {
		t.Fatal("threshold override ignored")
	}
}

func TestCustomRuleAndDisable(t *testing.T) {
	s, err := NewScanner(Options{
		Disabled: []string{"jwt"},
		Rules: []Rule{{ID: "project_code", Name: "프로젝트 코드명", Pattern: `PRJ-(ORION-\d{3})`,
			Severity: "high", Category: "confidential"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := ids(s.ScanText("x", "PRJ-ORION-042 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"))
	if _, ok := got["project_code"]; !ok {
		t.Error("custom rule not applied")
	}
	if _, ok := got["jwt"]; ok {
		t.Error("disabled detector ran")
	}
	if _, err := NewScanner(Options{Rules: []Rule{{ID: "x", Pattern: "(", Severity: "high"}}}); err == nil {
		t.Error("bad regex accepted")
	}
}

// ---- attachment formats ----

func zipOf(t *testing.T, files map[string]string, encrypted ...string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	enc := map[string]bool{}
	for _, e := range encrypted {
		enc[e] = true
	}
	for name, body := range files {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if enc[name] {
			h.Flags |= 0x1
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	zw.Close()
	return buf.Bytes()
}

func TestDocxRunsAreJoined(t *testing.T) {
	// Word splits text into runs; the RRN spans three runs.
	doc := `<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>주민번호 9001</w:t></w:r><w:r><w:t>01-12</w:t></w:r>` +
		`<w:r><w:t>34567</w:t></w:r></w:p></w:body></w:document>`
	data := zipOf(t, map[string]string{"[Content_Types].xml": "<Types/>", "word/document.xml": doc})
	texts, probs := ExtractText("첨부 a.docx", "a.docx", data, DefaultLimits())
	if len(probs) != 0 || len(texts) != 1 {
		t.Fatalf("texts=%v probs=%v", texts, probs)
	}
	if _, ok := ids(newScanner(t).ScanText("x", texts[0].Content))["kr_rrn"]; !ok {
		t.Fatalf("rrn in docx not found: %q", texts[0].Content)
	}
}

func TestXlsxCellsSeparated(t *testing.T) {
	ss := `<sst><si><t>이름</t></si><si><t>010-1111-2222</t></si></sst>`
	sheet := `<worksheet><sheetData><row><c><v>1234</v></c><c><v>5678</v></c></row></sheetData></worksheet>`
	data := zipOf(t, map[string]string{"[Content_Types].xml": "<Types/>", "xl/sharedStrings.xml": ss, "xl/worksheets/sheet1.xml": sheet})
	texts, _ := ExtractText("첨부 b.xlsx", "b.xlsx", data, DefaultLimits())
	c := texts[0].Content
	if !strings.Contains(c, "010-1111-2222") || strings.Contains(c, "12345678") {
		t.Fatalf("cells must be separated: %q", c)
	}
}

func TestNestedZipAndEncryptedEntry(t *testing.T) {
	inner := zipOf(t, map[string]string{"keys.env": "GITHUB_TOKEN=ghp_" + strings.Repeat("Q", 36)})
	outer := zipOf(t, map[string]string{"inner.zip": string(inner), "secret.txt": "x"}, "secret.txt")
	texts, probs := ExtractText("첨부 outer.zip", "outer.zip", outer, DefaultLimits())
	if len(texts) != 1 || texts[0].Location != "첨부 outer.zip > inner.zip > keys.env" {
		t.Fatalf("nested location wrong: %+v", texts)
	}
	if len(probs) != 1 || !strings.Contains(probs[0], "암호화") {
		t.Fatalf("encrypted entry not reported: %v", probs)
	}
}

func TestZipBombLimited(t *testing.T) {
	data := zipOf(t, map[string]string{"big.txt": strings.Repeat("A", 5<<20)})
	lim := DefaultLimits()
	lim.MaxInflate = 1 << 20
	_, probs := ExtractText("첨부 bomb.zip", "bomb.zip", data, lim)
	if len(probs) == 0 || !strings.Contains(probs[0], "한도") {
		t.Fatalf("inflate limit not enforced: %v", probs)
	}
}

func TestEUCKRTextFile(t *testing.T) {
	// "주민번호 900101-1234567" in EUC-KR
	euc, _ := base64.StdEncoding.DecodeString("wda5zrn4yKMgOTAwMTAxLTEyMzQ1Njc=")
	texts, _ := ExtractText("첨부 c.txt", "c.txt", euc, DefaultLimits())
	if !strings.Contains(texts[0].Content, "주민번호") {
		t.Fatalf("euc-kr not decoded: %q", texts[0].Content)
	}
}

// minimalPDF builds a valid one-page PDF showing text.
func minimalPDF(text string) []byte {
	var b bytes.Buffer
	var offs []int
	obj := func(s string) {
		offs = append(offs, b.Len())
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", len(offs), s)
	}
	b.WriteString("%PDF-1.4\n")
	obj("<< /Type /Catalog /Pages 2 0 R >>")
	obj("<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	obj("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>")
	content := fmt.Sprintf("BT /F1 12 Tf 72 720 Td (%s) Tj ET", text)
	obj(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content))
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(offs)+1)
	for _, o := range offs {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offs)+1, xref)
	return b.Bytes()
}

func TestPDF(t *testing.T) {
	data := minimalPDF("key AKIAIOSFODNN7EXAMPLE")
	texts, probs := ExtractText("첨부 d.pdf", "d.pdf", data, DefaultLimits())
	if len(probs) != 0 || len(texts) == 0 {
		t.Fatalf("pdf: %v %v", texts, probs)
	}
	if _, ok := ids(newScanner(t).ScanText("x", texts[0].Content))["aws_access_key"]; !ok {
		t.Fatalf("pdf text: %q", texts[0].Content)
	}
	_, probs = ExtractText("첨부 e.pdf", "e.pdf", []byte("%PDF-1.4 garbage"), DefaultLimits())
	if len(probs) == 0 {
		t.Fatal("broken pdf must be reported as uninspectable")
	}
}

func TestHWPRecords(t *testing.T) {
	enc := func(s string) []byte {
		var b []byte
		for _, u := range utf16.Encode([]rune(s)) {
			b = binary.LittleEndian.AppendUint16(b, u)
		}
		return b
	}
	para := enc("주민번호 ")
	// An extended control (e.g. field start, code 3) occupies 8 WCHARs.
	ctrl := make([]byte, 16)
	binary.LittleEndian.PutUint16(ctrl, 3)
	para = append(append(para, ctrl...), enc("900101-1234567")...)
	rec := func(tag uint32, body []byte) []byte {
		h := tag | uint32(len(body))<<20
		return append(binary.LittleEndian.AppendUint32(nil, h), body...)
	}
	stream := append(rec(0x10+50, []byte{1, 2, 3, 4}), rec(hwpTagParaText, para)...)
	var sb strings.Builder
	hwpRecords(&sb, stream)
	if !strings.Contains(sb.String(), "900101-1234567") || !strings.Contains(sb.String(), "주민번호") {
		t.Fatalf("hwp text: %q", sb.String())
	}
}

func TestScanMessage(t *testing.T) {
	csv := "이름,주민번호\n홍길동,900101-1234567\n"
	msg := "From: a@example.com\r\nTo: b@partner.com\r\nSubject: =?utf-8?B?" +
		base64.StdEncoding.EncodeToString([]byte("고객 명단")) + "?=\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=B\r\n\r\n" +
		"--B\r\nContent-Type: multipart/alternative; boundary=A\r\n\r\n" +
		"--A\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n접속키 AKIAIOSFODNN7EXAMPLE\r\n" +
		"--A\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>접속키 <b>AKIAIOSFODNN7EXAMPLE</b></p>\r\n--A--\r\n" +
		"--B\r\nContent-Type: text/csv; name=list.csv\r\nContent-Disposition: attachment; filename=list.csv\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte(csv)) + "\r\n--B--\r\n"
	rep := newScanner(t).ScanMessage(context.Background(), []byte(msg))
	if rep.MaxSeverity() != SeverityHigh {
		t.Fatalf("severity %v", rep.MaxSeverity())
	}
	locs := map[string]string{}
	for _, f := range rep.Findings {
		locs[f.Detector+"@"+f.Location] = f.Name
	}
	if _, ok := locs["aws_access_key@본문"]; !ok {
		t.Errorf("body key missing: %v", locs)
	}
	if _, ok := locs["kr_rrn@첨부 list.csv"]; !ok {
		t.Errorf("attachment rrn missing: %v", locs)
	}
	n := 0
	for _, f := range rep.Findings {
		if f.Detector == "aws_access_key" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("text+html duplicate not merged: %d", n)
	}
	if !strings.Contains(rep.Summary(), "주민등록번호/외국인등록번호 1건") {
		t.Errorf("summary %q", rep.Summary())
	}
}

func TestCardContiguousNeedsContext(t *testing.T) {
	s := newScanner(t)
	if _, ok := ids(s.ScanText("x", "주문번호 4111111111111111 배송 완료"))["credit_card"]; ok {
		t.Error("contiguous digits without card context flagged")
	}
	if _, ok := ids(s.ScanText("x", "결제 카드번호 4111111111111111"))["credit_card"]; !ok {
		t.Error("contiguous card number with context missed")
	}
	if _, ok := ids(s.ScanText("x", "번호 4111 1111 1111 1111"))["credit_card"]; !ok {
		t.Error("grouped card number missed")
	}
}

func TestPrefilterEdgeCases(t *testing.T) {
	s := newScanner(t)
	// Match right at the start/end of the text and next to multi-byte runes.
	got := ids(s.ScanText("x", "AKIAIOSFODNN7EXAMPLE가900101-1234567나"))
	if _, ok := got["aws_access_key"]; !ok {
		t.Error("hint at text start missed")
	}
	if _, ok := got["kr_rrn"]; !ok {
		t.Error("number token between Korean letters missed")
	}
	// A long digit run must not create matches inside it.
	if _, ok := ids(s.ScanText("x", "12345678901234567890123"))["kr_rrn"]; ok {
		t.Error("rrn inside longer number")
	}
}
