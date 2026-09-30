package mimeproc

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func crlf(s string) []byte {
	return []byte(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n"))
}

var banner = Banner{Text: "[BANNER-TEXT] https://sec/d/x", HTML: `<div id="banner">https://sec/d/x</div>`}

const pdfB64 = "JVBERi0xLjQKJcfsj6IK" // "%PDF-1.4\n%...."

func mustParse(t *testing.T, raw []byte) *Part {
	t.Helper()
	p, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func rewrite(t *testing.T, raw []byte, opts Options) (*Result, string) {
	t.Helper()
	root := mustParse(t, raw)
	res, err := Extract(root, opts)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(res.Attachments) > 0 {
		InsertBanner(root, banner)
	}
	out, err := root.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	// The output must itself be parseable.
	if _, err := Parse(out); err != nil {
		t.Fatalf("output does not re-parse: %v\n%s", err, out)
	}
	return res, string(out)
}

// decodedText returns all text/* leaves decoded, for assertions.
func decodedText(t *testing.T, msg string) string {
	root := mustParse(t, []byte(msg))
	var sb strings.Builder
	var walk func(*Part)
	walk = func(p *Part) {
		for _, c := range p.Children {
			walk(c)
		}
		if !p.IsMultipart() {
			mt, params := p.MediaType()
			if strings.HasPrefix(mt, "text/") {
				b, _ := ToUTF8(params["charset"], p.DecodeBody())
				sb.Write(b)
				sb.WriteString("\n")
			}
		}
	}
	walk(root)
	return sb.String()
}

func TestMixedWithAttachment(t *testing.T) {
	raw := crlf(`From: a@ext.com
To: b@example.com
Subject: test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="XX"

--XX
Content-Type: text/plain; charset=utf-8

hello body
--XX
Content-Type: application/pdf; name="report.pdf"
Content-Disposition: attachment; filename="report.pdf"
Content-Transfer-Encoding: base64

` + pdfB64 + `
--XX--
`)
	res, out := rewrite(t, raw, Options{KeepInlineImages: true})
	if len(res.Attachments) != 1 {
		t.Fatalf("want 1 attachment, got %d", len(res.Attachments))
	}
	a := res.Attachments[0]
	if a.Filename != "report.pdf" || a.ContentType != "application/pdf" || !bytes.HasPrefix(a.Data, []byte("%PDF-1.4")) {
		t.Fatalf("bad attachment: %+v", a)
	}
	if strings.Contains(out, pdfB64) || strings.Contains(out, "report.pdf\"") {
		t.Fatalf("attachment still present:\n%s", out)
	}
	txt := decodedText(t, out)
	if !strings.Contains(txt, "hello body") || !strings.Contains(txt, "[BANNER-TEXT]") {
		t.Fatalf("body/banner missing: %q", txt)
	}
	if !strings.Contains(out, "Subject: test") {
		t.Fatal("top-level headers lost")
	}
}

func TestAlternativeBothBodiesGetBanner(t *testing.T) {
	raw := crlf(`From: a@ext.com
Content-Type: multipart/mixed; boundary="M"

--M
Content-Type: multipart/alternative; boundary="A"

--A
Content-Type: text/plain; charset=us-ascii

plain body
--A
Content-Type: text/html; charset=us-ascii
Content-Transfer-Encoding: quoted-printable

<html><body><p>html body</p></body></html>
--A--
--M
Content-Type: application/octet-stream
Content-Disposition: attachment; filename=x.exe
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--M--
`)
	res, out := rewrite(t, raw, Options{})
	if len(res.Attachments) != 1 || res.Attachments[0].Filename != "x.exe" {
		t.Fatalf("unexpected attachments %+v", res.Attachments)
	}
	txt := decodedText(t, out)
	if !strings.Contains(txt, "plain body") || !strings.Contains(txt, "[BANNER-TEXT]") {
		t.Fatalf("plain banner missing: %q", txt)
	}
	if !strings.Contains(txt, `<div id="banner">https://sec/d/x</div></body>`) {
		t.Fatalf("html banner not inserted before </body>: %q", txt)
	}
}

func TestInlineImageKeptAndNamedInlineExtracted(t *testing.T) {
	raw := crlf(`Content-Type: multipart/related; boundary="R"

--R
Content-Type: text/html

<img src="cid:logo">
--R
Content-Type: image/png
Content-ID: <logo>
Content-Disposition: inline; filename="logo.png"
Content-Transfer-Encoding: base64

iVBORw0KGgo=
--R
Content-Type: application/zip; name="a.zip"
Content-Transfer-Encoding: base64

UEsDBA==
--R--
`)
	res, out := rewrite(t, raw, Options{KeepInlineImages: true})
	if len(res.Attachments) != 1 || res.Attachments[0].Filename != "a.zip" {
		t.Fatalf("want only a.zip extracted, got %+v", res.Attachments)
	}
	if !strings.Contains(out, "iVBORw0KGgo=") {
		t.Fatal("inline image should be kept")
	}

	res, _ = rewrite(t, raw, Options{KeepInlineImages: false})
	if len(res.Attachments) != 2 {
		t.Fatalf("with KeepInlineImages=false want 2, got %d", len(res.Attachments))
	}
}

func TestSinglePartAttachmentMessage(t *testing.T) {
	raw := crlf(`From: a@ext.com
Subject: scan
Content-Type: application/pdf; name="scan.pdf"
Content-Transfer-Encoding: base64

` + pdfB64 + `
`)
	res, out := rewrite(t, raw, Options{})
	if len(res.Attachments) != 1 || res.Attachments[0].Filename != "scan.pdf" {
		t.Fatalf("got %+v", res.Attachments)
	}
	root := mustParse(t, []byte(out))
	if mt, _ := root.MediaType(); mt != "multipart/mixed" {
		t.Fatalf("root should become multipart/mixed, got %s", mt)
	}
	if !strings.Contains(decodedText(t, out), "[BANNER-TEXT]") {
		t.Fatal("banner missing")
	}
	if strings.Contains(out, pdfB64) {
		t.Fatal("attachment still present")
	}
}

func TestSignedMessageIsUnwrapped(t *testing.T) {
	raw := crlf(`From: a@ext.com
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="S"

--S
Content-Type: multipart/mixed; boundary="M"

--M
Content-Type: text/plain

signed body
--M
Content-Type: application/pdf
Content-Disposition: attachment; filename="c.pdf"
Content-Transfer-Encoding: base64

` + pdfB64 + `
--M--
--S
Content-Type: application/pkcs7-signature; name=smime.p7s
Content-Disposition: attachment; filename=smime.p7s
Content-Transfer-Encoding: base64

MIAGCSqGSIb3DQEHAqCAMIACAQEx
--S--
`)
	res, out := rewrite(t, raw, Options{})
	if !res.SignatureRemoved {
		t.Fatal("expected SignatureRemoved")
	}
	if len(res.Attachments) != 1 || res.Attachments[0].Filename != "c.pdf" {
		t.Fatalf("got %+v", res.Attachments)
	}
	if strings.Contains(out, "smime.p7s") || strings.Contains(out, "multipart/signed") {
		t.Fatalf("signature wrapper should be removed:\n%s", out)
	}
	if !strings.Contains(decodedText(t, out), "signed body") {
		t.Fatal("signed content lost")
	}

	res, out = rewrite(t, raw, Options{SignedPassthrough: true})
	if res.Skipped != "signed" || len(res.Attachments) != 0 || !strings.Contains(out, "smime.p7s") {
		t.Fatal("passthrough should not modify signed message")
	}
}

func TestEncryptedPolicy(t *testing.T) {
	raw := crlf(`Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m
Content-Transfer-Encoding: base64

MIAGCSqGSIb3DQEHA6CAMIACAQAx
`)
	root := mustParse(t, raw)
	res, err := Extract(root, Options{})
	if err != nil || res.Skipped != "encrypted" {
		t.Fatalf("passthrough expected, got %v %+v", err, res)
	}
	if _, err := Extract(mustParse(t, raw), Options{EncryptedReject: true}); err != ErrEncrypted {
		t.Fatalf("want ErrEncrypted, got %v", err)
	}
}

func TestKoreanFilenamesAndCharset(t *testing.T) {
	// "보고서.hwp" in EUC-KR, RFC 2047 B-encoded; body in EUC-KR ("안녕하세요").
	raw := crlf(`Content-Type: multipart/mixed; boundary="K"

--K
Content-Type: text/plain; charset=ks_c_5601-1987
Content-Transfer-Encoding: base64

vsiz58fPvLy/5A==
--K
Content-Type: application/octet-stream; name="=?euc-kr?B?uriw7bytLmh3cA==?="
Content-Disposition: attachment; filename="=?euc-kr?B?uriw7bytLmh3cA==?="
Content-Transfer-Encoding: base64

AAAA
--K
Content-Type: application/octet-stream
Content-Disposition: attachment; filename*=UTF-8''%EA%B2%AC%EC%A0%81%EC%84%9C.xlsx
Content-Transfer-Encoding: base64

AAAA
--K--
`)
	res, out := rewrite(t, raw, Options{})
	if len(res.Attachments) != 2 {
		t.Fatalf("want 2, got %d", len(res.Attachments))
	}
	if res.Attachments[0].Filename != "보고서.hwp" {
		t.Errorf("rfc2047 euc-kr filename: got %q", res.Attachments[0].Filename)
	}
	if res.Attachments[1].Filename != "견적서.xlsx" {
		t.Errorf("rfc2231 filename: got %q", res.Attachments[1].Filename)
	}
	txt := decodedText(t, out)
	if !strings.Contains(txt, "안녕하세요") || !strings.Contains(txt, "[BANNER-TEXT]") {
		t.Fatalf("euc-kr body not converted: %q", txt)
	}
	if !strings.Contains(out, "charset=utf-8") {
		t.Fatal("rewritten body should be labelled utf-8")
	}
}

func TestForwardedMessageExtracted(t *testing.T) {
	raw := crlf(`Content-Type: multipart/mixed; boundary="F"

--F
Content-Type: text/plain

see below
--F
Content-Type: message/rfc822

From: x@y
Subject: inner

inner body
--F--
`)
	res, _ := rewrite(t, raw, Options{})
	if len(res.Attachments) != 1 || res.Attachments[0].Filename != "forwarded-message.eml" {
		t.Fatalf("got %+v", res.Attachments)
	}
}

func TestNoAttachmentRoundTripIsByteIdentical(t *testing.T) {
	raw := crlf(`From: a@ext.com
Subject: plain
Content-Type: multipart/alternative; boundary="A"

--A
Content-Type: text/plain

hi
--A
Content-Type: text/html

<b>hi</b>
--A--
`)
	root := mustParse(t, raw)
	res, err := Extract(root, Options{})
	if err != nil || len(res.Attachments) != 0 {
		t.Fatal(err, res)
	}
	out, _ := root.Bytes()
	if !bytes.Equal(out, raw) {
		t.Fatalf("round trip changed message:\n%q\n%q", raw, out)
	}
}

func TestOnlyAttachmentsGetsBannerPart(t *testing.T) {
	raw := crlf(`Content-Type: multipart/mixed; boundary="O"

--O
Content-Type: application/pdf; name=a.pdf
Content-Transfer-Encoding: base64

` + pdfB64 + `
--O--
`)
	res, out := rewrite(t, raw, Options{})
	if len(res.Attachments) != 1 {
		t.Fatal("want 1")
	}
	if !strings.Contains(decodedText(t, out), "[BANNER-TEXT]") {
		t.Fatal("banner part missing")
	}
}

func TestSanitizeFilename(t *testing.T) {
	cases := map[string]string{
		"../../etc/passwd":                "passwd",
		`C:\Users\x\evil.exe`:             "evil.exe",
		"inv\u202Egpj.exe":                "invgpj.exe",
		"...hidden":                       "hidden",
		"a\x00b\r\n.txt":                  "ab.txt",
		"quote\".pdf":                     "quote.pdf",
		strings.Repeat("가", 300) + ".pdf": "",
	}
	for in, want := range cases {
		got := SanitizeFilename(in)
		if want == "" {
			if len(got) > 200 || !strings.HasSuffix(got, ".pdf") {
				t.Errorf("long name not truncated properly: len=%d", len(got))
			}
			continue
		}
		if got != want {
			t.Errorf("SanitizeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLenientBase64(t *testing.T) {
	got := decodeBase64Lenient([]byte("aGVs\r\nbG8g*d29y\nbGQ"))
	if string(got) != "hello world" {
		t.Fatalf("got %q", got)
	}
}

func TestDeepNestingRejected(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 40; i++ {
		b.WriteString("Content-Type: multipart/mixed; boundary=\"b" + string(rune('a'+i%26)) + strings.Repeat("x", i) + "\"\r\n\r\n--b" + string(rune('a'+i%26)) + strings.Repeat("x", i) + "\r\n")
	}
	b.WriteString("Content-Type: text/plain\r\n\r\nx\r\n")
	if _, err := Parse([]byte(b.String())); err == nil {
		t.Fatal("expected error for deep nesting")
	}
}

func TestParseRejectsTooManyParts(t *testing.T) {
	var b strings.Builder
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n")
	for i := 0; i < maxParts+5; i++ {
		b.WriteString("--x\r\nContent-Type: text/plain\r\n\r\na\r\n")
	}
	b.WriteString("--x--\r\n")
	if _, err := Parse([]byte(b.String())); !errors.Is(err, ErrTooManyParts) {
		t.Fatalf("want ErrTooManyParts, got %v", err)
	}
}

func TestParseAllowsNormalPartCount(t *testing.T) {
	var b strings.Builder
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n")
	for i := 0; i < 20; i++ {
		b.WriteString("--x\r\nContent-Type: text/plain\r\n\r\na\r\n")
	}
	b.WriteString("--x--\r\n")
	if _, err := Parse([]byte(b.String())); err != nil {
		t.Fatalf("normal multipart rejected: %v", err)
	}
}
