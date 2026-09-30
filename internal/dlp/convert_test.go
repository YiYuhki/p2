package dlp

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func attachMsg(name, ctype string, data []byte) []byte {
	return []byte("From: a@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n" +
		"--B\r\nContent-Type: " + ctype + "; name=" + name + "\r\nContent-Disposition: attachment; filename=" + name +
		"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(data) + "\r\n--B--\r\n")
}

func rrnLocations(rep *Report) []string {
	var out []string
	for _, f := range rep.Findings {
		if f.Detector == "kr_rrn" {
			out = append(out, f.Location)
		}
	}
	return out
}

func needTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not installed", name)
	}
}

// ---- decoded in Go: only tesseract needed ----

func TestScannedPDFDecodedInGo(t *testing.T) {
	eng := tesseractOrSkip(t)
	s, _ := NewScanner(Options{ScanAttachments: true, OCR: OCROptions{Engine: eng}}) // no converter
	for _, f := range []string{"rrn-ccitt.pdf", "rrn-bilevel.pdf"} {
		rep := s.ScanMessage(context.Background(), attachMsg(f, "application/pdf", fixture(t, f)))
		locs := rrnLocations(rep)
		if len(locs) == 0 || locs[0] != "첨부 "+f+" > 이미지 1 (OCR)" {
			t.Errorf("%s: rrn locations %v (uninspectable %v)", f, locs, rep.Uninspectable)
		}
	}
}

// ---- external converters ----

func TestHEICAndAVIFConverted(t *testing.T) {
	eng := tesseractOrSkip(t)
	conv := DetectConverter("", "", "", 0, 0, 2)
	if conv.HEIFCmd == "" {
		t.Skip("libheif tools not installed")
	}
	s, _ := NewScanner(Options{ScanAttachments: true, OCR: OCROptions{Engine: eng}, Converter: conv})
	for _, f := range []string{"rrn.heic", "rrn.avif"} {
		rep := s.ScanMessage(context.Background(), attachMsg(f, "image/heic", fixture(t, f)))
		locs := rrnLocations(rep)
		if len(locs) == 0 || locs[0] != "첨부 "+f+" (OCR)" {
			t.Errorf("%s: rrn locations %v (uninspectable %v)", f, locs, rep.Uninspectable)
		}
	}
}

func TestJPEG2000PDFRendered(t *testing.T) {
	eng := tesseractOrSkip(t)
	needTool(t, "pdftoppm")
	data := fixture(t, "rrn-jpx.pdf")

	// Without poppler: reported, not silently passed.
	s0, _ := NewScanner(Options{ScanAttachments: true, OCR: OCROptions{Engine: eng}})
	rep := s0.ScanMessage(context.Background(), attachMsg("a.pdf", "application/pdf", data))
	if len(rep.Uninspectable) == 0 || !strings.Contains(strings.Join(rep.Uninspectable, " "), "JPEG2000") {
		t.Fatalf("without converter: %v", rep.Uninspectable)
	}

	s, _ := NewScanner(Options{ScanAttachments: true, OCR: OCROptions{Engine: eng},
		Converter: DetectConverter("", "", "", 0, 0, 2)})
	rep = s.ScanMessage(context.Background(), attachMsg("a.pdf", "application/pdf", data))
	locs := rrnLocations(rep)
	if len(locs) != 1 || locs[0] != "첨부 a.pdf > 페이지 1 (OCR)" {
		t.Fatalf("rendered: %v (uninspectable %v)", locs, rep.Uninspectable)
	}
	if len(rep.Uninspectable) != 0 {
		t.Errorf("nothing should remain uninspectable: %v", rep.Uninspectable)
	}
}

func TestPasswordPDFs(t *testing.T) {
	needTool(t, "pdftoppm")
	s, _ := NewScanner(Options{ScanAttachments: true, Converter: DetectConverter("", "", "", 0, 0, 2)})

	// Owner password only: readable, text layer must be scanned.
	rep := s.ScanMessage(context.Background(), attachMsg("o.pdf", "application/pdf", fixture(t, "rrn-owner-pw.pdf")))
	if locs := rrnLocations(rep); len(locs) == 0 {
		t.Errorf("owner-password PDF not scanned: %v", rep.Uninspectable)
	}
	// User password: cannot be opened, must be reported as encrypted.
	rep = s.ScanMessage(context.Background(), attachMsg("u.pdf", "application/pdf", fixture(t, "rrn-user-pw.pdf")))
	if len(rrnLocations(rep)) != 0 || len(rep.Encrypted) != 1 || !strings.Contains(rep.Encrypted[0], "암호") {
		t.Errorf("user-password PDF: findings=%v encrypted=%v", rrnLocations(rep), rep.Encrypted)
	}
}

// TestJBIG2Samples renders real JBIG2 PDFs when SECMAIL_TEST_PDF_DIR points
// to pikepdf's tests/resources (jbig2global.pdf: a Dutch recipe scan).
func TestJBIG2Samples(t *testing.T) {
	dir := os.Getenv("SECMAIL_TEST_PDF_DIR")
	if dir == "" {
		t.Skip("SECMAIL_TEST_PDF_DIR not set")
	}
	eng := tesseractOrSkip(t)
	needTool(t, "pdftoppm")
	data, err := os.ReadFile(filepath.Join(dir, "jbig2global.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	e := Extract("x.pdf", "x.pdf", data, DefaultLimits())
	render := 0
	for _, im := range e.Images {
		if im.Kind == KindPDF {
			render++
		}
	}
	if render != 1 {
		t.Fatalf("JBIG2 PDF should be queued for rendering: %+v", e.Images)
	}
	pages, _, err := DetectConverter("", "", "", 0, 0, 1).PDF(context.Background(), data, false)
	if err != nil || len(pages) == 0 {
		t.Fatalf("render: %v", err)
	}
	text, err := eng.Recognize(context.Background(), pages[0])
	if err != nil || !strings.Contains(strings.ToLower(text), "linzen") {
		t.Fatalf("OCR of rendered JBIG2 page: %v %q", err, text)
	}
}
