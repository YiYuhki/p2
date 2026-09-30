package dlp

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/ascii85"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
)

const nanum = "/usr/share/fonts/truetype/nanum/NanumGothic.ttf"

// renderText draws lines of text as a document-like image. It uses a
// Korean TrueType font when available, otherwise the built-in ASCII font.
func renderText(t *testing.T, lines ...string) image.Image {
	t.Helper()
	var face font.Face = basicfont.Face7x13
	lineH := 20
	if b, err := os.ReadFile(nanum); err == nil {
		f, err := opentype.Parse(b)
		if err == nil {
			face, _ = opentype.NewFace(f, &opentype.FaceOptions{Size: 28, DPI: 72})
			lineH = 45
		}
	}
	img := image.NewRGBA(image.Rect(0, 0, 900, 60+lineH*len(lines)))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	d := &font.Drawer{Dst: img, Src: image.NewUniform(color.Black), Face: face}
	for i, l := range lines {
		d.Dot = fixed.P(30, 50+lineH*i)
		d.DrawString(l)
	}
	return img
}

func encPNG(img image.Image) []byte {
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

func encJPEG(img image.Image) []byte {
	var b bytes.Buffer
	jpeg.Encode(&b, img, &jpeg.Options{Quality: 85})
	return b.Bytes()
}

// ---- fake engine: returns fixed text, counts calls ----

type fakeOCR struct {
	text  string
	delay time.Duration
	calls atomic.Int32
}

func (f *fakeOCR) Recognize(ctx context.Context, _ []byte) (string, error) {
	f.calls.Add(1)
	select {
	case <-time.After(f.delay):
		return f.text, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func mimeWithImages(imgs map[string][]byte, inline []byte) []byte {
	var b strings.Builder
	b.WriteString("From: a@example.com\r\nTo: x@ext.org\r\nSubject: s\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n")
	for name, data := range imgs {
		fmt.Fprintf(&b, "--B\r\nContent-Type: image/png; name=%q\r\nContent-Disposition: attachment; filename=%q\r\n"+
			"Content-Transfer-Encoding: base64\r\n\r\n%s\r\n", name, name, base64.StdEncoding.EncodeToString(data))
	}
	if inline != nil {
		fmt.Fprintf(&b, "--B\r\nContent-Type: image/jpeg\r\nContent-ID: <img1>\r\nContent-Disposition: inline\r\n"+
			"Content-Transfer-Encoding: base64\r\n\r\n%s\r\n", base64.StdEncoding.EncodeToString(inline))
	}
	b.WriteString("--B--\r\n")
	return []byte(b.String())
}

func blank(w, h int, shade uint8) []byte {
	img := image.NewGray(image.Rect(0, 0, w, h))
	for i := range img.Pix {
		img.Pix[i] = shade
	}
	return encPNG(img)
}

func TestOCRPipelineWithFakeEngine(t *testing.T) {
	eng := &fakeOCR{text: "주민번호 900101 - l234567"}
	s, _ := NewScanner(Options{ScanAttachments: true, OCR: OCROptions{Engine: eng}})
	same := blank(400, 200, 250)
	msg := mimeWithImages(map[string][]byte{
		"a.png":    same,
		"copy.png": same,              // duplicate: OCR'd once
		"icon.png": blank(16, 16, 10), // too small: skipped
	}, encJPEG(image.NewGray(image.Rect(0, 0, 300, 100))))
	rep := s.ScanMessage(context.Background(), msg)
	if n := eng.calls.Load(); n != 2 {
		t.Fatalf("want 2 OCR calls (dedupe + skip icon), got %d", n)
	}
	locs := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Detector == "kr_rrn" {
			locs[f.Location] = true
		}
	}
	if !locs["본문 삽입 이미지 (OCR)"] {
		t.Errorf("inline image finding missing: %v", locs)
	}
	if !locs["첨부 a.png (OCR)"] && !locs["첨부 copy.png (OCR)"] {
		t.Errorf("attachment image finding missing (OCR noise must be normalised): %v", locs)
	}
}

func TestOCRLimitsAndTimeouts(t *testing.T) {
	eng := &fakeOCR{text: "x", delay: 200 * time.Millisecond}
	s, _ := NewScanner(Options{ScanAttachments: true, OCR: OCROptions{Engine: eng, MaxImages: 1,
		Timeout: 50 * time.Millisecond}})
	rep := s.ScanMessage(context.Background(), mimeWithImages(map[string][]byte{
		"1.png": blank(400, 200, 200), "2.png": blank(400, 200, 100)}, nil))
	joined := strings.Join(rep.Uninspectable, "\n")
	if !strings.Contains(joined, "2개 중 1개만") || !strings.Contains(joined, "시간 한도 초과") {
		t.Fatalf("limits not reported: %v", rep.Uninspectable)
	}
	// Without an engine, images are ignored entirely.
	s2, _ := NewScanner(Options{ScanAttachments: true})
	if r := s2.ScanMessage(context.Background(), mimeWithImages(map[string][]byte{"1.png": blank(400, 200, 1)}, nil)); len(r.Uninspectable) != 0 {
		t.Fatalf("OCR disabled should not report images: %v", r.Uninspectable)
	}
}

func TestHEICReported(t *testing.T) {
	heic := append([]byte{0, 0, 0, 24}, []byte("ftypheic\x00\x00\x00\x00mif1heic")...)
	e := Extract("첨부 IMG_0001.HEIC", "IMG_0001.HEIC", heic, DefaultLimits())
	if len(e.Problems) != 1 || !strings.Contains(e.Problems[0], "HEIC") {
		t.Fatalf("heic: %+v", e.Problems)
	}
}

func TestNormalizeOCR(t *testing.T) {
	cases := map[string]string{
		"900101 - l234567":     "900101-1234567",
		"4111 –  1111":         "4111-1111",
		"O1O-1234-5678":        "010-1234-5678",
		"Hello Illinois":       "Hello Illinois", // words untouched
		"AKIAIOSFODNN7EXAMPLE": "AKIAIOSFODNN7EXAMPLE",
	}
	for in, want := range cases {
		if got := NormalizeOCR(in); got != want {
			t.Errorf("NormalizeOCR(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- embedded image extraction (no OCR engine needed) ----

func TestImagesFromDocxHwpxAndPDF(t *testing.T) {
	pic := blank(300, 120, 200)
	docx := zipOf(t, map[string]string{"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>",
		"word/media/image1.png": string(pic)})
	e := Extract("첨부 a.docx", "a.docx", docx, DefaultLimits())
	if len(e.Images) != 1 || e.Images[0].Location != "첨부 a.docx > word/media/image1.png" {
		t.Fatalf("docx media: %+v", e.Images)
	}
	hwpx := zipOf(t, map[string]string{"mimetype": "application/hwp+zip", "Contents/section0.xml": "<p/>",
		"BinData/image1.jpg": string(encJPEG(image.NewGray(image.Rect(0, 0, 50, 50))))})
	if e := Extract("첨부 b.hwpx", "b.hwpx", hwpx, DefaultLimits()); len(e.Images) != 1 {
		t.Fatalf("hwpx bindata: %+v", e.Images)
	}

	jpg := encJPEG(image.NewGray(image.Rect(0, 0, 64, 32)))
	pdf := scannedPDF(t, jpg, flateRGBWithPredictor(t, 8, 4))
	e = Extract("첨부 scan.pdf", "scan.pdf", pdf, DefaultLimits())
	if len(e.Images) != 2 {
		t.Fatalf("pdf images: %d %+v", len(e.Images), e.Problems)
	}
	if !bytes.Equal(e.Images[0].Data, jpg) {
		t.Error("DCT image must be passed through unchanged")
	}
	if w, h, err := imageSize(e.Images[1].Data); err != nil || w != 8 || h != 4 {
		t.Errorf("flate image decode: %d x %d %v", w, h, err)
	}
}

// flateRGBWithPredictor builds PNG-predicted (Up filter) RGB rows.
func flateRGBWithPredictor(t *testing.T, w, h int) []byte {
	var raw bytes.Buffer
	for r := 0; r < h; r++ {
		raw.WriteByte(2) // Up
		for i := 0; i < w*3; i++ {
			if r == 0 {
				raw.WriteByte(byte(i))
			} else {
				raw.WriteByte(0)
			}
		}
	}
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write(raw.Bytes())
	zw.Close()
	return z.Bytes()
}

func scannedPDF(t *testing.T, jpg, flate []byte) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	fmt.Fprintf(&b, "1 0 obj\n<< /Type /XObject /Subtype /Image /Width 64 /Height 32 /ColorSpace /DeviceGray "+
		"/BitsPerComponent 8 /Filter /DCTDecode /Length %d >>\nstream\n", len(jpg))
	b.Write(jpg)
	b.WriteString("\nendstream\nendobj\n")
	fmt.Fprintf(&b, "2 0 obj\n<< /Type /XObject /Subtype /Image /Width 8 /Height 4 /ColorSpace /DeviceRGB "+
		"/BitsPerComponent 8 /Filter /FlateDecode /DecodeParms << /Predictor 15 /Colors 3 /Columns 8 >> /Length %d >>\nstream\n", len(flate))
	b.Write(flate)
	b.WriteString("\nendstream\nendobj\n")
	b.WriteString("3 0 obj\n<< /Subtype /Image /Width 10 /Height 10 /Filter /JBIG2Decode /Length 3 >>\nstream\nabc\nendstream\nendobj\n%%EOF\n")
	return b.Bytes()
}

// ---- real tesseract ----

func tesseractOrSkip(t *testing.T) *Tesseract {
	t.Helper()
	if _, err := exec.LookPath("tesseract"); err != nil {
		t.Skip("tesseract not installed")
	}
	if err := CheckTesseract("tesseract", "kor+eng"); err != nil {
		t.Skip(err)
	}
	return NewTesseract("tesseract", "kor+eng", 4, 2)
}

func TestTesseractEndToEnd(t *testing.T) {
	eng := tesseractOrSkip(t)
	lines := []string{"고객 정보 확인서", "성명: 홍길동   주민등록번호: 900101-1234567",
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "카드번호 4111-1111-1111-1111"}
	if _, err := os.Stat(nanum); err != nil {
		lines = []string{"RRN 900101-1234567", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "CARD 4111-1111-1111-1111"}
	}
	doc := renderText(t, lines...)
	s, _ := NewScanner(Options{ScanAttachments: true, OCR: OCROptions{Engine: eng}})

	check := func(name string, rep *Report, wantLoc string) {
		t.Helper()
		got := map[string]string{}
		for _, f := range rep.Findings {
			got[f.Detector] = f.Location
		}
		for _, d := range []string{"kr_rrn", "aws_access_key", "credit_card"} {
			if got[d] != wantLoc {
				t.Errorf("%s: %s found at %q, want %q (uninspectable=%v)", name, d, got[d], wantLoc, rep.Uninspectable)
			}
		}
	}

	// 1. PNG screenshot attachment.
	rep := s.ScanMessage(context.Background(), mimeWithImages(map[string][]byte{"shot.png": encPNG(doc)}, nil))
	check("png", rep, "첨부 shot.png (OCR)")

	// 2. Picture pasted into a Word document.
	docx := zipOf(t, map[string]string{"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>",
		"word/media/image1.jpeg": string(encJPEG(doc))})
	msg := "From: a@example.com\r\nSubject: s\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n" +
		"Content-Type: application/octet-stream; name=a.docx\r\nContent-Disposition: attachment; filename=a.docx\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(docx) + "\r\n--B--\r\n"
	rep = s.ScanMessage(context.Background(), []byte(msg))
	check("docx", rep, "첨부 a.docx > word/media/image1.jpeg (OCR)")

	// 3. Scanned PDF (JPEG page image, no text layer).
	pdf := scannedPDF(t, encJPEG(doc), flateRGBWithPredictor(t, 8, 4))
	e := Extract("첨부 scan.pdf", "scan.pdf", pdf, DefaultLimits())
	text, err := eng.Recognize(context.Background(), e.Images[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ids(s.ScanText("pdf", NormalizeOCR(text)))["kr_rrn"]; !ok {
		t.Errorf("scanned pdf OCR: %q", text)
	}
}

func TestPDFFilterChainASCII85Flate(t *testing.T) {
	// 6x2 gray image, zlib-compressed then ASCII85-encoded (reportlab style).
	pix := []byte{0, 50, 100, 150, 200, 250, 250, 200, 150, 100, 50, 0}
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write(pix)
	zw.Close()
	a85 := make([]byte, ascii85.MaxEncodedLen(z.Len()))
	n := ascii85.Encode(a85, z.Bytes())
	stream := append(a85[:n], []byte("~>")...)
	pdf := fmt.Sprintf("%%PDF-1.4\n1 0 obj\n<< /Type /XObject /Subtype /Image /Width 6 /Height 2 /ColorSpace /DeviceGray "+
		"/BitsPerComponent 8 /Filter [ /ASCII85Decode /FlateDecode ] /Length %d >>\nstream\n%s\nendstream\nendobj\n", len(stream), stream)
	e := Extract("x.pdf", "x.pdf", []byte(pdf), DefaultLimits())
	if len(e.Images) != 1 {
		t.Fatalf("images=%d problems=%v", len(e.Images), e.Problems)
	}
	img, err := png.Decode(bytes.NewReader(e.Images[0].Data))
	if err != nil {
		t.Fatal(err)
	}
	if g := img.(*image.Gray); g.Pix[1] != 50 || g.Pix[11] != 0 {
		t.Fatalf("pixels wrong: %v", g.Pix)
	}
}

func TestASCII85ZeroShorthand(t *testing.T) {
	got, err := decodeASCII85([]byte("zz!!!$~>")) // 8 zero bytes then 0x00 0x00 0x01
	if err != nil || len(got) != 11 || got[10] != 1 {
		t.Fatalf("got %v %v", got, err)
	}
}
