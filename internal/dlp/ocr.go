package dlp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/yiyuhki/p2/internal/metrics"
	"image"
	"image/color"
	_ "image/gif" // register decoders
	_ "image/jpeg"
	"image/png"
	"os/exec"
	"regexp"
	"strings"
	"time"

	_ "golang.org/x/image/bmp"
	"golang.org/x/image/draw"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"
)

// OCR turns an image into text.
type OCR interface {
	Recognize(ctx context.Context, img []byte) (string, error)
}

// OCROptions bound OCR work per message.
type OCROptions struct {
	Engine OCR
	// MaxImages is the number of distinct images OCR'd per message.
	MaxImages int
	// MinPixels skips icons, logos and spacer images (width*height).
	MinPixels int
	// MaxPixels rejects absurd images (decompression bombs).
	MaxPixels int
	// Timeout per image and TotalTimeout per message.
	Timeout      time.Duration
	TotalTimeout time.Duration
	// Concurrency is the number of images OCR'd in parallel per message.
	Concurrency int
}

func (o *OCROptions) defaults() {
	if o.MaxImages == 0 {
		o.MaxImages = 20
	}
	if o.MinPixels == 0 {
		o.MinPixels = 150 * 60
	}
	if o.MaxPixels == 0 {
		o.MaxPixels = 60_000_000
	}
	if o.Timeout == 0 {
		o.Timeout = 20 * time.Second
	}
	if o.TotalTimeout == 0 {
		o.TotalTimeout = 60 * time.Second
	}
	if o.Concurrency == 0 {
		o.Concurrency = 2
	}
}

// ImageKind tells the OCR stage how to turn Data into pixels.
type ImageKind int

const (
	KindRaster ImageKind = iota // PNG/JPEG/GIF/BMP/TIFF/WebP, decoded in Go
	KindHEIF                    // HEIC/AVIF: converted with libheif
	KindPDF                     // whole PDF: rendered page by page with poppler
)

// Image is an embedded picture found while extracting a message.
type Image struct {
	Location string
	Data     []byte
	Kind     ImageKind
	// Reason is reported as uninspectable when a non-raster image cannot be
	// converted (converter missing or conversion failed).
	Reason string
	// NeedText (KindPDF): also extract the text layer with pdftotext because
	// the built-in parser could not read it.
	NeedText bool
}

// isImage recognises the formats we can decode by magic number.
func isImage(b []byte) bool {
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")),
		bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}),
		bytes.HasPrefix(b, []byte("GIF8")),
		bytes.HasPrefix(b, []byte("BM")) && len(b) > 26,
		bytes.HasPrefix(b, []byte("II*\x00")), bytes.HasPrefix(b, []byte("MM\x00*")),
		len(b) > 12 && bytes.HasPrefix(b, []byte("RIFF")) && string(b[8:12]) == "WEBP":
		return true
	}
	return false
}

var errTooLarge = errors.New("image too large")

// imageSize reads only the header.
func imageSize(b []byte) (int, int, error) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(b))
	return cfg.Width, cfg.Height, err
}

// prepare decodes any supported format and returns a grayscale PNG sized
// for OCR: very small images are upscaled, very large ones downscaled.
func prepare(b []byte, maxPixels int) ([]byte, error) {
	w, h, err := imageSize(b)
	if err != nil {
		return nil, err
	}
	if w*h > maxPixels {
		return nil, errTooLarge
	}
	src, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	long := max(w, h)
	scale := 1.0
	switch {
	case long < 800:
		scale = 2
	case long > 4000:
		scale = 4000 / float64(long)
	}
	dw, dh := int(float64(w)*scale), int(float64(h)*scale)
	dst := image.NewGray(image.Rect(0, 0, dw, dh))
	// Flatten transparency onto white (screenshots, logos).
	draw.Draw(dst, dst.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, src.Bounds(), draw.Over, nil)
	// Contrast-stretch and deskew for photos/scans.
	dst = preprocessGray(dst)
	var out bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestSpeed}).Encode(&out, dst); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Tesseract runs the tesseract CLI (https://github.com/tesseract-ocr).
type Tesseract struct {
	Command   string // default "tesseract"
	Languages string // default "kor+eng"
	PSM       int    // page segmentation mode, default 4 (single column)
	MaxPixels int

	sem chan struct{} // process-wide limit on concurrent tesseract runs
}

// NewTesseract returns an engine that runs at most maxProcs tesseract
// processes at a time across all messages.
func NewTesseract(command, languages string, psm, maxProcs int) *Tesseract {
	if maxProcs <= 0 {
		maxProcs = 4
	}
	return &Tesseract{Command: command, Languages: languages, PSM: psm, sem: make(chan struct{}, maxProcs)}
}

func (t *Tesseract) Recognize(ctx context.Context, img []byte) (string, error) {
	maxPx := t.MaxPixels
	if maxPx == 0 {
		maxPx = 60_000_000
	}
	if t.sem != nil {
		select {
		case t.sem <- struct{}{}:
			defer func() { <-t.sem }()
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	pngData, err := prepare(img, maxPx)
	if err != nil {
		return "", err
	}
	cmdName, lang, psm := t.Command, t.Languages, t.PSM
	if cmdName == "" {
		cmdName = "tesseract"
	}
	if lang == "" {
		lang = "kor+eng"
	}
	if psm == 0 {
		psm = 4
	}
	// One thread per process (OMP_THREAD_LIMIT set by sandboxCmd): we
	// parallelise across images instead.
	defer metrics.Time("ocr")()
	cmd := sandboxCmd(ctx, DefaultProcLimits, nil, cmdName, "stdin", "stdout", "-l", lang, "--psm", fmt.Sprint(psm))
	cmd.Stdin = bytes.NewReader(pngData)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("tesseract: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// CheckTesseract verifies the binary and language data are installed.
func CheckTesseract(command, languages string) error {
	if command == "" {
		command = "tesseract"
	}
	out, err := exec.Command(command, "--list-langs").CombinedOutput()
	if err != nil {
		return fmt.Errorf("tesseract not usable (%s): %v", command, err)
	}
	have := map[string]bool{}
	for _, l := range strings.Fields(string(out)) {
		have[l] = true
	}
	for _, l := range strings.Split(languages, "+") {
		if !have[l] {
			return fmt.Errorf("tesseract language data %q not installed (e.g. apt install tesseract-ocr-%s)", l, l)
		}
	}
	return nil
}

var (
	reDigitDash = regexp.MustCompile(`(\d)[ \t]*[-–—][ \t]*(\d)`)
	// A number-like run: digits and look-alike letters, possibly separated
	// by spaces or dashes (e.g. "O1O-1234-5678", "900101 - l234567").
	reNumberRun = regexp.MustCompile(`[0-9OoIl|][0-9OoIl| \t\-–—]{4,}[0-9OoIl|]`)
)

// NormalizeOCR repairs typical OCR confusions inside number-like runs so
// that the regular detectors can match: "900101 - l234567" -> "900101-1234567".
func NormalizeOCR(s string) string {
	s = reNumberRun.ReplaceAllStringFunc(s, func(run string) string {
		alnum, digits := 0, 0
		for _, c := range run {
			switch {
			case c >= '0' && c <= '9':
				digits++
				alnum++
			case c == 'O' || c == 'o' || c == 'I' || c == 'l' || c == '|':
				alnum++
			}
		}
		if digits < 4 || digits*10 < alnum*7 { // mostly letters: a word
			return run
		}
		return strings.NewReplacer("O", "0", "o", "0", "I", "1", "l", "1", "|", "1").Replace(run)
	})
	s = reDigitDash.ReplaceAllString(s, "$1-$2")
	return joinSpacedHangul(s)
}

func isHangul(r rune) bool { return r >= 0xAC00 && r <= 0xD7A3 }

// joinSpacedHangul undoes OCR output like "주 민 등 록 번 호" (three or more
// single syllables separated by single spaces) so that keyword context
// checks ("여권", "카드") work. Normal text such as "그 사람" is untouched.
func joinSpacedHangul(s string) string {
	lines := strings.Split(s, "\n")
	for li, line := range lines {
		toks := strings.Split(line, " ")
		var out []string
		for i := 0; i < len(toks); {
			j := i
			for j < len(toks) {
				r := []rune(toks[j])
				if len(r) != 1 || !isHangul(r[0]) {
					break
				}
				j++
			}
			if j-i >= 3 {
				out = append(out, strings.Join(toks[i:j], ""))
				i = j
				continue
			}
			out = append(out, toks[i])
			i++
		}
		lines[li] = strings.Join(out, " ")
	}
	return strings.Join(lines, "\n")
}

func imageKey(b []byte) [32]byte { return sha256.Sum256(b) }
