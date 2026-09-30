package dlp

import (
	"bytes"
	"context"
	"image"
	"image/png"
	"math"
	"os"
	"testing"
)

// barsImage draws horizontal black bars on white — a clean horizontal-text proxy.
func barsImage(w, h int) *image.Gray {
	g := image.NewGray(image.Rect(0, 0, w, h))
	for i := range g.Pix {
		g.Pix[i] = 255
	}
	for y := 20; y < h; y += 40 {
		for dy := 0; dy < 12; dy++ {
			for x := 20; x < w-20; x++ {
				g.Pix[(y+dy)*g.Stride+x] = 0
			}
		}
	}
	return g
}

func TestEstimateSkewRecoversAngle(t *testing.T) {
	base := barsImage(400, 400)
	for _, want := range []float64{-5, -2, 3, 6} {
		rotated := rotateGray(base, want) // content tilted by +want
		got := estimateSkew(rotated)      // correction should be about -want
		if math.Abs(got+want) > 1.0 {
			t.Errorf("skew for %.1f°: got %.1f° (want ~%.1f°)", want, got, -want)
		}
	}
}

func TestPreprocessIdempotentOnStraight(t *testing.T) {
	base := barsImage(300, 300)
	if a := estimateSkew(base); math.Abs(a) > 0.5 {
		t.Fatalf("straight image should have ~0 skew, got %.1f", a)
	}
}

// TestDeskewImprovesOCR renders text, tilts it, and checks the resident
// number is recovered after preprocessing (prepare deskews internally).
func TestDeskewImprovesOCR(t *testing.T) {
	eng := tesseractOrSkip(t)
	lines := []string{"주민등록번호 900101-1234567"}
	if !fileExists(nanum) {
		lines = []string{"RRN 900101-1234567"}
	}
	doc := renderText(t, lines...)
	// Tilt the rendered document by 6 degrees.
	gray := toGray(doc)
	tilted := rotateGray(gray, 6)
	var buf bytes.Buffer
	png.Encode(&buf, tilted)

	text, err := eng.Recognize(context.Background(), buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	s := newScanner(t)
	if _, ok := ids(s.ScanText("x", NormalizeOCR(text)))["kr_rrn"]; !ok {
		t.Errorf("tilted image: resident number not recovered after deskew: %q", text)
	}
}

func toGray(img image.Image) *image.Gray {
	b := img.Bounds()
	g := image.NewGray(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			g.Set(x, y, img.At(x, y))
		}
	}
	return g
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
