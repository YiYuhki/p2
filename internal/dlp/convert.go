package dlp

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Converter turns formats Go cannot decode into PNG using external tools:
//
//	HEIC/AVIF  -> libheif  (heif-dec, or heif-convert on older versions)
//	PDF pages  -> poppler  (pdftoppm; renders JBIG2, JPEG2000, CCITT G3-2D,
//	              owner-password-only PDFs, ... anything poppler can open)
//	PDF text   -> poppler  (pdftotext; text layer of PDFs the Go parser rejects)
//
// A zero field disables that conversion; affected files are then reported
// as uninspectable.
type Converter struct {
	HEIFCmd      string
	PDFToPPMCmd  string
	PDFToTextCmd string
	ScaleTo      int // long side of rendered pages in pixels, default 2400 (~A4 at 200 dpi)
	MaxPages     int // pages rendered per PDF, default 10

	sem chan struct{} // process-wide limit on converter processes
}

// DetectConverter finds the tools on PATH. Explicit command names take
// precedence; "none" disables a tool.
func DetectConverter(heif, pdftoppm, pdftotext string, scaleTo, maxPages, maxProcs int) *Converter {
	find := func(explicit string, candidates ...string) string {
		if explicit == "none" {
			return ""
		}
		if explicit != "" {
			candidates = []string{explicit}
		}
		for _, c := range candidates {
			if p, err := exec.LookPath(c); err == nil {
				return p
			}
		}
		return ""
	}
	if maxProcs <= 0 {
		maxProcs = 4
	}
	return &Converter{
		HEIFCmd:      find(heif, "heif-dec", "heif-convert"),
		PDFToPPMCmd:  find(pdftoppm, "pdftoppm"),
		PDFToTextCmd: find(pdftotext, "pdftotext"),
		ScaleTo:      scaleTo,
		MaxPages:     maxPages,
		sem:          make(chan struct{}, maxProcs),
	}
}

func (c *Converter) acquire(ctx context.Context) (func(), error) {
	if c.sem == nil {
		return func() {}, nil
	}
	select {
	case c.sem <- struct{}{}:
		return func() { <-c.sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := sandboxCmd(ctx, DefaultProcLimits, nil, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%s: %v: %s", filepath.Base(name), err, firstLine(errb.String()))
	}
	return out.Bytes(), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// workDir writes data into a fresh private temp directory.
func workDir(name string, data []byte) (dir, path string, err error) {
	dir, err = os.MkdirTemp("", "secmail-conv-*")
	if err != nil {
		return "", "", err
	}
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		os.RemoveAll(dir)
		return "", "", err
	}
	return dir, path, nil
}

// pngsIn returns the PNG files written into dir, in page order.
func pngsIn(dir, prefix string) ([][]byte, error) {
	files, _ := filepath.Glob(filepath.Join(dir, prefix+"*.png"))
	num := func(p string) int {
		base := strings.TrimSuffix(filepath.Base(p), ".png")
		i := strings.LastIndexAny(base, "-_")
		n, _ := strconv.Atoi(base[i+1:])
		return n
	}
	sort.Slice(files, func(i, j int) bool { return num(files[i]) < num(files[j]) })
	var out [][]byte
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// HEIF converts HEIC/AVIF to PNG (the primary image; a HEIF file may hold
// several, e.g. thumbnails or bursts).
func (c *Converter) HEIF(ctx context.Context, data []byte) ([][]byte, error) {
	if c == nil || c.HEIFCmd == "" {
		return nil, errNoConverter
	}
	release, err := c.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	dir, in, err := workDir("in.heic", data)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if _, err := run(ctx, c.HEIFCmd, in, filepath.Join(dir, "out.png")); err != nil {
		return nil, err
	}
	imgs, err := pngsIn(dir, "out")
	if err == nil && len(imgs) == 0 {
		err = fmt.Errorf("heif: no image produced")
	}
	return imgs, err
}

// PDF renders up to MaxPages pages (grayscale PNG) and, when withText is
// set, extracts the text layer too.
func (c *Converter) PDF(ctx context.Context, data []byte, withText bool) (pages [][]byte, text string, err error) {
	if c == nil || c.PDFToPPMCmd == "" {
		return nil, "", errNoConverter
	}
	release, err := c.acquire(ctx)
	if err != nil {
		return nil, "", err
	}
	defer release()
	dir, in, err := workDir("in.pdf", data)
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(dir)
	scale, maxPages := c.ScaleTo, c.maxPages()
	if scale <= 0 {
		scale = 2400
	}
	if withText && c.PDFToTextCmd != "" {
		if out, terr := run(ctx, c.PDFToTextCmd, "-l", strconv.Itoa(maxPages), "-enc", "UTF-8", in, "-"); terr == nil {
			text = string(out)
		}
	}
	if _, err := run(ctx, c.PDFToPPMCmd, "-scale-to", strconv.Itoa(scale), "-gray", "-png",
		"-f", "1", "-l", strconv.Itoa(maxPages), in, filepath.Join(dir, "p")); err != nil {
		return nil, text, err
	}
	pages, err = pngsIn(dir, "p")
	return pages, text, err
}

func (c *Converter) maxPages() int {
	if c.MaxPages <= 0 {
		return 10
	}
	return c.MaxPages
}

var errNoConverter = fmt.Errorf("converter not installed")
