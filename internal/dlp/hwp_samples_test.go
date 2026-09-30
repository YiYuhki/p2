package dlp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHWPSamples extracts text from real HWP 5 files when
// SECMAIL_TEST_HWP_DIR points to a directory of samples (e.g. the pyhwp
// project's tests/hwp5_tests/fixtures). Files named "password*" must be
// reported as encrypted and viewtext.hwp as a distribution document.
func TestHWPSamples(t *testing.T) {
	dir := os.Getenv("SECMAIL_TEST_HWP_DIR")
	if dir == "" {
		t.Skip("SECMAIL_TEST_HWP_DIR not set")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.hwp"))
	if len(files) == 0 {
		t.Fatal("no .hwp files found")
	}
	withText, totalImages := 0, 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(f)
		ex := Extract(name, name, data, DefaultLimits())
		texts, probs := ex.Texts, ex.Problems
		totalImages += len(ex.Images)
		if strings.HasPrefix(name, "password") {
			if len(ex.Encrypted) == 0 || !strings.Contains(ex.Encrypted[0], "암호") {
				t.Errorf("%s: encrypted HWP not reported: %v", name, ex.Encrypted)
			}
			continue
		}
		if name == "viewtext.hwp" { // distribution (배포용) document
			if len(probs) == 0 || !strings.Contains(probs[0], "배포용") {
				t.Errorf("%s: distribution document not reported: %v", name, probs)
			}
			continue
		}
		for _, p := range probs {
			if strings.Contains(p, "오류") || strings.Contains(p, "손상") {
				t.Errorf("%s: %s", name, p)
			}
		}
		if len(texts) > 0 {
			withText++
			t.Logf("%-40s %q", name, truncate(texts[0].Content, 60))
		}
	}
	t.Logf("embedded pictures extracted: %d", totalImages)
	if totalImages == 0 {
		t.Error("no BinData pictures extracted from samples")
	}
	if withText == 0 {
		t.Fatal("no text extracted from any sample")
	}
}

func truncate(s string, n int) string {
	r := []rune(strings.Join(strings.Fields(s), " "))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}
