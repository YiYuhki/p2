package dlp

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func hasRRN(rep *Report) bool {
	for _, f := range rep.Findings {
		if f.Detector == "kr_rrn" {
			return true
		}
	}
	return false
}

func need7z(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("7z"); err != nil {
		if _, err := exec.LookPath("7za"); err != nil {
			t.Skip("7z not installed")
		}
	}
}

func TestGzipAndTarExtracted(t *testing.T) {
	s, _ := NewScanner(Options{ScanAttachments: true})
	for _, f := range []string{"rrn.txt.gz", "rrn.tar.gz"} {
		rep := s.ScanMessage(context.Background(), attachMsg(f, "application/gzip", fixture(t, f)))
		if !hasRRN(rep) {
			t.Errorf("%s: resident number inside archive not found (uninspectable=%v)", f, rep.Uninspectable)
		}
	}
}

func TestSevenZipExtracted(t *testing.T) {
	need7z(t)
	SetArchiveTools("", 2)
	s, _ := NewScanner(Options{ScanAttachments: true})
	rep := s.ScanMessage(context.Background(), attachMsg("a.7z", "application/x-7z-compressed", fixture(t, "rrn.7z")))
	if !hasRRN(rep) {
		t.Fatalf("7z contents not scanned: findings=%v uninspectable=%v", rep.Findings, rep.Uninspectable)
	}
}

func TestEncryptedArchivesReported(t *testing.T) {
	need7z(t)
	SetArchiveTools("", 2)
	s, _ := NewScanner(Options{ScanAttachments: true})
	for _, f := range []string{"rrn-enc.7z", "rrn-enc.zip"} {
		rep := s.ScanMessage(context.Background(), attachMsg(f, "application/octet-stream", fixture(t, f)))
		if !rep.HasEncrypted() {
			t.Errorf("%s: encrypted archive not reported (uninspectable=%v)", f, rep.Uninspectable)
		}
		if hasRRN(rep) {
			t.Errorf("%s: content should not be readable", f)
		}
		for _, e := range rep.Encrypted {
			if !strings.Contains(e, "암호") {
				t.Errorf("%s: unexpected encrypted note %q", f, e)
			}
		}
	}
}

func TestSevenZipDisabled(t *testing.T) {
	SetArchiveTools("none", 1)
	defer SetArchiveTools("", 4)
	s, _ := NewScanner(Options{ScanAttachments: true})
	rep := s.ScanMessage(context.Background(), attachMsg("a.7z", "application/x-7z-compressed", fixture(t, "rrn.7z")))
	if hasRRN(rep) {
		t.Fatal("no 7z tool: must not read contents")
	}
	if len(rep.Uninspectable) == 0 || !strings.Contains(strings.Join(rep.Uninspectable, " "), "7-Zip") {
		t.Fatalf("disabled 7z should be reported as uninspectable, not silently passed: %v", rep.Uninspectable)
	}
}
