package dlp

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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

func TestParseSevenZipListing(t *testing.T) {
	out := "7-Zip 23.01\r\n\r\nListing archive: a.7z\r\n\r\n--\r\nPath = a.7z\r\nType = 7z\r\nPhysical Size = 300\r\nHeaders Size = 200\r\n\r\n----------\r\n" +
		"Path = dir\r\nSize = 0\r\nFolder = +\r\nAttributes = D_ drwxr-xr-x\r\n\r\n" +
		"Path = dir/a.txt\r\nSize = 1000\r\nPacked Size = 10\r\nFolder = -\r\nAttributes = A_ -rw-r--r--\r\nEncrypted = -\r\n\r\n" +
		"Path = dir/b.bin\r\nSize = 9223372036854775807\r\nFolder = -\r\nEncrypted = -\r\n\r\n" +
		"Path = stream\r\nSize = \r\n\r\n"
	ls := parseSevenZipListing(out)
	if ls.encrypted || ls.files != 3 || ls.totalSize < 1<<62 {
		t.Fatalf("listing = %+v", ls)
	}
	enc := parseSevenZipListing("----------\nPath = x\nSize = 5\nEncrypted = +\n")
	if !enc.encrypted || enc.files != 1 || enc.totalSize != 5 {
		t.Fatalf("encrypted listing = %+v", enc)
	}
}

// TestSevenZipBombRejectedBeforeExtract uses a fake 7z whose listing declares
// a huge entry: the archive must be rejected without running "x".
func TestSevenZipBombRejectedBeforeExtract(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "extracted")
	script := "#!/bin/sh\nif [ \"$1\" = l ]; then printf -- '----------\\nPath = big\\nSize = 99999999999\\nFolder = -\\n'; exit 0; fi\ntouch " + marker + "\n"
	fake := filepath.Join(dir, "7z")
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	SetArchiveTools(fake, 1)
	defer SetArchiveTools("", 4)
	s, _ := NewScanner(Options{ScanAttachments: true})
	rep := s.ScanMessage(context.Background(), attachMsg("a.7z", "application/x-7z-compressed", fixture(t, "rrn.7z")))
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("archive was extracted despite exceeding the inflate budget")
	}
	if !strings.Contains(strings.Join(rep.Uninspectable, " "), "한도") {
		t.Fatalf("bomb not reported: %v", rep.Uninspectable)
	}
}
