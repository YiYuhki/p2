package dlp

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	ls, err := parseSevenZipListing(out)
	if err != nil || ls.encrypted || ls.files != 3 || ls.entries != 4 || ls.totalSize < 1<<62 {
		t.Fatalf("listing = %+v, %v", ls, err)
	}
	enc, err := parseSevenZipListing("----------\nPath = x\nSize = 5\nEncrypted = +\n")
	if err != nil || !enc.encrypted || enc.files != 1 || enc.totalSize != 5 {
		t.Fatalf("encrypted listing = %+v, %v", enc, err)
	}
}

// Entry names are attacker-controlled and may contain newlines: a listing
// whose structure is ambiguous is refused instead of being trusted.
func TestParseSevenZipListingRejectsInjection(t *testing.T) {
	head := "Path = a.7z\nType = 7z\n\n----------\n"
	for name, body := range map[string]string{
		// "x\nAttributes = D" fakes a directory: duplicate key.
		"fake dir attribute": "Path = x\nAttributes = D_\nSize = 999999999\nAttributes = A_\n\n",
		// A fake size before the real one.
		"duplicate size": "Path = x\nSize = 0\nSize = 999999999\n\n",
		// A fake separator inside a name.
		"second separator": "Path = x\n----------\nPath = y\nSize = 1\n\n",
		// "x\n\nSize = ..." leaves fields outside any block.
		"orphan field": "Path = x\n\nSize = 999999999\n\n",
		// Name continuation lines that are not key/value pairs.
		"bare line in block": "Path = x\nmore name\nSize = 1\n\n",
		// Folder and Attributes disagree.
		"folder conflict": "Path = x\nSize = 9\nFolder = +\nAttributes = A_\n\n",
		"bad size":        "Path = x\nSize = -5\n\n",
		"bad folder":      "Path = x\nFolder = maybe\n\n",
		"two paths":       "Path = x\nPath = y\n\n",
	} {
		if ls, err := parseSevenZipListing(head + body); err == nil {
			t.Errorf("%s: accepted: %+v", name, ls)
		}
	}
	if _, err := parseSevenZipListing("Path = a.7z\nType = 7z\n"); err == nil {
		t.Error("listing without an entry section accepted")
	}
	// A faked directory still counts its declared size and as an entry.
	ls, err := parseSevenZipListing(head + "Path = x\nSize = 777\nFolder = +\n\n")
	if err != nil || ls.totalSize != 777 || ls.entries != 1 || ls.files != 0 {
		t.Fatalf("dir listing = %+v, %v", ls, err)
	}
	// Summary text after the last block is fine.
	if _, err := parseSevenZipListing(head + "Path = x\nSize = 1\n\nWarnings: 1\n"); err != nil {
		t.Fatalf("trailing summary rejected: %v", err)
	}
}

func TestArchiveNameSafe(t *testing.T) {
	for in, want := range map[string]string{
		"a.7z":                   "a.7z",
		"evil\n----------\nx.7z": "evil_----------_x.7z",
		"../../x.rar":            "x.rar",
		"":                       "archive",
		"-o.7z":                  "o.7z",
		"한글.7z":                  "__.7z",
	} {
		if got := archiveName(in); got != want {
			t.Errorf("archiveName(%q) = %q, want %q", in, got, want)
		}
	}
}

// fake7z installs a fake 7-Zip: `l` prints listing and exits with listExit;
// `x` runs extract (a shell snippet with $out set to the output directory)
// and touches a marker. Returns the marker path.
func fake7z(t *testing.T, listing string, listExit int, extract string) string {
	t.Helper()
	dir := t.TempDir()
	marker := filepath.Join(dir, "extracted")
	lst := filepath.Join(dir, "listing")
	if err := os.WriteFile(lst, []byte(listing), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nif [ \"$1\" = l ]; then cat " + lst + "; exit " + strconv.Itoa(listExit) + "; fi\n" +
		"for a in \"$@\"; do case \"$a\" in -o*) out=\"${a#-o}\";; esac; done\nmkdir -p \"$out\"\n" +
		extract + "\ntouch " + marker + "\n"
	fake := filepath.Join(dir, "7z")
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	SetArchiveTools(fake, 1)
	t.Cleanup(func() { SetArchiveTools("", 4) })
	return marker
}

func scan7z(t *testing.T) *Report {
	t.Helper()
	s, _ := NewScanner(Options{ScanAttachments: true})
	return s.ScanMessage(context.Background(), attachMsg("a.7z", "application/x-7z-compressed", fixture(t, "rrn.7z")))
}

const rrnText = "사원 주민번호 900101-1234567"

// A listing that fails (non-encryption error) or is oversized refuses
// extraction instead of extracting unchecked.
func TestSevenZipListingFailureRefusesExtraction(t *testing.T) {
	for name, tc := range map[string]struct {
		listing string
		exit    int
	}{
		"exit code":  {"----------\nPath = a.txt\nSize = 10\n\n", 2},
		"ambiguous":  {"----------\nPath = a.txt\nSize = 1\nSize = 2\n\n", 0},
		"too large":  {"----------\n" + strings.Repeat("Path = a\nSize = 1\n\n", (maxListingOutput/18)+10), 0},
		"no entries": {"garbage\n", 0},
	} {
		t.Run(name, func(t *testing.T) {
			marker := fake7z(t, tc.listing, tc.exit, "printf '"+rrnText+"' > \"$out/a.txt\"")
			rep := scan7z(t)
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("archive extracted despite an untrusted listing")
			}
			if hasRRN(rep) || len(rep.Uninspectable) == 0 {
				t.Fatalf("not reported as uninspectable: %v", rep.Uninspectable)
			}
		})
	}
}

// The listing is only a pre-check: the extracted tree is measured again and
// refused as a whole when it exceeds the budget or the entry count.
func TestSevenZipExtractedTreeEnforced(t *testing.T) {
	small := "----------\nPath = a.txt\nSize = 10\n\n"
	t.Run("ok", func(t *testing.T) {
		fake7z(t, small, 0, "printf '"+rrnText+"' > \"$out/a.txt\"")
		if rep := scan7z(t); !hasRRN(rep) {
			t.Fatalf("contents not scanned: %v", rep.Uninspectable)
		}
	})
	t.Run("too many files", func(t *testing.T) {
		n := DefaultLimits().MaxEntries + 1
		fake7z(t, small, 0, "i=0; while [ $i -lt "+strconv.Itoa(n)+" ]; do echo x > \"$out/f$i\"; i=$((i+1)); done; printf '"+rrnText+"' > \"$out/z.txt\"")
		rep := scan7z(t)
		if hasRRN(rep) || !strings.Contains(strings.Join(rep.Uninspectable, " "), "파일 수") {
			t.Fatalf("entry count not enforced: rrn=%v %v", hasRRN(rep), rep.Uninspectable)
		}
	})
	t.Run("too many dirs", func(t *testing.T) {
		n := 2*DefaultLimits().MaxEntries + 1
		fake7z(t, small, 0, "i=0; while [ $i -lt "+strconv.Itoa(n)+" ]; do mkdir \"$out/d$i\"; i=$((i+1)); done; printf '"+rrnText+"' > \"$out/z.txt\"")
		rep := scan7z(t)
		if hasRRN(rep) || !strings.Contains(strings.Join(rep.Uninspectable, " "), "파일 수") {
			t.Fatalf("entry count not enforced: rrn=%v %v", hasRRN(rep), rep.Uninspectable)
		}
	})
	t.Run("over budget", func(t *testing.T) {
		// Two 150 MiB sparse files (each under RLIMIT_FSIZE) vs the 200 MiB
		// default inflate budget.
		fake7z(t, small, 0, "printf '"+rrnText+"' > \"$out/a.txt\"; truncate -s 150M \"$out/big1.bin\" \"$out/big2.bin\"")
		rep := scan7z(t)
		if hasRRN(rep) || !strings.Contains(strings.Join(rep.Uninspectable, " "), "한도") {
			t.Fatalf("budget not enforced: rrn=%v %v", hasRRN(rep), rep.Uninspectable)
		}
	})
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
