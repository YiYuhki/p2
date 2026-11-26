package dlp

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"github.com/yiyuhki/p2/internal/metrics"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ArchiveTools decompresses formats without a Go decoder using the 7-Zip CLI
// (7z / 7za). Auto-detected on PATH; when absent, those archives are reported
// as uninspectable instead of silently passing.
type ArchiveTools struct {
	SevenZip string
	Timeout  time.Duration
	sem      chan struct{}
}

var archiveTools = DetectArchiveTools("", 4)

// DetectArchiveTools finds the 7-Zip binary ("none" disables it).
func DetectArchiveTools(command string, maxProcs int) *ArchiveTools {
	find := func() string {
		if command == "none" {
			return ""
		}
		for _, c := range []string{command, "7z", "7za", "7zr"} {
			if c == "" {
				continue
			}
			if p, err := exec.LookPath(c); err == nil {
				return p
			}
		}
		return ""
	}
	if maxProcs <= 0 {
		maxProcs = 4
	}
	return &ArchiveTools{SevenZip: find(), Timeout: 60 * time.Second, sem: make(chan struct{}, maxProcs)}
}

// SetArchiveTools configures the 7-Zip integration for the whole process.
// Call once at startup before serving.
func SetArchiveTools(command string, maxProcs int) {
	archiveTools = DetectArchiveTools(command, maxProcs)
}

// ---- gzip / bzip2 (single streams) ----

func (x *extractor) gzip(loc, name string, data []byte, depth int) {
	if depth >= x.lim.MaxDepth {
		x.problem(loc, "압축 중첩 한도 초과")
		return
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		x.problem(loc, "손상된 gzip 파일")
		return
	}
	defer zr.Close()
	inner := zr.Name
	if inner == "" {
		inner = strings.TrimSuffix(name, filepath.Ext(name))
	}
	x.decompressStream(loc, inner, zr, depth)
}

func (x *extractor) bzip2(loc, name string, data []byte, depth int) {
	if depth >= x.lim.MaxDepth {
		x.problem(loc, "압축 중첩 한도 초과")
		return
	}
	inner := strings.TrimSuffix(name, filepath.Ext(name))
	x.decompressStream(loc, inner, bzip2.NewReader(bytes.NewReader(data)), depth)
}

// decompressStream reads one decompressed stream within the inflate budget
// and recurses. A ".tar" inner name (or tar magic) is handled as a tar.
func (x *extractor) decompressStream(loc, inner string, r io.Reader, depth int) {
	if x.budget <= 0 {
		x.problem(loc, "압축 해제 한도 초과")
		return
	}
	b, err := io.ReadAll(io.LimitReader(r, x.budget+1))
	x.budget -= int64(len(b))
	if x.budget < 0 {
		x.problem(loc, "압축 해제 한도 초과 (압축폭탄 의심)")
		return
	}
	if err != nil && len(b) == 0 {
		x.problem(loc, "압축 해제 실패")
		return
	}
	sub := loc + " > " + inner
	if strings.HasSuffix(strings.ToLower(inner), ".tar") || isTar(b) {
		x.tar(sub, b, depth+1)
		return
	}
	x.file(sub, inner, b, depth+1)
}

// ---- tar ----

func isTar(b []byte) bool {
	return len(b) >= 512 && (bytes.Equal(b[257:262], []byte("ustar")) || bytes.Equal(b[257:263], []byte("ustar\x00")))
}

func (x *extractor) tar(loc string, data []byte, depth int) {
	if depth >= x.lim.MaxDepth {
		x.problem(loc, "압축 중첩 한도 초과")
		return
	}
	tr := tar.NewReader(bytes.NewReader(data))
	for i := 0; ; i++ {
		if i >= x.lim.MaxEntries {
			x.problem(loc, "압축파일 내 파일 수 한도 초과")
			return
		}
		h, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			x.problem(loc, "손상된 tar 파일")
			return
		}
		if h.Typeflag != tar.TypeReg || h.Size == 0 {
			continue
		}
		if x.budget <= 0 {
			x.problem(loc, "압축 해제 한도 초과")
			return
		}
		b, err := io.ReadAll(io.LimitReader(tr, x.budget+1))
		x.budget -= int64(len(b))
		if x.budget < 0 {
			x.problem(loc, "압축 해제 한도 초과 (압축폭탄 의심)")
			return
		}
		if err != nil && len(b) == 0 {
			continue
		}
		x.file(loc+" > "+h.Name, filepath.Base(h.Name), b, depth+1)
	}
}

// ---- 7z / RAR / xz / zstd via the 7-Zip CLI ----

func (x *extractor) sevenZip(loc, name string, data []byte, depth int) {
	at := archiveTools
	if at == nil || at.SevenZip == "" {
		x.problem(loc, "압축 형식 해제 도구(7-Zip) 없음 (검사 불가)")
		return
	}
	if depth >= x.lim.MaxDepth {
		x.problem(loc, "압축 중첩 한도 초과")
		return
	}
	release, err := at.acquire()
	if err != nil {
		x.problem(loc, "압축 해제 대기 취소")
		return
	}
	defer release()

	dir, in, err := workDir(archiveName(name), data)
	if err != nil {
		x.problem(loc, "임시 파일 생성 실패")
		return
	}
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithTimeout(context.Background(), at.Timeout)
	defer cancel()

	// List first: refuse to extract anything whose declared contents exceed
	// the entry count or the remaining inflate budget, so a bomb never hits
	// the disk. (Sizes a format cannot declare up front, e.g. a zstd stream,
	// are bounded by RLIMIT_FSIZE below.)
	ls := at.list(ctx, in)
	if ls.encrypted {
		x.locked(loc, "암호가 설정된 압축파일")
		return
	}
	if ls.files > x.lim.MaxEntries {
		x.problem(loc, "압축파일 내 파일 수 한도 초과")
		return
	}
	if x.budget <= 0 || ls.totalSize > x.budget {
		x.problem(loc, "압축 해제 한도 초과 (압축폭탄 의심)")
		return
	}
	lim := DefaultProcLimits
	if mb := int((x.budget + 1<<20 - 1) >> 20); lim.OutputFileMB <= 0 || mb < lim.OutputFileMB {
		lim.OutputFileMB = mb
	}
	out := filepath.Join(dir, "out")
	// -p (empty password), stdin from /dev/null: never wait for a prompt.
	defer metrics.Time("archive")()
	cmd := sandboxCmd(ctx, lim, nil, at.SevenZip, "x", "-p", "-y", "-bd", "-snl-", "-o"+out, in)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, io.Discard, io.Discard
	if err := cmd.Run(); err != nil && ctx.Err() != nil {
		x.problem(loc, "압축 해제 시간 초과")
		return
	}
	x.walkExtracted(loc, out, depth)
}

// walkExtracted feeds every regular file 7-Zip produced back into the pipeline.
func (x *extractor) walkExtracted(loc, root string, depth int) {
	n := 0
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if n >= x.lim.MaxEntries {
			x.problem(loc, "압축파일 내 파일 수 한도 초과")
			return filepath.SkipAll
		}
		n++
		if x.budget <= 0 {
			x.problem(loc, "압축 해제 한도 초과")
			return filepath.SkipAll
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		x.budget -= int64(len(b))
		if x.budget < 0 {
			x.problem(loc, "압축 해제 한도 초과 (압축폭탄 의심)")
			return filepath.SkipAll
		}
		rel, _ := filepath.Rel(root, p)
		x.file(loc+" > "+rel, filepath.Base(p), b, depth+1)
		return nil
	})
}

func (at *ArchiveTools) acquire() (func(), error) {
	if at.sem == nil {
		return func() {}, nil
	}
	at.sem <- struct{}{}
	return func() { <-at.sem }, nil
}

// archiveListing summarises `7z l -slt` output.
type archiveListing struct {
	encrypted bool
	files     int   // non-directory entries
	totalSize int64 // sum of the declared uncompressed sizes
}

// list runs `7z l -slt`. Any entry with "Encrypted = +" marks the archive as
// encrypted; header-encrypted archives fail to list at all without a
// password, which also counts as encrypted.
func (at *ArchiveTools) list(ctx context.Context, path string) archiveListing {
	cmd := sandboxCmd(ctx, DefaultProcLimits, nil, at.SevenZip, "l", "-slt", "-p", path)
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	s := string(out)
	ls := parseSevenZipListing(s)
	if err != nil && (strings.Contains(s, "Wrong password") || strings.Contains(s, "Cannot open encrypted archive")) {
		ls.encrypted = true
	}
	return ls
}

// parseSevenZipListing reads the per-entry blocks that follow the
// "----------" separator of `7z l -slt`. Each block starts with "Path = ".
func parseSevenZipListing(s string) archiveListing {
	var ls archiveListing
	_, entries, ok := strings.Cut("\n"+s, "\n----------")
	if !ok {
		ls.encrypted = strings.Contains(s, "Encrypted = +")
		return ls
	}
	var size int64
	inEntry, isDir := false, false
	flush := func() {
		if inEntry && !isDir {
			ls.files++
			if size > 0 {
				if ls.totalSize > (1<<62)-size {
					ls.totalSize = 1 << 62 // saturate instead of overflowing
				} else {
					ls.totalSize += size
				}
			}
		}
		inEntry, isDir, size = false, false, 0
	}
	for _, line := range strings.Split(entries, "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), " = ")
		if !ok {
			continue
		}
		switch k {
		case "Path":
			flush()
			inEntry = true
		case "Size":
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && n > 0 {
				size = n
			}
		case "Folder":
			if strings.TrimSpace(v) == "+" {
				isDir = true
			}
		case "Attributes":
			if strings.HasPrefix(strings.TrimSpace(v), "D") {
				isDir = true
			}
		case "Encrypted":
			if strings.TrimSpace(v) == "+" {
				ls.encrypted = true
			}
		}
	}
	flush()
	return ls
}

func archiveName(name string) string {
	base := filepath.Base(name)
	if base == "" || base == "." || base == "/" {
		return "archive"
	}
	return base
}
