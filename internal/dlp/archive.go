package dlp

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
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

// maxListingOutput caps the `7z l -slt` output read into memory.
const maxListingOutput = 8 << 20

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
	// the disk. A listing that fails, is oversized or cannot be parsed
	// unambiguously is refused outright. (Sizes a format cannot declare up
	// front, e.g. a zstd stream, are bounded by RLIMIT_FSIZE below and by
	// the post-extraction check in walkExtracted.)
	ls, err := at.list(ctx, in)
	if ls.encrypted {
		x.locked(loc, "암호가 설정된 압축파일")
		return
	}
	if err != nil {
		if ctx.Err() != nil {
			x.problem(loc, "압축 해제 시간 초과")
		} else {
			x.problem(loc, "압축파일 목록 확인 실패 (검사 불가)")
		}
		return
	}
	if ls.files > x.lim.MaxEntries || ls.entries > maxArchiveEntries(x.lim) {
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

// maxArchiveEntries bounds all entries (directories included) of one archive.
func maxArchiveEntries(lim Limits) int {
	return 2 * lim.MaxEntries
}

// walkExtracted feeds every regular file 7-Zip produced back into the
// pipeline. The listing is only a pre-check (it is derived from the archive
// and may lie), so the extracted tree is measured first and refused as a
// whole when it exceeds the entry count or the remaining inflate budget.
func (x *extractor) walkExtracted(loc, root string, depth int) {
	var entries, files int
	var total int64
	over := false
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if p == root {
			return nil
		}
		entries++
		if entries > maxArchiveEntries(x.lim) {
			over = true
			return filepath.SkipAll
		}
		if !d.Type().IsRegular() {
			return nil
		}
		files++
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		if files > x.lim.MaxEntries {
			over = true
			return filepath.SkipAll
		}
		return nil
	})
	if over {
		x.problem(loc, "압축파일 내 파일 수 한도 초과")
		return
	}
	if x.budget <= 0 || total > x.budget {
		x.problem(loc, "압축 해제 한도 초과 (압축폭탄 의심)")
		return
	}

	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		if x.budget <= 0 {
			x.problem(loc, "압축 해제 한도 초과")
			return filepath.SkipAll
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		b, err := io.ReadAll(io.LimitReader(f, x.budget+1))
		f.Close()
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
	entries   int   // all entries, directories included
	totalSize int64 // sum of the declared uncompressed sizes of all entries
}

// errListingTooLarge and errListingAmbiguous refuse a listing that cannot be
// trusted as a pre-check.
var (
	errListingTooLarge  = errors.New("7z listing output too large")
	errListingAmbiguous = errors.New("ambiguous 7z listing")
)

// cappedBuffer keeps the first max bytes written and records overflow. It
// never fails a write, so the child process is not blocked or killed by a
// broken pipe; the overflow is reported afterwards instead.
type cappedBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room < len(p) {
		c.overflow = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

// list runs `7z l -slt`. Any entry with "Encrypted = +" marks the archive as
// encrypted; header-encrypted archives fail to list at all without a
// password, which also counts as encrypted. Any other failure, output beyond
// maxListingOutput or an ambiguous listing is an error (the caller refuses
// to extract).
func (at *ArchiveTools) list(ctx context.Context, path string) (archiveListing, error) {
	cmd := sandboxCmd(ctx, DefaultProcLimits, nil, at.SevenZip, "l", "-slt", "-p", path)
	cmd.Stdin = nil
	out := &cappedBuffer{max: maxListingOutput}
	cmd.Stdout, cmd.Stderr = out, out
	runErr := cmd.Run()
	s := out.buf.String()
	if runErr != nil && (strings.Contains(s, "Wrong password") || strings.Contains(s, "Cannot open encrypted archive")) {
		return archiveListing{encrypted: true}, nil
	}
	if out.overflow {
		return archiveListing{}, errListingTooLarge
	}
	if runErr != nil {
		return archiveListing{}, runErr
	}
	return parseSevenZipListing(s)
}

// parseSevenZipListing reads the per-entry blocks that follow the
// "----------" separator of `7z l -slt`. Entry names are attacker-controlled
// and may contain newlines, so the structure is checked strictly and any
// ambiguity is an error:
//   - exactly one separator line;
//   - every block (lines up to an empty line) starts with "Path = ";
//   - inside a block every line is "Key = value" and no key repeats;
//   - "Folder" and "Attributes" must agree on whether an entry is a
//     directory, and a size must be a non-negative integer (or empty).
//
// Declared sizes are summed over all entries, directories included, so
// faking a directory gains nothing.
func parseSevenZipListing(s string) (archiveListing, error) {
	var ls archiveListing
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	sep := -1
	for i, l := range lines {
		if l == "----------" {
			if sep >= 0 {
				return archiveListing{}, errListingAmbiguous
			}
			sep = i
		}
	}
	if sep < 0 {
		if strings.Contains(s, "Encrypted = +") {
			return archiveListing{encrypted: true}, nil
		}
		return archiveListing{}, errListingAmbiguous
	}

	type block struct {
		seen                 map[string]bool
		size                 int64
		folder, attrDir      bool
		hasFolder, hasAttrib bool
	}
	var cur *block
	flush := func() error {
		if cur == nil {
			return nil
		}
		b := cur
		cur = nil
		if b.hasFolder && b.hasAttrib && b.folder != b.attrDir {
			return errListingAmbiguous
		}
		ls.entries++
		if !b.folder && !b.attrDir {
			ls.files++
		}
		if ls.totalSize > (1<<62)-b.size {
			ls.totalSize = 1 << 62 // saturate instead of overflowing
		} else {
			ls.totalSize += b.size
		}
		return nil
	}
	for _, line := range lines[sep+1:] {
		if line == "" {
			if err := flush(); err != nil {
				return archiveListing{}, err
			}
			continue
		}
		k, v, ok := strings.Cut(line, " = ")
		if cur == nil {
			if !ok {
				continue // summary text after the last block
			}
			if k != "Path" {
				return archiveListing{}, errListingAmbiguous
			}
			cur = &block{seen: map[string]bool{"Path": true}}
			continue
		}
		if !ok || cur.seen[k] {
			return archiveListing{}, errListingAmbiguous
		}
		cur.seen[k] = true
		v = strings.TrimSpace(v)
		switch k {
		case "Size":
			if v == "" {
				break // unknown (e.g. a stream): bounded after extraction
			}
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				return archiveListing{}, errListingAmbiguous
			}
			cur.size = n
		case "Folder":
			cur.hasFolder = true
			switch v {
			case "+":
				cur.folder = true
			case "-", "":
			default:
				return archiveListing{}, errListingAmbiguous
			}
		case "Attributes":
			cur.hasAttrib = true
			cur.attrDir = strings.HasPrefix(v, "D")
		case "Encrypted":
			if v == "+" {
				ls.encrypted = true
			}
		}
	}
	if err := flush(); err != nil {
		return archiveListing{}, err
	}
	return ls, nil
}

// archiveName is the temp file name for an archive: the attachment's base
// name restricted to a safe character set (it appears in 7-Zip's listing
// header, so it must not be able to inject lines there).
func archiveName(name string) string {
	base := filepath.Base(name)
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		}
		return '_'
	}, base)
	safe = strings.TrimLeft(safe, ".-")
	if safe == "" {
		return "archive"
	}
	if len(safe) > 100 {
		safe = safe[len(safe)-100:]
	}
	return safe
}
