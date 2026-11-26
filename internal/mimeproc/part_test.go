package mimeproc

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-message/textproto"
)

// refParse is the previous io.ReadAll-based parser built on go-message's
// MultipartReader. Parse must produce the same tree (or also fail).
func refParse(raw []byte) (*Part, error) {
	br := bufio.NewReader(bytes.NewReader(raw))
	h, err := textproto.ReadHeader(br)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(br)
	if err != nil {
		return nil, err
	}
	count := 1
	return refEntity(h, body, 0, &count)
}

func refEntity(h textproto.Header, body []byte, depth int, count *int) (*Part, error) {
	if depth > maxDepth {
		return nil, ErrTooDeep
	}
	p := &Part{Header: h}
	mt, params := p.MediaType()
	if !strings.HasPrefix(mt, "multipart/") {
		p.Body = body
		return p, nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, fmt.Errorf("no boundary")
	}
	if i := bytes.Index(body, []byte("--"+boundary)); i > 0 {
		p.Preamble = bytes.TrimRight(body[:i], "\r\n")
	}
	mr := textproto.NewMultipartReader(bytes.NewReader(body), boundary)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		pb, err := io.ReadAll(part)
		if err != nil {
			return nil, err
		}
		if *count++; *count > maxParts {
			return nil, ErrTooManyParts
		}
		child, err := refEntity(part.Header, pb, depth+1, count)
		if err != nil {
			return nil, err
		}
		p.Children = append(p.Children, child)
	}
	if len(p.Children) == 0 {
		return nil, fmt.Errorf("no parts")
	}
	return p, nil
}

func dumpTree(p *Part, b *strings.Builder, depth int) {
	fmt.Fprintf(b, "%d hdr=", depth)
	f := p.Header.Fields()
	for f.Next() {
		fmt.Fprintf(b, "%q:%q;", f.Key(), f.Value())
	}
	fmt.Fprintf(b, " body=%q pre=%q n=%d\n", p.Body, p.Preamble, len(p.Children))
	for _, c := range p.Children {
		dumpTree(c, b, depth+1)
	}
}

func checkSameAsRef(t *testing.T, raw []byte) {
	t.Helper()
	got, gerr := Parse(raw)
	want, werr := refParse(raw)
	if (gerr == nil) != (werr == nil) {
		t.Fatalf("error mismatch for %q: got %v, ref %v", raw, gerr, werr)
	}
	if gerr != nil {
		return
	}
	var gs, ws strings.Builder
	dumpTree(got, &gs, 0)
	dumpTree(want, &ws, 0)
	if gs.String() != ws.String() {
		t.Fatalf("tree mismatch for %q:\n got: %s\nwant: %s", raw, gs.String(), ws.String())
	}
}

var parseCorpus = []string{
	"From: a@b\r\n\r\nbody",
	"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nhi\r\n--x--\r\n",
	"Content-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain\n\nhi\n--x\n\nbare\n--x--\n",
	"Content-Type: multipart/mixed; boundary=x\r\n\r\npreamble\r\n--x \t\r\n\r\n\r\n--x\r\nA: b\r\n\r\n--x--",
	"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n\r\nbody --x inline\r\n--xy\r\n--x-\r\n--x--  \r\nepilogue",
	"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n\r\nno close",
	"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n\r\na\r\n--x\r\ngarbage\r\n--x--\r\n",
	"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n\r\na\r\n--x--junk\r\n",
	"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x--\r\n",
	"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nBad Header\r\n\r\na\r\n--x--\r\n",
	"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: multipart/alternative; boundary=y\r\n\r\n--y\r\n\r\nin\r\n--y--\r\n--x--\r\n",
	"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\nA: b\n\nlf\r\n--x--\r\n",
}

func TestParseMatchesMultipartReader(t *testing.T) {
	for _, s := range parseCorpus {
		checkSameAsRef(t, []byte(s))
	}
}

func FuzzParseMatchesMultipartReader(f *testing.F) {
	for _, s := range parseCorpus {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4000 { // MultipartReader errors on lines > its 4 KiB buffer
			return
		}
		checkSameAsRef(t, raw)
	})
}

// deepMessage builds a message nested depth levels deep around a leaf of
// leafSize bytes.
func deepMessage(depth, leafSize int) []byte {
	var b bytes.Buffer
	b.WriteString("From: a@b\r\n")
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=b%02d\r\n\r\n--b%02d\r\n", i, i)
	}
	b.WriteString("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	line := strings.Repeat("QUFB", 19) + "\r\n"
	for b.Len() < leafSize {
		b.WriteString(line)
	}
	for i := depth - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "\r\n--b%02d--\r\n", i)
	}
	return b.Bytes()
}

// TestParseDeepNestingMemoryBounded guards against per-level copies: a 5 MB
// leaf at depth 31 used to cost >300 MB to parse and serialise.
func TestParseDeepNestingMemoryBounded(t *testing.T) {
	raw := deepMessage(maxDepth-1, 5<<20)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	root, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := root.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	alloc := after.TotalAlloc - before.TotalAlloc
	if limit := uint64(10 * len(raw)); alloc > limit {
		t.Fatalf("parse+serialise of %d-byte message allocated %d bytes (> %d)", len(raw), alloc, limit)
	}
	if !bytes.Equal(out, raw) {
		t.Fatal("round trip changed the message")
	}
	// The leaf body aliases the input.
	leaf := root
	for len(leaf.Children) > 0 {
		leaf = leaf.Children[0]
	}
	if len(leaf.Body) == 0 || cap(leaf.Body) != len(leaf.Body) {
		t.Fatalf("leaf body len=%d cap=%d", len(leaf.Body), cap(leaf.Body))
	}
}

func TestBoundaryCollisionRegenerated(t *testing.T) {
	raw := "Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n\r\nhello\r\n--x--\r\n"
	root, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	root.Children[0].Body = []byte("contains --x inside\r\n")
	out, err := root.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	re, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, p := re.MediaType(); p["boundary"] == "x" {
		t.Fatal("colliding boundary kept")
	}
	if string(re.Children[0].Body) != "contains --x inside\r\n" {
		t.Fatalf("body = %q", re.Children[0].Body)
	}
}

func TestSanitizeFilenameHugeIsFast(t *testing.T) {
	name := strings.Repeat("가a", 1<<20/4) + ".pdf"
	start := time.Now()
	got := SanitizeFilename(name)
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("SanitizeFilename took %v", d)
	}
	if len(got) > maxFilenameBytes || !strings.HasSuffix(got, ".pdf") || !strings.HasPrefix(got, "가a") {
		t.Fatalf("bad truncation: len=%d suffix=%q", len(got), got[len(got)-4:])
	}
	if !strings.HasPrefix(got, strings.Repeat("가a", 10)) {
		t.Fatal("rune split")
	}
}

func TestFilenameRFC2231ContinuationsIsFast(t *testing.T) {
	var cd strings.Builder
	cd.WriteString("attachment")
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&cd, "; filename*%d=\"%s\"", i, strings.Repeat("x", 30))
	}
	fmt.Fprintf(&cd, "; filename*1000=\".exe\"")
	p := &Part{}
	p.Header.Set("Content-Disposition", cd.String())
	start := time.Now()
	got := p.Filename()
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("Filename took %v", d)
	}
	if len(got) > maxFilenameBytes || !strings.HasSuffix(got, ".exe") {
		t.Fatalf("got len=%d %q", len(got), got)
	}
}
