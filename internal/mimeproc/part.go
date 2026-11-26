// Package mimeproc parses a MIME message into a mutable tree, strips
// attachment parts and injects the download-link banner.
//
// The tree keeps the raw (still transfer-encoded) body of every leaf so that
// untouched parts are written back byte-for-byte; only parts that are removed
// or receive the banner are re-encoded.
package mimeproc

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"

	"github.com/emersion/go-message/textproto"
)

const (
	maxDepth = 32
	// maxParts caps the total number of MIME parts across the whole tree. A
	// legitimate message has at most a few dozen; a much larger count is a
	// crafted amplification attack (millions of tiny parts fit in a few MB, each
	// forcing an allocation). Hitting the cap fails the parse, so the processor
	// quarantines the whole message instead — mail is still delivered.
	maxParts = 10000
)

var (
	ErrTooDeep      = errors.New("mimeproc: MIME nesting too deep")
	ErrTooManyParts = errors.New("mimeproc: too many MIME parts")
)

// Part is one node of the MIME tree.
type Part struct {
	Header textproto.Header
	// Body is the raw, transfer-encoded body. Nil for multipart nodes.
	Body     []byte
	Children []*Part
	// Preamble/Epilogue of multipart nodes (usually empty).
	Preamble []byte
}

// MediaType returns the lower-cased media type and params. Missing or broken
// Content-Type defaults to text/plain as per RFC 2045.
func (p *Part) MediaType() (string, map[string]string) {
	ct := p.Header.Get("Content-Type")
	if ct == "" {
		return "text/plain", map[string]string{}
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		// Salvage the type even if params are malformed.
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
		if mt == "" || !strings.Contains(mt, "/") {
			mt = "application/octet-stream"
		}
		params = looseParams(ct)
	}
	return mt, params
}

func (p *Part) IsMultipart() bool {
	mt, _ := p.MediaType()
	return strings.HasPrefix(mt, "multipart/")
}

// Parse reads a complete RFC 5322 message.
//
// Every Part.Body and Part.Preamble is a sub-slice of raw (capacity-capped,
// so appending to one never overwrites its neighbours) rather than a copy
// made at each nesting level: a deeply nested message costs O(len(raw))
// memory, not O(depth*len(raw)). Callers must not modify raw afterwards.
func Parse(raw []byte) (*Part, error) {
	ps := &parser{}
	h, n, err := ps.readHeader(raw)
	if err != nil {
		return nil, fmt.Errorf("mimeproc: read header: %w", err)
	}
	count := 1 // the root entity itself
	return ps.parseEntity(h, raw[n:], 0, &count)
}

// parser carries a reusable bufio.Reader for header parsing.
type parser struct {
	rd bytes.Reader
	br *bufio.Reader
}

// readHeader parses the header block at the start of b and returns it with
// the number of bytes it occupied.
func (ps *parser) readHeader(b []byte) (textproto.Header, int, error) {
	ps.rd.Reset(b)
	if ps.br == nil {
		ps.br = bufio.NewReader(&ps.rd)
	} else {
		ps.br.Reset(&ps.rd)
	}
	h, err := textproto.ReadHeader(ps.br)
	if err != nil {
		return h, 0, err
	}
	return h, len(b) - ps.rd.Len() - ps.br.Buffered(), nil
}

func (ps *parser) parseEntity(h textproto.Header, body []byte, depth int, count *int) (*Part, error) {
	if depth > maxDepth {
		return nil, ErrTooDeep
	}
	p := &Part{Header: h}
	mt, params := p.MediaType()
	if !strings.HasPrefix(mt, "multipart/") {
		p.Body = body[:len(body):len(body)]
		return p, nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, fmt.Errorf("mimeproc: %s without boundary", mt)
	}
	if i := bytes.Index(body, []byte("--"+boundary)); i > 0 {
		pre := bytes.TrimRight(body[:i], "\r\n")
		p.Preamble = pre[:len(pre):len(pre)]
	}
	err := ps.splitMultipart(body, boundary, func(ch textproto.Header, pb []byte) error {
		if *count++; *count > maxParts {
			return ErrTooManyParts
		}
		child, err := ps.parseEntity(ch, pb, depth+1, count)
		if err != nil {
			return err
		}
		p.Children = append(p.Children, child)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(p.Children) == 0 {
		return nil, fmt.Errorf("mimeproc: %s has no parts", mt)
	}
	return p, nil
}

// splitMultipart walks the body parts of a multipart entity and calls fn with
// each part's header and body, the body being a sub-slice of body. It follows
// the delimiter rules of go-message's textproto.MultipartReader (derived from
// mime/multipart) so parse results are unchanged; it only avoids the copy that
// reading every part through an io.Reader would make at each nesting level.
func (ps *parser) splitMultipart(body []byte, boundary string, fn func(textproto.Header, []byte) error) error {
	dashBoundary := []byte("--" + boundary)
	nl := []byte("\r\n")
	partsRead := 0
	expectNewPart := false
	pos := 0
	for {
		// NextPart: read lines until a delimiter line.
		if pos >= len(body) {
			return fmt.Errorf("mimeproc: multipart: NextPart: %w", io.EOF)
		}
		var line []byte
		if end := bytes.IndexByte(body[pos:], '\n'); end >= 0 {
			line = body[pos : pos+end+1]
		} else {
			// Last line without a newline: only a close delimiter is valid.
			if isFinalBoundary(body[pos:], dashBoundary, nl) {
				return nil
			}
			return fmt.Errorf("mimeproc: multipart: NextPart: %w", io.EOF)
		}
		pos += len(line)
		if isDelimiterLine(line, dashBoundary, &nl, partsRead) {
			partsRead++
			// Headers are parsed independently of boundaries, exactly as
			// MultipartReader does, then the body runs to the next delimiter.
			h, hlen, err := ps.readHeader(body[pos:])
			if err != nil {
				return fmt.Errorf("mimeproc: multipart: %w", err)
			}
			bs := pos + hlen
			be, next, err := findBodyEnd(body, bs, dashBoundary, nl)
			if err != nil {
				return err
			}
			if err := fn(h, body[bs:be]); err != nil {
				return err
			}
			pos = next
			// The newline before the delimiter was consumed by findBodyEnd,
			// which is what MultipartReader's "expect a new part" state does.
			expectNewPart = true
			continue
		}
		if isFinalBoundary(line, dashBoundary, nl) {
			return nil
		}
		if expectNewPart {
			return fmt.Errorf("mimeproc: multipart: expecting a new Part; got line %q", line)
		}
		if partsRead == 0 {
			continue // preamble
		}
		return fmt.Errorf("mimeproc: multipart: unexpected line %q", line)
	}
}

// findBodyEnd returns the end of the part body starting at bs (the newline
// before the delimiter is not part of the body) and the offset of the
// delimiter line that follows it.
func findBodyEnd(body []byte, bs int, dashBoundary, nl []byte) (end, next int, err error) {
	if bytes.HasPrefix(body[bs:], dashBoundary) && matchAfter(body[bs:], len(dashBoundary)) {
		return bs, bs, nil // empty body directly followed by the delimiter
	}
	nlDash := make([]byte, 0, len(nl)+len(dashBoundary))
	nlDash = append(append(nlDash, nl...), dashBoundary...)
	from := bs
	for {
		i := bytes.Index(body[from:], nlDash)
		if i < 0 {
			return 0, 0, fmt.Errorf("mimeproc: multipart body: %w", io.ErrUnexpectedEOF)
		}
		at := from + i
		if matchAfter(body[at:], len(nlDash)) {
			return at, at + len(nl), nil
		}
		from = at + len(nlDash)
	}
}

// matchAfter reports whether a delimiter prefix of length n at the start of
// buf is a real delimiter: followed by LWSP, a newline, '-' or end of input.
func matchAfter(buf []byte, n int) bool {
	if len(buf) == n {
		return true
	}
	switch buf[n] {
	case ' ', '\t', '\r', '\n', '-':
		return true
	}
	return false
}

func isFinalBoundary(line, dashBoundary, nl []byte) bool {
	if !bytes.HasPrefix(line, dashBoundary) {
		return false
	}
	rest := line[len(dashBoundary):]
	if !bytes.HasPrefix(rest, []byte("--")) {
		return false
	}
	rest = skipLWSP(rest[2:])
	return len(rest) == 0 || bytes.Equal(rest, nl)
}

func isDelimiterLine(line, dashBoundary []byte, nl *[]byte, partsRead int) bool {
	if !bytes.HasPrefix(line, dashBoundary) {
		return false
	}
	rest := skipLWSP(line[len(dashBoundary):])
	if partsRead == 0 && len(rest) == 1 && rest[0] == '\n' {
		*nl = []byte("\n")
	}
	return bytes.Equal(rest, *nl)
}

func skipLWSP(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}

// WriteTo serialises the tree.
func (p *Part) WriteTo(w io.Writer) (int64, error) {
	b, err := p.Bytes()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	return int64(n), err
}

// Bytes serialises the tree into a single buffer.
func (p *Part) Bytes() ([]byte, error) {
	p.prepareBoundaries()
	var buf bytes.Buffer
	if err := p.write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// prepareBoundaries fixes every multipart boundary bottom-up, so the single
// pass of write never has to buffer a subtree: a node whose boundary is
// missing or occurs inside one of its (already fixed) children's
// serialisation gets a fresh one. The collision check streams each child
// through a matcher and allocates O(1) regardless of the message size.
func (p *Part) prepareBoundaries() {
	if !p.IsMultipart() {
		return
	}
	for _, c := range p.Children {
		c.prepareBoundaries()
	}
	mt, params := p.MediaType()
	boundary := params["boundary"]
	collides := boundary == ""
	if !collides {
		m := &matchWriter{needle: []byte("--" + boundary)}
		for _, c := range p.Children {
			m.tail = m.tail[:0] // children are checked one by one
			if c.write(m); m.found {
				break
			}
		}
		collides = m.found
	}
	if collides {
		params["boundary"] = NewBoundary()
		p.Header.Set("Content-Type", mime.FormatMediaType(mt, params))
	}
}

type writer interface {
	io.Writer
	io.StringWriter
}

// write serialises p; prepareBoundaries must have run first.
func (p *Part) write(w writer) error {
	if !p.IsMultipart() {
		if err := textproto.WriteHeader(w, p.Header); err != nil {
			return err
		}
		_, err := w.Write(p.Body)
		return err
	}
	_, params := p.MediaType()
	boundary := params["boundary"]
	if boundary == "" {
		return errors.New("mimeproc: multipart without boundary")
	}
	if err := textproto.WriteHeader(w, p.Header); err != nil {
		return err
	}
	if len(p.Preamble) > 0 {
		w.Write(p.Preamble)
		w.WriteString("\r\n")
	}
	for _, c := range p.Children {
		w.WriteString("--" + boundary + "\r\n")
		if err := c.write(w); err != nil {
			return err
		}
		w.WriteString("\r\n")
	}
	_, err := w.WriteString("--" + boundary + "--\r\n")
	return err
}

// matchWriter records whether needle occurs in the bytes written to it,
// including across Write calls, keeping only len(needle)-1 bytes of state.
type matchWriter struct {
	needle []byte
	tail   []byte
	found  bool
}

func (m *matchWriter) Write(b []byte) (int, error) {
	if m.found || len(b) == 0 {
		return len(b), nil
	}
	k := len(m.needle) - 1
	if len(m.tail) > 0 {
		// A match straddling the previous write.
		head := b
		if len(head) > k {
			head = head[:k]
		}
		joined := make([]byte, 0, len(m.tail)+len(head))
		joined = append(append(joined, m.tail...), head...)
		if bytes.Contains(joined, m.needle) {
			m.found = true
			return len(b), nil
		}
	}
	if bytes.Contains(b, m.needle) {
		m.found = true
		return len(b), nil
	}
	if len(b) >= k {
		m.tail = append(m.tail[:0], b[len(b)-k:]...)
	} else {
		m.tail = append(m.tail, b...)
		if len(m.tail) > k {
			m.tail = append(m.tail[:0], m.tail[len(m.tail)-k:]...)
		}
	}
	return len(b), nil
}

func (m *matchWriter) WriteString(s string) (int, error) {
	return m.Write([]byte(s))
}

func NewBoundary() string {
	var b [12]byte
	rand.Read(b[:])
	return "secmail-" + hex.EncodeToString(b[:])
}

// looseParams extracts key=value pairs from a header that
// mime.ParseMediaType rejected (unquoted spaces, raw 8-bit bytes, ...).
func looseParams(v string) map[string]string {
	out := map[string]string{}
	segs := strings.Split(v, ";")
	for _, s := range segs[1:] {
		k, val, ok := strings.Cut(s, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"`)
		if k != "" {
			out[k] = val
		}
	}
	return out
}
