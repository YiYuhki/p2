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
func Parse(raw []byte) (*Part, error) {
	br := bufio.NewReader(bytes.NewReader(raw))
	h, err := textproto.ReadHeader(br)
	if err != nil {
		return nil, fmt.Errorf("mimeproc: read header: %w", err)
	}
	body, err := io.ReadAll(br)
	if err != nil {
		return nil, err
	}
	count := 1 // the root entity itself
	return parseEntity(h, body, 0, &count)
}

func parseEntity(h textproto.Header, body []byte, depth int, count *int) (*Part, error) {
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
		return nil, fmt.Errorf("mimeproc: %s without boundary", mt)
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
			return nil, fmt.Errorf("mimeproc: multipart: %w", err)
		}
		pb, err := io.ReadAll(part)
		if err != nil {
			return nil, fmt.Errorf("mimeproc: multipart body: %w", err)
		}
		if *count++; *count > maxParts {
			return nil, ErrTooManyParts
		}
		child, err := parseEntity(part.Header, pb, depth+1, count)
		if err != nil {
			return nil, err
		}
		p.Children = append(p.Children, child)
	}
	if len(p.Children) == 0 {
		return nil, fmt.Errorf("mimeproc: %s has no parts", mt)
	}
	return p, nil
}

// WriteTo serialises the tree.
func (p *Part) WriteTo(w io.Writer) (int64, error) {
	var buf bytes.Buffer
	if err := p.write(&buf); err != nil {
		return 0, err
	}
	return buf.WriteTo(w)
}

func (p *Part) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	if err := p.write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *Part) write(w *bytes.Buffer) error {
	if !p.IsMultipart() {
		if err := textproto.WriteHeader(w, p.Header); err != nil {
			return err
		}
		w.Write(p.Body)
		return nil
	}
	children := make([][]byte, len(p.Children))
	for i, c := range p.Children {
		var cb bytes.Buffer
		if err := c.write(&cb); err != nil {
			return err
		}
		children[i] = cb.Bytes()
	}
	mt, params := p.MediaType()
	boundary := params["boundary"]
	if boundary == "" || boundaryCollides(boundary, children) {
		boundary = NewBoundary()
		params["boundary"] = boundary
		p.Header.Set("Content-Type", mime.FormatMediaType(mt, params))
	}
	if err := textproto.WriteHeader(w, p.Header); err != nil {
		return err
	}
	if len(p.Preamble) > 0 {
		w.Write(p.Preamble)
		w.WriteString("\r\n")
	}
	for _, c := range children {
		w.WriteString("--" + boundary + "\r\n")
		w.Write(c)
		w.WriteString("\r\n")
	}
	w.WriteString("--" + boundary + "--\r\n")
	return nil
}

func boundaryCollides(b string, children [][]byte) bool {
	needle := []byte("--" + b)
	for _, c := range children {
		if bytes.Contains(c, needle) {
			return true
		}
	}
	return false
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
