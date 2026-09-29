package mimeproc

import (
	"bytes"
	"errors"
	"mime"
	"mime/quotedprintable"
	"strings"
)

// Policy mirrors config.Rewrite*.
type Options struct {
	KeepInlineImages bool
	// SignedPassthrough leaves multipart/signed messages untouched.
	SignedPassthrough bool
	// EncryptedReject rejects encrypted messages instead of passing them.
	EncryptedReject bool
}

var ErrEncrypted = errors.New("mimeproc: encrypted message rejected by policy")

// Extracted is an attachment removed from the tree.
type Extracted struct {
	Filename    string
	ContentType string
	Data        []byte
}

// Result describes what Extract did.
type Result struct {
	Attachments []*Extracted
	// SignatureRemoved is set when a multipart/signed wrapper was dropped
	// because its content had to be modified.
	SignatureRemoved bool
	// Skipped is set when the message was left untouched by policy
	// (signed passthrough / encrypted passthrough).
	Skipped string
}

// Extract removes attachment parts from root in place.
func Extract(root *Part, opts Options) (*Result, error) {
	res := &Result{}
	mt, params := root.MediaType()

	if isEncrypted(mt, params) {
		if opts.EncryptedReject {
			return nil, ErrEncrypted
		}
		res.Skipped = "encrypted"
		return res, nil
	}
	if mt == "multipart/signed" && opts.SignedPassthrough {
		res.Skipped = "signed"
		return res, nil
	}

	if !root.IsMultipart() {
		if isAttachment(root, "", opts) {
			res.Attachments = append(res.Attachments, extractLeaf(root))
			// The whole body was the attachment: turn the message into an
			// empty multipart/mixed; the banner is added later.
			clearContentHeaders(root)
			root.Header.Set("Content-Type", mime.FormatMediaType("multipart/mixed", map[string]string{"boundary": NewBoundary()}))
			root.Body = nil
		}
		return res, nil
	}
	walk(root, opts, res)
	if len(root.Children) == 0 {
		// Keep root a (temporarily empty) multipart/mixed container.
		clearContentHeaders(root)
		root.Header.Set("Content-Type", mime.FormatMediaType("multipart/mixed", map[string]string{"boundary": NewBoundary()}))
	}
	return res, nil
}

func isEncrypted(mt string, params map[string]string) bool {
	if mt == "multipart/encrypted" {
		return true
	}
	if mt == "application/pkcs7-mime" || mt == "application/x-pkcs7-mime" {
		// enveloped-data (encrypted) and opaque signed-data: both are opaque
		// blobs we cannot rewrite without breaking the message.
		return true
	}
	return false
}

// walk processes a multipart node and returns true if anything was removed
// in its subtree.
func walk(p *Part, opts Options, res *Result) bool {
	mt, _ := p.MediaType()
	changed := false

	if mt == "multipart/signed" {
		if len(p.Children) == 0 {
			return false
		}
		content := p.Children[0]
		sub := false
		if content.IsMultipart() {
			sub = walk(content, opts, res)
		} else if isAttachment(content, mt, opts) {
			res.Attachments = append(res.Attachments, extractLeaf(content))
			content = nil
			sub = true
		}
		if !sub {
			return false
		}
		// Content changed -> signature is now invalid. Unwrap so clients do
		// not display a "tampered" warning; replace this node with content.
		res.SignatureRemoved = true
		if content == nil || (content.IsMultipart() && len(content.Children) == 0) {
			p.Children = nil
			return true
		}
		replaceContent(p, content)
		return true
	}

	kept := p.Children[:0]
	for _, c := range p.Children {
		if c.IsMultipart() {
			cmt, cparams := c.MediaType()
			if isEncrypted(cmt, cparams) {
				kept = append(kept, c)
				continue
			}
			if walk(c, opts, res) {
				changed = true
			}
			if c.IsMultipart() && len(c.Children) == 0 {
				continue // drop now-empty container
			}
			kept = append(kept, c)
			continue
		}
		if isAttachment(c, mt, opts) {
			res.Attachments = append(res.Attachments, extractLeaf(c))
			changed = true
			continue
		}
		kept = append(kept, c)
	}
	p.Children = kept
	return changed
}

// replaceContent makes dst carry src's content while keeping dst's
// non-content headers (important when dst is the message root).
func replaceContent(dst, src *Part) {
	clearContentHeaders(dst)
	fields := src.Header.Fields()
	for fields.Next() {
		if isContentHeader(fields.Key()) {
			dst.Header.Add(fields.Key(), fields.Value())
		}
	}
	dst.Body = src.Body
	dst.Children = src.Children
	dst.Preamble = src.Preamble
}

func isContentHeader(k string) bool {
	return strings.HasPrefix(strings.ToLower(k), "content-")
}

func clearContentHeaders(p *Part) {
	fields := p.Header.Fields()
	for fields.Next() {
		if isContentHeader(fields.Key()) {
			fields.Del()
		}
	}
}

func isAttachment(p *Part, parentType string, opts Options) bool {
	mt, _ := p.MediaType()
	disp := p.Disposition()
	name := p.Filename()

	switch {
	case disp == "attachment":
		return true
	case mt == "message/rfc822" || mt == "message/global":
		// Forwarded mails may carry their own attachments.
		return true
	case mt == "application/pgp-signature" || mt == "application/pkcs7-signature" ||
		mt == "application/x-pkcs7-signature":
		// Detached signatures of a signed part: only reachable when the
		// wrapper is being rewritten; they are dropped with the wrapper.
		return false
	}
	if opts.KeepInlineImages && strings.HasPrefix(mt, "image/") && p.Header.Get("Content-Id") != "" {
		return false
	}
	if name != "" {
		return true
	}
	if strings.HasPrefix(mt, "text/") || strings.HasPrefix(mt, "message/") {
		return false
	}
	// Nameless non-text leaves (application/octet-stream, etc.).
	return true
}

func extractLeaf(p *Part) *Extracted {
	mt, _ := p.MediaType()
	name := p.Filename()
	if name == "" {
		switch {
		case strings.HasPrefix(mt, "message/"):
			name = "forwarded-message.eml"
		default:
			name = "attachment"
			if exts, _ := mime.ExtensionsByType(mt); len(exts) > 0 {
				name += exts[0]
			} else {
				name += ".bin"
			}
		}
	}
	return &Extracted{Filename: name, ContentType: mt, Data: p.DecodeBody()}
}

// ---- banner ----

// Banner is inserted into the text/plain and text/html bodies.
type Banner struct {
	Text string
	HTML string
}

// InsertBanner appends the banner to the first text/plain and first
// text/html body parts. If none can be modified, a new banner part is added.
func InsertBanner(root *Part, b Banner) {
	var plain, html *Part
	findBodies(root, &plain, &html)

	okPlain := plain != nil && appendToText(plain, b.Text, false)
	okHTML := html != nil && appendToText(html, b.HTML, true)
	if okPlain || okHTML {
		return
	}
	addBannerPart(root, b)
}

func findBodies(p *Part, plain, html **Part) {
	if p.IsMultipart() {
		mt, params := p.MediaType()
		if mt == "multipart/signed" || isEncrypted(mt, params) {
			return
		}
		for _, c := range p.Children {
			findBodies(c, plain, html)
		}
		return
	}
	if p.Disposition() == "attachment" {
		return
	}
	switch mt, _ := p.MediaType(); mt {
	case "text/plain":
		if *plain == nil {
			*plain = p
		}
	case "text/html":
		if *html == nil {
			*html = p
		}
	}
}

func appendToText(p *Part, banner string, isHTML bool) bool {
	mt, params := p.MediaType()
	text, err := ToUTF8(params["charset"], p.DecodeBody())
	if err != nil {
		return false
	}
	if isHTML {
		text = insertBeforeBodyEnd(text, []byte(banner))
	} else {
		text = append(bytes.TrimRight(text, "\r\n"), []byte("\r\n\r\n"+banner+"\r\n")...)
	}
	params["charset"] = "utf-8"
	delete(params, "format") // appending breaks format=flowed / delsp semantics
	delete(params, "delsp")
	ct := mime.FormatMediaType(mt, params)
	if ct == "" { // params salvaged from a malformed header may not be encodable
		ct = mt + "; charset=utf-8"
	}
	p.Header.Set("Content-Type", ct)
	p.Header.Set("Content-Transfer-Encoding", "quoted-printable")
	p.Body = encodeQP(text)
	return true
}

func insertBeforeBodyEnd(html, banner []byte) []byte {
	lower := bytes.ToLower(html)
	if i := bytes.LastIndex(lower, []byte("</body>")); i >= 0 {
		out := make([]byte, 0, len(html)+len(banner))
		out = append(out, html[:i]...)
		out = append(out, banner...)
		return append(out, html[i:]...)
	}
	return append(html, banner...)
}

func encodeQP(b []byte) []byte {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func addBannerPart(root *Part, b Banner) {
	alt := &Part{}
	alt.Header.Set("Content-Type", mime.FormatMediaType("multipart/alternative", map[string]string{"boundary": NewBoundary()}))
	txt := &Part{Body: encodeQP([]byte(b.Text + "\r\n"))}
	txt.Header.Set("Content-Type", "text/plain; charset=utf-8")
	txt.Header.Set("Content-Transfer-Encoding", "quoted-printable")
	htm := &Part{Body: encodeQP([]byte("<html><body>" + b.HTML + "</body></html>\r\n"))}
	htm.Header.Set("Content-Type", "text/html; charset=utf-8")
	htm.Header.Set("Content-Transfer-Encoding", "quoted-printable")
	alt.Children = []*Part{txt, htm}

	mt, _ := root.MediaType()
	if mt == "multipart/mixed" {
		root.Children = append([]*Part{alt}, root.Children...)
		return
	}
	// Wrap the existing content into a new multipart/mixed root.
	inner := &Part{Body: root.Body, Children: root.Children, Preamble: root.Preamble}
	fields := root.Header.Fields()
	for fields.Next() {
		if isContentHeader(fields.Key()) {
			inner.Header.Add(fields.Key(), fields.Value())
		}
	}
	clearContentHeaders(root)
	root.Header.Set("Content-Type", mime.FormatMediaType("multipart/mixed", map[string]string{"boundary": NewBoundary()}))
	root.Body, root.Preamble = nil, nil
	root.Children = []*Part{alt, inner}
}
