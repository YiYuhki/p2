package dlp

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/ledongthuc/pdf"
	"github.com/richardlehane/mscfb"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/transform"
)

// Text is extracted content with a human-readable location, e.g.
// "첨부 고객명단.zip > 2026/list.xlsx".
type Text struct {
	Location string
	Content  string
}

// Limits bound the work done on hostile input (zip bombs, huge files).
type Limits struct {
	MaxDepth       int   // nested archives / attached messages
	MaxEntries     int   // files inside one archive
	MaxInflate     int64 // total decompressed bytes per top-level attachment
	MaxTextPerFile int   // bytes of extracted text kept per file
}

func DefaultLimits() Limits {
	return Limits{MaxDepth: 3, MaxEntries: 500, MaxInflate: 200 << 20, MaxTextPerFile: 10 << 20}
}

type extractor struct {
	lim      Limits
	budget   int64
	texts    []Text
	images   []Image
	problems []string
}

// Extracted is everything pulled out of one attachment.
type Extracted struct {
	Texts []Text
	// Images are pictures to OCR (attachments, pictures pasted into
	// documents, scanned PDF pages).
	Images   []Image
	Problems []string
}

// Extract walks an attachment (recursively for archives and documents).
func Extract(location, filename string, data []byte, lim Limits) Extracted {
	x := &extractor{lim: lim, budget: lim.MaxInflate}
	x.file(location, filename, data, 0)
	return Extracted{Texts: x.texts, Images: x.images, Problems: x.problems}
}

// ExtractText returns the text found in an attachment and a list of parts
// that could not be inspected (encrypted archives/documents, parse errors).
func ExtractText(location, filename string, data []byte, lim Limits) ([]Text, []string) {
	e := Extract(location, filename, data, lim)
	return e.Texts, e.Problems
}

func (x *extractor) addImage(loc string, b []byte) {
	if len(x.images) < 200 { // hard cap; the scanner applies MaxImages
		x.images = append(x.images, Image{Location: loc, Data: b})
	}
}

func isHEIF(b []byte) bool {
	if len(b) < 12 || string(b[4:8]) != "ftyp" {
		return false
	}
	switch string(b[8:12]) {
	case "heic", "heix", "hevc", "heim", "heis", "mif1", "msf1", "avif":
		return true
	}
	return false
}

func (x *extractor) add(loc, s string) {
	if strings.TrimSpace(s) == "" {
		return
	}
	if len(s) > x.lim.MaxTextPerFile {
		s = s[:x.lim.MaxTextPerFile]
	}
	x.texts = append(x.texts, Text{Location: loc, Content: s})
}

func (x *extractor) problem(loc, why string) {
	x.problems = append(x.problems, loc+": "+why)
}

func (x *extractor) file(loc, name string, data []byte, depth int) {
	defer func() {
		if r := recover(); r != nil { // third-party parsers on hostile input
			x.problem(loc, fmt.Sprintf("분석 중 오류 (%v)", r))
		}
	}()
	ext := strings.ToLower(path.Ext(name))
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")) || bytes.HasPrefix(data, []byte("PK\x05\x06")):
		x.zip(loc, data, depth)
	case bytes.HasPrefix(data, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}):
		x.ole(loc, data)
	case bytes.HasPrefix(data, []byte("%PDF")):
		x.pdf(loc, data)
		x.pdfImages(loc, data)
	case isImage(data):
		x.addImage(loc, data)
	case isHEIF(data):
		x.problem(loc, "HEIC/AVIF 이미지 (OCR 미지원, 검사 불가)")
	case isTextLike(ext, data):
		x.add(loc, decodeText(data))
	case ext == ".eml" || bytes.HasPrefix(data, []byte("From:")) || bytes.HasPrefix(data, []byte("Received:")):
		x.add(loc, decodeText(data))
	default:
		// Images, executables, media: no text to inspect.
	}
}

var textExt = map[string]bool{
	".txt": true, ".csv": true, ".tsv": true, ".json": true, ".xml": true, ".html": true, ".htm": true,
	".md": true, ".log": true, ".yaml": true, ".yml": true, ".ini": true, ".conf": true, ".cfg": true,
	".env": true, ".properties": true, ".sql": true, ".sh": true, ".ps1": true, ".py": true, ".js": true,
	".ts": true, ".go": true, ".java": true, ".kt": true, ".cs": true, ".php": true, ".rb": true,
	".tf": true, ".tfvars": true, ".pem": true, ".key": true, ".crt": true, ".toml": true, ".rtf": true,
}

func isTextLike(ext string, data []byte) bool {
	if textExt[ext] {
		return true
	}
	// Sniff: mostly printable bytes, no NULs in the first 8 KiB.
	n := min(len(data), 8192)
	if n == 0 || bytes.IndexByte(data[:n], 0) >= 0 {
		return false
	}
	printable := 0
	for _, c := range data[:n] {
		if c >= 0x20 || c == '\n' || c == '\r' || c == '\t' || c >= 0x80 {
			printable++
		}
	}
	return printable*100/n > 95
}

// decodeText handles UTF-8 (with BOM), UTF-16 (BOM) and EUC-KR/CP949.
func decodeText(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}):
		return string(b[3:])
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE}):
		return utf16le(b[2:])
	case bytes.HasPrefix(b, []byte{0xFE, 0xFF}):
		u := make([]uint16, len(b[2:])/2)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(b[2+2*i:])
		}
		return string(utf16.Decode(u))
	}
	if utf8.Valid(b) {
		return string(b)
	}
	if s, _, err := transform.Bytes(korean.EUCKR.NewDecoder(), b); err == nil {
		return string(s)
	}
	return strings.ToValidUTF8(string(b), " ")
}

func utf16le(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// ---- ZIP: plain archives and OOXML / HWPX / ODF documents ----

func (x *extractor) readZipEntry(f *zip.File) ([]byte, error) {
	if x.budget <= 0 {
		return nil, fmt.Errorf("압축 해제 한도 초과")
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, x.budget+1))
	x.budget -= int64(len(b))
	if x.budget < 0 {
		return nil, fmt.Errorf("압축 해제 한도 초과 (zip bomb 의심)")
	}
	return b, err
}

func (x *extractor) zip(loc string, data []byte, depth int) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		x.problem(loc, "손상된 압축파일")
		return
	}
	if isOfficeZip(zr) {
		x.officeZip(loc, zr)
		return
	}
	if depth >= x.lim.MaxDepth {
		x.problem(loc, "압축 중첩 한도 초과")
		return
	}
	for i, f := range zr.File {
		if i >= x.lim.MaxEntries {
			x.problem(loc, "압축파일 내 파일 수 한도 초과")
			return
		}
		if f.FileInfo().IsDir() {
			continue
		}
		sub := loc + " > " + f.Name
		if f.Flags&0x1 != 0 {
			x.problem(sub, "암호화된 압축파일 (검사 불가)")
			continue
		}
		b, err := x.readZipEntry(f)
		if err != nil {
			x.problem(sub, err.Error())
			if x.budget <= 0 {
				return
			}
			continue
		}
		x.file(sub, f.Name, b, depth+1)
	}
}

func isOfficeZip(zr *zip.Reader) bool {
	for _, f := range zr.File {
		switch f.Name {
		case "[Content_Types].xml", "mimetype", "META-INF/manifest.xml":
			return true
		}
	}
	return false
}

// officeZip extracts text from the XML parts of docx/xlsx/pptx, HWPX and
// ODF documents.
func (x *extractor) officeZip(loc string, zr *zip.Reader) {
	var sb strings.Builder
	for i, f := range zr.File {
		n := strings.ToLower(f.Name)
		if i < x.lim.MaxEntries && isMediaPath(n) {
			if b, err := x.readZipEntry(f); err == nil && isImage(b) {
				x.addImage(loc+" > "+f.Name, b)
			}
			continue
		}
		if !strings.HasSuffix(n, ".xml") || strings.Contains(n, "_rels/") ||
			strings.Contains(n, "theme") || strings.Contains(n, "styles") ||
			strings.HasPrefix(n, "[content_types]") || strings.Contains(n, "settings") ||
			strings.Contains(n, "fonttable") || strings.Contains(n, "manifest") {
			continue
		}
		b, err := x.readZipEntry(f)
		if err != nil {
			x.problem(loc, err.Error())
			return
		}
		xmlText(&sb, b)
		sb.WriteByte('\n')
		if sb.Len() > x.lim.MaxTextPerFile {
			break
		}
	}
	x.add(loc, sb.String())
}

// isMediaPath matches picture folders of OOXML, HWPX and ODF packages.
func isMediaPath(n string) bool {
	return strings.Contains(n, "/media/") || strings.HasPrefix(n, "bindata/") ||
		strings.HasPrefix(n, "pictures/")
}

// Element local names that end a line / cell in OOXML, HWPX and ODF.
var xmlBreak = map[string]string{
	"p": "\n", "si": "\n", "row": "\n", "tr": "\n", "br": "\n", "h": "\n",
	"c": "\t", "tc": "\t", "tab": "\t", "table-cell": "\t",
}

func xmlText(sb *strings.Builder, b []byte) {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = false
	for {
		tok, err := d.Token()
		if err != nil {
			return
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.EndElement:
			if s, ok := xmlBreak[t.Name.Local]; ok {
				sb.WriteString(s)
			}
		case xml.StartElement:
			if t.Name.Local == "br" || t.Name.Local == "tab" {
				sb.WriteString(" ")
			}
		}
	}
}

// ---- OLE compound files: HWP 5, legacy Office, encrypted OOXML ----

func (x *extractor) ole(loc string, data []byte) {
	doc, err := mscfb.New(bytes.NewReader(data))
	if err != nil {
		x.problem(loc, "손상된 문서")
		return
	}
	streams := map[string][]byte{}
	var order []string
	for f, err := doc.Next(); err == nil; f, err = doc.Next() {
		if f.Size <= 0 || f.Size > 100<<20 {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(f, f.Size))
		if err != nil {
			continue
		}
		key := strings.Join(append(append([]string{}, f.Path...), f.Name), "/")
		streams[key] = b
		order = append(order, key)
	}
	if _, ok := streams["EncryptedPackage"]; ok {
		x.problem(loc, "암호가 설정된 문서 (검사 불가)")
		return
	}
	if fh, ok := streams["FileHeader"]; ok && bytes.HasPrefix(fh, []byte("HWP Document File")) {
		x.hwp(loc, fh, streams, order)
		return
	}
	// Legacy .doc/.xls/.ppt: pull UTF-16 and ASCII runs out of every stream.
	var sb strings.Builder
	for _, k := range order {
		sb.WriteString(printableRuns(streams[k]))
		sb.WriteByte('\n')
	}
	x.add(loc, sb.String())
}

// hwp decodes HWP 5.x body text (BodyText/SectionN, raw-deflate records).
func (x *extractor) hwp(loc string, fh []byte, streams map[string][]byte, order []string) {
	if len(fh) < 40 {
		x.problem(loc, "손상된 HWP 문서")
		return
	}
	props := binary.LittleEndian.Uint32(fh[36:40])
	compressed, encrypted, distribution := props&1 != 0, props&2 != 0, props&4 != 0
	if encrypted {
		x.problem(loc, "암호가 설정된 HWP 문서 (검사 불가)")
		return
	}
	if distribution {
		// 배포용 문서: the real body lives encrypted in ViewText/; BodyText
		// only holds a stub, so scanning it would give a false "clean".
		x.problem(loc, "배포용(보호) HWP 문서 (검사 불가)")
		return
	}
	var sb strings.Builder
	for _, k := range order {
		if !strings.HasPrefix(k, "BodyText/Section") {
			continue
		}
		b := streams[k]
		if compressed {
			r := flate.NewReader(bytes.NewReader(b))
			d, err := io.ReadAll(io.LimitReader(r, 100<<20))
			r.Close()
			if err != nil && len(d) == 0 {
				x.problem(loc, "HWP 본문 해제 실패")
				continue
			}
			b = d
		}
		hwpRecords(&sb, b)
	}
	x.add(loc, sb.String())

	// Embedded pictures (BinData/BINxxxx.png|jpg|bmp...), deflated when the
	// document is compressed.
	for _, k := range order {
		if !strings.HasPrefix(k, "BinData/") {
			continue
		}
		b := streams[k]
		if compressed {
			r := flate.NewReader(bytes.NewReader(b))
			if d, err := io.ReadAll(io.LimitReader(r, 50<<20)); err == nil || len(d) > 0 {
				b = d
			}
			r.Close()
		}
		if isImage(b) {
			x.addImage(loc+" > "+k, b)
		}
	}
}

const hwpTagParaText = 0x10 + 51

func hwpRecords(sb *strings.Builder, b []byte) {
	for len(b) >= 4 {
		h := binary.LittleEndian.Uint32(b)
		tag, size := h&0x3FF, int(h>>20)
		b = b[4:]
		if size == 0xFFF {
			if len(b) < 4 {
				return
			}
			size = int(binary.LittleEndian.Uint32(b))
			b = b[4:]
		}
		if size > len(b) {
			return
		}
		if tag == hwpTagParaText {
			hwpParaText(sb, b[:size])
			sb.WriteByte('\n')
		}
		b = b[size:]
	}
}

// hwpParaText decodes UTF-16LE paragraph text, skipping inline/extended
// control characters (each occupies 8 WCHARs).
func hwpParaText(sb *strings.Builder, b []byte) {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); {
		c := binary.LittleEndian.Uint16(b[i:])
		if c < 32 {
			switch c {
			case 0, 10, 13, 24, 25, 26, 27, 28, 29, 30, 31: // char controls: 1 WCHAR
				if c == 10 || c == 13 {
					u = append(u, '\n')
				}
				i += 2
			default: // inline / extended controls: 8 WCHARs
				u = append(u, ' ')
				i += 16
			}
			continue
		}
		u = append(u, c)
		i += 2
	}
	sb.WriteString(string(utf16.Decode(u)))
}

// printableRuns mimics `strings` for UTF-16LE and single-byte text.
func printableRuns(b []byte) string {
	var sb strings.Builder
	// UTF-16LE runs (Word/Excel store most text this way).
	var run []uint16
	flush := func() {
		if len(run) >= 4 {
			sb.WriteString(string(utf16.Decode(run)))
			sb.WriteByte(' ')
		}
		run = run[:0]
	}
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if (c >= 0x20 && c < 0x7F) || (c >= 0xAC00 && c <= 0xD7A3) || (c >= 0x3130 && c <= 0x318F) {
			run = append(run, c)
		} else {
			flush()
		}
	}
	flush()
	// ASCII runs.
	start := -1
	for i, c := range b {
		if c >= 0x20 && c < 0x7F {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 6 {
			sb.Write(b[start:i])
			sb.WriteByte(' ')
		}
		start = -1
	}
	return sb.String()
}

// ---- PDF ----

func (x *extractor) pdf(loc string, data []byte) {
	r, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		if err == pdf.ErrInvalidPassword {
			x.problem(loc, "암호가 설정된 PDF (검사 불가)")
		} else {
			x.problem(loc, "PDF 해석 실패")
		}
		return
	}
	tr, err := r.GetPlainText()
	if err != nil {
		x.problem(loc, "PDF 텍스트 추출 실패")
		return
	}
	b, _ := io.ReadAll(io.LimitReader(tr, int64(x.lim.MaxTextPerFile)))
	x.add(loc, string(b))
}
