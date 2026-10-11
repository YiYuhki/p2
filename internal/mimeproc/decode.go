package mimeproc

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/transform"
)

// DecodeBody removes the Content-Transfer-Encoding of a leaf.
//
// Decoding is deliberately lenient (like most mail clients): a gateway that
// is stricter than the client can be bypassed with malformed encodings.
func (p *Part) DecodeBody() []byte {
	cte := strings.ToLower(strings.TrimSpace(p.Header.Get("Content-Transfer-Encoding")))
	switch cte {
	case "base64":
		return decodeBase64Lenient(p.Body)
	case "quoted-printable":
		out, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(p.Body)))
		if err != nil && len(out) == 0 {
			return p.Body
		}
		return out
	default:
		return p.Body
	}
}

func decodeBase64Lenient(in []byte) []byte {
	clean := make([]byte, 0, len(in))
	for _, c := range in {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			clean = append(clean, c)
		case c == '=':
			// padding: ignore, decoded with RawStdEncoding below
		}
	}
	if len(clean)%4 == 1 {
		clean = clean[:len(clean)-1]
	}
	out := make([]byte, base64.RawStdEncoding.DecodedLen(len(clean)))
	n, _ := base64.RawStdEncoding.Decode(out, clean)
	return out[:n]
}

// ToUTF8 converts text in the named charset to UTF-8.
func ToUTF8(charset string, b []byte) ([]byte, error) {
	cs := strings.ToLower(strings.TrimSpace(charset))
	switch cs {
	case "", "utf-8", "utf8", "us-ascii", "ascii":
		return b, nil
	}
	enc, err := htmlindex.Get(cs)
	if err != nil {
		return nil, fmt.Errorf("unsupported charset %q", charset)
	}
	out, _, err := transform.Bytes(enc.NewDecoder(), b)
	return out, err
}

var wordDecoder = &mime.WordDecoder{
	CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
		enc, err := htmlindex.Get(strings.ToLower(charset))
		if err != nil {
			return nil, err
		}
		return transform.NewReader(input, enc.NewDecoder()), nil
	},
}

// DecodeHeader decodes RFC 2047 encoded-words and repairs raw 8-bit values.
// Raw non-UTF-8 bytes are assumed to be EUC-KR (CP949), the most common
// legacy charset in Korean mail.
func DecodeHeader(v string) string {
	if !utf8.ValidString(v) {
		if dec, _, err := transform.String(korean.EUCKR.NewDecoder(), v); err == nil {
			v = dec
		} else {
			v = strings.ToValidUTF8(v, "�")
		}
	}
	if d, err := wordDecoder.DecodeHeader(v); err == nil {
		return d
	}
	return v
}

// Filename returns the sanitised filename of a part, or "" if none.
func (p *Part) Filename() string {
	name := ""
	if cd := p.Header.Get("Content-Disposition"); cd != "" {
		_, params, err := mime.ParseMediaType(cd)
		if err != nil {
			params = looseParams(cd)
		}
		name = params["filename"]
	}
	if name == "" {
		_, params := p.MediaType()
		name = params["name"]
	}
	if name == "" {
		return ""
	}
	return SanitizeFilename(DecodeHeader(name))
}

// Disposition returns the lower-cased Content-Disposition value.
func (p *Part) Disposition() string {
	cd := p.Header.Get("Content-Disposition")
	if cd == "" {
		return ""
	}
	d, _, err := mime.ParseMediaType(cd)
	if err != nil {
		d = strings.SplitN(cd, ";", 2)[0]
	}
	return strings.ToLower(strings.TrimSpace(d))
}

// SanitizeFilename strips directories and control characters so that the
// name is safe to show and to use in Content-Disposition.
func SanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = path.Base(name)
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '"' || r == '/' || r == 0x202E || r == 0x202D {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	name = strings.TrimLeft(name, ".")
	// Strip trailing dots/spaces: Windows and many mail clients drop them on
	// save, so "evil.exe." becomes "evil.exe". Normalizing here means every
	// consumer (storage, banner, analyzer, download Content-Disposition, the
	// blocked-extension gate) sees the name the OS will actually resolve.
	name = strings.TrimRight(name, ". ")
	if name == "" || name == "." {
		return ""
	}
	for len(name) > 200 {
		ext := path.Ext(name)
		if len(ext) > 20 {
			ext = ""
		}
		runes := []rune(strings.TrimSuffix(name, ext))
		name = string(runes[:len(runes)-1]) + ext
	}
	return name
}
