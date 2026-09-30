package dlp

import (
	"bytes"
	"compress/zlib"
	"encoding/ascii85"
	"encoding/hex"
	"fmt"
	"image"
	"image/png"
	"io"
	"regexp"
	"strconv"

	"golang.org/x/image/ccitt"
)

// pdfImages extracts image XObjects from a PDF so that scanned pages can be
// OCR'd. Image streams are always top-level indirect objects, so a byte
// scan for "obj ... stream" is sufficient without a full PDF parser.
//
// Decoded in Go: DCTDecode (JPEG), FlateDecode 8-bit Gray/RGB (with PNG
// predictors), ASCII85/ASCIIHex chains and CCITT Group 4 / Group 3 1-D.
// If any image uses another codec (JBIG2, JPEG2000, CCITT 2-D, ...), the
// whole PDF is additionally queued for page rendering with poppler; the OCR
// stage then drops the individually extracted images of that PDF.
func (x *extractor) pdfImages(loc string, data []byte) {
	n, unsupported := 0, 0
	for i := 0; ; {
		k := bytes.Index(data[i:], []byte("stream"))
		if k < 0 {
			break
		}
		pos := i + k
		i = pos + 6
		if pos >= 3 && string(data[pos-3:pos]) == "end" {
			continue
		}
		objStart := bytes.LastIndex(data[max(0, pos-4096):pos], []byte(" obj"))
		if objStart < 0 {
			continue
		}
		dict := data[max(0, pos-4096)+objStart : pos]
		if !reImageSubtype.Match(dict) {
			continue
		}
		body := pos + 6
		if body < len(data) && data[body] == '\r' {
			body++
		}
		if body < len(data) && data[body] == '\n' {
			body++
		}
		end := body + pdfInt(dict, reLength, -1)
		if m := reLength.FindSubmatch(dict); m != nil && bytes.HasSuffix(bytes.TrimSpace(m[0]), []byte("R")) {
			end = -1 // indirect length: fall back to endstream
		}
		if end <= body || end > len(data) {
			e := bytes.Index(data[body:], []byte("endstream"))
			if e < 0 {
				continue
			}
			end = body + e
		}
		raw := data[body:end]
		i = end
		n++
		label := fmt.Sprintf("%s > 이미지 %d", loc, n)
		img, err := decodePDFImage(dict, raw)
		if err != nil {
			unsupported++
			continue
		}
		x.addImage(label, img)
		if len(x.images) >= 200 {
			break
		}
	}
	if unsupported > 0 {
		x.addPDFRender(loc, data,
			fmt.Sprintf("이미지 %d개가 JBIG2/JPEG2000 등 형식 (렌더링 도구 없음, 검사 불가)", unsupported), false)
	}
}

var (
	reImageSubtype = regexp.MustCompile(`/Subtype\s*/Image`)
	reFilter       = regexp.MustCompile(`/Filter\s*(\[[^\]]*\]|/\w+)`)
	reLength       = regexp.MustCompile(`/Length\s+(\d+)(\s+\d+\s+R)?`)
	reWidth        = regexp.MustCompile(`/Width\s+(\d+)`)
	reHeight       = regexp.MustCompile(`/Height\s+(\d+)`)
	reBPC          = regexp.MustCompile(`/BitsPerComponent\s+(\d+)`)
	rePredictor    = regexp.MustCompile(`/Predictor\s+(\d+)`)
	reColumns      = regexp.MustCompile(`/Columns\s+(\d+)`)
)

func pdfInt(dict []byte, re *regexp.Regexp, def int) int {
	m := re.FindSubmatch(dict)
	if m == nil {
		return def
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return def
	}
	return n
}

var reFilterName = regexp.MustCompile(`/(\w+)`)

// decodePDFImage applies the stream's filter chain and returns an image
// file (JPEG as stored, or PNG built from raw pixels).
func decodePDFImage(dict, raw []byte) ([]byte, error) {
	var filters []string
	if m := reFilter.FindSubmatch(dict); m != nil {
		for _, f := range reFilterName.FindAllSubmatch(m[1], -1) {
			filters = append(filters, string(f[1]))
		}
	}
	data := raw
	for i, f := range filters {
		last := i == len(filters)-1
		var err error
		switch f {
		case "ASCII85Decode", "A85":
			data, err = decodeASCII85(data)
		case "ASCIIHexDecode", "AHx":
			data, err = decodeASCIIHex(data)
		case "FlateDecode", "Fl":
			var zr io.ReadCloser
			if zr, err = zlib.NewReader(bytes.NewReader(data)); err == nil {
				data, err = io.ReadAll(io.LimitReader(zr, 200<<20))
				if err != nil && len(data) > 0 {
					err = nil
				}
			}
		case "DCTDecode", "DCT":
			if !last {
				return nil, fmt.Errorf("DCT not last in chain")
			}
			return data, nil // a complete JPEG file
		case "CCITTFaxDecode", "CCF":
			if !last {
				return nil, fmt.Errorf("CCITT not last in chain")
			}
			img, err := ccittImage(dict, data)
			if err != nil {
				return nil, err
			}
			var buf bytes.Buffer
			if err := png.Encode(&buf, img); err != nil {
				return nil, err
			}
			return buf.Bytes(), nil
		default: // JBIG2Decode, CCITTFaxDecode, JPXDecode, RunLength, LZW...
			return nil, fmt.Errorf("unsupported filter %s", f)
		}
		if err != nil {
			return nil, err
		}
	}
	img, err := pixelsImage(dict, data)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var (
	reK    = regexp.MustCompile(`/K\s+(-?\d+)`)
	reRows = regexp.MustCompile(`/Rows\s+(\d+)`)
	reEBA  = regexp.MustCompile(`/EncodedByteAlign\s+(true|false)`)
)

// ccittImage decodes CCITT fax data (K<0: Group 4, K=0: Group 3 1-D).
// Mixed 2-D Group 3 (K>0) is left to page rendering.
func ccittImage(dict, data []byte) (*image.Gray, error) {
	k := pdfInt(dict, reK, 0)
	var sf ccitt.SubFormat
	switch {
	case k < 0:
		sf = ccitt.Group4
	case k == 0:
		sf = ccitt.Group3
	default:
		return nil, fmt.Errorf("CCITT K>0 not supported")
	}
	cols := pdfInt(dict, reColumns, pdfInt(dict, reWidth, 1728))
	rows := pdfInt(dict, reRows, pdfInt(dict, reHeight, 0))
	if cols <= 0 || rows <= 0 || cols*rows > 60_000_000 {
		return nil, fmt.Errorf("CCITT geometry")
	}
	opts := &ccitt.Options{Align: bytes.Contains(reEBA.Find(dict), []byte("true"))}
	img := image.NewGray(image.Rect(0, 0, cols, rows))
	if err := ccitt.DecodeIntoGray(img, bytes.NewReader(data), ccitt.MSB, sf, opts); err != nil {
		return nil, err
	}
	// BlackIs1 and /Decode arrays can flip polarity; OCR wants dark text on
	// a light page, and document pages are mostly white, so normalise by the
	// mean brightness instead of trusting the flags.
	sum := 0
	for _, v := range img.Pix {
		sum += int(v)
	}
	if sum/len(img.Pix) < 128 {
		for i := range img.Pix {
			img.Pix[i] = 255 - img.Pix[i]
		}
	}
	return img, nil
}

func decodeASCII85(b []byte) ([]byte, error) {
	b = bytes.TrimSpace(b)
	b = bytes.TrimPrefix(b, []byte("<~"))
	if i := bytes.Index(b, []byte("~>")); i >= 0 {
		b = b[:i]
	}
	out := make([]byte, 4*len(b)+4) // "z" expands one byte to four
	n, _, err := ascii85.Decode(out, b, true)
	return out[:n], err
}

func decodeASCIIHex(b []byte) ([]byte, error) {
	var clean []byte
	for _, c := range b {
		if c == '>' {
			break
		}
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			clean = append(clean, c)
		}
	}
	if len(clean)%2 == 1 {
		clean = append(clean, '0')
	}
	return hex.DecodeString(string(clean))
}

// pixelsImage builds an image from 8-bit Gray or RGB samples, undoing PNG
// predictors when present.
func pixelsImage(dict, pix []byte) (image.Image, error) {
	w, h := pdfInt(dict, reWidth, 0), pdfInt(dict, reHeight, 0)
	bpc := pdfInt(dict, reBPC, 8)
	if w <= 0 || h <= 0 || w*h > 60_000_000 || (bpc != 8 && bpc != 1) {
		return nil, fmt.Errorf("unsupported image geometry")
	}
	if bpc == 1 {
		return bilevelImage(dict, pix, w, h)
	}
	var err error
	pred := pdfInt(dict, rePredictor, 1)
	var comps int
	switch {
	case pred >= 10:
		// PNG predictors: every row starts with a filter-type byte.
		if c := len(pix)/h - 1; c == w || c == 3*w {
			comps = c / w
		}
	default:
		if len(pix) == w*h || len(pix) == 3*w*h {
			comps = len(pix) / (w * h)
		}
	}
	if comps == 0 {
		return nil, fmt.Errorf("unsupported colour space")
	}
	if pred >= 10 {
		if cols := pdfInt(dict, reColumns, w); cols != w {
			return nil, fmt.Errorf("predictor columns mismatch")
		}
		pix, err = unpredictPNG(pix, w*comps, comps, h)
		if err != nil {
			return nil, err
		}
	}
	if comps == 1 {
		img := image.NewGray(image.Rect(0, 0, w, h))
		copy(img.Pix, pix)
		return img, nil
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for p, q := 0, 0; p+2 < len(pix) && q+3 < len(img.Pix); p, q = p+3, q+4 {
		img.Pix[q], img.Pix[q+1], img.Pix[q+2], img.Pix[q+3] = pix[p], pix[p+1], pix[p+2], 0xFF
	}
	return img, nil
}

// bilevelImage unpacks 1-bit rows (MSB first, rows padded to a byte);
// 0 = black for DeviceGray. Polarity is normalised by mean brightness.
func bilevelImage(dict, pix []byte, w, h int) (image.Image, error) {
	stride := (w + 7) / 8
	if pdfInt(dict, rePredictor, 1) >= 10 {
		var err error
		if pix, err = unpredictPNG(pix, stride, 1, h); err != nil {
			return nil, err
		}
	}
	if len(pix) < stride*h {
		return nil, fmt.Errorf("short bilevel data")
	}
	img := image.NewGray(image.Rect(0, 0, w, h))
	white := 0
	for y := 0; y < h; y++ {
		row := pix[y*stride:]
		for x := 0; x < w; x++ {
			if row[x/8]&(0x80>>(x%8)) != 0 {
				img.Pix[y*w+x] = 0xFF
				white++
			}
		}
	}
	if white*2 < w*h {
		for i := range img.Pix {
			img.Pix[i] = 255 - img.Pix[i]
		}
	}
	return img, nil
}

// unpredictPNG reverses PNG row filters (None/Sub/Up/Average/Paeth).
func unpredictPNG(in []byte, stride, bpp, rows int) ([]byte, error) {
	if len(in) < rows*(stride+1) {
		return nil, fmt.Errorf("short predictor data")
	}
	out := make([]byte, rows*stride)
	prev := make([]byte, stride)
	for r := 0; r < rows; r++ {
		ft := in[r*(stride+1)]
		src := in[r*(stride+1)+1 : (r+1)*(stride+1)]
		cur := out[r*stride : (r+1)*stride]
		for i := 0; i < stride; i++ {
			var a, b, c byte
			if i >= bpp {
				a, c = cur[i-bpp], prev[i-bpp]
			}
			b = prev[i]
			switch ft {
			case 0:
				cur[i] = src[i]
			case 1:
				cur[i] = src[i] + a
			case 2:
				cur[i] = src[i] + b
			case 3:
				cur[i] = src[i] + byte((int(a)+int(b))/2)
			case 4:
				cur[i] = src[i] + paeth(a, b, c)
			default:
				return nil, fmt.Errorf("bad PNG filter %d", ft)
			}
		}
		prev = cur
	}
	return out, nil
}

func paeth(a, b, c byte) byte {
	p := int(a) + int(b) - int(c)
	pa, pb, pc := abs(p-int(a)), abs(p-int(b)), abs(p-int(c))
	switch {
	case pa <= pb && pa <= pc:
		return a
	case pb <= pc:
		return b
	}
	return c
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
