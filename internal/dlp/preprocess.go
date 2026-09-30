package dlp

import (
	"image"
	"math"
)

// preprocessGray improves a grayscale image for OCR: it stretches contrast
// and corrects small page skew (common in phone photos and scans). It is a
// no-op-ish transform for already-clean screenshots.
func preprocessGray(g *image.Gray) *image.Gray {
	g = stretchContrast(g)
	if angle := estimateSkew(g); math.Abs(angle) >= 0.3 {
		g = rotateGray(g, angle)
	}
	return g
}

// stretchContrast linearly rescales intensities between the 2nd and 98th
// percentile to [0,255], lifting faint photos without blowing out noise.
func stretchContrast(g *image.Gray) *image.Gray {
	var hist [256]int
	for _, v := range g.Pix {
		hist[v]++
	}
	n := len(g.Pix)
	if n == 0 {
		return g
	}
	lo, hi := percentile(hist[:], n, 0.02), percentile(hist[:], n, 0.98)
	if hi <= lo {
		return g
	}
	var lut [256]uint8
	scale := 255.0 / float64(hi-lo)
	for i := range lut {
		switch {
		case i <= lo:
			lut[i] = 0
		case i >= hi:
			lut[i] = 255
		default:
			lut[i] = uint8(float64(i-lo) * scale)
		}
	}
	out := image.NewGray(g.Bounds())
	for i, v := range g.Pix {
		out.Pix[i] = lut[v]
	}
	return out
}

func percentile(hist []int, total int, p float64) int {
	target := int(float64(total) * p)
	acc := 0
	for i, c := range hist {
		acc += c
		if acc >= target {
			return i
		}
	}
	return 255
}

// estimateSkew finds the small rotation (degrees, [-8,8]) that best aligns
// text rows, by maximising the variance of the horizontal projection profile
// (row ink counts) — sharp peaks mean rows are horizontal. It works on a
// downscaled binarised copy so it stays cheap.
func estimateSkew(g *image.Gray) float64 {
	small := downscaleForSkew(g)
	th := otsu(small)
	w, h := small.Bounds().Dx(), small.Bounds().Dy()
	if w < 16 || h < 16 {
		return 0
	}
	ink := make([]bool, w*h)
	any := false
	for i, v := range small.Pix {
		if v < th {
			ink[i] = true
			any = true
		}
	}
	if !any {
		return 0
	}
	best, bestScore := 0.0, -1.0
	for a := -8.0; a <= 8.0; a += 0.5 {
		if sc := projectionScore(ink, w, h, a); sc > bestScore {
			bestScore, best = sc, a
		}
	}
	return best
}

// projectionScore rotates row indices by angle and returns the variance of
// per-row ink counts (higher = rows better aligned).
func projectionScore(ink []bool, w, h int, angleDeg float64) float64 {
	tan := math.Tan(angleDeg * math.Pi / 180)
	rows := make([]int, 2*h+1)
	off := h
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if !ink[y*w+x] {
				continue
			}
			ry := y + int(float64(x-w/2)*tan)
			if idx := ry + off; idx >= 0 && idx < len(rows) {
				rows[idx]++
			}
		}
	}
	var mean, varr float64
	for _, c := range rows {
		mean += float64(c)
	}
	mean /= float64(len(rows))
	for _, c := range rows {
		d := float64(c) - mean
		varr += d * d
	}
	return varr
}

// downscaleForSkew returns a copy at most 1000 px on the long side (nearest
// neighbour is fine for a skew estimate).
func downscaleForSkew(g *image.Gray) *image.Gray {
	w, h := g.Bounds().Dx(), g.Bounds().Dy()
	long := max(w, h)
	if long <= 1000 {
		return g
	}
	s := float64(1000) / float64(long)
	nw, nh := int(float64(w)*s), int(float64(h)*s)
	out := image.NewGray(image.Rect(0, 0, nw, nh))
	for y := 0; y < nh; y++ {
		sy := int(float64(y) / s)
		for x := 0; x < nw; x++ {
			sx := int(float64(x) / s)
			out.Pix[y*nw+x] = g.Pix[sy*g.Stride+sx]
		}
	}
	return out
}

// otsu returns the intensity threshold separating fore/background.
func otsu(g *image.Gray) uint8 {
	var hist [256]int
	for _, v := range g.Pix {
		hist[v]++
	}
	total := len(g.Pix)
	var sum float64
	for i, c := range hist {
		sum += float64(i * c)
	}
	var sumB, wB float64
	var maxVar float64
	threshold := 128
	for i := 0; i < 256; i++ {
		wB += float64(hist[i])
		if wB == 0 {
			continue
		}
		wF := float64(total) - wB
		if wF == 0 {
			break
		}
		sumB += float64(i * hist[i])
		mB := sumB / wB
		mF := (sum - sumB) / wF
		between := wB * wF * (mB - mF) * (mB - mF)
		if between > maxVar {
			maxVar = between
			threshold = i
		}
	}
	return uint8(threshold)
}

// rotateGray rotates around the centre by angleDeg (small angles), filling
// exposed corners with white, using bilinear sampling.
func rotateGray(g *image.Gray, angleDeg float64) *image.Gray {
	w, h := g.Bounds().Dx(), g.Bounds().Dy()
	rad := angleDeg * math.Pi / 180
	sin, cos := math.Sin(rad), math.Cos(rad)
	cx, cy := float64(w)/2, float64(h)/2
	out := image.NewGray(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			sx := cx + dx*cos + dy*sin
			sy := cy - dx*sin + dy*cos
			out.Pix[y*out.Stride+x] = sampleBilinear(g, sx, sy)
		}
	}
	return out
}

func sampleBilinear(g *image.Gray, fx, fy float64) uint8 {
	w, h := g.Bounds().Dx(), g.Bounds().Dy()
	if fx < 0 || fy < 0 || fx > float64(w-1) || fy > float64(h-1) {
		return 255 // white background
	}
	x0, y0 := int(fx), int(fy)
	x1, y1 := min(x0+1, w-1), min(y0+1, h-1)
	ax, ay := fx-float64(x0), fy-float64(y0)
	p := func(x, y int) float64 { return float64(g.Pix[y*g.Stride+x]) }
	top := p(x0, y0)*(1-ax) + p(x1, y0)*ax
	bot := p(x0, y1)*(1-ax) + p(x1, y1)*ax
	return uint8(top*(1-ay) + bot*ay)
}
