package dlp

import (
	"fmt"
	"strings"
	"testing"
)

// benchText is ~1 MB of ordinary business mail / spreadsheet-like text.
func benchText() string {
	var b strings.Builder
	for i := 0; b.Len() < 1<<20; i++ {
		fmt.Fprintf(&b, "안녕하세요, 주문번호 %d 건 관련하여 회의 일정(2026-10-%02d 14:00)을 공유드립니다. "+
			"담당: 김철수 과장 / 내선 %04d / 금액 1,234,%03d원, 참고 https://intranet.example.com/docs/%d\n",
			100000+i, i%28+1, i%10000, i%1000, i)
	}
	return b.String()
}

func BenchmarkScanText(b *testing.B) {
	s, _ := NewScanner(Options{})
	text := benchText()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ScanText("x", text)
	}
}

func BenchmarkPerDetector(b *testing.B) {
	text := benchText()
	for _, d := range Builtin() {
		b.Run(d.ID, func(b *testing.B) {
			s := &Scanner{detectors: []*Detector{d}}
			_ = s
			b.SetBytes(int64(len(text)))
			for i := 0; i < b.N; i++ {
				s.ScanText("x", text)
			}
		})
	}
}
