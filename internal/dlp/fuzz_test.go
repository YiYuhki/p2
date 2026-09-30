package dlp

import (
	"strings"
	"testing"
)

// FuzzScanText feeds arbitrary text to the DLP detectors: outgoing mail bodies
// and extracted attachment text are attacker-influenced, so scanning must never
// panic and must never leak an unmasked raw value into a finding sample.
func FuzzScanText(f *testing.F) {
	seeds := []string{
		"",
		"900101-1234567",
		"카드 4111 1111 1111 1111",
		"AKIAIOSFODNN7EXAMPLE",
		"여권 M12345678 계좌 국민 123-45-678901 예금주 홍길동",
		"password=hunter2 api_key: sk-abcdefghijklmnop",
		strings.Repeat("010-1234-5678\n", 50),
		"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	s, err := NewScanner(Options{CombinePII: true, CombineMinPII: 2, CombineBulk: 20})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, text string) {
		findings := s.ScanText("fuzz", text)
		for _, fd := range findings {
			for _, sample := range fd.Samples {
				// A sample must be masked: it should not reproduce a long
				// verbatim run of the input's sensitive digits.
				if len(sample) > 0 && !strings.ContainsAny(sample, "*·… ") &&
					strings.Contains(text, sample) && len(sample) >= 12 &&
					fd.Detector != "pii_combination" {
					// Allow structured tokens (e.g. detector names) but flag a
					// long raw echo of the input.
					if isMostlyDigits(sample) {
						t.Fatalf("unmasked value leaked in sample: detector=%s sample=%q", fd.Detector, sample)
					}
				}
			}
		}
	})
}

func isMostlyDigits(s string) bool {
	d := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			d++
		}
	}
	return d*2 >= len(s)
}
