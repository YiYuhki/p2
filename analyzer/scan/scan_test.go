package scan

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	p1 "github.com/YiYuhki/p1/analyzer"
)

// rulesDir locates malengine's bundled YARA rules via the replace path.
func rulesDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "p1", "rules", "yara")
}

func newScanner(t *testing.T) *Scanner {
	t.Helper()
	sc, err := New(Options{YaraRuleDirs: []string{rulesDir(t)}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !sc.YaraAvailable() {
		t.Fatal("YARA rules did not load")
	}
	return sc
}

func TestParseBlockLevel(t *testing.T) {
	cases := map[string]int{
		"":                 p1.Rank(p1.Suspicious), // default
		"clean":            p1.Rank(p1.Clean),
		"SUSPICIOUS":       p1.Rank(p1.Suspicious),
		"likely":           p1.Rank(p1.LikelyMalicious),
		"likely_malicious": p1.Rank(p1.LikelyMalicious),
		"malicious":        p1.Rank(p1.Malicious),
	}
	for in, want := range cases {
		got, ok := ParseBlockLevel(in)
		if !ok || got != want {
			t.Errorf("ParseBlockLevel(%q) = %d,%v; want %d,true", in, got, ok, want)
		}
	}
	if _, ok := ParseBlockLevel("nonsense"); ok {
		t.Error("ParseBlockLevel accepted an invalid level")
	}
}

func TestNewRejectsBadBlockLevel(t *testing.T) {
	if _, err := New(Options{BlockLevel: "nope"}); err == nil {
		t.Fatal("New accepted an invalid block level")
	}
}

func TestScanBlocksEICAR(t *testing.T) {
	const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	sc := newScanner(t)
	r := sc.Scan(context.Background(), "x.com", []byte(eicar))
	if r.Status != StatusMalicious {
		t.Fatalf("status = %q, want MALICIOUS", r.Status)
	}
	if r.ThreatName == "" {
		t.Error("blocked result has no threat name")
	}
	if !json.Valid(r.Detail) {
		t.Error("detail is not valid JSON")
	}
}

func TestScanAllowsBenign(t *testing.T) {
	sc := newScanner(t)
	r := sc.Scan(context.Background(), "note.txt", []byte("just a harmless note\n"))
	if r.Status != StatusClean {
		t.Fatalf("status = %q, want CLEAN", r.Status)
	}
}

func TestErrorResultFailsClosed(t *testing.T) {
	r := ErrorResult("fetch", context.DeadlineExceeded)
	if r.Status != StatusError {
		t.Fatalf("status = %q, want ERROR", r.Status)
	}
	if !json.Valid(r.Detail) {
		t.Error("error detail is not valid JSON")
	}
}

func TestBuildDetailFull(t *testing.T) {
	rep := &p1.Report{EngineVersion: "x"}
	rep.Verdict.Level = p1.Clean
	detail := buildDetail(rep)
	var m map[string]any
	if err := json.Unmarshal(detail, &m); err != nil {
		t.Fatalf("detail not JSON: %v", err)
	}
	if _, truncated := m["truncated"]; truncated {
		t.Error("small report should not be truncated")
	}
	if _, hasVerdict := m["verdict"]; !hasVerdict {
		t.Error("full report detail should carry the verdict object")
	}
}

func TestBuildDetailTruncates(t *testing.T) {
	rep := &p1.Report{EngineVersion: "x"}
	rep.Verdict.Level = p1.Malicious
	rep.Verdict.Summary = strings.Repeat("A", maxDetailBytes+1024) // force oversize
	detail := buildDetail(rep)
	if len(detail) > maxDetailBytes {
		t.Errorf("truncated detail is still %d bytes (cap %d)", len(detail), maxDetailBytes)
	}
	var m map[string]any
	if err := json.Unmarshal(detail, &m); err != nil {
		t.Fatalf("detail not JSON: %v", err)
	}
	if m["truncated"] != true {
		t.Error("oversize report should be marked truncated")
	}
}
