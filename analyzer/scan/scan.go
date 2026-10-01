// Package scan runs the malengine engine (github.com/YiYuhki/p1) over
// attachment bytes and maps the result onto secmail's verdict contract
// (CLEAN / MALICIOUS / ERROR, see secmail docs/analyzer-contract.md).
//
// It is the shared core used by BOTH deployment shapes:
//   - the standalone Redis worker (this module's main), and
//   - secmail's in-process analyzer (secmail built with -tags malengine).
//
// Only the transport differs between the two (Redis + HTTP vs. a direct
// in-process call); the analysis and the verdict mapping live here so both
// behave identically.
//
// malengine links libyara via cgo, so importing this package pulls in that
// build dependency.
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	p1 "github.com/YiYuhki/p1/analyzer"
)

// Verdict statuses, per secmail's analyzer contract.
const (
	StatusClean     = "CLEAN"
	StatusMalicious = "MALICIOUS"
	StatusError     = "ERROR"
)

// maxDetailBytes keeps the detail under secmail's 64 KiB verdict cap with room
// to spare; a larger report is replaced by a compact summary.
const maxDetailBytes = 60 << 10

// Result is the engine's conclusion expressed in secmail's terms. The caller
// copies these three fields into whatever verdict type its transport uses.
type Result struct {
	Status     string
	ThreatName string
	Detail     json.RawMessage
}

// Options configures a Scanner. Empty/zero fields fall back to engine defaults.
type Options struct {
	YaraRuleDirs       []string
	ThreatIntelEnabled bool
	SandboxEnabled     bool
	MaxFileSize        int64
	TempDir            string
	// BlockLevel is the lowest malengine verdict level that maps to MALICIOUS:
	// clean | suspicious | likely | malicious. Empty defaults to suspicious
	// (fail-safe for a mail gateway).
	BlockLevel string
}

// Scanner is a reusable, concurrency-safe attachment scanner.
type Scanner struct {
	eng       *p1.Engine
	blockRank int
}

// New builds a Scanner from opts.
func New(opts Options) (*Scanner, error) {
	rank, ok := ParseBlockLevel(opts.BlockLevel)
	if !ok {
		return nil, fmt.Errorf("invalid block level %q (want clean|suspicious|likely|malicious)", opts.BlockLevel)
	}
	eo := p1.DefaultOptions()
	eo.ThreatIntelEnabled = opts.ThreatIntelEnabled
	eo.SandboxEnabled = opts.SandboxEnabled
	eo.TempDir = opts.TempDir
	if len(opts.YaraRuleDirs) > 0 {
		eo.YaraRuleDirs = opts.YaraRuleDirs
	}
	if opts.MaxFileSize > 0 {
		eo.MaxFileSize = opts.MaxFileSize
	}
	eng, err := p1.New(eo)
	if err != nil {
		return nil, err
	}
	return &Scanner{eng: eng, blockRank: rank}, nil
}

// YaraAvailable reports whether YARA rules compiled and loaded.
func (s *Scanner) YaraAvailable() bool { return s.eng.YaraAvailable() }

// Scan analyzes data (named filename, used only for the extension) and maps the
// engine verdict to a Result. A verdict at or above the block level yields
// MALICIOUS; below it, CLEAN. An engine failure yields ERROR so secmail fails
// closed.
func (s *Scanner) Scan(ctx context.Context, filename string, data []byte) Result {
	rep, err := s.eng.AnalyzeBytes(ctx, filename, data)
	if err != nil {
		return ErrorResult("analyze", err)
	}
	r := Result{Detail: buildDetail(rep)}
	if p1.Rank(rep.Verdict.Level) >= s.blockRank {
		r.Status = StatusMalicious
		if r.ThreatName = p1.ThreatName(rep); r.ThreatName == "" {
			r.ThreatName = string(rep.Verdict.Level)
		}
	} else {
		r.Status = StatusClean
	}
	return r
}

// ErrorResult builds a fail-closed ERROR result with a diagnostic detail,
// for a failure the caller hits before/around analysis (e.g. a fetch error).
func ErrorResult(stage string, err error) Result {
	b, _ := json.Marshal(map[string]any{"engine": "malengine", "error": stage + ": " + err.Error()})
	return Result{Status: StatusError, Detail: b}
}

// ParseBlockLevel maps a level name to its rank. Empty means the default
// (suspicious).
func ParseBlockLevel(s string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "suspicious":
		return p1.Rank(p1.Suspicious), true
	case "clean":
		return p1.Rank(p1.Clean), true
	case "likely", "likely_malicious", "likely-malicious":
		return p1.Rank(p1.LikelyMalicious), true
	case "malicious":
		return p1.Rank(p1.Malicious), true
	}
	return 0, false
}

// buildDetail returns the full report JSON when it fits under the verdict-size
// cap, otherwise a compact summary that links the key evidence.
func buildDetail(rep *p1.Report) json.RawMessage {
	if full, err := p1.CompactJSON(rep); err == nil && len(full) <= maxDetailBytes {
		return full
	}
	type reason struct {
		RuleID   string  `json:"rule_id"`
		Category string  `json:"category"`
		Points   float64 `json:"points"`
	}
	reasons := rep.Verdict.Reasons
	if len(reasons) > 10 {
		reasons = reasons[:10]
	}
	top := make([]reason, 0, len(reasons))
	for _, r := range reasons {
		top = append(top, reason{r.RuleID, r.Category, r.Points})
	}
	techniques := make([]string, 0, len(rep.Techniques))
	for _, t := range rep.Techniques {
		techniques = append(techniques, t.ID)
	}
	sum := map[string]any{
		"engine":            "malengine",
		"version":           rep.EngineVersion,
		"level":             rep.Verdict.Level,
		"score":             rep.Verdict.Score,
		"summary":           clip(rep.Verdict.Summary, 4096),
		"top_reasons":       top,
		"attack_techniques": techniques,
		"truncated":         true,
	}
	if rep.Static != nil {
		sum["sha256"] = rep.Static.Hashes.SHA256
	}
	b, _ := json.Marshal(sum)
	return b
}

// clip truncates s to at most n bytes, on a UTF-8 boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
