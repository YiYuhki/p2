package webhook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileDeadLetterAppends(t *testing.T) {
	if NewFileDeadLetter("") != nil {
		t.Fatal("empty path should disable the sink")
	}
	path := filepath.Join(t.TempDir(), "dlq.jsonl")
	f := NewFileDeadLetter(path)
	f.Fail(Event{Type: "dlp_outbound", Action: "block"}, nil, "status 502")
	f.Fail(Event{Type: "inbound_verdict", Status: "MALICIOUS"}, nil, "dial tcp: timeout")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 dead-letter lines, got %d", len(lines))
	}
	var rec deadLetterRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("line not JSON: %v", err)
	}
	if rec.Event.Action != "block" || rec.LastErr != "status 502" || rec.FailedAt.IsZero() {
		t.Fatalf("record fields: %+v", rec)
	}
}
