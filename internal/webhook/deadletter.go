package webhook

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// FileDeadLetter appends one JSON line per permanently-failed webhook event to
// a file, so deliveries that exhaust their retries can be inspected and
// replayed instead of being lost. It is safe for concurrent use.
type FileDeadLetter struct {
	mu   sync.Mutex
	path string
}

// NewFileDeadLetter returns a sink writing to path, or nil when path is empty.
func NewFileDeadLetter(path string) *FileDeadLetter {
	if path == "" {
		return nil
	}
	return &FileDeadLetter{path: path}
}

// deadLetterRecord is the line written: the original event plus failure context.
type deadLetterRecord struct {
	FailedAt time.Time `json:"failed_at"`
	LastErr  string    `json:"last_err"`
	Event    Event     `json:"event"`
}

// Fail appends ev to the dead-letter file. A nil receiver is a no-op.
func (f *FileDeadLetter) Fail(ev Event, _ []byte, lastErr string) {
	if f == nil {
		return
	}
	line, err := json.Marshal(deadLetterRecord{FailedAt: time.Now().UTC(), LastErr: lastErr, Event: ev})
	if err != nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	fh, err := os.OpenFile(f.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer fh.Close()
	fh.Write(append(line, '\n'))
}
