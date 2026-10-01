//go:build malengine

package main

import (
	"context"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"log/slog"

	"github.com/yiyuhki/p2/internal/config"
	"github.com/yiyuhki/p2/internal/mimeproc"
	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/queue"
	"github.com/yiyuhki/p2/internal/service"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
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

// End-to-end: a quarantined EICAR attachment is enqueued (memory queue),
// consumed and scanned by the in-process analyzer, and the verdict is applied
// to the store as MALICIOUS — exercising the same scan code the external worker
// uses, over queue.ConsumeJobs.
func TestInProcAnalyzerEndToEnd(t *testing.T) {
	const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

	st := store.NewMemory()
	obj, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatalf("NewFS: %v", err)
	}
	q := queue.NewMemory()
	svc := service.New(st, obj, q, service.Options{LinkTTL: time.Hour, MaxAttempts: 3}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	cfg := config.AnalyzerConfig{Enabled: true, YaraDir: rulesDir(t), BlockLevel: "suspicious"}
	if err := startInProcAnalyzer(ctx, &wg, cfg, q, svc, obj, slog.Default()); err != nil {
		t.Fatalf("startInProcAnalyzer: %v", err)
	}

	links, err := svc.Quarantine(ctx, &model.Message{ID: "m1", MessageID: "<m1@test>"},
		[]*mimeproc.Extracted{{Filename: "invoice.com", ContentType: "application/octet-stream", Data: []byte(eicar)}})
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("got %d links, want 1", len(links))
	}
	id := links[0].AttachmentID

	// Wait for the in-process analyzer to drive the attachment to a verdict.
	deadline := time.After(30 * time.Second)
	for {
		att, err := st.GetAttachment(ctx, id)
		if err != nil {
			t.Fatalf("GetAttachment: %v", err)
		}
		if att.Status.Final() {
			if att.Status != model.StatusMalicious {
				t.Fatalf("status = %q, want MALICIOUS", att.Status)
			}
			if att.ThreatName == "" {
				t.Error("malicious verdict has no threat name")
			}
			return
		}
		select {
		case <-deadline:
			t.Fatalf("attachment still %q after timeout", att.Status)
		case <-time.After(50 * time.Millisecond):
		}
	}
}
