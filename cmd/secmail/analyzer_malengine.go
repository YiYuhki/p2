//go:build malengine

// This file is compiled only with `-tags malengine`. It embeds the malengine
// engine (github.com/YiYuhki/p1, via the shared scan package), so this build of
// secmail links libyara through cgo. The default build omits it and stays pure
// Go, delegating analysis to the external worker (p2/analyzer).
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"

	"github.com/yiyuhki/p2/analyzer/scan"
	"github.com/yiyuhki/p2/internal/config"
	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/queue"
	"github.com/yiyuhki/p2/internal/service"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
)

func init() { startInProcAnalyzer = runInProcAnalyzer }

// inProcFetchCap bounds how many bytes are read from storage per attachment.
const inProcFetchCap = 256 << 20

// runInProcAnalyzer consumes analysis jobs from the queue, scans each
// attachment with the shared scan package (same logic as the external worker),
// and applies the verdict in-process. It works with both the redis and memory
// queues because it drives queue.ConsumeJobs.
func runInProcAnalyzer(ctx context.Context, wg *sync.WaitGroup, cfg config.AnalyzerConfig, q queue.Queue, svc *service.Service, obj storage.Storage, log *slog.Logger) error {
	opts := scan.Options{
		ThreatIntelEnabled: cfg.ThreatIntel,
		SandboxEnabled:     cfg.Sandbox,
		MaxFileSize:        cfg.MaxFileSize,
		BlockLevel:         cfg.BlockLevel,
	}
	if cfg.YaraDir != "" {
		opts.YaraRuleDirs = []string{cfg.YaraDir}
	}
	sc, err := scan.New(opts)
	if err != nil {
		return err
	}

	workers := cfg.Workers
	if workers <= 0 {
		workers = 1
	}
	log.Info("in-process analyzer started",
		"workers", workers, "yara", sc.YaraAvailable(),
		"sandbox", cfg.Sandbox, "threat_intel", cfg.ThreatIntel)

	handler := func(ctx context.Context, j model.Job) error {
		var r scan.Result
		if data, err := readObject(ctx, obj, j.Storage.Key); err != nil {
			r = scan.ErrorResult("fetch", err)
		} else {
			r = sc.Scan(ctx, j.Filename, data)
		}
		v := model.Verdict{
			AttachmentID: j.AttachmentID,
			Status:       model.Status(r.Status),
			ThreatName:   r.ThreatName,
			Detail:       r.Detail,
		}
		// ErrConflict means the attachment already has a final verdict
		// (idempotent); anything else is left for the stale-job sweep.
		if err := svc.ApplyVerdict(ctx, v); err != nil && !errors.Is(err, store.ErrConflict) {
			log.Warn("in-process verdict apply failed", "attachment", j.AttachmentID, "err", err)
		}
		return nil
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q.ConsumeJobs(ctx, handler)
		}()
	}
	return nil
}

func readObject(ctx context.Context, obj storage.Storage, key string) ([]byte, error) {
	rc, err := obj.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, inProcFetchCap))
}
