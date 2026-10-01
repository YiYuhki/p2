package main

import (
	"context"
	"log/slog"
	"sync"

	"github.com/yiyuhki/p2/internal/config"
	"github.com/yiyuhki/p2/internal/queue"
	"github.com/yiyuhki/p2/internal/service"
	"github.com/yiyuhki/p2/internal/storage"
)

// startInProcAnalyzer launches the optional in-process attachment analyzer,
// which embeds the malengine engine. It is set only in the build tagged
// `malengine` (see analyzer_malengine.go); in the default pure-Go build it is
// nil, so secmail carries no analysis engine (no cgo/libyara) and relies on the
// external analyzer worker. It returns after spawning its goroutines, which run
// until ctx is cancelled and are tracked by wg.
var startInProcAnalyzer func(ctx context.Context, wg *sync.WaitGroup, cfg config.AnalyzerConfig, q queue.Queue, svc *service.Service, obj storage.Storage, log *slog.Logger) error
