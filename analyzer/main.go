// Command analyzer is secmail's standalone attachment-analysis worker.
//
// It implements the analyzer contract (secmail docs/analyzer-contract.md):
// it consumes analysis jobs from the Redis queues, fetches each quarantined
// attachment over the internal API, runs the malengine engine over the bytes
// (via the shared scan package), and posts a verdict back — by HTTP POST to the
// job's verdict_url or by LPUSH to the results list.
//
// Run several replicas to scale: they BRPOP the same shared queue.
//
// It is a drop-in replacement for cmd/mock-analyzer. It shares its analysis and
// verdict-mapping logic with secmail's in-process analyzer (secmail built with
// -tags malengine) through the scan package. Unlike the mock it needs libyara
// at build/run time (see the Dockerfile).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/yiyuhki/p2/analyzer/scan"
)

// job is the unit of work published by secmail (docs/analyzer-contract.md).
// It is declared here, not imported, so this worker is an independent module.
type job struct {
	Version      int    `json:"version"`
	AttachmentID string `json:"attachment_id"`
	MessageID    string `json:"message_id"`
	Filename     string `json:"filename"`
	ContentType  string `json:"content_type"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	ContentURL   string `json:"content_url"`
	VerdictURL   string `json:"verdict_url"`
	Attempt      int    `json:"attempt"`
}

// verdict is what we report back to secmail.
type verdict struct {
	AttachmentID string          `json:"attachment_id"`
	Status       string          `json:"status"`
	ThreatName   string          `json:"threat_name,omitempty"`
	Detail       json.RawMessage `json:"detail,omitempty"`
}

type worker struct {
	sc       *scan.Scanner
	log      *slog.Logger
	token    string
	fetchCap int64
	httpc    *http.Client
}

func main() {
	var (
		redisAddr   = flag.String("redis", "localhost:6379", "redis address")
		prefix      = flag.String("prefix", "secmail", "queue key prefix")
		apiToken    = flag.String("token", os.Getenv("SECMAIL_INTERNAL_TOKEN"), "internal API bearer token")
		viaRedis    = flag.Bool("reply-redis", false, "push verdicts to the Redis results list instead of HTTP")
		yaraDir     = flag.String("yara-dir", os.Getenv("MALENGINE_YARA_DIR"), "directory of YARA rules (empty: engine default / skip YARA)")
		threatIntel = flag.Bool("threat-intel", false, "enable outbound threat-intel lookups (abuse.ch, VirusTotal)")
		sandbox     = flag.Bool("sandbox", false, "enable the dynamic sandbox stage (needs Docker/Firecracker)")
		blockLevel  = flag.String("block-level", "suspicious", "block at this verdict level or worse: clean|suspicious|likely|malicious")
		maxSize     = flag.Int64("max-size", 0, "max attachment size in bytes the engine will analyze (0: engine default)")
		tmpDir      = flag.String("tmp-dir", "", "scratch directory for AnalyzeBytes (empty: OS temp)")
		fetchCap    = flag.Int64("fetch-limit", 256<<20, "max bytes to download per attachment")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	opts := scan.Options{
		ThreatIntelEnabled: *threatIntel,
		SandboxEnabled:     *sandbox,
		TempDir:            *tmpDir,
		MaxFileSize:        *maxSize,
		BlockLevel:         *blockLevel,
	}
	if *yaraDir != "" {
		opts.YaraRuleDirs = []string{*yaraDir}
	}
	sc, err := scan.New(opts)
	if err != nil {
		log.Error("engine init", "err", err)
		os.Exit(1)
	}

	w := &worker{
		sc:       sc,
		log:      log,
		token:    *apiToken,
		fetchCap: *fetchCap,
		httpc:    &http.Client{Timeout: 60 * time.Second},
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rdb := redis.NewClient(&redis.Options{Addr: *redisAddr})
	high, normal, results := *prefix+":jobs:high", *prefix+":jobs:normal", *prefix+":results"
	log.Info("analyzer started",
		"queues", []string{high, normal},
		"yara", sc.YaraAvailable(),
		"sandbox", *sandbox,
		"threat_intel", *threatIntel,
		"block_level", strings.ToUpper(*blockLevel))

	for ctx.Err() == nil {
		res, err := rdb.BRPop(ctx, 5*time.Second, high, normal).Result()
		if err != nil {
			continue // timeout or shutdown
		}
		var j job
		if err := json.Unmarshal([]byte(res[1]), &j); err != nil {
			log.Warn("bad job", "err", err)
			continue
		}
		v := w.analyze(ctx, j)
		log.Info("analyzed", "attachment", j.AttachmentID, "file", j.Filename, "status", v.Status, "threat", v.ThreatName)

		if *viaRedis || j.VerdictURL == "" {
			b, _ := json.Marshal(v)
			if err := rdb.LPush(ctx, results, b).Err(); err != nil {
				log.Error("push result", "err", err)
			}
			continue
		}
		if err := w.postVerdict(ctx, j.VerdictURL, v); err != nil {
			log.Error("post verdict", "err", err)
		}
	}
}

// analyze fetches the attachment and scans it, mapping the result onto the
// contract's status. On a fetch failure it returns ERROR so secmail fails
// closed (blocks the download).
func (w *worker) analyze(ctx context.Context, j job) verdict {
	v := verdict{AttachmentID: j.AttachmentID}
	var r scan.Result
	if data, err := w.fetch(ctx, j); err != nil {
		r = scan.ErrorResult("fetch", err)
	} else {
		r = w.sc.Scan(ctx, j.Filename, data)
	}
	v.Status, v.ThreatName, v.Detail = r.Status, r.ThreatName, r.Detail
	return v
}

// fetch downloads the attachment bytes from the internal API's content_url.
func (w *worker) fetch(ctx context.Context, j job) ([]byte, error) {
	if j.ContentURL == "" {
		return nil, fmt.Errorf("job has no content_url (set secmail internal_api.advertise_url)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.ContentURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	resp, err := w.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("content: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, w.fetchCap))
}

// postVerdict reports the verdict over HTTP. 2xx and 409 (already finalized,
// idempotent) are treated as success.
func (w *worker) postVerdict(ctx context.Context, url string, v verdict) error {
	b, _ := json.Marshal(v)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 == 2 || resp.StatusCode == http.StatusConflict {
		return nil
	}
	return fmt.Errorf("verdict: HTTP %d", resp.StatusCode)
}
