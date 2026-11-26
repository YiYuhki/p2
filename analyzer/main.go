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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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
	apiBase  *url.URL // the bearer token is only ever sent below this URL
	fetchCap int64
	httpc    *http.Client
}

func main() {
	var (
		redisAddr   = flag.String("redis", "localhost:6379", "redis address")
		redisPass   = flag.String("redis-password", os.Getenv("SECMAIL_REDIS_PASSWORD"), "redis password (default $SECMAIL_REDIS_PASSWORD)")
		prefix      = flag.String("prefix", "secmail", "queue key prefix")
		apiToken    = flag.String("token", os.Getenv("SECMAIL_INTERNAL_TOKEN"), "internal API bearer token")
		apiBase     = flag.String("api-base", os.Getenv("SECMAIL_API_BASE"), "secmail internal API base URL (e.g. http://secmail:8081); the token is only sent to content/verdict URLs under it")
		viaRedis    = flag.Bool("reply-redis", false, "push verdicts to the Redis results list instead of HTTP")
		yaraDir     = flag.String("yara-dir", os.Getenv("MALENGINE_YARA_DIR"), "directory of YARA rules (empty: engine default / skip YARA)")
		threatIntel = flag.Bool("threat-intel", false, "enable outbound threat-intel lookups (abuse.ch, VirusTotal)")
		sandbox     = flag.Bool("sandbox", false, "enable the dynamic sandbox stage (needs Docker/Firecracker)")
		blockLevel  = flag.String("block-level", "suspicious", "block at this verdict level or worse: clean|suspicious|likely|malicious")
		maxSize     = flag.Int64("max-size", 0, "max attachment size in bytes the engine will analyze (0: engine default)")
		tmpDir      = flag.String("tmp-dir", "", "scratch directory for AnalyzeBytes (empty: OS temp)")
		fetchCap    = flag.Int64("fetch-limit", 256<<20, "max bytes to download per attachment (larger attachments get an ERROR verdict)")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	base, err := parseAPIBase(*apiBase)
	if err != nil {
		log.Error("invalid -api-base", "err", err)
		os.Exit(2)
	}

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
		apiBase:  base,
		fetchCap: *fetchCap,
		httpc:    &http.Client{Timeout: 60 * time.Second},
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rdb := redis.NewClient(&redis.Options{Addr: *redisAddr, Password: *redisPass})
	high, normal, results := *prefix+":jobs:high", *prefix+":jobs:normal", *prefix+":results"
	log.Info("analyzer started",
		"queues", []string{high, normal},
		"api_base", base.String(),
		"yara", sc.YaraAvailable(),
		"sandbox", *sandbox,
		"threat_intel", *threatIntel,
		"block_level", strings.ToUpper(*blockLevel))

	var backoff time.Duration
	for ctx.Err() == nil {
		res, err := rdb.BRPop(ctx, 5*time.Second, high, normal).Result()
		if ctx.Err() != nil {
			break
		}
		if errors.Is(err, redis.Nil) {
			backoff = 0
			continue // timeout: nothing queued
		}
		if err != nil {
			// Redis down / auth failure: back off instead of spinning.
			backoff = nextBackoff(backoff)
			log.Error("brpop failed", "err", err, "retry_in", backoff)
			sleepCtx(ctx, backoff)
			continue
		}
		backoff = 0
		var j job
		if err := json.Unmarshal([]byte(res[1]), &j); err != nil {
			log.Warn("bad job", "err", err)
			continue
		}
		v, ok := w.analyze(ctx, j)
		if !ok {
			// Transient failure: post nothing. The attachment stays PENDING
			// and secmail's stale-job sweep re-queues it.
			continue
		}
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

// parseAPIBase validates the internal API base URL.
func parseAPIBase(s string) (*url.URL, error) {
	if s == "" {
		return nil, errors.New("required: the internal API base URL (or set SECMAIL_API_BASE)")
	}
	u, err := url.Parse(strings.TrimRight(s, "/"))
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%q must be an http(s) URL with a host and no credentials/query", s)
	}
	return u, nil
}

// underBase reports whether target is on the API origin and below its path,
// so a job naming another host never receives the bearer token.
func underBase(base *url.URL, target string) bool {
	if base == nil {
		return false
	}
	u, err := url.Parse(target)
	if err != nil || u.User != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, base.Scheme) || !strings.EqualFold(u.Host, base.Host) {
		return false
	}
	p := u.EscapedPath()
	bp := base.EscapedPath()
	if bp == "" {
		return true
	}
	return p == bp || strings.HasPrefix(p, bp+"/")
}

func nextBackoff(d time.Duration) time.Duration {
	if d == 0 {
		return time.Second
	}
	if d *= 2; d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// transientError marks a failure worth retrying later (network, timeout,
// 5xx/429): no verdict is posted for it.
type transientError struct{ err error }

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }

// analyze fetches the attachment and scans it, mapping the result onto the
// contract's status. A permanent fetch failure (bad job, 4xx, oversize,
// hash mismatch) yields ERROR so secmail fails closed; a transient one
// returns ok=false and no verdict.
func (w *worker) analyze(ctx context.Context, j job) (verdict, bool) {
	v := verdict{AttachmentID: j.AttachmentID}
	var r scan.Result
	data, err := w.fetch(ctx, j)
	var te *transientError
	switch {
	case err == nil:
		r = w.sc.Scan(ctx, j.Filename, data)
	case errors.As(err, &te) || ctx.Err() != nil:
		w.log.Warn("fetch failed (transient); leaving the job to be re-queued", "attachment", j.AttachmentID, "err", err)
		return v, false
	default:
		r = scan.ErrorResult("fetch", err)
	}
	v.Status, v.ThreatName, v.Detail = r.Status, r.ThreatName, r.Detail
	return v, true
}

// fetch downloads the attachment bytes from the internal API's content_url.
func (w *worker) fetch(ctx context.Context, j job) ([]byte, error) {
	if j.ContentURL == "" {
		return nil, fmt.Errorf("job has no content_url (set secmail internal_api.advertise_url)")
	}
	if !underBase(w.apiBase, j.ContentURL) {
		return nil, fmt.Errorf("content_url %q is outside -api-base; refusing to send the token", j.ContentURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.ContentURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	resp, err := w.httpc.Do(req)
	if err != nil {
		return nil, &transientError{err} // network error / timeout
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("content: HTTP %d", resp.StatusCode)
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return nil, &transientError{err}
		}
		return nil, err
	}
	// Read one byte past the cap: a larger attachment is an error, never
	// silently truncated (scanning only a prefix could miss the payload).
	data, err := io.ReadAll(io.LimitReader(resp.Body, w.fetchCap+1))
	if err != nil {
		return nil, &transientError{err}
	}
	if int64(len(data)) > w.fetchCap {
		return nil, fmt.Errorf("attachment exceeds -fetch-limit (%d bytes)", w.fetchCap)
	}
	if j.SHA256 != "" {
		sum := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), j.SHA256) {
			return nil, errors.New("downloaded content does not match the job's sha256")
		}
	}
	return data, nil
}

// postVerdict reports the verdict over HTTP. 2xx and 409 (already finalized,
// idempotent) are treated as success.
func (w *worker) postVerdict(ctx context.Context, target string, v verdict) error {
	if !underBase(w.apiBase, target) {
		return fmt.Errorf("verdict_url %q is outside -api-base; refusing to send the token", target)
	}
	b, _ := json.Marshal(v)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(b))
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
