// Command mock-analyzer is a stand-in for the external static-analysis
// engine. It demonstrates the job/verdict contract (docs/analyzer-contract.md):
// files containing the EICAR test string are reported MALICIOUS, everything
// else CLEAN. Do not use it in production.
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

	"github.com/yiyuhki/p2/internal/model"
)

const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// fetchCap bounds the download; larger attachments get an ERROR verdict.
const fetchCap = 200 << 20

func main() {
	redisAddr := flag.String("redis", "localhost:6379", "redis address")
	redisPass := flag.String("redis-password", os.Getenv("SECMAIL_REDIS_PASSWORD"), "redis password (default $SECMAIL_REDIS_PASSWORD)")
	prefix := flag.String("prefix", "secmail", "queue key prefix")
	apiToken := flag.String("token", os.Getenv("SECMAIL_INTERNAL_TOKEN"), "internal API bearer token")
	apiBase := flag.String("api-base", os.Getenv("SECMAIL_API_BASE"), "secmail internal API base URL; the token is only sent to URLs under it")
	delay := flag.Duration("delay", 2*time.Second, "simulated analysis time")
	viaRedis := flag.Bool("reply-redis", false, "push verdicts to the Redis results list instead of HTTP")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	base, err := url.Parse(strings.TrimRight(*apiBase, "/"))
	if *apiBase == "" || err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		log.Error("-api-base (or SECMAIL_API_BASE) must be the internal API's http(s) base URL", "value", *apiBase)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rdb := redis.NewClient(&redis.Options{Addr: *redisAddr, Password: *redisPass})
	high, normal, results := *prefix+":jobs:high", *prefix+":jobs:normal", *prefix+":results"
	log.Info("mock analyzer started", "queues", []string{high, normal})

	var backoff time.Duration
	for ctx.Err() == nil {
		res, err := rdb.BRPop(ctx, 5*time.Second, high, normal).Result()
		if ctx.Err() != nil {
			break
		}
		if errors.Is(err, redis.Nil) {
			backoff = 0
			continue // timeout
		}
		if err != nil {
			if backoff = 2 * backoff; backoff == 0 {
				backoff = time.Second
			} else if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			log.Error("brpop failed", "err", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
		var job model.Job
		if err := json.Unmarshal([]byte(res[1]), &job); err != nil {
			log.Warn("bad job", "err", err)
			continue
		}
		v, ok := analyze(ctx, job, base, *apiToken, *delay)
		if !ok {
			log.Warn("transient fetch failure; leaving the job for the stale sweep", "attachment", job.AttachmentID)
			continue
		}
		log.Info("analyzed", "attachment", job.AttachmentID, "file", job.Filename, "status", v.Status)

		if *viaRedis || job.VerdictURL == "" {
			b, _ := json.Marshal(v)
			rdb.LPush(ctx, results, b)
			continue
		}
		if !underBase(base, job.VerdictURL) {
			log.Error("verdict_url outside -api-base; not sending the token", "url", job.VerdictURL)
			continue
		}
		b, _ := json.Marshal(v)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, job.VerdictURL, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+*apiToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Error("post verdict", "err", err)
			continue
		}
		resp.Body.Close()
	}
}

// underBase reports whether target is on the API origin and below its path.
func underBase(base *url.URL, target string) bool {
	u, err := url.Parse(target)
	if err != nil || u.User != nil || !strings.EqualFold(u.Scheme, base.Scheme) || !strings.EqualFold(u.Host, base.Host) {
		return false
	}
	bp := base.EscapedPath()
	return bp == "" || u.EscapedPath() == bp || strings.HasPrefix(u.EscapedPath(), bp+"/")
}

// errTransient marks fetch failures worth retrying (network, 5xx, 429).
var errTransient = errors.New("transient")

// analyze returns ok=false on a transient fetch failure: no verdict is sent
// and secmail's stale-job sweep re-queues the job.
func analyze(ctx context.Context, job model.Job, base *url.URL, tok string, delay time.Duration) (model.Verdict, bool) {
	v := model.Verdict{AttachmentID: job.AttachmentID}
	data, err := fetch(ctx, job, base, tok)
	if errors.Is(err, errTransient) || (err != nil && ctx.Err() != nil) {
		return v, false
	}
	if err != nil {
		v.Status = model.StatusError
		v.Detail, _ = json.Marshal(map[string]string{"error": err.Error()})
		return v, true
	}
	time.Sleep(delay)
	if bytes.Contains(data, []byte(eicar)) {
		v.Status = model.StatusMalicious
		v.ThreatName = "EICAR-Test-File"
		v.Detail, _ = json.Marshal(map[string]any{"engine": "mock", "rule": "eicar"})
		return v, true
	}
	v.Status = model.StatusClean
	v.Detail, _ = json.Marshal(map[string]any{"engine": "mock"})
	return v, true
}

func fetch(ctx context.Context, job model.Job, base *url.URL, tok string) ([]byte, error) {
	if job.ContentURL == "" {
		return nil, fmt.Errorf("job has no content_url (set internal_api.advertise_url)")
	}
	if !underBase(base, job.ContentURL) {
		return nil, fmt.Errorf("content_url %q is outside -api-base; refusing to send the token", job.ContentURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, job.ContentURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errTransient, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("%w: content: HTTP %d", errTransient, resp.StatusCode)
		}
		return nil, fmt.Errorf("content: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, fetchCap+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errTransient, err)
	}
	if len(data) > fetchCap {
		return nil, fmt.Errorf("attachment exceeds %d bytes", fetchCap)
	}
	if job.SHA256 != "" {
		sum := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), job.SHA256) {
			return nil, errors.New("downloaded content does not match the job's sha256")
		}
	}
	return data, nil
}
