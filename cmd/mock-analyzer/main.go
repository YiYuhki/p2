// Command mock-analyzer is a stand-in for the external static-analysis
// engine. It demonstrates the job/verdict contract (docs/analyzer-contract.md):
// files containing the EICAR test string are reported MALICIOUS, everything
// else CLEAN. Do not use it in production.
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
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/yiyuhki/p2/internal/model"
)

const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

func main() {
	redisAddr := flag.String("redis", "localhost:6379", "redis address")
	prefix := flag.String("prefix", "secmail", "queue key prefix")
	apiToken := flag.String("token", os.Getenv("SECMAIL_INTERNAL_TOKEN"), "internal API bearer token")
	delay := flag.Duration("delay", 2*time.Second, "simulated analysis time")
	viaRedis := flag.Bool("reply-redis", false, "push verdicts to the Redis results list instead of HTTP")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rdb := redis.NewClient(&redis.Options{Addr: *redisAddr})
	high, normal, results := *prefix+":jobs:high", *prefix+":jobs:normal", *prefix+":results"
	log.Info("mock analyzer started", "queues", []string{high, normal})

	for ctx.Err() == nil {
		res, err := rdb.BRPop(ctx, 5*time.Second, high, normal).Result()
		if err != nil {
			continue
		}
		var job model.Job
		if err := json.Unmarshal([]byte(res[1]), &job); err != nil {
			log.Warn("bad job", "err", err)
			continue
		}
		v := analyze(ctx, job, *apiToken, *delay)
		log.Info("analyzed", "attachment", job.AttachmentID, "file", job.Filename, "status", v.Status)

		if *viaRedis || job.VerdictURL == "" {
			b, _ := json.Marshal(v)
			rdb.LPush(ctx, results, b)
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

func analyze(ctx context.Context, job model.Job, tok string, delay time.Duration) model.Verdict {
	v := model.Verdict{AttachmentID: job.AttachmentID}
	data, err := fetch(ctx, job, tok)
	if err != nil {
		v.Status = model.StatusError
		v.Detail, _ = json.Marshal(map[string]string{"error": err.Error()})
		return v
	}
	time.Sleep(delay)
	if bytes.Contains(data, []byte(eicar)) {
		v.Status = model.StatusMalicious
		v.ThreatName = "EICAR-Test-File"
		v.Detail, _ = json.Marshal(map[string]any{"engine": "mock", "rule": "eicar"})
		return v
	}
	v.Status = model.StatusClean
	v.Detail, _ = json.Marshal(map[string]any{"engine": "mock"})
	return v
}

func fetch(ctx context.Context, job model.Job, tok string) ([]byte, error) {
	if job.ContentURL == "" {
		return nil, fmt.Errorf("job has no content_url (set internal_api.advertise_url)")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, job.ContentURL, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("content: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 200<<20))
}
