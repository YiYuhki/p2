// Package webhook posts security events (DLP decisions, malware verdicts) to an
// external endpoint (SIEM, Slack relay, chat-ops) as JSON, fire-and-forget.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Event is the JSON payload delivered to the webhook. Unset fields are omitted.
type Event struct {
	Type       string    `json:"type"` // dlp_outbound | inbound_verdict
	At         time.Time `json:"at"`
	Action     string    `json:"action,omitempty"`   // allow|notify|hold|block (dlp)
	Status     string    `json:"status,omitempty"`   // CLEAN|MALICIOUS|ERROR (verdict)
	Severity   string    `json:"severity,omitempty"` // high|medium|low (dlp)
	MailFrom   string    `json:"mail_from,omitempty"`
	RcptTo     []string  `json:"rcpt_to,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	Threat     string    `json:"threat,omitempty"`     // threat name (verdict)
	Attachment string    `json:"attachment,omitempty"` // attachment id (verdict)
	HoldID     string    `json:"hold_id,omitempty"`
	Summary    string    `json:"summary,omitempty"`
	DryRun     bool      `json:"dry_run,omitempty"`
}

// DeadLetter receives an event that could not be delivered after every attempt,
// so a permanent failure is never lost silently. body is the exact JSON that
// was POSTed.
type DeadLetter interface {
	Fail(ev Event, body []byte, lastErr string)
}

// Options tunes delivery. Zero values give the historical fire-and-forget
// behaviour (one attempt, no dead-letter sink).
type Options struct {
	Timeout    time.Duration
	Retries    int           // extra attempts after the first
	Backoff    time.Duration // initial retry delay, doubled each attempt
	DeadLetter DeadLetter    // optional sink for permanently-failed events
}

// Notifier posts events to a configured URL. A nil *Notifier is a no-op, so
// callers need not check whether a webhook is configured.
type Notifier struct {
	url     string
	secret  []byte
	client  *http.Client
	log     *slog.Logger
	retries int
	backoff time.Duration
	dlq     DeadLetter
	sleep   func(time.Duration) // overridable in tests
}

// New returns a Notifier, or nil when url is empty (disabled). timeout defaults
// to 5s. When secret is non-empty each request carries an
// X-Secmail-Signature: sha256=<hex> HMAC of the body. It keeps the historical
// fire-and-forget behaviour (no retries); use NewWithOptions for retries/DLQ.
func New(url, secret string, timeout time.Duration, log *slog.Logger) *Notifier {
	return NewWithOptions(url, secret, Options{Timeout: timeout}, log)
}

// NewWithOptions returns a Notifier with retry/backoff and an optional
// dead-letter sink, or nil when url is empty (disabled).
func NewWithOptions(url, secret string, o Options, log *slog.Logger) *Notifier {
	if url == "" {
		return nil
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Backoff <= 0 {
		o.Backoff = time.Second
	}
	if o.Retries < 0 {
		o.Retries = 0
	}
	return &Notifier{
		url: url, secret: []byte(secret), client: &http.Client{Timeout: o.Timeout}, log: log,
		retries: o.Retries, backoff: o.Backoff, dlq: o.DeadLetter, sleep: time.Sleep,
	}
}

// Send delivers ev asynchronously. It does not use the caller's context so the
// delivery is not cancelled when the triggering request returns. Safe on a nil
// Notifier.
func (n *Notifier) Send(ev Event) {
	if n == nil {
		return
	}
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	go n.deliver(ev, body)
}

// deliver attempts the POST up to 1+retries times with exponential backoff,
// retrying only on a network error or a retryable status (429/5xx). On final
// failure it hands the event to the dead-letter sink, if any.
func (n *Notifier) deliver(ev Event, body []byte) {
	delay := n.backoff
	var lastErr string
	for attempt := 0; attempt <= n.retries; attempt++ {
		if attempt > 0 {
			n.sleep(delay)
			delay *= 2
		}
		retryable, err := n.post(body, ev.Type)
		if err == nil {
			return
		}
		lastErr = err.Error()
		if !retryable {
			break
		}
	}
	if n.dlq != nil {
		n.dlq.Fail(ev, body, lastErr)
	}
	n.log.Warn("webhook: giving up", "type", ev.Type, "attempts", n.retries+1, "err", lastErr)
}

// post performs one delivery attempt. It returns (retryable, err): err is nil
// on a 2xx; retryable is true for a network error or a 429/5xx so the caller
// backs off and tries again, false for a 4xx (other than 429) which will never
// succeed.
func (n *Notifier) post(body []byte, kind string) (retryable bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), n.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "secmail-webhook")
	if len(n.secret) > 0 {
		m := hmac.New(sha256.New, n.secret)
		m.Write(body)
		req.Header.Set("X-Secmail-Signature", "sha256="+hex.EncodeToString(m.Sum(nil)))
	}
	resp, err := n.client.Do(req)
	if err != nil {
		n.log.Warn("webhook: deliver failed", "type", kind, "err", err)
		return true, err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		n.log.Warn("webhook: non-2xx response", "type", kind, "status", resp.StatusCode)
		retryable = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return retryable, fmt.Errorf("status %d", resp.StatusCode)
	}
	return false, nil
}
