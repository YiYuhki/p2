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

// Notifier posts events to a configured URL. A nil *Notifier is a no-op, so
// callers need not check whether a webhook is configured.
type Notifier struct {
	url    string
	secret []byte
	client *http.Client
	log    *slog.Logger
}

// New returns a Notifier, or nil when url is empty (disabled). timeout defaults
// to 5s. When secret is non-empty each request carries an
// X-Secmail-Signature: sha256=<hex> HMAC of the body.
func New(url, secret string, timeout time.Duration, log *slog.Logger) *Notifier {
	if url == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Notifier{url: url, secret: []byte(secret), client: &http.Client{Timeout: timeout}, log: log}
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
	go n.post(body, ev.Type)
}

func (n *Notifier) post(body []byte, kind string) {
	ctx, cancel := context.WithTimeout(context.Background(), n.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		n.log.Warn("webhook: build request", "err", err)
		return
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
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		n.log.Warn("webhook: non-2xx response", "type", kind, "status", resp.StatusCode)
	}
}
