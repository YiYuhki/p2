package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRetryThenSucceed(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503 -> retryable
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewWithOptions(srv.URL, "", Options{Timeout: time.Second, Retries: 3, Backoff: time.Millisecond}, quiet())
	n.sleep = func(time.Duration) {} // no real backoff in tests
	n.deliver(Event{Type: "t"}, []byte(`{"type":"t"}`))
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("hits = %d, want 3 (2 failures + 1 success)", got)
	}
}

func TestExhaustedGoesToDeadLetter(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusBadGateway) // always 502
	}))
	defer srv.Close()

	dlq := &capDLQ{}
	n := NewWithOptions(srv.URL, "", Options{Timeout: time.Second, Retries: 2, Backoff: time.Millisecond, DeadLetter: dlq}, quiet())
	n.sleep = func(time.Duration) {}
	n.deliver(Event{Type: "t", Action: "block"}, []byte(`{"type":"t"}`))

	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("hits = %d, want 3 (1 + 2 retries)", got)
	}
	if dlq.n != 1 || dlq.last.Action != "block" {
		t.Fatalf("dead-letter = %d %+v, want 1 with the event", dlq.n, dlq.last)
	}
}

func TestClientErrorNotRetried(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusBadRequest) // 400 -> not retryable
	}))
	defer srv.Close()
	dlq := &capDLQ{}
	n := NewWithOptions(srv.URL, "", Options{Timeout: time.Second, Retries: 5, Backoff: time.Millisecond, DeadLetter: dlq}, quiet())
	n.sleep = func(time.Duration) {}
	n.deliver(Event{Type: "t"}, []byte(`{}`))
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("hits = %d, want 1 (4xx is terminal)", got)
	}
	if dlq.n != 1 {
		t.Fatalf("a terminal failure should still dead-letter, got %d", dlq.n)
	}
}

type capDLQ struct {
	n    int
	last Event
}

func (c *capDLQ) Fail(ev Event, _ []byte, _ string) { c.n++; c.last = ev }

func TestNilNotifierIsNoop(t *testing.T) {
	var n *Notifier
	n.Send(Event{Type: "dlp_outbound"}) // must not panic
	if New("", "", 0, slog.Default()) != nil {
		t.Fatal("empty URL should disable the notifier")
	}
}

func TestSendPostsSignedJSON(t *testing.T) {
	type got struct {
		body []byte
		sig  string
		ct   string
	}
	ch := make(chan got, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- got{body: b, sig: r.Header.Get("X-Secmail-Signature"), ct: r.Header.Get("Content-Type")}
	}))
	defer srv.Close()

	n := New(srv.URL, "s3cr3t", 2*time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.Send(Event{Type: "dlp_outbound", Action: "block", Severity: "high", MailFrom: "a@x", Subject: "s"})

	select {
	case g := <-ch:
		if g.ct != "application/json" {
			t.Fatalf("content-type %q", g.ct)
		}
		var ev Event
		if err := json.Unmarshal(g.body, &ev); err != nil {
			t.Fatalf("payload not JSON: %v", err)
		}
		if ev.Action != "block" || ev.Severity != "high" || ev.At.IsZero() {
			t.Fatalf("payload fields: %+v", ev)
		}
		m := hmac.New(sha256.New, []byte("s3cr3t"))
		m.Write(g.body)
		if want := "sha256=" + hex.EncodeToString(m.Sum(nil)); g.sig != want {
			t.Fatalf("signature %q, want %q", g.sig, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook was not delivered")
	}
}

func TestSendNoSecretNoSignature(t *testing.T) {
	ch := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ch <- r.Header.Get("X-Secmail-Signature")
	}))
	defer srv.Close()
	New(srv.URL, "", time.Second, slog.New(slog.NewTextHandler(io.Discard, nil))).Send(Event{Type: "inbound_verdict", Status: "MALICIOUS"})
	select {
	case sig := <-ch:
		if sig != "" {
			t.Fatalf("unexpected signature %q", sig)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("not delivered")
	}
}
