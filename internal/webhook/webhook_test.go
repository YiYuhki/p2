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
	"testing"
	"time"
)

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
