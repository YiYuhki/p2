package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/yiyuhki/p2/analyzer/scan"
)

func slogDiscard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// rulesDir locates malengine's bundled YARA rules via the replace path.
func rulesDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "p1", "rules", "yara")
}

// testWorker returns a worker whose API base is base (a test server URL).
func testWorker(t *testing.T, base string) *worker {
	t.Helper()
	sc, err := scan.New(scan.Options{YaraRuleDirs: []string{rulesDir(t)}})
	if err != nil {
		t.Fatalf("scan.New: %v", err)
	}
	u, err := parseAPIBase(base)
	if err != nil {
		t.Fatalf("parseAPIBase: %v", err)
	}
	return &worker{
		sc:       sc,
		log:      slogDiscard(),
		token:    "test-token",
		apiBase:  u,
		fetchCap: 256 << 20,
		httpc:    http.DefaultClient,
	}
}

// contentServer serves body at / and checks the bearer token.
func contentServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write(body)
	}))
}

func TestAnalyzeBlocksEICAR(t *testing.T) {
	const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	srv := contentServer(t, []byte(eicar))
	defer srv.Close()
	w := testWorker(t, srv.URL)

	v, ok := w.analyze(context.Background(), job{AttachmentID: "a1", Filename: "x.com", ContentURL: srv.URL})
	if !ok || v.Status != scan.StatusMalicious {
		t.Fatalf("status = %q (ok=%v), want MALICIOUS", v.Status, ok)
	}
	if v.ThreatName == "" {
		t.Error("blocked verdict has no threat name")
	}
}

func TestAnalyzeAllowsBenign(t *testing.T) {
	body := []byte("just a harmless note\n")
	srv := contentServer(t, body)
	defer srv.Close()
	w := testWorker(t, srv.URL)

	sum := sha256.Sum256(body)
	v, ok := w.analyze(context.Background(), job{AttachmentID: "a2", Filename: "note.txt", ContentURL: srv.URL, SHA256: hex.EncodeToString(sum[:])})
	if !ok || v.Status != scan.StatusClean {
		t.Fatalf("status = %q (ok=%v), want CLEAN", v.Status, ok)
	}
}

// A 5xx is transient: no verdict is produced, so the job is re-queued by
// secmail's stale sweep instead of being finalised as ERROR.
func TestAnalyzeTransientFetchErrorPostsNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	w := testWorker(t, srv.URL)

	if v, ok := w.analyze(context.Background(), job{AttachmentID: "a3", Filename: "x", ContentURL: srv.URL}); ok {
		t.Fatalf("transient failure produced a verdict: %+v", v)
	}
}

func TestAnalyzePermanentFetchErrorFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	w := testWorker(t, srv.URL)

	v, ok := w.analyze(context.Background(), job{AttachmentID: "a3", Filename: "x", ContentURL: srv.URL})
	if !ok || v.Status != scan.StatusError {
		t.Fatalf("status = %q (ok=%v), want ERROR (fail closed)", v.Status, ok)
	}
}

func TestAnalyzeNoContentURL(t *testing.T) {
	w := testWorker(t, "http://127.0.0.1:1")
	v, ok := w.analyze(context.Background(), job{AttachmentID: "a4", Filename: "x"})
	if !ok || v.Status != scan.StatusError {
		t.Fatalf("status = %q, want ERROR", v.Status)
	}
}

func TestAnalyzeOversizeAndHashMismatch(t *testing.T) {
	srv := contentServer(t, []byte("0123456789"))
	defer srv.Close()
	w := testWorker(t, srv.URL)
	w.fetchCap = 5
	if v, ok := w.analyze(context.Background(), job{AttachmentID: "a5", Filename: "x", ContentURL: srv.URL}); !ok || v.Status != scan.StatusError {
		t.Fatalf("oversize: %q (ok=%v), want ERROR", v.Status, ok)
	}
	w.fetchCap = 1 << 20
	if v, ok := w.analyze(context.Background(), job{AttachmentID: "a6", Filename: "x", ContentURL: srv.URL, SHA256: "00"}); !ok || v.Status != scan.StatusError {
		t.Fatalf("hash mismatch: %q (ok=%v), want ERROR", v.Status, ok)
	}
}

// The bearer token must never go to a host other than the API base.
func TestTokenOnlySentUnderAPIBase(t *testing.T) {
	leaked := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked = true
		}
	}))
	defer evil.Close()
	w := testWorker(t, "http://secmail.internal:8081")
	v, ok := w.analyze(context.Background(), job{AttachmentID: "a7", Filename: "x", ContentURL: evil.URL + "/x"})
	if leaked {
		t.Fatal("token sent to a foreign host")
	}
	if !ok || v.Status != scan.StatusError {
		t.Fatalf("foreign content_url: %q (ok=%v), want ERROR", v.Status, ok)
	}
	if err := w.postVerdict(context.Background(), evil.URL+"/v", v); err == nil || leaked {
		t.Fatal("verdict posted to a foreign host")
	}
}

func TestUnderBase(t *testing.T) {
	base, _ := parseAPIBase("http://secmail:8081/api")
	cases := map[string]bool{
		"http://secmail:8081/api/internal/v1/x": true,
		"http://secmail:8081/api":               true,
		"http://secmail:8081/apix/y":            false,
		"http://secmail:8082/api/x":             false,
		"https://secmail:8081/api/x":            false,
		"http://evil:8081/api/x":                false,
		"http://u:p@secmail:8081/api/x":         false,
	}
	for in, want := range cases {
		if got := underBase(base, in); got != want {
			t.Errorf("underBase(%q) = %v, want %v", in, got, want)
		}
	}
}
