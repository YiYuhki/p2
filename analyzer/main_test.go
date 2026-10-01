package main

import (
	"context"
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

func testWorker(t *testing.T) *worker {
	t.Helper()
	sc, err := scan.New(scan.Options{YaraRuleDirs: []string{rulesDir(t)}})
	if err != nil {
		t.Fatalf("scan.New: %v", err)
	}
	return &worker{
		sc:       sc,
		log:      slogDiscard(),
		token:    "test-token",
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
	w := testWorker(t)
	srv := contentServer(t, []byte(eicar))
	defer srv.Close()

	v := w.analyze(context.Background(), job{AttachmentID: "a1", Filename: "x.com", ContentURL: srv.URL})
	if v.Status != scan.StatusMalicious {
		t.Fatalf("status = %q, want MALICIOUS", v.Status)
	}
	if v.ThreatName == "" {
		t.Error("blocked verdict has no threat name")
	}
}

func TestAnalyzeAllowsBenign(t *testing.T) {
	w := testWorker(t)
	srv := contentServer(t, []byte("just a harmless note\n"))
	defer srv.Close()

	v := w.analyze(context.Background(), job{AttachmentID: "a2", Filename: "note.txt", ContentURL: srv.URL})
	if v.Status != scan.StatusClean {
		t.Fatalf("status = %q, want CLEAN", v.Status)
	}
}

func TestAnalyzeFetchErrorFailsClosed(t *testing.T) {
	w := testWorker(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	v := w.analyze(context.Background(), job{AttachmentID: "a3", Filename: "x", ContentURL: srv.URL})
	if v.Status != scan.StatusError {
		t.Fatalf("status = %q, want ERROR (fail closed)", v.Status)
	}
}

func TestAnalyzeNoContentURL(t *testing.T) {
	w := testWorker(t)
	v := w.analyze(context.Background(), job{AttachmentID: "a4", Filename: "x"})
	if v.Status != scan.StatusError {
		t.Fatalf("status = %q, want ERROR", v.Status)
	}
}
