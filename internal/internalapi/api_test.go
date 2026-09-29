package internalapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yiyuhki/p2/internal/mimeproc"
	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/queue"
	"github.com/yiyuhki/p2/internal/service"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
)

const secret = "0123456789abcdef-secret"

func setup(t *testing.T) (*httptest.Server, string, *store.Memory) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.NewMemory()
	obj, _ := storage.NewFS(t.TempDir())
	svc := service.New(st, obj, queue.NewMemory(), service.Options{LinkTTL: time.Hour, MaxAttempts: 1}, log)
	links, err := svc.Quarantine(context.Background(), &model.Message{}, []*mimeproc.Extracted{
		{Filename: "x.doc", ContentType: "application/msword", Data: []byte("DOCDATA")},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(st, obj, svc, secret, log).Handler())
	t.Cleanup(srv.Close)
	return srv, links[0].AttachmentID, st
}

func do(t *testing.T, method, url, tok, body string) (int, string) {
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAuthRequired(t *testing.T) {
	srv, id, _ := setup(t)
	if code, _ := do(t, "GET", srv.URL+"/internal/v1/attachments/"+id, "", ""); code != 401 {
		t.Fatalf("want 401, got %d", code)
	}
	if code, _ := do(t, "GET", srv.URL+"/internal/v1/attachments/"+id, "wrong-token-xxxxxxxx", ""); code != 401 {
		t.Fatalf("want 401, got %d", code)
	}
}

func TestContentAndVerdict(t *testing.T) {
	srv, id, st := setup(t)
	base := srv.URL + "/internal/v1/attachments/" + id

	code, body := do(t, "GET", base+"/content", secret, "")
	if code != 200 || body != "DOCDATA" {
		t.Fatalf("content: %d %q", code, body)
	}
	code, body = do(t, "GET", base, secret, "")
	if code != 200 || !strings.Contains(body, `"status":"PENDING"`) {
		t.Fatalf("meta: %d %s", code, body)
	}
	if code, _ = do(t, "POST", base+"/verdict", secret, `{"status":"BOGUS"}`); code != 400 {
		t.Fatalf("bogus status: %d", code)
	}
	code, _ = do(t, "POST", base+"/verdict", secret, `{"status":"MALICIOUS","threat_name":"Macro.Downloader","detail":{"yara":["m1"]}}`)
	if code != 200 {
		t.Fatalf("verdict: %d", code)
	}
	if code, _ = do(t, "POST", base+"/verdict", secret, `{"status":"CLEAN"}`); code != 409 {
		t.Fatalf("duplicate verdict: %d", code)
	}
	a, _ := st.GetAttachment(context.Background(), id)
	if a.Status != model.StatusMalicious || !strings.Contains(string(a.VerdictDetail), "m1") {
		t.Fatalf("%+v", a)
	}
	if code, _ = do(t, "GET", srv.URL+"/internal/v1/attachments/not-a-uuid", secret, ""); code != 404 {
		t.Fatalf("bad id: %d", code)
	}
}
