// Package internalapi is the authenticated API used by the external analysis
// engine. It should only be reachable from the analysis network.
//
//	GET  /internal/v1/attachments/{id}          metadata
//	GET  /internal/v1/attachments/{id}/content  raw file bytes
//	POST /internal/v1/attachments/{id}/verdict  {"status":"CLEAN|MALICIOUS|ERROR","threat_name":"...","detail":{...}}
package internalapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/service"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
)

type VerdictApplier interface {
	ApplyVerdict(ctx context.Context, v model.Verdict) error
}

type API struct {
	store    store.Store
	storage  storage.Storage
	verdicts VerdictApplier
	token    []byte
	log      *slog.Logger
}

func New(st store.Store, obj storage.Storage, v VerdictApplier, token string, log *slog.Logger) *API {
	return &API{store: st, storage: obj, verdicts: v, token: []byte(token), log: log}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/v1/attachments/{id}", a.auth(a.meta))
	mux.HandleFunc("GET /internal/v1/attachments/{id}/content", a.auth(a.content))
	mux.HandleFunc("POST /internal/v1/attachments/{id}/verdict", a.auth(a.verdict))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	return mux
}

func (a *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), a.token) != 1 {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		next(w, r)
	}
}

type metaJSON struct {
	ID          string          `json:"id"`
	MessageID   string          `json:"message_id"`
	Filename    string          `json:"filename"`
	ContentType string          `json:"content_type"`
	Size        int64           `json:"size"`
	SHA256      string          `json:"sha256"`
	Status      model.Status    `json:"status"`
	ThreatName  string          `json:"threat_name,omitempty"`
	Detail      json.RawMessage `json:"detail,omitempty"`
	Attempts    int             `json:"attempts"`
	CreatedAt   time.Time       `json:"created_at"`
	AnalyzedAt  *time.Time      `json:"analyzed_at,omitempty"`
	ExpiresAt   time.Time       `json:"expires_at"`
}

func (a *API) get(w http.ResponseWriter, r *http.Request) (*model.Attachment, bool) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		writeJSON(w, http.StatusNotFound, errBody("not found"))
		return nil, false
	}
	att, err := a.store.GetAttachment(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, errBody("not found"))
		return nil, false
	}
	if err != nil {
		a.log.Error("internalapi: get", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return nil, false
	}
	return att, true
}

func (a *API) meta(w http.ResponseWriter, r *http.Request) {
	att, ok := a.get(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, metaJSON{
		ID: att.ID, MessageID: att.MessageID, Filename: att.Filename, ContentType: att.ContentType,
		Size: att.Size, SHA256: att.SHA256, Status: att.Status, ThreatName: att.ThreatName,
		Detail: att.VerdictDetail, Attempts: att.Attempts, CreatedAt: att.CreatedAt,
		AnalyzedAt: att.AnalyzedAt, ExpiresAt: att.ExpiresAt,
	})
}

func (a *API) content(w http.ResponseWriter, r *http.Request) {
	att, ok := a.get(w, r)
	if !ok {
		return
	}
	if att.Status == model.StatusExpired {
		writeJSON(w, http.StatusGone, errBody("expired"))
		return
	}
	obj, err := a.storage.Get(r.Context(), att.StorageKey)
	if err != nil {
		a.log.Error("internalapi: open object", "attachment", att.ID, "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("storage error"))
		return
	}
	defer obj.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(att.Size, 10))
	w.Header().Set("X-SHA256", att.SHA256)
	io.Copy(w, obj)
}

func (a *API) verdict(w http.ResponseWriter, r *http.Request) {
	var v model.Verdict
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(&v); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid JSON"))
		return
	}
	v.AttachmentID = r.PathValue("id")
	err := a.verdicts.ApplyVerdict(r.Context(), v)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"result": "applied"})
	case errors.Is(err, service.ErrInvalidVerdict):
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errBody("not found"))
	case errors.Is(err, store.ErrConflict):
		writeJSON(w, http.StatusConflict, errBody("attachment already has a final status"))
	default:
		a.log.Error("internalapi: apply verdict", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
	}
}

func errBody(msg string) map[string]string { return map[string]string{"error": msg} }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
