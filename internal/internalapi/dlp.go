package internalapi

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/store"
)

// HoldReviewer is implemented by outbound.Service.
type HoldReviewer interface {
	Release(ctx context.Context, id, by string) error
	Reject(ctx context.Context, id, by, reason string) error
}

// EnableDLPAdmin mounts the administration endpoints:
//
//	GET  /internal/v1/dlp/holds?status=HELD&limit=50
//	GET  /internal/v1/dlp/holds/{id}
//	POST /internal/v1/dlp/holds/{id}/release  {"by":"sec@example.com"}
//	POST /internal/v1/dlp/holds/{id}/reject   {"by":"...","reason":"..."}
//	GET  /internal/v1/dlp/events?limit=100
func (a *API) EnableDLPAdmin(adminToken string, h HoldReviewer) {
	a.adminToken = []byte(adminToken)
	a.holds = h
}

func (a *API) mountDLP(mux *http.ServeMux) {
	if len(a.adminToken) == 0 || a.holds == nil {
		return
	}
	mux.HandleFunc("GET /internal/v1/dlp/holds", a.admin(a.listHolds))
	mux.HandleFunc("GET /internal/v1/dlp/holds/{id}", a.admin(a.getHold))
	mux.HandleFunc("POST /internal/v1/dlp/holds/{id}/release", a.admin(a.decide(true)))
	mux.HandleFunc("POST /internal/v1/dlp/holds/{id}/reject", a.admin(a.decide(false)))
	mux.HandleFunc("GET /internal/v1/dlp/events", a.admin(a.listEvents))
}

func (a *API) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), a.adminToken) != 1 {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		next(w, r)
	}
}

type holdJSON struct {
	ID        string          `json:"id"`
	MailFrom  string          `json:"mail_from"`
	RcptTo    []string        `json:"rcpt_to"`
	Subject   string          `json:"subject"`
	Size      int64           `json:"size"`
	Status    string          `json:"status"`
	Findings  json.RawMessage `json:"findings"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	DecidedAt *time.Time      `json:"decided_at,omitempty"`
	DecidedBy string          `json:"decided_by,omitempty"`
	Reason    string          `json:"reason,omitempty"`
}

func toHoldJSON(h *model.Hold) holdJSON {
	return holdJSON{ID: h.ID, MailFrom: h.MailFrom, RcptTo: h.RcptTo, Subject: h.Subject, Size: h.Size,
		Status: string(h.Status), Findings: h.Findings, CreatedAt: h.CreatedAt, ExpiresAt: h.ExpiresAt,
		DecidedAt: h.DecidedAt, DecidedBy: h.DecidedBy, Reason: h.Reason}
}

func limitParam(r *http.Request, def int) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 || n > 500 {
		return def
	}
	return n
}

func (a *API) listHolds(w http.ResponseWriter, r *http.Request) {
	st := model.HoldStatus(strings.ToUpper(r.URL.Query().Get("status")))
	limit := limitParam(r, 50)
	hs, err := a.store.ListHolds(r.Context(), st, limit, decodeCursor(r.URL.Query().Get("cursor")))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}
	out := make([]holdJSON, 0, len(hs))
	for _, h := range hs {
		out = append(out, toHoldJSON(h))
	}
	if len(hs) == limit {
		last := hs[len(hs)-1]
		w.Header().Set("X-Next-Cursor", encodeCursor(last.CreatedAt, last.ID))
	}
	writeJSON(w, http.StatusOK, out)
}

// encodeCursor / decodeCursor carry a keyset position (time + id) as an opaque
// base64 token in the X-Next-Cursor header and the ?cursor= query parameter.
func encodeCursor(t time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(t.UnixNano(), 10) + "|" + id))
}

func decodeCursor(s string) store.Page {
	if s == "" {
		return store.Page{}
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return store.Page{}
	}
	ns, id, ok := strings.Cut(string(raw), "|")
	if !ok {
		return store.Page{}
	}
	n, err := strconv.ParseInt(ns, 10, 64)
	if err != nil {
		return store.Page{}
	}
	return store.Page{Before: time.Unix(0, n).UTC(), BeforeID: id}
}

func (a *API) getHold(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		writeJSON(w, http.StatusNotFound, errBody("not found"))
		return
	}
	h, err := a.store.GetHold(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, errBody("not found"))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}
	writeJSON(w, http.StatusOK, toHoldJSON(h))
}

func (a *API) decide(release bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if _, err := uuid.Parse(id); err != nil {
			writeJSON(w, http.StatusNotFound, errBody("not found"))
			return
		}
		var body struct{ By, Reason string }
		json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
		if body.By == "" {
			body.By = "admin-api"
		}
		var err error
		if release {
			err = a.holds.Release(r.Context(), id, body.By)
		} else {
			err = a.holds.Reject(r.Context(), id, body.By, body.Reason)
		}
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
		case errors.Is(err, store.ErrNotFound):
			writeJSON(w, http.StatusNotFound, errBody("not found"))
		case errors.Is(err, store.ErrConflict):
			writeJSON(w, http.StatusConflict, errBody("hold already decided"))
		default:
			a.log.Error("internalapi: hold decision", "hold", id, "err", err)
			writeJSON(w, http.StatusBadGateway, errBody(err.Error()))
		}
	}
}

func (a *API) listEvents(w http.ResponseWriter, r *http.Request) {
	limit := limitParam(r, 100)
	evs, err := a.store.ListDLPEvents(r.Context(), limit, decodeCursor(r.URL.Query().Get("cursor")))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}
	if len(evs) == limit {
		last := evs[len(evs)-1]
		w.Header().Set("X-Next-Cursor", encodeCursor(last.At, last.ID))
	}
	type evJSON struct {
		ID       string          `json:"id"`
		MailFrom string          `json:"mail_from"`
		RcptTo   []string        `json:"rcpt_to"`
		Subject  string          `json:"subject"`
		Action   string          `json:"action"`
		Severity string          `json:"severity"`
		Findings json.RawMessage `json:"findings"`
		HoldID   string          `json:"hold_id,omitempty"`
		At       time.Time       `json:"at"`
	}
	out := make([]evJSON, 0, len(evs))
	for _, e := range evs {
		out = append(out, evJSON{e.ID, e.MailFrom, e.RcptTo, e.Subject, e.Action, e.Severity, e.Findings, e.HoldID, e.At})
	}
	writeJSON(w, http.StatusOK, out)
}
