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

	"github.com/yiyuhki/p2/internal/config"
	"github.com/yiyuhki/p2/internal/dlp"
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
	mux.HandleFunc("GET /internal/v1/dlp/audit", a.admin(a.listAudit))
	mux.HandleFunc("POST /internal/v1/dlp/rules/test", a.admin(a.testRule))
	if _, ok := a.holds.(PolicyViewer); ok {
		mux.HandleFunc("GET /internal/v1/dlp/policy", a.admin(a.dlpPolicy))
	}
}

// PolicyViewer exposes the effective (hot-reloadable) DLP policy for the
// read-only admin view. outbound.Service implements it.
type PolicyViewer interface {
	Policy() (actions config.DLPActions, exemptSenders, exemptRecipientDomains []string, dryRun, scanInternal bool)
}

// dlpPolicy returns the currently effective tunable DLP policy. Edits are made
// in the config file and applied with SIGHUP.
func (a *API) dlpPolicy(w http.ResponseWriter, _ *http.Request) {
	pv, ok := a.holds.(PolicyViewer)
	if !ok {
		writeJSON(w, http.StatusNotFound, errBody("not available"))
		return
	}
	actions, es, erd, dry, si := pv.Policy()
	writeJSON(w, http.StatusOK, map[string]any{
		"actions": actions, "exempt_senders": es, "exempt_recipient_domains": erd,
		"dry_run": dry, "scan_internal": si,
	})
}

// testRule compiles a candidate dlp.rules pattern and returns what it would
// match (masked) in the supplied sample text — a tuning aid for custom rules.
//
//	POST /internal/v1/dlp/rules/test  {"pattern":"...","text":"..."}
func (a *API) testRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pattern string `json:"pattern"`
		Text    string `json:"text"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid JSON"))
		return
	}
	if body.Pattern == "" {
		writeJSON(w, http.StatusBadRequest, errBody("pattern is required"))
		return
	}
	matches, err := dlp.TestRule(body.Pattern, body.Text, 50)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid pattern: "+err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"matches": matches, "count": len(matches)})
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
	page, _ := decodeCursor(r.URL.Query().Get("cursor"))
	hs, err := a.store.ListHolds(r.Context(), st, limit, page)
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
		w.Header().Set("X-Next-Cursor", encodeCursor(last.CreatedAt, last.ID, store.EventFilter{}))
	}
	writeJSON(w, http.StatusOK, out)
}

// encodeCursor / decodeCursor carry a keyset position (time + id) and, for the
// events list, the active filter as an opaque base64 token in the X-Next-Cursor
// header and the ?cursor= query parameter. Carrying the filter means a client
// can page a filtered list by passing ?cursor= alone without the second page
// silently reverting to unfiltered.
func encodeCursor(t time.Time, id string, f store.EventFilter) string {
	raw := strings.Join([]string{strconv.FormatInt(t.UnixNano(), 10), id, f.Action, f.Severity}, "\x00")
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeCursor(s string) (store.Page, store.EventFilter) {
	if s == "" {
		return store.Page{}, store.EventFilter{}
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return store.Page{}, store.EventFilter{}
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) < 2 {
		return store.Page{}, store.EventFilter{}
	}
	n, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return store.Page{}, store.EventFilter{}
	}
	page := store.Page{Before: time.Unix(0, n).UTC(), BeforeID: parts[1]}
	var f store.EventFilter
	if len(parts) >= 4 {
		f = store.EventFilter{Action: parts[2], Severity: parts[3]}
	}
	return page, f
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
		action := "release"
		var err error
		if release {
			err = a.holds.Release(r.Context(), id, body.By)
		} else {
			action = "reject"
			err = a.holds.Reject(r.Context(), id, body.By, body.Reason)
		}
		switch {
		case err == nil:
			a.recordAdmin(r.Context(), body.By, action, id, body.Reason, "ok")
			writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
		case errors.Is(err, store.ErrNotFound):
			a.recordAdmin(r.Context(), body.By, action, id, body.Reason, "notfound")
			writeJSON(w, http.StatusNotFound, errBody("not found"))
		case errors.Is(err, store.ErrConflict):
			a.recordAdmin(r.Context(), body.By, action, id, body.Reason, "conflict")
			writeJSON(w, http.StatusConflict, errBody("hold already decided"))
		default:
			a.recordAdmin(r.Context(), body.By, action, id, body.Reason, "error")
			a.log.Error("internalapi: hold decision", "hold", id, "err", err)
			writeJSON(w, http.StatusBadGateway, errBody(err.Error()))
		}
	}
}

// listAudit returns the admin-action audit trail, newest first, with the same
// opaque cursor as the events list.
func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	limit := limitParam(r, 100)
	page, _ := decodeCursor(r.URL.Query().Get("cursor"))
	acts, err := a.store.ListAdminActions(r.Context(), limit, page)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}
	if len(acts) == limit {
		last := acts[len(acts)-1]
		w.Header().Set("X-Next-Cursor", encodeCursor(last.At, last.ID, store.EventFilter{}))
	}
	writeJSON(w, http.StatusOK, acts)
}

// recordAdmin appends an admin-action audit record (best-effort).
func (a *API) recordAdmin(ctx context.Context, actor, action, target, detail, result string) {
	if actor == "" {
		actor = "admin-api"
	}
	if len(detail) > 300 {
		detail = detail[:300]
	}
	err := a.store.RecordAdminAction(ctx, model.AdminAction{
		ID: uuid.NewString(), At: time.Now().UTC(), Actor: actor,
		Action: action, Target: target, Detail: detail, Source: "api", Result: result,
	})
	if err != nil {
		a.log.Warn("internalapi: admin audit record failed", "action", action, "err", err)
	}
}

func (a *API) listEvents(w http.ResponseWriter, r *http.Request) {
	limit := limitParam(r, 100)
	page, curFilter := decodeCursor(r.URL.Query().Get("cursor"))
	// On the first page the filter comes from the query; on subsequent pages it
	// is taken from the cursor so paging cannot silently drop it.
	filter := curFilter
	if !page.Set() {
		filter = store.EventFilter{
			Action:   strings.ToLower(strings.TrimSpace(r.URL.Query().Get("action"))),
			Severity: strings.ToLower(strings.TrimSpace(r.URL.Query().Get("severity"))),
		}
	}
	evs, err := a.store.ListDLPEvents(r.Context(), filter, limit, page)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}
	if len(evs) == limit {
		last := evs[len(evs)-1]
		w.Header().Set("X-Next-Cursor", encodeCursor(last.At, last.ID, filter))
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
