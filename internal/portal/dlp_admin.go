package portal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yiyuhki/p2/internal/config"
	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/store"
)

// The admin dashboard lists held DLP mail and lets a configured admin release or
// reject it from one page, instead of opening each per-hold review link.
//
//	GET  /dlp/admin                      dashboard page
//	GET  /dlp/admin/holds                JSON list (status, cursor)
//	POST /dlp/admin/auth                 OTP login (otp mode)
//	POST /dlp/admin/logout               end session
//	POST /dlp/admin/holds/{id}/release   release by id
//	POST /dlp/admin/holds/{id}/reject    reject by id (reason form field)
//
// It is only available when recipient authentication is enabled (otp/header),
// because in "none" mode there is no identity to check against DLPAdmins and the
// dashboard would expose every held message to anyone who reached the URL.

// adminGuard restricts access to the configured DLP admins.
func (s *Server) adminGuard() guard {
	return guard{
		base: "/dlp/admin",
		eligible: func(_ context.Context, u string) (bool, error) {
			for _, a := range s.opts.DLPAdmins {
				if NormalizeEmail(a) == u {
					return true, nil
				}
			}
			return false, nil
		},
		logID: "dlp-admin",
	}
}

// adminAuthDisabled reports whether the dashboard cannot identify admins.
func (s *Server) adminAuthDisabled() bool {
	return s.opts.Auth.Mode == config.AuthNone || s.opts.Auth.Mode == ""
}

type adminHoldJSON struct {
	ID       string   `json:"id"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	Subject  string   `json:"subject"`
	Status   string   `json:"status"`
	Severity string   `json:"severity"` // top finding severity: high|medium|low|""
	Findings int      `json:"findings"`
	Created  string   `json:"created"`
	Expires  string   `json:"expires"`
}

// adminHolds serves the JSON list the dashboard page fetches.
func (s *Server) adminHolds(w http.ResponseWriter, r *http.Request) {
	if s.adminAuthDisabled() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "admin dashboard requires recipient auth"})
		return
	}
	if !s.limiter.Allow(r) {
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
		return
	}
	if _, ok := s.authorizeGuard(w, r, s.adminGuard(), true); !ok {
		return
	}
	status := model.HoldStatus(strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status"))))
	if status == "ALL" {
		status = ""
	} else if status == "" {
		status = model.HoldHeld
	}
	const limit = 50
	hs, err := s.store.ListHolds(r.Context(), status, limit, decodeHoldCursor(r.URL.Query().Get("cursor")))
	if err != nil {
		s.log.Error("portal: admin list holds", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	out := make([]adminHoldJSON, 0, len(hs))
	for _, h := range hs {
		sev, n := summarizeFindings(h.Findings)
		row := adminHoldJSON{
			ID: h.ID, From: h.MailFrom, To: h.RcptTo, Subject: h.Subject, Status: string(h.Status),
			Severity: sev, Findings: n,
			Created: h.CreatedAt.In(s.opts.Location).Format("2006-01-02 15:04"),
			Expires: h.ExpiresAt.In(s.opts.Location).Format("2006-01-02 15:04"),
		}
		out = append(out, row)
	}
	resp := map[string]any{"holds": out}
	if len(hs) == limit {
		last := hs[len(hs)-1]
		resp["next"] = encodeHoldCursor(last.CreatedAt, last.ID)
	}
	writeJSON(w, http.StatusOK, resp)
}

// adminDecide releases or rejects a hold by id (admin dashboard action).
func (s *Server) adminDecide(release bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminAuthDisabled() {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "admin dashboard requires recipient auth"})
			return
		}
		user, ok := s.authorizeGuard(w, r, s.adminGuard(), true)
		if !ok {
			return
		}
		id := r.PathValue("id")
		if _, err := uuid.Parse(id); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
			return
		}
		var err error
		if release {
			err = s.opts.Holds.Release(r.Context(), id, user)
		} else {
			reason := strings.TrimSpace(r.PostFormValue("reason"))
			if len(reason) > 300 {
				reason = reason[:300]
			}
			err = s.opts.Holds.Reject(r.Context(), id, user, reason)
		}
		switch {
		case err == nil:
			st := model.HoldReleased
			if !release {
				st = model.HoldRejected
			}
			s.log.Info("portal: admin hold decision", "hold", id, "by", user, "status", st)
			writeJSON(w, http.StatusOK, map[string]string{"status": string(st)})
		case errors.Is(err, store.ErrConflict):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "already decided"})
		case errors.Is(err, store.ErrNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		default:
			s.log.Error("portal: admin hold decision failed", "hold", id, "err", err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "decision failed"})
		}
	}
}

// adminAuth handles the OTP login for the dashboard (otp mode only).
func (s *Server) adminAuth(w http.ResponseWriter, r *http.Request) {
	if s.opts.Auth.Mode != config.AuthOTP {
		http.NotFound(w, r)
		return
	}
	s.otpLogin(w, r, s.adminGuard())
}

// adminLogout clears the session and returns to the dashboard.
func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w)
	http.Redirect(w, r, "/dlp/admin", http.StatusSeeOther)
}

// adminDashboard renders the dashboard shell; data is fetched by its script.
func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	n := nonce()
	user := ""
	if s.adminAuthDisabled() {
		s.renderAdmin(w, http.StatusOK, n, "", true)
		return
	}
	var ok bool
	if user, ok = s.authorizeGuard(w, r, s.adminGuard(), false); !ok {
		return // the guard rendered the login/forbidden page
	}
	s.renderAdmin(w, http.StatusOK, n, user, false)
}

func (s *Server) renderAdmin(w http.ResponseWriter, code int, nonce, user string, disabled bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'nonce-"+nonce+"'; script-src 'nonce-"+nonce+"'; "+
			"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(code)
	d := struct {
		Nonce, User string
		Disabled    bool
		CanLogout   bool
	}{Nonce: nonce, User: user, Disabled: disabled, CanLogout: user != "" && s.opts.Auth.Mode == config.AuthOTP}
	if err := tmpl.ExecuteTemplate(w, "dlp_admin.html", d); err != nil {
		s.log.Error("portal: render admin", "err", err)
	}
}

// summarizeFindings returns the top severity and the finding count of a hold's
// stored findings blob.
func summarizeFindings(raw json.RawMessage) (string, int) {
	var rep struct {
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if json.Unmarshal(raw, &rep) != nil {
		return "", 0
	}
	rank := map[string]int{"low": 1, "medium": 2, "high": 3}
	top := ""
	for _, f := range rep.Findings {
		if rank[f.Severity] > rank[top] {
			top = f.Severity
		}
	}
	return top, len(rep.Findings)
}

// ---- cursor (time + id keyset), opaque base64 ----

func encodeHoldCursor(t time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(t.UnixNano(), 10) + "|" + id))
}

func decodeHoldCursor(s string) store.Page {
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
