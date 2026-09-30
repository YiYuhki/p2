package portal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/store"
	"github.com/yiyuhki/p2/internal/token"
)

// HoldReviewer is implemented by outbound.Service.
type HoldReviewer interface {
	Release(ctx context.Context, id, by string) error
	Reject(ctx context.Context, id, by, reason string) error
}

type holdFinding struct {
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Location string   `json:"location"`
	Count    int      `json:"count"`
	Samples  []string `json:"samples"`
}

type holdPageData struct {
	Nonce, Base, Status, Subject, From, Created, Expires, Decided, DecidedBy, Reason string
	To                                                                               []string
	Findings                                                                         []holdFinding
	Uninspectable                                                                    []string
	User, Error, Notice                                                              string
	CanLogout                                                                        bool
}

func (s *Server) holdGuard(r *http.Request, h *model.Hold) guard {
	return guard{
		base: "/dlp/" + r.PathValue("token"),
		eligible: func(_ context.Context, u string) (bool, error) {
			for _, a := range s.opts.DLPAdmins {
				if NormalizeEmail(a) == u {
					return true, nil
				}
			}
			return false, nil
		},
		logID: "hold:" + h.ID,
	}
}

func (s *Server) lookupHold(w http.ResponseWriter, r *http.Request) (*model.Hold, bool) {
	if !s.limiter.Allow(r) {
		w.Header().Set("Retry-After", "5")
		s.fail(w, r, http.StatusTooManyRequests, false, "요청이 너무 많습니다. 잠시 후 다시 시도하세요.")
		return nil, false
	}
	tok := r.PathValue("token")
	if !token.WellFormed(tok) {
		s.fail(w, r, http.StatusNotFound, false, "")
		return nil, false
	}
	h, err := s.store.GetHoldByTokenHash(r.Context(), token.Hash(tok))
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, http.StatusNotFound, false, "")
		return nil, false
	}
	if err != nil {
		s.log.Error("portal: hold lookup", "err", err)
		s.fail(w, r, http.StatusInternalServerError, false, "일시적인 오류가 발생했습니다.")
		return nil, false
	}
	return h, true
}

func (s *Server) renderHold(w http.ResponseWriter, r *http.Request, code int, h *model.Hold, user, errMsg, notice string) {
	d := holdPageData{
		Nonce: nonce(), Base: "/dlp/" + r.PathValue("token"), Status: string(h.Status),
		Subject: h.Subject, From: h.MailFrom, To: h.RcptTo,
		Created:   h.CreatedAt.In(s.opts.Location).Format("2006-01-02 15:04 MST"),
		Expires:   h.ExpiresAt.In(s.opts.Location).Format("2006-01-02 15:04 MST"),
		DecidedBy: h.DecidedBy, Reason: h.Reason,
		User: user, Error: errMsg, Notice: notice, CanLogout: user != "" && s.opts.Auth.Mode == "otp",
	}
	if h.DecidedAt != nil {
		d.Decided = h.DecidedAt.In(s.opts.Location).Format("2006-01-02 15:04 MST")
	}
	var rep struct {
		Findings      []holdFinding `json:"findings"`
		Uninspectable []string      `json:"uninspectable"`
	}
	if json.Unmarshal(h.Findings, &rep) == nil {
		d.Findings, d.Uninspectable = rep.Findings, rep.Uninspectable
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'nonce-"+d.Nonce+"'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(code)
	if err := tmpl.ExecuteTemplate(w, "dlp.html", d); err != nil {
		s.log.Error("portal: render hold", "err", err)
	}
}

func (s *Server) holdPage(w http.ResponseWriter, r *http.Request) {
	h, ok := s.lookupHold(w, r)
	if !ok {
		return
	}
	user, ok := s.authorizeGuard(w, r, s.holdGuard(r, h), false)
	if !ok {
		return
	}
	s.renderHold(w, r, http.StatusOK, h, user, "", "")
}

func (s *Server) holdAuth(w http.ResponseWriter, r *http.Request) {
	if s.opts.Auth.Mode != "otp" {
		http.NotFound(w, r)
		return
	}
	h, ok := s.lookupHold(w, r)
	if !ok {
		return
	}
	s.otpLogin(w, r, s.holdGuard(r, h))
}

func (s *Server) holdDecide(w http.ResponseWriter, r *http.Request, release bool) {
	h, ok := s.lookupHold(w, r)
	if !ok {
		return
	}
	user, ok := s.authorizeGuard(w, r, s.holdGuard(r, h), false)
	if !ok {
		return
	}
	by := user
	if by == "" {
		by = "review-link (" + s.limiter.clientIP(r) + ")"
	}
	var err error
	if release {
		err = s.opts.Holds.Release(r.Context(), h.ID, by)
	} else {
		reason := strings.TrimSpace(r.PostFormValue("reason"))
		if len(reason) > 300 {
			reason = reason[:300]
		}
		err = s.opts.Holds.Reject(r.Context(), h.ID, by, reason)
	}
	fresh, gerr := s.store.GetHold(r.Context(), h.ID)
	if gerr == nil {
		h = fresh
	}
	switch {
	case err == nil && release:
		s.renderHold(w, r, http.StatusOK, h, user, "", "승인되어 메일이 발송되었습니다.")
	case err == nil:
		s.renderHold(w, r, http.StatusOK, h, user, "", "반려되었습니다. 발신자에게 안내 메일이 발송됩니다.")
	case h.Status != model.HoldHeld:
		s.renderHold(w, r, http.StatusConflict, h, user, "이미 처리된 메일입니다.", "")
	default:
		s.log.Error("portal: hold decision failed", "hold", h.ID, "err", err)
		s.renderHold(w, r, http.StatusBadGateway, h, user, "처리 중 오류가 발생했습니다. 잠시 후 다시 시도하세요.", "")
	}
}

func (s *Server) holdRelease(w http.ResponseWriter, r *http.Request) { s.holdDecide(w, r, true) }
func (s *Server) holdReject(w http.ResponseWriter, r *http.Request)  { s.holdDecide(w, r, false) }
