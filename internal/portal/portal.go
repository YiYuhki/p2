// Package portal serves the public download pages linked from rewritten mail.
//
//	GET  /d/{token}           status page (PENDING / CLEAN / MALICIOUS / ERROR / EXPIRED)
//	GET  /d/{token}/status    JSON status, polled by the page while PENDING
//	POST /d/{token}/download  issues a one-time ticket (CLEAN only), 303 -> file
//	GET  /d/{token}/file?t=   streams the file once per ticket
package portal

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
	"github.com/yiyuhki/p2/internal/token"
)

//go:embed templates/*.html
var templateFS embed.FS

var pageTmpl = template.Must(template.New("page.html").Funcs(template.FuncMap{
	"size": humanSize,
}).ParseFS(templateFS, "templates/page.html"))

type Options struct {
	TicketTTL         time.Duration
	RateLimitRPS      float64
	RateLimitBurst    int
	TrustProxyHeaders bool
	Location          *time.Location
}

type Server struct {
	store   store.Store
	storage storage.Storage
	tickets Tickets
	opts    Options
	limiter *ipLimiter
	log     *slog.Logger
	now     func() time.Time
}

func New(st store.Store, obj storage.Storage, tk Tickets, opts Options, log *slog.Logger) *Server {
	if opts.Location == nil {
		opts.Location = time.Local
	}
	return &Server{
		store: st, storage: obj, tickets: tk, opts: opts, log: log, now: time.Now,
		limiter: newIPLimiter(opts.RateLimitRPS, opts.RateLimitBurst, opts.TrustProxyHeaders),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /d/{token}", s.page)
	mux.HandleFunc("GET /d/{token}/status", s.status)
	mux.HandleFunc("POST /d/{token}/download", s.download)
	mux.HandleFunc("GET /d/{token}/file", s.file)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Robots-Tag", "noindex, nofollow")
		next.ServeHTTP(w, r)
	})
}

// effectiveStatus folds link expiry into the stored status.
func (s *Server) effectiveStatus(a *model.Attachment) model.Status {
	if a.Status == model.StatusExpired || s.now().After(a.ExpiresAt) {
		return model.StatusExpired
	}
	return a.Status
}

// lookup resolves the path token; it writes the error response itself.
func (s *Server) lookup(w http.ResponseWriter, r *http.Request, asJSON bool) (*model.Attachment, bool) {
	if !s.limiter.Allow(r) {
		w.Header().Set("Retry-After", "5")
		s.fail(w, r, http.StatusTooManyRequests, asJSON, "요청이 너무 많습니다. 잠시 후 다시 시도하세요.")
		return nil, false
	}
	tok := r.PathValue("token")
	if !token.WellFormed(tok) {
		s.fail(w, r, http.StatusNotFound, asJSON, "")
		return nil, false
	}
	a, err := s.store.GetAttachmentByTokenHash(r.Context(), token.Hash(tok))
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, http.StatusNotFound, asJSON, "")
		return nil, false
	}
	if err != nil {
		s.log.Error("portal: lookup failed", "err", err)
		s.fail(w, r, http.StatusInternalServerError, asJSON, "일시적인 오류가 발생했습니다.")
		return nil, false
	}
	return a, true
}

type pageData struct {
	State      string
	Token      string
	Filename   string
	Size       int64
	ThreatName string
	Expires    string
	Message    string
	Nonce      string
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	a, ok := s.lookup(w, r, false)
	if !ok {
		return
	}
	st := s.effectiveStatus(a)
	code := http.StatusOK
	switch st {
	case model.StatusExpired:
		code = http.StatusGone
	case model.StatusMalicious, model.StatusError:
		code = http.StatusForbidden
	}
	s.render(w, code, pageData{
		State:      string(st),
		Token:      r.PathValue("token"),
		Filename:   a.Filename,
		Size:       a.Size,
		ThreatName: a.ThreatName,
		Expires:    a.ExpiresAt.In(s.opts.Location).Format("2006-01-02 15:04 MST"),
	})
}

type statusJSON struct {
	Status     model.Status `json:"status"`
	Filename   string       `json:"filename"`
	Size       int64        `json:"size"`
	ThreatName string       `json:"threat_name,omitempty"`
	ExpiresAt  time.Time    `json:"expires_at"`
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	a, ok := s.lookup(w, r, true)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, statusJSON{
		Status: s.effectiveStatus(a), Filename: a.Filename, Size: a.Size,
		ThreatName: a.ThreatName, ExpiresAt: a.ExpiresAt,
	})
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	a, ok := s.lookup(w, r, false)
	if !ok {
		return
	}
	if st := s.effectiveStatus(a); st != model.StatusClean {
		// Not downloadable: show the page for the current state.
		http.Redirect(w, r, "/d/"+r.PathValue("token"), http.StatusSeeOther)
		return
	}
	tk, err := s.tickets.Issue(r.Context(), a.ID, s.opts.TicketTTL)
	if err != nil {
		s.log.Error("portal: issue ticket", "err", err)
		s.fail(w, r, http.StatusInternalServerError, false, "일시적인 오류가 발생했습니다.")
		return
	}
	http.Redirect(w, r, "/d/"+r.PathValue("token")+"/file?t="+tk, http.StatusSeeOther)
}

func (s *Server) file(w http.ResponseWriter, r *http.Request) {
	a, ok := s.lookup(w, r, false)
	if !ok {
		return
	}
	id, err := s.tickets.Redeem(r.Context(), r.URL.Query().Get("t"))
	if err != nil || id != a.ID {
		// Expired/used ticket: send the user back to the page for a new one.
		http.Redirect(w, r, "/d/"+r.PathValue("token"), http.StatusSeeOther)
		return
	}
	// Re-check: the verdict must still be CLEAN at the moment of transfer.
	if s.effectiveStatus(a) != model.StatusClean {
		http.Redirect(w, r, "/d/"+r.PathValue("token"), http.StatusSeeOther)
		return
	}
	obj, err := s.storage.Get(r.Context(), a.StorageKey)
	if err != nil {
		s.log.Error("portal: open object", "attachment", a.ID, "err", err)
		s.fail(w, r, http.StatusInternalServerError, false, "파일을 불러오지 못했습니다.")
		return
	}
	defer obj.Close()

	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": a.Filename}))
	h.Set("Content-Length", strconv.FormatInt(a.Size, 10))
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, obj); err != nil {
		s.log.Warn("portal: stream interrupted", "attachment", a.ID, "err", err)
		return
	}
	if err := s.store.RecordDownload(r.Context(), a.ID, s.now().UTC()); err != nil {
		s.log.Warn("portal: record download", "err", err)
	}
	s.log.Info("portal: downloaded", "attachment", a.ID, "ip", s.limiter.clientIP(r))
}

func (s *Server) fail(w http.ResponseWriter, _ *http.Request, code int, asJSON bool, msg string) {
	if asJSON {
		writeJSON(w, code, map[string]string{"error": http.StatusText(code)})
		return
	}
	state := "NOTFOUND"
	if code != http.StatusNotFound {
		state = "FAILURE"
	}
	s.render(w, code, pageData{State: state, Message: msg})
}

func (s *Server) render(w http.ResponseWriter, code int, d pageData) {
	d.Nonce = nonce()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'nonce-"+d.Nonce+"'; script-src 'nonce-"+d.Nonce+"'; "+
			"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(code)
	if err := pageTmpl.Execute(w, d); err != nil {
		s.log.Error("portal: render", "err", err)
	}
}

func nonce() string {
	var b [16]byte
	rand.Read(b[:])
	return base64.StdEncoding.EncodeToString(b[:])
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return strconv.FormatFloat(float64(n)/float64(div), 'f', 1, 64) + " " + string("KMGTPE"[exp]) + "B"
}
