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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yiyuhki/p2/internal/metrics"
	"github.com/yiyuhki/p2/internal/model"
	"github.com/yiyuhki/p2/internal/storage"
	"github.com/yiyuhki/p2/internal/store"
	"github.com/yiyuhki/p2/internal/token"
)

//go:embed templates/*.html
var templateFS embed.FS

var tmpl = template.Must(template.New("page.html").Funcs(template.FuncMap{
	"size": humanSize,
	"sevko": func(s string) string {
		switch s {
		case "high":
			return "높음"
		case "medium":
			return "중간"
		case "low":
			return "낮음"
		}
		return s
	},
}).ParseFS(templateFS, "templates/*.html"))

type Options struct {
	TicketTTL      time.Duration
	RateLimitRPS   float64
	RateLimitBurst int
	// EnumPerIPBurst / EnumGlobalRPS bound token-guessing (failed lookups);
	// zero values fall back to safe defaults.
	EnumPerIPBurst    int
	EnumGlobalRPS     float64
	TrustProxyHeaders bool
	Location          *time.Location
	// PublicBaseURL is used to validate the Origin of POST requests.
	PublicBaseURL string
	Auth          AuthOptions
	// Codes and Mailer are required when Auth.Mode is "otp".
	Codes  CodeStore
	Mailer Mailer
	// Holds enables the DLP review pages (/dlp/{token}); DLPAdmins may use
	// them when Auth is enabled.
	Holds     HoldReviewer
	DLPAdmins []string
}

type Server struct {
	store   store.Store
	storage storage.Storage
	tickets Tickets
	codes   CodeStore
	mailer  Mailer
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
		store: st, storage: obj, tickets: tk, codes: opts.Codes, mailer: opts.Mailer,
		opts: opts, log: log, now: time.Now,
		limiter: newIPLimiterFull(opts.RateLimitRPS, opts.RateLimitBurst,
			opts.EnumPerIPBurst, opts.EnumGlobalRPS, 0, opts.TrustProxyHeaders),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /d/{token}", s.page)
	mux.HandleFunc("GET /d/{token}/status", s.status)
	mux.HandleFunc("POST /d/{token}/download", s.download)
	mux.HandleFunc("GET /d/{token}/file", s.file)
	mux.HandleFunc("POST /d/{token}/auth", s.authPost)
	mux.HandleFunc("POST /d/{token}/logout", s.logout)
	if s.opts.Holds != nil {
		mux.HandleFunc("GET /dlp/{token}", s.holdPage)
		mux.HandleFunc("POST /dlp/{token}/auth", s.holdAuth)
		mux.HandleFunc("POST /dlp/{token}/logout", s.logout)
		mux.HandleFunc("POST /dlp/{token}/release", s.holdRelease)
		mux.HandleFunc("POST /dlp/{token}/reject", s.holdReject)
		// Admin dashboard (identifiable admins only; see dlp_admin.go).
		mux.HandleFunc("GET /dlp/admin", s.adminDashboard)
		mux.HandleFunc("GET /dlp/admin/holds", s.adminHolds)
		mux.HandleFunc("GET /dlp/admin/events", s.adminEvents)
		mux.HandleFunc("GET /dlp/admin/export", s.adminExport)
		mux.HandleFunc("POST /dlp/admin/auth", s.adminAuth)
		mux.HandleFunc("POST /dlp/admin/logout", s.adminLogout)
		mux.HandleFunc("POST /dlp/admin/holds/{id}/release", s.adminDecide(true))
		mux.HandleFunc("POST /dlp/admin/holds/{id}/reject", s.adminDecide(false))
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	return securityHeaders(s.checkOrigin(mux))
}

// checkOrigin rejects cross-site form posts (CSRF). Modern browsers send
// Sec-Fetch-Site; older ones are checked via Origin. Requests carrying
// neither (non-browser clients) are allowed.
func (s *Server) checkOrigin(next http.Handler) http.Handler {
	allowed := map[string]bool{}
	if u, err := url.Parse(s.opts.PublicBaseURL); err == nil && u.Host != "" {
		allowed[strings.ToLower(u.Host)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && !s.sameOrigin(r, allowed) {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) sameOrigin(r *http.Request, allowed map[string]bool) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
	default: // same-site, cross-site
		return false
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil || o == "null" {
		return false
	}
	return allowed[strings.ToLower(u.Host)] || strings.EqualFold(u.Host, r.Host)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin") // never leak the token URL to other sites
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
		metrics.PortalRequests.WithLabelValues("throttled").Inc()
		w.Header().Set("Retry-After", "5")
		s.fail(w, r, http.StatusTooManyRequests, asJSON, "요청이 너무 많습니다. 잠시 후 다시 시도하세요.")
		return nil, false
	}
	tok := r.PathValue("token")
	if !token.WellFormed(tok) {
		return nil, s.miss(w, r, asJSON)
	}
	a, err := s.store.GetAttachmentByTokenHash(r.Context(), token.Hash(tok))
	if errors.Is(err, store.ErrNotFound) {
		return nil, s.miss(w, r, asJSON)
	}
	if err != nil {
		metrics.PortalRequests.WithLabelValues("error").Inc()
		s.log.Error("portal: lookup failed", "err", err)
		s.fail(w, r, http.StatusInternalServerError, asJSON, "일시적인 오류가 발생했습니다.")
		return nil, false
	}
	metrics.PortalRequests.WithLabelValues("ok").Inc()
	return a, true
}

// miss handles a lookup that resolved no attachment (unknown or malformed
// token). It charges the enumeration budget and returns 429 once a client — or
// the gateway as a whole — is guessing tokens too fast, and a plain 404
// otherwise. Either response is identical for every unknown token, so it never
// reveals whether a guessed token exists. Always returns false.
func (s *Server) miss(w http.ResponseWriter, r *http.Request, asJSON bool) bool {
	ip := s.limiter.clientIP(r)
	if !s.limiter.AllowFail(ip) {
		metrics.PortalRequests.WithLabelValues("throttled").Inc()
		s.log.Warn("portal: token enumeration throttled", "ip", ip)
		w.Header().Set("Retry-After", "30")
		s.fail(w, r, http.StatusTooManyRequests, asJSON, "요청이 너무 많습니다. 잠시 후 다시 시도하세요.")
		return false
	}
	metrics.PortalRequests.WithLabelValues("notfound").Inc()
	s.fail(w, r, http.StatusNotFound, asJSON, "")
	return false
}

type pageData struct {
	State      string
	Base       string // URL of the protected resource, e.g. /d/<token>
	Token      string
	Filename   string
	Size       int64
	ThreatName string
	Expires    string
	Message    string
	Nonce      string
	// Authentication-related fields.
	User      string
	Email     string
	Error     string
	Notice    string
	CanLogout bool
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	a, ok := s.lookup(w, r, false)
	if !ok {
		return
	}
	user, ok := s.authorize(w, r, a, false)
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
		Base:       "/d/" + r.PathValue("token"),
		Filename:   a.Filename,
		Size:       a.Size,
		ThreatName: a.ThreatName,
		Expires:    a.ExpiresAt.In(s.opts.Location).Format("2006-01-02 15:04 MST"),
		User:       user,
		CanLogout:  user != "" && s.opts.Auth.Mode == "otp",
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
	if _, ok := s.authorize(w, r, a, true); !ok {
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
	if _, ok := s.authorize(w, r, a, false); !ok {
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
	user, ok := s.authorize(w, r, a, false)
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
	h.Set("Content-Disposition", contentDisposition(a.Filename))
	h.Set("Content-Length", strconv.FormatInt(a.Size, 10))
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, obj); err != nil {
		s.log.Warn("portal: stream interrupted", "attachment", a.ID, "err", err)
		return
	}
	ip := s.limiter.clientIP(r)
	ev := model.DownloadEvent{AttachmentID: a.ID, User: user, RemoteIP: ip, UserAgent: r.UserAgent(), At: s.now().UTC()}
	if err := s.store.RecordDownload(r.Context(), ev); err != nil {
		s.log.Warn("portal: record download", "err", err)
	}
	s.log.Info("portal: downloaded", "attachment", a.ID, "user", user, "ip", ip)
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
	if err := tmpl.ExecuteTemplate(w, "page.html", d); err != nil {
		s.log.Error("portal: render", "err", err)
	}
}

// contentDisposition builds an "attachment" Content-Disposition that is always
// well-formed, so the browser downloads the file rather than rendering it
// inline (which would be dangerous for html/svg). It carries a sanitised ASCII
// filename plus an RFC 5987 filename* for the original UTF-8 name; control
// characters, quotes and path separators are stripped from both.
func contentDisposition(name string) string {
	// Reduce to a bare filename: drop any directory components on either
	// separator, so a saved file can never traverse out of its folder.
	name = name[strings.LastIndexAny(name, "/\\")+1:]
	// Drop control characters (they could inject header lines or hide an
	// extension from the user).
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		name = "download"
	}

	// ASCII fallback for legacy clients: printable ASCII only, no quotes/backslash.
	var ascii strings.Builder
	for _, r := range name {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			ascii.WriteByte('_')
		} else {
			ascii.WriteRune(r)
		}
	}
	disp := `attachment; filename="` + ascii.String() + `"`

	// RFC 5987 filename* preserves the original UTF-8 name for modern clients.
	if enc := rfc5987(name); enc != ascii.String() {
		disp += `; filename*=UTF-8''` + enc
	}
	return disp
}

const rfc5987Unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$&+-.^_`|~"

func rfc5987(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if strings.IndexByte(rfc5987Unreserved, c) >= 0 {
			b.WriteByte(c)
		} else {
			const hex = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
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
