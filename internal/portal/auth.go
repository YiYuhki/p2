package portal

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/yiyuhki/p2/internal/config"
	"github.com/yiyuhki/p2/internal/model"
)

// AuthOptions configures recipient authentication (see config.PortalAuthConfig).
type AuthOptions struct {
	Mode             string // config.AuthNone | AuthOTP | AuthHeader
	SessionSecret    []byte
	SessionTTL       time.Duration
	AllowDomainUsers bool
	AcceptedDomains  []string
	TrustedHeader    string
	OTPTTL           time.Duration
	OTPMaxAttempts   int
	OTPResendAfter   time.Duration
	// SecureCookie sets the Secure flag (true when the portal is served over HTTPS).
	SecureCookie bool
}

const sessionCookie = "secmail_session"

// NormalizeEmail lower-cases and strips angle brackets / whitespace.
func NormalizeEmail(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return strings.ToLower(strings.TrimSpace(s))
}

func validEmail(s string) bool {
	if len(s) < 3 || len(s) > 254 || strings.ContainsAny(s, " \t\r\n<>,;\"") {
		return false
	}
	at := strings.LastIndexByte(s, '@')
	return at > 0 && at < len(s)-1 && strings.Contains(s[at+1:], ".")
}

// ---- session cookie: base64(email) "." expiry "." base64(hmac) ----

func (s *Server) signSession(email string, exp time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(email)) + "." + strconv.FormatInt(exp.Unix(), 10)
	m := hmac.New(sha256.New, s.opts.Auth.SessionSecret)
	m.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) verifySession(v string) (string, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return "", false
	}
	m := hmac.New(sha256.New, s.opts.Auth.SessionSecret)
	m.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, m.Sum(nil)) {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || s.now().Unix() > exp {
		return "", false
	}
	email, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	return string(email), true
}

func (s *Server) setSession(w http.ResponseWriter, email string) {
	exp := s.now().Add(s.opts.Auth.SessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: s.signSession(email, exp), Path: "/",
		Expires: exp, HttpOnly: true, Secure: s.opts.Auth.SecureCookie, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.opts.Auth.SecureCookie, SameSite: http.SameSiteLaxMode,
	})
}

// currentUser returns the authenticated address, or "".
func (s *Server) currentUser(r *http.Request) string {
	switch s.opts.Auth.Mode {
	case config.AuthHeader:
		u := NormalizeEmail(r.Header.Get(s.opts.Auth.TrustedHeader))
		if validEmail(u) {
			return u
		}
	case config.AuthOTP:
		if c, err := r.Cookie(sessionCookie); err == nil {
			if u, ok := s.verifySession(c.Value); ok {
				return u
			}
		}
	}
	return ""
}

// eligible reports whether user may access attachment a: an envelope
// recipient of the message, or (optionally) any user of an accepted domain.
func (s *Server) eligible(ctx context.Context, user string, a *model.Attachment) (bool, error) {
	if user == "" {
		return false, nil
	}
	if s.opts.Auth.AllowDomainUsers {
		domain := user[strings.LastIndexByte(user, '@')+1:]
		for _, d := range s.opts.Auth.AcceptedDomains {
			if domain == d || (strings.HasPrefix(d, ".") && strings.HasSuffix(domain, d)) {
				return true, nil
			}
		}
	}
	msg, err := s.store.GetMessage(ctx, a.MessageID)
	if err != nil {
		return false, err
	}
	for _, rc := range msg.RcptTo {
		if NormalizeEmail(rc) == user {
			return true, nil
		}
	}
	return false, nil
}

// guard describes a protected resource: its URL base and who may see it.
type guard struct {
	base     string // "/d/<token>" or "/dlp/<token>"
	eligible func(ctx context.Context, user string) (bool, error)
	logID    string
}

func (s *Server) attachmentGuard(r *http.Request, a *model.Attachment) guard {
	return guard{
		base:     "/d/" + r.PathValue("token"),
		eligible: func(ctx context.Context, u string) (bool, error) { return s.eligible(ctx, u, a) },
		logID:    a.ID,
	}
}

// authorize enforces recipient authentication for a resolved attachment and
// writes the challenge / denial response itself when access is not granted.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, a *model.Attachment, asJSON bool) (string, bool) {
	return s.authorizeGuard(w, r, s.attachmentGuard(r, a), asJSON)
}

func (s *Server) authorizeGuard(w http.ResponseWriter, r *http.Request, g guard, asJSON bool) (string, bool) {
	if s.opts.Auth.Mode == config.AuthNone || s.opts.Auth.Mode == "" {
		return "", true
	}
	user := s.currentUser(r)
	if user == "" {
		if asJSON {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return "", false
		}
		if s.opts.Auth.Mode == config.AuthHeader {
			s.render(w, http.StatusUnauthorized, pageData{State: "AUTHREQ"})
		} else {
			s.render(w, http.StatusOK, pageData{State: "LOGIN", Base: g.base})
		}
		return "", false
	}
	ok, err := g.eligible(r.Context(), user)
	if err != nil {
		s.log.Error("portal: access check", "err", err)
		s.fail(w, r, http.StatusInternalServerError, asJSON, "일시적인 오류가 발생했습니다.")
		return "", false
	}
	if !ok {
		s.log.Warn("portal: access denied", "user", user, "resource", g.logID)
		if asJSON {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		} else {
			s.render(w, http.StatusForbidden, pageData{State: "FORBIDDEN", Base: g.base, User: user,
				CanLogout: s.opts.Auth.Mode == config.AuthOTP})
		}
		return "", false
	}
	return user, true
}

// authPost handles the OTP login for attachment links.
func (s *Server) authPost(w http.ResponseWriter, r *http.Request) {
	if s.opts.Auth.Mode != config.AuthOTP {
		http.NotFound(w, r)
		return
	}
	a, ok := s.lookup(w, r, false)
	if !ok {
		return
	}
	s.otpLogin(w, r, s.attachmentGuard(r, a))
}

// otpLogin handles both steps of the OTP login:
// email only -> send code; email + code -> verify and start a session.
func (s *Server) otpLogin(w http.ResponseWriter, r *http.Request, g guard) {
	email := NormalizeEmail(r.PostFormValue("email"))
	code := strings.TrimSpace(r.PostFormValue("code"))
	page := pageData{State: "CODE", Base: g.base, Email: email}

	if !validEmail(email) {
		s.render(w, http.StatusOK, pageData{State: "LOGIN", Base: g.base, Error: "올바른 이메일 주소를 입력하세요."})
		return
	}
	eligible, err := g.eligible(r.Context(), email)
	if err != nil {
		s.log.Error("portal: access check", "err", err)
		s.fail(w, r, http.StatusInternalServerError, false, "일시적인 오류가 발생했습니다.")
		return
	}

	if code == "" {
		// Same answer whether or not the address is eligible, so the page
		// does not reveal who received the mail.
		page.Notice = fmt.Sprintf("입력한 주소가 이 메일의 수신자(또는 담당자)라면 인증 코드가 발송되었습니다. (유효시간 %d분)",
			int(s.opts.Auth.OTPTTL.Minutes()))
		if eligible {
			c := newCode()
			sent, err := s.codes.Put(r.Context(), email, c, s.opts.Auth.OTPTTL, s.opts.Auth.OTPResendAfter)
			switch {
			case err != nil:
				s.log.Error("portal: store otp", "err", err)
			case !sent:
				page.Notice = "인증 코드가 이미 발송되었습니다. 잠시 후 다시 요청하세요."
			default:
				if err := s.mailer.SendCode(r.Context(), email, c, s.opts.Auth.OTPTTL); err != nil {
					s.log.Error("portal: send otp mail", "err", err)
				} else {
					s.log.Info("portal: otp sent", "user", email, "resource", g.logID)
				}
			}
		} else {
			s.log.Warn("portal: otp requested by ineligible address", "user", email, "resource", g.logID)
		}
		s.render(w, http.StatusOK, page)
		return
	}

	valid, err := s.codes.Check(r.Context(), email, code, s.opts.Auth.OTPMaxAttempts)
	if err != nil {
		s.log.Error("portal: check otp", "err", err)
	}
	if !valid || !eligible {
		page.Error = "인증 코드가 올바르지 않거나 만료되었습니다."
		s.render(w, http.StatusOK, page)
		return
	}
	s.setSession(w, email)
	s.log.Info("portal: login", "user", email)
	http.Redirect(w, r, g.base, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w)
	base := "/d/"
	if strings.HasPrefix(r.URL.Path, "/dlp/") {
		base = "/dlp/"
	}
	http.Redirect(w, r, base+r.PathValue("token"), http.StatusSeeOther)
}

func newCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%06d", n.Int64())
}

func hashKey(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}

// ---- one-time code storage ----

// CodeStore keeps one pending code per e-mail address.
type CodeStore interface {
	// Put stores code unless one was issued less than resendAfter ago, in
	// which case it returns false.
	Put(ctx context.Context, email, code string, ttl, resendAfter time.Duration) (bool, error)
	// Check consumes the code on success. After maxAttempts wrong guesses
	// the pending code is destroyed.
	Check(ctx context.Context, email, code string, maxAttempts int) (bool, error)
}

type RedisCodes struct {
	rdb    *redis.Client
	prefix string
}

func NewRedisCodes(rdb *redis.Client, prefix string) *RedisCodes {
	return &RedisCodes{rdb: rdb, prefix: prefix + ":otp:"}
}

func (c *RedisCodes) Put(ctx context.Context, email, code string, ttl, resendAfter time.Duration) (bool, error) {
	k := hashKey(email)
	ok, err := c.rdb.SetNX(ctx, c.prefix+"rl:"+k, 1, resendAfter).Result()
	if err != nil || !ok {
		return false, err
	}
	pipe := c.rdb.TxPipeline()
	pipe.Del(ctx, c.prefix+k)
	pipe.HSet(ctx, c.prefix+k, "code", hashKey(email, code), "attempts", 0)
	pipe.Expire(ctx, c.prefix+k, ttl)
	_, err = pipe.Exec(ctx)
	return err == nil, err
}

func (c *RedisCodes) Check(ctx context.Context, email, code string, maxAttempts int) (bool, error) {
	key := c.prefix + hashKey(email)
	stored, err := c.rdb.HGet(ctx, key, "code").Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(hashKey(email, code))) == 1 {
		// GETDEL-like: only the first concurrent verifier wins.
		n, err := c.rdb.Del(ctx, key).Result()
		return n == 1, err
	}
	n, err := c.rdb.HIncrBy(ctx, key, "attempts", 1).Result()
	if err == nil && int(n) >= maxAttempts {
		c.rdb.Del(ctx, key)
	}
	return false, err
}

type MemoryCodes struct {
	mu      sync.Mutex
	pending map[string]*memCode
	sentAt  map[string]time.Time
}

type memCode struct {
	hash     string
	exp      time.Time
	attempts int
}

func NewMemoryCodes() *MemoryCodes {
	return &MemoryCodes{pending: map[string]*memCode{}, sentAt: map[string]time.Time{}}
}

func (c *MemoryCodes) Put(_ context.Context, email, code string, ttl, resendAfter time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if t, ok := c.sentAt[email]; ok && now.Sub(t) < resendAfter {
		return false, nil
	}
	c.sentAt[email] = now
	c.pending[email] = &memCode{hash: hashKey(email, code), exp: now.Add(ttl)}
	return true, nil
}

func (c *MemoryCodes) Check(_ context.Context, email, code string, maxAttempts int) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pending[email]
	if !ok || time.Now().After(p.exp) {
		delete(c.pending, email)
		return false, nil
	}
	if subtle.ConstantTimeCompare([]byte(p.hash), []byte(hashKey(email, code))) == 1 {
		delete(c.pending, email)
		return true, nil
	}
	p.attempts++
	if p.attempts >= maxAttempts {
		delete(c.pending, email)
	}
	return false, nil
}
