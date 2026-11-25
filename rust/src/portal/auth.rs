//! Recipient authentication for the portal. Port of the Go `portal/auth.go`.
//!
//! Modes: `none` (anyone holding the link), `otp` (a one-time code mailed to an
//! envelope recipient, then an HMAC-signed session cookie) and `header` (an
//! authenticating reverse proxy supplies the address in a trusted header).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use super::html::esc;
use super::{
    fail, json_error, redirect, render_page, AuthMode, PageData, Portal, Req, MSG_TEMP_ERROR,
};

/// Name of the session cookie.
pub const SESSION_COOKIE: &str = "secmail_session";

type HmacSha256 = Hmac<Sha256>;
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Lower-cases and strips angle brackets / surrounding whitespace.
pub fn normalize_email(s: &str) -> String {
    let s = s.trim();
    let s = s.strip_prefix('<').unwrap_or(s);
    let s = s.strip_suffix('>').unwrap_or(s);
    s.trim().to_lowercase()
}

/// A cheap plausibility check on a (normalized) address.
pub fn valid_email(s: &str) -> bool {
    if s.len() < 3 || s.len() > 254 || s.contains([' ', '\t', '\r', '\n', '<', '>', ',', ';', '"'])
    {
        return false;
    }
    match s.rfind('@') {
        Some(at) => at > 0 && at < s.len() - 1 && s[at + 1..].contains('.'),
        None => false,
    }
}

// ---- session cookie: base64(email) "." expiry "." base64(hmac) ----

fn mac(secret: &[u8]) -> HmacSha256 {
    HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length")
}

/// Signs a session for `email` valid until the unix time `exp`.
pub fn sign_session(secret: &[u8], email: &str, exp: i64) -> String {
    let payload = format!("{}.{exp}", B64.encode(email.as_bytes()));
    let mut m = mac(secret);
    m.update(payload.as_bytes());
    format!("{payload}.{}", B64.encode(m.finalize().into_bytes()))
}

/// Verifies a session value; returns the address when the signature is valid
/// and the session has not expired at unix time `now`.
pub fn verify_session(secret: &[u8], v: &str, now: i64) -> Option<String> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let sig = B64.decode(parts[2]).ok()?;
    let mut m = mac(secret);
    m.update(parts[0].as_bytes());
    m.update(b".");
    m.update(parts[1].as_bytes());
    m.verify_slice(&sig).ok()?;
    let exp: i64 = parts[1].parse().ok()?;
    if now > exp {
        return None;
    }
    String::from_utf8(B64.decode(parts[0]).ok()?).ok()
}

fn cookie_header(value: &str, max_age: i64, secure: bool) -> HeaderValue {
    let mut c =
        format!("{SESSION_COOKIE}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax");
    if secure {
        c.push_str("; Secure");
    }
    HeaderValue::from_str(&c).expect("cookie is ASCII")
}

pub(crate) fn set_session(st: &Portal, resp: &mut Response, email: &str) {
    let o = st.options();
    let ttl = o.session_ttl.as_secs() as i64;
    let exp = chrono::Utc::now().timestamp() + ttl;
    let v = sign_session(&o.session_secret, email, exp);
    resp.headers_mut()
        .append(header::SET_COOKIE, cookie_header(&v, ttl, o.secure_cookie));
}

pub(crate) fn clear_session(st: &Portal, resp: &mut Response) {
    resp.headers_mut().append(
        header::SET_COOKIE,
        cookie_header("", 0, st.options().secure_cookie),
    );
}

/// Returns the value of cookie `name` from the request headers.
pub(crate) fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim().trim_matches('"').to_string())
}

/// The authenticated address of the request, or "".
pub(crate) fn current_user(st: &Portal, r: &Req) -> String {
    let o = st.options();
    match o.auth_mode {
        AuthMode::Header => {
            let u = r
                .headers
                .get(o.trusted_header.as_str())
                .and_then(|v| v.to_str().ok())
                .map(normalize_email)
                .unwrap_or_default();
            if valid_email(&u) {
                return u;
            }
        }
        AuthMode::Otp => {
            if let Some(c) = cookie(&r.headers, SESSION_COOKIE) {
                if let Some(u) =
                    verify_session(&o.session_secret, &c, chrono::Utc::now().timestamp())
                {
                    return u;
                }
            }
        }
        AuthMode::None => {}
    }
    String::new()
}

// ---- guards ----

/// Who may access a protected resource.
#[derive(Clone, Debug)]
pub(crate) enum Who {
    /// An envelope recipient of this message (or an accepted-domain user).
    Recipients(String),
    /// A configured DLP admin (full control).
    Admins,
    /// A DLP admin or auditor (read-only access).
    Viewers,
}

/// A protected resource: its URL base and who may see it.
#[derive(Clone, Debug)]
pub(crate) struct Guard {
    pub base: String,
    pub who: Who,
    pub log_id: String,
}

fn in_list(list: &[String], user: &str) -> bool {
    list.iter().any(|a| normalize_email(a) == user)
}

pub(crate) fn is_admin(st: &Portal, user: &str) -> bool {
    in_list(&st.options().dlp_admins, user)
}

pub(crate) fn is_viewer(st: &Portal, user: &str) -> bool {
    is_admin(st, user) || in_list(&st.options().dlp_auditors, user)
}

/// Reports whether `user` may access the guarded resource.
pub(crate) async fn eligible(
    st: &Portal,
    g: &Guard,
    user: &str,
) -> Result<bool, crate::store::StoreError> {
    if user.is_empty() {
        return Ok(false);
    }
    match &g.who {
        Who::Admins => Ok(is_admin(st, user)),
        Who::Viewers => Ok(is_viewer(st, user)),
        Who::Recipients(message_id) => {
            let o = st.options();
            if o.allow_domain_users {
                let domain = &user[user.rfind('@').map(|i| i + 1).unwrap_or(0)..];
                for d in &o.accepted_domains {
                    let d = d.to_lowercase();
                    if domain == d || (d.starts_with('.') && domain.ends_with(&d)) {
                        return Ok(true);
                    }
                }
            }
            let msg = st.store.get_message(message_id).await?;
            Ok(msg.rcpt_to.iter().any(|rc| normalize_email(rc) == user))
        }
    }
}

/// Enforces authentication for a guarded resource. Returns the user ("" in
/// `none` mode) or the challenge / denial response to send.
pub(crate) async fn authorize(
    st: &Portal,
    r: &Req,
    g: &Guard,
    as_json: bool,
) -> Result<String, Response> {
    let mode = st.options().auth_mode;
    if mode == AuthMode::None {
        return Ok(String::new());
    }
    let user = current_user(st, r);
    if user.is_empty() {
        if as_json {
            return Err(json_error(
                StatusCode::UNAUTHORIZED,
                "authentication required",
            ));
        }
        return Err(if mode == AuthMode::Header {
            render_page(st, StatusCode::UNAUTHORIZED, PageData::state("AUTHREQ"))
        } else {
            let mut d = PageData::state("LOGIN");
            d.base = g.base.clone();
            render_page(st, StatusCode::OK, d)
        });
    }
    match eligible(st, g, &user).await {
        Err(e) => {
            eprintln!("portal: access check: {e}");
            Err(fail(
                st,
                StatusCode::INTERNAL_SERVER_ERROR,
                as_json,
                MSG_TEMP_ERROR,
            ))
        }
        Ok(false) => {
            st.metrics
                .portal_requests
                .with_label_values(&["denied"])
                .inc();
            eprintln!("portal: access denied user={user} resource={}", g.log_id);
            if as_json {
                return Err(json_error(StatusCode::FORBIDDEN, "forbidden"));
            }
            let mut d = PageData::state("FORBIDDEN");
            d.base = g.base.clone();
            d.user = user;
            d.can_logout = mode == AuthMode::Otp;
            Err(render_page(st, StatusCode::FORBIDDEN, d))
        }
        Ok(true) => Ok(user),
    }
}

/// Both steps of the OTP login: email only -> send a code; email + code ->
/// verify and start a session (303 back to the resource).
pub(crate) async fn otp_login(st: &Portal, r: &Req, g: &Guard) -> Response {
    let o = st.options();
    let email = normalize_email(r.form_value("email"));
    let code = r.form_value("code").trim().to_string();

    if !valid_email(&email) {
        let mut d = PageData::state("LOGIN");
        d.base = g.base.clone();
        d.error = "올바른 이메일 주소를 입력하세요.".into();
        return render_page(st, StatusCode::OK, d);
    }
    let ok = match eligible(st, g, &email).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("portal: access check: {e}");
            return fail(st, StatusCode::INTERNAL_SERVER_ERROR, false, MSG_TEMP_ERROR);
        }
    };
    let mut page = PageData::state("CODE");
    page.base = g.base.clone();
    page.email = email.clone();

    if code.is_empty() {
        // Same answer whether or not the address is eligible, so the page does
        // not reveal who received the mail.
        page.notice = format!(
            "입력한 주소가 이 메일의 수신자(또는 담당자)라면 인증 코드가 발송되었습니다. (유효시간 {}분)",
            o.otp_ttl.as_secs() / 60
        );
        if ok {
            let c = new_code();
            match st
                .codes
                .put(&email, &c, o.otp_ttl, o.otp_resend_after)
                .await
            {
                Err(e) => eprintln!("portal: store otp: {e}"),
                Ok(false) => {
                    page.notice = "인증 코드가 이미 발송되었습니다. 잠시 후 다시 요청하세요.".into()
                }
                Ok(true) => {
                    let (subject, body) = code_message(&c, o.otp_ttl);
                    if let Err(e) = st.mailer.send(&email, &subject, &body).await {
                        eprintln!("portal: send otp mail: {e}");
                    }
                }
            }
        } else {
            eprintln!(
                "portal: otp requested by ineligible address user={email} resource={}",
                g.log_id
            );
        }
        return render_page(st, StatusCode::OK, page);
    }

    let valid = match st.codes.check(&email, &code, o.otp_max_attempts).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("portal: check otp: {e}");
            false
        }
    };
    if !valid || !ok {
        page.error = "인증 코드가 올바르지 않거나 만료되었습니다.".into();
        return render_page(st, StatusCode::OK, page);
    }
    let mut resp = redirect(&g.base);
    set_session(st, &mut resp, &email);
    resp
}

/// The subject and body of the OTP mail.
pub fn code_message(code: &str, ttl: Duration) -> (String, String) {
    let subject = format!("[보안 메일] 첨부파일 다운로드 인증 코드 {code}");
    let body = format!(
        "보안 첨부파일 다운로드 인증 코드입니다.\n\n    인증 코드: {code}\n\n유효시간: {}분\n\
         본인이 요청하지 않았다면 이 메일을 무시하세요. 코드를 다른 사람에게 알려주지 마세요.\n",
        ttl.as_secs() / 60
    );
    (subject, body)
}

fn new_code() -> String {
    use rand::Rng;
    format!("{:06}", rand::rngs::OsRng.gen_range(0..1_000_000u32))
}

fn hash_key(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(parts.join("\0").as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---- OTP delivery ----

/// Delivers one-time codes to recipients.
#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String>;
}

/// Discards every mail (default when OTP is not configured).
pub struct NoopMailer;

#[async_trait]
impl Mailer for NoopMailer {
    async fn send(&self, _to: &str, _subject: &str, _body: &str) -> Result<(), String> {
        Ok(())
    }
}

/// Records every mail in memory (tests).
#[derive(Default)]
pub struct RecordingMailer {
    sent: Mutex<Vec<(String, String, String)>>,
}

impl RecordingMailer {
    pub fn new() -> Self {
        Self::default()
    }

    /// All recorded mails as (to, subject, body).
    pub fn sent(&self) -> Vec<(String, String, String)> {
        self.sent.lock().unwrap().clone()
    }

    /// The most recent 6-digit code mailed to `to`, if any.
    pub fn last_code(&self, to: &str) -> Option<String> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(t, _, _)| t == to)
            .and_then(|(_, s, _)| s.rsplit(' ').next())
            .map(str::to_string)
    }
}

#[async_trait]
impl Mailer for RecordingMailer {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        self.sent
            .lock()
            .unwrap()
            .push((to.into(), subject.into(), body.into()));
        Ok(())
    }
}

// ---- one-time code storage ----

/// Keeps one pending code per e-mail address.
#[async_trait]
pub trait CodeStore: Send + Sync {
    /// Stores `code` unless one was issued less than `resend_after` ago, in
    /// which case it returns false.
    async fn put(
        &self,
        email: &str,
        code: &str,
        ttl: Duration,
        resend_after: Duration,
    ) -> Result<bool, String>;
    /// Consumes the code on success. After `max_attempts` wrong guesses the
    /// pending code is destroyed.
    async fn check(&self, email: &str, code: &str, max_attempts: u32) -> Result<bool, String>;
}

struct MemCode {
    hash: String,
    exp: Instant,
    attempts: u32,
}

/// In-memory [`CodeStore`] (single-instance deployments and tests).
#[derive(Default)]
pub struct MemoryCodes {
    inner: Mutex<(HashMap<String, MemCode>, HashMap<String, Instant>)>,
}

impl MemoryCodes {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CodeStore for MemoryCodes {
    async fn put(
        &self,
        email: &str,
        code: &str,
        ttl: Duration,
        resend_after: Duration,
    ) -> Result<bool, String> {
        let mut g = self.inner.lock().unwrap();
        let (pending, sent_at) = &mut *g;
        let now = Instant::now();
        // Opportunistic cleanup.
        pending.retain(|_, p| p.exp > now);
        sent_at.retain(|_, t| now.duration_since(*t) < resend_after.max(ttl));
        if let Some(t) = sent_at.get(email) {
            if now.duration_since(*t) < resend_after {
                return Ok(false);
            }
        }
        sent_at.insert(email.to_string(), now);
        pending.insert(
            email.to_string(),
            MemCode {
                hash: hash_key(&[email, code]),
                exp: now + ttl,
                attempts: 0,
            },
        );
        Ok(true)
    }

    async fn check(&self, email: &str, code: &str, max_attempts: u32) -> Result<bool, String> {
        let mut g = self.inner.lock().unwrap();
        let pending = &mut g.0;
        let Some(p) = pending.get_mut(email) else {
            return Ok(false);
        };
        if Instant::now() > p.exp {
            pending.remove(email);
            return Ok(false);
        }
        if ct_eq(p.hash.as_bytes(), hash_key(&[email, code]).as_bytes()) {
            pending.remove(email);
            return Ok(true);
        }
        p.attempts += 1;
        if p.attempts >= max_attempts {
            pending.remove(email);
        }
        Ok(false)
    }
}

/// Escaped `<strong>` helper used by the page renderer.
pub(crate) fn strong(s: &str) -> String {
    format!("<strong>{}</strong>", esc(s).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn normalize_and_validate() {
        assert_eq!(
            normalize_email("  <Alice@Example.COM> "),
            "alice@example.com"
        );
        assert!(valid_email("a@b.c"));
        assert!(!valid_email("a@b"));
        assert!(!valid_email("@b.c"));
        assert!(!valid_email("a b@c.d"));
        assert!(!valid_email("a@b.c>"));
    }

    #[test]
    fn session_roundtrip_tamper_expiry() {
        let now = 1_000_000;
        let v = sign_session(SECRET, "alice@example.com", now + 60);
        assert_eq!(
            verify_session(SECRET, &v, now).as_deref(),
            Some("alice@example.com")
        );
        assert!(verify_session(SECRET, &format!("{v}x"), now).is_none());
        assert!(verify_session(b"other-secret-other-secret-other!", &v, now).is_none());
        assert!(verify_session(SECRET, &v, now + 61).is_none(), "expired");
        // Swapping the payload keeps the old signature -> rejected.
        let forged = sign_session(SECRET, "bob@example.com", now + 60);
        let sig = v.rsplit('.').next().unwrap();
        let mut parts: Vec<&str> = forged.split('.').collect();
        parts[2] = sig;
        assert!(verify_session(SECRET, &parts.join("."), now).is_none());
    }

    #[tokio::test]
    async fn memory_codes_single_use_resend_and_attempts() {
        let c = MemoryCodes::new();
        let ttl = Duration::from_secs(600);
        let ra = Duration::from_secs(60);
        assert!(c.put("a@x.y", "123456", ttl, ra).await.unwrap());
        assert!(
            !c.put("a@x.y", "654321", ttl, ra).await.unwrap(),
            "throttled"
        );
        assert!(!c.check("a@x.y", "000000", 3).await.unwrap());
        assert!(c.check("a@x.y", "123456", 3).await.unwrap());
        assert!(!c.check("a@x.y", "123456", 3).await.unwrap(), "single use");

        let c = MemoryCodes::new();
        c.put("b@x.y", "111111", ttl, ra).await.unwrap();
        for _ in 0..3 {
            assert!(!c.check("b@x.y", "999999", 3).await.unwrap());
        }
        assert!(
            !c.check("b@x.y", "111111", 3).await.unwrap(),
            "destroyed after max attempts"
        );

        let c = MemoryCodes::new();
        c.put("c@x.y", "222222", Duration::ZERO, Duration::ZERO)
            .await
            .unwrap();
        std::thread::sleep(Duration::from_millis(2));
        assert!(!c.check("c@x.y", "222222", 3).await.unwrap(), "expired");
    }

    #[test]
    fn code_mail() {
        let (s, b) = code_message("123456", Duration::from_secs(600));
        assert!(s.ends_with("123456"));
        assert!(b.contains("인증 코드: 123456") && b.contains("10분"));
        assert_eq!(new_code().len(), 6);
    }
}
