//! The user-facing web portal. Port of the Go `internal/portal`.
//!
//! ```text
//! GET  /dl/{token}            download gate (alias /d/{token}): streams the file
//!                             when CLEAN, else a status page (PENDING polls,
//!                             MALICIOUS/ERROR 403, EXPIRED 410)
//! GET  /dl/{token}/status     JSON status (polled by the PENDING page)
//! POST /dl/{token}/auth       OTP login (otp mode)
//! POST /dl/{token}/logout     end the session
//! GET  /dlp/{token}           DLP hold review page (admins), see `dlp`
//! POST /dlp/{token}/release|reject|auth|logout
//! GET  /dlp/admin[...]        DLP admin dashboard, see `admin`
//! ```
//!
//! Every response carries the Go `securityHeaders`; HTML pages add a CSP with a
//! per-request nonce. Cross-site POSTs are rejected (`Sec-Fetch-Site` /
//! `Origin`). Token lookups are rate limited per client IP, with a separate
//! enumeration budget charged on misses.

// Handlers return `Result<_, Response>` so a guard can hand back the exact
// challenge/denial page to send (the idiomatic axum early-return pattern).
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    extract::{ConnectInfo, Path, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use chrono::{DateTime, FixedOffset, Utc};
use futures_util::StreamExt;

use crate::metrics::Metrics;
use crate::model::{Attachment, Status};
use crate::storage::Storage;
use crate::store::{Store, StoreError};

mod admin;
mod auth;
mod dlp;
mod html;
mod limiter;
mod proxy;
#[cfg(test)]
mod tests;

pub use admin::csv_safe;
pub use auth::{
    code_message, normalize_email, sign_session, valid_email, verify_session, CodeCheck, CodeStore,
    Mailer, MemoryCodes, NoopMailer, RecordingMailer, SESSION_COOKIE,
};
pub use dlp::{truncate, HoldReviewer, StoreHoldReviewer};
pub use html::html_escape;
pub use proxy::{bucket_key, parse_nets, Net};

use auth::OtpGuard;
use auth::{authorize, Guard, Who};
use html::{esc, fill, Html};
use limiter::IpLimiter;

pub(crate) const MSG_TEMP_ERROR: &str = "일시적인 오류가 발생했습니다.";
pub(crate) const MSG_TOO_MANY: &str = "요청이 너무 많습니다. 잠시 후 다시 시도하세요.";

/// Recipient authentication mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AuthMode {
    /// Anyone holding the link (no identity).
    #[default]
    None,
    /// One-time code mailed to the recipient, then a signed session cookie.
    Otp,
    /// A trusted reverse-proxy header carries the authenticated address.
    Header,
}

impl AuthMode {
    /// Parses the config value (`""`/`none`, `otp`, `header`).
    pub fn parse(s: &str) -> Option<AuthMode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "none" => Some(AuthMode::None),
            "otp" => Some(AuthMode::Otp),
            "header" => Some(AuthMode::Header),
            _ => None,
        }
    }
}

/// Portal configuration.
#[derive(Clone, Debug)]
pub struct PortalOptions {
    pub auth_mode: AuthMode,
    /// HMAC-SHA256 key for the session cookie (otp mode; >= 32 bytes).
    pub session_secret: Vec<u8>,
    pub session_ttl: Duration,
    pub otp_ttl: Duration,
    pub otp_max_attempts: u32,
    pub otp_resend_after: Duration,
    /// Envelope sender of OTP mails (used by the `Mailer` implementation).
    pub otp_from: String,
    /// Header carrying the authenticated address (header mode).
    pub trusted_header: String,
    /// Sets the cookie `Secure` flag (portal served over HTTPS).
    pub secure_cookie: bool,
    /// Lets any user of an accepted domain open attachment links.
    pub allow_domain_users: bool,
    pub accepted_domains: Vec<String>,
    /// DLP admins: review pages + dashboard with release/reject.
    pub dlp_admins: Vec<String>,
    /// DLP auditors: read-only dashboard (list, events, audit, export).
    pub dlp_auditors: Vec<String>,
    /// Used to validate the Origin of POST requests.
    pub public_base_url: String,
    /// Display time zone: offset east of UTC in minutes, and its label.
    pub tz_offset_minutes: i32,
    /// Label printed after times (empty: "UTC" or the numeric offset).
    pub tz_label: String,
    /// General per-IP lookup budget (`rps <= 0` disables it).
    pub rate_limit_rps: f64,
    pub rate_limit_burst: i64,
    /// Enumeration (failed lookup) budget; non-positive -> defaults (10, 20/s).
    pub enum_per_ip_burst: i64,
    pub enum_global_rps: f64,
    /// Take the client IP from X-Forwarded-For. Only honoured for requests
    /// whose TCP peer is a trusted proxy (see [`Portal::with_trusted_proxies`]).
    pub trust_proxy_headers: bool,
}

impl Default for PortalOptions {
    fn default() -> Self {
        PortalOptions {
            auth_mode: AuthMode::None,
            session_secret: Vec::new(),
            session_ttl: Duration::from_secs(12 * 3600),
            otp_ttl: Duration::from_secs(10 * 60),
            otp_max_attempts: 5,
            otp_resend_after: Duration::from_secs(60),
            otp_from: String::new(),
            trusted_header: String::new(),
            secure_cookie: false,
            allow_domain_users: false,
            accepted_domains: Vec::new(),
            dlp_admins: Vec::new(),
            dlp_auditors: Vec::new(),
            public_base_url: String::new(),
            tz_offset_minutes: 0,
            tz_label: String::new(),
            rate_limit_rps: 5.0,
            rate_limit_burst: 20,
            enum_per_ip_burst: 0,
            enum_global_rps: 0.0,
            trust_proxy_headers: false,
        }
    }
}

/// The portal's core dependencies. Kept to exactly these three public fields
/// so existing `PortalState { store, storage, metrics }` literals compile; its
/// `with_*` setters return a fully configurable [`Portal`].
#[derive(Clone)]
pub struct PortalState {
    pub store: Arc<dyn Store>,
    pub storage: Arc<dyn Storage>,
    pub metrics: Arc<Metrics>,
}

impl PortalState {
    pub fn new(store: Arc<dyn Store>, storage: Arc<dyn Storage>, metrics: Arc<Metrics>) -> Self {
        PortalState {
            store,
            storage,
            metrics,
        }
    }

    /// See [`Portal::with_options`].
    pub fn with_options(self, options: PortalOptions) -> Portal {
        Portal::from(self).with_options(options)
    }

    /// See [`Portal::with_mailer`].
    pub fn with_mailer(self, mailer: Arc<dyn Mailer>) -> Portal {
        Portal::from(self).with_mailer(mailer)
    }

    /// See [`Portal::with_codes`].
    pub fn with_codes(self, codes: Arc<dyn CodeStore>) -> Portal {
        Portal::from(self).with_codes(codes)
    }

    /// See [`Portal::with_holds`].
    pub fn with_holds(self, holds: Arc<dyn HoldReviewer>) -> Portal {
        Portal::from(self).with_holds(holds)
    }

    /// See [`Portal::with_store_holds`].
    pub fn with_store_holds(self) -> Portal {
        Portal::from(self).with_store_holds()
    }
}

impl From<PortalState> for Portal {
    fn from(s: PortalState) -> Portal {
        Portal::new(s.store, s.storage, s.metrics)
    }
}

/// The full portal state handed to the router: dependencies, options, OTP
/// mailer / code store and the (optional) DLP hold reviewer. Build with
/// [`Portal::new`] (or [`PortalState::new`]) and the `with_*` setters.
#[derive(Clone)]
pub struct Portal {
    pub store: Arc<dyn Store>,
    pub storage: Arc<dyn Storage>,
    pub metrics: Arc<Metrics>,
    pub mailer: Arc<dyn Mailer>,
    pub codes: Arc<dyn CodeStore>,
    pub holds: Option<Arc<dyn HoldReviewer>>,
    options: Arc<PortalOptions>,
    limiter: Arc<IpLimiter>,
    /// Reverse proxies whose X-Forwarded-For / identity header is trusted.
    trusted_proxies: Arc<Vec<Net>>,
    otp_guard: Arc<OtpGuard>,
}

impl Portal {
    /// Download-only portal with default options (auth `none`, no DLP pages).
    pub fn new(store: Arc<dyn Store>, storage: Arc<dyn Storage>, metrics: Arc<Metrics>) -> Self {
        let options = PortalOptions::default();
        Portal {
            store,
            storage,
            metrics,
            mailer: Arc::new(NoopMailer),
            codes: Arc::new(MemoryCodes::new()),
            holds: None,
            limiter: Arc::new(limiter_for(&options)),
            options: Arc::new(options),
            trusted_proxies: Arc::new(Vec::new()),
            otp_guard: Arc::new(OtpGuard::new(
                auth::OTP_LOCKOUT_FAILURES,
                auth::OTP_LOCKOUT_WINDOW,
            )),
        }
    }

    /// Sets the reverse proxies (IP addresses or CIDR networks) allowed to
    /// supply `X-Forwarded-For` (with `trust_proxy_headers`) and the identity
    /// header (header auth mode). Requests from any other peer have those
    /// headers ignored. Errors on an unparsable entry.
    pub fn with_trusted_proxies(mut self, proxies: &[String]) -> Result<Self, String> {
        self.trusted_proxies = Arc::new(parse_nets(proxies)?);
        Ok(self)
    }

    /// Per-address OTP lockout: after `max_failures` wrong codes within
    /// `window` (across re-sent codes) the address is locked for the rest of
    /// the window; no code is accepted or sent meanwhile. Defaults: 10 / 1h.
    pub fn with_otp_lockout(mut self, max_failures: u32, window: Duration) -> Self {
        self.otp_guard = Arc::new(OtpGuard::new(max_failures, window));
        self
    }

    /// Replaces the options (and rebuilds the rate limiter from them).
    pub fn with_options(mut self, options: PortalOptions) -> Self {
        self.limiter = Arc::new(limiter_for(&options));
        self.options = Arc::new(options);
        self
    }

    /// Sets the OTP mailer.
    pub fn with_mailer(mut self, mailer: Arc<dyn Mailer>) -> Self {
        self.mailer = mailer;
        self
    }

    /// Sets the OTP code store (default: in-memory).
    pub fn with_codes(mut self, codes: Arc<dyn CodeStore>) -> Self {
        self.codes = codes;
        self
    }

    /// Enables the DLP review pages and admin dashboard.
    pub fn with_holds(mut self, holds: Arc<dyn HoldReviewer>) -> Self {
        self.holds = Some(holds);
        self
    }

    /// Enables the DLP pages backed by [`StoreHoldReviewer`] (decisions are
    /// recorded in the store; relaying is wired elsewhere).
    pub fn with_store_holds(self) -> Self {
        let r = Arc::new(StoreHoldReviewer::new(self.store.clone()));
        self.with_holds(r)
    }

    pub fn options(&self) -> &PortalOptions {
        &self.options
    }

    /// Formats a time in the configured zone ("2006-01-02 15:04 MST" style).
    pub(crate) fn fmt_time(&self, t: DateTime<Utc>, with_zone: bool) -> String {
        let o = &self.options;
        let off = FixedOffset::east_opt(o.tz_offset_minutes * 60)
            .unwrap_or_else(|| FixedOffset::east_opt(0).unwrap());
        let s = t.with_timezone(&off).format("%Y-%m-%d %H:%M").to_string();
        if !with_zone {
            return s;
        }
        let label = if !o.tz_label.is_empty() {
            o.tz_label.clone()
        } else if o.tz_offset_minutes == 0 {
            "UTC".into()
        } else {
            off.to_string()
        };
        format!("{s} {label}")
    }
}

fn limiter_for(o: &PortalOptions) -> IpLimiter {
    IpLimiter::new(
        o.rate_limit_rps,
        o.rate_limit_burst,
        o.enum_per_ip_burst,
        o.enum_global_rps,
        0,
    )
}

/// Builds the portal router.
pub fn router(state: impl Into<Portal>) -> Router {
    let state: Portal = state.into();
    let mut r = Router::new();
    for p in ["/dl", "/d"] {
        r = r
            .route(&format!("{p}/{{token}}"), get(download))
            .route(&format!("{p}/{{token}}/status"), get(status))
            .route(&format!("{p}/{{token}}/auth"), post(auth_post))
            .route(&format!("{p}/{{token}}/logout"), post(logout));
    }
    if state.holds.is_some() {
        r = r
            .route("/dlp/{token}", get(dlp::hold_page))
            .route("/dlp/{token}/auth", post(dlp::hold_auth))
            .route("/dlp/{token}/logout", post(dlp::hold_logout))
            .route("/dlp/{token}/release", post(dlp::hold_release))
            .route("/dlp/{token}/reject", post(dlp::hold_reject))
            .route("/dlp/admin", get(admin::dashboard))
            .route("/dlp/admin/holds", get(admin::holds))
            .route("/dlp/admin/events", get(admin::events))
            .route("/dlp/admin/audit", get(admin::audit))
            .route("/dlp/admin/export", get(admin::export))
            .route("/dlp/admin/auth", post(admin::auth))
            .route("/dlp/admin/logout", post(admin::logout))
            .route("/dlp/admin/holds/{id}/release", post(admin::release))
            .route("/dlp/admin/holds/{id}/reject", post(admin::reject));
    }
    r.layer(middleware::from_fn_with_state(state.clone(), check_origin))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

// ---- middleware ----

async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    // Never leak the token URL to other sites.
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        "x-robots-tag",
        HeaderValue::from_static("noindex, nofollow"),
    );
    if !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        );
    }
    resp
}

/// Rejects cross-site form posts (CSRF). Modern browsers send Sec-Fetch-Site;
/// older ones are checked via Origin. Requests carrying neither (non-browser
/// clients) are allowed.
async fn check_origin(State(st): State<Portal>, req: Request, next: Next) -> Response {
    if req.method() == Method::POST && !same_origin(&st.options.public_base_url, req.headers()) {
        return (StatusCode::FORBIDDEN, "cross-origin request rejected").into_response();
    }
    next.run(req).await
}

/// Host[:port] of an absolute URL, lower-cased ("" when unparsable).
fn url_host(u: &str) -> String {
    let Some((scheme, rest)) = u.split_once("://") else {
        return String::new();
    };
    if scheme.is_empty() {
        return String::new();
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or("");
    host.to_ascii_lowercase()
}

pub(crate) fn same_origin(public_base_url: &str, h: &HeaderMap) -> bool {
    let hv = |n: &str| h.get(n).and_then(|v| v.to_str().ok()).unwrap_or("");
    match hv("sec-fetch-site") {
        "same-origin" | "none" => return true,
        "" => {}
        _ => return false, // same-site, cross-site
    }
    let o = hv("origin");
    if o.is_empty() {
        return true;
    }
    if o == "null" {
        return false;
    }
    let oh = url_host(o);
    if oh.is_empty() {
        return false;
    }
    let allowed = url_host(public_base_url);
    (!allowed.is_empty() && oh == allowed) || oh.eq_ignore_ascii_case(hv("host"))
}

// ---- request context ----

/// The parts of a request the handlers use, with the body parsed as a form.
pub(crate) struct Req {
    pub path: String,
    pub headers: HeaderMap,
    pub query: HashMap<String, String>,
    pub form: HashMap<String, String>,
    pub ip: String,
    /// The TCP peer is a configured trusted proxy (identity header honoured).
    pub peer_trusted: bool,
}

impl Req {
    pub(crate) async fn read(st: &Portal, req: Request) -> Req {
        let (parts, body) = req.into_parts();
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(a)| a.ip());
        let ip = client_ip(st, &parts.headers, peer);
        let peer_trusted = proxy::is_trusted(peer, &st.trusted_proxies);
        let query = parse_urlencoded(parts.uri.query().unwrap_or(""));
        let form = if parts.method == Method::POST {
            match axum::body::to_bytes(body, 64 * 1024).await {
                Ok(b) => parse_urlencoded(&String::from_utf8_lossy(&b)),
                Err(_) => HashMap::new(),
            }
        } else {
            HashMap::new()
        };
        Req {
            path: parts.uri.path().to_string(),
            headers: parts.headers,
            query,
            form,
            ip,
            peer_trusted,
        }
    }

    pub(crate) fn form_value(&self, k: &str) -> &str {
        self.form.get(k).map(String::as_str).unwrap_or("")
    }

    pub(crate) fn query_value(&self, k: &str) -> &str {
        self.query.get(k).map(String::as_str).unwrap_or("")
    }

    fn user_agent(&self) -> String {
        self.headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
}

/// The client address: the TCP peer, or (behind a trusted proxy with
/// `trust_proxy_headers`) the rightmost untrusted X-Forwarded-For hop.
fn client_ip(st: &Portal, h: &HeaderMap, peer: Option<std::net::IpAddr>) -> String {
    let xff: Vec<&str> = h
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    match proxy::client_ip(
        peer,
        &xff,
        st.options.trust_proxy_headers,
        &st.trusted_proxies,
    ) {
        Some(ip) => ip.to_string(),
        None => "unknown".into(),
    }
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses an `application/x-www-form-urlencoded` string (first value wins).
pub(crate) fn parse_urlencoded(s: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for pair in s.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        m.entry(pct_decode(k)).or_insert_with(|| pct_decode(v));
    }
    m
}

// ---- shared responses ----

pub(crate) fn json_response(code: StatusCode, v: serde_json::Value) -> Response {
    (code, axum::Json(v)).into_response()
}

pub(crate) fn json_error(code: StatusCode, msg: &str) -> Response {
    json_response(code, serde_json::json!({ "error": msg }))
}

pub(crate) fn redirect(loc: &str) -> Response {
    let mut r = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(loc) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r
}

/// Error page (or JSON error) for a failed request.
pub(crate) fn fail(st: &Portal, code: StatusCode, as_json: bool, msg: &str) -> Response {
    if as_json {
        return json_error(code, code.canonical_reason().unwrap_or("error"));
    }
    let mut d = PageData::state(if code == StatusCode::NOT_FOUND {
        "NOTFOUND"
    } else {
        "FAILURE"
    });
    d.message = msg.to_string();
    render_page(st, code, d)
}

fn throttled(st: &Portal, as_json: bool, retry_after: &'static str) -> Response {
    st.metrics
        .portal_requests
        .with_label_values(&["throttled"])
        .inc();
    let mut r = fail(st, StatusCode::TOO_MANY_REQUESTS, as_json, MSG_TOO_MANY);
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static(retry_after));
    r
}

/// Handles a lookup that resolved nothing: charges the enumeration budget and
/// returns 429 once the client (or the gateway as a whole) guesses too fast,
/// else an identical 404 for every unknown token.
pub(crate) fn miss(st: &Portal, r: &Req, as_json: bool) -> Response {
    if !st.limiter.allow_fail(&r.ip) {
        eprintln!("portal: token enumeration throttled ip={}", r.ip);
        return throttled(st, as_json, "30");
    }
    st.metrics
        .portal_requests
        .with_label_values(&["notfound"])
        .inc();
    fail(st, StatusCode::NOT_FOUND, as_json, "")
}

/// General per-IP throttle check for a token lookup.
pub(crate) fn check_rate(st: &Portal, r: &Req, as_json: bool) -> Result<(), Response> {
    if st.limiter.allow(&r.ip) {
        Ok(())
    } else {
        Err(throttled(st, as_json, "5"))
    }
}

/// Rejects obviously invalid tokens before touching the store.
pub(crate) fn well_formed(tok: &str) -> bool {
    !tok.is_empty()
        && tok.len() <= 128
        && tok
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

// ---- download page rendering ----

/// Data for `page.html`.
#[derive(Default)]
pub(crate) struct PageData {
    pub state: &'static str,
    pub base: String,
    pub filename: String,
    pub size: i64,
    pub threat_name: String,
    pub expires: String,
    pub message: String,
    pub user: String,
    pub email: String,
    pub error: String,
    pub notice: String,
    pub can_logout: bool,
}

impl PageData {
    pub(crate) fn state(state: &'static str) -> Self {
        PageData {
            state,
            ..Default::default()
        }
    }
}

pub(crate) fn render_page(_st: &Portal, code: StatusCode, d: PageData) -> Response {
    let nonce = html::nonce();
    let content: Html = match d.state {
        "PENDING" => Html::raw(
            r#"<span class="badge">검사 중</span>
  <h1>보안 검사가 진행 중입니다</h1>
  <p><span class="spinner"></span>현재 첨부파일의 악성코드 검사가 진행 중입니다. (예상 소요시간: 약 10초)</p>
  <p>검사가 끝나면 이 페이지가 자동으로 갱신되고 다운로드가 시작됩니다.</p>"#,
        ),
        "MALICIOUS" => {
            let mut h = Html::raw(
                r#"<span class="badge">위협 감지</span>
  <h1>다운로드가 차단되었습니다</h1>
  <p>해당 파일에서 악성코드가 감지되어 다운로드가 제한되었습니다.</p>"#,
            );
            if !d.threat_name.is_empty() {
                h.push_raw(r#"<p>탐지명: <span class="threat">"#);
                h.push_esc(&d.threat_name);
                h.push_raw("</span></p>");
            }
            h.push_raw("<p>발신자를 확인할 수 없다면 이 메일에 회신하거나 링크를 열지 말고 보안 담당자에게 신고하세요.</p>");
            h
        }
        "ERROR" => Html::raw(
            r#"<span class="badge">검사 실패</span>
  <h1>다운로드가 차단되었습니다</h1>
  <p>보안 검사를 완료하지 못해 안전을 위해 다운로드를 차단했습니다. 필요한 경우 보안 담당자에게 문의하세요.</p>"#,
        ),
        "EXPIRED" => Html::raw(
            r#"<span class="badge">만료</span>
  <h1>링크가 만료되었습니다</h1>
  <p>보관 기간이 지나 파일이 삭제되었습니다. 발신자에게 파일을 다시 요청하세요.</p>"#,
        ),
        "LOGIN" => Html::raw(
            r#"<span class="badge">수신자 확인</span>
  <h1>수신자 본인 확인이 필요합니다</h1>
  <p>이 첨부파일은 메일 수신자만 받을 수 있습니다. 메일을 받은 이메일 주소를 입력하면 인증 코드를 보내드립니다.</p>"#,
        ),
        "CODE" => Html::raw(format!(
            r#"<span class="badge">인증 코드</span>
  <h1>인증 코드를 입력하세요</h1>
  <p>{} 받은편지함에서 6자리 코드를 확인하세요.</p>"#,
            auth::strong(&d.email)
        )),
        "FORBIDDEN" => Html::raw(format!(
            r#"<span class="badge">권한 없음</span>
  <h1>이 파일에 접근할 권한이 없습니다</h1>
  <p>{} 계정은 이 메일의 수신자가 아닙니다.</p>"#,
            auth::strong(&d.user)
        )),
        "AUTHREQ" => Html::raw(
            r#"<span class="badge">로그인 필요</span>
  <h1>로그인이 필요합니다</h1>
  <p>회사 SSO 로그인 후 다시 시도하세요.</p>"#,
        ),
        "NOTFOUND" => Html::raw(
            r#"<span class="badge">없음</span>
  <h1>파일을 찾을 수 없습니다</h1>
  <p>링크가 올바르지 않거나 존재하지 않는 파일입니다.</p>"#,
        ),
        _ => {
            let mut h = Html::raw(
                r#"<span class="badge">오류</span>
  <h1>요청을 처리하지 못했습니다</h1>
  <p>"#,
            );
            h.push_esc(&d.message);
            h.push_raw("</p>");
            h
        }
    };

    let mut file = Html::default();
    if !d.filename.is_empty() {
        file.push_raw(r#"<div class="file"><strong>"#);
        file.push_esc(&d.filename);
        file.push_raw("</strong><br><small>");
        file.push_esc(&format!(
            "{} · 보관 기한 {}",
            html::human_size(d.size),
            d.expires
        ));
        file.push_raw("</small></div>");
    }

    let messages = messages_html(&d.error, &d.notice);

    let base = esc(&d.base).into_string();
    let forms = match d.state {
        "LOGIN" => Html::raw(format!(
            r#"<form method="post" action="{base}/auth">
    <label for="email">수신 이메일 주소</label>
    <input id="email" name="email" type="email" autocomplete="email" required autofocus>
    <button type="submit">인증 코드 받기</button>
  </form>"#
        )),
        "CODE" => {
            let email = esc(&d.email).into_string();
            Html::raw(format!(
                r#"<form method="post" action="{base}/auth">
    <input type="hidden" name="email" value="{email}">
    <label for="code">인증 코드</label>
    <input id="code" class="code" name="code" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6"
           autocomplete="one-time-code" required autofocus>
    <button type="submit">확인</button>
  </form>
  <form method="post" action="{base}/auth">
    <input type="hidden" name="email" value="{email}">
    <button class="secondary" type="submit">코드 다시 받기</button>
  </form>"#
            ))
        }
        _ => Html::default(),
    };

    let userbar = userbar_html(
        &d.user,
        d.can_logout,
        &format!("{}/logout", d.base),
        "다른 주소로 로그인",
    );

    let script = if d.state == "PENDING" {
        let url = html::js_string(&format!("{}/status", d.base)).into_string();
        Html::raw(format!(
            r#"<script nonce="{n}">
(function () {{
  var url = {url};
  var delay = 3000, tries = 0;
  function poll() {{
    fetch(url, {{ cache: "no-store", credentials: "same-origin" }})
      .then(function (r) {{ return r.ok ? r.json() : null; }})
      .then(function (j) {{
        if (j && j.status && j.status !== "PENDING") {{ location.reload(); return; }}
        schedule();
      }})
      .catch(schedule);
  }}
  function schedule() {{
    tries++;
    if (tries > 20) delay = 10000; // back off after ~1 minute
    setTimeout(poll, delay);
  }}
  schedule();
}})();
</script>"#,
            n = esc(&nonce).into_string()
        ))
    } else {
        Html::default()
    };

    let body = fill(
        html::PAGE,
        &[
            ("nonce", esc(&nonce)),
            ("styles", Html::raw(html::STYLES)),
            ("state", esc(d.state)),
            ("content", content),
            ("file", file),
            ("messages", messages),
            ("forms", forms),
            ("userbar", userbar),
            ("script", script),
        ],
    );
    html::html_response(code, &html::csp_with_script(&nonce), body)
}

pub(crate) fn messages_html(error: &str, notice: &str) -> Html {
    let mut h = Html::default();
    if !error.is_empty() {
        h.push_raw(r#"<div class="msg err">"#);
        h.push_esc(error);
        h.push_raw("</div>");
    }
    if !notice.is_empty() {
        h.push_raw(r#"<div class="msg info">"#);
        h.push_esc(notice);
        h.push_raw("</div>");
    }
    h
}

pub(crate) fn userbar_html(user: &str, can_logout: bool, logout_action: &str, label: &str) -> Html {
    let mut h = Html::default();
    if user.is_empty() {
        return h;
    }
    h.push_raw(r#"<div class="userbar"><span>"#);
    h.push_esc(user);
    h.push_raw("</span>");
    if can_logout {
        h.push_raw(r#"<form method="post" action=""#);
        h.push_esc(logout_action);
        h.push_raw(r#""><button class="link" type="submit">"#);
        h.push_esc(label);
        h.push_raw("</button></form>");
    }
    h.push_raw("</div>");
    h
}

// ---- download handlers ----

/// "/dl/" or "/d/" depending on the route the request came in on.
fn link_base(r: &Req, token: &str) -> String {
    let prefix = if r.path.starts_with("/d/") {
        "/d/"
    } else {
        "/dl/"
    };
    format!("{prefix}{token}")
}

fn effective_status(status: &Status, expires_at: DateTime<Utc>) -> Status {
    if *status == Status::Expired || Utc::now() > expires_at {
        Status::Expired
    } else {
        *status
    }
}

/// Resolves the path token to an attachment, or the response to send.
async fn lookup(st: &Portal, r: &Req, token: &str, as_json: bool) -> Result<Attachment, Response> {
    check_rate(st, r, as_json)?;
    if !well_formed(token) {
        return Err(miss(st, r, as_json));
    }
    match st
        .store
        .get_attachment_by_token_hash(&sha256_hex(token.as_bytes()))
        .await
    {
        Ok(a) => Ok(a),
        Err(StoreError::NotFound) => Err(miss(st, r, as_json)),
        Err(e) => {
            st.metrics
                .portal_requests
                .with_label_values(&["error"])
                .inc();
            eprintln!("portal: lookup failed: {e}");
            Err(fail(
                st,
                StatusCode::INTERNAL_SERVER_ERROR,
                as_json,
                MSG_TEMP_ERROR,
            ))
        }
    }
}

fn attachment_guard(base: String, a: &Attachment) -> Guard {
    Guard {
        base,
        who: Who::Recipients(a.message_id.clone()),
        log_id: a.id.clone(),
    }
}

async fn download(State(st): State<Portal>, Path(token): Path<String>, req: Request) -> Response {
    let r = Req::read(&st, req).await;
    let base = link_base(&r, &token);
    let a = match lookup(&st, &r, &token, false).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let user = match authorize(&st, &r, &attachment_guard(base.clone(), &a), false).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let state = effective_status(&a.status, a.expires_at);
    if state != Status::Clean {
        let code = match state {
            Status::Pending => StatusCode::OK,
            Status::Expired => StatusCode::GONE,
            _ => StatusCode::FORBIDDEN,
        };
        if state != Status::Pending {
            st.metrics
                .portal_requests
                .with_label_values(&["denied"])
                .inc();
        }
        let mut d = PageData::state(state.as_str());
        d.base = base;
        d.filename = a.filename.clone();
        d.size = a.size;
        d.threat_name = a.threat_name.clone();
        d.expires = st.fmt_time(a.expires_at, true);
        d.can_logout = !user.is_empty() && st.options.auth_mode == AuthMode::Otp;
        d.user = user;
        return render_page(&st, code, d);
    }

    // Stream the object (never buffered whole). The first chunk is read
    // before answering so an unreadable / undecryptable object still gets a
    // proper error page; a failure later aborts the response mid-body (the
    // client sees a truncated transfer, never a "complete" corrupt file).
    let opened = match st.storage.get_stream(&a.storage_key).await {
        Ok(mut s) => match s.next().await {
            Some(Err(e)) => Err(e.to_string()),
            first => Ok((first, s)),
        },
        Err(e) => Err(e.to_string()),
    };
    let (first, rest) = match opened {
        Ok(x) => x,
        Err(e) => {
            st.metrics
                .portal_requests
                .with_label_values(&["error"])
                .inc();
            eprintln!("portal: open object attachment={}: {e}", a.id);
            return fail(
                &st,
                StatusCode::INTERNAL_SERVER_ERROR,
                false,
                "파일을 불러오지 못했습니다.",
            );
        }
    };

    if let Err(e) = st
        .store
        .record_download(crate::model::DownloadEvent {
            attachment_id: a.id.clone(),
            user: user.clone(),
            remote_ip: r.ip.clone(),
            user_agent: r.user_agent(),
            at: Utc::now(),
        })
        .await
    {
        eprintln!("portal: record download: {e}");
    }
    st.metrics.portal_requests.with_label_values(&["ok"]).inc();

    let attachment_id = a.id.clone();
    let expected = u64::try_from(a.size).ok();
    let body = futures_util::stream::iter(first).chain(rest);
    let body = exact_length(body, expected).inspect(move |c| {
        if let Err(e) = c {
            eprintln!("portal: download aborted attachment={attachment_id}: {e}");
        }
    });
    let mut resp = Response::new(Body::from_stream(body));
    let h = resp.headers_mut();
    // The plaintext size is known: declare it so a body that ends early (a
    // decrypt / read error mid-stream) is a visible framing error for every
    // client, including HTTP/1.0 ones (nginx's default upstream protocol)
    // where a close-delimited body would otherwise look complete.
    if let Some(n) = expected {
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(n));
    }
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(v) = HeaderValue::from_str(&content_disposition(&a.filename)) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    resp
}

async fn status(State(st): State<Portal>, Path(token): Path<String>, req: Request) -> Response {
    let r = Req::read(&st, req).await;
    let base = link_base(&r, &token);
    let a = match lookup(&st, &r, &token, true).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if let Err(resp) = authorize(&st, &r, &attachment_guard(base, &a), true).await {
        return resp;
    }
    let mut v = serde_json::json!({
        "status": effective_status(&a.status, a.expires_at),
        "filename": a.filename,
        "size": a.size,
        "expires_at": a.expires_at,
    });
    if !a.threat_name.is_empty() {
        v["threat_name"] = a.threat_name.clone().into();
    }
    json_response(StatusCode::OK, v)
}

async fn auth_post(State(st): State<Portal>, Path(token): Path<String>, req: Request) -> Response {
    if st.options.auth_mode != AuthMode::Otp {
        return (StatusCode::NOT_FOUND, "404 page not found").into_response();
    }
    let r = Req::read(&st, req).await;
    let base = link_base(&r, &token);
    let a = match lookup(&st, &r, &token, false).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    auth::otp_login(&st, &r, &attachment_guard(base, &a)).await
}

async fn logout(State(st): State<Portal>, Path(token): Path<String>, req: Request) -> Response {
    let r = Req::read(&st, req).await;
    let base = if well_formed(&token) {
        link_base(&r, &token)
    } else {
        "/".into()
    };
    let mut resp = redirect(&base);
    auth::clear_session(&st, &mut resp);
    resp
}

/// Passes `s` through, but fails the stream unless it yields exactly
/// `expected` bytes (when known): a short or overlong object is an error that
/// aborts the response rather than a "complete" transfer of the wrong file.
pub(crate) fn exact_length<S>(
    s: S,
    expected: Option<u64>,
) -> impl futures_util::Stream<Item = std::io::Result<axum::body::Bytes>> + Send
where
    S: futures_util::Stream<Item = std::io::Result<axum::body::Bytes>> + Send + Unpin,
{
    futures_util::stream::unfold((s, 0u64, false), move |(mut s, seen, done)| async move {
        if done {
            return None;
        }
        let Some(want) = expected else {
            return s.next().await.map(|c| (c, (s, seen, false)));
        };
        match s.next().await {
            Some(Ok(c)) => {
                let seen = seen + c.len() as u64;
                if seen > want {
                    let e = std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("object longer than its recorded size {want}"),
                    );
                    return Some((Err(e), (s, seen, true)));
                }
                Some((Ok(c), (s, seen, false)))
            }
            Some(Err(e)) => Some((Err(e), (s, seen, true))),
            None if seen != want => {
                let e = std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("object ended after {seen} of {want} bytes"),
                );
                Some((Err(e), (s, seen, true)))
            }
            None => None,
        }
    })
}

/// Builds an "attachment" Content-Disposition that is always a safe bare
/// filename, with an ASCII fallback and an RFC 5987 UTF-8 `filename*`.
pub fn content_disposition(name: &str) -> String {
    // Bare filename (drop directory components on either separator).
    let bare = &name[name.rfind(['/', '\\']).map(|i| i + 1).unwrap_or(0)..];
    let cleaned: String = bare
        .chars()
        .filter(|&c| c as u32 >= 0x20 && c as u32 != 0x7f)
        .collect();
    let cleaned = cleaned.trim();
    let cleaned = if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "download"
    } else {
        cleaned
    };

    let ascii: String = cleaned
        .chars()
        .map(|c| {
            let u = c as u32;
            if !(0x20..=0x7e).contains(&u) || c == '"' || c == '\\' {
                '_'
            } else {
                c
            }
        })
        .collect();
    let mut disp = format!("attachment; filename=\"{ascii}\"");
    let enc = rfc5987(cleaned);
    if enc != ascii {
        disp.push_str(&format!("; filename*=UTF-8''{enc}"));
    }
    disp
}

/// RFC 5987 value-chars percent-encoding.
fn rfc5987(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            );
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
