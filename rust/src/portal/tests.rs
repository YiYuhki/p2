//! Portal tests over real HTTP (127.0.0.1:0, raw HTTP/1.1). Ports of the Go
//! `internal/portal/*_test.go` that apply to the Rust download flow.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::model::{DlpEvent, Hold, HoldStatus, Message};
use crate::storage::Fs;
use crate::store::Memory;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

// ---------- raw HTTP client ----------

struct Resp {
    code: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(i) = b.windows(2).position(|w| w == b"\r\n") {
        let size_line = String::from_utf8_lossy(&b[..i]);
        let size =
            usize::from_str_radix(size_line.split(';').next().unwrap().trim(), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        let start = i + 2;
        out.extend_from_slice(&b[start..start + size]);
        b = &b[start + size + 2..];
    }
    out
}

async fn send(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    form: Option<&str>,
) -> Resp {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    let body = form.unwrap_or("");
    if method == "POST" {
        req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&buf[..split]).into_owned();
    let raw_body = &buf[split + 4..];
    let mut lines = head.split("\r\n");
    let code: u16 = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.contains("chunked"));
    let body = if chunked {
        dechunk(raw_body)
    } else {
        raw_body.to_vec()
    };
    Resp {
        code,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// A client that keeps the session cookie (like a browser cookie jar).
struct Browser {
    addr: String,
    cookie: Option<String>,
    extra: Vec<(String, String)>,
}

impl Browser {
    fn new(addr: &str) -> Self {
        Browser {
            addr: addr.into(),
            cookie: None,
            extra: Vec::new(),
        }
    }

    async fn req(&mut self, method: &str, path: &str, form: Option<&str>) -> Resp {
        let cookie = self
            .cookie
            .as_ref()
            .map(|c| format!("{SESSION_COOKIE}={c}"));
        let mut h: Vec<(&str, &str)> = self
            .extra
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        if let Some(c) = &cookie {
            h.push(("Cookie", c));
        }
        let r = send(&self.addr, method, path, &h, form).await;
        for (k, v) in &r.headers {
            if k == "set-cookie" {
                let first = v.split(';').next().unwrap();
                if let Some(val) = first.strip_prefix(&format!("{SESSION_COOKIE}=")) {
                    self.cookie = if val.is_empty() || v.contains("Max-Age=0") {
                        None
                    } else {
                        Some(val.to_string())
                    };
                }
            }
        }
        r
    }

    async fn get(&mut self, path: &str) -> Resp {
        self.req("GET", path, None).await
    }

    async fn post(&mut self, path: &str, form: &str) -> Resp {
        self.req("POST", path, Some(form)).await
    }
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

// ---------- fixtures ----------

async fn temp_storage() -> Arc<dyn Storage> {
    let dir = std::env::temp_dir().join(format!("secmail-portal-{}", uuid::Uuid::new_v4()));
    Arc::new(Fs::new(dir.to_str().unwrap()).await.unwrap())
}

async fn serve_state(st: impl Into<Portal>) -> String {
    let st: Portal = st.into();
    // Header-mode fixtures stand in for the authenticating proxy: the test
    // client connects from loopback, so trust it unless a test chose otherwise.
    let st = if st.options().auth_mode == AuthMode::Header && st.trusted_proxies.is_empty() {
        st.with_trusted_proxies(&["127.0.0.1".into()]).unwrap()
    } else {
        st
    };
    serve_raw(st).await
}

/// Serves exactly the given portal (no implicit trusted proxy).
async fn serve_raw(st: Portal) -> String {
    let app = router(st);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });
    addr
}

fn test_options(mode: AuthMode) -> PortalOptions {
    PortalOptions {
        auth_mode: mode,
        session_secret: SECRET.to_vec(),
        session_ttl: Duration::from_secs(3600),
        otp_ttl: Duration::from_secs(600),
        otp_max_attempts: 3,
        otp_resend_after: Duration::from_secs(60),
        otp_from: "no-reply@example.com".into(),
        trusted_header: "X-Auth-Request-Email".into(),
        accepted_domains: vec!["example.com".into()],
        rate_limit_rps: 1000.0,
        rate_limit_burst: 1000,
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn attachment(id: &str, msg: &str, token: &str, status: Status, ttl_hours: i64) -> Attachment {
    let now = Utc::now();
    Attachment {
        id: id.into(),
        message_id: msg.into(),
        filename: "report.pdf".into(),
        content_type: "application/pdf".into(),
        size: 5,
        sha256: "s".into(),
        storage_key: format!("obj/{id}"),
        token_hash: sha256_hex(token.as_bytes()),
        status,
        threat_name: String::new(),
        verdict_detail: None,
        attempts: 0,
        created_at: now,
        updated_at: now,
        queued_at: now,
        analyzed_at: None,
        expires_at: now + chrono::Duration::hours(ttl_hours),
        download_count: 0,
        last_downloaded_at: None,
    }
}

async fn seed(store: &Memory, storage: &dyn Storage, token: &str, status: Status, ttl_hours: i64) {
    let att = attachment("a1", "m1", token, status, ttl_hours);
    let m = Message {
        id: "m1".into(),
        rcpt_to: vec!["Alice@Example.com".into(), "bob@example.com".into()],
        ..Default::default()
    };
    store.create_message(&m, &[att]).await.unwrap();
    storage.put("obj/a1", b"%PDF%").await.unwrap();
}

struct AuthFx {
    addr: String,
    store: Arc<Memory>,
    mailer: Arc<RecordingMailer>,
    base: String,
}

async fn auth_fixture(opts: PortalOptions) -> AuthFx {
    let store = Arc::new(Memory::new());
    let storage = temp_storage().await;
    let tok = "tok-auth-0123456789";
    seed(&store, &*storage, tok, Status::Clean, 1).await;
    let mailer = Arc::new(RecordingMailer::new());
    let st = PortalState::new(store.clone(), storage, Arc::new(Metrics::new()))
        .with_options(opts)
        .with_mailer(mailer.clone());
    let addr = serve_state(st).await;
    AuthFx {
        addr,
        store,
        mailer,
        base: format!("/dl/{tok}"),
    }
}

// ---------- download gate ----------

#[test]
fn content_disposition_safe() {
    assert_eq!(
        content_disposition("a/b/evil.pdf"),
        "attachment; filename=\"evil.pdf\""
    );
    assert!(content_disposition("보고서.pdf").contains("filename*=UTF-8''%EB"));
    assert_eq!(content_disposition(""), "attachment; filename=\"download\"");
    assert!(content_disposition("a\"b.txt").contains("filename=\"a_b.txt\""));
    for (name, want) in [
        ("report.pdf", "report.pdf"),
        ("보고서.pdf", "___.pdf"),
        ("a\r\nb.txt", "ab.txt"),
        ("../../etc/passwd", "passwd"),
        ("..", "download"),
        (r"x\y\z.bin", "z.bin"),
    ] {
        let got = content_disposition(name);
        assert!(got.starts_with("attachment;"), "{got}");
        assert!(
            got.contains(&format!("filename=\"{want}\"")),
            "{name:?}: {got}"
        );
        assert!(!got.contains(['\r', '\n']));
    }
    assert!(!content_disposition("report.pdf").contains("filename*="));
}

#[tokio::test]
async fn clean_downloads_blocked_denied_expired_gone() {
    // CLEAN -> 200 with body + content-disposition
    let store: Arc<Memory> = Arc::new(Memory::new());
    let storage = temp_storage().await;
    seed(&store, &*storage, "tok-clean", Status::Clean, 1).await;
    // Legacy construction (as main.rs does today) keeps working.
    let addr = serve_state(PortalState {
        store: store.clone(),
        storage,
        metrics: Arc::new(Metrics::new()),
    })
    .await;
    let r = send(&addr, "GET", "/dl/tok-clean", &[], None).await;
    assert_eq!(r.code, 200);
    assert_eq!(
        r.header("content-disposition"),
        Some("attachment; filename=\"report.pdf\"")
    );
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    assert_eq!(
        r.header("content-security-policy"),
        Some("default-src 'none'; sandbox")
    );
    assert_eq!(r.body, "%PDF%");
    assert_eq!(store.get_attachment("a1").await.unwrap().download_count, 1);
    // The Go-style /d/ alias serves the same link.
    assert_eq!(
        send(&addr, "GET", "/d/tok-clean", &[], None).await.code,
        200
    );
    let r = send(&addr, "GET", "/dl/does-not-exist", &[], None).await;
    assert_eq!(r.code, 404);
    assert!(r.body.contains("파일을 찾을 수 없습니다"));
    // Malformed token -> 404 without a store lookup.
    assert_eq!(
        send(&addr, "GET", "/dl/bad%20tok", &[], None).await.code,
        404
    );

    // MALICIOUS -> 403 page with the threat name, no form
    let store2: Arc<Memory> = Arc::new(Memory::new());
    let storage2 = temp_storage().await;
    seed(&store2, &*storage2, "tok-bad", Status::Pending, 1).await;
    store2
        .set_verdict(
            "a1",
            Status::Malicious,
            "Ransom.<Generic>",
            None,
            Utc::now(),
        )
        .await
        .unwrap();
    let addr2 = serve_state(Portal::new(store2, storage2, Arc::new(Metrics::new()))).await;
    let r = send(&addr2, "GET", "/dl/tok-bad", &[], None).await;
    assert_eq!(r.code, 403);
    assert!(r.body.contains("악성코드가 감지"));
    assert!(r.body.contains("Ransom.&lt;Generic&gt;"), "escaped threat");
    assert!(!r.body.contains("<form"));
    assert!(!r.body.contains("%PDF%"));

    // Expired (ttl in the past) -> 410
    let store3: Arc<Memory> = Arc::new(Memory::new());
    let storage3 = temp_storage().await;
    seed(&store3, &*storage3, "tok-old", Status::Clean, -1).await;
    let addr3 = serve_state(Portal::new(store3, storage3, Arc::new(Metrics::new()))).await;
    let r = send(&addr3, "GET", "/dl/tok-old", &[], None).await;
    assert_eq!(r.code, 410);
    assert!(r.body.contains("만료"));
}

#[tokio::test]
async fn pending_page_polls_status_and_sets_security_headers() {
    let store: Arc<Memory> = Arc::new(Memory::new());
    let storage = temp_storage().await;
    seed(&store, &*storage, "tok-pend", Status::Pending, 1).await;
    let addr = serve_state(Portal::new(
        store.clone(),
        storage,
        Arc::new(Metrics::new()),
    ))
    .await;
    let r = send(&addr, "GET", "/dl/tok-pend", &[], None).await;
    assert_eq!(r.code, 200);
    assert!(r.body.contains("보안 검사가 진행 중"));
    assert!(!r.body.contains("%PDF%"));
    let csp = r.header("content-security-policy").unwrap();
    let nonce = csp
        .split("'nonce-")
        .nth(1)
        .and_then(|s| s.split('\'').next())
        .unwrap();
    assert!(r.body.contains(&format!("<script nonce=\"{nonce}\">")));
    assert!(r.body.contains("\"/dl/tok-pend/status\""));
    assert!(csp.contains("frame-ancestors 'none'"));
    assert_eq!(r.header("x-frame-options"), Some("DENY"));
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(r.header("referrer-policy"), Some("same-origin"));
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("x-robots-tag"), Some("noindex, nofollow"));
    // Nonces differ per request.
    let r2 = send(&addr, "GET", "/dl/tok-pend", &[], None).await;
    assert_ne!(r2.header("content-security-policy"), Some(csp));

    let r = send(&addr, "GET", "/dl/tok-pend/status", &[], None).await;
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["status"], "PENDING");
    assert_eq!(v["filename"], "report.pdf");

    store
        .set_verdict("a1", Status::Clean, "", None, Utc::now())
        .await
        .unwrap();
    let r = send(&addr, "GET", "/d/tok-pend/status", &[], None).await;
    assert!(r.body.contains("\"CLEAN\""));
    assert_eq!(
        send(&addr, "GET", "/dl/tok-pend", &[], None).await.body,
        "%PDF%"
    );
}

#[tokio::test]
async fn rate_limit_and_enumeration_throttle() {
    let store: Arc<Memory> = Arc::new(Memory::new());
    let storage = temp_storage().await;
    seed(&store, &*storage, "tok-valid", Status::Clean, 1).await;
    let st = Portal::new(store.clone(), storage.clone(), Arc::new(Metrics::new())).with_options(
        PortalOptions {
            rate_limit_rps: 0.001,
            rate_limit_burst: 2,
            ..Default::default()
        },
    );
    let addr = serve_state(st).await;
    let mut codes = Vec::new();
    for i in 0..4 {
        codes.push(
            send(&addr, "GET", &format!("/dl/unknown{i}"), &[], None)
                .await
                .code,
        );
    }
    assert_eq!(codes[3], 429, "{codes:?}");

    // Enumeration: misses beyond the per-IP failure burst (10) get 429, while
    // a valid token keeps resolving.
    let st = Portal::new(store, storage, Arc::new(Metrics::new())).with_options(PortalOptions {
        rate_limit_rps: 1000.0,
        rate_limit_burst: 1000,
        ..Default::default()
    });
    let addr = serve_state(st).await;
    let (mut n404, mut n429) = (0, 0);
    for i in 0..20 {
        match send(&addr, "GET", &format!("/dl/guess{i}"), &[], None)
            .await
            .code
        {
            404 => n404 += 1,
            429 => n429 += 1,
            c => panic!("unexpected {c}"),
        }
    }
    assert_eq!(n404, 10);
    assert_eq!(n429, 10);
    assert_eq!(
        send(&addr, "GET", "/dl/tok-valid", &[], None).await.code,
        200
    );
}

// ---------- recipient auth ----------

#[tokio::test]
async fn otp_login_flow() {
    let f = auth_fixture(test_options(AuthMode::Otp)).await;
    let mut c = Browser::new(&f.addr);

    let r = c.get(&f.base).await;
    assert_eq!(r.code, 200);
    assert!(r.body.contains("수신자 본인 확인"));
    assert!(!r.body.contains("report.pdf") && !r.body.contains("%PDF%"));
    assert_eq!(c.get(&format!("{}/status", f.base)).await.code, 401);

    // Request a code (case-insensitive recipient match).
    let r = c
        .post(&format!("{}/auth", f.base), "email=ALICE%40example.com")
        .await;
    assert!(r.body.contains("인증 코드를 입력"), "{}", r.body);
    assert!(r.body.contains("라면 인증 코드가 발송되었습니다"));
    let code = f
        .mailer
        .last_code("alice@example.com")
        .expect("code mailed");
    assert_eq!(code.len(), 6);
    let (_, subject, body) = f.mailer.sent().pop().unwrap();
    assert!(subject.contains(&code) && body.contains(&code));

    // Resend is throttled.
    let r = c
        .post(&format!("{}/auth", f.base), "email=alice%40example.com")
        .await;
    assert!(r.body.contains("이미 발송되었습니다"));
    assert_eq!(f.mailer.sent().len(), 1);

    // Wrong code.
    let r = c
        .post(
            &format!("{}/auth", f.base),
            "email=alice%40example.com&code=000000x",
        )
        .await;
    assert!(r.body.contains("올바르지 않거나"));
    assert!(c.cookie.is_none());

    // Right code -> session cookie + redirect back to the link.
    let r = c
        .post(
            &format!("{}/auth", f.base),
            &format!("email=alice%40example.com&code={code}"),
        )
        .await;
    assert_eq!(r.code, 303);
    assert_eq!(r.header("location"), Some(f.base.as_str()));
    let set = r.header("set-cookie").unwrap();
    assert!(set.contains("HttpOnly") && set.contains("SameSite=Lax") && set.contains("Path=/"));
    assert!(c.cookie.is_some());

    let r = c.get(&f.base).await;
    assert_eq!(r.code, 200);
    assert_eq!(r.body, "%PDF%");
    assert_eq!(
        f.store.get_attachment("a1").await.unwrap().download_count,
        1
    );
    assert_eq!(c.get(&format!("{}/status", f.base)).await.code, 200);

    // Code is single use.
    let mut c2 = Browser::new(&f.addr);
    let r = c2
        .post(
            &format!("{}/auth", f.base),
            &format!("email=alice%40example.com&code={code}"),
        )
        .await;
    assert!(r.body.contains("올바르지 않거나"));

    // Logout clears the session.
    let r = c.post(&format!("{}/logout", f.base), "").await;
    assert_eq!(r.code, 303);
    assert!(c.cookie.is_none());
    assert!(c.get(&f.base).await.body.contains("수신자 본인 확인"));
}

#[tokio::test]
async fn otp_non_recipient_gets_no_code() {
    let f = auth_fixture(test_options(AuthMode::Otp)).await;
    let mut c = Browser::new(&f.addr);
    let r = c
        .post(&format!("{}/auth", f.base), "email=mallory%40evil.com")
        .await;
    assert!(r.body.contains("라면 인증 코드가 발송되었습니다"));
    assert!(f.mailer.sent().is_empty(), "code sent to non-recipient");
    // Invalid address -> login page with an error.
    let r = c.post(&format!("{}/auth", f.base), "email=nope").await;
    assert!(r.body.contains("올바른 이메일 주소"));
}

#[tokio::test]
async fn otp_brute_force_limit() {
    let f = auth_fixture(test_options(AuthMode::Otp)).await;
    let mut c = Browser::new(&f.addr);
    c.post(&format!("{}/auth", f.base), "email=bob%40example.com")
        .await;
    let code = f.mailer.last_code("bob@example.com").unwrap();
    for _ in 0..3 {
        c.post(
            &format!("{}/auth", f.base),
            "email=bob%40example.com&code=999999",
        )
        .await;
    }
    let r = c
        .post(
            &format!("{}/auth", f.base),
            &format!("email=bob%40example.com&code={code}"),
        )
        .await;
    assert!(
        r.body.contains("올바르지 않거나"),
        "destroyed after max attempts"
    );
}

#[tokio::test]
async fn session_for_other_recipient_forbidden() {
    let f = auth_fixture(test_options(AuthMode::Otp)).await;
    let now = Utc::now().timestamp();
    let mut c = Browser::new(&f.addr);
    c.cookie = Some(sign_session(SECRET, "carol@example.com", now + 3600));
    let r = c.get(&f.base).await;
    assert_eq!(r.code, 403);
    assert!(r.body.contains("권한이 없습니다"));
    assert!(r.body.contains("carol@example.com"));
    assert!(!r.body.contains("%PDF%"));

    // Tampered cookie is ignored -> login page.
    c.cookie = Some(format!(
        "{}x",
        sign_session(SECRET, "alice@example.com", now + 3600)
    ));
    assert!(c.get(&f.base).await.body.contains("수신자 본인 확인"));
    // Wrong key.
    c.cookie = Some(sign_session(
        b"another-secret-another-secret-xx",
        "alice@example.com",
        now + 3600,
    ));
    assert!(c.get(&f.base).await.body.contains("수신자 본인 확인"));
    // Expired cookie is ignored.
    c.cookie = Some(sign_session(SECRET, "alice@example.com", now - 60));
    assert!(c.get(&f.base).await.body.contains("수신자 본인 확인"));
    // A valid one works.
    c.cookie = Some(sign_session(SECRET, "alice@example.com", now + 60));
    assert_eq!(c.get(&f.base).await.body, "%PDF%");
}

#[tokio::test]
async fn header_mode() {
    let f = auth_fixture(test_options(AuthMode::Header)).await;
    let get = |email: &'static str| {
        let addr = f.addr.clone();
        let base = f.base.clone();
        async move {
            let h: Vec<(&str, &str)> = if email.is_empty() {
                vec![]
            } else {
                vec![("X-Auth-Request-Email", email)]
            };
            send(&addr, "GET", &base, &h, None).await.code
        }
    };
    assert_eq!(get("").await, 401);
    assert_eq!(get("<Bob@Example.com>").await, 200);
    assert_eq!(get("carol@example.com").await, 403);
    assert_eq!(get("not-an-address").await, 401);
    // OTP endpoints are disabled in header mode.
    let r = send(
        &f.addr,
        "POST",
        &format!("{}/auth", f.base),
        &[],
        Some("email=bob%40example.com"),
    )
    .await;
    assert_eq!(r.code, 404);
}

#[tokio::test]
async fn domain_users_allowed() {
    let mut o = test_options(AuthMode::Header);
    o.allow_domain_users = true;
    let f = auth_fixture(o).await;
    let r = send(
        &f.addr,
        "GET",
        &f.base,
        &[("X-Auth-Request-Email", "carol@example.com")],
        None,
    )
    .await;
    assert_eq!(r.code, 200);
    let r = send(
        &f.addr,
        "GET",
        &f.base,
        &[("X-Auth-Request-Email", "carol@evil.com")],
        None,
    )
    .await;
    assert_eq!(r.code, 403);
}

#[tokio::test]
async fn cross_origin_post_rejected() {
    let mut o = test_options(AuthMode::Otp);
    o.public_base_url = "https://portal.example.com/".into();
    let f = auth_fixture(o).await;
    let path = format!("{}/logout", f.base);
    let host_origin = format!("http://{}", f.addr);
    let cases: Vec<(Vec<(&str, &str)>, u16)> = vec![
        (vec![("Origin", "https://evil.example.net")], 403),
        (vec![("Sec-Fetch-Site", "cross-site")], 403),
        (vec![("Sec-Fetch-Site", "same-site")], 403),
        (vec![("Origin", "null")], 403),
        (vec![("Origin", host_origin.as_str())], 303),
        (vec![("Origin", "https://PORTAL.example.com")], 303),
        (
            vec![("Origin", "null"), ("Sec-Fetch-Site", "same-origin")],
            303,
        ),
        (vec![], 303), // non-browser client
    ];
    for (h, want) in cases {
        let r = send(&f.addr, "POST", &path, &h, Some("")).await;
        assert_eq!(r.code, want, "{h:?}");
    }
    // A cross-site OTP request is refused before any code is sent.
    let r = send(
        &f.addr,
        "POST",
        &format!("{}/auth", f.base),
        &[("Sec-Fetch-Site", "cross-site")],
        Some("email=alice%40example.com"),
    )
    .await;
    assert_eq!(r.code, 403);
    assert!(f.mailer.sent().is_empty());
}

// ---------- DLP review page ----------

/// Records decisions on top of the store-backed reviewer.
struct FakeReviewer {
    inner: StoreHoldReviewer,
    released: Mutex<Vec<String>>,
    rejected: Mutex<Vec<String>>,
}

#[async_trait]
impl HoldReviewer for FakeReviewer {
    async fn release(&self, id: &str, by: &str) -> Result<(), StoreError> {
        self.inner.release(id, by).await?;
        self.released.lock().unwrap().push(by.into());
        Ok(())
    }

    async fn reject(&self, id: &str, by: &str, reason: &str) -> Result<(), StoreError> {
        self.inner.reject(id, by, reason).await?;
        self.rejected.lock().unwrap().push(reason.into());
        Ok(())
    }
}

fn hold(id: &str, token_hash: &str, subject: &str, created_min: i64) -> Hold {
    let base = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
    Hold {
        id: id.into(),
        token_hash: token_hash.into(),
        mail_from: "kim@example.com".into(),
        rcpt_to: vec!["p@ext.org".into()],
        subject: subject.into(),
        storage_key: format!("hold/{id}"),
        size: 10,
        findings: Some(serde_json::json!({"findings": [
            {"name": "주민등록번호", "severity": "high", "location": "첨부 고객.xlsx", "count": 12,
             "samples": ["900101-1******"]},
            {"name": "여권", "severity": "medium", "location": "본문", "count": 1, "samples": ["M12****78"]}
        ], "uninspectable": ["암호화.zip"]})),
        status: HoldStatus::Held,
        created_at: base + chrono::Duration::minutes(created_min),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        decided_at: None,
        decided_by: String::new(),
        reason: String::new(),
    }
}

struct HoldFx {
    addr: String,
    store: Arc<Memory>,
    rv: Arc<FakeReviewer>,
    mailer: Arc<RecordingMailer>,
    ids: Vec<String>,
}

const HOLD_TOKEN: &str = "hold-token-0123456789";

async fn hold_fixture(opts: PortalOptions, n: usize) -> HoldFx {
    let store = Arc::new(Memory::new());
    let mut ids = Vec::new();
    for i in 0..n {
        let id = format!(
            "00000000-0000-0000-0000-00000000000{}",
            (b'a' + i as u8) as char
        );
        let th = if i == 0 {
            sha256_hex(HOLD_TOKEN.as_bytes())
        } else {
            format!("tok{id}")
        };
        store
            .create_hold(&hold(&id, &th, "고객 명단 <b>", i as i64))
            .await
            .unwrap();
        ids.push(id);
    }
    let rv = Arc::new(FakeReviewer {
        inner: StoreHoldReviewer::new(store.clone()),
        released: Mutex::new(vec![]),
        rejected: Mutex::new(vec![]),
    });
    let mailer = Arc::new(RecordingMailer::new());
    let st = Portal::new(
        store.clone(),
        temp_storage().await,
        Arc::new(Metrics::new()),
    )
    .with_options(opts)
    .with_mailer(mailer.clone())
    .with_holds(rv.clone());
    let addr = serve_state(st).await;
    HoldFx {
        addr,
        store,
        rv,
        mailer,
        ids,
    }
}

fn admin_options(mode: AuthMode) -> PortalOptions {
    let mut o = test_options(mode);
    o.dlp_admins = vec!["Sec@Example.com".into()];
    o
}

#[tokio::test]
async fn hold_review_no_auth() {
    let f = hold_fixture(admin_options(AuthMode::None), 1).await;
    let mut c = Browser::new(&f.addr);
    let base = format!("/dlp/{HOLD_TOKEN}");
    let r = c.get(&base).await;
    assert_eq!(r.code, 200);
    assert!(r.body.contains("검토 대기"));
    assert!(r.body.contains("900101-1******"));
    assert!(r.body.contains("첨부 고객.xlsx"));
    assert!(r.body.contains("암호화.zip"));
    assert!(r.body.contains("고객 명단 &lt;b&gt;"), "subject escaped");
    assert!(!r.body.contains("고객 명단 <b>"));
    assert!(r
        .header("content-security-policy")
        .unwrap()
        .contains("nonce-"));

    let r = c
        .post(
            &format!("{base}/reject"),
            &format!("reason={}", enc("마스킹 필요")),
        )
        .await;
    assert_eq!(r.code, 200);
    assert!(r.body.contains("반려되었습니다"), "{}", r.body);
    assert_eq!(*f.rv.rejected.lock().unwrap(), vec!["마스킹 필요"]);
    let h = f.store.get_hold(&f.ids[0]).await.unwrap();
    assert_eq!(h.status, HoldStatus::Rejected);
    assert!(
        h.decided_by.starts_with("review-link ("),
        "{}",
        h.decided_by
    );

    let r = c.post(&format!("{base}/release"), "").await;
    assert_eq!(r.code, 409);
    assert!(r.body.contains("이미 처리된"));
    // Unknown hold token -> 404.
    assert_eq!(c.get("/dlp/nope-nope-nope").await.code, 404);
}

#[tokio::test]
async fn hold_review_requires_admin_otp() {
    let f = hold_fixture(admin_options(AuthMode::Otp), 1).await;
    let mut c = Browser::new(&f.addr);
    let base = format!("/dlp/{HOLD_TOKEN}");
    let r = c.get(&base).await;
    assert!(r.body.contains("본인 확인"));
    assert!(!r.body.contains("고객 명단"));
    // Deciding without a session is refused.
    let r = c.post(&format!("{base}/release"), "").await;
    assert!(!r.body.contains("승인되어"));
    assert!(f.rv.released.lock().unwrap().is_empty());

    // The sender is not an admin: no code is sent.
    c.post(&format!("{base}/auth"), "email=kim%40example.com")
        .await;
    assert!(f.mailer.last_code("kim@example.com").is_none());

    c.post(&format!("{base}/auth"), "email=sec%40example.com")
        .await;
    let code = f.mailer.last_code("sec@example.com").unwrap();
    let r = c
        .post(
            &format!("{base}/auth"),
            &format!("email=sec%40example.com&code={code}"),
        )
        .await;
    assert_eq!(r.code, 303);
    let r = c.get(&base).await;
    assert!(r.body.contains("승인 후 발송"), "{}", r.body);
    assert!(r.body.contains("sec@example.com"));

    let r = c.post(&format!("{base}/release"), "").await;
    assert!(r.body.contains("승인되어"));
    assert_eq!(*f.rv.released.lock().unwrap(), vec!["sec@example.com"]);
}

#[tokio::test]
async fn hold_review_non_admin_session_forbidden() {
    let f = hold_fixture(admin_options(AuthMode::Header), 1).await;
    let base = format!("/dlp/{HOLD_TOKEN}");
    let r = send(
        &f.addr,
        "POST",
        &format!("{base}/release"),
        &[("X-Auth-Request-Email", "kim@example.com")],
        Some(""),
    )
    .await;
    assert_eq!(r.code, 403);
    assert!(f.rv.released.lock().unwrap().is_empty());
    let r = send(
        &f.addr,
        "GET",
        &base,
        &[("X-Auth-Request-Email", "sec@example.com")],
        None,
    )
    .await;
    assert_eq!(r.code, 200);
    assert!(r.body.contains("승인 후 발송"));
}

#[tokio::test]
async fn dlp_routes_absent_without_reviewer() {
    let f = auth_fixture(test_options(AuthMode::Otp)).await;
    assert_eq!(
        send(&f.addr, "GET", "/dlp/admin", &[], None).await.code,
        404
    );
    assert_eq!(
        send(&f.addr, "GET", &format!("/dlp/{HOLD_TOKEN}"), &[], None)
            .await
            .code,
        404
    );
}

// ---------- admin dashboard ----------

async fn admin_login(c: &mut Browser, f: &HoldFx, email: &str) {
    c.post("/dlp/admin/auth", &format!("email={}", enc(email)))
        .await;
    let code = f.mailer.last_code(email).expect("otp code");
    let r = c
        .post(
            "/dlp/admin/auth",
            &format!("email={}&code={code}", enc(email)),
        )
        .await;
    assert_eq!(r.code, 303);
    assert_eq!(r.header("location"), Some("/dlp/admin"));
}

#[tokio::test]
async fn admin_dashboard_list_and_decide() {
    let f = hold_fixture(admin_options(AuthMode::Otp), 3).await;
    let mut c = Browser::new(&f.addr);
    assert_eq!(c.get("/dlp/admin/holds").await.code, 401);
    let r = c.get("/dlp/admin").await;
    assert!(r.body.contains("본인 확인"), "login page for the dashboard");
    admin_login(&mut c, &f, "sec@example.com").await;

    let r = c.get("/dlp/admin").await;
    assert_eq!(r.code, 200);
    assert!(r.body.contains("발송 보류 관리"));
    assert!(r.body.contains("id=\"hrows\""));
    assert!(r.body.contains("sec@example.com"));
    assert!(r.body.contains("id=\"bulkRelease\""));
    assert!(r.body.contains("var canDecide = true;"));
    assert!(r.body.contains("textContent"));
    let csp = r.header("content-security-policy").unwrap();
    let nonce = csp
        .split("'nonce-")
        .nth(1)
        .and_then(|s| s.split('\'').next())
        .unwrap();
    assert!(r.body.contains(&format!("<script nonce=\"{nonce}\">")));

    let r = c.get("/dlp/admin/holds?status=HELD").await;
    assert_eq!(r.code, 200);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let holds = v["holds"].as_array().unwrap();
    assert_eq!(holds.len(), 3);
    assert_eq!(holds[0]["id"], f.ids[2].as_str(), "newest first");
    assert_eq!(holds[0]["severity"], "high");
    assert_eq!(holds[0]["findings"], 2);
    assert_eq!(holds[0]["subject"], "고객 명단 <b>");
    assert!(v.get("next").is_none());

    let r = c
        .post(&format!("/dlp/admin/holds/{}/release", f.ids[0]), "")
        .await;
    assert_eq!(r.code, 200, "{}", r.body);
    assert!(r.body.contains("RELEASED"));
    assert_eq!(*f.rv.released.lock().unwrap(), vec!["sec@example.com"]);

    let r = c
        .post(&format!("/dlp/admin/holds/{}/reject", f.ids[0]), "reason=x")
        .await;
    assert_eq!(r.code, 409);

    c.post(
        &format!("/dlp/admin/holds/{}/reject", f.ids[1]),
        &format!("reason={}", enc("마스킹 필요")),
    )
    .await;
    assert_eq!(*f.rv.rejected.lock().unwrap(), vec!["마스킹 필요"]);

    // Bad / unknown ids.
    assert_eq!(
        c.post("/dlp/admin/holds/not-a-uuid/release", "").await.code,
        400
    );
    assert_eq!(
        c.post(
            "/dlp/admin/holds/00000000-0000-0000-0000-0000000000ff/release",
            ""
        )
        .await
        .code,
        404
    );

    // Status filters.
    let r = c.get("/dlp/admin/holds").await;
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["holds"].as_array().unwrap().len(), 1, "default HELD");
    let r = c.get("/dlp/admin/holds?status=all").await;
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["holds"].as_array().unwrap().len(), 3);

    // Logout ends the session.
    let r = c.post("/dlp/admin/logout", "").await;
    assert_eq!(r.code, 303);
    assert_eq!(c.get("/dlp/admin/holds").await.code, 401);
}

#[tokio::test]
async fn admin_dashboard_non_admin_forbidden() {
    let f = hold_fixture(admin_options(AuthMode::Otp), 1).await;
    let mut c = Browser::new(&f.addr);
    c.post("/dlp/admin/auth", "email=kim%40example.com").await;
    assert!(f.mailer.last_code("kim@example.com").is_none());
    assert_eq!(c.get("/dlp/admin/holds").await.code, 401);
    // A signed session for a non-admin is forbidden, not challenged.
    c.cookie = Some(sign_session(
        SECRET,
        "kim@example.com",
        Utc::now().timestamp() + 60,
    ));
    assert_eq!(c.get("/dlp/admin/holds").await.code, 403);
    assert_eq!(c.get("/dlp/admin").await.code, 403);
    assert_eq!(
        c.post(&format!("/dlp/admin/holds/{}/release", f.ids[0]), "")
            .await
            .code,
        403
    );
}

fn roles_options() -> PortalOptions {
    let mut o = test_options(AuthMode::Otp);
    o.dlp_admins = vec!["admin@example.com".into()];
    o.dlp_auditors = vec!["auditor@example.com".into()];
    o
}

#[tokio::test]
async fn admin_auditor_is_read_only() {
    let f = hold_fixture(roles_options(), 2).await;
    let mut c = Browser::new(&f.addr);
    admin_login(&mut c, &f, "auditor@example.com").await;
    assert_eq!(c.get("/dlp/admin/holds?status=HELD").await.code, 200);
    assert_eq!(c.get("/dlp/admin/events").await.code, 200);
    assert_eq!(c.get("/dlp/admin/audit").await.code, 200);
    assert_eq!(c.get("/dlp/admin/export?kind=holds").await.code, 200);
    let r = c
        .post(&format!("/dlp/admin/holds/{}/release", f.ids[0]), "")
        .await;
    assert_eq!(r.code, 403);
    let r = c
        .post(&format!("/dlp/admin/holds/{}/reject", f.ids[0]), "")
        .await;
    assert_eq!(r.code, 403);
    assert!(f.rv.released.lock().unwrap().is_empty());
    assert_eq!(
        f.store.get_hold(&f.ids[0]).await.unwrap().status,
        HoldStatus::Held
    );
    let r = c.get("/dlp/admin").await;
    assert_eq!(r.code, 200);
    assert!(!r.body.contains("id=\"bulkRelease\""));
    assert!(r.body.contains("var canDecide = false;"));
    // The auditor cannot use per-hold review links either.
    assert_eq!(c.get(&format!("/dlp/{HOLD_TOKEN}")).await.code, 403);
}

#[tokio::test]
async fn admin_action_audited() {
    let f = hold_fixture(roles_options(), 2).await;
    let mut c = Browser::new(&f.addr);
    admin_login(&mut c, &f, "admin@example.com").await;
    let r = c
        .post(&format!("/dlp/admin/holds/{}/release", f.ids[0]), "")
        .await;
    assert_eq!(r.code, 200);
    c.post(&format!("/dlp/admin/holds/{}/release", f.ids[0]), "")
        .await;
    let r = c.get("/dlp/admin/audit").await;
    assert_eq!(r.code, 200);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let acts = v["actions"].as_array().unwrap();
    assert_eq!(acts.len(), 2);
    let ok = acts.iter().find(|a| a["result"] == "ok").unwrap();
    assert_eq!(ok["action"], "release");
    assert_eq!(ok["actor"], "admin@example.com");
    assert_eq!(ok["target"], f.ids[0].as_str());
    assert_eq!(ok["source"], "portal");
    assert!(acts.iter().any(|a| a["result"] == "conflict"));
}

#[tokio::test]
async fn admin_events_and_export() {
    let f = hold_fixture(admin_options(AuthMode::Otp), 1).await;
    for (id, from, subject, action, sev) in [
        ("ev-a", "kim@example.com", "유출 의심", "block", "high"),
        ("ev-b", "lee@example.com", "알림건", "notify", "medium"),
        (
            "ev-x",
            "evil@ext.org",
            r#"=HYPERLINK("http://evil","x")"#,
            "block",
            "high",
        ),
    ] {
        f.store
            .record_dlp_event(&DlpEvent {
                id: id.into(),
                mail_from: from.into(),
                rcpt_to: vec!["p@ext.org".into()],
                subject: subject.into(),
                action: action.into(),
                severity: sev.into(),
                findings: None,
                hold_id: String::new(),
                at: Utc::now(),
            })
            .await
            .unwrap();
    }
    let mut c = Browser::new(&f.addr);
    admin_login(&mut c, &f, "sec@example.com").await;

    let r = c.get("/dlp/admin/events?action=block").await;
    assert_eq!(r.code, 200);
    assert!(r.body.contains("\"action\":\"block\""));
    assert!(!r.body.contains("notify"));

    let r = c.get("/dlp/admin/export?kind=events").await;
    assert_eq!(r.code, 200);
    assert!(r.header("content-type").unwrap().starts_with("text/csv"));
    assert_eq!(
        r.header("content-disposition"),
        Some("attachment; filename=\"dlp-events.csv\"")
    );
    assert!(r
        .body
        .starts_with("id,at,action,severity,mail_from,rcpt_to,subject,hold_id\n"));
    assert!(r.body.contains("ev-a") && r.body.contains("ev-b"));
    assert!(r.body.contains("'=HYPERLINK"), "{}", r.body);
    assert!(!r.body.contains(",=HYPERLINK"));

    let r = c.get("/dlp/admin/export?kind=holds").await;
    assert_eq!(r.code, 200);
    assert!(r.body.contains("mail_from") && r.body.contains("kim@example.com"));
    assert_eq!(c.get("/dlp/admin/export?kind=bogus").await.code, 400);

    // Exports are audited.
    let r = c.get("/dlp/admin/audit").await;
    assert!(r.body.contains("\"action\":\"export\""));
}

#[tokio::test]
async fn admin_dashboard_disabled_without_auth() {
    let f = hold_fixture(admin_options(AuthMode::None), 1).await;
    let r = send(&f.addr, "GET", "/dlp/admin", &[], None).await;
    assert_eq!(r.code, 200);
    assert!(r.body.contains("수신자 인증이 설정된"));
    assert!(!r.body.contains("id=\"hrows\""));
    for p in [
        "/dlp/admin/holds",
        "/dlp/admin/events",
        "/dlp/admin/audit",
        "/dlp/admin/export?kind=holds",
    ] {
        assert_eq!(send(&f.addr, "GET", p, &[], None).await.code, 404, "{p}");
    }
    let r = send(
        &f.addr,
        "POST",
        &format!("/dlp/admin/holds/{}/release", f.ids[0]),
        &[],
        Some(""),
    )
    .await;
    assert_eq!(r.code, 404);
    assert!(f.rv.released.lock().unwrap().is_empty());
}

#[tokio::test]
async fn admin_holds_pagination_cursor() {
    let store = Arc::new(Memory::new());
    for i in 0..55 {
        let id = format!("00000000-0000-0000-0000-{:012}", i);
        store
            .create_hold(&hold(&id, &format!("t{i}"), "s", i))
            .await
            .unwrap();
    }
    let mut o = admin_options(AuthMode::Header);
    o.dlp_auditors = vec!["aud@example.com".into()];
    let st = Portal::new(store, temp_storage().await, Arc::new(Metrics::new()))
        .with_options(o)
        .with_store_holds();
    let addr = serve_state(st).await;
    let h = [("X-Auth-Request-Email", "aud@example.com")];
    let r = send(&addr, "GET", "/dlp/admin/holds", &h, None).await;
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["holds"].as_array().unwrap().len(), 50);
    let next = v["next"].as_str().unwrap().to_string();
    let r = send(
        &addr,
        "GET",
        &format!("/dlp/admin/holds?cursor={next}"),
        &h,
        None,
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let rest = v["holds"].as_array().unwrap();
    assert_eq!(rest.len(), 5);
    assert_eq!(rest[4]["id"], "00000000-0000-0000-0000-000000000000");
    assert!(v.get("next").is_none());
}

#[test]
fn same_origin_rules() {
    use axum::http::HeaderMap;
    let mk = |pairs: &[(&'static str, &'static str)]| {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, v.parse().unwrap());
        }
        h
    };
    let base = "https://portal.example.com";
    assert!(same_origin(base, &mk(&[])));
    assert!(same_origin(base, &mk(&[("sec-fetch-site", "none")])));
    assert!(!same_origin(base, &mk(&[("sec-fetch-site", "cross-site")])));
    assert!(same_origin(
        base,
        &mk(&[("origin", "https://portal.example.com")])
    ));
    assert!(!same_origin(
        base,
        &mk(&[("origin", "https://portal.example.com.evil.net")])
    ));
    assert!(same_origin(
        base,
        &mk(&[
            ("origin", "http://10.0.0.1:8080"),
            ("host", "10.0.0.1:8080")
        ])
    ));
    assert!(!same_origin(base, &mk(&[("origin", "garbage")])));
    assert!(!same_origin("", &mk(&[("origin", "https://x.y")])));
}

#[test]
fn form_parsing_and_tokens() {
    let m = parse_urlencoded("email=a%40b.c&code=12+34&x&email=dup&bad=%zz%4");
    assert_eq!(m["email"], "a@b.c");
    assert_eq!(m["code"], "12 34");
    assert_eq!(m["x"], "");
    assert_eq!(m["bad"], "%zz%4");
    assert!(well_formed("AbC-_09"));
    assert!(!well_formed(""));
    assert!(!well_formed("a/b"));
    assert!(!well_formed(&"a".repeat(129)));
    assert_eq!(AuthMode::parse("OTP"), Some(AuthMode::Otp));
    assert_eq!(AuthMode::parse(""), Some(AuthMode::None));
    assert_eq!(AuthMode::parse("magic"), None);
}

#[tokio::test]
async fn time_formatting_uses_configured_zone() {
    let t = Utc.with_ymd_and_hms(2026, 5, 1, 15, 30, 0).unwrap();
    let st = Portal::new(
        Arc::new(Memory::new()),
        temp_storage().await,
        Arc::new(Metrics::new()),
    );
    assert_eq!(st.fmt_time(t, true), "2026-05-01 15:30 UTC");
    let st = st.with_options(PortalOptions {
        tz_offset_minutes: 9 * 60,
        tz_label: "KST".into(),
        ..Default::default()
    });
    assert_eq!(st.fmt_time(t, true), "2026-05-02 00:30 KST");
    assert_eq!(st.fmt_time(t, false), "2026-05-02 00:30");
    let st = st.with_options(PortalOptions {
        tz_offset_minutes: -300,
        ..Default::default()
    });
    assert_eq!(st.fmt_time(t, true), "2026-05-01 10:30 -05:00");
}

// ---------- review regressions ----------

/// Regression: with `trust_proxy_headers` the leftmost (client-controlled)
/// X-Forwarded-For entry used to be the limiter key, so rotating it bypassed
/// the per-IP enumeration budget. Without a trusted proxy the header is now
/// ignored entirely.
#[tokio::test]
async fn review_xff_spoof_bypasses_enumeration_limit() {
    let store = Arc::new(Memory::new());
    let storage = temp_storage().await;
    let mut o = test_options(AuthMode::None);
    o.trust_proxy_headers = true;
    o.enum_per_ip_burst = 2;
    o.enum_global_rps = 1000.0;
    let st = Portal::new(store, storage, Arc::new(Metrics::new())).with_options(o);
    let addr = serve_state(st).await;
    let mut n404 = 0;
    for i in 0..30 {
        let xff = format!("10.9.{}.{}", i / 250, i % 250);
        let r = send(
            &addr,
            "GET",
            &format!("/dl/guess{i}"),
            &[("X-Forwarded-For", &xff)],
            None,
        )
        .await;
        if r.code == 404 {
            n404 += 1;
        }
    }
    assert_eq!(n404, 2, "per-IP enumeration budget must hold");
}

/// Behind a trusted proxy the rightmost untrusted hop is the client; spoofed
/// entries to its left do not create new buckets.
#[tokio::test]
async fn xff_from_trusted_proxy_uses_rightmost_untrusted_hop() {
    let store = Arc::new(Memory::new());
    let storage = temp_storage().await;
    let mut o = test_options(AuthMode::None);
    o.trust_proxy_headers = true;
    o.enum_per_ip_burst = 2;
    o.enum_global_rps = 1000.0;
    let st = Portal::new(store, storage, Arc::new(Metrics::new()))
        .with_options(o)
        .with_trusted_proxies(&["127.0.0.1".into(), "10.0.0.0/8".into()])
        .unwrap();
    let addr = serve_raw(st).await;
    let mut codes = Vec::new();
    for i in 0..6 {
        let xff = format!("6.6.6.{i}, 198.51.100.7, 10.0.0.2");
        codes.push(
            send(
                &addr,
                "GET",
                &format!("/dl/guess{i}"),
                &[("X-Forwarded-For", &xff)],
                None,
            )
            .await
            .code,
        );
    }
    assert_eq!(codes, [404, 404, 429, 429, 429, 429]);
    // A different real client (rightmost untrusted hop) has its own budget.
    let r = send(
        &addr,
        "GET",
        "/dl/guess-other",
        &[("X-Forwarded-For", "198.51.100.8")],
        None,
    )
    .await;
    assert_eq!(r.code, 404);
}

/// The identity header is ignored unless the TCP peer is a trusted proxy.
#[tokio::test]
async fn header_mode_ignores_identity_from_untrusted_peer() {
    let store = Arc::new(Memory::new());
    let storage = temp_storage().await;
    seed(&store, &*storage, "tok-hdr-0123456789", Status::Clean, 1).await;
    let mk = || {
        Portal::new(store.clone(), storage.clone(), Arc::new(Metrics::new()))
            .with_options(test_options(AuthMode::Header))
    };
    let h = [("X-Auth-Request-Email", "bob@example.com")];
    // No trusted proxies configured.
    let addr = serve_raw(mk()).await;
    let r = send(&addr, "GET", "/dl/tok-hdr-0123456789", &h, None).await;
    assert_eq!(r.code, 401);
    // Trusted proxies configured, but not this peer.
    let addr = serve_raw(mk().with_trusted_proxies(&["192.0.2.1".into()]).unwrap()).await;
    let r = send(&addr, "GET", "/dl/tok-hdr-0123456789", &h, None).await;
    assert_eq!(r.code, 401);
    // From the trusted proxy: honoured.
    let addr = serve_raw(mk().with_trusted_proxies(&["127.0.0.0/8".into()]).unwrap()).await;
    let r = send(&addr, "GET", "/dl/tok-hdr-0123456789", &h, None).await;
    assert_eq!(r.code, 200);
    assert!(
        Portal::new(store.clone(), storage.clone(), Arc::new(Metrics::new()))
            .with_trusted_proxies(&["not-an-ip".into()])
            .is_err()
    );
}

/// Regression: re-requesting a code used to reset the attempt counter, giving
/// unlimited guesses over time. Failures now count per address across codes
/// and lock the address (no code accepted or sent) for the window.
#[tokio::test]
async fn review_otp_attempts_reset_by_resend() {
    let mut o = test_options(AuthMode::Otp);
    o.otp_resend_after = Duration::from_millis(1);
    o.enum_per_ip_burst = 1000; // isolate the per-address lockout
    let f = auth_fixture(o).await;
    let mut c = Browser::new(&f.addr);
    let mut wrong = 0;
    // Rounds of: fresh code, 3 wrong guesses (the per-code limit).
    for _ in 0..4 {
        c.post(&format!("{}/auth", f.base), "email=bob%40example.com")
            .await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        for _ in 0..3 {
            let r = c
                .post(
                    &format!("{}/auth", f.base),
                    "email=bob%40example.com&code=999999",
                )
                .await;
            if r.code == 200 {
                wrong += 1;
            } else {
                assert_eq!(r.code, 429);
                assert!(r.body.contains("잠시 잠겼습니다"));
            }
        }
    }
    assert_eq!(wrong, 10, "10 wrong guesses per address per window");
    let sent = f.mailer.sent().len();
    assert_eq!(sent, 4);
    // Locked: no new code is mailed...
    let r = c
        .post(&format!("{}/auth", f.base), "email=bob%40example.com")
        .await;
    assert_eq!(r.code, 429);
    assert_eq!(f.mailer.sent().len(), sent, "no code sent while locked");
    // ...and even the correct code is refused.
    let code = f.mailer.last_code("bob@example.com").unwrap();
    let r = c
        .post(
            &format!("{}/auth", f.base),
            &format!("email=bob%40example.com&code={code}"),
        )
        .await;
    assert_eq!(r.code, 429);
    assert!(r.header("set-cookie").is_none());
    // Other addresses are unaffected.
    c.post(&format!("{}/auth", f.base), "email=alice%40example.com")
        .await;
    let code = f.mailer.last_code("alice@example.com").unwrap();
    let r = c
        .post(
            &format!("{}/auth", f.base),
            &format!("email=alice%40example.com&code={code}"),
        )
        .await;
    assert_eq!(r.code, 303);
}

/// OTP guesses are charged to the client's per-IP miss budget, so one source
/// cannot spread guesses over many addresses.
#[tokio::test]
async fn otp_guesses_charge_ip_miss_budget() {
    let mut o = test_options(AuthMode::Otp);
    o.enum_per_ip_burst = 3;
    o.enum_global_rps = 1000.0;
    let f = auth_fixture(o).await;
    let mut c = Browser::new(&f.addr);
    let mut codes = Vec::new();
    for who in ["alice", "bob", "x1", "x2", "x3"] {
        codes.push(
            c.post(
                &format!("{}/auth", f.base),
                &format!("email={who}%40example.com&code=123456"),
            )
            .await
            .code,
        );
    }
    assert_eq!(codes, [200, 200, 200, 429, 429]);
}

/// /dlp/{token} release and reject are written to the admin audit log.
#[tokio::test]
async fn hold_review_decisions_are_audited() {
    let f = hold_fixture(admin_options(AuthMode::None), 2).await;
    let mut c = Browser::new(&f.addr);
    let base = format!("/dlp/{HOLD_TOKEN}");
    let r = c
        .post(&format!("{base}/reject"), &format!("reason={}", enc("pii")))
        .await;
    assert_eq!(r.code, 200);
    let r = c.post(&format!("{base}/release"), "").await;
    assert_eq!(r.code, 409);
    let acts = f
        .store
        .list_admin_actions(10, crate::store::Page::default())
        .await
        .unwrap();
    assert_eq!(acts.len(), 2, "{acts:?}");
    let reject = acts.iter().find(|a| a.action == "reject").unwrap();
    assert_eq!(
        (
            reject.target.as_str(),
            reject.detail.as_str(),
            reject.result.as_str()
        ),
        (f.ids[0].as_str(), "pii", "ok")
    );
    assert_eq!(reject.source, "portal");
    assert!(reject.actor.starts_with("review-link ("));
    let release = acts.iter().find(|a| a.action == "release").unwrap();
    assert_eq!(release.result, "conflict");
}

/// Raw GET returning (status line + headers, raw body bytes).
async fn raw_get(addr: &str, path: &str) -> (String, Vec<u8>) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf).await;
    // A response aborted before its headers were flushed reads as empty.
    let Some(split) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return (String::new(), buf);
    };
    (
        String::from_utf8_lossy(&buf[..split]).into_owned(),
        buf[split + 4..].to_vec(),
    )
}

/// Downloads stream from (encrypted) storage; a truncated object aborts the
/// transfer instead of completing it, and an undecryptable one is a 500.
#[tokio::test]
async fn download_streams_and_aborts_on_truncation() {
    let store = Arc::new(Memory::new());
    let fs: Arc<dyn Storage> = temp_storage().await;
    let storage: Arc<dyn Storage> =
        Arc::new(crate::storage::Encrypted::new(fs.clone(), &[3u8; 32]).unwrap());
    seed(&store, &*storage, "tok-stream-0123456789", Status::Clean, 1).await;
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    storage.put("obj/a1", &big).await.unwrap();
    let st = Portal::new(store.clone(), storage.clone(), Arc::new(Metrics::new()));
    let addr = serve_state(st).await;

    let (head, body) = raw_get(&addr, "/dl/tok-stream-0123456789").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked"));
    assert!(body.ends_with(b"0\r\n\r\n"), "complete chunked body");
    assert_eq!(dechunk(&body), big);

    // Cut the stored ciphertext mid-way: headers go out, but the chunked
    // body never gets its terminating chunk.
    let ct = fs.get("obj/a1").await.unwrap();
    fs.put("obj/a1", &ct[..ct.len() - 100]).await.unwrap();
    // (If the error hits before hyper flushed the headers, the connection
    // is simply dropped: also an aborted transfer.)
    let (head, body) = raw_get(&addr, "/dl/tok-stream-0123456789").await;
    if !head.is_empty() {
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(!body.ends_with(b"0\r\n\r\n"), "truncated transfer");
    }
    assert!(body.len() < big.len());

    // Undecryptable from the first frame: a proper error page.
    let mut bad = ct.clone();
    bad[20] ^= 1;
    fs.put("obj/a1", &bad).await.unwrap();
    let (head, _) = raw_get(&addr, "/dl/tok-stream-0123456789").await;
    assert!(head.starts_with("HTTP/1.1 500"), "{head}");
}
