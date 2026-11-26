//! Internal API for the external analyzer and DLP administration. Port of the Go
//! `internal/internalapi`: verdict submission (analyzer token) and the DLP admin
//! endpoints — holds list/release/reject, events, audit log, rule test — guarded
//! by the admin token.
//!
//! Verdicts go through [`VerdictHandler::apply`] (the same validation and
//! notification path as the queue consumer). Hold decisions go through the
//! configured [`HoldReviewer`] so a release actually relays the mail; without
//! one, release is refused (503) rather than silently marking the hold
//! released.

use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::janitor::VerdictHandler;
use crate::model::{HoldStatus, Status, Verdict};
use crate::portal::HoldReviewer;
use crate::queue::HandlerError;
use crate::store::{EventFilter, Page, Store, StoreError};

/// Request bodies larger than this are rejected (413).
pub const MAX_BODY_BYTES: usize = 1 << 20;

/// Maximum stored length (bytes) of a decision reason / audit detail.
const MAX_REASON_BYTES: usize = 300;

/// Core dependencies of the internal API. Kept to these three public fields
/// so existing `ApiState { store, token, admin_token }` literals compile; the
/// `with_*` setters return a fully configured [`Api`].
#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<dyn Store>,
    pub token: String,       // analyzer token (verdicts/content)
    pub admin_token: String, // DLP admin token
}

impl ApiState {
    /// See [`Api::with_holds`].
    pub fn with_holds(self, holds: Arc<dyn HoldReviewer>) -> Api {
        Api::from(self).with_holds(holds)
    }

    /// See [`Api::with_verdicts`].
    pub fn with_verdicts(self, verdicts: Arc<VerdictHandler>) -> Api {
        Api::from(self).with_verdicts(verdicts)
    }
}

/// The full internal API state handed to the router.
#[derive(Clone)]
pub struct Api {
    pub store: Arc<dyn Store>,
    pub token: String,
    pub admin_token: String,
    /// Decides holds (release relays the mail). `None`: release answers 503
    /// and reject only records the decision in the store.
    pub holds: Option<Arc<dyn HoldReviewer>>,
    /// Validates and applies analyzer verdicts.
    pub verdicts: Arc<VerdictHandler>,
}

impl From<ApiState> for Api {
    fn from(s: ApiState) -> Api {
        // Fallback handler (no notifications; metrics on a private registry).
        // Production wiring passes the shared handler with `with_verdicts`.
        let verdicts = Arc::new(VerdictHandler::new(
            s.store.clone(),
            Arc::new(crate::metrics::Metrics::new()),
        ));
        Api {
            store: s.store,
            token: s.token,
            admin_token: s.admin_token,
            holds: None,
            verdicts,
        }
    }
}

impl Api {
    /// Sets the hold reviewer used for release/reject.
    pub fn with_holds(mut self, holds: Arc<dyn HoldReviewer>) -> Self {
        self.holds = Some(holds);
        self
    }

    /// Sets the verdict handler (shared with the queue consumer).
    pub fn with_verdicts(mut self, verdicts: Arc<VerdictHandler>) -> Self {
        self.verdicts = verdicts;
        self
    }
}

/// Builds the internal API router.
pub fn router(state: impl Into<Api>) -> Router {
    let state: Api = state.into();
    Router::new()
        .route("/internal/v1/verdicts", post(post_verdict))
        .route("/internal/v1/dlp/holds", get(list_holds))
        .route("/internal/v1/dlp/holds/{id}/release", post(release_hold))
        .route("/internal/v1/dlp/holds/{id}/reject", post(reject_hold))
        .route("/internal/v1/dlp/events", get(list_events))
        .route("/internal/v1/dlp/audit", get(list_audit))
        .route("/internal/v1/dlp/rules/test", post(test_rule))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

fn bearer(headers: &HeaderMap, want: &str) -> bool {
    if want.is_empty() {
        return false;
    }
    let got = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match got {
        Some(tok) => constant_time_eq(tok.as_bytes(), want.as_bytes()),
        None => false,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn err(code: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (code, Json(json!({ "error": msg })))
}

// ---- verdicts (analyzer token) ----

#[derive(Deserialize)]
struct VerdictBody {
    attachment_id: String,
    status: String,
    #[serde(default)]
    threat_name: String,
    #[serde(default)]
    detail: Option<serde_json::Value>,
}

async fn post_verdict(
    State(st): State<Api>,
    headers: HeaderMap,
    Json(body): Json<VerdictBody>,
) -> impl IntoResponse {
    if !bearer(&headers, &st.token) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let status = match body.status.as_str() {
        "CLEAN" => Status::Clean,
        "MALICIOUS" => Status::Malicious,
        "ERROR" => Status::Error,
        _ => return err(StatusCode::BAD_REQUEST, "invalid status").into_response(),
    };
    let v = Verdict {
        attachment_id: body.attachment_id,
        status,
        threat_name: body.threat_name,
        detail: body.detail,
    };
    match st.verdicts.apply(&v).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "result": "ok" }))).into_response(),
        Err(HandlerError::Permanent(m)) if m == "unknown attachment" => {
            err(StatusCode::NOT_FOUND, "not found").into_response()
        }
        Err(HandlerError::Permanent(m)) => err(StatusCode::BAD_REQUEST, &m).into_response(),
        Err(HandlerError::Transient(e)) => {
            eprintln!("internalapi: verdict for {}: {e}", v.attachment_id);
            err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable").into_response()
        }
    }
}

// ---- DLP admin (admin token) ----

#[derive(Deserialize)]
struct ListQuery {
    status: Option<String>,
    action: Option<String>,
    severity: Option<String>,
}

async fn list_holds(
    State(st): State<Api>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> impl IntoResponse {
    if !bearer(&headers, &st.admin_token) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let status = q.status.as_deref().and_then(parse_hold_status);
    match st.store.list_holds(status, 50, Page::default()).await {
        Ok(hs) => {
            let out: Vec<_> = hs
                .iter()
                .map(|h| {
                    json!({
                        "id": h.id, "mail_from": h.mail_from, "rcpt_to": h.rcpt_to,
                        "subject": h.subject, "status": h.status.as_str(), "size": h.size,
                        "created_at": h.created_at, "expires_at": h.expires_at,
                        "decided_by": h.decided_by, "reason": h.reason,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!(out))).into_response()
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    }
}

fn parse_hold_status(s: &str) -> Option<HoldStatus> {
    match s.to_uppercase().as_str() {
        "HELD" => Some(HoldStatus::Held),
        "RELEASED" => Some(HoldStatus::Released),
        "REJECTED" => Some(HoldStatus::Rejected),
        "EXPIRED" => Some(HoldStatus::Expired),
        _ => None,
    }
}

#[derive(Deserialize, Default)]
struct DecideBody {
    #[serde(default)]
    by: String,
    #[serde(default)]
    reason: String,
}

async fn decide(
    st: &Api,
    id: &str,
    status: HoldStatus,
    action: &str,
    body: &DecideBody,
) -> (StatusCode, Json<serde_json::Value>) {
    // Validate and normalize everything before any state change, so nothing
    // after the decision can fail on the input.
    let by = crate::portal::truncate(body.by.trim(), 254);
    let by = if by.is_empty() {
        "admin-api".to_string()
    } else {
        by
    };
    let reason = crate::portal::truncate(body.reason.trim(), MAX_REASON_BYTES);
    if status == HoldStatus::Released && st.holds.is_none() {
        record_admin(st, &by, action, id, &reason, "unavailable").await;
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "release relay not configured",
        );
    }
    let res = match (&st.holds, status) {
        (Some(r), HoldStatus::Released) => r.release(id, &by).await,
        (Some(r), _) => r.reject(id, &by, &reason).await,
        (None, _) => {
            st.store
                .decide_hold(id, status, &by, &reason, Utc::now())
                .await
        }
    };
    let result = match &res {
        Ok(()) => "ok",
        Err(StoreError::NotFound) => "notfound",
        Err(StoreError::Conflict) => "conflict",
        Err(_) => "error",
    };
    record_admin(st, &by, action, id, &reason, result).await;
    match res {
        Ok(()) => (StatusCode::OK, Json(json!({ "result": "ok" }))),
        Err(StoreError::NotFound) => err(StatusCode::NOT_FOUND, "not found"),
        Err(StoreError::Conflict) => err(StatusCode::CONFLICT, "hold already decided or expired"),
        Err(e) => {
            eprintln!("internalapi: hold {action} {id}: {e}");
            err(StatusCode::BAD_GATEWAY, "decision failed")
        }
    }
}

async fn record_admin(
    st: &Api,
    actor: &str,
    action: &str,
    target: &str,
    detail: &str,
    result: &str,
) {
    if let Err(e) = st
        .store
        .record_admin_action(crate::model::AdminAction {
            id: uuid::Uuid::new_v4().to_string(),
            at: Utc::now(),
            actor: actor.to_string(),
            action: action.to_string(),
            target: crate::portal::truncate(target, 128),
            detail: crate::portal::truncate(detail, MAX_REASON_BYTES),
            source: "api".to_string(),
            result: result.to_string(),
        })
        .await
    {
        eprintln!("internalapi: admin audit record failed action={action}: {e}");
    }
}

async fn release_hold(
    State(st): State<Api>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<DecideBody>,
) -> impl IntoResponse {
    if !bearer(&headers, &st.admin_token) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    decide(&st, &id, HoldStatus::Released, "release", &body)
        .await
        .into_response()
}

async fn reject_hold(
    State(st): State<Api>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<DecideBody>,
) -> impl IntoResponse {
    if !bearer(&headers, &st.admin_token) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    decide(&st, &id, HoldStatus::Rejected, "reject", &body)
        .await
        .into_response()
}

async fn list_events(
    State(st): State<Api>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> impl IntoResponse {
    if !bearer(&headers, &st.admin_token) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let filter = EventFilter {
        action: q.action.unwrap_or_default().to_lowercase(),
        severity: q.severity.unwrap_or_default().to_lowercase(),
    };
    match st.store.list_dlp_events(filter, 100, Page::default()).await {
        Ok(evs) => {
            let out: Vec<_> = evs
                .iter()
                .map(|e| {
                    json!({
                        "id": e.id, "mail_from": e.mail_from, "rcpt_to": e.rcpt_to, "subject": e.subject,
                        "action": e.action, "severity": e.severity, "hold_id": e.hold_id, "at": e.at,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!(out))).into_response()
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    }
}

async fn list_audit(State(st): State<Api>, headers: HeaderMap) -> impl IntoResponse {
    if !bearer(&headers, &st.admin_token) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    match st.store.list_admin_actions(100, Page::default()).await {
        Ok(acts) => {
            let out: Vec<_> = acts
                .iter()
                .map(|a| {
                    json!({
                        "id": a.id, "at": a.at, "actor": a.actor, "action": a.action,
                        "target": a.target, "detail": a.detail, "source": a.source, "result": a.result,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!(out))).into_response()
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    }
}

#[derive(Deserialize)]
struct TestRuleBody {
    pattern: String,
    #[serde(default)]
    text: String,
}

async fn test_rule(
    State(st): State<Api>,
    headers: HeaderMap,
    Json(body): Json<TestRuleBody>,
) -> impl IntoResponse {
    if !bearer(&headers, &st.admin_token) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    if body.pattern.is_empty() {
        return err(StatusCode::BAD_REQUEST, "pattern is required").into_response();
    }
    match crate::dlp::test_rule(&body.pattern, &body.text, 50) {
        Ok(matches) => (
            StatusCode::OK,
            Json(json!({ "count": matches.len(), "matches": matches })),
        )
            .into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, &format!("invalid pattern: {e}")).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Hold;
    use crate::store::Memory;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const ANALYZER: &str = "analyzer-token-0123456789";
    const ADMIN: &str = "admin-token-0123456789";

    async fn serve_api(api: Api) -> String {
        let app = router(api);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        addr
    }

    fn base(store: &Arc<Memory>) -> ApiState {
        ApiState {
            store: store.clone(),
            token: ANALYZER.into(),
            admin_token: ADMIN.into(),
        }
    }

    /// API without a hold reviewer.
    async fn serve() -> (String, Arc<Memory>) {
        let store: Arc<Memory> = Arc::new(Memory::new());
        let addr = serve_api(base(&store).into()).await;
        (addr, store)
    }

    /// Records reviewer calls and decides in the store.
    struct Recorder {
        inner: crate::portal::StoreHoldReviewer,
        calls: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl HoldReviewer for Recorder {
        async fn release(&self, id: &str, by: &str) -> Result<(), StoreError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("release {id} {by}"));
            self.inner.release(id, by).await
        }
        async fn reject(&self, id: &str, by: &str, reason: &str) -> Result<(), StoreError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("reject {id} {by} {}", reason.len()));
            self.inner.reject(id, by, reason).await
        }
    }

    async fn serve_with_reviewer() -> (String, Arc<Memory>, Arc<Recorder>) {
        let store: Arc<Memory> = Arc::new(Memory::new());
        let rec = Arc::new(Recorder {
            inner: crate::portal::StoreHoldReviewer::new(store.clone()),
            calls: Mutex::new(Vec::new()),
        });
        let addr = serve_api(base(&store).with_holds(rec.clone())).await;
        (addr, store, rec)
    }

    async fn request(
        addr: &str,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: &str,
    ) -> (u16, String) {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
        if let Some(t) = token {
            req.push_str(&format!("Authorization: Bearer {t}\r\n"));
        }
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        ));
        // The server may answer (413) before reading a large body.
        let _ = s.write_all(req.as_bytes()).await;
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        let text = String::from_utf8_lossy(&buf);
        let code: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (code, body)
    }

    fn pending(id: &str) -> crate::model::Attachment {
        crate::model::Attachment {
            id: id.into(),
            message_id: "m1".into(),
            filename: "f".into(),
            content_type: "x".into(),
            size: 1,
            sha256: "s".into(),
            storage_key: "k".into(),
            token_hash: format!("t{id}"),
            status: Status::Pending,
            threat_name: String::new(),
            verdict_detail: None,
            attempts: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            queued_at: Utc::now(),
            analyzed_at: None,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            download_count: 0,
            last_downloaded_at: None,
        }
    }

    async fn seed_pending(store: &Memory, ids: &[&str]) {
        let m = crate::model::Message {
            id: "m1".into(),
            ..Default::default()
        };
        let atts: Vec<_> = ids.iter().map(|i| pending(i)).collect();
        store.create_message(&m, &atts).await.unwrap();
    }

    fn hold(id: &str) -> Hold {
        let now = Utc::now();
        Hold {
            id: id.into(),
            token_hash: format!("t{id}"),
            mail_from: "a@x".into(),
            rcpt_to: vec!["b@y".into()],
            subject: "s".into(),
            storage_key: "k".into(),
            size: 1,
            findings: None,
            status: HoldStatus::Held,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            decided_at: None,
            decided_by: String::new(),
            reason: String::new(),
        }
    }

    #[tokio::test]
    async fn verdict_requires_analyzer_token() {
        let (addr, store) = serve().await;
        let id = uuid::Uuid::new_v4().to_string();
        seed_pending(&store, &[&id]).await;

        let body = format!(r#"{{"attachment_id":"{id}","status":"CLEAN"}}"#);
        // wrong token -> 401
        let (code, _) = request(&addr, "POST", "/internal/v1/verdicts", Some(ADMIN), &body).await;
        assert_eq!(code, 401);
        // right token -> 200
        let (code, _) = request(
            &addr,
            "POST",
            "/internal/v1/verdicts",
            Some(ANALYZER),
            &body,
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(
            store.get_attachment(&id).await.unwrap().status,
            Status::Clean
        );
    }

    #[tokio::test]
    async fn verdict_goes_through_handler_validation() {
        let (addr, store) = serve().await;
        let (a, b) = (
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
        );
        seed_pending(&store, &[&a, &b]).await;
        let post = |body: String| {
            let addr = addr.clone();
            async move {
                request(
                    &addr,
                    "POST",
                    "/internal/v1/verdicts",
                    Some(ANALYZER),
                    &body,
                )
                .await
            }
        };
        // Non-UUID id -> 400 (handler validation), unknown -> 404.
        let (code, _) = post(r#"{"attachment_id":"a1","status":"CLEAN"}"#.into()).await;
        assert_eq!(code, 400);
        let (code, _) = post(format!(
            r#"{{"attachment_id":"{}","status":"CLEAN"}}"#,
            uuid::Uuid::new_v4()
        ))
        .await;
        assert_eq!(code, 404);
        // PENDING is not a verdict.
        let (code, _) = post(format!(r#"{{"attachment_id":"{a}","status":"PENDING"}}"#)).await;
        assert_eq!(code, 400);
        // Detail over 64 KiB -> 400, nothing recorded.
        let big = "x".repeat(70 * 1024);
        let (code, _) = post(format!(
            r#"{{"attachment_id":"{a}","status":"MALICIOUS","detail":{{"d":"{big}"}}}}"#
        ))
        .await;
        assert_eq!(code, 400);
        assert_eq!(
            store.get_attachment(&a).await.unwrap().status,
            Status::Pending
        );
        // Threat name is sanitized (control characters stripped).
        let (code, _) = post(format!(
            r#"{{"attachment_id":"{a}","status":"MALICIOUS","threat_name":"Eicar\u0007\n"}}"#
        ))
        .await;
        assert_eq!(code, 200);
        let att = store.get_attachment(&a).await.unwrap();
        assert_eq!(att.status, Status::Malicious);
        assert_eq!(att.threat_name, "Eicar");
        // Duplicate verdict is idempotent.
        let (code, _) = post(format!(r#"{{"attachment_id":"{a}","status":"CLEAN"}}"#)).await;
        assert_eq!(code, 200);
        assert_eq!(
            store.get_attachment(&a).await.unwrap().status,
            Status::Malicious
        );
    }

    #[tokio::test]
    async fn oversized_body_rejected() {
        let (addr, _store) = serve().await;
        let big = format!(
            r#"{{"pattern":"x","text":"{}"}}"#,
            "y".repeat(MAX_BODY_BYTES)
        );
        let (code, _) = request(
            &addr,
            "POST",
            "/internal/v1/dlp/rules/test",
            Some(ADMIN),
            &big,
        )
        .await;
        assert_eq!(code, 413);
    }

    #[tokio::test]
    async fn admin_holds_release_and_audit() {
        let (addr, store, rec) = serve_with_reviewer().await;
        store.create_hold(&hold("h1")).await.unwrap();
        // analyzer token rejected for admin endpoints
        let (code, _) = request(&addr, "GET", "/internal/v1/dlp/holds", Some(ANALYZER), "").await;
        assert_eq!(code, 401);
        // list
        let (code, body) = request(
            &addr,
            "GET",
            "/internal/v1/dlp/holds?status=HELD",
            Some(ADMIN),
            "",
        )
        .await;
        assert_eq!(code, 200);
        assert!(body.contains("\"id\":\"h1\""));
        // release goes through the reviewer (which relays the mail)
        let (code, _) = request(
            &addr,
            "POST",
            "/internal/v1/dlp/holds/h1/release",
            Some(ADMIN),
            r#"{"by":"sec"}"#,
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(rec.calls.lock().unwrap().as_slice(), ["release h1 sec"]);
        assert_eq!(
            store.get_hold("h1").await.unwrap().status,
            HoldStatus::Released
        );
        // second decide conflicts
        let (code, _) = request(
            &addr,
            "POST",
            "/internal/v1/dlp/holds/h1/reject",
            Some(ADMIN),
            r#"{"by":"sec"}"#,
        )
        .await;
        assert_eq!(code, 409);
        // audit recorded
        let (code, body) = request(&addr, "GET", "/internal/v1/dlp/audit", Some(ADMIN), "").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"action\":\"release\"") && body.contains("\"actor\":\"sec\""));
    }

    #[tokio::test]
    async fn release_without_reviewer_is_refused() {
        let (addr, store) = serve().await;
        store.create_hold(&hold("h1")).await.unwrap();
        let (code, body) = request(
            &addr,
            "POST",
            "/internal/v1/dlp/holds/h1/release",
            Some(ADMIN),
            r#"{"by":"sec"}"#,
        )
        .await;
        assert_eq!(code, 503);
        assert!(body.contains("release relay not configured"));
        assert_eq!(store.get_hold("h1").await.unwrap().status, HoldStatus::Held);
        // Reject still works (records the decision in the store).
        let (code, _) = request(
            &addr,
            "POST",
            "/internal/v1/dlp/holds/h1/reject",
            Some(ADMIN),
            r#"{"by":"sec","reason":"pii"}"#,
        )
        .await;
        assert_eq!(code, 200);
        let h = store.get_hold("h1").await.unwrap();
        assert_eq!((h.status, h.reason.as_str()), (HoldStatus::Rejected, "pii"));
        let acts = store.list_admin_actions(10, Page::default()).await.unwrap();
        assert!(acts.iter().any(|a| a.result == "unavailable"));
    }

    /// Regression: a multibyte reason used to be sliced at byte 300 after the
    /// decision was committed, panicking the handler (no response, no audit).
    #[tokio::test]
    async fn multibyte_reason_is_truncated_safely() {
        let (addr, store, rec) = serve_with_reviewer().await;
        store.create_hold(&hold("h1")).await.unwrap();
        let reason = format!("a{}", "가".repeat(101)); // 304 bytes, byte 300 mid-char
        let body = serde_json::json!({ "by": "sec", "reason": reason }).to_string();
        let (code, _) = request(
            &addr,
            "POST",
            "/internal/v1/dlp/holds/h1/reject",
            Some(ADMIN),
            &body,
        )
        .await;
        assert_eq!(code, 200, "handler must answer");
        let h = store.get_hold("h1").await.unwrap();
        assert_eq!(h.status, HoldStatus::Rejected);
        assert_eq!(h.reason.len(), 298, "truncated on a char boundary");
        assert_eq!(rec.calls.lock().unwrap().as_slice(), ["reject h1 sec 298"]);
        let acts = store.list_admin_actions(10, Page::default()).await.unwrap();
        assert_eq!(acts.len(), 1, "audit row written");
        assert_eq!(acts[0].detail, h.reason);
    }

    #[tokio::test]
    async fn rule_test_endpoint() {
        let (addr, _store) = serve().await;
        let body = r#"{"pattern":"(\\d{3}-\\d{2}-\\d{4})","text":"111-22-3333 and 111-22-3333"}"#;
        let (code, out) = request(
            &addr,
            "POST",
            "/internal/v1/dlp/rules/test",
            Some(ADMIN),
            body,
        )
        .await;
        assert_eq!(code, 200);
        assert!(out.contains("\"count\":1"), "out={out}");
    }
}
