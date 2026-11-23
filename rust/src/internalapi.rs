//! Internal API for the external analyzer and DLP administration. Port of the Go
//! `internal/internalapi`: verdict submission (analyzer token) and the DLP admin
//! endpoints — holds list/release/reject, events, audit log, rule test — guarded
//! by the admin token.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::model::{HoldStatus, Status};
use crate::store::{EventFilter, Page, Store, StoreError};

/// Shared state for the internal API.
#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<dyn Store>,
    pub token: String,       // analyzer token (verdicts/content)
    pub admin_token: String, // DLP admin token
}

/// Builds the internal API router.
pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/internal/v1/verdicts", post(post_verdict))
        .route("/internal/v1/dlp/holds", get(list_holds))
        .route("/internal/v1/dlp/holds/{id}/release", post(release_hold))
        .route("/internal/v1/dlp/holds/{id}/reject", post(reject_hold))
        .route("/internal/v1/dlp/events", get(list_events))
        .route("/internal/v1/dlp/audit", get(list_audit))
        .route("/internal/v1/dlp/rules/test", post(test_rule))
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
    State(st): State<ApiState>,
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
    match st
        .store
        .set_verdict(
            &body.attachment_id,
            status,
            &body.threat_name,
            body.detail,
            Utc::now(),
        )
        .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({ "result": "ok" }))).into_response(),
        Err(StoreError::NotFound) => err(StatusCode::NOT_FOUND, "not found").into_response(),
        Err(StoreError::Conflict) => err(StatusCode::CONFLICT, "already decided").into_response(),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
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
    State(st): State<ApiState>,
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
    st: &ApiState,
    id: &str,
    status: HoldStatus,
    action: &str,
    body: &DecideBody,
) -> (StatusCode, Json<serde_json::Value>) {
    let by = if body.by.is_empty() {
        "admin-api"
    } else {
        &body.by
    };
    let res = st
        .store
        .decide_hold(id, status, by, &body.reason, Utc::now())
        .await;
    let result = match &res {
        Ok(()) => "ok",
        Err(StoreError::NotFound) => "notfound",
        Err(StoreError::Conflict) => "conflict",
        Err(_) => "error",
    };
    record_admin(st, by, action, id, &body.reason, result).await;
    match res {
        Ok(()) => (StatusCode::OK, Json(json!({ "result": "ok" }))),
        Err(StoreError::NotFound) => err(StatusCode::NOT_FOUND, "not found"),
        Err(StoreError::Conflict) => err(StatusCode::CONFLICT, "hold already decided"),
        Err(_) => err(StatusCode::BAD_GATEWAY, "decision failed"),
    }
}

async fn record_admin(
    st: &ApiState,
    actor: &str,
    action: &str,
    target: &str,
    detail: &str,
    result: &str,
) {
    let detail = if detail.len() > 300 {
        &detail[..300]
    } else {
        detail
    };
    let _ = st
        .store
        .record_admin_action(crate::model::AdminAction {
            id: uuid::Uuid::new_v4().to_string(),
            at: Utc::now(),
            actor: actor.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            detail: detail.to_string(),
            source: "api".to_string(),
            result: result.to_string(),
        })
        .await;
}

async fn release_hold(
    State(st): State<ApiState>,
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
    State(st): State<ApiState>,
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
    State(st): State<ApiState>,
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

async fn list_audit(State(st): State<ApiState>, headers: HeaderMap) -> impl IntoResponse {
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
    State(st): State<ApiState>,
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn serve() -> (String, Arc<Memory>) {
        let store: Arc<Memory> = Arc::new(Memory::new());
        let app = router(ApiState {
            store: store.clone(),
            token: "analyzer-token-0123456789".into(),
            admin_token: "admin-token-0123456789".into(),
        });
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        (addr, store)
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
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        let code: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (code, body)
    }

    #[tokio::test]
    async fn verdict_requires_analyzer_token() {
        let (addr, store) = serve().await;
        // seed a pending attachment
        let m = crate::model::Message {
            id: "m1".into(),
            ..Default::default()
        };
        let att = crate::model::Attachment {
            id: "a1".into(),
            message_id: "m1".into(),
            filename: "f".into(),
            content_type: "x".into(),
            size: 1,
            sha256: "s".into(),
            storage_key: "k".into(),
            token_hash: "t".into(),
            status: Status::Pending,
            threat_name: String::new(),
            verdict_detail: None,
            attempts: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            queued_at: Utc::now(),
            analyzed_at: None,
            expires_at: Utc::now(),
            download_count: 0,
            last_downloaded_at: None,
        };
        store.create_message(&m, &[att]).await.unwrap();

        let body = r#"{"attachment_id":"a1","status":"CLEAN"}"#;
        // wrong token -> 401
        let (code, _) = request(
            &addr,
            "POST",
            "/internal/v1/verdicts",
            Some("admin-token-0123456789"),
            body,
        )
        .await;
        assert_eq!(code, 401);
        // right token -> 200
        let (code, _) = request(
            &addr,
            "POST",
            "/internal/v1/verdicts",
            Some("analyzer-token-0123456789"),
            body,
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(
            store.get_attachment("a1").await.unwrap().status,
            Status::Clean
        );
    }

    #[tokio::test]
    async fn admin_holds_release_and_audit() {
        let (addr, store) = serve().await;
        let now = Utc::now();
        store
            .create_hold(&Hold {
                id: "h1".into(),
                token_hash: "t".into(),
                mail_from: "a@x".into(),
                rcpt_to: vec!["b@y".into()],
                subject: "s".into(),
                storage_key: "k".into(),
                size: 1,
                findings: None,
                status: HoldStatus::Held,
                created_at: now,
                expires_at: now,
                decided_at: None,
                decided_by: String::new(),
                reason: String::new(),
            })
            .await
            .unwrap();
        let admin = "admin-token-0123456789";
        // analyzer token rejected for admin endpoints
        let (code, _) = request(
            &addr,
            "GET",
            "/internal/v1/dlp/holds",
            Some("analyzer-token-0123456789"),
            "",
        )
        .await;
        assert_eq!(code, 401);
        // list
        let (code, body) = request(
            &addr,
            "GET",
            "/internal/v1/dlp/holds?status=HELD",
            Some(admin),
            "",
        )
        .await;
        assert_eq!(code, 200);
        assert!(body.contains("\"id\":\"h1\""));
        // release
        let (code, _) = request(
            &addr,
            "POST",
            "/internal/v1/dlp/holds/h1/release",
            Some(admin),
            r#"{"by":"sec"}"#,
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(
            store.get_hold("h1").await.unwrap().status,
            HoldStatus::Released
        );
        // second decide conflicts
        let (code, _) = request(
            &addr,
            "POST",
            "/internal/v1/dlp/holds/h1/reject",
            Some(admin),
            r#"{"by":"sec"}"#,
        )
        .await;
        assert_eq!(code, 409);
        // audit recorded
        let (code, body) = request(&addr, "GET", "/internal/v1/dlp/audit", Some(admin), "").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"action\":\"release\"") && body.contains("\"actor\":\"sec\""));
    }

    #[tokio::test]
    async fn rule_test_endpoint() {
        let (addr, _store) = serve().await;
        let admin = "admin-token-0123456789";
        let body = r#"{"pattern":"(\\d{3}-\\d{2}-\\d{4})","text":"111-22-3333 and 111-22-3333"}"#;
        let (code, out) = request(
            &addr,
            "POST",
            "/internal/v1/dlp/rules/test",
            Some(admin),
            body,
        )
        .await;
        assert_eq!(code, 200);
        assert!(out.contains("\"count\":1"), "out={out}");
    }
}
