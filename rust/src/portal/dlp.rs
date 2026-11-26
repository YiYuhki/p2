//! DLP hold review page (`/dlp/{token}`). Port of the Go `portal/dlp.go`.
//!
//! The review link mailed to the DLP admins shows the held message's envelope
//! and (masked) findings and lets an admin release or reject it. With
//! authentication enabled only configured `dlp_admins` may open it; in `none`
//! mode the unguessable link itself is the credential (as in Go).

use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::Deserialize;

use super::auth::{self, authorize, Guard, Who};
use super::html::{self, esc, fill, Html};
use super::{
    check_rate, fail, messages_html, miss, redirect, sha256_hex, userbar_html, well_formed,
    AuthMode, Portal, Req, MSG_TEMP_ERROR,
};
use crate::model::{Hold, HoldStatus};
use crate::store::{Store, StoreError};

/// Decides held messages. The production implementation (in the outbound
/// service) also relays released mail; [`StoreHoldReviewer`] only records the
/// decision.
#[async_trait]
pub trait HoldReviewer: Send + Sync {
    async fn release(&self, id: &str, by: &str) -> Result<(), StoreError>;
    async fn reject(&self, id: &str, by: &str, reason: &str) -> Result<(), StoreError>;
}

/// A [`HoldReviewer`] that records decisions with `Store::decide_hold`.
pub struct StoreHoldReviewer {
    store: Arc<dyn Store>,
}

impl StoreHoldReviewer {
    pub fn new(store: Arc<dyn Store>) -> Self {
        StoreHoldReviewer { store }
    }
}

#[async_trait]
impl HoldReviewer for StoreHoldReviewer {
    async fn release(&self, id: &str, by: &str) -> Result<(), StoreError> {
        self.store
            .decide_hold(id, HoldStatus::Released, by, "", Utc::now())
            .await
    }

    async fn reject(&self, id: &str, by: &str, reason: &str) -> Result<(), StoreError> {
        self.store
            .decide_hold(id, HoldStatus::Rejected, by, reason, Utc::now())
            .await
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct Finding {
    pub name: String,
    pub severity: String,
    pub location: String,
    pub count: i64,
    pub samples: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct Report {
    pub findings: Vec<Finding>,
    pub uninspectable: Vec<String>,
}

pub(crate) fn parse_report(v: &Option<serde_json::Value>) -> Report {
    v.as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

fn sevko(s: &str) -> &str {
    match s {
        "high" => "높음",
        "medium" => "중간",
        "low" => "낮음",
        _ => s,
    }
}

fn hold_guard(token: &str, h: &Hold) -> Guard {
    Guard {
        base: format!("/dlp/{token}"),
        who: Who::Admins,
        log_id: format!("hold:{}", h.id),
    }
}

async fn lookup_hold(st: &Portal, r: &Req, token: &str) -> Result<Hold, Response> {
    check_rate(st, r, false)?;
    if !well_formed(token) {
        return Err(miss(st, r, false));
    }
    match st
        .store
        .get_hold_by_token_hash(&sha256_hex(token.as_bytes()))
        .await
    {
        Ok(h) => Ok(h),
        Err(StoreError::NotFound) => Err(miss(st, r, false)),
        Err(e) => {
            eprintln!("portal: hold lookup: {e}");
            Err(fail(
                st,
                StatusCode::INTERNAL_SERVER_ERROR,
                false,
                MSG_TEMP_ERROR,
            ))
        }
    }
}

fn render_hold(
    st: &Portal,
    code: StatusCode,
    token: &str,
    h: &Hold,
    user: &str,
    error: &str,
    notice: &str,
) -> Response {
    let nonce = html::nonce();
    let base = format!("/dlp/{token}");
    let status = h.status.as_str();
    let badge = match h.status {
        HoldStatus::Held => "검토 대기",
        HoldStatus::Released => "발송 승인됨",
        HoldStatus::Rejected => "반려됨",
        HoldStatus::Expired => "기한 만료",
    };

    let mut decision = Html::default();
    if h.status == HoldStatus::Held {
        decision.push_raw("<dt>기한</dt><dd>");
        decision.push_esc(&st.fmt_time(h.expires_at, true));
        decision.push_raw(" (이후 자동 폐기)</dd>");
    } else {
        let decided = h
            .decided_at
            .map(|t| st.fmt_time(t, true))
            .unwrap_or_default();
        let mut s = format!("{decided} · {}", h.decided_by);
        if !h.reason.is_empty() {
            s.push_str(&format!(" · {}", h.reason));
        }
        decision.push_raw("<dt>처리</dt><dd>");
        decision.push_esc(&s);
        decision.push_raw("</dd>");
    }

    let rep = parse_report(&h.findings);
    let mut rows = Html::default();
    for f in &rep.findings {
        rows.push_raw(r#"<tr><td><span class="sev "#);
        rows.push_esc(&f.severity);
        rows.push_raw(r#"">"#);
        rows.push_esc(sevko(&f.severity));
        rows.push_raw("</span></td><td>");
        rows.push_esc(&format!("{} {}건", f.name, f.count));
        rows.push_raw("</td><td>");
        rows.push_esc(&f.location);
        rows.push_raw("</td><td>");
        rows.push_esc(&f.samples.join(", "));
        rows.push_raw("</td></tr>\n");
    }
    for u in &rep.uninspectable {
        rows.push_raw(r#"<tr><td><span class="sev medium">검사불가</span></td><td colspan="3">"#);
        rows.push_esc(u);
        rows.push_raw("</td></tr>\n");
    }

    let forms = if h.status == HoldStatus::Held {
        let b = esc(&base).into_string();
        Html::raw(format!(
            r#"<form method="post" action="{b}/release"><button type="submit">승인 후 발송</button></form>
  <form method="post" action="{b}/reject">
    <label for="reason">반려 사유 (선택, 발신자에게 전달됨)</label>
    <input id="reason" name="reason" maxlength="300" placeholder="예: 고객 주민번호를 마스킹한 뒤 다시 보내주세요">
    <button class="danger" type="submit">반려</button>
  </form>"#
        ))
    } else {
        Html::default()
    };

    let can_logout = !user.is_empty() && st.options().auth_mode == AuthMode::Otp;
    let body = fill(
        html::DLP,
        &[
            ("nonce", esc(&nonce)),
            ("styles", Html::raw(html::STYLES)),
            ("status", esc(status)),
            ("badge", {
                let mut b = Html::raw(r#"<span class="badge">"#);
                b.push_esc(badge);
                b.push_raw("</span>");
                b
            }),
            ("subject", esc(&h.subject)),
            ("from", esc(&h.mail_from)),
            ("to", esc(&h.rcpt_to.join(", "))),
            ("created", esc(&st.fmt_time(h.created_at, true))),
            ("decision", decision),
            ("findings", rows),
            ("messages", messages_html(error, notice)),
            ("forms", forms),
            (
                "userbar",
                userbar_html(
                    user,
                    can_logout,
                    &format!("{base}/logout"),
                    "다른 주소로 로그인",
                ),
            ),
        ],
    );
    html::html_response(code, &html::csp_style_only(&nonce), body)
}

pub(crate) async fn hold_page(
    State(st): State<Portal>,
    Path(token): Path<String>,
    req: Request,
) -> Response {
    let r = Req::read(&st, req).await;
    let h = match lookup_hold(&st, &r, &token).await {
        Ok(h) => h,
        Err(resp) => return resp,
    };
    let user = match authorize(&st, &r, &hold_guard(&token, &h), false).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    render_hold(&st, StatusCode::OK, &token, &h, &user, "", "")
}

pub(crate) async fn hold_auth(
    State(st): State<Portal>,
    Path(token): Path<String>,
    req: Request,
) -> Response {
    if st.options().auth_mode != AuthMode::Otp {
        return (StatusCode::NOT_FOUND, "404 page not found").into_response();
    }
    let r = Req::read(&st, req).await;
    let h = match lookup_hold(&st, &r, &token).await {
        Ok(h) => h,
        Err(resp) => return resp,
    };
    auth::otp_login(&st, &r, &hold_guard(&token, &h)).await
}

pub(crate) async fn hold_logout(State(st): State<Portal>, Path(token): Path<String>) -> Response {
    let base = if well_formed(&token) {
        format!("/dlp/{token}")
    } else {
        "/".into()
    };
    let mut resp = redirect(&base);
    auth::clear_session(&st, &mut resp);
    resp
}

/// Truncates to at most `max` bytes on a char boundary.
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

async fn hold_decide(st: Portal, token: String, req: Request, release: bool) -> Response {
    let Some(reviewer) = st.holds.clone() else {
        return (StatusCode::NOT_FOUND, "404 page not found").into_response();
    };
    let r = Req::read(&st, req).await;
    let mut h = match lookup_hold(&st, &r, &token).await {
        Ok(h) => h,
        Err(resp) => return resp,
    };
    let user = match authorize(&st, &r, &hold_guard(&token, &h), false).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let by = if user.is_empty() {
        format!("review-link ({})", r.ip)
    } else {
        user.clone()
    };
    let (action, reason) = if release {
        ("release", String::new())
    } else {
        ("reject", truncate(r.form_value("reason").trim(), 300))
    };
    let res = if release {
        reviewer.release(&h.id, &by).await
    } else {
        reviewer.reject(&h.id, &by, &reason).await
    };
    let result = match &res {
        Ok(()) => "ok",
        Err(StoreError::NotFound) => "notfound",
        Err(StoreError::Conflict) => "conflict",
        Err(_) => "error",
    };
    super::admin::record_admin(&st, &by, action, &h.id, &reason, result).await;
    if let Ok(fresh) = st.store.get_hold(&h.id).await {
        h = fresh;
    }
    match res {
        Ok(()) if release => render_hold(
            &st,
            StatusCode::OK,
            &token,
            &h,
            &user,
            "",
            "승인되어 메일이 발송되었습니다.",
        ),
        Ok(()) => render_hold(
            &st,
            StatusCode::OK,
            &token,
            &h,
            &user,
            "",
            "반려되었습니다. 발신자에게 안내 메일이 발송됩니다.",
        ),
        Err(_) if h.status != HoldStatus::Held => render_hold(
            &st,
            StatusCode::CONFLICT,
            &token,
            &h,
            &user,
            "이미 처리된 메일입니다.",
            "",
        ),
        Err(e) => {
            eprintln!("portal: hold decision failed hold={}: {e}", h.id);
            render_hold(
                &st,
                StatusCode::BAD_GATEWAY,
                &token,
                &h,
                &user,
                "처리 중 오류가 발생했습니다. 잠시 후 다시 시도하세요.",
                "",
            )
        }
    }
}

pub(crate) async fn hold_release(
    State(st): State<Portal>,
    Path(token): Path<String>,
    req: Request,
) -> Response {
    hold_decide(st, token, req, true).await
}

pub(crate) async fn hold_reject(
    State(st): State<Portal>,
    Path(token): Path<String>,
    req: Request,
) -> Response {
    hold_decide(st, token, req, false).await
}
