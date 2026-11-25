//! DLP admin dashboard. Port of the Go `portal/dlp_admin.go`.
//!
//! ```text
//! GET  /dlp/admin                      dashboard page (viewers)
//! GET  /dlp/admin/holds                JSON list (status, cursor)       (viewers)
//! GET  /dlp/admin/events               JSON DLP events (action, severity, cursor)
//! GET  /dlp/admin/audit                JSON admin-action audit trail    (viewers)
//! GET  /dlp/admin/export?kind=holds|events   CSV export                 (viewers)
//! POST /dlp/admin/auth                 OTP login (otp mode)
//! POST /dlp/admin/logout               end session
//! POST /dlp/admin/holds/{id}/release   release by id                    (admins)
//! POST /dlp/admin/holds/{id}/reject    reject by id (reason form field) (admins)
//! ```
//!
//! Only available when recipient authentication is enabled (otp/header): in
//! `none` mode there is no identity to check against the admin list. Viewers
//! are DLP admins plus read-only DLP auditors; only admins may decide.

use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::json;

use super::auth::{self, authorize, is_admin, Guard, Who};
use super::dlp::{parse_report, truncate};
use super::html::{self, esc, fill, Html};
use super::{json_error, json_response, redirect, AuthMode, Portal, Req};
use crate::model::{AdminAction, HoldStatus};
use crate::store::{EventFilter, Page, StoreError};

const PAGE_LIMIT: usize = 50;
const EXPORT_CAP: usize = 50_000;
const EXPORT_BATCH: usize = 500;
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn admin_guard() -> Guard {
    Guard {
        base: "/dlp/admin".into(),
        who: Who::Admins,
        log_id: "dlp-admin".into(),
    }
}

fn viewer_guard() -> Guard {
    Guard {
        base: "/dlp/admin".into(),
        who: Who::Viewers,
        log_id: "dlp-admin".into(),
    }
}

fn disabled(st: &Portal) -> bool {
    st.options().auth_mode == AuthMode::None
}

fn disabled_json() -> Response {
    json_error(
        StatusCode::NOT_FOUND,
        "admin dashboard requires recipient auth",
    )
}

/// Common prologue of the JSON read endpoints: availability, throttle, viewer
/// authorization.
async fn json_viewer(st: &Portal, req: Request) -> Result<Req, Response> {
    if disabled(st) {
        return Err(disabled_json());
    }
    let r = Req::read(st, req).await;
    if !st.limiter.allow(&r.ip) {
        let mut resp = json_error(StatusCode::TOO_MANY_REQUESTS, "too many requests");
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        return Err(resp);
    }
    authorize(st, &r, &viewer_guard(), true).await?;
    Ok(r)
}

fn internal() -> Response {
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

/// Top finding severity (high > medium > low) and the finding count.
pub(crate) fn summarize_findings(v: &Option<serde_json::Value>) -> (String, usize) {
    let rank = |s: &str| match s {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        _ => 0,
    };
    let rep = parse_report(v);
    let mut top = String::new();
    for f in &rep.findings {
        if rank(&f.severity) > rank(&top) {
            top = f.severity.clone();
        }
    }
    (top, rep.findings.len())
}

/// Opaque keyset cursor: base64url("<unix nanos>|<id>").
pub(crate) fn encode_cursor(t: DateTime<Utc>, id: &str) -> String {
    let ns = t.timestamp_nanos_opt().unwrap_or(0);
    B64.encode(format!("{ns}|{id}"))
}

pub(crate) fn decode_cursor(s: &str) -> Page {
    let parse = || -> Option<Page> {
        let raw = String::from_utf8(B64.decode(s).ok()?).ok()?;
        let (ns, id) = raw.split_once('|')?;
        let ns: i64 = ns.parse().ok()?;
        Some(Page {
            before: Some(DateTime::from_timestamp_nanos(ns)),
            before_id: id.to_string(),
        })
    };
    if s.is_empty() {
        return Page::default();
    }
    parse().unwrap_or_default()
}

/// Parses the `status` filter: "" -> HELD, "ALL" -> any.
fn status_filter(s: &str, default_held: bool) -> Result<Option<HoldStatus>, ()> {
    match s.trim().to_ascii_uppercase().as_str() {
        "" if default_held => Ok(Some(HoldStatus::Held)),
        "" | "ALL" => Ok(None),
        "HELD" => Ok(Some(HoldStatus::Held)),
        "RELEASED" => Ok(Some(HoldStatus::Released)),
        "REJECTED" => Ok(Some(HoldStatus::Rejected)),
        "EXPIRED" => Ok(Some(HoldStatus::Expired)),
        _ => Err(()),
    }
}

fn event_filter(r: &Req) -> EventFilter {
    EventFilter {
        action: r.query_value("action").trim().to_lowercase(),
        severity: r.query_value("severity").trim().to_lowercase(),
    }
}

pub(crate) async fn holds(State(st): State<Portal>, req: Request) -> Response {
    let r = match json_viewer(&st, req).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let Ok(status) = status_filter(r.query_value("status"), true) else {
        return json_error(StatusCode::BAD_REQUEST, "bad status");
    };
    let hs = match st
        .store
        .list_holds(status, PAGE_LIMIT, decode_cursor(r.query_value("cursor")))
        .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("portal: admin list holds: {e}");
            return internal();
        }
    };
    let out: Vec<_> = hs
        .iter()
        .map(|h| {
            let (sev, n) = summarize_findings(&h.findings);
            json!({
                "id": h.id, "from": h.mail_from, "to": h.rcpt_to, "subject": h.subject,
                "status": h.status.as_str(), "severity": sev, "findings": n,
                "created": st.fmt_time(h.created_at, false),
                "expires": st.fmt_time(h.expires_at, false),
            })
        })
        .collect();
    let mut resp = json!({ "holds": out });
    if hs.len() == PAGE_LIMIT {
        let last = &hs[hs.len() - 1];
        resp["next"] = encode_cursor(last.created_at, &last.id).into();
    }
    json_response(StatusCode::OK, resp)
}

pub(crate) async fn events(State(st): State<Portal>, req: Request) -> Response {
    let r = match json_viewer(&st, req).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let evs = match st
        .store
        .list_dlp_events(
            event_filter(&r),
            PAGE_LIMIT,
            decode_cursor(r.query_value("cursor")),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("portal: admin list events: {e}");
            return internal();
        }
    };
    let out: Vec<_> = evs
        .iter()
        .map(|e| {
            let mut v = json!({
                "id": e.id, "at": st.fmt_time(e.at, false), "mail_from": e.mail_from,
                "to": e.rcpt_to, "subject": e.subject, "action": e.action, "severity": e.severity,
            });
            if !e.hold_id.is_empty() {
                v["hold_id"] = e.hold_id.clone().into();
            }
            v
        })
        .collect();
    let mut resp = json!({ "events": out });
    if evs.len() == PAGE_LIMIT {
        let last = &evs[evs.len() - 1];
        resp["next"] = encode_cursor(last.at, &last.id).into();
    }
    json_response(StatusCode::OK, resp)
}

pub(crate) async fn audit(State(st): State<Portal>, req: Request) -> Response {
    let r = match json_viewer(&st, req).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let acts = match st
        .store
        .list_admin_actions(PAGE_LIMIT, decode_cursor(r.query_value("cursor")))
        .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("portal: admin list audit: {e}");
            return internal();
        }
    };
    let out: Vec<_> = acts
        .iter()
        .map(|a| {
            let mut v = json!({
                "id": a.id, "at": st.fmt_time(a.at, false), "actor": a.actor, "action": a.action,
            });
            for (k, val) in [
                ("target", &a.target),
                ("detail", &a.detail),
                ("source", &a.source),
                ("result", &a.result),
            ] {
                if !val.is_empty() {
                    v[k] = val.clone().into();
                }
            }
            v
        })
        .collect();
    let mut resp = json!({ "actions": out });
    if acts.len() == PAGE_LIMIT {
        let last = &acts[acts.len() - 1];
        resp["next"] = encode_cursor(last.at, &last.id).into();
    }
    json_response(StatusCode::OK, resp)
}

/// Neutralizes spreadsheet formula injection (CWE-1236): a field starting with
/// `=`, `+`, `-`, `@`, tab or CR is prefixed with `'` so spreadsheets treat it
/// as literal text.
pub fn csv_safe(v: &str) -> String {
    match v.as_bytes().first() {
        Some(b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r') => format!("'{v}"),
        _ => v.to_string(),
    }
}

/// Appends one CSV record (Go `encoding/csv` quoting, `\n` line ends).
fn csv_row(out: &mut String, fields: &[&str]) {
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let quote = !f.is_empty()
            && (f.contains([',', '"', '\r', '\n'])
                || f.starts_with(char::is_whitespace)
                || *f == r"\.");
        if quote {
            out.push('"');
            out.push_str(&f.replace('"', "\"\""));
            out.push('"');
        } else {
            out.push_str(f);
        }
    }
    out.push('\n');
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub(crate) async fn export(State(st): State<Portal>, req: Request) -> Response {
    if disabled(&st) {
        return (StatusCode::NOT_FOUND, "404 page not found").into_response();
    }
    let r = Req::read(&st, req).await;
    let user = match authorize(&st, &r, &viewer_guard(), true).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let kind = r.query_value("kind");
    if kind != "holds" && kind != "events" {
        return json_error(StatusCode::BAD_REQUEST, "kind must be holds or events");
    }
    record_admin(&st, &user, "export", kind, kind, "ok").await;

    let mut out = String::new();
    let mut page = Page::default();
    let mut n = 0usize;
    if kind == "holds" {
        csv_row(
            &mut out,
            &[
                "id",
                "created_at",
                "expires_at",
                "status",
                "mail_from",
                "rcpt_to",
                "subject",
                "decided_by",
                "reason",
            ],
        );
        let status = status_filter(r.query_value("status"), false).unwrap_or(None);
        while n < EXPORT_CAP {
            let hs = match st.store.list_holds(status, EXPORT_BATCH, page).await {
                Ok(v) if !v.is_empty() => v,
                _ => break,
            };
            for h in &hs {
                csv_row(
                    &mut out,
                    &[
                        &h.id,
                        &rfc3339(h.created_at),
                        &rfc3339(h.expires_at),
                        h.status.as_str(),
                        &csv_safe(&h.mail_from),
                        &csv_safe(&h.rcpt_to.join(" ")),
                        &csv_safe(&h.subject),
                        &csv_safe(&h.decided_by),
                        &csv_safe(&h.reason),
                    ],
                );
                n += 1;
            }
            if hs.len() < EXPORT_BATCH {
                break;
            }
            let last = &hs[hs.len() - 1];
            page = Page {
                before: Some(last.created_at),
                before_id: last.id.clone(),
            };
        }
    } else {
        csv_row(
            &mut out,
            &[
                "id",
                "at",
                "action",
                "severity",
                "mail_from",
                "rcpt_to",
                "subject",
                "hold_id",
            ],
        );
        let filter = event_filter(&r);
        while n < EXPORT_CAP {
            let evs = match st
                .store
                .list_dlp_events(filter.clone(), EXPORT_BATCH, page)
                .await
            {
                Ok(v) if !v.is_empty() => v,
                _ => break,
            };
            for e in &evs {
                csv_row(
                    &mut out,
                    &[
                        &csv_safe(&e.id),
                        &rfc3339(e.at),
                        &csv_safe(&e.action),
                        &csv_safe(&e.severity),
                        &csv_safe(&e.mail_from),
                        &csv_safe(&e.rcpt_to.join(" ")),
                        &csv_safe(&e.subject),
                        &csv_safe(&e.hold_id),
                    ],
                );
                n += 1;
            }
            if evs.len() < EXPORT_BATCH {
                break;
            }
            let last = &evs[evs.len() - 1];
            page = Page {
                before: Some(last.at),
                before_id: last.id.clone(),
            };
        }
    }

    let mut resp = Response::new(Body::from(out));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"dlp-{kind}.csv\"")).expect("ascii"),
    );
    resp
}

async fn decide(st: Portal, id: String, req: Request, release: bool) -> Response {
    if disabled(&st) {
        return disabled_json();
    }
    let Some(reviewer) = st.holds.clone() else {
        return disabled_json();
    };
    let r = Req::read(&st, req).await;
    let user = match authorize(&st, &r, &admin_guard(), true).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    if uuid::Uuid::parse_str(&id).is_err() {
        return json_error(StatusCode::BAD_REQUEST, "bad id");
    }
    let (action, reason, res) = if release {
        ("release", String::new(), reviewer.release(&id, &user).await)
    } else {
        let reason = truncate(r.form_value("reason").trim(), 300);
        let res = reviewer.reject(&id, &user, &reason).await;
        ("reject", reason, res)
    };
    match res {
        Ok(()) => {
            let st_ = if release {
                HoldStatus::Released
            } else {
                HoldStatus::Rejected
            };
            record_admin(&st, &user, action, &id, &reason, "ok").await;
            eprintln!(
                "portal: admin hold decision hold={id} by={user} status={}",
                st_.as_str()
            );
            json_response(StatusCode::OK, json!({ "status": st_.as_str() }))
        }
        Err(StoreError::Conflict) => {
            record_admin(&st, &user, action, &id, &reason, "conflict").await;
            json_error(StatusCode::CONFLICT, "already decided")
        }
        Err(StoreError::NotFound) => {
            record_admin(&st, &user, action, &id, &reason, "notfound").await;
            json_error(StatusCode::NOT_FOUND, "not found")
        }
        Err(e) => {
            record_admin(&st, &user, action, &id, &reason, "error").await;
            eprintln!("portal: admin hold decision failed hold={id}: {e}");
            json_error(StatusCode::BAD_GATEWAY, "decision failed")
        }
    }
}

pub(crate) async fn release(
    State(st): State<Portal>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    decide(st, id, req, true).await
}

pub(crate) async fn reject(
    State(st): State<Portal>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    decide(st, id, req, false).await
}

/// Appends an admin-action audit record (best effort: a store failure is
/// logged and never blocks the response).
pub(crate) async fn record_admin(
    st: &Portal,
    actor: &str,
    action: &str,
    target: &str,
    detail: &str,
    result: &str,
) {
    let a = AdminAction {
        id: uuid::Uuid::new_v4().to_string(),
        at: Utc::now(),
        actor: actor.into(),
        action: action.into(),
        target: target.into(),
        detail: truncate(detail, 300),
        source: "portal".into(),
        result: result.into(),
    };
    if let Err(e) = st.store.record_admin_action(a).await {
        eprintln!("portal: admin audit record failed action={action}: {e}");
    }
}

pub(crate) async fn auth(State(st): State<Portal>, req: Request) -> Response {
    if st.options().auth_mode != AuthMode::Otp {
        return (StatusCode::NOT_FOUND, "404 page not found").into_response();
    }
    let r = Req::read(&st, req).await;
    auth::otp_login(&st, &r, &viewer_guard()).await
}

pub(crate) async fn logout(State(st): State<Portal>) -> Response {
    let mut resp = redirect("/dlp/admin");
    auth::clear_session(&st, &mut resp);
    resp
}

/// Renders the dashboard shell; the data is fetched by its script.
pub(crate) async fn dashboard(State(st): State<Portal>, req: Request) -> Response {
    let nonce = html::nonce();
    let body = if disabled(&st) {
        Html::raw(
            r#"  <div class="msg err">관리자 대시보드는 수신자 인증이 설정된 경우에만 사용할 수 있습니다
    (<code>portal.auth.mode</code> = <code>otp</code> 또는 <code>header</code>).</div>"#,
        )
    } else {
        let r = Req::read(&st, req).await;
        let user = match authorize(&st, &r, &viewer_guard(), false).await {
            Ok(u) => u,
            Err(resp) => return resp, // login / forbidden page
        };
        let can_decide = is_admin(&st, &user);
        let can_logout = !user.is_empty() && st.options().auth_mode == AuthMode::Otp;
        let bulk = if can_decide {
            Html::raw(
                r#"    <div class="bulk" id="hbulk" hidden>
      <button id="bulkRelease" type="button">선택 승인</button>
      <button id="bulkReject" class="danger" type="button">선택 반려</button>
    </div>"#,
            )
        } else {
            Html::default()
        };
        Html::raw(fill(
            html::DLP_ADMIN_APP,
            &[
                ("nonce", esc(&nonce)),
                ("bulk", bulk),
                (
                    "userbar",
                    super::userbar_html(&user, can_logout, "/dlp/admin/logout", "로그아웃"),
                ),
                (
                    "can_decide",
                    Html::raw(if can_decide { "true" } else { "false" }),
                ),
            ],
        ))
    };
    let page = fill(
        html::DLP_ADMIN,
        &[
            ("nonce", esc(&nonce)),
            ("styles", Html::raw(html::STYLES)),
            ("body", body),
        ],
    );
    html::html_response(StatusCode::OK, &html::csp_with_script(&nonce), page)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_safe_neutralizes_formulas() {
        for (inp, want) in [
            ("", ""),
            ("kim@example.com", "kim@example.com"),
            ("유출 의심", "유출 의심"),
            (
                r#"=HYPERLINK("http://evil","x")"#,
                r#"'=HYPERLINK("http://evil","x")"#,
            ),
            ("+1234", "'+1234"),
            ("-cmd", "'-cmd"),
            ("@SUM(A1)", "'@SUM(A1)"),
            ("\tx", "'\tx"),
            ("\rx", "'\rx"),
        ] {
            assert_eq!(csv_safe(inp), want, "{inp:?}");
        }
    }

    #[test]
    fn csv_quoting() {
        let mut s = String::new();
        csv_row(&mut s, &["a", "b,c", "d\"e", "", " x"]);
        assert_eq!(s, "a,\"b,c\",\"d\"\"e\",,\" x\"\n");
    }

    #[test]
    fn cursor_roundtrip() {
        let t = DateTime::from_timestamp_nanos(1_777_000_000_123_456_789);
        let p = decode_cursor(&encode_cursor(t, "id-1"));
        assert_eq!(p.before, Some(t));
        assert_eq!(p.before_id, "id-1");
        assert!(!decode_cursor("!!!").set());
        assert!(!decode_cursor("").set());
    }

    #[test]
    fn summarize() {
        let v = Some(
            json!({"findings": [{"severity": "medium"}, {"severity": "high"}, {"severity": "low"}]}),
        );
        assert_eq!(summarize_findings(&v), ("high".into(), 3));
        assert_eq!(summarize_findings(&None), (String::new(), 0));
    }
}
