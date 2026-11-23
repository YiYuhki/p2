//! The download portal (user-facing). Port of the Go `internal/portal` download
//! gate: a token resolves to a quarantined attachment, which is served only when
//! its effective status is CLEAN, with a safe Content-Disposition. The OTP/
//! session auth, DLP review pages and admin dashboard are a follow-up.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use chrono::Utc;

use crate::metrics::Metrics;
use crate::model::Status;
use crate::storage::Storage;
use crate::store::{Store, StoreError};

/// Shared portal state.
#[derive(Clone)]
pub struct PortalState {
    pub store: Arc<dyn Store>,
    pub storage: Arc<dyn Storage>,
    pub metrics: Arc<Metrics>,
}

/// Builds the portal router (download endpoint).
pub fn router(state: PortalState) -> Router {
    Router::new()
        .route("/dl/{token}", get(download))
        .with_state(state)
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

async fn download(State(st): State<PortalState>, Path(token): Path<String>) -> Response {
    let hash = sha256_hex(token.as_bytes());
    let att = match st.store.get_attachment_by_token_hash(&hash).await {
        Ok(a) => a,
        Err(StoreError::NotFound) => {
            st.metrics
                .portal_requests
                .with_label_values(&["notfound"])
                .inc();
            return (StatusCode::NOT_FOUND, "not found").into_response();
        }
        Err(_) => {
            st.metrics
                .portal_requests
                .with_label_values(&["error"])
                .inc();
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };

    match effective_status(&att.status, att.expires_at) {
        Status::Clean => {}
        Status::Expired => {
            st.metrics
                .portal_requests
                .with_label_values(&["denied"])
                .inc();
            return (StatusCode::GONE, "This download link has expired.").into_response();
        }
        _ => {
            st.metrics
                .portal_requests
                .with_label_values(&["denied"])
                .inc();
            return (
                StatusCode::FORBIDDEN,
                "This file was blocked by security scanning.",
            )
                .into_response();
        }
    }

    let data = match st.storage.get(&att.storage_key).await {
        Ok(d) => d,
        Err(_) => {
            st.metrics
                .portal_requests
                .with_label_values(&["error"])
                .inc();
            return (StatusCode::INTERNAL_SERVER_ERROR, "object unavailable").into_response();
        }
    };

    let _ = st
        .store
        .record_download(crate::model::DownloadEvent {
            attachment_id: att.id.clone(),
            user: String::new(),
            remote_ip: String::new(),
            user_agent: String::new(),
            at: Utc::now(),
        })
        .await;
    st.metrics.portal_requests.with_label_values(&["ok"]).inc();

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, att.content_type.clone()),
            (
                header::CONTENT_DISPOSITION,
                content_disposition(&att.filename),
            ),
        ],
        data,
    )
        .into_response()
}

fn effective_status(status: &Status, expires_at: chrono::DateTime<Utc>) -> Status {
    if *status == Status::Expired || Utc::now() > expires_at {
        Status::Expired
    } else {
        *status
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Fs;
    use crate::store::Memory;
    use chrono::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn content_disposition_safe() {
        assert_eq!(
            content_disposition("a/b/evil.pdf"),
            "attachment; filename=\"evil.pdf\""
        );
        assert!(content_disposition("보고서.pdf").contains("filename*=UTF-8''%EB"));
        assert_eq!(content_disposition(""), "attachment; filename=\"download\"");
        assert!(content_disposition("a\"b.txt").contains("filename=\"a_b.txt\""));
    }

    async fn seed(
        store: &Memory,
        storage: &dyn Storage,
        token: &str,
        status: Status,
        ttl_hours: i64,
    ) {
        let now = Utc::now();
        let att = crate::model::Attachment {
            id: "a1".into(),
            message_id: "m1".into(),
            filename: "report.pdf".into(),
            content_type: "application/pdf".into(),
            size: 5,
            sha256: "s".into(),
            storage_key: "obj/a1".into(),
            token_hash: sha256_hex(token.as_bytes()),
            status,
            threat_name: String::new(),
            verdict_detail: None,
            attempts: 0,
            created_at: now,
            updated_at: now,
            queued_at: now,
            analyzed_at: None,
            expires_at: now + Duration::hours(ttl_hours),
            download_count: 0,
            last_downloaded_at: None,
        };
        let m = crate::model::Message {
            id: "m1".into(),
            ..Default::default()
        };
        store.create_message(&m, &[att]).await.unwrap();
        storage.put("obj/a1", b"%PDF%").await.unwrap();
    }

    async fn serve(store: Arc<Memory>, storage: Arc<dyn Storage>) -> String {
        let app = router(PortalState {
            store,
            storage,
            metrics: Arc::new(Metrics::new()),
        });
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        addr
    }

    async fn get(addr: &str, path: &str) -> (u16, String) {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let code: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        (code, text)
    }

    #[tokio::test]
    async fn clean_downloads_blocked_denied_expired_gone() {
        let dir = std::env::temp_dir().join(format!("secmail-portal-{}", uuid::Uuid::new_v4()));
        // CLEAN -> 200 with body + content-disposition
        let store: Arc<Memory> = Arc::new(Memory::new());
        let storage: Arc<dyn Storage> = Arc::new(Fs::new(dir.to_str().unwrap()).await.unwrap());
        seed(&store, &*storage, "tok-clean", Status::Clean, 1).await;
        let addr = serve(store, storage).await;
        let (code, resp) = get(&addr, "/dl/tok-clean").await;
        assert_eq!(code, 200);
        assert!(resp.contains("content-disposition: attachment; filename=\"report.pdf\""));
        assert!(resp.contains("%PDF%"));
        let (code, _) = get(&addr, "/dl/does-not-exist").await;
        assert_eq!(code, 404);

        // MALICIOUS -> 403
        let dir2 = std::env::temp_dir().join(format!("secmail-portal-{}", uuid::Uuid::new_v4()));
        let store2: Arc<Memory> = Arc::new(Memory::new());
        let storage2: Arc<dyn Storage> = Arc::new(Fs::new(dir2.to_str().unwrap()).await.unwrap());
        seed(&store2, &*storage2, "tok-bad", Status::Malicious, 1).await;
        let addr2 = serve(store2, storage2).await;
        assert_eq!(get(&addr2, "/dl/tok-bad").await.0, 403);

        // Expired (ttl in the past) -> 410
        let dir3 = std::env::temp_dir().join(format!("secmail-portal-{}", uuid::Uuid::new_v4()));
        let store3: Arc<Memory> = Arc::new(Memory::new());
        let storage3: Arc<dyn Storage> = Arc::new(Fs::new(dir3.to_str().unwrap()).await.unwrap());
        seed(&store3, &*storage3, "tok-old", Status::Clean, -1).await;
        let addr3 = serve(store3, storage3).await;
        assert_eq!(get(&addr3, "/dl/tok-old").await.0, 410);
    }
}
