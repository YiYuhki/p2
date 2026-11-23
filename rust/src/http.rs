//! Lightweight HTTP surface: the Prometheus metrics endpoint and health check.
//! The download portal, DLP review/admin pages and the internal analyzer API
//! are ported on top of this as further handlers.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};

use crate::metrics::Metrics;

/// Shared HTTP state.
#[derive(Clone)]
pub struct AppState {
    pub metrics: Arc<Metrics>,
}

/// Builds the ops router: `/metrics` (Prometheus text) and `/healthz`.
pub fn ops_router(state: AppState) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
}

/// Serves `router` on `listener` until it errors.
pub async fn serve(listener: tokio::net::TcpListener, router: Router) -> std::io::Result<()> {
    axum::serve(listener, router).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn healthz_and_metrics() {
        let metrics = Arc::new(Metrics::new());
        metrics
            .inbound_messages
            .with_label_values(&["relayed"])
            .inc();
        let app = ops_router(AppState { metrics });
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve(l, app).await;
        });

        let body = get_path(&addr.to_string(), "/healthz").await;
        assert!(body.contains("ok"));
        let m = get_path(&addr.to_string(), "/metrics").await;
        assert!(m.contains("secmail_inbound_messages_total"));
    }

    async fn get_path(addr: &str, path: &str) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }
}
