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
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
}

/// Serves `router` over HTTPS. Handshakes run in their own tasks (10s limit)
/// so one slow client cannot stall the accept loop.
pub async fn serve_tls(
    listener: tokio::net::TcpListener,
    router: Router,
    cfg: std::sync::Arc<rustls::ServerConfig>,
) -> std::io::Result<()> {
    use axum::serve::ListenerExt;
    axum::serve(
        TlsListener::new(listener, cfg)?.tap_io(|_| {}),
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
}

/// A TLS-terminating [`axum::serve::Listener`].
pub struct TlsListener {
    rx: tokio::sync::mpsc::Receiver<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        std::net::SocketAddr,
    )>,
    local: std::net::SocketAddr,
}

impl TlsListener {
    pub fn new(
        tcp: tokio::net::TcpListener,
        cfg: std::sync::Arc<rustls::ServerConfig>,
    ) -> std::io::Result<Self> {
        let local = tcp.local_addr()?;
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
        tokio::spawn(async move {
            loop {
                let (sock, addr) = match tcp.accept().await {
                    Ok(x) => x,
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let (acc, txc) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    let hs =
                        tokio::time::timeout(std::time::Duration::from_secs(10), acc.accept(sock))
                            .await;
                    if let Ok(Ok(tls)) = hs {
                        let _ = txc.send((tls, addr)).await;
                    }
                });
                if tx.is_closed() {
                    return;
                }
            }
        });
        Ok(TlsListener { rx, local })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(x) => x,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
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

    #[tokio::test]
    async fn https_serves_with_client_addr() {
        use axum::extract::ConnectInfo;
        use axum::routing::get;
        let cfg = crate::tls::server_config_from_pem(
            include_bytes!("../testdata/tls-cert.pem"),
            include_bytes!("../testdata/tls-key.pem"),
        )
        .unwrap();
        let app =
            Router::new().route(
                "/ip",
                get(
                    |ConnectInfo(a): ConnectInfo<std::net::SocketAddr>| async move {
                        a.ip().to_string()
                    },
                ),
            );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(serve_tls(l, app, cfg));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut s = crate::tls::connect(Box::new(tcp), "localhost", true)
            .await
            .unwrap();
        s.write_all(b"GET /ip HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(out.ends_with("127.0.0.1"), "{out}");
    }
}
