//! secmail binary entry point (Rust port).
//!
//! Subcommands:
//!   secmail validate-config -config config.yaml   check config, exit
//!   secmail                 -config config.yaml   run the gateway

use std::sync::Arc;

use secmail::arc::Sealer;
use secmail::config;
use secmail::gateway::{Backend, BackendOptions};
use secmail::http::{ops_router, AppState};
use secmail::metrics::Metrics;
use secmail::processor::InboundProcessor;
use secmail::smtpclient::Options as UpstreamOptions;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("validate-config") {
        std::process::exit(match validate_config(&args[2..]) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("{e}");
                1
            }
        });
    }

    let cfg_path = flag(&args, "-config").unwrap_or_else(|| "config.yaml".to_string());
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    if let Err(e) = rt.block_on(run(&cfg_path)) {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}

/// Finds `-flag value` in argv.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn validate_config(args: &[String]) -> Result<(), String> {
    let path = flag(args, "-config").unwrap_or_else(|| "config.yaml".to_string());
    config::load(&path).map(|_| ())?;
    println!("{path}: OK");
    Ok(())
}

/// Normalizes a listen spec like ":2525" to a bindable address.
fn bind_addr(listen: &str) -> String {
    if let Some(rest) = listen.strip_prefix(':') {
        format!("0.0.0.0:{rest}")
    } else {
        listen.to_string()
    }
}

async fn run(cfg_path: &str) -> Result<(), String> {
    let cfg = config::load(cfg_path)?;
    let metrics = Arc::new(Metrics::new());

    // ARC sealer (optional).
    let arc = if cfg.arc.sign {
        let pem = std::fs::read_to_string(&cfg.arc.private_key_file)
            .map_err(|e| format!("arc key: {e}"))?;
        Some(Arc::new(Sealer::load(
            &cfg.arc.domain,
            &cfg.arc.selector,
            &cfg.arc.authserv_id,
            &pem,
        )?))
    } else {
        None
    };

    // Inbound SMTP proxy.
    let backend = Arc::new(Backend::new(
        Arc::new(InboundProcessor::new(arc)),
        BackendOptions {
            recipient_domains: cfg.smtp.accepted_domains.clone(),
            hostname: cfg.smtp.hostname.clone(),
            max_message_bytes: cfg.smtp.max_message_bytes as usize,
            upstream: UpstreamOptions {
                addr: cfg.upstream.addr.clone(),
                helo_name: if cfg.upstream.helo_name.is_empty() {
                    cfg.smtp.hostname.clone()
                } else {
                    cfg.upstream.helo_name.clone()
                },
                timeout: cfg.upstream.timeout,
            },
            ..Default::default()
        },
    ));
    let smtp_listen = bind_addr(&cfg.smtp.listen);
    let smtp_l = tokio::net::TcpListener::bind(&smtp_listen)
        .await
        .map_err(|e| format!("bind smtp {smtp_listen}: {e}"))?;
    eprintln!(
        "inbound SMTP proxy listening on {smtp_listen} -> upstream {}",
        cfg.upstream.addr
    );
    let smtp_task = tokio::spawn(backend.serve(smtp_l));

    // Ops HTTP (metrics + health).
    let ops_listen = bind_addr(if cfg.internal_api.listen.is_empty() {
        "127.0.0.1:8081"
    } else {
        &cfg.internal_api.listen
    });
    let ops_l = tokio::net::TcpListener::bind(&ops_listen)
        .await
        .map_err(|e| format!("bind ops {ops_listen}: {e}"))?;
    let mut app = ops_router(AppState { metrics });
    // Internal API (analyzer verdicts + DLP admin) on the same listener when a
    // token is configured.
    if !cfg.internal_api.token.is_empty() {
        let store: Arc<dyn secmail::store::Store> = Arc::new(secmail::store::Memory::new());
        app = app.merge(secmail::internalapi::router(
            secmail::internalapi::ApiState {
                store,
                token: cfg.internal_api.token.clone(),
                admin_token: cfg.internal_api.admin_token.clone(),
            },
        ));
        eprintln!("internal API mounted (/internal/v1/...)");
    }
    eprintln!("ops HTTP (/metrics, /healthz) listening on {ops_listen}");
    let http_task = tokio::spawn(secmail::http::serve(ops_l, app));

    // Run until Ctrl-C.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => { eprintln!("shutting down"); }
        r = smtp_task => { r.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?; }
        r = http_task => { r.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?; }
    }
    let _ = &cfg; // config fields consumed above; keep binding alive
    Ok(())
}
