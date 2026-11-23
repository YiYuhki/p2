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

    // Shared dependencies (in-memory store/queue; FS object store).
    let store: Arc<dyn secmail::store::Store> = Arc::new(secmail::store::Memory::new());
    let storage: Arc<dyn secmail::storage::Storage> = Arc::new(
        secmail::storage::Fs::new(&cfg.storage.dir)
            .await
            .map_err(|e| e.to_string())?,
    );
    let queue: Arc<dyn secmail::queue::Queue> = Arc::new(secmail::queue::Memory::new());

    // Inbound quarantine service.
    let service = Arc::new(secmail::service::Service::new(
        store.clone(),
        storage.clone(),
        queue.clone(),
        metrics.clone(),
        cfg.portal.public_base_url.clone(),
        cfg.portal.link_ttl,
        cfg.rewrite.gateway_id.clone(),
        &cfg.rewrite.blocked_extensions,
    ));

    // Optional inbound protections (greylisting, per-IP message rate limit).
    let mut greylist: Option<Arc<dyn secmail::gateway::Greylister>> = None;
    if cfg.greylist.enabled {
        let gl = Arc::new(secmail::greylist::Greylist::new(cfg.greylist.delay, cfg.greylist.expiry));
        let sweep = gl.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                t.tick().await;
                sweep.sweep();
            }
        });
        greylist = Some(gl);
        eprintln!("greylisting enabled");
    }
    let mut rate_limit: Option<Arc<dyn secmail::gateway::RateLimiter>> = None;
    if let Some(rl) = secmail::ratelimit::Limiter::new(cfg.smtp.rate_limit_per_ip_rps, cfg.smtp.rate_limit_per_ip_burst) {
        let rl = Arc::new(rl);
        let sweep = rl.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(600));
            loop {
                t.tick().await;
                sweep.sweep(std::time::Duration::from_secs(3600));
            }
        });
        rate_limit = Some(rl);
        eprintln!("inbound per-IP rate limit enabled");
    }

    // Inbound SMTP proxy.
    let backend = Arc::new(Backend::new(
        Arc::new(InboundProcessor::new(Some(service), arc)),
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
            greylist,
            rate_limit,
            ..Default::default()
        },
    ));

    // Optional outbound DLP listener.
    if cfg.outbound.enabled {
        let scanner = Arc::new(
            secmail::dlp::Scanner::new(secmail::dlp::Options { combine_pii: true, ..Default::default() })
                .map_err(|e| e.to_string())?,
        );
        let policy = secmail::outbound::Policy {
            high: cfg.dlp.actions.high.clone(),
            medium: cfg.dlp.actions.medium.clone(),
            low: cfg.dlp.actions.low.clone(),
            uninspectable: cfg.dlp.actions.uninspectable.clone(),
            encrypted: cfg.dlp.actions.encrypted.clone(),
            exempt_senders: cfg.dlp.exempt_senders.clone(),
            exempt_recipient_domains: cfg.dlp.exempt_recipient_domains.clone(),
            dry_run: cfg.dlp.dry_run,
        };
        let out_svc = Arc::new(secmail::outbound::Service::new(
            scanner,
            store.clone(),
            storage.clone(),
            policy,
            cfg.dlp.hold_ttl,
        ));
        let obe = Arc::new(Backend::new(
            out_svc,
            BackendOptions {
                sender_domains: if cfg.outbound.sender_domains.is_empty() {
                    cfg.smtp.accepted_domains.clone()
                } else {
                    cfg.outbound.sender_domains.clone()
                },
                hostname: cfg.smtp.hostname.clone(),
                name: "outbound".into(),
                max_message_bytes: cfg.outbound.max_message_bytes as usize,
                upstream: UpstreamOptions {
                    addr: cfg.outbound.next_hop.addr.clone(),
                    helo_name: cfg.smtp.hostname.clone(),
                    timeout: cfg.outbound.next_hop.timeout,
                },
                ..Default::default()
            },
        ));
        let out_listen = bind_addr(&cfg.outbound.listen);
        let out_l = tokio::net::TcpListener::bind(&out_listen)
            .await
            .map_err(|e| format!("bind outbound {out_listen}: {e}"))?;
        eprintln!("outbound DLP proxy listening on {out_listen} -> next-hop {}", cfg.outbound.next_hop.addr);
        tokio::spawn(obe.serve(out_l));
    }

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
    let mut app = ops_router(AppState {
        metrics: metrics.clone(),
    })
    // Download portal gate on the same listener.
    .merge(secmail::portal::router(secmail::portal::PortalState {
        store: store.clone(),
        storage: storage.clone(),
        metrics: metrics.clone(),
    }));
    // Internal API (analyzer verdicts + DLP admin) when a token is configured.
    if !cfg.internal_api.token.is_empty() {
        app = app.merge(secmail::internalapi::router(
            secmail::internalapi::ApiState {
                store: store.clone(),
                token: cfg.internal_api.token.clone(),
                admin_token: cfg.internal_api.admin_token.clone(),
            },
        ));
        eprintln!("internal API mounted (/internal/v1/...)");
    }
    eprintln!("ops HTTP (/metrics, /healthz, /dl/) listening on {ops_listen}");
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
