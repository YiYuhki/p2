//! secmail binary entry point (Rust port).
//!
//! Subcommands:
//!   secmail validate-config -config config.yaml   check config, exit
//!   secmail                 -config config.yaml   run the gateway

use std::sync::Arc;
use std::time::Duration;

use secmail::arc::Sealer;
use secmail::config::{self, Config};
use secmail::dns::Resolver;
use secmail::gateway::{Backend, BackendOptions};
use secmail::http::{ops_router, AppState};
use secmail::metrics::Metrics;
use secmail::processor::{AuthOptions, InboundProcessor, Options as ProcOptions};
use secmail::smtpclient::Options as SmtpOptions;

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

fn smtp_opts(u: &config::Upstream, default_helo: &str) -> SmtpOptions {
    SmtpOptions {
        addr: u.addr.clone(),
        helo_name: if u.helo_name.is_empty() {
            default_helo.to_string()
        } else {
            u.helo_name.clone()
        },
        timeout: u.timeout,
        starttls: u.starttls,
        require_tls: u.require_tls,
        insecure_skip_verify: u.insecure_skip_verify,
    }
}

/// Connection/session limits shared by the inbound and outbound listeners.
fn limits(cfg: &Config) -> BackendOptions {
    let n = |v: i32| usize::try_from(v).unwrap_or(0);
    BackendOptions {
        read_timeout: cfg.smtp.read_timeout,
        write_timeout: cfg.smtp.write_timeout,
        max_connections: n(cfg.smtp.max_connections),
        max_connections_per_ip: n(cfg.smtp.max_connections_per_ip),
        max_recipients: n(cfg.smtp.max_recipients),
        max_line_length: n(cfg.smtp.max_line_length),
        ..Default::default()
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Display offset (minutes east of UTC) and label for the configured time
/// zone. Fixed offsets ("+09:00") and a few common zone names are supported.
fn tz_offset(tz: &str) -> (i32, String) {
    let t = tz.trim();
    match t {
        "" | "UTC" | "Etc/UTC" => return (0, "UTC".into()),
        "Asia/Seoul" => return (540, "KST".into()),
        "Asia/Tokyo" => return (540, "JST".into()),
        "Asia/Shanghai" | "Asia/Singapore" | "Asia/Taipei" | "Asia/Hong_Kong" => {
            return (480, t.into())
        }
        _ => {}
    }
    let (sign, rest) = match t.as_bytes().first() {
        Some(b'+') => (1, &t[1..]),
        Some(b'-') => (-1, &t[1..]),
        _ => {
            eprintln!("timezone {t:?} not supported; using UTC (use +HH:MM)");
            return (0, "UTC".into());
        }
    };
    let (h, m) = rest.split_once(':').unwrap_or((rest, "0"));
    let mins = h.parse::<i32>().unwrap_or(0) * 60 + m.parse::<i32>().unwrap_or(0);
    (sign * mins, format!("UTC{t}"))
}

/// Builds the Redis URL from host:port (or a full redis:// URL) plus auth/db.
fn redis_url(r: &config::Redis) -> String {
    if r.addr.starts_with("redis://") || r.addr.starts_with("rediss://") {
        return r.addr.clone();
    }
    let auth = if r.password.is_empty() {
        String::new()
    } else {
        format!(":{}@", r.password)
    };
    format!("redis://{auth}{}/{}", r.addr, r.db)
}

async fn run(cfg_path: &str) -> Result<(), String> {
    let cfg: Config = config::load(cfg_path)?;
    let metrics = Arc::new(Metrics::new());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let upstream = smtp_opts(&cfg.upstream, &cfg.smtp.hostname);

    // ---- persistence ----
    let store: Arc<dyn secmail::store::Store> = if cfg.database.kind == "postgres" {
        let pg = secmail::store::postgres::Postgres::connect(
            &cfg.database.dsn,
            cfg.database.max_conns.max(1) as usize,
        )
        .await?;
        eprintln!("store: postgres (migrations applied)");
        Arc::new(pg)
    } else {
        eprintln!("store: in-memory (data is lost on restart)");
        Arc::new(secmail::store::Memory::new())
    };
    let mut storage: Arc<dyn secmail::storage::Storage> = Arc::new(
        secmail::storage::Fs::new(&cfg.storage.dir)
            .await
            .map_err(|e| e.to_string())?,
    );
    if !cfg.storage.encryption_key.is_empty() {
        let key = hex_decode(&cfg.storage.encryption_key)
            .map_err(|e| format!("storage.encryption_key: {e}"))?;
        storage =
            Arc::new(secmail::storage::Encrypted::new(storage, &key).map_err(|e| e.to_string())?);
        eprintln!("attachment at-rest encryption enabled (AES-256-GCM)");
    }

    // ---- analysis queue ----
    let verdicts = Arc::new(
        secmail::janitor::VerdictHandler::new(store.clone(), metrics.clone()).with_notifier_opt(
            cfg.analysis.notify_recipients && !cfg.analysis.notify_from.is_empty(),
            || {
                Arc::new(secmail::janitor::SmtpMailer::new(
                    upstream.clone(),
                    &cfg.analysis.notify_from,
                    "보안 메일 게이트웨이",
                ))
            },
        ),
    );
    let queue: Arc<dyn secmail::queue::Queue> = if cfg.queue.kind == "redis" {
        let rq = Arc::new(
            secmail::redisq::RedisQueue::connect(&redis_url(&cfg.redis), &cfg.queue.key_prefix)
                .await?,
        );
        let (c, h, sd) = (rq.clone(), verdicts.clone(), shutdown_rx.clone());
        tokio::spawn(async move { c.consume_results(h.as_ref(), sd).await });
        eprintln!("queue: redis {} (verdict consumer started)", cfg.redis.addr);
        rq
    } else {
        eprintln!("queue: in-memory (verdicts arrive via the internal API)");
        Arc::new(secmail::queue::Memory::new())
    };

    // ---- background janitor ----
    let audit_retention = match cfg.analysis.audit_retention.as_deref() {
        Some(s) if !s.trim().is_empty() => {
            Some(config::dur::parse(s).map_err(|e| format!("analysis.audit_retention: {e}"))?)
        }
        _ => None,
    };
    tokio::spawn(
        secmail::janitor::Janitor {
            store: store.clone(),
            storage: storage.clone(),
            queue: queue.clone(),
            analysis_timeout: cfg.analysis.timeout,
            max_attempts: cfg.analysis.max_attempts,
            audit_retention,
        }
        .run(cfg.analysis.janitor_interval, shutdown_rx.clone()),
    );

    // ---- inbound quarantine ----
    let service = Arc::new(
        secmail::service::Service::new(
            store.clone(),
            storage.clone(),
            queue.clone(),
            metrics.clone(),
            cfg.portal.public_base_url.clone(),
            cfg.portal.link_ttl,
            cfg.rewrite.gateway_id.clone(),
            &cfg.rewrite.blocked_extensions,
        )
        .with_rewrite(secmail::mimetree::Options {
            keep_inline_images: cfg.rewrite.keep_inline_images,
            signed_passthrough: cfg.rewrite.signed_policy == config::POLICY_PASSTHROUGH,
            encrypted_reject: cfg.rewrite.encrypted_policy == config::POLICY_REJECT,
        }),
    );

    // ---- inbound authentication ----
    let resolver: Arc<dyn Resolver> = Arc::new(secmail::dns::Hickory::new());
    let auth = AuthOptions {
        spf: cfg.spf.verify_inbound.then(|| {
            Arc::new(secmail::spf::Checker::new(
                resolver.clone(),
                cfg.spf.timeout,
            )) as Arc<dyn secmail::spf::Check>
        }),
        dkim: cfg.dkim.verify_inbound.then(|| resolver.clone()),
        dmarc: cfg.dmarc.verify_inbound.then(|| {
            Arc::new(secmail::dmarc::Evaluator::new(
                resolver.clone(),
                cfg.dmarc.timeout,
            ))
        }),
        enforce_dmarc: cfg.dmarc.enforce,
    };
    let signer = if cfg.dkim.sign {
        let pem = std::fs::read_to_string(&cfg.dkim.private_key_file)
            .map_err(|e| format!("dkim key: {e}"))?;
        Some(Arc::new(secmail::dkim::Signer::load(
            &cfg.dkim.domain,
            &cfg.dkim.selector,
            &pem,
        )?))
    } else {
        None
    };
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
    let processor = Arc::new(InboundProcessor::with_options(
        Some(service),
        arc,
        ProcOptions {
            hostname: cfg.smtp.hostname.clone(),
            auth,
            strip_original_dkim: cfg.dkim.strip_original,
            signer,
            metrics: Some(metrics.clone()),
        },
    ));

    // ---- optional inbound protections ----
    let mut greylist: Option<Arc<dyn secmail::gateway::Greylister>> = None;
    if cfg.greylist.enabled {
        let gl = Arc::new(secmail::greylist::Greylist::new(
            cfg.greylist.delay,
            cfg.greylist.expiry,
        ));
        let sweep = gl.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(3600));
            loop {
                t.tick().await;
                sweep.sweep();
            }
        });
        greylist = Some(gl);
        eprintln!("greylisting enabled");
    }
    let mut rate_limit: Option<Arc<dyn secmail::gateway::RateLimiter>> = None;
    if let Some(rl) = secmail::ratelimit::Limiter::new(
        cfg.smtp.rate_limit_per_ip_rps,
        cfg.smtp.rate_limit_per_ip_burst,
    ) {
        let rl = Arc::new(rl);
        let sweep = rl.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(600));
            loop {
                t.tick().await;
                sweep.sweep(Duration::from_secs(3600));
            }
        });
        rate_limit = Some(rl);
        eprintln!("inbound per-IP rate limit enabled");
    }
    let mut conn_gate: Option<Arc<dyn secmail::gateway::ConnGate>> = None;
    if let Some(c) =
        secmail::dnsbl::AsyncChecker::new(&cfg.dnsbl.zones, resolver.clone(), cfg.dnsbl.timeout)
    {
        conn_gate = Some(Arc::new(c));
        eprintln!("dnsbl enabled: {:?}", cfg.dnsbl.zones);
    }
    let smtp_tls = if cfg.smtp.tls_cert_file.is_empty() {
        None
    } else {
        eprintln!("inbound STARTTLS enabled");
        Some(secmail::tls::server_config(
            &cfg.smtp.tls_cert_file,
            &cfg.smtp.tls_key_file,
        )?)
    };

    // ---- inbound SMTP proxy ----
    let backend = Arc::new(Backend::new(
        processor,
        BackendOptions {
            recipient_domains: cfg.smtp.accepted_domains.clone(),
            hostname: cfg.smtp.hostname.clone(),
            max_message_bytes: cfg.smtp.max_message_bytes as usize,
            conn_gate,
            upstream: upstream.clone(),
            greylist,
            rate_limit,
            tls: smtp_tls.clone(),
            ..limits(&cfg)
        },
    ));

    // ---- optional outbound DLP listener ----
    let next_hop = smtp_opts(&cfg.outbound.next_hop, &cfg.smtp.hostname);
    if cfg.outbound.enabled {
        let scanner = Arc::new(
            secmail::dlp::Scanner::new(secmail::dlp::Options {
                combine_pii: true,
                ..Default::default()
            })
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
                upstream: next_hop.clone(),
                tls: smtp_tls.clone(),
                allowed_clients: cfg.outbound.allowed_clients.clone(),
                ..limits(&cfg)
            },
        ));
        let out_listen = bind_addr(&cfg.outbound.listen);
        let out_l = tokio::net::TcpListener::bind(&out_listen)
            .await
            .map_err(|e| format!("bind outbound {out_listen}: {e}"))?;
        eprintln!(
            "outbound DLP proxy listening on {out_listen} -> next-hop {}",
            next_hop.addr
        );
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

    // ---- recipient portal (downloads, OTP login, DLP review + dashboard) ----
    let (tz_minutes, tz_label) = tz_offset(&cfg.timezone);
    let mut portal =
        secmail::portal::PortalState::new(store.clone(), storage.clone(), metrics.clone())
            .with_options(secmail::portal::PortalOptions {
                auth_mode: secmail::portal::AuthMode::parse(&cfg.portal.auth.mode)
                    .unwrap_or_default(),
                session_secret: cfg.portal.auth.session_secret.as_bytes().to_vec(),
                session_ttl: cfg.portal.auth.session_ttl,
                otp_ttl: cfg.portal.auth.otp_ttl,
                otp_max_attempts: cfg.portal.auth.otp_max_attempts.max(1) as u32,
                otp_resend_after: cfg.portal.auth.otp_resend_after,
                otp_from: cfg.portal.auth.otp_from.clone(),
                trusted_header: cfg.portal.auth.trusted_header.clone(),
                secure_cookie: cfg.portal.public_base_url.starts_with("https://"),
                allow_domain_users: cfg.portal.auth.allow_domain_users,
                accepted_domains: cfg.smtp.accepted_domains.clone(),
                dlp_admins: cfg.dlp.admins.clone(),
                dlp_auditors: cfg.dlp.auditors.clone(),
                public_base_url: cfg.portal.public_base_url.clone(),
                tz_offset_minutes: tz_minutes,
                tz_label,
                rate_limit_rps: cfg.portal.rate_limit_rps,
                rate_limit_burst: cfg.portal.rate_limit_burst as i64,
                enum_per_ip_burst: cfg.portal.enum_per_ip_burst,
                enum_global_rps: cfg.portal.enum_global_rps,
                trust_proxy_headers: cfg.portal.trust_proxy_headers,
            })
            .with_trusted_proxies(&cfg.portal.trusted_proxies)?
            .with_otp_lockout(
                cfg.portal.auth.otp_lockout_failures,
                cfg.portal.auth.otp_lockout_window,
            );
    if !cfg.portal.auth.otp_from.is_empty() {
        portal = portal.with_mailer(Arc::new(secmail::janitor::SmtpMailer::new(
            upstream.clone(),
            &cfg.portal.auth.otp_from,
            "보안 메일 게이트웨이",
        )));
    }
    if cfg.outbound.enabled {
        portal = portal.with_holds(Arc::new(secmail::janitor::RelayHoldReviewer::new(
            store.clone(),
            storage.clone(),
            next_hop.clone(),
        )));
    }
    let portal_listen = bind_addr(&cfg.portal.listen);
    let portal_l = tokio::net::TcpListener::bind(&portal_listen)
        .await
        .map_err(|e| format!("bind portal {portal_listen}: {e}"))?;
    let portal_app = secmail::portal::router(portal);
    let portal_task = if cfg.portal.tls_cert_file.is_empty() {
        eprintln!("portal listening on http://{portal_listen}");
        tokio::spawn(secmail::http::serve(portal_l, portal_app))
    } else {
        let tls = secmail::tls::server_config(&cfg.portal.tls_cert_file, &cfg.portal.tls_key_file)?;
        eprintln!("portal listening on https://{portal_listen}");
        tokio::spawn(secmail::http::serve_tls(portal_l, portal_app, tls))
    };

    // ---- ops / internal API (metrics, health, analyzer verdicts, DLP admin) ----
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
    });
    if !cfg.internal_api.token.is_empty() {
        let mut api = secmail::internalapi::ApiState {
            store: store.clone(),
            token: cfg.internal_api.token.clone(),
            admin_token: cfg.internal_api.admin_token.clone(),
        }
        .with_verdicts(verdicts.clone());
        if cfg.outbound.enabled {
            api = api.with_holds(Arc::new(secmail::janitor::RelayHoldReviewer::new(
                store.clone(),
                storage.clone(),
                next_hop.clone(),
            )));
        }
        app = app.merge(secmail::internalapi::router(api));
        eprintln!("internal API mounted (/internal/v1/...)");
    }
    eprintln!("ops HTTP (/metrics, /healthz) listening on {ops_listen}");
    let http_task = tokio::spawn(secmail::http::serve(ops_l, app));

    // Run until Ctrl-C / SIGTERM or a listener fails.
    let term = async {
        #[cfg(unix)]
        {
            let mut s =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
            match s.as_mut() {
                Some(s) => {
                    s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        }
        #[cfg(not(unix))]
        std::future::pending::<()>().await
    };
    let res = tokio::select! {
        _ = tokio::signal::ctrl_c() => { eprintln!("shutting down"); Ok(()) }
        _ = term => { eprintln!("shutting down (SIGTERM)"); Ok(()) }
        r = smtp_task => flatten("smtp", r),
        r = http_task => flatten("ops http", r),
        r = portal_task => flatten("portal", r),
    };
    let _ = shutdown_tx.send(true);
    // Give the queue consumer a moment to finish an in-flight verdict.
    tokio::time::sleep(Duration::from_millis(200)).await;
    res
}

fn flatten(
    name: &str,
    r: Result<std::io::Result<()>, tokio::task::JoinError>,
) -> Result<(), String> {
    match r {
        Ok(Ok(())) => Err(format!("{name} listener stopped")),
        Ok(Err(e)) => Err(format!("{name}: {e}")),
        Err(e) => Err(format!("{name}: {e}")),
    }
}
