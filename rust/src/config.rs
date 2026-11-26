//! Loads the gateway configuration from a YAML file. `${ENV_VAR}` references are
//! expanded from the environment before parsing so secrets need not be on disk.
//! Port of the Go `internal/config` (full feature set).

use std::time::Duration;

use serde::Deserialize;

pub mod dur {
    //! Go-style duration (`"60s"`, `"5m"`, `"72h"`, `"1h30m"`, `"0s"`) <-> Duration.
    use super::Duration;
    use serde::{Deserialize, Deserializer};

    pub fn parse(s: &str) -> Result<Duration, String> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Duration::ZERO);
        }
        if s == "0" {
            return Ok(Duration::ZERO);
        }
        let mut total = Duration::ZERO;
        let mut num = String::new();
        let mut it = s.chars().peekable();
        let mut saw = false;
        while let Some(&c) = it.peek() {
            if c.is_ascii_digit() || c == '.' {
                num.push(c);
                it.next();
                continue;
            }
            // read unit (1-2 chars)
            let mut unit = String::new();
            while let Some(&u) = it.peek() {
                if u.is_ascii_alphabetic() || u == 'µ' {
                    unit.push(u);
                    it.next();
                } else {
                    break;
                }
            }
            let v: f64 = num
                .parse()
                .map_err(|_| format!("bad number in duration {s:?}"))?;
            let mult = match unit.as_str() {
                "ns" => 1e-9,
                "us" | "µs" => 1e-6,
                "ms" => 1e-3,
                "s" => 1.0,
                "m" => 60.0,
                "h" => 3600.0,
                other => return Err(format!("unknown duration unit {other:?} in {s:?}")),
            };
            total += Duration::from_secs_f64(v * mult);
            num.clear();
            saw = true;
        }
        if !saw {
            return Err(format!("missing unit in duration {s:?}"));
        }
        Ok(total)
    }

    pub fn de_opt<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        // Accept a missing/empty value as zero.
        let s = Option::<String>::deserialize(d)?;
        match s {
            None => Ok(Duration::ZERO),
            Some(s) => parse(&s).map_err(serde::de::Error::custom),
        }
    }
}

// ---- policy / action / auth constants ----
pub const POLICY_REWRITE: &str = "rewrite";
pub const POLICY_PASSTHROUGH: &str = "passthrough";
pub const POLICY_REJECT: &str = "reject";
pub const ACTION_ALLOW: &str = "allow";
pub const ACTION_NOTIFY: &str = "notify";
pub const ACTION_HOLD: &str = "hold";
pub const ACTION_BLOCK: &str = "block";
pub const AUTH_NONE: &str = "none";
pub const AUTH_OTP: &str = "otp";
pub const AUTH_HEADER: &str = "header";

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    pub timezone: String,
    pub smtp: Smtp,
    pub upstream: Upstream,
    pub rewrite: Rewrite,
    pub dkim: Dkim,
    pub arc: Arc,
    pub spf: Spf,
    pub dmarc: Dmarc,
    pub portal: Portal,
    pub internal_api: InternalApi,
    pub storage: Storage,
    pub database: Database,
    pub redis: Redis,
    pub queue: Queue,
    pub outbound: Outbound,
    pub dlp: Dlp,
    pub webhook: Webhook,
    pub dnsbl: Dnsbl,
    pub greylist: Greylist,
    pub analysis: Analysis,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Smtp {
    pub listen: String,
    pub hostname: String,
    pub accepted_domains: Vec<String>,
    pub max_message_bytes: i64,
    pub max_recipients: i32,
    pub max_line_length: i32,
    #[serde(deserialize_with = "dur::de_opt")]
    pub read_timeout: Duration,
    #[serde(deserialize_with = "dur::de_opt")]
    pub write_timeout: Duration,
    pub max_connections: i32,
    pub max_connections_per_ip: i32,
    pub tls_cert_file: String,
    pub tls_key_file: String,
    pub rate_limit_per_ip_rps: f64,
    pub rate_limit_per_ip_burst: i64,
    /// Limit on a whole SMTP session (0 = 30m).
    #[serde(deserialize_with = "dur::de_opt")]
    pub session_timeout: Duration,
    /// Limit on one DATA upload (0 = 10m).
    #[serde(deserialize_with = "dur::de_opt")]
    pub data_timeout: Duration,
    /// Limit on processing one message (0 = 5m).
    #[serde(deserialize_with = "dur::de_opt")]
    pub process_timeout: Duration,
    /// Concurrent DATA phases, all clients (0 = 16).
    pub max_concurrent_data: i32,
    /// Concurrent DATA phases per client IP / IPv6 /64 (0 = 4).
    pub max_data_per_ip: i32,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Upstream {
    pub addr: String,
    pub helo_name: String,
    pub starttls: bool,
    pub insecure_skip_verify: bool,
    #[serde(deserialize_with = "dur::de_opt")]
    pub timeout: Duration,
    pub require_tls: bool,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Rewrite {
    pub keep_inline_images: bool,
    pub signed_policy: String,
    pub encrypted_policy: String,
    pub gateway_id: String,
    pub blocked_extensions: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Dkim {
    pub verify_inbound: bool,
    pub strip_original: bool,
    pub sign: bool,
    pub domain: String,
    pub selector: String,
    pub private_key_file: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Arc {
    pub sign: bool,
    pub domain: String,
    pub selector: String,
    pub private_key_file: String,
    pub authserv_id: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Spf {
    pub verify_inbound: bool,
    #[serde(deserialize_with = "dur::de_opt")]
    pub timeout: Duration,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Dmarc {
    pub verify_inbound: bool,
    #[serde(deserialize_with = "dur::de_opt")]
    pub timeout: Duration,
    pub enforce: bool,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Portal {
    pub listen: String,
    pub public_base_url: String,
    #[serde(deserialize_with = "dur::de_opt")]
    pub link_ttl: Duration,
    #[serde(deserialize_with = "dur::de_opt")]
    pub ticket_ttl: Duration,
    pub rate_limit_rps: f64,
    pub rate_limit_burst: i32,
    pub tls_cert_file: String,
    pub tls_key_file: String,
    pub auth: PortalAuth,
    /// Take the client IP from X-Forwarded-For. Honoured only for requests
    /// arriving from one of `trusted_proxies`; requires that list.
    pub trust_proxy_headers: bool,
    /// Reverse proxies (IP addresses or CIDR networks) allowed to set
    /// X-Forwarded-For and, in header auth mode, the identity header.
    pub trusted_proxies: Vec<String>,
    pub enum_per_ip_burst: i64,
    pub enum_global_rps: f64,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct PortalAuth {
    pub mode: String,
    pub session_secret: String,
    pub trusted_header: String,
    pub otp_from: String,
    #[serde(deserialize_with = "dur::de_opt")]
    pub session_ttl: Duration,
    #[serde(deserialize_with = "dur::de_opt")]
    pub otp_ttl: Duration,
    pub otp_max_attempts: i32,
    #[serde(deserialize_with = "dur::de_opt")]
    pub otp_resend_after: Duration,
    /// Let any user of an accepted domain open attachment links.
    pub allow_domain_users: bool,
    /// Wrong OTP codes allowed per address within `otp_lockout_window`
    /// (counted across re-sent codes) before the address is locked.
    pub otp_lockout_failures: u32,
    #[serde(deserialize_with = "dur::de_opt")]
    pub otp_lockout_window: Duration,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct InternalApi {
    pub listen: String,
    pub token: String,
    pub admin_token: String,
    pub advertise_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Storage {
    #[serde(rename = "type")]
    pub kind: String,
    pub encryption_key: String,
    pub dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Database {
    #[serde(rename = "type")]
    pub kind: String,
    pub dsn: String,
    pub max_conns: i32,
    pub min_conns: i32,
    #[serde(deserialize_with = "dur::de_opt")]
    pub conn_max_lifetime: Duration,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Redis {
    pub addr: String,
    pub pool_size: i32,
    pub password: String,
    pub db: i64,
}

/// Analysis queue backend.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Queue {
    /// "memory" (in-process; verdicts via the internal API) or "redis".
    #[serde(rename = "type")]
    pub kind: String,
    pub key_prefix: String,
}

impl Default for Queue {
    fn default() -> Self {
        Queue {
            kind: "memory".into(),
            key_prefix: "secmail".into(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Outbound {
    pub enabled: bool,
    pub listen: String,
    pub max_message_bytes: i64,
    pub allowed_clients: Vec<String>,
    pub sender_domains: Vec<String>,
    pub next_hop: Upstream,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Dlp {
    pub scan_attachments: bool,
    pub actions: DlpActions,
    pub notify_sender: bool,
    pub admins: Vec<String>,
    pub auditors: Vec<String>,
    pub notify_from: String,
    #[serde(deserialize_with = "dur::de_opt")]
    pub hold_ttl: Duration,
    pub exempt_senders: Vec<String>,
    pub exempt_recipient_domains: Vec<String>,
    pub scan_internal: bool,
    pub dry_run: bool,
    pub digest: Digest,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct DlpActions {
    pub high: String,
    pub medium: String,
    pub low: String,
    pub uninspectable: String,
    pub encrypted: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Digest {
    pub enabled: bool,
    #[serde(deserialize_with = "dur::de_opt")]
    pub interval: Duration,
    pub recipients: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Webhook {
    pub url: String,
    pub secret: String,
    #[serde(deserialize_with = "dur::de_opt")]
    pub timeout: Duration,
    pub retries: i32,
    #[serde(deserialize_with = "dur::de_opt")]
    pub backoff: Duration,
    pub dead_letter_file: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Dnsbl {
    pub zones: Vec<String>,
    #[serde(deserialize_with = "dur::de_opt")]
    pub timeout: Duration,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Greylist {
    pub enabled: bool,
    #[serde(deserialize_with = "dur::de_opt")]
    pub delay: Duration,
    #[serde(deserialize_with = "dur::de_opt")]
    pub expiry: Duration,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Analysis {
    #[serde(deserialize_with = "dur::de_opt")]
    pub timeout: Duration,
    pub max_attempts: i32,
    #[serde(deserialize_with = "dur::de_opt")]
    pub verdict_reuse_window: Duration,
    #[serde(deserialize_with = "dur::de_opt")]
    pub janitor_interval: Duration,
    pub audit_retention: Option<String>,
    pub notify_recipients: bool,
    pub notify_from: String,
}

// ---- defaults (mirror Go Default()) ----

impl Default for Config {
    fn default() -> Self {
        Config {
            timezone: "Asia/Seoul".into(),
            smtp: Smtp::default(),
            upstream: Upstream {
                timeout: Duration::from_secs(60),
                ..Default::default()
            },
            rewrite: Rewrite::default(),
            dkim: Dkim {
                strip_original: true,
                ..Default::default()
            },
            arc: Arc::default(),
            spf: Spf {
                timeout: Duration::from_secs(10),
                ..Default::default()
            },
            dmarc: Dmarc {
                timeout: Duration::from_secs(5),
                ..Default::default()
            },
            portal: Portal::default(),
            internal_api: InternalApi {
                listen: "127.0.0.1:8081".into(),
                ..Default::default()
            },
            storage: Storage::default(),
            database: Database::default(),
            queue: Queue::default(),
            redis: Redis {
                addr: "localhost:6379".into(),
                ..Default::default()
            },
            outbound: Outbound {
                listen: ":10025".into(),
                max_message_bytes: 50 << 20,
                next_hop: Upstream {
                    timeout: Duration::from_secs(60),
                    ..Default::default()
                },
                ..Default::default()
            },
            dlp: Dlp::default(),
            webhook: Webhook::default(),
            dnsbl: Dnsbl::default(),
            greylist: Greylist::default(),
            analysis: Analysis::default(),
        }
    }
}

impl Default for Smtp {
    fn default() -> Self {
        Smtp {
            listen: ":2525".into(),
            hostname: "localhost".into(),
            accepted_domains: vec![],
            max_message_bytes: 50 << 20,
            max_recipients: 100,
            max_line_length: 2000,
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(60),
            max_connections: 1024,
            max_connections_per_ip: 50,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            rate_limit_per_ip_rps: 0.0,
            rate_limit_per_ip_burst: 0,
            session_timeout: Duration::ZERO,
            data_timeout: Duration::ZERO,
            process_timeout: Duration::ZERO,
            max_concurrent_data: 0,
            max_data_per_ip: 0,
        }
    }
}

impl Default for Upstream {
    fn default() -> Self {
        Upstream {
            addr: String::new(),
            helo_name: String::new(),
            starttls: false,
            insecure_skip_verify: false,
            timeout: Duration::ZERO,
            require_tls: false,
        }
    }
}

impl Default for Rewrite {
    fn default() -> Self {
        Rewrite {
            keep_inline_images: true,
            signed_policy: POLICY_REWRITE.into(),
            encrypted_policy: POLICY_PASSTHROUGH.into(),
            gateway_id: "secmail".into(),
            blocked_extensions: vec![],
        }
    }
}

impl Default for Portal {
    fn default() -> Self {
        Portal {
            listen: ":8080".into(),
            public_base_url: "http://localhost:8080".into(),
            link_ttl: Duration::from_secs(14 * 24 * 3600),
            ticket_ttl: Duration::from_secs(60),
            rate_limit_rps: 5.0,
            rate_limit_burst: 20,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            auth: PortalAuth::default(),
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
            enum_per_ip_burst: 0,
            enum_global_rps: 0.0,
        }
    }
}

impl Default for PortalAuth {
    fn default() -> Self {
        PortalAuth {
            mode: AUTH_NONE.into(),
            session_secret: String::new(),
            trusted_header: String::new(),
            otp_from: String::new(),
            session_ttl: Duration::from_secs(12 * 3600),
            otp_ttl: Duration::from_secs(10 * 60),
            otp_max_attempts: 5,
            otp_resend_after: Duration::from_secs(60),
            allow_domain_users: false,
            otp_lockout_failures: 10,
            otp_lockout_window: Duration::from_secs(3600),
        }
    }
}

impl Default for Storage {
    fn default() -> Self {
        Storage {
            kind: "fs".into(),
            encryption_key: String::new(),
            dir: "./data/objects".into(),
        }
    }
}

impl Default for Database {
    fn default() -> Self {
        Database {
            kind: "memory".into(),
            dsn: String::new(),
            max_conns: 20,
            min_conns: 2,
            conn_max_lifetime: Duration::from_secs(30 * 60),
        }
    }
}

impl Default for Dlp {
    fn default() -> Self {
        Dlp {
            scan_attachments: true,
            actions: DlpActions::default(),
            notify_sender: true,
            admins: vec![],
            auditors: vec![],
            notify_from: String::new(),
            hold_ttl: Duration::from_secs(72 * 3600),
            exempt_senders: vec![],
            exempt_recipient_domains: vec![],
            scan_internal: false,
            dry_run: false,
            digest: Digest::default(),
        }
    }
}

impl Default for DlpActions {
    fn default() -> Self {
        DlpActions {
            high: ACTION_HOLD.into(),
            medium: ACTION_NOTIFY.into(),
            low: ACTION_ALLOW.into(),
            uninspectable: ACTION_NOTIFY.into(),
            encrypted: ACTION_HOLD.into(),
        }
    }
}

impl Default for Analysis {
    fn default() -> Self {
        Analysis {
            timeout: Duration::from_secs(5 * 60),
            max_attempts: 3,
            verdict_reuse_window: Duration::from_secs(24 * 3600),
            janitor_interval: Duration::from_secs(60),
            audit_retention: None,
            notify_recipients: false,
            notify_from: String::new(),
        }
    }
}

/// Loads a config file, expanding `${ENV}` references, applying defaults for
/// missing keys, and validating. Port of Go `Load`.
pub fn load(path: &str) -> Result<Config, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("open {path}: {e}"))?;
    load_str(&raw)
}

/// Like [`load`] but from an in-memory YAML string (for tests).
pub fn load_str(raw: &str) -> Result<Config, String> {
    let expanded = expand_env(raw);
    let mut cfg: Config =
        serde_norway::from_str(&expanded).map_err(|e| format!("parse config: {e}"))?;
    cfg.validate()?;
    Ok(cfg)
}

/// Expands `${VAR}` from the environment (unset -> empty), mirroring os.ExpandEnv
/// for the `${VAR}` form used in the config.
fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            if let Some(end) = s[i + 2..].find('}') {
                let name = &s[i + 2..i + 2 + end];
                out.push_str(&std::env::var(name).unwrap_or_default());
                i = i + 2 + end + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

impl Config {
    /// Validates and normalizes the config in place. Port of Go `Validate`.
    pub fn validate(&mut self) -> Result<(), String> {
        let mut errs: Vec<String> = Vec::new();

        if self.upstream.addr.is_empty() {
            errs.push("upstream.addr is required".into());
        }
        match self.queue.kind.as_str() {
            "memory" => {}
            "redis" if self.redis.addr.is_empty() => {
                errs.push("redis.addr is required when queue.type is redis".into())
            }
            "redis" => {}
            v => errs.push(format!("queue.type: unknown value {v:?} (memory|redis)")),
        }
        match self.database.kind.as_str() {
            "memory" => {}
            "postgres" if self.database.dsn.is_empty() => {
                errs.push("database.dsn is required when database.type is postgres".into())
            }
            "postgres" => {}
            v => errs.push(format!(
                "database.type: unknown value {v:?} (memory|postgres)"
            )),
        }
        if !self.storage.encryption_key.is_empty() {
            let k = self.storage.encryption_key.trim();
            if k.len() != 64 || !k.chars().all(|c| c.is_ascii_hexdigit()) {
                errs.push("storage.encryption_key must be 64 hex characters (AES-256)".into());
            }
        }
        if (self.smtp.tls_cert_file.is_empty()) != (self.smtp.tls_key_file.is_empty()) {
            errs.push("smtp.tls_cert_file and smtp.tls_key_file must be set together".into());
        }
        if (self.portal.tls_cert_file.is_empty()) != (self.portal.tls_key_file.is_empty()) {
            errs.push("portal.tls_cert_file and portal.tls_key_file must be set together".into());
        }
        if self.smtp.max_message_bytes <= 0 {
            errs.push(
                "smtp.max_message_bytes must be positive (messages are buffered in memory)".into(),
            );
        }
        if self.outbound.enabled && self.outbound.max_message_bytes <= 0 {
            errs.push("outbound.max_message_bytes must be positive".into());
        }
        if self.smtp.accepted_domains.is_empty() {
            errs.push("smtp.accepted_domains must not be empty (open relay protection)".into());
        }
        if self.dmarc.verify_inbound && !self.spf.verify_inbound && !self.dkim.verify_inbound {
            errs.push(
                "dmarc.verify_inbound requires spf.verify_inbound and/or dkim.verify_inbound"
                    .into(),
            );
        }
        for d in self.smtp.accepted_domains.iter_mut() {
            *d = d.trim().to_lowercase();
        }
        self.portal.public_base_url = self
            .portal
            .public_base_url
            .trim_end_matches('/')
            .to_string();
        self.internal_api.advertise_url = self
            .internal_api
            .advertise_url
            .trim_end_matches('/')
            .to_string();

        match self.rewrite.signed_policy.as_str() {
            POLICY_REWRITE | POLICY_PASSTHROUGH => {}
            v => errs.push(format!("rewrite.signed_policy: unknown value {v:?}")),
        }
        match self.rewrite.encrypted_policy.as_str() {
            POLICY_PASSTHROUGH | POLICY_REJECT => {}
            v => errs.push(format!("rewrite.encrypted_policy: unknown value {v:?}")),
        }

        match self.portal.auth.mode.as_str() {
            AUTH_NONE => {}
            AUTH_OTP => {
                if self.portal.auth.session_secret.len() < 32 {
                    errs.push("portal.auth.session_secret must be at least 32 characters".into());
                }
                if self.portal.auth.otp_from.is_empty() {
                    errs.push("portal.auth.otp_from is required in otp mode".into());
                }
            }
            AUTH_HEADER => {
                if self.portal.auth.trusted_header.is_empty() {
                    errs.push("portal.auth.trusted_header is required in header mode".into());
                }
                // The identity header is only trusted from these peers;
                // without them every client could claim any address.
                if self.portal.trusted_proxies.is_empty() {
                    errs.push(
                        "portal.trusted_proxies is required in header mode (the authenticating proxy)"
                            .into(),
                    );
                }
            }
            v => errs.push(format!("portal.auth.mode: unknown value {v:?}")),
        }
        if self.portal.auth.mode == AUTH_OTP && self.portal.auth.otp_lockout_failures == 0 {
            errs.push("portal.auth.otp_lockout_failures must be at least 1".into());
        }
        if self.portal.trust_proxy_headers && self.portal.trusted_proxies.is_empty() {
            errs.push(
                "portal.trust_proxy_headers requires portal.trusted_proxies (X-Forwarded-For is client-controlled otherwise)"
                    .into(),
            );
        }
        if let Err(e) = crate::portal::parse_nets(&self.portal.trusted_proxies) {
            errs.push(format!("portal.trusted_proxies: {e}"));
        }

        if self.outbound.enabled {
            if self.outbound.next_hop.addr.is_empty() {
                errs.push("outbound.next_hop.addr is required".into());
            }
            if self.outbound.allowed_clients.is_empty() {
                errs.push(
                    "outbound.allowed_clients must list the internal mail servers (open relay protection)".into(),
                );
            }
            if self.outbound.sender_domains.is_empty() {
                self.outbound.sender_domains = self.smtp.accepted_domains.clone();
            }
            for d in self.outbound.sender_domains.iter_mut() {
                *d = d.trim().to_lowercase();
            }
            if self.dlp.actions.encrypted.is_empty() {
                self.dlp.actions.encrypted = self.dlp.actions.uninspectable.clone();
            }
            let a = &self.dlp.actions;
            for (name, v) in [
                ("high", &a.high),
                ("medium", &a.medium),
                ("low", &a.low),
                ("uninspectable", &a.uninspectable),
                ("encrypted", &a.encrypted),
            ] {
                match v.as_str() {
                    ACTION_ALLOW | ACTION_NOTIFY | ACTION_HOLD | ACTION_BLOCK => {}
                    other => errs.push(format!("dlp.actions.{name}: unknown action {other:?}")),
                }
            }
            if self.dlp.notify_from.is_empty()
                && (self.dlp.notify_sender || !self.dlp.admins.is_empty())
            {
                errs.push("dlp.notify_from is required for notifications".into());
            }
            let any_hold = [&a.high, &a.medium, &a.low, &a.uninspectable, &a.encrypted]
                .iter()
                .any(|v| v.as_str() == ACTION_HOLD);
            if any_hold && self.dlp.admins.is_empty() {
                errs.push("dlp.admins is required when an action is \"hold\"".into());
            }
        }

        if self.dkim.sign
            && (self.dkim.domain.is_empty()
                || self.dkim.selector.is_empty()
                || self.dkim.private_key_file.is_empty())
        {
            errs.push("dkim.sign requires domain, selector and private_key_file".into());
        }
        if self.arc.sign {
            if self.arc.domain.is_empty() {
                self.arc.domain = self.dkim.domain.clone();
            }
            if self.arc.selector.is_empty() {
                self.arc.selector = self.dkim.selector.clone();
            }
            if self.arc.private_key_file.is_empty() {
                self.arc.private_key_file = self.dkim.private_key_file.clone();
            }
            if self.arc.authserv_id.is_empty() {
                self.arc.authserv_id = self.smtp.hostname.clone();
            }
            if self.arc.domain.is_empty()
                || self.arc.selector.is_empty()
                || self.arc.private_key_file.is_empty()
            {
                errs.push("arc.sign requires domain, selector and private_key_file (or dkim.* to inherit from)".into());
            }
        }
        if self.upstream.require_tls {
            if !self.upstream.starttls {
                errs.push("upstream.require_tls needs upstream.starttls: true".into());
            }
            if self.upstream.insecure_skip_verify {
                errs.push(
                    "upstream.require_tls forbids upstream.insecure_skip_verify: true".into(),
                );
            }
        }
        if !self.internal_api.listen.is_empty() && self.internal_api.token.len() < 16 {
            errs.push("internal_api.token must be at least 16 characters".into());
        }
        if !self.internal_api.admin_token.is_empty() && self.internal_api.admin_token.len() < 16 {
            errs.push("internal_api.admin_token must be at least 16 characters".into());
        }
        if !self.internal_api.admin_token.is_empty()
            && self.internal_api.admin_token == self.internal_api.token
        {
            errs.push("internal_api.admin_token must differ from internal_api.token".into());
        }
        if self.analysis.max_attempts < 1 {
            self.analysis.max_attempts = 1;
        }

        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parsing() {
        assert_eq!(dur::parse("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(dur::parse("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(dur::parse("72h").unwrap(), Duration::from_secs(72 * 3600));
        assert_eq!(dur::parse("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(dur::parse("0s").unwrap(), Duration::ZERO);
        assert_eq!(dur::parse("").unwrap(), Duration::ZERO);
        assert!(dur::parse("5x").is_err());
    }

    #[test]
    fn valid_minimal_config() {
        let cfg = load_str(
            "upstream:\n  addr: 127.0.0.1:25\nsmtp:\n  accepted_domains: [example.com]\ninternal_api:\n  token: 0123456789abcdef0123\n",
        )
        .expect("valid config");
        assert_eq!(cfg.smtp.accepted_domains, vec!["example.com".to_string()]);
        assert_eq!(cfg.smtp.max_connections_per_ip, 50); // default applied
        assert_eq!(cfg.dlp.actions.high, "hold"); // default applied
    }

    #[test]
    fn domain_normalised() {
        let cfg = load_str(
            "upstream: {addr: 'mx:25'}\nsmtp: {accepted_domains: [Example.COM]}\ninternal_api: {listen: ''}\n",
        )
        .unwrap();
        assert_eq!(cfg.smtp.accepted_domains[0], "example.com");
    }

    #[test]
    fn validation_failures() {
        let base = "upstream: {addr: 'mx:25'}\nsmtp: {accepted_domains: [a.com]}\ninternal_api: {listen: ''}\n";
        let secret = "x".repeat(32);
        let bad = vec![
            ("no upstream", "smtp: {accepted_domains: [a.com]}\ninternal_api: {listen: ''}\n".to_string()),
            ("open relay", "upstream: {addr: 'mx:25'}\ninternal_api: {listen: ''}\n".to_string()),
            ("short secret", format!("{base}portal: {{auth: {{mode: otp, session_secret: short, otp_from: a@b.c}}}}\n")),
            ("otp without from", format!("{base}portal: {{auth: {{mode: otp, session_secret: {secret}}}}}\n")),
            ("header without name", format!("{base}portal: {{auth: {{mode: header}}, trusted_proxies: [10.0.0.1]}}\n")),
            ("header without proxies", format!("{base}portal: {{auth: {{mode: header, trusted_header: X-Email}}}}\n")),
            ("xff without proxies", format!("{base}portal: {{trust_proxy_headers: true}}\n")),
            ("bad proxy", format!("{base}portal: {{trusted_proxies: ['10.0.0.0/40']}}\n")),
            ("unknown auth mode", format!("{base}portal: {{auth: {{mode: magic}}}}\n")),
            ("weak api token", "upstream: {addr: 'mx:25'}\nsmtp: {accepted_domains: [a.com]}\ninternal_api: {listen: ':8081', token: x}\n".to_string()),
            ("require_tls without starttls", "upstream: {addr: 'mx:25', require_tls: true}\nsmtp: {accepted_domains: [a.com]}\ninternal_api: {listen: ''}\n".to_string()),
            ("require_tls insecure", "upstream: {addr: 'mx:25', starttls: true, require_tls: true, insecure_skip_verify: true}\nsmtp: {accepted_domains: [a.com]}\ninternal_api: {listen: ''}\n".to_string()),
        ];
        for (name, body) in bad {
            assert!(
                load_str(&body).is_err(),
                "{name}: expected validation error"
            );
        }
        // require_tls with verified starttls is valid.
        load_str("upstream: {addr: 'mx:25', starttls: true, require_tls: true}\nsmtp: {accepted_domains: [a.com]}\ninternal_api: {listen: ''}\n").expect("require_tls+starttls valid");
        // Header mode / XFF behind configured proxies is valid.
        let cfg = load_str(&format!("{base}portal: {{trust_proxy_headers: true, trusted_proxies: [10.0.0.0/8, '::1'], auth: {{mode: header, trusted_header: X-Email}}}}\n"))
            .expect("header mode behind trusted proxies");
        assert_eq!(cfg.portal.trusted_proxies.len(), 2);
        assert_eq!(cfg.portal.auth.otp_lockout_failures, 10);
    }
}
