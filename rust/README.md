# secmail (Rust port)

A ground-up Rust reimplementation of the Go `secmail` secure mail gateway
(DLP, inbound authentication, quarantine portal). It is being ported **subsystem
by subsystem**: each lands compiling and unit-tested before the next.

The pure-logic layers are ported first; the async I/O layers (SMTP proxy, HTTP
portal, Postgres/Redis stores) follow, built on `tokio`.

The binary **runs**: `secmail -config config.yaml` starts the inbound SMTP
proxy (lock-step relay to the upstream) and an ops HTTP server
(`/metrics`, `/healthz`); `secmail validate-config` checks a config and exits.

## Status

| Module | Go source | Status |
|--------|-----------|--------|
| `arc::canon` + `arc::seal` | `internal/arc` | ✅ RFC 6376 canon + RSA-SHA256 AMS/Seal |
| `dnsbl` | `internal/dnsbl` | ✅ reversal/zone logic + `Resolver` trait |
| `greylist` | `internal/greylist` | ✅ |
| `ratelimit` | `internal/ratelimit` | ✅ token bucket |
| `model` | `internal/model` | ✅ |
| `config` | `internal/config` | ✅ full sections + validation + `${ENV}` |
| `storage::encrypt` | `internal/storage` | ✅ AES-256-GCM, byte-compatible framing |
| `webhook` | `internal/webhook` | ✅ HMAC + retry/backoff + DLQ |
| `dlp` | `internal/dlp` | ✅ detectors + scanner + escalation + `test_rule` |
| `store` | `internal/store` | ✅ async trait + in-memory (Postgres pending) |
| `queue` | `internal/queue` | ✅ memory + verdict retry (Redis pending) |
| `metrics` | `internal/metrics` | ✅ Prometheus collectors |
| `smtpclient` + `gateway` | `internal/smtpclient`, `internal/gateway` | ✅ async SMTP proxy (STARTTLS pending) |
| `http` | — | ✅ metrics + health (portal/admin/internal-API pending) |
| `main` | `cmd/secmail` | ✅ runs proxy + ops HTTP; `validate-config` |
| MIME rewrite, attachment quarantine | `internal/mimeproc`, `internal/service` | ⏳ |
| SPF/DKIM/DMARC verification | `internal/{spfutil,dkimutil,dmarc}` | ⏳ |
| outbound DLP service, portal, admin dashboard, internal API, Postgres/Redis | — | ⏳ |

## Build & test

```sh
cd rust
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

## Scope

As with the Go implementation, the file static/dynamic **analysis engine** stays
a separate project; this port provides the gateway and the analyzer integration
contract, not the engine.
