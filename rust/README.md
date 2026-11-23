# secmail (Rust port)

A ground-up Rust reimplementation of the Go `secmail` secure mail gateway
(DLP, inbound authentication, quarantine portal). It is being ported **subsystem
by subsystem**: each lands compiling and unit-tested before the next.

The pure-logic layers are ported first; the async I/O layers (SMTP proxy, HTTP
portal, Postgres/Redis stores) follow, built on `tokio`.

## Status

| Module | Go source | Status |
|--------|-----------|--------|
| `arc::canon` | `internal/arc` (RFC 6376 relaxed canonicalization) | ✅ ported + RFC-vector tests |
| `dnsbl` | `internal/dnsbl` | ✅ reversal/zone logic + `Resolver` trait (real DNS impl pending) |
| `greylist` | `internal/greylist` | ✅ ported + tests |
| `ratelimit` | `internal/ratelimit` | ✅ token bucket + tests |
| `arc` signing | `internal/arc` (AMS/Seal) | ⏳ needs RSA crypto |
| `config`, `model` | `internal/config`, `internal/model` | ⏳ next |
| crypto (`storage::encrypt`, DKIM/ARC sign, webhook HMAC) | — | ⏳ |
| SMTP proxy, portal, stores, DLP | — | ⏳ |

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
