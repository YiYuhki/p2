# secmail (Rust port)

A ground-up Rust reimplementation of the Go `secmail` secure mail gateway
(DLP, inbound authentication, attachment quarantine, recipient portal), built on
`tokio`, `axum`, `tokio-rustls`, `tokio-postgres` and `redis`.

`secmail -config config.yaml` runs the full gateway:

- **Inbound SMTP proxy** (STARTTLS, DNSBL, greylisting, per-IP rate limit):
  SPF/DKIM/DMARC verification, optional DMARC enforcement, attachment
  quarantine with a structural MIME rewrite and download banner,
  `Authentication-Results` + `Received`, ARC sealing and gateway DKIM signing.
- **Outbound DLP proxy**: scan, then relay, hold for review, or block.
- **Recipient portal** (HTTP or HTTPS): token-gated downloads, OTP/header
  authentication, DLP review pages and the admin dashboard. Releasing a held
  message relays it to the outbound next hop.
- **Ops/internal API**: `/metrics`, `/healthz`, analyzer verdict and DLP admin
  endpoints.
- **Background workers**: Redis verdict consumer and the janitor (re-queue
  stalled analyses, give up after `max_attempts`, expire attachments and holds,
  prune audit events).

`secmail validate-config -config config.yaml` checks a config and exits.

## Backends

| Setting | Values |
|---------|--------|
| `database.type` | `memory` (default) or `postgres` (`database.dsn`; migrations run at startup under the same advisory lock as the Go service) |
| `queue.type` | `memory` (default; verdicts via the internal API) or `redis` (`redis.addr`, `queue.key_prefix`) |
| `storage.encryption_key` | 64 hex chars enables AES-256-GCM at rest (byte-compatible with Go) |
| `smtp.tls_cert_file` / `tls_key_file` | enables inbound STARTTLS |
| `upstream.starttls` / `require_tls` / `insecure_skip_verify` | upstream STARTTLS |
| `portal.tls_cert_file` / `tls_key_file` | serves the portal over HTTPS |

## Modules

| Module | Go source |
|--------|-----------|
| `gateway`, `smtpclient`, `tls` | `internal/gateway`, `internal/smtpclient` |
| `processor` | `internal/gateway` processor (auth → quarantine → headers → ARC → DKIM) |
| `spf`, `dkim`, `dmarc`, `dns` | `internal/{spfutil,dkimutil,dmarc}` (native verifiers, hickory DNS) |
| `arc`, `authres` | `internal/arc`, `internal/authres` |
| `mimetree`, `mimeproc` | `internal/mimeproc` (raw-byte MIME tree, extract, banner) |
| `service`, `janitor` | `internal/service` (quarantine, verdicts, janitor, notices) |
| `outbound`, `dlp` | `internal/outbound`, `internal/dlp` |
| `portal` | `internal/portal` (downloads, OTP/session/CSRF, DLP review, dashboard) |
| `internalapi`, `http`, `metrics` | `internal/internalapi`, ops HTTP |
| `store::{memory,postgres}`, `queue`, `redisq`, `storage` | `internal/{store,queue,storage}` |
| `config`, `model`, `dnsbl`, `greylist`, `ratelimit`, `webhook` | same-named Go packages |

### Differences from the Go version

- The portal streams CLEAN files directly from `GET /dl/{token}`; Go's
  one-time download-ticket step is not ported.
- OTP codes are kept in memory (no Redis code store).
- The webhook notifier has no production HTTP transport wired in yet.
- `timezone` accepts fixed offsets (`+09:00`) and a few common zone names.
- DKIM verification supports `rsa-sha256` (not `ed25519-sha256`).

## Build & test

```sh
cd rust
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

The Postgres and Redis integration tests run when these are set (they skip
otherwise):

```sh
SECMAIL_TEST_PG='host=127.0.0.1 user=postgres password=postgres dbname=secmail_test' \
SECMAIL_TEST_REDIS=redis://127.0.0.1:6379/ cargo test
```

## Scope

As with the Go implementation, the file static/dynamic **analysis engine** stays
a separate project; this port provides the gateway and the analyzer integration
contract (jobs on the queue, verdicts back via Redis or the internal API), not
the engine.
