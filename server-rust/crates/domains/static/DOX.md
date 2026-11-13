# Static, health, metrics and Assist (F22 + F20, #271)

`setjoin-static` holds the documents and decisions behind the public surface
and the AI-assist route; it depends only on foundation crates (`setjoin-pg`) and
no other family. HTTP framing, the Go listener-chain headers (security headers,
the `Cache-Control` policy table, `X-Request-Id`) and routing are the gateway
adapters `bins/gateway/src/surface.rs` (F22), `assist.rs` (F20) and `translate.rs`
(Chat's translate route, deferred here by #268). Frozen Go is the oracle (ARCH-029).

## Routes (26 ON by default, kill switch returns each to Go)

F22: `/api/openapi.{yaml,json}`, `/api/docs`, `/api/redoc.standalone.js`,
`/api/logo.svg`, `/api/fonts/*` (2), `/api/openapi.full.{yaml,json}`,
`/downloads`, `/downloads/{platform}`, `/downloads/asset/{asset}`,
`/favicon.ico`, `/health`, `/ready`, `/metrics`, `/.well-known/{setjoin,
autoconfig/mail/config-v1.1.xml,caldav,carddav}`, `/api/cert-hint`,
`/api/discover`, `POST /telemetry`. F20: `POST /assist/complete`, `/assist/stream`.
F12: `POST /chat/messages/{id}/translate`. Go mounts `/telemetry` and `/assist/*`
under `/api` (not pinned prefixes); `inventory.rs` therefore dispatches them as
`/api/...` and a bare mutation is Go's 308 alias.

The structural F22 entries `* /` (SPA fallback) and `* /api/` (API mount)
transfer with #416 in the gateway catch-all adapter; see the [gateway
contract](../../../bins/gateway/DOX.md#catch-all-mux-and-spa-416).

## Answered in Rust, forwarded to Go

Native answers: every static document, downloads, device-proof telemetry,
discovery, ready, health (including errors and configured live probes), cert hint (always `none`: the front door
never receives a client certificate, and Go behind a TLS-terminating proxy
never did), the three assist problems/success, translate. A request goes to Go
whole, never partially answered, when Rust cannot prove Go's answer:

- Shared security-policy shapes still owned by #405/#420. Configured legacy JWTs,
  ordinary authentication denials and full-spec permission denials are native
  through shared admission (#406). Full-spec reads resolve active governed grants
  for signed admins; non-admin signed grants preserve Go's semantics, including
  domain-scoped `system.config`. Console denials write the exact durable audit.
- `/health` with SFU/egress/ASR sidecars configured (`LIVEKIT_*`, `ASR_URL`) when the gate has
  no probe runner (the gateway always supplies one: #457). An `error` row is served natively
  (503) and raises `system.health_alert` through `HealthGate::with_alerts` on the ok-to-error
  transition.
- Configuration is resolved by the gateway's YAML/environment loader (#414).
  Well-known, autoconfig, downloads and favicon use that startup snapshot and
  do not forward because `SETJOIN_CONFIG` is present.
The #416 catch-all handles ServeMux clean-path redirects before adapter dispatch.

Gateway process environment mirrors the names Go's koanf environment layer
applies: `NETWORK_MODE`, `WEBSITE_DIR`, `CRYPTO_ALGORITHM_PROFILE`, `IMAP_TLS_ADDR`
(default `:993`; a present empty value disables it) and Go's direct
`METRICS_TOKEN`, `METRICS_ALLOW_UNAUTHENTICATED`. `auth.login_field` and the
domain hint have no default key, so Go's environment layer ignores their
variables. Go also never decodes the file values into Config, so both stay
empty; Rust reports `email` and no hint (recorded by #414).

## Parity facts worth knowing

- `HEAD /downloads` and `HEAD /downloads/{platform}` return Go's 405 (the
  handlers refuse every method but GET inside the handler).
- `/metrics` answers with the Go metric names and help text; process counters
  come from the front door (`served_stats.rs`), identity gauges from the same
  SQL as Go's collector. Go's TCP/TLS/per-method families depend on Go mail
  protocols and are omitted; the SMTP queue gauge is a constant 0 in Go too.
  `/metrics` therefore reports the front door's traffic, not Go's. Accepted
  divergence: values are per process.
- OpenAPI documents: `assets/openapi.{public.yaml,public.json,full.json}` are
  Go's startup-derived outputs, recorded from the frozen binary (Go's YAML
  emitter cannot be reproduced byte for byte elsewhere); the golden bodies
  prove them by SHA-256. Regenerate from a Go binary if `mailserver/api/openapi.yaml` changes.
- Assist JSON decoding reuses the Chat decoder (Go field folding, null and
  duplicate-key rules, one invalid byte per U+FFFD). Provider calls use
  `reqwest` (rustls, system roots, 30 s, 1 MiB response cap) like Go's client.
- Translate keeps Go's order: id, body, locale (422), assist toggle (503),
  thread read through `chat_thread_list` (membership), config, the
  `translate.egress` audit before any egress (only while `feature.chat_compliance`
  is ON, via `members::translate_egress`), provider.

## Writes, ownership, divergences

The `translate.egress` audit is one call of the
existing `chat_access_audit` reducer through `members::translate_egress` (a
receipted F12 command whose actor and mailbox come from the verified token; the
oracle shows Go's identical audit row and pre-egress ordering). Telemetry insert and device-proof effects are native (#417, below). Request bodies and
paths never supply an actor; the only caller-chosen identifier is the translate
message id, read through `chat_thread_list(actor, id)` for membership.

Accepted divergences: (1) `/metrics` values are per process (front-door traffic,
Rust RSS for memory, task count for goroutines) and Go's mail-protocol families
are absent; the recordings blur only those process counters. (2) caldav/carddav
redirects follow the toggle at request time, Go at its startup. No other
divergence is recorded; HEAD answers, 405s, redirects and Go's `ServeMux` path
cleaning are covered by recordings. Rollback: `GATEWAY_ENABLED=false` or an
inventory entry set OFF returns every route (`static_native`
`both_kill_switches_return_every_route_to_go`, with per-family proxy counters).

## Oracle

`bins/gateway/tests/static_recorded.rs` replays frozen-Go recordings
([ledger](../../../tests/conformance/static1/README.md)) plus route/status mutants and
the two family mutants (`autoconfig_oracle_rejects_missing_domain_filter`,
`assist_oracle_rejects_missing_authentication`). Cases the adapters hand to Go
replay against a fake upstream serving the recorded Go answer and must forward
exactly once; native cases must never reach Go.

## Webmail representations and catch-all (#416)

`website.rs` owns operator-build validation, representation negotiation and the
static cache policy. `WEBSITE_DIR` must contain a build-matched
`static-representations.v1.json` and `_app/version.json`. Every identity and
sidecar is hash/size verified before serving; undeclared files/sidecars,
symlinks, parent paths, duplicate identities, wrong build IDs and misbound or
non-saving sidecars refuse startup, as frozen Go does. This directory contains
operator release assets, never tenant uploads.

The gateway's `catchall.rs` and `catchall/static_file.rs` preserve the root/API
mux boundary, SPA fallback, asset misses, Go's 307 clean/slash redirects and
bare mutation 308 aliases. The file responder streams at most 64 KiB per
read, selects identity/gzip/Brotli by Go's quality rules, forces identity for
Range, and preserves representation-specific SHA-256 ETags, Last-Modified,
HEAD, conditional requests, single and multipart ranges. Cache policy uses
the original decoded request path before the resolved representation, including
Go's long-lived SPA-shell cache quirk under `/chat/unfurl/image/`.

The public first-boot predicate is Go's global `COUNT(*) FROM users`: only
GET/HEAD `/` uses the aggregate to redirect to `/setup`; no identity row is
returned, and read failure serves the page normally. All other authenticated
reads take the verified user through the shared admission context. No catch-all
request writes application data, audit rows, state or notifications.

`SETJOIN_CONFIG` is resolved before the async runtime starts (#414); root
fallback requests use the same validated startup website directory. Identity checks the shared foundation cannot
prove remain with Go until #331–#333; entitlement denials retain Go's existing
audit behavior. Neither case is silently answered with an invented denial.

The six structural entries are ON, with inventory and global rollback.
`catchall_recorded` replays frozen-Go HTTP responses without a Go upstream and
checks the proxy counter is zero; `catchall_startup` proves executable wiring,
both rollback paths, valid-build serving and invalid-build refusal. Recording,
normalization and catalog regeneration: [catch-all oracle](../../../tests/conformance/catchall/README.md).

Full-spec parity (#406): `authz-defer/full-spec.json` records raw denied problems,
complete business audit fields, and SHA-256 of successful YAML/JSON bytes under
missing, stale signed, signed member, scoped member and active governed grants.
Native replay has no Go upstream and requires zero proxy attempts.

## Sealed Assist configuration (#417)

Assist and translate open value-detected EK01 envelopes through the foundation
`setjoin-config-secret` codec, using `identity.deployment_id` and the resolved
startup keyring environment (including retiring versions). Plaintext remains
readable. Unavailable keys, corrupt ciphertext and non-string plaintext produce
Go's native 503 and never reach the provider or Go. JSON null preserves Go's
empty-string result. Only code-owned config keys are read; no request supplies
key material, deployment identity or an envelope to decrypt. The HTTP/provider
recordings are `static_recorded::{assist_sealed_key,translate_sealed_key}`.

DAV redirects with their feature OFF use the same root mux as an absent Go
registration (404 or the validated website SPA), never a Go fallback. Main
shares its startup catch-all snapshot with `SurfaceRoute::fallback`. The
existing request-time toggle divergence remains unchanged. Native replays
`caldav_disabled` and `carddav_disabled` use the original Go recordings with
no upstream configured.

## Device telemetry (#417)

`gateway::telemetry` preserves OFF's bare 204, the 64 KiB consumed-body limit,
Go JSON field folding/null/duplicate rules and first-value decoding, proof before
admission, ten reports per device per hour and Go's bare problem responses. The
proof signs the inner `/telemetry` URI after `/api` stripping, including query.
The shared verifier consumes each deployment-wide nonce once before attribution.
The legacy secret reseal is best effort and precedes HMAC comparison, as in Go.

`telemetry::insert` accepts only sealed `VerifiedDevice` authority. It performs
one INSERT on `DB_WORKER_DSN` (fallback `DB_DSN`), because telemetry's FORCE-RLS
posture denies ordinary app reads/writes. No request supplies a user/mailbox GUC
or insert identity. Go's credential migration, nonce reducer and report insert
are separate commits; combining them would change failed-insert/replay behavior.
Reports add no audit, state bump or notify in Go. No worker is introduced.

The `static_recorded` device-proof branch compares normalized complete report,
nonce and credential rows. Replay leaves Go unset. Recording restores the entire
`system_config` snapshot, including deployment ID and boot-migrated connector
secrets; restoring the ID alone leaves envelopes bound to the wrong AAD.

## Discovery and live health (#417)

`gateway::discovery` uses the system DNS resolver (Hickory) for SRV then MX,
with Go's priority/weight ordering, a public-IP-only HTTPS dialer, verified TLS,
no redirects, five-second requests and a 64 KiB decoded document cap. Literal
IP targets, including URL-normalized numeric aliases, pass the same SSRF policy.
Successful results alone enter the five-minute, 1024-entry process cache;
expired entries are pruned and the earliest expiry is evicted at capacity.
No application rows, audit events or notifications are written by discovery.
The optional transport mapping is a test seam; main uses the system resolver.

`static2_discovery` records real frozen-Go DNS queries and certificate-verified
HTTPS exchanges. Private targets must make zero TCP connections. The ledger
includes SRV, MX, failure bodies and cache reuse. Recording instructions and
normalizations: [static leftovers](../../../tests/conformance/static2/README.md).
`static2_health` exercises the actual LiveKit/Egress/ASR probe adapters through
public HTTP; each service's failure must produce Go's aggregate 503.

Frozen health is not a reducer transaction: its SELECT, in-memory previous-status
update and webhook dispatcher are separate. Preserve that boundary (ARCH-029).
`health_alerts_recorded::health_alerts_on_ok_to_error_transitions` seeds history,
sends a native `/health` request without Go, and compares the existing Go oracle's
signed webhook payloads and durable delivery rows, including no repeat alert for
persistent errors. Live probes affect the verdict but never generate history
alerts. No background worker or ownership transfer is added by this ticket.
