# ADR: ARCH-027 — The Rust front door proxies to Go; routes leave Go one transfer at a time

**Status:** Accepted; the front door is optional and default-OFF in every deployment until its own rollout decision
**Date:** 2026-10-29
**Authority:** spec setjoin/setjoin#209, ticket #220; owner decision 2026-10-29 ("Rust in front", strangler direction); builds on [ARCH-026](ARCH-026-per-command-rust-authority-transfer.md)

## Context

The owner's end state is no Go server. ARCH-026 fixes how business authority moves from a
PL/pgSQL reducer to a Rust command, but not where a ported command receives its requests.
Two compositions were possible: Go stays the front door and calls Rust for ported routes, or
Rust becomes the front door and forwards everything it has not ported to Go. With Go in front,
every ported route still runs through Go's listener, middleware and process, so Go never
shrinks to zero. With Rust in front, each ported route is one entry in a Rust route table and
Go loses a route each time; once the table covers everything, Go can be removed.

The webmail and native clients reach the Go mailserver over plain HTTP, a WebSocket push
channel (`GET /jmap/ws`) and an SSE stream (`GET /jmap/eventsource`). Go's per-client
controls (rate limits, threat detection, audit IPs, Secure cookies) depend on the client IP
and scheme it resolves through its trusted-proxy rules (`shared/clientip`, the
`trusted_proxy_ips` list in `mailserver/internal/middleware`).

## Decision

1. **Rust is the front door.** `server-rust/bins/gateway` (`setjoin-gateway`) receives
   client traffic and reverse-proxies every request to the Go mailserver unless its route
   table claims the request. It has no business logic of its own; its only local response is
   its liveness probe, `GET /_gateway/healthz`.
2. **Unported routes pass through unchanged.** Method, path, query, `Host`, end-to-end
   headers, body and status pass through as received; bodies stream without buffering in
   both directions; `Connection: upgrade` requests (WebSocket) become a byte tunnel after
   Go's `101`; SSE responses stream event by event. Only hop-by-hop headers (RFC 9110
   §7.6.1) are dropped, as Go's `httputil.ReverseProxy` does.
3. **The front door is the single authority on client identity headers.** It removes every
   client-supplied `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` and
   `X-Real-IP`, then sets exactly one `X-Forwarded-For` (the resolved client IP),
   `X-Forwarded-Proto` and `X-Forwarded-Host` (the inbound `Host`), the shape
   `mailserver/internal/authproxy` already sends to authserver. The client IP and scheme
   are resolved by the same rules as `shared/clientip`: trust is anchored to the socket peer;
   forwarded headers are read only from a peer in `GATEWAY_TRUSTED_PROXIES` (default empty);
   from a trusted peer the rightmost `X-Forwarded-For` entry wins and a malformed one fails
   closed to the peer; the scheme is `https` only when a trusted peer says so. Go must
   trust exactly the front door's address (`TRUSTED_PROXY_IP` and `trusted_proxy_ips`).
4. **A route moves only through an ARCH-026 transfer.** A route enters the table only as a
   qualified per-command transfer behind its own default-OFF flag; flag OFF means the
   request proxies to Go and the reducer writes. A route that inspects a request and cannot
   express all of it as its command forwards the whole request to Go; it never answers part
   of a request. Rust never writes a command's state while Go also writes it.
5. **Authentication is verified at the front door per ported route.** A ported route
   verifies authserver-issued tokens through the published JWKS
   ([ARCH-005](ARCH-005-asymmetric-jwt-jwks.md)) and takes tenancy only from the verified
   token or session, never from request fields. Proxied routes are authenticated by Go
   exactly as today. Authserver stays in place until its own slice.
6. **Deployment is opt-in.** No deployment, compose file or installer starts the front
   door until a rollout decision admits it. Without it, clients reach Go directly as today.

## Deployment shape

- Listener: `GATEWAY_LISTEN` (default `127.0.0.1:8090`), plaintext HTTP/1.1. TLS stays where
  it terminates today: a reverse proxy in front (add its address to
  `GATEWAY_TRUSTED_PROXIES`) or, for a direct-TLS deployment, a TLS terminator placed in
  front of the gateway. Go's own TLS listener is not proxied through the gateway.
- Upstream: `GATEWAY_UPSTREAM`, the Go mailserver's HTTP listener as `http://host:port`
  (for example `HTTP_MODE=proxy` on `:80` or an internal `LISTEN_ADDR`), reachable only from
  the gateway host.
- Health: `GET`/`HEAD /_gateway/healthz` answers `200 ok` from the gateway alone
  (liveness). Readiness is Go's `GET /health` through the gateway.
- Shutdown: SIGTERM/SIGINT stops accepting connections; open push streams are closed and
  clients reconnect, as on a Go restart.
- Rollback: route client traffic back to Go's listener directly.

## Consequences

- Every later Rust route lands as a table entry plus its ARCH-026 flag; Go shrinks one route
  at a time and can be removed when nothing proxies to it.
- The front door adds one local hop to every request while it only proxies.
- Go's client-IP and scheme decisions stay correct only while Go trusts the front door's
  address and no other peer; a deployment that also exposes Go directly must not list
  untrusted networks as proxies.
- Push channels pass through as tunnels and streams; their delivery semantics remain Go's
  until a push route is itself transferred.
- Rate limit (RP07 review fix): once a Rust route is installed, the front door holds Go's
  coarse per-IP core budget (`CORE_RATE_LIMIT`, epoch-minute windows) and counts **every**
  request it receives, proxied or served by Rust, in memory. A request over the budget is
  answered with Go's own `429` bytes only while at least one Rust route flag is ON (the
  bounded, fail-closed toggle read, made only for over-budget requests); with every flag
  OFF, or a failed/slow read, it is forwarded untouched and Go's own limiter decides, so
  flags OFF stays Go's behaviour unchanged. With a flag ON, Go only sees admitted requests,
  so a client gets one budget across both processes, never one per process. Per gateway
  process, like Go's in-memory windows; the gateway does not warm up from
  `rate_limit_counters`.

## Alternatives rejected

- **Go in front, calling Rust for ported routes:** Go never reaches zero, and every ported
  route still depends on Go's process and middleware.
- **A generic proxy (nginx, Caddy) with path routing between Go and Rust:** routing decisions
  for a ported command depend on the request body (`Email/set` with only `$seen`), which a
  path router cannot see; the decline-to-Go rule needs code that understands the command.
- **Trusting client forwarding headers or appending to them:** lets a client choose the IP
  Go rate-limits and audits.
