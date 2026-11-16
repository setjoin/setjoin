# SSE event source oracle (#319)

`bins/gateway/tests/jmap_sse_recorded.rs` observes `GET /jmap/eventsource`
through the real front door. Goldens come from frozen Go with coverage enabled;
native replay has no Go upstream. Frames are compared as bytes, including
JSON key order, whitespace and the terminating blank line. Fixture mailbox IDs
are named; state token values remain observable.

Run with the disposable owner/direct/app DSNs, `REQUIRE_DB=1` and bounded
Cargo settings specified by the task:

```
cargo test --locked -p setjoin-gateway --test jmap_sse_recorded -- --test-threads=1
```

Recording sets `GOFREE_RECORD_GO_BINARY` to a covered frozen-Go executable and
`GOFREE_GO_SOURCE` to its full source commit. The runner starts its own uniquely
named `gofree-jmap5-*` Go container, JWKS responder and proxy-only gateway; Drop
reaps the container. `GOFREE_RESOURCE_LEDGER` records exact resource ownership.
Goldens use exclusive creation: record new names, never replace an existing file.
Normal replay does not need Go, Docker or a JWKS service.

The 53 immutable recordings include success, cross-tenant isolation and invalid
input, plus cookie/Bearer precedence, production origins, parameters, raw JSON,
guests, targeted revocation, periodic authorization, HEAD and write deadlines.
Every native replay checks the bundled ON decision and zero Go proxies.
Complete user, mailbox, message, tag, journal, audit and JMAP receipt rows are
observed before/after and must be unchanged. The transport writes no SQL.
`cookie-same-origin.json` predates Host preservation from absolute request
authority: Go actually saw a different upstream Host and rejected the cookie.
Replay states that mismatched Host explicitly, retaining the immutable 403.
`cookie-matching-authority.json` records frozen Go accepting a matching explicit
Host/Origin pair; native replay checks that acceptance separately. No SSE
production behavior or existing golden was changed for boot integration (#415).
The status mutant changes a real native response and must fail its Go golden;
the existing F18 family effect mutants remain with the command corpus.

`jmap_sse_lifetime/resources.rs` records one SSE plus 998 WS connections, then
a final SSE connection: both transports reject connection 1001, and releasing a
WS slot admits another SSE request. The presence recording checks false → true
→ true → false while SSE/WS coexist and disconnect. A separate native public
registry test checks mailbox/user eviction, untargeted survival, SSE body drop,
shared-budget release and permanent shutdown. The executable probe checks its
actual route assembly with the Go mail upstream unset. Its required auth
upstream points at an unreachable #112 endpoint; the proxy counter remains 0.

Frozen facts retained: SSE discards offline.wipe/capsChanged/MailWorkEvent
control payloads; multiline application JSON is emitted with only one `data:`
prefix. The HTTP server's 120-second write deadline is never cleared for SSE. Its next
write/final chunk after the deadline is truncated; the idle 300-second authorization
case therefore records abrupt endings for token expiry, withdrawn guest app
entitlement and withdrawn Drive admin permission. Guest readiness uses HTTP
presence so a heartbeat cannot end it at 120 seconds first. Native replay waits expiry,
then advances Tokio by 301 seconds; the explicit write-deadline probe advances by 121 seconds.
Trailing ping frames are drained while classifying an exact clean/abrupt EOF;
other errors or partial events fail. Go recordings use real wall-clock windows.

Go EventSource status branches reached:401 missing/invalid/non-access/scoped/
expired/no-iat tokens;403 cookie origin/no primary mailbox;503 shared capacity;
200 closeafter/filter/ping/raw/state/guest/lifetime paths. Streaming-unsupported
is unreachable through net/http's real Flusher-preserving middleware. Required
subscription error returns after successful headers; channels are fixed names
with positive authenticated IDs, so clients cannot construct an invalid channel.
No accepted divergence was added. No rollback or kill-switch tests were added.

#418 preserves the original `cookie-same-origin` 403: this HTTP/1 absolute-form
fixture omits Host, and the frozen Go proxy recording rejected its cookie Origin.
HTTP/2 authority synthesis must not alter this HTTP/1 input. The golden remains
unchanged; `tls_front::direct_tls_is_authoritative_and_http2_authority_is_preserved`
checks the HTTP/2 counterpart.
