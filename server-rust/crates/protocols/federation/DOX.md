# Federation peer protocol (#346)

`setjoin-federation` is the Rust port of Go's `mailserver/internal/federation`
s2s transport: the wire codec, the mutual-certificate handshake (dial and
accept), the bounded accept loop, the per-peer Receiver/Sender pair, federated
typing, SRV discovery and the reconcile-driven `Service`. The gateway now owns the whole listener through the inherited
`federation` socket (#347), with Go's complete `federation-service` disabled
through `GO_WORKERS_OFF`. No authority lives here: sequencing, dedup, allow-list and apply are reducer calls
on the worker credential (`DB_WORKER_DSN`, else `DB_DSN`), so federation tables
(FORCE RLS deny-all to the request role) are reachable only through it.

## Parity contract (ARCH-029)

Frozen Go is the target. Frames are byte-identical: `gojson` reproduces the
parts of `encoding/json` the wire depends on (validation, case-insensitive
last-wins member matching, including Unicode folding to ASCII names, invalid UTF-8 and lone surrogates becoming U+FFFD,
HTML-escaping string encoder, whitespace-compacting raw-message encoder). A
peer's stanzaId is echoed in acks through that encoder. Mirrored Go behaviour
that looks odd: unrecognised content types are stored only as a redacted
`{"redacted":true,...}` envelope; a literal NUL/`\u0000` payload takes the redacted stand-in path; Go’s malformed
surrogate regex misses lowercase lone surrogates, which abort the jsonb cast
and close the stream. A NUL stanzaId/contentType also closes the stream because
the fallback still passes the NUL text to PostgreSQL; the ingress check is advisory-logged and never
enforced; poison and duplicates are still acked; a gap (BZ202) answers
`replay_req` naming `last_applied_seq+1`; a forged future ack or replay request
halts the stream; honoured rewinds are token-bucketed (burst 5, 1/s) and clamped
to the durable ack; the in-flight window is 256; the accept scope is the `dm`
floor; `Dial` has no deadline on the hello exchange (Go bug, mirrored but
cancellable).

## Layout

- `src/gojson.rs`, `src/wire.rs` — codec, `Frame`, `Hello`, `MsgEnvelope`.
- `src/trust.rs` — `Anchor` (PEM CA), `verify_against_anchor` (webpki chain to
  the pinned CA, Go's ExtKeyUsageAny, exact DNS SAN match, validity of leaf and
  CA), the dial verifier, the accept-side any-client-cert verifier, `Identity`.
  TLS 1.3 only, resumption and tickets off. Audited crates only (rustls/ring,
  webpki, x509-parser).
- `src/stream.rs` — `accept_stream`, `dial`, `listen`, `Bounds` (Go's defaults:
  10 s handshake/hello/lookup deadlines, 64 handshakes, 256 streams, 100 ms
  backoff), `PeerStream` (single reader, serialized writer, close wakes the
  reader, the connection slot is released on close).
- `src/receiver.rs`, `src/spam.rs` — inbound `msg` handling and the ported
  `shared/spam` text detectors (mixed charset, fake HTML).
- `src/sender.rs` — drain/read loops, ack/replay guards, ephemeral handling.
- `src/service.rs` — accept loop dormant while the feature is OFF, reconcile
  (dial loops, outbox NOTIFY wakes, eviction of disabled peers), registries,
  supersede-and-close, `send_typing` and the hub relay. `run_with_listener`
  accepts an already bound or inherited listener.
- `src/discover.rs` — `_setjoin-im._tcp.<domain>` SRV via an injectable `Resolver`.
- `src/db.rs` — `FedDb` seam, `WorkerPool`, `RawJsonb` (jsonb sent verbatim like
  pgx `[]byte`), `JsonbText`.

Differences in plumbing: one LISTEN connection per channel (Go multiplexes one).
`Flags` supplies the product snapshot; production wiring is `runtime.rs`.
The residue reaper is independent of the transport (below).

## Oracle

`oracle/cases.py` authors only requests (`v2-requests.json`: 108 scripted-peer
sessions covering handshake outcomes, inbound chat/room/unknown/ephemeral
frames, outbox drain/ack/replay/window/reconnect, eviction and supersede).
The build-tagged recorder `mailserver/internal/federation/listener_oracle_record_test.go`
runs the production Go `Service` against the disposable database and records
every server frame plus the federation/chat effects (`observe.json`) into
`v2-go-sessions.json`; recorded goldens are immutable. Identities are the fixture
CAs under `oracle/certs` (regenerate with `go run oracle/gencerts.go oracle/certs`
in the CI image only together with a full re-record; the keys protect nothing).
Rust replays the same scripts over TLS against `Service::run_with_listener` and
compares frames byte for byte and effects as JSON.

Record: reset the disposable schema, then in the CI image with `REQUIRE_DB=1`,
`DB_DSN` (owner), `DB_DIRECT_DSN`, `FED_ORACLE_DIR=<abs oracle dir>`, `FED_ORACLE_VARIANT=v2-`:
`go test -tags gofree_record ./internal/federation -run '^TestRecordFederationListener$' -count=1`.
Replay: `cargo test --locked -p setjoin-federation -- --test-threads=1` with the
assigned DSNs. Never run the Go recorder and Rust tests at once (shared DB).


The original 107-case `requests.json` / `go-sessions.json` and `recording.json`
are retained unchanged. That first recording caught Go’s sent-cursor race:
a wire write completes before `sentCursor` updates (`sender.go:244`), so a
prompt valid receipt can be rejected as forged. Twelve identical Go runs
reproduced both outcomes (11 accepted, 1 rejected). V2 preserves every case,
adds Unicode field folding, and models 100 ms of peer apply/ack latency after
outbound batch reads. It records fresh responses to these new inputs; no
response normalization or golden editing hides the race. `v2-recording.json`
binds requests, recordings, fixture identities and the frozen source.

Interop: `cargo test --locked -p setjoin-federation --test interop -- --test-threads=1`
builds and runs frozen Go `fedharness` only in `setjoin-ci-linux-tc:local-amd64`.
Docker, that image and a Go module cache (`GOFREE_GO_MOD_CACHE`, default `$HOME/go/pkg/mod`) are prerequisites. Each role
(Rust dialer / Rust acceptor) exchanges 300 messages in both directions,
exceeding the 256-frame window, and verifies durable cursors and a gap-free
inbox through the Go control API. #418 also sends native typing to the real Go
peer in both roles, compares its committed notification with the unchanged Go
Chat typing golden, and requires no additional inbox/outbox rows. Opposite peer-domain keys isolate both sides
in the one assigned disposable DB; no second database is created. Containers
use `GOFREE_RESOURCE_PREFIX` (default `gofree-fed2`), owned temporary binaries/logs
are removed, and the Go build
cache stays under `CARGO_TARGET_DIR/go-build` when configured.

`Flags` is an injected product-feature cache, not a Rust-to-Go routing switch.
The production runtime and admitted Chat producer are wired by #347 (below).

Startup parity: the service completes its first allow-list LISTEN attempt before
accepting peers, matching Go's preconnected dispatcher. The delayed-real-DB
regression `immediate_revocation_survives_slow_initial_notification_connection`
reuses the immutable disable/eviction transcript with 500 ms of connection delay;
it rejects the former fire-and-forget startup and passes with the readiness wait.
An initial connection failure still leaves the reconnect loop and periodic
reconcile available. Startup wait and connection attempts honor cancellation.

## Residue reaper (#347)

`reap::Reaper` invokes the existing `federation_reap('7 days')` reducer on
`WorkerPool`, once immediately then hourly. Failures log and leave the next
hourly attempt enabled; cancellation stops a running pass. It does not depend
on the local domain, certificates or `feature.federation`.
`tests/reaper.rs::residue_reap_seed_plus_one_tick` compares committed effects
with immutable `oracle/reap-go.json`. The Go adapter `oracle/reap_test.go.txt`
is injected with a Go overlay; it calls frozen Go's one-tick worker seam.
`reap-recording.json` binds the source revision, seed, observation and recording
adapter by SHA-256. Record only against the assigned disposable database, in
the CI image with the module cache mounted. Output creation is exclusive.

## Native activation and delivery (#347)

`runtime::Runtime::prepare` consumes the systemd descriptor named `federation`.
With all of `FEDERATION_LOCAL_DOMAIN` (trimmed/lowercase), `FEDERATION_CERT`
and `FEDERATION_KEY` configured it is ON without a Rust routing flag. Missing
static configuration or invalid leaf material stays inert, matching Go. Without
an inherited socket it logs an error and leaves federation inert while HTTP keeps
serving. With the socket, complete configuration requires
`GO_WORKERS_OFF=federation-service`, `DB_DSN` and `DB_DIRECT_DSN`;
`DB_WORKER_DSN` selects the separate federation worker pool.
The Go switch disables both accepting and dialing; no TCP proxy exists.

The process-local feature snapshot subscribes to `config_changed` before its
initial/reconnect read. Notifications are reload hints only, including malformed
payloads; database failure closes admission. Live eviction follows Go's existing
20-second reconcile cadence. The service starts dormant with the feature OFF
while the initial LISTEN/read runs independently; an unavailable direct DB
connection cannot block startup. Failed connects warn with the error and retry
delay. Only a post-LISTEN authoritative read opens admission. The first snapshot
wakes outbound reconciliation immediately, preserving prompt initial dialing;
subsequent feature reloads retain Go's 20-second cadence. Losing only the
notification connection preserves the last valid snapshot, as Go does;
reconnect uses 1–30 second exponential backoff. Production
calls the same `Service` as the immutable session replay and fedharness interop.
TLS 1.3 session resumption remains disabled as in frozen Go, so no ticket-key
handover or certificate monitor is introduced.

The gateway's `federation_typing` producer stamps a per-channel one-second
debounce before `chat_typing_signal`, sends only after a committed local signal,
and performs a detached five-second user-scoped channel read with an explicit
visibility/membership predicate. It passes DM, spoke-room and hub-room shapes
to `Service::send_typing`; ephemeral frames never enter the durable outbox.
`typing-go.json` records the frozen wire-frame encoder; its receipt binds source
and recording adapter. Gateway `federation_activation` checks real inherited
FDs in the executable, a recorded message/ack exchange, graceful shutdown,
startup guards, foreign-user refusal and admitted/debounced HTTP typing over TLS.
It also proves HTTP remains healthy with an absent federation FD or an initial
notification outage, and verifies dormant TLS admission plus logged retries.

`runtime::reaper_from_env` starts the independent reaper only with both
`RUST_WORKERS_ON=federation-residue-reap` and
`GO_WORKERS_OFF=federation-residue-reap`, and requires a database credential.
Run all protocol targets with supplied DSNs and `REQUIRE_DB=1`:
`cargo test --locked -p setjoin-federation -- --test-threads=1`.
Gateway activation: `cargo test --locked -p setjoin-gateway --test
federation_activation -- --test-threads=1`; Chat regression: `--test
chat_channels_recorded typing -- --test-threads=1`.

On the root/systemd test host, `python3 scripts/test-federation-systemd.py
<gateway>` exercises native TLS/recorded delivery through a real named systemd
socket as `nobody` with empty capability sets, restarts with durable dedup,
and cleans its transient `gofree-fed2-*` units. It also runs the real installer
renderer with an occupied federation port and proves the optional socket fails
without taking down HTTP, with the missing-leg error in the journal. It requires
psql and explicitly refuses any database except the assigned `gofree_e2e_fed2` fixture.

Gateway startup fixtures (#418) pass the required direct DSN even without peering.
The delayed-first-snapshot case uses an owned worker-only search-path view and
advisory barrier, rather than locking public feature toggles needed by shared
HTTP startup. It verifies the real blocked read before releasing it, then requires
immediate outbound reconcile. Child exit assertions retain stderr diagnostics;
process names honor `GOFREE_RESOURCE_PREFIX`.
