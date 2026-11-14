# Rust source workspace — recording transaction/publication successor

Historical qualification log: the paragraphs below describe the workspace at
each ticket's adoption point. Current layout, transfer defaults, front-door
inventory and verification contracts live in [AGENTS.md](AGENTS.md).

## Rate limits and threat

The front door counts booking writes, admin and auth requests across Rust and Go
in separate per-IP, epoch-aligned buckets. `BOOKING_WRITE_RATE_LIMIT` defaults to
5 per 15 minutes, `ADMIN_RATE_LIMIT` to 60 per minute and `AUTH_RATE_LIMIT` to
20 per 15 minutes, matching `mailserverd`. Route matching uses the Go middleware
inventory, honors literal `/api` routes and the API mount, and excludes unpinned
bare paths; unguarded routes override a limited subtree.
Root pin checks use Go's decoded URL path, so an escaped spelling such as
`/s%65tup/status` cannot evade the `/setup/status` bucket. Route selection still
matches escaped segments independently, as Go's ServeMux does. The executable
enforces these route budgets even when the JMAP pilot is not installed; this covers
direct auth traffic that no longer passes through Go mailserver. A spent bucket
uses the recorded Go 429; the gateway kill switch bypasses the limiter.
Additional buckets mirror Go's booking read (60/min), guest meeting read
(120/min) and write (20/15 min per IP plus decoded meeting slug), setup
(60/min), recovery upload (2400/min), telemetry (30/min), and link protection
(60/min). Their `*_RATE_LIMIT` environment overrides use Go's names.
When `SCIM_ENABLED` is set true, SCIM's registered routes use the separate
`SCIM_RATE_LIMIT` bucket (120/min by default). Go also permits SCIM to be
enabled through its config file; that source is not yet mirrored here, so
disabled or unresolved SCIM requests defer to Go even if inventory says ON.
The gateway starts its buckets cold and does not write `rate_limit_counters`.
In the pinned Go build, a disposable-DB probe found that warm-up also starts
cold: scanning the timestamp column into Go's integer variable fails. Go
still periodically writes counters, an effect not yet reproduced by Rust.

Scope follows [#258's clarification](https://github.com/setjoin/setjoin/issues/258#issuecomment-6539052545):
front-door budgets belong here; guest fallback, SCIM file configuration and
other handler-level limits move with their families. Login/post-auth threat
decisions move with Identity; no independent threat interceptor wraps Go's
outer mailserver mux.

The native CSRF and guest gates precede route-specific buckets (#406).
JWT-bearing requests spend the route budget after guest containment; invalid
credentials then get the native RequireAuth response. Neither condition hands
the completed shape back to Go. See [terminal admission](bins/gateway/DOX.md#terminal-shared-admission-406). The executable
also sends ON Rust-auth entries to Go auth until Identity ports its threat
interceptor. The forwarding test `unmirrored_threat_pipeline_defers_rust_auth_to_go`
covers the recorded feed-block, IP-block and allow outcomes. The captured Go
responses and their reproduction method are in
`bins/gateway/tests/golden/THREAT_RECORDING.md`; these are forwarding evidence,
not local Rust threat-policy parity.

## Database verification prerequisites

- `setjoin-pg` DB tests (`crates/pg/tests/db_scope.rs`) need a schema from
  `scripts/load-test-schema.sh`, owner DSN in `TEST_DB_DSN`/`DB_DSN` and the
  `setjoin_app` credential in `DB_APP_DSN`; absent → `SETJOIN-PG-DB-SKIP
  (reason=no-dsn)` per test, `REQUIRE_DB=1` → FAIL. Rust has no runtime skip,
  so a skipped DB test still counts as `ok`: a skip line is never a pass.
  CI's guard step sets all three plus `REQUIRE_DB=1`.
- Conformance cases need `TEST_DB_DSN`/`DB_DSN` (owner: fixtures and
  observation; LISTEN uses `DB_DIRECT_DSN` when set; the command under test
  runs as `setjoin_app` via `DB_APP_DSN` when set) on the same schema;
  absent → `CONFORMANCE-SKIP (reason=no-db …)`
  per case plus a per-root count from the guard, `REQUIRE_DB` → FAIL.

## Historical qualification

Coordinator selected this three-member source workspace: contracts, db and domains/recording. Resolver2/edition2021; workspace production compiler target1.97.1. Exact selected workspace and recording adapter were qualified offline with rustc1.97.1 (8bab26f4f).18 adapter tests passed. Existing retained contracts/db manifests and sources remain byte-identical; their workspace.package inheritance is preserved. This is a new bounded engineering allocation, not the recovered original first-start allocation or completion of the broader foundation package list.

The recording package uses retained typed PublishRecording/ReferenceState contracts and a recording-specific transaction wrapper. It does not call the mail lifecycle's hard-pinned accepted_contract. Trusted store/transaction/verifier/observer implementations remain injected. There is no gateway, startup wiring, real DB driver, capture, network, content deletion or authority-transfer integration in this workspace. See crates/domains/recording/DOX.md for exact methods and production gates.

The independent tools/schema-simulation workspace is explicitly excluded. Its accepted Rust1.99/resolver3 tooling profile and99 frozen files remain separate, unchanged evidence. The root does not raise the production compiler target or import simulation reports as runtime authority.

Ownership: coordinator owns root/workspace plus retained contracts/db source adoption; meeting owner01a1452f-fafb-772c-977b-b0dcdc28002a owns the recording source. No shared concurrent writes. Retained inputs,18 named outcomes, compiler, staged source hashes and cleanup bind to task-4/RP11-S02-RECORDING-ADAPTER-EVIDENCE-03/SOURCE-BINDINGS.json SHA b1751dd0668e47b8704a4d314b978b9fbe989d7487ca040187b697b59a525ec1. Coordinator integration manifest/rollback evidence is task-2/setjoin-coordination/RUST-WORKSPACE-BINDING-01/integration-01.

Real driver/schema/roles/current entitlement, trusted content/observer implementations, membership/ACL/holds/retention/GC, media stop/cancellation, C01-C03/SYS-05 and runtime adoption remain unqualified. Offline trusted-fixture tests establish this source contract only. No whole RP11-S02 or RP04/RP05 completion follows.

Addendum (#213, 2026-10-29): the workspace gained a fourth member, `crates/pg` (`setjoin-pg`), the scoped PostgreSQL executor over tokio-postgres 0.7.18 + deadpool-postgres 0.14.2. It is the only real DB driver in the workspace and is not wired into any gateway, startup path or deployment; the recording statement above about "no real DB driver" covers the recording package only. Contract: `crates/pg/src/lib.rs`.

Ticket #212 (spec #209) adds a fifth member, tests/conformance (setjoin-conformance): the mark-read parity oracle against the current reducer, run against PostgreSQL 17 with the scripts/load-test-schema.sh schema. It links tokio-postgres for test fixtures and observation only (same versions as setjoin-pg); the oracle deliberately does not depend on setjoin-pg, so it stays independent of the Rust command it will judge.

Ticket #214 (spec #209) adds a sixth member, crates/domains/jmap (setjoin-jmap): the Rust `SetMessageSeen` command (`set_message_seen`) on setjoin-pg — one scoped transaction with the reducer's `$seen` effects plus the Go call site's `email_set` actor audit row, committed atomically; a no-op read writes only the audit row (owner decision 2026-10-29, #219). Since #224 (owner direction 2026-10-29) the transaction body is one `jmap_email_set_update` call plus the audit row, replacing the hand-written per-statement SQL whose unnamed statements on the `received_at`-partitioned tables were re-planned every call. It adds no runtime dependency of its own (the driver comes through setjoin-pg); its DB tests dev-depend on setjoin-conformance for the gate and fixtures. The conformance crate links setjoin-jmap/setjoin-pg in `tests/` only. Not wired into any gateway or flag; the reducer stays the writer. Contract: `crates/domains/jmap/src/set_seen.rs`.

Ticket #220 (spec #209) adds a seventh member, bins/gateway (setjoin-gateway): the Rust front door ([ARCH-027](../docs/adr/ARCH-027-rust-front-door-gateway.md)). A binary plus library with no business logic: it reverse-proxies every request to the Go mailserver (bodies streamed, WebSocket upgrades tunnelled, SSE unbuffered), replaces client identity headers by the shared/clientip trusted-proxy rules, and exposes an empty route table (`src/routes.rs`) where ARCH-026 transfers will intercept a request type (#215 first). Dependencies, pinned exactly: hyper 1.12.0, hyper-util 0.1.21, http-body-util 0.1.5, tokio 1.54.1, bytes 1.12.1; no database driver. Not part of any deployment until a rollout decision. Contract: `bins/gateway/src/lib.rs`.

Historical pilot provenance (#215/#216; superseded by JMAP1 #315): the
following paragraphs describe the original flags. Current native command
admission ignores both flags; #405 also supersedes the historical security-toggle
forwarding with [native runtime gates](bins/gateway/runtime-access.DOX.md).
Configured HS256/SM2 verification is now shared authz authority (#331).

Ticket #215 (spec #209) adds the gateway's first route, `bins/gateway/src/mark_read/` (`MarkReadRoute`; renamed `src/jmap/`, `JmapRoute`, in the RP07 review-fix pass): webmail mark-read served by `setjoin_jmap::set_message_seen` behind the default-OFF toggle `feature.rust_mark_read` (shared/toggle registry, projection V274; read only by the gateway, per request, with the unmirrored security toggles). It serves a `POST /jmap` only when the body is exactly one `Email/set` `{"keywords":{"$seen":b}}` update and every Go precondition it mirrors holds; otherwise the unmodified request is forwarded and Go authenticates and answers as today, so a request Go would reject is rejected by Go. Mirrored: the Go CSRF check, ES256 verification against `AUTHSERVER_JWKS_URL` with the Go JWKS cache rules (5 min TTL, 30 s refresh floor, serve-stale, fail closed) and claim rules (iss/aud/exp/nbf, `typ` access, no `scp`), the `CORE_RATE_LIMIT` budget (per process), the guest belt, the session denylist predicate, the primary-mailbox `accountId` rule and `mailbox_lifecycle_access_allowed`, the pre-dispatch `sessionState`, and the Go response bytes and headers. Not mirrored (route defers while ON): `feature.cae_runtime`, `feature.device_trust_enforcement`, `feature.conditional_access`/`feature.device_lockdown`. Configured HS256/SM2 verification now runs natively (#331/#333/#406); the terminal admission/profile corpora are in `bins/gateway/tests/authz_defer_recorded.rs`. `setjoin-pg` gains `ScopedExecutor::read` (one admitted autocommit `SELECT`, for those pre-command reads); `SeenEffect` variants now carry the mailbox email state so the reply can report `oldState`/`newState`. Contract: `bins/gateway/src/mark_read/mod.rs`.

Ticket #216 (spec #209) adds the second command on the same `POST /jmap` route: the webmail inbox list, `Email/query` served by `setjoin_jmap::query_email_list` behind its own default-OFF toggle `feature.rust_inbox_list` (shared/toggle registry, projection V275; read only by the gateway). Owned request shape (`bins/gateway/src/email_list.rs`): one `Email/query` with `accountId`, `filter` = `inMailbox` plus optional `focus` and `hasKeyword` `$seen`/`$unseen`, optional `receivedAt` sort, `position` (0..=i32::MAX) and `limit` (clamped as Go clamps it); anything else (search filters, other sorts, `anchor`, back-referenced `Email/get`, several calls) is forwarded. The two shapes never overlap; each checks its own flag, then the same mirrored precondition chain runs. The read is one static parameterised SELECT in a `READ ONLY` transaction scoped to the verified mailbox (`setjoin-pg` gains `ScopedExecutor::read_scoped`), so it cannot mark anything read, bump state, journal, audit or notify; any read failure forwards to Go. The reply is Go's bytes: the reducer JSONB compacted in PostgreSQL key order. `Email/get` (the rows' keywords) is not ported: in Go it writes an `email_get` audit row and decrypts S/MIME on read. Parity: `tests/conformance` `email_list` (13 cases, reducer and Rust; #223 added the total order `received_at` then `id`, same direction, on both sides) and gateway DB cases comparing the route's bytes with the reducer-through-Go-encoding bytes. Contract: `crates/domains/jmap/src/email_list.rs`.

Ticket #217 (spec #209) adds `tools/bench-mark-read` (`bench-mark-read`), a separate std-only package with its own `Cargo.lock`, excluded from the workspace and run by `scripts/check-server-rust.sh` as a fourth root. It is the Rust-vs-Go mark-read comparison harness: a keep-alive HTTP/1.1 load driver over a frozen request sequence (each message flipped on every visit, workers own disjoint messages), nearest-rank latency percentiles, `/proc` CPU and RSS sampling of the serving processes, an interruption timeline, and a Go/Rust reply normaliser for parity; `fixture.sql` delivers the 64-message frozen fixture through `deliver()`. Evidence tooling only, never runtime authority, never linked into the gateway. Method and results: `retired-docs:verification/2026-10-29-rp07-rust-vs-go-mark-read.md`.

Ticket #252 renames the pilot `mail` crate to the JMAP family, and gates the workspace on resolved family isolation and cargo-deny licence/source policy. `license-exception-reasons.toml` records a reason for each exception. See [AGENTS.md](AGENTS.md#local-contracts) for the write rule and guard commands.

Ticket #256 extracts the pilot's ES256/JWKS and request-precondition chain into the shared `crates/authz` foundation. Its sealed context exposes verified user and signed claims plus the primary mailbox resolved from that user. `AuthContext::roles()` returns current active governed role-group IDs (not JWT role names), read per request for signed admin tokens with the same expiry and `admin_assignment_active` predicate as Go's `shared/permissions.ResolveAuthority`. A revoked, expired or dormant JIT assignment contributes no role; a failed or timed-out read defers to Go. Signed permissions/scope remain claims, and per-target domain/OU/set reach still needs the family's SQL guards. As CONTEXT.md defines, the mailbox is the mailstore isolation unit; domains are not tenants. Both pilot commands use the chain and preserve deferral to Go. The gateway's `go-auth-responses.json` records full frozen `mailserverd` responses through the Rust front door for expired, wrong-audience, guest and denylisted tokens; the database-backed replay checks status, headers (excluding date and hop-by-hop fields), body and unchanged mailbox, audit and notification effects. See [AGENTS.md](AGENTS.md) for its exact contract and verification.

The gateway's `go-unsupported-tokens.json` contains test-only HS256 and SM2 access tokens minted and verified with frozen `shared/cryptokey` and `shared/jwtutil`; its public key and synthetic HMAC secret permit independent verification. It expires in 2100. The original tests proved whole-request forwarding for these algorithm variants and
unmirrored toggles. Current `jmap_db` retains the unconfigured-key forwarding cases;
#405 gate-ON cases now prove native outcomes with zero proxies.

## Benchmark details

- `tools/bench-mark-read/` (`bench-mark-read`, #217) — Rust-vs-Go mark-read
  comparison harness: std-only load driver (frozen request sequence, keep-alive
  HTTP/1.1, per-process CPU/RSS from `/proc`) plus its frozen fixture
  (`fixture.sql`). Own package and `Cargo.lock`, excluded from the workspace;
  evidence tooling, never runtime authority. Results:
  `retired-docs:verification/2026-10-29-rp07-rust-vs-go-mark-read.md`.

## Shared format vectors

The shared Go recorder and Rust loader are documented in [shared-vectors/README.md](tests/conformance/shared-vectors/README.md). The committed vectors are test-only parity inputs; family implementations are added on demand.

## Verification detail

- Shared authz HTTP tests in `bins/gateway/tests/jmap_db.rs` cover verified
  identity versus spoofed fields, same-token role revocation, assignment expiry,
  JIT activation/expiry, and the signed non-admin resolution gate.

- `repeat_read_emits_no_state_change` (was an ignored reducer FINDING) runs
  against both the reducer and Rust: owner decision 2026-10-29, no-op means
  no effect; #219 fixed the reducer.
- RP07 review-fix pass adds: `setjoin-pg` `tests/bounds.rs` (black-hole
  DB, locked table, a dropped read never pooled), gateway `tests/stalled_db.rs`
  (no DB) and proxy cases (504 header bound, one shared core budget with
  Go's 429), REAL Go response goldens (`bins/gateway/tests/golden/go-*.json`,
  captured from mailserverd; unit tests compare bytes, DB cases re-target
  them), DB cases for the reducer per-item error, the operation lookup and a
  blocked security-admission read. The guard counts every `<NAME>-SKIP (reason=` marker
  (`DB-SKIP` line) and fails under `REQUIRE_DB=1` on any skip.
Ticket #253 permits an unset `GATEWAY_UPSTREAM` for Go-free replay. Locally served requests work; unclaimed or declined requests to Go mailserver return 502 without attempting a connection.

The conformance `golden` module (#253) writes new recordings without overwriting, applies declared scalar normalization, and compares all observed fields. Divergences require an explicit reviewed status, a nonempty reviewer and reason, plus an exact route, case, JSON Pointer and before/after value; invalid records fail even when they name another case.

The JMAP pilot uses that module at the gateway HTTP boundary with a fresh per-case fixture in the assigned database. Go recordings capture response, audit, notifications, selected snapshots and complete row effects over the declared mailbox-scoped tables; replay has its Go upstream unset. Go coverage builds select both main and handler packages so Go 1.26.6 emits profiles. [jmap/README.md](tests/conformance/jmap/README.md) documents the recorder, substitutions and reviewer reference.

The server Rust guard (#253) rejects libtest ignored cases as well as failing tests and required-database skip markers; its self-test exercises each condition.

Ticket #257 shares one-statement scoped execution and receipt lookup in `setjoin-pg`; JMAP mark-read uses both. Family statements or reducers supply their own atomic audit and notification effects, and lookups constrain their receipts to current authority. A transaction advisory lock tied to mailbox, actor and operation is acquired with the scope GUC; a lookup waits for it and uses a fresh READ COMMITTED snapshot, so an unresolved transaction cannot appear absent. A lookup failure remains unknown. Callers must generate unique operation IDs and must not blindly replay an unknown command.

- The pre-#213 workspace and the pilot also pass on rustc 1.97.1; the
  DB-linked crates were verified on 1.99 only. The CI toolchain image
  (`.github/ci/linux-toolchain.Dockerfile`) asserts rustc ≥ 1.99 but cannot
  test at build time: `bash scripts/verify-server-rust-image.sh` runs the
  guard (+ `--self-test`) inside it — executed on amd64 (PASS, 2026-10-29);
  **arm64 NOT_RUN**.

## Oracle adequacy

- `python3 scripts/check-gofree-oracle-adequacy.py --execute --coverage` checks
  each ON route's success, cross-tenant and invalid-input recordings, plus
  mutator row effects and repeat, then executes exact replay and route/family
  mutant tests and reports instrumented Rust handler coverage for ON and
  staged OFF routes with recordings. The Rust lane
  runs this when a DB is supplied; without one it reports an explicit skip.
  Rust `llvm-tools` and disposable owner/app DSNs are required for evidence.
  Family effect mutants are required only for effects in that family's ON-route
  goldens (#266 ruling): `no-notify` uses recorded notifications, `no-audit`
  uses recorded audit rows, and `double-bump` uses recorded state snapshots
  (including unchanged state). Zero observations print a not-applicable receipt
  with corpus counts. Cross-tenant cases still require `no-tenant-filter`;
  every declared mutant executes and must emit its rejection receipt.
- Coverage builds each distinct test binary once, then measures entries
  `LANE_COVERAGE_JOBS` (default: CPU count) at a time. A route whose replays
  sit in several test binaries is measured over all of them: each replay runs in
  its own binary and the profiles merge into one report. Every launch goes through
  the `CARGO_TARGET_<triple>_RUNNER` (per-replay DB clone). `handler_sources`
  must name files that hold executable handler code: a re-export stub or a
  data-only file maps to no lines and fails the entry, so point at the file with
  the code. Progress prints every `LANE_COVERAGE_HEARTBEAT` s (default 300);
  one replay is killed after `LANE_COVERAGE_REPLAY_TIMEOUT` s (default 900) and
  fails its entry; every replay must write a profile. Each replay's profile is kept
  per replay and merged once per entry. Entries run side by side only when the
  per-replay clone runner is set (default: CPU count then, else 1; more without
  it is an error). Entries whose test binaries share a nextest serial group
  (fixed ports, docker, /tmp names; read from `server-rust-lane-groups.py`'s TOML output)
  never overlap; an entry spanning binaries holds every group, the rest stay parallel.
- `--preflight-only` (also the first step of `check-server-rust.sh` and of every
  gate run) checks statically, in seconds, that each handler source exists and
  defines a function and that every replay/mutant selector names a real package and
  test target; a route spread over several test binaries is listed and measured as
  a union. `--only replays,coverage --entries 'GET /health,POST /auth/login'`
  re-runs a subset and is never a lane result; the workflow inputs
  `adequacy_only`/`adequacy_entries` (env `LANE_ADEQUACY_ONLY`/`_ENTRIES`) set it
  and skip the workspace tests. Default runs are unchanged.

## Gateway test coverage

On SIGINT/SIGTERM the gateway closes its listener and allows active HTTP
responses to finish for up to 30 seconds. Idle keep-alive connections are
closed during the drain; streaming responses still running at the deadline
are cut off. Upgraded connections are detached and are not preserved across
process exit. `tests/startup.rs` checks an in-flight response through the
executable and verifies connections queued on an activated listener across a
restart.

- `setjoin-gateway` proxy tests need no DB or network: 7 unit tests on the
  forwarded-header rules and black-box tests (`tests/proxy.rs`) through a
  local fake upstream (plain HTTP, identity-header spoofing, trusted peer,
  16 MiB streamed body, SSE, status codes, WebSocket tunnel, upstream down,
  route-table seam). The mark-read route adds 15 unit tests (request shape,
  token rules, JWKS cache, CSRF, limiter, Go-encoded reply) and 6 DB cases
  (`tests/jmap_db.rs`, conformance gate; native service with flags OFF/ON, non-`$seen`
  patches, rejected/revoked tokens, mailbox scope, native runtime gates; serial,
  they restore the toggle rows they flip). The inbox list (#216) adds 7
  unit tests (request shape, limit/position rules, Go-encoded reply) and 3
  DB cases (native lists independent of pilot flags, byte-equality with the reducer through
  Go's encoding across pages/filters/empty/stale positions, deferred encrypted mail).
- `tests/approvals.rs` (F10) runs under libtest's default parallelism: a
  per-file `SERIAL` guard (#362) covers every case that observes global
  state (audit-log id window, approval NOTIFY channels, F10 receipt set
  difference, global policy priorities, fault triggers); the read-only list
  cases stay parallel. New F10 cases that touch those must take the guard.
  `tests/chat_recorded.rs` (F12) takes the same guard in every case: each
  snapshots the audit-log id window and removes shared denial audits.
  `tests/guests.rs` (F11) too: cases install shared `system_config` keys and
  a fixed-priority guest policy, and snapshot global audit/NOTIFY windows.
  `bins/mailctl/tests/backup.rs` serializes its two oracles: both take the
  host-wide backup flock, which outlasts the preflight's 30 s deadline.
- `tests/http_lifecycle.rs` exercises shutdown at the HTTP boundary: the
  listener closes, active requests finish, and shutdown waits for them. The
  gateway signals connections to stop keepalives and bounds draining at 30 s,
  matching Go's shutdown deadline. This is a behavioral test, not a recorded
  Go lifecycle oracle; Go's shutdown is inline in the full server process.
  HTTP shutdown is mandatory in each process and is not a `GO_WORKERS_OFF`
  worker. Socket activation and listener handover belong to packaging (#248).

## Session GUC requirements

- Scoped transactions support Go's configured encryption and protected audit
  keys through the [named foundation allowlist](crates/pg/DOX.md#protected-audit-gucs).
  Values are trusted deployment configuration bound to the verified transaction
  context, never request claims; SET/set_config in command SQL remains refused.

## Manual evidence and image qualification

- Evidence kinds: two-client convergence, browser checks, the Rust-vs-Go
  benchmark and recovery runs are **manual real-stack checks** (scratchpad
  kits), not automated lanes; `scripts/verify-all.sh browser` is NOT_RUN on
  the dev host.
- Historical toolchain-image qualification is in [DOX.md](DOX.md).

## Runtime dependency constraints

- New dependencies land with a committed `Cargo.lock`; every guard run uses
  `--locked`. Do not commit `target/`. The current JMAP pilot has no external
  runtime dependencies and reaches the driver through `setjoin-pg`; the gateway
  pins its external HTTP, ES256/JWKS and JSON dependencies exactly, and reaches
  PostgreSQL only through `setjoin-pg`/`setjoin-jmap`.
  `contracts`/`db` stay driver-free. Future families may add dependencies
  subject to the licence, source and family-isolation checks above.

## Worker oracle

`mailserver/cmd/mailserverd/worker_oracle_test.go` invokes Go's frozen
`loadActiveSessionRevocations` and `threat.SessionDenylist.Refresh` with two
seeded users and fake live sessions. The committed
`bins/gateway/tests/golden/go-session-refresh.json` records revocation
decisions, session closures and unchanged database state. Rust replays it via
`session_refresh_replays_the_frozen_go_worker_oracle`; its listener and
failure tests use the assigned disposable DB. The Go named-launcher test
checks `GO_WORKERS_OFF=session-denylist-refresh`.
The Rust protocol-session registry independently retains revocations until
expiry, including Go's 31-day fallback for old notifications without expiry;
removing a row from a later denylist snapshot does not resurrect a session.

Run the two Go oracle tests in the Go toolchain container from
`mailserver/cmd/mailserverd`: `go test security_runtime.go worker_launch.go
worker_oracle_test.go -run '^TestWorkerOracle'`; `DB_DSN` and `REQUIRE_DB=1`
must name a disposable full-schema DB. To record a new file, set
`GOFREE_RECORD_WORKER` to its previously nonexistent absolute path and run
only `TestWorkerOracleSessionDenylistOneTick`; recording uses exclusive create.
Per #260's orchestrator clarification, this process-local refresh runs in
both Go and Rust until Go is deleted: each refreshes its own cache and live
session registry. Enable Rust with `RUST_WORKERS_ON=session-denylist-refresh`
and leave Go's refresh enabled. `GO_WORKERS_OFF` transfers workers with
shared effects; the launcher test above proves the switch, not a denylist
handover requirement. This worker's acceptance gate is recorded-Go parity.

The certificate-monitor oracle in `mailserver/internal/tlsutil/cert_monitor_oracle_test.go`
records frozen Go's `health_history` rows for no certificate, expiry thresholds,
DNS-name fallback and the earliest chain certificate to
`bins/gateway/tests/golden/go-cert-monitor.json`. `cert_monitor_matches_frozen_go_health_rows`
replays the one-tick effects against a disposable database. Set
`GOFREE_RECORD_CERT_MONITOR` to a nonexistent path for exclusive-create recording;
ordinary Go runs replay the committed golden. The monitor starts immediately and
checks every 24 hours. Its certificate source must reflect the certificates actually
served by TLS (including the selected chain and the first usable configured SNI):
the HTTPS integration in #413 supplies this source and requires the named Go copy off;
see the [gateway HTTPS contract](bins/gateway/DOX.md#https-runtime-413).
Shutdown cancels and drains an in-flight health insert; if cancellation
or connection draining fails, a sent write may have an unknown outcome.

The ticket rotation oracle `mailserver/internal/tlsutil/ticket_worker_oracle_test.go`
starts the frozen Go manager with a seeded `system_config` row and observes one
timer tick. Set `GOFREE_RECORD_TICKET_WORKER` to a nonexistent absolute path to
record `bins/gateway/tests/golden/go-ticket-rotation.json`; the Rust replay is
`ticket_rotation_matches_go_worker_oracle`. The manager loads on startup without
writing, rotates after the configured interval (default 24 hours), persists
new current and old current as previous, and Go's production wiring stores
plaintext JSON despite its `encrypted` label. The #413 HTTPS runtime consumes these
keys and translates Go-compatible encrypted session state, with archived Go TLS 1.2/1.3
resumption proof in `crates/tls/tests/go_interchange.rs`. `TicketKeys::run` supplies `None` for Go's all-zero previous
sentinel, takes an injected entropy source and listener consumer, and cancels
and drains an in-flight DB write on shutdown. Entropy failures stop the worker;
Go 1.26's `crypto/rand.Read` terminates the process on failure; the #413 HTTPS
runtime treats the worker error as fatal and shuts down the listeners.

Per #261's orchestrator clarification, these TLS tasks are process-local. #413
wires the HTTPS swap; other listener owners keep Go's copies ON until their swaps (Platform ACME/control #305, LDAP #342, IMAP #345,
federation #347, SMTP #351);
the listener ticket owns cross-swap resumption proof. The experimental TLS
bridge is retained only as ignored task evidence, never shipped. The named
launcher regression `TestLaunchWorkerHonorsWorkersOff` includes `cert-monitor`
and `tls-ticket-keys` for those later swaps. HTTP shutdown is mandatory in Go
and has no worker switch. Rust's `http_lifecycle.rs` observes listener closure,
completion of active requests and the 30-second drain limit over HTTP sockets.
`ticket_rotation_matches_go_worker_oracle` also checks elapsed intervals and
that the second rotation retains only the immediately previous generation.
Startup rejects malformed JSON field types and stops on entropy failure;
`ticket_worker_fresh_key_and_entropy_failure_follow_go_startup` covers these
through the seeded worker and its listener consumer.

Cron's lifetime advisory lock is also held by the Go scheduler. Disabling a
single Go cron task does not release that lock, so a Rust scheduler built with
`CronScheduler::acquire` cannot run beside live Go cron; #365's per-task mode
below is how tasks leave Go one at a time. The scheduler catalog registers no
callbacks on its own. Frozen Go's current scheduler does not write
`cron_run_log`.

### Cron handover: per-task locks

`CronScheduler::per_task` never takes Go's `cron:scheduler-single-flight`. Each
task is added with `register_transferred(name, action, GO_WORKERS_OFF)`, which
(1) refuses unless Go's copy is off (`cron:<name>` or the whole-scheduler
`cron`, the same guard as the other workers), and (2) holds the session
advisory lock `cron-task:<name>` on its own backend for as long as the task is
registered, so a second Rust scheduler cannot run it either. Go keeps its
scheduler lock for the tasks it still runs and skips names in `GO_WORKERS_OFF`
(#259), so a task never runs in both. Every tick checks each task connection;
losing one aborts running jobs and stops the scheduler. Shutdown joins the
jobs, then releases the locks. The executable maps
`RUST_WORKERS_ON=cron:<task>` to this, needing `DB_DSN` (worker credential via
`DB_WORKER_DSN`; audit keys `DB_ENCRYPTION_KEY`/`AUDIT_HMAC_KEY` when set, as
Go's pool does), and refuses a task without a Rust callback
(`cron_catalog::cron_action`; since #407 every Go task has one). To move a family's cron task: add its callback
(one fixed reducer statement through `WorkerDatabase::run_cron_statement`),
record a Go seed-plus-one-tick oracle (the `cron_tick_test.go.txt` overlay runs
Go's real `Worker.runDueTasks`), then deploy Go with `GO_WORKERS_OFF=cron:<task>`
and Rust with `RUST_WORKERS_ON=cron:<task>`; roll back by removing both.
Tests: `cron_handover` (no double run, guard, lock loss, executable startup);
`chat_cron_recorded` (Chat oracle, #365). Chat's `chat-chain-anchor` and
`chat-purge-expired` are the first tasks moved.

### Cron catalog (#407)

`bins/gateway/src/cron_catalog.rs` holds all 31 frozen Go statements (`AllTasks()`
order) copied verbatim, with the `system_config` COALESCE arguments and the inline
`prune-bulk-role-jobs` DELETE, each run through `run_cron_statement`; Chat's two keep
their `chat_workers` callbacks. Schedules and timeouts are `workers::task_spec`
(`go_task_spec` renders Go's spelling). Credential per task: worker DSN, except
`refresh-antiphish-contact-graph` and `create-monthly-partitions` on `DB_OWNER_DSN`
(falls back to the worker/request DSN; Go itself runs every task on its worker pool).
`RUST_WORKERS_ON=cron:<task>` now accepts every Go task name. Tests: `cron_catalog`
(parses Go's `tasks.go`: names, statements, schedules, timeouts; startup guard for all
31; credential split) and `cron_catalog_recorded` (29 seed-plus-one-tick goldens in
`tests/conformance/cron/goldens/`: rows, `admin_audit_log` rows and NOTIFY events,
including Go with `GO_WORKERS_OFF=cron:<task>` doing nothing). Re-record: delete a
golden, `GOFREE_RECORD_CRON=<task|all> GOFREE_GO_SOURCE=<sha>` (needs docker, the
module cache mount and the overlay `tests/conformance/cron/cron_tick_test.go.txt`).

Scheduler shutdown cancels callbacks immediately, matching Go's parent-context
cancellation, and joins them before releasing the singleton. The regression
`shutdown_cancels_pending_work_before_releasing_the_singleton` observes this
through a registered callback and a second scheduler connection.

## Conformance and JMAP DB tests

- Conformance cases need `TEST_DB_DSN`/`DB_DSN` (owner: fixtures and
  observation; LISTEN uses `DB_DIRECT_DSN` when set; the command under test
  runs as `setjoin_app` via `DB_APP_DSN` when set) on the same schema;
  absent → `CONFORMANCE-SKIP (reason=no-db …)`
  per case plus a per-root count from the guard, `REQUIRE_DB` → FAIL.
- `setjoin-jmap` DB tests (`crates/domains/jmap/tests/set_seen_db.rs`: audit
  row, audit failure rolls back, foreign-mailbox refusal) use the
  conformance gate and fixtures; they run serially within the file (one adds
  a trigger to the partitioned audit table).

## Conformance harness contract

  - `tests/conformance` (`setjoin-conformance`) — DB-backed parity oracles
    (ARCH-026). `mark_read` pins today's `$seen` behaviour of
    `jmap_email_set_update` behind the `SetSeen` trait; `tests/` runs it per
    implementation (`mark_read_reducer.rs`, `mark_read_rust.rs`) plus a
    negative self-test. `email_list` (#216) pins `jmap_email_query` for the
    inbox-list shape behind `ListEmails` (`email_list_reducer.rs`,
    `email_list_rust.rs`; 13 cases with literal expected pages). The library links `tokio-postgres` directly (not
    `setjoin-pg`, so the oracle stays independent of the command it judges);
    `setjoin-jmap`/`setjoin-pg` are dev-dependencies for `tests/` only.
    `golden` creates immutable recordings, normalizes declared scalar fields,
    and reports JSON Pointer differences; accepted divergences bind a reviewed
    route, case, field, explicit reviewed status and exact before/after values.
    `route-catalog.json` binds ON inventory entries and multiplexed commands to
    recorded cases, replay selectors, handler sources and mutant self-tests.
    For recording and replaying the JMAP pilot, including row effects,
    notification capture, Go coverage builds, cross-tenant observation and
    family mutant fixtures, read [jmap/README.md](tests/conformance/jmap/README.md).
    Shared Go format vectors and their loader: [shared-vectors](tests/conformance/shared-vectors/README.md).
    Statements are `query_typed` (unnamed) or simple. Fixtures are committed
    in throwaway domains and removed by each case (append-only
    `mailbox_audit_log` rows first, triggers suspended for that one statement
    via `SET LOCAL session_replication_role`). Test-only; never linked into a
    gateway.

Declared oracle `handler_sources` lists contain nonempty code-path strings;
the static guard rejects malformed entries before Cargo runs. Executable replay
selectors and their recordings belong in `cases`, including supplemental cases
on OFF routes. Coverage validates that every named source has executable mapping.

## Pilot workspace contract

- `pilot/` (`setjoin-pilot`) — Seen-intent pilot with fixtures. Its own package
  and `Cargo.lock` (pinned `sha2 =0.11.1`), excluded from the workspace.

## Schema simulation workspace

- `tools/schema-simulation/` — independent tooling workspace (resolver 3,
  edition 2024, `rust-version` 1.99). Evidence tooling, never runtime authority;
  excluded from the workspace.

## Socket activation

The gateway accepts one systemd `Accept=no` TCP listening descriptor at fd 3
when `LISTEN_PID` matches and `LISTEN_FDS=1`; it validates the descriptor,
marks it close-on-exec, clears the activation environment, and otherwise binds `GATEWAY_LISTEN` as
before. Systemd retains the listener across restarts so queued connections
can be accepted by the next process. Existing accepted connections are not
preserved when the process exits. The gateway listener is HTTP, not TLS.
Executable test: `activated_listener_keeps_connections_queued_across_restart`.

With `LISTEN_FDNAMES` the gateway also adopts up to five descriptors (#345/#347,
`activation.rs`): `imap` and `imaps` are the IMAP listeners served in-process
(see `crates/protocols/imap/DOX.md#activation-345`), `acme` is HTTP-01,
`federation` is the native peer listener (see its protocol DOX); any other single name (systemd's default
is the unit name) is HTTP, unnamed counts above one are refused.

On a root/systemd host, `python3 scripts/test-gateway-systemd.py <gateway>`
additionally checks real `Accept=no` socket activation, a default-ON health
response, and a queued HTTP connection during a service restart. It runs as
`nobody` with empty effective/permitted/bounding/ambient/inheritable capability
sets. Its unique `gofree-t13-*` transient units and `/tmp` executable copy are
removed on exit; no installed Setjoin units are changed. The mandatory portable
Rust lane continues to use the parent-owned socket executable tests.

The installer runs the front door ON by default as the socket-activated
`setjoin-gateway` unit behind the existing TLS terminator, with Go's
`HTTP_MODE=proxy` listener as `GATEWAY_UPSTREAM`; the signed updater stages and
adopts the gateway in the core cohort and `*.prev` rollback covers it (installer
contract: `mailserver/DOX.md`). Go retains public TLS/ACME and protocol listeners
until their whole-listener transfers (#305, #342, #345, #347, #351) and keeps its
bind capability while it owns privileged ports. The Rust release format and
updater are #357–#359.

## Parallel full lane (#550)

`.github/workflows/server-rust-lane.yml` runs the lane on GitHub-hosted runners (no self-hosted
label) for every pull request and every push to `main`: always the FULL lane including oracle
coverage. `workflow_dispatch` takes `shards` (default 8), `coverage_shards` (6), `jobs` (4) and the
debug inputs `filter`/`adequacy_only`/`adequacy_entries`, which run one `debug` job and are never a
lane result. Jobs: `plan` (shard lists, debug or full); `build` (one `cargo nextest archive` of every
workspace test binary plus the expected test list `nextest list`); `roots` (static guards,
cargo-deny, doc tests, pilot, schema-simulation, bench-mark-read: `SERVER_RUST_STAGES=static,roots`);
`shard 1..N` (nextest `--partition hash:k/N` of the archive plus every N-th replay and mutant);
`coverage-build` (instrumented archive of the coverage binaries only) and `coverage-shard 1..M`
(every M-th coverage entry); `aggregate`, the required check. Each job is its own VM with its own
Postgres, so host state cannot collide across shards; inside a shard the serial groups stay.
`aggregate` runs `scripts/merge-lane-shards.py`: red unless every job wrote `lane-complete.txt`
`rc=0`, every non-ignored test of the build's list ran exactly once and passed, no log prints a
`*-SKIP (reason=` marker, the shards together replayed every replay and mutant of the manifest and
the coverage shards measured every coverage entry (`python3 scripts/test-merge-lane-shards.py`).
Evidence is the `lane-results-<sha>` artifact (30 days); there is no serial or compare mode on
hosted runners (`LANE_MODE=serial` and `scripts/compare-lane-runs.py` stay for a dev host).

`scripts/check-server-rust.sh` is unchanged by default; hosted CI selects with
`SERVER_RUST_STAGES` (static, workspace, roots, adequacy), `SERVER_RUST_NEXTEST_ARCHIVE`/`_EXTRACT_TO`/
`_PARTITION`, `LANE_ADEQUACY_SHARD=K/N`, `LANE_ADEQUACY_BINARIES` (replays and coverage launch the
archive's binaries through the clone runner instead of `cargo test`), `LANE_COVERAGE=0` (no
coverage) and `LANE_ADEQUACY_COVERAGE_ONLY=1`. `CARGO_BIN_EXE_*` and `CARGO_MANIFEST_DIR` are
compiled in, so every job uses the same absolute `CARGO_TARGET_DIR` (`$HOME/lane-build/target`) and
checkout path, and the archive is extracted to `$HOME/lane-build`. Replays and mutants run
`LANE_ADEQUACY_JOBS` (default `LANE_JOBS`, else 5) at a time when the per-replay clone runner is set
(1 without it; more is an error); each distinct test target is built once first (`--no-run`, outside
`LANE_REPLAY_TIMEOUT`) unless prebuilt; replays whose binaries share a serial group never overlap.
The summary and `--keep-going` failures are in manifest order, named
`<entry> :: <package>::<target>::<test>`.

Images: `.github/workflows/ci-images.yml` (only workflow with `packages: write`, job-scoped; runs on
same-repo pull requests, pushes to `main` and dispatch for `.github/ci/**` changes, never on fork pull
requests; `images.lock` is excluded from its path filter to avoid a digest loop; the lane's `plan`
job fails fast while `images.lock` has `PLACEHOLDER`) builds the lane images and mirrors tag-referenced third-party images to
`ghcr.io/setjoin`, printing `.github/ci/images.lock`; `.github/actions/lane-setup` pulls exactly
those digests (and refuses `PLACEHOLDER` lines). The GHCR packages must be public. Fork pull
requests get a read-only token and no secrets (the lane needs none); caches are saved only from
`main`. Locally: `bash scripts/pre-ci.sh` checks the workflow `run:` blocks.

- **Database per test, not per binary.** nextest runs each test in its own process; roughly 100
  gateway binaries serialise through an in-process `static SERIAL` mutex over shared database
  state and others seed once per process, so one shared database per binary would break
  them. `scripts/nextest-db-wrapper.sh` (nextest wrapper script, experimental
  `wrapper-scripts`) runs `CREATE DATABASE <prefix><hash> TEMPLATE <tpl> STRATEGY file_copy`,
  re-points every inherited DSN env var (`TEST_DB_DSN`, `DB_DSN`, `DB_DIRECT_DSN`,
  `DB_APP_DSN`, `DB_WORKER_DSN`, ...) from the base database to the clone, runs the test and
  drops the clone `WITH (FORCE)`. The template is loaded once by `scripts/load-test-schema.sh`
  (`ALLOW_CONNECTIONS false`); roles are cluster-wide and provisioned once with it.
  The lane sweeps leaked `<prefix><24 hex>` clones; it never touches other databases.
- **Serial groups.** nextest cannot isolate host state, so `scripts/server-rust-lane-groups.py`
  scans every test target (following `mod` files and the python/shell helpers a test names) for the
  host resources it uses: fixed TCP/UDP ports, fixed `/tmp` file names, fixed docker container names
  (`docker-name:<prefix>`; a name built from the pid, clock or a counter is unique per nextest process, so
  docker users alone no longer share one group, which cut `host-00` from 65 binaries to the 6 that share
  the pebble ports and moved the `127.0.0.1:80` binders into their own group; a name must carry a pid or clock in the very expression passed to `--name`/`-t`, a counter alone
  does not count; anything else, and every fixed name, joins the shared `docker-unverified`; fixed host
  paths (`test-results/gofree-*`, `target/gofree-*`, `CARGO_TARGET_TMPDIR` names, `go build -o` outputs)
  are resources too, which leaves `host-00` at 43 binaries), `/dev/shm` and pebble. Binaries that
  share a resource form a connected component, generated at run time as a test group
  (`--tool-config-file`) with `max-threads = 1` across all its binaries; unrelated binaries run in
  parallel. `--list` shows the groups. Never weaken a test to avoid a group.
- **Seasoned sequences.** The golden oracles normalise ids by substring replacement (`<admin>`), which
  collides when every id starts at 1, as in a fresh clone; the long-lived database the goldens were
  recorded on has large ids. The lane sets each template sequence to `LANE_SEQUENCE_FLOOR`
  (100000) plus a distinct offset, in both modes.
- **Root container.** `scripts/lane-container.sh` runs each lane step as root in the pinned
  `setjoin-server-rust-lane` image on the host network with the Docker socket, as on the dev host:
  oracles bind `:53`/`:80`/`:636`, assert root ownership and start sibling containers. Workspace,
  `$HOME` and `/tmp` are mounted at identical paths; ownership returns to the runner user on exit.
- **Postgres.** `lane-setup` starts the baked `setjoin-lane-pg:17` (pgtap) on a job-owned data
  directory under `$RUNNER_TEMP` with `fsync=off`, `synchronous_commit=off`, `full_page_writes=off`,
  loopback publish and a per-job SCRAM secret (CI only, masked). Tools are pinned by
  `scripts/server-rust-lane-tools.sh` (nextest, cargo-deny, pebble) inside the lane image.

## Frozen Go recording workflow

`.github/workflows/gofree-record.yml` (#339) is `workflow_dispatch` only (`contents: read`,
`packages: read`, never pull_request or push) and is deleted with Go (#142). Inputs: `package`,
`test`, optional `case_filter`, `go_source` (40-hex commit, default this ref) and `extra_env`
(allowlisted `GOFREE_RECORD_*|ORACLE_*|VERIFY_*` lines, e.g. `GOFREE_RECORD_DRAIN=all`). It builds
`go build -cover ./mailserver/cmd/mailserverd` in `setjoin-ci-linux-tc`, exports
`GOFREE_RECORD_GO_BINARY` and `GOFREE_GO_SOURCE`, and `scripts/gofree-record.sh` (in the lane
container) loads one disposable DB, sets `REQUIRE_DB=1`, `TEST_DB_DSN`/`DB_DSN`/`DB_DIRECT_DSN`/
`DB_APP_DSN`, `GOFREE_RESOURCE_PREFIX`, a created `GOFREE_RESOURCE_LEDGER` and runs
`cargo test -p <package> --test <test> -- --test-threads=1 --skip mutant --skip fault`. Goldens are
exclusive-create, so existing ones are only compared; new files, `git status --porcelain` and the
diff upload as artifact `gofree-record` and are never committed. Input `go_upstream=authserverd` also
builds `authserverd`, installs the synthetic `identity-login/keys.json` signing row, starts it on
`127.0.0.1:47335` (host network, fixture DB only, ledgered, stopped always) and exports
`GOFREE_RECORD_UPSTREAM` for auth-listener `*_oracle` targets.

## Rust guard self-test

- `bash scripts/check-server-rust.sh --self-test` — proves the guard fires on a
  throwaway crate. Both run automatically from `scripts/run-guards.sh`.

## Family dependency guards

- Family crates must not depend on another family crate. `python3 scripts/check-rust-family-isolation.py` inspects Cargo's resolved graph, including direct dev/build dependencies, transitive dependencies and local overrides; non-workspace paths are forbidden. Dev-only dependencies of intermediate crates are excluded, as Cargo does not build them for dependants. `cargo deny --locked check` enforces `deny.toml` (licences, sources, bans and RustSec advisories, #388; an advisory `ignore` needs `{ id, reason }`, enforced by the exception guard); MPL-2.0 dependencies must remain unmodified. Record each licence exception's exact crate spec and reason in `license-exception-reasons.toml`; `scripts/check-rust-license-exceptions.py` enforces it. The guards and fixtures run in `scripts/check-server-rust.sh` (Python 3.11+, cargo-deny 0.19.0).

Conformance fixture teardown releases audit/message-partition locks before
atomic mailbox/user/domain deletion, retaining FK cascades and the deferred
primary-mailbox invariant. The pg DB fixture additionally checks UID-ledger
integrity so the standalone CLI's dump/restore does not inherit orphan rows.

## Drive sub-router B (#275)

F14's `/drive/*` registrations retain their external `/api` mount when an
inventory override selects Go, including the deferred native-token route.
`drive_b_dispatch` exercises 28 native registrations with Go unset, both
rollback switches, exact forwarded requests and F14 counters. Native-token
issuance remains forwarded pending identity #331's shared Postgres signer.
The [Drive contract](crates/domains/drive/DOX.md#sub-router-b-275) and
[recorded seams](tests/conformance/drive-b/CASES.md) own the route details.

Drive's missing-object oracle also covers the proxy's committed-head contract:
`proxy::CommitHeaders` yields once before polling an upstream body, so an
immediately ready body error cannot erase Go's already committed HTTP status
and Content-Length. The byte stream still fails and stays unbuffered.
`drive_b_stream_failure` proves this using a real truncated TCP response.

## Guests F11 (#272)

All twenty guest administration/member-submission registrations are native by
default with recorded Go floors, row effects, repeats and HTTP/effect mutants.
The gateway also composes F10 guest approval with the Guests helper; neither
domain crate depends on the other. Acceptance stays with F21 Go (#331–#333).
`guest-lifecycle` is an explicitly named shared-effect worker; disable its Go
counterpart when enabling Rust. See the [Guests contract](crates/domains/guests/DOX.md)
for atomic preparation, postcommit mail/drain ordering, worker cadence, resource
isolation and executable rollback proofs. The measured Go baseline and remaining
branch conditions are in the [coverage receipt](tests/conformance/guests/COVERAGE.md).

## Drive sharing and drive-watch (#276)

F14 `sharing-watch` (20 routes) is native by default; `drive-watch` is a shared-effect
worker (it `pg_notify`s watchers): enable with `RUST_WORKERS_ON=drive-watch` and
`GO_WORKERS_OFF=drive-watch` together. Contract: [Drive](crates/domains/drive/DOX.md).

## JMAP second command (#216)

Moved verbatim from AGENTS.md (budget):
Same route, second command (#216,
`src/jmap/list.rs`): one inbox-list `Email/query` (`inMailbox` + optional
`focus`/`$seen`/`$unseen`, `receivedAt` sort, `position`/`limit`) runs
`query_email_list` through the shared security precondition chain; a failed
read forwards to Go. JMAP1 (#315) retired both pilot transfer flags: native
Email/set and Email/query service is independent of their values.

## Problem bodies (#364, #394)

Every Rust `application/problem+json` body is built by `bins/gateway/src/problem.rs`
(`Problem` builder, `title`, `set_body`), never from `serde_json::json!` (it sorts keys).
It writes Go's `httputil.Problem` bytes: key order `type,title,status,detail,instance,
invalid-params,remediation,remediation_tou_id,code,retryable,holderId`, HTML-escaped
strings, trailing newline. The default title is Go's `http.StatusText` (413 is "Request
Entity Too Large", not hyper's "Payload Too Large"); never use `canonical_reason()`.
Replays check the raw bytes: `tests/common/problem_bytes.rs` runs inside
`common::body_bytes` for every problem response (`tests/problem_bytes.rs` pins the
checker). A new family builds problems through the helper and reads bodies with it.

## Admin identity job workers (#412)

`bulk-role-jobs`, `email-address-policy-jobs`, `identity-operations` and
`identity-transitions` (`bins/gateway/src/admin_job_workers.rs`) are explicitly named
shared-effect workers: `RUST_WORKERS_ON=<name>` starts one, and the gateway refuses to
start unless `GO_WORKERS_OFF` lists that exact name (`tests/admin_job_workers_startup.rs`).
They run on `DB_WORKER_DSN` with the deployment audit keys set per session
(`WorkerDatabase::connect_session`, Go's `AfterConnect`), call Go's reducers and
statements unchanged and keep Go's cadence (3 s, 3 s, 2 s with an immediate first tick,
5 s with an immediate first tick). `identity-transitions` takes `LIVEKIT_API_KEY`,
`LIVEKIT_API_SECRET` and `LIVEKIT_URL` (all three, else it has no SFU, as Go's nil
`meetRooms`) and reuses `guest_worker::remove_participant`.
Oracle: `tests/admin_job_workers_recorded.rs` runs one iteration of frozen Go's real worker
(overlays in `tests/conformance/admin-workers/`, `go test -overlay` in the CI image) over a
seeded database, then the Rust worker over the same seed; rows, audit rows, NOTIFY payloads,
LiveKit calls and the diagnostic artifact (zip structure, inflated entries) must be equal
before a golden is written. Differences kept: the zip's deflate stream is `flate2`'s, not
`compress/flate`'s (same entries, different compressed bytes and `bytes` count, which the
oracle masks); the database-wide `boundedMetrics` counts are masked in the stored goldens
only. Horizon waiting of the eviction loop is asserted directly
(`livekit_eviction_waits_for_the_horizon`). Record: `GOFREE_RECORD_JOBS=all` with
`GOFREE_GO_SOURCE=<sha>` (existing goldens are skipped; delete one to re-record).

WebAuthn's verification-only RSA advisory scope (#335): [reviewed call surface](crates/domains/identity/WEBAUTHN.md#verification-only-rsa-dependency).
