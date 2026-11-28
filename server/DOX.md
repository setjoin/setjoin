# Rust source workspace — canonical server reference & qualification log

> **Post-Go status (`#142`, [ARCH-031](../docs/adr/ARCH-031-go-is-deleted.md)):** All server-side Go code, Go oracle recorders, `.github/workflows/gofree-record.yml`, and Go-rehearsal guards (`check-gofree-rehearsal.py`, `check-gofree-route-inventory.py`, `gomod-cache`) were deleted in `#142`. The primary server binary target in `bins/gateway/Cargo.toml` was renamed from `setjoin-gateway` to `setjoin-server` while keeping the Cargo package name `setjoin-gateway` and systemd unit name `setjoin-gateway.service` unchanged until Wave 1 `#544`. All recorded JSON goldens, transcripts, vectors, and `divergences.json` remain under `tests/conformance/` as permanent Rust regression tests.

Historical qualification log: the paragraphs below describe the workspace at
each ticket's adoption point. Current layout, binary names, and verification
contracts live in [AGENTS.md](AGENTS.md).

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

Ticket #217 (spec #209) adds `tools/bench-mark-read` (`bench-mark-read`), a separate std-only package with its own `Cargo.lock`, excluded from the workspace and run by `scripts/guards/check-server-rust.sh` as a fourth root. It is the Rust-vs-Go mark-read comparison harness: a keep-alive HTTP/1.1 load driver over a frozen request sequence (each message flipped on every visit, workers own disjoint messages), nearest-rank latency percentiles, `/proc` CPU and RSS sampling of the serving processes, an interruption timeline, and a Go/Rust reply normaliser for parity; `fixture.sql` delivers the 64-message frozen fixture through `deliver()`. Evidence tooling only, never runtime authority, never linked into the gateway. Method and results: `retired-docs:verification/2026-10-29-rp07-rust-vs-go-mark-read.md`.

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
  test at build time: `bash scripts/ci/verify-server-rust-image.sh` runs the
  guard (+ `--self-test`) inside it — executed on amd64 (PASS, 2026-10-29);
  **arm64 NOT_RUN**.

## Oracle adequacy

- `python3 scripts/guards/check-gofree-oracle-adequacy.py --execute --coverage` checks
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

The Go TLS session-ticket DB rotation worker (`tls-ticket-keys`) and Go session-ticket
wire-interchange bridge (`crates/tls/src/{state,tickets}.rs`, `crates/tls/tests/go_interchange.rs`,
`bins/gateway/src/ticket_keys.rs`) were retired in Release N+1 (`#560`). TLS session
resumption is now handled natively in-process by `rustls`'s standard `Ticketer` inside
`setjoin-tls`; a legacy `RUST_WORKERS_ON=tls-ticket-keys` entry is tolerated with a
deprecation log until stripped by `upgrade.sh refresh-gateway-env`.

Per #261's orchestrator clarification, `cert-monitor` is process-local. #413 wires the
HTTPS swap; HTTP shutdown has no worker switch, and Rust's `http_lifecycle.rs` observes
listener closure, completion of active requests, and the 30-second drain limit over HTTP
sockets.

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
`prune-bulk-role-jobs` DELETE, each run through `run_cron_statement` (Chat's two keep
their `chat_workers` callbacks), plus the Rust-only retention task
`prune-rust-operation-receipts` (#473, `@every 1h`, 30 s timeout, `Credential::Worker`,
running `prune_rust_operation_receipts(5000)` in bounded per-batch transactions up to
20 batches / 20 s soft budget with `SET LOCAL statement_timeout` bounded to
`1..=10_000` ms). When `RUST_WORKERS_ON` enables any `cron:*` task and does not
explicitly list `prune-rust-operation-receipts`, the gateway auto-registers it with
non-fatal lock-contention skip (still failing on DB/config errors); explicitly listing
it remains fail-fast. Schedules and timeouts are `workers::task_spec`
(`go_task_spec` renders Go's spelling). Credential per task: worker DSN, except
`refresh-antiphish-contact-graph` and `create-monthly-partitions` on `DB_OWNER_DSN`
(falls back to the worker/request DSN; Go itself runs every task on its worker pool).
`RUST_WORKERS_ON=cron:<task>` accepts every Go task name and `prune-rust-operation-receipts`. Tests: `cron_catalog`
(parses Go's `tasks.go`: 31 Go tasks + 1 Rust-only task; names, statements, schedules,
timeouts; startup guard; credential split; multi-batch receipt drain and
auto-registration lock-contention skip) and `cron_catalog_recorded` (29 seed-plus-one-tick goldens in
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
- `setjoin-jmap` DB tests (`bins/gateway/tests/set_seen_db.rs`: audit
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

With `LISTEN_FDNAMES` the server adopts up to nine active descriptors (#345/#347/#413/#501/#544,
`activation.rs`): `http` (or systemd's default unit name), `https`, `imap`, `imaps`, `smtp`,
`smtps`, `submission`, `federation` (see its protocol DOX), and `auth` (in `setjoind`).
The retired `acme` descriptor is refused fail-closed (`#560`), and unnamed counts above one
are refused.

On a root/systemd host, `python3 scripts/deploy/test-gateway-systemd.py <gateway>`
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
contract: `deploy/DOX.md`). Go retains public TLS/ACME and protocol listeners
until their whole-listener transfers (#305, #342, #345, #347, #351) and keeps its
bind capability while it owns privileged ports. The Rust release format and
updater are #357–#359.

## Parallel full lane (#550)

`.github/workflows/server-rust-lane.yml` runs the lane on GitHub-hosted runners (no self-hosted
label) on the merge queue's `merge_group` commit (one run per queue entry) and `workflow_dispatch`: always the
FULL lane including oracle coverage, except a queue entry that left the queue while waiting (`mode=gone`, see below).
Merge-queue batching (`queue` job, `scripts/ci/lane-job-gate.py queue-role`; default OFF, enabled by repo variable
`LANE_QUEUE_BATCHING=1` on a ruleset with `grouping_strategy` HEADGREEN): the batch head runs the full lane on its commit,
which contains every earlier entry; an entry with a later queued entry (a queue branch whose commit descends from its
own, found by `git for-each-ref --contains` over a `--depth 6 --filter=tree:0` fetch) waits and runs no lane, polling `ls-remote`
every 60 s after a 120 s settle. A waiter's run stays in progress and its `aggregate` pending. When its branch is gone
it ends `mode=gone`: no job runs, `aggregate` is red with "nothing ran; not a test pass" (cosmetic, the commit is no
longer queued). Exceptions that run the full lane: a late arrival (queued after the head had already decided) runs its own
lane, and a waiter that reaches the CAP (5400 s) runs it too; errors keep the waiter waiting until then. The clock is read
after every git call, and the deadline is checked before EACH git subprocess of the ancestry check, so no subprocess
starts at or after CAP and a waiter returns by CAP + 255 s of worst-case I/O (ls-remote 60 s, init 15 s, cat-file 15 s,
fetch 60 s, for-each-ref 30 s, and up to five run lookups of 15 s each, `QUEUE_POLL_WORST_IO_S`). The fetch depth is `--depth 6`, which is QUEUE_FETCH_DEPTH: the ruleset's
`max_entries_to_build` 5 plus one, so a later entry is at most 5 commits above ours. Shallow history can only HIDE a
descendant, and a hidden one means `head`, which runs our own full lane: a miss is safe. A reported descendant is always
real, because a ref is listed only when our commit is an ancestor of its tip in the fetched graph. A failed command, a
missing own commit (`cat-file -e`) or a passed deadline returns unknown (None), never an empty set. Worst case per entry is SETTLE + CAP + the lane; the queue job
times out at 110 min (6600 s), above CAP + 255 s + 300 s of checkout and setup (5955 s), and `scripts/ci/test-lane-job-gate.py` asserts that. The 255 s is ENFORCED, not assumed: every git call and every API lookup is a child process run by `subprocess.run` with a timeout (`QUEUE_*_TIMEOUT_S`), and the child is killed at that timeout. A per-socket timeout would not do: `urlopen(timeout=)` bounds each blocking socket operation, not the whole response, so a trickling body could outlive the job. A `check_response_timeout`
overrun (360 min) ejects a PR, which fails closed and never merges it. Tests: `python3 scripts/ci/test-lane-job-gate.py`
(git, clock, sleep and the Actions API injected; no network).

Commits on main before a batch's last commit are not tested individually;
the tip is, and the nightly full lane is the backstop. Known: a `gone` run and a rebuilt entry leave red marks on discarded commits.

Why the failed-later check exists (GitHub HEADGREEN behaviour, live pilot 2026-11-17): the queue held #441, #446 and #447.
#447's lane run concluded `failure` at 10:09, but under HEADGREEN GitHub did NOT remove #447 or delete its
`gh-readonly-queue` branch while the earlier entries' checks were pending. #441 and #446 kept seeing #447 as a later
descendant and waited until the CAP (90 min); dequeuing #447 by hand freed them at once. So a later ref whose
server-rust lane run for its merge_group commit is COMPLETED with a conclusion other than `success` no longer counts as
later. `failed_later_from_api` runs one `curl` child per later head sha (`--fail --max-time 12`, under `subprocess.run` with a 15 s hard timeout; headers, token included, on stdin via `-H @-`, never in argv), `GET /repos/{REPO}/actions/workflows/server-rust-lane.yml/runs?event=merge_group&head_sha={sha}&per_page=5`,
and the newest run (max id) decides; the function returns the failed shas with their conclusions. A run that is queued, in
progress or missing keeps the ref later, and `success` does too (GitHub then merges us with it). It is asked on every poll
that has later refs (run states change while the sha set stays the same); the descendant sha-set cache is unchanged. Any
non-zero exit, timeout, JSON or shape error, or a CAP reached before a request, returns unknown, which keeps every later
ref, so the entry waits until CAP and runs its own full lane: fail-safe. Each poll logs one line (`excluded_failed=[ref sha=... conclusion=...]`);
the token is never logged.
Permission: only the `queue` job gets `permissions: { contents: read, actions: read }` at job level (the workflow-level
permissions are unchanged; no other job gains one). `GH_TOKEN: ${{ github.token }}` is passed to the queue step, and it is
used only when `LANE_QUEUE_BATCHING=1` on a `merge_group` event; otherwise the head-at-once path makes no network call.
`scripts/guards/check-test-gate-wiring.sh` pins `actions: read` and the token env in the queue job.
Rollout and rollback (coordinator, not this PR): the ruleset (`rulesets/27288657`, merge_queue `grouping_strategy` and
`max_entries_to_build` 5) and `vars.LANE_QUEUE_BATCHING` change together, back up the ruleset first. Rollback: delete the
variable (`gh variable delete LANE_QUEUE_BATCHING -R setjoin/setjoin`), restore the saved ruleset (`gh api -X PUT
repos/setjoin/setjoin/rulesets/27288657 --input restore.json`), confirm `ALLGREEN`, build 1, merge 5, min 1, wait 10,
timeout 360 on that ruleset, then cancel the in-progress merge_group runs whose `queue` job is still waiting
(`gh run list -w server-rust-lane.yml -e merge_group -s in_progress`, then `gh run cancel <id>`) before requeueing.
A push to `main` runs CACHE REFRESH ONLY
(`plan` output `mode=cache`: `build` saves the instrumented cargo cache; no test,
coverage, replay or guard job; step summary "cache refresh only, no tests"; not a test pass, the queue already tested it).
A nightly `schedule` (`30 2 * * *`, main) runs the full lane plus coverage as the backstop (`mode=full`) and skips
cleanly (`mode=skip`) when main has no commit in the last 26 hours. The rules live in `scripts/ci/lane-job-gate.py` (tests: `python3 scripts/ci/test-lane-job-gate.py`, run by `aggregate` and `pre-ci.sh`). `aggregate` accepts `cache` only on push and
`full`/`skip` only on schedule, and is red on `merge_group`/`workflow_dispatch` unless `mode=full`. Pull
requests run only `pr-precheck.yml` (gate job `aggregate` over `light`: `scripts/ci/quick-check.sh`, changed-package
clippy/`--lib` tests and cheap guards, and `integration`: the `tests/*.rs` targets `scripts/ci/precheck-integration.py`
selects, run by `server-rust-parallel-lane.sh` with `SERVER_RUST_STAGES=workspace` and `SERVER_RUST_NEXTEST_SELECT`,
30-minute cap, see `.github/CI-RUNNERS.md`); the ruleset requires `aggregate` on both, so the full lane gates every merge. The concurrency group falls back to `github.ref` (unique per queue entry). `workflow_dispatch` takes `shards` (default 8), `jobs` (4) and the
debug inputs `filter`/`adequacy_only`/`adequacy_entries`, which run one `debug` job and are never a
lane result. Jobs: `queue` (merge-queue batching decision, head or gone; prints head on every run unless batching is on); `plan` (mode, shard list; debug or full); `build` (one instrumented `cargo nextest archive` of every
workspace test binary plus the expected test list `nextest list`, saved under `shared-key: lane-coverage`); `roots` (static guards,
cargo-deny, doc tests, pilot, schema-simulation, bench-mark-read: `SERVER_RUST_STAGES=static,roots`);
`shard 1..N` (route-aligned `scripts/ci/lane-shard-plan.py` filter file of the archive, capturing lock-free per-case sparse `.profdata`
in `scripts/nextest-db-wrapper.sh` under `cases/<eid>/` and verifying JUnit replays/mutants plus batched `llvm-profdata merge` + `llvm-cov export` coverage in one pass);
`aggregate`, the required check. Each job is its own VM with its own
Postgres, so host state cannot collide across shards; inside a shard the serial groups stay.
`aggregate` runs `scripts/ci/merge-lane-shards.py`: red unless every job wrote `lane-complete.txt`
`rc=0`, every non-ignored test of the build's list ran exactly once and passed, no log prints a
`*-SKIP (reason=` marker, and the shards together verified every replay, mutant, and coverage entry
of the manifest (`python3 scripts/ci/test-merge-lane-shards.py`).
Evidence is the `lane-results-<sha>` artifact (30 days); there is no serial or compare mode on
hosted runners (`LANE_MODE=serial` and `scripts/ci/compare-lane-runs.py` stay for a dev host).

`scripts/guards/check-server-rust.sh` is unchanged by default; hosted CI selects with
`SERVER_RUST_STAGES` (static, workspace, roots, adequacy), `SERVER_RUST_NEXTEST_ARCHIVE`/`_EXTRACT_TO`/
`_PARTITION`/`_FILTER_FILE`, `LANE_ADEQUACY_SHARD=K/N`, `LANE_ADEQUACY_BINARIES`, `LANE_COVERAGE_MAP`/
`_PROF_DIR`/`_SHARD_ENTRIES` (single-pass profile capture + `llvm-cov export` verification), `LANE_COVERAGE=0` (no
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
job fails fast while `images.lock` has `PLACEHOLDER`) builds the lane images, the protocol interop client images
(`scripts/build-interop-images.sh`: `setjoin-interop-imap`, `-smtp`, `-ldap`; tests never build images) and mirrors tag-referenced third-party images to
`ghcr.io/setjoin`, printing `.github/ci/images.lock`; `.github/actions/lane-setup` pulls exactly
those digests (and refuses `PLACEHOLDER` lines). The GHCR packages must be public. Fork pull
requests get a read-only token and no secrets (the lane needs none); caches are saved only from
`main`. Locally: `bash scripts/ci/pre-ci.sh` checks the workflow `run:` blocks.

- **Database per test, not per binary.** nextest runs each test in its own process; roughly 100
  gateway binaries serialise through an in-process `static SERIAL` mutex over shared database
  state and others seed once per process, so one shared database per binary would break
  them. `scripts/nextest-db-wrapper.sh` (nextest wrapper script, experimental
  `wrapper-scripts`) re-points every inherited DSN env var (`TEST_DB_DSN`, `DB_DSN`, `DB_DIRECT_DSN`,
  `DB_APP_DSN`, `DB_WORKER_DSN`, ...) from the base database to an isolated database for each test.
  In parallel non-quick runs (`LANE_DB_POOL=1`, default), `scripts/ci/server-rust-parallel-lane.sh`
  pre-creates `LANE_JOBS` reusable slot databases (`<prefix>slot_0..N-1`) from the template and
  generates a self-contained SQL reset script (`scripts/ci/lane-db-pool-meta.py`, `$LANE_DB_POOL_META`)
  from `slot_0`. Each nextest invocation acquires an exclusive slot lockdir (`slot_<i>.busy`), runs
  against `<prefix>slot_<i>`, and before releasing the lock runs the single-round-trip reset script
  (terminates lingering backends, verifies a strict catalog + `pg_db_role_setting` + matview +
  prepared-xact + large-object fingerprint, truncates/clears dirty initially-empty tables and
  throwaway `public.domains` rows, verifies exact row counts and content MD5 of every seed table,
  and restores any shifted sequences). Any non-zero exit, catalog/seed drift, or reset error
  triggers a fail-safe `DROP DATABASE ... WITH (FORCE)` + `CREATE DATABASE ... TEMPLATE` re-clone
  before releasing the slot lock; if all slots are busy or `LANE_DB_POOL=0`, the wrapper falls back
  transparently to a fresh per-test clone (`<prefix><24 hex>`). The template is loaded once by
  `scripts/load-test-schema.sh` (`ALLOW_CONNECTIONS false`); roles are cluster-wide and provisioned
  once with it. The lane sweeps leaked `<prefix><24 hex>` clones and `<prefix>slot_<N>` slots at
  startup and exit; it never touches other databases.
- **Serial groups.** nextest cannot isolate host state, so `scripts/ci/server-rust-lane-groups.py`
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
- **Root container.** `scripts/ci/lane-container.sh` runs each lane step as root in the pinned
  `setjoin-server-rust-lane` image on the host network with the Docker socket, as on the dev host:
  oracles bind `:53`/`:80`/`:636`, assert root ownership and start sibling containers. Workspace,
  `$HOME` and `/tmp` are mounted at identical paths; ownership returns to the runner user on exit.
- **Postgres.** `lane-setup` starts the baked `setjoin-lane-pg:17` (pgtap) on a job-owned data
  directory under `$RUNNER_TEMP` with `fsync=off`, `synchronous_commit=off`, `full_page_writes=off`,
  loopback publish and a per-job SCRAM secret (CI only, masked). Tools are pinned by
  `scripts/server-rust-lane-tools.sh` (nextest, cargo-deny, pebble) inside the lane image.

## Go-deletion rehearsal (#141)

> **Completed and retired in `#142` ([ARCH-031](../docs/adr/ARCH-031-go-is-deleted.md)):** `#141` passed with `PENDING = 0`, `REHEARSAL-FORWARD-SITES = 0`, `MATRIX_HOPS = 0/0`, and `GO_PEER_REFERENCES = 0`. Go and `scripts/check-gofree-rehearsal.py` were deleted in `#142`; `scripts/dev/test-samlacs-mutants.py` remains active in CI `roots` under `REQUIRE_DB=1`. Historical rehearsal record preserved below.

`scripts/check-gofree-rehearsal.py` (self-test `scripts/test-check-gofree-rehearsal.py`) makes the hosted
lane the rehearsal for deleting Go. `static` (`roots` and `aggregate`): every route-inventory entry ON
except the six `fedharness` test-tool entries (owner decision 2026-11-02) and the shrink-only `PENDING`
list; no ON entry with a `go-*` upstream; `FORWARD_SITES` pins the exact count of forward-to-Go call
sites in `server-rust/bins/*/src` (auth `.forward(`, gateway `.forward(`, plus Go-hop plumbing
`Target::GoMail/GoAuth`, `.with_go_counter(`, auth `go_upstream`; `forward_body(`, `forward_unported(`,
`ws_client`/`client_async(`, and `unported_push_target` are 0 / banned; only the single gateway arm
`let mut response = upstream.forward(req, &identity).await;` under `Some(upstream) => {` in
`match &shared.rust_auth_upstream` is exempt as a Rust-to-Rust hop). A pin of 0 is red and an
unpinned kind is banned: the proof that Go can be deleted is this static ratchet reaching
`FORWARD_SITES = {}` (DELETE gate, #358).
The DELETE matrices are a behavioural supplement, not the proof:
`bins/auth/tests/delete_gate.rs` covers login (plain, device proof, captcha, DPoP, guest) and refresh
across 12 toggle cells; `bins/gateway/tests/delete_gate.rs` covers Basic/Negotiate on `/caldav/`,
`/carddav/` and `/api/drive/native-token`, guest and member drive tokens and member CalDAV/CardDAV
PROPFIND controls across 5 cells. Every cell has a reviewed expected outcome (`Native(status)` or
`Hop(owner)`); `MATRIX_HOPS` pins expected Go-hop cells (`auth 0`, `gateway 15`), which only shrink.
In the `roots` stage under `REQUIRE_DB=1`, `scripts/guards/check-server-rust.sh` also runs
`scripts/dev/test-samlacs-mutants.py` (38 SAML ACS mutant rejections and positive controls).
`GO_PEER_REFERENCES` pins every source reference
to a retired frozen Go peer binary (now `0`: absolute ban); reviewed divergences; the 51
`worker_semantics.json` workers owned by Rust; every seam present. #141 criteria 1 and 4 stay open until
`PENDING` is empty and `FORWARD_SITES` is 0 (gateway `.forward(` stands at `12`, excluding the exempt `rust_auth_upstream` arm, with F04 WORM `PutObjectLegalHold`, `mailboxes` `CanonicalEmail`, `mail_security` TLS/trace settings, `directory_sync`, `surface`, `rtc`, and non-Kerberos `drive_native` checks native). `env` (every lane job): any Go upstream or recording
variable present (even empty) is red; with `LANE_GO_MASKED=1` a reachable `go` is red.
`scripts/ci/lane-container.sh` masks `/usr/local/go` in the lane container. `lane_go_watch` wraps the
nextest run and the adequacy gate: ready only after a probe's event came back through `docker events`
(container and image events, no event filter); the ready line holds the image id of every
`.github/ci/images.lock` entry (a tag that does not resolve to its pinned digest is red), a snapshot of
every existing container, and a scan of the whole lane-container filesystem for executable Go-built ELFs
(`.go.buildinfo`); stop drains up to a second probe and scans again. Red: a container create, start or
exec whose image is not pinned in `images.lock`; one from a Go-capable image (`setjoin-ci-linux-tc`,
`setjoin-server-rust-lane`) without a `GO_TASKS` label (only `gofree-rel3`, which runs the Rust updater;
both Go peers `gofree-fed2` and `gofree-tlsfront` are retired)
other than the lane container itself; an image tag/untag/delete/load/import or a pull by tag during the
lane; any Go ELF other than the docker CLI and pebble; an
incomplete window. Every docker call is bounded (60 s) and probes are removed and checked. Residuals,
not claimed: `exec()` is not traced, so a Go ELF created and deleted within one window and run in the
lane tree would be missed (only allowlisted sibling tasks can produce one; the toolchain is masked);
running an allowlisted Go ELF from the lane tree is excluded by the source pin, not by tracing;
`gofree-rel3` runs no Go by script review. The proxied-to-Go counter is not summed lane-wide (tests
drive in-process fake upstreams by design); zero comes from the inventory and `FORWARD_SITES`. The
webmail Playwright e2e is outside the rehearsal (needs a deployed stack via `E2E_SERVER`, no hosted
workflow); the front-door goldens cover its HTTP surface.

## Frozen Go recording workflow

> **Deleted in `#142` ([ARCH-031](../docs/adr/ARCH-031-go-is-deleted.md)):** `.github/workflows/gofree-record.yml` and Go recording helpers (`scripts/gofree-record.sh`, `*.go.txt` overlays) were deleted with Go. Existing goldens remain as permanent regression tests; historical workflow record preserved below.

`.github/workflows/gofree-record.yml` (#339) is `workflow_dispatch` only (`contents: read`,
`packages: read`, never pull_request or push) and is deleted with Go (#142). Inputs: `package`,
`test`, optional `case_filter`, `go_source` (empty or the dispatched ref's own commit: dispatch on the frozen ref, since recorders such as drain run `go test` on the checkout) and `extra_env`
(allowlisted `GOFREE_RECORD_*|ORACLE_*|VERIFY_*` lines, e.g. `GOFREE_RECORD_DRAIN=all`). It builds
`go build -cover ./mailserver/cmd/mailserverd` in `setjoin-ci-linux-tc`, exports
`GOFREE_RECORD_GO_BINARY` and `GOFREE_GO_SOURCE`, and `scripts/gofree-record.sh` (in the lane
container) loads one disposable DB, sets `REQUIRE_DB=1`, `TEST_DB_DSN`/`DB_DSN`/`DB_DIRECT_DSN`/
`DB_APP_DSN`, `GOFREE_RESOURCE_PREFIX`, a created `GOFREE_RESOURCE_LEDGER` and runs
`cargo test -p <package> --test <test> -- --test-threads=1 --skip mutant --skip fault`. Goldens are
exclusive-create, so existing ones are only compared; new files, `git status --porcelain` and the
diff upload as artifact `gofree-record` and are never committed; any modified or deleted tracked file (drain's recorder deletes before it records) fails the run after the upload. After recording, every new file must be JSON whose `go_source` fields equal the checked-out commit, so new oracles (#341, #342 and later) must stamp `GOFREE_GO_SOURCE` (older auth oracles hardcode a historical constant and fail this check for new cases). `*_LEARN` variables are rejected, a run needs at least one `GOLDEN-` line or new file, and all job-started containers are removed and verified. `go_upstream=authserverd` accepts only setjoin-auth `oracle`, `token_oracle`, `mfa_oracle`, `webauthn_oracle`, `guest_invite_oracle`, `threat_oracle`, `device_proof_oracle` and `ca_issuance_oracle` (targets may not exist yet). Input `go_upstream=authserverd` also
builds `authserverd`, installs the synthetic `identity-login/keys.json` signing row, starts it on
`127.0.0.1:47335` (host network, fixture DB only, ledgered, stopped always) and exports
`GOFREE_RECORD_UPSTREAM` for auth-listener `*_oracle` targets.

`extra_env` `GOFREE_RECORD_AUTH_PRESET` (strict `off|threat|tarpit|geo|ca`, default `off`, authserverd mode only) sets Go's threat env in its 0600 env file, each variable once:
`off` and `ca` = the five `*_ENABLED=false` (`ca`: the oracle seeds CA DB toggles); `threat` = all five true, fixture `CAPTCHA_SECRET`,
`GEO_BLOCK_COUNTRIES=US`, no GeoIP (country ""), `TRUSTED_PROXY_IP=127.0.0.1`, `THREAT_RATE_LIMIT_PER_MIN=3`, `THREAT_CAPTCHA_THRESHOLD=3`,
`THREAT_SPRAY_MAX_USERS=3`; `geo` = `threat` plus `GEOIP_DB_PATH=server-rust/tests/conformance/authzgates/us.mmdb` (a one-node tree:
every address is US, so every source is geo-blocked); `tarpit` = `geo` with `GEO_BLOCK_ENABLED=false`, `CAPTCHA_ENABLED=false`,
`THREAT_TARPIT_THRESHOLD=2` (every source is a high-risk country).

## Rust guard self-test

- `bash scripts/guards/check-server-rust.sh --self-test` — proves the guard fires on a
  throwaway crate. Both run automatically from `scripts/run-guards.sh`.

## Family dependency guards

- Family crates must not depend on another family crate. `python3 scripts/guards/check-rust-family-isolation.py` inspects Cargo's resolved graph, including direct dev/build dependencies, transitive dependencies and local overrides; non-workspace paths are forbidden. Dev-only dependencies of intermediate crates are excluded, as Cargo does not build them for dependants. `cargo deny --locked check` enforces `deny.toml` (licences, sources, bans and RustSec advisories, #388; an advisory `ignore` needs `{ id, reason }`, enforced by the exception guard); MPL-2.0 dependencies must remain unmodified. Record each licence exception's exact crate spec and reason in `license-exception-reasons.toml`; `scripts/guards/check-rust-license-exceptions.py` enforces it. The guards and fixtures run in `scripts/guards/check-server-rust.sh` (Python 3.11+, cargo-deny 0.19.0).

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
statements unchanged (`bulk-role-jobs` leaves the job `'queued'` on PostgreSQL
SQLSTATE `57014` instead of stamping `'error'`, matching Go's
`applyFailureIsCancellation`, #194) and keep Go's cadence (3 s, 3 s, 2 s with
an immediate first tick, 5 s with an immediate first tick). `identity-transitions`
takes `LIVEKIT_API_KEY`,
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

---

## Relocated core server & protocol contracts (from `mailserver/DOX.md`)

<!-- Preserved verbatim from mailserver/DOX.md during #577 top-level layout promotion. -->
<!-- Deployment/installer/native-socket contracts moved to deploy/DOX.md. -->

### Gated domain rails

Client-assisted recovery is an independent OFF-gated U5–U8 rail. V180 and
`internal/continuity` issue/present installation-, account-, timeline-, state-,
boot-, and digest-bound witnesses and receipts using a dedicated signing key.
V181 and `internal/mailrecovery` translate bounded incident/upload/quarantine
requests to reducers; Go never decides ingest authority. ClamAV is mandatory
and fails closed. Exact raw MIME/blob hashes, current user/delegate scope,
fresh admin authority, user consent, fork consent, state/audit/notify, and blob
refcounts are reducer/trigger-owned. The cleanup worker drains expired chunks
even while intake is OFF. See `docs/guides/CLIENT_ASSISTED_MAIL_RECOVERY.md`.

Drive node ACL and access governance is the V184–V193 gated rail. PL/pgSQL owns
closure, exact capabilities, grants/breaks, directory-group generations, epoch
fences, approvals, leases, invalidations, audit, and rollback refusal. Go remains
a bounded wire translator; native/web caches must consume the opaque invalidation
stream and quarantine revoked bytes. `feature.drive_node_acl_reads`,
`feature.drive_node_acl_writes`, `feature.drive_access_governance`, and
`feature.drive_emergency_access` are all seeded OFF. Integration and operator
contracts live in `docs/guides/DRIVE_ACL_INTEGRATION.md` and
`docs/guides/DRIVE_ACL_OPERATIONS.md`.
Grant and access-request creation require one canonical UUID
`Idempotency-Key` header exactly matching the body; cross-actor reuse is a typed
conflict. Revoke remains authorization-first, then returns a no-write replay only
to the same still-authorized revoker. Inheritance conflicts refresh access and
re-preview impact rather than bypassing the epoch fence.

Mail platform modernization V195–V208 is an OFF-gated rail. `internal/migration`
and IMAP translate immutable-source/checkpoint and membership-UID contracts.
IMAP pre-auth IDLE is refused (`NO [AUTHENTICATIONREQUIRED]`) before any
deadline-clearing path (med-shard3-012 SHIP): unauthenticated sockets stay under
the ordinary slowloris read deadline and cannot pin `tlsutil.LimitListener`
accept slots; authenticated long-lived IDLE accommodation is unchanged.
IMAP checkpoint writers emit canonical `uid`; readers accept the pre-V209
`lastUID` spelling, reject conflicting mixed payloads, and the checkpoint reducer
atomically projects committed UIDs into legacy `resume_cursor.uids`;
every resumable connector now implements the mandatory `SourceSession` seam:
the adapter owns source identity plus provider-native closed page/candidate
serialization, while the orchestrator applies and commits exactly one bounded
page before acknowledging the next read. IMAP uses UID ranges/UIDVALIDITY, EWS
durable scopes use stable folder IDs while the reducer atomically dual-projects
legacy display-name delta keys, and M365 retains per-category Graph links;
cancellation interrupts source reads and bounded-joins the producer, while
cross-page replay is reducer-operation-ID authority rather than Go heap state;
`internal/mailboxlifecycle` drains retained-mailbox effects and purge work;
`internal/mailwork` scans SLA state and drains local/signed-webhook plus exact
Task/Chat/Drive action effects;
JMAP exposes reducer-owned work, comments, calm preferences, cohort-safe metrics,
stable shared-draft sessions, collaborator catalogs, and full-access business-
calendar administration. `internal/mailwork` also dispatches authorization-first
daily resets and records real first responses. Admin and protocol gateways must not recreate
lifecycle, purge, source-rebind, notification, analytics, or draft-lease decisions.
See `retired-docs:verification/2026-08-10-mail-platform-modernization.md`.

## 3. Local Contracts

### Startup order (mandatory)

> **Post-Go note (`#142` / `ARCH-031`):** Go `cmd/mailserverd/main.go` was deleted. The canonical Rust boot sequence is owned by `server/crates/boot/DOX.md` and `server/bins/gateway/DOX.md` (binary `setjoin-server`). The numbered invariant list below is preserved as the behavioral startup contract.

1. `config.Load()` + encryption key validation
2. Network mode detection (China/Global/Airgap)
3. GeoIP DB download (fail-open)
4. Config atomic pointer + SIGHUP hot-reload goroutine
5. PgBouncer pool (`DB_DSN`) + database-schema-version guard: refuse to start if `MAX(schema_migrations.version)` is behind the version the binary ships. Expected version is **derived** from the embedded `V<NNN>__*.sql` in `sql/dbschema/` (`dbschema.ExpectedVersion()`) — no constant to bump. The loud error names the pending files + `mailctl schema apply`.
5a. Worker + owner pools (native-RLS W1b, INERT): `DB_WORKER_DSN` → `setjoin_worker` (BYPASSRLS) pool for cross-tenant carve-outs (the cron worker today), `DB_OWNER_DSN` → `setjoin_owner` pool for partition DDL. Both **default to `DB_DSN`** when unset — and when equal/unset they ALIAS the main pool (no second connection opened, no extra `defer Close`), so connection count is identical to today. Never `SET ROLE` on a shared pool.
6. Direct connection (`DB_DIRECT_DSN`) — LISTEN/NOTIFY only
7. MinIO/SeaweedFS client init
8. Monthly partition creation (`startup.EnsureMonthlyPartitions`, on the owner pool — new partitions are owner-owned; a thin `SELECT create_monthly_partitions(1)` — the catalog-derived reducer is the ONE owner of the month-partitioned table set, shared with the cron 25th task)
9. Stale multipart abort (`startup.AbortStaleMultiparts`)
10. WORM immutability startup check (`startup.InitWORM`)
11. Secret bootstrap (`startup.BootstrapSecrets`)
12. Feature toggle system (`toggle.New`) — must precede protocol servers
13. LISTEN/NOTIFY dispatcher + `toggle.BindNotifications` config_changed lifecycle. After every direct
    connection reconnect it first restores every LISTEN subscription, then
    reloads every registered authoritative cache before resuming notification
    service; PostgreSQL does not replay notifications missed during an outage.
    Any refresher failure closes the new connection and retries with backoff.
    Feature toggles enter their per-key conservative failure posture, and the
    authentication chain retains only signed bearer verification until a
    complete auth-method snapshot succeeds. Its process-lifetime
    `config_changed` handler is durable: an initial LISTEN failure retains the
    handler for reconnect replay, while request-scoped subscriptions keep the
    ordinary remove-on-failure contract. The shared binder performs the
    readiness-critical post-LISTEN reload and unregisters its notify/reconnect
    callbacks on cancellation. The gateway observer exposes two independent
    capacity-one signals and fixed context-bound goroutines for identity and
    legacy AD reconciliation: bursts coalesce per effect class while a slow AD
    reload cannot block normalized identity replacement. It does not consume or
    replace other `config_changed` subscribers.
14. Threat interceptor (`threat.New`)
15. Spam trainer goroutine
16. Auth chain (`auth.NewChain`) + threat wiring
17. Handlers constructed. Immediately after the AD/LDAP handlers and
    connector-secret validation, the normalized identity-source runtime
    reconciles active AD/LDAP workers only when `feature.identity_model_v2` is
    ON; remaining handlers follow. `config_changed` gives immediate generation
    replacement and a 30-second catalog poll reads the master toggle and source
    rows in one statement, closing lost-NOTIFY/cache windows and stopping every
    worker when the database master gate is OFF.
    Replacement cancels and joins the old generation; shutdown joins every
    worker.
18. Routes registered on `http.NewServeMux` — app JSON is registered with root-relative literals and served canonically under **`/api`** (the SPA block mounts the API mux via StripPrefix; pinned root surfaces per `scripts/api-pinned-prefixes.txt`; old-path non-GETs 308 to `/api/…` for one release)
19. HTTP/2 server (TLS via autocert or static cert; h2c in dev mode)
   In redirect mode, port 80 always targets the configured `HOSTNAME`; request-owned `Host` is never reflected into `Location`.
20. Protocol servers: SMTP inbound (`:25`), SMTP submission (`:587`), IMAP (`:143`/`:993`), LDAP GAL (`:389`/`:636`) — each gated by feature toggle
21. On SIGTERM, disable HTTP keep-alives and signal the overseer worker with
    SIGUSR2 before `http.Server.Shutdown`. Overseer releases inherited
    listeners only on its restart signal; omitting this step deadlocks
    listener teardown until `TimeoutStopSec`. A normal systemd restart must log
    `gateway stopped cleanly`; the outer 35-second bound is defense in depth,
    not the expected path.

`GO_WORKERS_OFF=name,…` suppresses exact, case-sensitive, whitespace-trimmed
worker names at startup and notification dispatch; empty/unknown entries are inert.
Names and original lifecycle policies are pinned in
`cmd/mailserverd/testdata/worker_launch_inventory.golden` and `worker_semantics.json`.
All asynchronous gateway workers, notification callbacks and self-starting helpers
are named. `startWorker` keeps helper startup synchronous (notably the webhook
first claim and AD/LDAP controllers); the identity runtime preserves its startup
error path and deferred join. `ad-sync`/`ldap-sync` also suppress background
config-change syncs so reload cannot restart transferred work. Request-owned
operations and mandatory shutdown still run. Non-HTTP protocol listeners keep
their existing whole-listener config/toggle gates (#238).

Cron's scheduler is `cron`; each task is independently switchable as
`cron:<AllTasks Name>` (for example `cron:scan-due-reminders`). `user-risk` is a
separate loop. Disabling a worker transfers its existing residue/drain obligation
to Rust; with the variable unset all original contexts, retries and joins remain.
`UPDATE_GOLDEN=1` regenerates the launch inventory from the real main.go after
reviewing launch changes; fixture overrides remain read-only.
`bash scripts/check-worker-launch-inventory.sh --self-test` proves new bypasses fail.

`pushjobs.NewWorker` is constructed once and then configured with the worker
pool, MinIO bucket, `noreply@<cfg.Hostname>`, `SetJoin`, and
`https://<cfg.Hostname>`. Its third Guest G1 leg drains
`guest_notification_intents` and reaps sent/stale rows unconditionally; the
guest feature toggle gates enqueue only, never residue drain. Each guest batch
uses a transaction-scoped advisory lock; the bounded mail phase keeps its
`outbound_queue` insert and intent stamp in that same transaction, preserving
atomicity through transaction-mode PgBouncer.

Guest G1 member invitations add `POST /api/me/guest-invites` to the authenticated
user surface. The handler requires both `feature.guest_accounts` and
`approval.guest_invite`, creates a `guest.invite` approval on the worker pool,
and performs the RLS-scoped visibility lookup before any worker-side decision.
On approval, decision + guest provisioning + SHA-256-only invite creation commit
in one worker transaction; the raw 256-bit token is emailed only after commit.

Guest G2a adds the admin management API behind an outer
`feature.guest_accounts` 404 gate, before audited `guests.view`/`guests.manage`
permission middleware. It exposes guest list/detail/lifecycle/profile assignment
and guest-profile CRUD, while `POST /api/admin/guests` creates new guests and
accepts an optional profile. Lifecycle writes
still route through the database-owned `guest_set_status` authority, which
independently requires persisted `guests.manage` before target lookup and keeps
host-domain reach in both the locked read and final mutation.

Guest G2b routes Chat, Drive, and Meet through a user-id entitlement checker
after each feature toggle's 404 gate. Mailbox-less guests therefore share the
same authoritative reducer as members; missing guest rows deny, missing member
rows preserve default allow, and capability lookup errors hide every app.

Guest G2c applies the assigned profile at every Chat grant choke. Memberships
snapshot explicit posting policy plus an immutable join-time history floor;
live profile edits update posting only. BZ220 rejects a read-only guest before
any send-side effect, while every member-facing reader applies the floor and
wall-clock join belt. The web console and constrained Chat shell consume only
server-derived entitlement and External/Removed/container fields.

Guest G2d is the release gate. Real independent sessions prove member-add and
disable serialize to either grant-then-delete or disable-then-BZ219, always
with zero membership after disable. The gate is composite: the admin lifecycle
tracer proves the full profile/entitlement/grant/post/lifecycle/re-invite arc,
and an independent Chat integration tracer observes a real `event: chat` SSE
frame. Because guests have no primary mailbox, EventSource
omits only their JMAP state subscriptions and initial StateChange; their
self-scoped revocation and app push channels remain live. The feature toggle
remains seeded OFF after this gate and is enabled only by deployment choice.

Guest G4 splits Drive preview from original-byte authority without exposing a
standalone Drive app. Chat-derived guests are viewers, meeting attendance keeps
its historical role, and only the exact office-PDF preview route is added to
the guest allowlist. Raw content calls the reducer-owned download gate before
version lookup; `allow_download=false` is constant-shaped BZ215. Preview and
raw reads both inherit live Chat attachment/history-floor revocation. Native
Drive-token minting remains denied. Guest viewers cannot upload attachments:
the chunk handler checks the reducer-owned editor requirement before storage,
and the Chat conversations capability hides composer upload/voice controls.

Guest G5 completes lifecycle ownership. `guest_set_status` is still the single
writer for admin disable/enable/extend and system due-expiry; disable/expiry
atomically align `guest_accounts` with `users.enabled`, revoke all sessions,
and snapshot the guest identity against every parent and breakout room belonging
to each ongoing meeting in which it participated. Meet token mint paths take
the guest lifecycle share lock, so no grant can race past that snapshot. The unconditional
`guestlifecycle.Worker` runs an hourly expiry sweep and a 5s durable SFU drain,
retrying even successful/absent removals through the stale-token horizon.
Guest status handlers and reducers acquire the V172 authority fence before any
guest/user row lock; `provision_account` takes the same fence before identity
resolution, so status changes, expiry, and guest reprovision serialize in the
universal advisory-to-row order rather than forming an ABBA deadlock.
Admin guest detail flags sponsor review and offers a same-scope explicit
sponsor/Chat-owner/Drive-owner transfer; attribution and compliance history are
never rewritten. Conditional Access also accepts targetless `guests` scope.

Guest credential recovery adds the explicit
`POST /api/admin/guests/{id}/reinvite` transition. In one worker transaction it
keeps the same identity, freezes sign-in at invited/disabled, revokes sessions,
records `action='reinvite'` SFU eviction intents, and replaces the pending
invite digest. Expired guests require a supplied future expiry; SSO-linked
guest rows fail closed rather than receiving a local-password fallback. The
post-commit fast drain runs before mail queueing, and all authenticated guest
Meet token paths remain fenced until the durable recovery intents complete.

Guest acceptance is limited to the exact unauthenticated `GET`/`POST
`/auth/guest-invite/accept` pair, the exact GET-only
`/auth/password-policy` bootstrap, and the bare-root, GET-only SPA prefix
`/guest-invite/`. The gateway registers all three authserver routes explicitly
so they cannot fall through to the SPA's HTTP-200 HTML response. The authserver
applies its enumeration guard and performs the
invite tombstone, guest activation, and user credential enablement atomically;
all other guest routes remain subject to `guestgate`. A 16-leg integration
tracer is the G1 hard gate across direct/member invites, disclosure, acceptance,
digest authorization, replay, revoke, and toggle-off behavior.

Violating this order causes startup failures (pool not ready, toggles not loaded before protocol init, etc.).

### Key files

| File | Role |
|---|---|
| `sql/reducers/README.md` | Full reducer contract index |
| `sql/dbschema/` | Canonical schema migration files (`V001`–latest; embedded by `server/crates/schema/`) |
| `api/openapi.yaml` | Static OpenAPI 3.1 contract + ReDoc assets embedded by `server/crates/domains/static/` |
| `webmail/` | SvelteKit SPA and Playwright E2E suite |
| `deploy/` | Systemd unit templates (`setjoin-gateway.service` running `setjoin-server`), `scripts/install.sh`, `scripts/upgrade.sh`, `scripts/setjoin-lifecycle.sh`, monitoring |

### Feature toggle gates

Protocol servers are gated by `feature_toggles` (loaded from DB at startup, updated live via `config_changed` NOTIFY):
The direct listener performs a full atomic reload after reconnect; consumers
that also hold long-lived authority must retain their own bounded database
reconciliation backstop.

| Toggle key | Controls |
|---|---|
| `feature.caldav` | CalDAV bridge (`/caldav/`) |
| `feature.carddav` | CardDAV bridge (`/carddav/`) |
| `feature.smtp_inbound` | SMTP MTA on `:25` |
| `feature.smtp_submission` | SMTP MSA on `:587` |
| `feature.imap` | IMAP4 on `:143` / `:993` |
| `feature.ldap_gal` | Read-only LDAP GAL on `:389` / `:636` |
| `feature.gal_carddav` | Read-only GAL CardDAV collection at `/carddav/gal/` (default ON) |
| `feature.dmarc_reporting` | Aggregate DMARC report receiver |
| `feature.tls_rpt` | TLS-RPT (RFC 8460) report receiver |
| `feature.assist` | AI compose assist + admin ops copilot (default off; provider not yet implemented) |
| `feature.offline_mail` | Native-shell offline mail cache (default OFF; seeded by `V029__offline_mail_toggle.sql`; gated by bridge presence + `caps.offline.allowed` before activating UI) |
| `feature.rust_inbox_list` | Answerer for the webmail inbox list (default OFF; #216, ARCH-026/027). Read only by the Rust front door, never by Go: ON, the gateway answers a verified single-tag `Email/query` with a READ ONLY scoped read; OFF, everything proxies here and `jmap_email_query` answers |
| `feature.rust_mark_read` | Writer for webmail mark-read (default OFF; #215, ARCH-026/027). Read only by the Rust front door (`server/bins/gateway`), never by Go: ON, the gateway serves a verified `$seen`-only `Email/set`; OFF, everything proxies here and the reducer writes |
| `device_telemetry` | Privacy-first device telemetry endpoint |

### Auth priority chain (gateway layer)

JWT Bearer (priority 10) → Kerberos/SPNEGO (priority 20, blocked if user has TOTP) → Basic Auth (priority 30, disableable). All `/auth/*` routes and the explicitly registered OIDC Provider/OAuth protocol endpoints proxy to authserver. The root allowlist includes discovery/JWKS, `/authorize` plus `/authorize/callback`, exact `/oauth/token` and `/oauth/introspect`, `/userinfo`, `/end_session`, and `/revoke`; broad `/oauth/` and `/authorize/` gateway patterns are local 404 sinks, never proxies, so unknown protocol paths cannot expose a future internal authserver endpoint or fall through as SPA HTML 200. App passwords are first-class HTTP Basic credentials (per-app scoped token, no TOTP bypass).

**JWT dual-verify (ADR-005).** `JWTProvider.Validate` (`internal/auth/jwt.go`) verifies BOTH legacy **HS256** access tokens (shared `JWT_SECRET`, kid `authserver-hmac-1`/`mailserver-hmac-1`) AND first-party **ES256** access tokens (authserver JWKS). It dispatches on the header `alg`: `ES256` → the shared `jwtutil.ParseES256` primitive (which re-asserts ES256 + requires a kid → resolves the key SOLELY via the JWKS client; closes alg-confusion + jku/x5u injection), then the SAME iss/aud/exp checks as the HS256 path. The ES256 key source is `internal/auth/jwks.go` (`JWKSClient`): fetches the authserver JWKS from `AUTHSERVER_JWKS_URL` ONLY (no token-supplied URL is ever trusted), parses it (`go-jose` `jose.JSONWebKeySet`) into a kid→`*ecdsa.PublicKey` map, caches it (bounded TTL), refreshes on an unknown kid (rate-limited so bogus-kid floods can't hammer authserver), serves stale on fetch error, and fails closed with no cache (verification fails, never panics). Wired in `chain.go`: when `AUTHSERVER_JWKS_URL` is set the client is constructed and attached via `JWTProvider.SetES256Verifier` (startup log line either way); when unset, ES256 tokens are rejected (HS256-only mode). `JWT_SECRET` stays required (HS256 path + derived keys). This is the gateway half of the never-a-flag-day rollout: deploy gateway dual-verify first, then flip authserver issuance to ES256; HS256 acceptance is removed in a later release. **SM2 (Xinchuang `smx`/`hybrid` profile, kid `authserver-sm2-1`):** the third verify branch. SM2 is NOT distributed via the JWKS (only ES256 is) — it uses the symmetric-trust model, so `NewChain` loads the shared `SM2_PRIVATE_KEY_FILE` (the same PEM mounted to authserver, exactly as `JWT_SECRET` is shared for HS256) via `cryptokey.LoadSM2PrivateKey` and passes it to `NewJWTProvider` whenever `CryptoProfile == smx` (or `hybrid` with a key file). Without this the SMx gateway has `sm2Key==nil` and rejects EVERY token (authserver issues SM2-only under `smx`); load failure is fatal at chain construction (fail-closed).

### Database security (enforced)

Follows root AGENTS.md R1–R4. See `docs/standards/DATABASE_SECURITY.md`. Every reducer with `p_mailbox_id` must reference it and scope its user-data statements by the mailbox (the account slot is a `mailbox_id`, ARCH-003). **Per-user isolation (R4) is enforced at the application layer — `p_mailbox_id` propagation in reducers + ownership predicates in raw gateway queries — NOT by native PostgreSQL RLS** (zero policies exist; native RLS is *deferred*). The load-bearing CI controls are `scripts/guards/check-account-scope.sh` (reducer layer: negative A–G + positive H) and `scripts/check-gateway-ownership.sh` (positive, over the raw gateway query surface). See `sql/AGENTS.md:42` and [ARCH-006](../docs/adr/ARCH-006-app-level-isolation-posture.md). Do not claim native RLS is enforced.

### Account-scope currency (ARCH-003)

The account-slot argument every reducer receives is ALWAYS a **mailbox id** (the caller's PRIMARY mailbox), never a `users.id` — `users.id` and `mailboxes.id` are independent BIGSERIAL sequences and `mailboxes.user_id` is nullable, so confusing them matches the wrong row (or zero rows) and fails silently. In the canonical Rust server (`server/`), primary-mailbox resolution is centralized in `setjoin-authz` and `server/bins/gateway/src/jmap/account.rs` (superseding the deleted Go `shared/identity` package).

- `identity.ResolvePrimaryMailbox(ctx, q, userID)` — the canonical primary-mailbox lookup (gateway-wide; ~46 former inline copies routed here). Returns `identity.ErrNoPrimaryMailbox` (wrapping `pgx.ErrNoRows`) when there is no primary.
- `identity.ValidateAccountID(ctx, q, reqMailboxID, userID)` — true iff `reqMailboxID` is the user's primary mailbox. JMAP `parseAccountID` (`internal/jmap/handler.go`) is the thin gateway wrapper around this: it returns the resolved `int64` + the JMAP `accountNotFound` error, and preserves the nil-pool unit-test fallback (compares against `userID`, no DB call). The `*pgxpool.Pool` satisfies `identity.Querier`.
- NOT routed (behavior-preserving, out of scope): in-statement `mailbox_id IN (SELECT … WHERE user_id=$N)` ownership subqueries (R3 — splitting would open a TOCTOU window), multi-column mailbox selects, the address-by-email lookup (`WHERE email=$1`), and the CalDAV primary-or-any `UNION ALL` fallback. The address-union predicate (`resolve_identity`) is Concern B and stays as the two guarded twins.
- The ADR-003 guard (`scripts/guards/check-account-scope.sh`, wired into `scripts/test.sh`) keeps the currency rule un-writable in reducers.

---

## 4. Features / Capabilities

### 4.1 Protocol layer

**SMTP — inbound MTA (`:25`, `internal/smtp/inbound.go`)**
- Receive inbound SMTP with STARTTLS (RFC 5321 + RFC 3207)
- Implicit TLS on `:465` when `smtp.inbound_tls_addr` set
- Per-IP and per-user connection limits (`smtp.inbound_max_conns`, `smtp.per_user_max_conns`)
- Large-message spool-to-disk before pipeline processing
- Greylisting
- RBL/DNSBL checking
- SPF verification (`spf.go`)
- DKIM verification + ARC chain (`arc.go`)
- DMARC enforcement + aggregate report receiver (`dmarc_report.go`)
- Anti-spam scoring: per-user FTRL ML model (`antispam.go`, `spam/` package), plus the `shared/spam` deterministic-detector suite (arch review #A5) wired ADDITIVELY via `ml_detectors.go`'s `applyMLDetectorSignal` — sender-mismatch, forged-recipients, mixed-charset, fake-HTML — behind `feature.spam_ml_detectors` (DEFAULT OFF, V137); off, scoring is byte-for-byte unchanged. The rest of `shared/spam` (OSB tokenizer / multi-class FTRL / composite YAML rules / phishing-template hash / image hash / spamtrap) stays unwired — each needs infra (attachment-byte extraction, a template/hash feed, a trained model store, a rule config file) not yet built. See `internal/AGENTS.md` "Spam scoring" + `docs/design/mail/archive/spam-enhancement.md`.
- ClamAV antivirus (`clamav.go`)
- Milter protocol integration — external filter appliance (SpamAssassin, etc.)
- Attachment behavioral sandbox via CAPE (`sandbox.go`)
- Anti-phishing: display-name spoofing, lookalike domains, contact-trust checks (`antiphish*.go`)
- DLP policy enforcement inline on inbound (`pipeline_deliver_store.go`)
- Link protection — URL rewriting to `/link-protect` click handler (`link_protect.go`)
- Journal-on-delivery (BCC archive) via `journal_if_policy_matches` reducer
- Retention tagging at delivery via `tag_retention` reducer
- Vacation auto-reply + distribution group expansion in `deliver` reducer

**SMTP — submission MSA (`:587`, `internal/smtp/submission.go`)**
- AUTH PLAIN / LOGIN over STARTTLS (RFC 6409)
- Per-user send quota enforcement in `send` reducer
- DLP check, send-as delegation, auto-BCC, signature injection (all in `send` reducer)
- App-password authentication for mail clients (no TOTP bypass)
- DANE/MTA-STS outbound policy enforcement (`dane.go`, `mtasts.go`, `tls_policy.go`)
- DSN generation for bounces (async, in the `scheduled_action_dsn` reducer — the `dsn` scheduled-action handler; the synchronous Go `dsn.go` was retired in WAVE 9)
- TLS-RPT aggregate report submission (`tlsrpt.go`)
- Outbound DKIM signing (`pipeline_modify_dkim.go`)
- Spool-to-disk for large messages before queuing

**IMAP4rev2 (`:143`/`:993`, `internal/imap/`)**
- Full IMAP4rev2 (RFC 9051): LOGIN, SELECT, FETCH, STORE, SEARCH, APPEND, EXPUNGE, IDLE, UID commands
- STARTTLS on `:143`; implicit TLS on `:993` (default when the shared TLS certificate is configured). Pre-TLS capability includes `STARTTLS LOGINDISABLED`; both `LOGIN` and `AUTHENTICATE` fail with `PRIVACYREQUIRED` until the upgrade succeeds. Configuration validation rejects a non-loopback `IMAP_ADDR` unless both `TLS_CERT` and `TLS_KEY` are set; only an explicitly loopback-bound development listener may run without transport TLS.
- Per-user and total connection limits (`imap_limits.go`)
- Tag-based folder model: IMAP folders map to tags; `imap_uid_next` tracked per tag
- App-password authentication

**JMAP (RFC 8620/8621, `internal/jmap/`)**
- Full JMAP Core session (`/.well-known/jmap`, `/jmap`)
- HTTP and WebSocket requests share `JMAPHandler.ExecuteBatch`, the sole owner of non-empty `using`, 32-call and 2,000,000-byte per-call limits, ordered result references, `createdIds`, continuation, registry-derived entitlement/delegate invocation metadata, dispatch metrics, and method error ordering. HTTP retains RFC 7807 request problems; WebSocket projects the same typed failures as RFC 8887 `RequestError` with `requestId`. The transports retain their existing 10 MB/10 MiB body/frame bounds and own no execution loop.
- Email/get, Email/query, Email/changes, Email/set (create/update/destroy), Email/queryChanges
- Thread/get, Thread/changes, SearchSnippet/get (plain GIN + `ts_headline`, not ParadeDB/BM25 — see `sql/AGENTS.md` "Full-text search")
- Mailbox/get, Mailbox/query, Mailbox/changes, Mailbox/set, Mailbox/queryChanges
- EmailSubmission/set (send), EmailSubmission/get, EmailSubmission/query (scheduled send listing)
- Identity/get (from aliases + delegation), Identity/set
- QuickStep/get, QuickStep/set (create/update/destroy), QuickStep/apply (A2) — user-defined one-click triage macros (`internal/jmap/quicksteps.go` → `quick_step_*` reducers); mailbox id resolved from auth (R2), action allowlist + ownership enforced in the reducer
- CalendarEvent/get, /query, /changes, /set (set carries `valarm` reminder alerts), /import (bulk `.ics` file import → `calendar_import_ics` reducer, calendar-ownership checked; parser reuses `migration.SplitAndParseICS`, never the raw-INSERT path)
- Calendar/get, /changes, /set
- **A3 calendar parity** (`internal/jmap/calendar_a3.go`): Calendar/getShared, CalendarEvent/getShared (open another user's calendar; viewer = authenticated `user.UserID`, never a body field; `freebusy` grants redact title/location/description), Calendar/shareGet, Calendar/shareSet (calendar_acls grant/revoke; owner/admin-gated; levels freebusy/read/write/admin via V084), Calendar/delegateList, CalendarEvent/setOccurrence (this/following/series recurring edit), CalendarEvent/resourceList (bookable rooms), CalendarEvent/sendUpdate (SEQUENCE bump + iTIP REQUEST re-issue). CalendarEvent/rsvp gained `onBehalfOf` (delegate respond). CalendarEvent/set create books `role='resource'` attendees via `calendar_book_resource`.
- **Self-service booking pages** (feature #6; `feature.booking_pages`, DEFAULT OFF; V113 `booking_pages`/`booking_requests`; `sql/reducers/booking_pages.sql`; BZ134-BZ137). An owner publishes `/book/<slug>`; a booker picks a slot computed from the owner's REAL free/busy through the existing `calendar_busy_intervals` seam (busy-only, never event detail), submits (mandatory double opt-in — no calendar event exists until the emailed verify link is clicked), and the confirm step creates the event via `jmap_calendar_event_set_create` + sends an iTIP invite via `jmap.EnqueueInvite` (the same egress `CalendarEvent/set create` uses). This is setjoin's **first deliberate unauthenticated public app surface** — see §4.6 and `docs/adr/DES-007-public-booking-surface.md` for the full security posture (enumeration parity, rate limits, honeypot, hashed single-use tokens, the BYPASSRLS worker-pool carve-out). Owner CRUD: `GET/PUT/DELETE /api/booking/pages` (authed, `internal/booking.Handler`). Webmail: `/settings/booking` (owner config) + `/book/[slug]` + `/book/confirm` (public, standalone — no app shell).
- Contact/get, /query, /changes, /set; AddressBook/get, /changes, /set
- Task/get, /query, /changes, /set
- JMAP blob upload (`/jmap/upload/{accountId}`) and download (`/jmap/download/...`)
- WebSocket push and JMAP requests over `/jmap/ws` (JWT from HttpOnly cookie, no Authorization header); Request frames route through the same execution envelope as HTTP.
- Read receipt endpoint (`POST /auth/me/read-receipt`, body `{messageId, consent}`) — MDN RFC 3798. The **recipient** controls whether an MDN is ever sent via the per-user `read_receipt_policy` ∈ {ask (default), always, never} (V081); `send_read_receipt()` is the hard gate (`never` suppresses even with consent, `ask` needs consent). Set on the Privacy settings page
- Mailtips endpoint (`GET /auth/me/mailtips`) — compose-time warnings: large audience, external recipient, missing send-as, and **out-of-office (QoL #7)**. The OOO branch routes through the `recipients_ooo_status(p_mailbox_id, p_emails jsonb)` reducer (logic-where-the-data-is) — resolves each address via `resolve_identity` (external/unknown → absent, no directory-enumeration oracle) and returns **dates only** (`type:'ooo'`, `until` = end-date or null for indefinite), never the auto-reply body. Active-window logic verbatim from `deliver_group_vacation`.

**CalDAV (RFC 4791, `internal/caldav/`)**
- PROPFIND, REPORT, PUT, GET, DELETE on `/caldav/`
- iCalendar read/write with recurrence expansion (`ical.go`)
- iMIP parsing and delivery (`imip.go`)
- iTIP REQUEST/REPLY/CANCEL processing (`itip.go`) — a RECURRENCE-ID REQUEST/CANCEL applies to the recipient's local master via `jmap_calendar_event_set_occurrence('this', ...)` instead of the whole-series dedup/cancel (`retired-docs:superpowers/plans/archive/2026-07-08-recurring-event-occurrence-edit.md`). Round 6 (Astra HOLD): the series-CANCEL sweep is gated PER AFFECTED MAILBOX, not bound to the signer's domain — `cancelAffectedDomains` enumerates owner domains of every non-cancelled local copy sharing uid+organizer, each copy is cancelled only when its owner domain's `domainAcceptsCancelEvidence` policy accepts the authenticated evidence (S/MIME evidence must be covered by that domain's trust; DKIM/SPF evidence is not tenant-scoped; `SmimeTrustNone` accepts nothing), and the reducer is invoked once per accepted domain. External-organizer cancellations reach exactly the mailboxes whose policy trusts the evidence.
- Free/busy batch query (`freebusy_batch.go`)
- Calendar invite endpoint (`POST /calendar/free-busy`)
- Feature-toggle gated (`feature.caldav`)
- PROPFIND/REPORT property selection uses `internal/webdav.ResolveProperties`: requested and allprop catalogs are ordered, present values precede missing values in exact 200/404 propstats, typed nil is absent, and explicitly missing CalDAV values retain their namespace as empty XML elements. CalDAV owns only its typed request catalog/value installer.
- **Resource model: one CalDAV resource per uid.** A recurring master + its detached-occurrence override rows (`recurrence_override` set, same `uid`) render as ONE `.ics` resource: `listEvents`/`listEventsFiltered`/`getEventByUID` scope to the master row (`recurrence_override IS NULL`); `eventToICalWithOverrides` (`caldav.go`) renders the master plus one VEVENT per override inside a single `VCALENDAR`, each override tagged `RECURRENCE-ID` (`ical.go`'s `writeVEVENT`, split out of `eventToICal` for this). PUT parses the whole body via `ParseICalObjects` (Apple/Google send master + exception VEVENTs in one request; the single-object `parseICal` wrapper stays for every non-recurring caller) and reconciles exception VEVENTs/EXDATEs against existing override rows through `jmap_calendar_event_set_occurrence` — RFC 4791 PUT replaces the whole resource, so an exception dropped from the wire is dropped from the DB. EXDATE/RECURRENCE-ID parse both the bare UTC-Z form (Google) and `TZID=`/`VALUE=DATE` parameter forms (Apple), resolved to the same instant either way.

**CardDAV (RFC 6352, `internal/carddav/`)**
- PROPFIND, REPORT, PUT, GET, DELETE on `/carddav/`
- vCard 3.0/4.0 read/write (`vcard.go`)
- Feature-toggle gated (`feature.carddav`)
- PROPFIND/REPORT property selection uses the same `internal/webdav.ResolveProperties` authority and exact 200/404 grouping; CardDAV owns only its typed request catalog/value installer, including namespaced empty elements for explicitly missing properties.
- **GAL collection (`/carddav/gal/`, `gal.go`, read-only).** The org directory
  (webmail `/directory` + LDAP GAL's same audience) exposed as a third CardDAV
  addressbook, auto-appearing next to personal books in the home PROPFIND
  (Depth 1 on `/carddav/`) — no per-user opt-in. Members are
  `/carddav/gal/u{userID}.vcf`, `UID:setjoin-gal-u{userID}` (stable across
  renames), served straight off `directory_visible_users(p_mailbox_id)` — the
  SAME ADR-004 visibility seam webmail directory browsing and the LDAP GAL
  read from (one seam, three protocols; see `sql/AGENTS.md`). Guest P7 is
  enforced in that seam by excluding every `guest_accounts` discriminator row
  regardless of lifecycle state, so GAL/CardDAV never publishes guests. People only (no
  distribution groups / resource mailboxes as vCards). PROPFIND/GET/REPORT
  (addressbook-query with a parameterized `text-match` filter,
  addressbook-multiget, sync-collection via the `gal_changes` reducer) all
  work; PUT/DELETE (and the OPTIONS `Allow` list) are hard-rejected with a
  403 `DAV:cannot-modify-protected-property` — the directory is provisioned
  by admin/AD-sync, not by CardDAV clients, same stance as the LDAP GAL's
  `handleReadOnly`. Sync-collection token = `{maxUpdatedµs}-{visibleCount}`;
  a count mismatch (hard-delete, not just disable/hide) forces a full resync
  instead of ever serving a stale delta. Toggle `feature.gal_carddav`
  (default ON — parity with `feature.ldap_gal`; exposes nothing an
  authenticated user can't already browse at `/directory`), runtime-checked
  per request so an admin can flip it live; the whole bridge is still gated
  behind `feature.carddav` + `requireApp("contacts")`. `.well-known/carddav`
  and `.well-known/caldav` (RFC 6764, `main.go`'s `registerProtocolRoutes`)
  301-redirect to `/carddav/` / `/caldav/` so Apple/GNOME/DAVx5 auto-discover
  the server without a manual path — the GAL then rides the existing
  account's next collection-list poll.

**LDAP GAL (read-only, `internal/ldap/`)**
- RFC 4510 LDAP server on `:389`/`:636`; serves Global Address List (company directory)
- Paged search with `paging.go`, filter evaluation with `search.go`
- DN escaping via `dn.go`
- Every People base/subtree search and Compare resolves the bound user's primary mailbox through `identity.ResolvePrimaryMailbox` and reads `directory_visible_users(mailbox_id)`, the same ADR-004 authority as CardDAV/webmail. Hidden and Guest principals disappear uniformly; alias and UPN matching use the seam's full address set. Missing caller mailbox or query failure returns an LDAP operation failure, never a broader directory.
- Feature-toggle gated (`feature.ldap_gal`)
- Every data-returning handler (`handleSearch`/`handleCompare`) must assert a typed `BoundPrincipal` via `isBound(msg)` before touching the DB — `handleBind` (server.go) is the only place that stores it, after `auth.CheckPassword` succeeds. A client that never Binds (or fails to) gets `LDAPResultInsufficientAccessRights`, not a directory dump (A1 fix). `scripts/check-ldap-bound-state.sh` guards every `routes.Search()`/`routes.Compare()` registration in `server.go` against a reintroduced unguarded handler.

**SCIM 2.0 (RFC 7644, `internal/scim/`)**
- User and Group provisioning endpoints
- PATCH/PUT/DELETE for user lifecycle management
- Token validation via `scim_validate_token` reducer
- Every Group mutation carries the authenticated token's exact source
  generation. The reducer locks and rechecks `kind=scim,state=active,generation`
  in the mutation transaction; stale generations are BZ229 and inactive
  sources are BZ224.
- Optional; enabled via `SCIM_ENABLED=true`

### 4.2 Mail features

**Tag system (Phase 17)**
- Gmail-style multi-label model — `message_tags` junction table
- Exclusive groups: `location` {Inbox, Sent, Drafts, Trash, Spam}; `snooze` {Snoozed, Scheduled}
- Archive = remove location tag; All Mail = messages without Trash/Spam. The Archive **view** (A2) is the read side: `jmap_email_query`'s `inArchive` filter selects messages with no `location`-group tag
- State tokens: `jmap_email_state`, `jmap_mailbox_state`, `jmap_tag_state` (all bumped atomically in reducers via `notify_state_change`)
- NOTIFY channel: `tag:{mailbox_id}` → WebSocket fan-out

**Triage (A2 — V083)**
- **Quick Steps**: `quick_steps` table (per-mailbox named action macros) + `quick_step_{list,set,delete,apply}` reducers (`sql/reducers/quick_steps.sql`). A macro is an ordered array of a SUBSET of the rule-engine action vocabulary (move_to/categorize/flag/mark_read/forward_to) run through the shared `apply_action`. The allowlist (`quick_step_action_allowed`) is enforced at BOTH set and apply time — privileged rule actions (add_header/discard/delete) are rejected (`BZ043`), never silently passed through. Errors `BZ040`–`BZ043` (see `docs/reducer-error-codes.md`).
- **Flag for follow-up**: `messages.flag_due_at` / `flag_reminder_at` columns; set/cleared via `jmap_email_set_update` (`flagDueAt`/`flagReminderAt` patch keys; clearing `$flagged` nulls both), echoed by `jmap_email_get`. A2 only **stores** the instants — A6's `scan_due_reminders()` + `remind` handler fire the reminder (no parallel timer).
- **`jmap_email_get` property-projection contract (offline #1a):** when the client sends `properties: [...]` in an `Email/get` call, `jmap_email_get` projects only the requested columns. The offline sync engine requests exactly `METADATA_PROPS` (12 fields: `id`,`threadId`,`mailboxIds`,`keywords`,`receivedAt`,`hasAttachment`,`preview`,`subject`,`from`,`to`,`cc`,`bcc`) so sync fetches never over-fetch body content. Body content is fetched separately on open via an unrestricted `Email/get`. Callers must not add body properties to the sync projection.

**Message delivery**
- `deliver` reducer (`sql/reducers/deliver_group_vacation.sql`): alias resolution, group expansion, spam verdict, quota enforcement, vacation auto-reply, rule application, journal, retention tag
- **Focused/Other inbox split (V078)**: an Inbox message is Focused (no `Other` tag) or Other (carries the `Other` system tag — `exclusive_group=NULL`, `imap_expose=FALSE`, like `Muted`; absence = Focused). `deliver`'s Inbox arm calls `classify_focus` (deterministic, NOT ML — first match wins: per-sender override → contacts → internal sender → List-Id → first-time-external → else Focused); a TRUE verdict tags `Other`. `set_message_focus` moves a message + upserts a per-sender preference in `focus_sender_overrides` (per-user RLS). Read side: `jmap_email_query`'s `focus` filter (`'focused'`/`'other'`). Endpoint `POST /messages/{id}/focus` (`user/focus.go`, body `{focused}`). Webmail UI deferred.
- **Per-sender remote-image trust (WAVE-5 #5, V091)**: `user_image_allow(user_id, sender)` — EXACT-ADDRESS grain (not domain: a domain grain would trust every local-part at a shared big provider off one opt-in), FORCE RLS self policy copying V078 `focus_sender_overrides`'s shape. `internal/user/image_allow.go` (`GET/POST /settings/trusted-senders`, `DELETE /settings/trusted-senders/{sender}`), every statement via `dbscope.RunUserScoped` + an explicit `user_id=$1` predicate (R1–R3). Ungates the webmail's remote-image FETCH only — HTML always still passes DOMPurify sanitize.
- Soft-delete / Trash / permanent purge lifecycle (`jmap_email_set_destroy`, `jmap_email_purge`)
- Deleted-items recovery (`jmap_email_query_deleted`, `jmap_email_recover`)
- Auto-purge of soft-deleted messages >30 days (`purge_deleted_messages` cron)

**Outbound send**
- `send` reducer (`sql/reducers/send.sql`): authorization, send-as delegation, DLP check, local delivery, SMTP outbound queue, identity rules (signature injection, auto-BCC)
- Scheduled send (B2): `sendAt` field on EmailSubmission; `process_message_timers` cron wakes them; listed via `jmap_email_submission_get/query`
- Undo send (Stage 1.6): cancel within configurable delay window — `POST /messages/{id}/undo`; user configures delay at `PUT /settings/undo-send`; `user/undo_send.go`
- Message recall (after delivery): `POST /messages/{id}/recall`; 5-minute window; `internal/user/recall.go`, `sql/reducers/recall.sql`
- Message snooze (B1): `message_snooze` reducer applies Snoozed tag + `snooze_until`; `process_message_timers` cron wakes; `SnoozePicker.svelte` in webmail
- Tag-on-send (B3): add tag atomically during send via `send` reducer `p_tag_on_send` parameter

**Distribution groups + shared mailboxes**
- Distribution group expansion in `deliver` reducer
- Shared mailboxes via `mailbox_delegates` (not mailbox type)
- `deliver_group_vacation.sql` handles both

**Vacation auto-reply / Out-of-Office (A5)**
- Configured per mailbox; throttled (one reply per sender per day)
- Triggered in `deliver` reducer; respects RFC 3834
- **Separate internal vs external reply bodies** (Outlook OOO parity, V086): external senders get `body_external`, internal senders get the internal body; `external_audience` ∈ all/contacts/none gates whether external senders are replied to (`contacts` = only the owner's saved contacts)
- Self-service: `GET/PUT /user/automatic-replies` (`user/auto_reply.go`) → `get_vacation`/`set_vacation` reducers; mailbox derived from auth (R2). The settings PAGE is a later webmail step

**Out-of-office approval delegation / entrust (QoL #23, V105)**
- A date-range "entrust" distinct from the mail vacation reply: while active, an incoming **approval** request that resolves to the delegator is rerouted to the delegate. `approval_resolve_approver` calls `approval_active_delegate(user_id)` at resolution time (before the approver is snapshotted onto the request), so only requests created *during* the window are reassigned — already-created ones are untouched (DingTalk/Feishu semantics). Single-hop only (a delegate who is themselves OOO is not chained). Only the `user` kind is substituted; `role_group`/`skip` are untouched.
- `approval_delegations` (V105) deliberately has **NO RLS** (mirrors `vacation_settings`, not `approval_requests`): the resolution read runs on behalf of the *approver*, a different user than the requester, so FORCE RLS would hide the row — reads/writes are scoped by the `p_user_id` param instead (app-layer R1–R4 by propagation).
- Reducers: `approval_active_delegate` (resolver hook), `set_approval_delegation`/`get_approval_delegation` (user CRUD; BZ119 on invalid window / self / cross-domain delegate). Self-service: `GET/PUT /user/approval-delegation` (`user/approval_delegation.go`), delegator derived from auth (R2). Webmail: `src/routes/settings/approval-delegation/+page.svelte` (delegate picker reuses `directorySearch` + native `datetime-local` window).

**Send-as / delegation**
- Authorized via `mailbox_delegates` table; checked in `send` reducer (BZ003 on unauthorized)
- Send-as aliases: `jmap_identity_get` returns all user aliases as From identities

**User signatures**
- Multiple named signatures per user; applied by `send` reducer identity rules
- CRUD at `GET/PUT/DELETE /settings/signatures`; `user/signatures.go`

**Email annotations / external sender banner**
- External sender visual banner injected at read time; configurable threshold via `PUT /settings/external-sender`
- `EmailAnnotations.svelte`, `ExternalSenderBanner.svelte`

**RFC 8058 one-click unsubscribe**
- `POST /messages/{emailId}/unsubscribe`; `user/newsletter.go`, `NewsletterBundle.svelte`

**Raw .eml download**
- `GET /messages/{emailId}/download` — user self-service; `user/raw_email.go`

**Message recall (post-delivery)**
- `POST /messages/{id}/recall`; `user/recall.go` → `recall_message()` reducer (ARCH-002 — no raw cross-mailbox UPDATE in Go). Handler keeps the `isSender` + 5-min-window pre-checks as defense-in-depth, then routes the recall through the reducer (the structural gate). Recall is **unread-only + local-only + soft-to-Trash + visible stub** (the residual bound — Message-ID is forgeable; see `retired-docs:superpowers/plans/archive/2026-06-19-recall-harden.md`). The HTTP response is caller-safe `{status, recalled}` only (no cross-mailbox count / recipient list — that is a recipient-enumeration oracle); verdict→status: success→200, notFound→404, alreadyRecalled→409, disabled→404. `sql/reducers/recall.sql`.

**Sender allow/block lists**
- Per-user allow list (never-block) and block list at `GET/PUT /settings/senders`; `user/sender_list.go`

**View preferences + IMAP visibility**
- `GET/PUT /settings/view` — view density, thread grouping; `user/view_prefs.go`. Includes `offlineWindow` (default `"30d"`) — the offline sync retention window requested by the client. Validated against the enum `{7d,30d,90d,180d,365d,all}` by `validOfflineWindow` in `view_prefs.go` (mirrors `lib/offline/window.ts OFFLINE_WINDOWS`); read by the webmail's sync engine to compute the cache cutoff. Back-filled from the default map when the stored row predates the field.
- `GET/PUT /settings/imap` — IMAP folder visibility flags; `user/imap_settings.go`

**Migration (Phase 18)**
- Self-service user migration: IMAP, EWS (Exchange), Microsoft Graph / M365
- ICS calendar import, VCF contact import
- PST file import: `internal/pst/` — Microsoft Outlook PST parser
- Orchestrator: `internal/migration/orchestrator.go` dispatching on source_type
- Admin job control: list, cancel, retry, pause, resume; `admin/` + `user/migration.go`
- Admin bulk actions: `POST /admin/migration/test-connection` + `POST /admin/migration/start` (one job per target); `internal/migration/admin_api.go` (`migration.AdminAPI`), both `mail.pipeline`-gated
- Global source configs stored encrypted in `system_config` (EWS, M365)
- Admin-scoped: `PUT /admin/migration/source/{type}`, M365 OAuth consent flow
- **M365 admin-consent states (`V234` + reducers, med-shard2-023 SHIP)**: the consent lifecycle is reducer-authoritative — `m365_consent_state_mint` (one server-side single-use expiring state + same-actor spent/expired prune in one tx, DB-clock expiry), `m365_consent_state_consume` (guarded consumption commits before OAuth verification, so a competing callback can never double-consume; consumption deliberately survives verification failure), `m365_consent_complete` (final config+audit in one tx). The gateway (`internal/user` M365Connect) only orchestrates: random 32-byte token, calls mint inside `dbscope.RunUserScoped`; ownership (`actor_user_id`) is bound in every statement (R1/R3), never GUC-only. V234 is ENABLE+FORCE RLS with actor equality in `USING`/`WITH CHECK` (denial, not filtering). pgTAP covers replay/verify-failure; concurrent same-token exactly-one-winner is reducer-guaranteed.
- Operator docs + source×capability coverage matrix (mail/calendar/contacts/delta/rules, all 3 connectors + Zimbra): `docs/guides/M365_MIGRATION.md`. No native Zimbra connector — deliberate (ACCEPTED-RISK, `docs/audit/2026-07-04-ga-gap-list.md` G0-007): Zimbra migrates via the generic IMAP connector + `.ics`/`.vcf` upload, documented as a runbook in that guide. EWS's `SyncFolderItems`/`FetchDeltaItems` is built + tested but does **not** implement `DeltaLinker` — unlike M365, it is not orchestrator-wired for incremental resync (one-shot bulk pull only; M365 is the only connector with real delta resume via `orchestrator.go`'s `DeltaLinker` restore/persist).

**App passwords**
- Per-app scoped HTTP Basic credentials; no TOTP bypass; time-limited or permanent
- `GET/POST/DELETE /auth/me/app-passwords`; admin oversight at `/admin/users/{id}/app-passwords`
- `user/app_passwords.go`, `admin/admin_app_passwords.go`

**User webhooks**
- User-scoped outgoing webhooks with HMAC-SHA256 signing; self-service creation is always explicit `scope=self`
- `POST/GET/DELETE /auth/me/webhooks`; `user/user_webhooks.go`

**Org chart + directory**
- `GET /auth/me/org-chart` → recursive manager/reports chains; `user/org_chart.go`
- `DirectorySidebar.svelte`, `DirectoryMemberList.svelte`, `OrgChart.svelte`

**Security score**
- Per-user security posture score (MFA enrollment, passkeys, recent activity)
- `GET /user/security-score`; `user/security_score.go`

**Login history + device management**
- `GET /user/login-history`, `POST /user/login-history/{id}/report`
- `GET /user/devices`, `DELETE /user/devices/{fingerprint}/sessions`
- `user/login_history.go`, `user/devices.go`

**Notification preferences**
- Push, email, DND scheduling, per-device preferences
- `GET/PUT /user/notification-preferences`; `user/notification_prefs.go`
- Also carries the per-user `read_receipt_policy` (Track A privacy; `ask`/`always`/`never`). PUT validates the value and, when omitted, defaults to `ask` on insert but **preserves** the existing value on update (so saving unrelated notification prefs never resets the receipt choice) — this preserve-on-update contract only actually held for the global (NULL `device_fingerprint`) row after **V123** (`sql/dbschema/V123__notification_prefs_dedup.sql`) fixed a pre-existing bug: `user_notification_prefs`' `UNIQUE(user_id, device_fingerprint)` was a PLAIN unique constraint, and Postgres treats every NULL as distinct from every other NULL under a plain UNIQUE, so `ON CONFLICT (user_id, device_fingerprint) DO UPDATE` (SetPrefs' only write path) never actually conflicted for the global row — every save silently INSERTed a duplicate instead of updating one, and GetPrefs's `ORDER BY device_fingerprint NULLS FIRST` (no secondary sort key) then returned an arbitrary tie. V123 switches to `NULLS NOT DISTINCT` (PG15+, already used at V015/V041/V109) after a dedup DELETE for any deployment that already accumulated duplicates.
- **VIP senders (QoL #10a)**: `GET/PUT /user/vip-senders` on the same handler → `vip_sender_set`/`vip_senders_list` reducers (`sql/reducers/vip_senders.sql`), table `vip_senders` (V106, per-user FORCE RLS, `sql/dbschema/V106__vip_senders.sql`). Deliberately reuses `user_notification_prefs` + the existing Muted-tag mute-thread path rather than a new prefs table (H3). Webmail: star toggle in `SenderCard.svelte` (`$lib/stores/vipSenders.svelte.ts`), VIP filter chip in the inbox topbar (hidden until ≥1 VIP; composes a single `from:` search term — ponytail, no OR-of-senders in v1).

### 4.3 Security features

**SMTP inbound pipeline checks** (all in `internal/smtp/`)
- SPF (RFC 7208) — `spf.go`
- DKIM (RFC 6376) + ARC (RFC 8617) — `dkim.go`, `arc.go`
- DMARC (RFC 7489) + DMARC aggregate report receiver — `dmarc.go`, `dmarc_report.go`; feature-toggle gated (`feature.dmarc_reporting`)
- Greylisting
- RBL / Spamhaus DROP
- ClamAV antivirus — `clamav.go`
- Milter protocol support
- Attachment sandbox (CAPE behavioral analysis) — `sandbox.go`; fail-open by default
- Anti-phishing: display-name spoofing (`antiphish_display.go`), lookalike domain detection (`antiphish_lookalike.go`), contact trust checks (`antiphish_contact.go`), confusable Unicode characters (`confusables.go`)

**Outbound security**
- DKIM signing — `pipeline_modify_dkim.go`; per-domain keys managed via admin
- DANE/TLSA verification — `dane.go`
- MTA-STS policy enforcement — `mtasts.go`
- TLS-RPT report submission — `tlsrpt.go`; feature-toggle gated
- Outbound TLS policy per domain — `tls_policy.go`; admin at `GET/PUT /admin/outbound-tls-policy`

**Link protection**
- URL rewriting to signed `/link-protect` redirect; Google Safe Browsing + Spamhaus DBL scanners
- `internal/linkprotect/`; click audit log at `/admin/link-protect/audit`

**S/MIME**
- Per-user certificate upload, signing, verification
- `internal/smime/`, `admin/admin_smime.go`
- User CRUD at `/auth/me/smime/certs`
- Inbound verify (`feature.smime_verify`) chains against **per-recipient-domain** trust pools: bundled Mozilla roots ∪ deployment-wide anchors (`smime_trust_anchors.domain_id IS NULL`) ∪ the recipient domain's anchors — one tenant's imported root cannot grant trust in another. Built lazily + cached per domain in `InboundServer.smimeDomainPools` (RWMutex-guarded), cleared on the `smime_trust_changed` notify (admin trust-anchor CRUD emits it). Pool is never nil (fail-open → empty pool → untrusted, delivery proceeds). Round 6 (Astra HOLD): admin import persists ONE ROW PER CERTIFICATE of an uploaded PEM (each row its own single-cert PEM + fingerprint, via `smime.ParseAnchorChain`), and `smime.BuildTrustPool([]smime.AnchorPEM)` loads only certs whose DER fingerprint equals the authorizing row — a bundle can never smuggle unfingerprinted roots into a pool. `InboundServer.smimeAnchorTrustScope` resolves a validated chain's anchor into the tri-state `caldav.SmimeTrustScope` — unrestricted (bundled root via `smime.IsBundledRoot` or deployment-wide row), domain-scoped (tenant row's domains), or NONE (unknown/removed/unresolvable anchor or DB error — fail closed). Admin trust store: `admin/admin_trust_anchors.go`, `sql/dbschema/V015__smime_trust_anchors.sql`.

**WORM / S3 Object Lock (compliance)**
- Governance or compliance mode; configurable retention days (default 2557 / 7 years)
- `startup.InitWORM`; retention registry wired into blob handler
- `sql/dbschema/` (WORM schema integrated in initial schema)

**DLP (Data Loss Prevention)**
- Pattern library managed at `/admin/dlp/patterns`; applied inline on `send` reducer
- admin DLP config; `admin/admin_dlp.go`
- Consolidation migration: `V075__dlp_consolidate.sql`

**Threat interceptor (shared)**
- `shared/threat/interceptor.go` — 8-step pipeline: feed-block → IP-rules → geo-block → lockout → spray-detect → CAPTCHA → tarpit → rate-limit
- Wired into gateway at startup; also used by authserver
- Policy engine + conditional access: device trust, IP risk scoring, conditional access policies

**Conditional access policies (CA-F substrate — V025; CA-0a engine + write path)**
- Admin CRUD at `/admin/conditional-access/policies`; `admin/admin_conditional_access.go`. Create and Update each wrap `ca_policy_upsert` plus optional `set_session_control` in one transaction, so BZ098/BZ080 cannot commit a partial policy mutation.
- Break-glass read/write: `GET /admin/conditional-access/break-glass` (resolves set to display data) + `PUT /admin/conditional-access/break-glass` (calls `ca_break_glass_set` reducer); `ConditionalAccessHandler.GetBreakGlass`/`SetBreakGlass`. Gated: `access.policy_read`/`access.policy_write`. V222 serializes this write with policy and admin-authority mutations; deferred database validation rejects a commit that would remove the last enabled, permanent, non-JIT escape admin.
- Resolve-principals: `GET /admin/conditional-access/resolve-principals?users=…&groups=…` — batch id→display for exclude picker; `ConditionalAccessHandler.ResolvePrincipals`. Gated: `access.policy_read`.
- All CA routes now use `access.policy_read` (read) / `access.policy_write` (write) (adopted from CA-F §F5; replaced prior `requireAuthPerm`/`requireIdentityWrite`).
- **CA-F substrate (`V025__ca_foundation.sql`)**: `user_group_members` table (+ RLS FORCE); `user_devices.device_id` FK→`devices.id` (SET NULL; canonical device model F3); `oauth_tokens.family_id` (refresh-family UUID, inert until CA-3); `access.policy_read`/`access.policy_write` seeds in `admin_permissions`; `ca_fail_mode` seed in `system_config` (`"closed"` default); `ca_validate_policy_document(p_conditions jsonb, p_grants jsonb) RETURNS boolean` SQL allow-list CHECK helper (F6 mirror of `shared/threat/policyschema.go`).
- **`ca_notify_policy_change(p_reason TEXT)`** reducer (`reducers/ca_notify_policy_change.sql`): the single choke point that announces any CA policy mutation. Calls `app_notify('conditional_access', …)`. Error BZ079 on empty reason. All admin CA write paths call this reducer; both servers subscribe to the resulting NOTIFY.
- **`ca_break_glass_set(p_actor, p_ip, p_ids[])→VOID`** reducer: writes `system_config.ca_break_glass_user_ids`, appends `admin_audit_log` row, calls `PERFORM ca_notify_policy_change('break_glass_set')`. Requires non-empty array (22000). See `sql/AGENTS.md` for details.
- **`conditional_access` NOTIFY channel**: the single fixed channel both mailserver and authserver LISTEN on. Mailserver: `listener.Subscribe(ctx, "conditional_access", …)` calls `policyEngine.InvalidateCache()` + `policyStore.LoadBreakGlass` + `policyEngine.SetBreakGlass` (CA-0a Task 9). Authserver: same pattern in the LISTEN goroutine. `InvalidateCache()` flushes BOTH the policy-set cache and the F8 per-principal decision cache; `SetBreakGlass` refreshes the break-glass snapshot so changes propagate within the engine's TTL window.
- **`session_revoke` NOTIFY channel** (CA-3a): fixed global channel; gateway LISTENs once at startup and applies each `{user_id, scope, not_before, expires_at, jti?, family_id?}` payload to both `SessionDenylist` (indexed future request/handshake rejection) and the process-wide `ProtocolSessionRegistry` (immediate closure of established IMAP/SMTP/WS/SSE transports). Paired access/refresh tokens carry the same family; WS/SSE's client signal uses exact all/JTI/family semantics rather than a user-wide fallback. Missing-`iat` push tokens are refused. The 30 s reconcile repairs missed notifications; refreshes serialize and merge concurrent `Apply`, and both caches compact keys and prune expired enforcement. `revoke_user_sessions` is the sole producer: all scope is the complete user boundary and compacts to one watermark, family scope also revokes matching OAuth anchors, and JTI scope removes its persisted web session. V172 requires expiry and adds targeted indexes; audit evidence remains separate. Expired rows are pruned daily. Possession gate (V273): the same boundary also deletes the first-factor gate's artifacts — all scope deletes every `mfa_reauth_step_ups`/`webauthn_ceremonies` row for the user; family/JTI scopes delete the rows whose `refresh_family_id`/`session_jti` match (narrow predicate — no widening).
- **`sessions` table population (web-session-revoke Tier 1)**: authserver's `issueTokensWithFactors` now INSERTs one row per web login (id = the access token's jti); before this the table was only ever written by tests. `GET /user/sessions` (`internal/user/sessions.go` `SessionsHandler.List`) surfaces these alongside OAuth/IMAP families. `sessions_auth_method_check` (V001 baseline + V066 + V094) must stay a superset of every value authserver's `authMethodFromFactors` can emit.
- **Break-glass startup load (CA-0a Task 9)**: at startup (after `policyEngine.CheckFailModePosture()`), both mailserver and authserver call `policyStore.LoadBreakGlass(ctx)` and `policyEngine.SetBreakGlass(bg)` so the engine honours the break-glass set immediately on boot.
- **IMAP/SMTP post-auth gate (CA-F F1)**: after a successful LOGIN/AUTHENTICATE (IMAP) or AUTH PLAIN (SMTP submission), `threat.ThreatInterceptor.EvaluatePostAuth(ctx, &meta)` runs a user-scoped CA evaluation with resolved UserID/GroupIDs. A `threat.ActionReject` result disconnects the session. Wired at the IMAP LOGIN+AUTHENTICATE completion points and the SMTP PLAIN/LOGIN completion points.
- **`scripts/guards/check-migration-allocation.sh`**: CI guard (wired into `scripts/test.sh`) — confirms V025 is the true next-free migration and BZ079 is unused before CA-F allocation. Self-tested by `check-migration-allocation-selftest.sh`.
- **CA-0b sign-in log (`V027__ca_signin_log.sql`, CA-F §6 structured-decision-log)**: the `ca_signin_log` table is append-only telemetry (BZ083 on UPDATE or unauthorized DELETE — see [`docs/reducer-error-codes.md#BZ083`](../docs/reducer-error-codes.md#BZ083)). Each row records: `user_id`, `source_ip`, `protocol`, `client_type`, `device_fp`, `country`, `matched_policy_id`, `decision`, `report_only`, `evaluated` (jsonb — ordered per-policy outcome trace: `applied`/`would_block`/`would_step_up`/`would_notify`/`skipped`/`excluded`), `correlation_id` (opaque `CA-<hex>` reference minted on enforcing or report-only evaluations), `occurred_at`. No hash-chain; retention pruned by the `prune-ca-signin-log` cron (see below). **CA-F §6 satisfied**: `ca_signin_log` records all resolved attributes (trust_tier, ip_band/score, geo_tier, auth_method/acr via `evaluated` jsonb + `protocol`/`client_type`), matched `policy_id`, decision, principal, source_ip, ts, report_only flag, and correlation_id — the structured decision log the CA-F §6/CONDITIONAL_ACCESS_BREAK_GLASS deferred TODO required.
- **`ca_signin_log_append(p_row jsonb)→VOID`** reducer (`reducers/ca_signin_log_append.sql`): the single write seam for telemetry rows; called by `shared/threat/recorder.go` (`pgxSignInRecorder`). Best-effort — a write failure is logged and never blocks the sign-in.
- **`ca_signin_log_prune(p_retain_days int)→VOID`** reducer (`reducers/ca_signin_log_prune.sql`): deletes rows older than `p_retain_days` days. Must run on the `DB_WORKER_DSN` (`setjoin_worker`, BYPASSRLS) pool — `setjoin_app` cannot DELETE from `ca_signin_log` (BZ083). Wired as the `prune-ca-signin-log` cron task (`internal/cron/tasks.go`, daily at 03:45, retention from `system_config.ca_signin_log_retain_days`, default 30 days).
- **`GET /admin/conditional-access/signin-log`** endpoint (`ConditionalAccessHandler.SignInLog`): returns recent `ca_signin_log` rows filtered by `user_id` OR `correlation_id` query param (one required). Gated: `access.policy_read`. Direct SELECT on `ca_signin_log` — no reducer (read-only telemetry query). Limit 200 rows; ordered by `occurred_at DESC`. **⚠ IMAP/SMTP caveat (CA-F F1 pending)**: `ca_signin_log` records evaluations at the **web-login seam only** (HTTP auth chain + IMAP/SMTP post-auth gate via `threat.ThreatInterceptor`). IMAP and SMTP logins produce rows with `user_id=NULL` until CA-F §F1 (post-auth identity injection) lands — the `EvaluatePostAuth` pass today resolves group memberships but the `ca_signin_log` recorder does not yet receive the resolved `UserID` from that path. A `user_id`-filtered trace returns empty for IMAP/SMTP protocol logins until CA-F §F1 ships. Verify report-only policies over web login; IMAP/SMTP trace requires the `correlation_id` lookup path.
- **Named locations (CA-1 D1)** (`admin/admin_named_locations.go`, `NamedLocationsHandler`): CRUD for `named_locations` rows (IP ranges + country codes). Routes: `GET /admin/conditional-access/named-locations` (list; `?include_deleted=1` for tombstoned), `POST` (create), `PUT /{id}` (update), `DELETE /{id}` (soft-delete via `ca_named_location_set(p_deleted=true)`), `POST /{id}/restore` (clear `deleted_at` + audit log + notify). Reducers: `ca_named_location_set`. Gated: read (`access.policy_read`) / write (`access.policy_write`).
- **Auth strengths (CA-1 D1)** (`admin/admin_auth_strengths.go`, `AuthStrengthsHandler`): CRUD for `auth_strengths` rows (authenticator-combination requirements). Routes: `GET /admin/conditional-access/auth-strengths` (list built-in + custom), `POST` (create custom), `PUT /{id}` (update custom), `DELETE /{id}` (custom only; built-in → 400 via reducer EXCEPTION). Reducers: `ca_auth_strength_set`. Gated: read / write. Built-in delete guard: reducer raises plain EXCEPTION (`cannot delete built-in auth strength`) → `caAuthStrengthErrorStatus` maps to 400.
- **What-If simulator (CA-1 D6)** (`admin/admin_ca_simulate.go`, `CASimulateHandler`): `POST /admin/conditional-access/simulate`. Accepts a hypothetical `PolicyEvalContext` (user_id, ip, client_type, country, device_fp, auth_method, protocol, user_agent; `from_signin:<id>` seeds from a `ca_signin_log` row). Loads a **fresh uncached** policy/location/strength snapshot, calls `engine.SimulateWithPolicies` (added to `shared/threat/policy.go`), and returns `{matched_policy, decision, grants[], evaluated[{policy_id,name,priority,scope,outcome,first_failed}]}`. `first_failed` names the failing condition key (`"client_type"`, `"country_in"`, etc.) or `"scope:<type>"` for a scope miss. NO-MATCH → `matched_policy:null, decision:"applied"` (calm path). Read-only — no enforcement, no `ca_signin_log` append. Gated: `access.policy_read`. Engine extension: `SimulateEntry`, `SimulateResult`, `PolicyEngine.SimulateWithPolicies` added to `shared/threat/policy.go` (calls `matchAllVerbose` for first_failed annotation).
- **Doctor health check (CA-1 G1)** (`admin/admin_ca_doctor.go`, `CADoctorHandler`): `GET /admin/conditional-access/doctor`. Aggregates 4 read-only checks into a health score + per-gap next-actions: `feature_on` (feature_toggles), `break_glass_configured` (system_config), `has_report_only_policy` (conditional_access_policies), `no_coverage_gaps` (ca_coverage_report()). Also surfaces policy hygiene (`stale_report_only` = report_only policies older than 30 days) and `time_to_first_policy_sec` (interval from first `ca_policy_upsert` to first `ca_policy_promote` in admin_audit_log). Returns `{score, total, checks:[{name, passed, next_action}], hygiene:{stale_report_only:[...]}, time_to_first_policy_sec}`. Passed checks omit `next_action`. Read-only — no audit / no notify. Gated: `requireCAPolicyRead`. Exit non-zero via `caDoctorCmd` when score < total.

**Device lockdown (CA-2 — 终端安全)** — `feature.device_lockdown` (DEFAULT OFF via the toggle registry; fail-closed)
- **`DeviceLockdownGate`** (`internal/middleware/device_trust_gate.go`) — strict HTTP gate: blocks unenrolled/unbound devices at 403 BZ095 when lockdown is ON. Build-gate (Decision-9): refuses to enforce unless `ca_break_glass_user_ids` is non-empty in `system_config`. Layered AFTER `DeviceTrustGate` on the authenticated chain in `main.go`. See `mailserver/internal/AGENTS.md` middleware entry.
- **IMAP/SMTP enforcement**: `ConnectionMeta.DeviceBound=false` / `DeviceID=0` set for IMAP and SMTP connections (legacy protocols cannot carry X-Device-* headers); `EvaluatePostAuth` blocks them when a `client_type:legacy` policy is enforcing. `user_imap_settings.imap_enabled` (V033) is a per-user IMAP kill switch (default `true`).
- **Admin device endpoints** (`admin/admin_device_lockdown.go`): `GET /admin/devices/queue` (approval queue), `GET /admin/devices?user_id=` (by-user list), `POST /admin/devices/{id}/enroll|approve|revoke` (lifecycle via `device_enroll_transition` reducer; BZ095 → 409). `mam.read` / `mam.write`.
- **Webmail device-approval console** (`src/routes/admin/device-lockdown/+page.svelte`): DeviceEnrollBadge state map, two-tab queue/by-user layout, revoke-confirm dialog. End-user lockout screen shown when the bridge cannot produce a device proof under lockdown (DeviceNotApprovedBanner / lockout route).
- **`effective_capabilities` block**: `device_lockdown` boolean emitted in the `features` block of the JMAP session capabilities (default `false`); the SPA reads it to decide whether to show the lockout screen / request deviceProof from the `window.setjoinNative` bridge.
- **Schema**: V033 (`devices` enrollment columns, `device_enroll_events`, `user_imap_settings.imap_enabled`, toggle seed, `device-lockdown` ca_template). V034 (`ca_validate_policy_document` updated for `device_bound` / `require_compliant_device`). Reducer: `device_enroll_transition` (BZ095). Tests: `device_lockdown_schema.pg`, `device_enroll_transition.pg`, `ca_template_instantiate.pg` (17/17).

**Mobile Device Management (MDM / MAM)**
- Device check-in, policy engine, compliance evaluation, remote wipe
- `internal/mdm/`: `engine.go`, `mam_policy.go`, `conditional_access.go`, `device_identity.go`, `policy_push.go`
- Admin UI at `/admin/mam`. Admin mutations emit a `device_policy` `pg_notify` (`mdm.NotifyPolicyChange`); the gateway LISTENs and logs it for observability, but does **not** yet push it to WebSocket clients — the JMAP WS path is mailbox-keyed (`tag:{mailbox_id}` → StateChange) and `device_policy` is a global/per-device broadcast with no StateChange mapping or deviceID→connection routing. Clients pick up changes on their next MAM check-in (`internal/mdm/checkin.go`). Real-time WS push is unwired (would need new push plumbing). See the NOTE on `mdm.PolicyChangeNotification`.
- Schema: `V029__mdm_schema.sql`, `V060__mam_policy_engine.sql`

**ACME / TLS certificate management**
- Let's Encrypt autocert via TLS-ALPN-01, HTTP-01, or DNS-01 (lego multi-provider)
- Stable TLSA SPKI hash via key reuse or 2×TLSA rolling rollout
- Admin import of static certs; TLS status/config at `/admin/tls/`
- `internal/acme/`, `internal/tlsutil/`

**GeoIP blocking**
- DB-IP Lite auto-downloaded at startup; `internal/geoip/`
- Country block list via `GEO_BLOCK_COUNTRIES` env or conditional access policy

**Auth log**
- Full auth event log at `/admin/auth-log`; `admin/admin_auth_log.go`

### 4.4 Compliance features

**Journaling (BCC archive)**
- Policy-based journaling: match by direction (inbound/outbound/all), domain, user
- `journal_if_policy_matches` reducer + `drain_journal_queue` cron
- `sql/reducers/journal.sql`

**Retention management**
- Per-domain and global retention policies; litigation hold exemption
- `tag_retention` at delivery; `enforce_retention` cron hard-deletes expired messages
- Admin CRUD at `/admin/retention/policies`; `admin/admin_retention.go`
- MRM templates for named policy sets; `admin/admin_templates.go`

**eDiscovery**
- KQL (Keyword Query Language) parser: `internal/kql/`
- `POST /admin/ediscovery/search` — search across mailboxes; export selected; legal hold
- Case management: `/admin/ediscovery/cases` CRUD
- `admin/admin_ediscovery.go`, `admin/admin_ediscovery_cases.go`

**Content Search & Purge**
- Admin hard-delete across mailboxes: `POST /admin/content-search/delete`
- `content_purge_messages` reducer logs single audit entry; skips litigation-held messages
- `admin/admin_content_search.go`, `sql/reducers/content_purge.sql`

**Audit log**
- Append-only `admin_audit_log` table (trigger blocks UPDATE/DELETE)
- CSV export; cryptographic chain verification (`GET /admin/audit/verify`)
- `admin/admin_audit.go`; schema: `V050__admin_audit_log.sql`
- Audit policy singleton (`audit_policy` table, `V038__audit_policy.sql`): `GET/PUT /admin/audit/policy` — level (`lean`/`full`) + reason-required areas; PUT gated `audit.export`, always requires non-empty reason, self-audits with before/after core entry. Handler: `admin/audit_policy.go`.

**WORM immutability** — see Security features above.

**Xinchuang (国产) compliance**
- `internal/xinchuang/db/` — PostgreSQL adapter, error map, NOTIFY bridge
- Supports domestic Chinese platform requirements

### 4.5 Admin capabilities

**Users + mailboxes**
- Full CRUD: `/admin/users`, `/admin/mailboxes`; CSV import
- Alias management; quota per user; password reset
- Folder management per mailbox (create, update, delete)
- Import/export per mailbox (`.eml` / ICS / VCF)
- `admin/admin_users.go`, `admin/admin_mailboxes.go`, `admin/admin_import_export.go`

**Domains**
- Domain CRUD at `/admin/domains`; per-domain settings (greylisting, DLP, retention)
- `admin/admin_domains.go`

**Departments**
- Hierarchical department tree; user assignment; org chart backing store
- `/admin/departments`; `admin/admin_departments.go`

**Rules engine**
- Admin transport rules + per-user rules; OR grouping; stop-processing flag
- Rule templates with visibility control; test endpoint
- `/admin/rules`, `/admin/rule-templates`; `user/rules.go`
- End-user own-rule CRUD at `/settings/rules*` (`user/user_rules.go`, non-transport, own-mailbox-scoped)
- **Apply rule retroactively (QoL #5)**: `POST /settings/rules/{id}/apply {window: 90d|1y|all}` → 202 + action id; `GET /settings/rules/apply/{actionId}` polls progress. Async via a `rules_retro` scheduled_action (`rules_apply_retroactive` enqueuer → `scheduled_action_rules_retro` handler, dispatched by the 1-min `dispatch-scheduled-actions` cron). The handler batches the mailbox's messages in the window through `apply_rules(p_organize_only=>TRUE, p_rule_id)` — **organize-only suppresses send-time actions (forward_to/redirect/bcc/append_footer/add_header) so no historical mail is re-sent** — caps at 5000 with a `truncated` flag, R1-scoped throughout. `apply_rules`/`apply_action` gained `p_organize_only` + (apply_rules) `p_rule_id` params, defaulted so the delivery/send call sites are unchanged.

**DNS wizard**
- Generate and verify SPF/DKIM/DMARC/MX/TLSA DNS records
- `GET /admin/dns/records`, `GET /admin/dns/verify`; `admin/admin_dns.go`

**DMARC dashboard**
- Live feed + failure details + trend; `admin/admin_dmarc.go`

**Spam classifier dashboard**
- Per-user Bayesian model management; reset/disable/enable
- `GET /admin/spam`; `admin/admin_spam.go`

**Outbound queue dashboard**
- List, force-retry, bounce; `/admin/queue`; `admin/admin_queue.go`

**Quarantine**
- Admin: list, preview, release, reject; `/admin/quarantine`. **Preview returns RAW stored `body_html`** (no server-side sanitize/mutation — forensic fidelity). The webmail client sanitizes (DOMPurify) + sandboxes + CSP-locks the render; the prior false-safety string-replace blocklist in `admin_quarantine.go` was deleted (2026-06-19; see CONTEXT.md "Layered containment for untrusted HTML").
- User self-service: list count, release, reject; `/quarantine`; `user/quarantine.go`
- User spam/phishing report: `POST /report`; `user/report.go`

**SMTP pipeline config**

**Anti-phishing config**
- Domain-level protection; `GET/PUT /admin/anti-phish`; `admin/admin_antiphish.go`

**Message trace**
- Per-message delivery trace events (SMTP inbound, rules, delivery, errors)
- `GET /admin/trace`, export CSV; `admin/admin_trace.go`

**Alerts**
- Health-check-driven alerts; acknowledge, unsuppress, configure thresholds
- `/admin/alerts`; `admin/admin_alerts.go`

**Reports**
- Summary reports (message volume, spam, quota); `admin/admin_reports.go`

**Live monitor**
- Real-time protocol connection stats; `GET /admin/monitor/live`; `admin/admin_monitor.go`

**Branding**
- Logo upload, color, org name; stored in S3 blob store
- `GET/POST /admin/branding`; `admin/admin_branding.go`

**AD sync**
- LDAPS sync of Active Directory identities; paged search; `uSNChanged` delta cursor
- Config, test, sync-now, log, health, conflict resolution, field policy
- `admin/admin_ad.go`; `internal/ad/`
- Normalized sources honor the catalog's exact host/port, `ldaps|starttls|none`
  transport, base DN, user filter, and `objectGUID|msDS-ConsistencyGuid`
  immutable anchor. The legacy singleton/domain-discovery constructor remains
  only for the compatibility path.

**LDAP sync**
- Generic LDAP identity sync; `internal/ldapsync/`
- `admin/admin_ldap.go`; same admin API shape as AD sync
- Normalized sources honor the exact endpoint/TLS mode, base DN, user filter,
  and operator-approved immutable subject; no DN/email fallback is permitted.

**Auth methods**
- List and update per-method config (Basic, Kerberos, etc.)
- `GET/PUT /admin/auth/methods`; `admin/admin_auth.go`

**Identity + RBAC**
- SAML/OIDC group-to-role mappings; `admin/admin_identity.go`
- Role CRUD + member assignment; `admin/admin_roles.go`. Mutating endpoints enforce **P2 hardening** (spec `2026-06-21-rbac-role-editor-design.md` §9): **grant-only-what-you-hold** (CreateRole/UpdateRole reject any permission the acting admin does not hold via `claims.HasPermission`; AssignMember fetches the role's permissions and rejects if the actor lacks any → 403) and **mutation-scope-confinement** (only when `middleware.DomainScopeFromContext > 0`: a scoped admin may create/edit/delete only roles whose `domain_scope` equals their scope — out-of-scope roles are 404, never leaked — and may assign only in-scope target users to roles whose effective `COALESCE(domain_override, domain_scope)` equals their scope). UpdateRole, DeleteRole, and AssignMember acquire the V172 `admin_authority_fence` immediately after opening their transaction and before any role/principal/scope `FOR UPDATE`, preserving advisory→row order with assignment/group triggers. The legacy `IsAdmin`/super-admin bridge holds all perms and is unscoped, so both authorization rules are inert for it.

**Email Address Policies** (`internal/admin/admin_email_address_policy.go`, `internal/eapjobs/worker.go`)
- Conditional policy engine: condition→template→priority; CJK pinyin via `cjk_to_ascii`
- REST CRUD + preview + match-count + bulk-apply enqueue + reorder: `GET/POST /admin/email-address-policies`, `PUT/DELETE /admin/email-address-policies/{id}`, `/reorder`, `/{id}/preview`, `/match-count`, `/apply`, `/apply/{jobId}`
- Async apply worker (`eapjobs.NewWorker`): drains `eap_apply_jobs` (status=`queued`) by calling `email_address_policy_apply_bulk`; started as a goroutine in `cmd/mailserverd/main.go`; uses the `DB_WORKER_DSN` (worker pool)
- Gated by `feature.email_address_policy` toggle (DEFAULT OFF); per-recipient opt-out via `users.address_policy_enabled`

**Feature toggles**
- Live enable/disable of feature flags stored in `feature_toggles` DB table
- `GET /admin/features`, `PUT /admin/features/{key}`; changes propagated via `config_changed` NOTIFY. Each list row additively projects the shared operator semantics (`changeMode`, `disableBehavior`, non-null `dependencies`, `confirmationRequired`) without changing the behavior registry digest or generated SQL. Unknown/unannotated keys project no warning semantics. Webmail and mailctl consume this server-owned metadata rather than maintaining key-name heuristics.
- **Exception — `dengbao.sod_mode` (等保三级 SoD):** the generic `PUT /admin/features/{key}` **refuses** this key (4xx). It is flipped only via the dedicated gated route `PUT /admin/dengbao/sod-mode` (`admin.SodModeHandler`, gated on `security.write` not a role), which runs `admin_sod_precheck()` + the toggle UPDATE in **one transaction** — any precheck violation rolls back and returns 409 (toggle stays OFF); a clean precheck commits + writes an `admin_audit_log` row. Turning OFF is unconditional + audited. (Historical note: the legacy `is_admin`→`AllPermissions` bridge and the SSO `users.admin_role` write path the SoD gate once tightened are both GONE — the RBAC cut-over deleted the bridge and `V017` dropped `users.admin_role`; authorization is now pure permission-set membership, and SSO group→role writes target governed `admin_role_assignments`.) Toggle key constant: `toggle.FeatureDengbaoSodMode` / `admin.SodModeToggleKey` (DEFAULT OFF).

**Config management**
- Key/value `system_config` table; get/set/export/import
- SIGHUP or `POST /admin/reload` for hot reload

**Storage (SeaweedFS)**
- Status, DR scan (integrity check), reconcile, blob-level storage migration
- `/admin/storage/`; `admin/admin_storage.go`, `admin/admin_storage_migrate.go`

**Backup + disaster recovery** (the ARCH-007 collapse had dropped the `backup_runs` table, leaving this dormant; rebuilt 2026-06-21)
- **Blob backup to S3/OSS/B2.** A `backup_runs` row — admin `POST /admin/system/backup` or a scheduled insert — fires `trg_backup_runs_notify` → the worker CAS-claims it (single-flight; a startup drain reprocesses stranded `pending` rows), snapshots live blobs, idempotently copies them (HeadObject **size**-skip + post-write size check), emits the manifest set (`manifests/incr-<ts>.json`, `config-<ts>.json`, the `backup-manifest-<ts>.json` index + the `backup-manifest.json` latest pointer written LAST as the commit point), mirrors to the optional cross-region replica (async, best-effort), then applies **real GFS tiered retention** (the `7d4w12m` counts are tier depths — retain the newest run per the most-recent `daily` distinct days, `weekly` distinct ISO-weeks, `monthly` distinct months; prune only runs in no retained bucket, so old monthly snapshots survive — prunes index objects, never blobs; per pruned run the secondary incr/config objects delete FIRST and the self-contained `backup-manifest-<ts>.json` index LAST, and the run's remaining deletes abort at the first failure: the `backup_runs` row is removed only after every object delete of that run succeeded (D-MAILSERVER-INTERNAL-BACKUP-F-003), so a failed pass keeps row + surviving objects for the next-pass retry). Restore treats that embedded manifest as integrity evidence only: it automatically applies reducer-classified safe configuration and quarantines every operator-approved/protected/unknown row; no public boolean can promote an embedded-only backup to a trusted source.
- **OSS driver transport posture** (storage-s3-plaintext-downgrade SHIP): empty `Endpoint` with explicit `Secure=false` is rejected before client construction (the region-derived default endpoint is always TLS); nil/true keep TLS — same contract as the backup-S3 constructor, enforced in direct construction and `NewDriver`. Loopback-HTTP compatibility and both scheme-conflict rejections unchanged. Migration `setStatus` detached writes are timeout-bounded (10s) and never silently ignored (errors log migration ID + intended status for reconciliation).
- **Restore.** `mailctl restore` drives the gateway setup-mode `POST /setup/{preflight,restore}` for config + blob restore (`internal/restore`, SHA-256-verified, hash-validated, single-flight). The full DB dump/restore (`pg_dump`/`pg_restore`) is operator-run via `mailctl backup-db`/`restore` with operator creds — the gateway's `setjoin_app` role is RLS-constrained, so it cannot dump every row. A full restore does blob-restore-through-the-gateway FIRST (while the system is empty, past the no-users guard) then `pg_restore`.
- **Encrypted-at-rest mail = two non-blob backup dependencies (SP1).** S/MIME recipient-encrypted mail (SP1) stores ONLY ciphertext in the blob and NULLs the body columns. Recovering it needs two secrets that live **outside** the blob store the Engine snapshots: (1) `user_smime_certs.private_key_enc` — per-user keys encrypted via `pgp_sym_encrypt` (`admin/admin_smime.go`), captured ONLY by the `pg_dump` (NOT the blob snapshot); and (2) `DB_ENCRYPTION_KEY` (= the `app.encryption_key` GUC set per-connection in `internal/db/pool.go`), captured by NO backup artifact at all — it must be stored separately in the operator secret store. Lose the key ⇒ every `private_key_enc` is undecryptable ⇒ every encrypted-at-rest body is permanently unrecoverable. The DR runbook MUST restore `DB_ENCRYPTION_KEY` before starting `mailserverd`. Full detail + the planned P5 post-restore zero-decryptable-rows assertion: `retired-docs:superpowers/plans/archive/2026-06-21-backup-restore-dr.md` §"S/MIME keystore + encryption key — permanent-loss risk".
- Design: `docs/design/archive/storage-ha-backup-restore.md`, `docs/design/mail/archive/mailctl-restore-lock-replication.md`. Plan: `retired-docs:superpowers/plans/archive/2026-06-21-backup-restore-dr.md`.
- `internal/backup/engine.go`, `internal/restore/engine.go`
- Admin: `POST /admin/system/backup`, list, download, delete
- WORM Object Lock on backup bucket: governance or compliance mode; configurable retention days

**HA Deploy wizard (Phase 37)**
- SeaweedFS HA deployment planner; scale-up/scale-down; systemd unit generation
- `GET/POST/DELETE /admin/deploy/`; `admin/admin_deploy.go`, `internal/deploy/`

**System + upgrade**
- The legacy `POST /admin/system/upgrade/{check,apply,rollback}` compatibility routes fail closed with typed RFC 7807 `410 Gone` before parsing input or touching the filesystem/database. `GET /admin/system/upgrade/status` remains read-only. No web or CLI path accepts a caller binary/path mutation.
- U0/V178 provides signed Community/Enterprise release and intent authority. U1 adds the root-owned no-listener observer, isolated updater credential, journal, and recovery guide. U2 adds immutable staging/adoption, fixed migration/systemd/rollback adapters, and `/usr/libexec/setjoin-recovery`. U3/V179 binds the current database timeline, HMACed application recovery set, exact intent recovery UUID/digest, and separate isolated restore proof; `shared/recoveryset` is the portable verifier. U4 exposes only bounded reducer-authoritative `/admin/system/upgrades*` routes for console/preview/challenge/intent/cancel/diagnostics/recovery evidence. V183+ release manifests additionally bind feature-registry digest/mode/rollback compatibility; updater preflight checks it before host mutation and rechecks post-commit/rollback. The daemon loads its fixed compiled mutation catalog only when root execution config, database execution gate, and verified recovery evidence all agree. Disposable-Ubuntu recovery/switch/rollback and the bilingual browser state matrix pass; production rollout flags remain OFF.
- The old path-based auto-update and separate maintenance-window routes remain authenticated compatibility shells only: every method returns typed RFC 7807 `410 Gone` before parsing or persistence and points operators to `/admin/updates/server`. No caller-controlled path can reach updater execution.
- `/admin/system/upgrade/`, `/admin/system/auto-update`, `/admin/system/maintenance-window`; `admin/admin_upgrade.go`, `admin/admin_autoupdate.go`

**Webhooks**
- Admin-scoped outgoing webhooks + HMAC-SHA256 signing; event catalog; delivery log. Admin creation may explicitly select `self` or `organization`; all pre-V211 rows default to `self` and intended organization subscriptions must be recreated explicitly.
- `/admin/webhooks`; `admin/admin_webhooks.go`; `internal/webhook/`
- `feature.webhook_publication_outbox` is DEFAULT OFF and gates only new durable enrollment. The unconditional WorkerPool drain converges committed residue. Delivery rows are atomically leased through the worker credential only when the fixed executor has capacity; active/retry policy and total attempts are rechecked at claim, and settlement is lease-owner fenced. Migrated groups include `user.created|updated|deleted`, `migration.completed|failed`, and committed `mail.received|mail.sent`. Mail facts are enrolled by worker-only protocol reducers with database-derived user/mailbox subjects; payload remains exact SMTP-envelope `{from,to}`, one stable event per recipient. Held/denied/system/local-fanout/group-recursion paths do not invent facts; scheduled and approved sends publish only when they actually commit. OFF compatibility dispatches only after commit through `DispatchForMailbox`. HTTP is at-least-once and receivers deduplicate by stable CloudEvent `id`. Operator contract: `docs/guides/WEBHOOK_DELIVERY.md`.

**Air-gap update feed**
- Admin uploads binary bundle; clients download locally (no internet required)
- `POST /admin/updates/airgap/upload`, `GET /updates/appcast`; `internal/updates/`

**Client version control**
- Track device update status; push update to specific devices
- `/admin/updates/`; `admin/admin_updates.go`

**Telemetry**
- Privacy-first device telemetry; no PII stored; admin opt-in via `device_telemetry` toggle
- `POST /telemetry`; `internal/telemetry/`

**Client download page**
- Desktop client distribution with version cache; `GET /downloads`; `internal/downloads/`

### 4.6 Discovery + well-known + the public booking surface

- `GET /.well-known/setjoin` — SetJoin client discovery (crypto profile, MAM, login field)
- `GET /api/discover` — SRV/MX/.well-known auto-discovery for client setup
- `GET /.well-known/jmap` — JMAP session discovery (auth required)
- `GET /.well-known/autoconfig/mail/config-v1.1.xml` — Thunderbird (and compatible clients') autoconfig, unauthenticated (`internal/wellknown/autoconfig.go`). `r.Host` (port stripped, lowercased) must match an `is_local=TRUE` row in `domains`, else plain `http.NotFound` (the consumer is an XML client, not JSON — no RFC7807 problem body). Renders Mozilla's config-v1.1 XML: IMAP prefers implicit TLS (993/SSL) when `IMAPTLSAddr` is configured else STARTTLS (143); SMTP submission prefers implicit TLS (465/SSL) when a TLS submission listener is configured else STARTTLS (587) — today there is no dedicated 465 submission listener in `config.go`, so it always advertises 587/STARTTLS until one is added. This `.well-known` path works zero-DNS on the primary vhost; the `autoconfig.<domain>` subdomain convention some clients also probe is an optional manual DNS/SAN step, not auto-provisioned. MS Autodiscover is out of scope.
- **`/api/public/booking/*` — the FIRST unauthenticated public app surface** (feature #6, `feature.booking_pages`, DEFAULT OFF; `internal/booking.PublicHandler`; mounted in `registerPublicRoutes` outside `requireAuth`, exactly like the routes above): `GET /{slug}` (page meta) · `GET /{slug}/slots` · `POST /{slug}/book` · `POST /confirm` · `POST /cancel`. Toggle-off and an unknown/disabled slug are byte-identical 404s (enumeration parity — no oracle for "does this org even have booking enabled"). Two dedicated `HybridRateLimiter`s (read 60/min, write 5/15min); the global `middleware.SecurityHeaders` CSP still applies (proven for this surface by a dedicated test, not assumed). Full threat model + the recommended reverse-proxy/vhost exposure pattern: `docs/adr/DES-007-public-booking-surface.md`.

### 4.7 First-boot setup

- `GET /` → 302 to `/setup` when no users exist (`needsSetup()` checks `SELECT COUNT(*) FROM users`)
- Public HTTP exposes only read-only `GET /setup/status`. The former public mutation routes are absent from the router and OpenAPI contract. The setup SPA is status/instructions only and never accepts bootstrap or restore secrets.
- `mailctl bootstrap-admin` connects through the local owner database credential. `ensure_default_admin` takes the transaction-scoped bootstrap advisory lock and atomically refuses creation when any user already exists.
- **Local restore control** (`cmd/mailserverd/setup_control.go`, `admin/admin_setup.go`, consuming `internal/restore.Engine`): `mailctl restore` dials the filesystem-permissioned Unix socket (`SETJOIN_CONTROL_SOCKET`, default `/run/setjoin/control.sock`; directory 0750, socket 0600). The socket alone mounts `POST /setup/preflight` and `POST /setup/restore`; the public TCP listener never does. Restore remains synchronous, re-checks the no-users rail, uses the reducer-authoritative single-flight job, and finalizes job state with a bounded request-independent context so a disconnected operator cannot strand the lease. Signed recovery trust, stored source profiles/secret references, and quarantine-on-untrusted-restore remain owned by the active security-boundary plan.
- `admin/admin_setup.go`; local control listener at `cmd/mailserverd/setup_control.go`; read-only setup SPA at `webmail/src/routes/setup/`

### 4.8 Webmail SPA (thin map — detail in `webmail/AGENTS.md`)

The production SPA responder is `cmd/mailserverd/static_responder.go`, shared
directly by production and table tests. At startup it validates the build-bound
representation manifest and refuses a mismatched/tampered artifact. It serves
Brotli, then gzip, then identity with representation-correct strong ETags and
`Vary: Accept-Encoding`; Range stays identity. Hashed `_app/immutable` assets
are one-year immutable, while HTML, the service worker, and mutable manifests
revalidate. Path containment and the pinned API/SPA fallback boundary remain
fail closed. Performance verification enters through
`bash scripts/ci/verify-webmail-performance.sh`; details are owned by the webmail
DOX and `docs/guides/WEBMAIL_PERFORMANCE_VERIFICATION.md`.

| Area | Routes | Key components |
|---|---|---|
| Inbox + mail | `/inbox`, `/quarantine` | `ComposeModal.svelte`, `ShadowDomEmail.svelte`, `EmailAnnotations.svelte`, `UndoToast.svelte`, `SnoozePicker.svelte`, `NewsletterBundle.svelte` |
| Calendar | `/calendar` | `CalendarApp.svelte` (+ `lib/components/calendar/`: `RecurrenceEditor.svelte`, `RoomFinder.svelte`, `ShareCalendarDialog.svelte`); RRULE compose/parse helper `lib/calendar/rrule.ts`. A3 wired: recurrence editor, occurrence-vs-series prompt, open-shared-calendar, share dialog, room finder, send-update, delegate respond, in-editor scheduling assistant |
| Contacts | `/contacts` | `DirectorySidebar.svelte`, `DirectoryMemberList.svelte` |
| Tasks | (integrated) | — |
| Directory | `/directory` | `OrgChart.svelte` |
| Settings | `/settings/**` | Language, TOTP, signatures, notifications, appearance, security score, login history, migration |
| Admin — mail | `/admin/(mail)/**` | users, mailboxes, domains, departments, rules, templates, quarantine, queue, reports, retention, DMARC, DNS, TLS, SMTP pipeline, spam, trace, migration, storage |
| Admin — identity | `/admin/(identity)/**` | auth methods, conditional access, identity / group mappings |
| Admin — system | `/admin/(system)/**` | features, alerts, deploy, system, updates, webhooks, logs, audit, eDiscovery, content-search, MAM, welcome email |
| UI library | `src/lib/components/ui/` | 28 primitives: Avatar, Badge, Button, Card, Checkbox, DateTimePicker, Dialog, EmptyState, IconButton, Input, Menu, Pagination, Progress, Radio, Resizer, Tooltip, + utilities |

---

## 5. Work Guidance

- All rules from root `AGENTS.md` apply here (DB security, PL/pgSQL conventions, webmail gates).
- Server-side Rust code, HTTP/protocol handlers, and background workers live under `server/` (see `server/AGENTS.md` and `server/bins/gateway/DOX.md`).
- When adding a reducer, update `sql/reducers/README.md` and the relevant pgTAP tests. Add a forward migration only for schema or seed changes; reducer-body updates are not migrations.
- Route inventory and OpenAPI coverage/visibility guards consume `server/bins/gateway/data/route-inventory.json` (validated against `server/bins/gateway/data/route_inventory.golden`).
- The expected database-schema version is **derived** from the embedded `V<NNN>__*.sql` files in `sql/dbschema/` via `server/crates/schema/` — adding a `V<NNN>__*.sql` bumps it automatically, with no manual constant to increment.

---

## 6. Verification

```bash
# Build Rust server binaries (setjoin-server, setjoin-auth, mailctl, asrbotd, setjoin-updater)
bash scripts/ci/build.sh

# Rust server tests and conformance gates
bash scripts/guards/check-server-rust.sh

# Reducer tests (requires test DB)
pg_prove -d mailserver_test sql/tests/*.pg

# Webmail type-check (must be 0 errors, 0 warnings)
cd mailserver/webmail && npm run check

# Webmail unit tests
cd mailserver/webmail && npm test

# Full suite
bash scripts/test.sh

# E2E protocol tests
bash scripts/dev/e2e.sh          # all
bash scripts/dev/e2e.sh imap
bash scripts/dev/e2e.sh smtp
bash scripts/dev/e2e.sh ldap
```

The IMAP E2E lane starts two loopback-only disposable servers: Alpine Dovecot
for plaintext protocol compatibility and the digest-pinned Apache James demo
for verified STARTTLS. Both consume the same three-message/flag fixture and
must pass connection, full fetch, cursor resume and bad-credential cases. The
test-only loopback dial injection does not relax the production migration SSRF
policy.

---
