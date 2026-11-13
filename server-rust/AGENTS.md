# server-rust — Rust server rewrite workspace (DOX child)

## Purpose

Source for the Go-free Rust server rewrite (spec #251). ARCH-029 (decision
on #231, superseding ARCH-026/027's rollout defaults) makes the front door ON
by default and transfers routes after parity. Reducers remain business
authority; each request has one writer. JMAP ignores its retired pilot flags;
see the [family contract](crates/domains/jmap/DOX.md).
[DOX.md](DOX.md) is the detailed provenance and qualification reference for the
workspace.

## Layout and ownership

- `Cargo.toml` — workspace (resolver 2, edition 2021, `rust-version` 1.97.1):
  - `bins/gateway` (`setjoin-gateway`, #220, [ARCH-027](../docs/adr/ARCH-027-rust-front-door-gateway.md))
    — Rust front door (#255): [contract](bins/gateway/DOX.md). Route inventory dispatch, proxy, workers (incl. notify/push drains, #408), auth upstream, first JMAP route.
  - `bins/asrbot` (`setjoin-asrbot`, #356) — Rust `asrbotd`, the Meet captions room bot: [contract](bins/asrbot/DOX.md).
  - `crates/authz` (`setjoin-authz`) — shared `authorize` chain; [contract](crates/authz/DOX.md#shared-authorize-chain-moved-verbatim-from-server-rustagentsmd-385).
  - `crates/contracts` (`setjoin-contracts`) — typed command/authority
    contracts (`SetMessageSeen`, `CommandSheet`, `CommandEnvelope::validate`,
    `OperationResult`, `EffectRequirement`, `SavepointPolicy`). No SQL, I/O or
    credentials.
  - `crates/db` (`setjoin-db`) — pure transaction-lifecycle model
    (`recover(CommitObservation)`). No database driver is linked here.
  - `crates/domains/blobs` (`setjoin-blobs`, #265) — F16 qualified adapters and cleanup worker; read [DOX.md](crates/domains/blobs/DOX.md).
  - `crates/domains/jmap` (`setjoin-jmap`, #214/#316) — F18 mail and mailbox methods on `setjoin-pg`; [contract](crates/domains/jmap/DOX.md).
  - `crates/domains/static` (`setjoin-static`, #271) — F20/F22 public surface and Assist; read [DOX.md](crates/domains/static/DOX.md).
  - `crates/domains/recording` (`setjoin-recording`) — recording publication
    adapter over injected trusted stores; see its [DOX.md](crates/domains/recording/DOX.md).
  - `crates/pg` (`setjoin-pg`) — scoped executor, workers and standalone
    operator connections; [contract](crates/pg/DOX.md).
  - `tests/conformance` — DB-backed parity and recorded-golden harness; [contract](DOX.md#conformance-harness-contract).
- `pilot/` — separate pilot workspace; [contract](DOX.md#pilot-workspace-contract).
- `tools/schema-simulation/` — separate tooling workspace; [contract](DOX.md#schema-simulation-workspace).

- `tools/bench-mark-read/` — see [benchmark details](DOX.md#benchmark-details).

## Local contracts

- A write is one Rust statement only when the entire Go transaction is that statement, with no other write, audit, state bump or notify; otherwise call a reducer reproducing the transaction. When in doubt use a reducer (ARCH-028, #243).
- Family isolation and licence policy: [dependency guards](DOX.md#family-dependency-guards).

- Root rails apply unchanged: reducers own business authority until a command
  is switched; database rules R1–R4; never `SET ROLE` on a shared pool.
- Driver (owner decision): `tokio-postgres` + `deadpool-postgres` with unnamed
  or simple statements, because `DB_DSN` is a PgBouncer transaction pool.
- An unknown commit outcome never reports success; it returns the operation ID
  for lookup.
- Commit dependency lockfiles; all guards use `--locked`. Keep `target/` untracked.
  Runtime dependency constraints: [DOX.md](DOX.md#runtime-dependency-constraints).
- Session encryption/audit GUC requirements: [DOX.md](DOX.md#session-guc-requirements).
- Lowering a crate's `rust-version`, merging the pilot, schema-simulation or
  bench-mark-read into the workspace, or adding a member changes this rail and `scripts/check-server-rust.sh`.

## Verification

- `python3 scripts/report-gofree-oracle-coverage.py --route <name> --binary
  <instrumented-test-binary> --source <handler-file> --test <replay-name>`
  measures per-handler line and region coverage for the selected exact golden
  replay tests. Repeat `--source` and `--test` as needed. Build the binary with
  `-C instrument-coverage`; Rust's `llvm-tools` component is required. Each
  replay must run once with the database and no skip; recording mode is cleared.
- `python3 scripts/check-gofree-route-inventory.py` — completeness/provenance
  check against every non-test Go HTTP registration in the server modules
  and the runtime-derived gateway golden. No Go runtime edits or DB needed.
  `--write` preserves existing transfer decisions and adds/removes entries;
  review family/slice assignments before committing. Non-literal registrations
  fail closed. Narrow exclusions cover the recorder, DNS mux and two named
  non-HTTP Handle methods. `--self-test` plants a missing auth route and a
  dynamic registration. Both execute in the Rust lane via `inventory_guard.rs`.
- Gateway `tests/proxy.rs` covers four-target inventory dispatch, direct auth,
  the all-Go kill switch and per-family/total proxy metrics through HTTP.
  `tests/startup.rs` checks default-ON and the environment kill switch through
  the executable, reaping each owned child process on success or failure.
- `bash scripts/check-server-rust.sh` — `cargo test --locked` in the workspace,
  the pilot, schema-simulation and bench-mark-read; red on any failing test or a root with zero
  tests or ignored tests. Without cargo it prints `SERVER-RUST-SKIP (reason=cargo-not-found …)`.
  Workspace and pilot fetch their locked dependencies once if uncached.
  `SERVER_RUST_NEXTEST=1` runs the workspace through nextest with a database per test;
  the CI full lane is [DOX.md](DOX.md#parallel-full-lane-550).
- Oracle adequacy gate and coverage: [DOX.md](DOX.md#oracle-adequacy).
- `setjoin-pg` DB tests (`crates/pg/tests/db_scope.rs`) need a schema from
  `scripts/load-test-schema.sh`, owner DSN in `TEST_DB_DSN`/`DB_DSN` and the
  `setjoin_app` credential in `DB_APP_DSN`; absent → `SETJOIN-PG-DB-SKIP
  (reason=no-dsn)` per test, `REQUIRE_DB=1` → FAIL. Rust has no runtime skip,
  so a skipped DB test still counts as `ok`: a skip line is never a pass.
  CI's guard step sets all three plus `REQUIRE_DB=1`.
- `crates/pg/tests/workers.rs` exercises the scheduler lock against Go's SQL,
  worker credential selection and direct LISTEN using the disposable test DB.
- Gateway `tests/workers.rs` covers the Go task catalog, interval/cron timing,
  cancellation, lock loss and the recorded Go denylist worker oracle. Gateway
  `tests/startup.rs` proves the executable opens its direct LISTEN connection.
- Conformance and JMAP DB test contracts: [DOX.md](DOX.md#conformance-and-jmap-db-tests).

- Guard self-test: [DOX.md](DOX.md#rust-guard-self-test).
- Gateway test coverage: [DOX.md](DOX.md#gateway-test-coverage).
- The shared authz HTTP probe in `bins/gateway/tests/jmap_db.rs` checks that
  the verified context ignores request-supplied user, mailbox and scope;
  guest and fallback cases check guest belts and whole-request forwarding.
- RP07 bounds, stalled-read, proxy and recorded-response coverage is in
  [DOX.md](DOX.md#verification-detail). The guard fails under `REQUIRE_DB=1`
  on any DB skip marker.
- Manual evidence and image qualification: [DOX.md](DOX.md#manual-evidence-and-image-qualification).

- `bins/mailctl` — operator CLI, backups and process oracles: [contract](bins/mailctl/DOX.md) (#352–#355).
- `crates/push` (`setjoin-push`) — shared push transports; [contract](crates/push/DOX.md) (#354).
- `crates/schema` (`setjoin-schema`) — embedded canonical SQL catalog; [contract](crates/schema/DOX.md) (#354).

- `crates/backup` (`setjoin-backup`) — backup formats and transports; [contract](crates/backup/DOX.md) (#355).
- `crates/acme` (`setjoin-acme`) — managed ACME challenges, issuance and cache; [contract](crates/acme/DOX.md) (#305, #413).
Unflagged request admission: [authz DOX](crates/authz/DOX.md).

Rust operation receipts: [foundation contract](crates/pg/DOX.md#rust-operation-receipts-257265).
Protected audit GUCs: [named foundation allowlist](crates/pg/DOX.md#protected-audit-gucs).
F16 defaults ON with qualified replays; [family contract](crates/domains/blobs/DOX.md).
- `crates/domains/office` (`setjoin-office`, #270) — F15; [contract](crates/domains/office/DOX.md).

Authenticated Drive user scope: [foundation contract](crates/pg/DOX.md#authenticated-user-scope), used by F15.
Direct-DB oracle restoration releases partition locks between DDL statements; see the [mailctl contract](bins/mailctl/DOX.md#direct-database-commands-354).
- `crates/domains/approvals` (`setjoin-approvals`, #269) — F10; read its [DOX.md](crates/domains/approvals/DOX.md).
- `crates/domains/chat` (`setjoin-chat`, #266) — F12 slices and compliance adapters; [contract](crates/domains/chat/DOX.md).
Shared CSV format: [contracts DOX](crates/contracts/DOX.md) (#266).
Conformance fixture boundaries: [contract](tests/conformance/DOX.md) (#266).
F12 user channel scope and HTTP oracle: [Chat contract](crates/domains/chat/DOX.md#user-channel-scope-267) (#267).

- `crates/domains/guests` (`setjoin-guests`, #272) — F11; [contract](crates/domains/guests/DOX.md).
- `crates/domains/calendar` (`setjoin-calendar`, #296–#298/#426–#427) — F17 calendar, contacts, DAV and both workers, all ON; [contract](crates/domains/calendar/DOX.md).
- `crates/domains/drive` (`setjoin-drive`, #273) — F14 slices; [contract](crates/domains/drive/DOX.md).
- `crates/domains/admin-identity` (`setjoin-admin-identity`, #277) — F01 six-slice map, users+roles slices; [contract](crates/domains/admin-identity/DOX.md).
- `crates/domains/directory-sync` (`setjoin-directory-sync`, #283) — F02 AD+LDAP+SCIM; [contract](crates/domains/directory-sync/DOX.md).
- `crates/domains/meet` (`setjoin-meet`, #285) — F13 slices; [contract](crates/domains/meet/DOX.md).
- `crates/domains/mailboxes` (`setjoin-mailboxes`, #292) — F05 slices (#293 migration); [contract](crates/domains/mailboxes/DOX.md).
- `crates/domains/devices` (`setjoin-devices`, #310–#312) — F07 MDM/MAM/offline; [contract](crates/domains/devices/DOX.md).

Go list handlers that ignore Rows.Err: see the [iterated-read contract](crates/pg/DOX.md#frozen-go-row-iteration-reads-273).
- `crates/config-secret` — EK01 codec; [DOX](crates/config-secret/DOX.md).
- `crates/protocols/ldap` (`setjoin-ldap`, #342) — inbound GAL listener; [contract](crates/protocols/ldap/DOX.md).
- `crates/protocols/imap` (`setjoin-imap`, #343–#345) — IMAP listener (all commands, shared threat admission #420); [contract](crates/protocols/imap/DOX.md).
- `crates/domains/compliance` (`setjoin-compliance`, #289) — F04 eDiscovery, retention/audit and slice ownership; [contract](crates/domains/compliance/DOX.md).
- `crates/domains/mail-security` (`setjoin-mail-security`, #320) — F06 Mail security: nine-slice map, quarantine; [contract](crates/domains/mail-security/DOX.md), per-slice detail in `slices/*.md`.
- `crates/domains/platform` (`setjoin-platform`, #299) — F08 Platform: seven-slice map, system and features; [contract](crates/domains/platform/DOX.md).
- `crates/domains/user-settings` (`setjoin-user-settings`, #306) — F19 User mail settings and profile: four-slice map (all ON); [contract](crates/domains/user-settings/DOX.md).
- `crates/domains/conditional-access` (`setjoin-conditional-access`, #313) — F03 Conditional access: two-slice map, policy model, policies; [contract](crates/domains/conditional-access/DOX.md).
- `crates/protocols/federation` (`setjoin-federation`, #346) — native socket-activated peer protocol and residue reaper; [contract](crates/protocols/federation/DOX.md).
- `crates/domains/rules` (`setjoin-rules`, #329) — F09 rules and templates; [contract](crates/domains/rules/DOX.md).
- `crates/protocols/smtp` (`setjoin-smtp`, #348–#351) — native listener, enabled inbound security, mail authentication and outbound delivery; [contract](crates/protocols/smtp/DOX.md).
- `crates/mime` (`setjoin-mime`, #348) — shared Go-compatible MIME byte parser; [contract](crates/mime/DOX.md).
Typed worker error projection: [PG contract](crates/pg/DOX.md#typed-worker-query-failures-348).

- `bins/auth` (`setjoin-auth`, #331) — standalone identity HTTP process; [contract](bins/auth/DOX.md).
- `crates/domains/identity` (`setjoin-identity`, #331) — F21 login/session/token, MFA and connector slices; [contract](crates/domains/identity/DOX.md).
Authentication-time user transactions: [pg contract](crates/pg/DOX.md#authentication-time-user-transactions-331).
- `crates/tls` (`setjoin-tls`, #413) — native TLS, certificates and Go-compatible session tickets; [contract](crates/tls/DOX.md).


Shared HTTP runtime gates and F03 evaluator (#405): [gateway contract](bins/gateway/runtime-access.DOX.md).

Terminal HTTP denials and mailbox-less guest discovery (#406): [gateway](bins/gateway/DOX.md#terminal-shared-admission-406) and [authz](crates/authz/DOX.md#mailbox-less-http-guest-proof-406).
Mailbox-less user transaction scope (#406): [PG contract](crates/pg/DOX.md#mailbox-less-user-transactions-406).

- `crates/release-format` (`setjoin-release-format`, #357) — shared signed manifest format; [contract](crates/release-format/DOX.md).
- `bins/release` (`setjoin-release`, #357) — CI-only release publisher; [contract](bins/release/DOX.md).
- `bins/updater` (`setjoin-updater`, #358–#359) — privileged updater/recovery process; [contract](bins/updater/DOX.md), [security divergences](bins/updater/SECURITY.md).
- `crates/threat` (`setjoin-threat`, #420) — shared auth runtime and protocol admission; [contract](crates/threat/DOX.md).


- `crates/boot` (`setjoin-boot`, #415) — pre-listener startup checks; [contract](crates/boot/DOX.md).

Shared mailbox mail-read grants (#419): [authz contract](crates/authz/DOX.md#mailbox-mail-read-grants-419).

Mailserver-local F21 self-service (#494): [identity contract](crates/domains/identity/SELF_SERVICE.md).
Shared Go UUID identifiers (#455): [contracts](crates/contracts/DOX.md#go-uuid-identifiers-455).

- `crates/spam` (`setjoin-spam`, #526) — shared keyed FTRL model and inbound batch scorer; [contract](crates/spam/DOX.md).

- `crates/certificates` — shared Go certificate/PEM profile and recipient trust cache; [contract](crates/certificates/DOX.md).

- `crates/calendar-format` — shared Go calendar parser; [contract](crates/calendar-format/DOX.md).
