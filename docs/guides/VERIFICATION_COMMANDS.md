# Verification command directory

Paths and commands below are relative to the repository root. Choose only the lane
relevant to the task and its required gates. Reuse valid unchanged evidence; this is a
catalog, not an instruction to run every command after every edit.

## Review-boundary check discipline (owner 2026-09-23)

Model review is gated on machine checks, not the reverse. Before handing a change to
review, run the lanes this change actually touches: `quick` tier after each
small batch (format, lint, affected unit tests), `review` tier before model review
(required lint + types + build + affected integration/acceptance scenarios). Add
risk-specific verification — authz changes probe cross-tenant paths, migrations verify
rollback conditions, concurrency changes probe races and replays — never skipped for
the ones the change's risk makes relevant. Explicit tool failures are fixed by the
executor and re-run; after two failed fix rounds, escalate rather than iterate. Never
manufacture green by deleting assertions, skipping tests, weakening rules or swallowing
errors; legitimate gate-config changes are separate reviewed diffs. Exit 0 with
warnings is not a pass where the lane's threshold blocks on warnings, and a
configuration error is an evidence failure, not a clean result.

## Build and verification

- Build: `bash scripts/ci/build.sh` (builds Rust binaries `setjoin-server`, `setjoin-auth`, `mailctl`, `asrbotd`, `setjoin-updater` and webmail)
- Test: `bash scripts/test.sh` (runs Rust server tests, pgTAP, and webmail Vitest)
- Lint: `bash scripts/ci/lint.sh`
- Unified code quality: `bash scripts/ci/quality.sh doctor|fast|full|security`
- Quality catalog guard: `bash scripts/guards/check-quality-tool-catalog.sh --self-test`
- E2E: `bash scripts/dev/e2e.sh [imap|smtp|ldap]`
- First-boot E2E: `bash scripts/verify-all.sh onboarding` (disposable uninitialized DB)
- Complete verification matrix: `bash scripts/verify-all.sh list`; `all` runs deterministic local lanes and `extended` adds an explicitly bounded live browser origin plus iOS/Android runtime probes.
- Browser lanes route through `scripts/ci/playwright-supported.sh`: supported hosts run locally, unsupported Linux fails closed unless an explicit loopback endpoint reaches a separate supported browser host; the exact-version container is diagnostic because it still shares the host kernel.
- Fresh test DB: `bash scripts/load-test-schema.sh`
- Server archive staging (no publishing): `scripts/deploy/package-server-release.sh` (stages Rust `setjoin-server`, `setjoin-auth`, `mailctl`, `asrbotd`, `setjoin-updater` and webmail); contract test `python3 scripts/deploy/test-package-server-release.py`
- Toolchain-upgrade smoke: `bash scripts/deploy/post-upgrade-smoke.sh`
- Architecture R4 focused lanes: `bash scripts/ci/verify-architecture-r4.sh --doctor`; CLI/self-test contract: `bash scripts/ci/verify-architecture-r4.test.sh`
- Three-stack deployment rehearsal: `RUN_PREFIX=<unique> bash scripts/deploy/unified-deployment-readiness.sh provision`; use `resume-provision` only for its guarded pre-install retry path.
- Portable rewind after successful A/B provisioning and updater rehearsal: `RUN_PREFIX=<same> REWIND_ATTEMPT=<new> bash scripts/deploy/transactional-upgrade-rehearsal.sh rewind`.
- Structural guards: `bash scripts/run-guards-selftest.sh && bash scripts/run-guards.sh --known-red scripts/guards-known-red.txt` (the lane's `guards` job; plain `run-guards.sh` treats every red guard as failure)
- pgTAP suites: `bash scripts/ci/run-pgtap-lane.sh scripts/pgtap-known-red.txt -h HOST -p PORT -U USER -d DB` (the lane's `pgtap` job; suites listed in `scripts/pgtap-known-red.txt` run and warn, and a listed suite that passes fails the ratchet)
- Hot-context guard: `bash scripts/guards/check-agent-context-budget.sh` and `bash scripts/guards/check-agent-docs.sh`
- Rust server, front-door inventory and oracle adequacy: `bash scripts/guards/check-server-rust.sh`
  (runs golden floor, per-route replay/coverage, and mutant checks against `server/`;
  Rust's `llvm-tools` component is required. With no DB the dynamic
  oracle reports a skip; `REQUIRE_DB=1` with disposable test DSNs requires all cases).
- Oracle adequacy: replays and mutants run `LANE_ADEQUACY_JOBS` (default `LANE_JOBS`) at a time on per-replay clones; timeouts: `LANE_REPLAY_TIMEOUT` (default 900 s, run time of one replay or mutant).
- Rust server full lane in parallel (#550): the `server-rust lane` workflow on GitHub-hosted
  runners (merge-queue entries: with batching on, only the batch head runs the lane; exceptions are a late arrival queued after the head had decided, which runs its own lane, and a waiter that reaches the 90-minute cap, which runs the full lane itself; manual dispatch: full lane plus coverage, sharded; `aggregate` is the
  required check; pull requests run only `pr-precheck.yml`, whose `aggregate` gates its `light` quick check and its `integration` job (selected `tests/*.rs` targets on the lane Postgres; selection self-test `python3 scripts/ci/precheck-integration.py selftest`); a push to `main` only refreshes caches, and a nightly 02:30 UTC run is the full-lane backstop), or locally `LANE_PG_PORT=<port> PGPASSWORD=<pw> bash scripts/ci/server-rust-parallel-lane.sh`
  (runs nextest with serial groups for docker/fixed-port/`/dev/shm` binaries; on a dev host `LANE_MODE=serial` is the serial fallback).
- Upgrade contract guard: `bash scripts/guards/check-upgrade-contracts.sh`
- HTTP socket activation on a root/systemd host: `python3 scripts/deploy/test-gateway-systemd.py <built-setjoin-server>`
  (temporary `gofree-t13-*` units; checks capability-empty execution and queued
  connections during restart; public TLS/installer handover is not covered).
- Installer front door (#264 / #142): `bash deploy/scripts/test-install-front-door.sh [<built-setjoin-server>]`
  (unchanged unit name `setjoin-gateway.service` executing `setjoin-server`, Rust `*.prev` rollback; with a binary it runs the rendered config, and as
  root on systemd the rendered socket+service under `gofree-t13-*` names —
  `REQUIRE_SYSTEMD=1` makes that arm mandatory).
- Architecture R3 focused front door: `bash scripts/ci/verify-architecture-r3.sh --doctor`; no arguments attempt all eight named lanes, and any unimplemented lane or escalation mode fails closed.
- Security-boundary front door: `bash scripts/ci/verify-security-boundaries.sh --doctor`; `all` runs the eight source-bound G0-G4 lanes and `evidence` rejects stale or incomplete retained results.
- Future-code test evidence: `docs/standards/AI_ASSISTED_TESTING.md`

The canonical core lane retains Rust/nextest results, verbose pgTAP/TAP, Vitest JSON, and
exact-case verdicts below the ignored `test-results/` trees. The explicit
browser lane additionally retains Playwright JSON, the mutable suite and
static-CSP origins separately, and Guest terminal-lifecycle screenshots.
The mutable suite also carries a deterministic Chinese mobile Guest-activation
pixel baseline with a bounded cross-runtime antialiasing tolerance.
Required named cases reject missing, skipped, failed, ambiguous, malformed, or
flaky-after-retry outcomes.

Xinchuang CI merge-gate evidence is retained for 14 days below
`$RUNNER_WORKSPACE/setjoin-ci-evidence/setjoin_setjoin/`; it does not consume
GitHub Actions artifact storage. Release packaging has a separate artifact
transport contract.

Reducer loading is deterministic fixed-point iteration. It retries forward references until no new file succeeds, then fails loudly with every survivor named. Do not restore `-- deps:` parsing or a manual two-pass wrapper.


