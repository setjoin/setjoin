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

- Build: `bash scripts/build.sh`
- Test: `bash scripts/test.sh` (`RACE=1` enables the sequential Go race lane)
- Lint: `bash scripts/lint.sh`
- Unified code quality: `bash scripts/quality.sh doctor|fast|full|security`
- Quality catalog guard: `bash scripts/check-quality-tool-catalog.sh --self-test`
- E2E: `bash scripts/e2e.sh [imap|smtp|ldap]`
- First-boot E2E: `bash scripts/verify-all.sh onboarding` (disposable uninitialized DB)
- Complete verification matrix: `bash scripts/verify-all.sh list`; `all` runs deterministic local lanes and `extended` adds an explicitly bounded live browser origin plus iOS/Android runtime probes.
- Browser lanes route through `scripts/playwright-supported.sh`: supported hosts run locally, unsupported Linux fails closed unless an explicit loopback endpoint reaches a separate supported browser host; the exact-version container is diagnostic because it still shares the host kernel.
- Fresh test DB: `bash scripts/load-test-schema.sh`
- Server archive staging (no publishing): `scripts/package-server-release.sh`; contract test `python3 scripts/test-package-server-release.py`
- Toolchain-upgrade smoke: `bash scripts/post-upgrade-smoke.sh`
- Fixed deployment-unit catalog/projection: `bash scripts/check-deploy-unit-catalog.sh --self-test`
- Architecture R4 focused lanes: `bash scripts/verify-architecture-r4.sh --doctor`; CLI/self-test contract: `bash scripts/verify-architecture-r4.test.sh`
- Go module inventory: `config/go-modules.json` is the sole fixed capability
  catalog for workspace plus isolated modules; `scripts/check-go-module-catalog.sh`
  fails on an unclassified `go.mod`. Build/test/lint/vulnerability front doors
  consume its projections while retaining lane-specific artifact and CGO policy.
- Three-stack deployment rehearsal: `RUN_PREFIX=<unique> bash scripts/unified-deployment-readiness.sh provision`; use `resume-provision` only for its guarded pre-install retry path.
- Portable rewind after successful A/B provisioning and updater rehearsal: `RUN_PREFIX=<same> REWIND_ATTEMPT=<new> bash scripts/transactional-upgrade-rehearsal.sh rewind`.
- Structural guards: `bash scripts/run-guards-selftest.sh && bash scripts/run-guards.sh --known-red scripts/guards-known-red.txt` (the lane's `guards` job; plain `run-guards.sh` treats every red guard as failure)
- Hot-context guard: `bash scripts/check-agent-context-budget.sh`
- Rust server, front-door inventory and oracle adequacy: `bash scripts/check-server-rust.sh`
  (runs route completeness, golden floor, per-route replay/coverage and mutant
  checks; Rust's `llvm-tools` component is required. With no DB the dynamic
  oracle reports a skip; `REQUIRE_DB=1` with disposable test DSNs requires all cases).
  ports, tracked bytecode, context budget, hosted-lane shard merge; `--lane <filter|changed>` prints the quick-lane command).
- Oracle adequacy: replays and mutants run `LANE_ADEQUACY_JOBS` (default `LANE_JOBS`) at a time on per-replay clones; timeouts: `LANE_REPLAY_TIMEOUT` (default 900 s, run time of one replay or mutant,
- Rust server full lane in parallel (#550): the `server-rust lane` workflow on GitHub-hosted
  runners (every pull request and push to `main`: full lane plus coverage, sharded; `aggregate` is the
  required check), or locally `LANE_PG_PORT=<port> PGPASSWORD=<pw> bash scripts/server-rust-parallel-lane.sh`
  test with serial groups for docker/fixed-port/`/dev/shm` binaries; on a dev host `LANE_MODE=serial` is the
- Upgrade contract guard: `bash scripts/check-upgrade-contracts.sh`
- HTTP socket activation on a root/systemd host: `python3 scripts/test-gateway-systemd.py <built-setjoin-gateway>`
  (temporary `gofree-t13-*` units; checks capability-empty execution and queued
  connections during restart; public TLS/installer handover is not covered).
- Installer front door (#264): `bash mailserver/deploy/scripts/test-install-front-door.sh [<built-setjoin-gateway>]`
  (unchanged unit names, gateway rendered/enabled/started by default in the ARCH-027
  shape, Go+Rust `*.prev` rollback; with a binary it runs the rendered config, and as
  root on systemd the rendered socket+service under `gofree-t13-*` names —
  `REQUIRE_SYSTEMD=1` makes that arm mandatory).
- Architecture R3 focused front door: `bash scripts/verify-architecture-r3.sh --doctor`; no arguments attempt all eight named lanes, and any unimplemented lane or escalation mode fails closed.
- Security-boundary front door: `bash scripts/verify-security-boundaries.sh --doctor`; `all` runs the eight source-bound G0-G4 lanes and `evidence` rejects stale or incomplete retained results.
- Future-code test evidence: `docs/standards/AI_ASSISTED_TESTING.md`

The canonical core lane retains Go JSON, verbose pgTAP/TAP, Vitest JSON, and
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


