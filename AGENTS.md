# Setjoin

Setjoin is a self-hosted productivity suite: Go gateways, PL/pgSQL reducers,
SvelteKit UI, native clients and collaboration sidecars. `AGENTS.md` is canonical;
`CLAUDE.md` is its symlink.

## DOX contract

AGENTS.md files are binding contracts for their subtrees ([DOX](https://github.com/agent0ai/dox)).

1. **Before editing:** walk root → target path and read every AGENTS.md on the route,
   then the task-relevant DOX sections and standards. The nearest doc controls local
   detail; no child weakens root.
2. **After editing:** update the owning AGENTS.md/DOX and its parent's Child DOX Index
   when purpose, contracts, workflows, permissions, side effects or structure change.
3. **Closeout:** remove stale or contradictory text, run the affected verification, and
   report any doc intentionally left unchanged.

Budgets: root ≤10,000 bytes, child ≤16,000, root-to-child chain ≤32,000, enforced by
`scripts/check-agent-context-budget.sh`. Move detail behind pointers; mechanical moves
preserve text verbatim.

## Architecture invariants

- **Logic where the data is:** PL/pgSQL reducers in `mailserver/sql/reducers/` own
  business logic; Go translates protocols today and Rust replaces it route by route
  ([ARCH-028](docs/adr/ARCH-028-rust-replaces-go-reducers-stay.md),
  [ARCH-026](docs/adr/ARCH-026-per-command-rust-authority-transfer.md)). Rust calls a
  reducer rather than reimplementing multi-statement logic. A mutator commits data, state
  bumps, audit and `pg_notify` in one transaction.
- **Connections:** `DB_DSN` is the PgBouncer request pool; `DB_DIRECT_DSN` serves only
  `LISTEN/NOTIFY`; `DB_WORKER_DSN` (`setjoin_worker`, BYPASSRLS) serves explicit
  cross-tenant workers; `DB_OWNER_DSN` owns partitions/DDL. Worker and owner default to
  `DB_DSN` until the native-RLS flip. Split privileges by credential, never `SET ROLE`
  on a shared pool. Startup/drain detail: `mailserver/AGENTS.md`.
- **Storage:** attachments are SHA-256 content-addressed in SeaweedFS/S3;
  `blobs.ref_count` is trigger-maintained.
- **Tags:** mail uses Gmail-style multi-label tags; `location` and `snooze` are
  exclusive groups; Archive removes the location tag.
- **Sidecars:** LiveKit, Egress, Valkey, FunASR and native preview helpers are
  peripherals, never authority stores. Revocation evicts live media sessions.

## Database query security (enforced)

Read `docs/standards/DATABASE_SECURITY.md` before touching a user-data query.

- **R1:** SELECT filters by authenticated `user_id`/`mailbox_id`.
- **R2:** INSERT ownership comes from auth context, never request-owned identity fields.
- **R3:** UPDATE/DELETE include ownership in the same WHERE; no check-then-mutate TOCTOU.
- **R4:** every user-data table has the project-required isolation/RLS posture and tests.

## Conventions and verification

- Go: [CODE_QUALITY.md](docs/standards/CODE_QUALITY.md); PL/pgSQL: `mailserver/sql/AGENTS.md`;
  Svelte: `mailserver/webmail/AGENTS.md`.
- Git: branch from `main`; stage, commit, push or deploy only when asked; preserve
  unrelated dirty-worktree changes.
- Verification: pick affected lanes from [Verification commands](docs/guides/VERIFICATION_COMMANDS.md)
  or `bash scripts/verify-all.sh list`. Missing, skipped or flaky-after-retry cases are
  failures. Fix failures you caused; keep tests strict.
- Server archive staging: `scripts/package-server-release.sh` assembles committed
  source and prebuilt binaries; it does not publish or update the signed cohort.
  Check its packaging contract with `python3 scripts/test-package-server-release.py`.
- Rust floor builds: `.github/workflows/rust-floor.yml` calls `scripts/cross-build.sh
  --rust` in glibc 2.28 (x86_64/arm64) and a glibc 2.36 loong64 sysroot, verifies
  ELF version needs and smokes the gateway in a scratch loong64 runtime. The loong64
  toolchain image adds Python from the pinned x86 floor image for the build guards.

## Execution environment and task cleanup

Read [execution and cleanup](docs/guides/TASK_EXECUTION_AND_CLEANUP.md) before builds,
tests, services or delegates. Never borrow another project's connection details.
Record temporary resources before launch and clean only what you own.

## Programs and documentation

- Status: [program directory](docs/agents/PROGRAM_STATUS.md); queue: GitHub issues. Read only
  the owning plan; behavior stays OFF until its rollout decision admits it.
- Agent workflows: `docs/agents/` (planning pipeline, governance handoff); select by task.

## Agent skills

- **Issue tracker:** GitHub issues on `setjoin/setjoin` via `gh`. See `docs/agents/issue-tracker.md`.
- **Triage labels:** five canonical roles mapped to repo labels. See `docs/agents/triage-labels.md`.
- **Domain docs:** single-context (`CONTEXT.md` + `docs/adr/`). See `docs/agents/domain.md`.
- **Matt Pocock flow:** `/grill-with-docs`, `/to-spec`, `/to-tickets`, `/implement`, `/retro` and
  peers are user-invoked; `/ask-matt` routes between them.

## Child DOX Index

- `mailserver/AGENTS.md` — gateway, SQL, webmail, protocols, worker transfer gates and session/TLS oracle recorders.
- `authserver/AGENTS.md` — identity, MFA, sync and threat policy.
- `shared/AGENTS.md` — shared Go contracts and parity-vector recorder.
- `mailctl/AGENTS.md` — frozen Go CLI parity reference; shipped CLI is in `server-rust/bins/mailctl/`.
- `clients/AGENTS.md` — desktop, mobile and shared Rust.
- `server-rust/AGENTS.md` — Rust rewrite: front door, shared authz/live roles, scoped commands, workers and TLS lifecycle, family isolation, licence policy, pilot and recorded parity/adequacy gate including shared-format vectors.
- `asrbot/AGENTS.md` — Meet captions bot.
- `docs/AGENTS.md` — documentation taxonomy and owners.

Excluded: `node_modules/`, generated `build/`.
