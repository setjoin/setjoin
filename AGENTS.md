# Setjoin

Setjoin is a self-hosted productivity suite: a Rust server replacing the frozen Go one,
PL/pgSQL reducers, SvelteKit UI, native clients and collaboration sidecars. `AGENTS.md` is canonical;
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
  business logic. Go is frozen and serves only as the parity reference while Rust replaces
  it route by route (Go-free spec #25,
  [ARCH-028](docs/adr/ARCH-028-rust-replaces-go-reducers-stay.md)). Rust calls a
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

- Rust: `server-rust/AGENTS.md`; PL/pgSQL: `mailserver/sql/AGENTS.md`; Svelte:
  `mailserver/webmail/AGENTS.md`; frozen Go: [CODE_QUALITY.md](docs/standards/CODE_QUALITY.md).
- Frozen Go is not patched. A Go security bug is fixed in Rust as a recorded divergence; a
  functional Go behaviour is mirrored.
- Git: branch from `main`; commit and push only your own branch when asked or as the
  [subagent workflow](docs/agents/subagent-workflow.md) allows; never push `main`; deploy
  only when asked; preserve unrelated dirty-worktree changes.
- Verification: pick affected lanes from [Verification commands](docs/guides/VERIFICATION_COMMANDS.md)
  or `bash scripts/verify-all.sh list`. Missing, skipped or flaky-after-retry cases are
  failures. Fix failures you caused; keep tests strict.
- CI: GitHub-hosted runners only; workflows and lanes are listed in `.github/CI-RUNNERS.md`.
  Only the merge-queue lane runs `scripts/run-guards.sh`, so run the standalone guards for
  the area you touched before opening a PR. A known-red guard that starts passing blocks
  until its entry is removed from `scripts/guards-known-red.txt`.

## Execution environment and task cleanup

Read [execution and cleanup](docs/guides/TASK_EXECUTION_AND_CLEANUP.md) before builds,
tests, services or delegates. Never borrow another project's connection details.
Record temporary resources before launch and clean only what you own.

## Programs and documentation

- Status: [program directory](docs/agents/PROGRAM_STATUS.md); queue: GitHub issues. Read only
  the owning plan; behavior stays OFF until its rollout decision admits it.
- Agent workflows: `docs/agents/`. Delegated work follows the
  [subagent workflow](docs/agents/subagent-workflow.md): Claude Code coordinates; Codex
  `gpt-6.2-sol` implements, plans and gates, with `gpt-6.2-astra` as the fallback and
  tie-break; review gates decide merges. When Codex is unavailable, Claude Code does the
  work itself under the same gates. Risk-area designs get a plan review before code.

## Agent skills

- **Issue tracker:** GitHub issues on `setjoin/setjoin` via `gh`. See `docs/agents/issue-tracker.md`.
- **Triage labels:** five canonical roles mapped to repo labels. See `docs/agents/triage-labels.md`.
- **Domain docs:** single-context (`CONTEXT.md` + `docs/adr/`). See `docs/agents/domain.md`.

## Child DOX Index

- `mailserver/AGENTS.md` — frozen Go gateway, SQL reducers, webmail and oracle recorders.
- `authserver/AGENTS.md` — identity, MFA, sync and threat policy.
- `shared/AGENTS.md` — shared Go contracts and parity-vector recorder.
- `mailctl/AGENTS.md` — frozen Go CLI parity reference; shipped CLI is in `server-rust/bins/mailctl/`.
- `clients/AGENTS.md` — desktop, mobile and shared Rust.
- `server-rust/AGENTS.md` — Rust server: front door, authz, scoped commands, workers, licence policy and parity gates.
- `asrbot/AGENTS.md` — Meet captions bot.
- `docs/AGENTS.md` — documentation taxonomy and owners.

Excluded: `node_modules/`, generated `build/`.
