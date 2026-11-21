# Setjoin

Self-hosted productivity suite: Rust server replacing frozen Go, PL/pgSQL reducers, SvelteKit UI, native clients, and collaboration sidecars. `AGENTS.md` is canonical; `CLAUDE.md` is its symlink.

## DOX contract

`AGENTS.md` files bind their subtrees ([DOX](https://github.com/agent0ai/dox)).

1. **Before editing:** read `AGENTS.md` from root → target, then task-relevant DOX sections and standards. Nearest doc controls local detail; no child weakens root.
2. **After editing:** update the owning `AGENTS.md`/DOX and parent Child DOX Index when purpose, contracts, workflows, permissions, side effects, or structure change.
3. **Closeout:** remove stale/contradictory text, run affected verification, and report any doc intentionally left unchanged.

Budgets: root ≤10,000 bytes, child ≤16,000, chain ≤32,000 (`scripts/check-agent-context-budget.sh`). Move detail behind pointers; mechanical moves preserve text verbatim.

## Architecture invariants

- **Logic where data lives:** PL/pgSQL reducers in `mailserver/sql/reducers/` own business logic. Go is frozen parity reference as Rust replaces it route by route (Go-free spec #25, [ARCH-028](docs/adr/ARCH-028-rust-replaces-go-reducers-stay.md)). Rust calls reducers instead of reimplementing multi-statement logic; mutators commit data, state bumps, audit, and `pg_notify` in one transaction.
- **Connections:** `DB_DSN` is the PgBouncer request pool; `DB_DIRECT_DSN` is `LISTEN/NOTIFY` only; `DB_WORKER_DSN` (`setjoin_worker`, `BYPASSRLS`) serves explicit cross-tenant workers; `DB_OWNER_DSN` owns partitions/DDL (worker/owner default to `DB_DSN` until native-RLS flip). Split privileges by credential; keep `SET ROLE` off shared pools. Startup/drain: `mailserver/AGENTS.md`.
- **Storage:** attachments are SHA-256 content-addressed in SeaweedFS/S3; `blobs.ref_count` is trigger-maintained.
- **Tags:** Gmail-style multi-label tags; `location` and `snooze` are exclusive groups; Archive removes `location`.
- **Sidecars:** LiveKit, Egress, Valkey, FunASR, and native preview helpers are peripherals, never authority stores. Revocation evicts live media sessions.

## Database query security (enforced)

Read `docs/standards/DATABASE_SECURITY.md` before touching a user-data query.

- **R1:** `SELECT` filters by authenticated `user_id`/`mailbox_id`.
- **R2:** `INSERT` ownership comes from auth context, never request identity fields.
- **R3:** `UPDATE`/`DELETE` include ownership in the same `WHERE` (no check-then-mutate TOCTOU).
- **R4:** every user-data table has required isolation/RLS posture and tests.

## Conventions and verification

- Rust: `server-rust/AGENTS.md`; PL/pgSQL: `mailserver/sql/AGENTS.md`; Svelte: `mailserver/webmail/AGENTS.md`; frozen Go: [CODE_QUALITY.md](docs/standards/CODE_QUALITY.md).
- Frozen Go stays unpatched: fix Go security bugs in Rust as recorded divergences; mirror functional behavior.
- Git: branch from `main`; commit/push only your branch when asked or per [subagent workflow](docs/agents/subagent-workflow.md); never push `main`; deploy only when asked; preserve unrelated dirty files.
- Verification: run affected lanes from [Verification commands](docs/guides/VERIFICATION_COMMANDS.md) or `bash scripts/verify-all.sh list`. Missing, skipped, or flaky-after-retry cases fail; keep tests strict and fix failures you caused.
- CI: GitHub-hosted runners only (`.github/CI-RUNNERS.md`). Only merge-queue runs `scripts/run-guards.sh`, so run standalone guards for touched areas before opening a PR. A passing known-red guard blocks until removed from `scripts/guards-known-red.txt`.

## Execution environment and task cleanup

Read [execution and cleanup](docs/guides/TASK_EXECUTION_AND_CLEANUP.md) before builds, tests, services, or delegates. Use only Setjoin connection details; record temp resources before launch and clean only what you own.

## Programs and documentation

- Status: [program directory](docs/agents/PROGRAM_STATUS.md); queue: GitHub issues. Read only the owning plan; features stay OFF until a rollout decision admits them.
- Agent workflows: see [subagent workflow](docs/agents/subagent-workflow.md) for risk-area plan reviews, CI-first guards, merge-queue rules, and fresh read-only review gates.

## Agent skills

- **Issue tracker:** GitHub issues via `gh` (`docs/agents/issue-tracker.md`).
- **Triage labels:** five canonical roles (`docs/agents/triage-labels.md`).
- **Domain docs:** single-context (`CONTEXT.md` + `docs/adr/`, `docs/agents/domain.md`).

## Child DOX Index

- `mailserver/AGENTS.md` — frozen Go gateway, SQL reducers, webmail, oracle recorders.
- `authserver/AGENTS.md` — identity, MFA, sync, threat policy.
- `shared/AGENTS.md` — shared Go contracts, parity-vector recorder.
- `mailctl/AGENTS.md` — frozen Go CLI parity reference (shipped CLI: `server-rust/bins/mailctl/`).
- `clients/AGENTS.md` — desktop, mobile, shared Rust.
- `server-rust/AGENTS.md` — Rust server: front door, authz, commands, workers, licence policy, parity gates.
- `asrbot/AGENTS.md` — Meet captions bot.
- `docs/AGENTS.md` — documentation taxonomy and owners.

Excluded: `node_modules/`, generated `build/`.
