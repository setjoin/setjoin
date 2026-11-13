# Contributing to setjoin

The counted path from a fresh clone to a green test suite. Follow it top to
bottom; each step names the exact command and the expected output.

> **Architecture in one line:** business logic lives in PL/pgSQL reducers
> (`mailserver/sql/reducers/`); the Go gateway is a thin protocol translator.
> Read [`AGENTS.md`](AGENTS.md) (project rules + the per-area doc index) and
> [`CONTEXT.md`](CONTEXT.md) (the domain glossary) before changing code.

## Prerequisites

Versions are read from `go.mod` / the build scripts — install at least these:

| Tool         | Version | Why                                              |
|--------------|---------|--------------------------------------------------|
| Go           | 1.26.4+ | gateway, auth server, `mailctl` (`go.mod`)       |
| Node + npm   | 20+     | webmail (Svelte 5 / Vite 8)                       |
| PostgreSQL   | 18+     | server **and** `psql` client; all data + logic   |
| pg_prove     | any     | pgTAP runner (`cpan TAP::Parser::SourceHandler::pgTAP`) |
| PgBouncer    | any     | query pool — **runtime only**, not needed for tests |
| SeaweedFS (`weed`) | recent | blob storage — only for the **live** dev server |
| libopus (`pkg-config opus`) | any | Meet captions bot (`asrbot/`) — optional; missing it LOUDLY skips just that module in `build.sh`/`test.sh`/`lint.sh` (`brew install pkg-config opus` / `apt install pkg-config libopus-dev`) |

The pgTAP + Go test suites need **only** PostgreSQL (direct, `127.0.0.1:5432`,
role `mail`). PgBouncer and SeaweedFS are for running the live server
(`scripts/setup-test-env.sh`), not for `scripts/test.sh`.

> **No AI tooling required.** `scripts/test.sh`, `scripts/build.sh`, and everything
> in this guide run without any agent skills or hooks.

## Clone → green (the counted path)

```bash
# 1. Clone
git clone https://github.com/setjoin/setjoin.git
cd setjoin

# 2. Preflight — verifies your toolchain + a reachable, baseline-loaded test DB,
#    failing LOUD with a named fix instead of a cryptic error mid-suite.
bash scripts/preflight.sh

# 3. Load the test database (MANDATORY before any DB test).
#    Recreates mailserver_test from the collapsed baseline:
#    V001__baseline.sql → forward migrations → reducers ×2 → pgTAP fixtures.
bash scripts/load-test-schema.sh
#    → ends with: "==> Schema loaded clean."

# 4. Run the full suite (Go + webmail + pgTAP).
bash scripts/test.sh
```

`scripts/test.sh` invokes `preflight.sh` at the top, so step 2 is also enforced
automatically (set `PREFLIGHT_SKIP=1` to bypass in a CI image that provisions
services separately).

### Expected result

The mailserver pgTAP, Go, and webmail Vitest lanes must all pass. Exact test counts
are intentionally emitted by the runners instead of copied into this guide, so a
new required case cannot make the documentation stale. Missing, skipped, failed,
ambiguous, malformed, or flaky-after-retry named cases fail the canonical gate.

## The edit-a-reducer loop

Reducers are the heart of the system. After a fresh `load-test-schema.sh`, you
don't reload the whole schema for each change — just the reducers:

```bash
# 1. Edit a reducer (one function per file).
$EDITOR mailserver/sql/reducers/transition_message_location.sql

# 2. Reload reducers into the loaded test DB (fail-loud; names a broken file).
DB_NAME=mailserver_test bash scripts/reload-reducers.sh

# 3. Re-run just the affected pgTAP test(s).
pg_prove -d mailserver_test mailserver/sql/tests/jmap_email.pg
```

`reload-reducers.sh` loads files in deterministic path order and iterates to a
fixed point: a file that fails (e.g. a forward reference to a function that
hasn't loaded yet) is retried on the next iteration until an iteration adds
zero new successes. Whatever survives at the fixed point — a genuine SQL error
or a real dependency cycle — is fatal and **names the file**; a transient
connection blip (exit 2) is retried inline with backoff. It never silently
drops a reducer.

Reducer conventions (enforced — see `mailserver/sql/AGENTS.md`): `p_`/`v_`
prefixes; errors via `RAISE EXCEPTION ... USING ERRCODE='BZ0xx'`; mutating
reducers bump the relevant `jmap_*_state` in-txn; every reducer needs a pgTAP
test; never `NOT NULL` on a function parameter.

## Parallel builds and the role-provisioning race

The sequential `check-schema-determinism.sh` guard (double-build + normalized
`pg_dump` diff) is green; an earlier draft blamed "connection pressure / a
different MISSING-objects set each time," but that diagnosis was **wrong** and is
overturned. The real flake only appears under **truly parallel** builds (a CI
matrix, or two `load-test-schema.sh` runs sharing one Postgres cluster): roles +
GRANTs are cluster-global catalog objects, so concurrent runs race on them
(`tuple concurrently updated` / `duplicate_object`).

This is now **self-healing**: `load-test-schema.sh` step 4 retries
`provision-roles.sql` with jittered backoff (it's idempotent), so you may see a
benign `OK (after N attempts — lost a cluster-global role race, idempotent retry
won)` line under parallel builds — that is expected, not an error. A real
schema-determinism failure reproduces every run.
Do **not** weaken the fail-loud `ON_ERROR_STOP=1` contract to quiet it.

### Parallel git worktrees: give each one its own test DB

Two worktrees running the gate at the same time against the shared
`mailserver_test` clobber each other's fixtures (one worktree's `go test ./...`
seeds users, another's pgTAP run reads them mid-suite). Every DB script
(`load-test-schema.sh`, `reload-reducers.sh`, `preflight.sh`, …) already reads
its target database from the `DB_NAME` env var (default `mailserver_test` —
zero change if you don't set it), so a second worktree just needs its own name:

```bash
# In worktree #2:
DB_NAME=mailserver_test2 bash scripts/load-test-schema.sh
```

`scripts/worktree-gate.sh <db-name>` wraps this: it loads the schema into
`<db-name>`, then runs `go build`/`go test` (with `DB_DSN` pointed at
`<db-name>`) and pgTAP (`pg_prove -d <db-name>`) against it — the same three
gates `scripts/test.sh` runs, parameterized so it never touches the default
`mailserver_test`:

```bash
bash scripts/worktree-gate.sh mailserver_test2
```

## Other commands

```bash
bash scripts/build.sh         # build mailserverd + authserverd
bash scripts/lint.sh          # Go + web type/ESLint/Stylelint checks
bash scripts/quality.sh fast  # all authored-language change-time checks
bash scripts/quality.sh full  # fast + Clippy/platform-owned checks
bash scripts/e2e.sh [imap|smtp|ldap]   # protocol end-to-end tests
bash scripts/setup-test-env.sh         # run the live dev server (needs weed)
```

## Resume whole-codebase security coverage

The control plane is read-only by default. From a fresh shell, run:

```bash
bash scripts/verify-security-program.sh --doctor
bash scripts/verify-security-program.sh coverage status
bash scripts/verify-security-program.sh coverage resume
```

The first two commands must report verified state. `resume` may exit 3 with a
structured HOLD while prerequisites remain; it never starts a scanner. Ownership:
inventory and section changes stay with the root security maintainer; attempt/lease,
publication, CLI/error, guide, and benchmark changes require their focused
security-program tests plus the single `--self-test` front door. Full procedures are
in [`docs/guides/security-remediation/START-HERE.md`](docs/guides/security-remediation/START-HERE.md).

To extend the security program, change the owning source and its proof together:

- Add or move a section in `PROVISIONAL_SECTION_CATALOG`, regenerate the canonical C0
  records through the approved compiler flow, and prove exact union/no overlap.
- Change shard construction in the inventory module and add exact count, order, and
  path-token round trips to `security-program-inventory.test.mjs`.
- Add schema adapters in `scripts/lib/security-program-migrations.mjs`; test old/current,
  unknown-future, active-attempt fence, interruption replay, and rollback rejection.
- Add each `E_SECURITY_PROGRAM_*` code to the CLI catalog and troubleshooting guide,
  with a code-specific exit family, safe action, and `rerun.argv` assertion.
- Put planted failures in the nearest `security-program-*.test.mjs`, assert the exact
  fail-closed code, and retain scanner/network start counts of zero. Benchmark changes
  must refresh the source-bound retained JSON and pass its digest/current-source reader.

## Focused architecture checks

For Architecture Round 3 workstreams, use the current focused front door. It
composes the package tests already owned by each workstream and retains an atomic,
hash-bound manifest. Run doctor first when the local toolchain or PostgreSQL state is
unknown:

```bash
bash scripts/verify-architecture-r3.sh --doctor
bash scripts/verify-architecture-r3.sh --help
bash scripts/verify-architecture-r3.sh
bash scripts/verify-architecture-r3.sh migration-checkpoint
bash scripts/verify-architecture-r3.sh mam-lifecycle --self-test
bash scripts/verify-architecture-r3.sh aal2 --json --verbose
bash scripts/verify-architecture-r3.sh evidence
bash scripts/verify-architecture-r3.sh evidence --run-id <run-directory>
bash scripts/check-architecture-r3-evidence.sh --self-test
```

The no-argument command attempts all eight named focused lanes. Every lane's
`--self-test` routes a disposable tool mutant through the actual lane command,
requires the expected failed manifest and stable diagnostic, and verifies the
working-tree digest is unchanged. `--json` emits one summary object; `--verbose`
streams the underlying lane while retaining the same manifest.

`compatibility`, `devices` and `live-media` validate real source-bound release
receipts below `test-results/architecture-r3/release-evidence/`; missing evidence
is a stable fail-closed result, never a local surrogate pass. `core` runs the eight
lanes and merge aggregate. `full` additionally requires those three release groups
and validates the release aggregate. Completed runs retain results below
`test-results/architecture-r3/`.
The checked-in exact-case authority is
`docs/verification/architecture-r3-cases.json`; its evidence checker rejects
unknown, duplicate, missing, skipped, unsupported, malformed,
flaky-after-retry, source-mismatched and hash-mismatched results. Physical
device, retained-binary and live-media cases stay separate release gates and
cannot be satisfied by local surrogate evidence.
Once every focused lane is green for the same source state, `evidence` composes and
checks the merge dossier. Release evidence uses
`node scripts/aggregate-architecture-r3-evidence.mjs --gate release --release-root <dir>`.
For the DX timing contract, run
`bash scripts/verify-architecture-r3.sh benchmark`: two discarded warmups followed
by 20 same-fingerprint quick samples, nearest-rank p95 ≤300 seconds.

For route, app-navigation, worker-lifecycle, feature-registry, upgrade-hold, or
native-bridge changes, start with the five-minute front door:

```bash
bash scripts/verify-architecture-r2.sh --doctor
bash scripts/verify-architecture-r2.sh --help
bash scripts/verify-architecture-r2.sh
bash scripts/verify-architecture-r2.sh route --self-test
```

The no-argument command runs the six hermetic lanes and publishes atomic,
hash-bound evidence below `test-results/architecture-r2/`. `full` adds the
isolated registry database lane and canonical deterministic gates. CI measures
the same quick command with a five-sample surrogate; scheduled/promotion runs
use the twenty-sample p95 contract.

See
[`docs/guides/FEATURE_REGISTRY_DEVELOPMENT.md`](docs/guides/FEATURE_REGISTRY_DEVELOPMENT.md)
for copy-paste route, app prefix, worker, feature-key/V184+, native-member,
N-1, rollback, diagnostics, and benchmark recipes. Developers may run the
registry/native generators with `--write`; CI always uses check-only mode.

Webmail-only checks (run from `mailserver/webmail`):

```bash
npm ci
npm run check      # 0 errors / 0 warnings required
npm run lint       # ESLint TypeScript/Svelte correctness rules
npm run lint:css   # Stylelint CSS/Svelte style rules
npm test           # Vitest
```

## House rules (the short version)

- **Branch off `main`** for work. Commit/push only when asked.
- **Go:** `golangci-lint run ./...` clean; `slog` logging; propagate
  `context.Context`; no cross-package copy-paste (extract to `internal/` shared
  packages).
- **Webmail (Svelte 5 runes):** `$state`/`$derived`/`$effect`, `onclick=` (not
  `on:click`); token-only styling; type, ESLint and Stylelint gates must be clean.
- **All authored languages:** use the checked-in, check-only quality front door;
  suppressions must be narrow and reasoned. See
  [`docs/standards/CODE_QUALITY.md`](docs/standards/CODE_QUALITY.md).
- **DB security (enforced):** every user-data query filters by
  `user_id`/`mailbox_id` from the auth context; ownership in the same `WHERE`;
  no `fmt.Sprintf` of user input into SQL. See
  [`docs/standards/DATABASE_SECURITY.md`](docs/standards/DATABASE_SECURITY.md).
- **Docs are canonical:** update the nearest owning `AGENTS.md` when a change
  affects purpose, contracts, workflows, or durable structure (the "Update After
  Editing" pass in [`AGENTS.md`](AGENTS.md)). `CLAUDE.md` is a symlink to it.

## Where things live

| Area            | Doc                            |
|-----------------|--------------------------------|
| Project rules + index | [`AGENTS.md`](AGENTS.md)  |
| Domain glossary | [`CONTEXT.md`](CONTEXT.md)      |
| Mail server (Go + reducers + webmail) | `mailserver/AGENTS.md` |
| Reducers / schema / tests | `mailserver/sql/AGENTS.md` |
| Auth server     | `authserver/AGENTS.md`         |
| Admin CLI       | `mailctl/AGENTS.md`            |
| Integration (curl flows) | [`docs/guides/INTEGRATION_EXAMPLES.md`](docs/guides/INTEGRATION_EXAMPLES.md) |
| Single-node prod | [`docs/guides/SINGLE_NODE_SETUP.md`](docs/guides/SINGLE_NODE_SETUP.md) |
| Feature registry + architecture checks | [`docs/guides/FEATURE_REGISTRY_DEVELOPMENT.md`](docs/guides/FEATURE_REGISTRY_DEVELOPMENT.md) |

Thanks for contributing.
