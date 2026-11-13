# Code quality and static-analysis standard

Status: mandatory for newly changed code. The fixed machine-readable catalog is
`config/quality-tools.json`; the evidence and license review is
`retired-docs:superpowers/research/2026-08-25-repository-static-analysis-toolchain.md`.

## Objectives

Setjoin separates three concerns instead of treating every tool as a generic
"linter":

1. code conventions and deterministic formatting;
2. compiler/type/static correctness and project-specific invariants; and
3. source, dependency, container and deployment security.

A blocking gate must be pinned, reproducible without uploading source, and usable from a
checked-in front door. Scanners must not install themselves, fetch unpinned rule
packs, rewrite source, or contact production systems during a check.

## Front doors

```bash
bash scripts/quality.sh list       # fixed language/tool inventory
bash scripts/quality.sh doctor     # runner readiness, no scan
bash scripts/quality.sh fast       # change-time blocking checks
bash scripts/quality.sh full       # fast + Clippy/platform checks
bash scripts/quality.sh security   # dependency, secret and workflow authorities
```

## Language ownership matrix

| Authored surface | Convention/correctness authority | Security authority | Runner |
| --- | --- | --- | --- |
| Go | `gofmt`; GolangCI with a small reviewed set | `govulncheck`; curated `gosec` where enabled | macOS + Ubuntu |
| PL/pgSQL/SQL | schema load, PostgreSQL parser, project guards, pgTAP | R1-R4/RLS/reducer guards | Ubuntu + disposable PostgreSQL |
| TypeScript/Svelte/CSS | strict TypeScript, `svelte-check`, ESLint, Stylelint | npm audit and project CSP/XSS tests | macOS + Ubuntu |
| Electron TypeScript | TypeScript and Biome | npm audit and Electron security tests | macOS + Ubuntu/Windows packaging |
| Rust | `rustfmt --check`, Clippy with warnings denied | guarded RustSec audit | macOS + Ubuntu |
| ArkTS | pinned Hvigor/DevEco compile and Setjoin bridge guards | platform build/security checks | DevEco-capable macOS runner |
| Shell | declared-shell syntax, ShellCheck, and shfmt debt ratchet | ShellCheck plus project destructive-action guards | macOS + Ubuntu |
| Python | parser gate plus pinned Ruff check/format | choose one measured AST rule owner before promotion | Ubuntu |
| PowerShell | parser gate; PSScriptAnalyzer | signed collector and Exchange evidence guards | Windows |
| Docker/YAML/JSON/TOML | owning schema/build checks | Actionlint for workflows | Ubuntu |

There is no tracked authored Swift, Kotlin or Java. Tauri/UniFFI-generated
products are checked by their platform compiler/build lane; generated or
vendored reference code must not become a second lint authority.

## Go authoring conventions

Beyond the toolchain gate above, Go code follows these house rules:

- `golangci-lint run ./...` clean.
- Typed discriminator constants.
- `slog` for logging.
- Propagate `context.Context`.
- Extract shared code instead of copy/paste.
- Register every new package in its owning child DOX.

## Current Go ratchet

The repository-wide root GolangCI configuration blocks on `govet` and
`ineffassign`; mailserver keeps its broader reviewed set. The first unlimited
mailserver `errcheck` pass found 328 occurrences under the old generic close/copy
exclusions. Eight were corrected; removing those exclusions exposed 67 more, so
the remaining 387 are registered by exact path and call name in
`config/errcheck-mailserver.baseline`; `scripts/check-errcheck-ratchet.sh`
rejects every new occurrence and every multiplicity increase. This is an
explicit debt ledger, not a clean-lane claim. Entries are removed as code is
fixed; the broad duplicate Gosec G104 diagnostic stays disabled only because the
exact ratchet owns that finding class.

## SQL boundary

Generic SQL formatters cannot prove mailbox ownership, RLS, reducer state bumps,
transactional notifications or audit effects. PostgreSQL schema load, pgTAP and
Setjoin's database-security guards remain authoritative.

## Suppressions and generated code

- Fix a real defect before suppressing it.
- A suppression names the exact rule, has the smallest practical scope, and
  explains why the operation is safe or intentionally ignored.
- Do not disable an analyzer by matching its entire diagnostic class unless a
  stricter checked-in exact-occurrence ratchet owns that same class and the
  exception names the replacement gate.
- Do not weaken tests, warnings-as-errors, type checking or security rules to
  make a lane green.
- Exclude generated builds, dependency trees, offline references and retained
  evidence at the inventory boundary, not through scattered wildcard ignores.
- Auto-fix commands are developer conveniences only; blocking lanes are
  check-only and the resulting diff must be reviewed.

## Admission of another tool

A new tool enters the catalog only after all of the following are recorded:

1. exact version and license obligations;
2. checked-in configuration and deterministic exit-code contract;
3. an offline installation or mirror procedure for the owning runner;
4. a self-test proving malformed input or a planted finding fails;
5. measured noise/duplication against existing authorities; and
6. a clean repository run, or a checked-in exact-occurrence debt ledger that
   rejects additions and is described honestly as a ratchet rather than clean.

Ruff is blocking. shfmt is addition-blocking with 147 registered legacy files.
PSScriptAnalyzer 1.25.0 is clean locally and remains Windows-only for its platform
gate. Gitleaks scans staged changes (`--pre-commit`); the stale full-history
baseline was retired for the public release (#555). Actionlint is clean. Semgrep, OSV Scanner, Trivy, Zizmor, `plpgsql_check`,
Hadolint, yamllint, cargo-deny and the unverified ArkTS Code Linter were removed
from the active catalog on 2026-08-25: they did not have a deterministic,
offline, clean and non-duplicative runner contract. Reconsidering one requires a
new evidence-backed admission rather than carrying a non-running queue.
