# CI runners and labels

Every workflow runs on GitHub-hosted runners. `scripts/check-workflow-log-hygiene.sh`
(run by `scripts/run-guards.sh`) fails on any `self-hosted` mention outside a comment.

## Where jobs run

| Label | Used by |
|---|---|
| `ubuntu-24.04` | webmail, rust-floor (x86_64, loongarch64), meet-renderer-qualification |
| `ubuntu-24.04-arm` | rust-floor (aarch64) |

`webmail.yml` runs svelte-check and the Vitest coverage ratchet on `mailserver/webmail/**` changes
(pull_request, push to main, manual). The legacy Go `xinchuang-ci.yml` was removed (#142); the
structural guards run in the server-rust lane's `guards` job (below) and locally (`scripts/run-guards.sh`).

rust-floor runs on push to main and manual dispatch only (no pull_request trigger) and runs `scripts/cross-build.sh --rust` in glibc 2.28 (x86_64/arm64) and a glibc 2.36 loong64
sysroot, checks ELF version needs and smokes the gateway in a scratch loong64 runtime.

## Rules

- Pin the image (`ubuntu-24.04`, not `ubuntu-latest`) so an image bump is a reviewed change.
- No workflow publishes releases yet; release builds and owner-side signing are planned
  separately. No job holds signing material.
- Fork pull requests get a read-only token and no secrets; jobs that run on
  `pull_request` must not need secrets.

## Log hygiene

Steps print tool versions only (`go version`, `node --version`), never environment or
host dumps (`env`, `printenv`, `go env`, `set -x`, `docker info`, `uname -a`, `ip addr`).
The same guard enforces this.

## server-rust lane (GitHub-hosted)

`.github/workflows/server-rust-lane.yml` (its `pgtap` job runs the mailserver/authserver reducer pgTAP suites and its `guards` job runs `scripts/run-guards.sh --known-red scripts/guards-known-red.txt`; both gate `aggregate`) runs only on GitHub-hosted `ubuntu-latest` runners (no
self-hosted label); the rows above do not apply to it. Images come from `ghcr.io/setjoin` as pinned
in `.github/ci/images.lock`. See `server-rust/DOX.md#parallel-full-lane-550`.

`run-guards.sh --known-red FILE` tolerates the guards named in `scripts/guards-known-red.txt` (each with an
issue reference, today #348): they still run and warn. The allowlist only shrinks: a listed guard that
passes fails the run until its line is removed; a name with no guard file is an error.
`scripts/run-guards-selftest.sh` proves these cases and runs before the guards in the job;
`scripts/check-test-gate-wiring.sh` asserts the job and its `aggregate` requirement.

## gofree record (manual, deleted with Go)

`.github/workflows/gofree-record.yml` is `workflow_dispatch` only (`contents: read`, `packages: read`;
no pull_request or push trigger). It records new Go-free oracle goldens from the frozen Go coverage
binary inside the pinned `setjoin-ci-linux-tc` image, never commits, and uploads new goldens plus a
`git status --porcelain` and diff as an artifact. It is removed with Go (#142).
