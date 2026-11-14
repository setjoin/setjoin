# CI runners and labels

Every workflow runs on GitHub-hosted runners. `scripts/check-workflow-log-hygiene.sh`
(run by `scripts/run-guards.sh`) fails on any `self-hosted` mention outside a comment.

## Where jobs run

| Label | Used by |
|---|---|
| `ubuntu-24.04` | xinchuang-ci (all jobs), rust-floor (x86_64, loongarch64), meet-renderer-qualification |
| `ubuntu-24.04-arm` | rust-floor (aarch64) |

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

`.github/workflows/server-rust-lane.yml` runs only on GitHub-hosted `ubuntu-latest` runners (no
self-hosted label); the rows above do not apply to it. Images come from `ghcr.io/setjoin` as pinned
in `.github/ci/images.lock`. See `server-rust/DOX.md#parallel-full-lane-550`.
