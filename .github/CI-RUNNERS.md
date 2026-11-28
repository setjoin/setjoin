# CI runners and labels

Every workflow runs on GitHub-hosted runners. `scripts/guards/check-workflow-log-hygiene.sh`
(run by `scripts/run-guards.sh`) fails on any `self-hosted` mention outside a comment.

## Where jobs run

| Label | Used by |
|---|---|
| `ubuntu-24.04` | webmail, rust-floor (x86_64, loongarch64), meet-renderer-qualification |
| `ubuntu-24.04-arm` | rust-floor (aarch64) |

`webmail.yml` runs svelte-check and the Vitest coverage ratchet on `webmail/**` changes
(pull_request, push to main, manual). The legacy Go `xinchuang-ci.yml` was removed (#142); the
structural guards run in the server-rust lane's `guards` job (below) and locally (`scripts/run-guards.sh`).

rust-floor runs on push to main and manual dispatch only (no pull_request trigger) and runs `scripts/ci/cross-build.sh --rust` in glibc 2.28 (x86_64/arm64) and a glibc 2.36 loong64
sysroot, checks ELF version needs and smokes the gateway in a scratch loong64 runtime.

## Rules

- Pin the image (`ubuntu-24.04`, not `ubuntu-latest`) so an image bump is a reviewed change.
- No workflow publishes releases yet; release builds and owner-side signing are planned
  separately. No job holds signing material.
- Fork pull requests get a read-only token and no secrets; jobs that run on
  `pull_request` must not need secrets.

## Log hygiene

Steps print tool versions only (`rustc --version`, `node --version`), never environment or
host dumps (`env`, `printenv`, `go env`, `set -x`, `docker info`, `uname -a`, `ip addr`).
The same guard enforces this.

## server-rust lane (GitHub-hosted)

`.github/workflows/server-rust-lane.yml` (its `pgtap` job runs the mailserver/authserver reducer pgTAP suites and its `guards` job runs `scripts/run-guards.sh --known-red scripts/guards-known-red.txt`; both gate `aggregate`) runs only on GitHub-hosted `ubuntu-latest` runners (no
self-hosted label) and, on the `main` merge queue, runs the FULL lane on `merge_group` and `workflow_dispatch`.
Each queue entry has its own run. Without batching (the default) every entry runs the full lane on its own commit.
With `LANE_QUEUE_BATCHING=1` (repo variable) and the ruleset on HEADGREEN, the `queue` job lets the entry with no
later queued entry (the batch head) run the full lane on its commit, which contains every earlier entry, while each
entry with a later queued entry waits: its run stays in progress, its queue job polls every 60 s and runs no lane.
Later means a queue branch whose commit descends from the entry's commit (`git for-each-ref --contains` over a
`--filter=tree:0` fetch of the public repo; anonymous). The name suffix is logged as a cross-check only.
A later ref whose merge_group lane run is completed with a conclusion other than `success` does not count: GitHub
keeps a failed entry's ref queued under HEADGREEN, which held the earlier entries until CAP in the live pilot
(2026-11-17). The `queue` job asks the Actions API for that (one curl child per later sha, `actions: read`, the only API call
of the queue job; `server/DOX.md#parallel-full-lane-550`). Unknown answers keep the ref later.
Timing: SETTLE 120 s before the first decision, CAP 5400 s (90 min); no git or API call starts at or after the CAP, and the
worst-case I/O of one poll is 255 s (git 180 s, plus up to five run lookups of 15 s), and each subprocess checks the deadline first.
The ancestry fetch is `--depth 6` (the ruleset's batch of 5 plus one); a shallow miss means head, never an untested merge. The queue job
times out at 110 min (6600 s), above CAP + 255 s + 300 s of setup (5955 s). The 255 s is enforced by subprocess kills: each git call and each API lookup is a child run by `subprocess.run` with a timeout, and the child is killed at it. A per-socket urlopen timeout would not bound a trickling response.
Worst case for one entry: SETTLE + CAP + the lane. Any ls-remote or fetch error waits, and at the CAP the entry runs the
full lane itself: slower, never unsafe. A late arrival (queued after the head had already decided) runs its own lane. A waiter holds one hosted runner (up to four
while a head runs). A `gone` entry (its branch left the queue) runs nothing and its `aggregate` is red, with the summary
"nothing ran; not a test pass"; the red sits on a commit nothing reads. A check_response_timeout (360 min) overrun
ejects the entry, which fails closed. Every waiter keeps `aggregate` pending until it ends, never green. Intermediate
commits of a batch are not tested one by one: the batch tip's lane is their test. The nightly full lane is the backstop.
Rollback and rollout: `server/DOX.md#parallel-full-lane-550`.
A push to `main` only refreshes the cache (`build`; no tests, summary
"cache refresh only, no tests"), and a nightly `schedule` (02:30 UTC) runs the full lane plus coverage as the backstop,
skipping cleanly when main has no commit in the last 26 hours. It never runs on `pull_request`; PRs get only `.github/workflows/pr-precheck.yml`
(jobs `light` = `scripts/ci/quick-check.sh` and `integration` = the changed packages' integration tests selected by
`scripts/ci/precheck-integration.py`, gated by a job also named `aggregate`). The rows above do not apply to either. Images come from `ghcr.io/setjoin` as pinned
in `.github/ci/images.lock`. See `server/DOX.md#parallel-full-lane-550`.

`run-guards.sh --known-red FILE` tolerates the guards named in `scripts/guards-known-red.txt` (each with an
issue reference, today #348): they still run and warn. The allowlist only shrinks: a listed guard that
passes fails the run until its line is removed; a name with no guard file is an error.
`scripts/run-guards-selftest.sh` proves these cases and runs before the guards in the job;
`scripts/guards/check-test-gate-wiring.sh` asserts the job and its `aggregate` requirement.

## quick check (agent branches)

`.github/workflows/quick-check.yml` is one `ubuntu-latest` job (pinned lane image, `scripts/ci/quick-check.sh`) on `workflow_dispatch` only (`packages`, `tests`; pull requests get the same script from `pr-precheck.yml`): `cargo clippy --all-targets` (errors fail, lints are warnings) + `cargo test --lib` for changed packages, cheap guards, rustfmt on added files.
It stays one job so it never competes with the 19-job full lane for the 20-job concurrency limit; pull requests run only `pr-precheck` and the merge queue runs the full lane (per batch head when batching is on; waiting entries run none).

## PR pre-check (`pr-precheck.yml`)

On every pull-request update: `light` (as quick check above) and `integration` run side by side (peak two jobs per PR),
then a ~10 s gate job `aggregate`, the ruleset's required check, is red unless both succeeded. `integration` ends at once
when no `server/` file other than `*.md` changed. Otherwise `scripts/ci/precheck-integration.py plan` selects test targets
(rule in its docstring, fixtures in `selftest`, which runs first in the job): every `tests/*.rs` target of each changed
package and of its normal/build reverse dependents when there are at most 5 of them; for `setjoin-gateway` and
`setjoin-auth` only targets whose test file changed or names a changed test helper or golden, or whose name matches a
changed path (soft caps 30 and 20: over the cap, only changed or referencing test files run);
nothing for `server/Cargo.toml`, `Cargo.lock` or `rust-toolchain*` changes. It runs them through
`scripts/ci/server-rust-parallel-lane.sh` with `SERVER_RUST_STAGES=workspace` and `SERVER_RUST_NEXTEST_SELECT` on the lane
Postgres (`REQUIRE_DB=1`, skip markers, ignored and zero tests red), restoring the `lane` cargo cache
without saving. The test step is capped at 30 minutes (job 45; an auth-domain selection of ~2000 tests needs ~5 min build + ~16 min tests + teardown); hitting the cap is red. Anything not selected, doc tests,
replays, mutants and coverage stay with the merge queue's full lane.
