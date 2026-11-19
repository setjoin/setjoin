# Subagent workflow

Binding rules for delegating work to subagents. The latest owner instruction wins.

## Roles

- The **coordinator** is the Claude Code main session. It picks and sizes tickets,
  writes briefs and launches Codex. It commits Codex's work and pushes an explicit
  SHA to the ticket branch. Never push `main` or force-push. It opens PRs, waits for
  CI through the shared poller, runs gates, merges, closes issues and owns owner
  questions. It may make inline edits of at most 5 lines and logs each one.
  It runs no Claude subagents for routine work.
- The **implementer** runs Codex CLI (`codex exec`) in a workspace-write sandbox through
  `codex-work.sh <worktree> <out.md> <sol|astra> <effort> <brief-file> [session-id]`.
  The sandbox confines edits to the worktree and blocks network access. Git metadata
  lives outside the worktree, so the implementer cannot commit. A PATH stub refuses
  `cargo`, `rustc`, `go`, `npm`, `npx`, `pnpm`, `yarn`, `make` and `docker`.
  `rustfmt` is allowed. The final report is at most 20 lines and covers files changed,
  what was done, stop reasons and open questions.
- Use `gpt-6.2-sol` at medium effort by default. Use `gpt-6.2-astra` at high effort
  for L or risk-area plans, unknown causes, or escalation after sol hits the same CI
  failure twice or stops on capability. See also the M planning rule below.
- Fix rounds resume the same Codex session. Pass its session ID and point the brief
  to a file with the failing log excerpt or review findings. The coordinator reads
  CI logs only to pick the excerpt.
- Fable is the standing second opinion for risk areas. Use Opus only on owner
  request or when Codex and Fable disagree. Haiku and Sonnet are not used for
  implementation.
- Reviews never write. Gates never change product code or tests. Run one Codex
  session per worktree at a time. Run tickets that touch the same files serially.

## Sizing

Record the size on the ticket. Check the approach, callers, loop time and risk area.

**Risk areas:** auth/tokens, tenant isolation/ACL, crypto/keys/signing, user-data delete or
move, migrations, data egress, production. Auth or a migration means size M or larger.

| Size | Signals | Route |
|---|---|---|
| XS | Decided, 1-2 files | sol, low effort, with the exact edit |
| S | Up to ~4 files in one module | sol, medium effort, with the decided approach |
| M | Several modules | sol, medium effort, after a short coordinator plan in the brief. astra plans first if the approach is undecided |
| L or risk area | Large change or any risk area | astra writes a read-only plan (`-s read-only`). Fable reviews risk-area plans before code. sol implements the plan |
| ? | Cause unknown | astra investigates read-only. Size the result again |

Cap runs at ~30 min, including investigations. At the cap, write `PROGRESS.md` and
stop. The coordinator decides whether to continue, split the ticket or re-plan.
A stop is an escalation, not a failure.

If the diff exceeds the prediction, upgrade the review and re-record the size.

## Briefs

- Use a shared common brief and a short per-ticket brief. Name the files, symbols,
  approach, exact steps, verification commands, stop conditions and report format.
  Codex stays within that scope except to follow a named caller or callee.
- Give the root cause or goal with evidence (file and line, or output). Give the
  exact change per file (find, replace, base commit) and the first failing test.
- Risk-area planners list threats, failure cases (full quota, old or large data,
  restart midway, concurrency), abusable inputs and the upgrade path. Fable reviews
  the plan before code. Its cases become required tests.
- A case the implementer calls "bounded" or "unlikely" is a finding. Fix it or file a follow-up.
- Before a "delete X" ticket the coordinator checks X's callers itself.
- Keep `PROGRESS.md` so work can continue after a cut-off run.
- Any export, copy or squash step must verify that its output file list equals
  `git ls-tree -r` of the source commit.
- Include the coordinator's recurring-findings list in every implementer brief.
  Check the diff for cleanup leaks, stale docs, pinned counts, weakened assertions,
  Go-only checks skipped by a native route, transaction error paths, wrong-scope
  code and merge-resolution loss before reporting.
- Before a Rust commit, the coordinator runs `bash scripts/fmt-added.sh`.

## Builds and tests

- CI-first: builds and tests run on GitHub-hosted runners (the PR pre-check per pull-request
  update, the `server-rust lane` per merge-queue entry). Local Rust work is limited to `rustfmt`
  on files you add.
- Do not compile Rust locally. The implementer never builds. The coordinator commits and
  pushes, then reads the PR's required
  `aggregate` check (`pr-precheck.yml`: changed packages' clippy and `--lib` tests, cheap guards,
  plus the selected integration tests on the lane Postgres; ~10-25 min) through the shared poller.
  With no PR yet, the coordinator dispatches the light part only:
  `gh workflow run quick-check.yml -R setjoin/setjoin --ref <branch>` (it no longer runs on push;
  no integration tests: open a draft PR for those).
- Before fixing a failing test, search open issues and other branches for its name.
- Before committing Rust changes: `git add`, run `bash scripts/fmt-added.sh` (formats added files through stdin, the same set the pre-check checks), then `git add` the reformatted files and commit.

## Review

- Run the Codex merge gate in a fresh read-only session (`codex exec -s read-only`).
  Use sol at high effort for normal PRs and astra at high effort for risk areas.
  At most 3 rounds per ticket. A 4th means re-plan.
  - Name the diff range, files and callers to read. Paste greps the coordinator
    already ran. Codex stays within that scope and runs no builds.
  - Fix rounds get a delta review of the fix commits only.
  - Small PRs that queue together may share one call, with one verdict per PR.
  - No Codex for PRs that change no code and weaken no check: docs only, deleting
    unreferenced files (coordinator greps for references), Dependabot version bumps
    (CI is the gate). Changes to CI, guards, `deny.toml` or other checks keep Codex.
- Fable reviews risk-area plans before code and reviews the code after Codex is
  clean. No standing Claude review elsewhere.
- The coordinator reads Codex's final report and the diffstat. It reads the full
  diff when it is under ~150 changed lines or when the ticket touches a risk area.
- Verify each finding in the code before requiring a fix. One fix round carries
  all open findings. File follow-up issues for non-blocking findings.
- Gate the integration tip after several merges.
- Reviewers apply docs/standards/AI_ASSISTED_TESTING.md (time windows, normalisation) to every test diff.

## GitHub API usage

The REST limit is 5,000 calls per hour per user account, shared by every token, login and machine; going over blocks every agent until the reset.

1. Agents never poll GitHub (no `gh run watch`, no loops over `gh run view`, `gh api` or `gh issue list`). Wait for the one shared poller or a task notification.
2. One shared poller per machine, not one per job: waiters read its cache, refreshed at most every ~100 s under a file lock.
3. Use conditional requests: keep the `ETag` and send `If-None-Match`; a 304 is free.
4. Read the rate-limit headers and back off: under 1,000 left poll every 5 min, under 200 every 15 min, after a 403/429 wait for the reset.
5. An API error is never a result: retry later; never report a test, run or gate as failed because GitHub did not answer.
6. Slow intervals: CI at least every 100 s, issue/label watchers at least every 180 s.
7. Cache results per commit; fetch logs only on failure, filtered.
8. Batch reads: one list call over many single calls; GraphQL (separate budget) for issues, labels and PR checks.
9. `gh api rate_limit` is free: check it before a burst and after a 403.
10. If the limit is still too small, use a GitHub App (its own limit); a second token for the same user does not help.

## Flake rule

Re-run a failing test alone. Passes alone: flake, file it, re-gate once. Fails twice: real.

## Scripts and processes

- Never edit a script while a run uses it: write a temp file, then `mv` it into place.
- Stop only processes you started, by recorded PID and start time; never by name or pattern.
- Wait with background notifications, not polling loops. Keep status turns minimal.
- Codex and workers never touch production or git metadata outside their own worktree.
- A cut-off run continues as a fresh run that reads the worktree, issue and newest handoff.

## Cost log

Log one row per Codex or Claude run. Record the ticket, size, model, effort,
input/cached/output tokens, minutes, review rounds and outcome. The wrapper prints
the token counts. After the merge, compare prediction with actual and adjust the
size borders and the sol/astra split.
