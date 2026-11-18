# Subagent workflow

Binding rules for delegating work to subagents. The latest owner instruction wins.

## Roles

- **Coordinator** (main session): picks, sizes, plans, routes, briefs, reads receipts, runs
  merge gates, merges, closes issues and owns owner questions. It does not implement,
  except a decided edit of at most 5 lines (for example a CI or config fix inside a
  fix-push-watch loop). Log each inline edit.
- **Workers** implement, commit and push their own ticket branch. They never push `main`,
  the integration branch or anyone else's branch, never use `--no-verify`, and stop and
  report when a hook refuses. The coordinator reviews the pushed diff before any PR or merge.
- **Workers stop when they push.** They never wait on CI, inside the run or in a background
  command. The coordinator starts any lane run and waits for its notification; a red result
  starts a new fix round, and a green one goes to review.
- **Reviews never write. Gates never change product code or tests.**
- Set `model` explicitly on every agent call. Never use Opus or Fable as an implementer.
- No fixed cap on parallel editing agents. Limits: disjoint files (serialize tickets that
  touch the same code), one agent per worktree (stop the previous one before a fix round),
  and coordinator attention.

## Sizing

Record the size on the ticket. Ask: is the change decided, what is the blast radius
(grep the symbol), how long is the loop, is it a risk area?

**Risk areas:** auth/tokens, tenant isolation/ACL, crypto/keys/signing, user-data delete or
move, migrations, data egress, production. Auth or a migration means size M or larger.

| Size | Signals | Route |
|---|---|---|
| XS | decided, 1-2 files, one fast check | Haiku with the exact edit |
| S | up to ~4 files in one module, short loop, small design call | Haiku first with the decided approach; on a capability stop (wrong fix, stuck, same CI failure twice) Sonnet takes over from Haiku's `PROGRESS.md`. Tasks capped at ~30 min (slice larger ones) |
| M/L | several modules, long loop or real design | Opus planner (read-only) produces an exact plan, Haiku executes; gaps go back to the planner, never to Sonnet |
| ? | cause or approach unknown | investigate (Sonnet, Opus if hard), then size the resulting plan |

Haiku stops and reports instead of guessing: a Haiku brief names its stop conditions, and a
stop is an escalation, not a failure. Investigations skip Haiku, because a wrong diagnosis costs
more downstream (CI loops, review rounds) than the Sonnet run.

If the diff exceeds the prediction, upgrade the review and re-record the size.

The ~30 min cap covers investigations too. At the cap the worker writes `PROGRESS.md` and
stops; the coordinator decides whether to continue, re-slice or re-plan. An investigation
ends with a decided fix, which is sized again: at most 5 lines is an inline coordinator edit,
XS goes to Haiku with the exact edit. Never resume the investigator to apply a decided fix.

## Briefs

- One shared common brief plus a short per-ticket brief: paths, exact steps, verify
  commands, stop conditions, report format.
- Plan format: root cause or goal with evidence (file:line, output); exact change per
  file (find, replace, base commit); the first failing test.
- Risk-area planners list threats, failure cases (full quota, old or large data, restart
  midway, concurrency), abusable inputs and the upgrade path. The plan gets a Fable review
  before any code; its cases become required tests.
- A case a worker calls "bounded" or "unlikely" is a finding: fix it or file a follow-up.
- Before a "delete X" ticket the coordinator checks X's callers itself.
- Workers keep a `PROGRESS.md` so a cut-off run resumes (SendMessage to the same agent).
- Any export, copy or squash step must verify that its output file list equals
  `git ls-tree -r` of the source commit.

## Builds and tests

- CI-first: builds and tests run on GitHub-hosted runners (the PR pre-check per pull-request
  update, the `server-rust lane` per merge-queue entry). Local Rust work is limited to `rustfmt`
  on files you add.
- Do not compile Rust locally. Workers push and stop; the coordinator reads the PR's required
  `aggregate` check (`pr-precheck.yml`: changed packages' clippy and `--lib` tests, cheap guards,
  plus the selected integration tests on the lane Postgres; ~10-25 min) through the shared poller.
  With no PR yet, the coordinator dispatches the light part only:
  `gh workflow run quick-check.yml -R setjoin/setjoin --ref <branch>` (it no longer runs on push;
  no integration tests: open a draft PR for those).
- Before fixing a failing test, search open issues and other branches for its name.
- Before committing Rust changes: `git add`, run `bash scripts/fmt-added.sh` (formats added files through stdin, the same set the pre-check checks), then `git add` the reformatted files and commit.

## Review

- Codex merge gate: `codex exec -m gpt-6.2-astra` (codex-cli >= 0.169), reasoning `high`, read-only. At most 3
  rounds per ticket; a 4th means re-plan. Usage is input-bound (files read, not reasoning):
  - The prompt names the diff range, the files and callers to read, and pastes greps the
    coordinator already ran; Codex does not explore the repo beyond that or run builds.
  - Before round 1 a Haiku pre-check reads the diff against the coordinator's recurring
    Codex findings list. Fix rounds get a delta review of the fix commits only.
  - Small PRs that queue together may share one call, with one verdict per PR.
  - No Codex for PRs that change no code and weaken no check: docs only, deleting
    unreferenced files (coordinator greps for references), Dependabot version bumps
    (CI is the gate). Changes to CI, guards, `deny.toml` or other checks keep Codex.
- Fable reviews risk areas (plan review before code, code review after Codex is clean).
  Opus reviews other M/L work. No Claude review for XS or for S outside risk areas.
- Never review with the planner or the implementer.
- Verify each finding in the code before requiring a fix. One fix round carries all open
  findings. Non-blocking findings become follow-up issues; do not widen the ticket.
- Gate the integration tip itself after several merges.
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

After every hand-back, the coordinator logs one line per run (token and minute figures from the
agent cost tool): ticket, size, model, tokens, minutes, review rounds, outcome. After
the merge compare prediction with actual and adjust the size borders. Token counts are a
mis-size alarm, not a cap. Review cost per merged ticket periodically.
