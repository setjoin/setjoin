# Subagent workflow

Binding rules for orchestrating, delegating, and reviewing Setjoin work. The latest owner instruction wins.

## Authority & isolation

- **Root session** owns git commits, explicit-SHA pushes to feature branches (never push `main` or force-push), PRs, merges, issue tracking, and owner decisions.
- **Parallel writers** use isolated worktrees (one writer per worktree); serialize tickets touching overlapping files. Workers never touch production or git metadata outside their worktree.
- **Reviews** run read-only and never share the authoring session.

## Risk-area plan review

Changes touching **auth/tokens, tenant isolation/ACL, crypto/keys/signing, user-data delete/move, migrations, data egress, production**, or concurrency/protocol design write a short `PLAN.md` (threats, invariant, failure cases—full quota, old/large data, mid-run restart, concurrency—abusable inputs, upgrade path, and required tests; keep `PLAN.md` out of commits) and get a **fresh read-only plan review** before coding. Reviewer cases become required tests.

Investigate unknown causes read-only first. Cap stalled runs (~30 min) by writing `PROGRESS.md` and escalating.

## Pre-report checklist

- Treat "bounded" or "unlikely" caveats as findings: fix them or file a follow-up.
- Check callers before any "delete X" ticket; verify export/copy/squash file lists match `git ls-tree -r` of the source commit.
- Check diffs for: cleanup leaks, stale docs, pinned counts, weakened assertions, Go-only checks skipped by native routes, transaction error paths, wrong-scope code, and merge-resolution loss.

## Builds, guards & tests

- **CI-first:** run builds and tests on GitHub-hosted runners (`pr-precheck.yml` `aggregate` on PRs; `server-rust lane` on merge queue; manual `gh workflow run quick-check.yml -R setjoin/setjoin --ref <branch>` without a PR).
- **Local Rust:** no local Rust compilation; run `rustfmt` on added files only (`git add`, `bash scripts/fmt-added.sh`, `git add`, commit).
- **Standalone guards:** PR pre-check omits merge-queue `guards`, so run relevant no-cargo/no-DB guards before opening a PR:
  - Reducers/callers: `bash scripts/check-audit-coverage.sh`, `bash scripts/check-app-notify.sh`
  - Route flips: `python3 scripts/test-check-gofree-rehearsal.py`
  - New SQL functions: `bash scripts/check-xinchuang-matrix.sh`
  - Conformance READMEs: `bash scripts/check-recorder-docs.sh`
  - Oracle/catalog changes: `python3 scripts/check-gofree-oracle-adequacy.py --preflight-only`
  - AGENTS/DOX edits: `bash scripts/check-agent-context-budget.sh`, `bash scripts/check-agent-docs.sh`
- Search open issues and branches before fixing a failing test.
- **Flake rule:** rerun a failing test alone (passes = flake, file + re-gate once; fails twice = real failure).

## Review gate

- Run a fresh read-only review per PR (never the authoring session) with explicit diff range, files/callers, and pre-run greps. Small PRs queuing together may share one call (one verdict per PR).
- Skip LLM review for pure docs-only changes, deleting unreferenced files (after grepping callers), and Dependabot version bumps (CI is gate); keep review for CI, guards, `deny.toml`, and code.
- Verify findings in code and label each `INTRODUCED` or `PRE-EXISTING`, plus `IN-SCOPE` or `OUT-OF-SCOPE`. Only `INTRODUCED` or `IN-SCOPE` defects block; file follow-ups for non-blocking findings.
- Bundle all open blocking findings into one fix round; fix rounds get a delta review of fix commits only. Max 3 rounds normal (4th triggers re-plan); 1 full + 1 delta for risk areas (escalate unresolved disputes to owner).
- Apply `docs/standards/AI_ASSISTED_TESTING.md` to test diffs; gate the integration tip after several merges.

## Merge queue & GitHub API

- Merge `origin/main` (merge commit, never force-push) into each ticket branch before queuing; resolve conflicts and rerun CI if needed. Queue green PRs as a group.
- Respect the shared 5,000 REST/hr account limit: never run `gh run watch` or polling loops; use `If-None-Match` ETags (304 is free), batch/GraphQL reads, filtered failure logs only, and `gh api rate_limit` (free) before bursts. Back off at `<1,000` (5 min), `<200` (15 min), and wait for reset on 403/429; an API error is never a test/gate failure.
- Edit running scripts atomically (write temp file, then `mv`); stop only owned processes by recorded PID and start time.
