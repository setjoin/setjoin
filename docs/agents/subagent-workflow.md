# Subagent workflow & agent governance

Canonical operating contract for orchestrating, delegating, planning, reviewing, and maintaining agent work in Setjoin. The latest owner instruction wins.

## Precedence, authority & isolation

- **Precedence:** system/developer/user instructions win first, then root `/AGENTS.md`, then the nearest applicable child `AGENTS.md`. A child may add stricter local rules but may never weaken root safety contracts.
- **Root-only authority:** the root session is the orchestrator and may delegate useful, independent work without per-use approval. Credentials, git commits, explicit-SHA pushes to feature branches (never push `main` or force-push), PRs, merges, deployments, destructive actions, production changes, issue tracking, integration, final verification, and ship/owner decisions remain root-only.
- **Physical & logical isolation:**
  - Read-only delegates receive a minimal tool allowlist and a bounded dossier; they may use the current checkout only when they cannot mutate state.
  - Parallel writers/runners own disjoint paths inside root-controlled isolated worktrees (one writer per worktree); serialize tickets touching overlapping files. Workers never touch production or git metadata outside their worktree.
  - Delegated lifecycle: `prepared → running → review → correction → accepted` or `held`. The root owns all state transitions.
  - Review sessions are fresh per module; never share the authoring session or carry one module's conversation history, assumptions, or tool permissions into another.
- **Harness-level model selection:** models are selected by the active harness/UI rather than hardcoded in repo rules. Prompt-enforced `bypassPermissions` is not policy. External agent runtimes, SDKs, and CLI lifecycles are tooling references only; Setjoin implements no third-party agent protocol unless a separate approved plan says so.
- **Execution & cleanup:** execution hosts, mandatory CI, evidence reuse, dirty-worktree preservation, DOX closeout, and root-owned resource cleanup follow [TASK_EXECUTION_AND_CLEANUP.md](../guides/TASK_EXECUTION_AND_CLEANUP.md). Record task-specific temporary paths, processes, containers, images, and volumes before launch; clean only owned resources and retain evidence/caches with a recorded reason.
- **External project isolation:** external project addresses, accounts, credentials, deployment details, and release-state facts do not authorize Setjoin access.

## Bounded context & feedback (Write–Select–Compress–Isolate)

Setjoin treats the **repository as the system of record** and prefers **invariants over implementation**: durable decisions, plans, evidence, source fingerprints, corrections, and unresolved risks belong in owned files, while rules state authority, ownership, safety boundaries, outputs, and acceptance checks rather than incidental algorithms or prompt style. A conversation, model response, or attachment is not a durable fact until the root records it with scope and provenance.

- **Write (persist useful state):** at the end of a meaningful unit, record the smallest durable handoff in the owning plan, verification receipt, or governance record: (1) objective and bounded scope, (2) owner and reviewer stage, (3) approved inputs and source fingerprint/file hashes, (4) changes, commands, exit status, and retained evidence, (5) accepted/deferred findings and residual risk, (6) next queue item or explicit `HOLD` reason. Never copy transient narration, raw traces, credentials, customer data, or completed program narratives into `AGENTS.md` or the issue queue.
- **Select (load only needed context):** known-path work reads source directly. Read ancestor/nearest `AGENTS.md` rails once, then only the owning DOX/standard sections needed for the task. Treat each bounded unit as a required-input manifest (paths, size/token estimate, source version, expected outputs). Reuse a receipt only while its input hash and applicable invariants are unchanged; pass environment changes as deltas (`changed_paths`, new services, invalidated evidence).
- **Compress (preserve decisions, not transcript volume):** retain exact verdicts, hashes, unresolved risks, and next actions. A bounded packet's `SHIP` is not a whole-plan 10/10; aggregate release claims require every required packet, integration boundary, and external gate. Compaction or new sessions consume durable receipts—never infer completion from truncated streams. Missing, malformed, or truncated required inputs, reviews, or terminal events remain `HOLD`/unavailable and are never converted into a pass.
- **Feedback loop & acceptance:** before calling any meaningful change complete: (1) name the deterministic command, test, lint, browser lane, or source-bound checker that falsifies the claim, (2) run it against the exact manifest source version and fixtures, (3) retain exit status, source fingerprint, and artifact hashes, (4) have a fresh read-only reviewer inspect the bounded result, and (5) integrate only after the root verifies links, ownership, scope, and stale evidence. A review never substitutes for missing tests; historical reviewer names and scores remain historical. For authorized implementation, completion includes relevant checks, fixing task-caused failures, recording unrelated failures separately, and cleanup—do not rerun unrelated suites or ask approval for every mechanical step.

## Planning pipeline, risk areas & stop rule

- **Risk-area plan review:** changes touching **auth/tokens, tenant isolation/ACL, crypto/keys/signing, user-data delete/move, migrations, data egress, production**, or concurrency/protocol design must write a short `PLAN.md` (threats, invariant, failure cases—full quota, old/large data, mid-run restart, concurrency—abusable inputs, upgrade path, and required tests; keep `PLAN.md` out of commits) and pass a **fresh read-only plan review** before coding. Reviewer cases become required tests.
- **Stage contracts:**
  - **Plans carry requirements:** unfiltered (sanitized) original requirements, owner follow-ups, and attachments reach the author; summaries navigate and never override original requirements.
  - **Mechanical checks first:** verify file hashes vs receipts, acceptance greps, path existence, context budgets, and link guards by script before human/LLM review.
  - **Fresh read & delta review:** reviewers never share the authoring session. Delta review covers affected invariants and integration boundaries against an accepted baseline; read full relevant scope when no baseline exists.
  - **Owner decisions & holds:** the user owns material decisions (scope, provenance, visual/user gates, ungranted implementation authority). Existing approvals remain valid for unchanged scope; existing implementation/release holds remain binding.
- **Receipts & stop rule:** every planning/review stage exits into a frozen receipt (input hashes, per-finding IDs, accepted/rejected dispositions) so later stages review only the changed delta and reuse unchanged accepted evidence. After at most **two correction cycles per stage**, reassess remaining findings: continue safe authorized corrections or isolate the next bounded unit; escalate new material user decisions or unavailable irreplaceable evidence as a named `HOLD`. Never repeat an unchanged review to seek a better score.
- **Investigation & stalls:** investigate unknown causes read-only first. Cap stalled runs (~30 min) by writing `PROGRESS.md` and escalating.

## Pre-report checklist

- Treat "bounded" or "unlikely" caveats as findings: fix them or file a follow-up.
- Check callers before any "delete X" ticket; verify export/copy/squash file lists match `git ls-tree -r` of the source commit.
- Check diffs for: cleanup leaks, stale docs, pinned counts, weakened assertions, Go-only checks skipped by native routes, transaction error paths, wrong-scope code, and merge-resolution loss.

## Builds, guards & tests

- **CI-first:** run builds and tests on GitHub-hosted runners (`pr-precheck.yml` `aggregate` on PRs; `server-rust lane` on merge queue; manual `gh workflow run quick-check.yml -R setjoin/setjoin --ref <branch>` without a PR).
- **Local Rust:** no local Rust compilation; run `rustfmt` on added files only (`git add`, `bash scripts/ci/fmt-added.sh`, `git add`, commit).
- **Standalone guards:** PR pre-check omits merge-queue `guards`, so run relevant no-cargo/no-DB guards before opening a PR:
  - Reducers/callers: `bash scripts/guards/check-audit-coverage.sh`, `bash scripts/guards/check-app-notify.sh`
  - Route flips: `python3 scripts/test-check-gofree-rehearsal.py`
  - New SQL functions: `bash scripts/guards/check-xinchuang-matrix.sh`
  - Conformance READMEs: `bash scripts/check-recorder-docs.sh`
  - Oracle/catalog changes: `python3 scripts/guards/check-gofree-oracle-adequacy.py --preflight-only`
  - AGENTS/DOX edits: `bash scripts/guards/check-agent-context-budget.sh`, `bash scripts/guards/check-agent-docs.sh`
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

## Skill & DOX maintenance

- **Local skills:** skills live per developer machine in each harness's plugin/skill directory; this repo ships no agent skills, hooks, or harness config. Keep skill entrypoints short and conditional—do not preload full planning workflows for routine edits or doc moves.
- **Skill updates:** (1) inspect the actual launcher/interpreter and package manager first, (2) back up only affected files/hooks/config to a task-owned dir, (3) review upstream changes (never infer latest from a version marker alone) and validate frontmatter, references, invocation, and package/skill parity (new sessions reload the catalog), (4) preserve unrelated hooks/config, and (5) clean task-only artifacts while retaining rollback caches/snapshots with provenance in the receipt.
- **Project design authority:** pick the smallest suitable design workflow with no overlapping audits. Project authority overrides skill defaults: keep Svelte 5, existing components, semantic design tokens, approved fonts/icons, localization, accessibility, and CSP—never add React/Next.js, Tailwind, animation libraries, remote fonts, or placeholder assets because a skill suggests them. Dense dashboards, tables, multi-step workflows, native mobile, and real-time collaboration keep their existing UI owners and approved plans. `audit`/`critique` requests are read-only unless corrections are requested.
- **DOX & context-budget maintenance:** budgets are root ≤10,000 bytes, child ≤16,000, ancestor chain ≤32,000 (`bash scripts/guards/check-agent-context-budget.sh`; `bash scripts/guards/check-agent-docs.sh` adds link/anchor checks). When a hot rail grows, keep the invariant, owner, and link in the rail and move detail/history to the owning guide, plan, or archive—never delete a durable decision just to shorten a file. The dynamic guard covers new/untracked first-party rails, excludes generated/dependency dirs and directory symlinks, and requires instruction-file symlinks to resolve within the repo; never exploit exclusions to hide oversized rules. Preserve anchors with same-heading redirects, keep mechanical preservation separate from reviewed procedural corrections in receipts, and resolve historical domain contradictions via the current standard/ADR rather than invented policy.
