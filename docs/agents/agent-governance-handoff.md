# Agent governance handoff

Setjoin adopts a shared portable agent operating model while retaining Setjoin's own
DOX hierarchy, reducer authority, database-security rules, protocol references, build and
test matrix, active-program sources, and rollout gates.

## Installed governance

- The root session is the orchestrator and may delegate useful, independent work without
  per-use approval.
- Credentials, commits, pushes, merges, deployments, destructive actions, production
  changes, integration, final verification, and ship decisions remain root-only.
- Read-only delegates get a minimal tool allowlist. Writer/runner delegates require an
  isolated worktree or equivalent root-controlled filesystem boundary.
- There is no model-routing ladder (retired 2026-10-29; history in
  `retired-docs:agent-context/`). Prompt-enforced `bypassPermissions` is not policy.
- Dirty-worktree preservation, and DOX closeout remain mandatory.
- Execution hosts, mandatory CI, evidence reuse and root-owned resource cleanup follow
  `../guides/TASK_EXECUTION_AND_CLEANUP.md`.

## Canonical files

| File | Authority |
| --- | --- |
| `/AGENTS.md` | DOX contract, domain invariants, security boundary, tools, and child index |
| `/docs/agents/HARNESS_CONTEXT_AND_FEEDBACK.md` | Write–Select–Compress–Isolate, bounded context, lifecycle checkpoints, and feedback contract |
| `/docs/agents/planning-review-pipeline.md` | Planning stage contracts, receipts and stop rule |
| Nearest child `AGENTS.md` | Domain-specific implementation and verification rules |

If these documents conflict, system/developer/user instructions win first, then root
`AGENTS.md`, then the nearest applicable child. A child may add stricter local rules but
may not weaken the root safety contract.

## Rules intentionally not copied

The source project's addresses, accounts, credentials, deployment and release-state
facts do not authorize Setjoin access.

## Verification checklist

1. Run `bash scripts/check-agent-context-budget.sh`.
2. Run `git diff --check` and verify Markdown links.
3. Review the complete diff and preserve unrelated dirty files.
