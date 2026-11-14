# docs/ — AGENTS.md (hot documentation rail)

## Purpose

`docs/` is Setjoin’s authoritative knowledge base for standards, ADRs, specs, plans,
protocols, guides, compliance, audits and archives. It owns docs, not code.

Use targeted search for old material rather than keeping a catalog of every historical document in hot context.

## Local contracts

- Specs define what/why; plans define executable engineering steps.
- Specs and plans are not kept in this repository. `retired-docs:<path>` citations name
  removed internal documents and do not resolve.
- Durable architecture decisions live in `adr/` as `ARCH-NNN-*` or `DES-NNN-*`.
- Enforced rules live in `standards/` and are mandatory.
- Raw RFC text under `ref/rfcs/` or `ref/rfc/` is normative when protocol behavior is disputed.
- Operator procedures live in `guides/`; compliance claims live in `compliance/`; audit history lives in `audit/`.

## Find the right document

Follow the known source path and relevant owner sections; search for unknown entry points. These are stable entry points, not a reading list:

- System architecture: `architecture.md`
- Work-order/phases: `phases.md`
- Feature matrix: `features.md`
- Product positioning and claim gates: `product-positioning.md`
- Reducer errors: `reducer-error-codes.md`
- Database security: `standards/DATABASE_SECURITY.md`
- Input validation: `standards/INPUT_VALIDATION.md`
- AI-assisted testing and evidence: `standards/AI_ASSISTED_TESTING.md`
- Identity account classes and protected-account boundary: `standards/IDENTITY_ACCOUNT_CLASSES.md`
- Dependencies/toolchain: `standards/DEPENDENCIES.md`
- Code quality and static analysis: `standards/CODE_QUALITY.md`
- API error shape: `standards/API_ERROR_SHAPE.md`
- Conditional-access break glass: `standards/CONDITIONAL_ACCESS_BREAK_GLASS.md`
- Push ECIES wire contract: `standards/PUSH_ECIES_CONTRACT.md`
- Current active queue: GitHub issues on `setjoin/setjoin` (`agents/issue-tracker.md`)
- Agent governance and transfer receipt: `agents/agent-governance-handoff.md`
- Agent harness context and feedback: `agents/HARNESS_CONTEXT_AND_FEEDBACK.md`
- Program status directory: `agents/PROGRAM_STATUS.md`
- Skill maintenance and controlled overlays: `agents/SKILL_MAINTENANCE.md`
- Verification command catalog: `guides/VERIFICATION_COMMANDS.md`
- Execution/cleanup: `guides/TASK_EXECUTION_AND_CLEANUP.md`
- Planning stage contracts: `agents/planning-review-pipeline.md`
- Subagent workflow rules: `agents/subagent-workflow.md`

Protocol work must read the matching `ref/protocols/*.md` and raw RFC before code changes. Do not rely on model memory for normative protocol behavior.

## Naming and lifecycle

- Specs/plans: `YYYY-MM-DD-topic[-design].md`.
- Standards: `SCREAMING_SNAKE.md`.
- ADRs: `ARCH-NNN-topic.md` or `DES-NNN-topic.md`.
- Do not leave a completed plan marked active.
- Delete stale hot-context prose; preserve useful history in an archive with a pointer from the current authority.
- Never copy large completed-program narratives back into root `AGENTS.md` or the issue queue.

## Programs and history

Status: `agents/PROGRAM_STATUS.md`; queue: GitHub issues. `verification/` keeps only the
machine-read inputs that guards and tests consume.
Implementation completion does not enable production: each feature keeps its default-OFF
flags until a separate rollout decision.

## Verification

- R3/R4/R5 verification front doors are `scripts/verify-architecture-r{3,4,5}.sh`
  (`--doctor` before affected runtime work); cases and evidence contracts stay in
  `verification/architecture-r{3,4,5}-*.json`.
- Confirm every newly referenced path exists.
- Run `git diff --check`.
- Run `bash scripts/check-agent-docs.sh` when changing hot agent/TODO context.
- When changing reducer-error documentation, cross-check codes against `mailserver/sql/` and the shared Go parser.

## Child DOX Index

None. `docs/` is documentation-only.
