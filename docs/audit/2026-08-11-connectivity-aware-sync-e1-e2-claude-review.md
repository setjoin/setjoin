# Claude Opus 5 review — connectivity-aware sync E1/E2

Date: 2026-08-11

Mode: independent read-only second voice

Model: `claude-opus-5`, effort `xhigh`

## Scope

Claude reviewed the uncommitted E1/E2 working tree against E0 head `0eda705d`,
covering V209/V210, reducers and wrappers, strict Go routes, OpenAPI, eligibility,
and scheduler behavior. It used repository inspection and Graphify but modified
nothing. Codex had already completed its own implementation review and tests.

## Findings and disposition

| Finding | Severity | Disposition |
|---|---:|---|
| Device background preference collapsed the hard network ceiling, blocking explicit work | Medium | Accepted; projection now separates automatic admission from the server ceiling; SQL/TS regression evidence added |
| Saturated/backoff classes accumulated unbounded DRR deficit | Medium | Accepted; non-servable classes earn no credit; saturation regression test added |
| OpenAPI required `syncQoS` while flag-OFF runtime omits it | Medium-low | Accepted; property remains documented but conditional/optional; schema regression test added |
| Legacy policy wrapper could overwrite a concurrent v2 update | Low | Accepted; compatibility read now locks the row before delegating |
| Admin preview was available while the feature was OFF | Low | Accepted as intentional operator behavior; OpenAPI/verification now pin read-only pre-enablement `mode=off` semantics |
| Legacy unknown-mailbox behavior and RLS rationale drifted | Low | Accepted; silent unknown-mailbox contract and security rationale restored while known foreign devices still fail loudly |
| Window clamp used `MIN` rather than the precedence winner | Pre-existing | Accepted as adjacent correction; canonical write and snapshot now share total ordering and a focused test |

Claude explicitly agreed that device binding, R3 ownership, auth-first opaque
preview denial, additive migration, OFF seeding, reducer authority, and legacy
five-key projection held. It did not execute tests and only partially reviewed
the status-projection privacy module; Codex independently reviewed that module and
ran the complete focused test set.

## Result

Claude's pre-correction verdict was 7/10 because of three correctness/compatibility
defects, not a security defect. Its bounded post-correction review found every
original finding fully closed, no new release-relevant defect, and rated the result
9/10. The only implementation-side deduction was a missing parallel RLS maintenance
comment on the snapshot's group-membership read; that comment was restored after
the review. The remaining retained pre-V209-binary/exact-HTTP artifact is release
evidence, not an implementation defect, and remains explicitly unclaimed.
