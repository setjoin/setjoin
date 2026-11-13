# Claude Fable 5 portfolio-plan review — 2026-08-10

## Scope and invocation

Codex completed its own repository and plan analysis first, then asked Claude Fable 5
one repository-aware, read-only portfolio question covering the three active,
engineering-ready but unimplemented programs:

- `retired-docs:superpowers/plans/archive/2026-08-10-mail-interoperability-correctness.md`
- `retired-docs:superpowers/plans/archive/2026-08-09-mailbox-lifecycle-retention.md`
- `retired-docs:superpowers/plans/archive/2026-08-10-webmail-competitive-productivity-roadmap.md`

The direct CLI invocation used the exact model `claude-fable-5`, `xhigh` effort,
disabled slash commands, and prompt-enforced read-only repository access. It completed
successfully. The review asked for evidence, missing assumptions, failure modes, exact
corrections, per-plan scores, cross-plan dependencies, and what prevented 10/10.

## Raw verdict summary

Fable scored the pre-correction plans as:

| Plan | Fable score |
|---|---:|
| Mail Interoperability Correctness | 8/10 |
| Mailbox Lifecycle & Retention | 7/10 |
| Webmail Competitive Productivity | 6/10 |

The response was useful as a broad long-horizon completeness pass, but it also included
false positives and contradictory ordering recommendations. Codex therefore verified
every finding against source and confirmed product/security decisions before changing a
plan.

## Accepted corrections

### Mail Interoperability Correctness

1. Specify remote immutable-source resolution, atomic local source/job binding, and
   first-page revalidation.
2. Persist thread-reconciliation continuation as a durable job phase and prohibit
   terminal success while work remains.
3. Make IMAP UID repair bounded and resumable with an idempotent evidence ledger and
   progressless fail-closed behavior.
4. Name exact shadow-readiness thresholds and retained benchmark artifacts.

### Mailbox Lifecycle & Retention

1. Bind reconnect to exact versioned identity-link or Local-user proof and revalidate it
   under locks.
2. State that user-keyed sender preferences remain with stable `users.id` across detach
   and reconnect; they are neither moved nor deleted by mailbox purge.
3. Add a fail-closed retention-domain registry and one purge-blocker projection so later
   collaboration records compose legal hold and delayed purge safely.

### Webmail Competitive Productivity

1. Define replay of an old shared-draft save after later revisions: immutable original
   receipt plus current safe projection, never rewind.
2. Freeze notification caps, analytics privacy floor, business-calendar defaults, and
   search provider timeout/fallback behavior.
3. Register shared-work retention into Mailbox Lifecycle before shared-work writes can
   be enabled.
4. Clarify and test that work identity is mailbox-scoped and folder/tag-independent.

## Rejected or narrowed findings

| Proposal/claim | Disposition | Evidence/rationale |
|---|---|---|
| Reserve fixed V195–V234/BZ ranges now | Rejected | Plans intentionally allocate against live `main`; programs execute serially, so early fixed reservations create stale collisions rather than prevent them. |
| Force every IMAP session to disconnect on flag-generation mismatch | Rejected | Connection-pinned UID mode prevents mixed interpretation; explicit operator drain remains available. |
| Mailbox Lifecycle and Shared Work table names/authorities collide | Rejected | `mailbox_lifecycle` and `mail_thread_work` are distinct, intentionally composed authorities. |
| Lifecycle omitted SMTP delivery and hold composition | Rejected | Existing normative integration and engineering sections already cover both exhaustively. |
| Sender Control should be delegated-mailbox policy | Rejected | V1 is intentionally personal/user-keyed; shared policy needs a separate authority and product decision. |
| Any send-capable delegate may assign other people | Rejected | Self-claim solves participation; assigning others remains owner/`full_access` by confirmed authorization policy. |
| Work identity collides across folders | Rejected as defect, clarified in plan | `compute_thread_id(..., mailbox_id)` is mailbox-scoped; folder/tag independence is deliberate. |
| Arbitrary repair-pass and extreme-CI corpus numbers | Narrowed | Adopted bounded batching and progress proof, not unsupported magic counts or impractical mandatory corpus sizes. |

## Codex synthesis and final verdict

The evidence-backed corrections close real execution ambiguity without changing the
confirmed product scope, security boundaries, default-OFF rollout posture, or public
protocol identity model. Fable's two different ordering suggestions were not treated as
authority. Codex selected one evidence-backed serial order:

1. Mail Interoperability Correctness;
2. Mailbox Lifecycle & Retention;
3. Webmail Competitive Productivity, which then registers its retention domain into
   the completed lifecycle seam.

After the correction cycle, the CEO, applicable Design, Engineering, and DX reviews
remain 10/10 in all three plans with no unresolved implementation decision. A 10/10
plan score is a work-order completeness claim; implementation must still earn every
test, security, performance, browser, upgrade, rollback, and documentation gate.
