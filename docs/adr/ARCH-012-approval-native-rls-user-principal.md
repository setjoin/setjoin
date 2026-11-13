# ADR: ARCH-012 — Approvals adopt native RLS on a second (user-keyed) principal as the first user-scoped increment of the native-RLS-backstop program

**Status:** Accepted
**Date:** 2026-06-28
**Source:** `/improve-codebase-architecture` over the approval engine (branch `approval-engine`), grilled 2026-06-28. Candidate A ("the approval engine's native RLS is a second, ungoverned isolation principal").

## Context

The approval engine (`V070__approval_engine.sql`) added **`ENABLE`+`FORCE ROW LEVEL SECURITY`** to `approval_requests` / `approval_policies` / `held_inbound_messages`, keyed on a **new GUC `app.current_user_id`**, set via a new `dbscope.RunUserScoped(ctx, pool, userID, fn)` (the user-keyed sibling of the existing `dbscope.RunScoped` mailbox seam). This is the **first native-RLS adoption outside** the `native-rls-backstop` program's mailbox-keyed surface (`messages` / `message_tags` / `delivery_attempts`, W6/V004 + V017).

ARCH-006 records that native RLS is **deferred** as the codebase posture (application-layer isolation + the positive guards), and explicitly: a review that finds native RLS "must not re-suggest it as new — it **updates the plan or fires the trigger**." So the architecture review's job here is to reconcile what the approval engine *did* with the program that *owns* native RLS, not to invent a parallel mechanism.

Measured facts (`/improve-codebase-architecture` 2026-06-28):

- **Inert today, like the rest of the program.** The dev/test/prod connection is the superuser+owner `mail`/DSN, which bypasses FORCE; the approval FORCE is a no-op until the gateway connects as the non-owner `setjoin_app` role (the program's deferred DSN-switch deploy gate). The approval RLS is in the *exact same inert state* as W6/V004's `messages`/`message_tags` FORCE.
- **A second principal, because approval data has no mailbox.** An `approval_request` belongs to a **requester + an approver** (a user, or a role-group pool) — it is not mailbox-scoped. The program's mailbox-keying (ARCH-003 currency) does not fit; `app.current_user_id` is the correct principal for this data.
- **Defense-in-depth, not the sole control.** `approval_decide.sql` already self-enforces SoD/authz on `p_actor_user_id` (BZ106/BZ107) independent of RLS; the FORCE RLS is the read-path visibility control + a write-path backstop.
- **Ungoverned by the W7 coverage guard.** `scripts/check-rls-coverage.sh` (the W7 machine-checked guard) scans only `messages`/`message_tags` literals — so the 14 app-pool query sites on the approval tables are **FORCE'd but unguarded**, the identical gap the program already recorded and is fixing for `delivery_attempts` (the "W7 FOLLOW-UP" in `2026-06-18-native-rls-backstop.md`).
- **One system-op mis-route.** `mailserver/internal/approval/email_page.go:298` (`SendApprovalNotification`) queries `approval_requests` outside `RunUserScoped`. It is a **system operation** (a notification *about* a request, sent *by the system* — no acting user), so it belongs on the **BYPASS worker pool**, not a user scope. It works today (superuser bypass) and would fail-closed-blind at the DSN switch — exactly the carve-out class the program handles (recall, content-search, outbound drain, …).

The architecture review's own first instinct — build an approval-only "scoped handle / two-door" seam — was measured against this plan and found to be a **re-invention of the program's existing mechanism** (`RunScoped`/`RunUserScoped` + the `workerPool` BYPASS carve-out + the `check-rls-coverage.sh` guard). Building it approval-only now would entrench an island and duplicate W7.

## Decision

1. **Native RLS on approval data, keyed on `app.current_user_id`, is RETAINED — not reverted to the application-layer posture.** The data is genuinely user-scoped, fail-closed is appropriate for privilege-approval data, and the FORCE policy **concentrates** the non-trivial visibility predicate (requester ∨ approver ∨ role-group ∨ admin) that 14 sites would otherwise duplicate (the deletion test favors keeping it). The application-layer alternative was considered and rejected (moves complexity to 14 duplicated predicates; loses fail-closed).

2. **Approvals are the FIRST user-keyed increment of the `native-rls-backstop` program** (`retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md`), not a one-off island and not to be re-suggested for reversal. The program now governs **two principals**: `app.current_mailbox_id` (mailbox tables) and `app.current_user_id` (approval tables). `dbscope.RunUserScoped` is the user-keyed mirror of `dbscope.RunScoped`.

3. **No new mechanism is built for this.** The program's seams (`RunScoped`/`RunUserScoped`, the `workerPool` BYPASS carve-out, the `check-rls-coverage.sh` guard) are the mechanism. The review must not fork a parallel approval-only version (ARCH-006: update the plan).

4. **The governance lands in the program, as a tracked pre-DSN-switch action** — mirroring the `delivery_attempts` W7-FOLLOW-UP. Before the DSN switch: (a) extend `check-rls-coverage.sh`'s table set to the 3 approval tables and teach its `WRAPPED` classification to accept `RunUserScoped`/the `app.current_user_id` GUC; (b) classify the 14 sites in `rls-coverage-allowlist.txt` (WRAPPED for the user paths; BYPASS for the system paths); (c) move `email_page.go:298` (`SendApprovalNotification`) onto the BYPASS `workerPool` and classify it BYPASS. The DSN-switch deploy gate's "coverage guard green" precondition then covers approvals.

   **✅ DONE (2026-07-05).** `check-rls-coverage.sh`'s table set was extended to the 3 approval tables; the 14 app-pool sites were classified in `rls-coverage-allowlist.txt` (WRAPPED inside `RunUserScoped`, BYPASS for the system paths); `SendApprovalNotification`/`HandleApprovalCreatedNotify` were moved onto the BYPASS `workerPool` (`main.go:378`). (Per the 2026-07-05 autoplan gauntlet review: the guard is pure-allowlist by design — the `mailbox_delegates` `RunUserScoped` entries already proved allowlist-only coverage works — so no seam-recognizer was added to the guard itself; sub-item (a)'s "teach the guard the GUC" framing was superseded by that finding.) See `retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md` W7 FOLLOW-UP.

5. **The approval branch merges as-is.** The approval RLS is inert and correct on today's superuser DSN (the approval pgTAP/Go/webmail suites are green); the runtime break is latent on the deferred DSN switch, which is gated on (4). No code change is required before merge.

## Considered options

- **Build an approval-only scoped-handle seam now.** Rejected: it re-invents the program's `RunUserScoped`+BYPASS+guard mechanism (ARCH-006 forbids re-suggesting native RLS as new), entrenches an island, and pays the refactor tax now for a latent-only break that the very program building the general fix would otherwise close.
- **Conform — drop the approval FORCE RLS, use explicit per-query visibility predicates + `check-gateway-ownership.sh`.** Rejected: the deletion test shows this **moves** complexity to 14 duplicated OR-predicates (a step down in depth), and it gives up fail-closed on the most compliance-sensitive data in the system (who may approve a privileged action) for the sake of posture-uniformity — when the program is already converging the whole codebase toward native RLS anyway.
- **Record + fold into the program (this ADR).** Accepted.

## Consequences

- The approval tables become **tracked native-RLS-program members on the user principal**; `native-rls-backstop.md` gains a W7-FOLLOW-UP for them (the coverage-guard extension + the `:298` BYPASS move) as a pre-DSN-switch action, exactly like `delivery_attempts`.
- The program now has **two GUCs / two principals**; `dbscope` exports both `RunScoped` (mailbox) and `RunUserScoped` (user). Future native-RLS tables choose their principal by whether their data is mailbox- or user-scoped.
- `email_page.go:298` is recorded as a known **inert latent** carve-out (works on superuser DSN; must move to `workerPool` before the flip). Listed in `TODOS.md` and the plan.
- **Reversibility:** trivial while inert — the approval RLS could be reverted to the application-layer posture if the native-RLS program were ever abandoned (the reducer self-enforcement remains). No runtime depends on the FORCE until the DSN switch.
- Future `/improve-codebase-architecture` reviews must not re-suggest either (a) an approval-only RLS seam or (b) reverting the approval RLS — they update the plan or fire the program's trigger.
