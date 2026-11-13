# ADR: ARCH-003 — Account-scope currency is `p_mailbox_id`, not `p_account_id`

**Status:** Accepted
**Date:** 2026-06-17
**Source:** `/improve-codebase-architecture` review (the `p_account_id` convention) + the `user_id`/`mailbox_id` bug cluster (MDN read-receipt, calendar RSVP, resource booking, `jmap_calendar_event_set_update:546`)

## Context

`parseAccountID` (the gateway) resolves a JMAP `accountId` to the authenticated user's **primary mailbox id** — it validates `accountId == (SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary)`. So the value a reducer receives is a `mailbox_id`. But the reducer parameter was named `p_account_id`, and "account" reads like *user-account*.

82 reducer functions take this parameter. ~93% correctly scope by the mailbox (`mailbox_id = p_account_id`); a minority hand-wrote `mailboxes.user_id = p_account_id`. Because `users.id` and `mailboxes.id` are **independent `BIGSERIAL` sequences** and `mailboxes.user_id` is **nullable** (shared/resource mailboxes), a `user_id = p_account_id` predicate matches **zero rows in production** — the feature fails silently (RSVP never persists, a booking always raises `BZ001`, a destroy reports success but deletes nothing). pgTAP fixtures that set `mailbox.id == user_id` (coincident ids) made the buggy predicate pass by accident, so the test suite never caught it. The same bug landed at least four times.

The ambiguity is at an **interface** (an overloaded parameter name) and the masking is at a **test surface** (coincident fixtures). Documenting the convention was not enough — the drift happened *with* docs present.

## Decision

1. **One currency.** The account-slot argument is **always a `mailbox_id`**. The reducer parameter is named **`p_mailbox_id`**; `p_account_id` is retired.
2. **User-keyed inputs are a distinct concept with a distinct name.** Where a reducer genuinely keys on the authenticated person rather than a mailbox, the parameter is **`p_viewer_id`** / `p_user_id` (e.g. the shared-calendar *viewer* in `jmap_calendar_*_get_shared`). `send_read_receipt` **converts** from user-keyed to `p_mailbox_id` and resolves the sender identity internally — so the account slot carries one currency with no exceptions, and the only user-keyed parameter names a different concept (who is looking), not a different currency for the same one.
3. **A single resolver seam.** `account_scope(p_mailbox_id) → (mailbox_id, user_id, domain_id)` is the one place the mailbox→user→domain mapping lives (including the `user_id IS NULL` shared case). Reducers that need the user or domain behind a mailbox call it instead of hand-joining `mailboxes`.
4. **Divergent test fixtures by construction.** pgTAP fixtures create accounts via `mk_account(label) → mailbox_id` / `mk_shared_mailbox(...)`, which allocate `user_id` and `mailbox_id` from **disjoint ranges**. Coincident ids are banned — divergent ids are the regression guard for this entire bug class.
5. **A self-enforcing guard.** A suite check fails on any `user_id = p_mailbox_id` (or legacy `p_account_id`) ownership predicate that is not an approved user-keyed exception, and on any **new** `p_account_id` reducer parameter.
6. **The wire term stays.** `parseAccountID` and the Go `accountID` variable keep their names — `accountId` is the correct JMAP protocol word. The rename happens **only at the reducer parameter**, the seam where the meaning was being lost.

## Considered options

- **Document-only** (a `CONTEXT.md` convention note, no rename). Rejected: the drift already happened *with* documentation in place, and coincident fixtures defeat the test suite. A note relies on everyone remembering; it is not self-enforcing.
- **Full structural fix** (chosen): rename to the currency, add the resolver seam, force divergent fixtures, add the guard. Makes the bug class un-writable and un-maskable.

## Consequences

- A one-time mechanical rename of ~82 reducer parameters and a sweep of ~60 pgTAP fixtures onto the helpers. Pure rename + fixture-shape change — no behavior change — so the existing suite is the safety net, done family-by-family.
- **Sequencing:** executes as a dedicated wave **after** the in-flight Track-A feature work (A1–A6) commits, never concurrently (a sweeping rename would collide with the feature waves in the tree).
- After landing, the divergent-fixture helper + the grep guard make the invariant self-enforcing; `account_scope()` concentrates a NULL-prone mapping into one tested seam.
- See `CONTEXT.md` → **Account scope (`parseAccountID`) / `p_account_id`** for the working glossary form of this rule.

## Implementation notes (step 2 — mechanical rename, 2026-06-17)

- The wholesale rename `p_account_id` → `p_mailbox_id` is done across all `mailserver/sql/reducers/*.sql` and the `mailserver/sql/schema/*.sql` comments. Pure, reducer-internal rename (positional call sites in Go/pgTAP are unaffected); pgTAP unchanged at 86 files / 626 tests.
- **Two exceptions keep `p_account_id`:** `calendar_free_busy` and `calendar_free_busy_multi`. Frozen migration `V061__calendar_transp_exdate.sql` does an inline `CREATE OR REPLACE FUNCTION` of both with the parameter named `p_account_id`, and `V001__initial_schema.sql` `\i`-includes these reducers *before* V061 replays. Postgres forbids renaming an input parameter via `CREATE OR REPLACE`, so renaming the reducer param makes the V061 replay fail with `cannot change name of input parameter`. Migrations are frozen historical files (must not be edited), so these two account-scope params retain the legacy name. Each declaration carries an inline NOTE; the value is still a mailbox id. (Future cleanup, if desired: a NEW forward migration could `DROP FUNCTION` + recreate both with `p_mailbox_id`, after which the reducer rename becomes safe — out of scope for the frozen-files-only step 2.)
