# Database Query Security — Enforced Standards

> **Status:** Enforced for all new and modified database queries.  
> **Standards:** OWASP A01:2021, API1:2023 (BOLA), CWE-639/862/566, NIST 800-53 AC-16  
> **References:** `docs/specs/SECURITY.md` (email security), `docs/reducer-error-codes.md` (PL/pgSQL error contract)  
> **Memory:** [[reference-owasp-security-standards]], [[reference-cwe-authorization]], [[reference-rls-best-practices]], [[reference-nist-database-security]]

## The Four Rules

Every database query **must** satisfy all four rules. No exceptions.

| Rule | Applies to | Test |
|------|-----------|------|
| **R1 — SELECT filter** | Every SELECT on user-data tables | Does the WHERE/JOIN constrain rows to the authenticated user? |
| **R2 — INSERT from auth** | Every INSERT into user-data tables | Is `user_id`/`mailbox_id` set from auth context, never the request body? |
| **R3 — Mutate with ownership** | Every UPDATE/DELETE on user-data tables | Does the WHERE clause include BOTH the resource ID AND the ownership column? |
| **R4 — Per-user isolation** | Every table containing per-user data | Does every access carry an ownership-scoping predicate, propagated from auth? (Enforced at the **application layer** — see Rule 4. Native RLS is *deferred*, not enforced → [ARCH-006](../adr/ARCH-006-app-level-isolation-posture.md).) |

## Rule 1: SELECT Must Filter by Ownership

### Go (gateway/authserver)

```go
// CORRECT — ownership filter in WHERE
row := h.pool.QueryRow(ctx,
    `SELECT id, name FROM mailboxes WHERE id = $1 AND user_id = $2`,
    mailboxID, user.UserID)

// CORRECT — ownership via JOIN
rows, _ := h.pool.Query(ctx,
    `SELECT m.id, m.subject FROM messages m
     JOIN mailboxes mb ON mb.id = m.mailbox_id
     WHERE m.id = $1 AND mb.user_id = $2`,
    messageID, user.UserID)

// WRONG — no ownership filter
row := h.pool.QueryRow(ctx,
    `SELECT id, name FROM mailboxes WHERE id = $1`, mailboxID)
```

### PL/pgSQL reducers

```sql
-- CORRECT — p_mailbox_id in WHERE (the account slot is a mailbox_id; ARCH-003)
SELECT * INTO v_row FROM messages
WHERE id = p_message_id AND mailbox_id = p_mailbox_id;

-- WRONG — p_mailbox_id accepted but never used (Check H fails this)
SELECT * INTO v_row FROM messages WHERE id = p_message_id;
```

**Rule of thumb:** If a function receives `p_mailbox_id`, grep the function body — the parameter must appear in every SELECT FROM a user-data table. `check-account-scope.sh` Check H enforces the floor of this (param-is-used); the per-statement scoping is a review item (ARCH-006 §residual). The legacy `p_account_id` name is retired (Check B); only the frozen `calendar_free_busy[_multi]` keep it.

### Global/admin queries — the exception that proves the rule

Queries against shared tables (`system_config`, `domains`, `feature_toggles`) must verify the admin role (the permission-gated admin handlers / `requireAdmin`) before execution. (An admin-only RLS policy would also satisfy this, but native RLS is deferred — see Rule 4.) These tables are org-wide by design and are out of the per-user R4 boundary; the gateway-ownership guard does not require a per-user predicate on them.

## Rule 2: INSERT Must Set Ownership from Auth

```go
// CORRECT — user_id from auth context
h.pool.Exec(ctx,
    `INSERT INTO rules (mailbox_id, name, ...) VALUES ($1, $2, ...)`,
    verifiedMailboxID, req.Name, ...)  // mailboxID pre-validated against user.UserID

// WRONG — user_id or mailbox_id from request body
h.pool.Exec(ctx,
    `INSERT INTO rules (mailbox_id, name, ...) VALUES ($1, $2, ...)`,
    req.MailboxID, req.Name, ...)  // req.MailboxID could be ANY mailbox
```

**`user_id` and `mailbox_id` must never come from `req.*`.** They must come from:
- `user.UserID` / `claims.UserID` (auth middleware)
- A server-side lookup validated against the authenticated user
- A trusted internal context (delivery, journal, retention)

## Rule 3: UPDATE/DELETE Must Verify Ownership

```go
// CORRECT — both resource ID AND ownership in WHERE
h.pool.Exec(ctx,
    `DELETE FROM rules WHERE id = $1
     AND mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $2)`,
    ruleID, user.UserID)

// WRONG — only resource ID in WHERE (IDOR — CWE-639)
h.pool.Exec(ctx, `DELETE FROM rules WHERE id = $1`, ruleID)

// WRONG — ownership checked in separate query (TOCTOU race — CWE-367)
var owned bool
h.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rules WHERE id = $1 AND mailbox_id = ...)`, ruleID).Scan(&owned)
// ... time passes, another request modifies the row ...
h.pool.Exec(ctx, `DELETE FROM rules WHERE id = $1`, ruleID)  // race window!
```

**The ownership check must be in the same SQL statement as the mutation.** Separate SELECT-then-mutate is a TOCTOU vulnerability.

### Defense-in-depth for reducers

Even when the SELECT verified ownership earlier in the function, the final DELETE/UPDATE should re-check:

```sql
-- GOOD (SELECT verified ownership)
SELECT id INTO v_id FROM messages WHERE id = p_id AND mailbox_id = p_account_id;
DELETE FROM messages WHERE id = v_id;  -- id was verified, but no re-check

-- BETTER (defense in depth)
SELECT id INTO v_id FROM messages WHERE id = p_id AND mailbox_id = p_account_id;
DELETE FROM messages WHERE id = v_id AND mailbox_id = p_account_id;
```

## Rule 4: Per-User Isolation — Enforced at the Application Layer

> **The real boundary (ARCH-006), now backstopped by native RLS on the hot tables.**
> Per-user isolation is enforced in **application code** — `p_mailbox_id` propagated
> through the reducer layer and explicit ownership predicates in raw gateway queries —
> and, as of the native-RLS enforcement-flip (W6 / `V004__rls_enable.sql`), **also by
> native PostgreSQL Row-Level Security on `messages` + `message_tags`**: both parents
> are `ENABLE`+`FORCE ROW LEVEL SECURITY` with per-mailbox policies (`V003`) keyed on a
> transaction-scoped `app.current_mailbox_id` GUC the gateway sets per request
> (JMAP `CallScoped`, IMAP `withScope`).
>
> **The RLS backstop is a no-op until the prod DSN switches to the non-owner
> `setjoin_app` role.** A superuser/owner bypasses RLS even under FORCE, so today's
> runtime (and the dev/test `mail` connection) is unaffected — V004 is safe to apply
> ahead of the cut-over. The **DSN switch to `setjoin_app` is a separate,
> hand-authorized deploy gate** (preconditions in the *Deploy gate* section below and

> **STATUS (2026-07-03): the switch is the DEFAULT everywhere.** There is no production deployment yet; the e2e harness (`start-test-stack.sh`) permanently launches the gateway + authserver as `setjoin_app` / `setjoin_worker` (loader stays the owner identity), so every test run exercises the production credential shape. The checklist below remains the runbook for any future production install's own cutover.
> in `scripts/provision-roles.sql`'s header). The application-layer predicates + the
> positive CI guards below remain **load-bearing** (cheaper, earlier CI-time feedback;
> cover the raw-query surface RLS may not) — native RLS *subsumes the runtime half*,
> it does not retire the guards. RLS does NOT yet cover the other user-data tables
> (`mailboxes`, `contacts`, `calendar_events`, …) — those remain app-layer-only; see
> [ARCH-006](../adr/ARCH-006-app-level-isolation-posture.md).

Every user-data access must carry an ownership-scoping predicate derived from auth.
The seams and guards that make this enforceable, not just aspirational:

### 1. `p_mailbox_id` propagation (the reducer currency — ARCH-003)

The account slot every reducer receives is **always a `mailbox_id`** (the caller's
primary mailbox, from `parseAccountID`). Reducer ownership scopes by the mailbox —
`mailboxes.id = p_mailbox_id` or `mailbox_id = p_mailbox_id` — **never**
`user_id = <the mailbox arg>` (that type-confusion matches zero rows in production;
ARCH-003). Need the user/domain behind a mailbox? Resolve through the **one seam**
`account_scope(p_mailbox_id) → (mailbox_id, user_id, domain_id)`; provision through its
write-side inverse `provision_account(...)`. R1/R3 (above) are how each statement
inside a reducer carries that scope.

### 2. Raw gateway queries (IMAP/SMTP/CalDAV/CardDAV/JMAP/admin)

The Go gateway issues raw user-data queries the reducer layer never sees. Each must
carry an ownership predicate (`mailbox_id`/`user_id` in WHERE/JOIN) — R1/R2/R3 apply
verbatim. A query with **no** ownership scoping is a cross-mailbox leak.

### 3. The positive CI guards (the load-bearing compensating controls)

Because RLS is deferred, the steady state is fail-open: a forgotten predicate leaks and
nothing at the DB layer denies it. These guards convert that to **fail-closed-at-CI**:

- **`scripts/check-account-scope.sh`** — over the reducer layer. **Negative** checks
  A–G catch a *wrong* predicate (the `user_id`/`mailbox_id` confusion, a retired
  `p_account_id` param, a mailbox id matched against `users`, seam bypasses, user-keyed
  push channels, single-address calendar lookups). **Positive** check **H** catches the
  *accept-but-ignore* bug: a reducer that declares the account slot but never references
  it (scopes nothing). H's honest bound is **"param-is-used", not
  "every-statement-scoped"** — the finer per-statement gap stays on A/C + review (see
  ARCH-006 §residual). Reducer fixtures use **divergent `user_id != mailbox_id`** ids
  (`mk_account`/`mk_shared_mailbox`) so the confusion class is un-maskable; Check D
  fails on a coincident-id fixture.
- **`scripts/check-gateway-ownership.sh`** — **positive** over the raw gateway
  user-data query literals. Every one must carry a scoping token
  (`mailbox_id`/`user_id`/`account_id`/`domain_id`, or an FK-collection handle
  `tag_id`/`folder_id`/`calendar_id`/`addressbook_id` that is mailbox-owned one hop
  away) **in a predicate context** (WHERE / JOIN…ON / AND / OR / HAVING / USING, or
  the WHERE of an UPDATE/DELETE) — a token that only labels a SELECT-projection /
  INSERT-column-list / VALUES / RETURNING column does **not** count (it does not
  scope rows; this is the recall.go:56 info-disclosure IDOR shape) — **or** be on
  the explicit, reason-commented allowlist (R2-INSERTs that set the ownership column
  from auth, admin reports, org-wide GAL per ADR-004, the delivery/SMTP path, SCIM
  provisioning, prior-ownership-checked user reads). A new unscoped raw query, or one
  carrying its ownership column only in the projection, fails CI.
  - **Covered tables (UDT_RE — keep in sync with the guard):** messages,
    message_tags, tags, quarantined_messages, mailboxes, contacts, contact_groups,
    contact_group_members, calendars, calendar_events, addressbooks, tasks, aliases,
    rules, vacation_settings, read_receipts, folders, message_snooze, signatures,
    drafts, user_spam_model, user_sender_list, user_smime_certs, user_signatures,
    user_imap_settings, message_attachments (owned transitively via `message_id →
    messages`), app_passwords, sessions. Not covered (org-wide/admin/system by
    design): message_trace and other trace/journal tables, system_config, domains,
    feature_toggles, signing_keys, threat/audit tables.

Both guards ship with a `-selftest.sh` that injects a violation and asserts the guard
fires (a guard that never fires is theater); both run **selftest-first** in
`scripts/test.sh`.

### State vs transition invariants (when a rule is a `CHECK`)

A DB `CHECK` enforces a property of **one row's state** only (it fires on every row
unconditionally), never a property of a **transition**. Floors/enums/NOT-NULL-pairs are
state invariants → `CHECK` (free, un-bypassable). Ceilings and quotas (e.g.
`used_bytes ≤ quota_bytes`) are *transition* invariants an admin legitimately violates
by lowering a quota under current usage → they stay in the **reducer/trigger that owns
the transition**, never a `CHECK`. See CONTEXT.md → *State invariant vs transition
invariant*.

### Native RLS — ADOPTED on `messages` + `message_tags` (W6), LATENT until the DSN switch

Native PostgreSQL RLS (`ENABLE`+`FORCE ROW LEVEL SECURITY` + per-action `CREATE POLICY`
keyed on a transaction-scoped `set_config('app.current_mailbox_id', …, true)` gateway
injection) is the only **fail-closed-at-runtime** control. The enforcement-flip program
(`retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md`, W0→W6) **adopted it for
`messages` + `message_tags`**: the per-request tx wrappers landed (`internal/jmap`
`CallScoped`, `internal/imap` `withScope`), `scripts/provision-roles.sql` defines the
constrained `setjoin_app` + `BYPASSRLS` `setjoin_worker` roles, `V003` created the inert
policies (keyed on `mailbox_id`; `message_tags` derives its tenant via EXISTS-against-
`messages`), and **`V004__rls_enable.sql` ENABLEd+FORCEd both parents**. Cross-mailbox
paths (`deliver()`/inbound MTA, submission fan-out, the dispatcher, recall, admin
content-search) run on the `setjoin_worker` (BYPASSRLS) pool.

**It is LATENT, not yet live in production:** RLS is bypassed by the superuser/owner
identity the gateway uses today, so V004 is a no-op until the runtime DSN switches to
`setjoin_app`. That switch is the user's **hand-authorized deploy gate** (below). The
other user-data tables (`mailboxes`, `contacts`, `calendar_events`, …) are NOT yet
RLS-covered — app-layer + CI-guard only. **Do not re-suggest native RLS as new in a
review — it is adopted for messages/message_tags and tracked for expansion in that
plan.** Proven by `rls_policies.pg`, `rls_jmap_reducers.pg`, `rls_smtp_delivery.pg`, and
`mailserver/internal/imap/imap_isolation_test.go` (the IMAP-handler dual-tenant proof).

### Deploy gate — switching the prod `DB_DSN` to `setjoin_app` (USER-AUTHORIZED, not automatic)

**Operator runbook (plain-language steps + footgun checklist):**
`docs/guides/NATIVE_RLS_FLIP_RUNBOOK.md`. This section is the canonical
engineering-standard copy of the preconditions; the runbook is the
customer-sysadmin-facing walkthrough of the same gate.

Applying `V004` (the FORCE flip) is inert for the superuser and fail-closing for the
`setjoin_owner` identity: the owner is `NOSUPERUSER NOBYPASSRLS`, so FORCE'd RLS
applies to it (it retains only its standing table privileges and the authority to
reshape policy). **Making RLS LIVE = pointing the gateway's tenant-facing `DB_DSN` at
the `setjoin_app` role.** This is a deliberate, hand-authorized step — do NOT flip it as part of a code
deploy. Preconditions (ALL must hold; mirrored in `scripts/provision-roles.sql` header):

1. **Verify the prod role list** so V004 is confirmed inert pre-switch: `setjoin_app`
   exists, is `NOSUPERUSER NOBYPASSRLS` and **does not own** `messages`/`message_tags`
   (else owner-bypass); `setjoin_worker` exists with `BYPASSRLS`; `setjoin_owner` owns
   the user-data tables. `rls_role_model.pg` asserts this shape.
2. **All isolation tests green** — especially the IMAP streaming dual-tenant proof
   (`go test ./internal/imap -run TestIMAPIsolation` with `DB_DSN` set, V004 applied) +
   the JMAP/SMTP pgTAP proofs + the full pgTAP suite under FORCE.
3. **User reviews the implementation** (V004 + the carve-out routing + the proofs).
4. **V004 applied in a maintenance window** per lock-DDL safety (ENABLE/FORCE take a
   brief `ACCESS EXCLUSIVE` lock on each parent).
5. **DSN-switch rollback rehearsed** — switching `DB_DSN` back to the superuser/owner
   role (or `setjoin_worker`) instantly disables enforcement without a migration; rehearse
   it so the rollback is a known, fast operation. (Wrong-pool symptom under a bad switch:
   tenant reads return empty because the GUC is unset on an un-wrapped path — fail-closed,
   not a leak.)

Once live, the policy column already leads the hot indexes (`messages (mailbox_id,
received_at)`, + the `messages(received_at,id) INCLUDE (mailbox_id)` covering index) so
the predicate adds cost but no new seq-scan.

---

## Query Builder Restrictions

### No string concatenation into SQL

```go
// WRONG — SQL injection (A03:2021)
query := `SELECT id, url FROM webhook_subscriptions WHERE event_types @> '["` + eventType + `"]'::jsonb`

// CORRECT — parameterized
eventJSON, _ := json.Marshal([]string{eventType})
query := `SELECT id, url FROM webhook_subscriptions WHERE event_types @> $1::jsonb`
rows, _ := pool.Query(ctx, query, string(eventJSON))
```

### No fmt.Sprintf for user-controlled values

`fmt.Sprintf` with `%s`/`%d` for SQL fragments is prohibited unless the value is:
- A hardcoded constant in the same function
- From an allow-list (e.g., validated sort column names)

Parameters (`$1`, `$2`) must carry all user-supplied values.

---

## Review Checklist

Before merging any PR that touches database queries, verify:

- [ ] **SELECT:** Every SELECT on a user-data table has `user_id`/`mailbox_id` in WHERE or JOIN
- [ ] **INSERT:** `user_id`/`mailbox_id` comes from auth context, never `req.*`
- [ ] **UPDATE:** WHERE clause includes both `id` AND ownership column
- [ ] **DELETE:** WHERE clause includes both `id` AND ownership column
- [ ] **Per-user isolation:** Every raw gateway user-data query carries an ownership predicate (or is allowlisted in `check-gateway-ownership.sh`); native RLS is *deferred* — not required (ARCH-006)
- [ ] **Injection:** No string concatenation or `fmt.Sprintf` with user input into SQL
- [ ] **TOCTOU:** No separate SELECT-then-mutate ownership patterns (must be in same SQL statement)
- [ ] **Index:** The ownership column (`mailbox_id`) is leading in composite indexes (already true for the hot paths; matters for the deferred RLS too)
- [ ] **Reducers:** `p_mailbox_id` is referenced in the body and scopes the user-data statements (Check H is the floor; per-statement scoping on review)

---

## Audit Commands

Run these before claiming a feature is complete:

```bash
# Find queries missing user_id in WHERE (Go)
grep -rn 'WHERE.*=.*\$' --include="*.go" mailserver/gateway/internal/ authserver/internal/ \
  | grep -v 'user_id\|mailbox_id\|account_id\|domain_id'

# Find DELETEs without ownership check (SQL)
grep -rn 'DELETE FROM' mailserver/sql/reducers/ \
  | grep -v 'user_id\|mailbox_id\|account_id\|p_account'

# Find INSERTs using req.* for ownership (Go)
grep -rn 'req\.MailboxID\|req\.UserID\|req\.UserId' --include="*.go" mailserver/gateway/internal/handlers/

# Per-user isolation: the positive CI guards (load-bearing) PLUS native RLS on the
# messages/message_tags hot tables (W6/V004 — latent until the prod DSN switch):
bash scripts/check-account-scope.sh        # reducer layer (negative A–G + positive H)
bash scripts/check-gateway-ownership.sh    # raw gateway query surface (positive)
# Native RLS is now ENABLE+FORCE on messages + message_tags only (V004); confirm:
#   psql -d <db> -tAc "SELECT relname, relforcerowsecurity FROM pg_class
#     WHERE relname IN ('messages','message_tags');"   -- expect both 't'
# (no-op until the runtime connects as the non-owner setjoin_app role — Deploy gate above)

# Check for string concatenation in SQL
grep -rn '"\s*+\s*' --include="*.go" mailserver/ authserver/ | grep -i 'select\|insert\|update\|delete\|query\|exec'
```
