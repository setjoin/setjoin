# Database Query Security — Enforced Standards

> **Status:** Enforced for all new and modified database queries.  
> **Standards:** OWASP A01:2021, API1:2023 (BOLA), CWE-639/862/566, NIST 800-53 AC-16  
> **References:** `docs/ref/SECURITY.md` (email security), `docs/reducer-error-codes.md` (PL/pgSQL error contract)
> **Memory:** [[reference-owasp-security-standards]], [[reference-cwe-authorization]], [[reference-rls-best-practices]], [[reference-nist-database-security]]

## The Four Rules

Every database query **must** satisfy all four rules. No exceptions.

| Rule | Applies to | Test |
|------|-----------|------|
| **R1 — SELECT filter** | Every SELECT on user-data tables | Does the WHERE/JOIN constrain rows to the authenticated user? |
| **R2 — INSERT from auth** | Every INSERT into user-data tables | Is `user_id`/`mailbox_id` set from auth context, never the request body? |
| **R3 — Mutate with ownership** | Every UPDATE/DELETE on user-data tables | Does the WHERE clause include BOTH the resource ID AND the ownership column? |
| **R4 — Per-user isolation** | Every table containing per-user data | Does every access carry an ownership-scoping predicate, propagated from auth, AND pass unconditional fail-closed `FORCE ROW LEVEL SECURITY` under `setjoin_app`? (Both application-layer predicates/CI guards and native `FORCE RLS` are enforced — see Rule 4 and [ARCH-006](../adr/ARCH-006-app-level-isolation-posture.md).) |

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

## Rule 4: Per-User Isolation — Application Layer + Mandatory Fail-Closed Native `FORCE RLS`

> **Release N+1 (`#547`) mandatory baseline:** Per-user isolation is enforced
> **both** in application code (`p_mailbox_id` / `ScopedTx` / `PolicyGate`
> predicates guarded in CI) **and** by **unconditional fail-closed PostgreSQL
> `ENABLE` + `FORCE ROW LEVEL SECURITY`**. Starting in Release N+1 (`#547`),
> `setjoin-server` and `setjoin-auth` unconditionally refuse to start (exit `1`)
> if `DB_DSN` connects as a superuser, a `BYPASSRLS` role, or any role that owns
> (directly or via `pg_has_role(..., 'MEMBER')`) a `FORCE RLS` table; if
> `DB_WORKER_DSN` is omitted or shares a role with `DB_DSN`; if an explicitly
> configured `DB_OWNER_DSN` shares a role with `DB_DSN`; if any table with RLS
> policies lacks `ENABLE` or `FORCE ROW LEVEL SECURITY`; if PostgreSQL is
> vulnerable to `CVE-2026-14666` (`< 17.11` or `18.0–18.5`); or if canonical
> roles or ARCH-018 `SECURITY DEFINER` scope helpers have drifted.
>
> **The application-layer R1–R3 predicates and positive CI guards remain
> load-bearing** (cheaper, earlier CI-time feedback and defense-in-depth across
> every raw query and reducer). Native `FORCE RLS` is the mandatory runtime
> backstop; it does not retire the CI guards. See
> [ARCH-006](../adr/ARCH-006-app-level-isolation-posture.md) and
> `docs/guides/NATIVE_RLS_FLIP_RUNBOOK.md`.

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

- **`scripts/check-table-ownership-manifest.sh`** (`config/table-ownership-manifest.json`,
  Issue #539) — **positive** static guard over all logical base/parent tables in
  `mailserver/sql/dbschema/V*.sql` and all Rust domain crates (`server-rust/crates/domains/*`):
  1. Classifies every logical table with an owning domain crate (or `foundation`),
     security class (`mailbox_scoped`, `user_scoped`, `org_global`, `system_only`),
     RLS posture (`enforced` requires both `ENABLE`+`FORCE ROW LEVEL SECURITY` in
     replayed `V*.sql`; `pending_wave1_cutover` is ratcheted strictly to the frozen
     legacy baseline tracked by `#546` so no new table may omit `FORCE RLS`), and
     required `rls_scope_column` for scoped tables.
  2. Rejects uncontracted cross-domain SQL reads/writes in `server-rust/crates/domains/*`
     and ratchets `legacy_write_migration_pending` contracts monotonically.
  3. Enforces R1–R3 ownership predicates in predicate context (`WHERE`/`JOIN ... ON`/
     `HAVING`/`USING`, never projection-only) for `SELECT`, and in `WHERE` for
     `UPDATE`/`DELETE`, respecting explicit `r1_r3_allowlist` entries.
  Ships with `scripts/check-table-ownership-manifest-selftest.sh` (auto-discovered by
  `scripts/run-guards.sh`) proving all failure modes fire.

All three guards ship with a `-selftest.sh` that injects a violation and asserts the guard
fires (a guard that never fires is theater); all run **selftest-first** in
`scripts/test.sh`.

### State vs transition invariants (when a rule is a `CHECK`)

A DB `CHECK` enforces a property of **one row's state** only (it fires on every row
unconditionally), never a property of a **transition**. Floors/enums/NOT-NULL-pairs are
state invariants → `CHECK` (free, un-bypassable). Ceilings and quotas (e.g.
`used_bytes ≤ quota_bytes`) are *transition* invariants an admin legitimately violates
by lowering a quota under current usage → they stay in the **reducer/trigger that owns
the transition**, never a `CHECK`. See CONTEXT.md → *State invariant vs transition
invariant*.

### Native RLS — MANDATORY FAIL-CLOSED RUNTIME BASELINE (Release N+1 `#547`)

Native PostgreSQL RLS (`ENABLE`+`FORCE ROW LEVEL SECURITY` + per-action `CREATE POLICY`
keyed on transaction-scoped `set_config` GUCs injected by `ScopedTx` / `PolicyGate`)
is the **mandatory fail-closed runtime control**. `scripts/provision-roles.sql` and
`mailctl schema provision-roles` provision the constrained `setjoin_app` (`NOSUPERUSER
NOBYPASSRLS`, owns nothing), `setjoin_worker` (`BYPASSRLS`, cross-tenant workers),
`setjoin_owner` (DDL/migrations), and `setjoin_updater` roles.

`setjoin-server`, `setjoin-auth`, `mailctl schema preflight`, `setjoin-updater`,
`install.sh`, and `upgrade.sh` all enforce Release N+1 (`FailClosedReleaseNPlus1`)
unconditionally with zero production bypass flags (guarded by
`scripts/check-rls-fail-closed.sh`). Single-DSN permissive installs and
superuser-DSN rollbacks are retired. See `docs/guides/NATIVE_RLS_FLIP_RUNBOOK.md`
for operator preflight and provisioning steps.

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
- [ ] **Per-user isolation:** Every raw gateway user-data query carries an ownership predicate (or is allowlisted in `check-gateway-ownership.sh`), AND new/modified user-data tables have `ENABLE` + `FORCE ROW LEVEL SECURITY` policies verified under `setjoin_app` (ARCH-006 / Release N+1 `#547`)
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
bash scripts/check-table-ownership-manifest.sh  # schema ownership, FORCE RLS ratchet, Rust cross-domain & R1-R3 guard
bash scripts/check-gateway-ownership.sh    # raw gateway query surface (positive)
# Native RLS is now ENABLE+FORCE on messages + message_tags only (V004); confirm:
#   psql -d <db> -tAc "SELECT relname, relforcerowsecurity FROM pg_class
#     WHERE relname IN ('messages','message_tags');"   -- expect both 't'
# (no-op until the runtime connects as the non-owner setjoin_app role — Deploy gate above)

# Check for string concatenation in SQL
grep -rn '"\s*+\s*' --include="*.go" mailserver/ authserver/ | grep -i 'select\|insert\|update\|delete\|query\|exec'
```
