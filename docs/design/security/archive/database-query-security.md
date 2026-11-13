# Database Query Security — Audit & Fix Design

## Context

Systematic audit of every database query (Go handlers + PL/pgSQL reducers) against the 4 rules in `docs/specs/DATABASE_SECURITY.md`. Found 0 SQL injection vulnerabilities but 8 critical and 10 high-severity ownership enforcement gaps in PL/pgSQL reducers. Go handlers are generally safe — admin endpoints rely on middleware, user-facing endpoints are compliant.

## Design Principles

1. **Same-statement ownership** — UPDATE/DELETE must include ownership in their own WHERE clause, not rely on a prior SELECT (no TOCTOU).
2. **Auth context, never request body** — `user_id`/`mailbox_id`/`tag_id` must be resolved from `p_account_id`, never from user-supplied input.
3. **Defense in depth** — even admin endpoints should include ownership WHERE clauses where practical.
4. **Backward compatible** — function signatures that change must use default values or create new wrapper functions.

## Fix Approach by Severity

### Critical (8 functions) — Add auth context, verify ownership

**Problem:** Functions completely lack `p_account_id` or accept ownership identifiers from request input.

**Fix pattern:**

For functions lacking `p_account_id` entirely (calendar, iTIP, send_read_receipt):
```sql
-- Before:
CREATE FUNCTION calendar_book_resource(
    p_resource_calendar_id BIGINT,
    p_event_id BIGINT,
    p_booked_by TEXT
) ...

-- After:
CREATE FUNCTION calendar_book_resource(
    p_account_id BIGINT,           -- NEW
    p_resource_calendar_id BIGINT,
    p_event_id BIGINT,
    p_booked_by TEXT
) ...
-- Add at function entry:
PERFORM 1 FROM calendars WHERE id = p_resource_calendar_id
  AND mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = p_account_id);
IF NOT FOUND THEN
    RAISE EXCEPTION 'Calendar not found' USING ERRCODE = 'BZ001';
END IF;
```

For tag_id injection (jmap_email_set_create/update):
```sql
-- Before: v_tag_id comes from jsonb_each(v_mailbox_ids) — request input
INSERT INTO message_tags (message_id, tag_id, ...) VALUES (v_id, v_tag_id, ...);

-- After: verify tag ownership before using it
PERFORM 1 FROM mailboxes WHERE id = v_tag_id
  AND (user_id = p_account_id OR id IN (
    SELECT id FROM mailboxes WHERE user_id = p_account_id
  ));
IF NOT FOUND THEN
    RAISE EXCEPTION 'Tag not found' USING ERRCODE = 'BZ002';
END IF;
```

### High (10 functions) — Add ownership to DML WHERE

**Problem:** UPDATE/DELETE uses only `WHERE id = v_id` or `WHERE id = v_id AND received_at = v_received_at` without ownership. Previous SELECT verified ownership, but R3 requires it in the same statement.

**Fix pattern:**
```sql
-- Before:
UPDATE messages SET is_read = TRUE WHERE id = v_id;
DELETE FROM message_tags WHERE message_id = v_id;

-- After:
UPDATE messages SET is_read = TRUE
  WHERE id = v_id AND mailbox_id = v_mailbox_id;
DELETE FROM message_tags WHERE message_id = v_id
  AND tag_id IN (SELECT id FROM mailboxes WHERE user_id = p_account_id);
```

### Medium (3 functions) — Document or add guard

- **jmap_email_purge dedup query:** Accept as inherent to content-addressed storage. Document.
- **gal_search domain scoping:** Add `AND u.domain_id = (SELECT domain_id FROM mailboxes WHERE user_id = p_account_id LIMIT 1)`.
- **calendar_free_busy permission check:** Add `AND EXISTS (SELECT 1 FROM ... WHERE shared_with = p_account_id)` or document as intentionally public.

### Low (1 function) — Use parameterized EXECUTE

- **jmap_mailbox_query_changes** line 300: Replace string concatenation with `USING` clause or `format('%L', v_since_state)`.

### Go Admin Handlers — Defense in depth (documented limitation)

All admin endpoints are protected by `requireAdmin`/`requireSuperAdmin` middleware that gates before the handler runs. The fix for admin handlers is:

1. **Where practical:** Add `AND user_id = (SELECT id FROM users WHERE ...)` subqueries to UPDATE/DELETE statements.
2. **Where not practical** (list all users, cross-user admin operations): Document that the admin middleware is the authorization boundary.
3. **Quarantine Release/Reject:** Add `AND mailbox_id IN (SELECT id FROM mailboxes WHERE ...)` — this is the most actionable admin fix.

## Priority Order

| Priority | Functions | Effort | Risk of regression |
|----------|-----------|--------|-------------------|
| P0 | 8 Critical: tag_id injection, no-auth calendar/iTIP/read_receipt | Medium (add params, ownership checks) | High — function signature changes |
| P1 | 10 High: DML without ownership WHERE | Low (mechanical: add WHERE clause) | Medium — need to ensure v_mailbox_id is available |
| P2 | 3 Medium: information leaks | Low | Low |
| P3 | 1 Low: dynamic SQL | Low | Low |
| P4 | Go admin defense-in-depth | Low | Low |

## Testing Strategy

Each fix gets a pgTAP test that:
1. Creates two users (alice, bob) with separate mailboxes
2. Attempts the operation as alice on bob's data → must fail
3. Attempts the operation as alice on alice's data → must succeed

Example for tag_id injection fix:
```sql
SELECT plan(3);

-- Setup: alice (user 1), bob (user 2), each with mailboxes
-- alice has tag 'alice_tag', bob has tag 'bob_tag'

-- Test 1: Alice cannot set bob's tag on her email
PREPARE cross_user_tag AS
  SELECT jmap_email_set_create(
    1, -- alice's account_id
    jsonb_build_object(...) -- includes bob's tag_id
  );
SELECT throws_ok('cross_user_tag', 'BZ002', NULL, 'Rejects cross-user tag');

-- Test 2: Alice can set her own tag
-- Test 3: Bob can set his own tag
```

## Backward Compatibility

Functions that gain new parameters must handle existing callers:
- Go handlers that call these reducers must be updated to pass `p_account_id`
- If a function is called from multiple contexts (user-facing + system/cron), use a default `NULL` for `p_account_id` and skip the check when NULL (for system callers)

## Verification

1. `pg_prove -d mailserver mailserver/sql/tests/*.pg` — all pgTAP tests pass
2. `cd mailserver/gateway && go build ./cmd/gateway && go test ./...` — Go tests pass
3. Manual: attempt cross-user mutation via modified JMAP request → 403/error
