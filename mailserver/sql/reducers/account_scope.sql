-- account_scope.sql
-- The single resolver seam for the mailbox → user → domain mapping (ADR-003).
--
-- The reducer account-slot argument is ALWAYS a mailbox_id (parseAccountID returns
-- the caller's primary mailbox id, never a users.id — see CONTEXT.md → Account scope).
-- Any reducer that needs the user_id or domain_id BEHIND that mailbox calls this
-- function instead of hand-joining `mailboxes`, which re-introduces the
-- user_id/mailbox_id confusion and the `user_id IS NULL` shared-mailbox edge.
--
-- Behaviour:
--   - One SELECT off `mailboxes`. STABLE (read-only; depends only on DB state).
--   - Returns exactly ONE row for a known mailbox; ZERO rows for an unknown one
--     (callers decide how to treat "not found" — most fail-safe or RAISE).
--   - user_id is returned AS-IS: it is NULL for shared/resource mailboxes
--     (mailboxes.user_id is nullable). Callers must handle the NULL case; this
--     function never substitutes the mailbox id for a missing user.
--   - domain_id is NOT NULL in the schema, so it is always populated for a hit.
--
-- This is the one place the mapping lives; do not hand-derive user_id/domain_id
-- from a mailbox elsewhere.

CREATE OR REPLACE FUNCTION account_scope(
    p_mailbox_id BIGINT
) RETURNS TABLE(
    mailbox_id BIGINT,
    user_id    BIGINT,
    domain_id  BIGINT
) AS $$
    SELECT m.id, m.user_id, m.domain_id
      FROM mailboxes m
     WHERE m.id = p_mailbox_id;
$$ LANGUAGE sql STABLE;

COMMENT ON FUNCTION account_scope(BIGINT) IS
  'Resolver seam (ADR-003): account_scope(p_mailbox_id) → (mailbox_id, user_id, '
  'domain_id). The one place the mailbox→user→domain mapping lives. user_id is '
  'returned as-is (NULL for shared/resource mailboxes). Zero rows for an unknown '
  'mailbox. STABLE. Reducers needing the user/domain behind a mailbox call this '
  'instead of hand-joining mailboxes.';
