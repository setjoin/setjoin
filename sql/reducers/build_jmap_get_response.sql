-- build_jmap_get_response.sql
-- The single JMAP get-envelope seam (RFC 8621 §5.1 "/get" response).
--
-- Every jmap_*_get reducer re-implements the same envelope by hand:
--   {accountId, state, list, notFound}
-- where notFound is "the requested ids that were not returned". The notFound
-- ownership probe was copy-pasted ~9 times and HAD DRIFTED — five copies scoped
-- the existence check by p_mailbox_id, four did NOT (they probed `WHERE id = x`
-- org-wide), making the latter a cross-mailbox existence oracle + a list/notFound
-- contract violation. This seam removes the drift by construction.
--
-- DESIGN (found-set diff, NOT a shared re-probe):
--   The caller's main FOR-LOOP is ALREADY owner-scoped (that is how it built
--   p_list). So "the ids that made it into the list" (p_found_ids) IS the
--   owner-scoped found-set. notFound is then PURELY set-theoretic:
--       notFound = p_requested  minus  p_found_ids
--   The seam reads NO base table and has NO table knowledge — it CANNOT mis-scope
--   the existence check, because there is no second existence check. The scoped-
--   vs-unscoped drift becomes un-expressible.
--
-- CONTRACT (pinned byte-for-byte against the pre-seam reducers):
--   * accountId : p_mailbox_id::TEXT
--   * state     : p_state::TEXT
--   * list      : p_list (the caller's per-type projection, passed through as-is)
--   * notFound  :
--       - p_requested IS NULL ⇒ SQL NULL ⇒ JSON null, key PRESENT (the old
--         `CASE WHEN p_ids IS NOT NULL` returned NULL for the all-objects "get").
--       - otherwise ⇒ array_agg of the requested ids NOT in the found-set, in
--         p_requested ORDER (the old probe yielded ids in unnest(p_ids) order).
--         Zero misses ⇒ array_agg over no rows ⇒ NULL ⇒ JSON null (the old probe
--         did the same; there is no `[]` case).
--
-- ORDERING is load-bearing: the misses are computed with
--   array_agg(x) FROM unnest(p_requested) x WHERE x <> ALL(p_found_ids)
-- which preserves p_requested order. A set EXCEPT would reorder — do not use it.
--
-- TEXT-id thread variant: jmap_thread_get passes its emitted thread-id list as
-- p_found_ids and p_email_ids (its TEXT[] requested) as p_requested. The diff
-- semantics are identical; the seam needs no special case.
--
-- -- deps: (none — pure JSONB assembly off its arguments, no base-table read). STABLE.

CREATE OR REPLACE FUNCTION build_jmap_get_response(
  p_mailbox_id BIGINT,
  p_state      BIGINT,
  p_list       JSONB,
  p_found_ids  TEXT[],
  p_requested  TEXT[]
) RETURNS JSONB AS $$
  SELECT jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'state',     p_state::TEXT,
    'list',      p_list,
    'notFound',  CASE WHEN p_requested IS NOT NULL THEN
      (SELECT array_agg(x)
         FROM unnest(p_requested) AS x
        WHERE x <> ALL(COALESCE(p_found_ids, ARRAY[]::TEXT[])))
    END
  );
$$ LANGUAGE sql STABLE;

COMMENT ON FUNCTION build_jmap_get_response(BIGINT, BIGINT, JSONB, TEXT[], TEXT[]) IS
  'JMAP get-envelope seam (RFC 8621 §5.1): {accountId, state, list, notFound}. '
  'notFound is a found-set diff (p_requested minus p_found_ids, in p_requested '
  'order) off the caller''s already-owner-scoped found-set — no table knowledge, '
  'so it cannot mis-scope. p_requested NULL ⇒ notFound NULL. STABLE.';
