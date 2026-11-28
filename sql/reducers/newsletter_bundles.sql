-- reducers/newsletter_bundles.sql
-- B5.2 — Computed newsletter bundle grouping query
--
-- newsletter_bundles_list(p_mailbox_id, p_limit, p_offset)
--
-- Groups messages by list_id for the calling account's primary mailbox,
-- excluding Trash/Spam-tagged messages and messages with NULL list_id.
-- Returns a JSONB array of bundle objects sorted by latest received_at DESC.
--
-- Per-user opt-out: lists stored in users.view_prefs->>'newsletterOptouts'
-- (a JSON array of list_id strings) are excluded from the result — the client
-- sends individual messages for those lists instead of a collapsed bundle.
--
-- Auth scoping (R1): every query is scoped to p_mailbox_id's mailbox; no
-- cross-mailbox data is ever returned.
--
-- STABLE: read-only, no side effects, no state bumps (query-only path).
--

CREATE OR REPLACE FUNCTION newsletter_bundles_list(
  p_mailbox_id BIGINT,
  p_limit      INT     DEFAULT 50,
  p_offset     INT     DEFAULT 0
) RETURNS JSONB
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
  v_user_id   BIGINT;
  v_optouts   JSONB;
  v_result    JSONB;
BEGIN
  -- Resolve the user from the account (mailbox) id via the resolver seam — R1.
  -- (v_user_id is NULL for an unknown mailbox OR a shared/resource one; either
  -- way there is no owning user whose newsletter bundles we can list.)
  SELECT s.user_id INTO v_user_id
    FROM account_scope(p_mailbox_id) s;

  IF v_user_id IS NULL THEN
    RETURN '[]'::JSONB;
  END IF;

  -- Read the per-user newsletter opt-out list from view_prefs.
  -- view_prefs->>'newsletterOptouts' is a JSON array of list_id strings, e.g.
  --   ["news.acme.io","deals.shop.io"]
  -- Absent key or NULL view_prefs ⇒ no opt-outs (all bundles shown).
  SELECT COALESCE(view_prefs->'newsletterOptouts', '[]'::JSONB)
    INTO v_optouts
    FROM users
   WHERE id = v_user_id;

  -- Build the bundle list:
  --   - Scope to the mailbox (p_mailbox_id) — R1
  --   - Exclude NULL list_id (non-newsletter messages)
  --   - Exclude messages in Trash or Spam (by checking their tag names)
  --   - Exclude opted-out list_ids
  --   - Aggregate count per list_id
  --   - Pick the latest message per list_id (DISTINCT ON would require a
  --     subquery; use GROUP BY with MAX for latest id and received_at)
  SELECT COALESCE(jsonb_agg(bundle ORDER BY bundle->>'latestReceivedAt' DESC), '[]'::JSONB)
    INTO v_result
    FROM (
      SELECT
        jsonb_build_object(
          'listId',           m.list_id,
          'count',            COUNT(*),
          'latestEmailId',    MAX(m.id),
          'latestReceivedAt', MAX(m.received_at)
        ) AS bundle
      FROM messages m
     WHERE m.mailbox_id = p_mailbox_id
       AND m.list_id IS NOT NULL
       AND m.is_deleted = FALSE
       -- Exclude opted-out list_ids: reject any row whose list_id appears in
       -- the opt-out array.  v_optouts is a JSONB array; ? operator checks
       -- membership by value.
       AND NOT (v_optouts @> to_jsonb(m.list_id))
       -- Exclude messages currently in Trash or Spam (check tag name via tags
       -- table; a message may have at most one location-group tag).
       AND NOT EXISTS (
         SELECT 1
           FROM message_tags mt
           JOIN tags t ON t.id = mt.tag_id
          WHERE mt.message_id = m.id
            AND mt.received_at = m.received_at
            AND t.mailbox_id = p_mailbox_id
            AND t.name IN ('Trash', 'Spam')
       )
     GROUP BY m.list_id
     ORDER BY MAX(m.received_at) DESC
     LIMIT  GREATEST(1, LEAST(COALESCE(p_limit, 50), 200))
     OFFSET GREATEST(0, COALESCE(p_offset, 0))
    ) sub;

  RETURN COALESCE(v_result, '[]'::JSONB);
END;
$$;

COMMENT ON FUNCTION newsletter_bundles_list(BIGINT, INT, INT) IS
  'Computed newsletter bundle list for a mailbox account (p_mailbox_id). '
  'Groups messages by list_id, excluding NULL list_id, Trash/Spam, and '
  'list_ids in the user''s opt-out set (users.view_prefs->''newsletterOptouts''). '
  'Returns a JSONB array of {listId, count, latestEmailId, latestReceivedAt} '
  'sorted by latestReceivedAt DESC. STABLE — read-only, no side effects.';
