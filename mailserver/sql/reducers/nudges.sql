-- reducers/nudges.sql
-- #13 — Stale-thread / no-reply nudges (query-time computation, no cron table,
-- no new columns — mirrors the newsletter_bundles pattern exactly).
--
--   stale_thread_nudges_list(p_mailbox_id, p_limit, p_offset) → JSONB array
--   nudge_dismiss(p_mailbox_id, p_thread_id) → VOID
--
-- Both resolve the owning user via account_scope(p_mailbox_id) (ADR-003 / R1);
-- the mailbox id comes from the auth path, never from a request body.
--
-- Dismiss state rides users.view_prefs->'nudgeDismissed' (a JSONB array of
-- thread_id strings) — the same view_prefs idiom as newsletterOptouts, so this
-- feature needs zero migration for dismiss state. view_prefs is not JMAP-synced
-- state, so neither function bumps a jmap_*_state (matching the opt-out path).
--

-- ── stale_thread_nudges_list ──────────────────────────────────────────────
-- Per thread, classify the SINGLE latest message (by GREATEST(sent_at,
-- received_at)) among messages currently tagged Inbox or Sent (Trash/Spam/
-- Drafts are excluded because they carry a different location tag):
--   * latest is 'Sent'  AND sent_at     < now()-3d ⇒ kind='no_reply_sent'
--     (no later inbound exists — it IS the latest — so the reply never came)
--   * latest is 'Inbox' AND is_answered = FALSE
--                       AND received_at < now()-3d ⇒ kind='stale_unanswered'
-- Classifying only the single latest row per thread makes the two kinds
-- mutually exclusive per thread — that is the dedupe (no extra logic needed).
CREATE OR REPLACE FUNCTION stale_thread_nudges_list(
  p_mailbox_id BIGINT,
  p_limit      INT DEFAULT 50,
  p_offset     INT DEFAULT 0
) RETURNS JSONB
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
  v_user_id   BIGINT;
  v_dismissed JSONB;
  v_result    JSONB;
BEGIN
  -- Resolve the owning user (R1). NULL for an unknown or shared/resource mailbox.
  SELECT s.user_id INTO v_user_id FROM account_scope(p_mailbox_id) s;
  IF v_user_id IS NULL THEN
    RETURN '[]'::JSONB;
  END IF;

  SELECT COALESCE(view_prefs->'nudgeDismissed', '[]'::JSONB)
    INTO v_dismissed
    FROM users
   WHERE id = v_user_id;

  SELECT COALESCE(jsonb_agg(nudge ORDER BY latest DESC), '[]'::JSONB)
    INTO v_result
    FROM (
      SELECT
        jsonb_build_object(
          'threadId',       c.thread_id,
          'emailId',        c.id,
          'subject',        c.subject,
          'counterpart',    CASE WHEN c.location = 'Sent'
                                 THEN (c.to_addrs->0->>'email')
                                 ELSE c.from_addr END,
          'kind',           CASE WHEN c.location = 'Sent'
                                 THEN 'no_reply_sent'
                                 ELSE 'stale_unanswered' END,
          'lastActivityAt', c.latest
        ) AS nudge,
        c.latest
      FROM (
        SELECT DISTINCT ON (m.thread_id)
          m.thread_id,
          m.id,
          m.subject,
          m.from_addr,
          m.to_addrs,
          m.is_answered,
          m.sent_at,
          m.received_at,
          loc.name AS location,
          GREATEST(m.sent_at, m.received_at) AS latest
        FROM messages m
        JOIN message_tags mt
          ON mt.message_id = m.id AND mt.received_at = m.received_at
        JOIN tags loc
          ON loc.id = mt.tag_id
         AND loc.mailbox_id = p_mailbox_id
         AND loc.name IN ('Inbox', 'Sent')
       WHERE m.mailbox_id = p_mailbox_id
         AND m.is_deleted = FALSE
       ORDER BY m.thread_id, GREATEST(m.sent_at, m.received_at) DESC
      ) c
     WHERE NOT (v_dismissed @> to_jsonb(c.thread_id))
       AND (
         (c.location = 'Sent'  AND c.sent_at     < now() - interval '3 days')
         OR
         (c.location = 'Inbox' AND c.is_answered = FALSE
                               AND c.received_at < now() - interval '3 days')
       )
     ORDER BY c.latest DESC
     LIMIT  GREATEST(1, LEAST(COALESCE(p_limit, 50), 200))
     OFFSET GREATEST(0, COALESCE(p_offset, 0))
    ) sub;

  RETURN COALESCE(v_result, '[]'::JSONB);
END;
$$;

COMMENT ON FUNCTION stale_thread_nudges_list(BIGINT, INT, INT) IS
  'Computed stale-thread / no-reply-in-3-days nudge list for a mailbox account '
  '(p_mailbox_id). Classifies the single latest Inbox/Sent message per thread as '
  'kind=no_reply_sent or stale_unanswered; excludes thread_ids in '
  'users.view_prefs->''nudgeDismissed''. Returns a JSONB array of {threadId, '
  'emailId, subject, counterpart, kind, lastActivityAt} sorted by lastActivityAt '
  'DESC. STABLE — read-only, no side effects.';

-- ── nudge_dismiss ─────────────────────────────────────────────────────────
-- Append p_thread_id to users.view_prefs->'nudgeDismissed' for the owning user
-- (R1/R2 — user resolved from the mailbox auth path, not the request body).
-- Idempotent: the WHERE NOT @> guard makes a repeat dismiss a no-op (no dup).
-- Returns JSONB (the updated dismissed array) rather than VOID so the scoped
-- caller's QueryRow.Scan(&json.RawMessage) path works, matching reminder_dismiss.
CREATE OR REPLACE FUNCTION nudge_dismiss(
  p_mailbox_id BIGINT,
  p_thread_id  TEXT
) RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_user_id BIGINT;
BEGIN
  SELECT s.user_id INTO v_user_id FROM account_scope(p_mailbox_id) s;
  IF v_user_id IS NULL OR p_thread_id IS NULL OR p_thread_id = '' THEN
    RETURN '[]'::JSONB;
  END IF;

  UPDATE users
     SET view_prefs = jsonb_set(
           COALESCE(view_prefs, '{}'::JSONB),
           '{nudgeDismissed}',
           COALESCE(view_prefs->'nudgeDismissed', '[]'::JSONB) || to_jsonb(p_thread_id),
           TRUE
         )
   WHERE id = v_user_id
     AND NOT (COALESCE(view_prefs->'nudgeDismissed', '[]'::JSONB) @> to_jsonb(p_thread_id));

  RETURN COALESCE(
    (SELECT view_prefs->'nudgeDismissed' FROM users WHERE id = v_user_id),
    '[]'::JSONB
  );
END;
$$;

COMMENT ON FUNCTION nudge_dismiss(BIGINT, TEXT) IS
  'Dismiss a stale-thread nudge: append p_thread_id to '
  'users.view_prefs->''nudgeDismissed'' for the account''s owning user '
  '(resolved via account_scope — R1/R2). Idempotent; returns the updated '
  'dismissed array. No jmap_*_state bump (view_prefs is not JMAP-synced state).';
