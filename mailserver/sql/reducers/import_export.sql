-- import_export.sql: Mailbox import/export helpers
--
-- AUTHORIZATION (round 3/4, Astra HOLDs): import AND export are admin
-- operations on the BYPASSRLS worker pool, so the route permission alone is
-- necessary but NOT sufficient — the actor's domain scope is enforced
-- STATEMENT-LEVEL, inside SQL, via admin_can_reach_mailbox():
--
--   - import_message() carries p_actor_id/p_domain_scope and evaluates the
--     predicate in the INSERT's WHERE. A revocation between the route seam and
--     execution inserts ZERO rows and returns NULL (the Go caller reports the
--     message failed) — it never inserts on stale authority. p_actor_id IS NULL
--     is the SYSTEM path (migration orchestration) and skips the predicate.
--   - The export SELECT (admin_import_export.go) filters rows through the same
--     admin_can_reach_mailbox() predicate.
--
-- admin_can_reach_mailbox mirrors the Go canReachMailbox EXACTLY:
--   owner-present mailbox → admin_can_reach(actor, owner) decides for EVERY
--     caller; owner-less mailbox (distribution/shared) → LIVE authority on the
--     MAILBOX'S OWN domain only (round 6, Astra r5), or — only when NO scope is
--     in context — a genuinely-global live authority (NULL domain AND
--     is_unconfined); missing mailbox → FALSE.
-- INPUT: p_mailbox_id (BIGINT, REQUIRED) — target mailbox
-- INPUT: p_message_id (TEXT, REQUIRED) — RFC 5322 Message-ID header
-- INPUT: p_subject, p_from_addr, p_body_text (TEXT) — message content
-- INPUT: p_size_bytes (BIGINT) — checked against check_quota() before INSERT
-- INPUT: p_is_read, p_is_flagged (BOOL) — initial flags

-- ──────────────────────────────────────────────────────────────────────────
-- admin_can_reach_mailbox(p_actor_id, p_domain_scope, p_mailbox_id)
-- The single statement-level reach primitive for mailbox import/export. It is
-- the DB-side twin of Go canReachMailbox (admin_import_export.go): the Go seam
-- is the per-request FAST PATH (UX + 404/403 wording); this predicate is the
-- AUTHORITY evaluated in the same transaction as the data access, so a
-- revocation mid-upload/mid-stream is observed at execution time.
--
--   - Missing mailbox → FALSE (fail closed, no existence oracle).
--   - p_actor_id NULL (unauthenticated/system-less call) → FALSE on every arm
--     (admin_can_reach/admin_effective_authority match nothing for NULL).
--   - Owner-present mailbox → admin_can_reach(p_actor_id, owner), for EVERY
--     caller: genuinely global admins pass (active NULL-domain, NULL-scope_type
--     assignment covers every target); an OU/set-confined assignment without a
--     domain does NOT. There is deliberately no `scope = 0 → allow` shortcut
--     (round-2 HOLD: that shortcut was a privilege escalation).
--   - Owner-less mailbox (distribution/shared — admin_can_reach cannot decide,
--     no owner user row): LIVE authority only, never the cached context claim:
--       * LIVE domain authority on the MAILBOX'S OWN domain: an active
--         assignment whose effective (broadest) scope equals mb.domain_id
--         (NOT NULL, > 0). Round 6 (Astra r5): the pre-round-6 arm compared
--         the actor's live authority with the CLAIMED p_domain_scope instead,
--         so an actor scoped to domain A passed for an owner-less mailbox in
--         domain B — the mailbox's own domain was never consulted.
--       * p_domain_scope NULL/0 (no scope in context): only a genuinely-global
--         live authority passes — some active grant with NULL domain
--         (a.scope IS NULL) AND no OU/set narrowing (is_unconfined). A
--         non-matching context scope denies even a global actor (fallback
--         exactness with the Go arm ordering).
-- STABLE: genuinely read-only; safe per-row in INSERT..SELECT / export filters.
-- ──────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION admin_can_reach_mailbox(
  p_actor_id     BIGINT,
  p_domain_scope BIGINT,
  p_mailbox_id   BIGINT
) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT CASE
    WHEN NOT EXISTS (SELECT 1 FROM mailboxes mb WHERE mb.id = p_mailbox_id) THEN
      FALSE
    WHEN (SELECT mb.user_id FROM mailboxes mb WHERE mb.id = p_mailbox_id) IS NOT NULL THEN
      admin_can_reach(p_actor_id,
                      (SELECT mb.user_id FROM mailboxes mb WHERE mb.id = p_mailbox_id))
    ELSE
      -- Round 6 (Astra r5): LIVE authority anchored to the MAILBOX'S OWN
      -- domain — never to the caller's claimed context scope.
      EXISTS (
        SELECT 1
          FROM mailboxes mb
         WHERE mb.id = p_mailbox_id
           AND mb.domain_id IS NOT NULL
           AND mb.domain_id > 0
           AND EXISTS (
             SELECT 1 FROM admin_effective_authority(p_actor_id) a
              WHERE a.scope = mb.domain_id))
      OR (COALESCE(p_domain_scope, 0) = 0 AND EXISTS (
         SELECT 1 FROM admin_effective_authority(p_actor_id) a
          WHERE a.scope IS NULL
            AND a.is_unconfined))
  END;
$$;

-- Upgrade-proofing: drop the stale legacy 20-argument form (pre-round-3: no
-- p_actor_id/p_domain_scope tail). CREATE OR REPLACE cannot change the identity
-- of an existing signature, so an upgraded installation would otherwise keep
-- BOTH overloads and every 18-argument call would become ambiguous (42725).
-- On a fresh database this DROP is a no-op.
DROP FUNCTION IF EXISTS import_message(
  BIGINT, BIGINT, TEXT, TEXT, TEXT, TEXT, JSONB, JSONB, JSONB, TEXT, TEXT,
  TEXT, TEXT, BIGINT, BOOL, BOOL, TEXT, TIMESTAMPTZ, BIGINT, TEXT);

CREATE OR REPLACE FUNCTION import_message(
  p_mailbox_id     BIGINT,
  p_tag_id         BIGINT,        -- NULL = Inbox tag
  p_message_id     TEXT,
  p_subject        TEXT,
  p_from_addr      TEXT,
  p_from_name      TEXT,
  p_to_addrs       JSONB,
  p_cc_addrs       JSONB,
  p_bcc_addrs      JSONB,
  p_in_reply_to    TEXT,
  p_references_hdr TEXT,
  p_body_text      TEXT,
  p_body_html      TEXT,
  p_size_bytes     BIGINT,
  p_is_read        BOOL,
  p_is_flagged     BOOL,
  p_raw_ref        TEXT,
  p_date           TIMESTAMPTZ,   -- NULL = now()
  p_user_id        BIGINT DEFAULT NULL,  -- vestigial, never passed; signature stability only
  p_list_id        TEXT DEFAULT NULL,
  p_actor_id       BIGINT DEFAULT NULL,  -- NULL = system path (migration) → skip predicate
  p_domain_scope   BIGINT DEFAULT NULL   -- caller's admin domain scope (0/NULL = none)
) RETURNS BIGINT AS $$
DECLARE
  v_tag_id      BIGINT;
  v_tag_name    TEXT;
  v_thread_id   TEXT;
  v_imap_uid    BIGINT;
  v_message_id  BIGINT;
BEGIN
  -- 1. Resolve tag (default to Inbox). A supplied tag id MUST belong to the target
  -- mailbox: this runs on the BYPASSRLS worker pool, so an unowned tag id would
  -- otherwise write messages.folder_id pointing at another mailbox's tag (a
  -- cross-mailbox trust-boundary leak inside the privileged reducer).
  IF p_tag_id IS NOT NULL THEN
    v_tag_id := p_tag_id;
    SELECT name INTO v_tag_name FROM tags WHERE id = v_tag_id AND mailbox_id = p_mailbox_id;
    IF v_tag_name IS NULL THEN
      RAISE EXCEPTION 'Tag % does not belong to mailbox %', v_tag_id, p_mailbox_id
        USING ERRCODE = 'BZ002', HINT = jsonb_build_object('type', 'forbidden', 'mailbox_id', p_mailbox_id)::TEXT;
    END IF;
  ELSE
    v_tag_id := get_tag_id('Inbox', p_mailbox_id);
    v_tag_name := 'Inbox';
    IF v_tag_id IS NULL THEN
      RAISE EXCEPTION 'Mailbox has no Inbox tag'
        USING ERRCODE = 'BZ008', HINT = jsonb_build_object('type', 'missing_inbox', 'mailbox_id', p_mailbox_id)::TEXT;
    END IF;
  END IF;

  -- 2. Threading
  v_thread_id := compute_thread_id(p_message_id, p_in_reply_to, p_references_hdr, p_mailbox_id);

  -- 3. IMAP UID (tag-based)
  v_imap_uid := next_imap_uid_for_tag(v_tag_id);

  -- 3a. Quota enforcement
  IF NOT check_quota(p_mailbox_id, p_size_bytes) THEN
    RAISE EXCEPTION 'Mailbox over quota'
      USING ERRCODE = 'BZ001', HINT = jsonb_build_object('type', 'over_quota', 'mailbox_id', p_mailbox_id)::TEXT;
  END IF;

  -- 4. Insert message — statement-level authorization lives in this SELECT's
  -- WHERE (round 3/4): the actor claims ride INTO the reducer so authority is
  -- re-resolved LIVE at INSERT time, not at the route seam. p_actor_id IS NULL
  -- is the system path (migration orchestration — no human actor) and skips
  -- the predicate; actor 0 (unauthenticated fallback) matches no assignment
  -- and fails closed. A revocation during a slow upload inserts ZERO rows,
  -- RETURNING yields nothing, v_message_id stays NULL, and the caller reports
  -- the message failed — it is never inserted on stale authority.
  INSERT INTO messages (
    mailbox_id, folder_id,
    message_id, subject, from_addr, from_name,
    to_addrs, cc_addrs, bcc_addrs,
    in_reply_to, references_hdr,
    body_text, body_html,
    size_bytes, is_read, is_flagged,
    raw_ref, thread_id, imap_uid,
    received_at, sent_at,
    list_id
  )
  SELECT
    p_mailbox_id, v_tag_id,
    p_message_id, p_subject, p_from_addr, p_from_name,
    COALESCE(p_to_addrs, '[]'::JSONB),
    COALESCE(p_cc_addrs, '[]'::JSONB),
    COALESCE(p_bcc_addrs, '[]'::JSONB),
    p_in_reply_to, p_references_hdr,
    p_body_text, p_body_html,
    p_size_bytes, COALESCE(p_is_read, FALSE), COALESCE(p_is_flagged, FALSE),
    p_raw_ref, v_thread_id, v_imap_uid,
    COALESCE(p_date, now()), COALESCE(p_date, now()),
    normalize_list_id(p_list_id)
  WHERE (
    p_actor_id IS NULL
    OR admin_can_reach_mailbox(p_actor_id, p_domain_scope, p_mailbox_id)
  )
  RETURNING id INTO v_message_id;

  -- 5.+6. Tag + notify connected clients — ONLY when a row was actually
  -- inserted; the revocation no-op path must leave no side effects.
  IF v_message_id IS NOT NULL THEN
    -- Add tag (trigger handles counters)
    PERFORM tag_message(v_message_id, COALESCE(p_date, now())::TIMESTAMPTZ, v_tag_name, p_mailbox_id, 'import', TRUE);

    -- Notify connected clients
    PERFORM app_notify(
      'tag:' || p_mailbox_id,
      jsonb_build_object(
        'event', 'imported',
        'message_id', v_message_id,
        'tag_id', v_tag_id
      )::TEXT
    );
  END IF;

  RETURN v_message_id;
END;
$$ LANGUAGE plpgsql;
