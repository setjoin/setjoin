-- imap_modseq.sql — Wave 2.7 (#554): single-currency IMAP CONDSTORE / QRESYNC
-- read helpers backed by mailboxes.jmap_email_state + jmap_changes_journal.
--
-- Bijection (RFC 7162 §3.1.2):
--   * HIGHESTMODSEQ and every stamped imap_modseq use the exact 1:1 bijection
--     `imap_modseq = mailboxes.jmap_email_state + 1`.
--     - Empty mailbox (`jmap_email_state = 0`) → `HIGHESTMODSEQ 1`.
--     - First mutation (`jmap_email_state = 1`) → `MODSEQ 2` (`> 1`), so
--       `FETCH ... (CHANGEDSINCE 1)` never misses the first delivery.
--   * Pure SECURITY INVOKER with pinned search_path = pg_catalog, public: runs
--     under setjoin_app with fail-closed app.current_mailbox_id GUC verification
--     (only rolsuper / rolbypassrls roles bypass GUC matching) and explicit R1
--     mailbox_id predicates on every user-data table.

CREATE OR REPLACE FUNCTION imap_mailbox_highestmodseq(
  p_mailbox_id BIGINT
) RETURNS BIGINT
LANGUAGE sql STABLE
SET search_path = pg_catalog, public AS $$
  SELECT COALESCE(m.jmap_email_state, 0) + 1
    FROM public.mailboxes m
   WHERE m.id = p_mailbox_id
     AND (
       EXISTS (
         SELECT 1
           FROM pg_catalog.pg_roles r
          WHERE r.rolname = current_user
            AND (r.rolsuper OR r.rolbypassrls)
       )
       OR (
         CASE
           WHEN pg_catalog.current_setting('app.current_mailbox_id', TRUE) ~ '^[0-9]+$'
           THEN pg_catalog.current_setting('app.current_mailbox_id', TRUE)::BIGINT
         END
       ) = p_mailbox_id
     );
$$;

-- imap_vanished_uids_since: compute the sorted, deduplicated list of IMAP UIDs
-- that vanished from folder p_tag_id strictly after p_since_modseq, reading
-- directly from jmap_changes_journal (plus imap_membership_uid_ledger.retired_modseq
-- for folder moves and membership-UID mode — zero wall-clock timestamp races).
--
-- Returns JSONB:
--   { "highestModseq": <bigint>, "vanished": [<bigint>, ...], "resyncRequired": <bool> }
--
-- Mapping between IMAP MODSEQ and JMAP email state:
--   `v_highest = v_current + 1`
--   `v_since_state = GREATEST(v_since_modseq - 1, 0)`
--   so `j.state_seq > v_since_state` is equivalent to `(j.state_seq + 1) > v_since_modseq`.
CREATE OR REPLACE FUNCTION imap_vanished_uids_since(
  p_mailbox_id         BIGINT,
  p_tag_id             BIGINT,
  p_since_modseq       BIGINT,
  p_use_membership_uid BOOLEAN  DEFAULT FALSE,
  p_known_uids         BIGINT[] DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, public AS $$
DECLARE
  v_scoped_mb       BIGINT;
  v_current         BIGINT;
  v_highest         BIGINT;
  v_since_modseq    BIGINT := GREATEST(COALESCE(p_since_modseq, 0), 0);
  v_since_state     BIGINT := GREATEST(GREATEST(COALESCE(p_since_modseq, 0), 0) - 1, 0);
  v_oldest          BIGINT;
  v_tombstone_floor TIMESTAMPTZ;
  v_cursor_at       TIMESTAMPTZ;
  v_resync          BOOLEAN  := FALSE;
  v_vanished        BIGINT[] := '{}'::BIGINT[];
BEGIN
  -- Fail-closed GUC scope check: only superuser / BYPASSRLS roles may query
  -- across mailboxes; setjoin_app MUST match app.current_mailbox_id = p_mailbox_id.
  IF NOT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_roles r
     WHERE r.rolname = current_user
       AND (r.rolsuper OR r.rolbypassrls)
  ) THEN
    v_scoped_mb := CASE
      WHEN pg_catalog.current_setting('app.current_mailbox_id', TRUE) ~ '^[0-9]+$'
      THEN pg_catalog.current_setting('app.current_mailbox_id', TRUE)::BIGINT
      ELSE NULL
    END;
    IF v_scoped_mb IS DISTINCT FROM p_mailbox_id THEN
      RAISE EXCEPTION 'IMAP tag not found'
        USING ERRCODE = 'BZ268',
              HINT = jsonb_build_object('type', 'tag_not_found', 'tag_id', p_tag_id)::TEXT;
    END IF;
  END IF;

  -- R1: verify ownership of p_tag_id within p_mailbox_id.
  SELECT COALESCE(m.jmap_email_state, 0)
    INTO v_current
    FROM public.mailboxes m
    JOIN public.tags t ON t.mailbox_id = m.id
   WHERE m.id = p_mailbox_id
     AND t.id = p_tag_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'IMAP tag not found'
      USING ERRCODE = 'BZ268',
            HINT = jsonb_build_object('type', 'tag_not_found', 'tag_id', p_tag_id)::TEXT;
  END IF;

  v_highest := v_current + 1;

  -- Future modseq → caller's cached state is ahead of server truth.
  IF v_since_modseq > v_highest THEN
    v_resync := TRUE;
  ELSIF v_current = 0 THEN
    -- Fresh mailbox with zero mutations yet (v_since_modseq <= 1 == HIGHESTMODSEQ 1).
    RETURN jsonb_build_object(
      'highestModseq',  v_highest,
      'vanished',       '[]'::JSONB,
      'resyncRequired', FALSE
    );
  ELSE
    -- Pruned cursor check (handles v_since_state = 0 too: only non-pruned when v_oldest <= 1).
    SELECT MIN(state_seq)
      INTO v_oldest
      FROM public.jmap_changes_journal
     WHERE mailbox_id = p_mailbox_id
       AND datatype = 'email';  -- R1

    IF v_oldest IS NULL OR v_since_state < v_oldest - 1 THEN
      v_resync := TRUE;
    END IF;

    -- Resync sentinel anywhere in (v_since_state, v_current] → coarse fallback.
    IF NOT v_resync AND EXISTS (
      SELECT 1
        FROM public.jmap_changes_journal
       WHERE mailbox_id = p_mailbox_id
         AND datatype = 'email'
         AND state_seq > v_since_state
         AND op = 'resync'  -- R1
    ) THEN
      v_resync := TRUE;
    END IF;

    -- Wave 2.6 (#553) tombstone floor check: if scope revocations were pruned
    -- past the client's cursor timestamp (or cursor predates any state_seq),
    -- require a resync.
    v_tombstone_floor := public.sync_tombstone_floor_at();
    IF NOT v_resync AND v_tombstone_floor > '-infinity'::timestamptz THEN
      IF v_since_state = 0 THEN
        v_resync := TRUE;
      ELSE
        SELECT MAX(created_at)
          INTO v_cursor_at
          FROM public.jmap_changes_journal
         WHERE mailbox_id = p_mailbox_id
           AND datatype = 'email'
           AND state_seq <= v_since_state;  -- R1
        IF v_cursor_at IS NULL OR v_cursor_at < v_tombstone_floor THEN
          v_resync := TRUE;
        END IF;
      END IF;
    END IF;
  END IF;

  IF v_resync THEN
    -- Even when journal history is unavailable, a client-supplied known UID set
    -- lets us compute exact vanished UIDs without guessing. Unexpunged \Deleted
    -- messages still present in message_tags are NOT vanished.
    IF p_known_uids IS NOT NULL THEN
      SELECT COALESCE(array_agg(DISTINCT u ORDER BY u), '{}'::BIGINT[])
        INTO v_vanished
        FROM unnest(p_known_uids) AS u
       WHERE u > 0
         AND NOT EXISTS (
           SELECT 1
             FROM public.messages m
             JOIN public.message_tags mt
               ON mt.message_id = m.id
              AND mt.received_at = m.received_at
            WHERE m.mailbox_id = p_mailbox_id
              AND mt.tag_id = p_tag_id
              AND mt.is_primary = TRUE
              AND (CASE WHEN p_use_membership_uid THEN mt.imap_uid ELSE m.imap_uid END) = u
         );
    END IF;

    RETURN jsonb_build_object(
      'highestModseq',  v_highest,
      'vanished',       COALESCE(to_jsonb(v_vanished), '[]'::JSONB),
      'resyncRequired', TRUE
    );
  END IF;

  -- Up to date (no new journal rows > v_since_state).
  IF v_since_state >= v_current THEN
    RETURN jsonb_build_object(
      'highestModseq',  v_highest,
      'vanished',       '[]'::JSONB,
      'resyncRequired', FALSE
    );
  END IF;

  IF p_use_membership_uid THEN
    -- Per-folder membership UID mode: vanished UIDs strictly require journal
    -- state_seq > v_since_state AND l.retired_modseq > v_since_modseq so an
    -- earlier move-out/move-back membership UID is NEVER re-reported on a later
    -- expunge.
    SELECT COALESCE(array_agg(DISTINCT l.imap_uid ORDER BY l.imap_uid), '{}'::BIGINT[])
      INTO v_vanished
      FROM public.jmap_changes_journal j
      JOIN public.imap_membership_uid_ledger l
        ON l.tag_id = p_tag_id
       AND l.message_id = j.entity_id
     WHERE j.mailbox_id = p_mailbox_id
       AND j.datatype = 'email'
       AND j.state_seq > v_since_state
       AND j.op IN ('destroyed', 'updated')
       AND l.imap_uid > 0
       AND l.active = FALSE
       AND l.retired_modseq IS NOT NULL
       AND l.retired_modseq > v_since_modseq
       AND (p_known_uids IS NULL OR l.imap_uid = ANY(p_known_uids))
       AND NOT EXISTS (
         SELECT 1
           FROM public.messages m
           JOIN public.message_tags mt
             ON mt.message_id = m.id
            AND mt.received_at = m.received_at
          WHERE m.mailbox_id = p_mailbox_id
            AND mt.tag_id = p_tag_id
            AND mt.is_primary = TRUE
            AND mt.imap_uid = l.imap_uid
       );
  ELSE
    -- Legacy messages.imap_uid mode: recover UID from jmap_changes_journal.imap_uid
    -- (preserved even after hard DELETE) with fallback to messages.imap_uid.
    -- Strictly requires j.state_seq > v_since_state and (when correlated via ledger)
    -- l.retired_modseq > v_since_modseq so earlier moves are never re-reported.
    SELECT COALESCE(array_agg(DISTINCT cand.uid ORDER BY cand.uid), '{}'::BIGINT[])
      INTO v_vanished
      FROM (
        SELECT COALESCE(
                 j.imap_uid,
                 (SELECT m.imap_uid
                    FROM public.messages m
                   WHERE m.id = j.entity_id
                     AND m.mailbox_id = p_mailbox_id
                   LIMIT 1)
               ) AS uid,
               j.entity_id
          FROM public.jmap_changes_journal j
         WHERE j.mailbox_id = p_mailbox_id
           AND j.datatype = 'email'
           AND j.state_seq > v_since_state
           AND j.op IN ('destroyed', 'updated')
           AND (
             (
               j.op = 'destroyed'
               AND (
                 j.collection_id = p_tag_id
                 OR j.collection_id IS NULL
                 OR EXISTS (
                   SELECT 1
                     FROM public.imap_membership_uid_ledger l
                    WHERE l.tag_id = p_tag_id
                      AND l.message_id = j.entity_id
                      AND l.active = FALSE
                      AND l.retired_modseq IS NOT NULL
                      AND l.retired_modseq > v_since_modseq
                 )
               )
             )
             OR (
               j.op = 'updated'
               AND (
                 j.collection_id = p_tag_id
                 OR EXISTS (
                   SELECT 1
                     FROM public.imap_membership_uid_ledger l
                    WHERE l.tag_id = p_tag_id
                      AND l.message_id = j.entity_id
                      AND l.active = FALSE
                      AND l.retired_modseq IS NOT NULL
                      AND l.retired_modseq > v_since_modseq
                 )
               )
             )
           )
      ) cand
     WHERE cand.uid IS NOT NULL
       AND cand.uid > 0
       AND (p_known_uids IS NULL OR cand.uid = ANY(p_known_uids))
       AND NOT EXISTS (
         SELECT 1
           FROM public.messages m
           JOIN public.message_tags mt
             ON mt.message_id = m.id
            AND mt.received_at = m.received_at
          WHERE m.mailbox_id = p_mailbox_id
            AND mt.tag_id = p_tag_id
            AND mt.is_primary = TRUE
            AND m.imap_uid = cand.uid
       );
  END IF;

  RETURN jsonb_build_object(
    'highestModseq',  v_highest,
    'vanished',       COALESCE(to_jsonb(v_vanished), '[]'::JSONB),
    'resyncRequired', FALSE
  );
END;
$$;
