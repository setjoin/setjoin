-- ════════════════════════════════════════════════════════════════════════
-- V296__imap_modseq_journal_alignment.sql — Wave 2.7 (#554):
-- Align IMAP CONDSTORE/QRESYNC MODSEQ onto the single mailboxes.jmap_email_state +
-- jmap_changes_journal currency (bijection imap_modseq = jmap_email_state + 1)
-- and retire remaining hot-path mail 'resync' sentinels across SQL reducers.
--
-- Expand-only schema additions:
--   * public.jmap_changes_journal gains nullable imap_uid BIGINT so QRESYNC
--     VANISHED recovers exact vanished UIDs even after hard DELETE/EXPUNGE.
--   * public.imap_membership_uid_ledger gains nullable retired_modseq BIGINT so
--     folder-move QRESYNC VANISHED filters deterministically by MODSEQ with zero
--     wall-clock timestamp races.
--   * Existing FORCE RLS on jmap_changes_journal (V062) and
--     imap_membership_uid_ledger (V197) remains untouched.
--   * Upgrade currency backfill temporarily toggles NO FORCE on messages and
--     message_tags (canonical V140 pattern: table owner setjoin_owner bypasses
--     RLS while non-owner roles stay enforced), advances
--     mailboxes.jmap_email_state >= MAX(imap_modseq) (so jmap_email_state + 1
--     strictly exceeds every pre-upgrade row), and immediately restores
--     FORCE ROW LEVEL SECURITY.
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.jmap_changes_journal
  ADD COLUMN IF NOT EXISTS imap_uid BIGINT;

COMMENT ON COLUMN public.jmap_changes_journal.imap_uid IS
  'Email IMAP UID captured at journal append time so QRESYNC VANISHED recovers vanished UIDs after hard DELETE (#554).';

CREATE INDEX IF NOT EXISTS idx_changes_journal_imap_vanished
  ON public.jmap_changes_journal (mailbox_id, state_seq)
  WHERE datatype = 'email' AND op IN ('destroyed', 'updated') AND imap_uid IS NOT NULL;

ALTER TABLE public.imap_membership_uid_ledger
  ADD COLUMN IF NOT EXISTS retired_modseq BIGINT;

COMMENT ON COLUMN public.imap_membership_uid_ledger.retired_modseq IS
  'Bijective IMAP MODSEQ (jmap_email_state + 1) at which this folder membership was retired for deterministic QRESYNC VANISHED (#554).';

CREATE INDEX IF NOT EXISTS idx_imap_membership_uid_ledger_retired_modseq
  ON public.imap_membership_uid_ledger (tag_id, retired_modseq)
  WHERE NOT active AND retired_modseq IS NOT NULL;

-- Upgrade currency backfill (#554): mailctl schema apply connects as setjoin_owner
-- (table owner, NOBYPASSRLS). Temporarily drop FORCE on FORCE-RLS tables
-- (public.messages, public.message_tags, public.tags [V287], and public.mailboxes
-- [V288]) inside this transaction using NO FORCE ROW LEVEL SECURITY (the canonical
-- V140 pattern: table owner bypasses RLS while non-owner roles stay RLS-enforced),
-- backfill mailboxes.jmap_email_state >= MAX(imap_modseq), then immediately restore
-- FORCE ROW LEVEL SECURITY.
-- Advancing jmap_email_state >= MAX(imap_modseq) guarantees the post-V296
-- bijection (jmap_email_state + 1) strictly exceeds every pre-upgrade MODSEQ.
ALTER TABLE public.messages NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.message_tags NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tags NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.mailboxes NO FORCE ROW LEVEL SECURITY;

UPDATE public.mailboxes m
   SET jmap_email_state = GREATEST(m.jmap_email_state, sub.max_modseq)
  FROM (
    SELECT mailbox_id, MAX(max_m) AS max_modseq
      FROM (
        SELECT mailbox_id, MAX(imap_modseq) AS max_m
          FROM public.messages
         WHERE imap_modseq IS NOT NULL
         GROUP BY mailbox_id
        UNION ALL
        SELECT mailbox_id, MAX(imap_modseq) AS max_m
          FROM public.tags
         WHERE imap_modseq IS NOT NULL
         GROUP BY mailbox_id
        UNION ALL
        SELECT m2.mailbox_id, MAX(mt.imap_modseq) AS max_m
          FROM public.message_tags mt
          JOIN public.messages m2
            ON m2.id = mt.message_id AND m2.received_at = mt.received_at
         WHERE mt.imap_modseq IS NOT NULL
         GROUP BY m2.mailbox_id
      ) u
     GROUP BY mailbox_id
  ) sub
 WHERE m.id = sub.mailbox_id
   AND m.jmap_email_state < sub.max_modseq;

ALTER TABLE public.messages FORCE ROW LEVEL SECURITY;
ALTER TABLE public.message_tags FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tags FORCE ROW LEVEL SECURITY;
ALTER TABLE public.mailboxes FORCE ROW LEVEL SECURITY;

-- ── Verbatim embedded reducers (upgrade-only parity with mailserver/sql/reducers/) ──

-- Source: mailserver/sql/reducers/append_change.sql (append_change)
DROP FUNCTION IF EXISTS append_change(bigint, text, bigint, bigint, text);
DROP FUNCTION IF EXISTS append_change(bigint, text, bigint, bigint, text, bigint, text);
CREATE OR REPLACE FUNCTION append_change(
  p_mailbox_id    BIGINT,
  p_datatype      TEXT,
  p_state_seq     BIGINT,
  p_entity_id     BIGINT,
  p_op            TEXT,
  p_collection_id BIGINT DEFAULT NULL,
  p_resource_uid  TEXT   DEFAULT NULL,
  p_imap_uid      BIGINT DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
  v_entity BIGINT;
  v_op     TEXT;
BEGIN
  IF p_entity_id IS NULL OR p_op = 'resync' THEN
    v_entity := 0;
    v_op     := 'resync';
  ELSE
    v_entity := p_entity_id;
    v_op     := p_op;
  END IF;

  -- R2: mailbox_id is the reducer's auth-derived p_mailbox_id, never req.*.
  -- ponytail: upsert op on same (mailbox_id, datatype, state_seq, entity_id) — a
  -- same-seq same-id dup (rare, same batch) keeps latest op; collapse is at READ time.
  INSERT INTO jmap_changes_journal (
    mailbox_id, datatype, state_seq, entity_id, op, collection_id, resource_uid, imap_uid
  )
  VALUES (
    p_mailbox_id, p_datatype, p_state_seq, v_entity, v_op, p_collection_id, p_resource_uid, p_imap_uid
  )
  ON CONFLICT (mailbox_id, datatype, state_seq, entity_id)
    DO UPDATE SET op            = EXCLUDED.op,
                  collection_id = COALESCE(EXCLUDED.collection_id, jmap_changes_journal.collection_id),
                  resource_uid  = COALESCE(EXCLUDED.resource_uid,  jmap_changes_journal.resource_uid),
                  imap_uid      = COALESCE(EXCLUDED.imap_uid,      jmap_changes_journal.imap_uid);
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/append_change.sql (append_email_change)
DROP FUNCTION IF EXISTS append_email_change(bigint, bigint, bigint, text);
CREATE OR REPLACE FUNCTION append_email_change(
  p_mailbox_id  BIGINT,
  p_state_seq   BIGINT,
  p_message_id  BIGINT,
  p_op          TEXT,
  p_tag_id      BIGINT DEFAULT NULL,
  p_imap_uid    BIGINT DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
  v_uid             BIGINT := p_imap_uid;
  v_tag_id          BIGINT := p_tag_id;
  v_msg_uid         BIGINT;
  v_msg_tag_id      BIGINT;
  v_msg_received_at TIMESTAMPTZ;
  v_modseq          BIGINT := GREATEST(COALESCE(p_state_seq, 0), 0) + 1;
BEGIN
  IF p_message_id IS NOT NULL AND p_op IS DISTINCT FROM 'resync' THEN
    IF p_op IN ('created', 'updated', 'destroyed') THEN
      UPDATE messages
         SET imap_modseq = v_modseq
       WHERE id = p_message_id
         AND mailbox_id = p_mailbox_id
      RETURNING imap_uid, folder_id, received_at
        INTO v_msg_uid, v_msg_tag_id, v_msg_received_at;

      IF v_msg_received_at IS NOT NULL THEN
        UPDATE message_tags
           SET imap_modseq = v_modseq
         WHERE message_id = p_message_id
           AND received_at = v_msg_received_at;
      END IF;
    END IF;
    v_uid    := COALESCE(v_uid, v_msg_uid);
    v_tag_id := COALESCE(v_tag_id, v_msg_tag_id);

    UPDATE tags
       SET imap_modseq = GREATEST(COALESCE(imap_modseq, 0), v_modseq)
     WHERE mailbox_id = p_mailbox_id
       AND (
         id = v_tag_id
         OR (
           v_msg_received_at IS NOT NULL
           AND id IN (
             SELECT tag_id
               FROM message_tags
              WHERE message_id = p_message_id
                AND received_at = v_msg_received_at
           )
         )
       );
  END IF;

  PERFORM append_change(
    p_mailbox_id, 'email', p_state_seq, p_message_id, p_op,
    v_tag_id, NULL, v_uid
  );
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/notify_state_change.sql (notify_state_change)
CREATE OR REPLACE FUNCTION notify_state_change(
  p_mailbox_id BIGINT,
  p_tag_id     BIGINT,
  p_message_id BIGINT DEFAULT NULL,
  p_op         TEXT   DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
  v_email_state BIGINT;
BEGIN
  IF p_mailbox_id IS NULL THEN
    RAISE EXCEPTION 'notify_state_change requires a mailbox'
      USING ERRCODE = 'BZ034',
            HINT = jsonb_build_object('type', 'missing_mailbox')::TEXT;
  END IF;

  v_email_state := bump_email_state(p_mailbox_id);

  -- Offline #3: id-bearing callers thread (message_id, op) → precise journal row
  -- in the SAME txn as the bump. NULL callers (transition_message_location et al.)
  -- fall to the ELSE and emit a resync sentinel so every state bump has a record.
  -- Task 4 upgrades these sites to precise rows.
  -- ponytail: resync on null-caller path forces BZ011 cannotCalculateChanges for
  -- any spanning delta until Task 4 threads message_id; conservative but correct.
  -- Guard on v_email_state IS NOT NULL: a foreign / non-existent mailbox_id yields
  -- NULL from bump_email_state → skip the append (no-op, not a crash).
  IF v_email_state IS NOT NULL THEN
    IF p_message_id IS NOT NULL AND p_op IS NOT NULL THEN
      PERFORM append_email_change(p_mailbox_id, v_email_state, p_message_id, p_op, p_tag_id);
    ELSE
      PERFORM append_email_change(p_mailbox_id, v_email_state, NULL, 'resync');
    END IF;
  END IF;

  IF p_tag_id IS NOT NULL THEN
    PERFORM bump_tag_mailbox_state(p_mailbox_id);
    IF v_email_state IS NOT NULL THEN
      UPDATE tags
         SET imap_modseq = GREATEST(COALESCE(imap_modseq, 0), GREATEST(v_email_state, 0) + 1)
       WHERE id = p_tag_id
         AND mailbox_id = p_mailbox_id;
    END IF;
  END IF;

  PERFORM app_notify(
    'tag:' || p_mailbox_id,
    json_build_object(
      'event',  'state_change',
      'tag_id', p_tag_id,
      'state',  v_email_state
    )::TEXT
  );
  PERFORM public.emit_wakeup_bell('sync', 'mailbox:' || p_mailbox_id || ':0:Email');

  RETURN v_email_state;
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/imap_modseq.sql (imap_mailbox_highestmodseq)
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

-- Source: mailserver/sql/reducers/imap_modseq.sql (imap_vanished_uids_since)
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

-- Source: mailserver/sql/reducers/trg_imap_membership_uid_allocate.sql (trg_imap_membership_uid_allocate)
CREATE OR REPLACE FUNCTION trg_imap_membership_uid_allocate()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
  v_modseq bigint;
BEGIN
  SELECT COALESCE(mb.jmap_email_state, 0) + 1
    INTO v_modseq
    FROM public.tags t
    JOIN public.mailboxes mb ON mb.id = t.mailbox_id
   WHERE t.id = NEW.tag_id;
  v_modseq := GREATEST(COALESCE(v_modseq, 1), 1);

  IF NEW.imap_uid IS NULL OR NEW.imap_uid <= 0 THEN
    NEW.imap_uid := public.imap_membership_uid_allocate(NEW.tag_id);
  ELSE
    PERFORM 1 FROM public.tags WHERE id=NEW.tag_id FOR UPDATE;
    UPDATE public.tags
       SET imap_uid_next=GREATEST(imap_uid_next,NEW.imap_uid+1),
           imap_modseq=v_modseq,
           updated_at=now()
     WHERE id=NEW.tag_id;
  END IF;
  NEW.imap_modseq := v_modseq;
  INSERT INTO public.imap_membership_uid_ledger
    (tag_id,imap_uid,message_id,received_at,active)
  VALUES (NEW.tag_id,NEW.imap_uid,NEW.message_id,NEW.received_at,true);
  RETURN NEW;
END;
$$;

-- Source: mailserver/sql/reducers/trg_imap_membership_uid_retire.sql (trg_imap_membership_uid_retire)
CREATE OR REPLACE FUNCTION trg_imap_membership_uid_retire()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
  v_modseq bigint;
BEGIN
  -- Post-bump draft deletion paths (jmap_email_submission, mail_draft_replace)
  -- set app.imap_retire_modseq = (committed_state + 1) so retired_modseq matches
  -- the exact committed MODSEQ cursor without an off-by-one (#554).
  v_modseq := NULLIF(current_setting('app.imap_retire_modseq', TRUE), '')::bigint;
  IF v_modseq IS NULL THEN
    SELECT COALESCE(mb.jmap_email_state, 0) + 2
      INTO v_modseq
      FROM public.tags t
      JOIN public.mailboxes mb ON mb.id = t.mailbox_id
     WHERE t.id = OLD.tag_id;
  END IF;

  UPDATE public.imap_membership_uid_ledger
     SET active = false,
         retired_at = now(),
         retired_modseq = COALESCE(v_modseq, 1)
   WHERE tag_id = OLD.tag_id
     AND imap_uid = OLD.imap_uid
     AND message_id = OLD.message_id
     AND received_at = OLD.received_at
     AND active;
  RETURN OLD;
END;
$$;

-- Source: mailserver/sql/reducers/imap_membership_uid_allocate.sql (imap_membership_uid_allocate)
CREATE OR REPLACE FUNCTION imap_membership_uid_allocate(p_tag_id bigint)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
  v_uid        bigint;
  v_mailbox_id bigint;
  v_modseq     bigint;
BEGIN
  SELECT t.mailbox_id,
         GREATEST(t.imap_uid_next,
           COALESCE((SELECT max(l.imap_uid)+1 FROM public.imap_membership_uid_ledger l
                     WHERE l.tag_id=t.id),1))
    INTO v_mailbox_id, v_uid
    FROM public.tags t WHERE t.id=p_tag_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'IMAP tag not found' USING ERRCODE='BZ268';
  END IF;
  SELECT COALESCE(mb.jmap_email_state, 0) + 1
    INTO v_modseq
    FROM public.mailboxes mb WHERE mb.id=v_mailbox_id;
  UPDATE public.tags
     SET imap_uid_next=v_uid+1,
         imap_modseq=GREATEST(COALESCE(imap_modseq, 0), COALESCE(v_modseq, 1)),
         updated_at=now()
   WHERE id=p_tag_id;
  RETURN v_uid;
END;
$$;

-- Source: mailserver/sql/reducers/deliver_group_vacation.sql (deliver)
CREATE OR REPLACE FUNCTION deliver(
  p_raw_ref         TEXT,
  p_message_id      TEXT,
  p_from_addr       TEXT,
  p_from_name       TEXT,
  p_rcpt_addr       TEXT,
  p_to_addrs        JSONB,
  p_cc_addrs        JSONB,
  p_bcc_addrs       JSONB,
  p_subject         TEXT,
  p_in_reply_to     TEXT,
  p_references_hdr  TEXT,
  p_body_text       TEXT,
  p_body_html       TEXT,
  p_size_bytes      BIGINT,
  p_has_attachments BOOL,
  p_sent_at         TIMESTAMPTZ,
  p_spf_result      TEXT,
  p_dkim_result     TEXT,
  p_dmarc_result    TEXT,
  p_spam_score      REAL,
  p_spam_headers    JSONB,
  p_vote_response   TEXT DEFAULT NULL,
  p_crypto_type     TEXT DEFAULT NULL,
  p_is_external       BOOL DEFAULT FALSE,
  p_sender_display_name TEXT DEFAULT NULL,
  p_is_name_spoof     BOOL DEFAULT FALSE,
  p_depth           INT DEFAULT 0,
  p_list_id         TEXT DEFAULT NULL,
  p_smime_status        TEXT DEFAULT NULL,
  p_smime_signer_email  TEXT DEFAULT NULL,
  p_smime_signer_cn     TEXT DEFAULT NULL,
  p_smime_issuer_cn     TEXT DEFAULT NULL,
  p_is_encrypted        BOOLEAN DEFAULT FALSE, -- SP1: TRUE = encrypted-at-rest (raw_ref is ciphertext); null the body cols
  -- Attachment-metadata source: the sender's own message (draft id + its
  -- received_at) to copy message_attachments rows FROM, onto THIS delivered
  -- copy's own (message_id, received_at) key. NULL for callers with no such
  -- source (genuine external-inbound SMTP — no prior message_attachments rows
  -- exist to copy from; vacation auto-reply / NDR / DSN system messages).
  p_source_message_id   BIGINT DEFAULT NULL,
  p_source_received_at  TIMESTAMPTZ DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
  v_mailbox         RECORD;
  v_folder_id       BIGINT;
  v_inbox_tag_id    BIGINT;
  v_spam_tag_id     BIGINT;
  v_message_id      BIGINT;
  v_received_at     TIMESTAMPTZ;
  v_thread_id       TEXT;
  v_imap_uid        BIGINT;
  v_spam_threshold  REAL := 5.0;
  v_member          RECORD;
  v_vacation        RECORD;
  v_domain          TEXT;
  v_is_local        BOOL;
  v_sender_is_internal BOOL;
  v_send_reply      BOOL;
  v_reply_text      TEXT;
  v_reply_html      TEXT;
  v_is_muted        BOOL := FALSE;
  v_muted_tag_id    BIGINT;
  v_is_first_time   BOOL := TRUE;
  v_group_id        BIGINT;
BEGIN
  -- 1. Resolve the target mailbox (alias → mailbox, or direct mailbox email)
  SELECT mb.* INTO v_mailbox
  FROM mailboxes mb
  JOIN aliases a ON a.mailbox_id = mb.id
  WHERE lower(a.email) = lower(p_rcpt_addr)
    AND mailbox_lifecycle_delivery_mode(mb.id) <> 'rejecting';

  IF v_mailbox.id IS NULL THEN
    -- lower(email) match, index-backed by mailboxes_email_lower_idx: a mailbox
    -- stored with any uppercase (the unique index is on lower(email), so mixed
    -- case is allowed) must still be deliverable — case-sensitive '=' left such
    -- addresses silently undeliverable.
    SELECT * INTO v_mailbox FROM mailboxes
    WHERE lower(email) = lower(p_rcpt_addr)
      AND mailbox_lifecycle_delivery_mode(id) <> 'rejecting';
  END IF;

  IF v_mailbox.id IS NULL THEN
    v_domain := split_part(p_rcpt_addr, '@', 2);
    SELECT mb.* INTO v_mailbox
    FROM mailboxes mb
    JOIN domains d ON d.catch_all_mailbox_id = mb.id
    WHERE lower(d.name) = lower(v_domain)
      AND mailbox_lifecycle_delivery_mode(mb.id) <> 'rejecting';
  END IF;

  IF v_mailbox.id IS NULL THEN
    RAISE EXCEPTION 'no mailbox for %', p_rcpt_addr
      USING ERRCODE = 'BZ007', HINT = jsonb_build_object('type', 'no_mailbox', 'rcpt', p_rcpt_addr)::TEXT;
  END IF;

  -- Cycle guard: abort if recursion depth exceeds 10 (max nested groups).
  IF p_depth > 10 THEN
    RAISE EXCEPTION 'delivery_loop: distribution group nesting exceeded max depth';
  END IF;

  -- 1a. Distribution group expansion (detected via satellite table, not type enum)
  SELECT id INTO v_group_id FROM distribution_groups WHERE mailbox_id = v_mailbox.id;

  IF v_group_id IS NOT NULL THEN
    FOR v_member IN
      SELECT m.mailbox_id AS id FROM expand_group(v_group_id) m
    LOOP
      -- Per-member subtransaction: one member's over-quota (BZ001) / no-mailbox (BZ007)
      -- must NOT roll back delivery to the whole list (a 300-10,000-user static list
      -- almost always has one over-quota or disabled member). Skip + WARN the failing
      -- member; the rest still receive. expand_group already filters disabled/receive-
      -- disabled members, so the common residual failure here is over-quota.
      BEGIN
        -- Deliver individually to each member's primary email
        PERFORM deliver(
          p_raw_ref, p_message_id, p_from_addr, p_from_name,
          (SELECT email FROM mailboxes WHERE id = v_member.id),
          p_to_addrs, p_cc_addrs, p_bcc_addrs, p_subject,
          p_in_reply_to, p_references_hdr, p_body_text, p_body_html,
          p_size_bytes, p_has_attachments, p_sent_at,
          p_spf_result, p_dkim_result, p_dmarc_result,
          p_spam_score, p_spam_headers,
          p_vote_response, p_crypto_type,
          p_is_external, p_sender_display_name, p_is_name_spoof,
          p_depth + 1, p_list_id,
          p_smime_status, p_smime_signer_email, p_smime_signer_cn, p_smime_issuer_cn,
          -- SP1: thread encrypted-at-rest flag through to each member copy. Omitting it
          -- defaulted FALSE → members kept CLEARTEXT body cols even when the send was
          -- encrypted (raw_ref ciphertext but plaintext-at-rest body cache leak).
          p_is_encrypted => p_is_encrypted,
          -- Thread the attachment-metadata source through group fan-out too, so a
          -- distribution-group send with attachments doesn't regress the same way.
          p_source_message_id => p_source_message_id,
          p_source_received_at => p_source_received_at
        );
      EXCEPTION WHEN OTHERS THEN
        RAISE WARNING 'distribution group % fan-out: delivery to member % skipped: %',
          v_group_id, v_member.id, SQLERRM;
      END;
    END LOOP;
    RETURN NULL; -- group itself doesn't get a message row
  END IF;

  -- 2. Quota check (advisory early-exit; atomic enforcement at step 7b)
  IF NOT check_quota(v_mailbox.id, p_size_bytes) THEN
    RAISE EXCEPTION 'mailbox % is over quota', v_mailbox.id
      USING ERRCODE = 'BZ001', HINT = jsonb_build_object('type', 'over_quota', 'mailbox_id', v_mailbox.id)::TEXT;
  END IF;

  -- 3. Spam threshold
  SELECT (value #>> '{}')::REAL INTO v_spam_threshold
  FROM system_config WHERE key = 'spam_threshold';
  v_spam_threshold := coalesce(v_spam_threshold, 5.0);

  -- 4. Target tag (Inbox or Spam) — tag system with exclusivity
  v_inbox_tag_id := get_tag_id('Inbox', v_mailbox.id);
  v_spam_tag_id  := get_tag_id('Spam', v_mailbox.id);

  IF v_inbox_tag_id IS NULL THEN
    RAISE EXCEPTION 'mailbox % has no Inbox tag', v_mailbox.id
      USING ERRCODE = 'BZ008', HINT = jsonb_build_object('type', 'missing_inbox', 'mailbox_id', v_mailbox.id)::TEXT;
  END IF;

  IF v_mailbox.spam_folder_enabled
    AND p_spam_score IS NOT NULL
    AND p_spam_score >= v_spam_threshold THEN
    v_folder_id := COALESCE(v_spam_tag_id, v_inbox_tag_id);
  ELSE
    v_folder_id := v_inbox_tag_id;
  END IF;

  -- 5. Thread ID
  v_thread_id := compute_thread_id(p_message_id, p_in_reply_to, p_references_hdr, v_mailbox.id);

  -- 5b. First-time sender check (skip if feature toggle disabled)
  -- is_first_time defaults to TRUE; set to FALSE if a prior message from
  -- the same from_addr exists in this mailbox.
  IF current_setting('app.skip_external_sender_first_time', true) IS DISTINCT FROM 'true' THEN
    -- messages.from_addr is stored case-preserved (the gateway does not lowercase it),
    -- so compare case-insensitively. Comparing stored case vs lower(p_from_addr) made
    -- every message from a mixed-case sender (e.g. John.Doe@Example.com) look first-time,
    -- firing the external-sender banner every time and defeating its purpose.
    v_is_first_time := NOT EXISTS(
      SELECT 1 FROM messages
      WHERE mailbox_id = v_mailbox.id
        AND lower(from_addr) = lower(p_from_addr)
      LIMIT 1
    );
  END IF;

  -- 5a. Mute / Ignore Conversation (Gmail "Mute"): a muted thread carries the
  -- Muted tag on ≥1 of its messages. A reply to such a thread skips the Inbox
  -- (auto-archived — step 7 tags it Muted only, no Inbox location), so the
  -- conversation stays quiet but remains in All Mail / search. Muting is a pure
  -- tag operation via Email/set — there is no mute_thread rule (that gate was
  -- dead code keyed on a rule template nothing creates; removed 2026-07-01).
  v_muted_tag_id := get_tag_id('Muted', v_mailbox.id);
  IF v_muted_tag_id IS NOT NULL THEN
    v_is_muted := EXISTS(
      SELECT 1 FROM message_tags mt
      JOIN tags t ON t.id = mt.tag_id
      JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
      WHERE m.thread_id = v_thread_id
        AND m.mailbox_id = v_mailbox.id
        AND t.name = 'Muted'
    );

    -- Breakout: an explicit To/Cc recipient overrides the mute (the reply is
    -- directed at this user, so it should reach the Inbox).
    IF v_is_muted AND (
         p_to_addrs @> jsonb_build_array(jsonb_build_object('email', lower(p_rcpt_addr)))
      OR p_cc_addrs @> jsonb_build_array(jsonb_build_object('email', lower(p_rcpt_addr)))
    ) THEN
      v_is_muted := FALSE;
    END IF;
  END IF;

  -- 6. IMAP UID
  v_imap_uid := next_imap_uid_for_tag(v_folder_id);

  -- 7. Insert message (folder_id kept for backward compat, synced by primary tag trigger)
  INSERT INTO messages (
    mailbox_id, folder_id,
    message_id, subject, from_addr, from_name,
    to_addrs, cc_addrs, bcc_addrs,
    in_reply_to, references_hdr,
    body_text, body_html,
    size_bytes, has_attachments,
    thread_id, raw_ref, sent_at,
    spf_result, dkim_result, dmarc_result,
    spam_score, spam_headers,
    vote_response, crypto_type,
    is_external, sender_display_name, is_name_spoof, is_first_time,
    imap_uid, imap_modseq,
    held, received_at,
    list_id,
    smime_status, smime_signer_email, smime_signer_cn, smime_issuer_cn
  ) VALUES (
    v_mailbox.id, v_folder_id,
    p_message_id, p_subject, p_from_addr, p_from_name,
    p_to_addrs, p_cc_addrs, p_bcc_addrs,
    p_in_reply_to, p_references_hdr,
    -- SP1 encrypted-at-rest: store NO cleartext for the encrypted recipient copy.
    -- raw_ref carries the ciphertext; the FTS trigger blanks body_tsv from a NULL
    -- body_text. subject stays (S/MIME headers are unencrypted).
    CASE WHEN p_is_encrypted THEN NULL ELSE p_body_text END,
    CASE WHEN p_is_encrypted THEN NULL ELSE p_body_html END,
    p_size_bytes, p_has_attachments,
    v_thread_id, p_raw_ref, p_sent_at,
    p_spf_result, p_dkim_result, p_dmarc_result,
    p_spam_score, p_spam_headers,
    -- SP1: tie the at-rest crypto discriminator to the SAME flag that nulls the
    -- body cols (p_is_encrypted) so they can never diverge. Without this the
    -- encrypted recipient copy stored body=NULL but crypto_type=NULL, and the
    -- decrypt-on-read gate (mail_decrypt.go: cryptoType=='smime-encrypted') +
    -- the V029 FTS guard both silently skipped it → blank, unreadable mail.
    -- When NOT encrypted, preserve the inbound-detected p_crypto_type.
    p_vote_response, CASE WHEN p_is_encrypted THEN 'smime-encrypted' ELSE p_crypto_type END,
    p_is_external, p_sender_display_name, p_is_name_spoof, v_is_first_time,
    v_imap_uid, COALESCE(v_mailbox.jmap_email_state, 0) + 2,
    v_mailbox.litigation_hold, now(),
    normalize_list_id(p_list_id),
    p_smime_status, p_smime_signer_email, p_smime_signer_cn, p_smime_issuer_cn
  ) RETURNING id, received_at INTO v_message_id, v_received_at;

  -- 7a. Add tag (trigger enforces location exclusivity and updates counters)
  IF v_is_muted THEN
    -- No location tag → All Mail only; add Muted label for tracking
    PERFORM tag_message(v_message_id, now()::TIMESTAMPTZ, 'Muted', v_mailbox.id, 'deliver', FALSE);
  ELSE
    PERFORM tag_message(v_message_id, now()::TIMESTAMPTZ,
      CASE WHEN v_folder_id = v_spam_tag_id THEN 'Spam' ELSE 'Inbox' END,
      v_mailbox.id, 'deliver', TRUE);

    -- Focused/Other split: only for a message that actually landed in Inbox
    -- (not Spam). classify_focus (deterministic, first-match-wins) decides; a
    -- TRUE verdict adds the 'Other' tag (absence = Focused). The Other tag's
    -- counters come free from the message_tags counter trigger.
    IF v_folder_id = v_inbox_tag_id
       AND classify_focus(v_mailbox.id, p_from_addr, p_is_external, v_is_first_time, p_list_id) THEN
      PERFORM tag_message(v_message_id, now()::TIMESTAMPTZ, 'Other', v_mailbox.id, 'deliver', FALSE);
    END IF;
  END IF;

  -- 7a2. Copy attachment metadata (message_attachments rows) from the source
  -- message (the sender's own draft) onto THIS delivered copy's own (message_id,
  -- received_at) key. jmap_email_get / message_to_jmap_email project attachments
  -- and inlineImages by joining message_attachments on (message_id, received_at)
  -- per copy — without this, a locally-delivered copy (send() → deliver() for a
  -- local recipient) carried has_attachments=TRUE but zero message_attachments
  -- rows: Email/get showed attachments:[] / inlineImages:null and cid: images
  -- rendered as raw text. Mirrors the copy jmap_email_submission_set already does
  -- onto the SENT copy. p_source_message_id is NULL for callers with nothing to
  -- copy from (see the parameter's doc comment above).
  IF p_source_message_id IS NOT NULL AND p_has_attachments THEN
    INSERT INTO message_attachments
      (message_id, received_at, blob_sha256, content_type, filename, content_id, disposition, size_bytes)
    SELECT v_message_id, v_received_at, ma.blob_sha256, ma.content_type, ma.filename,
           ma.content_id, ma.disposition, ma.size_bytes
    FROM message_attachments ma
    WHERE ma.message_id = p_source_message_id AND ma.received_at = p_source_received_at;
  END IF;

  -- 7b. Atomic quota enforcement (serialized via row lock, prevents TOCTOU race)
  UPDATE mailboxes
  SET used_bytes = used_bytes + p_size_bytes
  WHERE id = v_mailbox.id
    AND used_bytes + p_size_bytes <= quota_bytes;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'mailbox % is over quota (needed % bytes, available %)',
      v_mailbox.id, p_size_bytes,
      (SELECT quota_bytes - used_bytes FROM mailboxes WHERE id = v_mailbox.id)
      USING ERRCODE = 'BZ001', HINT = jsonb_build_object('type', 'over_quota', 'mailbox_id', v_mailbox.id)::TEXT;
  END IF;

  -- 7c. Domain-level quota enforcement
  DECLARE
    v_domain_quota BIGINT;
    v_domain_used  BIGINT;
  BEGIN
    SELECT d.quota_bytes, COALESCE(SUM(mb.used_bytes), 0) + p_size_bytes
    INTO v_domain_quota, v_domain_used
    FROM domains d
    LEFT JOIN mailboxes mb ON mb.domain_id = d.id
    WHERE d.id = v_mailbox.domain_id
    GROUP BY d.id, d.quota_bytes;

    IF v_domain_quota IS NOT NULL AND v_domain_used > v_domain_quota THEN
      RAISE EXCEPTION 'domain % is over quota (needed % bytes, available %)',
        v_mailbox.domain_id, p_size_bytes,
        v_domain_quota - v_domain_used + p_size_bytes
        USING ERRCODE = 'BZ009', HINT = jsonb_build_object('type', 'domain_over_quota', 'domain_id', v_mailbox.domain_id)::TEXT;
    END IF;
  END;

  -- 8. Rules (skip if feature.rules_engine disabled)
  IF current_setting('app.skip_rules', true) IS DISTINCT FROM 'true' THEN
    PERFORM apply_rules(v_message_id, now()::TIMESTAMPTZ, v_mailbox.id, 'server');
  END IF;

  -- 10. Retention + journal (best-effort: journal failure must not abort delivery;
  --     skip tag_retention if a delivery rule 'discard'ed the message at step 8).
  IF current_setting('app.skip_retention', true) IS DISTINCT FROM 'true'
     AND EXISTS (
       SELECT 1 FROM messages
        WHERE id = v_message_id AND received_at = v_received_at AND mailbox_id = v_mailbox.id
     ) THEN
    PERFORM tag_retention(v_message_id, v_received_at, v_mailbox.id);
  END IF;
  IF current_setting('app.skip_journaling', true) IS DISTINCT FROM 'true' THEN
    BEGIN
      PERFORM journal_if_policy_matches(
        p_message_id, p_from_addr, p_rcpt_addr, p_raw_ref,
        v_mailbox.domain_id, 'inbound'
      );
    EXCEPTION WHEN OTHERS THEN
      -- Journal enqueue failure is logged but does not block delivery.
      NULL;
    END;
  END IF;

  -- 11. Vacation auto-reply (skip if feature.vacation disabled)
  IF current_setting('app.skip_vacation', true) IS DISTINCT FROM 'true' THEN
    SELECT * INTO v_vacation FROM vacation_settings
    WHERE mailbox_id = v_mailbox.id
      AND enabled = TRUE
      AND (start_date IS NULL OR start_date <= CURRENT_DATE)
      AND (end_date IS NULL OR end_date >= CURRENT_DATE);

    -- RFC 3834: never auto-reply to spam, mailing-list traffic, or a null/empty
    -- return-path. Auto-replying to spam (almost always a forged third party) is
    -- backscatter that gets the server blacklisted; list mail must not be answered;
    -- an empty Return-Path means a bounce/null sender. v_folder_id = v_spam_tag_id
    -- catches the spam-foldered case; the p_spam_score check also catches a high-spam
    -- message that stayed in Inbox because spam_folder_enabled is off.
    IF v_vacation.mailbox_id IS NOT NULL
       AND v_folder_id IS DISTINCT FROM v_spam_tag_id
       AND NOT (p_spam_score IS NOT NULL AND p_spam_score >= v_spam_threshold)
       AND p_list_id IS NULL
       AND p_from_addr IS NOT NULL AND p_from_addr <> '' THEN
    -- Rate limit: one reply per sender per day
    IF NOT EXISTS (
      SELECT 1 FROM vacation_replies
      WHERE sender_email = lower(p_from_addr)
        AND mailbox_id = v_mailbox.id
        AND replied_at > now() - interval '1 day'
    ) THEN
      -- Sender locality (independent of the legacy only_contacts gate): a sender is
      -- internal when their address is a local mailbox or on a local domain.
      v_domain := split_part(lower(p_from_addr), '@', 2);
      SELECT EXISTS(SELECT 1 FROM mailboxes WHERE email = lower(p_from_addr))
          OR EXISTS(SELECT 1 FROM domains WHERE lower(name) = v_domain AND is_local)
        INTO v_sender_is_internal;

      -- Decide whether to reply at all.
      v_send_reply := TRUE;

      -- Legacy only_contacts gate: when set, never reply to non-local senders.
      IF v_vacation.only_contacts AND NOT v_sender_is_internal THEN
        v_send_reply := FALSE;
      END IF;

      -- A5 external-audience gate (only applies to EXTERNAL senders):
      --   'none'     → never auto-reply to external senders
      --   'contacts' → reply only when the sender is in the OWNER's address book
      --   'all'      → reply to every external sender
      IF v_send_reply AND NOT v_sender_is_internal THEN
        IF v_vacation.external_audience = 'none' THEN
          v_send_reply := FALSE;
        ELSIF v_vacation.external_audience = 'contacts' THEN
          v_send_reply := EXISTS (
            SELECT 1
            FROM contacts c
            JOIN addressbooks ab ON ab.id = c.addressbook_id
            WHERE ab.mailbox_id = v_mailbox.id
              AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(c.emails) e
                WHERE lower(e->>'address') = lower(p_from_addr)
              )
          );
        END IF;
        -- 'all' leaves v_send_reply = TRUE.
      END IF;

      IF v_send_reply THEN
        -- Body selection: external sender uses the external body when present;
        -- internal senders (and a blank external body) fall back to the internal body.
        IF v_sender_is_internal OR v_vacation.body_external IS NULL THEN
          v_reply_text := COALESCE(v_vacation.body_text, '');
          v_reply_html := COALESCE(v_vacation.body_html, v_vacation.body_text);
        ELSE
          v_reply_text := COALESCE(v_vacation.body_external, '');
          v_reply_html := COALESCE(v_vacation.body_external_html, v_vacation.body_external);
        END IF;

        PERFORM send(
          NULL, v_mailbox.id, 'internal://vacation-reply',
          '<vacation-' || v_mailbox.id || '-' || extract(epoch from now())::bigint || '@mailserver>',
          v_mailbox.email,
          jsonb_build_array(jsonb_build_object('email', lower(p_from_addr))),
          '[]'::jsonb, '[]'::jsonb,
          coalesce(v_vacation.subject, 'Out of office'),
          p_message_id, '',
          v_reply_text,
          v_reply_html,
          0, FALSE, NULL
        );

        INSERT INTO vacation_replies (sender_email, mailbox_id, vacation_start, replied_at)
        VALUES (lower(p_from_addr), v_mailbox.id, COALESCE(v_vacation.start_date, CURRENT_DATE), now())
        ON CONFLICT (sender_email, mailbox_id, vacation_start) DO UPDATE SET replied_at = now();
      END IF;
    END IF;
  END IF;
  END IF; -- app.skip_vacation

  -- 12. Trace
  PERFORM trace(p_message_id, 'received', p_from_addr, p_rcpt_addr,
    NULL, jsonb_build_object('mailbox_id', v_mailbox.id, 'spam_score', p_spam_score));

  -- 13. Notify & 14. Push intent: skip if an inbound rule 'discard'ed the message
  --     at step 8 (delete_draft_message already emitted the precise 'destroyed' delta).
  IF EXISTS (
    SELECT 1 FROM messages
     WHERE id = v_message_id
       AND received_at = v_received_at
       AND mailbox_id = v_mailbox.id
  ) THEN
    PERFORM notify_state_change(v_mailbox.id, v_folder_id, v_message_id, 'created');

    -- 14. Push intent (QoL #9): enqueue for the mail-push worker when the feature is
    -- ON, the message did not land in Spam, and the thread isn't muted. The worker
    -- (pushjobs) re-checks push_should_notify (prefs / VIP / DND) before dispatching
    -- — this is only the cheap in-txn enqueue. Idempotent per delivered row via
    -- UNIQUE (mailbox_id, message_id).
    IF v_folder_id IS DISTINCT FROM v_spam_tag_id
       AND NOT v_is_muted
       AND COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.mail_push'), FALSE) THEN
      INSERT INTO push_intents (mailbox_id, message_id, received_at)
      VALUES (v_mailbox.id, v_message_id, v_received_at)
      ON CONFLICT (mailbox_id, message_id) DO NOTHING;
    END IF;
  END IF;

  RETURN v_message_id;
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/jmap_email.sql (jmap_email_set_create)
CREATE OR REPLACE FUNCTION jmap_email_set_create(
  p_mailbox_id BIGINT,
  p_creates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_created      JSONB := '{}'::JSONB;
  v_notCreated   JSONB := '{}'::JSONB;
  v_old_state    BIGINT;
  v_new_state    BIGINT;
  v_created_ids  BIGINT[] := '{}'::BIGINT[];
  v_created_tags BIGINT[] := '{}'::BIGINT[];
  v_idx          INT;
  v_creation_id  TEXT;
  v_obj          JSONB;
  v_from         JSONB;
  v_to           JSONB;
  v_subject      TEXT;
  v_body_values  JSONB;
  v_text_body    TEXT;
  v_html_body    TEXT;
  v_mailbox_ids  JSONB;
  v_first_tag_id BIGINT;
  v_tag_id       BIGINT;
  v_message_id   TEXT;
  v_raw_msg      TEXT;
  v_size_bytes   BIGINT;
  v_msg_id       BIGINT;
  v_attachments  JSONB;
  v_attach_bytes BIGINT;
  v_att          JSONB;
  v_now          TIMESTAMPTZ := now();
  v_from_addr    TEXT;
  v_from_name    TEXT;
  v_to_addrs     JSONB := '[]'::JSONB;
  v_cc_addrs     JSONB := '[]'::JSONB;
  v_bcc_addrs    JSONB := '[]'::JSONB;
  v_reply_to     TEXT;
  v_priority     INT := 0;
  v_sensitivity  TEXT;
  v_read_rr      BOOL := FALSE;
  v_deliver_rr   BOOL := FALSE;
  v_scheduled_at TIMESTAMPTZ;
  v_vote_options JSONB;
  v_vote_response TEXT;
  v_reply_to_arr JSONB;
BEGIN
  SELECT jmap_email_state INTO v_old_state FROM mailboxes WHERE id = p_mailbox_id;
  v_new_state := v_old_state;

  FOR v_creation_id, v_obj IN SELECT * FROM jsonb_each(p_creates)
  LOOP
    BEGIN
      -- Parse envelope
      v_from := COALESCE(v_obj->'from', '[]'::JSONB);
      v_to := COALESCE(v_obj->'to', '[]'::JSONB);
      v_subject := v_obj->>'subject';
      v_body_values := v_obj->'bodyValues';
      v_mailbox_ids := v_obj->'mailboxIds';
      v_reply_to_arr := COALESCE(v_obj->'replyTo', '[]'::JSONB);
      v_priority := COALESCE((v_obj->>'priority')::INT, 0);
      v_sensitivity := v_obj->>'sensitivity';
      v_read_rr := COALESCE((v_obj->>'readReceiptRequested')::BOOL, FALSE);
      v_deliver_rr := COALESCE((v_obj->>'deliveryReceiptRequested')::BOOL, FALSE);
      v_scheduled_at := (v_obj->>'scheduledAt')::TIMESTAMPTZ;
      v_vote_options := v_obj->'voteOptions';
      v_vote_response := v_obj->>'voteResponse';

      IF v_mailbox_ids IS NULL OR jsonb_typeof(v_mailbox_ids) != 'object' THEN
        v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
          jsonb_build_object('type', 'invalidArguments', 'description', 'mailboxIds required'));
        CONTINUE;
      END IF;

      -- Extract text body
      IF v_body_values ? 'text' THEN
        v_text_body := v_body_values->'text'->>'value';
      END IF;
      IF v_body_values ? 'html' THEN
        v_html_body := v_body_values->'html'->>'value';
      END IF;

      -- Build from
      IF jsonb_array_length(v_from) > 0 THEN
        v_from_addr := v_from->0->>'email';
        v_from_name := v_from->0->>'name';
      END IF;
      IF v_from_addr IS NULL THEN
        SELECT u.email INTO v_from_addr
        FROM users u
        JOIN mailboxes mb ON mb.user_id = u.id
        WHERE mb.id = p_mailbox_id
        LIMIT 1;
      END IF;

      -- Build to/cc/bcc/reply-to
      IF jsonb_array_length(v_to) > 0 THEN
        v_to_addrs := v_to;
      END IF;
      v_cc_addrs := COALESCE(v_obj->'cc', '[]'::JSONB);
      v_bcc_addrs := COALESCE(v_obj->'bcc', '[]'::JSONB);
      IF jsonb_array_length(v_reply_to_arr) > 0 THEN
        v_reply_to := v_reply_to_arr->0->>'email';
      END IF;

      -- Resolve first mailboxId to tag ID for folder_id
      SELECT key::BIGINT INTO v_first_tag_id
      FROM jsonb_each(v_mailbox_ids)
      WHERE key::BIGINT IN (SELECT id FROM tags WHERE mailbox_id = p_mailbox_id)
      LIMIT 1;

      IF v_first_tag_id IS NULL THEN
        v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
          jsonb_build_object('type', 'invalidArguments', 'description', 'mailboxIds empty'));
        CONTINUE;
      END IF;

      -- Generate Message-ID
      v_message_id := '<' || gen_random_uuid()::TEXT || '@mailserver>';

      -- Build RFC 5322 raw message with all headers
      v_raw_msg := 'Message-ID: ' || v_message_id || E'\r\n';
      -- email_header_value() strips CR/LF from every user-controlled value below → no
      -- RFC 5322 header injection (a bare CR/LF would otherwise inject arbitrary headers
      -- or split the message; the vote-response path can carry attacker CRLF from a
      -- received vote header).
      IF v_from_name IS NOT NULL AND v_from_name != '' THEN
        v_raw_msg := v_raw_msg || 'From: ' || email_header_value(v_from_name) || ' <' || email_header_value(v_from_addr) || '>' || E'\r\n';
      ELSE
        v_raw_msg := v_raw_msg || 'From: ' || email_header_value(v_from_addr) || E'\r\n';
      END IF;

      -- To header
      v_raw_msg := v_raw_msg || 'To: ' || email_header_value(COALESCE((
        SELECT string_agg(
          COALESCE((r->>'name')::text, (r->>'email')::text) || ' <' || (r->>'email')::text || '>',
          ', '
        )
        FROM jsonb_array_elements(v_to_addrs) AS r
      ), '')) || E'\r\n';

      -- Cc header
      IF jsonb_array_length(v_cc_addrs) > 0 THEN
        v_raw_msg := v_raw_msg || 'Cc: ' || email_header_value(COALESCE((
          SELECT string_agg(
            COALESCE((r->>'name')::text, (r->>'email')::text) || ' <' || (r->>'email')::text || '>',
            ', '
          )
          FROM jsonb_array_elements(v_cc_addrs) AS r
        ), '')) || E'\r\n';
      END IF;

      -- Reply-To header
      IF v_reply_to IS NOT NULL AND v_reply_to != '' THEN
        v_raw_msg := v_raw_msg || 'Reply-To: ' || email_header_value(v_reply_to) || E'\r\n';
      END IF;

      -- Priority header
      IF v_priority = 1 THEN
        v_raw_msg := v_raw_msg || 'X-Priority: 1 (High)' || E'\r\n';
        v_raw_msg := v_raw_msg || 'Importance: high' || E'\r\n';
      ELSIF v_priority = -1 THEN
        v_raw_msg := v_raw_msg || 'X-Priority: 5 (Low)' || E'\r\n';
        v_raw_msg := v_raw_msg || 'Importance: low' || E'\r\n';
      END IF;

      -- Sensitivity header
      IF v_sensitivity IS NOT NULL THEN
        v_raw_msg := v_raw_msg || 'Sensitivity: ' || email_header_value(v_sensitivity) || E'\r\n';
      END IF;

      -- Read receipt header
      IF v_read_rr THEN
        v_raw_msg := v_raw_msg || 'Disposition-Notification-To: ' || v_from_addr || E'\r\n';
      END IF;

      -- Voting buttons header
      IF v_vote_options IS NOT NULL AND jsonb_array_length(v_vote_options) > 0 THEN
        v_raw_msg := v_raw_msg || 'X-Mailserver-Voting: ' ||
          email_header_value(array_to_string(ARRAY(SELECT jsonb_array_elements_text(v_vote_options)), ';')) || E'\r\n';
      END IF;

      -- Vote response header
      IF v_vote_response IS NOT NULL AND v_vote_response != '' THEN
        v_raw_msg := v_raw_msg || 'X-Mailserver-Vote-Response: ' || email_header_value(v_vote_response) || E'\r\n';
      END IF;

      v_raw_msg := v_raw_msg || 'Subject: ' || email_header_value(v_subject) || E'\r\n';
      v_raw_msg := v_raw_msg || 'Date: ' || to_char(v_now, 'Dy, DD Mon YYYY HH24:MI:SS +0000') || E'\r\n';

      IF v_html_body IS NOT NULL AND v_html_body != '' THEN
        v_raw_msg := v_raw_msg || 'Content-Type: multipart/alternative; boundary="boundary_' || v_creation_id || '"' || E'\r\n';
        v_raw_msg := v_raw_msg || E'\r\n';
        v_raw_msg := v_raw_msg || '--boundary_' || v_creation_id || E'\r\n';
        v_raw_msg := v_raw_msg || 'Content-Type: text/plain; charset=utf-8' || E'\r\n';
        v_raw_msg := v_raw_msg || E'\r\n';
        v_raw_msg := v_raw_msg || COALESCE(v_text_body, '') || E'\r\n';
        v_raw_msg := v_raw_msg || '--boundary_' || v_creation_id || E'\r\n';
        v_raw_msg := v_raw_msg || 'Content-Type: text/html; charset=utf-8' || E'\r\n';
        v_raw_msg := v_raw_msg || E'\r\n';
        v_raw_msg := v_raw_msg || v_html_body || E'\r\n';
        v_raw_msg := v_raw_msg || '--boundary_' || v_creation_id || '--' || E'\r\n';
      ELSE
        v_raw_msg := v_raw_msg || 'Content-Type: text/plain; charset=utf-8' || E'\r\n';
        v_raw_msg := v_raw_msg || E'\r\n';
        v_raw_msg := v_raw_msg || COALESCE(v_text_body, '');
      END IF;

      -- Outbound attachments: the blob bytes are NOT in v_raw_msg (the wire MIME with
      -- the bytes is assembled in Go at submission — only Go can read MinIO). The
      -- message still accounts for the attachment bytes for quota + has_attachments.
      --
      -- er5-s12 (occ_913c9852b75a06f007751b04, resource-exhaustion
      -- .attachment-size-trust): blobId IS the sha256 of an ALREADY-UPLOADED
      -- blob (message_attachments.blob_sha256 FKs blobs.sha256), so the
      -- authoritative size is blobs.size_bytes — the client-declared "size"
      -- is untrusted request input. Summing the declaration let a create
      -- understate the 25MiB message cap and the mailbox quota (declare 0 or
      -- a negative size on an oversized blob) and defer the real bytes to the
      -- submission assembler. Every attachment must declare EXACTLY its
      -- blob's real size, and the accounting below sums blobs.size_bytes,
      -- never the declaration. A garbled (non-numeric) declaration raises
      -- inside the predicate and lands in the per-creation invalidArguments
      -- handler below, same as before; a blobId with no uploaded blob row is
      -- refused here with a clear SetError instead of the opaque FK failure
      -- at the message_attachments INSERT.
      v_attachments  := COALESCE(v_obj->'attachments', '[]'::JSONB);
      v_attach_bytes := COALESCE(
        (SELECT SUM(b.size_bytes) FROM jsonb_array_elements(v_attachments) a
           JOIN blobs b ON b.sha256 = a->>'blobId'), 0);
      v_size_bytes := octet_length(v_raw_msg) + v_attach_bytes;

      -- Per-message caps (trust boundary — enforce at the source, not at send).
      IF jsonb_array_length(v_attachments) > 100 THEN
        v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
          jsonb_build_object('type', 'tooManyAttachments', 'description', 'at most 100 attachments per message'));
        CONTINUE;
      END IF;
      -- er5-s12 (cont.): the size-trust refusal keeps the pre-existing
      -- refusal precedence (count cap first, then size-trust, then the total
      -- size cap): every attachment must reference an uploaded blob and
      -- declare its EXACT size — the declaration itself is never summed or
      -- persisted (see above).
      IF EXISTS (
        SELECT 1 FROM jsonb_array_elements(v_attachments) a
          LEFT JOIN blobs b ON b.sha256 = a->>'blobId'
         WHERE b.sha256 IS NULL
            OR COALESCE((a->>'size')::BIGINT, -1) IS DISTINCT FROM b.size_bytes
      ) THEN
        v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
          jsonb_build_object('type', 'invalidAttachments', 'description',
            'every attachment must reference an uploaded blob and declare its exact size'));
        CONTINUE;
      END IF;
      IF v_size_bytes > 26214400 THEN  -- 25 MiB/message (Gmail parity)
        v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
          jsonb_build_object('type', 'tooLarge', 'description', 'message exceeds the 25 MB size limit'));
        CONTINUE;
      END IF;

      -- Quota enforcement — reject if over limit
      IF NOT check_quota(p_mailbox_id, v_size_bytes) THEN
        v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
          jsonb_build_object('type', 'overQuota', 'description', 'mailbox is over quota'));
        CONTINUE;
      END IF;

      -- Insert message with all new fields
      INSERT INTO messages (
        mailbox_id, folder_id,
        message_id, subject, from_addr, from_name,
        to_addrs, cc_addrs, bcc_addrs, reply_to,
        body_text, body_html,
        size_bytes, has_attachments,
        thread_id, raw_ref, sent_at,
        is_read, is_draft, imap_uid,
        priority, sensitivity, read_receipt_requested, delivery_receipt_requested,
        vote_options, scheduled_at,
        held, received_at
      ) VALUES (
        p_mailbox_id, v_first_tag_id,
        v_message_id, v_subject, v_from_addr, v_from_name,
        v_to_addrs, v_cc_addrs, v_bcc_addrs, v_reply_to,
        v_text_body, v_html_body,
        v_size_bytes, (jsonb_array_length(v_attachments) > 0),
        compute_thread_id(v_message_id, v_obj->>'inReplyTo', v_obj->>'references', p_mailbox_id),
        v_raw_msg, COALESCE(v_scheduled_at, v_now),
        FALSE, TRUE, next_imap_uid_for_tag(v_first_tag_id),
        v_priority, v_sensitivity, v_read_rr, v_deliver_rr,
        v_vote_options, v_scheduled_at,
        FALSE, v_now
      ) RETURNING id INTO v_msg_id;

      -- Persist attachment metadata (one row per blobId). The AFTER INSERT trigger
      -- (V075) bumps blobs.ref_count; the Go submission assembler reads these rows to
      -- stream the bytes from S3 into the wire MIME. blobId IS the sha256 (no translate).
      FOR v_att IN SELECT * FROM jsonb_array_elements(v_attachments)
      LOOP
        INSERT INTO message_attachments
          (message_id, received_at, blob_sha256, content_type, filename, content_id, disposition, size_bytes)
        VALUES (
          v_msg_id, v_now,
          v_att->>'blobId',
          COALESCE(v_att->>'type', 'application/octet-stream'),
          v_att->>'name',
          v_att->>'cid',
          COALESCE(v_att->>'disposition', 'attachment'),
          -- er5-s12: persist the blob's authoritative size (equality with the
          -- declaration is already enforced above; the blob is the authority).
          COALESCE((SELECT b.size_bytes FROM blobs b WHERE b.sha256 = v_att->>'blobId'), 0)
        );
      END LOOP;

      -- Add tags
      FOR v_tag_id IN
        SELECT key::BIGINT FROM jsonb_each(v_mailbox_ids)
        WHERE key::BIGINT IN (SELECT id FROM tags WHERE mailbox_id = p_mailbox_id)
      LOOP
        -- Verify tag belongs to p_mailbox_id's mailbox (R3: ownership check)
        PERFORM 1 FROM tags
        WHERE id = v_tag_id AND mailbox_id = p_mailbox_id;
        IF NOT FOUND THEN
          RAISE EXCEPTION 'Tag not found'
            USING ERRCODE = 'BZ002', HINT = '{"type":"forbidden","tag_id":"' || v_tag_id || '"}';
        END IF;

        INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
        VALUES (v_msg_id, v_now, v_tag_id, 'user', v_tag_id = v_first_tag_id);
      END LOOP;

      v_created_ids  := array_append(v_created_ids,  v_msg_id);
      v_created_tags := array_append(v_created_tags, v_first_tag_id);
      v_created := v_created || jsonb_build_object(v_creation_id,
        jsonb_build_object('id', v_msg_id::TEXT));

    EXCEPTION WHEN OTHERS THEN
      IF SQLSTATE = 'BZ002' THEN
        RAISE;  -- Re-raise security violations (tag ownership)
      END IF;
      v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
        jsonb_build_object('type', 'invalidArguments', 'description', SQLERRM));
    END;
  END LOOP;

  -- Batch-collapse (#554): ONE bump + N precise 'created' journal rows + ONE push (no resync sentinel).
  IF array_length(v_created_ids, 1) IS NOT NULL THEN
    v_new_state := bump_email_state(p_mailbox_id);
    FOR v_idx IN 1..array_length(v_created_ids, 1) LOOP
      PERFORM append_email_change(
        p_mailbox_id, v_new_state, v_created_ids[v_idx], 'created', v_created_tags[v_idx]
      );
    END LOOP;
    PERFORM app_notify('tag:' || p_mailbox_id, json_build_object(
      'event', 'state_change', 'tag_id', NULL, 'state', v_new_state)::TEXT);
    PERFORM public.emit_wakeup_bell('sync', 'mailbox:' || p_mailbox_id || ':0:Email');
  END IF;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'created', v_created,
    'notCreated', v_notCreated
  );
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/jmap_email.sql (jmap_email_set_update)
CREATE OR REPLACE FUNCTION jmap_email_set_update(
  p_mailbox_id BIGINT,
  p_updates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_id           BIGINT;
  v_patch        JSONB;
  v_updated      JSONB    := '[]'::JSONB;
  v_notUpdated   JSONB    := '{}'::JSONB;
  v_old_state    BIGINT;
  v_new_state    BIGINT;
  v_folder_id    BIGINT;
  v_old_folder   BIGINT;
  v_is_read      BOOL;
  -- Patchable message fields before/after this message's patch, and whether
  -- anything (fields or labels) actually changed.
  v_fields_before JSONB;
  v_fields_after  JSONB;
  v_changed       BOOL;
  -- ponytail: collect successful ids → ONE bump + N journal rows + ONE push after loop.
  v_updated_ids  BIGINT[] := '{}'::BIGINT[];
BEGIN
  -- Capture oldState + acquire canonical #481 mailbox lock BEFORE locking messages.
  SELECT jmap_email_state INTO v_old_state FROM mailboxes WHERE id = p_mailbox_id FOR UPDATE;
  v_new_state := v_old_state;  -- fallback if no messages are updated

  FOR v_id, v_patch IN SELECT * FROM jsonb_each(p_updates)
  LOOP
    BEGIN
      -- Verify message exists
      SELECT is_read,
             jsonb_build_array(is_read, is_flagged, is_answered, is_draft,
                               flag_due_at, flag_reminder_at, pinned_at)
      INTO v_is_read, v_fields_before
      FROM messages WHERE id = v_id AND mailbox_id = p_mailbox_id FOR UPDATE;
      v_changed := FALSE;

      IF NOT FOUND THEN
        v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound'));
        CONTINUE;
      END IF;
      SELECT tag_id INTO v_old_folder
      FROM message_tags
      WHERE message_id = v_id AND is_primary = TRUE
      LIMIT 1
      FOR UPDATE;

      -- Handle keywords update
      IF v_patch ? 'keywords' THEN
        DECLARE
          v_kw JSONB := v_patch->'keywords';
          v_new_read BOOL;
          v_old_read BOOL;
        BEGIN
          SELECT is_read INTO v_old_read
          FROM messages WHERE id = v_id;

          UPDATE messages SET
            is_read = COALESCE((v_kw->>'$seen')::BOOL, is_read),
            is_flagged = COALESCE((v_kw->>'$flagged')::BOOL, is_flagged),
            is_answered = COALESCE((v_kw->>'$answered')::BOOL, is_answered),
            is_draft = COALESCE((v_kw->>'$draft')::BOOL, is_draft),
            -- Clearing the follow-up flag clears its due/reminder instants so a
            -- stale flag_reminder_at never fires for an un-flagged message (A2).
            flag_due_at = CASE WHEN (v_kw->>'$flagged') = 'false' THEN NULL ELSE flag_due_at END,
            flag_reminder_at = CASE WHEN (v_kw->>'$flagged') = 'false' THEN NULL ELSE flag_reminder_at END
          WHERE id = v_id AND mailbox_id = p_mailbox_id
          RETURNING is_read INTO v_new_read;

          -- Adjust unread count on ALL tags for this message
          IF v_new_read IS DISTINCT FROM v_old_read THEN
            UPDATE tags SET
                unread_count = GREATEST(0, unread_count + CASE WHEN v_new_read THEN -1 ELSE 1 END),
                jmap_state   = jmap_state + 1
            WHERE id IN (
                SELECT tag_id FROM message_tags
                WHERE message_id = v_id
                  AND received_at = (SELECT received_at FROM messages WHERE id = v_id)
            );
          END IF;
        END;
      END IF;

      -- Handle follow-up flag fields (A2). Stored only; A6's scan fires them.
      IF v_patch ? 'flagDueAt' THEN
        UPDATE messages SET flag_due_at = NULLIF(v_patch->>'flagDueAt', '')::TIMESTAMPTZ
        WHERE id = v_id AND mailbox_id = p_mailbox_id;
      END IF;
      IF v_patch ? 'flagReminderAt' THEN
        UPDATE messages SET flag_reminder_at = NULLIF(v_patch->>'flagReminderAt', '')::TIMESTAMPTZ
        WHERE id = v_id AND mailbox_id = p_mailbox_id;
      END IF;

      -- Handle pinned toggle (true → NOW(), null/false → NULL)
      IF v_patch ? 'pinned' THEN
        UPDATE messages SET pinned_at = CASE WHEN (v_patch->>'pinned')::BOOL THEN NOW() ELSE NULL END
        WHERE id = v_id AND mailbox_id = p_mailbox_id;
      END IF;

      -- Handle mailboxIds (tag-based multi-label assignment)
      IF v_patch ? 'mailboxIds' THEN
        DECLARE
          v_new_primary BIGINT := v_old_folder;
          v_tag_id      BIGINT;
          v_msg_received_at TIMESTAMPTZ;
          v_want_tags   BIGINT[] := '{}'::BIGINT[];
        BEGIN
          SELECT received_at INTO v_msg_received_at FROM messages WHERE id = v_id FOR UPDATE;

          -- Validate every tag of the mailboxIds map; first one becomes primary
          FOR v_tag_id IN SELECT key::BIGINT FROM jsonb_each(v_patch->'mailboxIds')
          LOOP
            -- Verify tag belongs to p_mailbox_id's mailbox (R3: ownership check)
            PERFORM 1 FROM tags
            WHERE id = v_tag_id AND mailbox_id = p_mailbox_id;
            IF NOT FOUND THEN
              RAISE EXCEPTION 'Tag not found'
                USING ERRCODE = 'BZ002', HINT = '{"type":"forbidden","tag_id":"' || v_tag_id || '"}';
            END IF;

            IF v_new_primary IS NULL THEN
              v_new_primary := v_tag_id;
            END IF;
            v_want_tags := array_append(v_want_tags, v_tag_id);
          END LOOP;

          -- Re-label only when the requested (tag, primary) set differs from the
          -- current one; an identical set is a no-op (#219).
          IF EXISTS (
            WITH cur AS (
              SELECT mt.tag_id, mt.is_primary
              FROM message_tags mt
              JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
              WHERE mt.message_id = v_id AND mt.received_at = v_msg_received_at
                AND m.mailbox_id = p_mailbox_id
            ), want AS (
              SELECT t AS tag_id, t = v_new_primary AS is_primary
              FROM unnest(v_want_tags) AS t
            )
            (SELECT * FROM cur EXCEPT SELECT * FROM want)
            UNION ALL
            (SELECT * FROM want EXCEPT SELECT * FROM cur)
          ) THEN
            -- Remove all current tags (counters handled by trigger)
            DELETE FROM message_tags
            WHERE message_id = v_id AND received_at = v_msg_received_at
              AND EXISTS (SELECT 1 FROM messages m
                          WHERE m.id = v_id AND m.received_at = v_msg_received_at
                            AND m.mailbox_id = p_mailbox_id);

            FOREACH v_tag_id IN ARRAY v_want_tags
            LOOP
              INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
              VALUES (v_id, v_msg_received_at, v_tag_id, 'user',
                      v_tag_id = v_new_primary);
            END LOOP;

            -- Bump mailbox state
            PERFORM bump_tag_mailbox_state(p_mailbox_id);
            v_changed := TRUE;
          END IF;
        END;
      END IF;

      -- Collect id for the post-loop batch bump (one bump + N journal rows + one
      -- push) only if a field or label actually changed (#219: no-op, no effect).
      IF NOT v_changed THEN
        SELECT jsonb_build_array(is_read, is_flagged, is_answered, is_draft,
                                 flag_due_at, flag_reminder_at, pinned_at)
        INTO v_fields_after
        FROM messages WHERE id = v_id AND mailbox_id = p_mailbox_id;
        v_changed := v_fields_after IS DISTINCT FROM v_fields_before;
      END IF;
      IF v_changed THEN
        v_updated_ids := array_append(v_updated_ids, v_id);
      END IF;
      v_updated := v_updated || to_jsonb(v_id);
    EXCEPTION WHEN OTHERS THEN
      IF SQLSTATE = 'BZ002' THEN
        RAISE;  -- Re-raise security violations (tag ownership)
      END IF;
      v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'Update failed'));
    END;
  END LOOP;

  -- Batch-collapse (offline #3): ONE bump + N precise journal rows at that seq + ONE push.
  -- All N ids land at the same state_seq; jmap_email_changes pages by seq (never splits a group).
  IF array_length(v_updated_ids, 1) IS NOT NULL THEN
    v_new_state := bump_email_state(p_mailbox_id);
    FOREACH v_id IN ARRAY v_updated_ids LOOP
      PERFORM append_email_change(p_mailbox_id, v_new_state, v_id, 'updated');
    END LOOP;
    PERFORM app_notify('tag:' || p_mailbox_id, json_build_object(
      'event', 'state_change', 'tag_id', NULL, 'state', v_new_state)::TEXT);
    PERFORM public.emit_wakeup_bell('sync', 'mailbox:' || p_mailbox_id || ':0:Email');
  END IF;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'updated', v_updated,
    'notUpdated', v_notUpdated
  );
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/jmap_email.sql (jmap_email_set_destroy)
CREATE OR REPLACE FUNCTION jmap_email_set_destroy(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[]
) RETURNS JSONB AS $$
DECLARE
  v_destroyed      JSONB    := '[]'::JSONB;
  v_notDestroyed   JSONB    := '{}'::JSONB;
  v_old_state      BIGINT;
  v_new_state      BIGINT;
  v_id             BIGINT;
  v_received_at    TIMESTAMPTZ;
  v_trash_id       BIGINT;
  -- ponytail: collect successful ids → ONE bump + N journal rows + ONE push after loop.
  v_destroyed_ids  BIGINT[] := '{}'::BIGINT[];
  v_destroyed_tags BIGINT[] := '{}'::BIGINT[];
  v_destroyed_uids BIGINT[] := '{}'::BIGINT[];
  v_primary_tag    BIGINT;
  v_imap_uid       BIGINT;
  v_size_bytes     BIGINT;
  v_idx            INT;
BEGIN
  SELECT id INTO v_trash_id FROM tags
  WHERE name = 'Trash' AND mailbox_id = p_mailbox_id;

  -- Capture oldState + acquire canonical #481 mailbox lock BEFORE mutating messages.
  SELECT jmap_email_state INTO v_old_state FROM mailboxes WHERE id = p_mailbox_id FOR UPDATE;
  v_new_state := v_old_state;

  FOREACH v_id IN ARRAY p_ids
  LOOP
    BEGIN
      -- Verify message exists and get metadata
      SELECT received_at, size_bytes, imap_uid INTO v_received_at, v_size_bytes, v_imap_uid
      FROM messages
      WHERE id = v_id AND mailbox_id = p_mailbox_id AND NOT is_deleted;

      IF NOT FOUND THEN
        v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound'));
        CONTINUE;
      END IF;

      -- Find current primary (location) tag
      SELECT tag_id INTO v_primary_tag
      FROM message_tags
      WHERE message_id = v_id AND received_at = v_received_at AND is_primary = TRUE
      LIMIT 1;

      IF v_trash_id IS NOT NULL AND v_primary_tag IS DISTINCT FROM v_trash_id THEN
        -- Move to Trash through the single location seam. p_notify=FALSE: the
        -- post-loop batch bump below owns the single bump + push.
        PERFORM transition_message_location(v_id, v_received_at, 'Trash', p_mailbox_id, 'user', FALSE);
      ELSE
        -- Already in Trash (or no Trash tag exists) → soft-delete
        DELETE FROM message_tags
        WHERE message_id = v_id AND received_at = v_received_at;

        UPDATE messages SET is_deleted = TRUE, deleted_at = NOW()
        WHERE id = v_id AND received_at = v_received_at
          AND mailbox_id = p_mailbox_id;

        -- Adjust quota: soft-deleted messages don't count
        UPDATE mailboxes SET used_bytes = GREATEST(0, used_bytes - v_size_bytes)
        WHERE id = p_mailbox_id;
      END IF;

      -- Collect id + pre-destroy folder/UID for the post-loop batch bump.
      v_destroyed_ids  := array_append(v_destroyed_ids,  v_id);
      v_destroyed_tags := array_append(v_destroyed_tags, v_primary_tag);
      v_destroyed_uids := array_append(v_destroyed_uids, v_imap_uid);
      v_destroyed := v_destroyed || to_jsonb(v_id::TEXT);
    EXCEPTION WHEN OTHERS THEN
      v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'Destroy failed'));
    END;
  END LOOP;

  -- Batch-collapse (offline #3, #554): ONE bump + N precise journal rows at that seq + ONE push.
  IF array_length(v_destroyed_ids, 1) IS NOT NULL THEN
    v_new_state := bump_email_state(p_mailbox_id);
    FOR v_idx IN 1..array_length(v_destroyed_ids, 1) LOOP
      PERFORM append_email_change(
        p_mailbox_id, v_new_state, v_destroyed_ids[v_idx], 'destroyed',
        v_destroyed_tags[v_idx], v_destroyed_uids[v_idx]
      );
    END LOOP;
    PERFORM app_notify('tag:' || p_mailbox_id, json_build_object(
      'event', 'state_change', 'tag_id', NULL, 'state', v_new_state)::TEXT);
    PERFORM public.emit_wakeup_bell('sync', 'mailbox:' || p_mailbox_id || ':0:Email');
  END IF;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'destroyed', v_destroyed,
    'notDestroyed', v_notDestroyed
  );
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/jmap_email.sql (jmap_email_recover)
CREATE OR REPLACE FUNCTION jmap_email_recover(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[]
) RETURNS JSONB AS $$
DECLARE
  v_recovered     JSONB    := '[]'::JSONB;
  v_notRecovered  JSONB    := '{}'::JSONB;
  v_new_state     BIGINT;
  v_id            BIGINT;
  v_received_at   TIMESTAMPTZ;
  v_size_bytes    BIGINT;
  v_recovered_ids BIGINT[] := '{}'::BIGINT[];
BEGIN
  -- Canonical #481 lock order (mailboxes -> messages -> message_tags).
  PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id FOR UPDATE;

  FOREACH v_id IN ARRAY p_ids
  LOOP
    BEGIN
      SELECT received_at, size_bytes INTO v_received_at, v_size_bytes
      FROM messages
      WHERE id = v_id AND mailbox_id = p_mailbox_id AND is_deleted;

      IF NOT FOUND THEN
        v_notRecovered := v_notRecovered || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound'));
        CONTINUE;
      END IF;

      -- Check quota BEFORE mutating messages/tags so an over-quota rejection
      -- never commits unjournaled writes.
      IF NOT check_quota(p_mailbox_id, v_size_bytes) THEN
        v_notRecovered := v_notRecovered || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'overQuota', 'description', 'Not enough free space to recover'));
        CONTINUE;
      END IF;

      -- Restore message
      UPDATE messages SET is_deleted = FALSE, deleted_at = NULL
      WHERE id = v_id AND received_at = v_received_at
        AND mailbox_id = p_mailbox_id;

      -- Move back to Inbox through the single location seam. Batch loop with ONE
      -- batch-collapsed bump + precise journal rows after the loop.
      PERFORM transition_message_location(v_id, v_received_at, 'Inbox', p_mailbox_id, 'user', FALSE);

      UPDATE mailboxes SET used_bytes = used_bytes + v_size_bytes
      WHERE id = p_mailbox_id;

      v_recovered_ids := array_append(v_recovered_ids, v_id);
      v_recovered := v_recovered || to_jsonb(v_id::TEXT);
    EXCEPTION WHEN OTHERS THEN
      v_notRecovered := v_notRecovered || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'Recover failed'));
    END;
  END LOOP;

  -- Batch-collapse (#554): ONE bump + N precise 'created' journal rows + ONE push (no resync sentinel).
  IF array_length(v_recovered_ids, 1) IS NOT NULL THEN
    v_new_state := bump_email_state(p_mailbox_id);
    FOREACH v_id IN ARRAY v_recovered_ids LOOP
      PERFORM append_email_change(p_mailbox_id, v_new_state, v_id, 'created');
    END LOOP;
    PERFORM app_notify('tag:' || p_mailbox_id, json_build_object(
      'event', 'state_change', 'tag_id', NULL, 'state', v_new_state)::TEXT);
    PERFORM public.emit_wakeup_bell('sync', 'mailbox:' || p_mailbox_id || ':0:Email');
  ELSE
    SELECT jmap_email_state INTO v_new_state FROM mailboxes WHERE id = p_mailbox_id;
  END IF;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'newState', v_new_state::TEXT,
    'recovered', v_recovered,
    'notRecovered', v_notRecovered
  );
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/jmap_email.sql (jmap_email_purge)
CREATE OR REPLACE FUNCTION jmap_email_purge(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[],
  p_notify     BOOLEAN DEFAULT TRUE
) RETURNS JSONB AS $$
DECLARE
  v_purged      JSONB    := '[]'::JSONB;
  v_notPurged   JSONB    := '{}'::JSONB;
  v_new_state   BIGINT;
  v_id          BIGINT;
  v_received_at TIMESTAMPTZ;
  v_raw_ref     TEXT;
  v_imap_uid    BIGINT;
  v_folder_id   BIGINT;
  v_primary_tag BIGINT;
  v_shared      INT;
  v_purged_ids  BIGINT[] := '{}'::BIGINT[];
  v_purged_tags BIGINT[] := '{}'::BIGINT[];
  v_purged_uids BIGINT[] := '{}'::BIGINT[];
  v_idx         INT;
BEGIN
  -- Canonical #481 lock order (mailboxes -> messages).
  PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id FOR UPDATE;

  FOREACH v_id IN ARRAY p_ids
  LOOP
    BEGIN
      SELECT received_at, raw_ref, imap_uid, folder_id
        INTO v_received_at, v_raw_ref, v_imap_uid, v_folder_id
      FROM messages
      WHERE id = v_id AND mailbox_id = p_mailbox_id AND is_deleted;

      IF NOT FOUND THEN
        v_notPurged := v_notPurged || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound'));
        CONTINUE;
      END IF;

      SELECT mt.tag_id INTO v_primary_tag
      FROM message_tags mt
      WHERE mt.message_id = v_id
        AND mt.received_at = v_received_at
        AND mt.is_primary = TRUE
      LIMIT 1;

      -- Deduplication check: is raw_ref shared by other messages?
      SELECT COUNT(*) INTO v_shared
      FROM messages
      WHERE raw_ref = v_raw_ref
        AND mailbox_id = p_mailbox_id  -- #470: another tenant's row must not decide (existence oracle); the cleanup worker re-checks globally
        AND (id != v_id OR received_at != v_received_at);

      IF v_shared = 0 THEN
        -- Safe to queue blob for deletion
        INSERT INTO orphaned_message_blobs(raw_ref)
        VALUES (v_raw_ref)
        ON CONFLICT DO NOTHING;
      END IF;

      -- Hard-delete the message row
      DELETE FROM messages WHERE id = v_id AND received_at = v_received_at
        AND mailbox_id = p_mailbox_id;

      v_purged_ids  := array_append(v_purged_ids,  v_id);
      v_purged_tags := array_append(v_purged_tags, COALESCE(v_primary_tag, v_folder_id));
      v_purged_uids := array_append(v_purged_uids, v_imap_uid);
      v_purged := v_purged || to_jsonb(v_id::TEXT);
    EXCEPTION WHEN OTHERS THEN
      v_notPurged := v_notPurged || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'Purge failed'));
    END;
  END LOOP;

  -- Batch-collapse (#554): ONE bump + N precise 'destroyed' journal rows (with
  -- pre-delete folder_id + imap_uid for QRESYNC VANISHED) + ONE push — unless
  -- the caller (IMAP expunge) already notified the soft-delete.
  IF p_notify AND array_length(v_purged_ids, 1) IS NOT NULL THEN
    v_new_state := bump_email_state(p_mailbox_id);
    FOR v_idx IN 1..array_length(v_purged_ids, 1) LOOP
      PERFORM append_email_change(
        p_mailbox_id, v_new_state, v_purged_ids[v_idx], 'destroyed',
        v_purged_tags[v_idx], v_purged_uids[v_idx]
      );
    END LOOP;
    PERFORM app_notify('tag:' || p_mailbox_id, json_build_object(
      'event', 'state_change', 'tag_id', NULL, 'state', v_new_state)::TEXT);
    PERFORM public.emit_wakeup_bell('sync', 'mailbox:' || p_mailbox_id || ':0:Email');
  ELSE
    SELECT jmap_email_state INTO v_new_state FROM mailboxes WHERE id = p_mailbox_id;
  END IF;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'newState', v_new_state::TEXT,
    'purged', v_purged,
    'notPurged', v_notPurged
  );
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/jmap_email_submission.sql (jmap_email_submission_set)
CREATE OR REPLACE FUNCTION jmap_email_submission_set(
  p_mailbox_id        BIGINT,
  p_user_id           BIGINT,
  p_submissions       JSONB,
  p_processed_raw_ref JSONB DEFAULT NULL, -- Phase 3: map creationId → processed-blob-ref (signed and/or encrypted; NULL = unchanged)
  p_is_encrypted      JSONB DEFAULT NULL  -- Phase 3: map creationId → bool (TRUE = encrypted-at-rest; 3.3 nulls body cols)
) RETURNS JSONB AS $$
DECLARE
  v_created       JSONB := '{}'::JSONB;
  v_notCreated    JSONB := '{}'::JSONB;
  v_old_state     BIGINT;
  v_new_state     BIGINT;
  v_creation_id   TEXT;
  v_sub           JSONB;
  v_email_id      BIGINT;
  v_msg           RECORD;
  v_to_addrs      JSONB;
  v_cc_addrs      JSONB;
  v_bcc_addrs     JSONB;
  v_send_at       TIMESTAMPTZ;
  v_sent_id       BIGINT;
  v_processed_ref TEXT;
  v_is_enc        BOOLEAN;
  v_clear_text    TEXT;       -- cleartext body kept for send()'s in-txn DLP scan on the encrypted path
  v_clear_html    TEXT;
  v_old_raw_ref   TEXT;
  v_shared        INT;
  v_webhook_rcpts JSONB;
  v_webhook_rcpt  JSONB;
  v_webhook_ordinal BIGINT;
  v_webhook_from TEXT;
BEGIN
  -- Authoritative baseline for the JMAP oldState (captured before any per-submission
  -- path advances jmap_email_state). newState is read — not re-bumped — at the end.
  SELECT jmap_email_state INTO v_old_state FROM mailboxes WHERE id = p_mailbox_id;

  FOR v_creation_id, v_sub IN SELECT * FROM jsonb_each(p_submissions)
  LOOP
    BEGIN
      v_email_id := (v_sub->>'emailId')::BIGINT;
      IF v_email_id IS NULL THEN
        v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
          jsonb_build_object('type', 'invalidArguments', 'description', 'emailId is required'));
        CONTINUE;
      END IF;

      -- R1: load the draft AND verify ownership in the same statement.
      SELECT * INTO v_msg
      FROM messages
      WHERE id = v_email_id AND mailbox_id = p_mailbox_id;

      IF v_msg.id IS NULL THEN
        v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
          jsonb_build_object('type', 'notFound', 'description', 'emailId not found'));
        CONTINUE;
      END IF;

      -- Shared-draft collaboration is opt-in per submission. Once a client
      -- supplies any lease field it must supply the complete tuple; the
      -- authorization reducer locks and terminalizes the session in this same
      -- send transaction, so a failed send rolls the terminal state back.
      IF v_sub ? 'draftSessionId' OR v_sub ? 'draftLeaseEpoch' OR v_sub ? 'draftRevision' THEN
        IF NOT (v_sub ? 'draftSessionId' AND v_sub ? 'draftLeaseEpoch' AND v_sub ? 'draftRevision') THEN
          v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
            jsonb_build_object('type','invalidArguments','description','complete shared draft lease tuple is required'));
          CONTINUE;
        END IF;
        PERFORM mail_draft_submission_authorize(
          p_mailbox_id,p_user_id,(v_sub->>'draftSessionId')::uuid,
          (v_sub->>'draftLeaseEpoch')::bigint,(v_sub->>'draftRevision')::bigint,
          v_email_id,v_msg.received_at);
      END IF;

      -- Phase 3: if the Go handler PROCESSED this submission (signed and/or
      -- encrypted), swap the draft's raw_ref to the processed blob in-txn so BOTH
      -- the immediate send() (via the v_msg snapshot, updated below) and the
      -- scheduled path (message_schedule re-reads the row) carry the final wire
      -- artifact.
      -- INVARIANT: raw_ref is the processed WIRE artifact. For a SIGNED-only blob
      -- body_text/body_html/body_tsv stay the cleartext display/search cache; the
      -- ENCRYPTED-at-rest body-null surgery lives in send()/deliver() (3.3),
      -- driven by p_is_encrypted. NULL/omitted p_processed_raw_ref => unchanged.
      v_processed_ref := p_processed_raw_ref ->> v_creation_id;
      IF v_processed_ref IS NOT NULL AND v_processed_ref IS DISTINCT FROM v_msg.raw_ref THEN
        -- lock the draft row for the swap (closes the concurrent-submission TOCTOU)
        SELECT raw_ref INTO v_old_raw_ref
          FROM messages WHERE id = v_email_id AND mailbox_id = p_mailbox_id FOR UPDATE;
        -- orphan the old (unprocessed) blob if no other message references it (raw_ref
        -- is NOT ref-counted; messages is partitioned by received_at so dedup keys on both).
        SELECT COUNT(*) INTO v_shared FROM messages
          WHERE raw_ref = v_old_raw_ref AND (id != v_email_id OR received_at != v_msg.received_at);
        IF v_shared = 0 THEN
          INSERT INTO orphaned_message_blobs(raw_ref) VALUES (v_old_raw_ref) ON CONFLICT DO NOTHING;
        END IF;
        -- swap (R3: ownership in the same WHERE)
        UPDATE messages SET raw_ref = v_processed_ref WHERE id = v_email_id AND mailbox_id = p_mailbox_id;
        v_msg.raw_ref := v_processed_ref;  -- REQUIRED: the immediate send() below passes the snapshot
      END IF;

      -- SP1: did the Go handler ENCRYPT this submission? Drives encrypted-at-rest:
      -- send()/deliver() null the stored body columns when TRUE. NULL/omitted => FALSE.
      v_is_enc := COALESCE((p_is_encrypted ->> v_creation_id)::BOOLEAN, FALSE);

      -- Cleartext snapshot for the immediate path's in-txn DLP: send() scans
      -- p_body_text/p_body_html (step 5a) but stores NULL when p_is_encrypted, so
      -- we MUST keep feeding it the cleartext (the "scan cleartext, store ciphertext"
      -- contract). v_msg already holds the cleartext draft bodies; capture them so
      -- nulling the stored draft row below doesn't also blank what send() scans.
      v_clear_text := v_msg.body_text;
      v_clear_html := v_msg.body_html;

      -- Encrypted-at-rest for the STORED draft row. The SCHEDULED path moves THIS
      -- row to Sent in place at fire time (scheduled_action_send: tag move, no
      -- re-store), so nulling its bodies now is what makes the scheduled Sent copy
      -- encrypted-at-rest; the immediate path also keeps this row when
      -- onSuccessUpdateEmail is present, so null it for that case too. The
      -- ciphertext is already in raw_ref (swapped above). Guarded so a signed-only
      -- submission leaves the cleartext draft cache untouched (Phase D invariant).
      -- R3: ownership in the same WHERE.
      -- SP1: also stamp the at-rest discriminator. The SCHEDULED path moves THIS
      -- row to Sent in place (scheduled_action_send: tag move, no re-store), so
      -- this UPDATE is the only place the scheduled Sent copy gets marked
      -- encrypted; without crypto_type the body is nulled but decrypt-on-read
      -- (cryptoType=='smime-encrypted') never fires → the sender's scheduled Sent
      -- copy renders blank. Same flag (v_is_enc) that nulls the body.
      IF v_is_enc THEN
        UPDATE messages SET body_text = NULL, body_html = NULL, crypto_type = 'smime-encrypted'
          WHERE id = v_email_id AND mailbox_id = p_mailbox_id;
      END IF;

      -- Recipients: explicit envelope wins, else message headers.
      IF v_sub ? 'envelope' THEN
        v_to_addrs := v_sub->'envelope'->'rcptTo';
        v_cc_addrs := '[]'::JSONB;
        v_bcc_addrs := '[]'::JSONB;
      ELSE
        v_to_addrs := v_msg.to_addrs;
        v_cc_addrs := v_msg.cc_addrs;
        v_bcc_addrs := v_msg.bcc_addrs;
      END IF;
      v_webhook_rcpts := COALESCE(v_to_addrs,'[]'::jsonb)
        || COALESCE(v_cc_addrs,'[]'::jsonb) || COALESCE(v_bcc_addrs,'[]'::jsonb);
      v_webhook_from := COALESCE(v_sub->'envelope'->'mailFrom'->>'email',v_msg.from_addr);

      -- B2: parse the namespaced sendAt (future = scheduled send).
      v_send_at := NULL;
      IF v_sub ? 'sendAt' AND (v_sub->>'sendAt') IS NOT NULL THEN
        v_send_at := (v_sub->>'sendAt')::TIMESTAMPTZ;
      END IF;

      -- S/MIME signing (Phase D) is handled entirely in the EmailSubmission/set Go
      -- handler BEFORE this reducer runs: it signs at submission, swaps the draft's
      -- raw_ref via p_processed_raw_ref (above), strips signSMIME, and surfaces a
      -- missing/unusable cert as a per-creation notCreated. No worker-side sign
      -- intent is threaded from here anymore (Phase D3 removed it).

      IF v_send_at IS NOT NULL AND v_send_at > now() THEN
        -- Scheduled send: keep the draft, tag it Scheduled, and enqueue a `send`
        -- scheduled_action (A6) via message_schedule(); the deferred-action
        -- dispatcher fires it when sendAt passes. message_schedule() does not bump
        -- state itself; the Scheduled tag move is a visibility change, so push it
        -- through the single owner here. The raw_ref already carries the signed
        -- wire artifact (swapped above), so no extra payload is threaded.
        PERFORM message_schedule(p_mailbox_id, v_email_id, v_send_at, NULL,
          jsonb_build_object(
            'actor_user_id',p_user_id,
            'webhook_envelope_from',v_webhook_from,
            'webhook_envelope_rcpts',v_webhook_rcpts));
        -- ponytail: scheduled-draft tag move is 'updated' (same message, re-tagged Scheduled)
        PERFORM notify_state_change(p_mailbox_id, NULL, v_email_id, 'updated');
        v_created := v_created || jsonb_build_object(v_creation_id, jsonb_build_object(
          'id', v_email_id::TEXT,
          'emailId', v_email_id::TEXT,
          'undoStatus', 'pending',
          'sendAt', v_send_at
        ));
        CONTINUE;  -- do not delete the draft; do not send now
      END IF;

      -- Immediate send (optionally with an undo-send window). send() handles
      -- the Sent copy + outbound queue; p_send_at NULL = send now.
      -- Pass the CLEARTEXT bodies (v_clear_*) so send()'s in-txn DLP scans real
      -- content; send() stores NULL bodies itself when p_is_encrypted=TRUE.
      PERFORM set_config('app.webhook_origin','jmap_submission',true);
      PERFORM set_config('app.webhook_envelope_rcpts',v_webhook_rcpts::text,true);
      v_sent_id := send(
        p_user_id, p_mailbox_id, v_msg.raw_ref, v_msg.message_id, v_msg.from_addr,
        v_to_addrs, v_cc_addrs, v_bcc_addrs, v_msg.subject,
        v_msg.in_reply_to, v_msg.references_hdr, v_clear_text, v_clear_html,
        v_msg.size_bytes, v_msg.has_attachments,
        CASE WHEN (v_sub->>'onSendUndoWindowSeconds')::INT > 0
             THEN now() + make_interval(secs => (v_sub->>'onSendUndoWindowSeconds')::INT)
             ELSE NULL END,
        v_is_enc,
        -- The draft (v_email_id/v_msg.received_at) is the attachment-metadata
        -- source: send() threads this through to deliver() so a LOCAL recipient's
        -- copy also gets the draft's message_attachments rows, not just the Sent
        -- copy (copied separately below).
        p_source_message_id => v_email_id,
        p_source_received_at => v_msg.received_at
      );

      IF v_sent_id IS NOT NULL THEN
        FOR v_webhook_rcpt,v_webhook_ordinal IN
          SELECT value,ordinality FROM jsonb_array_elements(v_webhook_rcpts) WITH ORDINALITY
        LOOP
          PERFORM webhook_mail_committed_publish(
            v_sent_id,'mail.sent','jmap_submission',v_webhook_from,
            v_webhook_rcpt->>'email',v_webhook_ordinal::integer);
        END LOOP;
        PERFORM mail_work_record_first_response(p_mailbox_id,p_user_id,v_msg.thread_id,v_sent_id);
      END IF;

      -- Carry the draft's attachment metadata onto the Sent copy so the sender's
      -- reading pane shows + downloads the attachments (the wire bytes are already in
      -- the assembled raw_ref). The V075 trigger bumps the blob ref_count for the Sent
      -- copy; the draft's rows decrement it back when the draft is deleted below.
      IF v_sent_id IS NOT NULL AND v_msg.has_attachments THEN
        INSERT INTO message_attachments
          (message_id, received_at, blob_sha256, content_type, filename, content_id, disposition, size_bytes)
        SELECT v_sent_id, ms.received_at, ma.blob_sha256, ma.content_type, ma.filename,
               ma.content_id, ma.disposition, ma.size_bytes
        FROM message_attachments ma, messages ms
        WHERE ma.message_id = v_email_id AND ma.received_at = v_msg.received_at
          AND ms.id = v_sent_id;
      END IF;

      -- RFC 8621 §7 onSuccessUpdateEmail: when present, keep the draft and apply
      -- the requested patch (tag-on-send). When absent, delete the draft (legacy).
      -- T7: v_sent_id IS NULL when send() held the message for external-send approval
      -- (no Sent copy was created). Guard draft deletion and patch application on
      -- v_sent_id IS NOT NULL — the draft must survive to keep the raw_ref blob
      -- ref_count ≥ 1 for the approve-replay path. Use COALESCE so the JMAP `id`
      -- field is never null (held path returns the draft's own id).
      IF v_sub ? 'onSuccessUpdateEmail' AND jsonb_typeof(v_sub->'onSuccessUpdateEmail') = 'object' THEN
        -- Only apply the patch when the send actually completed (v_sent_id IS NOT NULL).
        -- Held sends skip the patch: the send hasn't happened yet.
        IF v_sent_id IS NOT NULL THEN
          DECLARE
            v_patch_key   TEXT;
            v_patch_val   JSONB;
            v_norm        JSONB := '{}'::JSONB;
          BEGIN
            -- The patch map is keyed by an Email id or a "#creationId" back-ref.
            -- We re-key every patch onto the actual draft id (v_email_id) and
            -- delegate to jmap_email_set_update, which enforces p_mailbox_id (R1/R3).
            FOR v_patch_key, v_patch_val IN SELECT * FROM jsonb_each(v_sub->'onSuccessUpdateEmail')
            LOOP
              v_norm := v_norm || jsonb_build_object(v_email_id::TEXT, v_patch_val);
            END LOOP;
            PERFORM jmap_email_set_update(p_mailbox_id, v_norm);
          END;
        END IF;

        v_created := v_created || jsonb_build_object(v_creation_id, jsonb_build_object(
          'id', COALESCE(v_sent_id, v_email_id)::TEXT,
          'emailId', v_email_id::TEXT,
          -- T7: held for external-send approval → the client shows a "held" state and
          -- must NOT arm the undo-send timer (no scheduled/undo row exists — it is an
          -- approval_request). v_sent_id IS NULL exactly when send() held the message.
          'heldForApproval', (v_sent_id IS NULL)
        ));
      ELSE
        -- Legacy path: delete the draft on a normal (non-held) send. send() above
        -- already pushed the state change, so suppress the helper's bump (p_notify =>
        -- FALSE) to preserve the no-double-bump invariant, and record an exact
        -- 'destroyed' journal entry for the deleted draft on that same state seq
        -- so JMAP Email/changes & IMAP QRESYNC VANISHED observe the draft removal (#554).
        -- T7: skip deletion when held (v_sent_id IS NULL) — the draft must survive.
        IF v_sent_id IS NOT NULL THEN
          DECLARE
            v_draft_tag_id BIGINT;
            v_cur_state    BIGINT;
          BEGIN
            SELECT mt.tag_id INTO v_draft_tag_id
            FROM message_tags mt
            JOIN tags t ON t.id = mt.tag_id
            WHERE mt.message_id = v_email_id
              AND mt.received_at = v_msg.received_at
              AND t.mailbox_id = p_mailbox_id
              AND mt.is_primary = TRUE
            LIMIT 1;
            SELECT jmap_email_state INTO v_cur_state FROM mailboxes WHERE id = p_mailbox_id;
            IF v_cur_state IS NOT NULL THEN
              PERFORM set_config('app.imap_retire_modseq', (GREATEST(v_cur_state, 0) + 1)::TEXT, TRUE);
            END IF;
            PERFORM delete_draft_message(v_email_id, v_msg.received_at, p_mailbox_id, FALSE);
            PERFORM set_config('app.imap_retire_modseq', '', TRUE);
            IF v_cur_state IS NOT NULL THEN
              PERFORM append_email_change(
                p_mailbox_id, v_cur_state, v_email_id, 'destroyed',
                COALESCE(v_draft_tag_id, v_msg.folder_id), v_msg.imap_uid
              );
            END IF;
          END;
        END IF;

        v_created := v_created || jsonb_build_object(v_creation_id, jsonb_build_object(
          'id', COALESCE(v_sent_id, v_email_id)::TEXT,
          'emailId', v_email_id::TEXT,
          -- T7: held for external-send approval (see above) → client shows "held",
          -- must NOT arm undo-send. v_sent_id IS NULL exactly when send() held it.
          'heldForApproval', (v_sent_id IS NULL)
        ));
      END IF;

    EXCEPTION WHEN OTHERS THEN
      v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
        jsonb_build_object(
          -- BZ004 (daily sending quota, raised by send()) maps to the RFC 8621
          -- SetError type the client can branch on. Flattening it to
          -- invalidArguments destroyed the classification at this boundary and
          -- the UI showed "Please try again" for a quota that resets tomorrow.
          'type', CASE WHEN SQLSTATE = 'BZ004' THEN 'overQuota' ELSE 'invalidArguments' END,
          'description', SQLERRM));
    END;
  END LOOP;

  -- Each per-submission path (immediate send → notify_state_change inside send();
  -- scheduled send → notify_state_change above) has already advanced
  -- jmap_email_state through the single owner. Read the authoritative current
  -- value for the JMAP response instead of open-coding another bump (which would
  -- double-count and bypass the trigger/helper).
  SELECT jmap_email_state INTO v_new_state FROM mailboxes WHERE id = p_mailbox_id;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'created', v_created,
    'notCreated', v_notCreated
  );
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/transition_message_location.sql (transition_message_location)
CREATE OR REPLACE FUNCTION transition_message_location(
    p_message_id            BIGINT,
    p_received_at           TIMESTAMPTZ,
    p_new_location_tag_name TEXT,
    p_mailbox_id            BIGINT,
    p_added_by              TEXT    DEFAULT 'user',
    p_notify                BOOLEAN DEFAULT TRUE
) RETURNS VOID AS $$
DECLARE
    v_loc_count INT;
    v_new_tag_id BIGINT;
BEGIN
    -- Canonical #481 lock order (mailboxes -> messages -> message_tags/tags).
    PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id FOR UPDATE;

    -- Guard against corrupt multi-location state: a message must carry 0 or 1
    -- location tags. >1 means the invariant was already broken upstream.
    SELECT count(*) INTO v_loc_count
    FROM message_tags mt
    JOIN tags t ON t.id = mt.tag_id
    WHERE mt.message_id = p_message_id
      AND mt.received_at = p_received_at
      AND t.mailbox_id = p_mailbox_id
      AND t.exclusive_group = 'location';

    IF v_loc_count > 1 THEN
        RAISE EXCEPTION 'message % carries % location tags (expected <=1)', p_message_id, v_loc_count
          USING ERRCODE = 'BZ035',
                HINT = jsonb_build_object('type', 'location_invariant_violation',
                                          'message_id', p_message_id,
                                          'count', v_loc_count)::TEXT;
    END IF;

    -- The atomic swap itself (remove old location tag(s), add the new one as
    -- primary) is the internal primitive. set_message_location resolves the tag
    -- in the mailbox and RAISEs BZ019 if it does not exist (also covers a foreign
    -- p_mailbox_id, which cannot resolve the tag — no cross-tenant write).
    PERFORM set_message_location(p_message_id, p_received_at, p_new_location_tag_name, p_mailbox_id, p_added_by);

    -- The location tag membership changed → bump email + tag state and push
    -- through the single owner exactly once for the whole swap, UNLESS the caller
    -- already emits the single push for this operation (p_notify = FALSE).
    IF p_notify THEN
        v_new_tag_id := get_tag_id(p_new_location_tag_name, p_mailbox_id);
        PERFORM notify_state_change(p_mailbox_id, v_new_tag_id, p_message_id, 'updated');
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/transition_message_location.sql (delete_draft_message)
CREATE OR REPLACE FUNCTION delete_draft_message(
    p_message_id  BIGINT,
    p_received_at TIMESTAMPTZ,
    p_mailbox_id  BIGINT,
    p_notify      BOOLEAN DEFAULT TRUE
) RETURNS VOID AS $$
DECLARE
    v_primary_tag BIGINT;
    v_imap_uid    BIGINT;
    v_folder_id   BIGINT;
    v_state       BIGINT;
    v_deleted     BOOLEAN := FALSE;
BEGIN
    -- Canonical #481 lock order (mailboxes -> messages -> message_tags).
    PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id FOR UPDATE;

    SELECT mt.tag_id
      INTO v_primary_tag
      FROM message_tags mt
      JOIN tags t ON t.id = mt.tag_id
     WHERE mt.message_id = p_message_id
       AND mt.received_at = p_received_at
       AND t.mailbox_id = p_mailbox_id
       AND mt.is_primary = TRUE
     LIMIT 1;

    -- Remove location-group tags first (counter triggers fire on DELETE),
    -- scoped to the owning mailbox.
    DELETE FROM message_tags mt
    USING tags t
    WHERE mt.message_id = p_message_id
      AND mt.received_at = p_received_at
      AND mt.tag_id = t.id
      AND t.mailbox_id = p_mailbox_id
      AND t.exclusive_group = 'location';

    -- Delete the message row; ownership in the same WHERE (R3, no TOCTOU).
    -- Capture imap_uid + folder_id BEFORE the row vanishes so QRESYNC VANISHED
    -- can report the exact vanished UID from jmap_changes_journal (#554).
    -- The message_tags FK (ON DELETE CASCADE) clears any remaining tags.
    DELETE FROM messages
    WHERE id = p_message_id
      AND received_at = p_received_at
      AND mailbox_id = p_mailbox_id
    RETURNING imap_uid, folder_id INTO v_imap_uid, v_folder_id;
    v_deleted := FOUND;

    -- Mailbox-wide change (message removed) → push through the single owner with
    -- precise (p_message_id, 'destroyed') ONLY when a row was actually deleted.
    -- Suppressed (p_notify = FALSE) when the caller already pushed the change.
    IF v_deleted AND p_notify THEN
        v_state := notify_state_change(p_mailbox_id, NULL, p_message_id, 'destroyed');
        IF v_state IS NOT NULL AND (v_imap_uid IS NOT NULL OR COALESCE(v_primary_tag, v_folder_id) IS NOT NULL) THEN
            PERFORM append_email_change(
                p_mailbox_id, v_state, p_message_id, 'destroyed',
                COALESCE(v_primary_tag, v_folder_id), v_imap_uid
            );
        END IF;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/message_snooze.sql (message_snooze)
CREATE OR REPLACE FUNCTION message_snooze(
    p_mailbox_id BIGINT,
    p_message_id BIGINT,
    p_until      TIMESTAMPTZ
) RETURNS JSONB AS $$
DECLARE
    v_received_at TIMESTAMPTZ;
    v_snooze_tag  BIGINT;
BEGIN
    -- Reject a snooze time that is not in the future.
    IF p_until IS NULL OR p_until <= now() THEN
        RAISE EXCEPTION 'Snooze time must be in the future'
            USING ERRCODE = 'BZ031',
                  HINT = jsonb_build_object('type', 'snooze_past', 'until', p_until)::TEXT;
    END IF;

    -- Canonical #481 lock order (mailboxes -> messages) before locking message row.
    PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id FOR UPDATE;

    -- R1: resolve the message AND verify ownership in the same statement.
    SELECT received_at INTO v_received_at
    FROM messages
    WHERE id = p_message_id AND mailbox_id = p_mailbox_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Message not found'
            USING ERRCODE = 'BZ030',
                  HINT = jsonb_build_object('type', 'message_not_found', 'message_id', p_message_id)::TEXT;
    END IF;

    -- Resolve the Snoozed system tag for this mailbox (scoped by p_mailbox_id).
    SELECT id INTO v_snooze_tag
    FROM tags
    WHERE mailbox_id = p_mailbox_id AND name = 'Snoozed' AND exclusive_group = 'snooze';

    IF v_snooze_tag IS NULL THEN
        RAISE EXCEPTION 'Snoozed tag missing for mailbox'
            USING ERRCODE = 'BZ030',
                  HINT = jsonb_build_object('type', 'snooze_tag_missing', 'mailbox_id', p_mailbox_id)::TEXT;
    END IF;

    -- First fact: apply the Snoozed tag. The message_tags BEFORE INSERT trigger
    -- removes any other 'snooze'-group tag (exclusivity); the counter trigger
    -- maintains tags.total_count/unread_count/jmap_state. We set is_primary FALSE so
    -- the existing location tag (Inbox) remains the IMAP primary. snooze_until is
    -- kept as an informational mirror; the authoritative wake-time is the
    -- scheduled_action's fire_at enqueued below.
    INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary, snooze_until)
    VALUES (p_message_id, v_received_at, v_snooze_tag, 'snooze', FALSE, p_until)
    ON CONFLICT (message_id, received_at, tag_id) DO UPDATE
        SET snooze_until = EXCLUDED.snooze_until,
            added_by     = EXCLUDED.added_by;

    -- Second fact: cancel any prior pending snooze action for this message, then
    -- enqueue the new deferred `snooze` action (re-snooze replaces the wake-time).
    PERFORM cancel_scheduled_action(p_mailbox_id, 'snooze',
        jsonb_build_object('message_id', p_message_id));
    PERFORM enqueue_scheduled_action('snooze', p_until,
        jsonb_build_object('message_id', p_message_id, 'received_at', v_received_at),
        p_mailbox_id);

    -- One call: bump email + tag state (the Snoozed tag membership changed) and
    -- push on the canonical tag:{mailbox_id} channel. The counter trigger has
    -- already bumped the per-tag jmap_state; notify_state_change leaves it alone.
    PERFORM notify_state_change(p_mailbox_id, v_snooze_tag, p_message_id, 'updated');

    RETURN jsonb_build_object(
        'snoozed', TRUE,
        'messageId', p_message_id::TEXT,
        'snoozeUntil', p_until
    );
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/scheduled_action_snooze.sql (scheduled_action_snooze)
CREATE OR REPLACE FUNCTION scheduled_action_snooze(p_action scheduled_actions)
RETURNS JSONB AS $$
DECLARE
    v_message_id  BIGINT;
    v_received_at TIMESTAMPTZ;
    v_mailbox_id  BIGINT := p_action.mailbox_id;
    v_snooze_tag  BIGINT;
    v_deleted     INT := 0;
    v_has_loc     BOOLEAN;
BEGIN
    v_message_id  := (p_action.payload->>'message_id')::BIGINT;
    v_received_at := (p_action.payload->>'received_at')::TIMESTAMPTZ;

    -- Defensive: a payload without a message reference is a no-op success (e.g. a
    -- bare action used only to exercise the dispatcher).
    IF v_message_id IS NULL OR v_received_at IS NULL OR v_mailbox_id IS NULL THEN
        RETURN jsonb_build_object('status', 'ok', 'note', 'no message to wake');
    END IF;

    -- Resolve the mailbox's Snoozed tag (snooze exclusive group), scoped to owner.
    SELECT id INTO v_snooze_tag
    FROM tags
    WHERE mailbox_id = v_mailbox_id AND name = 'Snoozed' AND exclusive_group = 'snooze';

    -- Clear the Snoozed tag for this message (mailbox-scoped, R3).
    IF v_snooze_tag IS NOT NULL THEN
        WITH del AS (
            DELETE FROM message_tags mt
            USING tags t
            WHERE mt.message_id = v_message_id
              AND mt.received_at = v_received_at
              AND mt.tag_id = t.id
              AND t.mailbox_id = v_mailbox_id
              AND t.exclusive_group = 'snooze'
            RETURNING 1
        )
        SELECT count(*) INTO v_deleted FROM del;
    END IF;

    -- Restore Inbox only if the message no longer carries a location tag (idempotent:
    -- if it is already in some location, leave it). transition_message_location does
    -- the state-bumping swap + push through notify_state_change.
    SELECT EXISTS (
        SELECT 1 FROM message_tags mt
        JOIN tags t ON t.id = mt.tag_id
        WHERE mt.message_id = v_message_id
          AND mt.received_at = v_received_at
          AND t.mailbox_id = v_mailbox_id
          AND t.exclusive_group = 'location'
    ) INTO v_has_loc;

    IF NOT v_has_loc THEN
        PERFORM transition_message_location(v_message_id, v_received_at, 'Inbox', v_mailbox_id);
    ELSIF v_deleted > 0 THEN
        -- Snoozed tag removed but a location already present → still a visibility
        -- change; push once (no new location tag, so mailbox-wide bump).
        PERFORM notify_state_change(v_mailbox_id, NULL, v_message_id, 'updated');
    END IF;

    RETURN jsonb_build_object('status', 'ok', 'note', 'woken');
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/quarantine_message.sql (quarantine_message)
CREATE OR REPLACE FUNCTION quarantine_message(
    p_message_id  BIGINT,
    p_mailbox_id  BIGINT,
    p_reason      TEXT,
    p_reason_type TEXT    DEFAULT 'virus',
    p_virus_name  TEXT    DEFAULT NULL,
    p_notify      BOOLEAN DEFAULT TRUE
) RETURNS VOID AS $$
DECLARE
    v_received_at  TIMESTAMPTZ;
    v_quar_tag_id  BIGINT;
    v_original_tag TEXT;
BEGIN
    -- Canonical #481 lock order (mailboxes -> messages -> message_tags/tags).
    PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id FOR UPDATE;

    -- Ensure the Quarantined system tag exists in the target mailbox. The
    -- per-mailbox tag seed (create_system_tags) has never included it, so any
    -- mailbox created after the seed migration would BZ074-abort the whole
    -- quarantine and leave condemned mail in Inbox — exactly the outcome this
    -- seam exists to prevent (D-MAILSERVER-INTERNAL-SMTP-V003: the clamd
    -- verdict must fail CLOSED into the quarantine). Idempotent and
    -- CONFLICT-SAFE system-tag insert (med-shard2-002 item 3): two concurrent
    -- first quarantines in the same mailbox can both pass the old
    -- INSERT … WHERE NOT EXISTS check and race the unique (mailbox_id,name)
    -- constraint, aborting one transaction with its message left
    -- unquarantined; ON CONFLICT DO NOTHING lets the loser wait out the
    -- winner's insert and proceed. The unique key is
    -- tags_mailbox_id_name_key (V001 baseline).
    INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group, sort_order, imap_expose, imap_uid_validity)
    VALUES (p_mailbox_id, 'Quarantined', 'system', 'quarantine', 900, FALSE, EXTRACT(EPOCH FROM now())::BIGINT)
    ON CONFLICT (mailbox_id, name) DO NOTHING;

    -- Resolve the Quarantined tag IN the owning mailbox. A foreign p_mailbox_id
    -- cannot resolve it → BZ074 (R3: no cross-tenant write, no audit row).
    v_quar_tag_id := get_tag_id('Quarantined', p_mailbox_id);
    IF v_quar_tag_id IS NULL THEN
        RAISE EXCEPTION 'Quarantined tag not found in mailbox %', p_mailbox_id
          USING ERRCODE = 'BZ074',
                HINT = jsonb_build_object('type', 'quarantine_target_not_found',
                                          'message_id', p_message_id,
                                          'mailbox_id', p_mailbox_id)::TEXT;
    END IF;

    -- Resolve the message's received_at AND its REAL current location tag, scoped
    -- to the owning mailbox (R3). A foreign/absent message yields no row → BZ074
    -- (not-found / forbidden), nothing mutated.
    SELECT m.received_at,
           (SELECT t.name
              FROM message_tags mt
              JOIN tags t ON t.id = mt.tag_id
             WHERE mt.message_id  = m.id
               AND mt.received_at = m.received_at
               AND t.mailbox_id   = p_mailbox_id
               AND t.exclusive_group = 'location'
             LIMIT 1)
      INTO v_received_at, v_original_tag
      FROM messages m
     WHERE m.id         = p_message_id
       AND m.mailbox_id = p_mailbox_id;

    IF v_received_at IS NULL THEN
        RAISE EXCEPTION 'message % not found in mailbox %', p_message_id, p_mailbox_id
          USING ERRCODE = 'BZ074',
                HINT = jsonb_build_object('type', 'quarantine_message_not_found',
                                          'message_id', p_message_id,
                                          'mailbox_id', p_mailbox_id)::TEXT;
    END IF;

    -- Record the real original location; only fall back to 'Inbox' when the
    -- message carries no location tag at all (column is NOT NULL).
    v_original_tag := COALESCE(v_original_tag, 'Inbox');

    -- Remove the message's location-group tag(s) for this mailbox (it leaves
    -- Inbox/wherever). Counter triggers (trg_message_tags_counters) maintain
    -- tags.total_count / unread_count on the DELETE.
    DELETE FROM message_tags mt
    USING tags t
    WHERE mt.message_id  = p_message_id
      AND mt.received_at = v_received_at
      AND mt.tag_id      = t.id
      AND t.mailbox_id   = p_mailbox_id
      AND t.exclusive_group = 'location';

    -- Add the Quarantined (quarantine-group) tag as the primary tag. tag_message
    -- resolves it in p_mailbox_id again (R3) and the BEFORE INSERT exclusive
    -- trigger keeps the quarantine group singular.
    PERFORM tag_message(p_message_id, v_received_at, 'Quarantined', p_mailbox_id, 'system', TRUE);

    -- One audit row, with the REAL original location.
    INSERT INTO quarantined_messages
        (message_id, mailbox_id, original_tag, reason, reason_type, virus_name)
    VALUES
        (p_message_id, p_mailbox_id, v_original_tag, p_reason, p_reason_type, p_virus_name);

    -- The tag membership changed → push the change through the single owner so the
    -- webmail learns of the quarantine immediately (the named fix). Suppressible
    -- via p_notify = FALSE for strict behavior-preservation.
    IF p_notify THEN
        PERFORM notify_state_change(p_mailbox_id, v_quar_tag_id, p_message_id, 'updated');
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/release_quarantine_tags.sql (release_quarantine_tags)
CREATE OR REPLACE FUNCTION release_quarantine_tags(
    p_message_id   BIGINT,
    p_mailbox_id   BIGINT,
    p_original_tag TEXT,
    p_notify       BOOLEAN DEFAULT TRUE
) RETURNS VOID AS $$
DECLARE
    v_received_at TIMESTAMPTZ;
    v_quar_tag_id BIGINT;
BEGIN
    -- Canonical #481 lock order (mailboxes -> messages -> message_tags/tags).
    PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id FOR UPDATE;

    v_quar_tag_id := get_tag_id('Quarantined', p_mailbox_id);

    -- Source the message's real received_at (the composite-FK partition key), scoped
    -- to the owning mailbox (R3). A foreign/absent message yields no row → BZ074.
    SELECT received_at INTO v_received_at
      FROM messages
     WHERE id = p_message_id AND mailbox_id = p_mailbox_id;
    IF v_received_at IS NULL THEN
        RAISE EXCEPTION 'message % not found in mailbox %', p_message_id, p_mailbox_id
          USING ERRCODE = 'BZ074',
                HINT = jsonb_build_object('type', 'quarantine_message_not_found',
                                          'message_id', p_message_id,
                                          'mailbox_id', p_mailbox_id)::TEXT;
    END IF;

    -- Remove the Quarantined (quarantine-group) tag for this mailbox. Counter
    -- triggers maintain tags.total_count / unread_count on the DELETE.
    DELETE FROM message_tags mt
    USING tags t
    WHERE mt.message_id  = p_message_id
      AND mt.received_at = v_received_at
      AND mt.tag_id      = t.id
      AND t.mailbox_id   = p_mailbox_id
      AND t.name         = 'Quarantined';

    -- Restore the recorded original location tag with the FK-correct received_at.
    -- tag_message resolves the tag IN p_mailbox_id again (R3) and the exclusive
    -- trigger keeps the location group singular.
    PERFORM tag_message(p_message_id, v_received_at, p_original_tag, p_mailbox_id, 'system', TRUE);

    -- Tag membership changed → push through the single owner so the client sees the
    -- message return to its folder immediately. Suppressible via p_notify = FALSE.
    IF p_notify AND v_quar_tag_id IS NOT NULL THEN
        PERFORM notify_state_change(p_mailbox_id, v_quar_tag_id, p_message_id, 'updated');
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/rule_engine.sql (apply_action)
CREATE OR REPLACE FUNCTION apply_action(
  p_message_id  BIGINT,
  p_received_at TIMESTAMPTZ,
  p_mailbox_id  BIGINT,
  v_action      JSONB,
  p_rule_id     BIGINT,
  p_organize_only BOOLEAN DEFAULT FALSE
) RETURNS VOID AS $$
DECLARE
  v_type      TEXT := v_action->>'type';
  v_params    JSONB := v_action->'params';
  v_folder_id BIGINT;
  v_old_folder BIGINT;
  v_is_read BOOL;
BEGIN
  -- Retro sweep (organize_only) must NOT re-fire send-time actions: forward_to /
  -- redirect / bcc queue or mutate the outbound recipient set, add_header /
  -- append_footer inject into outbound MIME — replaying any of them over
  -- historical mail would mass re-send. Organize actions (move_to / flag /
  -- mark_read / categorize / delete / discard) reshape only the local mailbox
  -- and still run. Single root-cause guard in the shared reducer (all callers
  -- route through here), not a fork.
  IF p_organize_only AND v_type IN ('forward_to','redirect','bcc','append_footer','add_header') THEN
    RETURN;
  END IF;

  CASE v_type

    WHEN 'move_to' THEN
      SELECT id INTO v_folder_id FROM tags
      WHERE mailbox_id = p_mailbox_id
        AND (name = v_params->>'folder' OR name = v_params->>'role')
      LIMIT 1;
      IF v_folder_id IS NOT NULL THEN
        -- Move + notify consolidated into the single location seam (it does the
        -- atomic swap AND the one notify_state_change with the new tag id —
        -- equivalent to the prior set_message_location + notify pair).
        PERFORM transition_message_location(
          p_message_id, p_received_at, (SELECT name FROM tags WHERE id = v_folder_id), p_mailbox_id, 'rule');
      END IF;

    WHEN 'flag' THEN
      UPDATE messages SET is_flagged = TRUE
      WHERE id = p_message_id AND received_at = p_received_at
        AND mailbox_id = p_mailbox_id;
      -- Mailbox-wide change (no single tag) → bump email state and push.
      PERFORM notify_state_change(p_mailbox_id, NULL, p_message_id, 'updated');

    WHEN 'mark_read' THEN
      DECLARE
        v_already_read BOOL;
      BEGIN
        SELECT is_read INTO v_already_read FROM messages
        WHERE id = p_message_id AND received_at = p_received_at;
        UPDATE messages SET is_read = TRUE
        WHERE id = p_message_id AND received_at = p_received_at
          AND mailbox_id = p_mailbox_id;
        -- Adjust tag unread counts for all tags on this message. The per-tag
        -- jmap_state bump here is the counter side (orthogonal to the
        -- mailbox-level email-state bump done by notify_state_change below).
        IF NOT v_already_read THEN
          UPDATE tags SET
            unread_count = GREATEST(0, unread_count - 1),
            jmap_state = jmap_state + 1
          WHERE id IN (
            SELECT tag_id FROM message_tags
            WHERE message_id = p_message_id AND received_at = p_received_at
          );
        END IF;
      END;
      -- Mailbox-wide change (read flag) → bump email state and push.
      PERFORM notify_state_change(p_mailbox_id, NULL, p_message_id, 'updated');

    WHEN 'categorize' THEN
      UPDATE messages SET
        categories = array_append(categories, v_params->>'category')
      WHERE id = p_message_id AND received_at = p_received_at
        AND mailbox_id = p_mailbox_id
        AND NOT (v_params->>'category' = ANY(categories));
      -- Mailbox-wide change → bump email state and push only if row changed.
      IF FOUND THEN
        PERFORM notify_state_change(p_mailbox_id, NULL, p_message_id, 'updated');
      END IF;

    WHEN 'delete' THEN
      -- Move to Trash + notify consolidated into the single location seam (it
      -- resolves the Trash tag id and emits the one notify_state_change).
      PERFORM transition_message_location(p_message_id, p_received_at, 'Trash', p_mailbox_id, 'rule');

    WHEN 'discard' THEN
      IF NOT (SELECT litigation_hold FROM mailboxes WHERE id = p_mailbox_id) THEN
        -- Single owning reducer: remove location tags (mailbox-scoped, R3) +
        -- delete the message + push the mailbox-wide state change exactly once.
        PERFORM delete_draft_message(p_message_id, p_received_at, p_mailbox_id);
      END IF;

    WHEN 'forward_to' THEN
      -- Queue a copy for forwarding via the outbound SMTP pipeline.
      -- LINK-PROTECT rail (security correctness): the stored raw_ref body of an
      -- inbound message has had external URLs rewritten to the RECIPIENT's
      -- /link-protect?token=… redirects, which (a) are broken for the forward
      -- target and (b) leak the recipient mailbox_id + message_id encoded in the
      -- HMAC token. forward_unwrap_links=TRUE makes the Go egress un-rewrite those
      -- tokens back to the original URLs before signing/transmission, so the
      -- forwarded copy never re-emits the recipient's protected redirects.
      INSERT INTO outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status, forward_unwrap_links)
      SELECT message_id,
             'noreply-forward@' || COALESCE(
               (SELECT name FROM domains WHERE is_primary = TRUE LIMIT 1),
               (SELECT name FROM domains WHERE is_local = TRUE LIMIT 1),
               'localhost'
             ),
             ARRAY[v_params->>'address'],
             raw_ref,
             'pending',
             TRUE
      FROM messages WHERE id = p_message_id AND received_at = p_received_at;

    WHEN 'add_header' THEN
      -- Stored as metadata; Go SMTP layer injects into outbound messages.
      UPDATE messages SET spam_headers =
        coalesce(spam_headers,'{}') || jsonb_build_object(
          'X-Rule-' || p_rule_id::TEXT, v_params->>'value')
      WHERE id = p_message_id AND received_at = p_received_at
        AND mailbox_id = p_mailbox_id;

    WHEN 'bcc' THEN
      -- Silent copy: appended to bcc_addrs — never a visible header (that's the
      -- definition of BCC). Mirrors the existing per-identity auto-BCC in
      -- send.sql (the "Auto-BCC" step); send() re-reads bcc_addrs from this row
      -- right after apply_rules() so a rule-added BCC reaches the real outbound
      -- recipient set (SMTP envelope RCPT TO / local deliver() fan-out), not
      -- just this row. Deduped so a stacked/repeated bcc action targeting the
      -- same address doesn't add it twice.
      UPDATE messages SET bcc_addrs =
        COALESCE(bcc_addrs, '[]'::JSONB) || jsonb_build_array(
          jsonb_build_object('email', lower(v_params->>'address')))
      WHERE id = p_message_id AND received_at = p_received_at
        AND mailbox_id = p_mailbox_id
        AND NOT COALESCE(bcc_addrs, '[]'::JSONB) @> jsonb_build_array(
          jsonb_build_object('email', lower(v_params->>'address')));

    WHEN 'append_footer' THEN
      -- Disclaimer/footer append. Idempotent (skips if the exact text is
      -- already present, so stacked footer actions append once) — same guard
      -- style as the identity-signature append in send.sql. Reaches the Sent
      -- copy, any local recipient's stored copy, and JMAP body rendering
      -- (message_to_jmap_email reads body_text/body_html directly). KNOWN
      -- CEILING (ponytail): this does NOT rewrite the wire raw_ref MIME blob,
      -- so an externally-SMTP-relayed recipient's own mail client (or this
      -- server's IMAP FETCH, which serves raw_ref verbatim) will not see it —
      -- the same pre-existing gap the identity-signature append already has.
      -- Upgrade path if wire-level disclaimer injection becomes a real need:
      -- Go-side raw_ref MIME rewrite in the outbound worker, mirroring the
      -- existing link-protect-unwrap/DKIM-sign step (internal/smtp/outbound.go).
      -- SP1: skipped entirely on the encrypted-at-rest path (crypto_type =
      -- 'smime-encrypted') — body_text/body_html are NULL by design there
      -- (raw_ref carries the ciphertext); appending would inject a cleartext
      -- footer into a column that must stay NULL.
      UPDATE messages SET
        body_text = CASE
          WHEN COALESCE(body_text,'') LIKE '%' || (v_params->>'text') || '%' THEN body_text
          ELSE COALESCE(body_text,'') || E'\n\n' || (v_params->>'text')
        END,
        body_html = CASE
          WHEN body_html IS NULL THEN NULL
          WHEN body_html LIKE '%' || replace(v_params->>'text', E'\n', '<br>') || '%' THEN body_html
          ELSE body_html || '<br><br>' || replace(v_params->>'text', E'\n', '<br>')
        END
      WHERE id = p_message_id AND received_at = p_received_at
        AND mailbox_id = p_mailbox_id
        AND crypto_type IS DISTINCT FROM 'smime-encrypted';

    WHEN 'redirect' THEN
      -- Exchange-parity semantics: REDIRECT REPLACES the recipient set (to/cc/
      -- bcc all become just the redirect target) — the original addressee is
      -- never notified (no bounce, no forward-marker; their copy is simply
      -- never queued/delivered). This differs deliberately from forward_to,
      -- which ADDS a copy alongside normal delivery. send() re-reads to/cc/
      -- bcc_addrs from this row right after apply_rules() so the replacement
      -- reaches the real outbound recipient set.
      -- Loop protection: no new primitive is needed. Unlike distribution-group
      -- expansion (deliver()'s p_depth recursion guard, capped at 10), redirect
      -- fires once per send() call and does not re-invoke apply_rules against
      -- the new target — there is nothing here that can recurse within a
      -- single send.
      UPDATE messages SET
        to_addrs = jsonb_build_array(jsonb_build_object('email', lower(v_params->>'address'))),
        cc_addrs = '[]'::JSONB,
        bcc_addrs = '[]'::JSONB
      WHERE id = p_message_id AND received_at = p_received_at
        AND mailbox_id = p_mailbox_id;

    ELSE
      RAISE WARNING 'rule_engine: unknown action type % for rule_id=%', v_action, p_rule_id;
  END CASE;
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/rule_engine_or.sql (apply_rules)
CREATE OR REPLACE FUNCTION apply_rules(
  p_message_id  BIGINT,
  p_received_at TIMESTAMPTZ,
  p_mailbox_id  BIGINT,
  p_side        TEXT,
  p_organize_only BOOLEAN DEFAULT FALSE,
  p_rule_id     BIGINT DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
  v_msg        RECORD;
  v_orig_msgid TEXT;
  v_orig_from  TEXT;
  v_discarded  BOOL := FALSE;
  v_rule       RECORD;
  v_item       JSONB;
  v_action     JSONB;
  v_matched    BOOL;
BEGIN
  -- Bound delivery-path latency only. The retro sweep (p_organize_only=TRUE)
  -- runs up to c_cap statements in ONE transaction as a background scheduled
  -- action; a transaction-wide 1s statement cap there just makes the sweep
  -- flaky on large/busy databases (CI saw 'canceling statement due to
  -- statement timeout' inside apply_rules' messages lookup).
  IF NOT p_organize_only THEN
    PERFORM set_config('statement_timeout', '1000ms', true);
  END IF;

  IF p_side NOT IN ('server', 'outbound') THEN
    RAISE EXCEPTION 'invalid rule evaluation side: %', p_side USING ERRCODE = 'BZ010';
  END IF;

  -- Guard: prevent runaway rule count from degrading delivery performance
  IF (SELECT COUNT(*) FROM rules r
      WHERE r.enabled = TRUE
        AND r.run_on IN ('server', 'both')
        AND (
          (r.is_transport_rule = TRUE)
          OR (p_side = 'server' AND r.is_transport_rule = FALSE AND r.mailbox_id = p_mailbox_id)
        )) > 200 THEN
    RAISE WARNING 'too_many_rules: mailbox % has >200 active rules, delivery performance may degrade', p_mailbox_id;
  END IF;

  SELECT * INTO v_msg FROM messages
  WHERE id = p_message_id AND received_at = p_received_at
    AND mailbox_id = p_mailbox_id;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  v_orig_msgid := v_msg.message_id;
  v_orig_from  := v_msg.from_addr;

  FOR v_rule IN
    SELECT r.* FROM rules r
    WHERE r.enabled = TRUE
      AND r.run_on IN ('server', 'both')
      AND (p_rule_id IS NULL OR r.id = p_rule_id)
      AND (
        (r.is_transport_rule = TRUE)
        OR
        (p_side = 'server'
         AND r.is_transport_rule = FALSE
         AND r.mailbox_id = p_mailbox_id)
      )
    ORDER BY r.is_transport_rule DESC, r.priority ASC, r.id ASC
  LOOP
    BEGIN
      -- Evaluate conditions using the new group-aware function.
      -- If conditions is a flat array, eval_conditions handles each element.
      -- If conditions is a single group object, it handles that too.
      v_matched := TRUE;
      IF jsonb_typeof(v_rule.conditions) = 'array' THEN
        -- Flat array of conditions — implicit AND
        FOR v_item IN SELECT * FROM jsonb_array_elements(v_rule.conditions) LOOP
          IF NOT eval_conditions(v_msg, v_item) THEN
            v_matched := FALSE;
            EXIT;
          END IF;
        END LOOP;
      ELSIF jsonb_typeof(v_rule.conditions) = 'object' THEN
        -- Single condition or group object
        v_matched := eval_conditions(v_msg, v_rule.conditions);
      END IF;

      IF NOT v_matched THEN
        CONTINUE;
      END IF;

      FOR v_action IN SELECT * FROM jsonb_array_elements(v_rule.actions) LOOP
        PERFORM apply_action(p_message_id, p_received_at, p_mailbox_id, v_action, v_rule.id, p_organize_only);
        SELECT * INTO v_msg FROM messages
        WHERE id = p_message_id AND received_at = p_received_at
          AND mailbox_id = p_mailbox_id;
        IF NOT FOUND THEN
          v_discarded := TRUE;
          EXIT;
        END IF;
      END LOOP;

      PERFORM trace(COALESCE(v_msg.message_id, v_orig_msgid), 'rule_applied', COALESCE(v_msg.from_addr, v_orig_from), '',
        NULL, jsonb_build_object('rule_id', v_rule.id, 'rule_name', v_rule.name));

      IF v_discarded OR v_rule.stop_processing THEN
        EXIT;
      END IF;

    EXCEPTION
      WHEN invalid_text_representation OR invalid_regular_expression THEN
        PERFORM trace(COALESCE(v_msg.message_id, v_orig_msgid), 'rule_applied', COALESCE(v_msg.from_addr, v_orig_from), '',
          NULL, jsonb_build_object('rule_id', v_rule.id, 'status', 'skipped_invalid_condition'));
        CONTINUE;
      WHEN OTHERS THEN
        PERFORM trace(COALESCE(v_msg.message_id, v_orig_msgid), 'rule_applied', COALESCE(v_msg.from_addr, v_orig_from), '',
          NULL, jsonb_build_object('rule_id', v_rule.id, 'status', 'skipped_error', 'error', 'rule evaluation failed'));
        CONTINUE;
    END;
  END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/quick_steps.sql (quick_step_apply)
CREATE OR REPLACE FUNCTION quick_step_apply(
  p_mailbox_id BIGINT, p_id BIGINT, p_message_id BIGINT, p_received_at TIMESTAMPTZ
) RETURNS VOID AS $$
DECLARE
  v_actions JSONB;
  v_action  JSONB;
  v_type    TEXT;
BEGIN
  SELECT actions INTO v_actions FROM quick_steps
  WHERE id = p_id AND mailbox_id = p_mailbox_id;       -- R1: filter by mailbox
  IF v_actions IS NULL THEN
    RAISE EXCEPTION 'quick step not found'
      USING ERRCODE = 'BZ042', HINT = '{"type":"notFound"}';
  END IF;

  -- Canonical #481 lock order (mailboxes -> messages).
  PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id FOR UPDATE;

  -- Guard: the message must belong to this mailbox (R3 / no TOCTOU).
  PERFORM 1 FROM messages
    WHERE id = p_message_id AND received_at = p_received_at AND mailbox_id = p_mailbox_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'message not in mailbox'
      USING ERRCODE = 'BZ042', HINT = '{"type":"notFound"}';
  END IF;

  FOR v_action IN SELECT * FROM jsonb_array_elements(v_actions) LOOP
    v_type := v_action->>'type';
    -- Re-enforce the allowlist at apply time. A row that predates the set-time
    -- guard (or was tampered with) cannot smuggle a privileged action.
    IF NOT quick_step_action_allowed(v_type) THEN
      RAISE EXCEPTION 'quick step action type not allowed: %', COALESCE(v_type, '(null)')
        USING ERRCODE = 'BZ043', HINT = '{"type":"forbiddenAction"}';
    END IF;
    -- p_rule_id is NULL: only add_header reads it, and add_header is not allowed.
    PERFORM apply_action(p_message_id, p_received_at, p_mailbox_id, v_action, NULL);
  END LOOP;

  -- apply_action already pushes per-action via notify_state_change; a final
  -- precise bump guarantees a state change even for a macro whose actions
  -- all no-op'd (e.g. categorize a category already present) without emitting a
  -- 'resync' sentinel.
  PERFORM notify_state_change(p_mailbox_id, NULL, p_message_id, 'updated');
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/scheduled_action_rules_retro.sql (scheduled_action_rules_retro)
CREATE OR REPLACE FUNCTION scheduled_action_rules_retro(p_action scheduled_actions)
RETURNS JSONB AS $$
DECLARE
    v_mailbox_id BIGINT := p_action.mailbox_id;
    v_rule_id    BIGINT;
    v_window     TEXT;
    v_cutoff     TIMESTAMPTZ;
    v_msg        RECORD;
    v_seen          INT      := 0;
    v_processed     INT      := 0;
    v_truncated     BOOLEAN  := FALSE;
    c_cap CONSTANT INT := 5000;  -- ponytail: fixed cap; make it a system_config knob if a tenant needs deeper sweeps
BEGIN
    IF v_mailbox_id IS NULL THEN
        RETURN jsonb_build_object('status','ok','note','no mailbox','processed',0,'truncated',false);
    END IF;

    v_rule_id := NULLIF(p_action.payload->>'rule_id','')::BIGINT;
    v_window  := COALESCE(p_action.payload->>'window','90d');

    v_cutoff := CASE v_window
        WHEN '90d' THEN now() - interval '90 days'
        WHEN '1y'  THEN now() - interval '1 year'
        WHEN 'all' THEN NULL
        ELSE now() - interval '90 days'
    END;

    -- Sweep newest-first; pull one past the cap to detect truncation honestly.
    -- Every organizing action in apply_action (move_to, flag, mark_read,
    -- categorize, delete, discard) already emits its own precise journal row
    -- ('updated' or 'destroyed') + state bump via notify_state_change (#554).
    -- Non-matching candidates therefore emit ZERO spurious journal rows.
    FOR v_msg IN
        SELECT id, received_at
        FROM messages
        WHERE mailbox_id = v_mailbox_id
          AND (v_cutoff IS NULL OR received_at >= v_cutoff)
        ORDER BY received_at DESC
        LIMIT c_cap + 1
    LOOP
        v_seen := v_seen + 1;
        IF v_seen > c_cap THEN
            v_truncated := TRUE;
            EXIT;
        END IF;
        -- organize_only=TRUE: send-time actions are no-ops (no mass re-send).
        PERFORM apply_rules(v_msg.id, v_msg.received_at, v_mailbox_id, 'server', TRUE, v_rule_id);
        v_processed := v_processed + 1;
    END LOOP;

    -- Persist the outcome onto the action so the status read path can report it.
    UPDATE scheduled_actions
       SET payload = payload || jsonb_build_object('processed', v_processed, 'truncated', v_truncated)
     WHERE id = p_action.id;

    RETURN jsonb_build_object(
        'status','ok',
        'note', format('applied to %s message(s)%s', v_processed,
                       CASE WHEN v_truncated THEN ' (truncated at cap)' ELSE '' END),
        'processed', v_processed,
        'truncated', v_truncated);
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/set_message_focus.sql (set_message_focus)
CREATE OR REPLACE FUNCTION set_message_focus(
    p_message_id  BIGINT,
    p_received_at TIMESTAMPTZ,
    p_focused     BOOL,
    p_mailbox_id  BIGINT
) RETURNS VOID AS $$
DECLARE
    v_other_id BIGINT;
    v_sender   TEXT;
    v_user_id  BIGINT;
BEGIN
    -- Canonical #481 lock order (mailboxes -> messages) before any message/tag writes.
    PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id FOR UPDATE;

    v_other_id := get_tag_id('Other', p_mailbox_id);
    IF v_other_id IS NULL THEN
        RAISE EXCEPTION 'mailbox % has no Other tag', p_mailbox_id
          USING ERRCODE = 'BZ019',
                HINT = jsonb_build_object('type', 'tag_not_found', 'tag_name', 'Other', 'mailbox_id', p_mailbox_id)::TEXT;
    END IF;

    -- Resolve the message's real sender, scoped to this mailbox (R1/R3 — ownership
    -- in the same statement, no TOCTOU). Missing → not the caller's message.
    SELECT lower(from_addr) INTO v_sender
    FROM messages
    WHERE id = p_message_id AND received_at = p_received_at AND mailbox_id = p_mailbox_id;
    IF v_sender IS NULL THEN
        RAISE EXCEPTION 'message % not found in mailbox %', p_message_id, p_mailbox_id
          USING ERRCODE = 'BZ006',
                HINT = jsonb_build_object('type', 'not_found', 'message_id', p_message_id)::TEXT;
    END IF;

    IF p_focused THEN
        -- Focused: strip the Other tag (scoped delete, mirrors set_message_location).
        DELETE FROM message_tags mt
        USING tags t
        WHERE mt.message_id = p_message_id
          AND mt.received_at = p_received_at
          AND mt.tag_id = t.id
          AND t.mailbox_id = p_mailbox_id
          AND t.name = 'Other';
    ELSE
        -- Other: add the Other tag (idempotent — skip if already present, since
        -- tag_message inserts unconditionally and message_tags pk would reject a dup).
        IF NOT EXISTS (
            SELECT 1 FROM message_tags
            WHERE message_id = p_message_id AND received_at = p_received_at AND tag_id = v_other_id
        ) THEN
            PERFORM tag_message(p_message_id, p_received_at, 'Other', p_mailbox_id, 'user', FALSE);
        END IF;
    END IF;

    -- Remember the per-sender preference (keyed on the user behind the mailbox).
    SELECT user_id INTO v_user_id FROM account_scope(p_mailbox_id);
    IF v_user_id IS NOT NULL THEN
        INSERT INTO focus_sender_overrides (user_id, sender, focused)
        VALUES (v_user_id, v_sender, p_focused)
        ON CONFLICT (user_id, sender) DO UPDATE SET focused = EXCLUDED.focused, updated_at = now();
    END IF;

    PERFORM notify_state_change(p_mailbox_id, v_other_id, p_message_id, 'updated');
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/content_purge.sql (content_purge_messages)
CREATE OR REPLACE FUNCTION content_purge_messages(
  p_message_ids    BIGINT[],
  p_admin_user     TEXT,
  p_reason         TEXT,
  p_admin_user_id  BIGINT DEFAULT NULL
) RETURNS TABLE(deleted_count INT, held_count INT, not_found_count INT) AS $$
DECLARE
  v_id          BIGINT;
  v_deleted     INT := 0;
  v_held        INT := 0;
  v_not_found   INT := 0;
  v_affected    BIGINT[] := '{}';
  v_mailbox_ids BIGINT[] := '{}';
  v_mbid        BIGINT;
  v_imap_uid    BIGINT;
  v_folder_id   BIGINT;
  v_primary_tag BIGINT;
  v_state       BIGINT;
BEGIN
  -- Lock affected mailboxes in deterministic ascending order before deleting
  -- messages (#481 canonical lock order: mailboxes -> messages).
  PERFORM 1
    FROM mailboxes
   WHERE id IN (
     SELECT DISTINCT mailbox_id
       FROM messages
      WHERE id = ANY(p_message_ids)
   )
   ORDER BY id
   FOR UPDATE;

  FOREACH v_id IN ARRAY p_message_ids LOOP
    BEGIN
      SELECT mt.tag_id INTO v_primary_tag
        FROM message_tags mt
        JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
       WHERE m.id = v_id AND mt.is_primary = TRUE
       LIMIT 1;

      DELETE FROM messages WHERE id = v_id
      RETURNING mailbox_id, imap_uid, folder_id INTO v_mbid, v_imap_uid, v_folder_id;
      IF NOT FOUND THEN
        v_not_found := v_not_found + 1;
        CONTINUE;
      END IF;

      -- Emit precise 'destroyed' journal delta + state bump so JMAP/IMAP QRESYNC
      -- clients immediately observe compliance-purged UIDs (#554).
      v_state := notify_state_change(v_mbid, NULL, v_id, 'destroyed');
      IF v_state IS NOT NULL AND (v_imap_uid IS NOT NULL OR COALESCE(v_primary_tag, v_folder_id) IS NOT NULL) THEN
        PERFORM append_email_change(
          v_mbid, v_state, v_id, 'destroyed', COALESCE(v_primary_tag, v_folder_id), v_imap_uid
        );
      END IF;

      v_deleted := v_deleted + 1;
      v_affected := array_append(v_affected, v_id);
      IF NOT v_mbid = ANY(v_mailbox_ids) THEN
        v_mailbox_ids := array_append(v_mailbox_ids, v_mbid);
      END IF;
    EXCEPTION WHEN SQLSTATE 'BZ015' THEN
      -- ONLY the litigation-hold trigger (trg_messages_hold_check raises BZ015) is a
      -- "skip this row, keep going" outcome. Catching WHEN OTHERS silently miscounted
      -- every other failure (OOM, constraint/permission error, replication lag) as a
      -- litigation hold and returned apparent success to the compliance admin. Let any
      -- non-BZ015 exception propagate so the purge fails loudly instead of lying.
      v_held := v_held + 1;
    END;
  END LOOP;

  -- Single audit log entry for the batch (NULL ip: reducer-origin rows pass NULL, not '0.0.0.0')
  PERFORM audit_write(
    p_admin_user_id,
    'content_purge',
    'message',
    NULL,
    jsonb_build_object(
      'admin_user', p_admin_user,
      'reason', p_reason,
      'deleted_ids', v_affected,
      'deleted_count', v_deleted,
      'held_count', v_held,
      'not_found_count', v_not_found,
      'mailbox_ids', v_mailbox_ids,
      'purged_at', now()
    ),
    NULL,
    NULL,
    NULL,
    'core'
  );

  RETURN QUERY SELECT v_deleted, v_held, v_not_found;
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/retention.sql (enforce_retention)
CREATE OR REPLACE FUNCTION enforce_retention(p_batch_size INT DEFAULT 1000) RETURNS INT AS $$
DECLARE
  v_row             RECORD;
  v_new_email_state BIGINT;
  v_deleted         INT := 0;
BEGIN
  -- Canonical #481 lock order: pre-lock all distinct affected mailboxes in
  -- deterministic ascending order before deleting retention tags / messages.
  PERFORM 1
    FROM mailboxes
   WHERE id IN (
     SELECT DISTINCT m.mailbox_id
       FROM (
         SELECT t.message_id, t.received_at
           FROM message_retention_tags t
           JOIN retention_policies p ON p.id = t.policy_id
          WHERE t.expires_at IS NOT NULL
            AND t.expires_at <= now()
            AND p.action = 'delete'
          ORDER BY t.expires_at
          LIMIT p_batch_size
       ) due
       JOIN messages m ON m.id = due.message_id AND m.received_at = due.received_at
   )
   ORDER BY id
   FOR UPDATE;

  FOR v_row IN
    SELECT t.message_id, t.received_at, p.action,
           m.message_id AS rfc_msgid, m.from_addr, m.mailbox_id,
           m.size_bytes, m.imap_uid, m.folder_id,
           (SELECT mt.tag_id FROM message_tags mt
             WHERE mt.message_id = m.id AND mt.received_at = m.received_at AND mt.is_primary = TRUE
             LIMIT 1) AS primary_tag_id
    FROM message_retention_tags t
    JOIN retention_policies p ON p.id = t.policy_id
    JOIN messages m ON m.id = t.message_id AND m.received_at = t.received_at
    WHERE t.expires_at IS NOT NULL
      AND t.expires_at <= now()
      AND p.action = 'delete'
    ORDER BY t.expires_at
    LIMIT p_batch_size
  LOOP
    BEGIN
      PERFORM 1 FROM mailboxes WHERE id = v_row.mailbox_id FOR UPDATE;

      DELETE FROM message_retention_tags
      WHERE message_id = v_row.message_id AND received_at = v_row.received_at;

      DELETE FROM messages
      WHERE id = v_row.message_id AND received_at = v_row.received_at;
      IF NOT FOUND THEN
        CONTINUE;
      END IF;

      PERFORM trace(v_row.rfc_msgid, 'expired', v_row.from_addr, '',
        NULL, jsonb_build_object('policy_action', 'delete',
                                 'mailbox_id', v_row.mailbox_id));

      -- Free the mailbox quota + advance JMAP state with a precise 'destroyed'
      -- journal entry carrying (collection_id, imap_uid) so both JMAP Email/changes
      -- and IMAP QRESYNC VANISHED observe retention deletes incrementally (#554).
      -- The message_tags ON DELETE CASCADE counter trigger (trg_message_tags_counters)
      -- already decrements tags.total_count/unread_count for this message.
      UPDATE mailboxes
      SET used_bytes         = GREATEST(0, used_bytes - v_row.size_bytes),
          jmap_mailbox_state = jmap_mailbox_state + 1,
          jmap_email_state   = jmap_email_state + 1
      WHERE id = v_row.mailbox_id
      RETURNING jmap_email_state INTO v_new_email_state;
      PERFORM append_email_change(
        v_row.mailbox_id, v_new_email_state, v_row.message_id, 'destroyed',
        COALESCE(v_row.primary_tag_id, v_row.folder_id), v_row.imap_uid
      );

      v_deleted := v_deleted + 1;

    EXCEPTION WHEN SQLSTATE 'BZ015' THEN
      -- ONLY the litigation-hold trigger (trg_messages_hold_check raises BZ015) is a
      -- "skip this row, keep going" outcome. Catching WHEN OTHERS silently miscounted
      -- every other failure (OOM, constraint/permission error, replication lag) as a
      -- litigation hold and reported apparent success. Let any non-BZ015 exception
      -- propagate so the enforcer fails loudly instead of lying. (Mirrors
      -- content_purge_messages, which had this exact hazard and was narrowed first.)
      NULL;
    END;
  END LOOP;

  RETURN v_deleted;
END;
$$ LANGUAGE plpgsql;

-- Source: mailserver/sql/reducers/rust_mailsec_quarantine.sql (rust_mailsec_quarantine_release)
CREATE OR REPLACE FUNCTION rust_mailsec_quarantine_release(
 p_actor bigint,p_id bigint,p_admin boolean
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
 v_message bigint; v_mailbox bigint; v_tag text; v_lock_mb bigint;
BEGIN
 SELECT mailbox_id INTO v_lock_mb
   FROM quarantined_messages
  WHERE id = p_id AND released_at IS NULL
    AND (CASE WHEN p_admin
         THEN admin_can_reach_perm(p_actor, (SELECT mb.user_id FROM mailboxes mb WHERE mb.id = quarantined_messages.mailbox_id), ARRAY['security.write'])
         ELSE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = p_actor) END);
 IF v_lock_mb IS NULL THEN RETURN false; END IF;
 -- Acquire mailboxes lock before mutating quarantined_messages/messages (#481).
 PERFORM 1 FROM mailboxes WHERE id = v_lock_mb FOR UPDATE;
 UPDATE quarantined_messages SET released_at = now(), released_by = p_actor
  WHERE id = p_id AND released_at IS NULL
    AND (CASE WHEN p_admin
         THEN admin_can_reach_perm(p_actor, (SELECT mb.user_id FROM mailboxes mb WHERE mb.id = quarantined_messages.mailbox_id), ARRAY['security.write'])
         ELSE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = p_actor) END)
  RETURNING message_id, mailbox_id, original_tag INTO v_message, v_mailbox, v_tag;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM release_quarantine_tags(v_message, v_mailbox, v_tag, TRUE);
 RETURN true;
END;
$$;

-- Source: mailserver/sql/reducers/rust_mailsec_quarantine.sql (rust_mailsec_quarantine_reject)
CREATE OR REPLACE FUNCTION rust_mailsec_quarantine_reject(
 p_actor bigint,p_id bigint,p_admin boolean
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
 v_message bigint; v_mailbox bigint; v_primary_tag bigint;
 v_imap_uid bigint; v_folder_id bigint; v_state bigint; v_lock_mb bigint;
BEGIN
 SELECT mailbox_id INTO v_lock_mb
   FROM quarantined_messages
  WHERE id = p_id AND released_at IS NULL
    AND (CASE WHEN p_admin
         THEN admin_can_reach_perm(p_actor, (SELECT mb.user_id FROM mailboxes mb WHERE mb.id = quarantined_messages.mailbox_id), ARRAY['security.write'])
         ELSE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = p_actor) END);
 IF v_lock_mb IS NULL THEN RETURN false; END IF;
 -- Acquire mailboxes lock before mutating quarantined_messages/messages (#481).
 PERFORM 1 FROM mailboxes WHERE id = v_lock_mb FOR UPDATE;
 UPDATE quarantined_messages SET rejected_at = now(), rejected_by = p_actor
  WHERE id = p_id AND released_at IS NULL
    AND (CASE WHEN p_admin
         THEN admin_can_reach_perm(p_actor, (SELECT mb.user_id FROM mailboxes mb WHERE mb.id = quarantined_messages.mailbox_id), ARRAY['security.write'])
         ELSE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = p_actor) END)
  RETURNING message_id, mailbox_id INTO v_message, v_mailbox;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT mt.tag_id INTO v_primary_tag
   FROM message_tags mt
   JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
  WHERE m.id = v_message AND m.mailbox_id = v_mailbox AND mt.is_primary = TRUE
  LIMIT 1;
 IF p_admin THEN
  -- Go's admin Reject ignores the DELETE's error and still answers "rejected".
  BEGIN
   DELETE FROM messages WHERE id = v_message AND mailbox_id = v_mailbox
    RETURNING imap_uid, folder_id INTO v_imap_uid, v_folder_id;
   IF FOUND THEN
    v_state := notify_state_change(v_mailbox, NULL, v_message, 'destroyed');
    IF v_state IS NOT NULL AND (v_imap_uid IS NOT NULL OR COALESCE(v_primary_tag, v_folder_id) IS NOT NULL) THEN
     PERFORM append_email_change(v_mailbox, v_state, v_message, 'destroyed', COALESCE(v_primary_tag, v_folder_id), v_imap_uid);
    END IF;
   END IF;
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
 ELSE
  UPDATE messages SET is_deleted = TRUE WHERE id = v_message AND mailbox_id = v_mailbox
   RETURNING imap_uid, folder_id INTO v_imap_uid, v_folder_id;
  IF FOUND THEN
   v_state := notify_state_change(v_mailbox, NULL, v_message, 'destroyed');
   IF v_state IS NOT NULL AND (v_imap_uid IS NOT NULL OR COALESCE(v_primary_tag, v_folder_id) IS NOT NULL) THEN
    PERFORM append_email_change(v_mailbox, v_state, v_message, 'destroyed', COALESCE(v_primary_tag, v_folder_id), v_imap_uid);
   END IF;
  END IF;
 END IF;
 RETURN true;
END;
$$;

-- Source: mailserver/sql/reducers/mail_draft_replace.sql (mail_draft_replace)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    GRANT CREATE ON SCHEMA public TO setjoin_worker;
  END IF;
END $$;
CREATE OR REPLACE FUNCTION mail_draft_replace(
  p_mailbox_id bigint,p_actor_user_id bigint,p_operation_id uuid,p_draft_session_id uuid,
  p_expected_epoch bigint,p_base_revision bigint,p_draft jsonb,p_request_digest text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_existing mail_work_operations%ROWTYPE; v_session mail_draft_collaboration%ROWTYPE;
  v_create jsonb; v_new_id bigint; v_new_received timestamptz; v_content_digest text;
  v_attachment_digest text; v_result jsonb; v_state bigint; v_sender text;
  v_old_imap_uid bigint; v_old_folder_id bigint; v_old_primary_tag bigint; v_email_state bigint;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_drafts'),false) THEN
    RAISE EXCEPTION 'shared mail drafts are disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_operation_id IS NULL OR p_draft_session_id IS NULL OR p_expected_epoch<1
     OR p_base_revision<1 OR jsonb_typeof(p_draft)<>'object'
     OR octet_length(p_draft::text)>1048576 OR p_request_digest!~'^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid shared draft replacement' USING ERRCODE='BZ301';
  END IF;
  SELECT * INTO v_existing FROM mail_work_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.mailbox_id=p_mailbox_id AND v_existing.actor_user_id=p_actor_user_id
       AND v_existing.operation_kind='draft_save' AND v_existing.request_digest=p_request_digest THEN
      RETURN v_existing.result||jsonb_build_object('replayed',true,'current',
        mail_draft_get(p_mailbox_id,p_actor_user_id,ARRAY[p_draft_session_id])->'list'->0);
    END IF;
    RAISE EXCEPTION 'shared draft idempotency conflict' USING ERRCODE='BZ303';
  END IF;
  -- Acquire mailboxes lock before locking draft/message rows (#481).
  PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id FOR UPDATE;
  SELECT * INTO v_session FROM mail_draft_collaboration
   WHERE draft_session_id=p_draft_session_id AND mailbox_id=p_mailbox_id FOR UPDATE;
  IF NOT FOUND OR v_session.state<>'active' OR v_session.lease_holder_user_id<>p_actor_user_id
     OR v_session.lease_expires_at<=statement_timestamp() OR v_session.lease_epoch<>p_expected_epoch
     OR v_session.content_revision<>p_base_revision THEN
    RAISE EXCEPTION 'shared draft revision or lease is stale' USING ERRCODE='BZ304';
  END IF;
  IF NOT mail_work_can_collaborate(p_mailbox_id,p_actor_user_id)
     OR NOT EXISTS(SELECT 1 FROM mailbox_delegates d WHERE d.mailbox_id=p_mailbox_id
       AND d.user_id=p_actor_user_id AND d.permission IN ('send_as','send_on_behalf','full_access')) THEN
    RAISE EXCEPTION 'shared draft send permission required' USING ERRCODE='BZ005';
  END IF;
  v_sender:=lower(p_draft->'from'->0->>'email');
  IF v_sender IS NULL OR v_sender<>lower(v_session.final_sender_address)
     OR (NOT EXISTS(SELECT 1 FROM mailboxes m WHERE m.id=p_mailbox_id AND lower(m.email)=v_sender)
       AND NOT EXISTS(SELECT 1 FROM aliases a WHERE a.mailbox_id=p_mailbox_id AND lower(a.email)=v_sender)
       AND NOT EXISTS(SELECT 1 FROM users u WHERE u.id=p_actor_user_id AND lower(u.email)=v_sender)
       AND NOT EXISTS(SELECT 1 FROM aliases a JOIN mailboxes m ON m.id=a.mailbox_id
         WHERE m.user_id=p_actor_user_id AND lower(a.email)=v_sender)) THEN
    RAISE EXCEPTION 'final sender is not authorized' USING ERRCODE='BZ005';
  END IF;
  SELECT m.imap_uid, m.folder_id,
         (SELECT mt.tag_id FROM message_tags mt
           WHERE mt.message_id=m.id AND mt.received_at=m.received_at AND mt.is_primary=TRUE LIMIT 1)
    INTO v_old_imap_uid, v_old_folder_id, v_old_primary_tag
    FROM messages m
   WHERE m.mailbox_id=p_mailbox_id AND m.id=v_session.message_id
     AND m.received_at=v_session.received_at AND m.is_draft AND NOT m.is_deleted;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'shared draft not found' USING ERRCODE='BZ007';
  END IF;

  v_create:=jmap_email_set_create(p_mailbox_id,jsonb_build_object('replacement',p_draft));
  v_new_id:=(v_create->'created'->'replacement'->>'id')::bigint;
  IF v_new_id IS NULL THEN
    RAISE EXCEPTION 'shared draft replacement was rejected' USING ERRCODE='BZ301';
  END IF;
  SELECT received_at INTO v_new_received FROM messages
   WHERE mailbox_id=p_mailbox_id AND id=v_new_id AND is_draft AND NOT is_deleted;
  IF NOT FOUND THEN RAISE EXCEPTION 'replacement draft is unavailable' USING ERRCODE='BZ304'; END IF;
  SELECT encode(digest(jsonb_build_object('rawRef',m.raw_ref,'subject',m.subject,'from',m.from_addr,
    'to',m.to_addrs,'cc',m.cc_addrs,'bcc',m.bcc_addrs,'text',m.body_text,'html',m.body_html)::text,'sha256'),'hex')
    INTO v_content_digest FROM messages m WHERE m.mailbox_id=p_mailbox_id AND m.id=v_new_id AND m.received_at=v_new_received;
  SELECT encode(digest(COALESCE(string_agg(ma.blob_sha256||':'||ma.size_bytes::text,',' ORDER BY ma.blob_sha256,ma.size_bytes),'empty'),'sha256'),'hex')
    INTO v_attachment_digest FROM message_attachments ma WHERE ma.message_id=v_new_id AND ma.received_at=v_new_received;
  INSERT INTO mail_draft_revisions(draft_session_id,revision,message_id,received_at,editor_user_id,
    content_digest,attachment_digest) VALUES(p_draft_session_id,p_base_revision+1,v_new_id,v_new_received,
    p_actor_user_id,v_content_digest,v_attachment_digest);
  v_email_state:=NULLIF(v_create->>'newState','')::bigint;
  IF v_email_state IS NULL THEN
    SELECT jmap_email_state INTO v_email_state FROM mailboxes WHERE id=p_mailbox_id;
  END IF;
  IF v_email_state IS NOT NULL THEN
    PERFORM set_config('app.imap_retire_modseq',(GREATEST(v_email_state,0)+1)::text,true);
  END IF;
  PERFORM delete_draft_message(v_session.message_id,v_session.received_at,p_mailbox_id,false);
  PERFORM set_config('app.imap_retire_modseq','',true);
  IF v_email_state IS NOT NULL THEN
    PERFORM append_email_change(p_mailbox_id,v_email_state,v_session.message_id,'destroyed',
      COALESCE(v_old_primary_tag,v_old_folder_id),v_old_imap_uid);
  END IF;
  UPDATE mail_draft_collaboration SET message_id=v_new_id,received_at=v_new_received,
    content_revision=p_base_revision+1,lease_expires_at=statement_timestamp()+interval '2 minutes',
    generation=generation+1,last_operation_id=p_operation_id,updated_at=statement_timestamp()
   WHERE draft_session_id=p_draft_session_id RETURNING * INTO v_session;
  v_state:=notify_mailwork_state(p_mailbox_id,'draft',p_draft_session_id::text,'updated');
  v_result:=jsonb_build_object('accountId',p_mailbox_id::text,'id',p_draft_session_id,
    'contentRevision',v_session.content_revision::text,'leaseEpoch',v_session.lease_epoch::text,
    'leaseExpiresAt',v_session.lease_expires_at,'messageId',v_new_id::text,'receivedAt',v_new_received,
    'state',v_state::text,'replayed',false);
  INSERT INTO mail_work_operations(operation_id,mailbox_id,actor_user_id,operation_kind,request_digest,result)
    VALUES(p_operation_id,p_mailbox_id,p_actor_user_id,'draft_save',p_request_digest,v_result);
  RETURN v_result;
END $$;

ALTER FUNCTION mail_draft_replace(bigint,bigint,uuid,uuid,bigint,bigint,jsonb,text) OWNER TO setjoin_worker;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
  END IF;
END $$;

-- Source: mailserver/sql/reducers/mail_draft_submission_authorize.sql (mail_draft_submission_authorize)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    GRANT CREATE ON SCHEMA public TO setjoin_worker;
  END IF;
END $$;
CREATE OR REPLACE FUNCTION mail_draft_submission_authorize(
  p_mailbox_id bigint,p_actor_user_id bigint,p_draft_session_id uuid,
  p_expected_epoch bigint,p_expected_revision bigint,p_message_id bigint,p_received_at timestamptz
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_draft mail_draft_collaboration%ROWTYPE;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_drafts'),false) THEN
    RAISE EXCEPTION 'shared mail drafts are disabled' USING ERRCODE='BZ300';
  END IF;
  -- Canonical #481 lock order: acquire mailboxes lock before draft/message rows.
  PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id FOR UPDATE;
  SELECT * INTO v_draft FROM mail_draft_collaboration WHERE draft_session_id=p_draft_session_id
    AND mailbox_id=p_mailbox_id FOR UPDATE;
  IF NOT FOUND OR v_draft.state<>'active' OR v_draft.lease_holder_user_id<>p_actor_user_id
     OR v_draft.lease_expires_at<=statement_timestamp() OR v_draft.lease_epoch<>p_expected_epoch
     OR v_draft.content_revision<>p_expected_revision OR v_draft.message_id<>p_message_id
     OR v_draft.received_at<>p_received_at THEN
    RAISE EXCEPTION 'shared draft submission lease or revision is stale' USING ERRCODE='BZ304';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM mailbox_delegates d WHERE d.mailbox_id=p_mailbox_id
      AND d.user_id=p_actor_user_id AND d.permission IN ('send_as','send_on_behalf','full_access')) THEN
    RAISE EXCEPTION 'shared draft send permission was revoked' USING ERRCODE='BZ005';
  END IF;
  UPDATE mail_draft_collaboration SET state='submitted',lease_holder_user_id=NULL,lease_expires_at=NULL,
    generation=generation+1,updated_at=statement_timestamp() WHERE draft_session_id=p_draft_session_id;
  PERFORM notify_mailwork_state(p_mailbox_id,'draft',p_draft_session_id::text,'updated');
  RETURN true;
END $$;

ALTER FUNCTION mail_draft_submission_authorize(bigint,bigint,uuid,bigint,bigint,bigint,timestamptz) OWNER TO setjoin_worker;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
  END IF;
END $$;

INSERT INTO schema_migrations (version, applied_at)
VALUES (296, now())
ON CONFLICT (version) DO NOTHING;
