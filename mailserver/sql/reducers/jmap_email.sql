-- JMAP Email/* reducers (RFC 8621 §4)

-- jmap_email_get: return Email objects for given ids.
CREATE OR REPLACE FUNCTION jmap_email_get(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[],
  p_properties TEXT[] DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_result    JSONB := '[]'::JSONB;
  -- messages%ROWTYPE (not RECORD): a concrete composite so it can be passed to
  -- message_to_jmap_email(p_row messages) — a RECORD can't cast to a named type.
  v_row       messages%ROWTYPE;
  v_state     BIGINT;
  v_obj       JSONB;
  v_found     TEXT[] := ARRAY[]::TEXT[];
BEGIN
  SELECT jmap_email_state INTO v_state
  FROM mailboxes WHERE id = p_mailbox_id;
  IF v_state IS NULL THEN
    RAISE EXCEPTION 'Account not found'
      USING ERRCODE = 'BZ006', HINT = '{"type":"accountNotFound"}';
  END IF;

  FOR v_row IN
    SELECT m.*
    FROM messages m
    WHERE m.mailbox_id = p_mailbox_id
      AND m.id = ANY(p_ids)
      AND NOT m.is_deleted
    ORDER BY m.received_at DESC
  LOOP
    -- Shared row-derived projection (single-sourced with jmap_email_query_deleted
    -- in reducers/message_to_jmap_email.sql), then `||`-merge the request-guarded
    -- extras that are cross-table / p_properties-dependent and stay caller-local.
    v_obj := message_to_jmap_email(v_row) || jsonb_build_object(
      -- ponytail: CASE guard skips the join when mailboxIds not requested; ceiling is
      -- still a per-row subquery — promote to a lateral join if batch sizes grow large.
      'mailboxIds', CASE WHEN p_properties IS NULL OR 'mailboxIds' = ANY(p_properties)
        THEN COALESCE((
          SELECT jsonb_object_agg(mt.tag_id::TEXT, true)
          FROM message_tags mt
          WHERE mt.message_id = v_row.id AND mt.received_at = v_row.received_at
        ), '{}'::JSONB)
        ELSE NULL
      END,
      -- ponytail: CASE guard skips the attachment scan when inlineImages not requested;
      -- ceiling is still a per-row subquery — promote to lateral if batch sizes grow.
      'inlineImages', CASE WHEN p_properties IS NULL OR 'inlineImages' = ANY(p_properties)
        THEN (
          SELECT jsonb_object_agg('cid:' || ma.content_id, ma.blob_sha256)
          FROM message_attachments ma
          WHERE ma.message_id = v_row.id
            AND ma.received_at = v_row.received_at
            AND ma.disposition = 'inline'
            AND ma.content_id IS NOT NULL
        )
        ELSE NULL
      END,
      -- Read-only attachment list (RFC 8621 EmailBodyPart subset). Guarded like
      -- inlineImages so the per-row scan only runs when requested.
      'attachments', CASE WHEN p_properties IS NULL OR 'attachments' = ANY(p_properties)
        THEN (
          SELECT COALESCE(jsonb_agg(jsonb_build_object(
            'blobId', ma.blob_sha256,
            'type', ma.content_type,
            'name', ma.filename,
            'cid', ma.content_id,
            'disposition', ma.disposition,
            'size', ma.size_bytes
          ) ORDER BY ma.id), '[]'::JSONB)
          FROM message_attachments ma
          WHERE ma.message_id = v_row.id
            AND ma.received_at = v_row.received_at
        )
        ELSE NULL
      END
    );
    -- Property projection: when p_properties is given, keep only requested keys
    -- (id is always retained as the object identity). NULL => full object (legacy).
    -- ponytail: jsonb_each filter; upgrade to a jsonb_path_exists index if hotpath.
    IF p_properties IS NOT NULL THEN
      v_obj := (
        SELECT COALESCE(jsonb_object_agg(k, v), '{}'::JSONB)
        FROM jsonb_each(v_obj) AS e(k, v)
        WHERE e.k = 'id' OR e.k = ANY(p_properties)
      );
    END IF;
    v_result := v_result || v_obj;
    v_found := v_found || v_row.id::TEXT;
  END LOOP;

  RETURN build_jmap_get_response(
    p_mailbox_id, v_state, v_result, v_found,
    CASE WHEN p_ids IS NOT NULL
      THEN ARRAY(SELECT x::TEXT FROM unnest(p_ids) AS x) END
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_email_query: search/filter emails.
-- Supported filters: inMailbox, inArchive, focus, text, from, to, cc, bcc,
--                subject, body, hasAttachment, hasKeyword, before, after, minSize, maxSize
CREATE OR REPLACE FUNCTION jmap_email_query(
  p_mailbox_id  BIGINT,
  p_filter      JSONB DEFAULT NULL,
  p_sort        JSONB DEFAULT NULL,
  p_position    INT   DEFAULT 0,
  p_limit       INT   DEFAULT 50
) RETURNS JSONB AS $$
DECLARE
  v_state       BIGINT;
  v_ids         TEXT[];
  v_total       INT;
  v_sql         TEXT := '';
  v_where       TEXT := 'm.mailbox_id = $1 AND NOT m.is_deleted';
  -- Total order (#223): every sort ends with `m.id` in the primary key's
  -- direction, so equal sort keys (several messages sharing a received_at)
  -- page by position without repeats or gaps. The Rust inbox-list read
  -- (server-rust/crates/domains/jmap/src/email_list.rs) uses the same order.
  v_order       TEXT := 'm.pinned_at IS NOT NULL DESC, m.received_at DESC, m.id DESC';
  v_in_mailbox  BIGINT;
  v_text        TEXT;
  v_other       BIGINT;
BEGIN
  SELECT jmap_email_state INTO v_state
  FROM mailboxes WHERE id = p_mailbox_id;
  IF v_state IS NULL THEN
    RAISE EXCEPTION 'Account not found'
      USING ERRCODE = 'BZ006', HINT = '{"type":"accountNotFound"}';
  END IF;

  -- Parse filter
  IF p_filter IS NOT NULL THEN
    IF p_filter ? 'inMailbox' THEN
      -- The webmail sends the '__no_match__' sentinel when a `tag:`/`in:`/`label:`
      -- search names a tag that doesn't exist; a non-numeric id must return ZERO
      -- rows (the sentinel's intent), never crash the ::BIGINT cast below.
      IF p_filter->>'inMailbox' ~ '^\d+$' THEN
        v_in_mailbox := (p_filter->>'inMailbox')::BIGINT;
        v_where := v_where || format(' AND EXISTS (SELECT 1 FROM message_tags mt WHERE mt.message_id = m.id AND mt.received_at = m.received_at AND mt.tag_id = %s)', v_in_mailbox);
        -- Hide snoozed/scheduled messages from their LOCATION view. Snooze keeps the
        -- location tag (message_snooze sets is_primary FALSE so the message returns to
        -- Inbox on un-snooze) and adds a 'snooze'-group tag, so a location-mailbox query
        -- must exclude any message currently carrying a snooze-group tag. The Snoozed /
        -- Scheduled views query the snooze-group tag directly (inMailbox = that tag), so
        -- this exclusion must apply ONLY when the queried tag is itself in the 'location'
        -- group. Constant literal fragment (no user input) — DATABASE_SECURITY ok.
        IF (SELECT exclusive_group FROM tags WHERE id = v_in_mailbox) = 'location' THEN
          v_where := v_where ||
            ' AND NOT EXISTS (SELECT 1 FROM message_tags ms JOIN tags ts ON ts.id = ms.tag_id' ||
            ' WHERE ms.message_id = m.id AND ms.received_at = m.received_at' ||
            ' AND ts.exclusive_group = ''snooze'')';
        END IF;
      ELSE
        v_where := v_where || ' AND FALSE';
      END IF;
    END IF;

    -- inArchive (A2): archived = the message carries NO tag in the `location`
    -- exclusive group (Inbox/Sent/Drafts/Trash/Spam all do), but is not deleted.
    -- This naturally excludes every located mailbox view. The WHERE fragment is a
    -- constant literal (no user input concatenated) — DATABASE_SECURITY ok.
    IF p_filter ? 'inArchive' AND (p_filter->>'inArchive')::BOOL THEN
      v_where := v_where ||
        ' AND NOT EXISTS (SELECT 1 FROM message_tags mt JOIN tags t ON t.id = mt.tag_id' ||
        ' WHERE mt.message_id = m.id AND mt.received_at = m.received_at' ||
        ' AND t.exclusive_group = ''location'')';
    END IF;

    -- focus (Focused/Other inbox split): 'other' = carries the 'Other' tag;
    -- 'focused' (any other value) = does NOT. The Other tag id is a resolved
    -- BIGINT (%s-safe, no user input concatenated). A mailbox without an Other
    -- tag (e.g. journal): 'other' matches nothing (AND FALSE); 'focused' is a
    -- no-op (all rows qualify).
    IF p_filter ? 'focus' THEN
      v_other := get_tag_id('Other', p_mailbox_id);
      IF p_filter->>'focus' = 'other' THEN
        IF v_other IS NULL THEN
          v_where := v_where || ' AND FALSE';
        ELSE
          v_where := v_where || format(' AND EXISTS (SELECT 1 FROM message_tags mt WHERE mt.message_id = m.id AND mt.received_at = m.received_at AND mt.tag_id = %s)', v_other);
        END IF;
      ELSIF v_other IS NOT NULL THEN
        v_where := v_where || format(' AND NOT EXISTS (SELECT 1 FROM message_tags mt WHERE mt.message_id = m.id AND mt.received_at = m.received_at AND mt.tag_id = %s)', v_other);
      END IF;
    END IF;

    IF p_filter ? 'text' THEN
      v_text := lower(p_filter->>'text');
      v_where := v_where || format(
        ' AND (m.body_tsv @@ websearch_to_tsquery(''simple'', %L) OR m.subject_tsv @@ websearch_to_tsquery(''simple'', %L) OR m.from_tsv @@ websearch_to_tsquery(''simple'', %L))',
        v_text, v_text, v_text
      );
      -- Plain GIN/tsquery revert (2026-07-04 queue-B #2): no ParadeDB/BM25 is
      -- ever installed, so @@@/paradedb.score threw on every deployment. Rank
      -- by summed ts_rank across the 3 columns so a stronger match still sorts
      -- first; this is a plain-PostgreSQL relevance signal, not BM25.
      v_order := format(
        '(ts_rank(m.body_tsv, websearch_to_tsquery(''simple'', %L)) + ts_rank(m.subject_tsv, websearch_to_tsquery(''simple'', %L)) + ts_rank(m.from_tsv, websearch_to_tsquery(''simple'', %L))) DESC, %s',
        v_text, v_text, v_text, v_order
      );
    END IF;

    IF p_filter ? 'from' THEN
      v_where := v_where || format(' AND lower(m.from_addr) LIKE %L',
        '%' || lower(p_filter->>'from') || '%');
    END IF;

    IF p_filter ? 'to' THEN
      v_where := v_where || format(' AND m.to_addrs::TEXT ILIKE %L',
        '%' || p_filter->>'to' || '%');
    END IF;

    IF p_filter ? 'cc' THEN
      v_where := v_where || format(' AND m.cc_addrs::TEXT ILIKE %L',
        '%' || p_filter->>'cc' || '%');
    END IF;

    IF p_filter ? 'bcc' THEN
      v_where := v_where || format(' AND m.bcc_addrs::TEXT ILIKE %L',
        '%' || p_filter->>'bcc' || '%');
    END IF;

    IF p_filter ? 'subject' THEN
      v_where := v_where || format(' AND lower(m.subject) LIKE %L',
        '%' || lower(p_filter->>'subject') || '%');
    END IF;

    IF p_filter ? 'body' THEN
      v_text := lower(p_filter->>'body');
      v_where := v_where || format(' AND m.body_tsv @@ websearch_to_tsquery(''simple'', %L)',
        v_text);
      v_order := format('ts_rank(m.body_tsv, websearch_to_tsquery(''simple'', %L)) DESC, %s', v_text, v_order);
    END IF;

    IF p_filter ? 'hasAttachment' THEN
      v_where := v_where || format(' AND m.has_attachments = %L',
        (p_filter->>'hasAttachment')::BOOL);
    END IF;

    IF p_filter ? 'hasKeyword' THEN
      v_where := v_where || CASE lower(p_filter->>'hasKeyword')
        WHEN '$seen'     THEN ' AND m.is_read = TRUE'
        WHEN '$unseen'   THEN ' AND m.is_read = FALSE'
        WHEN '$flagged'  THEN ' AND m.is_flagged = TRUE'
        WHEN '$draft'    THEN ' AND m.is_draft = TRUE'
        WHEN '$answered' THEN ' AND m.is_answered = TRUE'
        ELSE ''
      END;
    END IF;

    IF p_filter ? 'before' THEN
      v_where := v_where || format(' AND m.received_at < %L', p_filter->>'before');
    END IF;

    IF p_filter ? 'after' THEN
      v_where := v_where || format(' AND m.received_at > %L', p_filter->>'after');
    END IF;

    IF p_filter ? 'minSize' THEN
      v_where := v_where || format(' AND m.size_bytes >= %s', (p_filter->>'minSize')::BIGINT);
    END IF;

    IF p_filter ? 'maxSize' THEN
      v_where := v_where || format(' AND m.size_bytes <= %s', (p_filter->>'maxSize')::BIGINT);
    END IF;
  END IF;

  -- Parse sort (simplified: only property + isAscending)
  IF p_sort IS NOT NULL AND jsonb_array_length(p_sort) > 0 THEN
    DECLARE
      v_sort_prop TEXT := p_sort->0->>'property';
      v_sort_asc  BOOL := COALESCE((p_sort->0->>'isAscending')::BOOL, true);
      v_sort_dir  TEXT;
    BEGIN
      v_sort_dir := CASE
        WHEN COALESCE(v_sort_prop, '') NOT IN ('receivedAt', 'sentAt', 'size', 'subject', 'from') THEN 'DESC'
        WHEN v_sort_asc THEN 'ASC' ELSE 'DESC' END;
      v_order := 'm.pinned_at IS NOT NULL DESC, ' || CASE v_sort_prop
        WHEN 'sentAt'     THEN 'm.sent_at '
        WHEN 'size'       THEN 'm.size_bytes '
        WHEN 'subject'    THEN 'm.subject '
        WHEN 'from'       THEN 'm.from_addr '
        ELSE 'm.received_at '
      END || v_sort_dir || ', m.id ' || v_sort_dir;
    END;
  END IF;

  -- Count total
  EXECUTE format('SELECT COUNT(*) FROM messages m WHERE %s', v_where)
    INTO v_total USING p_mailbox_id;

  -- Fetch ids
  EXECUTE format(
    'SELECT array_agg(id::TEXT) FROM (
      SELECT m.id FROM messages m WHERE %s ORDER BY %s LIMIT %s OFFSET %s
    ) sub',
    v_where, v_order, p_limit, p_position
  ) INTO v_ids USING p_mailbox_id;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'state', v_state::TEXT,
    'canCalculateChanges', false,
    'position', p_position,
    'total', v_total,
    'ids', COALESCE(to_jsonb(v_ids), '[]'::JSONB)
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_email_changes: real per-account delta from jmap_changes_journal (offline #3).
-- maxChanges is a SOFT cap (RFC 8620): paging never splits a state_seq — a state
-- bump is atomic (N rows at one state_seq are indivisible); a single oversized
-- state_seq group is returned whole. A 'resync' sentinel or a pruned/future
-- sinceState → BZ011 (cannotCalculateChanges) → client falls back to full-resync.
-- Collapse per message_id (RFC 8620 §5.2): created+destroyed → omit;
-- multiple updates → one; created+updated → created.
-- ponytail: collapse + group-boundary cap computed at read time, no separate table.
CREATE OR REPLACE FUNCTION jmap_email_changes(
  p_mailbox_id  BIGINT,
  p_since_state TEXT,
  p_max_changes INT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_current   BIGINT;
  v_since     BIGINT := p_since_state::BIGINT;
  v_oldest    BIGINT;
  v_new_state BIGINT;
  v_count     INT    := 0;
  v_prev_seq  BIGINT;
  v_created   BIGINT[] := '{}';
  v_updated   BIGINT[] := '{}';
  v_destroyed BIGINT[] := '{}';
  v_has_more  BOOLEAN  := FALSE;
  r RECORD;
BEGIN
  -- R1: always filter by auth-derived mailbox id
  SELECT jmap_email_state INTO v_current FROM mailboxes WHERE id = p_mailbox_id;
  IF v_current IS NULL THEN
    RAISE EXCEPTION 'Account not found'
      USING ERRCODE = 'BZ006', HINT = '{"type":"accountNotFound"}';
  END IF;

  IF v_since > v_current THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  -- Pruned: sinceState predates the oldest retained journal row (decision 11).
  -- Guard v_since>0: sinceState=0 always means "full history from start", never pruned.
  SELECT MIN(state_seq) INTO v_oldest
    FROM jmap_changes_journal WHERE mailbox_id = p_mailbox_id AND datatype = 'email';  -- R1
  IF v_since > 0 AND (v_oldest IS NULL OR v_since < v_oldest - 1) THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  -- Resync sentinel anywhere in (sinceState, currentState] → coarse path (BZ011).
  -- ponytail: sentinel means a counter-only bump happened here; we can't produce a
  -- precise list, so force full-resync. Task 4 converts sentinels to precise rows.
  IF EXISTS (
    SELECT 1 FROM jmap_changes_journal
     WHERE mailbox_id = p_mailbox_id AND datatype = 'email' AND state_seq > v_since AND op = 'resync'  -- R1
  ) THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  v_new_state := v_current;

  -- Collapse per entity_id (latest op; created+destroyed cancels).
  -- Walk in state_seq order; apply the soft cap at state_seq GROUP boundaries only
  -- (never split a group — all ids sharing a state_seq are an atomic batch).
  FOR r IN
    WITH per_id AS (
      SELECT entity_id,
             (array_agg(op ORDER BY state_seq DESC))[1] AS latest_op,
             bool_or(op = 'created')   AS had_created,
             bool_or(op = 'destroyed') AS had_destroyed,
             MAX(state_seq)            AS max_seq
        FROM jmap_changes_journal
       WHERE mailbox_id = p_mailbox_id AND datatype = 'email' AND state_seq > v_since AND op <> 'resync'  -- R1
       GROUP BY entity_id
    )
    SELECT entity_id, latest_op, had_created, max_seq
      FROM per_id
     ORDER BY max_seq, entity_id
  LOOP
    -- RFC 8620 §5.2: created+destroyed since oldState → noop (omit from all lists)
    IF r.had_created AND r.latest_op = 'destroyed' THEN
      CONTINUE;
    END IF;

    -- Soft cap: only trigger at a state_seq GROUP boundary, never mid-group.
    -- ponytail: v_prev_seq tracks the last emitted group; crossing to a new seq
    -- is the only legal cut point. A single oversized group is always returned
    -- whole (first iteration: v_prev_seq IS NULL → can't be a boundary yet).
    IF p_max_changes IS NOT NULL
       AND v_count >= p_max_changes
       AND v_prev_seq IS NOT NULL
       AND r.max_seq > v_prev_seq
    THEN
      v_has_more  := TRUE;
      v_new_state := v_prev_seq;  -- last fully-emitted state_seq is the new cursor
      EXIT;
    END IF;

    IF r.latest_op = 'destroyed' THEN
      v_destroyed := v_destroyed || r.entity_id;
    ELSIF r.had_created THEN
      v_created   := v_created   || r.entity_id;
    ELSE
      v_updated   := v_updated   || r.entity_id;
    END IF;
    v_count    := v_count + 1;
    v_prev_seq := r.max_seq;
  END LOOP;

  RETURN jsonb_build_object(
    'accountId',     p_mailbox_id::TEXT,
    'oldState',      p_since_state,
    'newState',      v_new_state::TEXT,
    'hasMoreChanges', v_has_more,
    'created',   COALESCE(to_jsonb(v_created),   '[]'::JSONB),
    'updated',   COALESCE(to_jsonb(v_updated),   '[]'::JSONB),
    'destroyed', COALESCE(to_jsonb(v_destroyed), '[]'::JSONB)
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_email_set_update: update emails (keywords, mailboxIds) and soft-delete.
-- No-op means no effect (#219, owner decision 2026-10-29): a message joins the
-- post-loop batch (state bump + `updated` journal row + push) only when at
-- least one of its fields actually changed. A no-op patch is still reported in
-- `updated` (the patch succeeded); a no-op mailboxIds leaves message_tags (and
-- the IMAP UIDs, counters and jmap_tag_state riding on it) untouched.
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
  -- Capture oldState before the loop so the batch return is correct.
  SELECT jmap_email_state INTO v_old_state FROM mailboxes WHERE id = p_mailbox_id;
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

-- jmap_email_set_destroy: move to Trash if not already there; soft-delete if in Trash.
-- Offline #3 (T8): batch-collapse — transition_message_location called with p_notify=FALSE
-- (suppresses per-swap push); after the loop ONE bump + N precise journal rows at that
-- state_seq + ONE push (no per-id push amplification). oldState captured pre-loop;
-- newState set by the post-loop bump (or equals oldState when nothing succeeded).
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
  v_primary_tag  BIGINT;
  v_size_bytes   BIGINT;
BEGIN
  SELECT id INTO v_trash_id FROM tags
  WHERE name = 'Trash' AND mailbox_id = p_mailbox_id;

  -- Capture oldState before any per-id bumps (mirrors jmap_email_set_update pattern).
  SELECT jmap_email_state INTO v_old_state FROM mailboxes WHERE id = p_mailbox_id;
  v_new_state := v_old_state;

  FOREACH v_id IN ARRAY p_ids
  LOOP
    BEGIN
      -- Verify message exists and get metadata
      SELECT received_at, size_bytes INTO v_received_at, v_size_bytes
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
        -- per-id notify_state_change below owns the single bump + push per id.
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

      -- Collect id for the post-loop batch bump.
      v_destroyed_ids := array_append(v_destroyed_ids, v_id);
      v_destroyed := v_destroyed || to_jsonb(v_id::TEXT);
    EXCEPTION WHEN OTHERS THEN
      v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'Destroy failed'));
    END;
  END LOOP;

  -- Batch-collapse (offline #3): ONE bump + N precise journal rows at that seq + ONE push.
  IF array_length(v_destroyed_ids, 1) IS NOT NULL THEN
    v_new_state := bump_email_state(p_mailbox_id);
    FOREACH v_id IN ARRAY v_destroyed_ids LOOP
      PERFORM append_email_change(p_mailbox_id, v_new_state, v_id, 'destroyed');
    END LOOP;
    PERFORM app_notify('tag:' || p_mailbox_id, json_build_object(
      'event', 'state_change', 'tag_id', NULL, 'state', v_new_state)::TEXT);
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

-- jmap_email_query_deleted: list soft-deleted emails for recovery.
CREATE OR REPLACE FUNCTION jmap_email_query_deleted(
  p_mailbox_id BIGINT,
  p_limit      INT DEFAULT 50,
  p_position   INT DEFAULT 0
) RETURNS JSONB AS $$
DECLARE
  v_result  JSONB := '[]'::JSONB;
  -- messages%ROWTYPE (not RECORD) so v_row can be passed to message_to_jmap_email().
  v_row     messages%ROWTYPE;
  v_total   INT;
BEGIN
  SELECT COUNT(*) INTO v_total
  FROM messages m
  WHERE m.mailbox_id = p_mailbox_id AND m.is_deleted;

  FOR v_row IN
    SELECT m.*
    FROM messages m
    WHERE m.mailbox_id = p_mailbox_id AND m.is_deleted
    ORDER BY m.deleted_at DESC
    LIMIT p_limit OFFSET p_position
  LOOP
    -- Same single-sourced row projection jmap_email_get uses, so the inline
    -- trash-view objects never re-drift from the live Email/get objects. Deleted-
    -- specific overlay: deletedAt, plus mailboxIds forced to '{}' (a soft-deleted
    -- message is detached from its tags — there are no mailboxes to report).
    v_result := v_result || (
      message_to_jmap_email(v_row)
      || jsonb_build_object('deletedAt', v_row.deleted_at, 'mailboxIds', '{}'::JSONB)
    );
  END LOOP;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'ids', (SELECT jsonb_agg(id::TEXT) FROM (
      SELECT m.id FROM messages m
      WHERE m.mailbox_id = p_mailbox_id AND m.is_deleted
      ORDER BY m.deleted_at DESC
      LIMIT p_limit OFFSET p_position
    ) sub),
    'total', v_total,
    'position', p_position,
    'list', v_result
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_email_recover: restore soft-deleted emails to Inbox.
--
-- INPUT: p_mailbox_id (BIGINT, REQUIRED) — mailbox (ownership verified by caller)
-- INPUT: p_ids (BIGINT[], REQUIRED) — deleted email IDs to recover
-- SIDE EFFECTS: UPDATE messages SET is_deleted=FALSE; transition_message_location(Inbox, notify=FALSE);
--               UPDATE mailboxes quota with check_quota() guard;
--               notify_state_change(mailbox, NULL) → push on 'tag:{mailbox_id}'
CREATE OR REPLACE FUNCTION jmap_email_recover(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[]
) RETURNS JSONB AS $$
DECLARE
  v_recovered   JSONB := '[]'::JSONB;
  v_notRecovered JSONB := '{}'::JSONB;
  v_new_state   BIGINT;
  v_id          BIGINT;
  v_received_at TIMESTAMPTZ;
  v_size_bytes  BIGINT;
BEGIN
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

      -- Restore message
      UPDATE messages SET is_deleted = FALSE, deleted_at = NULL
      WHERE id = v_id AND received_at = v_received_at
        AND mailbox_id = p_mailbox_id;

      -- Move back to Inbox through the single location seam. Batch loop with ONE
      -- notify_state_change after the loop → suppress the per-swap push.
      PERFORM transition_message_location(v_id, v_received_at, 'Inbox', p_mailbox_id, 'user', FALSE);

      -- Restore quota (with space check)
      IF check_quota(p_mailbox_id, v_size_bytes) THEN
        UPDATE mailboxes SET used_bytes = used_bytes + v_size_bytes
        WHERE id = p_mailbox_id;
      ELSE
        v_notRecovered := v_notRecovered || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'overQuota', 'description', 'Not enough free space to recover'));
        CONTINUE;
      END IF;

      v_recovered := v_recovered || to_jsonb(v_id::TEXT);
    EXCEPTION WHEN OTHERS THEN
      v_notRecovered := v_notRecovered || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'Recover failed'));
    END;
  END LOOP;

  -- Bump state + push on the canonical 'tag:{mailbox_id}' channel.
  v_new_state := notify_state_change(p_mailbox_id, NULL);

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'newState', v_new_state::TEXT,
    'recovered', v_recovered,
    'notRecovered', v_notRecovered
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_email_purge: permanently delete soft-deleted emails (dedup-safe).
-- Adding p_notify changed the arg list, so drop the old 2-arg signature first —
-- CREATE OR REPLACE would otherwise leave both overloads and make a 2-arg call
-- ambiguous ("function is not unique"). No-op on a fresh baseline load.
DROP FUNCTION IF EXISTS jmap_email_purge(BIGINT, BIGINT[]);
-- p_notify (DEFAULT TRUE): the JMAP purge path pushes a resync so connected
-- clients drop the ids. IMAP EXPUNGE/CLOSE pass FALSE — the message was already
-- soft-deleted (is_deleted) via a path that already emitted its 'destroyed' delta,
-- so a second resync-forcing notify here would needlessly invalidate every
-- client's Email/changes cursor. The blob-dedup + hard-delete still run; only the
-- push is suppressed (arch A8 — routing IMAP expunge through this reducer instead
-- of a raw DELETE that leaked the raw_ref blob).
CREATE OR REPLACE FUNCTION jmap_email_purge(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[],
  p_notify     BOOLEAN DEFAULT TRUE
) RETURNS JSONB AS $$
DECLARE
  v_purged     JSONB := '[]'::JSONB;
  v_notPurged  JSONB := '{}'::JSONB;
  v_new_state  BIGINT;
  v_id         BIGINT;
  v_received_at TIMESTAMPTZ;
  v_raw_ref    TEXT;
  v_shared     INT;
BEGIN
  FOREACH v_id IN ARRAY p_ids
  LOOP
    BEGIN
      SELECT received_at, raw_ref INTO v_received_at, v_raw_ref
      FROM messages
      WHERE id = v_id AND mailbox_id = p_mailbox_id AND is_deleted;

      IF NOT FOUND THEN
        v_notPurged := v_notPurged || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound'));
        CONTINUE;
      END IF;

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

      v_purged := v_purged || to_jsonb(v_id::TEXT);
    EXCEPTION WHEN OTHERS THEN
      v_notPurged := v_notPurged || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'Purge failed'));
    END;
  END LOOP;

  -- Bump state + push on the canonical 'tag:{mailbox_id}' channel — unless the
  -- caller (IMAP expunge) already notified the soft-delete and only wants the
  -- blob-safe hard-delete. Either way newState reflects the current counter.
  IF p_notify THEN
    v_new_state := notify_state_change(p_mailbox_id, NULL);
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

-- purge_deleted_messages: cron function to auto-hard-delete after 30 days.
CREATE OR REPLACE FUNCTION purge_deleted_messages()
RETURNS INT AS $$
DECLARE
  v_row RECORD;
  v_count INT := 0;
  v_shared INT;
BEGIN
  FOR v_row IN
    SELECT id, received_at, raw_ref, mailbox_id
    FROM messages
    WHERE is_deleted AND deleted_at < NOW() - INTERVAL '1 month'
  LOOP
    BEGIN
      -- Deduplication check
      SELECT COUNT(*) INTO v_shared
      FROM messages
      WHERE raw_ref = v_row.raw_ref
        AND (id != v_row.id OR received_at != v_row.received_at);

      IF v_shared = 0 THEN
        INSERT INTO orphaned_message_blobs(raw_ref)
        VALUES (v_row.raw_ref)
        ON CONFLICT DO NOTHING;
      END IF;

      DELETE FROM messages
      WHERE id = v_row.id AND received_at = v_row.received_at;

      v_count := v_count + 1;
    EXCEPTION WHEN OTHERS THEN
      -- Skip failures, they'll be retried next run
      CONTINUE;
    END;
  END LOOP;

  RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- jmap_email_set_create: create new email messages (drafts / composed messages).
--
-- INPUT: p_mailbox_id (BIGINT, REQUIRED) — mailbox ID (ownership verified via parseAccountID)
-- INPUT: p_creates (JSONB, REQUIRED) — map of creation_id → email object
--   Per-object fields:
--   - mailboxIds (JSONB object, REQUIRED) — {tag_id: true, ...}
--   - from, to, cc, bcc, replyTo (JSONB arrays) — address lists
--   - subject, bodyText, bodyHTML (TEXT) — message content
--   - voteOptions, voteResponse, readReceiptRequested (optional)
-- SIDE EFFECTS: INSERT messages + message_tags; bump jmap_state; pg_notify
-- VALIDATION: mailboxIds must be JSON object; check_quota() before INSERT
CREATE OR REPLACE FUNCTION jmap_email_set_create(
  p_mailbox_id BIGINT,
  p_creates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_created      JSONB := '{}'::JSONB;
  v_notCreated   JSONB := '{}'::JSONB;
  v_new_state    BIGINT;
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

  -- Bump state + push on the canonical 'tag:{mailbox_id}' channel.
  v_new_state := notify_state_change(p_mailbox_id, NULL);

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', (v_new_state - 1)::TEXT,
    'newState', v_new_state::TEXT,
    'created', v_created,
    'notCreated', v_notCreated
  );
END;
$$ LANGUAGE plpgsql;
