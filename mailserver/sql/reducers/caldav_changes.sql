-- caldav_changes: the per-COLLECTION RFC 6578 sync-collection delta for the
-- CalDAV/CardDAV bridges. Same resync/pruned/future guards as jmap_entity_changes
-- (the JMAP /changes reader), but scoped to a single collection (calendar or
-- addressbook) and shaped for WebDAV: changed resources carry their live href
-- token + etag, removed resources carry the href token recovered from the journal.
--
-- The sync token is the mailbox-wide entity_state(mailbox, datatype) counter —
-- RFC 6578 tokens are per-collection but reusing the datatype counter is legal:
-- the token may advance with no change to THIS collection (harmless — an empty
-- delta with a fresh token). newToken is always the current counter.
--
-- R1: every journal/live query filters by p_mailbox_id (CallScoped sets the GUC
-- to the same value, so the FORCE'd journal is readable under setjoin_app).
--
-- Result: {newToken TEXT, resync BOOL, changed [{uid,etag}], removed [uid]}.
-- resync=TRUE → the handler renders DAV:valid-sync-token (HTTP 403) → full sync.
CREATE OR REPLACE FUNCTION caldav_changes(
  p_mailbox_id    BIGINT,
  p_datatype      TEXT,
  p_collection_id BIGINT,
  p_since_token   TEXT
) RETURNS JSONB AS $$
DECLARE
  v_current BIGINT := entity_state(p_mailbox_id, p_datatype);  -- R1
  v_since   BIGINT := COALESCE(NULLIF(p_since_token, ''), '0')::BIGINT;
  v_oldest  BIGINT;
  v_changed JSONB  := '[]'::JSONB;
  v_removed JSONB  := '[]'::JSONB;
  v_uid       TEXT;
  v_etag      TEXT;
  v_is_master BOOLEAN;
  r RECORD;
BEGIN
  -- Future token → resync (RFC 6578 §3.6: token the server never issued).
  IF v_since > v_current THEN
    RETURN jsonb_build_object('newToken', v_current::TEXT, 'resync', TRUE,
                              'changed', '[]'::JSONB, 'removed', '[]'::JSONB);
  END IF;

  -- Pruned: sinceToken predates the oldest retained journal row for this datatype.
  -- since=0 always means initial full sync, never pruned.
  SELECT MIN(state_seq) INTO v_oldest
    FROM jmap_changes_journal
   WHERE mailbox_id = p_mailbox_id AND datatype = p_datatype;  -- R1
  IF v_since > 0 AND (v_oldest IS NULL OR v_since < v_oldest - 1) THEN
    RETURN jsonb_build_object('newToken', v_current::TEXT, 'resync', TRUE,
                              'changed', '[]'::JSONB, 'removed', '[]'::JSONB);
  END IF;

  -- Resync sentinel (mailbox-wide for this datatype, collection-agnostic) anywhere
  -- in (since, current] → coarse path → resync all collections of this datatype.
  IF EXISTS (
    SELECT 1 FROM jmap_changes_journal
     WHERE mailbox_id = p_mailbox_id AND datatype = p_datatype
       AND state_seq > v_since AND op = 'resync'  -- R1
  ) THEN
    RETURN jsonb_build_object('newToken', v_current::TEXT, 'resync', TRUE,
                              'changed', '[]'::JSONB, 'removed', '[]'::JSONB);
  END IF;

  -- Collapse per entity_id within THIS collection (latest op wins;
  -- created+destroyed-in-window cancels).
  FOR r IN
    WITH per_id AS (
      SELECT entity_id,
             (array_agg(op           ORDER BY state_seq DESC))[1] AS latest_op,
             (array_agg(resource_uid ORDER BY state_seq DESC))[1] AS last_uid,
             bool_or(op = 'created') AS had_created,
             MAX(state_seq)          AS max_seq
        FROM jmap_changes_journal
       WHERE mailbox_id = p_mailbox_id AND datatype = p_datatype
         AND collection_id = p_collection_id  -- R1 + per-collection scope
         AND state_seq > v_since AND op <> 'resync'
       GROUP BY entity_id
    )
    SELECT entity_id, latest_op, last_uid, had_created, max_seq
      FROM per_id ORDER BY max_seq, entity_id
  LOOP
    -- created + destroyed since the token → noop (omit).
    IF r.had_created AND r.latest_op = 'destroyed' THEN
      CONTINUE;
    END IF;

    IF r.latest_op = 'destroyed' THEN
      -- Removed: href token from the journal (live row is gone), etag null.
      -- COALESCE guards pre-V098 rows that predate resource_uid.
      v_removed := v_removed || to_jsonb(COALESCE(r.last_uid, r.entity_id::TEXT));
    ELSE
      -- Created/updated: look up the LIVE row's uid + etag, scoped to this
      -- mailbox + collection (R1). is_master (CalendarEvent only) distinguishes
      -- a recurring series' master row from a detached-occurrence override row
      -- sharing the same uid — Task 6 made uid the CalDAV resource identity, so
      -- an occurrence edit touching BOTH rows in one transaction must not
      -- surface as two 'changed' entries for one href (dedup below).
      v_uid := NULL; v_etag := NULL; v_is_master := TRUE;
      IF p_datatype = 'CalendarEvent' THEN
        SELECT ce.uid, ce.etag, ce.recurrence_override IS NULL INTO v_uid, v_etag, v_is_master
          FROM calendar_events ce JOIN calendars c ON c.id = ce.calendar_id
         WHERE ce.id = r.entity_id AND c.mailbox_id = p_mailbox_id
           AND ce.calendar_id = p_collection_id;
      ELSIF p_datatype = 'ContactCard' THEN
        SELECT ct.vcard_uid, ct.etag INTO v_uid, v_etag
          FROM contacts ct JOIN addressbooks ab ON ab.id = ct.addressbook_id
         WHERE ct.id = r.entity_id AND ab.mailbox_id = p_mailbox_id
           AND ct.addressbook_id = p_collection_id;
      END IF;
      -- Row vanished (raced destroy without a journal row): skip — no href to emit.
      IF v_uid IS NOT NULL THEN
        v_changed := v_changed || jsonb_build_object('uid', v_uid, 'etag', COALESCE(v_etag, ''), 'isMaster', v_is_master);
      END IF;
    END IF;
  END LOOP;

  -- Dedup 'changed' by uid: an occurrence edit bumps BOTH the master row
  -- (exdate/etag) and its override sibling (insert/update) in one transaction,
  -- and both share the master's uid (Task 6: one CalDAV resource per uid).
  -- Prefer the master's live etag — clients re-GET the whole resource,
  -- including any inline overrides, keyed on the master's etag.
  SELECT COALESCE(jsonb_agg(jsonb_build_object('uid', x.uid, 'etag', x.etag)), '[]'::jsonb)
    INTO v_changed
    FROM (
      SELECT DISTINCT ON (c.uid) c.uid, c.etag
        FROM jsonb_to_recordset(v_changed) AS c(uid TEXT, etag TEXT, "isMaster" BOOLEAN)
       ORDER BY c.uid, c."isMaster" DESC NULLS LAST
    ) x;

  -- A uid that still has ANY live representation is 'changed', not 'removed':
  -- deleting a detached occurrence (excluded:true) destroys the OVERRIDE row
  -- while the master resource survives — that must not read as the whole
  -- resource gone (RFC 4791 §4.1 — removed means the href itself is gone).
  SELECT COALESCE(jsonb_agg(u.rem), '[]'::jsonb) INTO v_removed
    FROM jsonb_array_elements_text(v_removed) AS u(rem)
   WHERE NOT EXISTS (
     SELECT 1 FROM jsonb_array_elements(v_changed) ch WHERE ch->>'uid' = u.rem
   );

  RETURN jsonb_build_object(
    'newToken', v_current::TEXT,
    'resync',   FALSE,
    'changed',  v_changed,
    'removed',  v_removed
  );
END;
$$ LANGUAGE plpgsql;
