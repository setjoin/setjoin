-- gal_changes: RFC 6578 sync-collection delta for the read-only GAL CardDAV
-- collection (/carddav/gal/). Change clock = users.updated_at (µs); visibility
-- = directory_visible_users (ADR-004 seam). The (micros, count) token pair
-- detects hard-deletes: a count mismatch forces resync (client full-syncs).
--
-- REMOVAL AXIS (V261, CARDDAV-V-002): the removed set is restricted to the
-- caller's gal_visibility_journal — the members this mailbox was actually
-- DISCLOSED (every delta journals its changed set through
-- gal_visibility_record atomically with the response, so "reported present"
-- and "journaled" are the same event). A never-visible directory id is
-- structurally impossible to report as removed: it was never journaled, no
-- matter how the hard-delete count arithmetic happens to balance (the
-- id-and-timing residual the count guard alone left open — triage
-- D-MAILSERVER-INTERNAL-CARDDAV-V-002). A journaled member whose users row
-- is hard-deleted cascades out of the journal, so hard-deletes keep flowing
-- through the count guard to a forced resync, unchanged. Volatile: it writes
-- the journal (disclosure recording) in-transaction.
CREATE OR REPLACE FUNCTION gal_changes(
  p_mailbox_id   BIGINT,
  p_since_micros BIGINT,  -- 0 = initial sync
  p_since_count  BIGINT   -- visible count at token issue; ignored when p_since_micros = 0
) RETURNS JSONB AS $$
DECLARE
  v_since     TIMESTAMPTZ;
  v_now_max   BIGINT;
  v_count     BIGINT;
  v_changed   JSONB;
  v_removed   JSONB;
  v_new       BIGINT;
  v_gone      BIGINT;
  v_seen_ids  BIGINT[];
BEGIN
  IF NOT EXISTS (SELECT 1 FROM mailboxes WHERE id = p_mailbox_id) THEN
    RAISE EXCEPTION 'gal_changes: unknown caller mailbox %', p_mailbox_id
      USING ERRCODE = 'BZ001';
  END IF;

  v_since := to_timestamp(p_since_micros / 1e6);

  SELECT COUNT(*) INTO v_count FROM directory_visible_users(p_mailbox_id);

  SELECT COALESCE(MAX((EXTRACT(EPOCH FROM u.updated_at) * 1e6)::BIGINT), p_since_micros)
    INTO v_now_max
    FROM users u;

  -- changed: visible users touched since the token (everything on initial sync)
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'id',   v.id,
           'etag', 'u' || v.id || '-' || (EXTRACT(EPOCH FROM u.updated_at) * 1e6)::BIGINT
         ) ORDER BY v.id), '[]'::JSONB)
    INTO v_changed
    FROM directory_visible_users(p_mailbox_id) v
    JOIN users u ON u.id = v.id
   WHERE p_since_micros = 0 OR u.updated_at > v_since;

  -- removed: JOURNALED (previously disclosed to this mailbox) users touched
  -- since the token who are no longer visible (disabled / newly
  -- hidden_from_gal). Initial sync never reports removals. gal_journal_seen
  -- is the FORCE-RLS journal's trusted membership predicate — the join keeps
  -- the removed set inside what this caller has actually seen, so a
  -- never-visible user touched in the same window as an unrelated count
  -- disturbance can never be rendered as a removal (CARDDAV-V-002).
  SELECT COALESCE(jsonb_agg(jsonb_build_object('id', u.id) ORDER BY u.id), '[]'::JSONB)
    INTO v_removed
    FROM users u
   WHERE p_since_micros > 0
     AND u.updated_at > v_since
     AND gal_journal_seen(p_mailbox_id, u.id)
     AND NOT EXISTS (SELECT 1 FROM directory_visible_users(p_mailbox_id) v WHERE v.id = u.id);

  -- Journal exactly what this delta DISCLOSES, atomically with the response
  -- that discloses it: an incremental delta's touched members, or — on
  -- initial sync — the whole visible set, so the journal is primed for every
  -- future removal decision. Re-recording is a no-op (ON CONFLICT DO
  -- NOTHING). gal_visibility_record re-filters through the seam (single
  -- writer, R1-by-resolution) and is a no-op on ids the seam no longer shows.
  SELECT COALESCE(array_agg(DISTINCT (e->>'id')::BIGINT), '{}')
    INTO v_seen_ids
    FROM jsonb_array_elements(v_changed) e;
  PERFORM gal_visibility_record(p_mailbox_id, v_seen_ids);

  -- hard-delete guard: since_count + newly-visible - newly-invisible must equal
  -- the current count; a deleted row breaks the equation (its updated_at is gone).
  IF p_since_micros > 0 THEN
    SELECT COUNT(*) INTO v_new
      FROM directory_visible_users(p_mailbox_id) v
      JOIN users u ON u.id = v.id
     WHERE u.created_at > v_since;
    v_gone := jsonb_array_length(v_removed);
    IF p_since_count + v_new - v_gone <> v_count THEN
      RETURN jsonb_build_object('resync', TRUE);
    END IF;
  END IF;

  RETURN jsonb_build_object(
    'resync',    FALSE,
    'changed',   v_changed,
    'removed',   v_removed,
    'newMicros', v_now_max,
    'newCount',  v_count
  );
END;
$$ LANGUAGE plpgsql VOLATILE;
