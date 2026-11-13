-- mailserver/sql/reducers/meeting_space_ensure.sql
--
-- Meet B2 — lazy org-governed Drive space per meeting (the chat_space_ensure
-- clone, spec §5).
--
-- Worker-owned SECURITY DEFINER: called ONLY by the ingest worker leg (no
-- user route reaches it), and the drive_spaces INSERT must not trip the
-- owner-GUC WITH CHECK at the native-RLS flip. No membership gate: the
-- caller is the worker, and membership of the RESULT is derived (arm 3),
-- never mirrored — this reducer writes ZERO drive_space_members rows
-- (DES-009 D2).
--
-- Deliberately NOT cloned from chat_space_ensure.sql:81: the 100 MiB
-- export_policy upload_max_bytes cap — BZ148 at drive_file_put_version.sql
-- would fail every real recording (spec §5, verbatim). quota_bytes NULL:
-- server-governed content, not user quota.
--
-- D6 seam (org retention knob): stamp classification/retention here from an
-- org setting when a customer demands it — exactly how gxp chat channels
-- stamp theirs; one INSERT-values change.
CREATE OR REPLACE FUNCTION meeting_space_ensure(p_meeting_id bigint)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_space_id bigint;
  v_title    text;
  v_owner    bigint;
BEGIN
  SELECT id INTO v_space_id FROM drive_spaces WHERE meeting_id = p_meeting_id;
  IF FOUND THEN
    RETURN v_space_id;
  END IF;

  SELECT title, owner_user_id INTO v_title, v_owner
    FROM meetings WHERE id = p_meeting_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'meeting % not found', p_meeting_id
      USING ERRCODE='BZ185', HINT='{"type":"notFound"}';
  END IF;

  INSERT INTO drive_spaces (name, classification, owner_user_id, meeting_id, quota_bytes)
  VALUES (left(btrim('Meeting — ' || COALESCE(v_title, p_meeting_id::text)), 200),
          'regular', v_owner, p_meeting_id, NULL)
  ON CONFLICT (meeting_id) WHERE meeting_id IS NOT NULL DO NOTHING
  RETURNING id INTO v_space_id;

  IF v_space_id IS NULL THEN
    -- lost the provisioning race (drive_spaces_meeting_uq): re-read the winner.
    SELECT id INTO v_space_id FROM drive_spaces WHERE meeting_id = p_meeting_id;
    RETURN v_space_id;
  END IF;

  PERFORM drive_access_audit(v_owner, v_space_id, 'space.create', 'space', v_space_id, NULL,
    jsonb_build_object('name', 'Meeting — ' || COALESCE(v_title, p_meeting_id::text),
                       'classification', 'regular', 'meetingId', p_meeting_id),
    NULL, NULL);
  PERFORM drive_notify_change(v_space_id, 0, 'space');
  RETURN v_space_id;
END;
$$;
SELECT apply_worker_ownership('meeting_space_ensure(bigint)'::regprocedure);
