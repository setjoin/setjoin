-- mailserver/sql/reducers/drive_branch_set_status.sql
-- Only the open<->review transitions live here; merged/discarded only ever
-- happen through drive_branch_resolve (else BZ150). review is the
-- CODEOWNERS-style merge-request moment (§5.5d, §5.6) -- audited; the
-- open<-review reversal is a plain status flip (no dedicated catalog action
-- for "un-review" -- audit only the forward transition, drive_watch_set's
-- "not every mutation needs an audit row" precedent).
CREATE OR REPLACE FUNCTION drive_branch_set_status(
  p_user_id BIGINT, p_branch_id BIGINT, p_status TEXT
) RETURNS VOID AS $$
DECLARE v_space BIGINT; v_file BIGINT; v_cur TEXT;
BEGIN
  SELECT space_id, file_node_id, status INTO v_space, v_file, v_cur
    FROM drive_file_branches WHERE id = p_branch_id;
  IF v_space IS NULL THEN
    RAISE EXCEPTION 'branch not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"branch not found"}';
  END IF;
  PERFORM public.drive_require_node_capability(
    p_user_id,v_file,'modify_content');
  IF p_status NOT IN ('open','review') OR v_cur NOT IN ('open','review') THEN
    RAISE EXCEPTION 'invalid branch status transition' USING ERRCODE='BZ150',
      HINT='{"type":"branchError","detail":"only open/review transitions here; merge or discard via resolve"}';
  END IF;

  UPDATE drive_file_branches SET status = p_status WHERE id = p_branch_id;
  IF p_status = 'review' THEN
    PERFORM drive_access_audit(p_user_id, v_space, 'branch.review', 'branch', p_branch_id,
      jsonb_build_object('status', v_cur), jsonb_build_object('status', p_status), NULL, NULL);
    -- Fan-out (Task 8): best-effort, never unwinds the status change.
    BEGIN
      PERFORM drive_notify_event('branch.review', p_user_id, v_space, v_file, p_branch_id);
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END IF;
  PERFORM drive_notify_change(v_space, v_file, 'update');
END;
$$ LANGUAGE plpgsql;
