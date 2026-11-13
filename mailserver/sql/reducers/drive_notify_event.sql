-- mailserver/sql/reducers/drive_notify_event.sql
-- P4 human fan-out (LR-3, §5.6). Genre: notify_task_assignee
-- (jmap_task.sql:169) — deliver() a one-off system message into each
-- recipient's primary mailbox; best-effort per recipient (EXCEPTION
-- swallow) so a delivery failure never unwinds the triggering write.
-- English bodies (system-mail precedent; ponytail: per-recipient locale for
-- system mail is a repo-wide item, not a Drive-specific one).
--
-- AUTOPLAN batch-1 #4 (BLOCKER — RLS-blind fan-out): drive_watches' own SELECT
-- policy is own-rows-only (drive_watches_own_read), and drive_folder_admins'
-- read policy is member-only — an invoker-rights recipient resolver running
-- as the ACTOR would see only the actor's own watch row and (if a member)
-- the folder-admin roster, never OTHER members' watch rows. drive_event_recipients
-- is therefore SECURITY DEFINER (the LR-12 posture), worker-owned, PUBLIC-revoked.
--
-- Revocation posture (D-MAILSERVER-INTERNAL-DRIVE-R-001): both subscription
-- arms re-derive the observer's CURRENT read capability on the event node via
-- drive_runtime_has_node_capability — the same authority drive_watch_set gates
-- watch creation with and drive_acl_revoke_bound_artifacts prunes stale bound
-- artifacts with. On legacy-mode spaces drive_member_revoke prunes watches only
-- via the acl-mode drive_acl_bump path, so a removed member's watch/folder-admin
-- row can outlive their membership; without this per-event re-derivation the
-- watcher email fan-out would stay a near-real-time activity oracle for anyone
-- whose access was revoked by a non-cutover path. Directed arms (branch
-- creator, lock holder) are untouched — lock rows are already pruned by
-- drive_acl_revoke_bound_artifacts on access loss.
CREATE OR REPLACE FUNCTION drive_event_recipients(
  p_node_id BIGINT, p_event TEXT, p_actor BIGINT,
  p_branch_creator BIGINT DEFAULT NULL, p_lock_holder BIGINT DEFAULT NULL
) RETURNS SETOF BIGINT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  WITH node_space AS (
    SELECT space_id FROM drive_nodes WHERE id = p_node_id
  ), up AS (
    SELECT a.node_id AS id
      FROM node_space s
      CROSS JOIN LATERAL drive_closure_ancestors(s.space_id, p_node_id) a
  ), observers AS (
    SELECT w.user_id FROM drive_watches w JOIN up ON up.id = w.node_id
     WHERE p_event IN ('branch.conflict', 'branch.review')
       AND (w.ops IS NULL OR 'branch' = ANY(w.ops))
       AND public.drive_runtime_has_node_capability(w.user_id, p_node_id, 'read_metadata')
    UNION
    SELECT fa.user_id FROM drive_folder_admins fa JOIN up ON up.id = fa.node_id
     WHERE p_event IN ('branch.conflict', 'branch.review')
       AND public.drive_runtime_has_node_capability(fa.user_id, p_node_id, 'read_metadata')
    UNION
    SELECT p_branch_creator WHERE p_event = 'branch.review' AND p_branch_creator IS NOT NULL
    UNION
    SELECT p_lock_holder WHERE p_event = 'lock.break' AND p_lock_holder IS NOT NULL
  )
  SELECT DISTINCT user_id FROM observers WHERE user_id IS NOT NULL AND user_id <> p_actor;
$$;

SELECT apply_worker_ownership('drive_event_recipients(BIGINT, TEXT, BIGINT, BIGINT, BIGINT)'::regprocedure);

-- drive_notify_event: builds the per-event copy and delivers it. Invoker-
-- rights (it only calls the DEFINER recipient resolver above + deliver(),
-- neither of which needs THIS function itself to hold elevated rights).
-- Callers wrap every PERFORM of this function in their own
-- BEGIN…EXCEPTION WHEN OTHERS THEN NULL block (the triggering write must
-- never be unwound by a fan-out failure) — this function ALSO swallows
-- per-recipient delivery failures as defense in depth.
CREATE OR REPLACE FUNCTION drive_notify_event(
  p_event TEXT, p_actor BIGINT, p_space_id BIGINT, p_node_id BIGINT,
  p_branch_id BIGINT DEFAULT NULL, p_lock_holder BIGINT DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
  v_name TEXT; v_branch_name TEXT; v_branch_creator BIGINT;
  v_actor_name TEXT;
  v_rcpt_id BIGINT; v_rcpt_email TEXT;
  v_subject TEXT; v_body TEXT; v_ref TEXT;
BEGIN
  SELECT n.name INTO v_name FROM drive_nodes n WHERE n.id = p_node_id;
  IF p_branch_id IS NOT NULL THEN
    SELECT b.name, b.created_by INTO v_branch_name, v_branch_creator
      FROM drive_file_branches b WHERE b.id = p_branch_id;
  END IF;
  SELECT COALESCE(m.display_name, m.email) INTO v_actor_name
    FROM mailboxes m WHERE m.user_id = p_actor AND m.is_primary;
  v_actor_name := COALESCE(v_actor_name, 'Someone');
  v_name := COALESCE(v_name, 'a file');
  v_branch_name := COALESCE(v_branch_name, '');

  -- Actor-directed copy (branch.conflict only — the saver needs to know
  -- their OWN save was kept as a branch; wording differs from observers').
  IF p_event = 'branch.conflict' THEN
    SELECT email INTO v_rcpt_email FROM mailboxes WHERE user_id = p_actor AND is_primary;
    IF v_rcpt_email IS NOT NULL THEN
      v_ref := 'drive-' || p_event || '/' || p_node_id::TEXT || '/actor/' || extract(epoch FROM clock_timestamp())::BIGINT;
      v_subject := 'Your save of ' || v_name || ' conflicted — kept as branch "' || v_branch_name || '"';
      v_body := 'Your save of ' || v_name || ' conflicted with another change — kept as branch "' ||
                v_branch_name || '". Review & merge in Drive.';
      BEGIN
        PERFORM deliver(v_ref, '<' || v_ref || '@mailserver.local>',
          'drive@mailserver.local', 'Drive', v_rcpt_email,
          jsonb_build_array(jsonb_build_object('email', v_rcpt_email)),
          '[]'::JSONB, '[]'::JSONB, v_subject, NULL, NULL, v_body, NULL,
          octet_length(v_body)::BIGINT, FALSE, now(), 'pass', NULL, NULL, 0.0, NULL);
      EXCEPTION WHEN OTHERS THEN NULL;
      END;
    END IF;
  END IF;

  -- Observer copy (watchers + folder admins + (review-only) branch creator).
  v_subject := CASE p_event
    WHEN 'branch.conflict' THEN v_name || ' has a new branch'
    WHEN 'branch.review'   THEN 'Branch ready for review: ' || v_branch_name
    WHEN 'lock.break'      THEN 'Your checkout was released'
    ELSE p_event END;
  v_body := CASE p_event
    WHEN 'branch.conflict' THEN v_name || ' now has a new branch "' || v_branch_name ||
      '" (by ' || v_actor_name || '). Review & merge in Drive.'
    WHEN 'branch.review' THEN v_actor_name || ' marked branch "' || v_branch_name ||
      '" of ' || v_name || ' ready for review.'
    WHEN 'lock.break' THEN 'Your checkout of ' || v_name || ' was released by ' || v_actor_name || '.'
    ELSE NULL END;

  FOR v_rcpt_id IN
    SELECT * FROM drive_event_recipients(p_node_id, p_event, p_actor, v_branch_creator, p_lock_holder)
  LOOP
    SELECT email INTO v_rcpt_email FROM mailboxes WHERE user_id = v_rcpt_id AND is_primary;
    CONTINUE WHEN v_rcpt_email IS NULL;
    v_ref := 'drive-' || p_event || '/' || p_node_id::TEXT || '/' || v_rcpt_id::TEXT || '/' ||
             extract(epoch FROM clock_timestamp())::BIGINT;
    BEGIN
      PERFORM deliver(v_ref, '<' || v_ref || '@mailserver.local>',
        'drive@mailserver.local', 'Drive', v_rcpt_email,
        jsonb_build_array(jsonb_build_object('email', v_rcpt_email)),
        '[]'::JSONB, '[]'::JSONB, v_subject, NULL, NULL, v_body, NULL,
        octet_length(v_body)::BIGINT, FALSE, now(), 'pass', NULL, NULL, 0.0, NULL);
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END LOOP;
END;
$$ LANGUAGE plpgsql;
