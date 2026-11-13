-- content_purge_messages: hard-deletes messages across mailboxes for
-- the Content Search & Purge admin tool. Skips messages under litigation
-- hold (the DELETE trigger blocks them; caught per-row).
-- Writes a single admin_audit_log entry for the batch.
--
-- Authorization is ROUTE-DECLARED, not in-reducer. The calling Go route
-- (POST /admin/content-search/delete) is gated on
-- RequirePermAudited(PermComplianceWrite, …) in main.go. The former
-- admin_role = 'super_admin' / is_local_admin self-authorization block has
-- been removed as part of the RBAC unification cut-over (Task 5).
-- p_admin_user_id is retained for audit provenance (recorded in
-- admin_audit_log via p_admin_user) but is no longer used for authorization.

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
BEGIN
  FOREACH v_id IN ARRAY p_message_ids LOOP
    BEGIN
      DELETE FROM messages WHERE id = v_id RETURNING mailbox_id INTO v_mbid;
      IF NOT FOUND THEN
        v_not_found := v_not_found + 1;
        CONTINUE;
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
