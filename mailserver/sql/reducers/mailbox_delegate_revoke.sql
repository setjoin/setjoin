-- mailbox_delegate_revoke.sql — revoke a mailbox delegate (all of the grantee's
-- permission rows on the mailbox; spec 2026-06-27-sharing-delegation-design.md
-- §4 / D8). Counterpart of mailbox_delegate_grant.
--
-- SECURITY (R1–R3): p_actor_user_id is claims.UserID from auth context.
-- Ownership rides in the DELETE's own WHERE (no TOCTOU); a non-owner deletes
-- zero rows and gets BZ114 — 404-indistinguishable from a missing mailbox.
-- An owner revoking a non-delegate is an idempotent no-op (no audit).
CREATE OR REPLACE FUNCTION mailbox_delegate_revoke(
  p_actor_user_id   BIGINT,
  p_mailbox_id      BIGINT,
  p_grantee_user_id BIGINT
) RETURNS VOID AS $$
DECLARE
  v_removed JSONB;
BEGIN
  WITH removed AS (
    DELETE FROM mailbox_delegates md
    WHERE md.mailbox_id = p_mailbox_id
      AND md.user_id = p_grantee_user_id
      AND EXISTS (SELECT 1 FROM mailboxes
                   WHERE id = p_mailbox_id AND user_id = p_actor_user_id)
    RETURNING md.permission
  )
  SELECT jsonb_agg(permission) INTO v_removed FROM removed;

  IF v_removed IS NULL THEN
    IF NOT EXISTS (SELECT 1 FROM mailboxes
                    WHERE id = p_mailbox_id AND user_id = p_actor_user_id) THEN
      RAISE EXCEPTION 'Mailbox not found'
        USING ERRCODE = 'BZ114',
              HINT = jsonb_build_object('type','sharing_not_owner',
                                        'mailbox_id', p_mailbox_id)::TEXT;
    END IF;
    RETURN;  -- owner, nothing to revoke: idempotent
  END IF;

  -- D8: one immutable audit row per revoke, tier core.
  PERFORM audit_write(
    p_actor_user_id, 'mailbox_delegate_revoked', 'mailbox_delegate', p_mailbox_id,
    jsonb_build_object('mailbox_id', p_mailbox_id,
                       'grantee_user_id', p_grantee_user_id,
                       'permissions', v_removed),
    NULL,
    NULL, NULL, 'core');
END;
$$ LANGUAGE plpgsql;
