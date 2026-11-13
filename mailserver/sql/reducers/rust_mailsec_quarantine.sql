-- Frozen Go's quarantine release/reject (user QuarantineHandler and admin
-- QuarantineHandler) as one transaction each: the ownership-gated UPDATE, then the tag
-- rewrite (release) or message removal (reject). Go commits the UPDATE and the follow-up
-- separately; here a failing follow-up rolls the UPDATE back too.
--
-- p_admin replaces the owner predicate with the admin's reach (the caller already passed
-- the permission gate); otherwise the row must sit in one of the verified user's own
-- mailboxes, in the same WHERE as the UPDATE (R3, no TOCTOU).
-- Owner-approved security fix 2026-11-05 (#448): frozen Go's admin Release/Reject had no
-- per-domain filter. The admin path now requires admin_can_reach_perm over security.write
-- for the owner of the mailbox stored on the quarantine row, in the same WHERE as the
-- UPDATE: a domain-scoped admin cannot release or reject another domain's mail, and a
-- foreign row answers exactly like a missing one (false -> 404).
-- Returns false when no row matched ("not found or already processed"), true otherwise.
CREATE OR REPLACE FUNCTION rust_mailsec_quarantine_release(
 p_actor bigint,p_id bigint,p_admin boolean
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
 v_message bigint; v_mailbox bigint; v_tag text;
BEGIN
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

CREATE OR REPLACE FUNCTION rust_mailsec_quarantine_reject(
 p_actor bigint,p_id bigint,p_admin boolean
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
 v_message bigint;
BEGIN
 UPDATE quarantined_messages SET rejected_at = now(), rejected_by = p_actor
  WHERE id = p_id AND released_at IS NULL
    AND (CASE WHEN p_admin
         THEN admin_can_reach_perm(p_actor, (SELECT mb.user_id FROM mailboxes mb WHERE mb.id = quarantined_messages.mailbox_id), ARRAY['security.write'])
         ELSE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = p_actor) END)
  RETURNING message_id INTO v_message;
 IF NOT FOUND THEN RETURN false; END IF;
 IF p_admin THEN
  -- Go's admin Reject ignores the DELETE's error and still answers "rejected".
  BEGIN
   DELETE FROM messages WHERE id = v_message;
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
 ELSE
  UPDATE messages SET is_deleted = TRUE WHERE id = v_message;
 END IF;
 RETURN true;
END;
$$;
