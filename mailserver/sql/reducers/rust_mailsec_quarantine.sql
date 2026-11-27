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
