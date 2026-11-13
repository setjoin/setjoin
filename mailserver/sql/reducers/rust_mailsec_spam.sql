-- Frozen Go's multi-statement spam-slice writes (F06 slice spam) as one transaction each.
-- Ownership comes from the verified token (p_user), never a request field, and sits in the
-- same statement as each write (R2/R3).

-- PUT /settings/senders with feature.sender_control_center OFF: Go deletes the user's whole
-- list and re-inserts every entry in one transaction (plain INSERTs, so a duplicate entry
-- hits the primary key and rolls the whole replacement back).
CREATE OR REPLACE FUNCTION rust_mailsec_sender_list_replace(
 p_user bigint,p_safe text[],p_blocked text[]
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 DELETE FROM user_sender_list WHERE user_id = p_user;
 INSERT INTO user_sender_list (user_id, sender, list_type)
  SELECT p_user, s, 'safe' FROM unnest(COALESCE(p_safe, '{}')) WITH ORDINALITY AS t(s, n) ORDER BY n;
 INSERT INTO user_sender_list (user_id, sender, list_type)
  SELECT p_user, s, 'blocked' FROM unnest(COALESCE(p_blocked, '{}')) WITH ORDINALITY AS t(s, n) ORDER BY n;
 RETURN true;
END;
$$;

-- POST /settings/senders/never-block (flag OFF): drop the sender from the blocked list and
-- add it to the safe list. Go runs the two statements on the pool, one after the other;
-- here they commit together.
CREATE OR REPLACE FUNCTION rust_mailsec_sender_never_block(p_user bigint,p_sender text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 DELETE FROM user_sender_list WHERE user_id = p_user AND sender = p_sender AND list_type = 'blocked';
 INSERT INTO user_sender_list (user_id, sender, list_type) VALUES (p_user, p_sender, 'safe')
  ON CONFLICT (user_id, sender, list_type) DO NOTHING;
 RETURN true;
END;
$$;

-- POST /report (flag OFF): the audit row for a report against a message in the caller's own
-- mailbox (ownership in the WHERE, unknown and foreign ids read alike: false). A spam report
-- is also a training signal: Go hands it to its in-process trainer queue, which a Rust
-- process cannot reach, so the same transaction emits the spam_train notification the
-- message_tags trigger uses (user_id, message_id, is_spam), which any trainer consumes.
CREATE OR REPLACE FUNCTION rust_mailsec_report(
 p_user bigint,p_message bigint,p_type text,p_note text
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
                 WHERE m.id = p_message AND mb.user_id = p_user) THEN
  RETURN false;
 END IF;
 PERFORM audit_write(p_user, 'report_' || p_type, 'message', p_message, NULL, NULL, NULL, p_note, 'routine');
 IF p_type = 'spam' THEN
  PERFORM pg_notify('spam_train',
   json_build_object('user_id', p_user, 'message_id', p_message, 'is_spam', TRUE)::text);
 END IF;
 RETURN true;
END;
$$;
