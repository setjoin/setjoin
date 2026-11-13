-- recall_message(): find unread internal copies of a message by RFC 5322 Message-ID,
-- move them to Trash, insert a recall-stub notice, and return a caller-safe verdict.
--
-- p_message_id: RFC 5322 Message-ID of the original message
-- p_recaller_user_id: user initiating the recall (explicit for future admin recall)
-- p_recaller_mailbox_id: mailbox initiating the recall
-- p_recall_source: 'user' | 'admin' (for future admin-initiated recall)
--
-- Returns JSONB: { type: 'success'|'notFound'|'alreadyRecalled'|'disabled', recalled: BOOL }
--   The TRUE copy_count / cannot_count are written to the internal message_recalls
--   audit row; they are deliberately NOT in the return (see RESIDUAL BOUND below).
--
-- RESIDUAL BOUND — until a server-stamped correlation key exists (see
-- 2026-06-19-recall-harden.md NEXT), recall stays unread-only + local-only +
-- soft-to-Trash + stub; no read messages, no hard-delete, no remote. Message-ID is
-- forgeable; do not widen. The success return must NOT expose the global
-- copyCount / cannotCount / per-recipient breakdown: under Message-ID forgery that
-- is a cross-mailbox recipient-state enumeration ORACLE. Caller sees only a
-- self-scoped verdict (type + recalled); the true counts live in the audit row.
CREATE OR REPLACE FUNCTION recall_message(
    p_message_id          TEXT,
    p_recaller_user_id    BIGINT,
    p_recaller_mailbox_id BIGINT,
    p_recall_source       TEXT DEFAULT 'user'
) RETURNS JSONB AS $$
DECLARE
    v_recalled   INT := 0;
    v_cannot     INT := 0;
    v_copy       RECORD;
    v_stub_id    BIGINT;
    v_now        TIMESTAMPTZ := now();
    v_orig_msg   RECORD;
    v_feature    BOOL;
    v_state      BIGINT;
BEGIN
    -- Check feature toggle
    SELECT enabled INTO v_feature FROM feature_toggles WHERE key = 'feature.recall';
    IF v_feature IS NOT TRUE THEN
        RETURN jsonb_build_object('type', 'disabled', 'description', 'Recall is disabled');
    END IF;

    -- Get original message metadata from the sender's Sent folder
    SELECT m.id, m.subject, m.from_addr, m.from_name, m.sent_at, m.body_text, m.body_html
    INTO v_orig_msg
    FROM messages m
    WHERE m.message_id = p_message_id
      AND m.mailbox_id = p_recaller_mailbox_id
    LIMIT 1;

    IF v_orig_msg.id IS NULL THEN
        -- Check if already recalled
        IF EXISTS (SELECT 1 FROM message_recalls WHERE message_id = p_message_id) THEN
            RETURN jsonb_build_object(
                'type', 'alreadyRecalled',
                'description', 'This message has already been recalled'
            );
        END IF;
        RETURN jsonb_build_object(
            'type', 'notFound',
            'description', 'Original message not found in your Sent folder'
        );
    END IF;

    -- Find all unread copies delivered to local recipients (same-org domains)
    FOR v_copy IN
        SELECT m.id, m.mailbox_id, m.received_at, m.subject
        FROM messages m
        JOIN mailboxes mb ON mb.id = m.mailbox_id
        JOIN domains d ON d.id = mb.domain_id
        WHERE m.message_id = p_message_id
          AND d.is_local = TRUE
          AND m.is_read = FALSE
          AND m.mailbox_id != p_recaller_mailbox_id  -- not the sender's own Sent copy
        FOR UPDATE
    LOOP
        BEGIN
            -- Move the original to Trash through the single location seam.
            -- recall emits its OWN bespoke 'recalled' push below (richer than a
            -- plain state_change — it carries the stub id), so suppress the
            -- seam's push (p_notify => FALSE). Provenance preserved ('recall').
            PERFORM transition_message_location(v_copy.id, v_copy.received_at, 'Trash', v_copy.mailbox_id, 'recall', FALSE);

            -- Insert a recall-stub notice in the recipient's inbox
            INSERT INTO messages (
                mailbox_id, message_id, subject, from_addr, from_name,
                to_addrs, cc_addrs, bcc_addrs,
                body_text, body_html, size_bytes, has_attachments,
                thread_id, raw_ref, sent_at, received_at,
                is_read, folder_id
            ) VALUES (
                v_copy.mailbox_id,
                'recall-' || p_message_id,
                'Message recalled: ' || COALESCE(v_orig_msg.subject, ''),
                v_orig_msg.from_addr,
                v_orig_msg.from_name,
                '[]'::JSONB, '[]'::JSONB, '[]'::JSONB,
                'The sender recalled the message "' || COALESCE(v_orig_msg.subject, '') ||
                '" sent on ' || to_char(COALESCE(v_orig_msg.sent_at, v_now), 'YYYY-MM-DD HH24:MI') || '.',
                '<p>The sender recalled the message <strong>' ||
                COALESCE(v_orig_msg.subject, '') || '</strong> sent on ' ||
                to_char(COALESCE(v_orig_msg.sent_at, v_now), 'YYYY-MM-DD HH24:MI') || '.</p>',
                0, FALSE,
                (SELECT thread_id FROM messages WHERE id = v_copy.id), 'recall-stub',
                v_now, v_now, TRUE,
                (SELECT id FROM tags WHERE name = 'Inbox' AND mailbox_id = v_copy.mailbox_id)
            ) RETURNING id INTO v_stub_id;

            -- Bind the stub to the recipient's Inbox via message_tags. folder_id alone
            -- does NOT make a message visible: the read path (jmap_email_query inMailbox,
            -- jmap_email_get mailboxIds) is message_tags-based, and the normal create path
            -- (jmap_email_set_create) sets BOTH folder_id AND a message_tags row. Without
            -- this the stub is journaled 'created' but never lists in the recipient's Inbox.
            PERFORM tag_message(v_stub_id, v_now, 'Inbox', v_copy.mailbox_id, 'recall', TRUE);

            -- Bump the recipient's email state OUTSIDE the pg_notify payload (lift
            -- the side-effecting bump into a local first), then reference it. recall
            -- emits its OWN bespoke 'recalled' push here (richer than a plain
            -- state_change — carries the stub id); transition_message_location above
            -- ran with p_notify=FALSE, so this is the single push and there is no
            -- double-bump. NOT rerouted through notify_state_change (that would
            -- double-push the recipient).
            v_state := bump_email_state(v_copy.mailbox_id);
            -- Journal both operations at this single state_seq so jmap_email_changes
            -- can produce a precise delta (offline #3, T6): the recalled copy is
            -- 'updated' (now in Trash), the notice stub is 'created'.
            PERFORM append_email_change(v_copy.mailbox_id, v_state, v_copy.id, 'updated');
            PERFORM append_email_change(v_copy.mailbox_id, v_state, v_stub_id, 'created');

            -- Notify the affected mailbox
            PERFORM app_notify(
                'tag:' || v_copy.mailbox_id,
                json_build_object(
                    'event', 'recalled',
                    'message_id', v_copy.id,
                    'stub_id', v_stub_id,
                    'origin_message_id', p_message_id,
                    'state', v_state
                )::TEXT
            );

            v_recalled := v_recalled + 1;
        EXCEPTION WHEN OTHERS THEN
            v_cannot := v_cannot + 1;
        END;
    END LOOP;

    -- Also report already-read internal copies as cannotRecall
    FOR v_copy IN
        SELECT m.id, m.mailbox_id
        FROM messages m
        JOIN mailboxes mb ON mb.id = m.mailbox_id
        JOIN domains d ON d.id = mb.domain_id
        WHERE m.message_id = p_message_id
          AND d.is_local = TRUE
          AND m.is_read = TRUE
          AND m.mailbox_id != p_recaller_mailbox_id
        FOR UPDATE
    LOOP
        v_cannot := v_cannot + 1;
    END LOOP;

    -- Record the recall. The TRUE copy_count / cannot_count are written here (audit
    -- intact) — they are deliberately absent from the caller-facing return.
    INSERT INTO message_recalls (message_id, recalled_by, recalled_at, copy_count, cannot_count)
    VALUES (p_message_id, p_recaller_user_id, v_now, v_recalled, v_cannot)
    ON CONFLICT (message_id) DO NOTHING;

    -- Caller-safe verdict only. Closing the recipient-enumeration oracle: do NOT
    -- return copyCount / cannotCount / recipients[] (see RESIDUAL BOUND in header).
    RETURN jsonb_build_object(
        'type', 'success',
        'recalled', TRUE
    );
END;
$$ LANGUAGE plpgsql;
