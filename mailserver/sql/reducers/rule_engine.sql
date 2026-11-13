-- apply_rules is defined in rule_engine_or.sql (OR-grouping version)

-- Evaluate a single condition against a message record.
CREATE OR REPLACE FUNCTION eval_condition(v_msg RECORD, v_cond JSONB) RETURNS BOOL AS $$
DECLARE
  v_field  TEXT := v_cond->>'field';
  v_op     TEXT := v_cond->>'op';
  v_value  TEXT := v_cond->>'value';
  v_actual TEXT;
BEGIN
  -- Resolve the field value from the message record
  v_actual := CASE v_field
    WHEN 'from_addr'    THEN lower(v_msg.from_addr)
    WHEN 'subject'      THEN lower(coalesce(v_msg.subject,''))
    WHEN 'body'         THEN lower(coalesce(v_msg.body_text,''))
    WHEN 'spam_score'   THEN v_msg.spam_score::TEXT
    WHEN 'size_bytes'   THEN v_msg.size_bytes::TEXT
    WHEN 'has_attachments' THEN v_msg.has_attachments::TEXT
    WHEN 'sender_domain' THEN lower(split_part(v_msg.from_addr,'@',2))
    ELSE NULL
  END;

  IF v_actual IS NULL THEN RETURN FALSE; END IF;

  RETURN CASE v_op
    WHEN 'contains'     THEN v_actual LIKE '%' || lower(v_value) || '%'
    WHEN 'not_contains' THEN v_actual NOT LIKE '%' || lower(v_value) || '%'
    WHEN 'equals'       THEN v_actual = lower(v_value)
    WHEN 'not_equals'   THEN v_actual != lower(v_value)
    WHEN 'starts_with'  THEN v_actual LIKE lower(v_value) || '%'
    WHEN 'gt'           THEN v_actual::NUMERIC > v_value::NUMERIC
    WHEN 'lt'           THEN v_actual::NUMERIC < v_value::NUMERIC
    WHEN 'gt_bytes'     THEN v_actual::BIGINT > v_value::BIGINT
    WHEN 'lt_bytes'     THEN v_actual::BIGINT < v_value::BIGINT
    WHEN 'is_true'      THEN v_actual = 'true'
    WHEN 'matches_regex' THEN v_actual ~ lower(v_value)
    WHEN 'in_list'      THEN v_actual = ANY(string_to_array(lower(v_value), ','))
    ELSE FALSE
  END;
END;
$$ LANGUAGE plpgsql STABLE;

-- Apply a single action to a message.
CREATE OR REPLACE FUNCTION apply_action(
  p_message_id  BIGINT,
  p_received_at TIMESTAMPTZ,
  p_mailbox_id  BIGINT,
  v_action      JSONB,
  p_rule_id     BIGINT,
  p_organize_only BOOLEAN DEFAULT FALSE
) RETURNS VOID AS $$
DECLARE
  v_type      TEXT := v_action->>'type';
  v_params    JSONB := v_action->'params';
  v_folder_id BIGINT;
  v_old_folder BIGINT;
  v_is_read BOOL;
BEGIN
  -- Retro sweep (organize_only) must NOT re-fire send-time actions: forward_to /
  -- redirect / bcc queue or mutate the outbound recipient set, add_header /
  -- append_footer inject into outbound MIME — replaying any of them over
  -- historical mail would mass re-send. Organize actions (move_to / flag /
  -- mark_read / categorize / delete / discard) reshape only the local mailbox
  -- and still run. Single root-cause guard in the shared reducer (all callers
  -- route through here), not a fork.
  IF p_organize_only AND v_type IN ('forward_to','redirect','bcc','append_footer','add_header') THEN
    RETURN;
  END IF;

  CASE v_type

    WHEN 'move_to' THEN
      SELECT id INTO v_folder_id FROM tags
      WHERE mailbox_id = p_mailbox_id
        AND (name = v_params->>'folder' OR name = v_params->>'role')
      LIMIT 1;
      IF v_folder_id IS NOT NULL THEN
        -- Move + notify consolidated into the single location seam (it does the
        -- atomic swap AND the one notify_state_change with the new tag id —
        -- equivalent to the prior set_message_location + notify pair).
        PERFORM transition_message_location(
          p_message_id, p_received_at, (SELECT name FROM tags WHERE id = v_folder_id), p_mailbox_id, 'rule');
      END IF;

    WHEN 'flag' THEN
      UPDATE messages SET is_flagged = TRUE
      WHERE id = p_message_id AND received_at = p_received_at
        AND mailbox_id = p_mailbox_id;
      -- Mailbox-wide change (no single tag) → bump email state and push.
      PERFORM notify_state_change(p_mailbox_id, NULL);

    WHEN 'mark_read' THEN
      DECLARE
        v_already_read BOOL;
      BEGIN
        SELECT is_read INTO v_already_read FROM messages
        WHERE id = p_message_id AND received_at = p_received_at;
        UPDATE messages SET is_read = TRUE
        WHERE id = p_message_id AND received_at = p_received_at
          AND mailbox_id = p_mailbox_id;
        -- Adjust tag unread counts for all tags on this message. The per-tag
        -- jmap_state bump here is the counter side (orthogonal to the
        -- mailbox-level email-state bump done by notify_state_change below).
        IF NOT v_already_read THEN
          UPDATE tags SET
            unread_count = GREATEST(0, unread_count - 1),
            jmap_state = jmap_state + 1
          WHERE id IN (
            SELECT tag_id FROM message_tags
            WHERE message_id = p_message_id AND received_at = p_received_at
          );
        END IF;
      END;
      -- Mailbox-wide change (read flag) → bump email state and push.
      PERFORM notify_state_change(p_mailbox_id, NULL);

    WHEN 'categorize' THEN
      UPDATE messages SET
        categories = array_append(categories, v_params->>'category')
      WHERE id = p_message_id AND received_at = p_received_at
        AND mailbox_id = p_mailbox_id
        AND NOT (v_params->>'category' = ANY(categories));
      -- Mailbox-wide change → bump email state and push.
      PERFORM notify_state_change(p_mailbox_id, NULL);

    WHEN 'delete' THEN
      -- Move to Trash + notify consolidated into the single location seam (it
      -- resolves the Trash tag id and emits the one notify_state_change).
      PERFORM transition_message_location(p_message_id, p_received_at, 'Trash', p_mailbox_id, 'rule');

    WHEN 'discard' THEN
      IF NOT (SELECT litigation_hold FROM mailboxes WHERE id = p_mailbox_id) THEN
        -- Single owning reducer: remove location tags (mailbox-scoped, R3) +
        -- delete the message + push the mailbox-wide state change exactly once.
        PERFORM delete_draft_message(p_message_id, p_received_at, p_mailbox_id);
      END IF;

    WHEN 'forward_to' THEN
      -- Queue a copy for forwarding via the outbound SMTP pipeline.
      -- LINK-PROTECT rail (security correctness): the stored raw_ref body of an
      -- inbound message has had external URLs rewritten to the RECIPIENT's
      -- /link-protect?token=… redirects, which (a) are broken for the forward
      -- target and (b) leak the recipient mailbox_id + message_id encoded in the
      -- HMAC token. forward_unwrap_links=TRUE makes the Go egress un-rewrite those
      -- tokens back to the original URLs before signing/transmission, so the
      -- forwarded copy never re-emits the recipient's protected redirects.
      INSERT INTO outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status, forward_unwrap_links)
      SELECT message_id,
             'noreply-forward@' || COALESCE(
               (SELECT name FROM domains WHERE is_primary = TRUE LIMIT 1),
               (SELECT name FROM domains WHERE is_local = TRUE LIMIT 1),
               'localhost'
             ),
             ARRAY[v_params->>'address'],
             raw_ref,
             'pending',
             TRUE
      FROM messages WHERE id = p_message_id AND received_at = p_received_at;

    WHEN 'add_header' THEN
      -- Stored as metadata; Go SMTP layer injects into outbound messages.
      UPDATE messages SET spam_headers =
        coalesce(spam_headers,'{}') || jsonb_build_object(
          'X-Rule-' || p_rule_id::TEXT, v_params->>'value')
      WHERE id = p_message_id AND received_at = p_received_at
        AND mailbox_id = p_mailbox_id;

    WHEN 'bcc' THEN
      -- Silent copy: appended to bcc_addrs — never a visible header (that's the
      -- definition of BCC). Mirrors the existing per-identity auto-BCC in
      -- send.sql (the "Auto-BCC" step); send() re-reads bcc_addrs from this row
      -- right after apply_rules() so a rule-added BCC reaches the real outbound
      -- recipient set (SMTP envelope RCPT TO / local deliver() fan-out), not
      -- just this row. Deduped so a stacked/repeated bcc action targeting the
      -- same address doesn't add it twice.
      UPDATE messages SET bcc_addrs =
        COALESCE(bcc_addrs, '[]'::JSONB) || jsonb_build_array(
          jsonb_build_object('email', lower(v_params->>'address')))
      WHERE id = p_message_id AND received_at = p_received_at
        AND mailbox_id = p_mailbox_id
        AND NOT COALESCE(bcc_addrs, '[]'::JSONB) @> jsonb_build_array(
          jsonb_build_object('email', lower(v_params->>'address')));

    WHEN 'append_footer' THEN
      -- Disclaimer/footer append. Idempotent (skips if the exact text is
      -- already present, so stacked footer actions append once) — same guard
      -- style as the identity-signature append in send.sql. Reaches the Sent
      -- copy, any local recipient's stored copy, and JMAP body rendering
      -- (message_to_jmap_email reads body_text/body_html directly). KNOWN
      -- CEILING (ponytail): this does NOT rewrite the wire raw_ref MIME blob,
      -- so an externally-SMTP-relayed recipient's own mail client (or this
      -- server's IMAP FETCH, which serves raw_ref verbatim) will not see it —
      -- the same pre-existing gap the identity-signature append already has.
      -- Upgrade path if wire-level disclaimer injection becomes a real need:
      -- Go-side raw_ref MIME rewrite in the outbound worker, mirroring the
      -- existing link-protect-unwrap/DKIM-sign step (internal/smtp/outbound.go).
      -- SP1: skipped entirely on the encrypted-at-rest path (crypto_type =
      -- 'smime-encrypted') — body_text/body_html are NULL by design there
      -- (raw_ref carries the ciphertext); appending would inject a cleartext
      -- footer into a column that must stay NULL.
      UPDATE messages SET
        body_text = CASE
          WHEN COALESCE(body_text,'') LIKE '%' || (v_params->>'text') || '%' THEN body_text
          ELSE COALESCE(body_text,'') || E'\n\n' || (v_params->>'text')
        END,
        body_html = CASE
          WHEN body_html IS NULL THEN NULL
          WHEN body_html LIKE '%' || replace(v_params->>'text', E'\n', '<br>') || '%' THEN body_html
          ELSE body_html || '<br><br>' || replace(v_params->>'text', E'\n', '<br>')
        END
      WHERE id = p_message_id AND received_at = p_received_at
        AND mailbox_id = p_mailbox_id
        AND crypto_type IS DISTINCT FROM 'smime-encrypted';

    WHEN 'redirect' THEN
      -- Exchange-parity semantics: REDIRECT REPLACES the recipient set (to/cc/
      -- bcc all become just the redirect target) — the original addressee is
      -- never notified (no bounce, no forward-marker; their copy is simply
      -- never queued/delivered). This differs deliberately from forward_to,
      -- which ADDS a copy alongside normal delivery. send() re-reads to/cc/
      -- bcc_addrs from this row right after apply_rules() so the replacement
      -- reaches the real outbound recipient set.
      -- Loop protection: no new primitive is needed. Unlike distribution-group
      -- expansion (deliver()'s p_depth recursion guard, capped at 10), redirect
      -- fires once per send() call and does not re-invoke apply_rules against
      -- the new target — there is nothing here that can recurse within a
      -- single send.
      UPDATE messages SET
        to_addrs = jsonb_build_array(jsonb_build_object('email', lower(v_params->>'address'))),
        cc_addrs = '[]'::JSONB,
        bcc_addrs = '[]'::JSONB
      WHERE id = p_message_id AND received_at = p_received_at
        AND mailbox_id = p_mailbox_id;

    ELSE
      RAISE WARNING 'rule_engine: unknown action type % for rule_id=%', v_action, p_rule_id;
  END CASE;
END;
$$ LANGUAGE plpgsql;
