-- JMAP EmailSubmission/* reducers (RFC 8621 §7)
-- Thin wrapper around the existing send() reducer.

-- jmap_email_submission_set: create email submissions (send mail).
-- p_submissions is a JSONB object keyed by creation-id. Supports:
--   onSendUndoWindowSeconds — existing undo-send window (immediate send + window)
--   sendAt (urn:setjoin:params:jmap:mail) — B2 future scheduled send; when set
--           the draft is kept and tagged Scheduled via message_schedule().
-- Returns the standard JMAP set response shape.
CREATE OR REPLACE FUNCTION jmap_email_submission_set(
  p_mailbox_id        BIGINT,
  p_user_id           BIGINT,
  p_submissions       JSONB,
  p_processed_raw_ref JSONB DEFAULT NULL, -- Phase 3: map creationId → processed-blob-ref (signed and/or encrypted; NULL = unchanged)
  p_is_encrypted      JSONB DEFAULT NULL  -- Phase 3: map creationId → bool (TRUE = encrypted-at-rest; 3.3 nulls body cols)
) RETURNS JSONB AS $$
DECLARE
  v_created       JSONB := '{}'::JSONB;
  v_notCreated    JSONB := '{}'::JSONB;
  v_old_state     BIGINT;
  v_new_state     BIGINT;
  v_creation_id   TEXT;
  v_sub           JSONB;
  v_email_id      BIGINT;
  v_msg           RECORD;
  v_to_addrs      JSONB;
  v_cc_addrs      JSONB;
  v_bcc_addrs     JSONB;
  v_send_at       TIMESTAMPTZ;
  v_sent_id       BIGINT;
  v_processed_ref TEXT;
  v_is_enc        BOOLEAN;
  v_clear_text    TEXT;       -- cleartext body kept for send()'s in-txn DLP scan on the encrypted path
  v_clear_html    TEXT;
  v_old_raw_ref   TEXT;
  v_shared        INT;
  v_webhook_rcpts JSONB;
  v_webhook_rcpt  JSONB;
  v_webhook_ordinal BIGINT;
  v_webhook_from TEXT;
BEGIN
  -- Authoritative baseline for the JMAP oldState (captured before any per-submission
  -- path advances jmap_email_state). newState is read — not re-bumped — at the end.
  SELECT jmap_email_state INTO v_old_state FROM mailboxes WHERE id = p_mailbox_id;

  FOR v_creation_id, v_sub IN SELECT * FROM jsonb_each(p_submissions)
  LOOP
    BEGIN
      v_email_id := (v_sub->>'emailId')::BIGINT;
      IF v_email_id IS NULL THEN
        v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
          jsonb_build_object('type', 'invalidArguments', 'description', 'emailId is required'));
        CONTINUE;
      END IF;

      -- R1: load the draft AND verify ownership in the same statement.
      SELECT * INTO v_msg
      FROM messages
      WHERE id = v_email_id AND mailbox_id = p_mailbox_id;

      IF v_msg.id IS NULL THEN
        v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
          jsonb_build_object('type', 'notFound', 'description', 'emailId not found'));
        CONTINUE;
      END IF;

      -- Shared-draft collaboration is opt-in per submission. Once a client
      -- supplies any lease field it must supply the complete tuple; the
      -- authorization reducer locks and terminalizes the session in this same
      -- send transaction, so a failed send rolls the terminal state back.
      IF v_sub ? 'draftSessionId' OR v_sub ? 'draftLeaseEpoch' OR v_sub ? 'draftRevision' THEN
        IF NOT (v_sub ? 'draftSessionId' AND v_sub ? 'draftLeaseEpoch' AND v_sub ? 'draftRevision') THEN
          v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
            jsonb_build_object('type','invalidArguments','description','complete shared draft lease tuple is required'));
          CONTINUE;
        END IF;
        PERFORM mail_draft_submission_authorize(
          p_mailbox_id,p_user_id,(v_sub->>'draftSessionId')::uuid,
          (v_sub->>'draftLeaseEpoch')::bigint,(v_sub->>'draftRevision')::bigint,
          v_email_id,v_msg.received_at);
      END IF;

      -- Phase 3: if the Go handler PROCESSED this submission (signed and/or
      -- encrypted), swap the draft's raw_ref to the processed blob in-txn so BOTH
      -- the immediate send() (via the v_msg snapshot, updated below) and the
      -- scheduled path (message_schedule re-reads the row) carry the final wire
      -- artifact.
      -- INVARIANT: raw_ref is the processed WIRE artifact. For a SIGNED-only blob
      -- body_text/body_html/body_tsv stay the cleartext display/search cache; the
      -- ENCRYPTED-at-rest body-null surgery lives in send()/deliver() (3.3),
      -- driven by p_is_encrypted. NULL/omitted p_processed_raw_ref => unchanged.
      v_processed_ref := p_processed_raw_ref ->> v_creation_id;
      IF v_processed_ref IS NOT NULL AND v_processed_ref IS DISTINCT FROM v_msg.raw_ref THEN
        -- lock the draft row for the swap (closes the concurrent-submission TOCTOU)
        SELECT raw_ref INTO v_old_raw_ref
          FROM messages WHERE id = v_email_id AND mailbox_id = p_mailbox_id FOR UPDATE;
        -- orphan the old (unprocessed) blob if no other message references it (raw_ref
        -- is NOT ref-counted; messages is partitioned by received_at so dedup keys on both).
        SELECT COUNT(*) INTO v_shared FROM messages
          WHERE raw_ref = v_old_raw_ref AND (id != v_email_id OR received_at != v_msg.received_at);
        IF v_shared = 0 THEN
          INSERT INTO orphaned_message_blobs(raw_ref) VALUES (v_old_raw_ref) ON CONFLICT DO NOTHING;
        END IF;
        -- swap (R3: ownership in the same WHERE)
        UPDATE messages SET raw_ref = v_processed_ref WHERE id = v_email_id AND mailbox_id = p_mailbox_id;
        v_msg.raw_ref := v_processed_ref;  -- REQUIRED: the immediate send() below passes the snapshot
      END IF;

      -- SP1: did the Go handler ENCRYPT this submission? Drives encrypted-at-rest:
      -- send()/deliver() null the stored body columns when TRUE. NULL/omitted => FALSE.
      v_is_enc := COALESCE((p_is_encrypted ->> v_creation_id)::BOOLEAN, FALSE);

      -- Cleartext snapshot for the immediate path's in-txn DLP: send() scans
      -- p_body_text/p_body_html (step 5a) but stores NULL when p_is_encrypted, so
      -- we MUST keep feeding it the cleartext (the "scan cleartext, store ciphertext"
      -- contract). v_msg already holds the cleartext draft bodies; capture them so
      -- nulling the stored draft row below doesn't also blank what send() scans.
      v_clear_text := v_msg.body_text;
      v_clear_html := v_msg.body_html;

      -- Encrypted-at-rest for the STORED draft row. The SCHEDULED path moves THIS
      -- row to Sent in place at fire time (scheduled_action_send: tag move, no
      -- re-store), so nulling its bodies now is what makes the scheduled Sent copy
      -- encrypted-at-rest; the immediate path also keeps this row when
      -- onSuccessUpdateEmail is present, so null it for that case too. The
      -- ciphertext is already in raw_ref (swapped above). Guarded so a signed-only
      -- submission leaves the cleartext draft cache untouched (Phase D invariant).
      -- R3: ownership in the same WHERE.
      -- SP1: also stamp the at-rest discriminator. The SCHEDULED path moves THIS
      -- row to Sent in place (scheduled_action_send: tag move, no re-store), so
      -- this UPDATE is the only place the scheduled Sent copy gets marked
      -- encrypted; without crypto_type the body is nulled but decrypt-on-read
      -- (cryptoType=='smime-encrypted') never fires → the sender's scheduled Sent
      -- copy renders blank. Same flag (v_is_enc) that nulls the body.
      IF v_is_enc THEN
        UPDATE messages SET body_text = NULL, body_html = NULL, crypto_type = 'smime-encrypted'
          WHERE id = v_email_id AND mailbox_id = p_mailbox_id;
      END IF;

      -- Recipients: explicit envelope wins, else message headers.
      IF v_sub ? 'envelope' THEN
        v_to_addrs := v_sub->'envelope'->'rcptTo';
        v_cc_addrs := '[]'::JSONB;
        v_bcc_addrs := '[]'::JSONB;
      ELSE
        v_to_addrs := v_msg.to_addrs;
        v_cc_addrs := v_msg.cc_addrs;
        v_bcc_addrs := v_msg.bcc_addrs;
      END IF;
      v_webhook_rcpts := COALESCE(v_to_addrs,'[]'::jsonb)
        || COALESCE(v_cc_addrs,'[]'::jsonb) || COALESCE(v_bcc_addrs,'[]'::jsonb);
      v_webhook_from := COALESCE(v_sub->'envelope'->'mailFrom'->>'email',v_msg.from_addr);

      -- B2: parse the namespaced sendAt (future = scheduled send).
      v_send_at := NULL;
      IF v_sub ? 'sendAt' AND (v_sub->>'sendAt') IS NOT NULL THEN
        v_send_at := (v_sub->>'sendAt')::TIMESTAMPTZ;
      END IF;

      -- S/MIME signing (Phase D) is handled entirely in the EmailSubmission/set Go
      -- handler BEFORE this reducer runs: it signs at submission, swaps the draft's
      -- raw_ref via p_processed_raw_ref (above), strips signSMIME, and surfaces a
      -- missing/unusable cert as a per-creation notCreated. No worker-side sign
      -- intent is threaded from here anymore (Phase D3 removed it).

      IF v_send_at IS NOT NULL AND v_send_at > now() THEN
        -- Scheduled send: keep the draft, tag it Scheduled, and enqueue a `send`
        -- scheduled_action (A6) via message_schedule(); the deferred-action
        -- dispatcher fires it when sendAt passes. message_schedule() does not bump
        -- state itself; the Scheduled tag move is a visibility change, so push it
        -- through the single owner here. The raw_ref already carries the signed
        -- wire artifact (swapped above), so no extra payload is threaded.
        PERFORM message_schedule(p_mailbox_id, v_email_id, v_send_at, NULL,
          jsonb_build_object(
            'actor_user_id',p_user_id,
            'webhook_envelope_from',v_webhook_from,
            'webhook_envelope_rcpts',v_webhook_rcpts));
        -- ponytail: scheduled-draft tag move is 'updated' (same message, re-tagged Scheduled)
        PERFORM notify_state_change(p_mailbox_id, NULL, v_email_id, 'updated');
        v_created := v_created || jsonb_build_object(v_creation_id, jsonb_build_object(
          'id', v_email_id::TEXT,
          'emailId', v_email_id::TEXT,
          'undoStatus', 'pending',
          'sendAt', v_send_at
        ));
        CONTINUE;  -- do not delete the draft; do not send now
      END IF;

      -- Immediate send (optionally with an undo-send window). send() handles
      -- the Sent copy + outbound queue; p_send_at NULL = send now.
      -- Pass the CLEARTEXT bodies (v_clear_*) so send()'s in-txn DLP scans real
      -- content; send() stores NULL bodies itself when p_is_encrypted=TRUE.
      PERFORM set_config('app.webhook_origin','jmap_submission',true);
      PERFORM set_config('app.webhook_envelope_rcpts',v_webhook_rcpts::text,true);
      v_sent_id := send(
        p_user_id, p_mailbox_id, v_msg.raw_ref, v_msg.message_id, v_msg.from_addr,
        v_to_addrs, v_cc_addrs, v_bcc_addrs, v_msg.subject,
        v_msg.in_reply_to, v_msg.references_hdr, v_clear_text, v_clear_html,
        v_msg.size_bytes, v_msg.has_attachments,
        CASE WHEN (v_sub->>'onSendUndoWindowSeconds')::INT > 0
             THEN now() + make_interval(secs => (v_sub->>'onSendUndoWindowSeconds')::INT)
             ELSE NULL END,
        v_is_enc,
        -- The draft (v_email_id/v_msg.received_at) is the attachment-metadata
        -- source: send() threads this through to deliver() so a LOCAL recipient's
        -- copy also gets the draft's message_attachments rows, not just the Sent
        -- copy (copied separately below).
        p_source_message_id => v_email_id,
        p_source_received_at => v_msg.received_at
      );

      IF v_sent_id IS NOT NULL THEN
        FOR v_webhook_rcpt,v_webhook_ordinal IN
          SELECT value,ordinality FROM jsonb_array_elements(v_webhook_rcpts) WITH ORDINALITY
        LOOP
          PERFORM webhook_mail_committed_publish(
            v_sent_id,'mail.sent','jmap_submission',v_webhook_from,
            v_webhook_rcpt->>'email',v_webhook_ordinal::integer);
        END LOOP;
        PERFORM mail_work_record_first_response(p_mailbox_id,p_user_id,v_msg.thread_id,v_sent_id);
      END IF;

      -- Carry the draft's attachment metadata onto the Sent copy so the sender's
      -- reading pane shows + downloads the attachments (the wire bytes are already in
      -- the assembled raw_ref). The V075 trigger bumps the blob ref_count for the Sent
      -- copy; the draft's rows decrement it back when the draft is deleted below.
      IF v_sent_id IS NOT NULL AND v_msg.has_attachments THEN
        INSERT INTO message_attachments
          (message_id, received_at, blob_sha256, content_type, filename, content_id, disposition, size_bytes)
        SELECT v_sent_id, ms.received_at, ma.blob_sha256, ma.content_type, ma.filename,
               ma.content_id, ma.disposition, ma.size_bytes
        FROM message_attachments ma, messages ms
        WHERE ma.message_id = v_email_id AND ma.received_at = v_msg.received_at
          AND ms.id = v_sent_id;
      END IF;

      -- RFC 8621 §7 onSuccessUpdateEmail: when present, keep the draft and apply
      -- the requested patch (tag-on-send). When absent, delete the draft (legacy).
      -- T7: v_sent_id IS NULL when send() held the message for external-send approval
      -- (no Sent copy was created). Guard draft deletion and patch application on
      -- v_sent_id IS NOT NULL — the draft must survive to keep the raw_ref blob
      -- ref_count ≥ 1 for the approve-replay path. Use COALESCE so the JMAP `id`
      -- field is never null (held path returns the draft's own id).
      IF v_sub ? 'onSuccessUpdateEmail' AND jsonb_typeof(v_sub->'onSuccessUpdateEmail') = 'object' THEN
        -- Only apply the patch when the send actually completed (v_sent_id IS NOT NULL).
        -- Held sends skip the patch: the send hasn't happened yet.
        IF v_sent_id IS NOT NULL THEN
          DECLARE
            v_patch_key   TEXT;
            v_patch_val   JSONB;
            v_norm        JSONB := '{}'::JSONB;
          BEGIN
            -- The patch map is keyed by an Email id or a "#creationId" back-ref.
            -- We re-key every patch onto the actual draft id (v_email_id) and
            -- delegate to jmap_email_set_update, which enforces p_mailbox_id (R1/R3).
            FOR v_patch_key, v_patch_val IN SELECT * FROM jsonb_each(v_sub->'onSuccessUpdateEmail')
            LOOP
              v_norm := v_norm || jsonb_build_object(v_email_id::TEXT, v_patch_val);
            END LOOP;
            PERFORM jmap_email_set_update(p_mailbox_id, v_norm);
          END;
        END IF;

        v_created := v_created || jsonb_build_object(v_creation_id, jsonb_build_object(
          'id', COALESCE(v_sent_id, v_email_id)::TEXT,
          'emailId', v_email_id::TEXT,
          -- T7: held for external-send approval → the client shows a "held" state and
          -- must NOT arm the undo-send timer (no scheduled/undo row exists — it is an
          -- approval_request). v_sent_id IS NULL exactly when send() held the message.
          'heldForApproval', (v_sent_id IS NULL)
        ));
      ELSE
        -- Legacy path: delete the draft on a normal (non-held) send. send() above
        -- already pushed the state change, so suppress the helper's bump (p_notify =>
        -- FALSE) to preserve the no-double-bump invariant.
        -- T7: skip deletion when held (v_sent_id IS NULL) — the draft must survive.
        IF v_sent_id IS NOT NULL THEN
          PERFORM delete_draft_message(v_email_id, v_msg.received_at, p_mailbox_id, FALSE);
        END IF;

        v_created := v_created || jsonb_build_object(v_creation_id, jsonb_build_object(
          'id', COALESCE(v_sent_id, v_email_id)::TEXT,
          'emailId', v_email_id::TEXT,
          -- T7: held for external-send approval (see above) → client shows "held",
          -- must NOT arm undo-send. v_sent_id IS NULL exactly when send() held it.
          'heldForApproval', (v_sent_id IS NULL)
        ));
      END IF;

    EXCEPTION WHEN OTHERS THEN
      v_notCreated := v_notCreated || jsonb_build_object(v_creation_id,
        jsonb_build_object(
          -- BZ004 (daily sending quota, raised by send()) maps to the RFC 8621
          -- SetError type the client can branch on. Flattening it to
          -- invalidArguments destroyed the classification at this boundary and
          -- the UI showed "Please try again" for a quota that resets tomorrow.
          'type', CASE WHEN SQLSTATE = 'BZ004' THEN 'overQuota' ELSE 'invalidArguments' END,
          'description', SQLERRM));
    END;
  END LOOP;

  -- Each per-submission path (immediate send → notify_state_change inside send();
  -- scheduled send → notify_state_change above) has already advanced
  -- jmap_email_state through the single owner. Read the authoritative current
  -- value for the JMAP response instead of open-coding another bump (which would
  -- double-count and bypass the trigger/helper).
  SELECT jmap_email_state INTO v_new_state FROM mailboxes WHERE id = p_mailbox_id;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'created', v_created,
    'notCreated', v_notCreated
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_email_submission_get: return pending submissions (Scheduled view).
-- A "submission" maps to a pending `send` scheduled_action (A6 deferred-action
-- infrastructure). sendAt = the action's fire_at; undoSendBefore = fire_at when
-- the action is an undo-send window (payload->>'undo' = 'true'). Filters strictly
-- by p_mailbox_id (R1). p_ids NULL/empty returns all scheduled submissions.
CREATE OR REPLACE FUNCTION jmap_email_submission_get(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[] DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_list JSONB;
  v_state BIGINT;
BEGIN
  SELECT jmap_email_state INTO v_state FROM mailboxes WHERE id = p_mailbox_id;

  SELECT COALESCE(jsonb_agg(row), '[]'::JSONB) INTO v_list
  FROM (
    SELECT jsonb_build_object(
      'id', (sa.payload->>'message_id'),
      'emailId', (sa.payload->>'message_id'),
      'undoStatus', 'pending',
      'sendAt', sa.fire_at,
      'undoSendBefore', CASE WHEN sa.payload->>'undo' = 'true' THEN sa.fire_at ELSE NULL END
    ) AS row
    FROM scheduled_actions sa
    WHERE sa.mailbox_id = p_mailbox_id          -- R1: ownership
      AND sa.action_kind = 'send'
      AND sa.status = 'pending'
      AND (p_ids IS NULL OR (sa.payload->>'message_id')::BIGINT = ANY(p_ids))
    ORDER BY sa.fire_at ASC
  ) sub;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'state', COALESCE(v_state, 0)::TEXT,
    'list', v_list,
    'notFound', '[]'::JSONB
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_email_submission_query: return ids of pending/deferred submissions.
-- Ordered by sendAt ascending. Filters strictly by p_mailbox_id (R1).
-- p_filter is reserved (accepted for JMAP shape compatibility, unused in wave-1).
CREATE OR REPLACE FUNCTION jmap_email_submission_query(
  p_mailbox_id BIGINT,
  p_filter     JSONB DEFAULT NULL,
  p_position   INT   DEFAULT 0,
  p_limit      INT   DEFAULT 50
) RETURNS JSONB AS $$
DECLARE
  v_ids   JSONB;
  v_total BIGINT;
  v_state BIGINT;
BEGIN
  SELECT jmap_email_state INTO v_state FROM mailboxes WHERE id = p_mailbox_id;

  SELECT COALESCE(jsonb_agg(mid ORDER BY fire_at ASC), '[]'::JSONB), count(*)
  INTO v_ids, v_total
  FROM (
    SELECT (sa.payload->>'message_id') AS mid, sa.fire_at
    FROM scheduled_actions sa
    WHERE sa.mailbox_id = p_mailbox_id           -- R1: ownership
      AND sa.action_kind = 'send'
      AND sa.status = 'pending'
    ORDER BY sa.fire_at ASC
    OFFSET GREATEST(p_position, 0)
    LIMIT LEAST(GREATEST(p_limit, 1), 256)
  ) sub;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'queryState', COALESCE(v_state, 0)::TEXT,
    'canCalculateChanges', FALSE,
    'position', GREATEST(p_position, 0),
    'total', v_total,
    'ids', v_ids
  );
END;
$$ LANGUAGE plpgsql;
