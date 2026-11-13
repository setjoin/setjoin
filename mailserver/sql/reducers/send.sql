-- send(): called by JMAP EmailSubmission when a user sends a message.
-- Validates authorization, runs outbound transport rules, saves to Sent,
-- queues for SMTP delivery, and notifies clients.
--
-- INPUT: p_user_id (BIGINT, REQUIRED) — authenticated user performing the send
-- INPUT: p_mailbox_id (BIGINT, REQUIRED) — sending mailbox (ownership verified)
-- INPUT: p_raw_ref (TEXT, REQUIRED) — RFC 5322 raw message (MinIO path or inline)
-- INPUT: p_from_addr (TEXT, REQUIRED) — verified against send_as delegation
-- INPUT: p_to_addrs, p_cc_addrs, p_bcc_addrs (JSONB) — recipient arrays
-- INPUT: p_subject, p_body_text, p_body_html (TEXT) — message content
-- INPUT: p_size_bytes (BIGINT) — checked against check_quota()
-- AUTHORIZATION: mailbox ownership + send_as delegation verified at lines 41-67
CREATE OR REPLACE FUNCTION send(
  p_user_id         BIGINT,
  p_mailbox_id      BIGINT,    -- the sending mailbox (personal or shared)
  p_raw_ref         TEXT,      -- MinIO path to the composed RFC 5322 message
  p_message_id      TEXT,
  p_from_addr       TEXT,
  p_to_addrs        JSONB,
  p_cc_addrs        JSONB,
  p_bcc_addrs        JSONB,
  p_subject         TEXT,
  p_in_reply_to     TEXT,
  p_references_hdr  TEXT,
  p_body_text       TEXT,
  p_body_html       TEXT,
  p_size_bytes      BIGINT,
  p_has_attachments BOOL,
  p_send_at         TIMESTAMPTZ DEFAULT NULL,   -- NULL = send now; future = scheduled send
  p_is_encrypted    BOOLEAN DEFAULT FALSE,       -- SP1: TRUE = encrypted-at-rest (raw_ref ciphertext); null the body cols, skip signature-append
  p_skip_approval   BOOLEAN DEFAULT FALSE,       -- T7: TRUE = bypass the external-send approval hold (set only by the approve-replay path)
  -- Attachment-metadata source for LOCAL delivery: threaded straight through to
  -- deliver() (see deliver.sql) so a local recipient's copy inherits the SAME
  -- message_attachments rows as the Sent copy (jmap_email_submission_set copies
  -- them onto the Sent copy separately, AFTER this call returns — local delivery
  -- has no other way to see them). Callers with nothing to copy (health-check
  -- alerts, vacation auto-reply — both p_has_attachments=>FALSE) simply omit it.
  p_source_message_id   BIGINT DEFAULT NULL,
  p_source_received_at  TIMESTAMPTZ DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
  v_mailbox       RECORD;
  v_sent_folder   BIGINT;
  v_message_id    BIGINT;
  v_rcpts         TEXT[];
  v_rcpt          TEXT;
  v_domain        TEXT;
  v_is_local      BOOL;
  v_sending_quota INT;
  v_is_owner      BOOL;
  v_can_send_as   BOOL;
  v_can_on_behalf BOOL;
BEGIN
  -- 1. Verify user is authorized to send from this mailbox
  SELECT mb.* INTO v_mailbox FROM mailboxes mb
  WHERE mb.id = p_mailbox_id AND mb.enabled = TRUE
  FOR UPDATE;

  IF v_mailbox.id IS NULL THEN
    RAISE EXCEPTION 'Mailbox not found or disabled'
      USING ERRCODE = 'BZ002', HINT = jsonb_build_object('type', 'forbidden', 'user_id', p_user_id)::TEXT;
  END IF;

  v_is_owner := p_user_id IS NOT NULL AND v_mailbox.user_id IS NOT DISTINCT FROM p_user_id;
  SELECT
    COALESCE(bool_or(permission IN ('send_as','full_access')), FALSE),
    COALESCE(bool_or(permission = 'send_on_behalf'), FALSE)
    INTO v_can_send_as, v_can_on_behalf
    FROM mailbox_delegates
   WHERE mailbox_id = p_mailbox_id
     AND user_id = p_user_id;

  -- NULL p_user_id is reserved for internal system paths. Every real caller
  -- must own the mailbox or hold an explicit send grant. Shared mailboxes have
  -- user_id NULL, so v_is_owner is deliberately false for them.
  IF p_user_id IS NOT NULL
     AND NOT v_is_owner
     AND NOT v_can_send_as
     AND NOT v_can_on_behalf THEN
    RAISE EXCEPTION 'User cannot send from this mailbox'
    USING ERRCODE = 'BZ002', HINT = jsonb_build_object('type', 'forbidden', 'user_id', p_user_id, 'mailbox_id', p_mailbox_id)::TEXT;
  END IF;

  -- 1.5 Validate p_from_addr against the exact grant semantics:
  --   owner/system: selected mailbox primary or alias;
  --   send_as/full_access: selected shared primary or alias;
  --   send_on_behalf only: the delegate's own primary address or alias.
  -- The legacy personal-account picker may also name a directly delegated
  -- mailbox primary, but only while the selected account is caller-owned.
  IF p_from_addr IS NULL OR btrim(p_from_addr) = '' THEN
    RAISE EXCEPTION 'From address is required'
    USING ERRCODE = 'BZ003', HINT = jsonb_build_object('type', 'send_as_unauthorized', 'from_addr', p_from_addr)::TEXT;
  END IF;

  IF lower(p_from_addr) = lower(v_mailbox.email) THEN
    IF p_user_id IS NOT NULL AND NOT v_is_owner AND NOT v_can_send_as THEN
      RAISE EXCEPTION 'Not authorized to send from this address'
      USING ERRCODE = 'BZ003', HINT = jsonb_build_object('type', 'send_as_unauthorized', 'from_addr', p_from_addr)::TEXT;
    END IF;
  ELSIF NOT (
    (
      (p_user_id IS NULL OR v_is_owner OR v_can_send_as)
      AND EXISTS (
        SELECT 1 FROM aliases
         WHERE mailbox_id = p_mailbox_id
           AND lower(email) = lower(p_from_addr)
      )
    )
    OR (
      v_is_owner
      AND EXISTS (
        SELECT 1 FROM mailboxes m
        JOIN mailbox_delegates md ON md.mailbox_id = m.id
        WHERE md.user_id = p_user_id
          AND md.permission IN ('send_as','full_access')
          AND lower(m.email) = lower(p_from_addr)
      )
    )
    OR (
      v_can_on_behalf
      AND (
        EXISTS (
          SELECT 1 FROM users u
           WHERE u.id = p_user_id
             AND lower(u.email) = lower(p_from_addr)
        )
        OR EXISTS (
          SELECT 1 FROM aliases a
          JOIN mailboxes m ON m.id = a.mailbox_id
           WHERE m.user_id = p_user_id
             AND m.is_primary = TRUE
             AND m.enabled = TRUE
             AND lower(a.email) = lower(p_from_addr)
        )
      )
    )
  ) THEN
    RAISE EXCEPTION 'Not authorized to send from this address'
    USING ERRCODE = 'BZ003', HINT = jsonb_build_object('type', 'send_as_unauthorized', 'from_addr', p_from_addr)::TEXT;
  END IF;

  -- 2. Sending quota check (reset daily by pg_cron)
  IF v_mailbox.sending_quota_reset_at < CURRENT_DATE THEN
    UPDATE mailboxes SET sending_sent_today = 0, sending_quota_reset_at = CURRENT_DATE
    WHERE id = p_mailbox_id;
    v_mailbox.sending_sent_today := 0;
  END IF;

  IF v_mailbox.sending_sent_today >= v_mailbox.sending_quota_day THEN
    RAISE EXCEPTION 'Daily sending quota reached'
      USING ERRCODE = 'BZ004', HINT = jsonb_build_object('type', 'sending_quota_exceeded', 'mailbox_id', p_mailbox_id)::TEXT;
  END IF;

  -- 2.6 Outbound external-send approval hold (T7). When approval.mail_external is on
  -- and a real user is sending to an external recipient, a matching policy can park the
  -- whole submission as an approval_request and RETURN NULL — BEFORE the Sent copy,
  -- quota bump, or outbound queue — so a denied message leaves no phantom Sent / consumed
  -- quota. The approve path replays this same send() with p_skip_approval=>true. Captured
  -- here (pre-signature/pre-auto-BCC) so the replay re-derives those exactly once.
  -- Skipped for: p_skip_approval (the replay), NULL p_user_id (system sends e.g. vacation;
  -- also requester_user_id is NOT NULL), toggle off, all-local recipients, or no policy.
  IF NOT COALESCE(p_skip_approval, FALSE)
     AND p_user_id IS NOT NULL
     AND COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'approval.mail_external'), FALSE)
  THEN
    DECLARE
      v_ext_domain TEXT;
      v_match      RECORD;
      v_akind      TEXT;
      v_aref       BIGINT;
      v_askip      BOOLEAN;
      v_ttl        INT;
    BEGIN
      -- First external recipient domain across to/cc/bcc (NULL = all local).
      -- ponytail: one domain drives the policy match (recipient_domain condition); a
      -- per-domain fan-out is YAGNI until a policy actually keys on a specific domain.
      SELECT split_part(addr, '@', 2) INTO v_ext_domain
      FROM (
        SELECT (jsonb_array_elements(COALESCE(p_to_addrs,  '[]'::JSONB))->>'email') AS addr
        UNION ALL
        SELECT (jsonb_array_elements(COALESCE(p_cc_addrs,  '[]'::JSONB))->>'email')
        UNION ALL
        SELECT (jsonb_array_elements(COALESCE(p_bcc_addrs, '[]'::JSONB))->>'email')
      ) r
      WHERE r.addr IS NOT NULL
        AND NOT EXISTS (
          SELECT 1 FROM domains d
          WHERE lower(d.name) = lower(split_part(r.addr, '@', 2)) AND d.is_local
        )
      ORDER BY 1
      LIMIT 1;

      IF v_ext_domain IS NOT NULL THEN
        SELECT * INTO v_match FROM approval_match_policies(
          'mail.external_send',
          jsonb_build_object('external', true, 'recipient_domain', v_ext_domain)
        );

        IF v_match.required THEN
          SELECT kind, ref, skip INTO v_akind, v_aref, v_askip
            FROM approval_resolve_approver(p_user_id, v_match.approver_spec);

          IF NOT COALESCE(v_askip, FALSE) THEN
            v_ttl := COALESCE(
              (SELECT (value #>> '{}')::int FROM system_config WHERE key = 'approval.request_ttl_minutes'),
              2880
            );
            PERFORM approval_request_create(
              'mail.external_send',
              p_user_id,
              'Send to ' || v_ext_domain,
              -- Replay payload: every send() arg, verbatim, so the approve path can
              -- re-invoke send() byte-identically (keys = the parameter names).
              jsonb_build_object(
                'p_user_id',         p_user_id,
                'p_mailbox_id',      p_mailbox_id,
                'p_raw_ref',         p_raw_ref,
                'p_message_id',      p_message_id,
                'p_from_addr',       p_from_addr,
                'p_to_addrs',        p_to_addrs,
                'p_cc_addrs',        p_cc_addrs,
                'p_bcc_addrs',       p_bcc_addrs,
                'p_subject',         p_subject,
                'p_in_reply_to',     p_in_reply_to,
                'p_references_hdr',  p_references_hdr,
                'p_body_text',       p_body_text,
                'p_body_html',       p_body_html,
                'p_size_bytes',      p_size_bytes,
                'p_has_attachments', p_has_attachments,
                'p_send_at',         p_send_at,
                'p_is_encrypted',    p_is_encrypted,
                'p_source_message_id',  p_source_message_id,
                'p_source_received_at', p_source_received_at,
                -- Protocol wrappers set these transaction-local values before
                -- calling send(). They are replay context only; send() itself
                -- never publishes, and generic/system callers leave them NULL.
                'p_webhook_origin', NULLIF(current_setting('app.webhook_origin',true),''),
                'p_webhook_envelope_rcpts', CASE
                  WHEN NULLIF(current_setting('app.webhook_envelope_rcpts',true),'') IS NULL THEN NULL
                  ELSE current_setting('app.webhook_envelope_rcpts',true)::jsonb
                END
              ),
              v_match.winner_policy_id,
              v_akind,
              v_aref,
              v_ttl
            );
            RETURN NULL;   -- held: no Sent, no quota, no queue (the Go send-handler treats NULL as pending-approval)
          END IF;
          -- v_askip=true (manager→skip fallback): fall through to a normal send.
        END IF;
      END IF;
    END;
  END IF;

  -- 2.5 Apply per-identity rules (signature, reply-to, auto-BCC)
  IF p_from_addr IS NOT NULL THEN
    DECLARE
      v_identity_sig      TEXT;
      v_identity_reply_to TEXT;
      v_identity_bcc      TEXT;
    BEGIN
      SELECT signature, reply_to, bcc_send
      INTO v_identity_sig, v_identity_reply_to, v_identity_bcc
      FROM aliases WHERE mailbox_id = p_mailbox_id AND lower(email) = lower(p_from_addr);

      -- Auto-BCC: add to BCC recipients
      IF v_identity_bcc IS NOT NULL AND v_identity_bcc != '' THEN
        p_bcc_addrs := COALESCE(p_bcc_addrs, '[]'::JSONB) || jsonb_build_array(
          jsonb_build_object('email', v_identity_bcc, 'name', COALESCE(v_identity_sig, ''))
        );
      END IF;

      -- Signature: append if not already present in body. SKIP entirely on the
      -- encrypted path: the body columns are not the wire artifact there (raw_ref
      -- is the ciphertext, built upstream WITH any signature already inside it), so
      -- mutating p_body_text/p_body_html would only corrupt the cleartext we are
      -- about to discard (3.4 stores the signature inside the encrypted blob).
      IF NOT p_is_encrypted
         AND v_identity_sig IS NOT NULL AND v_identity_sig != ''
         AND p_body_text NOT LIKE '%' || v_identity_sig || '%' THEN
        p_body_text := p_body_text || E'\n\n-- \n' || v_identity_sig;
        IF p_body_html IS NOT NULL THEN
          p_body_html := p_body_html || '<br><br>--<br>' || replace(v_identity_sig, E'\n', '<br>');
        END IF;
      END IF;
    END;
  END IF;

  -- 3. Get Sent tag
  v_sent_folder := get_tag_id('Sent', p_mailbox_id);

  -- 4. Save copy to Sent tag
  INSERT INTO messages (
    mailbox_id, folder_id,
    message_id, subject, from_addr, from_name,
    to_addrs, cc_addrs, bcc_addrs,
    in_reply_to, references_hdr,
    body_text, body_html,
    size_bytes, has_attachments,
    thread_id, raw_ref, sent_at,
    is_read, imap_uid,
    priority, sensitivity, read_receipt_requested, delivery_receipt_requested,
    scheduled_at,
    crypto_type,
    held, received_at
  )
  SELECT
    p_mailbox_id, v_sent_folder,
    p_message_id, p_subject, p_from_addr,
    (SELECT display_name FROM users WHERE id = p_user_id),
    p_to_addrs, p_cc_addrs, p_bcc_addrs,
    p_in_reply_to, p_references_hdr,
    -- SP1 encrypted-at-rest: store NO cleartext for the Sent copy. raw_ref carries
    -- the ciphertext; the FTS trigger blanks body_tsv from a NULL body_text.
    -- subject stays. DLP at step 5a still scans the cleartext p_body_text args.
    CASE WHEN p_is_encrypted THEN NULL ELSE p_body_text END,
    CASE WHEN p_is_encrypted THEN NULL ELSE p_body_html END,
    p_size_bytes, p_has_attachments,
    compute_thread_id(p_message_id, p_in_reply_to, p_references_hdr, p_mailbox_id),
    p_raw_ref, coalesce(p_send_at, now()),
    TRUE,   -- sent messages are pre-read
    next_imap_uid_for_tag(v_sent_folder),
    0, NULL, FALSE, FALSE,
    p_send_at,
    -- SP1: mark the encrypted-at-rest Sent copy so decrypt-on-read fires for the
    -- sender's own copy (encrypt-to-self). Same flag that nulled the body above.
    CASE WHEN p_is_encrypted THEN 'smime-encrypted' ELSE NULL END,
    v_mailbox.litigation_hold, now()
  RETURNING id INTO v_message_id;

  -- 4a. Add Sent tag (trigger handles location exclusivity and counters)
  PERFORM tag_message(v_message_id, now()::TIMESTAMPTZ, 'Sent', p_mailbox_id, 'send', TRUE);

  -- 5. Run outbound admin transport rules (DLP, disclaimers, BCC archive).
  -- Runs AFTER the Sent insert but within the same transaction. A DLP RAISE
  -- EXCEPTION rolls back the entire submission (Sent insert + quota bump +
  -- queue insert) — the user never sees a sent copy that never actually went out.
  IF current_setting('app.skip_rules', true) IS DISTINCT FROM 'true' THEN
    PERFORM apply_rules(v_message_id, now()::TIMESTAMPTZ, p_mailbox_id, 'outbound');

    -- 5.2 Re-read rule-mutated recipient/body columns. apply_action has no
    -- return channel back into this function's locals — a bcc/append_footer/
    -- redirect rule action (rule_engine.sql) UPDATEs the Sent-copy `messages`
    -- row directly. The recipient/content resolution below (steps 6-9) must
    -- see those mutations, not the stale pre-rule parameters, so the effect
    -- actually reaches the SMTP envelope / local deliver() fan-out. When no
    -- such action fired this is a no-op (re-reads back the same values).
    SELECT to_addrs, cc_addrs, bcc_addrs, body_text, body_html
    INTO p_to_addrs, p_cc_addrs, p_bcc_addrs, p_body_text, p_body_html
    FROM messages WHERE id = v_message_id;
  END IF;

  -- 5a. DLP check (skip if feature.dlp disabled)
  IF current_setting('app.skip_dlp', true) IS DISTINCT FROM 'true' THEN
    -- Set statement timeout to prevent catastrophic regex backtracking
    PERFORM set_config('statement_timeout', '500ms', true);
    DECLARE
      v_violation   RECORD;
      v_attachments JSONB;
    BEGIN
    -- BUG FIX: this used to hardcode NULL, so blocked_file_types/
    -- max_attachment_size policies were dead at enforcement. The draft's real
    -- attachment metadata already exists via p_source_message_id/received_at —
    -- the SAME lookup deliver_group_vacation.sql uses (~line 304) to copy
    -- message_attachments onto a local-delivery copy. NULL when there's
    -- nothing to copy from (mirrors that same p_source_message_id gate).
    IF p_has_attachments AND p_source_message_id IS NOT NULL THEN
      SELECT jsonb_agg(jsonb_build_object('filename', filename, 'size_bytes', size_bytes))
        INTO v_attachments
      FROM message_attachments
      WHERE message_id = p_source_message_id AND received_at = p_source_received_at;
    END IF;

    SELECT * INTO v_violation FROM dlp_check(
      p_mailbox_id, v_mailbox.domain_id,
      p_subject, p_body_text, p_body_html, v_attachments
    ) LIMIT 1;

    IF v_violation.violated THEN
      INSERT INTO dlp_violations (policy_id, message_id, mailbox_id, violation_type, matched_text, action_taken)
      VALUES (v_violation.policy_id, v_message_id, p_mailbox_id, 'content_match', v_violation.reason, v_violation.action);

      CASE v_violation.action
        WHEN 'block' THEN
          RAISE EXCEPTION 'Message blocked by DLP policy'
            USING ERRCODE = 'BZ005', HINT = jsonb_build_object('type', 'dlp_blocked', 'policy_id', v_violation.policy_id, 'reason', v_violation.reason)::TEXT;
        WHEN 'quarantine' THEN
          -- Move to Spam through the single location seam. send() emits ONE
          -- notify_state_change at step 10, so suppress the per-swap push here
          -- (p_notify => FALSE) — no double bump. Provenance preserved ('dlp').
          PERFORM transition_message_location(v_message_id, now()::TIMESTAMPTZ, 'Spam', p_mailbox_id, 'dlp', FALSE);
        WHEN 'notify_admin' THEN
          UPDATE messages SET spam_headers = coalesce(spam_headers,'{}') || jsonb_build_object('dlp_flag', TRUE)
          WHERE id = v_message_id;
        ELSE NULL;
      END CASE;
    END IF;
  END;
  -- The 500ms cap guards regex backtracking inside the DLP check only;
  -- restore the default so the rest of delivery (retention, journaling,
  -- deliver() fan-out) does not inherit a per-statement budget it can
  -- exceed under load.
  PERFORM set_config('statement_timeout', '0', true);
  END IF; -- app.skip_dlp

  -- 5b. Tag retention + enqueue journal copy per policy (no-op if none configured).
  IF current_setting('app.skip_retention', true) IS DISTINCT FROM 'true' THEN
    PERFORM tag_retention(v_message_id, now()::TIMESTAMPTZ, p_mailbox_id);
  END IF;
  IF current_setting('app.skip_journaling', true) IS DISTINCT FROM 'true' THEN
    PERFORM journal_if_policy_matches(
      p_message_id, p_from_addr,
      -- Envelope recipient: use the first recipient if any, else the sender.
      coalesce((p_to_addrs->0->>'email'), p_from_addr),
      p_raw_ref, v_mailbox.domain_id, 'outbound'
    );
  END IF;

  -- 6. Collect all recipient addresses into a flat array
  SELECT COALESCE(array_agg(r->>'email'), ARRAY[]::TEXT[])
  INTO v_rcpts
  FROM (
    SELECT jsonb_array_elements(p_to_addrs) AS r
    UNION ALL
    SELECT jsonb_array_elements(p_cc_addrs)
    UNION ALL
    SELECT jsonb_array_elements(p_bcc_addrs)
  ) x;

  -- 7. For local recipients, deliver directly via deliver() (avoids SMTP round-trip).
  --    We build a separate array of external recipients for the outbound queue.
  DECLARE
    v_external_rcpts TEXT[] := ARRAY[]::TEXT[];
  BEGIN
    FOREACH v_rcpt IN ARRAY v_rcpts
    LOOP
      v_domain := split_part(v_rcpt, '@', 2);
      SELECT EXISTS(SELECT 1 FROM domains WHERE lower(name) = lower(v_domain) AND is_local)
      INTO v_is_local;

      IF v_is_local THEN
        -- p_body_text/p_body_html are passed as the CLEARTEXT for the recipient's
        -- in-deliver scanning; deliver() nulls them for storage when p_is_encrypted.
        PERFORM deliver(
          p_raw_ref, p_message_id,
          p_from_addr, (SELECT display_name FROM users WHERE id = p_user_id),
          v_rcpt,
          p_to_addrs, p_cc_addrs, p_bcc_addrs,
          p_subject, p_in_reply_to, p_references_hdr,
          p_body_text, p_body_html,
          p_size_bytes, p_has_attachments, now(),
          'pass', NULL, NULL,
          0.0, NULL,
          p_is_encrypted => p_is_encrypted,
          p_source_message_id => p_source_message_id,
          p_source_received_at => p_source_received_at
        );
      ELSE
        v_external_rcpts := array_append(v_external_rcpts, v_rcpt);
      END IF;
    END LOOP;

    -- 8. Queue only external recipients for outbound SMTP delivery
    IF array_length(v_external_rcpts, 1) > 0 THEN
      IF p_send_at IS NULL OR p_send_at <= now() THEN
        INSERT INTO outbound_queue_hot
          (message_id, from_addr, rcpt_addrs, raw_ref, status, next_attempt_at, mailbox_id, message_pk)
        VALUES
          (p_message_id, p_from_addr, v_external_rcpts, p_raw_ref, 'pending', now(), p_mailbox_id, v_message_id);
      ELSE
        INSERT INTO outbound_queue
          (message_id, from_addr, rcpt_addrs, raw_ref, status, next_attempt_at, mailbox_id, message_pk)
        VALUES
          (p_message_id, p_from_addr, v_external_rcpts, p_raw_ref, 'deferred', p_send_at, p_mailbox_id, v_message_id);
      END IF;
    END IF;
  END;

  -- 9. Increment daily sending quota counter
  UPDATE mailboxes SET sending_sent_today = sending_sent_today + 1 WHERE id = p_mailbox_id;

  -- 10. Notify clients: precise 'created' journal row for the Sent copy
  --     (offline #3, T8) + tag state bump + push on tag:{mailbox_id}.
  PERFORM notify_state_change(p_mailbox_id, v_sent_folder, v_message_id, 'created');

  RETURN v_message_id;
END;
$$ LANGUAGE plpgsql;

-- send_read_receipt: queues an MDN (RFC 3798) when a recipient reads a message.
--
-- Privacy gate (Track A): the RECIPIENT controls whether an MDN is ever sent via the
-- per-user read_receipt_policy ∈ {ask, always, never} (V081). This is a HARD gate —
-- "logic where the data is" — so a buggy or hostile client cannot leak a receipt the
-- recipient disallowed:
--   never  → NEVER send (returns status 'suppressed'), even if a client passes consent.
--   ask    → send only with explicit recipient consent (p_consent = TRUE); otherwise
--            'declined'. The webmail prompts the user and passes their choice.
--   always → send.
-- Default policy is 'ask', so the privacy-preserving behavior holds with no setup.
-- p_consent is nullable per project rule (no NOT NULL on params); NULL is treated as FALSE.
--
-- The prior 3-arg overload (no policy gate) is dropped so the gate cannot be bypassed by
-- resolving to the older signature.
--
-- ADR-003 currency: p_mailbox_id is the caller's account MAILBOX id (parseAccountID),
-- never a users.id. Ownership is the mailbox itself (mb.id = p_mailbox_id). The sender
-- user behind that mailbox — needed for the per-recipient privacy policy — is resolved
-- through the account_scope() seam, not by treating the mailbox id as a user id.
-- (account_scope is declared in this file's top-of-file deps header.)
DROP FUNCTION IF EXISTS send_read_receipt(BIGINT, BIGINT, TEXT);

CREATE OR REPLACE FUNCTION send_read_receipt(
  p_mailbox_id BIGINT,
  p_message_id BIGINT,
  p_recipient_email TEXT,
  p_consent BOOLEAN DEFAULT FALSE
) RETURNS JSONB AS $$
DECLARE
  v_orig_msg_id   TEXT;
  v_orig_from     TEXT;
  v_orig_subject  TEXT;
  v_orig_received TIMESTAMPTZ;
  v_mdn_raw       TEXT;
  v_mdn_msg_id    TEXT;
  v_now           TIMESTAMPTZ := now();
  v_boundary      TEXT := 'mdn-boundary-20384727';
  v_policy        TEXT;
  v_user_id       BIGINT;
BEGIN
  -- Ownership: the message must live in the caller's account mailbox (R1/R3).
  -- p_mailbox_id is a mailbox id, so scope by mb.id (NOT mb.user_id, which would
  -- treat the mailbox id as a user id and match zero rows for any real account).
  PERFORM 1 FROM messages m
  JOIN mailboxes mb ON mb.id = m.mailbox_id
  WHERE m.id = p_message_id AND mb.id = p_mailbox_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Message not found'
      USING ERRCODE = 'BZ002', HINT = jsonb_build_object('type', 'forbidden', 'message_id', p_message_id, 'mailbox_id', p_mailbox_id)::TEXT;
  END IF;

  -- Resolve the owning (sender) user behind the account mailbox for the policy
  -- lookup. NULL for a shared/resource mailbox or an unknown one; a NULL user_id
  -- has no global policy row, so get_read_receipt_policy() falls back to 'ask'.
  SELECT s.user_id INTO v_user_id FROM account_scope(p_mailbox_id) s;

  -- Privacy gate (the enforcement point — every policy value is honored here).
  v_policy := get_read_receipt_policy(v_user_id);
  IF v_policy = 'never' THEN
    RETURN jsonb_build_object('status', 'suppressed', 'reason', 'policy_never');
  END IF;
  IF v_policy = 'ask' AND COALESCE(p_consent, FALSE) = FALSE THEN
    RETURN jsonb_build_object('status', 'declined', 'reason', 'no_consent');
  END IF;
  -- policy 'always', or 'ask' with consent -> fall through and send.

  -- Ownership already established above (mb.id = p_mailbox_id); fetch by message id.
  SELECT m.message_id, m.from_addr, COALESCE(m.subject, ''),
         COALESCE(m.sent_at, m.received_at)
  INTO v_orig_msg_id, v_orig_from, v_orig_subject, v_orig_received
  FROM messages m WHERE m.id = p_message_id;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('type', 'notFound', 'description', 'message not found');
  END IF;

  IF EXISTS (SELECT 1 FROM read_receipts WHERE message_id = p_message_id AND recipient_email = p_recipient_email) THEN
    RETURN jsonb_build_object('status', 'already_sent');
  END IF;

  v_mdn_msg_id := '<mdn-' || p_message_id || '-' || EXTRACT(EPOCH FROM v_now)::TEXT || '@mailserver>';

  -- email_header_value(): strip CR/LF from echoed original-message fields (From/Subject/
  -- Message-ID were attacker-supplied on the inbound side) → no MDN header injection.
  v_mdn_raw := 'From: ' || email_header_value(p_recipient_email) || E'\r\n' ||
    'To: ' || email_header_value(v_orig_from) || E'\r\n' ||
    'Message-ID: ' || v_mdn_msg_id || E'\r\n' ||
    'Date: ' || to_char(v_now, 'Dy, DD Mon YYYY HH24:MI:SS +0000') || E'\r\n' ||
    'Subject: Read: ' || email_header_value(v_orig_subject) || E'\r\n' ||
    'MIME-Version: 1.0' || E'\r\n' ||
    'Content-Type: multipart/report; report-type=disposition-notification; boundary="' || v_boundary || '"' || E'\r\n' ||
    E'\r\n' ||
    '--' || v_boundary || E'\r\n' ||
    'Content-Type: text/plain; charset=utf-8' || E'\r\n' || E'\r\n' ||
    'Your message was displayed on ' || to_char(v_now, 'Dy, DD Mon YYYY HH24:MI:SS +0000') || E'\r\n' ||
    '--' || v_boundary || E'\r\n' ||
    'Content-Type: message/disposition-notification' || E'\r\n' || E'\r\n' ||
    'Reporting-UA: mailserver; JMAP Webmail' || E'\r\n' ||
    'Original-Recipient: rfc822;' || email_header_value(p_recipient_email) || E'\r\n' ||
    'Final-Recipient: rfc822;' || email_header_value(p_recipient_email) || E'\r\n' ||
    'Original-Message-ID: ' || email_header_value(v_orig_msg_id) || E'\r\n' ||
    'Disposition: manual-action/MDN-sent-manually; displayed' || E'\r\n' ||
    '--' || v_boundary || '--';

  INSERT INTO outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status)
  VALUES (v_mdn_msg_id, p_recipient_email, ARRAY[v_orig_from], v_mdn_raw, 'pending');

  INSERT INTO read_receipts (message_id, received_at, recipient_email, read_at)
  VALUES (p_message_id, v_orig_received, p_recipient_email, v_now)
  ON CONFLICT DO NOTHING;

  RETURN jsonb_build_object('status', 'sent', 'mdnMessageId', v_mdn_msg_id);
END;
$$ LANGUAGE plpgsql;
