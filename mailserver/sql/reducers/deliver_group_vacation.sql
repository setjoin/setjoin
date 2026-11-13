-- deliver_group_vacation.sql: Phase 6 patches for deliver().
-- Adds distribution group expansion and vacation auto-reply.

CREATE OR REPLACE FUNCTION deliver(
  p_raw_ref         TEXT,
  p_message_id      TEXT,
  p_from_addr       TEXT,
  p_from_name       TEXT,
  p_rcpt_addr       TEXT,
  p_to_addrs        JSONB,
  p_cc_addrs        JSONB,
  p_bcc_addrs       JSONB,
  p_subject         TEXT,
  p_in_reply_to     TEXT,
  p_references_hdr  TEXT,
  p_body_text       TEXT,
  p_body_html       TEXT,
  p_size_bytes      BIGINT,
  p_has_attachments BOOL,
  p_sent_at         TIMESTAMPTZ,
  p_spf_result      TEXT,
  p_dkim_result     TEXT,
  p_dmarc_result    TEXT,
  p_spam_score      REAL,
  p_spam_headers    JSONB,
  p_vote_response   TEXT DEFAULT NULL,
  p_crypto_type     TEXT DEFAULT NULL,
  p_is_external       BOOL DEFAULT FALSE,
  p_sender_display_name TEXT DEFAULT NULL,
  p_is_name_spoof     BOOL DEFAULT FALSE,
  p_depth           INT DEFAULT 0,
  p_list_id         TEXT DEFAULT NULL,
  p_smime_status        TEXT DEFAULT NULL,
  p_smime_signer_email  TEXT DEFAULT NULL,
  p_smime_signer_cn     TEXT DEFAULT NULL,
  p_smime_issuer_cn     TEXT DEFAULT NULL,
  p_is_encrypted        BOOLEAN DEFAULT FALSE, -- SP1: TRUE = encrypted-at-rest (raw_ref is ciphertext); null the body cols
  -- Attachment-metadata source: the sender's own message (draft id + its
  -- received_at) to copy message_attachments rows FROM, onto THIS delivered
  -- copy's own (message_id, received_at) key. NULL for callers with no such
  -- source (genuine external-inbound SMTP — no prior message_attachments rows
  -- exist to copy from; vacation auto-reply / NDR / DSN system messages).
  p_source_message_id   BIGINT DEFAULT NULL,
  p_source_received_at  TIMESTAMPTZ DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
  v_mailbox         RECORD;
  v_folder_id       BIGINT;
  v_inbox_tag_id    BIGINT;
  v_spam_tag_id     BIGINT;
  v_message_id      BIGINT;
  v_received_at     TIMESTAMPTZ;
  v_thread_id       TEXT;
  v_imap_uid        BIGINT;
  v_spam_threshold  REAL := 5.0;
  v_member          RECORD;
  v_vacation        RECORD;
  v_domain          TEXT;
  v_is_local        BOOL;
  v_sender_is_internal BOOL;
  v_send_reply      BOOL;
  v_reply_text      TEXT;
  v_reply_html      TEXT;
  v_is_muted        BOOL := FALSE;
  v_muted_tag_id    BIGINT;
  v_is_first_time   BOOL := TRUE;
  v_group_id        BIGINT;
BEGIN
  -- 1. Resolve the target mailbox (alias → mailbox, or direct mailbox email)
  SELECT mb.* INTO v_mailbox
  FROM mailboxes mb
  JOIN aliases a ON a.mailbox_id = mb.id
  WHERE lower(a.email) = lower(p_rcpt_addr)
    AND mailbox_lifecycle_delivery_mode(mb.id) <> 'rejecting';

  IF v_mailbox.id IS NULL THEN
    -- lower(email) match, index-backed by mailboxes_email_lower_idx: a mailbox
    -- stored with any uppercase (the unique index is on lower(email), so mixed
    -- case is allowed) must still be deliverable — case-sensitive '=' left such
    -- addresses silently undeliverable.
    SELECT * INTO v_mailbox FROM mailboxes
    WHERE lower(email) = lower(p_rcpt_addr)
      AND mailbox_lifecycle_delivery_mode(id) <> 'rejecting';
  END IF;

  IF v_mailbox.id IS NULL THEN
    v_domain := split_part(p_rcpt_addr, '@', 2);
    SELECT mb.* INTO v_mailbox
    FROM mailboxes mb
    JOIN domains d ON d.catch_all_mailbox_id = mb.id
    WHERE lower(d.name) = lower(v_domain)
      AND mailbox_lifecycle_delivery_mode(mb.id) <> 'rejecting';
  END IF;

  IF v_mailbox.id IS NULL THEN
    RAISE EXCEPTION 'no mailbox for %', p_rcpt_addr
      USING ERRCODE = 'BZ007', HINT = jsonb_build_object('type', 'no_mailbox', 'rcpt', p_rcpt_addr)::TEXT;
  END IF;

  -- Cycle guard: abort if recursion depth exceeds 10 (max nested groups).
  IF p_depth > 10 THEN
    RAISE EXCEPTION 'delivery_loop: distribution group nesting exceeded max depth';
  END IF;

  -- 1a. Distribution group expansion (detected via satellite table, not type enum)
  SELECT id INTO v_group_id FROM distribution_groups WHERE mailbox_id = v_mailbox.id;

  IF v_group_id IS NOT NULL THEN
    FOR v_member IN
      SELECT m.mailbox_id AS id FROM expand_group(v_group_id) m
    LOOP
      -- Per-member subtransaction: one member's over-quota (BZ001) / no-mailbox (BZ007)
      -- must NOT roll back delivery to the whole list (a 300-10,000-user static list
      -- almost always has one over-quota or disabled member). Skip + WARN the failing
      -- member; the rest still receive. expand_group already filters disabled/receive-
      -- disabled members, so the common residual failure here is over-quota.
      BEGIN
        -- Deliver individually to each member's primary email
        PERFORM deliver(
          p_raw_ref, p_message_id, p_from_addr, p_from_name,
          (SELECT email FROM mailboxes WHERE id = v_member.id),
          p_to_addrs, p_cc_addrs, p_bcc_addrs, p_subject,
          p_in_reply_to, p_references_hdr, p_body_text, p_body_html,
          p_size_bytes, p_has_attachments, p_sent_at,
          p_spf_result, p_dkim_result, p_dmarc_result,
          p_spam_score, p_spam_headers,
          p_vote_response, p_crypto_type,
          p_is_external, p_sender_display_name, p_is_name_spoof,
          p_depth + 1, p_list_id,
          p_smime_status, p_smime_signer_email, p_smime_signer_cn, p_smime_issuer_cn,
          -- SP1: thread encrypted-at-rest flag through to each member copy. Omitting it
          -- defaulted FALSE → members kept CLEARTEXT body cols even when the send was
          -- encrypted (raw_ref ciphertext but plaintext-at-rest body cache leak).
          p_is_encrypted => p_is_encrypted,
          -- Thread the attachment-metadata source through group fan-out too, so a
          -- distribution-group send with attachments doesn't regress the same way.
          p_source_message_id => p_source_message_id,
          p_source_received_at => p_source_received_at
        );
      EXCEPTION WHEN OTHERS THEN
        RAISE WARNING 'distribution group % fan-out: delivery to member % skipped: %',
          v_group_id, v_member.id, SQLERRM;
      END;
    END LOOP;
    RETURN NULL; -- group itself doesn't get a message row
  END IF;

  -- 2. Quota check (advisory early-exit; atomic enforcement at step 7b)
  IF NOT check_quota(v_mailbox.id, p_size_bytes) THEN
    RAISE EXCEPTION 'mailbox % is over quota', v_mailbox.id
      USING ERRCODE = 'BZ001', HINT = jsonb_build_object('type', 'over_quota', 'mailbox_id', v_mailbox.id)::TEXT;
  END IF;

  -- 3. Spam threshold
  SELECT (value #>> '{}')::REAL INTO v_spam_threshold
  FROM system_config WHERE key = 'spam_threshold';
  v_spam_threshold := coalesce(v_spam_threshold, 5.0);

  -- 4. Target tag (Inbox or Spam) — tag system with exclusivity
  v_inbox_tag_id := get_tag_id('Inbox', v_mailbox.id);
  v_spam_tag_id  := get_tag_id('Spam', v_mailbox.id);

  IF v_inbox_tag_id IS NULL THEN
    RAISE EXCEPTION 'mailbox % has no Inbox tag', v_mailbox.id
      USING ERRCODE = 'BZ008', HINT = jsonb_build_object('type', 'missing_inbox', 'mailbox_id', v_mailbox.id)::TEXT;
  END IF;

  IF v_mailbox.spam_folder_enabled
    AND p_spam_score IS NOT NULL
    AND p_spam_score >= v_spam_threshold THEN
    v_folder_id := COALESCE(v_spam_tag_id, v_inbox_tag_id);
  ELSE
    v_folder_id := v_inbox_tag_id;
  END IF;

  -- 5. Thread ID
  v_thread_id := compute_thread_id(p_message_id, p_in_reply_to, p_references_hdr, v_mailbox.id);

  -- 5b. First-time sender check (skip if feature toggle disabled)
  -- is_first_time defaults to TRUE; set to FALSE if a prior message from
  -- the same from_addr exists in this mailbox.
  IF current_setting('app.skip_external_sender_first_time', true) IS DISTINCT FROM 'true' THEN
    -- messages.from_addr is stored case-preserved (the gateway does not lowercase it),
    -- so compare case-insensitively. Comparing stored case vs lower(p_from_addr) made
    -- every message from a mixed-case sender (e.g. John.Doe@Example.com) look first-time,
    -- firing the external-sender banner every time and defeating its purpose.
    v_is_first_time := NOT EXISTS(
      SELECT 1 FROM messages
      WHERE mailbox_id = v_mailbox.id
        AND lower(from_addr) = lower(p_from_addr)
      LIMIT 1
    );
  END IF;

  -- 5a. Mute / Ignore Conversation (Gmail "Mute"): a muted thread carries the
  -- Muted tag on ≥1 of its messages. A reply to such a thread skips the Inbox
  -- (auto-archived — step 7 tags it Muted only, no Inbox location), so the
  -- conversation stays quiet but remains in All Mail / search. Muting is a pure
  -- tag operation via Email/set — there is no mute_thread rule (that gate was
  -- dead code keyed on a rule template nothing creates; removed 2026-07-01).
  v_muted_tag_id := get_tag_id('Muted', v_mailbox.id);
  IF v_muted_tag_id IS NOT NULL THEN
    v_is_muted := EXISTS(
      SELECT 1 FROM message_tags mt
      JOIN tags t ON t.id = mt.tag_id
      JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
      WHERE m.thread_id = v_thread_id
        AND m.mailbox_id = v_mailbox.id
        AND t.name = 'Muted'
    );

    -- Breakout: an explicit To/Cc recipient overrides the mute (the reply is
    -- directed at this user, so it should reach the Inbox).
    IF v_is_muted AND (
         p_to_addrs @> jsonb_build_array(jsonb_build_object('email', lower(p_rcpt_addr)))
      OR p_cc_addrs @> jsonb_build_array(jsonb_build_object('email', lower(p_rcpt_addr)))
    ) THEN
      v_is_muted := FALSE;
    END IF;
  END IF;

  -- 6. IMAP UID
  v_imap_uid := next_imap_uid_for_tag(v_folder_id);

  -- 7. Insert message (folder_id kept for backward compat, synced by primary tag trigger)
  INSERT INTO messages (
    mailbox_id, folder_id,
    message_id, subject, from_addr, from_name,
    to_addrs, cc_addrs, bcc_addrs,
    in_reply_to, references_hdr,
    body_text, body_html,
    size_bytes, has_attachments,
    thread_id, raw_ref, sent_at,
    spf_result, dkim_result, dmarc_result,
    spam_score, spam_headers,
    vote_response, crypto_type,
    is_external, sender_display_name, is_name_spoof, is_first_time,
    imap_uid, imap_modseq,
    held, received_at,
    list_id,
    smime_status, smime_signer_email, smime_signer_cn, smime_issuer_cn
  ) VALUES (
    v_mailbox.id, v_folder_id,
    p_message_id, p_subject, p_from_addr, p_from_name,
    p_to_addrs, p_cc_addrs, p_bcc_addrs,
    p_in_reply_to, p_references_hdr,
    -- SP1 encrypted-at-rest: store NO cleartext for the encrypted recipient copy.
    -- raw_ref carries the ciphertext; the FTS trigger blanks body_tsv from a NULL
    -- body_text. subject stays (S/MIME headers are unencrypted).
    CASE WHEN p_is_encrypted THEN NULL ELSE p_body_text END,
    CASE WHEN p_is_encrypted THEN NULL ELSE p_body_html END,
    p_size_bytes, p_has_attachments,
    v_thread_id, p_raw_ref, p_sent_at,
    p_spf_result, p_dkim_result, p_dmarc_result,
    p_spam_score, p_spam_headers,
    -- SP1: tie the at-rest crypto discriminator to the SAME flag that nulls the
    -- body cols (p_is_encrypted) so they can never diverge. Without this the
    -- encrypted recipient copy stored body=NULL but crypto_type=NULL, and the
    -- decrypt-on-read gate (mail_decrypt.go: cryptoType=='smime-encrypted') +
    -- the V029 FTS guard both silently skipped it → blank, unreadable mail.
    -- When NOT encrypted, preserve the inbound-detected p_crypto_type.
    p_vote_response, CASE WHEN p_is_encrypted THEN 'smime-encrypted' ELSE p_crypto_type END,
    p_is_external, p_sender_display_name, p_is_name_spoof, v_is_first_time,
    v_imap_uid, nextval('imap_modseq_seq'),
    v_mailbox.litigation_hold, now(),
    normalize_list_id(p_list_id),
    p_smime_status, p_smime_signer_email, p_smime_signer_cn, p_smime_issuer_cn
  ) RETURNING id, received_at INTO v_message_id, v_received_at;

  -- 7a. Add tag (trigger enforces location exclusivity and updates counters)
  IF v_is_muted THEN
    -- No location tag → All Mail only; add Muted label for tracking
    PERFORM tag_message(v_message_id, now()::TIMESTAMPTZ, 'Muted', v_mailbox.id, 'deliver', FALSE);
  ELSE
    PERFORM tag_message(v_message_id, now()::TIMESTAMPTZ,
      CASE WHEN v_folder_id = v_spam_tag_id THEN 'Spam' ELSE 'Inbox' END,
      v_mailbox.id, 'deliver', TRUE);

    -- Focused/Other split: only for a message that actually landed in Inbox
    -- (not Spam). classify_focus (deterministic, first-match-wins) decides; a
    -- TRUE verdict adds the 'Other' tag (absence = Focused). The Other tag's
    -- counters come free from the message_tags counter trigger.
    IF v_folder_id = v_inbox_tag_id
       AND classify_focus(v_mailbox.id, p_from_addr, p_is_external, v_is_first_time, p_list_id) THEN
      PERFORM tag_message(v_message_id, now()::TIMESTAMPTZ, 'Other', v_mailbox.id, 'deliver', FALSE);
    END IF;
  END IF;

  -- 7a2. Copy attachment metadata (message_attachments rows) from the source
  -- message (the sender's own draft) onto THIS delivered copy's own (message_id,
  -- received_at) key. jmap_email_get / message_to_jmap_email project attachments
  -- and inlineImages by joining message_attachments on (message_id, received_at)
  -- per copy — without this, a locally-delivered copy (send() → deliver() for a
  -- local recipient) carried has_attachments=TRUE but zero message_attachments
  -- rows: Email/get showed attachments:[] / inlineImages:null and cid: images
  -- rendered as raw text. Mirrors the copy jmap_email_submission_set already does
  -- onto the SENT copy. p_source_message_id is NULL for callers with nothing to
  -- copy from (see the parameter's doc comment above).
  IF p_source_message_id IS NOT NULL AND p_has_attachments THEN
    INSERT INTO message_attachments
      (message_id, received_at, blob_sha256, content_type, filename, content_id, disposition, size_bytes)
    SELECT v_message_id, v_received_at, ma.blob_sha256, ma.content_type, ma.filename,
           ma.content_id, ma.disposition, ma.size_bytes
    FROM message_attachments ma
    WHERE ma.message_id = p_source_message_id AND ma.received_at = p_source_received_at;
  END IF;

  -- 7b. Atomic quota enforcement (serialized via row lock, prevents TOCTOU race)
  UPDATE mailboxes
  SET used_bytes = used_bytes + p_size_bytes
  WHERE id = v_mailbox.id
    AND used_bytes + p_size_bytes <= quota_bytes;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'mailbox % is over quota (needed % bytes, available %)',
      v_mailbox.id, p_size_bytes,
      (SELECT quota_bytes - used_bytes FROM mailboxes WHERE id = v_mailbox.id)
      USING ERRCODE = 'BZ001', HINT = jsonb_build_object('type', 'over_quota', 'mailbox_id', v_mailbox.id)::TEXT;
  END IF;

  -- 7c. Domain-level quota enforcement
  DECLARE
    v_domain_quota BIGINT;
    v_domain_used  BIGINT;
  BEGIN
    SELECT d.quota_bytes, COALESCE(SUM(mb.used_bytes), 0) + p_size_bytes
    INTO v_domain_quota, v_domain_used
    FROM domains d
    LEFT JOIN mailboxes mb ON mb.domain_id = d.id
    WHERE d.id = v_mailbox.domain_id
    GROUP BY d.id, d.quota_bytes;

    IF v_domain_quota IS NOT NULL AND v_domain_used > v_domain_quota THEN
      RAISE EXCEPTION 'domain % is over quota (needed % bytes, available %)',
        v_mailbox.domain_id, p_size_bytes,
        v_domain_quota - v_domain_used + p_size_bytes
        USING ERRCODE = 'BZ009', HINT = jsonb_build_object('type', 'domain_over_quota', 'domain_id', v_mailbox.domain_id)::TEXT;
    END IF;
  END;

  -- 8. Rules (skip if feature.rules_engine disabled)
  IF current_setting('app.skip_rules', true) IS DISTINCT FROM 'true' THEN
    PERFORM apply_rules(v_message_id, now()::TIMESTAMPTZ, v_mailbox.id, 'server');
  END IF;

  -- 10. Retention + journal (best-effort: journal failure must not abort delivery)
  IF current_setting('app.skip_retention', true) IS DISTINCT FROM 'true' THEN
    PERFORM tag_retention(v_message_id, now()::TIMESTAMPTZ, v_mailbox.id);
  END IF;
  IF current_setting('app.skip_journaling', true) IS DISTINCT FROM 'true' THEN
    BEGIN
      PERFORM journal_if_policy_matches(
        p_message_id, p_from_addr, p_rcpt_addr, p_raw_ref,
        v_mailbox.domain_id, 'inbound'
      );
    EXCEPTION WHEN OTHERS THEN
      -- Journal enqueue failure is logged but does not block delivery.
      NULL;
    END;
  END IF;

  -- 11. Vacation auto-reply (skip if feature.vacation disabled)
  IF current_setting('app.skip_vacation', true) IS DISTINCT FROM 'true' THEN
    SELECT * INTO v_vacation FROM vacation_settings
    WHERE mailbox_id = v_mailbox.id
      AND enabled = TRUE
      AND (start_date IS NULL OR start_date <= CURRENT_DATE)
      AND (end_date IS NULL OR end_date >= CURRENT_DATE);

    -- RFC 3834: never auto-reply to spam, mailing-list traffic, or a null/empty
    -- return-path. Auto-replying to spam (almost always a forged third party) is
    -- backscatter that gets the server blacklisted; list mail must not be answered;
    -- an empty Return-Path means a bounce/null sender. v_folder_id = v_spam_tag_id
    -- catches the spam-foldered case; the p_spam_score check also catches a high-spam
    -- message that stayed in Inbox because spam_folder_enabled is off.
    IF v_vacation.mailbox_id IS NOT NULL
       AND v_folder_id IS DISTINCT FROM v_spam_tag_id
       AND NOT (p_spam_score IS NOT NULL AND p_spam_score >= v_spam_threshold)
       AND p_list_id IS NULL
       AND p_from_addr IS NOT NULL AND p_from_addr <> '' THEN
    -- Rate limit: one reply per sender per day
    IF NOT EXISTS (
      SELECT 1 FROM vacation_replies
      WHERE sender_email = lower(p_from_addr)
        AND mailbox_id = v_mailbox.id
        AND replied_at > now() - interval '1 day'
    ) THEN
      -- Sender locality (independent of the legacy only_contacts gate): a sender is
      -- internal when their address is a local mailbox or on a local domain.
      v_domain := split_part(lower(p_from_addr), '@', 2);
      SELECT EXISTS(SELECT 1 FROM mailboxes WHERE email = lower(p_from_addr))
          OR EXISTS(SELECT 1 FROM domains WHERE lower(name) = v_domain AND is_local)
        INTO v_sender_is_internal;

      -- Decide whether to reply at all.
      v_send_reply := TRUE;

      -- Legacy only_contacts gate: when set, never reply to non-local senders.
      IF v_vacation.only_contacts AND NOT v_sender_is_internal THEN
        v_send_reply := FALSE;
      END IF;

      -- A5 external-audience gate (only applies to EXTERNAL senders):
      --   'none'     → never auto-reply to external senders
      --   'contacts' → reply only when the sender is in the OWNER's address book
      --   'all'      → reply to every external sender
      IF v_send_reply AND NOT v_sender_is_internal THEN
        IF v_vacation.external_audience = 'none' THEN
          v_send_reply := FALSE;
        ELSIF v_vacation.external_audience = 'contacts' THEN
          v_send_reply := EXISTS (
            SELECT 1
            FROM contacts c
            JOIN addressbooks ab ON ab.id = c.addressbook_id
            WHERE ab.mailbox_id = v_mailbox.id
              AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(c.emails) e
                WHERE lower(e->>'address') = lower(p_from_addr)
              )
          );
        END IF;
        -- 'all' leaves v_send_reply = TRUE.
      END IF;

      IF v_send_reply THEN
        -- Body selection: external sender uses the external body when present;
        -- internal senders (and a blank external body) fall back to the internal body.
        IF v_sender_is_internal OR v_vacation.body_external IS NULL THEN
          v_reply_text := COALESCE(v_vacation.body_text, '');
          v_reply_html := COALESCE(v_vacation.body_html, v_vacation.body_text);
        ELSE
          v_reply_text := COALESCE(v_vacation.body_external, '');
          v_reply_html := COALESCE(v_vacation.body_external_html, v_vacation.body_external);
        END IF;

        PERFORM send(
          NULL, v_mailbox.id, 'internal://vacation-reply',
          '<vacation-' || v_mailbox.id || '-' || extract(epoch from now())::bigint || '@mailserver>',
          v_mailbox.email,
          jsonb_build_array(jsonb_build_object('email', lower(p_from_addr))),
          '[]'::jsonb, '[]'::jsonb,
          coalesce(v_vacation.subject, 'Out of office'),
          p_message_id, '',
          v_reply_text,
          v_reply_html,
          0, FALSE, NULL
        );

        INSERT INTO vacation_replies (sender_email, mailbox_id, vacation_start, replied_at)
        VALUES (lower(p_from_addr), v_mailbox.id, COALESCE(v_vacation.start_date, CURRENT_DATE), now())
        ON CONFLICT (sender_email, mailbox_id, vacation_start) DO UPDATE SET replied_at = now();
      END IF;
    END IF;
  END IF;
  END IF; -- app.skip_vacation

  -- 12. Trace
  PERFORM trace(p_message_id, 'received', p_from_addr, p_rcpt_addr,
    NULL, jsonb_build_object('mailbox_id', v_mailbox.id, 'spam_score', p_spam_score));

  -- 13. Notify: one call bumps email + tag state (fixes the missed-bump /
  --     stale-token bug — a new inbound message now advances jmap_email_state)
  --     and pushes on tag:{mailbox_id}.
  PERFORM notify_state_change(v_mailbox.id, v_folder_id, v_message_id, 'created');

  -- 14. Push intent (QoL #9): enqueue for the mail-push worker when the feature is
  -- ON, the message did not land in Spam, and the thread isn't muted. The worker
  -- (pushjobs) re-checks push_should_notify (prefs / VIP / DND) before dispatching
  -- — this is only the cheap in-txn enqueue. Idempotent per delivered row via
  -- UNIQUE (mailbox_id, message_id).
  IF v_folder_id IS DISTINCT FROM v_spam_tag_id
     AND NOT v_is_muted
     AND COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.mail_push'), FALSE) THEN
    INSERT INTO push_intents (mailbox_id, message_id, received_at)
    VALUES (v_mailbox.id, v_message_id, v_received_at)
    ON CONFLICT (mailbox_id, message_id) DO NOTHING;
  END IF;

  RETURN v_message_id;
END;
$$ LANGUAGE plpgsql;
