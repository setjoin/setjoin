-- message_to_jmap_email.sql
--
-- The single-source JMAP Email projection (RFC 8621 §4) for ONE messages row.
--
-- Two reducers build a FULL Email object for the same row and MUST stay identical:
--   * jmap_email_get            (Email/get)
--   * jmap_email_query_deleted  (Email/deletedQuery — embeds full Email objects
--                                inline in its `list`, so a trash-view client reads
--                                them without an Email/get round-trip)
-- They were two hand-maintained jsonb_build_object() blocks and HAD DRIFTED: the
-- deleted projection was missing pinnedAt, isExternal, senderDisplayName,
-- isNameSpoof, isFirstTime, flagDueAt, flagReminderAt (and, before it was folded
-- in here, the S/MIME verdict block was a copy-pasted "mirror"). Net effect: an
-- email showed spoof/attachment/flag/pin badges while live, then lost those keys
-- the moment it entered the trash listing. Single-sourcing makes the drift
-- un-expressible: both callers emit exactly these keys for a given row.
--
-- SCOPE: only fields that come PURELY from the messages row live here. Request- or
-- cross-table-dependent fields stay in the caller and are `||`-merged on top:
--   * mailboxIds   — computed from message_tags in get; hard-coded '{}' in deleted
--                    (a soft-deleted message is detached from its tags).
--   * inlineImages / attachments — per-request message_attachments scans, guarded
--                    by p_properties in jmap_email_get.
--
-- STABLE (not IMMUTABLE): timestamptz→json serialization depends on the TimeZone
-- GUC, so the strongest honest volatility is STABLE. No table access — row only.
CREATE OR REPLACE FUNCTION message_to_jmap_email(p_row messages)
RETURNS JSONB AS $$
  SELECT jsonb_build_object(
    'id', p_row.id::TEXT,
    'blobId', p_row.raw_ref,
    'threadId', p_row.thread_id,
    'keywords', jsonb_build_object(
      '$seen', p_row.is_read,
      '$flagged', p_row.is_flagged,
      '$answered', p_row.is_answered,
      '$draft', p_row.is_draft
    ),
    'size', p_row.size_bytes,
    'receivedAt', p_row.received_at,
    'sentAt', p_row.sent_at,
    'hasAttachment', p_row.has_attachments,
    'priority', p_row.priority,
    'sensitivity', p_row.sensitivity,
    'readReceiptRequested', p_row.read_receipt_requested,
    'deliveryReceiptRequested', p_row.delivery_receipt_requested,
    'voteOptions', p_row.vote_options,
    'scheduledAt', p_row.scheduled_at,
    'pinnedAt', p_row.pinned_at,
    'preview', left(p_row.body_text, 256),
    'bodyText', CASE WHEN octet_length(p_row.body_text) <= 1048576
      THEN p_row.body_text
      ELSE left(p_row.body_text, 1048576) || E'\n\n[truncated — download raw message to view full content]'
    END,
    'bodyHTML', CASE WHEN p_row.body_html IS NOT NULL AND octet_length(p_row.body_html) <= 1048576
      THEN p_row.body_html
      WHEN p_row.body_html IS NOT NULL
      THEN left(p_row.body_html, 1048576)
      ELSE NULL
    END,
    'subject', p_row.subject,
    'from', jsonb_build_array(jsonb_build_object(
      'name', p_row.from_name,
      'email', p_row.from_addr
    )),
    'to', p_row.to_addrs,
    'cc', p_row.cc_addrs,
    'bcc', p_row.bcc_addrs,
    'replyTo', CASE WHEN p_row.reply_to IS NOT NULL
      THEN jsonb_build_array(jsonb_build_object('email', p_row.reply_to)) END,
    'messageId', jsonb_build_array(p_row.message_id),
    'isExternal', p_row.is_external,
    'senderDisplayName', p_row.sender_display_name,
    'isNameSpoof', p_row.is_name_spoof,
    'isFirstTime', p_row.is_first_time,
    -- Follow-up flag (A2): due + reminder instants (A6's scan fires them; here we
    -- only expose the stored value).
    'flagDueAt', to_jsonb(p_row.flag_due_at),
    'flagReminderAt', to_jsonb(p_row.flag_reminder_at),
    -- S/MIME verdict (A8): graded inbound signature result + signer identity.
    -- NULL when the smime_verify toggle is off or the message is unsigned.
    'cryptoType', p_row.crypto_type,
    'smimeStatus', p_row.smime_status,
    'smimeSignerEmail', p_row.smime_signer_email,
    'smimeSignerCn', p_row.smime_signer_cn,
    'smimeIssuerCn', p_row.smime_issuer_cn
  );
$$ LANGUAGE sql STABLE;
