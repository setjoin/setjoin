-- quarantine_message: the single, atomic owner of "a message ClamAV (or DLP/admin)
-- condemned leaves its current folder and enters Quarantine, with one audit row".
--
-- Why this is NOT transition_message_location: that seam swaps tags WITHIN the
-- `location` exclusive-group (Inbox→Trash→…). Quarantine is cross-group: the
-- `Quarantined` tag lives in the `quarantine` exclusive-group (schema/033_quarantine
-- widened the CHECK to ('location','snooze','quarantine')), so the message must
-- have its `location`-group tag(s) REMOVED (it leaves Inbox/wherever a rule already
-- put it) AND a `quarantine`-group tag ADDED AND a quarantined_messages audit row
-- written — a triad transition_message_location does not express. So quarantine
-- gets its own seam.
--
-- Replaces five non-atomic pool statements in the SMTP gateway
-- (smtp/inbound.go processQuarantine): resolve-mailbox + Inbox-tag-lookup +
-- Quarantined-tag-lookup + DELETE inbox tag + INSERT quarantine tag + INSERT audit.
-- A partial failure there left a message half-quarantined (tagged-but-no-audit or
-- audit-but-not-tagged); here it is one txn.
--
-- R3 (ownership-scoped): every statement filters by p_mailbox_id. The Quarantined
-- tag is resolved IN p_mailbox_id, so a foreign mailbox cannot resolve it →
-- BZ074 (no cross-tenant write, no audit row).
--
-- original_tag accuracy: the audit row records the message's REAL current location
-- tag (whatever the message actually carries now), not a hard-coded 'Inbox'. The
-- old Go assumed 'Inbox' even when a rule had already moved the message before
-- ClamAV fired — a latent inaccuracy this reducer fixes by reading the real
-- location (falls back to 'Inbox' only when the message carries no location tag).
--
-- p_notify (DEFAULT TRUE — the named fix, Decision 3): the old Go quarantine
-- emitted NO pg_notify, so the webmail showed a quarantined message as still in
-- Inbox until a manual refresh (a virus the user can't see leaving their inbox).
-- DEFAULT TRUE pushes the change through the single owner notify_state_change(
-- p_mailbox_id, <Quarantined tag id>) so the client learns of it immediately.
-- Behavior-preserving fallback: pass FALSE.
CREATE OR REPLACE FUNCTION quarantine_message(
    p_message_id  BIGINT,
    p_mailbox_id  BIGINT,
    p_reason      TEXT,
    p_reason_type TEXT    DEFAULT 'virus',
    p_virus_name  TEXT    DEFAULT NULL,
    p_notify      BOOLEAN DEFAULT TRUE
) RETURNS VOID AS $$
DECLARE
    v_received_at  TIMESTAMPTZ;
    v_quar_tag_id  BIGINT;
    v_original_tag TEXT;
BEGIN
    -- Ensure the Quarantined system tag exists in the target mailbox. The
    -- per-mailbox tag seed (create_system_tags) has never included it, so any
    -- mailbox created after the seed migration would BZ074-abort the whole
    -- quarantine and leave condemned mail in Inbox — exactly the outcome this
    -- seam exists to prevent (D-MAILSERVER-INTERNAL-SMTP-V003: the clamd
    -- verdict must fail CLOSED into the quarantine). Idempotent and
    -- CONFLICT-SAFE system-tag insert (med-shard2-002 item 3): two concurrent
    -- first quarantines in the same mailbox can both pass the old
    -- INSERT … WHERE NOT EXISTS check and race the unique (mailbox_id,name)
    -- constraint, aborting one transaction with its message left
    -- unquarantined; ON CONFLICT DO NOTHING lets the loser wait out the
    -- winner's insert and proceed. The unique key is
    -- tags_mailbox_id_name_key (V001 baseline).
    INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group, sort_order, imap_expose, imap_uid_validity)
    VALUES (p_mailbox_id, 'Quarantined', 'system', 'quarantine', 900, FALSE, EXTRACT(EPOCH FROM now())::BIGINT)
    ON CONFLICT (mailbox_id, name) DO NOTHING;

    -- Resolve the Quarantined tag IN the owning mailbox. A foreign p_mailbox_id
    -- cannot resolve it → BZ074 (R3: no cross-tenant write, no audit row).
    v_quar_tag_id := get_tag_id('Quarantined', p_mailbox_id);
    IF v_quar_tag_id IS NULL THEN
        RAISE EXCEPTION 'Quarantined tag not found in mailbox %', p_mailbox_id
          USING ERRCODE = 'BZ074',
                HINT = jsonb_build_object('type', 'quarantine_target_not_found',
                                          'message_id', p_message_id,
                                          'mailbox_id', p_mailbox_id)::TEXT;
    END IF;

    -- Resolve the message's received_at AND its REAL current location tag, scoped
    -- to the owning mailbox (R3). A foreign/absent message yields no row → BZ074
    -- (not-found / forbidden), nothing mutated.
    SELECT m.received_at,
           (SELECT t.name
              FROM message_tags mt
              JOIN tags t ON t.id = mt.tag_id
             WHERE mt.message_id  = m.id
               AND mt.received_at = m.received_at
               AND t.mailbox_id   = p_mailbox_id
               AND t.exclusive_group = 'location'
             LIMIT 1)
      INTO v_received_at, v_original_tag
      FROM messages m
     WHERE m.id         = p_message_id
       AND m.mailbox_id = p_mailbox_id;

    IF v_received_at IS NULL THEN
        RAISE EXCEPTION 'message % not found in mailbox %', p_message_id, p_mailbox_id
          USING ERRCODE = 'BZ074',
                HINT = jsonb_build_object('type', 'quarantine_message_not_found',
                                          'message_id', p_message_id,
                                          'mailbox_id', p_mailbox_id)::TEXT;
    END IF;

    -- Record the real original location; only fall back to 'Inbox' when the
    -- message carries no location tag at all (column is NOT NULL).
    v_original_tag := COALESCE(v_original_tag, 'Inbox');

    -- Remove the message's location-group tag(s) for this mailbox (it leaves
    -- Inbox/wherever). Counter triggers (trg_message_tags_counters) maintain
    -- tags.total_count / unread_count on the DELETE.
    DELETE FROM message_tags mt
    USING tags t
    WHERE mt.message_id  = p_message_id
      AND mt.received_at = v_received_at
      AND mt.tag_id      = t.id
      AND t.mailbox_id   = p_mailbox_id
      AND t.exclusive_group = 'location';

    -- Add the Quarantined (quarantine-group) tag as the primary tag. tag_message
    -- resolves it in p_mailbox_id again (R3) and the BEFORE INSERT exclusive
    -- trigger keeps the quarantine group singular.
    PERFORM tag_message(p_message_id, v_received_at, 'Quarantined', p_mailbox_id, 'system', TRUE);

    -- One audit row, with the REAL original location.
    INSERT INTO quarantined_messages
        (message_id, mailbox_id, original_tag, reason, reason_type, virus_name)
    VALUES
        (p_message_id, p_mailbox_id, v_original_tag, p_reason, p_reason_type, p_virus_name);

    -- The tag membership changed → push the change through the single owner so the
    -- webmail learns of the quarantine immediately (the named fix). Suppressible
    -- via p_notify = FALSE for strict behavior-preservation.
    IF p_notify THEN
        PERFORM notify_state_change(p_mailbox_id, v_quar_tag_id);
    END IF;
END;
$$ LANGUAGE plpgsql;
