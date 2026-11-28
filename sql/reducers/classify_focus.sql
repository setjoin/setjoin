-- classify_focus.sql: deterministic Focused/Other inbox classifier (NOT ML).
--
-- Returns TRUE = "Other" (deprioritized), FALSE = "Focused". First match wins:
--   1. per-sender override (focus_sender_overrides) → NOT its `focused` flag
--   2. sender in the mailbox owner's contacts → Focused
--   3. internal sender (local mailbox or local domain) → Focused
--   4. mailing-list / bulk mail (List-Id present) → Other
--   5. cold first contact (first-time AND external) → Other
--   6. else → Focused
--
-- Called from deliver() in the Inbox arm. Read-only (STABLE). The contacts
-- predicate mirrors deliver_group_vacation.sql's external_audience='contacts'
-- gate; the internal-sender predicate mirrors its v_sender_is_internal logic.
CREATE OR REPLACE FUNCTION classify_focus(
    p_mailbox_id    BIGINT,
    p_from_addr     TEXT,
    p_is_external   BOOL DEFAULT FALSE,
    p_is_first_time BOOL DEFAULT TRUE,
    p_list_id       TEXT DEFAULT NULL
) RETURNS BOOL AS $$
DECLARE
    v_user_id  BIGINT;
    v_override BOOL;
    v_domain   TEXT;
BEGIN
    -- Rule 1: per-sender override, keyed on the user behind the mailbox.
    SELECT user_id INTO v_user_id FROM account_scope(p_mailbox_id);
    IF v_user_id IS NOT NULL THEN
        SELECT focused INTO v_override
        FROM focus_sender_overrides
        WHERE user_id = v_user_id AND sender = lower(p_from_addr);
        IF FOUND THEN
            RETURN NOT v_override;
        END IF;
    END IF;

    -- Rule 2: sender in the mailbox owner's contacts → Focused.
    IF EXISTS (
        SELECT 1 FROM contacts c
        JOIN addressbooks ab ON ab.id = c.addressbook_id
        WHERE ab.mailbox_id = p_mailbox_id
          AND EXISTS (
              SELECT 1 FROM jsonb_array_elements(c.emails) e
              WHERE lower(e->>'address') = lower(p_from_addr)
          )
    ) THEN
        RETURN FALSE;
    END IF;

    -- Rule 3: internal sender (local mailbox or local domain) → Focused.
    v_domain := split_part(lower(p_from_addr), '@', 2);
    IF EXISTS (SELECT 1 FROM mailboxes WHERE email = lower(p_from_addr))
       OR EXISTS (SELECT 1 FROM domains WHERE lower(name) = v_domain AND is_local) THEN
        RETURN FALSE;
    END IF;

    -- Rule 4: mailing-list / bulk mail → Other.
    IF p_list_id IS NOT NULL THEN
        RETURN TRUE;
    END IF;

    -- Rule 5: cold first contact (first-time external sender) → Other.
    IF COALESCE(p_is_first_time, TRUE) AND COALESCE(p_is_external, FALSE) THEN
        RETURN TRUE;
    END IF;

    -- Rule 6: default → Focused.
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE;
