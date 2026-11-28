-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V007: Add Outlook-style compose features

-- 1. Add compose metadata columns to messages
ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS priority INT NOT NULL DEFAULT 0
        CHECK (priority IN (-1, 0, 1)),
    ADD COLUMN IF NOT EXISTS sensitivity TEXT
        CHECK (sensitivity IN ('normal', 'personal', 'private', 'confidential')),
    ADD COLUMN IF NOT EXISTS read_receipt_requested BOOL NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS delivery_receipt_requested BOOL NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS vote_options JSONB,
    ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMPTZ;

-- 2. Email templates per mailbox
CREATE TABLE IF NOT EXISTS email_templates (
    id              BIGSERIAL   PRIMARY KEY,
    mailbox_id      BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    subject         TEXT,
    body_text       TEXT,
    body_html       TEXT,
    is_default      BOOL        NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (mailbox_id, name)
);

-- 3. Signatures per mailbox
CREATE TABLE IF NOT EXISTS signatures (
    id              BIGSERIAL   PRIMARY KEY,
    mailbox_id      BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    body_text       TEXT,
    body_html       TEXT,
    is_default      BOOL        NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (mailbox_id, name)
);

-- 4. Vote responses (for voting buttons)
CREATE TABLE IF NOT EXISTS vote_responses (
    id              BIGSERIAL   PRIMARY KEY,
    message_id      BIGINT      NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL,
    voter_email     TEXT        NOT NULL,
    vote_option     TEXT        NOT NULL,
    voted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (message_id, received_at, voter_email)
);

-- 5. Read receipt tracking
CREATE TABLE IF NOT EXISTS read_receipts (
    id              BIGSERIAL   PRIMARY KEY,
    message_id      BIGINT      NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL,
    recipient_email TEXT        NOT NULL,
    read_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_agent      TEXT,
    ip_address      TEXT,
    UNIQUE (message_id, received_at, recipient_email)
);

-- 6. Mailbox delegates lookup helper (for send-as selector)
CREATE OR REPLACE FUNCTION get_mailbox_delegates(p_mailbox_id BIGINT)
RETURNS JSONB AS $$
DECLARE
    v_result JSONB := '[]'::JSONB;
    v_row RECORD;
BEGIN
    FOR v_row IN
        SELECT mb.id, mb.email, u.display_name
        FROM mailboxes mb
        JOIN users u ON u.id = mb.user_id
        WHERE mb.id = p_mailbox_id
        UNION
        SELECT mb.id, mb.email, u.display_name
        FROM mailbox_delegates md
        JOIN mailboxes mb ON mb.id = md.mailbox_id
        JOIN users u ON u.id = mb.user_id
        WHERE md.mailbox_id = p_mailbox_id
          AND md.permission IN ('send_as', 'send_on_behalf', 'full_access')
    LOOP
        v_result := v_result || jsonb_build_object(
            'id', v_row.id::TEXT,
            'email', v_row.email,
            'name', v_row.display_name
        );
    END LOOP;
    RETURN v_result;
END;
$$ LANGUAGE plpgsql;
