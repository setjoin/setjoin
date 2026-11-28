-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 050_spam_model.sql — Per-user spam classifier model storage.
-- Depends on: 001_users.sql (users table), 019_tags.sql (tags table), 030_message_tags.sql
--
-- Each row holds the serialized FTRL weight table for one user.
-- The pg_notify trigger on message_tags emits events to the Go trainer
-- when messages are moved to/from the Spam tag by the user.

CREATE TABLE user_spam_model (
    user_id     BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    model_bytes BYTEA NOT NULL,
    trained_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    sample_count INTEGER NOT NULL DEFAULT 0
);

-- Per-user opt-out: if disabled=TRUE, FTRL scoring is skipped for that user.
ALTER TABLE user_spam_model ADD COLUMN IF NOT EXISTS disabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Accuracy tracking: false positive = Junk→Inbox rescue (model was wrong).
-- False negative = Inbox→Junk correction (model missed it).
ALTER TABLE user_spam_model ADD COLUMN IF NOT EXISTS fp_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE user_spam_model ADD COLUMN IF NOT EXISTS fn_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE user_spam_model ADD COLUMN IF NOT EXISTS classified_count BIGINT NOT NULL DEFAULT 0;

-- Trigger: when a message is moved to or from Spam, emit a training event.
-- The Go NOTIFY listener collects and batches these events.
CREATE OR REPLACE FUNCTION spam_train_notify() RETURNS TRIGGER AS $$
DECLARE
    v_is_spam BOOLEAN;
    v_user_id BIGINT;
    v_message_id BIGINT;
BEGIN
    -- Determine if this is a Spam tag (INSERT) or removal from Spam (DELETE).
    IF TG_OP = 'INSERT' THEN
        v_message_id := NEW.message_id;
        -- Check if the tag being added is the Spam system tag.
        SELECT EXISTS (
            SELECT 1 FROM tags WHERE id = NEW.tag_id
              AND name = 'Spam' AND tag_type = 'system' AND exclusive_group = 'location'
        ) INTO v_is_spam;
        IF NOT v_is_spam THEN
            RETURN NEW;
        END IF;
        -- Get user_id from the mailbox that owns this message.
        SELECT m.user_id INTO v_user_id
        FROM messages msg
        JOIN mailboxes m ON m.id = msg.mailbox_id
        WHERE msg.id = NEW.message_id;
    ELSIF TG_OP = 'DELETE' THEN
        v_message_id := OLD.message_id;
        -- Check if the tag being removed is the Spam system tag.
        SELECT EXISTS (
            SELECT 1 FROM tags WHERE id = OLD.tag_id
              AND name = 'Spam' AND tag_type = 'system' AND exclusive_group = 'location'
        ) INTO v_is_spam;
        IF NOT v_is_spam THEN
            RETURN OLD;
        END IF;
        SELECT m.user_id INTO v_user_id
        FROM messages msg
        JOIN mailboxes m ON m.id = msg.mailbox_id
        WHERE msg.id = OLD.message_id;
    END IF;

    IF v_is_spam AND v_user_id IS NOT NULL THEN
        PERFORM pg_notify('spam_train',
            json_build_object(
                'user_id', v_user_id,
                'message_id', v_message_id,
                'is_spam', (TG_OP = 'INSERT')
            )::text
        );
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS message_tags_spam_train ON message_tags;
CREATE TRIGGER message_tags_spam_train
    AFTER INSERT OR DELETE ON message_tags
    FOR EACH ROW EXECUTE FUNCTION spam_train_notify();

-- Feature toggle: per-user FTRL-Proximal spam classifier.
INSERT INTO feature_toggles (key, enabled, description) VALUES
('feature.ml_spam', TRUE, 'Per-user FTRL-Proximal spam classifier')
ON CONFLICT (key) DO NOTHING;
