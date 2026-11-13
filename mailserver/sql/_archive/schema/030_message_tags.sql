-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 030_message_tags.sql: Junction table linking messages to tags.
-- Partitioned by received_at to match the messages table.
-- Exclusive group enforcement via BEFORE INSERT trigger.

CREATE TABLE IF NOT EXISTS message_tags (
    message_id      BIGINT      NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL,
    tag_id          BIGINT      NOT NULL REFERENCES tags(id) ON DELETE CASCADE,

    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by        TEXT,                       -- 'user','rule','deliver','send','snooze','schedule'

    -- Timer support
    snooze_until    TIMESTAMPTZ,                -- wake-up time for Snoozed tag
    scheduled_at    TIMESTAMPTZ,                -- when to send for Scheduled tag

    -- Primary tag (IMAP fallback, ordering)
    is_primary      BOOL        NOT NULL DEFAULT FALSE,

    PRIMARY KEY (message_id, received_at, tag_id),
    FOREIGN KEY (message_id, received_at)
        REFERENCES messages(id, received_at) ON DELETE CASCADE
) PARTITION BY RANGE (received_at);

-- Default catch-all partition (pg_cron creates future month partitions).
CREATE TABLE IF NOT EXISTS message_tags_default PARTITION OF message_tags DEFAULT;

-- Indexes
CREATE INDEX IF NOT EXISTS message_tags_tag_idx    ON message_tags(tag_id, received_at DESC);
CREATE INDEX IF NOT EXISTS message_tags_primary_idx ON message_tags(message_id, received_at) WHERE is_primary;
CREATE INDEX IF NOT EXISTS message_tags_snooze_idx  ON message_tags(snooze_until) WHERE snooze_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS message_tags_scheduled_idx ON message_tags(scheduled_at) WHERE scheduled_at IS NOT NULL;

-- ── Exclusive group enforcement trigger ──

CREATE OR REPLACE FUNCTION trg_message_tags_exclusive() RETURNS TRIGGER AS $$
DECLARE
    v_group TEXT;
BEGIN
    SELECT t.exclusive_group INTO v_group
    FROM tags t WHERE t.id = NEW.tag_id;

    IF v_group IS NOT NULL THEN
        DELETE FROM message_tags mt
        USING tags t
        WHERE mt.message_id = NEW.message_id
          AND mt.received_at = NEW.received_at
          AND mt.tag_id = t.id
          AND t.exclusive_group = v_group
          AND mt.tag_id != NEW.tag_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS message_tags_exclusive ON message_tags;
CREATE TRIGGER message_tags_exclusive
    BEFORE INSERT ON message_tags
    FOR EACH ROW EXECUTE FUNCTION trg_message_tags_exclusive();

-- ── Counter maintenance trigger ──

CREATE OR REPLACE FUNCTION trg_message_tags_counters() RETURNS TRIGGER AS $$
DECLARE
    v_is_read BOOL;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT is_read INTO v_is_read FROM messages
        WHERE id = NEW.message_id AND received_at = NEW.received_at;

        UPDATE tags SET
            total_count  = total_count + 1,
            unread_count = unread_count + CASE WHEN v_is_read THEN 0 ELSE 1 END,
            jmap_state   = jmap_state + 1
        WHERE id = NEW.tag_id;

    ELSIF TG_OP = 'DELETE' THEN
        SELECT is_read INTO v_is_read FROM messages
        WHERE id = OLD.message_id AND received_at = OLD.received_at;

        UPDATE tags SET
            total_count  = GREATEST(0, total_count - 1),
            unread_count = GREATEST(0, unread_count - CASE WHEN v_is_read THEN 0 ELSE 1 END),
            jmap_state   = jmap_state + 1
        WHERE id = OLD.tag_id;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS message_tags_counters_insert ON message_tags;
CREATE TRIGGER message_tags_counters_insert
    AFTER INSERT ON message_tags
    FOR EACH ROW EXECUTE FUNCTION trg_message_tags_counters();

DROP TRIGGER IF EXISTS message_tags_counters_delete ON message_tags;
CREATE TRIGGER message_tags_counters_delete
    AFTER DELETE ON message_tags
    FOR EACH ROW EXECUTE FUNCTION trg_message_tags_counters();

-- ── Primary tag sync trigger ──
-- When is_primary is set, update messages.folder_id to match.

CREATE OR REPLACE FUNCTION trg_message_tags_primary_sync() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.is_primary THEN
        UPDATE messages SET folder_id = NEW.tag_id
        WHERE id = NEW.message_id AND received_at = NEW.received_at;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS message_tags_primary_sync ON message_tags;
CREATE TRIGGER message_tags_primary_sync
    AFTER INSERT OR UPDATE OF is_primary ON message_tags
    FOR EACH ROW WHEN (NEW.is_primary = TRUE)
    EXECUTE FUNCTION trg_message_tags_primary_sync();

-- ── All Mail parameterized function ──
-- Returns all messages not in Trash or Spam for a given mailbox.

DROP VIEW IF EXISTS all_mail;
CREATE OR REPLACE FUNCTION all_mail(p_mailbox_id BIGINT)
RETURNS TABLE(id BIGINT, received_at TIMESTAMPTZ) AS $$
    SELECT DISTINCT m.id, m.received_at
    FROM messages m
    JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
    WHERE m.mailbox_id = p_mailbox_id
      AND NOT m.is_deleted
      AND NOT EXISTS (
        SELECT 1 FROM message_tags mt2
        JOIN tags t ON t.id = mt2.tag_id
        WHERE mt2.message_id = m.id
          AND mt2.received_at = m.received_at
          AND t.name IN ('Trash', 'Spam')
      );
$$ LANGUAGE sql STABLE;

-- ── Helper: add a tag to a message ──

CREATE OR REPLACE FUNCTION tag_message(
    p_message_id    BIGINT,
    p_received_at   TIMESTAMPTZ,
    p_tag_name      TEXT,
    p_mailbox_id    BIGINT,
    p_added_by      TEXT DEFAULT 'user',
    p_is_primary    BOOL DEFAULT FALSE,
    p_snooze_until  TIMESTAMPTZ DEFAULT NULL,
    p_scheduled_at  TIMESTAMPTZ DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
    v_tag_id BIGINT;
BEGIN
    SELECT id INTO v_tag_id FROM tags
    WHERE mailbox_id = p_mailbox_id AND name = p_tag_name;

    IF v_tag_id IS NULL THEN
        RAISE EXCEPTION 'Tag % not found in mailbox %', p_tag_name, p_mailbox_id
          USING ERRCODE = 'BZ019', HINT = jsonb_build_object('type', 'tag_not_found', 'tag_name', p_tag_name, 'mailbox_id', p_mailbox_id)::TEXT;
    END IF;

    INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary, snooze_until, scheduled_at)
    VALUES (p_message_id, p_received_at, v_tag_id, p_added_by, p_is_primary, p_snooze_until, p_scheduled_at);
END;
$$ LANGUAGE plpgsql;

-- ── Helper: remove a tag from a message ──

CREATE OR REPLACE FUNCTION untag_message(
    p_message_id    BIGINT,
    p_received_at   TIMESTAMPTZ,
    p_tag_name      TEXT,
    p_mailbox_id    BIGINT
) RETURNS VOID AS $$
DECLARE
    v_tag_id BIGINT;
BEGIN
    SELECT id INTO v_tag_id FROM tags
    WHERE mailbox_id = p_mailbox_id AND name = p_tag_name;

    IF v_tag_id IS NULL THEN
        RETURN;
    END IF;

    DELETE FROM message_tags
    WHERE message_id = p_message_id
      AND received_at = p_received_at
      AND tag_id = v_tag_id;
END;
$$ LANGUAGE plpgsql;
