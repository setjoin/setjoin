-- Tag system utilities — loaded after tags table exists (see V005__tag_system.sql).

-- tag_message is defined in 030_message_tags.sql (schema version with FK + trigger integration)
-- (bump_tag_state + untag_message removed: dead code with no production caller.
-- bump_tag_state directly bumped tags.jmap_state, which notify_state_change documents
-- as owned EXCLUSIVELY by the message_tags counter trigger — wiring it would double-bump
-- and corrupt the sync token. untag_message had no caller. Location moves go through
-- set_message_location / transition_message_location.)

-- Get the tag ID for a named tag in a mailbox.
CREATE OR REPLACE FUNCTION get_tag_id(p_tag_name TEXT, p_mailbox_id BIGINT) RETURNS BIGINT AS $$
    SELECT id FROM tags WHERE mailbox_id = p_mailbox_id AND name = p_tag_name;
$$ LANGUAGE sql STABLE;

-- Increment a mailbox's JMAP tag state token and return new value.
CREATE OR REPLACE FUNCTION bump_tag_mailbox_state(p_mailbox_id BIGINT) RETURNS BIGINT AS $$
DECLARE
    v_state BIGINT;
BEGIN
    UPDATE mailboxes SET jmap_tag_state = jmap_tag_state + 1
    WHERE id = p_mailbox_id
    RETURNING jmap_tag_state INTO v_state;
    RETURN v_state;
END;
$$ LANGUAGE plpgsql;

-- Replace message location: remove all location-group tags,
-- add the specified tag as the new location.
CREATE OR REPLACE FUNCTION set_message_location(
    p_message_id    BIGINT,
    p_received_at   TIMESTAMPTZ,
    p_tag_name      TEXT,
    p_mailbox_id    BIGINT,
    p_added_by      TEXT DEFAULT 'user'
) RETURNS VOID AS $$
BEGIN
    -- Remove all existing location tags
    DELETE FROM message_tags mt
    USING tags t
    WHERE mt.message_id = p_message_id
      AND mt.received_at = p_received_at
      AND mt.tag_id = t.id
      AND t.mailbox_id = p_mailbox_id
      AND t.exclusive_group = 'location';

    -- Add the new location tag
    PERFORM tag_message(p_message_id, p_received_at, p_tag_name, p_mailbox_id, p_added_by, TRUE);
END;
$$ LANGUAGE plpgsql;

-- Next IMAP UID for a tag (replaces next_imap_uid for folders).
CREATE OR REPLACE FUNCTION next_imap_uid_for_tag(p_tag_id BIGINT) RETURNS BIGINT AS $$
DECLARE
    v_uid BIGINT;
BEGIN
    UPDATE tags SET imap_uid_next = imap_uid_next + 1
    WHERE id = p_tag_id
    RETURNING imap_uid_next - 1 INTO v_uid;
    RETURN v_uid;
END;
$$ LANGUAGE plpgsql;
