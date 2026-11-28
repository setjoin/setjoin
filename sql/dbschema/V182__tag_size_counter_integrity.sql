-- Keep live tag byte counters in the same transaction as tag membership.
-- V001's trigger maintained total/unread counts but omitted size_bytes, so every
-- new message caused startup_recovery() to repair counters on the next boot.
CREATE OR REPLACE FUNCTION public.trg_message_tags_counters() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_is_read    BOOL;
    v_size_bytes BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT is_read, size_bytes INTO v_is_read, v_size_bytes
        FROM messages
        WHERE id = NEW.message_id AND received_at = NEW.received_at;

        UPDATE tags SET
            total_count  = total_count + 1,
            unread_count = unread_count + CASE WHEN v_is_read THEN 0 ELSE 1 END,
            size_bytes   = size_bytes + COALESCE(v_size_bytes, 0),
            jmap_state   = jmap_state + 1
        WHERE id = NEW.tag_id;

    ELSIF TG_OP = 'DELETE' THEN
        SELECT is_read, size_bytes INTO v_is_read, v_size_bytes
        FROM messages
        WHERE id = OLD.message_id AND received_at = OLD.received_at;

        UPDATE tags SET
            total_count  = GREATEST(0, total_count - 1),
            unread_count = GREATEST(0, unread_count - CASE WHEN v_is_read THEN 0 ELSE 1 END),
            size_bytes   = GREATEST(0, size_bytes - COALESCE(v_size_bytes, 0)),
            jmap_state   = jmap_state + 1
        WHERE id = OLD.tag_id;
    END IF;

    RETURN NULL;
END;
$$;

-- A message-row DELETE can cascade into message_tags only after the parent row
-- is no longer visible to the message_tags AFTER DELETE trigger. Subtract tag
-- bytes while OLD is still available; explicit tag removals continue to use
-- trg_message_tags_counters above. If a caller removed memberships first, this
-- update sees none and cannot double-decrement.
CREATE OR REPLACE FUNCTION public.trg_messages_tag_size_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE tags t
    SET size_bytes = GREATEST(0, t.size_bytes - OLD.size_bytes)
    FROM message_tags mt
    WHERE mt.message_id = OLD.id
      AND mt.received_at = OLD.received_at
      AND t.id = mt.tag_id;
    RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS messages_tag_size_delete ON public.messages;
CREATE TRIGGER messages_tag_size_delete
    BEFORE DELETE ON public.messages
    FOR EACH ROW EXECUTE FUNCTION public.trg_messages_tag_size_delete();

-- Repair existing drift, including tags that currently have no messages.
UPDATE tags t
SET total_count = r.total_count,
    unread_count = r.unread_count,
    size_bytes = r.size_bytes
FROM (
    SELECT t0.id,
           COUNT(m.id) FILTER (WHERE NOT m.is_deleted) AS total_count,
           COUNT(m.id) FILTER (WHERE NOT m.is_deleted AND NOT m.is_read) AS unread_count,
           COALESCE(SUM(m.size_bytes) FILTER (WHERE NOT m.is_deleted), 0) AS size_bytes
    FROM tags t0
    LEFT JOIN message_tags mt ON mt.tag_id = t0.id
    LEFT JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
    GROUP BY t0.id
) r
WHERE r.id = t.id
  AND (t.total_count, t.unread_count, t.size_bytes)
      IS DISTINCT FROM (r.total_count, r.unread_count, r.size_bytes);

-- A mailbox quota counts message rows once, independent of how many labels a
-- message has. Do not derive it by summing per-tag counters.
UPDATE mailboxes mb
SET used_bytes = r.used_bytes
FROM (
    SELECT mb0.id,
           COALESCE(SUM(m.size_bytes) FILTER (WHERE NOT m.is_deleted), 0) AS used_bytes
    FROM mailboxes mb0
    LEFT JOIN messages m ON m.mailbox_id = mb0.id
    GROUP BY mb0.id
) r
WHERE r.id = mb.id
  AND mb.used_bytes IS DISTINCT FROM r.used_bytes;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (182, now())
  ON CONFLICT (version) DO NOTHING;
