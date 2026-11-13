-- V085: "a LIVE user keeps a primary mailbox" is a cross-row invariant — check
-- it at COMMIT for deletes, not per-statement.
--
-- The immediate AFTER DELETE check raised BZ013 in the middle of the admin
-- user-delete cascade (mailboxes go before the users row for FK reasons), so
-- DELETE /admin/users/{id} 500'd for EVERY user — admins could not delete
-- users at all. Deferred, the check still protects a live user from losing
-- their primary (nothing else in the tx removes the user row → raise at
-- commit), while a full teardown passes because the user row is gone by then.
--
-- INSERT/UPDATE keep the immediate trigger (statement-time feedback is right
-- for "set another primary first" UX); only the DELETE branch moves.

-- 1. Immediate trigger drops its DELETE arm.
DROP TRIGGER IF EXISTS mailbox_primary_enforce ON mailboxes;
CREATE TRIGGER mailbox_primary_enforce
  AFTER INSERT OR UPDATE ON mailboxes
  FOR EACH ROW EXECUTE FUNCTION trg_mailbox_primary_enforce();

-- 2. Deferred commit-time check for deletes.
CREATE OR REPLACE FUNCTION trg_mailbox_primary_enforce_delete() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.user_id IS NOT NULL AND OLD.is_primary THEN
    -- At commit: a still-existing user must still have a primary mailbox.
    IF EXISTS (SELECT 1 FROM users WHERE id = OLD.user_id)
       AND NOT EXISTS (SELECT 1 FROM mailboxes WHERE user_id = OLD.user_id AND is_primary) THEN
      RAISE EXCEPTION 'User % must have at least one primary mailbox; reassign before deleting', OLD.user_id
        USING ERRCODE = 'BZ013', HINT = jsonb_build_object('type', 'must_set_primary', 'user_id', OLD.user_id)::TEXT;
    END IF;
  END IF;
  RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS mailbox_primary_enforce_delete ON mailboxes;
CREATE CONSTRAINT TRIGGER mailbox_primary_enforce_delete
  AFTER DELETE ON mailboxes
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION trg_mailbox_primary_enforce_delete();

INSERT INTO schema_migrations (version, applied_at) VALUES (85, now()) ON CONFLICT DO NOTHING;
