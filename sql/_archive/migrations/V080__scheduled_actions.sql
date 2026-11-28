-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V080__scheduled_actions.sql
-- A6 — Scheduled Actions infrastructure (foundation piece "scheduled_actions_core").
--
-- One deferred-action infrastructure replacing the scattered per-kind "timer"
-- reducers (snooze on message_tags, scheduled-send / undo-send in
-- jmap_email_submission + message_lifecycle.process_message_timers) and the
-- never-firing calendar-VALARM / task-reminder scan.
--
-- Ships (Tasks 1 + 6 — one migration per the program-index reconciliation):
--   1. scheduled_actions + scheduled_action_log tables; the fire_at WHERE
--      status='pending' due-scan index; the partial-UNIQUE dedup_key index; the
--      reclaim index; the reminders ledger + mailboxes.jmap_reminder_state; the
--      outbound_queue_hot.dedup_key egress-idempotency column.
--   6. backfill_scheduled_actions() one-shot migrating legacy snooze/scheduled
--      message_tags rows into scheduled_actions, then dropping the V025
--      tags.timer_type side-channel.
--
-- See docs/superpowers/specs/2026-06-16-scheduled-actions-design.md.

\i ../schema/053_scheduled_actions.sql

-- ── Task 6: backfill legacy timers + drop the tags.timer_type side-channel ──

-- backfill_scheduled_actions(): one-shot migration of pre-A6 timer state into
-- scheduled_actions. For every message_tags row that carries a future snooze_until
-- (→ a `snooze` action) or scheduled_at (→ a `send` action) with NO corresponding
-- scheduled_action yet, insert the matching action. Self-contained (no reducer
-- dependency) so it is safe to call inside the migration body, before reducers
-- load. Idempotent via the per-message NOT EXISTS guard.
CREATE OR REPLACE FUNCTION backfill_scheduled_actions() RETURNS INT AS $$
DECLARE
    v_rec   RECORD;
    v_count INT := 0;
    v_id    UUID;
BEGIN
    -- Legacy snoozes.
    FOR v_rec IN
        SELECT mt.message_id, mt.received_at, mt.snooze_until, t.mailbox_id
        FROM message_tags mt
        JOIN tags t ON t.id = mt.tag_id
        WHERE t.exclusive_group = 'snooze' AND t.name = 'Snoozed'
          AND mt.snooze_until IS NOT NULL AND mt.snooze_until > now()
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM scheduled_actions
            WHERE action_kind = 'snooze' AND mailbox_id = v_rec.mailbox_id
              AND payload @> jsonb_build_object('message_id', v_rec.message_id)
        ) THEN
            INSERT INTO scheduled_actions (action_kind, fire_at, payload, mailbox_id)
            VALUES ('snooze', v_rec.snooze_until,
                    jsonb_build_object('message_id', v_rec.message_id, 'received_at', v_rec.received_at),
                    v_rec.mailbox_id);
            v_count := v_count + 1;
        END IF;
    END LOOP;

    -- Legacy scheduled sends (Scheduled tag with a future scheduled_at).
    FOR v_rec IN
        SELECT mt.message_id, mt.received_at, mt.scheduled_at, t.mailbox_id
        FROM message_tags mt
        JOIN tags t ON t.id = mt.tag_id
        WHERE t.name = 'Scheduled'
          AND mt.scheduled_at IS NOT NULL AND mt.scheduled_at > now()
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM scheduled_actions
            WHERE action_kind = 'send' AND mailbox_id = v_rec.mailbox_id
              AND payload @> jsonb_build_object('message_id', v_rec.message_id)
        ) THEN
            INSERT INTO scheduled_actions (action_kind, fire_at, payload, mailbox_id)
            VALUES ('send', v_rec.scheduled_at,
                    jsonb_build_object('message_id', v_rec.message_id, 'received_at', v_rec.received_at, 'undo', FALSE),
                    v_rec.mailbox_id)
            RETURNING id INTO v_id;
            -- Default the egress dedup_key to the action id (idempotency).
            UPDATE scheduled_actions SET dedup_key = v_id::TEXT WHERE id = v_id;
            v_count := v_count + 1;
        END IF;
    END LOOP;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

SELECT backfill_scheduled_actions();

-- Drop the V025 tags.timer_type side-channel — superseded by
-- scheduled_actions.action_kind. The two cron wrappers that read it
-- (process_snoozed_messages / process_scheduled_messages) and the unified
-- process_message_timers() are removed; firing is now the dispatcher + handlers.
DROP FUNCTION IF EXISTS process_message_timers();
DROP FUNCTION IF EXISTS process_snoozed_messages();
DROP FUNCTION IF EXISTS process_scheduled_messages();

-- create_system_tags no longer writes timer_type; redefine it without the column
-- before the column is dropped (the canonical schema/019_tags.sql mirrors this).
CREATE OR REPLACE FUNCTION create_system_tags(p_mailbox_id BIGINT) RETURNS VOID AS $$
DECLARE
    v_uid_validity BIGINT := EXTRACT(EPOCH FROM now())::BIGINT;
    v_type         TEXT;
    v_inbox_id     BIGINT;
BEGIN
    SELECT type INTO v_type FROM mailboxes WHERE id = p_mailbox_id;

    IF v_type = 'journal' THEN
        INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group, is_default, sort_order,
                          imap_uid_validity, imap_expose)
        VALUES (p_mailbox_id, 'Inbox', 'system', 'location', TRUE, 0, v_uid_validity, TRUE)
        ON CONFLICT (mailbox_id, name) DO NOTHING;
        RETURN;
    END IF;

    INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group, is_default,
                      icon, color, sort_order, imap_uid_validity, imap_expose, imap_name)
    VALUES
        (p_mailbox_id, 'Inbox',     'system', 'location', TRUE,
         'inbox',    '#7C8DB5', 0,  v_uid_validity, TRUE,  NULL)
    ON CONFLICT (mailbox_id, name) DO NOTHING
    RETURNING id INTO v_inbox_id;

    INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group,
                      icon, color, sort_order, imap_uid_validity, imap_expose, imap_name)
    VALUES
        (p_mailbox_id, 'Sent',      'system', 'location',
         'send',     '#5CB85C', 10, v_uid_validity, TRUE,  NULL),
        (p_mailbox_id, 'Drafts',    'system', 'location',
         'edit',     '#F0AD4E', 20, v_uid_validity, TRUE,  NULL),
        (p_mailbox_id, 'Trash',     'system', 'location',
         'delete',   '#D9534F', 30, v_uid_validity, TRUE,  '[Gmail]/Trash'),
        (p_mailbox_id, 'Spam',      'system', 'location',
         'warning',  '#D9534F', 40, v_uid_validity, TRUE,  '[Gmail]/Spam'),
        (p_mailbox_id, 'Starred',   'system', NULL,
         'star',     '#F5A623', 50, v_uid_validity, TRUE,  NULL),
        (p_mailbox_id, 'Snoozed',   'system', 'snooze',
         'clock',    '#9B59B6', 60, v_uid_validity, FALSE, NULL),
        (p_mailbox_id, 'Scheduled', 'system', 'snooze',
         'calendar', '#3498DB', 70, v_uid_validity, TRUE,  '[Gmail]/Scheduled'),
        (p_mailbox_id, 'Important', 'system', NULL,
         'priority', '#E74C3C', 80, v_uid_validity, FALSE, NULL),
        (p_mailbox_id, 'Muted',     'system', NULL,
         'volume_off', '#888888', 90, v_uid_validity, FALSE, NULL)
    ON CONFLICT (mailbox_id, name) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

ALTER TABLE tags DROP CONSTRAINT IF EXISTS tags_timer_type_check;
ALTER TABLE tags DROP CONSTRAINT IF EXISTS tags_timer_check;   -- V025 named constraint
ALTER TABLE tags DROP COLUMN IF EXISTS timer_type;
