-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Tasks: personal and assigned tasks, linked to emails and calendar events.
CREATE TABLE tasks (
  id                          BIGSERIAL   PRIMARY KEY,
  mailbox_id                  BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  parent_id                   BIGINT      REFERENCES tasks(id) ON DELETE CASCADE,
  title                       TEXT        NOT NULL,
  description                 TEXT,
  status                      TEXT        NOT NULL DEFAULT 'needs-action'
                                CHECK (status IN ('needs-action','in-progress','completed','cancelled')),
  priority                    INT         NOT NULL DEFAULT 0
                                CHECK (priority IN (0,1,2,3,4,5,6,7,8,9)),
  due_at                      TIMESTAMPTZ,
  reminder_at                 TIMESTAMPTZ,
  completed_at                TIMESTAMPTZ,
  assignee_user_id            BIGINT      REFERENCES users(id) ON DELETE SET NULL,
  -- Link to originating email (optional)
  linked_message_id           BIGINT,
  linked_message_received_at  TIMESTAMPTZ,
  FOREIGN KEY (linked_message_id, linked_message_received_at) REFERENCES messages(id, received_at) ON DELETE SET NULL,
  -- Link to calendar event (optional)
  linked_event_id             BIGINT      REFERENCES calendar_events(id) ON DELETE SET NULL,
  categories                  TEXT[]      NOT NULL DEFAULT '{}',
  -- Recurrence (simplified — RFC 5545 RRULE)
  rrule                       TEXT,
  jmap_state                  BIGINT      NOT NULL DEFAULT 0,
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX tasks_mailbox_idx   ON tasks(mailbox_id, status);
CREATE INDEX tasks_assignee_idx  ON tasks(assignee_user_id) WHERE assignee_user_id IS NOT NULL;
CREATE INDEX tasks_due_idx       ON tasks(due_at)           WHERE due_at IS NOT NULL;
CREATE INDEX tasks_parent_idx    ON tasks(parent_id)        WHERE parent_id IS NOT NULL;
CREATE INDEX tasks_linked_msg_idx ON tasks(linked_message_id) WHERE linked_message_id IS NOT NULL;
CREATE INDEX tasks_linked_event_idx ON tasks(linked_event_id) WHERE linked_event_id IS NOT NULL;
