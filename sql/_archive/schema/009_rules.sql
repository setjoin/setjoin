-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Rules: Outlook-style rules with server/client/both execution modes.
CREATE TABLE rules (
  id                  BIGSERIAL   PRIMARY KEY,
  user_id             BIGINT      REFERENCES users(id)     ON DELETE CASCADE,
  mailbox_id          BIGINT      REFERENCES mailboxes(id) ON DELETE CASCADE,
  name                TEXT        NOT NULL,
  enabled             BOOL        NOT NULL DEFAULT TRUE,
  priority            INT         NOT NULL DEFAULT 0 CHECK (priority BETWEEN 0 AND 100),  -- lower value = runs first
  run_on              TEXT        NOT NULL DEFAULT 'server'
                        CHECK (run_on IN ('server','client','both')),
  is_transport_rule   BOOL        NOT NULL DEFAULT FALSE,  -- admin-only; runs before user rules

  -- conditions: array of {field, op, value}
  -- fields: from_addr, to_addr, subject, body, size_bytes, has_attachments,
  --         sender_domain, category, spam_score, header_{name}
  -- ops:    contains, not_contains, equals, not_equals, gt, lt, matches_regex, in_list
  conditions          JSONB       NOT NULL DEFAULT '[]',

  -- actions: array of {type, params}
  -- server types: move_to, copy_to, forward_to, redirect_to, flag, categorize,
  --               mark_read, delete, discard, add_header, remove_header,
  --               set_spam_score, notify_admin, bcc_to
  -- client types: highlight_color, play_sound, desktop_notification, local_move
  actions             JSONB       NOT NULL DEFAULT '[]',

  stop_processing     BOOL        NOT NULL DEFAULT FALSE,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX rules_mailbox_idx   ON rules(mailbox_id, enabled, priority)
  WHERE mailbox_id IS NOT NULL;
CREATE INDEX rules_transport_idx ON rules(enabled, priority)
  WHERE is_transport_rule = TRUE;
CREATE INDEX rules_user_idx      ON rules(user_id)
  WHERE user_id IS NOT NULL;

ALTER TABLE rules ADD CONSTRAINT rules_conditions_check CHECK (jsonb_typeof(conditions) IN ('array', 'object'));
ALTER TABLE rules ADD CONSTRAINT rules_actions_check CHECK (jsonb_typeof(actions) = 'array');

-- NOTIFY trigger for rule cache invalidation
CREATE OR REPLACE FUNCTION trg_rules_notify() RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    PERFORM pg_notify('rules_changed', json_build_object(
      'op', 'delete', 'mailbox_id', OLD.mailbox_id, 'rule_id', OLD.id)::text);
  ELSE
    PERFORM pg_notify('rules_changed', json_build_object(
      'op', lower(TG_OP), 'mailbox_id', NEW.mailbox_id, 'rule_id', NEW.id)::text);
  END IF;
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_rules_notify
  AFTER INSERT OR UPDATE OR DELETE ON rules
  FOR EACH ROW EXECUTE FUNCTION trg_rules_notify();
