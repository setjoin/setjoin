-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 032_rule_templates.sql: Admin-managed rule templates for users.
-- Templates provide one-click rule creation with pre-filled conditions and actions.
-- Parameters are user-filled at creation time (e.g. forward address, sender email).
-- Visibility can be controlled globally or per-user by admins.

-- Predefined rule templates with parameter placeholders.
CREATE TABLE rule_templates (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    category    TEXT NOT NULL DEFAULT 'general'
                    CHECK (category IN ('forwarding','organization','automation','security','general')),
    conditions  JSONB NOT NULL DEFAULT '[]',
    actions     JSONB NOT NULL DEFAULT '[]',
    parameters  JSONB NOT NULL DEFAULT '[]',
    -- e.g. [{"key":"forward_address","label":"Forward to","type":"email","required":true}]
    is_system   BOOL NOT NULL DEFAULT FALSE,
    enabled     BOOL NOT NULL DEFAULT TRUE,
    sort_order  INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX templates_category_idx ON rule_templates(category, enabled, sort_order);

-- Per-user visibility override. NULL user_id = global override.
CREATE TABLE rule_template_visibility (
    template_id BIGINT NOT NULL REFERENCES rule_templates(id) ON DELETE CASCADE,
    user_id     BIGINT REFERENCES users(id) ON DELETE CASCADE,
    hidden      BOOL NOT NULL DEFAULT FALSE,
    PRIMARY KEY (template_id, COALESCE(user_id, -1))
);

-- Seed built-in system templates.
INSERT INTO rule_templates (name, description, category, conditions, actions, parameters, is_system, sort_order)
VALUES
-- Forwarding templates (1-4)
('Auto-forward all mail',
 'Forward every incoming message to another email address.',
 'forwarding',
 '[]'::JSONB,
 '[{"type":"forward_to"}]'::JSONB,
 '[{"key":"address","label":"Forward to","type":"email","required":true}]'::JSONB,
 TRUE, 1),

('Forward non-spam only',
 'Forward incoming mail, but skip messages marked as spam.',
 'forwarding',
 '[{"field":"spam_score","op":"lt","value":"5.0"}]'::JSONB,
 '[{"type":"forward_to"}]'::JSONB,
 '[{"key":"address","label":"Forward to","type":"email","required":true}]'::JSONB,
 TRUE, 2),

('Forward & keep copy',
 'Forward a copy and keep the original in your Inbox.',
 'forwarding',
 '[]'::JSONB,
 '[{"type":"forward_to"},{"type":"categorize","params":{"category":"Forwarded"}}]'::JSONB,
 '[{"key":"address","label":"Forward to","type":"email","required":true}]'::JSONB,
 TRUE, 3),

('Forward only (skip inbox)',
 'Forward all mail and do not keep a local copy.',
 'forwarding',
 '[]'::JSONB,
 '[{"type":"forward_to"},{"type":"discard"}]'::JSONB,
 '[{"key":"address","label":"Forward to","type":"email","required":true}]'::JSONB,
 TRUE, 4),

-- Automation templates (5)
('Smart Mute',
 'When a muted conversation gets new replies, skip your Inbox unless you are in the To or Cc line.',
 'automation',
 '[]'::JSONB,
 '[{"type":"mute_thread"}]'::JSONB,
 '[]'::JSONB,
 TRUE, 5),

-- Organization templates (6-8)
('Auto-archive from sender',
 'Automatically archive messages from a specific sender.',
 'organization',
 '[{"field":"from_addr","op":"eq"}]'::JSONB,
 '[{"type":"move_to","params":{"role":"archive"}}]'::JSONB,
 '[{"key":"sender","label":"Sender email","type":"email","required":true}]'::JSONB,
 TRUE, 6),

('Auto-label by sender',
 'Apply a label to all messages from a specific sender.',
 'organization',
 '[{"field":"from_addr","op":"eq"}]'::JSONB,
 '[{"type":"categorize"}]'::JSONB,
 '[{"key":"sender","label":"Sender email","type":"email","required":true},{"key":"label","label":"Label name","type":"text","required":true}]'::JSONB,
 TRUE, 7),

('Move to Trash from sender',
 'Move all messages from a specific sender directly to Trash.',
 'organization',
 '[{"field":"from_addr","op":"eq"}]'::JSONB,
 '[{"type":"move_to","params":{"role":"trash"}}]'::JSONB,
 '[{"key":"sender","label":"Sender email","type":"email","required":true}]'::JSONB,
 TRUE, 8),

-- Security template (9)
('Auto-delete spam',
 'Automatically discard messages with a high spam score.',
 'security',
 '[{"field":"spam_score","op":"gte","value":"7.0"}]'::JSONB,
 '[{"type":"discard"}]'::JSONB,
 '[]'::JSONB,
 TRUE, 9),

-- General template (10)
('Mark newsletters as read',
 'Mark all mail containing certain keywords as read and label them.',
 'general',
 '[{"field":"subject","op":"contains"}]'::JSONB,
 '[{"type":"mark_read"},{"type":"categorize"}]'::JSONB,
 '[{"key":"keyword","label":"Subject contains","type":"text","required":true},{"key":"label","label":"Label name","type":"text","required":true}]'::JSONB,
 TRUE, 10);
