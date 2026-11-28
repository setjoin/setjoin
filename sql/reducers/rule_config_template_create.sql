-- rule_config_template_create.sql — create a rule from a resolved template
-- (WP3: the INSERT moved out of internal/user/rules.go's createFromTemplate;
-- the template LOOKUP and placeholder resolution stay in Go — they are reads
-- plus string substitution — while the WRITE is reducer-owned and audited).
-- The mailbox is server-derived in Go via identity.ResolvePrimaryMailbox and
-- passed in; it is never request-owned (R2).

CREATE OR REPLACE FUNCTION rule_config_template_create(
    p_actor       BIGINT,
    p_mailbox_id  BIGINT,
    p_name        TEXT,
    p_conditions  JSONB,
    p_actions     JSONB
) RETURNS BIGINT AS $$
DECLARE
    v_id BIGINT;
BEGIN
    INSERT INTO rules (mailbox_id, name, enabled, priority, run_on, conditions, actions, stop_processing)
    VALUES (p_mailbox_id, p_name, TRUE, 0, 'server', p_conditions, p_actions, FALSE)
    RETURNING id INTO v_id;

    -- WP3 audit coverage: template instantiation writes a rule (core).
    PERFORM audit_write(
        p_actor, 'rule_config_template_create', 'rule', v_id,
        NULL,
        jsonb_build_object('name', p_name,
                           'mailbox_id', p_mailbox_id,
                           'source', 'template'),
        NULL, NULL, 'core');

    RETURN v_id;
END;
$$ LANGUAGE plpgsql;
