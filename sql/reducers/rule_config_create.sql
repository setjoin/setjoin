-- rule_config_create.sql — mail-rule configuration create (WP3: the write
-- moved out of internal/user/rules.go's raw INSERT into the one-reducer-per-file
-- home so configuration changes carry an admin_audit_log row; rule EXECUTION
-- stays in rule_engine.sql and remains EXEMPT — per-message traffic is never
-- audited).
--
-- Containment mirrors the handler's shape: transport rules have no mailbox
-- (p_mailbox_id IS NULL); a non-transport rule must name an existing mailbox.
-- The /admin/rules route gates the admin identity; the audit row records the
-- authenticated actor.

CREATE OR REPLACE FUNCTION rule_config_create(
    p_actor         BIGINT,
    p_mailbox_id    BIGINT,
    p_name          TEXT,
    p_enabled       BOOLEAN,
    p_priority      INT,
    p_run_on        TEXT,
    p_is_transport  BOOLEAN,
    p_conditions    JSONB,
    p_actions       JSONB,
    p_stop          BOOLEAN
) RETURNS BIGINT AS $$
DECLARE
    v_id BIGINT;
BEGIN
    IF NULLIF(btrim(COALESCE(p_name, '')), '') IS NULL THEN
        RAISE EXCEPTION 'rule name required'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"name required"}';
    END IF;
    IF p_mailbox_id IS NULL AND NOT COALESCE(p_is_transport, FALSE) THEN
        RAISE EXCEPTION 'mailbox_id required for non-transport rules'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments"}';
    END IF;
    IF p_mailbox_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM mailboxes WHERE id = p_mailbox_id
    ) THEN
        RAISE EXCEPTION 'mailbox not found'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"mailbox not found"}';
    END IF;

    INSERT INTO rules (mailbox_id, name, enabled, priority, run_on, is_transport_rule,
                       conditions, actions, stop_processing)
    VALUES (p_mailbox_id, p_name, COALESCE(p_enabled, TRUE), COALESCE(p_priority, 0),
            COALESCE(NULLIF(p_run_on, ''), 'server'), COALESCE(p_is_transport, FALSE),
            p_conditions, p_actions, COALESCE(p_stop, FALSE))
    RETURNING id INTO v_id;

    -- WP3 audit coverage: rule configuration is governance authority (core).
    -- Minimal metadata only — never the full conditions/actions payloads.
    PERFORM audit_write(
        p_actor, 'rule_config_create', 'rule', v_id,
        NULL,
        jsonb_build_object('name', p_name,
                           'mailbox_id', p_mailbox_id,
                           'is_transport_rule', COALESCE(p_is_transport, FALSE),
                           'enabled', COALESCE(p_enabled, TRUE),
                           'priority', COALESCE(p_priority, 0)),
        NULL, NULL, 'core');

    RETURN v_id;
END;
$$ LANGUAGE plpgsql;
