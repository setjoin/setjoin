-- rule_config_update.sql — mail-rule configuration update (WP3: the write
-- moved out of internal/user/rules.go's raw UPDATE; the actor-containment
-- predicate stays IN the mutation (R3, no check-then-mutate). Execution stays
-- in rule_engine.sql, EXEMPT.
--
-- Returns TRUE when the row was found and updated, FALSE when the actor has no
-- such rule (the handler maps FALSE to 404, preserving the API outcome).

CREATE OR REPLACE FUNCTION rule_config_update(
    p_actor         BIGINT,
    p_rule_id       BIGINT,
    p_mailbox_id    BIGINT,
    p_name          TEXT,
    p_enabled       BOOLEAN,
    p_priority      INT,
    p_run_on        TEXT,
    p_is_transport  BOOLEAN,
    p_conditions    JSONB,
    p_actions       JSONB,
    p_stop          BOOLEAN
) RETURNS BOOLEAN AS $$
DECLARE
    v_before jsonb;
BEGIN
    SELECT jsonb_build_object('name', name, 'mailbox_id', mailbox_id,
                              'is_transport_rule', is_transport_rule,
                              'enabled', enabled, 'priority', priority)
      INTO v_before
      FROM rules WHERE id = p_rule_id;

    UPDATE rules SET
        mailbox_id = COALESCE(p_mailbox_id, mailbox_id),
        name = COALESCE(NULLIF(p_name,''), name),
        enabled = COALESCE(p_enabled, enabled),
        priority = COALESCE(p_priority, priority),
        run_on = COALESCE(NULLIF(p_run_on,''), run_on),
        is_transport_rule = COALESCE(p_is_transport, is_transport_rule),
        conditions = COALESCE(p_conditions, conditions),
        actions = COALESCE(p_actions, actions),
        stop_processing = COALESCE(p_stop, stop_processing),
        updated_at = now()
    WHERE id = p_rule_id
      AND mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = p_actor);

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    -- WP3 audit coverage: configuration change on an owned rule (core).
    PERFORM audit_write(
        p_actor, 'rule_config_update', 'rule', p_rule_id,
        v_before,
        jsonb_build_object('name', COALESCE(NULLIF(p_name,''), v_before->>'name'),
                           'mailbox_id', COALESCE(p_mailbox_id, NULLIF(v_before->>'mailbox_id','null')::bigint),
                           'is_transport_rule', COALESCE(p_is_transport, (v_before->>'is_transport_rule')::boolean),
                           'enabled', COALESCE(p_enabled, (v_before->>'enabled')::boolean),
                           'priority', COALESCE(p_priority, (v_before->>'priority')::int)),
        NULL, NULL, 'core');

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;
