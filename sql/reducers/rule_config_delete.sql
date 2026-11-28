-- rule_config_delete.sql — mail-rule configuration delete (WP3: moved out of
-- internal/user/rules.go's raw DELETE; actor containment stays IN the mutation
-- (R3). Returns TRUE when a row was deleted, FALSE for "not found" (handler
-- maps to 404, preserving the API outcome).

CREATE OR REPLACE FUNCTION rule_config_delete(
    p_actor   BIGINT,
    p_rule_id BIGINT
) RETURNS BOOLEAN AS $$
DECLARE
    v_before jsonb;
BEGIN
    DELETE FROM rules
     WHERE id = p_rule_id
       AND mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = p_actor)
    RETURNING jsonb_build_object('name', name, 'mailbox_id', mailbox_id,
                                 'is_transport_rule', is_transport_rule)
      INTO v_before;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    -- WP3 audit coverage: configuration deletion (core).
    PERFORM audit_write(
        p_actor, 'rule_config_delete', 'rule', p_rule_id,
        v_before, NULL, NULL, NULL, 'core');

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;
