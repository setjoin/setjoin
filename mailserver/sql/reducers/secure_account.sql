-- Reducer: secure_account — "This wasn't me → secure account".
-- Atomically: flag the account for a forced password change, write a tamper-evident
-- admin_audit_log row attributing the actor, and emit an admin:alert notification.
-- Session/token revocation is composed by the Go caller in the same tx (Tasks 7, 9).
-- p_actor = the user (self-report) or an admin (admin force).
-- Raises BZ084 if p_user_id does not exist.
CREATE OR REPLACE FUNCTION secure_account(
    p_user_id bigint,
    p_actor   bigint,
    p_ip      inet,
    p_reason  text
) RETURNS jsonb AS $$
DECLARE
    v_email text;
BEGIN
    SELECT email INTO v_email FROM users WHERE id = p_user_id;
    IF v_email IS NULL THEN
        RAISE EXCEPTION 'secure_account: user % not found', p_user_id
            USING ERRCODE = 'BZ084';
    END IF;

    -- R3: UPDATE scopes to the validated user_id (same WHERE as the existence check).
    UPDATE users SET must_change_password = true WHERE id = p_user_id;

    -- Tamper-evident audit row; target_id is bigint per schema.
    PERFORM audit_write(p_actor, 'secure_account', 'user', p_user_id,
            NULL, NULL, p_ip, COALESCE(p_reason, ''), 'core');

    -- ponytail: route through app_notify (the single pg_notify choke point) so
    -- test-mode capture works and "did this reducer push?" is answerable in one place.
    PERFORM app_notify('admin:alert', jsonb_build_object(
        'kind',    'secure_account',
        'user_id', p_user_id,
        'actor',   p_actor,
        'reason',  p_reason,
        'at',      now()
    )::text);

    RETURN jsonb_build_object('secured', true, 'user_id', p_user_id);
END;
$$ LANGUAGE plpgsql VOLATILE;
