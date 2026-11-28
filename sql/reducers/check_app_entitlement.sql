-- check_app_entitlement.sql -- Mailbox-keyed compatibility wrapper (B8/G2).
CREATE OR REPLACE FUNCTION check_app_entitlement(
    p_mailbox_id BIGINT,
    p_app        TEXT
) RETURNS BOOLEAN AS $$
DECLARE
    v_user_id BIGINT;
BEGIN
    SELECT s.user_id INTO v_user_id FROM account_scope(p_mailbox_id) s;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    RETURN check_user_app_entitlement(v_user_id, p_app);
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public;
SELECT apply_worker_ownership('check_app_entitlement(bigint,text)'::regprocedure);
