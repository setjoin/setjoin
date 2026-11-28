-- #336: fixed recovery window; worker-only accessors retain shared row authority.
CREATE OR REPLACE FUNCTION rust_identity_recovery_budget(p_user_id bigint)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_row record; v_now timestamptz; v_first boolean:=FALSE;
BEGIN
    SELECT * INTO STRICT v_row FROM recovery_budget_acquire(p_user_id);
    v_now:=clock_timestamp();
    IF v_row.window_until<=v_now THEN
        PERFORM recovery_budget_record(p_user_id,1,v_now+interval '15 minutes');
        RETURN jsonb_build_object('refused',FALSE,'first',FALSE);
    ELSIF v_row.attempt_count>=30 THEN
        v_first:=v_row.attempt_count=30;
        PERFORM recovery_budget_record(p_user_id,v_row.attempt_count+1,v_row.window_until);
        RETURN jsonb_build_object('refused',TRUE,'first',v_first);
    ELSE
        PERFORM recovery_budget_record(p_user_id,v_row.attempt_count+1,v_row.window_until);
        RETURN jsonb_build_object('refused',FALSE,'first',FALSE);
    END IF;
END;
$$;
