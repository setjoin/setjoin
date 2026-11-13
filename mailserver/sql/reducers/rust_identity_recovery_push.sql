-- #336: worker-owned recovery lockout and challenge proof share one transaction.
CREATE OR REPLACE FUNCTION rust_identity_recovery_push_read(p_user_id bigint,p_nonce bytea)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_lock record;v_challenge push_mfa_challenges%ROWTYPE;v_locked boolean:=FALSE;
BEGIN
    SELECT * INTO STRICT v_lock FROM push_lockout_acquire(p_user_id);
    v_locked:=v_lock.locked_until>clock_timestamp();
    IF v_locked THEN
        PERFORM push_lockout_count_locked(p_user_id);
        RETURN jsonb_build_object('status','locked');
    END IF;
    SELECT * INTO v_challenge FROM push_mfa_challenges
        WHERE user_id=p_user_id AND nonce=p_nonce AND verified_at IS NULL
        AND expires_at>now() AND COALESCE(session_id,'')='forgot-password'
        ORDER BY created_at DESC LIMIT 1 FOR UPDATE;
    IF NOT FOUND THEN RETURN jsonb_build_object('status','invalid'); END IF;
    RETURN jsonb_build_object('status','ready','id',v_challenge.id,'code',v_challenge.challenge_code);
EXCEPTION WHEN OTHERS THEN
    -- The Go seam uniformly refuses infrastructure failures. A locked verdict
    -- remains locked even when its count-only bookkeeping rolls back.
    RETURN jsonb_build_object('status',CASE WHEN v_locked THEN 'locked' ELSE 'invalid' END);
END;
$$;

CREATE OR REPLACE FUNCTION rust_identity_recovery_push_finish(p_user_id bigint,p_id bigint,p_valid boolean)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_lock record;v_failed integer;v_count integer;v_now timestamptz:=clock_timestamp();
BEGIN
    SELECT * INTO STRICT v_lock FROM push_lockout_acquire(p_user_id);
    SELECT failed_attempts INTO v_failed FROM push_mfa_challenges
        WHERE id=p_id AND user_id=p_user_id AND verified_at IS NULL
        AND expires_at>now() AND COALESCE(session_id,'')='forgot-password' FOR UPDATE;
    IF NOT FOUND THEN RETURN 'invalid'; END IF;
    v_failed:=COALESCE(v_failed,0);
    IF v_failed<3 AND p_valid THEN
        UPDATE push_mfa_challenges SET verified_at=now() WHERE id=p_id AND user_id=p_user_id;
        PERFORM push_lockout_record(p_user_id,0,NULL);
        RETURN 'accepted';
    END IF;
    IF v_failed>=3 THEN
        UPDATE push_mfa_challenges SET verified_at=now() WHERE id=p_id AND user_id=p_user_id;
    ELSE
        UPDATE push_mfa_challenges SET failed_attempts=COALESCE(failed_attempts,0)+1
            WHERE id=p_id AND user_id=p_user_id;
    END IF;
    v_count:=CASE WHEN v_lock.updated_at<=v_now-interval '15 minutes' THEN 1 ELSE v_lock.failed_count+1 END;
    PERFORM push_lockout_record(p_user_id,v_count,CASE WHEN v_count>=5 THEN v_now+interval '15 minutes' ELSE NULL END);
    RETURN 'invalid';
END;
$$;
