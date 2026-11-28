-- #332 frozen password-change/reset transaction. Verified JWT identity supplies
-- p_user_id and p_email; credential/history proofs are rechecked under the fence.
-- Reset deliberately preserves Go's flag/history behavior (no redesign).
CREATE OR REPLACE FUNCTION rust_identity_password_write(
    p_user_id bigint, p_email text, p_old_hash text, p_history jsonb,
    p_new_hash text, p_history_depth integer, p_reset boolean
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
    v_target bigint;
    v_hash text;
    v_history jsonb;
    v_phase text:='fence';
BEGIN
    BEGIN
        PERFORM identity_auth_local_mint_fence(p_user_id);
        v_phase:='write';
        IF NOT p_reset THEN
            -- Owner-approved security fix 2026-11-05 (#490): the credential row is
            -- keyed on the verified JWT uid (like history and revocation), never
            -- on the signed email, which can be stale or address another row.
            SELECT id,password_hash INTO v_target,v_hash FROM users WHERE id=p_user_id FOR UPDATE;
            IF NOT FOUND OR v_hash<>p_old_hash THEN RETURN jsonb_build_object('status','invalid-current'); END IF;
            SELECT COALESCE(jsonb_agg(password_hash),'[]') INTO v_history
              FROM (SELECT password_hash FROM password_history WHERE user_id=p_user_id ORDER BY created_at DESC LIMIT p_history_depth) h;
            IF v_history<>p_history THEN RETURN jsonb_build_object('status','retry'); END IF;
            UPDATE users SET password_hash=p_new_hash,must_change_password=false WHERE id=v_target;
            IF NOT FOUND THEN RETURN jsonb_build_object('status','internal'); END IF;
            -- Ignored history errors abort Go's tx, then surface as revocation failure.
            v_phase:='revoke';
            INSERT INTO password_history(user_id,password_hash) VALUES(p_user_id,p_new_hash);
            DELETE FROM password_history WHERE user_id=p_user_id AND id NOT IN
                (SELECT id FROM password_history WHERE user_id=p_user_id ORDER BY created_at DESC LIMIT p_history_depth);
        ELSE
            UPDATE users SET password_hash=p_new_hash WHERE id=p_user_id;
        END IF;
        v_phase:='revoke';
        PERFORM revoke_user_sessions(p_user_id,'all','credential_change',NULL,NULL,NULL);
        IF NULLIF(current_setting('app.rust_operation_id',true),'') IS NOT NULL THEN
            INSERT INTO rust_operation_receipts(operation_id,family,command)
            VALUES(current_setting('app.rust_operation_id')::uuid,'F21',CASE WHEN p_reset THEN 'password-reset' ELSE 'password-change' END);
        END IF;
        RETURN jsonb_build_object('status','ok');
    EXCEPTION WHEN OTHERS THEN
        -- The exception subtransaction rolls back EVERY credential/revocation effect.
        RETURN jsonb_build_object('status',CASE v_phase WHEN 'fence' THEN 'fence-failed' WHEN 'revoke' THEN 'revoke-failed' ELSE 'internal' END);
    END;
END;
$$;
