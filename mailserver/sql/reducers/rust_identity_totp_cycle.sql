-- #334: VerifyTOTPWithLockoutTx writes, under the read/crypto transaction fence.
DROP FUNCTION IF EXISTS rust_identity_totp_cycle(bigint,boolean);
CREATE OR REPLACE FUNCTION rust_identity_totp_cycle(p_user_id bigint,p_valid boolean,p_counter bigint,p_secret_hash bytea)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_locked timestamptz;v_used timestamptz;
BEGIN
    SELECT totp_locked_until,last_totp_used_at INTO v_locked,v_used FROM users WHERE id=p_user_id FOR NO KEY UPDATE;
    IF NOT FOUND THEN RETURN 'invalid'; END IF;
    IF v_locked>clock_timestamp() THEN RETURN 'locked'; END IF;
    -- SECURITY-COUNTER-BEGIN: owner-approved security fix 2026-11-05.
    IF p_valid AND (p_counter IS NULL OR p_counter<0 OR octet_length(p_secret_hash) IS DISTINCT FROM 32) THEN
        RAISE EXCEPTION 'verified TOTP counter binding missing' USING ERRCODE='22023';
    END IF;
    IF p_valid AND EXISTS(SELECT 1 FROM totp_counter_claims WHERE user_id=p_user_id
        AND secret_hash=p_secret_hash AND last_counter>=p_counter) THEN p_valid:=FALSE; END IF;
    IF p_valid AND v_used IS NOT NULL AND NOT EXISTS(SELECT 1 FROM totp_counter_claims WHERE user_id=p_user_id)
        AND p_counter<=floor(extract(epoch FROM v_used)/30)::bigint+1 THEN p_valid:=FALSE; END IF;
    -- SECURITY-COUNTER-END
    IF p_valid THEN
        UPDATE users SET last_totp_used_at=now() WHERE id=p_user_id
            AND (last_totp_used_at IS NULL OR last_totp_used_at<now()-interval '30 seconds');
        IF FOUND THEN
            -- SECURITY-COUNTER-BEGIN: claim and cycle commit together.
            INSERT INTO totp_counter_claims(user_id,secret_hash,last_counter) VALUES(p_user_id,p_secret_hash,p_counter)
                ON CONFLICT(user_id) DO UPDATE SET secret_hash=EXCLUDED.secret_hash,last_counter=EXCLUDED.last_counter
                WHERE totp_counter_claims.user_id=p_user_id;
            -- SECURITY-COUNTER-END
            UPDATE users SET totp_failed_attempts=0,totp_locked_until=NULL WHERE id=p_user_id;
            RETURN 'accepted';
        END IF;
    END IF;
    UPDATE users SET totp_failed_attempts=totp_failed_attempts+1,
        totp_locked_until=CASE WHEN totp_failed_attempts+1>=5 THEN now()+interval '15 minutes' ELSE totp_locked_until END
        WHERE id=p_user_id AND (totp_locked_until IS NULL OR totp_locked_until<=now());
    RETURN 'invalid';
END;
$$;
