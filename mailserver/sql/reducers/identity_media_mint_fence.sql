-- Reserve one short-lived authenticated LiveKit admission under the same
-- per-person advisory lock used by identity transitions. If mint wins first,
-- the transition records the lease and repeatedly evicts through its expiry.
-- If transition wins first, the admission recheck fails closed.
CREATE OR REPLACE FUNCTION identity_media_mint_fence(
    p_user_id BIGINT,
    p_room_name TEXT,
    p_identity TEXT,
    p_requested_ttl_seconds INTEGER
) RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_ttl INTEGER := LEAST(COALESCE(p_requested_ttl_seconds,0),60);
BEGIN
    IF p_user_id IS NULL
       OR p_room_name IS NULL
       OR p_identity IS DISTINCT FROM 'u:'||p_user_id::text
       OR octet_length(p_room_name) NOT BETWEEN 1 AND 255
       OR p_room_name ~ '[[:cntrl:]]'
       OR v_ttl<1 THEN
        RAISE EXCEPTION 'invalid identity media admission'
            USING ERRCODE='BZ241',
                  HINT='{"type":"identity_transition_admission_fenced"}';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-person:'||p_user_id::text,0
    ));
    PERFORM 1 FROM users
     WHERE id=p_user_id AND enabled
     FOR SHARE;
    IF NOT FOUND OR NOT identity_transition_admission_allowed(p_user_id) THEN
        RAISE EXCEPTION 'identity transition security effects are pending'
            USING ERRCODE='BZ234',
                  HINT='{"type":"identity_transition_admission_fenced","remediation":"wait for or exactly retry the pending session/SFU effect"}';
    END IF;

    DELETE FROM identity_media_admissions
     WHERE user_id=p_user_id AND expires_at<=statement_timestamp();
    INSERT INTO identity_media_admissions(
        user_id,room_name,identity,expires_at
    ) VALUES(
        p_user_id,p_room_name,p_identity,
        -- LiveKit validates exp with clock tolerance. Keep eviction active for
        -- fifteen seconds beyond the signed token's 60-second admission TTL.
        statement_timestamp()+make_interval(secs=>v_ttl+15)
    )
    ON CONFLICT(user_id,room_name,identity) DO UPDATE
      SET expires_at=EXCLUDED.expires_at,
          created_at=statement_timestamp(),
          updated_at=statement_timestamp();
    RETURN v_ttl;
END;
$$;
SELECT apply_worker_ownership(
    'identity_media_mint_fence(bigint,text,text,integer)'::regprocedure
);
