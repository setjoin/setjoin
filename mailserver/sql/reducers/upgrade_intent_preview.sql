CREATE OR REPLACE FUNCTION upgrade_intent_preview(
    p_actor BIGINT,
    p_release_id TEXT,
    p_reason TEXT,
    p_schedule_at TIMESTAMPTZ DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_preview JSONB;
    v_digest BYTEA;
BEGIN
    v_preview := upgrade_preview_payload(
        p_actor,p_release_id,p_reason,p_schedule_at
    );
    v_digest := digest(v_preview::text,'sha256');
    RETURN jsonb_build_object(
        'preview',v_preview,
        'previewDigest',encode(v_digest,'hex'),
        'expiresAt',v_preview->'expiresAt'
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_intent_preview(bigint,text,text,timestamptz)'::regprocedure,true,false
);
