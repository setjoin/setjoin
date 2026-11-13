-- V243: blob upload accounting reducer — install record for
-- blob_upload_account (med-blob-reclamation-001, Astra wave1/2 HOLD).
--
-- The blob gateway's PUT bookkeeping (per-user admission decision, charge
-- insertion, reclamation arming) used to live as a Go multi-statement
-- transaction in internal/blob/handler.go, violating the repository's
-- mandatory reducer boundary. This migration is the deployment install record
-- for the user-scoped reducer that now owns that transition; the LIVE source
-- stays mailserver/sql/reducers/blob_upload_account.sql (post-ARCH-007 the
-- fixed-point reducer reload re-applies it on top, so any later logic fix is a
-- reducer edit, never a new migration — this file keeps only the original
-- CREATE, mirroring how V240/V241 registered their reducer-owned functions).
-- The body below is byte-identical to the reducer file at install time
-- (schema-qualified name), preserving the V235 measured-byte accounting,
-- deduplication (a sha256 conflict stores no new bytes and charges nothing),
-- and serialized quota enforcement (the blob_user_usage aggregate is read
-- FOR UPDATE inside the caller's transaction, so simultaneous uploads
-- serialize per user; over-bound admission raises BZ001/over_quota, aborting
-- the whole write). No schema objects: the reducer touches only the existing
-- blobs / blob_user_charges / blob_user_usage / blob_cleanup_queue tables —
-- there is nothing here for the schema-truth determinism guard to diff beyond
-- the function itself.

-- From reducers/blob_upload_account.sql (byte-identical body; schema-qualified name):
CREATE OR REPLACE FUNCTION public.blob_upload_account(
    p_user_id       BIGINT,
    p_blob_sha256   TEXT,
    p_minio_ref     TEXT,
    p_size_bytes    BIGINT,
    p_content_type  TEXT,
    p_grace_minutes INTEGER,
    p_quota_bytes   BIGINT DEFAULT 0
) RETURNS JSONB AS $$
DECLARE
    v_stored  TEXT;
    v_charged BIGINT;
BEGIN
    IF p_user_id IS NULL OR p_user_id <= 0 THEN
        RAISE EXCEPTION 'blob_upload_account: p_user_id must be a positive user id'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"user_id"}'::TEXT;
    END IF;
    IF p_blob_sha256 IS NULL OR p_blob_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'blob_upload_account: p_blob_sha256 must be a lowercase hex SHA-256'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"blob_sha256"}'::TEXT;
    END IF;
    IF p_size_bytes IS NULL OR p_size_bytes < 0 THEN
        RAISE EXCEPTION 'blob_upload_account: p_size_bytes must be a measured non-negative byte count'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"size_bytes"}'::TEXT;
    END IF;
    IF p_grace_minutes IS NULL OR p_grace_minutes <= 0 THEN
        RAISE EXCEPTION 'blob_upload_account: p_grace_minutes must be a positive grace window'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"grace_minutes"}'::TEXT;
    END IF;

    -- 1. ADMISSION: content-addressed insert; a conflict is a dedup (the
    -- canonical key holds identical bytes — no new bytes stored).
    INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type, ref_count)
    VALUES (p_blob_sha256, p_minio_ref, p_size_bytes, p_content_type, 0)
    ON CONFLICT (sha256) DO NOTHING
    RETURNING sha256 INTO v_stored;

    IF v_stored IS NOT NULL THEN
        -- 2./3. CHARGE + QUOTA: only a NEWLY stored blob charges bytes. The
        -- aggregate is read FOR UPDATE, so concurrent uploads by one user
        -- serialize here and the bound can never be exceeded.
        INSERT INTO blob_user_usage (user_id, charged_bytes) VALUES (p_user_id, 0)
            ON CONFLICT (user_id) DO NOTHING;

        SELECT charged_bytes INTO v_charged
            FROM blob_user_usage
            WHERE user_id = p_user_id
            FOR UPDATE;

        IF p_quota_bytes > 0 AND v_charged > p_quota_bytes - p_size_bytes THEN
            RAISE EXCEPTION 'blob upload rejected: per-user storage bound exceeded'
                USING ERRCODE = 'BZ001',
                      HINT = jsonb_build_object(
                          'type', 'over_quota',
                          'user_id', p_user_id,
                          'charged_bytes', v_charged,
                          'limit_bytes', p_quota_bytes,
                          'size_bytes', p_size_bytes)::TEXT;
        END IF;

        INSERT INTO blob_user_charges (blob_sha256, user_id, size_bytes)
            VALUES (p_blob_sha256, p_user_id, p_size_bytes);
    END IF;

    -- 4. ARMING: queue any now-unattached blob for reclamation after the
    -- grace window. Fresh inserts are at ref_count=0 by construction; a dedup
    -- re-upload re-arms only if the canonical row is STILL unattached.
    INSERT INTO blob_cleanup_queue (blob_sha256, scheduled_at, delay_minutes)
        SELECT p_blob_sha256, now(), p_grace_minutes FROM blobs b
        WHERE b.sha256 = p_blob_sha256 AND b.ref_count = 0
        ON CONFLICT (blob_sha256) DO UPDATE
            SET scheduled_at = now(), delay_minutes = EXCLUDED.delay_minutes;

    RETURN jsonb_build_object(
        'result',  CASE WHEN v_stored IS NOT NULL THEN 'stored' ELSE 'dedup' END,
        'charged', v_stored IS NOT NULL);
END;
$$ LANGUAGE plpgsql;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (243, now())
  ON CONFLICT (version) DO NOTHING;
