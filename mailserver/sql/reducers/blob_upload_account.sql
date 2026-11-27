-- blob_upload_account.sql — user-scoped blob upload accounting: admission,
-- charge insertion, GC reactivation, and durable staging promote recovery in
-- ONE reducer transaction (#243, Wave 2.3 #550, Wave 2.4 #551).
--
-- Called by the blob gateway (blobs.rs / jmap/upload.rs) AFTER the body has
-- been streamed to a random tmp/blob-upload/<op> staging key and hash-verified,
-- BEFORE the staging -> canonical promote. One call lands everything the PUT
-- means to the database:
--
--   1. SERIALIZE — acquires pg_advisory_xact_lock(blob_gc_lock_key(sha256)) so
--      Mark-and-Sweep GC Tx 2A/2B cannot concurrently purge bytes being promoted.
--   2. ADMISSION — INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type)
--      ON CONFLICT (sha256) DO NOTHING. A conflict is a DEDUP (no new bytes,
--      nothing charged).
--   3. CHARGE + QUOTA — a NEWLY stored blob charges its measured byte size to
--      the uploading user via blob_user_charges -> blob_user_usage (V235 triggers),
--      serialized per-user on blob_user_usage FOR UPDATE. Over-bound raises BZ001.
--   4. REACTIVATION + PROMOTE RECOVERY — calls blob_gc_reactivate_v2(sha256,
--      staging_key) so any reclaim_eligible/purging row flips back to active
--      (and enqueues delayed blob.promote_verify if it was purging), and when
--      p_staging_key is provided, enqueues durable blob.promote_recover
--      returning promoteWorkItemId in the JSONB result.
--
-- ISOLATION POSTURE (R1-R4): p_user_id is bound from authenticated claims (R2).
CREATE OR REPLACE FUNCTION blob_upload_account(
    p_user_id       BIGINT,
    p_blob_sha256   TEXT,
    p_minio_ref     TEXT,
    p_size_bytes    BIGINT,
    p_content_type  TEXT,
    p_grace_minutes INTEGER,
    p_quota_bytes   BIGINT DEFAULT 0,
    p_staging_key   TEXT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
    v_stored     TEXT;
    v_charged    BIGINT;
    v_react      JSONB;
    v_promote_id BIGINT := NULL;
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
    IF p_staging_key IS NOT NULL
       AND p_staging_key !~ '^tmp/blob-upload/[0-9a-f]{16,64}$' THEN
        RAISE EXCEPTION 'blob_upload_account: p_staging_key must match ^tmp/blob-upload/[0-9a-f]{16,64}$'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"staging_key"}'::TEXT;
    END IF;

    -- 0. SERIALIZE WITH MARK-AND-SWEEP GC (#550/#551): acquire the per-sha256
    -- transaction advisory lock before admitting/deduping blobs so Tx 2A/2B
    -- cannot concurrently delete bytes we are about to promote.
    PERFORM pg_catalog.pg_advisory_xact_lock(public.blob_gc_lock_key(p_blob_sha256));

    -- 1. ADMISSION: content-addressed insert; a conflict is a dedup (the
    -- canonical key holds identical bytes — no new bytes stored).
    INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type)
    VALUES (p_blob_sha256, p_minio_ref, p_size_bytes, p_content_type)
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

    -- 4. Reactivate any reclaim_eligible/purging companion GC state row and
    -- proactively enqueue delayed blob.promote_verify when reactivating from
    -- purging (#551).
    v_react := public.blob_gc_reactivate_v2(p_blob_sha256, p_staging_key);

    -- 5. Durably enqueue staging promote recovery when caller staged under
    -- tmp/blob-upload/* (#551).
    IF p_staging_key IS NOT NULL THEN
        v_promote_id := public.blob_promote_recover_enqueue(p_blob_sha256, p_staging_key, 30.0);
    END IF;

    RETURN jsonb_build_object(
        'result',            CASE WHEN v_stored IS NOT NULL THEN 'stored' ELSE 'dedup' END,
        'charged',           v_stored IS NOT NULL,
        'wasPurging',        COALESCE((v_react->>'was_purging')::BOOLEAN, FALSE),
        'promoteWorkItemId', v_promote_id,
        'verifyWorkItemId',  (v_react->>'verify_work_item_id')::BIGINT
    );
END;
$$ LANGUAGE plpgsql;
