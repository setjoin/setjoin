-- blob_upload_account.sql — user-scoped blob upload accounting: admission,
-- charge insertion, and reclamation arming in ONE reducer transaction
-- (med-blob-reclamation-001, Astra wave1/2 HOLD: the quota decision and the
-- multi-step accounting lived in handler.go's Go transaction, violating the
-- mandatory reducer boundary).
--
-- Called by the blob gateway (internal/blob/handler.go Put) AFTER the body has
-- been streamed to a random temp key and hash-verified, BEFORE the temp→canonical
-- promote. One call lands everything the PUT means to the database:
--
--   1. ADMISSION — the content-addressed blobs row INSERT ... ON CONFLICT
--      (sha256) DO NOTHING. A conflict is a DEDUP: the canonical key already
--      holds identical bytes, so no new bytes are stored and NOTHING is
--      charged (the caller still gets a 201).
--   2. CHARGE — a NEWLY stored blob charges its MEASURED byte size (counted
--      from the streamed body by the gateway, so chunked/unknown-length
--      uploads are charged their real bytes, never a zero-size fallback) to
--      the uploading user: blob_user_charges → blob_user_usage (the V235 ref
--      triggers keep the aggregate exact; ON DELETE CASCADE from blobs credits
--      the user back on EVERY deletion path, including reclamation).
--   3. QUOTA — with a bound configured (p_quota_bytes > 0), the check reads
--      the user's aggregate FOR UPDATE inside THIS transaction, so
--      simultaneous uploads serialize per user on that row lock and can never
--      exceed the bound. Rejection raises BZ001 (HINT type over_quota — the
--      registered storage-quota code, same code deliver/import_export raise),
--      which aborts the WHOLE reducer: the blobs row insert rolls back with
--      the rejection, so an over-quota upload persists no row and no charge.
--      The rejection shape avoids overflow exactly as the former Go check did:
--      charged + measured could wrap; charged > bound - measured cannot.
--      p_quota_bytes <= 0 leaves enforcement OFF (accounting still recorded).
--   4. ARMING — a blob_cleanup_queue row is written for any now-unattached
--      blob (fresh inserts are at ref_count=0 by construction; a dedup
--      re-upload re-arms only if the canonical row is STILL unattached —
--      attached blobs are owned by the V075 UPDATE-to-zero trigger, which
--      re-arms on detach), with the configured grace window as delay_minutes.
--      The arm targets only blobs still at ref_count=0 and reaps only through
--      reapCleanupCandidate's atomic DELETE ... WHERE ref_count = 0 re-check,
--      so a late attach or a cross-user deduplicated reference can never
--      delete referenced bytes.
--
-- ISOLATION POSTURE (R1–R4, D-MAILSERVER-INTERNAL-BLOB-002). The accounting
-- tables are user-keyed aggregates (V235 header: blob-family posture — no RLS,
-- isolation at the gateway), so the scope currency here is p_user_id, bound by
-- the gateway from the authenticated claims (R2 — never a request-owned
-- field): the usage upsert, its FOR UPDATE read, and the charge INSERT all
-- carry p_user_id. blobs/blob_cleanup_queue are content-addressed shared
-- stores, keyed by the exact SHA-256, not per-user rows.
--
-- Validation (BZ040 invalidArguments) is defense-in-depth: the gateway
-- validates the hash format before streaming and always binds p_user_id from
-- auth, so a failure here means a caller bypassed the gateway contract.
--
-- BZ040 reuse note (mirrors cron_retention_days): invalidArguments is the
-- registry's generic invalid-argument code, so reusing it needs no
-- reducererr contract change.
CREATE OR REPLACE FUNCTION blob_upload_account(
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
