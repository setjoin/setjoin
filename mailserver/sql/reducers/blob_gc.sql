-- blob_gc.sql — Mark-and-Sweep S3 Blob GC reducers, live-catalog reader,
-- uploader reactivation, and durable staging promote recovery (#550/#551).
--
-- Security posture:
--   - Worker-only GC reducers (blob_has_live_reference, blob_gc_live_sources,
--     blob_is_held_or_retained, blob_gc_mark, blob_gc_claim_purging,
--     blob_gc_record_worm_lock) are SECURITY INVOKER SET search_path = pg_catalog, public
--     and enforce (rolbypassrls OR rolsuper) raising BZ003, with EXECUTE revoked
--     from PUBLIC & setjoin_app and granted only to setjoin_worker (restated in
--     scripts/provision-roles.sql exact_worker).
--   - Narrow uploader/recovery SECURITY DEFINER seams (blob_gc_reactivate,
--     blob_gc_reactivate_v2, blob_promote_recover_enqueue,
--     blob_promote_recover_complete) are owned by setjoin_worker, SET search_path =
--     pg_catalog, public, revoked from PUBLIC, granted to setjoin_app,
--     setjoin_worker, setjoin_owner. They NEVER accept worm_locked_until.
--   - Set-based live-catalog reader blob_live_catalog() is SECURITY DEFINER,
--     owned by setjoin_worker, SET search_path = pg_catalog, public, revoked from
--     PUBLIC and setjoin_app, and granted ONLY to setjoin_worker and setjoin_owner.
--   - blob_gc_register_and_reactivate(text, text, bigint, text) is SECURITY INVOKER
--     so setjoin_app uploaders (chat_unfurl, platform_storage) serialize on the
--     per-sha256 advisory lock, admit the blobs row, and reactivate blob_gc_state
--     via blob_gc_reactivate() in a single atomic transaction.

CREATE OR REPLACE FUNCTION blob_gc_lock_key(p_sha256 text)
RETURNS bigint
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
    SELECT pg_catalog.hashtextextended('blob-gc:' || p_sha256, 0);
$$;

DO $$
BEGIN
    REVOKE ALL ON FUNCTION public.blob_gc_lock_key(text) FROM PUBLIC;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        GRANT EXECUTE ON FUNCTION public.blob_gc_lock_key(text) TO setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.blob_gc_lock_key(text) TO setjoin_worker;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
        GRANT EXECUTE ON FUNCTION public.blob_gc_lock_key(text) TO setjoin_owner;
    END IF;
END
$$;

-- Narrow SECURITY DEFINER helper allowing setjoin_app uploaders to serialize
-- on the per-sha256 transaction advisory lock and reactivate any reclaim_eligible
-- or purging row in FORCE-RLS deny-all public.blob_gc_state without granting
-- setjoin_app direct table access or WORM-lock mutation privileges.
-- Signature intentionally unchanged across V288->V289 (zero ACL churn).
CREATE OR REPLACE FUNCTION blob_gc_reactivate(
    p_sha256 text
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_existing public.blob_gc_state%ROWTYPE;
BEGIN
    IF p_sha256 IS NULL OR p_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'blob_gc_reactivate: p_sha256 must be a lowercase 64-hex SHA-256'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"sha256"}'::text;
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(public.blob_gc_lock_key(p_sha256));

    IF NOT EXISTS (SELECT 1 FROM public.blobs WHERE sha256 = p_sha256) THEN
        RETURN false;
    END IF;

    SELECT * INTO v_existing
      FROM public.blob_gc_state
     WHERE blob_sha256 = p_sha256
       FOR UPDATE;

    IF FOUND
       AND v_existing.gc_state = 'active'
       AND v_existing.last_touched_at >= now() - interval '1 hour' THEN
        RETURN true;
    END IF;

    INSERT INTO public.blob_gc_state (
        blob_sha256,
        gc_state,
        reclaim_eligible_at,
        purging_at,
        last_touched_at
    )
    VALUES (
        p_sha256,
        'active',
        NULL,
        NULL,
        now()
    )
    ON CONFLICT (blob_sha256) DO UPDATE
        SET gc_state            = 'active',
            reclaim_eligible_at = NULL,
            purging_at          = NULL,
            last_touched_at     = now();

    RETURN true;
END;
$$;

-- Companion proactive-fencing reactivation seam (#551): reports whether the
-- previous state was 'purging' (and its purging_at timestamp) and, when
-- p_staging_key is supplied on a 'purging' row, atomically enqueues a delayed
-- blob.promote_verify work item (run_at = now() + 60s) to fence delayed
-- unversioned S3 DELETEs without relying on volatile post-hoc timeout timestamps.
CREATE OR REPLACE FUNCTION blob_gc_reactivate_v2(
    p_sha256      text,
    p_staging_key text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_existing    public.blob_gc_state%ROWTYPE;
    v_was_purging boolean := false;
    v_purging_at  timestamptz := NULL;
    v_verify_id   bigint := NULL;
BEGIN
    IF p_sha256 IS NULL OR p_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'blob_gc_reactivate_v2: p_sha256 must be a lowercase 64-hex SHA-256'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"sha256"}'::text;
    END IF;
    IF p_staging_key IS NOT NULL
       AND p_staging_key !~ '^tmp/blob-upload/[0-9a-f]{16,64}$' THEN
        RAISE EXCEPTION 'blob_gc_reactivate_v2: p_staging_key must match ^tmp/blob-upload/[0-9a-f]{16,64}$'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"staging_key"}'::text;
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(public.blob_gc_lock_key(p_sha256));

    IF NOT EXISTS (SELECT 1 FROM public.blobs WHERE sha256 = p_sha256) THEN
        RETURN jsonb_build_object(
            'reactivated', false,
            'was_purging', false,
            'purging_at', NULL,
            'verify_work_item_id', NULL
        );
    END IF;

    SELECT * INTO v_existing
      FROM public.blob_gc_state
     WHERE blob_sha256 = p_sha256
       FOR UPDATE;

    IF FOUND AND v_existing.gc_state = 'purging' THEN
        v_was_purging := true;
        v_purging_at := v_existing.purging_at;
    END IF;

    IF NOT (
        FOUND
        AND v_existing.gc_state = 'active'
        AND v_existing.last_touched_at >= now() - interval '1 hour'
    ) THEN
        INSERT INTO public.blob_gc_state (
            blob_sha256,
            gc_state,
            reclaim_eligible_at,
            purging_at,
            last_touched_at
        )
        VALUES (
            p_sha256,
            'active',
            NULL,
            NULL,
            now()
        )
        ON CONFLICT (blob_sha256) DO UPDATE
            SET gc_state            = 'active',
                reclaim_eligible_at = NULL,
                purging_at          = NULL,
                last_touched_at     = now();
    END IF;

    IF v_was_purging AND p_staging_key IS NOT NULL THEN
        SELECT w.work_item_id INTO v_verify_id
          FROM public.work_enqueue(
              'blob.promote_verify',
              jsonb_build_object('sha256', p_sha256, 'staging_key', p_staging_key),
              'blob.promote_verify:' || p_sha256 || ':' || p_staging_key,
              now() + interval '60 seconds',
              0::smallint,
              20
          ) w;
    END IF;

    RETURN jsonb_build_object(
        'reactivated', true,
        'was_purging', v_was_purging,
        'purging_at', v_purging_at,
        'verify_work_item_id', v_verify_id
    );
END;
$$;

-- Narrow app-callable SECURITY DEFINER seam (#551) to durably enqueue a
-- delayed blob.promote_recover WorkQueue item inside blob_upload_account so a
-- crash between DB commit and S3 promote never leaves a live blobs row missing
-- its canonical S3 object.
CREATE OR REPLACE FUNCTION blob_promote_recover_enqueue(
    p_sha256      text,
    p_staging_key text,
    p_delay_secs  double precision DEFAULT 30.0
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_delay double precision;
    v_id    bigint;
BEGIN
    IF p_sha256 IS NULL OR p_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'blob_promote_recover_enqueue: p_sha256 must be a lowercase 64-hex SHA-256'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"sha256"}'::text;
    END IF;
    IF p_staging_key IS NULL OR p_staging_key !~ '^tmp/blob-upload/[0-9a-f]{16,64}$' THEN
        RAISE EXCEPTION 'blob_promote_recover_enqueue: p_staging_key must match ^tmp/blob-upload/[0-9a-f]{16,64}$'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"staging_key"}'::text;
    END IF;

    v_delay := LEAST(GREATEST(COALESCE(p_delay_secs, 30.0), 1.0), 3600.0);

    PERFORM pg_catalog.pg_advisory_xact_lock(public.blob_gc_lock_key(p_sha256));

    IF NOT EXISTS (SELECT 1 FROM public.blobs WHERE sha256 = p_sha256) THEN
        RETURN NULL;
    END IF;

    SELECT w.work_item_id INTO v_id
      FROM public.work_enqueue(
          'blob.promote_recover',
          jsonb_build_object('sha256', p_sha256, 'staging_key', p_staging_key),
          'blob.promote_recover:' || p_sha256 || ':' || p_staging_key,
          now() + make_interval(secs => v_delay),
          0::smallint,
          20
      ) w;

    RETURN v_id;
END;
$$;

-- Narrow app-callable SECURITY DEFINER seam (#551) to cancel a pending
-- blob.promote_recover item ONLY when it is still unleased and matches
-- (p_sha256, p_staging_key). Returns true iff cancelled (caller may delete
-- p_staging_key); returns false if already leased/completed (worker owns
-- deletion of p_staging_key after promoting).
CREATE OR REPLACE FUNCTION blob_promote_recover_complete(
    p_work_item_id bigint,
    p_sha256       text,
    p_staging_key  text
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_work_item_id IS NULL OR p_work_item_id <= 0 THEN
        RAISE EXCEPTION 'blob_promote_recover_complete: p_work_item_id must be positive'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"work_item_id"}'::text;
    END IF;
    IF p_sha256 IS NULL OR p_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'blob_promote_recover_complete: p_sha256 must be a lowercase 64-hex SHA-256'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"sha256"}'::text;
    END IF;
    IF p_staging_key IS NULL OR p_staging_key !~ '^tmp/blob-upload/[0-9a-f]{16,64}$' THEN
        RAISE EXCEPTION 'blob_promote_recover_complete: p_staging_key must match ^tmp/blob-upload/[0-9a-f]{16,64}$'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"staging_key"}'::text;
    END IF;

    DELETE FROM public.work_items
     WHERE id = p_work_item_id
       AND kind = 'blob.promote_recover'
       AND status = 'pending'
       AND payload->>'sha256' = p_sha256
       AND payload->>'staging_key' = p_staging_key;

    RETURN FOUND;
END;
$$;

DO $$
DECLARE
    v_had_create boolean := false;
    v_sig        text;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        SELECT has_schema_privilege('setjoin_worker', 'public', 'CREATE') INTO v_had_create;
        IF NOT v_had_create THEN
            GRANT CREATE ON SCHEMA public TO setjoin_worker;
        END IF;
        FOREACH v_sig IN ARRAY ARRAY[
            'public.blob_gc_reactivate(text)',
            'public.blob_gc_reactivate_v2(text,text)',
            'public.blob_promote_recover_enqueue(text,text,double precision)',
            'public.blob_promote_recover_complete(bigint,text,text)'
        ] LOOP
            EXECUTE format('ALTER FUNCTION %s OWNER TO setjoin_worker', v_sig);
        END LOOP;
        IF NOT v_had_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    END IF;

    FOREACH v_sig IN ARRAY ARRAY[
        'public.blob_gc_reactivate(text)',
        'public.blob_gc_reactivate_v2(text,text)',
        'public.blob_promote_recover_enqueue(text,text,double precision)',
        'public.blob_promote_recover_complete(bigint,text,text)'
    ] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', v_sig);
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_worker', v_sig);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_app', v_sig);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_owner', v_sig);
        END IF;
    END LOOP;
END
$$;

-- Atomic lock + blobs admission + blob_gc_state reactivation for non-quota
-- uploaders (chat unfurl thumbnails, platform storage DR reimport, mailbox import).
CREATE OR REPLACE FUNCTION blob_gc_register_and_reactivate(
    p_sha256       text,
    p_minio_ref    text,
    p_size_bytes   bigint,
    p_content_type text DEFAULT 'application/octet-stream'
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_sha256 IS NULL OR p_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'blob_gc_register_and_reactivate: p_sha256 must be a lowercase 64-hex SHA-256'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"sha256"}'::text;
    END IF;
    IF p_size_bytes IS NULL OR p_size_bytes < 0 THEN
        RAISE EXCEPTION 'blob_gc_register_and_reactivate: p_size_bytes must be non-negative'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"size_bytes"}'::text;
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(public.blob_gc_lock_key(p_sha256));

    INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type)
    VALUES (
        p_sha256,
        p_minio_ref,
        p_size_bytes,
        COALESCE(NULLIF(p_content_type, ''), 'application/octet-stream')
    )
    ON CONFLICT (sha256) DO NOTHING;

    PERFORM public.blob_gc_reactivate(p_sha256);
END;
$$;

DO $$
BEGIN
    REVOKE ALL ON FUNCTION public.blob_gc_register_and_reactivate(text, text, bigint, text) FROM PUBLIC;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        GRANT EXECUTE ON FUNCTION public.blob_gc_register_and_reactivate(text, text, bigint, text) TO setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.blob_gc_register_and_reactivate(text, text, bigint, text) TO setjoin_worker;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
        GRANT EXECUTE ON FUNCTION public.blob_gc_register_and_reactivate(text, text, bigint, text) TO setjoin_owner;
    END IF;
END
$$;

-- Authoritative live-root catalog checked by Mark-and-Sweep GC.
-- Every EXISTS arm MUST match config/blob-reference-manifest.json live_roots
-- 1:1 (enforced bidirectionally by scripts/check-blob-reference-manifest.py)
-- and preserve exact predicate parity with partial btree indexes from V288.
CREATE OR REPLACE FUNCTION blob_has_live_reference(p_sha256 text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'blob_has_live_reference: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_sha256 IS NULL OR p_sha256 !~ '^[0-9a-f]{64}$' THEN
        RETURN false;
    END IF;

    RETURN EXISTS (
        SELECT 1 FROM public.message_attachments ma
         WHERE ma.blob_sha256 = p_sha256
    ) OR EXISTS (
        SELECT 1 FROM public.hr_expense_receipts her
         WHERE her.blob_sha256 = p_sha256
    ) OR EXISTS (
        SELECT 1 FROM public.chat_link_previews clp
         WHERE clp.image_blob_sha256 = p_sha256
    ) OR EXISTS (
        SELECT 1 FROM public.users u
         WHERE u.avatar_sha256 = p_sha256
    ) OR EXISTS (
        SELECT 1 FROM public.contacts c
         WHERE c.avatar_sha256 = p_sha256
    ) OR EXISTS (
        SELECT 1 FROM public.mail_recovery_upload_items mrui
         WHERE mrui.status = 'verified'
           AND mrui.object_ref = p_sha256
    ) OR EXISTS (
        SELECT 1 FROM public.mail_recovery_quarantine_artifacts mrqa
         WHERE mrqa.status NOT IN ('rejected', 'tampered')
           AND mrqa.raw_ref = p_sha256
    ) OR EXISTS (
        SELECT 1 FROM public.mail_recovery_quarantine_artifacts mrqa
        CROSS JOIN LATERAL jsonb_array_elements(mrqa.blob_inventory) elem
         WHERE mrqa.status NOT IN ('rejected', 'tampered')
           AND (elem->>'sha256' = p_sha256 OR elem->>'objectRef' = p_sha256)
    ) OR EXISTS (
        SELECT 1 FROM public.messages m
         WHERE m.raw_ref = p_sha256
           AND length(m.raw_ref) = 64
           AND m.raw_ref ~ '^[0-9a-f]{64}$'
    ) OR EXISTS (
        SELECT 1 FROM public.outbound_queue oq
         WHERE oq.raw_ref = p_sha256
           AND length(oq.raw_ref) = 64
           AND oq.raw_ref ~ '^[0-9a-f]{64}$'
    ) OR EXISTS (
        SELECT 1 FROM public.outbound_queue_hot oqh
         WHERE oqh.raw_ref = p_sha256
           AND length(oqh.raw_ref) = 64
           AND oqh.raw_ref ~ '^[0-9a-f]{64}$'
    ) OR EXISTS (
        SELECT 1 FROM public.journal_queue jq
         WHERE jq.raw_ref = p_sha256
           AND length(jq.raw_ref) = 64
           AND jq.raw_ref ~ '^[0-9a-f]{64}$'
    ) OR EXISTS (
        SELECT 1 FROM public.held_inbound_messages him
         WHERE him.raw_ref = p_sha256
           AND length(him.raw_ref) = 64
           AND him.raw_ref ~ '^[0-9a-f]{64}$'
    ) OR EXISTS (
        SELECT 1 FROM public.ediscovery_searches es
         WHERE es.export_ref IS NOT NULL
           AND es.export_ref = p_sha256
           AND length(es.export_ref) = 64
           AND es.export_ref ~ '^[0-9a-f]{64}$'
    );
END;
$$;

-- Set-based, owner- and worker-callable live blob catalog (#551).
-- Replaces legacy `SELECT ... FROM blobs WHERE ref_count > 0` across backup,
-- recovery, storage migration, and DR scan readers in O(total_roots) using a
-- single UNION CTE across all 14 manifest live-root tables joined once to
-- public.blobs (excluding rows currently in gc_state = 'purging').
-- Owned by setjoin_worker (SECURITY DEFINER, BYPASSRLS) so non-superuser
-- setjoin_owner backup/upgrade paths read all 14 roots cleanly without BZ003.
-- Strictly revoked from PUBLIC and setjoin_app.
CREATE OR REPLACE FUNCTION blob_live_catalog()
RETURNS TABLE (
    sha256     text,
    minio_ref  text,
    size_bytes bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    WITH live_shas(sha256) AS (
        SELECT ma.blob_sha256 FROM public.message_attachments ma
        UNION
        SELECT her.blob_sha256 FROM public.hr_expense_receipts her
        UNION
        SELECT clp.image_blob_sha256 FROM public.chat_link_previews clp
         WHERE clp.image_blob_sha256 IS NOT NULL
        UNION
        SELECT u.avatar_sha256 FROM public.users u
         WHERE u.avatar_sha256 IS NOT NULL
        UNION
        SELECT c.avatar_sha256 FROM public.contacts c
         WHERE c.avatar_sha256 IS NOT NULL
        UNION
        SELECT mrui.object_ref FROM public.mail_recovery_upload_items mrui
         WHERE mrui.status = 'verified' AND mrui.object_ref IS NOT NULL
        UNION
        SELECT mrqa.raw_ref FROM public.mail_recovery_quarantine_artifacts mrqa
         WHERE mrqa.status NOT IN ('rejected', 'tampered')
           AND mrqa.raw_ref IS NOT NULL
        UNION
        SELECT elem->>'sha256'
          FROM public.mail_recovery_quarantine_artifacts mrqa
          CROSS JOIN LATERAL jsonb_array_elements(mrqa.blob_inventory) elem
         WHERE mrqa.status NOT IN ('rejected', 'tampered')
           AND elem->>'sha256' IS NOT NULL
           AND elem->>'sha256' <> ''
        UNION
        SELECT elem->>'objectRef'
          FROM public.mail_recovery_quarantine_artifacts mrqa
          CROSS JOIN LATERAL jsonb_array_elements(mrqa.blob_inventory) elem
         WHERE mrqa.status NOT IN ('rejected', 'tampered')
           AND elem->>'objectRef' IS NOT NULL
           AND elem->>'objectRef' <> ''
        UNION
        SELECT m.raw_ref FROM public.messages m
         WHERE length(m.raw_ref) = 64 AND m.raw_ref ~ '^[0-9a-f]{64}$'
        UNION
        SELECT oq.raw_ref FROM public.outbound_queue oq
         WHERE length(oq.raw_ref) = 64 AND oq.raw_ref ~ '^[0-9a-f]{64}$'
        UNION
        SELECT oqh.raw_ref FROM public.outbound_queue_hot oqh
         WHERE length(oqh.raw_ref) = 64 AND oqh.raw_ref ~ '^[0-9a-f]{64}$'
        UNION
        SELECT jq.raw_ref FROM public.journal_queue jq
         WHERE length(jq.raw_ref) = 64 AND jq.raw_ref ~ '^[0-9a-f]{64}$'
        UNION
        SELECT him.raw_ref FROM public.held_inbound_messages him
         WHERE length(him.raw_ref) = 64 AND him.raw_ref ~ '^[0-9a-f]{64}$'
        UNION
        SELECT es.export_ref FROM public.ediscovery_searches es
         WHERE es.export_ref IS NOT NULL
           AND length(es.export_ref) = 64
           AND es.export_ref ~ '^[0-9a-f]{64}$'
    )
    SELECT b.sha256, b.minio_ref, b.size_bytes
      FROM live_shas l
      JOIN public.blobs b ON b.sha256 = l.sha256
      LEFT JOIN public.blob_gc_state s ON s.blob_sha256 = b.sha256
     WHERE COALESCE(s.gc_state, 'active') <> 'purging'
     ORDER BY b.sha256;
$$;

DO $$
DECLARE
    v_had_create boolean := false;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        SELECT has_schema_privilege('setjoin_worker', 'public', 'CREATE') INTO v_had_create;
        IF NOT v_had_create THEN
            GRANT CREATE ON SCHEMA public TO setjoin_worker;
        END IF;
        ALTER FUNCTION public.blob_live_catalog() OWNER TO setjoin_worker;
        IF NOT v_had_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    END IF;
    REVOKE ALL ON FUNCTION public.blob_live_catalog() FROM PUBLIC;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE ALL ON FUNCTION public.blob_live_catalog() FROM setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.blob_live_catalog() TO setjoin_worker;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
        GRANT EXECUTE ON FUNCTION public.blob_live_catalog() TO setjoin_owner;
    END IF;
END
$$;

-- Enumerates every live root table.column referencing p_sha256 for diagnostics.
CREATE OR REPLACE FUNCTION blob_gc_live_sources(p_sha256 text)
RETURNS text[]
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_sources text[] := ARRAY[]::text[];
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'blob_gc_live_sources: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_sha256 IS NULL OR p_sha256 !~ '^[0-9a-f]{64}$' THEN
        RETURN v_sources;
    END IF;

    IF EXISTS (SELECT 1 FROM public.message_attachments ma WHERE ma.blob_sha256 = p_sha256) THEN
        v_sources := array_append(v_sources, 'message_attachments.blob_sha256');
    END IF;
    IF EXISTS (SELECT 1 FROM public.hr_expense_receipts her WHERE her.blob_sha256 = p_sha256) THEN
        v_sources := array_append(v_sources, 'hr_expense_receipts.blob_sha256');
    END IF;
    IF EXISTS (SELECT 1 FROM public.chat_link_previews clp WHERE clp.image_blob_sha256 = p_sha256) THEN
        v_sources := array_append(v_sources, 'chat_link_previews.image_blob_sha256');
    END IF;
    IF EXISTS (SELECT 1 FROM public.users u WHERE u.avatar_sha256 = p_sha256) THEN
        v_sources := array_append(v_sources, 'users.avatar_sha256');
    END IF;
    IF EXISTS (SELECT 1 FROM public.contacts c WHERE c.avatar_sha256 = p_sha256) THEN
        v_sources := array_append(v_sources, 'contacts.avatar_sha256');
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.mail_recovery_upload_items mrui
         WHERE mrui.status = 'verified' AND mrui.object_ref = p_sha256
    ) THEN
        v_sources := array_append(v_sources, 'mail_recovery_upload_items.object_ref');
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.mail_recovery_quarantine_artifacts mrqa
         WHERE mrqa.status NOT IN ('rejected', 'tampered') AND mrqa.raw_ref = p_sha256
    ) THEN
        v_sources := array_append(v_sources, 'mail_recovery_quarantine_artifacts.raw_ref');
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.mail_recovery_quarantine_artifacts mrqa
        CROSS JOIN LATERAL jsonb_array_elements(mrqa.blob_inventory) elem
         WHERE mrqa.status NOT IN ('rejected', 'tampered')
           AND (elem->>'sha256' = p_sha256 OR elem->>'objectRef' = p_sha256)
    ) THEN
        v_sources := array_append(v_sources, 'mail_recovery_quarantine_artifacts.blob_inventory');
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.messages m
         WHERE m.raw_ref = p_sha256 AND length(m.raw_ref) = 64 AND m.raw_ref ~ '^[0-9a-f]{64}$'
    ) THEN
        v_sources := array_append(v_sources, 'messages.raw_ref');
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.outbound_queue oq
         WHERE oq.raw_ref = p_sha256 AND length(oq.raw_ref) = 64 AND oq.raw_ref ~ '^[0-9a-f]{64}$'
    ) THEN
        v_sources := array_append(v_sources, 'outbound_queue.raw_ref');
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.outbound_queue_hot oqh
         WHERE oqh.raw_ref = p_sha256 AND length(oqh.raw_ref) = 64 AND oqh.raw_ref ~ '^[0-9a-f]{64}$'
    ) THEN
        v_sources := array_append(v_sources, 'outbound_queue_hot.raw_ref');
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.journal_queue jq
         WHERE jq.raw_ref = p_sha256 AND length(jq.raw_ref) = 64 AND jq.raw_ref ~ '^[0-9a-f]{64}$'
    ) THEN
        v_sources := array_append(v_sources, 'journal_queue.raw_ref');
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.held_inbound_messages him
         WHERE him.raw_ref = p_sha256 AND length(him.raw_ref) = 64 AND him.raw_ref ~ '^[0-9a-f]{64}$'
    ) THEN
        v_sources := array_append(v_sources, 'held_inbound_messages.raw_ref');
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.ediscovery_searches es
         WHERE es.export_ref IS NOT NULL
           AND es.export_ref = p_sha256
           AND length(es.export_ref) = 64
           AND es.export_ref ~ '^[0-9a-f]{64}$'
    ) THEN
        v_sources := array_append(v_sources, 'ediscovery_searches.export_ref');
    END IF;

    RETURN v_sources;
END;
$$;

-- Legal-hold, retention-tag (including infinite expires_at IS NULL), detached
-- mailbox_lifecycle retention, WORM gate, and active promote recovery/verify intents.
CREATE OR REPLACE FUNCTION blob_is_held_or_retained(
    p_sha256    text,
    p_worm_days integer DEFAULT 0
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'blob_is_held_or_retained: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_worm_days IS NULL OR p_worm_days < 0 THEN
        RAISE EXCEPTION 'blob_is_held_or_retained: p_worm_days must be non-negative'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"worm_days"}'::text;
    END IF;

    IF p_sha256 IS NULL OR p_sha256 !~ '^[0-9a-f]{64}$' THEN
        RETURN false;
    END IF;

    -- 1. Companion state explicit retain_until / worm_locked_until.
    IF EXISTS (
        SELECT 1 FROM public.blob_gc_state s
         WHERE s.blob_sha256 = p_sha256
           AND (
               (s.retain_until IS NOT NULL AND s.retain_until > now())
               OR (s.worm_locked_until IS NOT NULL AND s.worm_locked_until > now())
           )
    ) THEN
        RETURN true;
    END IF;

    -- 2. Active WORM_MODE retention horizon from blobs.created_at.
    IF p_worm_days > 0 AND EXISTS (
        SELECT 1 FROM public.blobs b
         WHERE b.sha256 = p_sha256
           AND b.created_at + make_interval(days => p_worm_days) > now()
    ) THEN
        RETURN true;
    END IF;

    -- 3. Message legal hold / mailbox litigation_hold via attachments or raw_ref.
    IF EXISTS (
        SELECT 1
          FROM public.message_attachments ma
          JOIN public.messages m
            ON m.id = ma.message_id AND m.received_at = ma.received_at
          JOIN public.mailboxes mb ON mb.id = m.mailbox_id
         WHERE ma.blob_sha256 = p_sha256
           AND (m.held OR mb.litigation_hold)
    ) OR EXISTS (
        SELECT 1
          FROM public.messages m
          JOIN public.mailboxes mb ON mb.id = m.mailbox_id
         WHERE m.raw_ref = p_sha256
           AND length(m.raw_ref) = 64
           AND m.raw_ref ~ '^[0-9a-f]{64}$'
           AND (m.held OR mb.litigation_hold)
    ) THEN
        RETURN true;
    END IF;

    -- 4. Retention tags: hold policy OR infinite retention (expires_at IS NULL) OR unexpired.
    IF EXISTS (
        SELECT 1
          FROM public.message_attachments ma
          JOIN public.message_retention_tags mrt
            ON mrt.message_id = ma.message_id AND mrt.received_at = ma.received_at
          JOIN public.retention_policies rp ON rp.id = mrt.policy_id
         WHERE ma.blob_sha256 = p_sha256
           AND (rp.action = 'hold' OR mrt.expires_at IS NULL OR mrt.expires_at > now())
    ) OR EXISTS (
        SELECT 1
          FROM public.messages m
          JOIN public.message_retention_tags mrt
            ON mrt.message_id = m.id AND mrt.received_at = m.received_at
          JOIN public.retention_policies rp ON rp.id = mrt.policy_id
         WHERE m.raw_ref = p_sha256
           AND length(m.raw_ref) = 64
           AND m.raw_ref ~ '^[0-9a-f]{64}$'
           AND (rp.action = 'hold' OR mrt.expires_at IS NULL OR mrt.expires_at > now())
    ) THEN
        RETURN true;
    END IF;

    -- 5. Detached-retained mailbox_lifecycle retention window.
    IF EXISTS (
        SELECT 1
          FROM public.message_attachments ma
          JOIN public.messages m
            ON m.id = ma.message_id AND m.received_at = ma.received_at
          JOIN public.mailbox_lifecycle ml ON ml.mailbox_id = m.mailbox_id
         WHERE ma.blob_sha256 = p_sha256
           AND ml.binding_state = 'retained'
           AND ml.retention_until > now()
    ) OR EXISTS (
        SELECT 1
          FROM public.messages m
          JOIN public.mailbox_lifecycle ml ON ml.mailbox_id = m.mailbox_id
         WHERE m.raw_ref = p_sha256
           AND length(m.raw_ref) = 64
           AND m.raw_ref ~ '^[0-9a-f]{64}$'
           AND ml.binding_state = 'retained'
           AND ml.retention_until > now()
    ) THEN
        RETURN true;
    END IF;

    -- 6. Unsettled durable staging promote recovery / post-purging verification intents (#551).
    IF EXISTS (
        SELECT 1
          FROM public.work_items wi
         WHERE wi.kind IN ('blob.promote_recover', 'blob.promote_verify')
           AND wi.status IN ('pending', 'leased')
           AND wi.payload->>'sha256' = p_sha256
    ) THEN
        RETURN true;
    END IF;

    RETURN false;
END;
$$;

-- Phase 1 (Mark): transitions unreferenced, unheld blobs past >=24h grace to
-- reclaim_eligible, and reactivates any reclaim_eligible blob that gained a
-- live root, hold/WORM lock, or fresh touch.
CREATE OR REPLACE FUNCTION blob_gc_mark(
    p_grace_minutes integer DEFAULT 1440,
    p_worm_days     integer DEFAULT 0,
    p_batch_size    integer DEFAULT 500
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_grace       integer;
    v_limit       integer;
    v_marked      integer := 0;
    v_reactivated integer := 0;
    v_sha         text;
    v_row         RECORD;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'blob_gc_mark: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_worm_days IS NULL OR p_worm_days < 0 THEN
        RAISE EXCEPTION 'blob_gc_mark: p_worm_days must be non-negative'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"worm_days"}'::text;
    END IF;

    v_grace := GREATEST(COALESCE(p_grace_minutes, 1440), 1440);
    v_limit := LEAST(GREATEST(COALESCE(p_batch_size, 500), 1), 10000);

    -- A. Reactivate reclaim_eligible blobs that are now referenced, held, or freshly touched.
    FOR v_sha IN
        SELECT s.blob_sha256
          FROM public.blob_gc_state s
         WHERE s.gc_state = 'reclaim_eligible'
           AND (
               s.last_touched_at > now() - make_interval(mins => v_grace)
               OR public.blob_has_live_reference(s.blob_sha256)
               OR public.blob_is_held_or_retained(s.blob_sha256, p_worm_days)
           )
         ORDER BY s.reclaim_eligible_at ASC, s.blob_sha256 ASC
         LIMIT v_limit
         FOR UPDATE OF s SKIP LOCKED
    LOOP
        IF NOT pg_catalog.pg_try_advisory_xact_lock(public.blob_gc_lock_key(v_sha)) THEN
            CONTINUE;
        END IF;
        UPDATE public.blob_gc_state
           SET gc_state = 'active',
               reclaim_eligible_at = NULL,
               purging_at = NULL
         WHERE blob_sha256 = v_sha
           AND gc_state = 'reclaim_eligible';
        IF FOUND THEN
            v_reactivated := v_reactivated + 1;
        END IF;
    END LOOP;

    -- B. Mark unreferenced, unheld active canonical 64-hex blobs (including implicit
    -- active rows with no companion blob_gc_state row) past the >=24h grace floor.
    FOR v_row IN
        SELECT b.sha256,
               COALESCE(s.last_touched_at, b.created_at) AS eff_touched
          FROM public.blobs b
          LEFT JOIN public.blob_gc_state s ON s.blob_sha256 = b.sha256
         WHERE b.sha256 ~ '^[0-9a-f]{64}$'
           AND COALESCE(s.gc_state, 'active') = 'active'
           AND COALESCE(s.last_touched_at, b.created_at) <= now() - make_interval(mins => v_grace)
           AND NOT public.blob_has_live_reference(b.sha256)
           AND NOT public.blob_is_held_or_retained(b.sha256, p_worm_days)
         ORDER BY COALESCE(s.last_touched_at, b.created_at) ASC, b.sha256 ASC
         LIMIT v_limit
         FOR UPDATE OF b SKIP LOCKED
    LOOP
        IF NOT pg_catalog.pg_try_advisory_xact_lock(public.blob_gc_lock_key(v_row.sha256)) THEN
            CONTINUE;
        END IF;
        IF public.blob_has_live_reference(v_row.sha256)
           OR public.blob_is_held_or_retained(v_row.sha256, p_worm_days) THEN
            CONTINUE;
        END IF;

        INSERT INTO public.blob_gc_state (
            blob_sha256,
            gc_state,
            reclaim_eligible_at,
            purging_at,
            last_touched_at
        )
        VALUES (
            v_row.sha256,
            'reclaim_eligible',
            now(),
            NULL,
            v_row.eff_touched
        )
        ON CONFLICT (blob_sha256) DO UPDATE
            SET gc_state            = 'reclaim_eligible',
                reclaim_eligible_at = now(),
                purging_at          = NULL
          WHERE public.blob_gc_state.gc_state = 'active'
            AND public.blob_gc_state.last_touched_at <= now() - make_interval(mins => v_grace);

        IF FOUND THEN
            v_marked := v_marked + 1;
        END IF;
    END LOOP;

    RETURN jsonb_build_object(
        'marked_eligible', v_marked,
        'reactivated', v_reactivated,
        'effective_grace_minutes', v_grace
    );
END;
$$;

-- Phase 2 Tx 2A: acquires per-sha256 advisory lock, locks blobs + blob_gc_state
-- FOR UPDATE, re-verifies reclaim_eligible + grace + cooldown + zero live roots
-- + zero holds/WORM, and transitions to purging (or resets to active).
CREATE OR REPLACE FUNCTION blob_gc_claim_purging(
    p_sha256           text,
    p_grace_minutes    integer DEFAULT 1440,
    p_cooldown_minutes integer DEFAULT 1440,
    p_worm_days        integer DEFAULT 0
)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_grace    integer;
    v_cooldown integer;
    v_state    public.blob_gc_state%ROWTYPE;
    v_blob_sha text;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'blob_gc_claim_purging: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_sha256 IS NULL OR p_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'blob_gc_claim_purging: p_sha256 must be a lowercase 64-hex SHA-256'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"sha256"}'::text;
    END IF;
    IF p_worm_days IS NULL OR p_worm_days < 0 THEN
        RAISE EXCEPTION 'blob_gc_claim_purging: p_worm_days must be non-negative'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"worm_days"}'::text;
    END IF;
    IF p_cooldown_minutes IS NULL OR p_cooldown_minutes < 0 THEN
        RAISE EXCEPTION 'blob_gc_claim_purging: p_cooldown_minutes must be non-negative'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"cooldown_minutes"}'::text;
    END IF;

    v_grace := GREATEST(COALESCE(p_grace_minutes, 1440), 1440);
    v_cooldown := p_cooldown_minutes;

    PERFORM pg_catalog.pg_advisory_xact_lock(public.blob_gc_lock_key(p_sha256));

    SELECT sha256 INTO v_blob_sha
      FROM public.blobs
     WHERE sha256 = p_sha256
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'missing';
    END IF;

    SELECT * INTO v_state
      FROM public.blob_gc_state
     WHERE blob_sha256 = p_sha256
       FOR UPDATE;
    IF NOT FOUND OR v_state.gc_state <> 'reclaim_eligible' THEN
        RETURN 'skipped';
    END IF;

    IF v_state.last_touched_at > now() - make_interval(mins => v_grace)
       OR public.blob_has_live_reference(p_sha256)
       OR public.blob_is_held_or_retained(p_sha256, p_worm_days) THEN
        UPDATE public.blob_gc_state
           SET gc_state            = 'active',
               reclaim_eligible_at = NULL,
               purging_at          = NULL
         WHERE blob_sha256 = p_sha256;
        RETURN 'reactivated';
    END IF;

    IF v_state.reclaim_eligible_at > now() - make_interval(mins => v_cooldown) THEN
        RETURN 'cooldown';
    END IF;

    UPDATE public.blob_gc_state
       SET gc_state   = 'purging',
           purging_at = now()
     WHERE blob_sha256 = p_sha256;

    RETURN 'purging';
END;
$$;

-- Records an S3 Object Lock WORM horizon in blob_gc_state:
--   - Ordinary successful arming ('worm_put_apply', 'worm_arm_worker') logs
--     routine action 'blob_gc_worm_lock_armed' without firing an error alert.
--   - Denied GC DELETE 403 logs core action 'blob_gc_worm_lock_detected' and
--     reverts the blob to active so sweep never infinite-loops on WORM objects.
CREATE OR REPLACE FUNCTION blob_gc_record_worm_lock(
    p_sha256            text,
    p_worm_locked_until timestamptz,
    p_reason            text DEFAULT 's3_object_lock_403'
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_until  timestamptz;
    v_reason text;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'blob_gc_record_worm_lock: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_sha256 IS NULL OR p_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'blob_gc_record_worm_lock: p_sha256 must be a lowercase 64-hex SHA-256'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"sha256"}'::text;
    END IF;

    v_until := COALESCE(p_worm_locked_until, now() + interval '1 day');
    v_reason := COALESCE(p_reason, 's3_object_lock_403');

    PERFORM pg_catalog.pg_advisory_xact_lock(public.blob_gc_lock_key(p_sha256));

    IF NOT EXISTS (SELECT 1 FROM public.blobs WHERE sha256 = p_sha256) THEN
        RETURN false;
    END IF;

    INSERT INTO public.blob_gc_state (
        blob_sha256,
        gc_state,
        reclaim_eligible_at,
        purging_at,
        last_touched_at,
        worm_locked_until
    )
    VALUES (
        p_sha256,
        'active',
        NULL,
        NULL,
        now(),
        v_until
    )
    ON CONFLICT (blob_sha256) DO UPDATE
        SET gc_state            = 'active',
            reclaim_eligible_at = NULL,
            purging_at          = NULL,
            last_touched_at     = now(),
            worm_locked_until   = CASE
                WHEN public.blob_gc_state.worm_locked_until IS NULL THEN EXCLUDED.worm_locked_until
                ELSE GREATEST(public.blob_gc_state.worm_locked_until, EXCLUDED.worm_locked_until)
            END;

    IF v_reason IN ('worm_put_apply', 'worm_arm_worker') THEN
        PERFORM public.audit_write(
            NULL,
            'blob_gc_worm_lock_armed',
            'blob',
            NULL,
            NULL,
            jsonb_build_object(
                'sha256', p_sha256,
                'worm_locked_until', v_until,
                'reason', v_reason
            ),
            NULL,
            'Recorded S3 Object Lock WORM retention horizon in blob_gc_state',
            'core'
        );
    ELSE
        PERFORM public.audit_write(
            NULL,
            'blob_gc_worm_lock_detected',
            'blob',
            NULL,
            NULL,
            jsonb_build_object(
                'sha256', p_sha256,
                'worm_locked_until', v_until,
                'reason', v_reason
            ),
            NULL,
            'Blob GC Tx 2B encountered S3 Object Lock 403; reverted to active',
            'core'
        );
    END IF;

    RETURN true;
END;
$$;

-- Worker-only ACLs on all SECURITY INVOKER GC reducers (restated in
-- scripts/provision-roles.sql exact_worker so reprovisioning preserves them).
DO $$
DECLARE
    v_sig text;
BEGIN
    FOREACH v_sig IN ARRAY ARRAY[
        'public.blob_has_live_reference(text)',
        'public.blob_gc_live_sources(text)',
        'public.blob_is_held_or_retained(text,integer)',
        'public.blob_gc_mark(integer,integer,integer)',
        'public.blob_gc_claim_purging(text,integer,integer,integer)',
        'public.blob_gc_record_worm_lock(text,timestamptz,text)'
    ] LOOP
        IF to_regprocedure(v_sig) IS NOT NULL THEN
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', v_sig);
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
                EXECUTE format('REVOKE ALL ON FUNCTION %s FROM setjoin_app', v_sig);
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
                EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_worker', v_sig);
            END IF;
        END IF;
    END LOOP;
END
$$;
