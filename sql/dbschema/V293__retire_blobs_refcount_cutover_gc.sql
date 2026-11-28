-- V293__retire_blobs_refcount_cutover_gc.sql — Wave 2.4 (#551):
-- Cut over blob cleanup to Mark-and-Sweep GC under WorkerSupervisor, retire
-- public.blobs.ref_count triggers/column and public.blob_cleanup_queue, add
-- set-based owner-callable public.blob_live_catalog(), proactive purging_at
-- verification fencing (blob_gc_reactivate_v2), and durable staging promote
-- recovery (blob_promote_recover_enqueue / blob_promote_recover_complete).
--
-- ROLLING-UPGRADE & ROLLBACK BOUNDARY (ARCH-019):
--   Mandatory 2-step production rollout order:
--     Step 1: Run Wave 2.3 (#550) binaries on V292 with BLOB_GC_MODE=shadow
--             and verify zero shadow discrepancies.
--     Step 2: During cutover, drain all old / Wave 2.3 replicas and in-flight
--             legacy deletes, apply V293 (which flips public.blob_gc_config.mode
--             = 'live' and contracts public.blobs.ref_count +
--             public.blob_cleanup_queue past the reversible schema boundary),
--             and start Wave 2.4 (#551) binaries with BLOB_GC_MODE unset or live.
--   Emergency halt after V293: set BLOB_GC_MODE=off (halts live sweeping
--   immediately without re-enabling legacy ref_count cleanup).
--
-- Invariants preserved:
--   - V235 per-user storage accounting (blob_user_charges / blob_user_usage /
--     trg_blob_user_charge_inc / trg_blob_user_charge_dec) stays 100% INTACT.
--   - V114 Drive chunk ref_count triggers (trg_drive_chunk_zero_ref) stay INTACT.
--   - public.feature_toggles stays 100% UNCHANGED (zero new rows).
--   - Executes cleanly under both superuser and non-superuser setjoin_owner
--     (NOBYPASSRLS) with zero other_secdef_drifted rows.

-- ── 1. Retire the 6 blobs.ref_count / blob_cleanup_queue triggers & functions ─

DROP TRIGGER IF EXISTS attachment_blob_refcount ON public.message_attachments;
DROP TRIGGER IF EXISTS attachment_blob_refcount_inc ON public.message_attachments;
DROP TRIGGER IF EXISTS blob_refcount_cleanup ON public.blobs;
DROP TRIGGER IF EXISTS trg_hr_expense_receipts_inc ON public.hr_expense_receipts;
DROP TRIGGER IF EXISTS trg_hr_expense_receipts_dec ON public.hr_expense_receipts;
DROP TRIGGER IF EXISTS chat_link_preview_blob_refcount ON public.chat_link_previews;

DROP FUNCTION IF EXISTS public.trg_attachment_deleted();
DROP FUNCTION IF EXISTS public.trg_attachment_inserted();
DROP FUNCTION IF EXISTS public.trg_blob_refcount_zero();
DROP FUNCTION IF EXISTS public.trg_hr_receipt_ref_inc();
DROP FUNCTION IF EXISTS public.trg_hr_receipt_ref_dec();
DROP FUNCTION IF EXISTS public.trg_chat_link_preview_deleted();

-- Retire shadow reconciliation reducer (referenced dropped blobs.ref_count) and
-- drop the 7-arg blob_upload_account signature before replacing with the 8-arg
-- default-compatible signature (avoiding ambiguous overloads).
DROP FUNCTION IF EXISTS public.blob_gc_shadow_reconcile(integer, integer, integer);
DROP FUNCTION IF EXISTS public.blob_upload_account(bigint, text, text, bigint, text, integer, bigint);
DROP FUNCTION IF EXISTS public.mail_recovery_upload_item_verify(bigint, uuid, text, text);

-- ── 2. Contract public.blobs.ref_count & public.blob_cleanup_queue ───────────

ALTER TABLE public.blobs DROP COLUMN IF EXISTS ref_count;
DROP TABLE IF EXISTS public.blob_cleanup_queue;

-- ── 3. Flip public.blob_gc_config.mode -> 'live' (setjoin_owner NOBYPASSRLS safe) ─
-- Table owner uses NO FORCE ROW LEVEL SECURITY (keeping RLS enabled for all
-- non-owner roles) so UPDATE succeeds under non-superuser setjoin_owner, then
-- restores FORCE ROW LEVEL SECURITY immediately after verifying ROW_COUNT = 1.

ALTER TABLE public.blob_gc_config NO FORCE ROW LEVEL SECURITY;

DO $$
DECLARE
    v_updated integer := 0;
BEGIN
    UPDATE public.blob_gc_config
       SET mode       = 'live',
           updated_at = now()
     WHERE id = 1;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    IF v_updated <> 1 THEN
        RAISE EXCEPTION 'V293: expected to update 1 blob_gc_config row to mode=live, updated %', v_updated;
    END IF;
END
$$;

ALTER TABLE public.blob_gc_config FORCE ROW LEVEL SECURITY;

-- ── 4. Embedded canonical reducers (byte-identical to reducers/ for mailctl schema apply) ─

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
-- Signature intentionally unchanged across V292->V293 (zero ACL churn).
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
-- 1:1 (enforced bidirectionally by scripts/guards/check-blob-reference-manifest.py)
-- and preserve exact predicate parity with partial btree indexes from V292.
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

-- PG 15+ owner-safe transient CREATE grant on schema public around legacy
-- apply_worker_ownership() calls in chat_unfurl.sql and
-- mail_recovery_artifact_ingest.sql so non-superuser setjoin_owner upgrades cleanly.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker')
       AND NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
        GRANT CREATE ON SCHEMA public TO setjoin_worker;
        PERFORM set_config('app._v293_granted_worker_create', '1', false);
    END IF;
END
$$;

-- chat_unfurl.sql: link-unfurl cache + message-payload merge (Pillar A3 QoL
-- Task 13 — full unfurl with images, SSRF-hardened at the Go fetch layer,
-- internal/chat/unfurl.go).
--
-- chat_link_previews (V122 §E) is a global url_hash-keyed cache with FORCE
-- RLS and ZERO policies — deny-all even to a function's own owner unless
-- that owner is a BYPASSRLS role (the V114/chat_space_ensure precedent:
-- SECURITY DEFINER alone is not enough — the FUNCTION OWNER is what native
-- RLS actually checks, so every reducer here that touches chat_link_previews
-- is SECURITY DEFINER + apply_worker_ownership). This is a worker/background
-- cache, never an interactive p_user_id-authorized user action — there is no
-- membership or ownership concept for a URL.
--
-- Claim/fetch/apply is a three-step protocol so two concurrent posts of the
-- SAME url only ever fetch it once (URL possession is the capability, per
-- the plan's grill-decided shared-cache posture — the cache itself carries
-- no per-user scope):
--   1. chat_link_preview_claim — the Go worker calls this FIRST for a fresh
--      url_hash; only the caller whose INSERT actually lands (ON CONFLICT DO
--      NOTHING) goes on to fetch. Everyone else calls chat_link_preview_lookup
--      instead — if status='ok', they apply the already-cached result to
--      their OWN message without fetching anything.
--   2. chat_link_preview_cache_write — the claim-winner calls this EXACTLY
--      ONCE after fetching (the gateway has already PUT the image bytes and
--      registered the blobs row via blob_gc_register_and_reactivate by this
--      point), to record the final ok/error state and reactivate the image
--      blob under Mark-and-Sweep GC (chat_link_previews.image_blob_sha256 is
--      an authoritative live root; legacy blobs.ref_count was retired in V293).
--   3. chat_message_unfurl_apply — merges the cached preview into ONE
--      message's payload + fans out a message_edited-style notify. Called by
--      both the claim-winner (after cache_write) and every subsequent poster
--      of an already-cached URL (skipping steps 1+2 entirely).
--
-- ponytail: a caller that finds the cache row status='pending' (someone
-- else's fetch is still in flight, or a prior fetch crashed before writing a
-- result) does nothing — no retry, no queueing. The TTL eviction worker leg
-- (internal/chat, ~14d) reaps a stuck pending row same as any other, so a
-- later post of the same URL gets to re-claim and retry. Good enough for a
-- best-effort v1 enrichment; a retry queue is not built.
--
-- No new BZ code: the plan's Global Constraints allocate BZ176-179 to Tasks
-- 3/6/9/2 only. Every failure mode here (fetch denied, oversized, wrong
-- content-type, stuck pending, message soft-deleted/gone) degrades silently
-- — unfurl is best-effort enrichment, never a blocking part of send, so
-- nothing here ever RAISEs.
--
-- ── Metadata bound (occ_980dba9c476e43f3e6d8ef7e —
-- unfurl-unbounded-title-description) ────────────────────────────────────────
-- og:title / og:description are parsed from attacker-controlled page bytes
-- (up to maxHTMLBytes = 2 MiB of HTML) and V122 types both columns as
-- unbounded text, so without a bound the fetch path could persist megabytes
-- of third-party junk per URL and duplicate it into chat_messages.payload
-- via chat_message_unfurl_apply. The bound is a state invariant on the write
-- path this file owns (chat_link_previews is FORCE RLS deny-all; every write
-- is chat_link_preview_cache_write), expressed as truncation-with-marker —
-- NOT a CHECK, because a CHECK would fail the whole cache write (RAISE) and
-- this file's settled posture is silent degradation, never a blocked fetch.
-- chat_unfurl_bound_text truncates to the character cap and marks the
-- truncation with a trailing ellipsis occupying the cap's final character, so
-- the stored value is always ≤ the cap and visibly marked. Both writers bound:
-- cache_write at ingress (caps 512 title / 1024 description characters) and
-- chat_message_unfurl_apply at the payload merge (same caps — idempotent on
-- already-bounded values, so pre-bound legacy cache rows are bounded at
-- duplication too). The Go fetch path mirrors the same caps in
-- internal/chat/unfurl.go (boundUnfurlText) before it ever calls cache_write.

CREATE OR REPLACE FUNCTION chat_unfurl_bound_text(p_text text, p_max_chars integer) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
BEGIN
    IF char_length(p_text) <= p_max_chars THEN
        RETURN p_text; -- at-cap and under-cap values pass through unmarked
    END IF;
    -- The ellipsis occupies the cap's final character: the result is always
    -- exactly p_max_chars characters (never exceeds the bound) and visibly
    -- marked as truncated.
    RETURN left(p_text, p_max_chars - 1) || '…';
END;
$$;

CREATE OR REPLACE FUNCTION chat_link_preview_claim(p_url_hash text, p_url text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    INSERT INTO chat_link_previews (url_hash, url, status)
      VALUES (p_url_hash, p_url, 'pending')
      ON CONFLICT (url_hash) DO NOTHING;
    RETURN FOUND;
END;
$$;
SELECT apply_worker_ownership('chat_link_preview_claim(text,text)'::regprocedure);

CREATE OR REPLACE FUNCTION chat_link_preview_lookup(p_url_hash text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = pg_catalog, public AS $$
DECLARE
    v_row chat_link_previews;
BEGIN
    SELECT * INTO v_row FROM chat_link_previews WHERE url_hash = p_url_hash;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    RETURN jsonb_build_object(
      'status', v_row.status, 'url', v_row.url, 'title', v_row.title,
      'description', v_row.description, 'imageBlobSha256', v_row.image_blob_sha256);
END;
$$;
SELECT apply_worker_ownership('chat_link_preview_lookup(text)'::regprocedure);

CREATE OR REPLACE FUNCTION chat_link_preview_cache_write(
    p_url_hash text, p_title text, p_description text,
    p_image_blob_sha256 text, p_status text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    -- Metadata bound (occ_980dba9c476e43f3e6d8ef7e): the fetched page is
    -- attacker-controlled, so title/description are truncated-with-marker to
    -- this file's caps at the only write path before they can reach
    -- chat_link_previews (and from there chat_messages.payload). See the file
    -- header's "Metadata bound" section.
    UPDATE chat_link_previews
       SET title = chat_unfurl_bound_text(p_title, 512),
           description = chat_unfurl_bound_text(p_description, 1024),
           image_blob_sha256 = p_image_blob_sha256, status = p_status,
           fetched_at = now()
     WHERE url_hash = p_url_hash;
END;
$$;
SELECT apply_worker_ownership('chat_link_preview_cache_write(text,text,text,text,text)'::regprocedure);

CREATE OR REPLACE FUNCTION chat_message_unfurl_apply(p_message_id bigint, p_url_hash text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_channel_id bigint;
    v_preview    chat_link_previews;
BEGIN
    SELECT * INTO v_preview FROM chat_link_previews WHERE url_hash = p_url_hash AND status = 'ok';
    IF NOT FOUND THEN
        RETURN; -- no cached success yet (pending/error/never-fetched) — no-op
    END IF;

    -- Trusted-preview provenance (med-chat-unfurl-href-001): reduce-time
    -- scheme allowlist — the anchor href this merge produces may only ever be
    -- http(s); javascript:, data:, scheme-less/relative and malformed URLs
    -- never reach the trusted enrichment chrome. Primary gates live at the Go
    -- fetch layer and at chat_message_send (sender-supplied previews are
    -- stripped outright); this is the belt-and-braces check on the cache row
    -- itself, failing closed as a silent no-op like every other guard in this
    -- file — never a RAISE.
    --
    -- Provenance epoch marker (r2): every preview this function merges carries
    -- 'appliedBy' => 'chat_message_unfurl_apply' — the ONLY field combination
    -- the renderer trusts. Pre-fix stored rows (a forged HTTPS card smuggled
    -- in before chat_message_send stripped payload.preview, and genuine
    -- reducer-written rows alike) carry no marker and provenance is not
    -- retroactively client-verifiable, so they fail closed at render: no
    -- card. Going forward send-time stripping keeps the attacker out of
    -- payload.preview entirely, so the marker cannot be forged through any
    -- reducer path (chat_message_edit writes body only).
    IF v_preview.url IS NULL OR v_preview.url !~* '^https?://\S+$' THEN
        RETURN;
    END IF;

    SELECT channel_id INTO v_channel_id FROM chat_messages
     WHERE id = p_message_id AND deleted_at IS NULL;
    IF v_channel_id IS NULL THEN
        RETURN; -- message gone/soft-deleted by the time the fetch completed
    END IF;

    -- Chat A4a Task 8 / spec-delta 5: payload is EXEMPT from the WORM trigger
    -- (pin/poll counters need it to stay writable), and unfurl COPIES
    -- third-party title/description text into it — so without this skip, a
    -- content-bearing column would be freely mutable in an "immutable"
    -- channel and the product's own claim ("messages cannot be edited or
    -- deleted") would be false. Not fetching on behalf of a records channel
    -- is also the right compliance posture, so this is a silent no-op, not
    -- a raised error — same best-effort-enrichment posture as every other
    -- guard in this file.
    IF (SELECT classification FROM chat_channels WHERE id = v_channel_id) = 'gxp' THEN
        RETURN;
    END IF;

    -- Second bound half (occ_980dba9c476e43f3e6d8ef7e): the payload merge
    -- re-applies the same caps as cache_write, so rows cached before the bound
    -- landed (or any future unbounded writer) are still bounded at the moment
    -- their metadata duplicates into chat_messages.payload. Idempotent on
    -- already-bounded values.
    UPDATE chat_messages
       SET payload = COALESCE(payload, '{}'::jsonb) || jsonb_build_object('preview',
             jsonb_build_object('url', v_preview.url, 'title', chat_unfurl_bound_text(v_preview.title, 512),
               'description', chat_unfurl_bound_text(v_preview.description, 1024), 'imageSha256', v_preview.image_blob_sha256,
               'appliedBy', 'chat_message_unfurl_apply'))
     WHERE id = p_message_id;

    -- ponytail: no change_seq bump (same write-amplification ceiling as poll
    -- votes, chat_poll.sql) — this is async metadata enrichment arriving
    -- after the message already replayed once, not a user-visible edit; a
    -- client that missed the live push heals on its next normal fetch/
    -- re-open of the channel, not via since(seq) replay.
    PERFORM notify_chat_state(v_channel_id, 'message_edited', p_message_id, NULL);
END;
$$;
SELECT apply_worker_ownership('chat_message_unfurl_apply(bigint,text)'::regprocedure);

-- chat_link_preview_image_owner: the authorization boundary for the image-
-- serving route (GET /chat/unfurl/image/{sha256}, internal/chat/unfurl.go).
-- blobs is a GLOBAL content-addressed table shared with mail attachments/
-- Drive/HR receipts — without this check, the route would be an oracle for
-- ANY blob's bytes+content-type given its bare sha256, not just unfurl
-- images. Only a sha256 actually cached as a successful unfurl image is
-- servable.
CREATE OR REPLACE FUNCTION chat_link_preview_image_owner(p_sha256 text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = pg_catalog, public AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM chat_link_previews
                    WHERE image_blob_sha256 = p_sha256 AND status = 'ok');
END;
$$;
SELECT apply_worker_ownership('chat_link_preview_image_owner(text)'::regprocedure);

CREATE OR REPLACE FUNCTION mail_recovery_artifact_ingest(
    p_actor_user_id bigint,
    p_quarantine_id uuid,
    p_resolution text,
    p_reason text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    v_artifact mail_recovery_quarantine_artifacts%ROWTYPE;
    v_incident mail_recovery_incidents%ROWTYPE;
    v_existing mail_recovery_ledger%ROWTYPE;
    v_inbox_id bigint;
    v_recovered_tag_id bigint;
    v_message_id bigint;
    v_received_at timestamptz;
    v_message_header text;
    v_from_addr text;
    v_thread_id text;
    v_blob jsonb;
    v_blob_count integer:=0;
    v_total_size bigint;
BEGIN
    IF NOT mail_recovery_feature_enabled() OR NOT mail_recovery_has_global_permission(p_actor_user_id) THEN
        RAISE EXCEPTION 'global system.recovery permission and enabled intake are required'
            USING ERRCODE='BZ003',HINT='{"type":"forbidden"}';
    END IF;
    IF p_quarantine_id IS NULL OR p_resolution NOT IN ('accept','accept_fork') OR
       length(btrim(COALESCE(p_reason,''))) NOT BETWEEN 8 AND 1024 OR p_reason~'[\r\n]' THEN
        RAISE EXCEPTION 'invalid recovery ingestion request'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    SELECT * INTO STRICT v_artifact FROM mail_recovery_quarantine_artifacts
     WHERE id=p_quarantine_id FOR UPDATE;
    SELECT * INTO STRICT v_incident FROM mail_recovery_incidents
     WHERE id=v_artifact.incident_id FOR SHARE;
    SELECT * INTO v_existing FROM mail_recovery_ledger
     WHERE artifact_identity=v_artifact.artifact_identity;
    IF FOUND THEN
        RETURN jsonb_build_object('id',p_quarantine_id,'status',v_existing.outcome,
                                  'messageId',CASE WHEN v_existing.recovered_message_id IS NULL THEN NULL
                                                   ELSE v_existing.recovered_message_id::text END,'replayed',true);
    END IF;
    IF v_incident.status<>'open' OR v_incident.expires_at<=statement_timestamp() OR
       (v_incident.approval_required AND v_incident.approved_by IS NULL) OR
       v_artifact.malware_status<>'clean' OR
       v_artifact.status NOT IN ('quarantined','fork_conflict') OR
       NOT EXISTS(SELECT 1 FROM mail_recovery_incident_accounts account
                   WHERE account.incident_id=v_incident.id AND account.mailbox_id=v_artifact.mailbox_id) OR
       NOT EXISTS(SELECT 1 FROM mailboxes mailbox JOIN users affected ON affected.id=mailbox.user_id
                   WHERE mailbox.id=v_artifact.mailbox_id AND mailbox.enabled AND affected.enabled) THEN
        RAISE EXCEPTION 'recovery artifact is not eligible for ingestion'
            USING ERRCODE='BZ002',HINT='{"type":"state_mismatch"}';
    END IF;
    IF v_artifact.status='fork_conflict' AND
       (p_resolution<>'accept_fork' OR v_artifact.fork_consented_by IS NULL OR v_artifact.fork_consented_at IS NULL) THEN
        RAISE EXCEPTION 'fork recovery requires explicit affected-user consent and admin resolution'
            USING ERRCODE='BZ003',HINT='{"type":"fork_consent_required"}';
    END IF;

    v_message_header:=COALESCE(NULLIF(v_artifact.parsed_headers->>'messageId',''),
                               '<recovered-'||encode(v_artifact.artifact_identity,'hex')||'@setjoin.invalid>');
    v_from_addr:=NULLIF(v_artifact.parsed_headers->>'fromAddr','');
    IF v_from_addr IS NULL OR octet_length(v_from_addr)>320 OR
       octet_length(v_message_header)>998 OR
       jsonb_typeof(COALESCE(v_artifact.parsed_headers->'toAddrs','[]'::jsonb))<>'array' OR
       jsonb_typeof(COALESCE(v_artifact.parsed_headers->'ccAddrs','[]'::jsonb))<>'array' OR
       jsonb_typeof(COALESCE(v_artifact.parsed_headers->'bccAddrs','[]'::jsonb))<>'array' THEN
        RAISE EXCEPTION 'recovery MIME metadata is invalid'
            USING ERRCODE='BZ251',HINT='{"type":"malformed_message"}';
    END IF;
    BEGIN
        v_received_at:=COALESCE((v_artifact.parsed_headers->>'receivedAt')::timestamptz,statement_timestamp());
    EXCEPTION WHEN OTHERS THEN
        v_received_at:=statement_timestamp();
    END;
    IF v_received_at>statement_timestamp()+interval '5 minutes' OR
       v_received_at<statement_timestamp()-interval '20 years' THEN
        v_received_at:=statement_timestamp();
    END IF;
    v_total_size:=v_artifact.raw_mime_size+
        COALESCE((SELECT sum((blob->>'size')::bigint)
                   FROM jsonb_array_elements(v_artifact.blob_inventory) blob),0);
    IF NOT check_quota(v_artifact.mailbox_id,v_total_size) THEN
        RAISE EXCEPTION 'mailbox over quota'
            USING ERRCODE='BZ001',HINT='{"type":"over_quota"}';
    END IF;
    v_inbox_id:=get_tag_id('Inbox',v_artifact.mailbox_id);
    IF v_inbox_id IS NULL THEN
        RAISE EXCEPTION 'recovery mailbox has no Inbox tag'
            USING ERRCODE='BZ008',HINT='{"type":"missing_inbox"}';
    END IF;
    INSERT INTO tags(mailbox_id,name,color,icon,sort_order,tag_type,is_default,imap_expose,imap_name)
    VALUES(v_artifact.mailbox_id,'Recovered from device','#b45309','history',900,'user',false,true,'Recovered from device')
    ON CONFLICT(mailbox_id,name) DO NOTHING;
    SELECT id INTO STRICT v_recovered_tag_id FROM tags
     WHERE mailbox_id=v_artifact.mailbox_id AND name='Recovered from device';
    v_thread_id:=compute_thread_id(v_message_header,v_artifact.parsed_headers->>'inReplyTo',
                                   v_artifact.parsed_headers->>'references',v_artifact.mailbox_id);

    INSERT INTO messages(
        mailbox_id,folder_id,message_id,subject,from_addr,from_name,to_addrs,cc_addrs,bcc_addrs,
        in_reply_to,references_hdr,body_text,body_html,size_bytes,has_attachments,is_read,is_flagged,
        is_draft,raw_ref,thread_id,imap_uid,received_at,sent_at,spf_result,dkim_result,dmarc_result,
        spam_headers,is_external
    ) VALUES(
        v_artifact.mailbox_id,v_inbox_id,v_message_header,v_artifact.parsed_headers->>'subject',v_from_addr,
        v_artifact.parsed_headers->>'fromName',COALESCE(v_artifact.parsed_headers->'toAddrs','[]'::jsonb),
        COALESCE(v_artifact.parsed_headers->'ccAddrs','[]'::jsonb),COALESCE(v_artifact.parsed_headers->'bccAddrs','[]'::jsonb),
        v_artifact.parsed_headers->>'inReplyTo',v_artifact.parsed_headers->>'references',
        left(COALESCE(v_artifact.parsed_headers->>'bodyText',''),65536),
        left(COALESCE(v_artifact.parsed_headers->>'bodyHtml',''),65536),v_artifact.raw_mime_size,
        jsonb_array_length(v_artifact.blob_inventory)>0,false,false,false,v_artifact.raw_ref,v_thread_id,
        next_imap_uid_for_tag(v_inbox_id),v_received_at,
        CASE WHEN v_artifact.parsed_headers->>'eligibility'='sent-terminal' THEN v_received_at ELSE NULL END,
        NULL,NULL,NULL,jsonb_build_object('recoveryProvenance',jsonb_build_object(
            'incidentId',v_artifact.incident_id,'artifactIdentity',encode(v_artifact.artifact_identity,'hex'),
            'sourceTimeline',v_artifact.signed_timeline::text,'sourceBootEpoch',v_artifact.signed_boot_epoch,
            'deviceId',v_artifact.device_id,'authenticationResultsPreserved',false)),false
    ) RETURNING id INTO v_message_id;
    PERFORM tag_message(v_message_id,v_received_at,'Inbox',v_artifact.mailbox_id,'recovery',true);
    PERFORM tag_message(v_message_id,v_received_at,'Recovered from device',v_artifact.mailbox_id,'recovery',false);

    FOR v_blob IN SELECT blob FROM jsonb_array_elements(v_artifact.blob_inventory) blob LOOP
        IF v_blob->>'sha256'!~'^[0-9a-f]{64}$' OR v_blob->>'objectRef'<>v_blob->>'sha256' OR
           v_blob->>'role' NOT IN ('attachment','inline') OR v_blob->>'size'!~'^[1-9][0-9]{0,18}$' THEN
            RAISE EXCEPTION 'recovery blob inventory is invalid'
                USING ERRCODE='BZ251',HINT='{"type":"continuity_receipt_invalid"}';
        END IF;
        INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type)
        VALUES(v_blob->>'sha256',v_blob->>'objectRef',(v_blob->>'size')::bigint,'application/octet-stream')
        ON CONFLICT(sha256) DO NOTHING;
        IF NOT EXISTS(
            SELECT 1 FROM blobs
             WHERE sha256=v_blob->>'sha256'
               AND minio_ref=v_blob->>'objectRef'
               AND size_bytes=(v_blob->>'size')::bigint
        ) THEN
            RAISE EXCEPTION 'recovery blob conflicts with existing content address'
                USING ERRCODE='BZ251',HINT='{"type":"continuity_blob_conflict"}';
        END IF;
        INSERT INTO message_attachments(message_id,received_at,blob_sha256,filename,content_type,disposition,size_bytes)
        VALUES(v_message_id,v_received_at,v_blob->>'sha256',left(v_blob->>'blobId',255),'application/octet-stream',
               v_blob->>'role',(v_blob->>'size')::bigint);
        v_blob_count:=v_blob_count+1;
    END LOOP;

    INSERT INTO mail_recovery_ledger(
        artifact_identity,incident_id,mailbox_id,quarantine_id,outcome,recovered_message_id,recovered_received_at
    ) VALUES(v_artifact.artifact_identity,v_artifact.incident_id,v_artifact.mailbox_id,v_artifact.id,
             'accepted',v_message_id,v_received_at);
    UPDATE mail_recovery_quarantine_artifacts
       SET status='accepted',terminal_at=statement_timestamp(),rejection_reason=NULL
     WHERE id=v_artifact.id;
    PERFORM notify_state_change(v_artifact.mailbox_id,v_inbox_id,v_message_id,'created');
    PERFORM audit_write(p_actor_user_id,'mail_recovery_artifact_accept','mail_recovery_artifact',v_message_id,NULL,
        jsonb_build_object('incidentId',v_artifact.incident_id,'quarantineId',v_artifact.id,
                           'mailboxId',v_artifact.mailbox_id::text,
                           'artifactIdentity',encode(v_artifact.artifact_identity,'hex'),
                           'blobCount',v_blob_count,'resolution',p_resolution,'reason',btrim(p_reason)),
        NULL,NULL,'core');
    PERFORM app_notify('mail_recovery_incident_changed',jsonb_build_object(
        'incident_id',v_artifact.incident_id,'status','accepted','message_id',v_message_id)::text);
    RETURN jsonb_build_object('id',v_artifact.id,'status','accepted','messageId',v_message_id::text,
                              'receivedAt',v_received_at,'replayed',false);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_artifact_ingest(bigint,uuid,text,text) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION mail_recovery_artifact_ingest(bigint,uuid,text,text) TO setjoin_worker;
    END IF;
END $$;
SELECT apply_worker_ownership('mail_recovery_artifact_ingest(bigint,uuid,text,text)'::regprocedure);

CREATE OR REPLACE FUNCTION upgrade_recovery_context_read(
    p_actor BIGINT
) RETURNS JSONB
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_control upgrade_control_state%ROWTYPE;
    v_schema INTEGER;
    v_users BIGINT;
    v_mailboxes BIGINT;
    v_blobs BIGINT;
    v_blob_bytes BIGINT;
    v_representative_ids JSONB;
BEGIN
    IF NOT upgrade_actor_authorized(p_actor) THEN
        RAISE EXCEPTION 'global system.upgrade authority is required'
            USING ERRCODE='BZ250',HINT='{"type":"upgrade_authorization_invalid"}';
    END IF;
    SELECT * INTO STRICT v_control FROM upgrade_control_state WHERE singleton;
    SELECT COALESCE(max(version),0) INTO v_schema FROM schema_migrations;
    SELECT count(*) INTO v_users FROM users;
    SELECT count(*) INTO v_mailboxes FROM mailboxes;
    SELECT count(*),COALESCE(sum(size_bytes),0) INTO v_blobs,v_blob_bytes
      FROM public.blob_live_catalog();
    SELECT COALESCE(jsonb_agg(candidate ORDER BY candidate),'[]'::jsonb)
      INTO v_representative_ids
      FROM (
        (SELECT 'user:'||id::text AS candidate FROM users ORDER BY id LIMIT 4)
        UNION ALL
        (SELECT 'mailbox:'||id::text FROM mailboxes ORDER BY id LIMIT 4)
        UNION ALL
        (SELECT 'blob:'||sha256 FROM public.blob_live_catalog() ORDER BY sha256 LIMIT 4)
      ) sample;
    RETURN jsonb_build_object(
        'installationId',v_control.installation_id::text,
        'timelineId',v_control.timeline_id::text,
        'schemaVersion',v_schema,
        'counts',jsonb_build_object(
            'users',v_users,'mailboxes',v_mailboxes,
            'blobs',v_blobs,'blobBytes',v_blob_bytes
        ),
        'representativeIds',v_representative_ids
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_recovery_context_read(bigint)'::regprocedure,true,false
);

-- ── 4f. mail_recovery_upload_item_verify.sql (verbatim) ───────────────────────

CREATE OR REPLACE FUNCTION mail_recovery_upload_item_verify(
    p_user_id bigint,
    p_session_id uuid,
    p_item_id text,
    p_object_ref text,
    p_staging_key text DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_item mail_recovery_upload_items%ROWTYPE;
BEGIN
    IF p_user_id IS NULL OR p_session_id IS NULL OR p_item_id IS NULL OR p_object_ref!~'^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid recovery item verification'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM mail_recovery_upload_sessions session
                   WHERE session.id=p_session_id AND session.uploading_user_id=p_user_id
                     AND session.status='uploading' AND session.expires_at>statement_timestamp()) THEN
        RAISE EXCEPTION 'recovery upload session is unavailable'
            USING ERRCODE='BZ002',HINT='{"type":"state_mismatch"}';
    END IF;
    SELECT * INTO STRICT v_item FROM mail_recovery_upload_items
     WHERE session_id=p_session_id AND item_id=p_item_id FOR UPDATE;
    IF v_item.status='verified' THEN
        IF v_item.object_ref=p_object_ref THEN
            RETURN jsonb_build_object('itemId',p_item_id,'status','verified','replayed',true);
        END IF;
        RAISE EXCEPTION 'verified recovery item differs'
            USING ERRCODE='BZ251',HINT='{"type":"continuity_chunk_mismatch"}';
    END IF;
    IF v_item.next_offset<>v_item.declared_size OR encode(v_item.sha256,'hex')<>p_object_ref THEN
        RAISE EXCEPTION 'recovery item is incomplete or digest differs'
            USING ERRCODE='BZ251',HINT='{"type":"continuity_chunk_mismatch"}';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(public.blob_gc_lock_key(p_object_ref));
    UPDATE mail_recovery_upload_items SET status='verified',object_ref=p_object_ref
     WHERE session_id=p_session_id AND item_id=p_item_id;
    PERFORM public.blob_gc_reactivate_v2(p_object_ref, p_staging_key);
    RETURN jsonb_build_object('itemId',p_item_id,'status','verified','replayed',false);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_upload_item_verify(bigint,uuid,text,text,text) FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION mail_recovery_upload_item_verify(bigint,uuid,text,text,text) TO setjoin_worker;
    END IF;
END
$$;
SELECT apply_worker_ownership('mail_recovery_upload_item_verify(bigint,uuid,text,text,text)'::regprocedure);

-- ── 4g. import_export.sql::import_message (verbatim) ──────────────────────────

CREATE OR REPLACE FUNCTION import_message(
  p_mailbox_id     BIGINT,
  p_tag_id         BIGINT,        -- NULL = Inbox tag
  p_message_id     TEXT,
  p_subject        TEXT,
  p_from_addr      TEXT,
  p_from_name      TEXT,
  p_to_addrs       JSONB,
  p_cc_addrs       JSONB,
  p_bcc_addrs      JSONB,
  p_in_reply_to    TEXT,
  p_references_hdr TEXT,
  p_body_text      TEXT,
  p_body_html      TEXT,
  p_size_bytes     BIGINT,
  p_is_read        BOOL,
  p_is_flagged     BOOL,
  p_raw_ref        TEXT,
  p_date           TIMESTAMPTZ,   -- NULL = now()
  p_user_id        BIGINT DEFAULT NULL,  -- vestigial, never passed; signature stability only
  p_list_id        TEXT DEFAULT NULL,
  p_actor_id       BIGINT DEFAULT NULL,  -- NULL = system path (migration) → skip predicate
  p_domain_scope   BIGINT DEFAULT NULL   -- caller's admin domain scope (0/NULL = none)
) RETURNS BIGINT AS $$
DECLARE
  v_tag_id      BIGINT;
  v_tag_name    TEXT;
  v_thread_id   TEXT;
  v_imap_uid    BIGINT;
  v_message_id  BIGINT;
BEGIN
  -- 1. Resolve tag (default to Inbox). A supplied tag id MUST belong to the target
  -- mailbox: this runs on the BYPASSRLS worker pool, so an unowned tag id would
  -- otherwise write messages.folder_id pointing at another mailbox's tag (a
  -- cross-mailbox trust-boundary leak inside the privileged reducer).
  IF p_tag_id IS NOT NULL THEN
    v_tag_id := p_tag_id;
    SELECT name INTO v_tag_name FROM tags WHERE id = v_tag_id AND mailbox_id = p_mailbox_id;
    IF v_tag_name IS NULL THEN
      RAISE EXCEPTION 'Tag % does not belong to mailbox %', v_tag_id, p_mailbox_id
        USING ERRCODE = 'BZ002', HINT = jsonb_build_object('type', 'forbidden', 'mailbox_id', p_mailbox_id)::TEXT;
    END IF;
  ELSE
    v_tag_id := get_tag_id('Inbox', p_mailbox_id);
    v_tag_name := 'Inbox';
    IF v_tag_id IS NULL THEN
      RAISE EXCEPTION 'Mailbox has no Inbox tag'
        USING ERRCODE = 'BZ008', HINT = jsonb_build_object('type', 'missing_inbox', 'mailbox_id', p_mailbox_id)::TEXT;
    END IF;
  END IF;

  -- 2. Threading
  v_thread_id := compute_thread_id(p_message_id, p_in_reply_to, p_references_hdr, p_mailbox_id);

  -- 3. IMAP UID (tag-based)
  v_imap_uid := next_imap_uid_for_tag(v_tag_id);

  -- 3a. Quota enforcement
  IF NOT check_quota(p_mailbox_id, p_size_bytes) THEN
    RAISE EXCEPTION 'Mailbox over quota'
      USING ERRCODE = 'BZ001', HINT = jsonb_build_object('type', 'over_quota', 'mailbox_id', p_mailbox_id)::TEXT;
  END IF;

  -- 3b. Serialize with Mark-and-Sweep GC / orphan cleanup (#551) in the same
  -- transaction that inserts the message row (holding the lock through COMMIT).
  IF p_raw_ref IS NOT NULL AND p_raw_ref <> '' AND p_raw_ref !~ E'[\r\n]' THEN
    PERFORM pg_catalog.pg_advisory_xact_lock(public.blob_gc_lock_key(p_raw_ref));
  END IF;

  -- 4. Insert message — statement-level authorization lives in this SELECT's
  -- WHERE (round 3/4): the actor claims ride INTO the reducer so authority is
  -- re-resolved LIVE at INSERT time, not at the route seam. p_actor_id IS NULL
  -- is the system path (migration orchestration — no human actor) and skips
  -- the predicate; actor 0 (unauthenticated fallback) matches no assignment
  -- and fails closed. A revocation during a slow upload inserts ZERO rows,
  -- RETURNING yields nothing, v_message_id stays NULL, and the caller reports
  -- the message failed — it is never inserted on stale authority.
  INSERT INTO messages (
    mailbox_id, folder_id,
    message_id, subject, from_addr, from_name,
    to_addrs, cc_addrs, bcc_addrs,
    in_reply_to, references_hdr,
    body_text, body_html,
    size_bytes, is_read, is_flagged,
    raw_ref, thread_id, imap_uid,
    received_at, sent_at,
    list_id
  )
  SELECT
    p_mailbox_id, v_tag_id,
    p_message_id, p_subject, p_from_addr, p_from_name,
    COALESCE(p_to_addrs, '[]'::JSONB),
    COALESCE(p_cc_addrs, '[]'::JSONB),
    COALESCE(p_bcc_addrs, '[]'::JSONB),
    p_in_reply_to, p_references_hdr,
    p_body_text, p_body_html,
    p_size_bytes, COALESCE(p_is_read, FALSE), COALESCE(p_is_flagged, FALSE),
    p_raw_ref, v_thread_id, v_imap_uid,
    COALESCE(p_date, now()), COALESCE(p_date, now()),
    normalize_list_id(p_list_id)
  WHERE (
    p_actor_id IS NULL
    OR admin_can_reach_mailbox(p_actor_id, p_domain_scope, p_mailbox_id)
  )
  RETURNING id INTO v_message_id;

  -- 5.+6. Tag + notify connected clients — ONLY when a row was actually
  -- inserted; the revocation no-op path must leave no side effects.
  IF v_message_id IS NOT NULL THEN
    -- Register bare 64-hex raw body in public.blobs atomically under the held
    -- per-sha256 advisory lock (never on the revoked-authority no-op path).
    IF p_raw_ref IS NOT NULL AND p_raw_ref ~ '^[0-9a-f]{64}$' THEN
      PERFORM public.blob_gc_register_and_reactivate(
        p_raw_ref,
        p_raw_ref,
        GREATEST(COALESCE(p_size_bytes, 0), 0),
        'message/rfc822'
      );
    END IF;

    -- Add tag (trigger handles counters)
    PERFORM tag_message(v_message_id, COALESCE(p_date, now())::TIMESTAMPTZ, v_tag_name, p_mailbox_id, 'import', TRUE);

    -- Notify connected clients
    PERFORM app_notify(
      'tag:' || p_mailbox_id,
      jsonb_build_object(
        'event', 'imported',
        'message_id', v_message_id,
        'tag_id', v_tag_id
      )::TEXT
    );
  END IF;

  RETURN v_message_id;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
    IF current_setting('app._v293_granted_worker_create', true) = '1' THEN
        REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        PERFORM set_config('app._v293_granted_worker_create', '0', false);
    END IF;
END
$$;

-- ── 5. Migration bookkeeping ──────────────────────────────────────────────────

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (293, now())
ON CONFLICT (version) DO NOTHING;
