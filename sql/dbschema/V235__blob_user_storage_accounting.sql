-- ════════════════════════════════════════════════════════════════════════
-- V235__blob_user_storage_accounting.sql — per-user blob storage accounting
-- (D-MAILSERVER-INTERNAL-BLOB-002 remediation).
--
-- WHY. Blob PUT inserted rows at ref_count=0 and reclamation was armed only by
-- the UPDATE-to-zero trigger (trg_blob_refcount_zero, V001), so
-- uploaded-but-never-attached objects were never queued for cleanup and any
-- authenticated user could grow appliance storage unboundedly and unmetered.
-- The gateway fix (mailserver/internal/blob/handler.go) has two halves; this
-- migration owns the accounting half's durable state:
--
--   1. Reclamation arming at PUT is a blob_cleanup_queue row written by the
--      handler in the SAME transaction as the blobs insert, with the grace
--      window as delay_minutes (cfg blob.reclaim_grace_minutes). NO new queue
--      table and NO trigger change: the existing atomic reference recheck in
--      reapCleanupCandidate (DELETE ... WHERE ref_count = 0, one-statement
--      gate) is untouched, so a late attach (message_attachments V075 or
--      hr_expense_receipts V110 — both refcount triggers bump ref_count 0→1)
--      or a cross-user deduplicated re-upload can never lose referenced
--      bytes; trg_blob_refcount_zero keeps re-arming rows the way it always
--      has. A blob armed at PUT and later attached keeps its queue row until
--      the blob itself is deleted (FK CASCADE), which is harmless: the
--      candidate scan and the reap re-check both require ref_count = 0.
--
--   2. blob_user_charges is the per-blob charge ledger: one row per NEWLY
--      stored blob (a deduplicated re-upload conflicts on blobs.sha256 and is
--      never charged), attributing the blob's MEASURED byte size — counted
--      from the streamed body, so chunked/unknown-length uploads are charged
--      their real bytes, not a zero-size fallback — to the uploading user.
--      blob_user_usage is the per-user aggregate the gateway's bound check
--      (cfg blob.user_quota_bytes; <=0 = enforcement OFF, accounting still
--      recorded) reads under a row lock, so simultaneous uploads serialize
--      per user and can never exceed the configured bound. The ref triggers
--      keep the aggregate exact: INSERT adds, and the ON DELETE CASCADE from
--      blobs credits the user back on EVERY deletion path — including the
--      background reclamation sweeper, which runs on an unscoped role.
--
-- ISOLATION POSTURE (R4, ARCH-006). These are aggregate metering tables, not
-- user content: they follow the blob family posture (blobs / blob_cleanup_queue
-- / orphaned_message_blobs carry no RLS policies; isolation is enforced at the
-- gateway, whose charge/usage statements bind user_id from the authenticated
-- claims — R1/R2 in-statement, never from request-owned fields). V048
-- login_events is the precedent for a user-keyed bigint user_id without a
-- users FK; charges instead FK to blobs ON DELETE CASCADE so ledger rows and
-- stored bytes share a lifetime.
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE public.blob_user_charges (
    blob_sha256 text        PRIMARY KEY REFERENCES public.blobs(sha256) ON DELETE CASCADE,
    user_id     bigint      NOT NULL,
    size_bytes  bigint      NOT NULL CHECK (size_bytes >= 0),
    charged_at  timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE INDEX blob_user_charges_user_idx ON public.blob_user_charges (user_id);

CREATE TABLE public.blob_user_usage (
    user_id       bigint      PRIMARY KEY,
    charged_bytes bigint      NOT NULL DEFAULT 0,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- AFTER INSERT: add the charge to the user's aggregate (upsert mints the row).
CREATE FUNCTION public.blob_user_charge_ref_inc() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  INSERT INTO public.blob_user_usage AS u (user_id, charged_bytes, updated_at)
  VALUES (NEW.user_id, NEW.size_bytes, now())
  ON CONFLICT (user_id) DO UPDATE
    SET charged_bytes = u.charged_bytes + EXCLUDED.charged_bytes,
        updated_at    = now();
  RETURN NEW;
END;
$$;

-- AFTER DELETE: fires via the blobs ON DELETE CASCADE from ANY deletion path
-- (reclamation sweeper, admin tooling) and credits the aggregate back. The
-- charged_bytes guard keeps the counter non-negative if a usage row was
-- recreated after a partial user purge (the update simply matches 0 rows).
CREATE FUNCTION public.blob_user_charge_ref_dec() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  UPDATE public.blob_user_usage
     SET charged_bytes = charged_bytes - OLD.size_bytes,
         updated_at    = now()
   WHERE user_id = OLD.user_id
     AND charged_bytes >= OLD.size_bytes;
  RETURN OLD;
END;
$$;

CREATE TRIGGER trg_blob_user_charge_inc
    AFTER INSERT ON public.blob_user_charges
    FOR EACH ROW EXECUTE FUNCTION public.blob_user_charge_ref_inc();

CREATE TRIGGER trg_blob_user_charge_dec
    AFTER DELETE ON public.blob_user_charges
    FOR EACH ROW EXECUTE FUNCTION public.blob_user_charge_ref_dec();

INSERT INTO public.schema_migrations(version, applied_at) VALUES (235, now()) ON CONFLICT DO NOTHING;
