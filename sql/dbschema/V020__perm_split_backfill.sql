-- ════════════════════════════════════════════════════════════════════════
-- V020__perm_split_backfill.sql — backfill 等保 split permission keys onto
-- existing role groups that hold the deprecated umbrella keys.
--
-- Background: V019 added the four split keys to the permission catalog.
-- V020 patches every existing admin_role_groups row that was granted the
-- pre-split umbrella key so it also holds the corresponding split keys.
-- The umbrella keys (users.write, mail.write) are intentionally retained —
-- V021+ will gate their removal on existing consumer audit.
--
-- Backfill map (§4 of the SoD spec):
--   users.write → users.create, users.suspend
--   mail.write  → mail.pipeline, mail.security
--
-- Note: audit.export is NOT backfilled here — it seeds only onto the
-- 审计管理员 preset (V019) and must never be granted via umbrella backfill.
--
-- Idempotent: both UPDATE statements use array_agg(DISTINCT …) which is a
-- no-op on the second run (the keys are already present, dedup has no effect).
-- Safe to run twice with no observable change on the second run.
-- ════════════════════════════════════════════════════════════════════════

-- Backfill users.write → users.create + users.suspend
UPDATE public.admin_role_groups
SET    permissions = (
         SELECT array_agg(DISTINCT p ORDER BY p)
         FROM   unnest(permissions || ARRAY['users.create','users.suspend']) AS p
       ),
       updated_at  = now()
WHERE  permissions @> ARRAY['users.write'];

-- Backfill mail.write → mail.pipeline + mail.security
UPDATE public.admin_role_groups
SET    permissions = (
         SELECT array_agg(DISTINCT p ORDER BY p)
         FROM   unnest(permissions || ARRAY['mail.pipeline','mail.security']) AS p
       ),
       updated_at  = now()
WHERE  permissions @> ARRAY['mail.write'];


-- ── Schema migration record ────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (20, now())
  ON CONFLICT (version) DO NOTHING;
