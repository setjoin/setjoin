-- ════════════════════════════════════════════════════════════════════════
-- V002__link_protect_audit_nullable.sql — forward migration (RLS-flip Wave 0).
--
-- Retires the ARCH-007 completion-pass hand-edit of the FROZEN V001 baseline:
-- link_protect_audit.message_id was hand-changed from `bigint NOT NULL` to
-- `bigint` in V001 to make the snapshot match the running schema. V001 is now
-- restored to its clean dump (message_id bigint NOT NULL) and this forward
-- migration carries the nullability change through the proper baseline→forward
-- path. Net loaded schema is unchanged (message_id ends nullable).
--
-- link_protect audit rows are written before a message_id exists (the URL scan
-- happens during delivery, ahead of the row insert), so message_id must be
-- nullable. See mailserver/sql/tests/link_protect_check_and_audit.pg.
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.link_protect_audit ALTER COLUMN message_id DROP NOT NULL;

-- Advance MAX(version) so the loader's apply step + main.go / admin_system see
-- this migration as applied. Columns match the V001 seed (version, applied_at).
INSERT INTO public.schema_migrations (version, applied_at) VALUES (2, now())
    ON CONFLICT (version) DO NOTHING;
