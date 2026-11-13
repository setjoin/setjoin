-- ════════════════════════════════════════════════════════════════════════
-- V004__rls_enable.sql — forward migration (native-RLS enforcement-flip W6).
--
-- 🔒 THE PRODUCTION FORCE FLIP — the single all-or-nothing milestone of the
-- enforcement-flip program. This migration ENABLEs + FORCEs Row-Level Security
-- on the messages + message_tags partitioned PARENTs, turning the V003 inert
-- policies LIVE. Everything before this wave was wrap-only (INERT); this is the
-- one DDL that opens the road.
--
-- 🔒 NO-OP UNTIL THE GATEWAY CONNECTS AS setjoin_app. RLS does not constrain a
-- SUPERUSER or the table OWNER (owner tables are not FORCE'd against the owner's
-- own role unless they ARE the FORCE target — and FORCE only binds the owner,
-- never lifts the superuser exemption). In the dev/test cluster the tables are
-- owned by `mail` (a SUPERUSER + owner), so after this migration applies the
-- existing pgTAP suite + Go tests — which all connect as `mail` — still see every
-- row and stay green. RLS only BITES once a connection runs as the non-owner,
-- non-superuser, non-bypassrls setjoin_app role (provision-roles.sql). The
-- production cut-over is therefore the SEPARATE, hand-authorized DB_DSN switch to
-- setjoin_app — NOT this migration. Applying V004 is safe to do ahead of that
-- switch precisely because it is a no-op for the superuser/owner identity the
-- gateway uses today.
--
-- WHY ENABLE *AND* FORCE (not just ENABLE): so the production state == every
-- proof test's tested state. The proofs (rls_policies.pg, rls_jmap_reducers.pg,
-- rls_smtp_delivery.pg, and the Go imap_isolation_test.go) all run under
-- ENABLE+FORCE as setjoin_app — this migration makes prod match that exactly.
-- FORCE is a zero-cost belt: under fork 1 the app role is constrained by
-- NON-OWNERSHIP alone, so FORCE buys no additional security on the app path —
-- but it FAILS CLOSED if anything ever runs owner-level DML on these tables
-- WITHOUT a GUC (e.g. a future migration/script that forgets to set
-- app.current_mailbox_id while connected as the owner): without FORCE the owner
-- silently bypasses and could write unscoped rows; with FORCE that write is
-- policy-checked too (empty GUC → WITH CHECK denies → 42501, a loud failure).
-- It is the belt that catches the one hole non-ownership leaves on the owner
-- identity.
--
-- PARTITIONED PARENTS ONLY (W1a CONFIRMED, fork 1 / rls_partition_via_parent.pg):
-- messages + message_tags are RANGE-partitioned by received_at. Parent
-- ENABLE+FORCE+policy governs the WHOLE hierarchy on the via-parent access path
-- (the ONLY path the gateway/reducers use — they always name `FROM messages`,
-- never a leaf partition). Per-partition flags are NOT inherited, but the
-- codebase has ZERO direct-leaf runtime access, so the via-parent guarantee is
-- the operative one; new monthly partitions need NO per-partition handling.
--
-- Plan: docs/superpowers/plans/archive/2026-06-18-native-rls-backstop.md (W6 bullet).
-- Policies enabled here were CREATEd (inert) by V003__rls_policies.sql.
-- ════════════════════════════════════════════════════════════════════════

-- ── messages (the PARTITIONED PARENT) ───────────────────────────────────────
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages FORCE  ROW LEVEL SECURITY;

-- ── message_tags (the PARTITIONED PARENT) ───────────────────────────────────
ALTER TABLE public.message_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.message_tags FORCE  ROW LEVEL SECURITY;

-- Advance MAX(version) so the loader's apply step + main.go / admin_system see
-- this migration as applied. Columns match the V001 seed (version, applied_at).
INSERT INTO public.schema_migrations (version, applied_at) VALUES (4, now())
    ON CONFLICT (version) DO NOTHING;
