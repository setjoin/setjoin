-- V067__audit_canon_array_fix.sql
--
-- Merge-integration fix (CA/offline × main's audit hash-chain).
--
-- V037 (audit_chain_v2) canonicalises before/after_state via jsonb_each, which
-- raises 22023 ("cannot deconstruct ... non-object") on an ARRAY or scalar jsonb.
-- main's own reducers only ever audit OBJECT state, so the bug was latent; the
-- merged CA reducers DO audit arrays (ca_policy_reorder = ordered policy-id list,
-- ca_break_glass_set = to_jsonb(bigint[])), which trip it the moment those rows
-- hit the admin_audit_chain BEFORE-INSERT trigger.
--
-- Fix: branch on jsonb_typeof. The 'object' branch is the EXACT original
-- expression, so every existing object-state row canonicalises byte-identically
-- and the existing hash chain still verifies (tamper-evidence preserved).
-- Non-object jsonb (array/scalar) canonicalises to its deterministic ::text form.
CREATE OR REPLACE FUNCTION public.audit_canon(p jsonb) RETURNS text AS $$
  SELECT CASE jsonb_typeof(COALESCE(p, '{}'::jsonb))
    WHEN 'object' THEN COALESCE(
      (SELECT string_agg(key || ':' || value::text, ',' ORDER BY key)
         FROM jsonb_each(COALESCE(p, '{}'::jsonb))), '')
    ELSE COALESCE(p::text, '')
  END;
$$ LANGUAGE sql IMMUTABLE;

-- ── schema_migrations row ────────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (67, now());
