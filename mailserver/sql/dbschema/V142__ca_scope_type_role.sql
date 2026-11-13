-- V142: widen conditional_access_policies.scope_type to allow 'role'.
--
-- The Go policy engine (shared/threat/policy.go scopeMatches) already implements
-- 'role' scope in full (ResolveRoleGroups threaded through IMAP/SMTP/runtime_access/
-- interceptor/cache-key hashing) and the webmail CA editor already offers a "Role
-- group" scope option — but the DB CHECK never allowed it, so saving a role-scoped
-- policy 400ed with a raw 23514. This migration is the missing piece; no Go/reducer
-- change needed (ca_policy_upsert has no scope_type allow-list of its own — the
-- CHECK below is the sole gate, see ca_policy_upsert.sql:11).
--
-- 'domain' is deliberately NOT added — it is offered nowhere in scopeMatches and is
-- being removed from the editor in this same change (see AGENTS.md TODOS.md note).

ALTER TABLE public.conditional_access_policies DROP CONSTRAINT conditional_access_policies_scope_type_check;
ALTER TABLE public.conditional_access_policies ADD CONSTRAINT conditional_access_policies_scope_type_check
  CHECK (scope_type = ANY (ARRAY['global'::text, 'user'::text, 'group'::text, 'role'::text]));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (142, now())
  ON CONFLICT (version) DO NOTHING;
