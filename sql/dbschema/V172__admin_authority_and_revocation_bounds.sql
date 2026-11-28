-- V172: serialize live admin-reach decisions with every authority-topology
-- mutation, and bound the runtime session-revocation enforcement set.

CREATE OR REPLACE FUNCTION public.admin_authority_fence()
RETURNS void
LANGUAGE sql
VOLATILE
AS $$
  -- A fixed signed BIGINT avoids narrowing a relation OID to INTEGER and keeps
  -- this lock in PostgreSQL's one-key advisory-lock namespace. The value is a
  -- project-owned protocol constant; changing it would split the serialization
  -- domain across mixed-version nodes during an upgrade.
  SELECT pg_advisory_xact_lock(831755170172::bigint);
$$;

CREATE OR REPLACE FUNCTION public.trg_admin_authority_fence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM admin_authority_fence();
  RETURN NULL;
END;
$$;

-- Statement-level BEFORE triggers acquire the fence before PostgreSQL takes
-- row locks for the mutation. This preserves the global order:
-- authority fence -> person fence -> principal rows -> token/session rows.
CREATE TRIGGER trg_admin_authority_assignments_fence
  BEFORE INSERT OR UPDATE OR DELETE ON public.admin_role_assignments
  FOR EACH STATEMENT EXECUTE FUNCTION public.trg_admin_authority_fence();
CREATE TRIGGER trg_admin_authority_groups_fence
  BEFORE INSERT OR UPDATE OR DELETE ON public.admin_role_groups
  FOR EACH STATEMENT EXECUTE FUNCTION public.trg_admin_authority_fence();
CREATE TRIGGER trg_admin_authority_departments_fence
  BEFORE INSERT OR UPDATE OR DELETE ON public.departments
  FOR EACH STATEMENT EXECUTE FUNCTION public.trg_admin_authority_fence();
CREATE TRIGGER trg_admin_authority_scope_members_fence
  BEFORE INSERT OR UPDATE OR DELETE ON public.admin_scope_set_members
  FOR EACH STATEMENT EXECUTE FUNCTION public.trg_admin_authority_fence();
CREATE TRIGGER trg_admin_authority_group_members_fence
  BEFORE INSERT OR UPDATE OR DELETE ON public.distribution_group_members
  FOR EACH STATEMENT EXECUTE FUNCTION public.trg_admin_authority_fence();
CREATE TRIGGER trg_admin_authority_users_fence
  BEFORE UPDATE OF department_id, domain_id OR DELETE ON public.users
  FOR EACH STATEMENT EXECUTE FUNCTION public.trg_admin_authority_fence();
CREATE TRIGGER trg_admin_authority_mailboxes_fence
  BEFORE UPDATE OF user_id, is_primary OR DELETE ON public.mailboxes
  FOR EACH STATEMENT EXECUTE FUNCTION public.trg_admin_authority_fence();
CREATE TRIGGER trg_admin_authority_guest_domain_fence
  BEFORE UPDATE OF host_domain_id ON public.guest_accounts
  FOR EACH STATEMENT EXECUTE FUNCTION public.trg_admin_authority_fence();

-- session_revocations is an enforcement cache, not the audit ledger. Access
-- JWTs are capped at 30 days; the extra day is the rolling compatibility
-- margin. Family rows may receive a later exact oauth-token expiry at write
-- time. Existing NULL rows are bounded before the column becomes mandatory.
UPDATE public.session_revocations
   SET expires_at = created_at + interval '31 days'
 WHERE expires_at IS NULL;
ALTER TABLE public.session_revocations
  ALTER COLUMN expires_at SET NOT NULL;

CREATE INDEX IF NOT EXISTS session_revocations_active_all
  ON public.session_revocations (user_id, not_before DESC)
  WHERE scope = 'all';
CREATE INDEX IF NOT EXISTS session_revocations_active_jti
  ON public.session_revocations (user_id, jti)
  WHERE scope = 'jti';
CREATE INDEX IF NOT EXISTS session_revocations_active_family
  ON public.session_revocations (user_id, family_id)
  WHERE scope = 'family';
CREATE INDEX IF NOT EXISTS session_revocations_expiry
  ON public.session_revocations (expires_at);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (172, now())
  ON CONFLICT (version) DO NOTHING;
