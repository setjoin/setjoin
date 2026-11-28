-- V041: Admin scope-sets (P3-#8 v2). Named governed scope container.
-- Realises docs/superpowers/specs/2026-06-26-admin-scope-set-design.md.

CREATE TABLE public.admin_scope_sets (
  id          bigserial PRIMARY KEY,
  name        text NOT NULL,
  domain_id   bigint REFERENCES public.domains(id) ON DELETE RESTRICT,  -- NULL = global
  description text,
  created_by  bigint,
  created_at  timestamptz DEFAULT now() NOT NULL,
  updated_at  timestamptz DEFAULT now() NOT NULL,
  CONSTRAINT admin_scope_sets_name_key UNIQUE NULLS NOT DISTINCT (domain_id, name)
);

CREATE TABLE public.admin_scope_set_members (
  set_id      bigint NOT NULL REFERENCES public.admin_scope_sets(id) ON DELETE CASCADE,
  member_type text NOT NULL CHECK (member_type IN ('ou','group','user')),
  member_id   bigint NOT NULL,
  added_by    bigint,
  added_at    timestamptz DEFAULT now() NOT NULL,
  PRIMARY KEY (set_id, member_type, member_id)
);
CREATE INDEX admin_scope_set_members_member_idx
  ON public.admin_scope_set_members (member_type, member_id);

-- Opt-in eligibility for a group to be usable as an admin scope (spec §3.3).
ALTER TABLE public.distribution_groups
  ADD COLUMN usable_as_admin_scope boolean DEFAULT false NOT NULL;

-- Grant scope: retire group/user, allow 'set'.
ALTER TABLE public.admin_role_assignments DROP CONSTRAINT admin_role_assignments_scope_type_chk;
ALTER TABLE public.admin_role_assignments ADD CONSTRAINT admin_role_assignments_scope_type_chk
  CHECK (scope_type IS NULL OR scope_type IN ('ou','set'));
ALTER TABLE public.bulk_role_jobs DROP CONSTRAINT bulk_role_jobs_scope_type_chk;
ALTER TABLE public.bulk_role_jobs ADD CONSTRAINT bulk_role_jobs_scope_type_chk
  CHECK (scope_type IS NULL OR scope_type IN ('ou','set'));

-- Drop-member triggers: deleting a referent removes the matching member row
-- (per member_type; member_id is polymorphic so no FK fits) and audits it.
-- audit_write actor=NULL: system-origin row; admin_audit_log.user_id is nullable.
CREATE OR REPLACE FUNCTION public.trg_scope_member_drop_dept() RETURNS trigger AS $$
BEGIN
  DELETE FROM admin_scope_set_members WHERE member_type='ou' AND member_id=OLD.id;
  IF FOUND THEN
    PERFORM audit_write(NULL, 'scope_set_member_dropped', 'department', OLD.id,
                        NULL, NULL, NULL, 'referent_deleted', 'core');
  END IF;
  RETURN OLD;
END; $$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION public.trg_scope_member_drop_group() RETURNS trigger AS $$
BEGIN
  DELETE FROM admin_scope_set_members WHERE member_type='group' AND member_id=OLD.id;
  IF FOUND THEN
    PERFORM audit_write(NULL, 'scope_set_member_dropped', 'distribution_group', OLD.id,
                        NULL, NULL, NULL, 'referent_deleted', 'core');
  END IF;
  RETURN OLD;
END; $$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION public.trg_scope_member_drop_user() RETURNS trigger AS $$
BEGIN
  DELETE FROM admin_scope_set_members WHERE member_type='user' AND member_id=OLD.id;
  IF FOUND THEN
    PERFORM audit_write(NULL, 'scope_set_member_dropped', 'user', OLD.id,
                        NULL, NULL, NULL, 'referent_deleted', 'core');
  END IF;
  RETURN OLD;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_scope_member_drop_dept  BEFORE DELETE ON public.departments
  FOR EACH ROW EXECUTE FUNCTION public.trg_scope_member_drop_dept();
CREATE TRIGGER trg_scope_member_drop_group BEFORE DELETE ON public.distribution_groups
  FOR EACH ROW EXECUTE FUNCTION public.trg_scope_member_drop_group();
CREATE TRIGGER trg_scope_member_drop_user  BEFORE DELETE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.trg_scope_member_drop_user();

-- RESTRICT-in-use: a set referenced by any grant cannot be deleted.
CREATE OR REPLACE FUNCTION public.trg_scope_set_restrict_inuse() RETURNS trigger AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM admin_role_assignments
              WHERE scope_type='set' AND scope_id=OLD.id) THEN
    RAISE EXCEPTION 'scope-set % is referenced by an active grant', OLD.id
      USING ERRCODE='P0001', HINT='{"type":"scope_set_in_use"}';
  END IF;
  RETURN OLD;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_scope_set_restrict_inuse BEFORE DELETE ON public.admin_scope_sets
  FOR EACH ROW EXECUTE FUNCTION public.trg_scope_set_restrict_inuse();

-- Decision 7: replace V039's dept-delete trigger — DROP the grant row, never
-- null-to-unrestricted (which broadens). V039 created trigger 'dept_delete_nulls_scope'
-- (note: no trg_ prefix on the trigger name; the function was trg_dept_delete_nulls_scope).
DROP TRIGGER IF EXISTS dept_delete_nulls_scope ON public.departments;
DROP FUNCTION IF EXISTS public.trg_dept_delete_nulls_scope();
CREATE OR REPLACE FUNCTION public.trg_dept_delete_drops_grant() RETURNS trigger AS $$
BEGIN
  DELETE FROM admin_role_assignments WHERE scope_type='ou' AND scope_id=OLD.id;
  RETURN OLD;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_dept_delete_drops_grant BEFORE DELETE ON public.departments
  FOR EACH ROW EXECUTE FUNCTION public.trg_dept_delete_drops_grant();

-- Seed scope_sets.manage to Super Admin only (spec §3.4: v2 Super-only).
UPDATE public.admin_role_groups
   SET permissions = (SELECT array_agg(DISTINCT p ORDER BY p)
                        FROM unnest(permissions || ARRAY['scope_sets.manage']) AS p)
 WHERE id = 1;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (41, now())
  ON CONFLICT (version) DO NOTHING;
