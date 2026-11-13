-- V039: OU (org-unit) scope axis for admin role assignments. Additive; existing
-- rows get scope_type=NULL (no OU narrowing) → behavior unchanged.
ALTER TABLE public.admin_role_assignments
  ADD COLUMN scope_type text,
  ADD COLUMN scope_id   bigint,
  ADD CONSTRAINT admin_role_assignments_scope_type_chk
    CHECK (scope_type IS NULL OR scope_type IN ('ou','group','user')),
  ADD CONSTRAINT admin_role_assignments_scope_pair_chk
    CHECK ((scope_type IS NULL) = (scope_id IS NULL));

CREATE INDEX admin_role_assignments_scope_idx
  ON public.admin_role_assignments (scope_type, scope_id) WHERE scope_type IS NOT NULL;

-- Stale-scope safety: deleting a department NULLs any OU scope pointing at it
-- (mirrors users.department_id ON DELETE SET NULL). Re-parent is intentionally
-- NOT nulled (the admin keeps the node they were scoped to).
CREATE OR REPLACE FUNCTION public.trg_dept_delete_nulls_scope() RETURNS trigger AS $$
BEGIN
  UPDATE public.admin_role_assignments
     SET scope_type = NULL, scope_id = NULL
   WHERE scope_type = 'ou' AND scope_id = OLD.id;
  RETURN OLD;
END; $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS dept_delete_nulls_scope ON public.departments;
CREATE TRIGGER dept_delete_nulls_scope
  BEFORE DELETE ON public.departments
  FOR EACH ROW EXECUTE FUNCTION public.trg_dept_delete_nulls_scope();

INSERT INTO public.schema_migrations (version, applied_at) VALUES (39, now())
  ON CONFLICT (version) DO NOTHING;
