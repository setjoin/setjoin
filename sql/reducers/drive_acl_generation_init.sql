-- Keeps the expand-only epoch row complete even for a direct, policy-admitted
-- drive_spaces insert. Normal application creation still uses
-- drive_space_create; this trigger is the invariant backstop.
CREATE OR REPLACE FUNCTION trg_drive_acl_generation_init()
RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  INSERT INTO public.drive_acl_generations (space_id)
  VALUES (NEW.id)
  ON CONFLICT (space_id) DO NOTHING;
  RETURN NEW;
END;
$$;
SELECT apply_worker_ownership('trg_drive_acl_generation_init()'::regprocedure);
