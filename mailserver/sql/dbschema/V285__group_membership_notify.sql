-- V285__group_membership_notify.sql — Wave 1.4 (#542):
-- Emit `app_notify('group_membership_changed', ...)` whenever membership in
-- any of the three group namespaces changes so `setjoin_authz::groups::GroupResolver`
-- invalidates its bounded per-user LRU cache immediately over DB_DIRECT_DSN LISTEN.
--
-- Payloads:
--   {"source":"...","user_id":<bigint>}  -> invalidate_user(user_id)
--   {"source":"...","all":true}          -> invalidate_all()

CREATE OR REPLACE FUNCTION public.trg_user_group_members_notify()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM public.app_notify(
      'group_membership_changed',
      jsonb_build_object('source', 'user_group_members', 'user_id', NEW.user_id)::text
    );
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    PERFORM public.app_notify(
      'group_membership_changed',
      jsonb_build_object('source', 'user_group_members', 'user_id', OLD.user_id)::text
    );
    RETURN OLD;
  ELSE
    PERFORM public.app_notify(
      'group_membership_changed',
      jsonb_build_object('source', 'user_group_members', 'user_id', NEW.user_id)::text
    );
    IF OLD.user_id IS DISTINCT FROM NEW.user_id THEN
      PERFORM public.app_notify(
        'group_membership_changed',
        jsonb_build_object('source', 'user_group_members', 'user_id', OLD.user_id)::text
      );
    END IF;
    RETURN NEW;
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.trg_directory_group_invalidations_notify()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.user_id IS NULL THEN
      PERFORM public.app_notify(
        'group_membership_changed',
        jsonb_build_object('source', 'directory_group_invalidations', 'all', true)::text
      );
    ELSE
      PERFORM public.app_notify(
        'group_membership_changed',
        jsonb_build_object('source', 'directory_group_invalidations', 'user_id', NEW.user_id)::text
      );
    END IF;
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    IF OLD.user_id IS NULL THEN
      PERFORM public.app_notify(
        'group_membership_changed',
        jsonb_build_object('source', 'directory_group_invalidations', 'all', true)::text
      );
    ELSE
      PERFORM public.app_notify(
        'group_membership_changed',
        jsonb_build_object('source', 'directory_group_invalidations', 'user_id', OLD.user_id)::text
      );
    END IF;
    RETURN OLD;
  ELSE
    IF NEW.user_id IS NULL OR OLD.user_id IS NULL THEN
      PERFORM public.app_notify(
        'group_membership_changed',
        jsonb_build_object('source', 'directory_group_invalidations', 'all', true)::text
      );
    ELSE
      PERFORM public.app_notify(
        'group_membership_changed',
        jsonb_build_object('source', 'directory_group_invalidations', 'user_id', NEW.user_id)::text
      );
      IF OLD.user_id IS DISTINCT FROM NEW.user_id THEN
        PERFORM public.app_notify(
          'group_membership_changed',
          jsonb_build_object('source', 'directory_group_invalidations', 'user_id', OLD.user_id)::text
        );
      END IF;
    END IF;
    RETURN NEW;
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.trg_distribution_group_members_notify()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_user_id bigint;
  v_old_user_id bigint;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT mb.user_id INTO v_user_id FROM public.mailboxes mb WHERE mb.id = NEW.mailbox_id;
    IF v_user_id IS NOT NULL THEN
      PERFORM public.app_notify(
        'group_membership_changed',
        jsonb_build_object('source', 'distribution_group_members', 'user_id', v_user_id)::text
      );
    ELSE
      PERFORM public.app_notify(
        'group_membership_changed',
        jsonb_build_object('source', 'distribution_group_members', 'all', true)::text
      );
    END IF;
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    SELECT mb.user_id INTO v_user_id FROM public.mailboxes mb WHERE mb.id = OLD.mailbox_id;
    IF v_user_id IS NOT NULL THEN
      PERFORM public.app_notify(
        'group_membership_changed',
        jsonb_build_object('source', 'distribution_group_members', 'user_id', v_user_id)::text
      );
    ELSE
      PERFORM public.app_notify(
        'group_membership_changed',
        jsonb_build_object('source', 'distribution_group_members', 'all', true)::text
      );
    END IF;
    RETURN OLD;
  ELSE
    SELECT mb.user_id INTO v_user_id FROM public.mailboxes mb WHERE mb.id = NEW.mailbox_id;
    IF v_user_id IS NOT NULL THEN
      PERFORM public.app_notify(
        'group_membership_changed',
        jsonb_build_object('source', 'distribution_group_members', 'user_id', v_user_id)::text
      );
    ELSE
      PERFORM public.app_notify(
        'group_membership_changed',
        jsonb_build_object('source', 'distribution_group_members', 'all', true)::text
      );
    END IF;
    IF OLD.mailbox_id IS DISTINCT FROM NEW.mailbox_id THEN
      SELECT mb.user_id INTO v_old_user_id FROM public.mailboxes mb WHERE mb.id = OLD.mailbox_id;
      IF v_old_user_id IS NOT NULL AND v_old_user_id IS DISTINCT FROM v_user_id THEN
        PERFORM public.app_notify(
          'group_membership_changed',
          jsonb_build_object('source', 'distribution_group_members', 'user_id', v_old_user_id)::text
        );
      ELSIF v_old_user_id IS NULL THEN
        PERFORM public.app_notify(
          'group_membership_changed',
          jsonb_build_object('source', 'distribution_group_members', 'all', true)::text
        );
      END IF;
    END IF;
    RETURN NEW;
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.trg_distribution_groups_admin_scope_notify()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.is_dynamic IS DISTINCT FROM OLD.is_dynamic
     OR NEW.scim_external_id IS DISTINCT FROM OLD.scim_external_id
     OR NEW.usable_as_admin_scope IS DISTINCT FROM OLD.usable_as_admin_scope THEN
    PERFORM public.app_notify(
      'group_membership_changed',
      jsonb_build_object('source', 'distribution_groups', 'all', true)::text
    );
  END IF;
  RETURN NEW;
END;
$$;

DO $$
DECLARE v_fn regprocedure;
BEGIN
  FOREACH v_fn IN ARRAY ARRAY[
    'public.trg_user_group_members_notify()'::regprocedure,
    'public.trg_directory_group_invalidations_notify()'::regprocedure,
    'public.trg_distribution_group_members_notify()'::regprocedure,
    'public.trg_distribution_groups_admin_scope_notify()'::regprocedure
  ] LOOP
    PERFORM public.apply_worker_ownership(v_fn);
  END LOOP;
END $$;

DROP TRIGGER IF EXISTS user_group_members_notify ON public.user_group_members;
CREATE TRIGGER user_group_members_notify
  AFTER INSERT OR UPDATE OR DELETE ON public.user_group_members
  FOR EACH ROW EXECUTE FUNCTION public.trg_user_group_members_notify();

DROP TRIGGER IF EXISTS directory_group_invalidations_notify ON public.directory_group_invalidations;
CREATE TRIGGER directory_group_invalidations_notify
  AFTER INSERT OR UPDATE OR DELETE ON public.directory_group_invalidations
  FOR EACH ROW EXECUTE FUNCTION public.trg_directory_group_invalidations_notify();

DROP TRIGGER IF EXISTS distribution_group_members_notify ON public.distribution_group_members;
CREATE TRIGGER distribution_group_members_notify
  AFTER INSERT OR UPDATE OR DELETE ON public.distribution_group_members
  FOR EACH ROW EXECUTE FUNCTION public.trg_distribution_group_members_notify();

DROP TRIGGER IF EXISTS distribution_groups_admin_scope_notify ON public.distribution_groups;
CREATE TRIGGER distribution_groups_admin_scope_notify
  AFTER UPDATE OF is_dynamic, scim_external_id, usable_as_admin_scope ON public.distribution_groups
  FOR EACH ROW EXECUTE FUNCTION public.trg_distribution_groups_admin_scope_notify();

INSERT INTO public.schema_migrations (version, applied_at) VALUES (285, now())
  ON CONFLICT (version) DO NOTHING;
