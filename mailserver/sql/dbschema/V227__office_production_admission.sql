-- V227: admit the implemented Office/Drive production path. The repository is
-- still pre-release, so this is an explicit product-default decision rather
-- than a customer rollout. Compiled missing-row fallbacks remain fail closed.

UPDATE public.feature_toggles
   SET enabled=true, updated_at=now()
 WHERE key IN (
   'feature.drive',
   'feature.drive_history',
   'feature.office_editing',
   'feature.office_local_open',
   'feature.office_managed_delivery'
 );

-- Root-controlled, undocumented E2E seam. Real deployments retain false.
-- The app runner independently requires its one-shot app-only CLI gate.
INSERT INTO public.system_config(key,value,encrypted,description)
VALUES('office.insecure_test_transport','false'::jsonb,false,
       'Root-only E2E seam for loopback Collabora/WOPI HTTP; never a product setting')
ON CONFLICT(key) DO NOTHING;

CREATE OR REPLACE FUNCTION public.office_test_transport_enabled()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
  SELECT COALESCE((SELECT (value #>> '{}')::boolean
                     FROM public.system_config
                    WHERE key='office.insecure_test_transport'),false)
$$;
REVOKE ALL ON FUNCTION public.office_test_transport_enabled() FROM PUBLIC;
SELECT apply_worker_ownership('office_test_transport_enabled()'::regprocedure);

INSERT INTO public.schema_migrations(version,applied_at) VALUES (227,now())
ON CONFLICT (version) DO NOTHING;
