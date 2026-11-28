-- Assessment data is administrator-only and all reads/mutations flow through
-- the worker credential plus reducer authority. FORCE RLS with no app policy is
-- the native-RLS backstop: setjoin_app can hold broad compatibility grants but
-- can never read or mutate these rows directly. setjoin_worker has BYPASSRLS.
DO $$
DECLARE v_table text;
BEGIN
  FOREACH v_table IN ARRAY ARRAY[
    'exchange_assessment_projects','exchange_assessment_runs','exchange_assessment_leases',
    'exchange_assessment_probe_results','exchange_assessment_artifacts','exchange_assessment_evidence',
    'exchange_assessment_decisions','exchange_assessment_publications','exchange_assessment_tombstones',
    'exchange_assessment_attestations','exchange_assessment_claim_snapshots','exchange_assessment_receipts',
    'exchange_assessment_uploads','exchange_assessment_upload_chunks','exchange_assessment_deletion_requests'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',v_table);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',v_table);
  END LOOP;
END;
$$;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (217, now()) ON CONFLICT (version) DO NOTHING;
