-- gal_journal_seen: membership predicate over gal_visibility_journal (V261,
-- CARDDAV-V-002) — has THIS caller's mailbox been disclosed this directory
-- member before?
--
-- Why a function and not a plain join: gal_visibility_journal is FORCE-RLS
-- deny-all to every runtime role (V246/V249/V253 posture), and its only
-- consumer gal_changes is invoker-rights (runs as setjoin_app on the gateway
-- pool). Routing the membership test through this worker-owned SECURITY
-- DEFINER predicate gives gal_changes journal access WITHOUT widening the
-- app role's direct reach on the table and without flipping gal_changes
-- itself to definer rights — its users/mailboxes reads keep the caller's
-- context exactly as before.
--
-- R1: both arguments are scoped — the mailbox is the validated caller scope
-- gal_changes already resolved, the user id is the candidate removal row; the
-- WHERE carries BOTH, so the answer is always about this mailbox's own
-- journal rows. Read-only (STABLE); no state bump, no notify.
--
-- r2 (CARDDAV-V-002 hold finding, P1): the journal relation is schema-
-- qualified (the V254 trusted-seam form) AND the pinned search_path lists
-- pg_temp LAST (`pg_catalog, public, pg_temp`). PostgreSQL searches an
-- existing TEMP schema FIRST when pg_temp is omitted, so an unqualified
-- gal_visibility_journal here would have let any TEMP-privileged caller plant
-- a same-named TEMP table (GRANTed to the definer) and forge the membership
-- answer. With pg_temp last, the shadow can never win. Pinned by
-- tests/gal_visibility_journal.pg section 10 (app-role TEMP shadow regression).
CREATE OR REPLACE FUNCTION gal_journal_seen(
  p_mailbox_id BIGINT,
  p_user_id    BIGINT
) RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.gal_visibility_journal j
     WHERE j.mailbox_id = p_mailbox_id
       AND j.user_id    = p_user_id
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp;

-- Ownership + EXECUTE grants (V254 guarded form): the definer is the worker
-- credential; EXECUTE is revoked from PUBLIC and re-granted to the runtime
-- roles. App-invokable ON PURPOSE — gal_changes (running as setjoin_app)
-- calls it per candidate removal row, and the gateway never calls it
-- directly. Must NOT join provision-roles.sql's worker-only EXECUTE
-- carve-out.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        ALTER FUNCTION public.gal_journal_seen(bigint, bigint) OWNER TO setjoin_worker;
    END IF;
    REVOKE EXECUTE ON FUNCTION public.gal_journal_seen(bigint, bigint) FROM PUBLIC;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        GRANT EXECUTE ON FUNCTION public.gal_journal_seen(bigint, bigint) TO setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
        GRANT EXECUTE ON FUNCTION public.gal_journal_seen(bigint, bigint) TO setjoin_owner;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.gal_journal_seen(bigint, bigint) TO setjoin_worker;
    END IF;
END $$;
