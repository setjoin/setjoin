-- #542 owner-approved security fix 2026-11-05: the deploy wizard's unresolved
-- remote-command fence survives a gateway restart. A deployment cancelled
-- while a remote SSH command had unconfirmed termination leaves a row here;
-- until an operator resolves it (as the table owner: DELETE FROM deploy_remote_fence) no new
-- deployment run is admitted, even after a restart.
-- Only the Rust gateway reads or writes this table. Frozen Go never references
-- it and its statements on deployment_steps are untouched. It holds no user
-- data (a singleton operational flag), so there is no per-user RLS posture.
CREATE TABLE public.deploy_remote_fence (
    id            boolean PRIMARY KEY DEFAULT true CHECK (id),
    fenced_at     timestamptz NOT NULL DEFAULT now(),
    actor_user_id bigint,
    detail        text NOT NULL DEFAULT ''
);
-- Owner-only clearing: the app and worker roles may read, set and update the fence but
-- never delete it, so resolving it is an operator action (default privileges would
-- otherwise grant DELETE).
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='setjoin_owner') THEN
        ALTER TABLE public.deploy_remote_fence OWNER TO setjoin_owner;
    END IF;
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='setjoin_app') THEN
        REVOKE ALL ON public.deploy_remote_fence FROM setjoin_app;
        GRANT SELECT,INSERT,UPDATE ON public.deploy_remote_fence TO setjoin_app;
    END IF;
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='setjoin_worker') THEN
        REVOKE ALL ON public.deploy_remote_fence FROM setjoin_worker;
        GRANT SELECT,INSERT,UPDATE ON public.deploy_remote_fence TO setjoin_worker;
    END IF;
END $$;
INSERT INTO public.schema_migrations (version, applied_at) VALUES (280, now())
    ON CONFLICT (version) DO NOTHING;
