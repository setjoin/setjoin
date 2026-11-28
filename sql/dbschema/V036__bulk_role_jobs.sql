-- V036__bulk_role_jobs.sql — durable queue for bulk admin-role assign/revoke jobs.
-- Mirrors eap_apply_jobs: enqueue returns immediately, a worker drains it. No RLS
-- (admin-data, cross-tenant; worker runs BYPASSRLS) — same posture as
-- admin_role_assignments / eap_apply_jobs. No enqueue-time authority snapshot:
-- the worker re-derives actor perms+scope and the role's perms LIVE at processing.
CREATE TABLE public.bulk_role_jobs (
    id          bigserial PRIMARY KEY,
    op          text NOT NULL CHECK (op IN ('assign','revoke')),
    role_id     bigint NOT NULL,
    actor_id    bigint NOT NULL,
    user_ids    bigint[] NOT NULL,
    expires_at  timestamptz,
    status      text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','done','error')),
    total       integer NOT NULL,
    processed   integer NOT NULL DEFAULT 0,   -- count applied; loop RESUMES here (never reset)
    results     jsonb   NOT NULL DEFAULT '[]'::jsonb,
    error       text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX bulk_role_jobs_queued_idx ON public.bulk_role_jobs (created_at) WHERE status = 'queued';

INSERT INTO public.schema_migrations (version, applied_at) VALUES (36, now()) ON CONFLICT (version) DO NOTHING;
