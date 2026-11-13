-- ════════════════════════════════════════════════════════════════════════
-- V234__m365_consent_states.sql — server-side single-use M365 consent state
--
-- Security remediation (D-MAILSERVER-INTERNAL-USER-F-002, CWE-306): the M365
-- admin-consent callback trusted an attacker-suppliable cookie/query state
-- pair — equality of two caller-owned values is not authentication — and it
-- persisted cfg.TenantID into system_config BEFORE any connection
-- verification. The callback now requires a server-generated, expiring,
-- SINGLE-USE consent authorization bound to the authenticated admin session;
-- this table is that authorization store.
--
-- Lifecycle: GET /admin/migration/m365/connect (authenticated admin) mints a
-- row carrying a 32-byte random token and redirects to Microsoft with the
-- token as OAuth state. The callback atomically consumes the row
-- (consumed_at) ONLY for the minting actor while unconsumed and unexpired —
-- fabrication, replay, and expiry all fail closed. The tenant id is persisted
-- only AFTER the verified tenant connection succeeds, with the
-- consent-completion audit row in the same transaction.
--
-- RLS (R4): ENABLE + FORCE with a per-actor policy keyed on
-- app.current_user_id, mirroring login_events (V048). Fail-closed: unset GUC
-- → NULL → no rows visible. The gateway accesses the table exclusively
-- through dbscope.RunUserScoped with the authenticated actor's id, and every
-- statement ALSO filters actor_user_id explicitly (R1/R3 in-statement
-- ownership, never GUC-only).
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE public.m365_consent_states (
    id            BIGSERIAL PRIMARY KEY,
    state_token   TEXT NOT NULL UNIQUE,
    actor_user_id BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    cloud         TEXT NOT NULL DEFAULT 'global' CHECK (cloud IN ('global','china')),
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ,
    CONSTRAINT m365_consent_states_expiry_check CHECK (expires_at > issued_at),
    CONSTRAINT m365_consent_states_consumed_check
        CHECK (consumed_at IS NULL OR consumed_at >= issued_at)
);

-- Active-authorization lookup per actor (callback consumption + prune paths).
CREATE INDEX m365_consent_states_actor_active_idx
    ON public.m365_consent_states (actor_user_id, expires_at)
    WHERE consumed_at IS NULL;

ALTER TABLE public.m365_consent_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.m365_consent_states FORCE  ROW LEVEL SECURITY;

CREATE POLICY m365_consent_states_actor ON public.m365_consent_states
    FOR ALL TO public
    USING (
        actor_user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    )
    WITH CHECK (
        actor_user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    );

INSERT INTO public.schema_migrations(version, applied_at) VALUES (234, now()) ON CONFLICT DO NOTHING;
