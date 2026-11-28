-- V048__signin_activity.sql
-- Sign-in activity & session management.
-- Unify login_events as the canonical, all-protocol sign-in history:
--   * nullable user_id (failed/unknown sign-ins)
--   * client/protocol/auth_method/session_id/correlation_id columns + CHECKs
--   * convert to monthly RANGE partitioning (rename-attach-backfill-drop)
--   * RLS enable + force + per-user policy (app.current_user_id, fail-closed)
--   * retention config: system_config 'login_events_retain_days'
-- auth_attempts (V001) is untouched — it stays the threat/forensic log.

BEGIN;

-- 1. Rename the existing plain table aside (its PK/FK/indexes go with it).
ALTER TABLE public.login_events RENAME TO login_events_legacy;

-- 2. New partitioned parent with the all-protocol shape; user_id nullable.
--    No compound PK: audit log rows are identified by id (sequence-unique); the
--    partition key occurred_at makes a single-col PK impossible without including
--    the partition key, and we follow the mailbox_audit_log no-PK precedent here.
--    ponytail: no PK on partitioned parent; add (id, occurred_at) PK if dedup is needed.
CREATE TABLE public.login_events (
    id              bigint NOT NULL DEFAULT nextval('public.login_events_id_seq'::regclass),
    user_id         bigint,                     -- NULLABLE: failed/unknown sign-ins
    device_fingerprint uuid,
    device_name     text,
    platform        text,
    source_ip       inet,
    location        text,
    success         boolean NOT NULL,
    fail_reason     text,
    client          text,   -- web|imap|smtp|caldav|carddav
    protocol        text,   -- http|imap|smtp|caldav|carddav
    auth_method     text,   -- password|webauthn|totp|push|backup_code|saml|oidc|kerberos|app_password
    session_id      text,   -- nullable link to sessions.id / oauth refresh family
    correlation_id  text,   -- ca_signin_log.correlation_id when CA evaluated this sign-in
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT login_events_client_chk
        CHECK (client IS NULL OR client IN ('web','imap','smtp','caldav','carddav')),
    CONSTRAINT login_events_auth_method_chk
        CHECK (auth_method IS NULL OR auth_method IN
            ('password','webauthn','totp','push','backup_code','saml','oidc','kerberos','app_password'))
) PARTITION BY RANGE (occurred_at);

ALTER SEQUENCE public.login_events_id_seq OWNED BY public.login_events.id;

-- 3. Current + next month partitions (create_monthly_partitions keeps it rolling).
DO $mig$
DECLARE
    v_cur_ts   timestamptz := date_trunc('month', now());
    v_nxt_ts   timestamptz := date_trunc('month', now() + interval '1 month');
    v_cur_name text := 'login_events_' || to_char(v_cur_ts, 'YYYY_MM');
    v_nxt_name text := 'login_events_' || to_char(v_nxt_ts, 'YYYY_MM');
BEGIN
    EXECUTE format(
        'CREATE TABLE %I PARTITION OF public.login_events FOR VALUES FROM (%L) TO (%L)',
        v_cur_name,
        to_char(v_cur_ts, 'YYYY-MM-DD'),
        to_char(v_cur_ts + interval '1 month', 'YYYY-MM-DD'));
    EXECUTE format(
        'CREATE TABLE %I PARTITION OF public.login_events FOR VALUES FROM (%L) TO (%L)',
        v_nxt_name,
        to_char(v_nxt_ts, 'YYYY-MM-DD'),
        to_char(v_nxt_ts + interval '1 month', 'YYYY-MM-DD'));
END
$mig$;

-- 4. Back-fill: create any missing month partitions for legacy rows, then copy.
--    COALESCE(occurred_at, now()) guards the NOT NULL partition key if any legacy
--    rows somehow have NULL (the column had no NOT NULL in V001).
DO $bf$
DECLARE
    r      record;
    v_name text;
BEGIN
    FOR r IN
        SELECT DISTINCT
               to_char(date_trunc('month', COALESCE(occurred_at, now())), 'YYYY_MM') AS ym,
               date_trunc('month', COALESCE(occurred_at, now())) AS start_ts
        FROM public.login_events_legacy
    LOOP
        v_name := 'login_events_' || r.ym;
        IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = v_name) THEN
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF public.login_events FOR VALUES FROM (%L) TO (%L)',
                v_name,
                to_char(r.start_ts, 'YYYY-MM-DD'),
                to_char(r.start_ts + interval '1 month', 'YYYY-MM-DD'));
        END IF;
    END LOOP;

    INSERT INTO public.login_events
        (id, user_id, device_fingerprint, device_name, platform, source_ip, location,
         success, fail_reason, client, protocol, auth_method, occurred_at)
    SELECT id, user_id, device_fingerprint, device_name, platform, source_ip, location,
           success, fail_reason,
           'web',      -- legacy rows were all web sign-ins
           'http',
           'password',
           COALESCE(occurred_at, now())
    FROM public.login_events_legacy;
END
$bf$;

DROP TABLE public.login_events_legacy;

-- 5. Indexes on the partitioned parent (cascade to all partitions automatically).
CREATE INDEX login_events_user_time_idx ON public.login_events (user_id, occurred_at DESC);
CREATE INDEX login_events_corr_idx      ON public.login_events (correlation_id)
    WHERE correlation_id IS NOT NULL;
CREATE INDEX login_events_ip_idx        ON public.login_events (source_ip);

-- 6. RLS (R4): per-user policy; owner/admin access via app.current_user_id GUC.
--    InitPlan scalar subquery evaluated once per query (not per-row volatile).
--    NULLIF(…,'')::bigint → fail-closed: unset GUC → NULL → no rows visible (USING).
--    WITH CHECK allows NULL user_id rows: failed/unknown sign-ins where the
--    authserver cannot supply a user identity. The USING clause still ensures
--    users can only read their own rows (NULL user_id rows stay invisible).
ALTER TABLE public.login_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.login_events FORCE  ROW LEVEL SECURITY;

CREATE POLICY login_events_owner ON public.login_events
    FOR ALL
    TO public
    USING (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    )
    WITH CHECK (
        user_id IS NULL  -- failed/unknown sign-ins (service writer, no user identity)
        OR user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    );

-- 7. Retention config seed.
INSERT INTO public.system_config (key, value)
VALUES ('login_events_retain_days', '180')
ON CONFLICT (key) DO NOTHING;

-- 8. Migration record.
INSERT INTO public.schema_migrations (version, applied_at) VALUES (48, now())
    ON CONFLICT (version) DO NOTHING;

COMMIT;
