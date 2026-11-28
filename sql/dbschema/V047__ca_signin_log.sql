-- V047 (CA-0b): ca_signin_log — append-only per-evaluation telemetry.
-- NO hash-chain (that is reserved for admin_audit_log / CA-CHANGE events).
-- Append-only trigger blocks UPDATE always; blocks DELETE unless the txn-local
-- GUC ca.signin_log_prune='on' is set (only ca_signin_log_prune() sets it).
-- Role-independent: works in default (worker DSN aliases main) and split-DSN alike.
-- (Spec L6/§6.2.)
-- ponytail: single table; partition like auth_attempts if volume warrants (CA-2).

CREATE TABLE ca_signin_log (
  id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at       timestamptz NOT NULL DEFAULT now(),
  user_id           bigint,                       -- nullable: pre-auth IMAP/SMTP lack a resolved user
  source_ip         inet,
  protocol          text,                         -- http|imap|smtp|caldav
  client_type       text,                         -- web|mobile|imap|smtp
  device_fp         text,                         -- forgeable FP; CA-2 replaces with a bound id
  country           text,
  matched_policy_id bigint,                        -- first-match policy (NULL = no match → default allow)
  decision          text NOT NULL,                -- the EFFECTIVE decision: allow|block|step_up|notify
  would_decision    text,                         -- the report-only would-be decision, if report_only
  report_only       boolean NOT NULL DEFAULT false,
  correlation_id    text,                         -- 'why blocked' ID stamped on the block response + echoed here
  evaluated         jsonb NOT NULL DEFAULT '[]'::jsonb
    -- ordered [{policy_id,name,outcome}], outcome ∈
    --   applied|would_block|would_step_up|would_notify|skipped|excluded
);

CREATE INDEX ca_signin_log_user_time_idx ON ca_signin_log (user_id, occurred_at DESC);
CREATE INDEX ca_signin_log_time_idx      ON ca_signin_log (occurred_at);
CREATE INDEX ca_signin_log_corr_idx      ON ca_signin_log (correlation_id);

ALTER TABLE ca_signin_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_signin_log FORCE ROW LEVEL SECURITY;

-- Read policy: this telemetry is admin-read-only (gated at the app layer on
-- access.policy_read); the worker (BYPASSRLS) handles the cross-tenant prune.
-- No per-end-user SELECT in CA-0 (end-user diagnostics = CA-1).
CREATE POLICY ca_signin_log_admin_read ON ca_signin_log
  FOR SELECT USING (true);

-- Insert policy: setjoin_app (NOBYPASSRLS) needs a permissive INSERT policy or
-- FORCE RLS default-deny blocks every append. WITH CHECK (true) = no row-level
-- restriction on what can be written; the append-only trigger prevents mutations.
-- ponytail: open insert (any row allowed); tighten to CHECK(user_id IS NOT NULL)
--   if pre-auth telemetry rows are dropped in CA-2.
CREATE POLICY ca_signin_log_app_insert ON ca_signin_log
  FOR INSERT WITH CHECK (true);

-- ca_signin_log_append_only: blocks all UPDATE and any DELETE that doesn't come
-- through ca_signin_log_prune(). The prune reducer sets a txn-local GUC
-- (ca.signin_log_prune = 'on') before the DELETE; the trigger checks for it.
-- Role-independent: works in the default deployment (worker pool aliases the
-- main pool → same current_user) and in the split-DSN deployment alike.
-- Any ad-hoc DELETE — even as setjoin_worker — is still blocked: the flag is
-- the gate, not the role (stronger append-only than the prior role check).
CREATE OR REPLACE FUNCTION ca_signin_log_append_only() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'ca_signin_log is append-only' USING ERRCODE = 'BZ083',
      HINT = 'ca_signin_log rows are immutable telemetry; never UPDATE them';
  END IF;
  -- DELETE: permit only when the sanctioned prune reducer set the txn-local flag.
  IF current_setting('ca.signin_log_prune', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'ca_signin_log rows may only be deleted via ca_signin_log_prune()'
      USING ERRCODE = 'BZ083',
      HINT = 'call ca_signin_log_prune(<days>) — ad-hoc DELETE is blocked';
  END IF;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ca_signin_log_append_only_trg
  BEFORE UPDATE OR DELETE ON ca_signin_log
  FOR EACH ROW EXECUTE FUNCTION ca_signin_log_append_only();

-- ── system_config seed ───────────────────────────────────────────────────────
-- Seed the retention key so operators can discover and change it via normal
-- config tooling; the cron task COALESCE defaults to this same value (30 days).
INSERT INTO public.system_config (key, value, encrypted, description, updated_at, updated_by)
  VALUES ('ca_signin_log_retain_days', '30', false,
          'Number of days to retain ca_signin_log rows. 0 = keep forever.', now(), NULL)
  ON CONFLICT (key) DO NOTHING;

-- ── schema_migrations row ────────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (47, now())
    ON CONFLICT (version) DO NOTHING;
