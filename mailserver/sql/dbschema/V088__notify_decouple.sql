-- V088__notify_decouple.sql — durable push-intent table for the NOTIFY
-- decouple (inert behind feature.notify_decouple, seeded OFF).
--
-- Each NOTIFY at commit takes a DB-wide AccessExclusiveLock on the notify
-- queue — fine at 10k users, a throughput cliff beyond. When the toggle is ON,
-- app_notify writes an intent row inside the reducer txn instead of calling
-- pg_notify in the hot commit; the notifyjobs worker (mailserver/internal/
-- notifyjobs, workerPool) drains batches on its own short txns and emits the
-- pg_notify there. Toggle OFF (the default) = app_notify behaves
-- byte-identically to today (proof: tests/notify_decouple.pg).
--
-- Infra queue like eap_apply_jobs: no per-user RLS (rows are transient
-- cross-tenant push intents; the app role inserts via app_notify, the
-- BYPASSRLS worker deletes). Runtime-role table privileges come from
-- provision-roles.sql's schema-wide + default-privilege GRANTs.

CREATE TABLE public.notify_intents (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    channel text NOT NULL,
    payload text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Seed the toggle row OFF (V083 form): flip deliberately, only if write p99
-- degrades. ON CONFLICT DO NOTHING keeps a deliberate flip on existing installs.
INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.notify_decouple', false, 'NOTIFY decouple: app_notify writes durable notify_intents drained by the notifyjobs worker instead of pg_notify in the hot commit. Seeded OFF; flip only if write p99 degrades.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (88, now()) ON CONFLICT DO NOTHING;
