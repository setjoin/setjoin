-- V101__seed_nudges_toggle.sql — #13 stale-thread / no-reply nudges.
--
-- Query-time computation (reducers/nudges.sql: stale_thread_nudges_list +
-- nudge_dismiss) — no new columns, no cron table. Dismiss state rides
-- users.view_prefs->'nudgeDismissed', so this migration only seeds the
-- default-OFF gating toggle for the new user-visible inbox banner.

INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.stale_nudges', false, 'Background-detected stale-thread / no-reply-in-3-days inbox nudges. Seeded OFF.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (101, now()) ON CONFLICT DO NOTHING;
