-- V123: fix user_notification_prefs' global-row dedup (bug found mid Chat A3
-- QoL Task 7 "notif_level + DND client surface" — not chat-specific).
--
-- user_notification_prefs_user_id_device_fingerprint_key was a PLAIN
-- UNIQUE (user_id, device_fingerprint) constraint. Postgres treats every
-- NULL as distinct from every other NULL under a plain UNIQUE constraint, so
-- `ON CONFLICT (user_id, device_fingerprint) DO UPDATE`
-- (internal/user/notification_prefs.go's SetPrefs, the ONLY writer of this
-- table) never actually conflicts for the GLOBAL preference row
-- (device_fingerprint IS NULL — the common case: every plain Settings >
-- Notifications save uses it, not just per-device pushes). Two back-to-back
-- global PUTs silently INSERT two rows instead of updating one; GetPrefs's
-- `ORDER BY device_fingerprint NULLS FIRST` (no secondary sort key) then
-- returns an ARBITRARY tie among them — a user who saves notification
-- preferences twice can see stale settings on next load. This broke the
-- "preserve unrelated fields on update" promise the code already claimed
-- for read_receipt_policy (and now chat_notifications) since the table was
-- created; internal/user/notification_prefs_test.go's pre-existing
-- TestNotificationPrefsHandler_RoundTrip worked around it with an explicit
-- DELETE before each PUT rather than fixing the constraint.
--
-- Fix: NULLS NOT DISTINCT (PG15+, already used at V015/V041/V109 for the
-- identical "NULL should still dedupe" need) makes two NULL
-- device_fingerprints collide for uniqueness purposes too, so ON CONFLICT
-- fires correctly for the global row going forward.
--
-- Dedup first: a deployment that already accumulated duplicate global rows
-- would fail ADD CONSTRAINT on an existing violation. Keep the most-recently
-- -updated row per (user_id, device_fingerprint) — "last save wins", the
-- same semantics the fixed ON CONFLICT path enforces from here on.
DELETE FROM public.user_notification_prefs a
  USING public.user_notification_prefs b
 WHERE a.user_id = b.user_id
   AND a.device_fingerprint IS NOT DISTINCT FROM b.device_fingerprint
   AND (a.updated_at, a.id) < (b.updated_at, b.id);

ALTER TABLE public.user_notification_prefs
  DROP CONSTRAINT user_notification_prefs_user_id_device_fingerprint_key;
ALTER TABLE public.user_notification_prefs
  ADD CONSTRAINT user_notification_prefs_user_id_device_fingerprint_key
    UNIQUE NULLS NOT DISTINCT (user_id, device_fingerprint);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (123, now())
  ON CONFLICT (version) DO NOTHING;
