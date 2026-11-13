-- V209: additive connectivity-aware sync policy and device preferences.
-- All runtime behavior remains OFF behind feature.connectivity_aware_sync.

INSERT INTO public.feature_toggles(key, enabled, description) VALUES
  ('feature.connectivity_aware_sync', false,
   'Bounded optional mail sync and transfer scheduling under effective device policy. DEFAULT OFF.')
ON CONFLICT(key) DO NOTHING;

ALTER TABLE public.offline_policies
  ADD COLUMN background_sync_allowed boolean NOT NULL DEFAULT true,
  ADD COLUMN automatic_network_max text NOT NULL DEFAULT 'unmetered'
    CHECK(automatic_network_max IN ('never','unmetered','any')),
  ADD COLUMN attachment_prefetch_max text NOT NULL DEFAULT 'never'
    CHECK(attachment_prefetch_max IN ('never','unmetered','always')),
  ADD COLUMN opportunistic_requires_charging boolean NOT NULL DEFAULT true,
  ADD COLUMN connectivity_sync_mode text NOT NULL DEFAULT 'off'
    CHECK(connectivity_sync_mode IN ('off','observe','execute'));

ALTER TABLE public.user_devices
  ADD COLUMN background_sync_enabled boolean NOT NULL DEFAULT true,
  ADD COLUMN automatic_network_pref text NOT NULL DEFAULT 'unmetered'
    CHECK(automatic_network_pref IN ('never','unmetered','any')),
  ADD COLUMN attachment_prefetch_pref text NOT NULL DEFAULT 'never'
    CHECK(attachment_prefetch_pref IN ('never','unmetered','always'));

INSERT INTO public.schema_migrations(version, applied_at) VALUES (209, now())
ON CONFLICT(version) DO NOTHING;
