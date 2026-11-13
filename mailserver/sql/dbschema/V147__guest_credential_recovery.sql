-- V147__guest_credential_recovery.sql — allow the G5 durable LiveKit
-- eviction rail to fence Meet while an administrator re-invites an existing
-- guest after credential loss. The identity stays u:<user_id>; the recovery
-- intent remains incomplete through the stale-token horizon, so new Meet
-- grants cannot race an old token that can still reconnect.

ALTER TABLE public.guest_live_eviction_intents
    DROP CONSTRAINT IF EXISTS guest_live_eviction_intents_action_check;
ALTER TABLE public.guest_live_eviction_intents
    ADD CONSTRAINT guest_live_eviction_intents_action_check
        CHECK (action IN ('disable','expire','reinvite'));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (147, now())
    ON CONFLICT (version) DO NOTHING;
