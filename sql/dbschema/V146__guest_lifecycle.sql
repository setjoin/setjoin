-- V146__guest_lifecycle.sql — Guest Accounts G5 lifecycle, live-eviction
-- evidence, sponsorship backfill, and Conditional Access guest scope.

-- Durable exact-target outbox. guest_set_status snapshots the guest identity
-- against the parent and every breakout room of each ongoing meeting in which
-- it has a participant row, including recently-left rows whose token remains
-- valid. Token-mint reducers share-lock the lifecycle row before returning a
-- grant. A drain keeps each target live through the maximum 4h LiveKit token lifetime plus 5m:
-- success/not-found before retry_until is not terminal because a token minted
-- before the transition may still connect or reconnect later.
CREATE TABLE public.guest_live_eviction_intents (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    transition_id   uuid NOT NULL,
    guest_user_id   bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    action           text NOT NULL CHECK (action IN ('disable','expire')),
    room_name        uuid NOT NULL,
    identity         text NOT NULL,
    transition_at   timestamptz NOT NULL DEFAULT now(),
    retry_until      timestamptz NOT NULL DEFAULT now() + interval '4 hours 5 minutes',
    attempt_count    integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error       text,
    last_attempt_at  timestamptz,
    completed_at     timestamptz,
    UNIQUE (transition_id, room_name, identity),
    CHECK (retry_until > transition_at)
);
CREATE INDEX guest_live_eviction_due_idx
    ON public.guest_live_eviction_intents (next_attempt_at, id)
    WHERE completed_at IS NULL;
CREATE INDEX guest_live_eviction_guest_idx
    ON public.guest_live_eviction_intents (guest_user_id, id);

-- Worker-only queue/evidence. No public policy: FORCE RLS denies the app role;
-- the BYPASSRLS worker pool drains and the admin surface reads only aggregated
-- state through its already-authenticated worker-pool handler.
ALTER TABLE public.guest_live_eviction_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.guest_live_eviction_intents FORCE ROW LEVEL SECURITY;

-- Existing accepted guests predate the sponsor writer. Recover the inviter
-- only when it is still an enabled ordinary member. Missing/disabled/guest
-- inviters deliberately remain NULL and surface as sponsor-needs-review.
UPDATE public.guest_accounts g
   SET sponsor_user_id = g.invited_by,
       updated_at = now()
  FROM public.users sponsor
 WHERE g.sponsor_user_id IS NULL
   AND sponsor.id = g.invited_by
   AND sponsor.enabled
   AND NOT EXISTS (
       SELECT 1 FROM public.guest_accounts sg WHERE sg.user_id = sponsor.id
   );

-- Guest-scoped Conditional Access policies carry an empty scope_target and
-- match the authoritative guest satellite bit in PolicyEvalContext.
ALTER TABLE public.conditional_access_policies
    DROP CONSTRAINT IF EXISTS conditional_access_policies_scope_type_check;
ALTER TABLE public.conditional_access_policies
    ADD CONSTRAINT conditional_access_policies_scope_type_check
        CHECK (scope_type = ANY (
            ARRAY['global'::text, 'user'::text, 'group'::text, 'role'::text, 'guests'::text]
        ));
ALTER TABLE public.conditional_access_policies
    ADD CONSTRAINT conditional_access_policies_guest_scope_target_check
        CHECK (scope_type <> 'guests' OR scope_target = '');

ALTER TABLE public.ca_templates
    DROP CONSTRAINT IF EXISTS ca_templates_scope_type_check;
ALTER TABLE public.ca_templates
    ADD CONSTRAINT ca_templates_scope_type_check
        CHECK (scope_type = ANY (
            ARRAY['global'::text, 'user'::text, 'group'::text, 'role'::text, 'guests'::text]
        ));
ALTER TABLE public.ca_templates
    ADD CONSTRAINT ca_templates_guest_scope_target_check
        CHECK (scope_type <> 'guests' OR scope_target = '');

INSERT INTO public.schema_migrations (version, applied_at) VALUES (146, now())
    ON CONFLICT (version) DO NOTHING;
