-- V270__meet_lobby_mint_fence.sql — the meet guest-lobby DURABLE admitted
-- re-mint fence (occ_bcdf321b15332f109a69e653's reducer half).
--
-- §A meeting_lobby_mint_fences — ONE immutable window row per admitted join
--     request: the FIRST admitted mint's wall-clock anchor and the 15-minute
--     horizon. meeting_lobby.sql's meeting_lobby_mint_fence (the
--     identity_media_mint_fence genre) inserts it on the first admitted poll
--     and refuses every past-window mint with BZ329; meeting_join_request_poll
--     maps that refusal to the reducer's own {"state":"expired"} wire shape —
--     the exact shape lobby.go's per-process admittedMintFence already
--     produces, which this table now makes durable (a replica restart or a
--     second gateway replica can no longer reopen the window: the anchor is
--     THE DATABASE's, not a process map's). lobby.go's in-process fence stays
--     as the second layer (belt and braces); the reducer owns the truth.
--
--     The row is INSERT-only and immutable by construction — the window never
--     extends (a fast poller only accelerates the close for everyone, the
--     occ_bcdf321 contract) — and the horizon is pinned to the V125
--     pending-expiry interval (15 minutes) by a CHECK, not a parameter, so a
--     future caller cannot silently widen the mint capability.
-- §B FORCE RLS (R4) with NO policies — the identity_media_admissions posture
--     (V168): the table is a worker/reducer-plane fence ledger, never a
--     user-data read surface. setjoin_app sees nothing (denial proven as
--     setjoin_app in tests/meet_lobby_mint_fence_rls.pg); every write flows
--     through the SECURITY DEFINER worker-owned fence function, whose owner
--     setjoin_worker is BYPASSRLS. Rows are tiny, INSERT-only, and
--     deliberately outlive their window (an expired row is the durable
--     CLOSED marker — sweeping it would reopen the window); they cascade
--     away with their join request. No worker arm is owed.
--
-- Feature flag: NONE seeded here. The fence admits nothing new — it only
-- bounds an existing admitted-leg capability at the reducer layer, and the
-- within-window behavior is byte-identical to today's.

-- ════════════════════════════════════════════════════════════════════════
-- §A — the durable admitted re-mint window ledger
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE public.meeting_lobby_mint_fences (
    join_request_id BIGINT PRIMARY KEY
        REFERENCES public.meeting_join_requests(id) ON DELETE CASCADE,
    meeting_id      BIGINT NOT NULL
        REFERENCES public.meetings(id) ON DELETE CASCADE,
    identity        TEXT NOT NULL CHECK (
        octet_length(identity) BETWEEN 3 AND 255
        AND identity !~ '[[:cntrl:]]'
    ),
    -- the FIRST admitted mint's anchor. DEFAULT statement_timestamp() (not
    -- now()): the fence function inserts both columns from ONE statement, so
    -- the §A CHECK below holds exactly — the window is anchored at the mint
    -- statement, never at the enclosing transaction's start.
    first_mint_at   TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    expires_at      TIMESTAMPTZ NOT NULL,
    -- 15 minutes = admittedReMintWindow (lobby.go) = the V125 join-request
    -- pending-expiry horizon. A table-level pin: the horizon is a constant
    -- of the capability, never a tunable.
    CHECK (expires_at = first_mint_at + interval '15 minutes')
);
CREATE INDEX meeting_lobby_mint_fences_expiry_idx
    ON public.meeting_lobby_mint_fences(expires_at);

-- ════════════════════════════════════════════════════════════════════════
-- §B — FORCE RLS, zero policies (the V168 identity_media_admissions posture)
-- ════════════════════════════════════════════════════════════════════════
ALTER TABLE public.meeting_lobby_mint_fences ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meeting_lobby_mint_fences FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.meeting_lobby_mint_fences OWNER TO setjoin_owner;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (270, now())
    ON CONFLICT (version) DO NOTHING;
