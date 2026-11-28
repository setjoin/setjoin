-- V127__chat_oversight.sql — Chat A4b oversight substrate.
-- Durable case/custodian holds (dissolves A4a's BZ195 one-matter-per-channel
-- ceiling + the custodian snapshot-loop ceiling through exactly ONE new
-- OR EXISTS arm in chat_hold_active — contract #4), the eDiscovery search
-- record table, the join-coverage trigger, and the chat.ediscovery perm.
-- Spec: docs/superpowers/specs/2026-07-15-chat-A4b-oversight-design.md §5.

-- §A — durable case holds (L3). FORCE RLS, ZERO policies (deny-all — holds
-- invisible to custodians; every read is a workerPool admin route).
CREATE TABLE public.chat_case_holds (
  id                bigserial PRIMARY KEY,
  case_id           bigint      NOT NULL REFERENCES public.ediscovery_cases(id),
  custodian_user_id bigint,                -- scope A: every channel the user is/becomes a member of
  channel_id        bigint      REFERENCES public.chat_channels(id) ON DELETE RESTRICT,  -- scope B
  -- RESTRICT, not CASCADE: a hold table must fail loudly on channel deletion,
  -- never silently vanish coverage.
  reason            text        NOT NULL,
  created_by        bigint      NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  released_at       timestamptz,
  released_by       bigint,
  CHECK ((custodian_user_id IS NULL) <> (channel_id IS NULL))
);
CREATE UNIQUE INDEX chat_case_holds_active_uq ON public.chat_case_holds
  (case_id, coalesce(custodian_user_id,0), coalesce(channel_id,0)) WHERE released_at IS NULL;
CREATE INDEX chat_case_holds_custodian_idx ON public.chat_case_holds (custodian_user_id)
  WHERE released_at IS NULL;
ALTER TABLE public.chat_case_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_case_holds FORCE  ROW LEVEL SECURITY;

-- §B — materialized coverage (L4): snapshot at hold-set (current memberships
-- UNION channels where the custodian authored any message — pre-hold
-- departures covered) + join-trigger appends; NEVER pruned on leave
-- (leave-can't-expose). Coverage ends only with the hold's release (the
-- rows stay as history; the predicate arm joins released_at IS NULL).
CREATE TABLE public.chat_case_hold_channels (
  hold_id    bigint NOT NULL REFERENCES public.chat_case_holds(id) ON DELETE CASCADE,
  channel_id bigint NOT NULL REFERENCES public.chat_channels(id) ON DELETE RESTRICT,  -- fail loudly, never vanish coverage
  source     text   NOT NULL CHECK (source IN ('snapshot','join')),
  added_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (hold_id, channel_id)
);
CREATE INDEX chat_case_hold_channels_chan_idx ON public.chat_case_hold_channels (channel_id);
ALTER TABLE public.chat_case_hold_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_case_hold_channels FORCE  ROW LEVEL SECURITY;

-- §C — the case record of every reader invocation (L7: search rows persist,
-- result rows don't — results are re-runnable over destruction-proof held
-- scope; the export is the production artifact). FORCE RLS deny-all.
CREATE TABLE public.chat_ediscovery_searches (
  id           bigserial PRIMARY KEY,
  case_id      bigint      NOT NULL REFERENCES public.ediscovery_cases(id),
  kind         text        NOT NULL CHECK (kind IN ('search','read','export')),
  query        jsonb       NOT NULL,   -- terms/participants/channelIds/date-range OR channel+seq-range
  result_count integer     NOT NULL,
  executed_by  bigint      NOT NULL,
  executed_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.chat_ediscovery_searches ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_ediscovery_searches FORCE  ROW LEVEL SECURITY;

-- §D — chat_hold_active v2: arm 1 (the V126 boolean) + exactly ONE new arm
-- (contract #4). The BZ194 trigger and the purge sweep call this and are
-- untouched; Task 8 repoints the three admin raw-boolean reads here.
CREATE OR REPLACE FUNCTION public.chat_hold_active(p_channel_id bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT COALESCE((SELECT legal_hold FROM public.chat_channels WHERE id = p_channel_id), false)
      OR EXISTS (SELECT 1 FROM public.chat_case_hold_channels hc
                   JOIN public.chat_case_holds h ON h.id = hc.hold_id AND h.released_at IS NULL
                  WHERE hc.channel_id = p_channel_id)
$$;
SELECT apply_worker_ownership('chat_hold_active(bigint)'::regprocedure);

-- §E — join-materialization trigger (L4). SECURITY DEFINER + worker-owned:
-- chat_case_holds is deny-all, so an invoker-rights lookup would see 0 rows
-- and silently never materialize coverage (the DEFINER-under-FORCE-RLS trap,
-- failing OPEN — the worst direction for a hold).
-- BOTH-MISS RACE (L4): under READ COMMITTED a member-add concurrent with
-- hold-set is seen by neither side — the snapshot can't see the uncommitted
-- join, this trigger can't see the uncommitted hold. Both sides serialize on
-- pg_advisory_xact_lock(hashtext('chat_hold_user_' || <uid>)): this trigger
-- takes it BEFORE its hold lookup; chat_case_hold_set takes the same lock
-- BEFORE its snapshot (the A4a FIX-5 precedent, lifted to two statements).
CREATE FUNCTION public.trg_chat_member_case_hold_fn() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_hold RECORD;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('chat_hold_user_' || NEW.user_id::text));
  FOR v_hold IN
    SELECT id, case_id FROM public.chat_case_holds
     WHERE custodian_user_id = NEW.user_id AND released_at IS NULL
  LOOP
    INSERT INTO public.chat_case_hold_channels (hold_id, channel_id, source)
    VALUES (v_hold.id, NEW.channel_id, 'join')
    ON CONFLICT DO NOTHING;
    IF FOUND THEN
      PERFORM public.chat_access_audit(NULL, NEW.channel_id, 'hold.set', 'channel',
        NEW.channel_id, NULL,
        jsonb_build_object('caseId', v_hold.case_id, 'holdId', v_hold.id,
                           'scope', 'custodian', 'source', 'join'),
        NULL, NULL);
    END IF;
  END LOOP;
  RETURN NEW;
END $$;
SELECT apply_worker_ownership('trg_chat_member_case_hold_fn()'::regprocedure);
CREATE TRIGGER trg_chat_member_case_hold
  AFTER INSERT ON public.chat_channel_members
  FOR EACH ROW EXECUTE FUNCTION public.trg_chat_member_case_hold_fn();

-- §F — perm (D-A): the most privileged read in the product gets its own key.
-- Deliberately OUTSIDE the SoD class map (the drive.view/drive.manage
-- V114:551-560 precedent — do NOT touch classes.go PermClasses or
-- sod_exclusion_guard(); classify when the chat SoD pass happens).
INSERT INTO public.admin_permissions (permission_key, category, description, is_sensitive) VALUES
  ('chat.ediscovery', 'Chat', 'Search, read and export chat content for eDiscovery cases', true)
ON CONFLICT (permission_key) DO NOTHING;

UPDATE public.admin_role_groups
   SET permissions = (SELECT array_agg(DISTINCT p ORDER BY p)
                        FROM unnest(permissions || ARRAY['chat.ediscovery']) AS p)
 WHERE id = 1;   -- Super Admin, exactly as V126:234-237

-- No new toggle (L1). No new act types (L9/contract #1).
INSERT INTO public.schema_migrations (version, applied_at) VALUES (127, now())
    ON CONFLICT (version) DO NOTHING;
