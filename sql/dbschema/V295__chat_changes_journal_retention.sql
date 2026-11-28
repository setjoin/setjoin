-- V295__chat_changes_journal_retention.sql — Wave 2.6 (#553): dedicated
-- monotonic public.chat_changes journal, compliance purge 'resync' sentinel,
-- unified effective_journal_retention_days() >= 30d retention floor across
-- mail/chat/drive/revocations, and public.sync_tombstone_floor mandatory
-- scope-membership reconcile signaling.
--
-- Isolation posture:
--   * public.chat_changes is ENABLE + FORCE ROW LEVEL SECURITY with member-only
--     SELECT and bounded INSERT policies via public.chat_member_role(channel_id,
--     app.current_user_id) and change_seq <= chat_channels.change_seq
--     (fail-closed on unset GUC; no UPDATE/DELETE by setjoin_app; worker-only
--     pruning via setjoin_worker).
--   * public.sync_tombstone_floor is ENABLE + FORCE ROW LEVEL SECURITY with
--     ZERO permissive policies (deny-all to setjoin_app; worker-only DML; read
--     by app/worker solely through worker-owned SECURITY DEFINER
--     sync_tombstone_floor_at()).
--   * ZERO public.blobs columns and ZERO public.feature_toggles rows.
--   * chat_channels.last_purged_seq semantics remain strictly unchanged
--     (compliance record-floor provenance for eDiscovery/chain-anchor).

CREATE TABLE public.chat_changes (
    channel_id BIGINT      NOT NULL REFERENCES public.chat_channels(id) ON DELETE CASCADE,
    change_seq BIGINT      NOT NULL,
    message_id BIGINT      NULL,
    op         TEXT        NOT NULL
        CHECK (op IN ('created', 'updated', 'destroyed', 'pinned', 'unpinned', 'resync')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (channel_id, change_seq),
    CHECK ((op = 'resync' AND message_id IS NULL) OR (op <> 'resync' AND message_id IS NOT NULL))
);

CREATE INDEX idx_chat_changes_created_at
    ON public.chat_changes (created_at);

COMMENT ON TABLE public.chat_changes IS
  'Dedicated monotonic per-channel Chat sync change journal (V295, #553). '
  'Appended transactionally on every chat_channels.change_seq bump and compliance '
  'purge resync sentinel; member-scoped SELECT/INSERT under FORCE RLS, worker-only prune.';

ALTER TABLE public.chat_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_changes FORCE ROW LEVEL SECURITY;

CREATE POLICY chat_changes_select ON public.chat_changes
    FOR SELECT TO public
    USING (public.chat_member_role(
        channel_id,
        (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
    ) IS NOT NULL);

CREATE POLICY chat_changes_insert ON public.chat_changes
    FOR INSERT TO public
    WITH CHECK (
        public.chat_member_role(
            channel_id,
            (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
        ) IS NOT NULL
        AND change_seq <= (
            SELECT c.change_seq
              FROM public.chat_channels c
             WHERE c.id = channel_id
        )
    );

REVOKE ALL ON public.chat_changes FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
        ALTER TABLE public.chat_changes OWNER TO setjoin_owner;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE ALL ON public.chat_changes FROM setjoin_app;
        GRANT SELECT, INSERT ON public.chat_changes TO setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        REVOKE ALL ON public.chat_changes FROM setjoin_worker;
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.chat_changes TO setjoin_worker;
    END IF;
END $$;

CREATE TABLE public.sync_tombstone_floor (
    id                          SMALLINT    PRIMARY KEY CHECK (id = 1),
    pruned_before_at            TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
    pruned_before_revocation_id BIGINT      NOT NULL DEFAULT 0,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO public.sync_tombstone_floor (id, pruned_before_at, pruned_before_revocation_id, updated_at)
VALUES (1, '-infinity', 0, now())
ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE public.sync_tombstone_floor IS
  'Singleton watermark recording the oldest retained scope_revocations horizon '
  '(V295, #553). FORCE RLS deny-all to setjoin_app; read only via worker-owned '
  'SECURITY DEFINER sync_tombstone_floor_at().';

ALTER TABLE public.sync_tombstone_floor ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sync_tombstone_floor FORCE ROW LEVEL SECURITY;

REVOKE ALL ON public.sync_tombstone_floor FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
        ALTER TABLE public.sync_tombstone_floor OWNER TO setjoin_owner;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE ALL ON public.sync_tombstone_floor FROM setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        REVOKE ALL ON public.sync_tombstone_floor FROM setjoin_worker;
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.sync_tombstone_floor TO setjoin_worker;
    END IF;
END $$;

-- ── Upgrade-safe verbatim reducer definitions (canonical sources under
--    mailserver/sql/reducers/) so `upgrade.sh` -> `mailctl schema apply --yes`
--    installs every Wave 2.6 reducer atomically alongside V295 DDL while fresh
--    installs remain byte-identical under scripts/check-schema-determinism.sh.

-- [embedded verbatim from reducers/chat_changes.sql]
CREATE OR REPLACE FUNCTION effective_journal_retention_days(
    p_requested_days INT DEFAULT 30
) RETURNS INT
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT GREATEST(
        COALESCE(p_requested_days, 30),
        COALESCE((
            SELECT MAX(max_offline_days)
              FROM public.offline_policies
             WHERE enabled = TRUE
               AND max_offline_days IS NOT NULL
        ), 0),
        30
    );
$$;

DO $$
DECLARE
    v_granted_create BOOLEAN := FALSE;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        IF NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
            GRANT CREATE ON SCHEMA public TO setjoin_worker;
            v_granted_create := TRUE;
        END IF;
        PERFORM public.apply_worker_ownership(
            'public.effective_journal_retention_days(integer)'::regprocedure
        );
        IF v_granted_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    ELSE
        REVOKE ALL ON FUNCTION public.effective_journal_retention_days(integer) FROM PUBLIC;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION sync_tombstone_floor_at()
RETURNS TIMESTAMPTZ
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT COALESCE(
        (SELECT pruned_before_at FROM public.sync_tombstone_floor WHERE id = 1),
        '-infinity'::timestamptz
    );
$$;

DO $$
DECLARE
    v_granted_create BOOLEAN := FALSE;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        IF NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
            GRANT CREATE ON SCHEMA public TO setjoin_worker;
            v_granted_create := TRUE;
        END IF;
        PERFORM public.apply_worker_ownership(
            'public.sync_tombstone_floor_at()'::regprocedure
        );
        IF v_granted_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    ELSE
        REVOKE ALL ON FUNCTION public.sync_tombstone_floor_at() FROM PUBLIC;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION append_chat_change(
    p_channel_id BIGINT,
    p_change_seq BIGINT,
    p_message_id BIGINT,
    p_op         TEXT
) RETURNS VOID
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_channel_id IS NULL OR p_change_seq IS NULL OR p_change_seq <= 0 THEN
        RAISE EXCEPTION 'append_chat_change requires positive channel_id and change_seq'
            USING ERRCODE = 'BZ160', HINT = '{"type":"invalidArguments"}';
    END IF;
    IF p_op IS NULL OR p_op NOT IN ('created', 'updated', 'destroyed', 'pinned', 'unpinned', 'resync') THEN
        RAISE EXCEPTION 'append_chat_change: invalid op %', p_op
            USING ERRCODE = 'BZ160', HINT = '{"type":"invalidArguments"}';
    END IF;
    IF p_op = 'resync' AND p_message_id IS NOT NULL THEN
        RAISE EXCEPTION 'append_chat_change: resync sentinel requires NULL message_id'
            USING ERRCODE = 'BZ160', HINT = '{"type":"invalidArguments"}';
    END IF;
    IF p_op <> 'resync' AND p_message_id IS NULL THEN
        RAISE EXCEPTION 'append_chat_change: op % requires non-NULL message_id', p_op
            USING ERRCODE = 'BZ160', HINT = '{"type":"invalidArguments"}';
    END IF;

    INSERT INTO public.chat_changes (channel_id, change_seq, message_id, op)
    VALUES (p_channel_id, p_change_seq, p_message_id, p_op)
    ON CONFLICT (channel_id, change_seq) DO NOTHING;
END;
$$;

CREATE OR REPLACE FUNCTION chat_changes_since(
    p_user_id    BIGINT,
    p_channel_id BIGINT,
    p_since_seq  BIGINT,
    p_limit      INT DEFAULT 200
) RETURNS JSONB
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_invoker_role       TEXT := COALESCE(NULLIF(current_setting('role', TRUE), 'none'), session_user);
    v_is_privileged      BOOLEAN := FALSE;
    v_guc_uid_txt        TEXT := NULLIF(current_setting('app.current_user_id', TRUE), '');
    v_guc_uid            BIGINT;
    v_head               BIGINT;
    v_floor              BIGINT;
    v_joined_at          TIMESTAMPTZ;
    v_since              BIGINT;
    v_effective_since    BIGINT;
    v_oldest             BIGINT;
    v_lim                INT;
    v_tombstone_floor    TIMESTAMPTZ;
    v_cursor_at          TIMESTAMPTZ;
    v_tombstone_exceeded BOOLEAN := FALSE;
    v_changes            JSONB;
    v_new_state          BIGINT;
    v_has_more           BOOLEAN := FALSE;
BEGIN
    SELECT COALESCE(r.rolsuper OR r.rolbypassrls, FALSE)
      INTO v_is_privileged
      FROM pg_catalog.pg_roles r
     WHERE r.rolname = v_invoker_role;

    IF v_guc_uid_txt IS NOT NULL AND v_guc_uid_txt ~ '^[0-9]+$' THEN
        v_guc_uid := v_guc_uid_txt::BIGINT;
    END IF;

    IF NOT v_is_privileged AND v_guc_uid IS DISTINCT FROM p_user_id THEN
        RAISE EXCEPTION 'not a member of channel %', p_channel_id
            USING ERRCODE = 'BZ163', HINT = '{"type":"forbidden"}';
    ELSIF v_guc_uid IS NOT NULL AND v_guc_uid <> p_user_id THEN
        RAISE EXCEPTION 'not a member of channel %', p_channel_id
            USING ERRCODE = 'BZ163', HINT = '{"type":"forbidden"}';
    END IF;

    SELECT c.change_seq, m.history_floor_seq, m.joined_at
      INTO v_head, v_floor, v_joined_at
      FROM public.chat_channels c
      JOIN public.chat_channel_members m
        ON m.channel_id = c.id AND m.user_id = p_user_id
     WHERE c.id = p_channel_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not a member of channel %', p_channel_id
            USING ERRCODE = 'BZ163', HINT = '{"type":"forbidden"}';
    END IF;

    v_since := COALESCE(p_since_seq, 0);
    IF v_since < 0 OR v_since > v_head THEN
        RAISE EXCEPTION 'Cannot calculate changes'
            USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
    END IF;

    SELECT MIN(cc.change_seq)
      INTO v_oldest
      FROM public.chat_changes cc
     WHERE cc.channel_id = p_channel_id
       AND cc.change_seq <= v_head;

    v_effective_since := GREATEST(v_since, COALESCE(v_floor, 0));

    IF v_effective_since < COALESCE(v_oldest - 1, v_head) THEN
        RAISE EXCEPTION 'Cannot calculate changes'
            USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM public.chat_changes cc
         WHERE cc.channel_id = p_channel_id
           AND cc.change_seq > v_effective_since
           AND cc.change_seq <= v_head
           AND cc.op = 'resync'
    ) THEN
        RAISE EXCEPTION 'Cannot calculate changes'
            USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
    END IF;

    v_tombstone_floor := public.sync_tombstone_floor_at();
    IF v_since > 0 AND v_tombstone_floor > '-infinity'::timestamptz THEN
        SELECT MAX(cc.created_at)
          INTO v_cursor_at
          FROM public.chat_changes cc
         WHERE cc.channel_id = p_channel_id
           AND cc.change_seq <= v_since;
        IF v_cursor_at IS NULL OR v_cursor_at < v_tombstone_floor THEN
            v_tombstone_exceeded := TRUE;
        END IF;
    END IF;

    v_lim := LEAST(GREATEST(COALESCE(p_limit, 200), 1), 1000);

    WITH scanned AS MATERIALIZED (
        SELECT cc.change_seq, cc.op, cc.message_id
          FROM public.chat_changes cc
         WHERE cc.channel_id = p_channel_id
           AND cc.change_seq > v_effective_since
           AND cc.change_seq <= v_head
           AND cc.op <> 'resync'
         ORDER BY cc.change_seq ASC
         LIMIT v_lim
    ),
    projected AS (
        SELECT s.change_seq,
               CASE
                   WHEN m.id IS NULL THEN
                       jsonb_build_object(
                           'seq', s.change_seq,
                           'op', s.op,
                           'messageId', s.message_id
                       )
                   WHEN m.parent_message_id IS NOT NULL AND NOT EXISTS (
                       SELECT 1
                         FROM public.chat_messages parent
                        WHERE parent.id = m.parent_message_id
                          AND parent.seq > COALESCE(v_floor, 0)
                          AND (v_floor IS NULL OR parent.created_at >= v_joined_at)
                   ) THEN
                       jsonb_build_object(
                           'seq', s.change_seq,
                           'op', s.op,
                           'messageId', s.message_id,
                           'message', public.chat_message_to_json(m, p_user_id)
                                      || jsonb_build_object('parentMessageId', NULL, 'parentUnavailable', TRUE)
                       )
                   ELSE
                       jsonb_build_object(
                           'seq', s.change_seq,
                           'op', s.op,
                           'messageId', s.message_id,
                           'message', public.chat_message_to_json(m, p_user_id)
                       )
               END AS item
          FROM scanned s
          LEFT JOIN public.chat_messages m
            ON m.id = s.message_id
           AND m.channel_id = p_channel_id
         WHERE v_floor IS NULL
            OR (
                m.id IS NOT NULL
                -- GUEST_HISTORY_FLOOR: chat_changes_since
                AND m.seq > v_floor
                AND m.created_at >= v_joined_at
            )
    )
    SELECT COALESCE(
               (SELECT jsonb_agg(p.item ORDER BY p.change_seq ASC) FROM projected p),
               '[]'::jsonb
           ),
           COALESCE(
               (SELECT MAX(s.change_seq) FROM scanned s),
               GREATEST(v_since, COALESCE(LEAST(v_floor, v_head), 0))
           )
      INTO v_changes, v_new_state;

    v_has_more := EXISTS (
        SELECT 1
          FROM public.chat_changes cc
         WHERE cc.channel_id = p_channel_id
           AND cc.change_seq > v_new_state
           AND cc.change_seq <= v_head
    );

    RETURN jsonb_build_object(
        'channelId', p_channel_id,
        'oldState', v_since::TEXT,
        'newState', v_new_state::TEXT,
        'hasMoreChanges', v_has_more,
        'changes', v_changes,
        'tombstoneFloorExceeded', v_tombstone_exceeded
    );
END;
$$;

CREATE OR REPLACE FUNCTION prune_chat_changes(
    p_max_window_days INT DEFAULT 30,
    p_high_water      INT DEFAULT 50000
) RETURNS BIGINT
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_deleted        BIGINT := 0;
    v_n              BIGINT;
    v_retention_days INT;
    v_high_water     INT;
    v_cutoff         TIMESTAMPTZ;
BEGIN
    PERFORM public.work_queue_require_worker();

    v_retention_days := public.effective_journal_retention_days(p_max_window_days);
    v_high_water     := GREATEST(COALESCE(p_high_water, 50000), 0);
    v_cutoff         := now() - make_interval(days => v_retention_days);

    -- Arm 1: contiguous prefix-only age prune per channel_id (never punches a
    -- hole after a retained seq when concurrent commits have skewed timestamps).
    WITH bounds AS (
        SELECT channel_id,
               MIN(change_seq) FILTER (WHERE created_at >= v_cutoff) AS keep_from_seq
          FROM public.chat_changes
         GROUP BY channel_id
    ),
    del AS (
        DELETE FROM public.chat_changes c
         USING bounds b
         WHERE c.channel_id = b.channel_id
           AND (b.keep_from_seq IS NULL OR c.change_seq < b.keep_from_seq)
        RETURNING 1
    )
    SELECT count(*) INTO v_n FROM del;
    v_deleted := v_deleted + v_n;

    WITH ranked AS (
        SELECT channel_id, change_seq,
               dense_rank() OVER (PARTITION BY channel_id ORDER BY change_seq DESC) AS rnk
          FROM public.chat_changes
    ),
    del2 AS (
        DELETE FROM public.chat_changes c
         USING ranked r
         WHERE c.channel_id = r.channel_id
           AND c.change_seq = r.change_seq
           AND r.rnk > v_high_water
        RETURNING 1
    )
    SELECT count(*) INTO v_n FROM del2;
    v_deleted := v_deleted + v_n;

    RETURN v_deleted;
END;
$$;

DO $$
BEGIN
    REVOKE ALL ON FUNCTION public.prune_chat_changes(integer, integer) FROM PUBLIC;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE ALL ON FUNCTION public.prune_chat_changes(integer, integer) FROM setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.prune_chat_changes(integer, integer) TO setjoin_worker;
    END IF;
END $$;

-- [embedded verbatim from reducers/chat_message.sql]
CREATE OR REPLACE FUNCTION chat_message_send(
    p_user_id bigint, p_channel_id bigint, p_body text,
    p_parent_id bigint DEFAULT NULL, p_mentions bigint[] DEFAULT '{}',
    p_broadcast text DEFAULT NULL, p_attachments jsonb DEFAULT '[]',
    p_msg_type text DEFAULT 'text', p_payload jsonb DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_role      text;
    v_can_post  boolean;
    v_history_floor bigint;
    v_joined_at timestamptz;
    v_post      text;
    v_archived  boolean;
    v_seq       bigint;
    v_id        bigint;
    v_natt      int;
    v_att       jsonb;
    v_space_id  bigint;
    v_ord       int := 0;
    v_base      text;
    v_ext       text;
    v_candidate text;
    v_suffix    int;
    v_node_id   bigint;
    v_put       jsonb;
    v_msg_type  text;
    v_broadcast_perm text;
    v_rate      int;
    v_sent      int;
    v_fed_domain text;
    v_fed_remote text;
    v_room_id      text;
    v_room_removed timestamptz;
    v_channel_kind text;
    v_rec          record;
    v_payload      jsonb;
BEGIN
    PERFORM guest_require_active(p_user_id);  -- BZ219 belt (no-op for members)
    v_msg_type := COALESCE(p_msg_type, 'text');
    -- C2 Task 1 (V140 msg_type widening — the forge guard the widening
    -- requires): 'system' is reserved for the federation applier's own
    -- LOCAL gap-marker insert (Q9 coverage epochs, Task 5) — never a
    -- user-settable value. Without this refusal, V140's widened CHECK would
    -- let any user forge a 'system' row through the ordinary send path.
    -- Runs for EVERY channel, federated or not.
    IF v_msg_type = 'system' THEN
        RAISE EXCEPTION 'msg_type ''system'' is reserved for federation gap markers'
            USING ERRCODE='BZ168', HINT='{"type":"invalidArguments","detail":"msg_type ''system'' is not user-settable"}';
    END IF;
    -- C1 Task 2 / C2 Task 3: federation branch guards run FIRST, ahead of
    -- the generic BZ168 body checks below, so a federated channel's
    -- oversized/toggle-off/closed-room/wrong-content send surfaces a
    -- federation-specific code instead. v_room_id/v_room_removed cover BOTH
    -- room shapes (hub: federated_peer_domain NULL; spoke mirror:
    -- federated_peer_domain = the bound hub) — a spoke mirror carries BOTH
    -- v_fed_domain and v_room_id, so the toggle/body checks below fire off
    -- either condition alone (harmlessly redundant for a spoke send).
    SELECT federated_peer_domain, federated_remote_id, federated_room_id, federated_room_removed_at
      INTO v_fed_domain, v_fed_remote, v_room_id, v_room_removed
      FROM chat_channels WHERE id = p_channel_id;
    IF v_fed_domain IS NOT NULL OR v_room_id IS NOT NULL THEN
        IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.federation'), FALSE) THEN
            RAISE EXCEPTION 'federated messaging unavailable (feature.federation is disabled)'
                USING ERRCODE='BZ206', HINT='{"type":"forbidden","detail":"feature.federation is disabled"}';
        END IF;
        -- BZ213: the kicked/closed-mirror choke, enforced at the send
        -- checkpoint (Q3/Q9's advisory reuses the SAME field) — never just
        -- a UI affordance. A hub channel never carries removed_at (only
        -- Task 5's spoke applier ever sets it), so this only ever fires for
        -- a spoke mirror.
        IF v_room_removed IS NOT NULL THEN
            RAISE EXCEPTION 'this federated room was closed (kicked or revoked) — archive-read-only'
                USING ERRCODE='BZ213', HINT='{"type":"forbidden","detail":"federated room removed/closed"}';
        END IF;
        IF p_body IS NOT NULL AND octet_length(p_body) > 65536 THEN
            RAISE EXCEPTION 'federated message body over 64KiB'
                USING ERRCODE='BZ206',
                      HINT='{"type":"invalidArguments","detail":"federated messages are capped at 64KiB, mirroring the inbound poison cap"}';
        END IF;
        -- BZ212 (Q11 content scope): a federated room propagates plain text
        -- messages only — an attachment or a non-'text' msg_type (poll/
        -- voice/call/etc.) could never propagate to the other member orgs'
        -- copies, structurally desyncing them. DM sends are unaffected
        -- (v_room_id IS NULL there). Computed inline (not v_natt, which is
        -- assigned further below) since this guard runs first.
        IF v_room_id IS NOT NULL AND (
             jsonb_array_length(COALESCE(p_attachments, '[]'::jsonb)) > 0
             OR v_msg_type <> 'text') THEN
            RAISE EXCEPTION 'federated rooms carry plain text messages only'
                USING ERRCODE='BZ212',
                      HINT='{"type":"invalidArguments","detail":"attachments and non-text msg_type cannot propagate to a federated room"}';
        END IF;
    END IF;
    -- BZ178: voice cap. A missing/non-numeric durationMs is left for the
    -- caller's own reducer (Task 9's poll wrapper, a future voice route) to
    -- shape-validate — this is strictly the numeric cap, same posture as
    -- BZ172's "cap first, shape second" split.
    IF v_msg_type = 'voice' AND jsonb_typeof(p_payload -> 'durationMs') = 'number'
       AND (p_payload ->> 'durationMs')::numeric > 300000 THEN
        RAISE EXCEPTION 'voice message exceeds the 5-minute (300000ms) cap'
            USING ERRCODE='BZ178', HINT='{"type":"invalidArguments","detail":"voice messages are capped at 300000ms"}';
    END IF;
    v_natt := jsonb_array_length(COALESCE(p_attachments, '[]'::jsonb));
    -- attachment-only messages are legal (Design C2/D2): empty/whitespace
    -- body is fine iff at least one attachment rides along.
    IF v_natt = 0 AND coalesce(btrim(p_body), '') = '' THEN
        RAISE EXCEPTION 'message body empty or over 64KiB'
            USING ERRCODE='BZ168', HINT='{"type":"invalidArguments"}';
    END IF;
    IF p_body IS NOT NULL AND octet_length(p_body) > 65536 THEN
        RAISE EXCEPTION 'message body empty or over 64KiB'
            USING ERRCODE='BZ168', HINT='{"type":"invalidArguments"}';
    END IF;
    -- BZ172: cap + basic shape (per-item deep manifest validation is
    -- drive_file_put_version's own BZ141 job — not duplicated here).
    IF v_natt > 8 THEN
        RAISE EXCEPTION 'too many attachments (max 8 per message)'
            USING ERRCODE='BZ172', HINT='{"type":"invalidArguments","detail":"max 8 attachments per message"}';
    END IF;
    IF v_natt > 0 AND EXISTS (
         SELECT 1 FROM jsonb_array_elements(p_attachments) a
          WHERE jsonb_typeof(a) <> 'object'
             OR NULLIF(btrim(a->>'sha256'), '') IS NULL
             OR NULLIF(btrim(a->>'name'), '') IS NULL
             OR (a->>'size') IS NULL OR (a->>'size')::bigint < 0
             OR jsonb_typeof(COALESCE(a->'manifest', '[]'::jsonb)) <> 'array') THEN
        RAISE EXCEPTION 'invalid attachment payload'
            USING ERRCODE='BZ172', HINT='{"type":"invalidArguments","detail":"bad attachment name/size/manifest"}';
    END IF;
    SELECT m.role, m.can_post, m.history_floor_seq, m.joined_at,
           c.post_permission, c.is_archived, c.broadcast_permission, c.kind
      INTO v_role, v_can_post, v_history_floor, v_joined_at,
           v_post, v_archived, v_broadcast_perm, v_channel_kind
      FROM chat_channel_members m JOIN chat_channels c ON c.id = m.channel_id
     WHERE m.channel_id = p_channel_id AND m.user_id = p_user_id;
    IF v_role IS NULL THEN
        RAISE EXCEPTION 'not a member of channel %', p_channel_id
            USING ERRCODE='BZ163', HINT='{"type":"forbidden"}';
    END IF;
    -- Guest G2: NULL is legacy-member inheritance only. A pre-V145 guest
    -- membership has no trustworthy posting snapshot, so it fails closed;
    -- ordinary members retain the historical NULL=allowed behavior. This
    -- check precedes every send-side write (rate counter, state, message,
    -- mention, intent, and notify).
    IF v_can_post IS FALSE OR (v_can_post IS NULL AND is_guest_account(p_user_id)) THEN
        RAISE EXCEPTION 'channel membership is read-only'
            USING ERRCODE='BZ220', HINT='{"type":"forbidden","detail":"channel membership is read-only"}';
    END IF;
    -- A4a Task 10 rate limit (send.sql BZ004 genre, per-minute window).
    -- 60/min default: a hard abuse ceiling no human sustains for a minute, while
    -- leaving CJK short-burst chat (好的/收到/嗯) unimpeded — 30/min is one message
    -- every 2s sustained and a lively 讨论 with IME quick-sends crosses it.
    -- Deliberately NOT gated on feature.chat_compliance — this is abuse
    -- control, not a compliance feature, and ships live to every deployment.
    -- ponytail: single-row upsert counter; per-channel or token-bucket limits
    -- only if a real deployment outgrows the flat per-user cap.
    v_rate := COALESCE((SELECT (value #>> '{}')::int FROM system_config
                         WHERE key = 'chat.send_rate_per_minute'), 60);
    IF v_rate > 0 THEN
      INSERT INTO chat_send_counters AS c (user_id, window_start, sent_count)
      VALUES (p_user_id, date_trunc('minute', now()), 1)
      ON CONFLICT (user_id) DO UPDATE SET
        sent_count   = CASE WHEN c.window_start = date_trunc('minute', now())
                            THEN c.sent_count + 1 ELSE 1 END,
        window_start = date_trunc('minute', now())
      RETURNING sent_count INTO v_sent;
      IF v_sent > v_rate THEN
        RAISE EXCEPTION 'chat send rate exceeded'
          USING ERRCODE='BZ196',
                HINT=jsonb_build_object('type','sending_quota_exceeded',
                        'detail','per-user chat send rate',
                        'retryAfterSeconds',
                        GREATEST(1, 60 - EXTRACT(SECOND FROM now())::int))::text;
      END IF;
    END IF;
    -- archive = read-only (Task 4 interface, decision-audit row 24): no new
    -- posts once a channel is archived.
    IF v_archived THEN
        RAISE EXCEPTION 'channel % is archived (read-only)', p_channel_id
            USING ERRCODE='BZ171', HINT='{"type":"forbidden"}';
    END IF;
    IF v_post = 'admins' AND v_role NOT IN ('owner', 'admin') THEN
        RAISE EXCEPTION 'announcement channel: post restricted to admins'
            USING ERRCODE='BZ164', HINT='{"type":"forbidden"}';
    END IF;
    -- Pillar A3 QoL Task 8: the gate now reads the channel's OWN
    -- broadcast_permission (V122, default 'admins') instead of a hard-coded
    -- owner/admin-only rule — chat_channel_update lets an owner/admin flip it
    -- to 'all' so any member may @channel/@all in that specific channel.
    IF p_broadcast IS NOT NULL AND v_broadcast_perm = 'admins' AND v_role NOT IN ('owner', 'admin') THEN
        RAISE EXCEPTION '@channel/@all restricted to channel admins'
            USING ERRCODE='BZ166', HINT='{"type":"forbidden"}';
    END IF;
    -- One code for every unusable parent, including a remembered pre-floor
    -- id after a guest is removed/re-added. A caller may only create a reply
    -- to a parent they can currently read; otherwise the write itself would
    -- confirm hidden history and create a permanent covert thread edge.
    IF p_parent_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM chat_messages
          WHERE id = p_parent_id AND channel_id = p_channel_id AND deleted_at IS NULL
            -- GUEST_HISTORY_FLOOR: chat_message_send
            AND seq > COALESCE(v_history_floor, 0)
            AND (v_history_floor IS NULL OR created_at >= v_joined_at)) THEN
        RAISE EXCEPTION 'thread parent not in this channel (or deleted)'
            USING ERRCODE='BZ165', HINT='{"type":"invalidArguments"}';
    END IF;
    -- BZ173: reducer-level defense (route gate is primary) — membership has
    -- already been proven above, so this fires strictly after BZ163.
    IF v_natt > 0 AND NOT COALESCE(
         (SELECT enabled FROM feature_toggles WHERE key = 'feature.drive'), FALSE) THEN
        RAISE EXCEPTION 'attachments unavailable (feature.drive is disabled)'
            USING ERRCODE='BZ173', HINT='{"type":"forbidden","detail":"feature.drive is disabled"}';
    END IF;
    -- commit-ordered seq: the channel row lock serializes concurrent
    -- senders, so seq order == commit order and since(seq) can never skip a
    -- row (the raw-identity cursor provably can — review C2/F2).
    UPDATE chat_channels SET change_seq = change_seq + 1
      WHERE id = p_channel_id RETURNING change_seq INTO v_seq;
    -- Trusted-preview provenance (med-chat-unfurl-href-001): payload.preview
    -- is EXCLUSIVELY the unfurl worker's write — chat_message_unfurl_apply
    -- copying the chat_link_previews record that internal/chat/unfurl.go
    -- fetched server-side (SSRF-hardened) for the message's own URL. A
    -- sender-supplied preview used to be stored verbatim, handing every
    -- future renderer an attacker-chosen anchor href plus fully
    -- attacker-authored title/description inside the trusted enrichment
    -- chrome (an HTTPS allowlist alone would still admit forged HTTPS
    -- cards). Stripping the key here binds the rendered card to the
    -- authoritative unfurl result: title/body/image can only ever come from
    -- the server-side unfurl record, never from attacker-authored payload
    -- fields. Sanitize (not RAISE): preview is best-effort enrichment, so a
    -- forged preview degrades to a plain message, the same silent posture as
    -- every unfurl failure mode (chat_unfurl.sql) — and the jsonb_typeof
    -- guard covers the non-object payload shapes (NULL / scalar / array)
    -- that `- 'preview'` cannot delete from.
    v_payload := p_payload;
    IF jsonb_typeof(v_payload) = 'object' THEN
        v_payload := v_payload - 'preview';
    END IF;
    -- message row FIRST: chat_message_attachments.message_id is NOT NULL
    -- (Eng L1), and an attachment-only send stores '' for the body (the
    -- projection already treats '' as empty for a soft-deleted row; here
    -- it's simply the literal body of a no-caption attachment message).
    INSERT INTO chat_messages (channel_id, seq, author_id, parent_message_id, body, broadcast, msg_type, payload)
      VALUES (p_channel_id, v_seq, p_user_id, p_parent_id, COALESCE(p_body, ''), p_broadcast, v_msg_type, v_payload)
      RETURNING id INTO v_id;
    PERFORM append_chat_change(p_channel_id, v_seq, v_id, 'created');

    -- C1 Task 2 / C2 Task 3: the outbound federation enqueue, SAME
    -- transaction as the local write above — a rollback of this call
    -- unwinds both. author_id stays the local sender here (normal) —
    -- author_id=NULL/federated_sender_addr is exclusively the INBOUND shape
    -- (Task 4), never written on send. clientMsgId = this sender's own
    -- local chat_messages.id (the plan's "Identity, keys, and the one
    -- poison-proof invariant": per-sender-DB, never a global key).
    --
    -- Three-way split (a spoke mirror carries BOTH v_fed_domain and
    -- v_room_id — the DM arm below MUST exclude v_room_id or every spoke
    -- send would double-enqueue as a DM too):
    --   DM      (v_fed_domain set, v_room_id NULL)     -> one federation_enqueue
    --           to the DM peer, application/x-setjoin-chat (C1, unchanged).
    --   SPOKE   (v_room_id set, v_fed_domain set)      -> one user-initiated
    --           federation_enqueue to the bound hub, application/x-setjoin-room.
    --   HUB     (v_room_id set, v_fed_domain NULL)     -> federation_room_fanout
    --           to the whole roster (the local land above already happened;
    --           this is the relay leg), BZ205-exempt system frames.
    IF v_fed_domain IS NOT NULL AND v_room_id IS NULL THEN
        -- C1 Task 7: p_user_initiated=true — this IS the one user-facing send
        -- path (federation_room_fanout.sql's system fanout and the C0
        -- fedharness control endpoint both stay on the DEFAULT false, so the
        -- backpressure/dead-peer cap (BZ205) only ever protects a human
        -- sender, never a system frame).
        PERFORM federation_enqueue(v_fed_domain, v_id::text, 'application/x-setjoin-chat',
          jsonb_build_object(
            'fromAddr', (SELECT email FROM users WHERE id = p_user_id),
            'toAddr', v_fed_remote,
            'body', COALESCE(p_body, ''),
            'sentAt', now(),
            'clientMsgId', v_id::text),
          p_user_initiated := true);
    ELSIF v_room_id IS NOT NULL AND v_fed_domain IS NOT NULL THEN
        -- SPOKE: a single, user-initiated enqueue to the bound hub (Q9 —
        -- BZ205 protects the human; webmail surfaces the stale-hub banner
        -- on refusal, Task 7). NO originDomain in the payload — the hub
        -- stamps origin from the stream peer, never trusts the payload (Q2).
        PERFORM federation_enqueue(v_fed_domain, v_id::text, 'application/x-setjoin-room',
          jsonb_build_object(
            'op', 'message',
            'roomId', v_room_id,
            'fromAddr', (SELECT email FROM users WHERE id = p_user_id),
            'body', COALESCE(p_body, ''),
            'sentAt', now(),
            'clientMsgId', v_id::text),
          p_user_initiated := true);
    ELSIF v_room_id IS NOT NULL THEN
        -- HUB: the local chat_messages row above IS this org's own copy;
        -- fan the SAME message out to every other roster member (the fan-out
        -- stamps originDomain from the room's own hub_domain since
        -- p_origin_domain is NULL here — this is the hub's own send, not a
        -- relay of someone else's). BZ205-exempt (Q9 — system frames).
        PERFORM federation_room_fanout(v_room_id, v_id::text, 'application/x-setjoin-room',
          jsonb_build_object(
            'op', 'message',
            'roomId', v_room_id,
            'fromAddr', (SELECT email FROM users WHERE id = p_user_id),
            'body', COALESCE(p_body, ''),
            'sentAt', now(),
            'clientMsgId', v_id::text),
          NULL);
    END IF;

    IF v_natt > 0 THEN
        -- lazy per-channel space (DES-009): zero drive_space_members rows,
        -- access derives from chat_channel_members via drive_member_role.
        v_space_id := chat_space_ensure(p_user_id, p_channel_id);
        FOR v_att IN SELECT * FROM jsonb_array_elements(p_attachments) LOOP
            -- name split for the collision suffix ("report.pdf" ->
            -- "report (2).pdf"); lower()-compared uniqueness lives in the
            -- drive_nodes_live_name_uniq index (V114), enforced by
            -- drive_node_create raising the opaque BZ260 on collision.
            v_base := left(btrim(v_att->>'name'), 255);
            IF v_base ~ '\.[^./]+$' THEN
                v_ext  := substring(v_base from '\.[^./]+$');
                v_base := left(v_base, length(v_base) - length(v_ext));
            ELSE
                v_ext := '';
            END IF;
            v_candidate := v_base || v_ext;
            v_suffix := 1;
            LOOP
                BEGIN
                    -- btrim: a dotfile base ('' from '.env') or a 255+-char
                    -- truncation can leave the candidate with a leading/
                    -- trailing space, which drive_nodes' `name = btrim(name)`
                    -- CHECK rejects (BZ141) instead of BZ260 auto-suffixing.
                    v_candidate := btrim(v_candidate);
                    v_node_id := drive_node_create(p_user_id, v_space_id, NULL, 'file',
                                                    v_candidate, v_att->>'contentType');
                    EXIT;
                EXCEPTION
                    WHEN SQLSTATE 'BZ260' THEN
                        v_suffix := v_suffix + 1;
                        v_candidate := ' (' || v_suffix || ')';
                        -- cap the WHOLE candidate at 255 (drive_nodes CHECK):
                        -- truncate the base, never the suffix or extension.
                        v_candidate := left(v_base, greatest(255 - length(v_candidate) - length(v_ext), 1))
                                       || v_candidate || v_ext;
                END;
            END LOOP;
            v_put := drive_file_put_version(p_user_id, v_node_id, v_att->>'sha256',
                       (v_att->>'size')::bigint, v_att->>'contentType', NULL,
                       COALESCE(v_att->'manifest', '[]'::jsonb), NULL, 'chat', NULL);
            INSERT INTO chat_message_attachments
                (channel_id, message_id, file_node_id, version_id, filename, content_type, size_bytes, ordinal)
              VALUES (p_channel_id, v_id, v_node_id, (v_put->>'versionId')::bigint,
                      v_candidate, v_att->>'contentType', (v_att->>'size')::bigint, v_ord);
            v_ord := v_ord + 1;
        END LOOP;
    END IF;

    -- R2: mention rows only for verified channel members; non-members
    -- dropped silently — no sentinel row, no oracle (F4/L1).
    INSERT INTO chat_mentions (message_id, mentioned_user_id)
      SELECT v_id, u FROM unnest(p_mentions) u
       WHERE EXISTS (SELECT 1 FROM chat_channel_members
                      WHERE channel_id = p_channel_id AND user_id = u)
      ON CONFLICT DO NOTHING;

    -- Guest G1 digest intents ride the real message transaction. The helper
    -- no-ops for members and while feature.guest_accounts is disabled.
    FOR v_rec IN
        SELECT DISTINCT mentioned_user_id
          FROM chat_mentions WHERE message_id = v_id
    LOOP
        PERFORM guest_notification_intent_enqueue(
            v_rec.mentioned_user_id, 'mention',
            p_channel_id::text || ':' || v_id::text);
    END LOOP;
    IF v_channel_kind = 'dm' THEN
        FOR v_rec IN
            SELECT user_id FROM chat_channel_members
             WHERE channel_id = p_channel_id AND user_id <> p_user_id
        LOOP
            PERFORM guest_notification_intent_enqueue(
                v_rec.user_id, 'dm', p_channel_id::text || ':' || v_id::text);
        END LOOP;
    END IF;

    -- A3.5 Task 2: one enqueue row per MESSAGE (not per member — a 1k-member
    -- channel must not write 1k rows in this txn). ON CONFLICT DO NOTHING is
    -- free insurance (message_id is a fresh identity per call, so the sole
    -- writer can never actually replay one) — see chat_push.pg's direct
    -- duplicate-INSERT test for the UNIQUE(message_id) itself.
    IF COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.chat_push'), FALSE) THEN
        INSERT INTO chat_push_intents (channel_id, message_id, sender_user_id)
          VALUES (p_channel_id, v_id, p_user_id)
          ON CONFLICT (message_id) DO NOTHING;
    END IF;

    PERFORM notify_chat_state(p_channel_id, 'message_created', v_id, v_seq);
    RETURN jsonb_build_object('messageId', v_id, 'seq', v_seq);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION chat_message_edit(
    p_user_id bigint, p_message_id bigint, p_body text
) RETURNS bigint AS $$
DECLARE
    v_channel_id bigint;
    v_author_id  bigint;
    v_deleted    timestamptz;
    v_seq        bigint;
BEGIN
    PERFORM guest_require_active(p_user_id);  -- BZ219 belt (no-op for members)
    IF coalesce(btrim(p_body), '') = '' OR octet_length(p_body) > 65536 THEN
        RAISE EXCEPTION 'message body empty or over 64KiB'
            USING ERRCODE='BZ168', HINT='{"type":"invalidArguments"}';
    END IF;
    SELECT channel_id, author_id, deleted_at
      INTO v_channel_id, v_author_id, v_deleted
      FROM chat_messages WHERE id = p_message_id;
    -- one code for "doesn't exist", "not yours", and "already deleted" — an
    -- author can't tell which of the three happened (BZ167, same anti-oracle
    -- posture as BZ170's channel-join lump).
    IF v_channel_id IS NULL OR v_author_id <> p_user_id OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'only the author may edit this message'
            USING ERRCODE='BZ167', HINT='{"type":"forbidden"}';
    END IF;
    -- Resolve history visibility before checking archival state. A remembered
    -- pre-floor id and an absent id must remain the same BZ167 even when the
    -- channel is archived; otherwise BZ171 becomes a hidden-history oracle.
    IF NOT EXISTS (
      SELECT 1 FROM chat_messages m
      JOIN chat_channel_members cm
        ON cm.channel_id = m.channel_id AND cm.user_id = p_user_id
     WHERE m.id = p_message_id AND m.author_id = p_user_id AND m.deleted_at IS NULL
       AND m.seq > COALESCE(cm.history_floor_seq, 0)
       AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at)
    ) THEN
        RAISE EXCEPTION 'only the author may edit this message'
            USING ERRCODE='BZ167', HINT='{"type":"forbidden"}';
    END IF;
    -- archive = read-only: folded into the SAME row-lock UPDATE as the
    -- membership/authorship checks above it in this file's R3 pattern — a
    -- channel archived concurrently with this call closes the window the
    -- same way a concurrent chat_member_remove does (NOT FOUND below).
    UPDATE chat_channels SET change_seq = change_seq + 1
      WHERE id = v_channel_id AND NOT is_archived RETURNING change_seq INTO v_seq;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'channel is archived (read-only)'
            USING ERRCODE='BZ171', HINT='{"type":"forbidden"}';
    END IF;
    -- grill Q3: the prior body is captured AFTER the change_seq row lock is
    -- held, never from a pre-lock variable. Concurrent edits serialize on
    -- that lock, and this INSERT..SELECT is a new statement under READ
    -- COMMITTED — it re-reads the body the previous editor COMMITTED, so
    -- every committed body appears in the revision chain (an author cannot
    -- scrub a briefly-broadcast body by racing two edits). If the UPDATE
    -- below fails, the whole call unwinds and neither write lands.
    INSERT INTO chat_message_revisions (channel_id, message_id, prior_body, edited_by)
      SELECT channel_id, id, body, p_user_id
        FROM chat_messages WHERE id = p_message_id;
    -- R3: ownership + deleted_at IS NULL + a CURRENT channel membership (a
    -- member removed via chat_member_remove can no longer rewrite their own
    -- history) folded into the mutation's own WHERE — closes the
    -- check-then-act gap between the guard above and this row lock for a
    -- concurrent chat_member_remove or a concurrent delete/edit.
    UPDATE chat_messages m SET body = p_body, edited_at = now(), seq = v_seq
      WHERE m.id = p_message_id AND m.author_id = p_user_id AND m.deleted_at IS NULL
        AND EXISTS (SELECT 1 FROM chat_channel_members cm
                     WHERE cm.channel_id = m.channel_id AND cm.user_id = p_user_id
                       -- GUEST_HISTORY_FLOOR: chat_message_edit
                       AND m.seq > COALESCE(cm.history_floor_seq, 0)
                       AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at));
    IF NOT FOUND THEN
        RAISE EXCEPTION 'only the author may edit this message'
            USING ERRCODE='BZ167', HINT='{"type":"forbidden"}';
    END IF;
    PERFORM append_chat_change(v_channel_id, v_seq, p_message_id, 'updated');
    -- A4a Task 3: chained ACT, never message content — the prior body is
    -- already evidenced by the chat_message_revisions insert above; the chain
    -- row just proves an edit act happened, at what seq, by whom. Inert
    -- (zero rows) while feature.chat_compliance is OFF (risk-4 rail: this is
    -- an act write, not a per-send hot-path cost).
    IF COALESCE((SELECT enabled FROM feature_toggles
                 WHERE key = 'feature.chat_compliance'), FALSE) THEN
        PERFORM chat_access_audit(p_user_id, v_channel_id, 'message.edit',
          'message', p_message_id, NULL, jsonb_build_object('seq', v_seq), NULL, NULL);
    END IF;
    PERFORM notify_chat_state(v_channel_id, 'message_edited', p_message_id, v_seq);
    RETURN v_seq;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION chat_message_delete(
    p_user_id bigint, p_message_id bigint
) RETURNS bigint AS $$
DECLARE
    v_channel_id bigint;
    v_deleted    timestamptz;
    v_seq        bigint;
BEGIN
    PERFORM guest_require_active(p_user_id);  -- BZ219 belt (no-op for members)
    SELECT channel_id, deleted_at INTO v_channel_id, v_deleted
      FROM chat_messages WHERE id = p_message_id;
    -- one code for "doesn't exist" and "already deleted" (BZ167, same
    -- anti-oracle posture as edit) — a double-delete must not re-stamp seq,
    -- re-fire the message_deleted notify, or clobber the original deleted_at
    -- evidence timestamp with a fresh now().
    IF v_channel_id IS NULL OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'author or channel owner/admin required'
            USING ERRCODE='BZ167', HINT='{"type":"forbidden"}';
    END IF;
    -- Same anti-oracle order as edit: authorize the CURRENT, history-visible
    -- target before an archived-channel error may disclose its channel.
    IF NOT EXISTS (
      SELECT 1 FROM chat_messages m
      JOIN chat_channel_members cm
        ON cm.channel_id = m.channel_id AND cm.user_id = p_user_id
     WHERE m.id = p_message_id AND m.deleted_at IS NULL
       AND (m.author_id = p_user_id OR cm.role IN ('owner', 'admin'))
       AND m.seq > COALESCE(cm.history_floor_seq, 0)
       AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at)
    ) THEN
        RAISE EXCEPTION 'author or channel owner/admin required'
            USING ERRCODE='BZ167', HINT='{"type":"forbidden"}';
    END IF;
    -- C1: body RETAINED — only deleted_at is set. A compliance product must
    -- never destroy content at user-delete time; real purge is A4 retention's
    -- job. seq is re-stamped exactly like send/edit so since(seq) replays the
    -- tombstone instead of silently leaving a stale live copy behind.
    -- archive = read-only, same fold-into-the-row-lock treatment as edit.
    UPDATE chat_channels SET change_seq = change_seq + 1
      WHERE id = v_channel_id AND NOT is_archived RETURNING change_seq INTO v_seq;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'channel is archived (read-only)'
            USING ERRCODE='BZ171', HINT='{"type":"forbidden"}';
    END IF;
    -- R3: ownership (author, OR a CURRENT owner/admin — a member removed via
    -- chat_member_remove can no longer delete their own old messages either)
    -- AND deleted_at IS NULL folded into the same WHERE as the mutation — no
    -- check-then-act window where a concurrent chat_member_remove or a
    -- concurrent double-delete/edit could slip a stale authorization through.
    UPDATE chat_messages m SET deleted_at = now(), seq = v_seq
      WHERE m.id = p_message_id
        AND m.deleted_at IS NULL
        AND EXISTS (
          SELECT 1 FROM chat_channel_members cm
           WHERE cm.channel_id = m.channel_id AND cm.user_id = p_user_id
             AND (m.author_id = p_user_id OR cm.role IN ('owner', 'admin'))
             -- GUEST_HISTORY_FLOOR: chat_message_delete
             AND m.seq > COALESCE(cm.history_floor_seq, 0)
             AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at)
        );
    IF NOT FOUND THEN
        RAISE EXCEPTION 'author or channel owner/admin required'
            USING ERRCODE='BZ167', HINT='{"type":"forbidden"}';
    END IF;
    PERFORM append_chat_change(v_channel_id, v_seq, p_message_id, 'destroyed');
    -- Review blocker fix (chat_pin.sql Task 3): soft-delete closes any pin,
    -- mirroring the poll-anchor-soft-delete posture (chat_poll.sql, Task 9)
    -- — a pin on a message nobody can see is dead weight, not a curation
    -- record. Without this, chat_pin_toggle's BZ169 "message not
    -- found/deleted" guard fires before the toggle can ever run, so the pin
    -- row survives forever and no member/admin/owner can unpin it (a
    -- routine moderation delete of a pinned message would otherwise leave a
    -- permanently stuck pin — chat_message_pins is current-state-only, so
    -- there is no history to preserve here; the tombstoned message itself
    -- still carries the pin/unpin acts once A4's audit chain lands).
    DELETE FROM chat_message_pins WHERE message_id = p_message_id;
    -- A4a Task 3: chained ACT (same posture as edit above).
    IF COALESCE((SELECT enabled FROM feature_toggles
                 WHERE key = 'feature.chat_compliance'), FALSE) THEN
        PERFORM chat_access_audit(p_user_id, v_channel_id, 'message.delete',
          'message', p_message_id, NULL, jsonb_build_object('seq', v_seq), NULL, NULL);
    END IF;
    PERFORM notify_chat_state(v_channel_id, 'message_deleted', p_message_id, v_seq);
    RETURN v_seq;
END;
$$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/chat_pin.sql]
CREATE OR REPLACE FUNCTION chat_pin_toggle(
    p_user_id bigint, p_message_id bigint
) RETURNS boolean AS $$
DECLARE
    v_channel_id bigint;
    v_deleted    timestamptz;
    v_kind       text;
    v_role       text;
    v_seq        bigint;
    v_pinned     boolean;
    v_floor      bigint;
    v_joined_at  timestamptz;
BEGIN
    SELECT channel_id, deleted_at INTO v_channel_id, v_deleted
      FROM chat_messages WHERE id = p_message_id;
    IF v_channel_id IS NULL OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'message not found'
            USING ERRCODE='BZ169', HINT='{"type":"notFound"}';
    END IF;
    SELECT c.kind, m.role, m.history_floor_seq, m.joined_at
      INTO v_kind, v_role, v_floor, v_joined_at
      FROM chat_channels c JOIN chat_channel_members m
        ON m.channel_id = c.id AND m.user_id = p_user_id
     WHERE c.id = v_channel_id;
    IF v_role IS NULL THEN
        RAISE EXCEPTION 'not a member of channel %', v_channel_id
            USING ERRCODE='BZ163', HINT='{"type":"forbidden"}';
    END IF;
    -- GUEST_HISTORY_FLOOR: chat_pin_toggle
    IF NOT EXISTS (
        SELECT 1 FROM chat_messages m
         WHERE m.id = p_message_id
           AND m.seq > COALESCE(v_floor, 0)
           AND (v_floor IS NULL OR m.created_at >= v_joined_at)
    ) THEN
        RAISE EXCEPTION 'message not found'
            USING ERRCODE='BZ169', HINT='{"type":"notFound"}';
    END IF;
    -- BZ176: channels require owner/admin; DMs/group-DMs are all-member.
    IF v_kind = 'channel' AND v_role NOT IN ('owner', 'admin') THEN
        RAISE EXCEPTION 'owner/admin required to pin in a channel'
            USING ERRCODE='BZ176', HINT='{"type":"forbidden"}';
    END IF;

    -- re-stamp seq (same rail as send/edit/delete) so a since(seq) replay
    -- re-surfaces the message with its new pinned state.
    UPDATE chat_channels SET change_seq = change_seq + 1
      WHERE id = v_channel_id RETURNING change_seq INTO v_seq;
    UPDATE chat_messages SET seq = v_seq WHERE id = p_message_id;

    -- toggle: the PK is the natural mutex. Collective unpin — no
    -- pinned_by-only guard; the role check above already authorizes ANY
    -- eligible member to flip either direction.
    DELETE FROM chat_message_pins
     WHERE channel_id = v_channel_id AND message_id = p_message_id;
    IF FOUND THEN
        v_pinned := false;
    ELSE
        INSERT INTO chat_message_pins (channel_id, message_id, pinned_by)
          VALUES (v_channel_id, p_message_id, p_user_id);
        v_pinned := true;
    END IF;
    PERFORM append_chat_change(
        v_channel_id, v_seq, p_message_id,
        CASE WHEN v_pinned THEN 'pinned' ELSE 'unpinned' END
    );
    -- A4a Task 3: chained ACT (pin.add / pin.remove), inert while
    -- feature.chat_compliance is OFF.
    IF COALESCE((SELECT enabled FROM feature_toggles
                 WHERE key = 'feature.chat_compliance'), FALSE) THEN
        PERFORM chat_access_audit(p_user_id, v_channel_id,
          CASE WHEN v_pinned THEN 'pin.add' ELSE 'pin.remove' END,
          'message', p_message_id, NULL, jsonb_build_object('seq', v_seq), NULL, NULL);
    END IF;
    PERFORM notify_chat_state(v_channel_id, 'message_pinned', p_message_id, v_seq);
    RETURN v_pinned;
END;
$$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/chat_purge_expired.sql]
CREATE OR REPLACE FUNCTION chat_purge_expired(
  p_batch_size INT DEFAULT 1000,
  p_dry_run    BOOLEAN DEFAULT FALSE
) RETURNS TABLE(channel_id BIGINT, purged_count INT, id_from BIGINT, id_to BIGINT,
                retention_days INT)
LANGUAGE plpgsql AS $$
DECLARE
  v_ch RECORD; v_total INT := 0; v_ret INT;
  v_n INT; v_from BIGINT; v_to BIGINT; v_seq_max BIGINT; v_resync_seq BIGINT; v_elems JSONB;
  v_nodes BIGINT[];
  -- F4 (pipeline review fix): the scheduled_actions DELETE below had no
  -- RETURNING and no digest — a failed scheduled send is an A4b export class
  -- while retained, so its destruction was an unrecorded records event.
  -- scheduled_actions.id is a uuid (no MIN/MAX aggregate in this PG
  -- version, and no meaningful ordering over random uuids anyway, unlike
  -- chat_messages' sequential bigint identity) — array_agg is the honest
  -- "which rows" signal, not a fabricated range.
  v_sched_n INT; v_sched_ids uuid[];
  -- C2 Task 8 Step 4: origin-qualified {origin,key} pairs captured from the
  -- doomed chat_messages rows BEFORE they die — the federation_outbox purge
  -- scrub's match key (see federation_outbox_redact_purged.sql).
  v_fed_origin_keys jsonb;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles
                   WHERE key='feature.chat_compliance'), FALSE) THEN
    RETURN;
  END IF;
  FOR v_ch IN
    SELECT c.id, chat_effective_retention(c.id) AS ret
      FROM chat_channels c
     WHERE c.classification = 'regular'        -- 1: gxp is never destroyed by a cron
       AND NOT chat_hold_active(c.id)          -- 2: hold, single-homed predicate
       AND chat_effective_retention(c.id) IS NOT NULL
  LOOP
    v_ret := v_ch.ret;
    BEGIN
      IF p_dry_run THEN
        SELECT count(*)::int, MIN(m.id), MAX(m.id) INTO v_n, v_from, v_to
          FROM chat_messages m
         WHERE m.channel_id = v_ch.id
           AND m.created_at + make_interval(days => v_ret) <= now();
        IF v_n > 0 THEN
          channel_id := v_ch.id; purged_count := v_n; id_from := v_from;
          id_to := v_to; retention_days := v_ret; RETURN NEXT;
        END IF;
        CONTINUE;
      END IF;

      -- Attachment-node collection BEFORE the message DELETE (Task 7): the
      -- CASCADE (chat_message_attachments.message_id ON DELETE CASCADE,
      -- V120:45) clears the link rows the moment the messages die, so this
      -- must run first or there is nothing left to join against.
      SELECT array_agg(DISTINCT a.file_node_id) INTO v_nodes
        FROM chat_message_attachments a
        JOIN chat_messages m ON m.id = a.message_id
       WHERE m.channel_id = v_ch.id
         AND m.created_at + make_interval(days => v_ret) <= now();

      -- risk 5 (verify N5 — BLOCKER in v2): message content OUTSIDE chat_messages.
      -- THIS DELETE RUNS BEFORE THE `CONTINUE WHEN v_n = 0` BELOW, DELIBERATELY.
      -- v2 had it after, so a channel with ZERO expired MESSAGES but expired
      -- failed/done chat_send rows — a scheduled send that failed and never became
      -- a message; or a channel whose messages were all purged on an earlier run —
      -- kept its verbatim body in a no-RLS `payload` FOREVER. Nothing else in the
      -- repo reaps these rows. Do not "tidy" this back below the CONTINUE.
      -- status NOT IN ('pending', 'enqueued'): never destroy an UNFIRED scheduled
      -- message (that is silent content loss, not retention).
      --
      -- F4 (pipeline review fix): RETURNING id captures a count + id range so
      -- this destruction folds into the SAME purge.execute act below
      -- (alongside the message stats) instead of leaving it unrecorded — a
      -- failed/done scheduled-send body is A4b export content while
      -- retained. Originally scoped to when this destruction co-occurred
      -- with a message purge in the same channel/run — a channel with ONLY
      -- expired scheduled rows and zero expired messages still had its rows
      -- destroyed here, but the CONTINUE below used to short-circuit BEFORE
      -- the act, leaving that scheduled-only destruction unrecorded (the F4
      -- residual, closed by the confirmation-review fix: the CONTINUE below
      -- now only skips a channel with NOTHING destroyed on either leg — see
      -- chat_purge.pg's p_sched0 case).
      WITH sched_gone AS (
        DELETE FROM scheduled_actions
         WHERE action_kind = 'chat_send'
           AND (payload->>'channelId')::bigint = v_ch.id
           AND status NOT IN ('pending', 'enqueued')
           AND created_at + make_interval(days => v_ret) <= now()
        RETURNING id
      )
      SELECT count(*)::int, array_agg(id) INTO v_sched_n, v_sched_ids FROM sched_gone;

      -- The DELETE is BOUNDED (eng review #6). p_batch_size checked only BETWEEN
      -- channels would let ONE channel with millions of expired messages run a
      -- single unbounded DELETE + cascades in one transaction, blow the cron
      -- Timeout, roll back, and never make progress on ANY later tick. This is
      -- exactly what enforce_retention's LIMIT p_batch_size driving scan avoids
      -- (retention.sql:68). All of purgedCount/idFrom/idTo/destroyedElems derive
      -- from the `gone` CTE — never from a pre-scan, which would over-report.
      --
      -- LEAF HASH IS sha256, NEVER md5 (verify N3): this is evidentiary material
      -- in a 防篡改 feature; md5 has practical chosen-prefix collisions. Same
      -- one-liner, same cost.
      -- RETURNING builds the EXACT digest element Task 9's anchor concatenated:
      --   id ':' author_id ':' epoch(created_at) ':' sha256(original_body)
      -- author_id and created_at die with the row, so the act must record the
      -- whole element, not just the leaf — that is what lets the verifier
      -- reconcile an anchor over a purged range to a HARD boolean instead of
      -- shrugging with a purge_overlap flag (verify N1). epoch, not ::text: a
      -- timestamptz's rendering is DateStyle/TimeZone-dependent and would produce
      -- false tamper verdicts across sessions.
      WITH gone AS (
        DELETE FROM chat_messages
         WHERE id IN (SELECT id FROM chat_messages
                       -- table-qualified: chat_purge_expired's own OUT
                       -- parameter is also named channel_id, and PL/pgSQL's
                       -- default #variable_conflict=error rejects the bare
                       -- reference here as ambiguous (a real compile bug,
                       -- caught red-first, not a design point of the plan).
                       WHERE chat_messages.channel_id = v_ch.id
                         AND created_at + make_interval(days => v_ret) <= now()
                       ORDER BY id
                       LIMIT GREATEST(p_batch_size - v_total, 0))
        RETURNING id, seq, federated_origin_domain, federated_stanza_id,
                  id::text||':'||author_id::text||':'||
                  extract(epoch from created_at)::text||':'||
                  encode(sha256(convert_to(COALESCE(
                    (SELECT rv.prior_body FROM chat_message_revisions rv
                      WHERE rv.message_id = chat_messages.id
                      ORDER BY rv.id LIMIT 1), body), 'UTF8')), 'hex') AS elem
      )
      SELECT count(*)::int, MIN(id), MAX(id), MAX(seq),
             jsonb_object_agg(id::text, elem),
             jsonb_agg(jsonb_build_object('origin', federated_origin_domain,
                                           'key', COALESCE(federated_stanza_id, id::text)))
        INTO v_n, v_from, v_to, v_seq_max, v_elems, v_fed_origin_keys
        FROM gone;

      -- C2 Task 8 Step 4: scrub the transport-residue outbox copy of every
      -- doomed row's body — the ONE new call site at this choke point (see
      -- federation_outbox_redact_purged.sql for the origin-qualified match
      -- rules; a no-op on a non-federated channel or an empty batch).
      -- v_fed_origin_keys is jsonb_agg over ZERO rows (v_n = 0) -> NULL,
      -- which federation_outbox_redact_purged already treats as a no-op.
      PERFORM federation_outbox_redact_purged(v_ch.id, v_fed_origin_keys);
      -- FIX (pipeline-review confirmation, F4 residual): only skip the
      -- whole channel when NEITHER messages NOR scheduled rows were
      -- destroyed. Before this, `CONTINUE WHEN v_n = 0` also skipped the
      -- act below on a scheduled-only channel (v_sched_n > 0, v_n = 0) —
      -- leaving that destruction completely unrecorded, the exact
      -- "unrecorded destruction" gap F4 was meant to close, just on the
      -- zero-message path.
      CONTINUE WHEN v_n = 0 AND v_sched_n = 0;

      -- Node destroy loop AFTER the message DELETE (Task 7 — the A2 storage-
      -- reclamation deferral). drive_node_destroy_hard is the tier-2 trash
      -- sweeper: it returns false (never raises) unless purged_at IS NOT NULL
      -- (drive_node_destroy_hard.sql:45-47). A chat-attached node is
      -- permanently LIVE (BZ175 blocks trashing it through Drive — the very
      -- immutability guard A2 built), so calling it on a live node destroys
      -- nothing. This is a deliberate, purge-only lift of the never-trash
      -- posture: BZ175 lives in the drive *reducers* (drive_node_trash etc.),
      -- not in a trigger on drive_nodes, so a direct UPDATE here is not
      -- blocked (spec-delta 1). The NOT EXISTS guard on both statements
      -- excludes any node still referenced by another chat_message_attachments
      -- row (e.g. a shared-chunk sibling attached to a message that survives
      -- this run) — its OWN version/chunk-link stays alive even though the
      -- underlying chunk's ref_count still drops when a to-be-destroyed
      -- sibling version releases its own drive_version_chunks row.
      -- drive_node_destroy_hard already deletes chat_message_attachments rows
      -- itself (:71) — defense in depth, since the CASCADE above already
      -- cleared them — so no ordering dance around the link rows is needed.
      IF v_nodes IS NOT NULL THEN
        UPDATE drive_nodes
           SET deleted_at = COALESCE(deleted_at, now()),
               purged_at  = COALESCE(purged_at, now())
         WHERE id = ANY(v_nodes)
           AND NOT EXISTS (SELECT 1 FROM chat_message_attachments a
                            WHERE a.file_node_id = drive_nodes.id);
        PERFORM drive_node_destroy_hard(n)
           FROM unnest(v_nodes) AS n
          WHERE NOT EXISTS (SELECT 1 FROM chat_message_attachments a
                             WHERE a.file_node_id = n);
        v_nodes := NULL;
      END IF;

      -- last_purged_seq only ever advances on an actual message purge
      -- (v_seq_max is NULL for a scheduled-only channel; GREATEST ignores a
      -- NULL argument so the UPDATE would be a harmless no-op regardless,
      -- but skip it outright rather than write a no-op row).
      IF v_n > 0 THEN
        UPDATE chat_channels
           SET last_purged_seq = GREATEST(last_purged_seq, v_seq_max),
               change_seq      = change_seq + 1
         WHERE id = v_ch.id
         RETURNING change_seq INTO v_resync_seq;
        PERFORM append_chat_change(v_ch.id, v_resync_seq, NULL, 'resync');
        PERFORM public.emit_wakeup_bell('sync', 'channel:' || v_ch.id || ':' || v_resync_seq);
      END IF;

      -- Proof of disposition, not just a count (gate 3, rewritten per verify N1/N2).
      -- `destroyedElems` is a PER-ID map {messageId -> the exact digest element
      -- the anchor concatenated: id:author_id:epoch(created_at):sha256(original_body)},
      -- naturally bounded by p_batch_size. It is what lets chat_chain_anchor_verify
      -- return a HARD boolean over a purged range: the verifier recomputes the
      -- anchor digest over (surviving leaves ∪ these recovered leaves) and gets an
      -- exact match or a genuine tamper verdict. There is NO `purge_overlap` excuse
      -- field anywhere in this design — v2 had one, and it made a lawful purge and a
      -- body rewrite inside a purged range produce the IDENTICAL verdict, i.e. the
      -- cron laundered tampering. Both this act and the anchor act ride the same
      -- HMAC chain, so these leaves cannot be forged.
      --
      -- A scalar "digest over the destroyed rows" (v2) is NOT retained: nobody can
      -- recompute a pre-image over rows that no longer exist, so it proved nothing.
      -- Do not re-add it.
      --
      -- FIX 4 — destroyedElems is KEPT despite the anchor-before-purge ordering.
      -- The anchor (02:40) always runs before the purge (02:50) and retention_days
      -- > 0 forbids same-day create-and-purge, so every purged row IS anchored
      -- before it dies — but that only guarantees a GOVERNING anchor exists to
      -- reconcile against; it does NOT make the destroyed elements recoverable. The
      -- anchor commits a SCALAR digest H(elem1|...|elemN), and a one-way hash cannot
      -- yield elem_k back, so H(surviving ∪ destroyed) is uncomputable after a purge
      -- without these retained elements. Dropping destroyedElems would break FIX 1's
      -- hard-boolean reconciliation, not simplify it.
      -- ponytail: ~120 B/destroyed message, permanent (chat_audit_log is never
      -- purged, A4a↔A4b contract #3): a 2M-message purge = ~240 MB of durable
      -- digest — the deliberate price of hard-boolean reconciliation. Upgrade path
      -- if it ever bites: a per-message body-hash column would let the anchor store
      -- recoverable-enough per-leaf commitments and shrink the purge act to bare ids
      -- (the §Goal-named tamper-evidence gap); not before a regulator or a disk asks.
      -- destroyedElems is COALESCEd to '{}' for a scheduled-only purge
      -- (v_n=0 -> jsonb_object_agg over zero rows is NULL, not '{}') — the
      -- anchor verifier's destroyedElems join is keyed on message id ranges
      -- (chat_chain_anchor.sql), so an empty map here reconciles nothing and
      -- is inert, never a gap.
      PERFORM chat_access_audit(NULL, v_ch.id, 'purge.execute', 'channel', v_ch.id,
        NULL, jsonb_build_object('purgedCount', v_n, 'idFrom', v_from, 'idTo', v_to,
                                 'seqMax', v_seq_max, 'retentionDays', v_ret,
                                 'source', 'retention', 'destroyedElems', COALESCE(v_elems, '{}'::jsonb),
                                 'scheduledDestroyedCount', v_sched_n,
                                 'scheduledDestroyedIds', COALESCE(to_jsonb(v_sched_ids), '[]'::jsonb)),
        NULL, NULL);

      -- The TABLE-returning summary row (purged_count/id_from/id_to) and the
      -- batch-size bookkeeping stay scoped to an ACTUAL message purge — a
      -- scheduled-only channel gets its act (above) but never a summary row
      -- of purged_count=0 (unchanged caller contract: chat_purge_run's
      -- SUM(purged_count)/batch-exit logic and chat_purge.pg's "no run row"
      -- assertions for a message-free channel both stay correct).
      IF v_n > 0 THEN
        channel_id := v_ch.id; purged_count := v_n; id_from := v_from;
        id_to := v_to; retention_days := v_ret; RETURN NEXT;
        v_total := v_total + v_n;
        EXIT WHEN v_total >= p_batch_size;
      END IF;
    EXCEPTION WHEN SQLSTATE 'BZ194' THEN
      -- ONLY the legal-hold trigger is a "skip this channel" outcome (belt for a
      -- hold flipped mid-run). Everything else propagates loudly — catching WHEN
      -- OTHERS here would miscount real failures as holds (retention.sql:96
      -- lesson, verbatim).
      NULL;
    END;
  END LOOP;
END $$;

-- [embedded verbatim from reducers/federation_apply_chat.sql]
CREATE OR REPLACE FUNCTION federation_apply_chat(
    p_peer_domain       text,
    p_peer_seq          bigint,
    p_stanza_id         text,
    p_payload           jsonb,
    p_spam_quarantined  boolean DEFAULT false,
    p_spam_reason       text    DEFAULT NULL
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_last          bigint;
  v_from_raw      text;
  v_to_raw        text;
  v_from_addr     text;   -- lowercased, for domain/key/mailbox comparisons
  v_to_addr       text;   -- lowercased, ditto
  v_body          text;
  v_client_msg_id text;
  v_to_user_id    bigint;
  v_key           text;
  v_channel_id    bigint;
  v_seq           bigint;
  v_msg_id        bigint;
BEGIN
  -- ══════════════════════════════════════════════════════════════════════
  -- Step 1: exactly-once bookkeeping FIRST, unchanged from
  -- federation_apply_inbound — this runs BEFORE any content is even parsed,
  -- so a dup or a gap is decided purely from (peer_domain, peer_seq),
  -- independent of whatever garbage might be sitting in p_payload.
  -- ══════════════════════════════════════════════════════════════════════
  IF EXISTS (
    SELECT 1 FROM federation_inbox
     WHERE peer_domain = p_peer_domain AND peer_seq = p_peer_seq
  ) THEN
    RETURN 'dup';
  END IF;

  INSERT INTO federation_inbox_cursor (peer_domain) VALUES (p_peer_domain)
    ON CONFLICT (peer_domain) DO NOTHING;

  SELECT last_applied_seq INTO v_last FROM federation_inbox_cursor
    WHERE peer_domain = p_peer_domain FOR UPDATE;

  -- Task 8 Step 2 (the cursor-regression guard — federation_reap.sql's
  -- header names this as the gap it closes): the PK-EXISTS check above only
  -- catches a dup whose federation_inbox row still exists. Once the reaper
  -- (federation_reap) deletes old applied rows, a replayed/malicious
  -- p_peer_seq at-or-below the cursor would fall through that check
  -- entirely — and without this guard, the gap check below is silent (it
  -- only fires on p_peer_seq TOO HIGH) and the unconditional cursor SET
  -- further down would move last_applied_seq BACKWARD. Any already-passed
  -- seq (<=, not just <, since an exact match with its row already reaped
  -- must ALSO dup rather than re-apply) is a dup, full stop — cursor left
  -- untouched, no write below this point.
  IF p_peer_seq <= v_last THEN
    RETURN 'dup';
  END IF;

  IF p_peer_seq > v_last + 1 THEN
    RAISE EXCEPTION 'federation: sequence gap for peer % — got % expected %',
      p_peer_domain, p_peer_seq, v_last + 1
      USING ERRCODE='BZ202',
            HINT='{"type":"conflict","detail":"sequence gap — replay required"}';
  END IF;

  -- envelope-only inbox row (C1 delta from federation_apply_inbound): the
  -- body now lives in chat_messages, so storing it a second time here would
  -- be a needless duplicate copy of user content sitting in a deny-all
  -- infra table nobody reads for record-keeping purposes. `->>` on a
  -- key that's missing/wrong-typed returns SQL NULL, never errors — safe to
  -- call before any well-formedness check below.
  INSERT INTO federation_inbox (peer_domain, peer_seq, stanza_id, content_type, payload)
    VALUES (p_peer_domain, p_peer_seq, p_stanza_id, 'application/x-setjoin-chat',
            jsonb_build_object('fromAddr', p_payload->>'fromAddr',
                                'toAddr', p_payload->>'toAddr',
                                'clientMsgId', p_payload->>'clientMsgId'));

  UPDATE federation_inbox_cursor SET last_applied_seq = p_peer_seq, updated_at = now()
    WHERE peer_domain = p_peer_domain;

  -- ══════════════════════════════════════════════════════════════════════
  -- Step 2: trust validations. From here on, EVERY failure is 'poison' —
  -- the seq/cursor above are already committed-in-this-txn, so returning
  -- (rather than raising) is what makes the drop durable exactly once.
  -- ══════════════════════════════════════════════════════════════════════
  v_from_raw      := NULLIF(btrim(p_payload->>'fromAddr'), '');
  v_to_raw        := NULLIF(btrim(p_payload->>'toAddr'), '');
  v_body          := p_payload->>'body';
  v_client_msg_id := NULLIF(btrim(p_payload->>'clientMsgId'), '');

  -- (iv) malformed: any required key missing/empty. Checked first — every
  -- later check dereferences one of these values, so a NULL here must never
  -- reach them.
  IF v_from_raw IS NULL OR v_to_raw IS NULL OR v_body IS NULL OR v_client_msg_id IS NULL THEN
    RAISE NOTICE 'federation: poison — malformed chat payload from peer % seq %',
      p_peer_domain, p_peer_seq;
    RETURN 'poison';
  END IF;

  -- (review fold, F1) clientMsgId feeds chat_messages_fed_stanza_uk, a
  -- PARTIAL btree index on (channel_id, federated_origin_domain,
  -- federated_stanza_id) — an attacker-controlled value with no length cap
  -- can blow past Postgres's ~2.7KB btree index-row ceiling ("index row size
  -- exceeds btree maximum", SQLSTATE 54000). That failure is NOT caught by
  -- this function's poison-return contract: it fires deep inside the INSERT
  -- in Step 3, AFTER the seq/cursor advance above already committed, so it
  -- aborts and unwinds that advance too — the exact livelock this file's
  -- header explains, just triggered by index-row size instead of a bad
  -- domain. Capped well under the ceiling; poison, never a raise.
  IF octet_length(v_client_msg_id) > 512 THEN
    RAISE NOTICE 'federation: poison — clientMsgId over 512 octets (btree index ceiling) from peer % seq %',
      p_peer_domain, p_peer_seq;
    RETURN 'poison';
  END IF;

  -- fromAddr feeds federated_sender_addr — not itself index-bound today,
  -- but an unbounded attacker-controlled address is already nonsensical
  -- wire content; cap at the RFC address ceiling, poison-shaped, same
  -- defensive posture as the clientMsgId cap above.
  IF octet_length(v_from_raw) > 320 THEN
    RAISE NOTICE 'federation: poison — fromAddr over 320 octets (RFC address ceiling) from peer % seq %',
      p_peer_domain, p_peer_seq;
    RETURN 'poison';
  END IF;

  v_from_addr := lower(v_from_raw);
  v_to_addr   := lower(v_to_raw);

  -- (i) anti-spoof: bravo cannot assert mallory@charlie or ceo@alpha —
  -- fromAddr's domain MUST equal the domain this stream was authenticated
  -- as at handshake time (p_peer_domain, verified against the presented
  -- client cert — stream.go, never trusted from the payload itself).
  IF split_part(v_from_addr, '@', 2) <> lower(p_peer_domain) THEN
    RAISE NOTICE 'federation: poison — spoofed fromAddr domain (got %, stream peer %)',
      split_part(v_from_addr, '@', 2), p_peer_domain;
    RETURN 'poison';
  END IF;

  -- (iii) size cap — mirrors chat_message_send's federated-branch BZ206 cap
  -- (chat_message.sql), so a compliant local sender's own cap and this
  -- side's inbound cap can never disagree about what "too big" means.
  IF octet_length(v_body) > 65536 THEN
    RAISE NOTICE 'federation: poison — body over 64KiB from peer % seq %',
      p_peer_domain, p_peer_seq;
    RETURN 'poison';
  END IF;

  -- (ii) toAddr must resolve to a real, enabled local user — join
  -- mailboxes/users on the lowercased address (mailboxes_email_lower_idx,
  -- the deliver_group_vacation.sql precedent), require the mailbox to be
  -- both enabled and receive_enabled (this IS an inbound-delivery check)
  -- and the user account itself enabled. A shared/resource mailbox with no
  -- owning user_id can never receive a federated DM (mb.user_id IS NOT NULL
  -- is enforced by the JOIN itself since users.id is NOT NULL).
  SELECT mb.user_id INTO v_to_user_id
    FROM mailboxes mb JOIN users u ON u.id = mb.user_id
   WHERE lower(mb.email) = v_to_addr
     AND mb.enabled AND mb.receive_enabled AND u.enabled
   LIMIT 1;

  IF v_to_user_id IS NULL THEN
    RAISE NOTICE 'federation: poison — toAddr % does not resolve to a real enabled local user',
      v_to_addr;
    RETURN 'poison';
  END IF;

  -- ══════════════════════════════════════════════════════════════════════
  -- Step 3: valid — lazily mirror the channel, land the message.
  -- ══════════════════════════════════════════════════════════════════════

  -- federated_local_key recomputed SERVER-SIDE from (toAddr, fromAddr) —
  -- NEVER read from the stanza (the invariant). Identical formula to
  -- federation_dm_ensure.sql's outbound side: least/greatest on the two
  -- lowered addresses gives an order-independent pair, so this side's
  -- "local vs remote" (to vs from) hashes to the SAME key the sender
  -- computed with ITS "local vs remote" (from vs to).
  v_key := encode(digest(
      least(v_to_addr, v_from_addr) || ':' || greatest(v_to_addr, v_from_addr),
      'sha256'), 'hex');

  INSERT INTO chat_channels (kind, federated_peer_domain, federated_remote_id, federated_local_key, member_key, created_by)
    VALUES ('dm', lower(p_peer_domain), v_from_raw, v_key, NULL, v_to_user_id)
    ON CONFLICT (federated_peer_domain, federated_local_key) WHERE federated_peer_domain IS NOT NULL DO NOTHING
    RETURNING id INTO v_channel_id;

  IF v_channel_id IS NULL THEN
    SELECT id INTO v_channel_id FROM chat_channels
     WHERE federated_peer_domain = lower(p_peer_domain) AND federated_local_key = v_key;
  END IF;

  -- sole local member, seeded lazily + idempotently (ON CONFLICT DO NOTHING
  -- — this runs on every inbound message, not just the first, since the
  -- channel may pre-exist from a prior message): the remote party is
  -- identity metadata on the channel row (federated_remote_id) only, never
  -- a chat_channel_members row (Global Constraints).
  INSERT INTO chat_channel_members (channel_id, user_id, role)
    VALUES (v_channel_id, v_to_user_id, 'owner')
    ON CONFLICT (channel_id, user_id) DO NOTHING;

  -- Pre-check the stanza dedup BEFORE bumping change_seq: a clientMsgId
  -- resend under a new peer_seq (already ruled a safe no-op above) should
  -- not burn a change_seq value for a row that will never be inserted. This
  -- pre-check is race-free: the federation_inbox_cursor row lock taken in
  -- Step 1 serializes every call for THIS peer_domain for the duration of
  -- this transaction, and a federated mirror channel only ever receives
  -- writes from the one peer_domain it is bound to. The ON CONFLICT DO
  -- NOTHING below remains as the hard backstop regardless (never a bare
  -- INSERT here — see the file header).
  --
  -- V140 (C2 Task 1, THE DEDUP FIX): scoped on
  -- (channel_id, federated_origin_domain, federated_stanza_id), NOT the old
  -- 2-column (channel_id, federated_stanza_id) pair — a DM's origin IS the
  -- stream peer, so this is a no-op change of VALUE for every C1 DM row,
  -- but it re-aligns the pre-check with the re-scoped partial unique index
  -- below (a stale 2-column arbiter would match NO index and ABORT the
  -- txn on every inbound dup — the exact BZ202 livelock the arbiter exists
  -- to prevent).
  SELECT id INTO v_msg_id FROM chat_messages
   WHERE channel_id = v_channel_id AND federated_origin_domain = lower(p_peer_domain)
     AND federated_stanza_id = v_client_msg_id;

  IF v_msg_id IS NULL THEN
    UPDATE chat_channels SET change_seq = change_seq + 1
      WHERE id = v_channel_id RETURNING change_seq INTO v_seq;

    -- chat_messages_fed_stanza_uk (V140) is a PARTIAL unique index on
    -- (channel_id, federated_origin_domain, federated_stanza_id) WHERE
    -- federated_stanza_id IS NOT NULL — the ON CONFLICT arbiter must repeat
    -- that predicate verbatim, same requirement as federation_dm_ensure's
    -- own partial-UNIQUE arbiter above. federated_origin_domain is stamped
    -- here as the stream-authenticated peer (never trusted from the
    -- payload) — for a DM this origin IS the peer.
    INSERT INTO chat_messages (channel_id, seq, author_id, federated_sender_addr, federated_origin_domain, federated_stanza_id, body, spam_quarantined, spam_reason)
      VALUES (v_channel_id, v_seq, NULL, v_from_raw, lower(p_peer_domain), v_client_msg_id, v_body, COALESCE(p_spam_quarantined, false), p_spam_reason)
      ON CONFLICT (channel_id, federated_origin_domain, federated_stanza_id) WHERE federated_stanza_id IS NOT NULL DO NOTHING
      RETURNING id INTO v_msg_id;

    IF v_msg_id IS NOT NULL THEN
      PERFORM append_chat_change(v_channel_id, v_seq, v_msg_id, 'created');
      PERFORM notify_chat_state(v_channel_id, 'message_created', v_msg_id, v_seq);
    ELSE
      PERFORM append_chat_change(v_channel_id, v_seq, NULL, 'resync');
    END IF;
  END IF;

  RETURN 'applied';
END;
$$;
DO $$
DECLARE
    v_granted_create BOOLEAN := FALSE;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        IF NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
            GRANT CREATE ON SCHEMA public TO setjoin_worker;
            v_granted_create := TRUE;
        END IF;
        PERFORM public.apply_worker_ownership(
            'public.federation_apply_chat(text,bigint,text,jsonb,boolean,text)'::regprocedure
        );
        IF v_granted_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    ELSE
        REVOKE ALL ON FUNCTION public.federation_apply_chat(text,bigint,text,jsonb,boolean,text) FROM PUBLIC;
    END IF;
END $$;

-- [embedded verbatim from reducers/federation_apply_room.sql]
CREATE OR REPLACE FUNCTION federation_apply_room(
    p_peer_domain       text,
    p_peer_seq          bigint,
    p_stanza_id         text,
    p_payload           jsonb,
    p_spam_quarantined  boolean DEFAULT false,
    p_spam_reason       text    DEFAULT NULL,
    p_content_type      text    DEFAULT 'application/x-setjoin-room'
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_last            bigint;
  v_op              text;
  v_room_id         text;
  v_from_raw        text;
  v_from_addr       text;
  v_body            text;
  v_client_msg_id   text;
  v_channel_id      bigint;
  v_room_hub_domain text;
  v_ch_peer_domain  text;
  v_ch_removed_at   timestamptz;
  v_origin          text;
  v_seq             bigint;
  v_msg_id          bigint;
  v_landed_now      boolean;
  v_relay_payload   jsonb;
  -- Task 5: control-op locals.
  v_existing_hub        text;
  v_existing_channel_id bigint;
  v_contact_raw         text;
  v_contact_addr        text;
  v_contact_user_id     bigint;
  v_title               text;
  v_roster              jsonb;
  v_roster_domains      text[];
  v_domain              text;
  v_state               text;
  v_gap_from            timestamptz;
  v_gap_to              timestamptz;
BEGIN
  -- ══════════════════════════════════════════════════════════════════════
  -- Step 1: exactly-once bookkeeping FIRST, verbatim from
  -- federation_apply_chat — before any content is even parsed.
  -- ══════════════════════════════════════════════════════════════════════
  IF EXISTS (
    SELECT 1 FROM federation_inbox
     WHERE peer_domain = p_peer_domain AND peer_seq = p_peer_seq
  ) THEN
    RETURN 'dup';
  END IF;

  INSERT INTO federation_inbox_cursor (peer_domain) VALUES (p_peer_domain)
    ON CONFLICT (peer_domain) DO NOTHING;

  SELECT last_applied_seq INTO v_last FROM federation_inbox_cursor
    WHERE peer_domain = p_peer_domain FOR UPDATE;

  -- Task 8 Step 2 (the cursor-regression guard) — verbatim from
  -- federation_apply_chat.sql, see that file for the full rationale: once
  -- federation_reap deletes an old federation_inbox row, the PK-EXISTS dup
  -- check above no longer catches a replay of that reaped seq; this guard
  -- closes it so the cursor can never move backward.
  IF p_peer_seq <= v_last THEN
    RETURN 'dup';
  END IF;

  IF p_peer_seq > v_last + 1 THEN
    RAISE EXCEPTION 'federation: sequence gap for peer % — got % expected %',
      p_peer_domain, p_peer_seq, v_last + 1
      USING ERRCODE='BZ202',
            HINT='{"type":"conflict","detail":"sequence gap — replay required"}';
  END IF;

  -- envelope-only inbox row — same rationale as federation_apply_chat: the
  -- body lives in chat_messages, this is a deny-all infra archive, never a
  -- second copy of user content.
  INSERT INTO federation_inbox (peer_domain, peer_seq, stanza_id, content_type, payload)
    VALUES (p_peer_domain, p_peer_seq, p_stanza_id, p_content_type,
            jsonb_build_object('op', p_payload->>'op',
                                'roomId', p_payload->>'roomId',
                                'originDomain', p_payload->>'originDomain',
                                'clientMsgId', p_payload->>'clientMsgId'));

  UPDATE federation_inbox_cursor SET last_applied_seq = p_peer_seq, updated_at = now()
    WHERE peer_domain = p_peer_domain;

  -- (review fold, MINOR #4 — self-federation belt) a stream peer whose OWN
  -- domain is one of this org's own local domains can only mean a
  -- self-federation misconfiguration (this org allow-listed and is now
  -- receiving a stream FROM itself) — reuses the F2 predicate verbatim (the
  -- same "is this a local domain" check every other reducer uses:
  -- classify_focus.sql/deliver_group_vacation.sql/send.sql), placed once
  -- here so it protects every op (message AND every control op) rather than
  -- being duplicated per arm.
  IF EXISTS (SELECT 1 FROM domains WHERE lower(name) = lower(p_peer_domain) AND is_local) THEN
    RAISE NOTICE 'federation: poison — stream peer % is one of this org''s own local domains (self-federation misconfig)',
      p_peer_domain;
    RETURN 'poison';
  END IF;

  -- ══════════════════════════════════════════════════════════════════════
  -- Step 2: op dispatch. Task 4 implements 'message'; Task 5 implements
  -- 'invite'/'remove'/'roster'/'room_revoked' (the spoke-side control-op
  -- arms) below. Any other op is still a poison stub — the seq/cursor
  -- above already committed this call exactly once either way.
  -- ══════════════════════════════════════════════════════════════════════
  v_op := p_payload->>'op';
  IF v_op NOT IN ('message', 'invite', 'remove', 'roster', 'room_revoked') THEN
    RAISE NOTICE 'federation: poison — unknown/unimplemented room op % from peer % seq %',
      v_op, p_peer_domain, p_peer_seq;
    RETURN 'poison';
  END IF;

  -- ══════════════════════════════════════════════════════════════════════
  -- Step 3: scope, per-payload (Q12 apply-side) — poison-shaped, NEVER a
  -- raise (risk 3). Runs for 'message' and the control ops 'invite'/
  -- 'remove'/'roster'. 'room_revoked' SKIPS this — the ONE deliberate skip
  -- (contract section): this org's room scope was just withdrawn, so the
  -- dm-floor advisory that EXPLAINS the revocation must still apply —
  -- running the authorize check here would poison the very frame telling
  -- the user why they're read-only. Keyed on the op, not the content type.
  -- ══════════════════════════════════════════════════════════════════════
  IF v_op <> 'room_revoked' THEN
    BEGIN
      PERFORM federation_peer_authorize(p_peer_domain, 'room');
    EXCEPTION WHEN SQLSTATE 'BZ203' THEN
      RAISE NOTICE 'federation: poison — peer % not authorized at scope room (seq %, op %)',
        p_peer_domain, p_peer_seq, v_op;
      RETURN 'poison';
    END;
  END IF;

  IF v_op = 'message' THEN
    -- ════════════════════════════════════════════════════════════════════
    -- Step 4 (message op): resolve + trust. From here on, every failure is
    -- 'poison'.
    -- ════════════════════════════════════════════════════════════════════
    v_room_id       := NULLIF(btrim(p_payload->>'roomId'), '');
    v_from_raw      := NULLIF(btrim(p_payload->>'fromAddr'), '');
    v_body          := p_payload->>'body';
    v_client_msg_id := NULLIF(btrim(p_payload->>'clientMsgId'), '');

    IF v_room_id IS NULL OR v_from_raw IS NULL OR v_body IS NULL OR v_client_msg_id IS NULL THEN
      RAISE NOTICE 'federation: poison — malformed room message payload from peer % seq %',
        p_peer_domain, p_peer_seq;
      RETURN 'poison';
    END IF;

    -- (review fold, F1) clientMsgId feeds chat_messages_fed_stanza_uk, a
    -- PARTIAL btree index on (channel_id, federated_origin_domain,
    -- federated_stanza_id) — an attacker-controlled value with no length cap
    -- can blow past Postgres's ~2.7KB btree index-row ceiling ("index row size
    -- exceeds btree maximum", SQLSTATE 54000). That failure is NOT a
    -- poison-shaped return: it fires deep inside the INSERT in Step 5, AFTER
    -- the seq/cursor advance in Step 1 already committed, so it aborts and
    -- unwinds that advance too — a permanent stream livelock (the sender
    -- resends the identical oversized frame forever). Capped well under the
    -- ceiling; poison, never a raise.
    IF octet_length(v_client_msg_id) > 512 THEN
      RAISE NOTICE 'federation: poison — clientMsgId over 512 octets (btree index ceiling) from peer % seq %',
        p_peer_domain, p_peer_seq;
      RETURN 'poison';
    END IF;

    -- fromAddr feeds federated_sender_addr — not itself index-bound today,
    -- but an unbounded attacker-controlled address is already nonsensical
    -- wire content; cap at the RFC address ceiling, poison-shaped, same
    -- defensive posture as the clientMsgId cap above.
    IF octet_length(v_from_raw) > 320 THEN
      RAISE NOTICE 'federation: poison — fromAddr over 320 octets (RFC address ceiling) from peer % seq %',
        p_peer_domain, p_peer_seq;
      RETURN 'poison';
    END IF;

    v_from_addr := lower(v_from_raw);

    -- THE ORDERING GUARANTEE (contract section): invite always precedes the
    -- first message an org should apply, so a message for a room this org
    -- holds no live mirror of is 'poison' (not invited / kicked / hub bug) —
    -- NEVER a blind mirror-ensure.
    SELECT channel_id, hub_domain INTO v_channel_id, v_room_hub_domain
      FROM federation_rooms WHERE room_id = v_room_id;

    IF v_channel_id IS NULL THEN
      RAISE NOTICE 'federation: poison — unknown/unbound room % from peer % seq %',
        v_room_id, p_peer_domain, p_peer_seq;
      RETURN 'poison';
    END IF;

    IF octet_length(v_body) > 65536 THEN
      RAISE NOTICE 'federation: poison — room body over 64KiB from peer % seq %',
        p_peer_domain, p_peer_seq;
      RETURN 'poison';
    END IF;

    SELECT federated_peer_domain, federated_room_removed_at
      INTO v_ch_peer_domain, v_ch_removed_at
      FROM chat_channels WHERE id = v_channel_id;

    IF v_ch_peer_domain IS NULL THEN
      -- ── HUB side ──────────────────────────────────────────────────────
      -- stream peer must be a non-left roster member of this room (a
      -- REVOKED member is left — its in-flight room frames poison here,
      -- unchanged poison discipline; the Q9 advisory means its users already
      -- saw read-only before they'd send).
      IF NOT EXISTS (
        SELECT 1 FROM federation_room_members
         WHERE room_id = v_room_id AND member_domain = lower(p_peer_domain) AND left_at IS NULL
      ) THEN
        RAISE NOTICE 'federation: poison — % is not a non-left roster member of room % (hub side)',
          p_peer_domain, v_room_id;
        RETURN 'poison';
      END IF;

      -- C1 anti-spoof VERBATIM: fromAddr's domain must equal the
      -- stream-authenticated peer. originDomain is NEVER trusted from the
      -- payload on the hub side — it is DERIVED from the stream peer (Q2).
      IF split_part(v_from_addr, '@', 2) <> lower(p_peer_domain) THEN
        RAISE NOTICE 'federation: poison — spoofed fromAddr domain (got %, stream peer %)',
          split_part(v_from_addr, '@', 2), p_peer_domain;
        RETURN 'poison';
      END IF;

      v_origin := lower(p_peer_domain);
    ELSE
      -- ── SPOKE side ────────────────────────────────────────────────────
      -- the stream peer must EQUAL the mirror's bound hub — only the true
      -- hub may relay into a mirror.
      IF v_ch_peer_domain <> lower(p_peer_domain) THEN
        RAISE NOTICE 'federation: poison — room frame from non-hub stream peer % (mirror bound to %)',
          p_peer_domain, v_ch_peer_domain;
        RETURN 'poison';
      END IF;

      -- a kicked/closed mirror is archive-read-only — stragglers drop (Q3).
      IF v_ch_removed_at IS NOT NULL THEN
        RAISE NOTICE 'federation: poison — room frame for removed/closed mirror (room %)', v_room_id;
        RETURN 'poison';
      END IF;

      v_origin := NULLIF(lower(btrim(p_payload->>'originDomain')), '');
      IF v_origin IS NULL THEN
        RAISE NOTICE 'federation: poison — room message missing originDomain (room %, peer %)',
          v_room_id, p_peer_domain;
        RETURN 'poison';
      END IF;

      -- (review fold, F2) reflected-self origin: legit traffic can NEVER carry
      -- origin == this org's own local domain — federation_room_fanout's own
      -- origin-skip (member_domain <> v_origin) guarantees a spoke never
      -- receives a relay whose origin is itself. A malicious/compromised hub
      -- could otherwise plant this org's own domain in the roster mirror
      -- (which the hub authors) and assert it as originDomain here, landing
      -- author_id NULL + federated_sender_addr naming a LOCAL address —
      -- internal impersonation of a real local user. Checked before the
      -- roster-mirror trust below (the same predicate every other reducer
      -- uses to test "is this a local domain" — classify_focus.sql/
      -- deliver_group_vacation.sql/send.sql).
      IF EXISTS (SELECT 1 FROM domains WHERE lower(name) = v_origin AND is_local) THEN
        RAISE NOTICE 'federation: poison — asserted originDomain % is one of this org''s own local domains (room %, peer %)',
          v_origin, v_room_id, p_peer_domain;
        RETURN 'poison';
      END IF;

      -- the hub asserts origin for roster members (Q2, MUC posture): trust it
      -- only when it names a non-left roster member of THIS org's own
      -- hub-maintained roster mirror, or the hub itself.
      IF v_origin <> lower(v_room_hub_domain) AND NOT EXISTS (
        SELECT 1 FROM federation_room_members
         WHERE room_id = v_room_id AND member_domain = v_origin AND left_at IS NULL
      ) THEN
        RAISE NOTICE 'federation: poison — asserted originDomain % not in room %''s roster mirror (nor the hub)',
          v_origin, v_room_id;
        RETURN 'poison';
      END IF;

      -- cheap consistency re-check of what the hub already enforced at
      -- ingest: fromAddr's domain must equal the (now-trusted) origin.
      IF split_part(v_from_addr, '@', 2) <> v_origin THEN
        RAISE NOTICE 'federation: poison — fromAddr domain % does not match originDomain % (room %)',
          split_part(v_from_addr, '@', 2), v_origin, v_room_id;
        RETURN 'poison';
      END IF;
    END IF;

    -- ══════════════════════════════════════════════════════════════════════
    -- Step 5: land (both sides). Dedup pre-check on
    -- (channel_id, origin, clientMsgId) BEFORE bumping change_seq — a resend
    -- under a new peer_seq (already ruled safe above) must not burn a
    -- change_seq value for a row that will never be inserted. The
    -- ON CONFLICT arbiter below remains the hard backstop regardless.
    -- ══════════════════════════════════════════════════════════════════════
    SELECT id INTO v_msg_id FROM chat_messages
     WHERE channel_id = v_channel_id AND federated_origin_domain = v_origin
       AND federated_stanza_id = v_client_msg_id;
    v_landed_now := (v_msg_id IS NULL);

    IF v_landed_now THEN
      UPDATE chat_channels SET change_seq = change_seq + 1
        WHERE id = v_channel_id RETURNING change_seq INTO v_seq;

      INSERT INTO chat_messages (channel_id, seq, author_id, federated_sender_addr, federated_origin_domain, federated_stanza_id, body, spam_quarantined, spam_reason)
        VALUES (v_channel_id, v_seq, NULL, v_from_raw, v_origin, v_client_msg_id, v_body, COALESCE(p_spam_quarantined, false), p_spam_reason)
        ON CONFLICT (channel_id, federated_origin_domain, federated_stanza_id) WHERE federated_stanza_id IS NOT NULL DO NOTHING
        RETURNING id INTO v_msg_id;

      -- a concurrent racer may have landed the SAME row between this call's
      -- precheck and its own INSERT — the ON CONFLICT DO NOTHING then returns
      -- no row, v_msg_id stays NULL, and v_landed_now must NOT relay a second
      -- time (the concurrent winner's own call already will/did).
      v_landed_now := (v_msg_id IS NOT NULL);

      IF v_landed_now THEN
        PERFORM append_chat_change(v_channel_id, v_seq, v_msg_id, 'created');
        PERFORM notify_chat_state(v_channel_id, 'message_created', v_msg_id, v_seq);
      ELSE
        PERFORM append_chat_change(v_channel_id, v_seq, NULL, 'resync');
      END IF;
    END IF;

    -- ══════════════════════════════════════════════════════════════════════
    -- Step 6: relay (HUB side only, SAME txn, ONLY on a genuinely fresh land).
    -- A content-level dedup (clientMsgId resend under a brand-new peer_seq —
    -- already ruled safe/no-op above) must NOT relay a second time: this
    -- content already relayed the first time it landed, and federation_enqueue
    -- assigns a fresh peer_seq per call with no stanza_id-level idempotency of
    -- its own — re-running the fanout here would hand every other member a
    -- genuine SECOND outbox row for content they already received. The payload
    -- is REBUILT from validated fields — NEVER the inbound payload forwarded
    -- verbatim. The fan-out's own origin-skip (member_domain <> v_origin)
    -- prevents re-relaying to the sender; parked/left/revoke discipline is
    -- entirely federation_room_enqueue_member's job (Task 2/3), unchanged here.
    -- ══════════════════════════════════════════════════════════════════════
    IF v_ch_peer_domain IS NULL AND v_landed_now THEN
      v_relay_payload := jsonb_build_object(
        'op', 'message',
        'roomId', v_room_id,
        'fromAddr', v_from_raw,
        'body', v_body,
        'clientMsgId', v_client_msg_id);

      -- (review fold, F5) sentAt is forwarded ONLY when it's a plausible
      -- timestamp-shaped string (<=64 octets) — otherwise omitted entirely
      -- from the rebuilt payload, never a bare forward of the inbound value:
      -- an unbounded, attacker-controlled sentAt here would get copied
      -- verbatim into every OTHER room member's outbox row by the fan-out
      -- below, amplifying a single oversized string ×N members. Spokes never
      -- parse/store sentAt out of this payload (informational only), so its
      -- absence is tolerated structurally, not just by convention.
      IF p_payload->>'sentAt' IS NOT NULL AND octet_length(p_payload->>'sentAt') <= 64 THEN
        v_relay_payload := v_relay_payload || jsonb_build_object('sentAt', p_payload->>'sentAt');
      END IF;

      PERFORM federation_room_fanout(v_room_id, v_origin || '/' || v_client_msg_id,
        'application/x-setjoin-room', v_relay_payload, v_origin);
    END IF;

    RETURN 'applied';
  END IF;

  -- ══════════════════════════════════════════════════════════════════════
  -- Task 5: control-op arms — spoke-side only. A channel that resolves
  -- HUB-shaped locally means a peer is sending US control ops, which only a
  -- hub may originate — enforced per-op below (invite carries its OWN
  -- structural/hub-binding guards instead, since there may be no local row
  -- for it yet; remove/roster/room_revoked all require an EXISTING
  -- spoke-shaped local room bound to the stream peer).
  -- ══════════════════════════════════════════════════════════════════════
  v_room_id := NULLIF(btrim(p_payload->>'roomId'), '');
  IF v_room_id IS NULL THEN
    RAISE NOTICE 'federation: poison — control op % missing roomId from peer % seq %',
      v_op, p_peer_domain, p_peer_seq;
    RETURN 'poison';
  END IF;

  -- (review fold, B1 BLOCKER) roomId feeds TWO btree structures the invite
  -- arm below writes into: chat_channels.federated_room_id (a partial-UNIQUE
  -- btree index, V140) and federation_rooms.room_id (a text PRIMARY KEY,
  -- also btree) — an attacker-controlled roomId with no length cap can blow
  -- past Postgres's ~2.7KB btree index-row ceiling ("index row size exceeds
  -- btree maximum", SQLSTATE 54000), the SAME F1/54000 livelock as
  -- clientMsgId/fromAddr in the message arm above: it would fire deep inside
  -- an INSERT below, AFTER Step 1's cursor advance already committed,
  -- permanently wedging the stream. Checked once here, before dispatch to
  -- any control-op arm, since remove/roster/room_revoked also look v_room_id
  -- up against these same btree structures.
  IF octet_length(v_room_id) > 512 THEN
    RAISE NOTICE 'federation: poison — roomId over 512 octets (btree index ceiling) from peer % seq % op %',
      p_peer_domain, p_peer_seq, v_op;
    RETURN 'poison';
  END IF;

  IF v_op = 'invite' THEN
    -- ── the mirror constructor — the ONLY spoke-side mirror-creation path.
    -- Every guard below runs BEFORE ANY WRITE (the eng-review BLOCKER):
    -- without them, any allow-listed org that learned a roomId from relayed
    -- payloads could hijack another hub's mirror on a shared spoke.
    -- ────────────────────────────────────────────────────────────────────

    -- 1. Structural: only the domain that minted a roomId may introduce it
    --    (the roomId contract, contract section) — makes cross-hub roomId
    --    hijack structurally impossible.
    IF lower(split_part(v_room_id, '@', 2)) <> lower(p_peer_domain) THEN
      RAISE NOTICE 'federation: poison — invite roomId % does not belong to stream peer % (structural hijack guard)',
        v_room_id, p_peer_domain;
      RETURN 'poison';
    END IF;

    -- 2. Hub-binding belt: an existing local room row bound to a DIFFERENT
    --    hub must never be resurrected/rewritten by another peer — belt for
    --    any legacy/free-text roomId that predates the structural rule
    --    above (guard 1 already makes this practically unreachable for a
    --    roomId minted under the current scheme, kept as defense in depth).
    SELECT hub_domain, channel_id INTO v_existing_hub, v_existing_channel_id
      FROM federation_rooms WHERE room_id = v_room_id;
    IF v_existing_hub IS NOT NULL AND lower(v_existing_hub) <> lower(p_peer_domain) THEN
      RAISE NOTICE 'federation: poison — invite for room % is already bound to a DIFFERENT hub % (peer % is not it)',
        v_room_id, v_existing_hub, p_peer_domain;
      RETURN 'poison';
    END IF;

    -- 3. hubDomain (payload) must equal the stream-authenticated peer.
    IF lower(btrim(COALESCE(p_payload->>'hubDomain', ''))) <> lower(p_peer_domain) THEN
      RAISE NOTICE 'federation: poison — invite hubDomain does not match stream peer % (room %)',
        p_peer_domain, v_room_id;
      RETURN 'poison';
    END IF;

    -- resolve contactAddr to a real, enabled local user (the
    -- federation_apply_chat toAddr join, verbatim). Unresolvable is a
    -- disclosed v1 limitation — no invite-NACK back to the hub (Task 10
    -- ledger); silence is the only symptom.
    v_contact_raw := NULLIF(btrim(p_payload->>'contactAddr'), '');
    IF v_contact_raw IS NULL THEN
      RAISE NOTICE 'federation: poison — invite missing contactAddr (room %, peer %)',
        v_room_id, p_peer_domain;
      RETURN 'poison';
    END IF;
    v_contact_addr := lower(v_contact_raw);
    SELECT mb.user_id INTO v_contact_user_id
      FROM mailboxes mb JOIN users u ON u.id = mb.user_id
     WHERE lower(mb.email) = v_contact_addr
       AND mb.enabled AND mb.receive_enabled AND u.enabled
     LIMIT 1;
    IF v_contact_user_id IS NULL THEN
      RAISE NOTICE 'federation: poison — invite contactAddr % does not resolve to a real enabled local user (room %)',
        v_contact_addr, v_room_id;
      RETURN 'poison';
    END IF;

    -- validate the roster payload shape BEFORE any write — a malformed
    -- invite must leave zero side effects, same law as every other guard.
    v_roster := p_payload->'roster';
    IF v_roster IS NULL OR jsonb_typeof(v_roster) <> 'array' THEN
      RAISE NOTICE 'federation: poison — invite missing/malformed roster array (room %, peer %)',
        v_room_id, p_peer_domain;
      RETURN 'poison';
    END IF;

    -- (review fold, M1 MAJOR) cap roster cardinality BEFORE any write — an
    -- allow-listed-but-malicious hub could otherwise hand a 16MiB frame
    -- ~10^5 roster elements, each landing as a permanent never-DELETEd
    -- federation_room_members row (the roster mirror is read history, never
    -- pruned) — a multi-GB write primitive from a single frame.
    IF jsonb_array_length(v_roster) > 4096 THEN
      RAISE NOTICE 'federation: poison — invite roster exceeds 4096 elements (room %, peer %)',
        v_room_id, p_peer_domain;
      RETURN 'poison';
    END IF;

    v_title := left(p_payload->>'title', 256);
    -- (review fold, MINOR #1) truncate, don't poison — a long title is not a
    -- trust/shape violation, just cosmetic. left() counts CHARACTERS, not
    -- octets; capping at 256 characters bounds worst-case UTF-8 (4 octets/
    -- char) at 1024 octets without ever splitting a multibyte codepoint.

    -- create the mirror IDEMPOTENTLY (ON CONFLICT on the partial-UNIQUE
    -- federated_room_id index, the federation_apply_chat DM-mirror
    -- precedent) — a re-invite/re-admit reuses the SAME mirror channel,
    -- never a second row. visibility='private' is pinned deliberately:
    -- V119's default is 'public' and DES-008 makes public channels
    -- self-joinable — a public mirror would let any local user join the
    -- cross-org room before the contact owner acts.
    IF v_existing_channel_id IS NULL THEN
      INSERT INTO chat_channels (kind, name, visibility, federated_room_id, federated_peer_domain, created_by)
        VALUES ('channel', v_title, 'private', v_room_id, lower(p_peer_domain), v_contact_user_id)
        ON CONFLICT (federated_room_id) WHERE federated_room_id IS NOT NULL DO NOTHING
        RETURNING id INTO v_channel_id;
      IF v_channel_id IS NULL THEN
        SELECT id INTO v_channel_id FROM chat_channels WHERE federated_room_id = v_room_id;
      END IF;
      INSERT INTO federation_rooms (room_id, hub_domain, channel_id)
        VALUES (v_room_id, lower(p_peer_domain), v_channel_id)
        ON CONFLICT (room_id) DO NOTHING;
    ELSE
      v_channel_id := v_existing_channel_id;
    END IF;

    -- the contact user as (at least) an owner of the mirror, idempotently —
    -- they add local colleagues via normal chat membership (Q3/Q4). A
    -- re-invite naming a new contact simply adds them alongside whoever
    -- already joined; it never demotes/removes an existing owner.
    INSERT INTO chat_channel_members (channel_id, user_id, role)
      VALUES (v_channel_id, v_contact_user_id, 'owner')
      ON CONFLICT (channel_id, user_id) DO NOTHING;

    -- resurrect a previously kicked/revoked mirror — reachable only past
    -- guards 1-3 above, so only the true hub can resurrect it; join-forward,
    -- no backfill (Q9).
    UPDATE chat_channels SET federated_room_removed_at = NULL WHERE id = v_channel_id;
  ELSE
    -- remove / roster / room_revoked: the room must ALREADY resolve
    -- spoke-shaped locally, bound to the stream peer as hub.
    SELECT fr.channel_id, c.federated_peer_domain INTO v_channel_id, v_ch_peer_domain
      FROM federation_rooms fr JOIN chat_channels c ON c.id = fr.channel_id
     WHERE fr.room_id = v_room_id;

    IF v_channel_id IS NULL THEN
      RAISE NOTICE 'federation: poison — control op % for unknown/unbound room % from peer %',
        v_op, v_room_id, p_peer_domain;
      RETURN 'poison';
    END IF;

    IF v_ch_peer_domain IS NULL THEN
      RAISE NOTICE 'federation: poison — control op % arrived for a HUB-shaped room % — only a hub may originate control ops',
        v_op, v_room_id;
      RETURN 'poison';
    END IF;

    IF v_ch_peer_domain <> lower(p_peer_domain) THEN
      RAISE NOTICE 'federation: poison — control op % from non-hub stream peer % (mirror bound to %)',
        v_op, p_peer_domain, v_ch_peer_domain;
      RETURN 'poison';
    END IF;

    IF v_op IN ('remove', 'room_revoked') THEN
      -- the kicked-mirror machinery, reused verbatim by BOTH: archive-
      -- read-only + banner (notify_chat_state's 'federation_removed' event,
      -- Task 7); sends refuse BZ213 from here on (chat_message.sql, Task
      -- 3); straggler inbound message frames poison (the message arm's
      -- v_ch_removed_at check above). No roster rewrite, no message
      -- destruction — retention/hold/purge continue to govern the LOCAL
      -- copy only (Q6). TRULY idempotent (review fold, MINOR #5): only
      -- stamps federated_room_removed_at on the FIRST transition (the WHERE
      -- guard below), and only fires the banner notify on that same first
      -- transition (IF FOUND on the guarded UPDATE) — a re-delivery must
      -- never keep pushing removed_at forward or re-notify.
      UPDATE chat_channels SET federated_room_removed_at = now()
        WHERE id = v_channel_id AND federated_room_removed_at IS NULL;
      IF FOUND THEN
        PERFORM notify_chat_state(v_channel_id, 'federation_removed');
      END IF;
      RETURN 'applied';
    END IF;

    -- v_op = 'roster': validate the payload shape before any write.
    v_roster := p_payload->'roster';
    IF v_roster IS NULL OR jsonb_typeof(v_roster) <> 'array' THEN
      RAISE NOTICE 'federation: poison — roster op missing/malformed roster array (room %, peer %)',
        v_room_id, p_peer_domain;
      RETURN 'poison';
    END IF;

    -- (review fold, M1 MAJOR) same cardinality cap as the invite arm above —
    -- op:'roster' hits the SAME shared roster-replace loop below.
    IF jsonb_array_length(v_roster) > 4096 THEN
      RAISE NOTICE 'federation: poison — roster op array exceeds 4096 elements (room %, peer %)',
        v_room_id, p_peer_domain;
      RETURN 'poison';
    END IF;
  END IF;

  -- (review fold, B2 BLOCKER) validate EVERY roster element's domain in its
  -- OWN pass, before the mutating loop below touches a single row: member_domain
  -- feeds federation_room_members's (room_id, member_domain) btree PRIMARY
  -- KEY — same 54000 btree-row-ceiling livelock as B1/F1 above — and a
  -- garbage domain mid-frame must never partially apply the rest of the
  -- roster (a mutating per-element CONTINUE/poison split here would leave
  -- the earlier elements' upserts committed with no way to unwind them
  -- short of a RAISE, which would re-livelock the exact way this whole
  -- file's header forbids). Whole-frame poison, not a silent per-element
  -- skip — a hub sending malformed domains is not a partial-trust
  -- situation. 255 octets is the DNS name ceiling; this also catches a
  -- missing/empty domain (previously a silent CONTINUE).
  IF EXISTS (
    SELECT 1 FROM jsonb_array_elements(v_roster) elem
     WHERE COALESCE(octet_length(elem->>'domain'), 0) = 0
        OR octet_length(elem->>'domain') > 255
  ) THEN
    RAISE NOTICE 'federation: poison — roster element with empty/oversized (>255 octets, DNS ceiling) domain (room %, peer %, op %)',
      v_room_id, p_peer_domain, v_op;
    RETURN 'poison';
  END IF;

  -- ══════════════════════════════════════════════════════════════════════
  -- SHARED roster-mirror replace — reached only by 'invite' (after its own
  -- setup writes above) and 'roster' (validated above); 'remove'/
  -- 'room_revoked' already returned. Upsert each {domain,state}; set
  -- left_at on local rows absent from the payload (NEVER DELETE — the
  -- roster mirror is also read history, contract section).
  -- ══════════════════════════════════════════════════════════════════════
  FOR v_domain, v_state IN
    SELECT lower(elem->>'domain'), elem->>'state' FROM jsonb_array_elements(v_roster) elem
  LOOP
    IF v_domain IS NULL OR v_domain = '' THEN
      CONTINUE;
    END IF;
    IF v_state = 'parked' THEN
      INSERT INTO federation_room_members (room_id, member_domain, parked_at, parked_reason)
        VALUES (v_room_id, v_domain, now(), 'backpressure')
        ON CONFLICT (room_id, member_domain) DO UPDATE
          SET parked_at     = COALESCE(federation_room_members.parked_at, now()),
              parked_reason = COALESCE(federation_room_members.parked_reason, 'backpressure'),
              left_at = NULL, left_reason = NULL;
    ELSE
      INSERT INTO federation_room_members (room_id, member_domain)
        VALUES (v_room_id, v_domain)
        ON CONFLICT (room_id, member_domain) DO UPDATE
          SET parked_at = NULL, parked_reason = NULL, left_at = NULL, left_reason = NULL;
    END IF;
  END LOOP;

  SELECT array_agg(lower(elem->>'domain')) INTO v_roster_domains
    FROM jsonb_array_elements(v_roster) elem WHERE elem->>'domain' IS NOT NULL;

  UPDATE federation_room_members
     SET left_at = now()
   WHERE room_id = v_room_id AND left_at IS NULL
     AND NOT (member_domain = ANY (COALESCE(v_roster_domains, ARRAY[]::text[])));

  -- the gap marker (Q9 coverage epochs, invite only): ONE local system
  -- message when the payload carries gapFrom/gapTo (the re-admit UPSERT
  -- closing an open epoch on the hub side) — a purely LOCAL record, never
  -- wire content: no federated_stanza_id/origin. A malformed/garbled
  -- gapFrom/gapTo must never raise mid-transaction (poison discipline) —
  -- caught locally and treated as absent.
  IF v_op = 'invite' THEN
    v_gap_from := NULL;
    v_gap_to   := NULL;
    IF p_payload ? 'gapFrom' AND p_payload ? 'gapTo' THEN
      BEGIN
        v_gap_from := (p_payload->>'gapFrom')::timestamptz;
        v_gap_to   := (p_payload->>'gapTo')::timestamptz;
      EXCEPTION WHEN OTHERS THEN
        v_gap_from := NULL;
        v_gap_to   := NULL;
      END;
    END IF;

    IF v_gap_from IS NOT NULL AND v_gap_to IS NOT NULL THEN
      UPDATE chat_channels SET change_seq = change_seq + 1
        WHERE id = v_channel_id RETURNING change_seq INTO v_seq;
      INSERT INTO chat_messages (channel_id, seq, author_id, msg_type, body)
        VALUES (v_channel_id, v_seq, NULL, 'system',
                jsonb_build_object('kind', 'federation_gap', 'from', v_gap_from, 'to', v_gap_to)::text)
        RETURNING id INTO v_msg_id;
      PERFORM append_chat_change(v_channel_id, v_seq, v_msg_id, 'created');
      PERFORM notify_chat_state(v_channel_id, 'message_created', v_msg_id, v_seq);
    END IF;
  END IF;

  PERFORM notify_chat_state(v_channel_id, 'federation_roster');
  RETURN 'applied';
END;
$$;
DO $$
DECLARE
    v_granted_create BOOLEAN := FALSE;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        IF NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
            GRANT CREATE ON SCHEMA public TO setjoin_worker;
            v_granted_create := TRUE;
        END IF;
        PERFORM public.apply_worker_ownership(
            'public.federation_apply_room(text,bigint,text,jsonb,boolean,text,text)'::regprocedure
        );
        IF v_granted_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    ELSE
        REVOKE ALL ON FUNCTION public.federation_apply_room(text,bigint,text,jsonb,boolean,text,text) FROM PUBLIC;
    END IF;
END $$;

-- [embedded verbatim from reducers/federation_ack.sql]
CREATE OR REPLACE FUNCTION federation_ack(
    p_peer_domain text,
    p_peer_seq    bigint
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_stanza_id    text;
  v_content_type text;
  v_message_id   bigint;
  v_channel_id   bigint;
  v_seq          bigint;
  v_ack_window   bigint;
BEGIN
  -- Belt-and-braces future-ack refusal (doc block above): the ack window is
  -- the durable high-water mark of seqs this side ever enqueued for the peer.
  SELECT GREATEST(
           COALESCE((SELECT last_seq FROM federation_peers
                      WHERE peer_domain = p_peer_domain), 0),
           COALESCE((SELECT MAX(peer_seq) FROM federation_outbox
                      WHERE peer_domain = p_peer_domain), 0)
         ) INTO v_ack_window;

  IF p_peer_seq IS NULL OR p_peer_seq < 0 OR p_peer_seq > v_ack_window THEN
    RAISE EXCEPTION 'federation: ack for peer % names seq % outside the enqueued window (0..%) — forged/future ack refused',
      p_peer_domain, p_peer_seq, v_ack_window
      USING ERRCODE='BZ202',
            HINT='{"type":"conflict","detail":"ack sequence outside the enqueued outbox window"}';
  END IF;

  UPDATE federation_outbox SET acked_at = now()
    WHERE peer_domain = p_peer_domain AND peer_seq = p_peer_seq AND acked_at IS NULL
    RETURNING stanza_id, content_type INTO v_stanza_id, v_content_type;

  UPDATE federation_peers SET last_acked_seq = p_peer_seq, updated_at = now()
    WHERE peer_domain = p_peer_domain AND last_acked_seq < p_peer_seq;

  -- Receipt: only on the first (acked_at IS NULL -> acked) transition, and
  -- only for a chat-kind stanza whose id parses as a bigint (defensive —
  -- content_type already guarantees this in practice).
  IF FOUND AND v_content_type = 'application/x-setjoin-chat' THEN
    BEGIN
      v_message_id := v_stanza_id::bigint;
    EXCEPTION WHEN invalid_text_representation THEN
      v_message_id := NULL;
    END;

    IF v_message_id IS NOT NULL THEN
      SELECT m.channel_id INTO v_channel_id
        FROM chat_messages m
        JOIN chat_channels c ON c.id = m.channel_id
       WHERE m.id = v_message_id
         AND c.federated_peer_domain = p_peer_domain;

      IF v_channel_id IS NOT NULL THEN
        UPDATE chat_channels SET change_seq = change_seq + 1
          WHERE id = v_channel_id RETURNING change_seq INTO v_seq;

        UPDATE chat_messages SET seq = v_seq, delivered_at = now()
          WHERE id = v_message_id;

        PERFORM append_chat_change(v_channel_id, v_seq, v_message_id, 'updated');
        PERFORM notify_chat_state(v_channel_id, 'message_delivered', v_message_id, v_seq);
      END IF;
    END IF;
  END IF;
END;
$$;
DO $$
DECLARE
    v_granted_create BOOLEAN := FALSE;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        IF NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
            GRANT CREATE ON SCHEMA public TO setjoin_worker;
            v_granted_create := TRUE;
        END IF;
        PERFORM public.apply_worker_ownership(
            'public.federation_ack(text,bigint)'::regprocedure
        );
        IF v_granted_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    ELSE
        REVOKE ALL ON FUNCTION public.federation_ack(text,bigint) FROM PUBLIC;
    END IF;
END $$;

-- [embedded verbatim from reducers/prune_changes_journal.sql]
CREATE OR REPLACE FUNCTION prune_changes_journal(
  p_max_window_days INT DEFAULT 30,
  p_high_water      INT DEFAULT 50000
) RETURNS BIGINT AS $$
DECLARE
  v_invoker_role   TEXT := COALESCE(NULLIF(current_setting('role', TRUE), 'none'), session_user);
  v_deleted        BIGINT := 0;
  v_n              BIGINT;
  -- Wave 2.6 (#553): uniform GREATEST(requested, configured_offline_window_days, 30) floor.
  v_retention_days INT    := public.effective_journal_retention_days(p_max_window_days);
  v_high_water     INT    := GREATEST(COALESCE(p_high_water, 50000), 0);
  v_cutoff         TIMESTAMPTZ := now() - make_interval(days => v_retention_days);
BEGIN
  PERFORM public.work_queue_require_worker();
  IF NOT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_roles
     WHERE rolname = v_invoker_role
       AND (rolbypassrls OR rolsuper)
  ) THEN
    RAISE EXCEPTION 'prune_changes_journal: worker privilege (BYPASSRLS or superuser) required'
      USING ERRCODE = 'BZ003',
            HINT = '{"type":"worker_privilege_required"}';
  END IF;

  -- Arm 1: contiguous prefix-only age prune per (mailbox_id, datatype) so
  -- concurrent transactions with skewed timestamps never punch a hole after a
  -- retained sequence.
  WITH bounds AS (
    SELECT mailbox_id, datatype,
           MIN(state_seq) FILTER (WHERE created_at >= v_cutoff) AS keep_from_seq
      FROM jmap_changes_journal
     GROUP BY mailbox_id, datatype
  ),
  del AS (
    DELETE FROM jmap_changes_journal j
     USING bounds b
     WHERE j.mailbox_id = b.mailbox_id
       AND j.datatype   = b.datatype
       AND (b.keep_from_seq IS NULL OR j.state_seq < b.keep_from_seq)
    RETURNING 1
  )
  SELECT count(*) INTO v_n FROM del;
  v_deleted := v_deleted + v_n;

  -- Arm 2: high-water cap per mailbox (covers All-window accounts with
  -- offline_window_days IS NULL — they have no finite time horizon so the time
  -- arm never prunes them; the cap keeps the journal bounded).
  -- ponytail: dense_rank over state_seq DESC lets multiple rows at one seq
  -- (F2 batch) count as one rank — correct behaviour for the journal PK shape.
  WITH ranked AS (
    SELECT mailbox_id, datatype, state_seq,
           dense_rank() OVER (PARTITION BY mailbox_id, datatype ORDER BY state_seq DESC) AS rnk
      FROM jmap_changes_journal
  ),
  del2 AS (
    DELETE FROM jmap_changes_journal j
     USING ranked r
     WHERE j.mailbox_id = r.mailbox_id
       AND j.datatype   = r.datatype
       AND j.state_seq  = r.state_seq
       AND r.rnk > v_high_water
    RETURNING 1
  )
  SELECT count(*) INTO v_n FROM del2;
  v_deleted := v_deleted + v_n;

  RETURN v_deleted;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

DO $$
DECLARE
  v_granted_create BOOLEAN := FALSE;
BEGIN
  REVOKE ALL ON FUNCTION public.prune_changes_journal(integer, integer) FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
    REVOKE ALL ON FUNCTION public.prune_changes_journal(integer, integer) FROM setjoin_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    IF NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
      GRANT CREATE ON SCHEMA public TO setjoin_worker;
      v_granted_create := TRUE;
    END IF;
    ALTER FUNCTION public.prune_changes_journal(integer, integer) OWNER TO setjoin_worker;
    GRANT EXECUTE ON FUNCTION public.prune_changes_journal(integer, integer) TO setjoin_worker;
    IF v_granted_create THEN
      REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
    END IF;
  END IF;
END $$;

-- [embedded verbatim from reducers/drive_maintenance_sweep.sql]
CREATE OR REPLACE FUNCTION prune_drive_changes(
  p_max_window_days INT DEFAULT 90,
  p_high_water      INT DEFAULT 50000
) RETURNS BIGINT
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_deleted        BIGINT := 0;
  v_n              BIGINT;
  v_retention_days INT;
  v_high_water     INT;
  v_cutoff         TIMESTAMPTZ;
BEGIN
  PERFORM public.work_queue_require_worker();

  v_retention_days := public.effective_journal_retention_days(COALESCE(p_max_window_days, 90));
  v_high_water     := GREATEST(COALESCE(p_high_water, 50000), 0);
  v_cutoff         := now() - make_interval(days => v_retention_days);

  -- Arm 1: contiguous prefix-only age prune per space_id.
  WITH bounds AS (
    SELECT space_id,
           MIN(seq) FILTER (WHERE at >= v_cutoff) AS keep_from_seq
      FROM public.drive_changes
     GROUP BY space_id
  ),
  del AS (
    DELETE FROM public.drive_changes d
     USING bounds b
     WHERE d.space_id = b.space_id
       AND (b.keep_from_seq IS NULL OR d.seq < b.keep_from_seq)
    RETURNING 1
  )
  SELECT count(*) INTO v_n FROM del;
  v_deleted := v_deleted + v_n;

  WITH ranked AS (
    SELECT space_id, seq,
           dense_rank() OVER (PARTITION BY space_id ORDER BY seq DESC) AS rnk
      FROM public.drive_changes
  ),
  del2 AS (
    DELETE FROM public.drive_changes d
     USING ranked r
     WHERE d.space_id = r.space_id
       AND d.seq      = r.seq
       AND r.rnk > v_high_water
    RETURNING 1
  )
  SELECT count(*) INTO v_n FROM del2;
  v_deleted := v_deleted + v_n;

  RETURN v_deleted;
END;
$$;

DO $$
BEGIN
  REVOKE ALL ON FUNCTION public.prune_drive_changes(integer, integer) FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
    REVOKE ALL ON FUNCTION public.prune_drive_changes(integer, integer) FROM setjoin_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    GRANT EXECUTE ON FUNCTION public.prune_drive_changes(integer, integer) TO setjoin_worker;
  END IF;
END $$;

CREATE OR REPLACE FUNCTION drive_maintenance_sweep() RETURNS JSONB AS $$
DECLARE
  v_journal INT; v_access_journal INT; v_claims INT; v_grants_pruned INT;
  v_aged INT; v_destroyed INT;
  v_fired INT; v_orphan_chunks INT;
  v_retention_days INT; v_high_water INT;
BEGIN
  v_retention_days := public.effective_journal_retention_days(90);
  v_high_water     := COALESCE(
    (SELECT (value #>> '{}')::int FROM public.system_config WHERE key = 'offline_journal_high_water'),
    50000
  );
  v_journal := public.prune_drive_changes(v_retention_days, v_high_water)::int;
  -- Re-clamp after prune_drive_changes (which calls effective_journal_retention_days
  -- internally) so drive_access_invalidations retention is always >= drive_changes
  -- retention even under a concurrent offline_policies increase.
  v_retention_days := GREATEST(v_retention_days, public.effective_journal_retention_days(90));

  WITH doomed AS MATERIALIZED (
    SELECT space_id,max(cursor) AS floor FROM public.drive_access_invalidations
     WHERE created_at<now()-make_interval(days => v_retention_days) GROUP BY space_id
  ), floors AS (
    UPDATE public.drive_acl_generations g
       SET retained_after_cursor=GREATEST(g.retained_after_cursor,d.floor)
      FROM doomed d WHERE g.space_id=d.space_id RETURNING g.space_id
  )
  DELETE FROM public.drive_access_invalidations i
   USING public.drive_acl_generations g
   WHERE i.space_id=g.space_id AND i.cursor<g.retained_after_cursor;
  GET DIAGNOSTICS v_access_journal=ROW_COUNT;

  -- ponytail: single INSERT...SELECT, inline — reuses drive_chunk_gc_queue,
  -- no new deletion path. Order vs. the claims DELETE below doesn't matter:
  -- this only cares whether a NON-expired claim exists, which that DELETE
  -- (it only removes expired ones) never changes.
  INSERT INTO public.drive_chunk_gc_queue (scope_key, sha256)
  SELECT c.scope_key, c.sha256
    FROM public.drive_chunks c
   WHERE c.ref_count = 0
     AND NOT EXISTS (
       SELECT 1 FROM public.drive_upload_claims cl
        WHERE cl.scope_key = c.scope_key AND cl.sha256 = c.sha256
          AND cl.claimed_at >= now() - interval '7 days')
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS v_orphan_chunks = ROW_COUNT;

  -- ponytail: 1-line DELETE, inline (same reasoning).
  DELETE FROM drive_upload_claims WHERE claimed_at < now() - interval '7 days';
  GET DIAGNOSTICS v_claims = ROW_COUNT;
  -- ponytail: still a single DELETE statement (the WHERE just wraps across
  -- lines for the two-branch OR) — extracting it would be a shallow split.
  DELETE FROM drive_export_grants
   WHERE (consumed_at IS NOT NULL AND consumed_at < now() - interval '30 days')
      OR (consumed_at IS NULL AND expires_at < now() - interval '7 days');
  GET DIAGNOSTICS v_grants_pruned = ROW_COUNT;

  -- ── two-level trash cadence (P6 Task 4, spec §3.5) ──────────────────────
  -- Task 11: the age→destroy cadence itself now lives in
  -- drive_sweep_age_trash() — a real, independently testable body (two
  -- loops + a retry-until-no-progress pass), unlike the legs above.
  SELECT p_aged, p_destroyed INTO v_aged, v_destroyed FROM drive_sweep_age_trash();

  -- ── audit-alarm evaluation (P6 Task 5, spec §9.3) ───────────────────────
  -- Task 10: the evaluator itself now lives in drive_alarm_evaluate().
  v_fired := drive_alarm_evaluate();

  RETURN jsonb_build_object('journalPruned', v_journal,
                            'accessJournalPruned',v_access_journal,'claimsPruned', v_claims,
                            'grantsPruned', v_grants_pruned,
                            'trashAged', v_aged, 'trashDestroyed', v_destroyed,
                            'alarmsFired', v_fired, 'orphanChunksQueued', v_orphan_chunks);
END;
$$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/drive_changes_since.sql]
CREATE OR REPLACE FUNCTION drive_changes_since(
  p_user_id BIGINT, p_space_id BIGINT, p_since BIGINT, p_max INT DEFAULT 500
) RETURNS JSONB AS $$
DECLARE
  v_head BIGINT; v_floor BIGINT; v_rows JSONB; v_n BIGINT;
  v_tombstone_floor TIMESTAMPTZ; v_cursor_at TIMESTAMPTZ;
BEGIN
  SELECT s.change_seq INTO v_head FROM drive_spaces s
   WHERE s.id=p_space_id
     AND public.drive_user_has_space_access(p_user_id,s.id);
  IF v_head IS NULL THEN
    RAISE EXCEPTION 'drive space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  -- floor: the oldest seq still answerable from the journal (MIN(seq)-1); an
  -- empty journal can only answer p_since = head.
  SELECT COALESCE(MIN(seq) - 1, v_head) INTO v_floor FROM drive_changes WHERE space_id = p_space_id;
  IF p_since < v_floor THEN
    RETURN jsonb_build_object('cannotCalculateChanges', true);
  END IF;
  v_tombstone_floor := public.sync_tombstone_floor_at();
  IF p_since > 0 AND v_tombstone_floor > '-infinity'::timestamptz THEN
    SELECT MAX(at)
      INTO v_cursor_at
      FROM public.drive_changes
     WHERE space_id = p_space_id
       AND seq <= p_since;
    IF v_cursor_at IS NULL OR v_cursor_at < v_tombstone_floor THEN
      RETURN jsonb_build_object(
        'cannotCalculateChanges', true,
        'tombstoneFloorExceeded', true
      );
    END IF;
  END IF;
  WITH scanned AS MATERIALIZED (
    SELECT node_id,op,seq FROM drive_changes
     WHERE space_id=p_space_id AND seq>p_since
     ORDER BY seq LIMIT LEAST(GREATEST(p_max,1),1000)
  ), visible AS (
    SELECT s.* FROM scanned s
     WHERE s.node_id=0
        OR public.drive_runtime_has_node_capability(
             p_user_id,s.node_id,'read_metadata')
        OR (NOT EXISTS(SELECT 1 FROM public.drive_nodes n WHERE n.id=s.node_id)
            AND public.drive_runtime_has_space_root_capability(
              p_user_id,p_space_id,'read_metadata'))
        OR (s.op IN ('trash','destroy') AND EXISTS(
          SELECT 1 FROM public.drive_access_invalidations i
           WHERE i.space_id=p_space_id AND i.anchor_node_id=s.node_id
             AND (i.principal_kind='all'
                  OR (i.principal_kind='user' AND i.principal_id=p_user_id))
        ))
  )
  SELECT COALESCE((SELECT jsonb_agg(jsonb_build_object(
           'nodeId',node_id::text,'op',op,'seq',seq::text) ORDER BY seq)
         FROM visible),'[]'::jsonb),
         COALESCE((SELECT max(seq) FROM scanned),p_since)
    INTO v_rows,v_n;
  RETURN jsonb_build_object(
    'newState', v_n::text,
    'changed',  v_rows,
    'hasMore',  (SELECT EXISTS (SELECT 1 FROM drive_changes
                  WHERE space_id = p_space_id
                    AND seq > v_n)));
END;
$$ LANGUAGE plpgsql STABLE;

-- [embedded verbatim from reducers/scope_revocations.sql]
CREATE OR REPLACE FUNCTION prune_scope_revocations(
    p_retention_days INT DEFAULT 90
) RETURNS BIGINT
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_retain_days INT;
    v_cutoff      TIMESTAMPTZ;
    v_deleted     BIGINT := 0;
    v_max_id      BIGINT;
BEGIN
    PERFORM public.work_queue_require_worker();

    v_retain_days := public.effective_journal_retention_days(
        GREATEST(COALESCE(p_retention_days, 90), 90)
    );
    v_cutoff := now() - make_interval(days => v_retain_days);

    WITH del AS (
        DELETE FROM public.scope_revocations
         WHERE occurred_at < v_cutoff
        RETURNING id
    )
    SELECT count(*), MAX(id) INTO v_deleted, v_max_id FROM del;

    IF v_deleted > 0 THEN
        INSERT INTO public.sync_tombstone_floor (
            id, pruned_before_at, pruned_before_revocation_id, updated_at
        )
        VALUES (1, v_cutoff, COALESCE(v_max_id, 0), now())
        ON CONFLICT (id) DO UPDATE
           SET pruned_before_at = GREATEST(
                   public.sync_tombstone_floor.pruned_before_at,
                   EXCLUDED.pruned_before_at
               ),
               pruned_before_revocation_id = GREATEST(
                   public.sync_tombstone_floor.pruned_before_revocation_id,
                   EXCLUDED.pruned_before_revocation_id
               ),
               updated_at = now();
    END IF;

    RETURN v_deleted;
END;
$$;

DO $$
BEGIN
    REVOKE ALL ON FUNCTION public.prune_scope_revocations(integer) FROM PUBLIC;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE ALL ON FUNCTION public.prune_scope_revocations(integer) FROM setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.prune_scope_revocations(integer) TO setjoin_worker;
    END IF;
END $$;

-- [embedded verbatim from reducers/jmap_email.sql]
CREATE OR REPLACE FUNCTION jmap_email_changes(
  p_mailbox_id  BIGINT,
  p_since_state TEXT,
  p_max_changes INT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_current   BIGINT;
  v_since     BIGINT := p_since_state::BIGINT;
  v_oldest    BIGINT;
  v_new_state BIGINT;
  v_count     INT    := 0;
  v_prev_seq  BIGINT;
  v_created   BIGINT[] := '{}';
  v_updated   BIGINT[] := '{}';
  v_destroyed BIGINT[] := '{}';
  v_has_more        BOOLEAN  := FALSE;
  v_tombstone_floor TIMESTAMPTZ;
  v_cursor_at       TIMESTAMPTZ;
  r RECORD;
BEGIN
  -- R1: always filter by auth-derived mailbox id
  SELECT jmap_email_state INTO v_current FROM mailboxes WHERE id = p_mailbox_id;
  IF v_current IS NULL THEN
    RAISE EXCEPTION 'Account not found'
      USING ERRCODE = 'BZ006', HINT = '{"type":"accountNotFound"}';
  END IF;

  IF v_since > v_current THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  -- Pruned: sinceState predates the oldest retained journal row (decision 11).
  -- Guard v_since>0: sinceState=0 always means "full history from start", never pruned.
  SELECT MIN(state_seq) INTO v_oldest
    FROM jmap_changes_journal WHERE mailbox_id = p_mailbox_id AND datatype = 'email';  -- R1
  IF v_since > 0 AND (v_oldest IS NULL OR v_since < v_oldest - 1) THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  -- Resync sentinel anywhere in (sinceState, currentState] → coarse path (BZ011).
  -- ponytail: sentinel means a counter-only bump happened here; we can't produce a
  -- precise list, so force full-resync. Task 4 converts sentinels to precise rows.
  IF EXISTS (
    SELECT 1 FROM jmap_changes_journal
     WHERE mailbox_id = p_mailbox_id AND datatype = 'email' AND state_seq > v_since AND op = 'resync'  -- R1
  ) THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  -- Wave 2.6 (#553): if revocation tombstones have been pruned past this cursor
  -- (or no journal entry <= v_since remains to bound cursor age — fail-closed),
  -- force a mandatory full scope-membership reconcile via BZ011.
  v_tombstone_floor := public.sync_tombstone_floor_at();
  IF v_since > 0 AND v_tombstone_floor > '-infinity'::timestamptz THEN
    SELECT MAX(created_at)
      INTO v_cursor_at
      FROM jmap_changes_journal
     WHERE mailbox_id = p_mailbox_id
       AND datatype = 'email'
       AND state_seq <= v_since;  -- R1
    IF v_cursor_at IS NULL OR v_cursor_at < v_tombstone_floor THEN
      RAISE EXCEPTION 'Cannot calculate changes'
        USING ERRCODE = 'BZ011',
              HINT = '{"type":"cannotCalculateChanges","reason":"tombstoneFloorExceeded"}';
    END IF;
  END IF;

  v_new_state := v_current;

  -- Collapse per entity_id (latest op; created+destroyed cancels).
  -- Walk in state_seq order; apply the soft cap at state_seq GROUP boundaries only
  -- (never split a group — all ids sharing a state_seq are an atomic batch).
  FOR r IN
    WITH per_id AS (
      SELECT entity_id,
             (array_agg(op ORDER BY state_seq DESC))[1] AS latest_op,
             bool_or(op = 'created')   AS had_created,
             bool_or(op = 'destroyed') AS had_destroyed,
             MAX(state_seq)            AS max_seq
        FROM jmap_changes_journal
       WHERE mailbox_id = p_mailbox_id AND datatype = 'email' AND state_seq > v_since AND op <> 'resync'  -- R1
       GROUP BY entity_id
    )
    SELECT entity_id, latest_op, had_created, max_seq
      FROM per_id
     ORDER BY max_seq, entity_id
  LOOP
    -- RFC 8620 §5.2: created+destroyed since oldState → noop (omit from all lists)
    IF r.had_created AND r.latest_op = 'destroyed' THEN
      CONTINUE;
    END IF;

    -- Soft cap: only trigger at a state_seq GROUP boundary, never mid-group.
    -- ponytail: v_prev_seq tracks the last emitted group; crossing to a new seq
    -- is the only legal cut point. A single oversized group is always returned
    -- whole (first iteration: v_prev_seq IS NULL → can't be a boundary yet).
    IF p_max_changes IS NOT NULL
       AND v_count >= p_max_changes
       AND v_prev_seq IS NOT NULL
       AND r.max_seq > v_prev_seq
    THEN
      v_has_more  := TRUE;
      v_new_state := v_prev_seq;  -- last fully-emitted state_seq is the new cursor
      EXIT;
    END IF;

    IF r.latest_op = 'destroyed' THEN
      v_destroyed := v_destroyed || r.entity_id;
    ELSIF r.had_created THEN
      v_created   := v_created   || r.entity_id;
    ELSE
      v_updated   := v_updated   || r.entity_id;
    END IF;
    v_count    := v_count + 1;
    v_prev_seq := r.max_seq;
  END LOOP;

  RETURN jsonb_build_object(
    'accountId',     p_mailbox_id::TEXT,
    'oldState',      p_since_state,
    'newState',      v_new_state::TEXT,
    'hasMoreChanges', v_has_more,
    'created',   COALESCE(to_jsonb(v_created),   '[]'::JSONB),
    'updated',   COALESCE(to_jsonb(v_updated),   '[]'::JSONB),
    'destroyed', COALESCE(to_jsonb(v_destroyed), '[]'::JSONB)
  );
END;
$$ LANGUAGE plpgsql STABLE;

-- [embedded verbatim from reducers/jmap_entity_changes.sql]
CREATE OR REPLACE FUNCTION jmap_entity_changes(
  p_mailbox_id  BIGINT,
  p_datatype    TEXT,
  p_since_state TEXT,
  p_max_changes INT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_current   BIGINT := entity_state(p_mailbox_id, p_datatype);  -- R1: auth-derived mailbox
  v_since     BIGINT := p_since_state::BIGINT;
  v_oldest    BIGINT;
  v_new_state BIGINT;
  v_count     INT    := 0;
  v_prev_seq  BIGINT;
  v_created   BIGINT[] := '{}';
  v_updated   BIGINT[] := '{}';
  v_destroyed BIGINT[] := '{}';
  v_has_more        BOOLEAN  := FALSE;
  v_tombstone_floor TIMESTAMPTZ;
  v_cursor_at       TIMESTAMPTZ;
  r RECORD;
BEGIN
  IF v_since > v_current THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  -- Pruned: sinceState predates the oldest retained journal row for this datatype.
  -- Guard v_since>0: sinceState=0 always means "full history from start", never pruned.
  SELECT MIN(state_seq) INTO v_oldest
    FROM jmap_changes_journal
   WHERE mailbox_id = p_mailbox_id AND datatype = p_datatype;  -- R1
  IF v_since > 0 AND (v_oldest IS NULL OR v_since < v_oldest - 1) THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  -- Resync sentinel anywhere in (sinceState, currentState] → coarse path → BZ011.
  IF EXISTS (
    SELECT 1 FROM jmap_changes_journal
     WHERE mailbox_id = p_mailbox_id AND datatype = p_datatype
       AND state_seq > v_since AND op = 'resync'  -- R1
  ) THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  -- Wave 2.6 (#553): if revocation tombstones have been pruned past this cursor
  -- (or no journal entry <= v_since remains to bound cursor age — fail-closed),
  -- force a mandatory full scope-membership reconcile via BZ011.
  v_tombstone_floor := public.sync_tombstone_floor_at();
  IF v_since > 0 AND v_tombstone_floor > '-infinity'::timestamptz THEN
    SELECT MAX(created_at)
      INTO v_cursor_at
      FROM jmap_changes_journal
     WHERE mailbox_id = p_mailbox_id
       AND datatype = p_datatype
       AND state_seq <= v_since;  -- R1
    IF v_cursor_at IS NULL OR v_cursor_at < v_tombstone_floor THEN
      RAISE EXCEPTION 'Cannot calculate changes'
        USING ERRCODE = 'BZ011',
              HINT = '{"type":"cannotCalculateChanges","reason":"tombstoneFloorExceeded"}';
    END IF;
  END IF;

  v_new_state := v_current;

  -- Collapse per entity_id (latest op; created+destroyed cancels). Walk in state_seq
  -- order; apply the soft cap at state_seq GROUP boundaries only (never split a group).
  FOR r IN
    WITH per_id AS (
      SELECT entity_id,
             (array_agg(op ORDER BY state_seq DESC))[1] AS latest_op,
             bool_or(op = 'created')   AS had_created,
             MAX(state_seq)            AS max_seq
        FROM jmap_changes_journal
       WHERE mailbox_id = p_mailbox_id AND datatype = p_datatype
         AND state_seq > v_since AND op <> 'resync'  -- R1
       GROUP BY entity_id
    )
    SELECT entity_id, latest_op, had_created, max_seq
      FROM per_id
     ORDER BY max_seq, entity_id
  LOOP
    -- RFC 8620 §5.2: created+destroyed since oldState → noop (omit from all lists).
    IF r.had_created AND r.latest_op = 'destroyed' THEN
      CONTINUE;
    END IF;

    -- Soft cap: only trigger at a state_seq GROUP boundary, never mid-group.
    IF p_max_changes IS NOT NULL
       AND v_count >= p_max_changes
       AND v_prev_seq IS NOT NULL
       AND r.max_seq > v_prev_seq
    THEN
      v_has_more  := TRUE;
      v_new_state := v_prev_seq;
      EXIT;
    END IF;

    IF r.latest_op = 'destroyed' THEN
      v_destroyed := v_destroyed || r.entity_id;
    ELSIF r.had_created THEN
      v_created   := v_created   || r.entity_id;
    ELSE
      v_updated   := v_updated   || r.entity_id;
    END IF;
    v_count    := v_count + 1;
    v_prev_seq := r.max_seq;
  END LOOP;

  RETURN jsonb_build_object(
    'accountId',     p_mailbox_id::TEXT,
    'oldState',      p_since_state,
    'newState',      v_new_state::TEXT,
    'hasMoreChanges', v_has_more,
    'created',   COALESCE(to_jsonb(v_created),   '[]'::JSONB),
    'updated',   COALESCE(to_jsonb(v_updated),   '[]'::JSONB),
    'destroyed', COALESCE(to_jsonb(v_destroyed), '[]'::JSONB)
  );
END;
$$ LANGUAGE plpgsql STABLE;

INSERT INTO schema_migrations (version, applied_at)
VALUES (295, now())
ON CONFLICT (version) DO NOTHING;
