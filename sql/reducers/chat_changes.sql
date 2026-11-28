-- chat_changes.sql — Wave 2.6 (#553): dedicated monotonic public.chat_changes
-- journal, unified effective_journal_retention_days() floor, sync_tombstone_floor_at()
-- reader, chat_changes_since() delta reader, and worker-only prune_chat_changes().
--
-- Security & RLS model:
--   * public.chat_changes is ENABLE+FORCE RLS with member-scoped SELECT and
--     INSERT policies via public.chat_member_role(channel_id, app.current_user_id)
--     (fail-closed on unset GUC; no UPDATE/DELETE by setjoin_app).
--   * public.sync_tombstone_floor is ENABLE+FORCE RLS with zero policies
--     (deny-all to setjoin_app); read solely through worker-owned SECURITY DEFINER
--     sync_tombstone_floor_at().
--   * effective_journal_retention_days(...) is worker-owned SECURITY DEFINER
--     reading only the scalar MAX(max_offline_days) from public.offline_policies.
--   * prune_chat_changes(...) is SECURITY INVOKER requiring
--     work_queue_require_worker() (rolbypassrls OR rolsuper -> BZ003), strictly
--     worker-only (reasserted in scripts/provision-roles.sql exact_worker).

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
