-- chat_dm_open.sql — DM/group_dm open (extracted verbatim from the legacy
-- chat_channel.sql bundle per WP3 one-reducer-per-file; body unchanged except
-- the WP3 audit_write call on the freshly-created path).
--
-- SECURITY DEFINER + worker-owned (V134 / native-RLS W4 wave): a DM open
-- writes the OTHER founding members' chat_channel_members rows — cross-member
-- inserts no sane invoker-rights WITH CHECK can admit. Self-authorizing:
-- p_user_id is always folded into the member set (R2), the member set IS the
-- channel identity (member_key). Pinned search_path per ARCH-018.

CREATE OR REPLACE FUNCTION chat_dm_open(
    p_user_id bigint, p_other_ids bigint[]
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_all  bigint[];
    v_kind text;
    v_key  text;
    v_id   bigint;
    v_uid  bigint;
    v_channel_change_seq bigint;
    v_guest_can_post boolean;
    v_guest_history_from_join boolean;
    v_is_guest boolean;
    v_caller_is_guest boolean;
BEGIN
    SELECT array_agg(DISTINCT u ORDER BY u) INTO v_all
      FROM unnest(array_append(COALESCE(p_other_ids, '{}'::bigint[]), p_user_id)) u;
    v_caller_is_guest := is_guest_account(p_user_id);
    -- Serialize the guest caller itself before policy evaluation or any
    -- founding membership insert. Disable either sweeps a completed DM or
    -- wins first and refuses it; profile updates cannot leave stale policy.
    IF v_caller_is_guest THEN
        PERFORM guest_require_grantable(p_user_id);
    END IF;
    -- Guest G2: the one guest-initiation opening is deliberately narrow.
    -- One predicate binds profile authority, current guest lifecycle, one
    -- shared ordinary channel, and a live local non-guest target. Every deny
    -- is BZ215, including a nonexistent id; no target preflight can become an
    -- identity oracle.
    IF v_caller_is_guest AND NOT (
      array_length(v_all, 1) = 2
      AND guest_dm_policy_allows(p_user_id)
      AND EXISTS (
        SELECT 1
          FROM users target
          JOIN domains target_domain ON target_domain.id = target.domain_id
         WHERE target.id = (
                 SELECT x FROM unnest(v_all) x WHERE x <> p_user_id LIMIT 1)
           AND target.enabled AND target_domain.is_local
           AND NOT is_guest_account(target.id)
           AND EXISTS (
             SELECT 1
               FROM chat_channel_members caller_cm
               JOIN chat_channel_members target_cm
                 ON target_cm.channel_id = caller_cm.channel_id
                AND target_cm.user_id = target.id
               JOIN chat_channels shared_c ON shared_c.id = caller_cm.channel_id
              WHERE caller_cm.user_id = p_user_id
                AND shared_c.kind = 'channel' AND NOT shared_c.is_archived)
      )
    ) THEN
        RAISE EXCEPTION 'not available to guest accounts'
            USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
    END IF;
    IF array_length(v_all, 1) IS NULL OR array_length(v_all, 1) < 2 THEN
        RAISE EXCEPTION 'a DM requires at least 2 distinct members'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments"}';
    END IF;
    v_kind := CASE WHEN array_length(v_all, 1) = 2 THEN 'dm' ELSE 'group_dm' END;
    v_key  := array_to_string(v_all, ':');

    -- Anti-oracle target validation (BZ170, same code/anti-oracle shape as
    -- chat_channel_join's private-channel check): every OTHER named member
    -- must be a real, enabled user, else a caller could open a "DM" against a
    -- made-up id or a disabled/offboarded account with zero pushback — bare
    -- membership rows for an id nobody can ever answer from. A nonexistent id
    -- and a disabled id raise the IDENTICAL error so neither is distinguishable
    -- from outside (the same anti-oracle posture BZ170 already carries for
    -- channels). p_user_id itself is intentionally NOT re-checked here — by
    -- the time this reducer runs it is always an already-authenticated caller.
    --
    -- C-5: same serialization for DM targets — chat_dm_open is the second
    -- (and last) reducer that inserts membership rows for arbitrary targets.
    -- Placed BEFORE the enabled-target BZ170 check below so a disabled/
    -- expired guest target answers BZ219 (P9's honest "re-invite required")
    -- instead of the generic BZ170; behavior for disabled MEMBER targets is
    -- unchanged, they still hit BZ170 next.
    PERFORM guest_require_grantable(o.uid)
      FROM unnest(COALESCE(p_other_ids, '{}'::bigint[])) o(uid);
    IF EXISTS (
      SELECT 1 FROM unnest(COALESCE(p_other_ids, '{}'::bigint[])) o(uid)
       WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.id = o.uid AND u.enabled = TRUE)
    ) THEN
        RAISE EXCEPTION 'DM target user not found'
            USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;

    -- DB-enforced dedup (H3/F5 — closes the DM-open TOCTOU race): two
    -- concurrent opens for the same member set race on the partial unique
    -- index, not on a lookup-then-insert. The loser's INSERT is a no-op and
    -- it re-selects the winner's row. Plain INSERT..RETURNING (the
    -- chat_space_ensure/meeting_space_ensure shape) — unlike
    -- chat_channel_create above (invoker rights), this reducer is SECURITY
    -- DEFINER owned by setjoin_worker (BYPASSRLS via apply_worker_ownership),
    -- so RETURNING never has to pass the membership-scoped SELECT policy;
    -- the id-preallocation f59bc436 needed under invoker rights is moot here.
    INSERT INTO chat_channels (kind, member_key, created_by)
      VALUES (v_kind, v_key, p_user_id)
      ON CONFLICT (member_key) WHERE kind IN ('dm', 'group_dm') DO NOTHING
      RETURNING id, change_seq INTO v_id, v_channel_change_seq;
    IF v_id IS NULL THEN
        -- lost the race: another concurrent open won it first.
        SELECT id INTO v_id FROM chat_channels
         WHERE member_key = v_key AND kind IN ('dm', 'group_dm');
        RETURN v_id;
    END IF;
    FOREACH v_uid IN ARRAY v_all LOOP
        SELECT s.can_post, s.history_from_join
          INTO v_guest_can_post, v_guest_history_from_join
          FROM guest_chat_policy_snapshot(v_uid) s;
        v_is_guest := FOUND;
        INSERT INTO chat_channel_members
            (channel_id, user_id, role, can_post, history_floor_seq)
          VALUES (
            v_id, v_uid, 'member',
            CASE WHEN v_is_guest THEN v_guest_can_post ELSE NULL END,
            CASE WHEN v_is_guest AND v_guest_history_from_join
                 THEN v_channel_change_seq ELSE NULL END
          );
        -- A4a Task 3: one member.add per founding member (the DM's baseline
        -- membership) — only reached on the freshly-created path above, never
        -- the ON CONFLICT re-select of an existing DM.
        IF COALESCE((SELECT enabled FROM feature_toggles
                     WHERE key = 'feature.chat_compliance'), FALSE) THEN
            PERFORM chat_access_audit(p_user_id, v_id, 'member.add',
              'member', v_uid, NULL, jsonb_build_object('userId', v_uid, 'role', 'member'), NULL, NULL);
        END IF;
    END LOOP;

    -- WP3 audit coverage: a NEWLY-OPENED DM/group_dm is chat authority
    -- (core). The lost-race re-select arm above returned already, so an
    -- open of an existing DM emits no duplicate row (plan contract).
    PERFORM audit_write(
        p_user_id, 'chat_dm_open', 'chat_channel', v_id,
        NULL,
        jsonb_build_object('kind', v_kind, 'member_count', array_length(v_all, 1)),
        NULL, NULL, 'core');
    RETURN v_id;
END;
$$;
SELECT apply_worker_ownership('chat_dm_open(bigint,bigint[])'::regprocedure);
