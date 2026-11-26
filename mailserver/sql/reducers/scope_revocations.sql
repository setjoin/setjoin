-- scope_revocations.sql — Wave 2.5 (#552): durable scope revocation journal
-- emitter and retention pruner.
--
-- Security & RLS model:
--   * public.scope_revocations is ENABLE+FORCE RLS with zero policies
--     (deny-all to setjoin_app).
--   * emit_scope_revoked(...) is a narrow worker-owned SECURITY DEFINER seam
--     (SET search_path = pg_catalog, public, REVOKE ALL FROM PUBLIC, GRANT
--     EXECUTE TO setjoin_app, setjoin_worker) that verifies BOTH caller
--     authority (when invoked by a non-privileged role) AND authoritative
--     post-mutation DB revocation state before inserting into
--     public.scope_revocations and enqueuing an opaque pointer bell
--     ('scope_revoked', v_id::text) into public.notify_intents (+ _test_notify_log
--     under app.capture_notify='on').
--   * prune_scope_revocations(...) is SECURITY INVOKER requiring
--     work_queue_require_worker() (rolbypassrls OR rolsuper), strictly
--     worker-only (reasserted in scripts/provision-roles.sql exact_worker).

CREATE OR REPLACE FUNCTION emit_scope_revoked(
    p_user_id           BIGINT,
    p_scope_kind        TEXT,
    p_scope_id          BIGINT,
    p_reason            TEXT,
    p_subtree_anchor_id BIGINT DEFAULT NULL
) RETURNS BIGINT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_id                        BIGINT;
    v_existing_id               BIGINT;
    v_invoker_role              TEXT := COALESCE(NULLIF(current_setting('role', TRUE), 'none'), session_user);
    v_is_privileged             BOOLEAN := FALSE;
    v_caller_uid_txt            TEXT := NULLIF(current_setting('app.current_user_id', TRUE), '');
    v_caller_mbx_txt            TEXT := NULLIF(current_setting('app.current_mailbox_id', TRUE), '');
    v_caller_uid                BIGINT;
    v_caller_mbx                BIGINT;
    v_is_self_target            BOOLEAN := FALSE;
    v_is_mbx_owner_or_cal_admin BOOLEAN := FALSE;
    v_caller_authorized         BOOLEAN := FALSE;
    v_target_active_usr         BOOLEAN := TRUE;
BEGIN
    IF p_scope_kind IS NULL OR p_scope_kind NOT IN ('mailbox', 'space', 'channel') THEN
        RAISE EXCEPTION 'emit_scope_revoked: invalid scope_kind %', p_scope_kind
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_scope_kind"}';
    END IF;
    IF p_scope_id IS NULL OR p_scope_id <= 0 THEN
        RAISE EXCEPTION 'emit_scope_revoked: scope_id must be positive'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_scope_id"}';
    END IF;
    IF p_reason IS NULL OR octet_length(p_reason) = 0 OR octet_length(p_reason) > 128 THEN
        RAISE EXCEPTION 'emit_scope_revoked: reason must be 1..128 bytes'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_revocation_reason"}';
    END IF;
    IF p_subtree_anchor_id IS NOT NULL AND p_scope_kind <> 'space' THEN
        RAISE EXCEPTION 'emit_scope_revoked: subtree_anchor_id is only valid for space scopes'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_subtree_anchor"}';
    END IF;

    SELECT COALESCE(r.rolsuper OR r.rolbypassrls, FALSE)
      INTO v_is_privileged
      FROM pg_catalog.pg_roles r
     WHERE r.rolname = v_invoker_role;

    IF v_caller_uid_txt IS NOT NULL AND v_caller_uid_txt ~ '^[0-9]+$' THEN
        v_caller_uid := v_caller_uid_txt::BIGINT;
    END IF;
    IF v_caller_mbx_txt IS NOT NULL AND v_caller_mbx_txt ~ '^[0-9]+$' THEN
        v_caller_mbx := v_caller_mbx_txt::BIGINT;
    END IF;

    IF NOT v_is_privileged AND v_caller_uid IS NULL AND v_caller_mbx IS NULL THEN
        RAISE EXCEPTION 'emit_scope_revoked: unauthenticated caller is forbidden'
            USING ERRCODE = '42501';
    END IF;

    v_is_self_target := COALESCE(
        NOT v_is_privileged AND p_user_id IS NOT NULL
        AND v_caller_uid IS NOT NULL AND v_caller_uid = p_user_id,
        FALSE
    );

    -- Determine whether the target user is an active principal (disabled/expired
    -- guests keep frozen rows on expiry while losing all live scope access).
    IF p_user_id IS NOT NULL THEN
        SELECT COALESCE(u.enabled, TRUE)
               AND (
                   NOT public.is_guest_account(p_user_id)
                   OR EXISTS (
                       SELECT 1
                         FROM public.guest_accounts ga
                        WHERE ga.user_id = p_user_id
                          AND ga.status = 'active'
                          AND (ga.expires_at IS NULL OR ga.expires_at >= now())
                   )
               )
          INTO v_target_active_usr
          FROM public.users u
         WHERE u.id = p_user_id;
        v_target_active_usr := COALESCE(v_target_active_usr, TRUE);
    END IF;

    -- Authoritative caller-authority + post-mutation state verification:
    -- blocks spoofed setjoin_app calls from forging revocations against live
    -- access OR flooding scope_revocations/notify_intents for unrelated scopes.
    IF p_scope_kind = 'channel' THEN
        IF NOT v_is_privileged THEN
            v_caller_authorized := COALESCE(
                (p_user_id IS NOT NULL AND v_caller_uid IS NOT NULL AND v_caller_uid = p_user_id)
                OR COALESCE(v_caller_uid IS NOT NULL AND public.chat_member_role(p_scope_id, v_caller_uid) IN ('owner', 'admin'), FALSE)
                OR (v_caller_uid IS NOT NULL AND EXISTS (
                    SELECT 1
                      FROM public.meetings m
                     WHERE m.chat_channel_id = p_scope_id
                       AND COALESCE(public.meeting_member_role(m.id, v_caller_uid) IN ('host', 'cohost'), FALSE)
                ))
                OR COALESCE(v_caller_uid IS NOT NULL AND p_user_id IS NOT NULL
                    AND public.guest_admin_can_reach_with_permission(v_caller_uid, p_user_id, 'guests.manage'), FALSE),
                FALSE
            );
            IF NOT COALESCE(v_caller_authorized, FALSE) THEN
                RAISE EXCEPTION 'emit_scope_revoked: caller lacks channel revocation authority'
                    USING ERRCODE = '42501';
            END IF;
            IF v_is_self_target AND NOT EXISTS (
                SELECT 1
                  FROM public.chat_channels
                 WHERE id = p_scope_id
            ) THEN
                RAISE EXCEPTION 'emit_scope_revoked: target channel does not exist'
                    USING ERRCODE = '42501';
            END IF;
        END IF;

        IF p_user_id IS NULL THEN
            IF NOT EXISTS (
                SELECT 1
                  FROM public.chat_channels
                 WHERE id = p_scope_id
                   AND is_archived
            ) THEN
                RAISE EXCEPTION 'emit_scope_revoked: channel-wide revocation requires archived channel'
                    USING ERRCODE = '42501';
            END IF;
        ELSE
            IF v_target_active_usr AND EXISTS (
                SELECT 1
                  FROM public.chat_channel_members
                 WHERE channel_id = p_scope_id
                   AND user_id = p_user_id
            ) THEN
                RAISE EXCEPTION 'emit_scope_revoked: target user still holds channel membership'
                    USING ERRCODE = '42501';
            END IF;
        END IF;
    ELSIF p_scope_kind = 'space' THEN
        IF p_subtree_anchor_id IS NOT NULL THEN
            IF NOT v_is_privileged THEN
                RAISE EXCEPTION 'emit_scope_revoked: subtree anchor revocation requires privileged worker role'
                    USING ERRCODE = '42501';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                  FROM public.drive_access_invalidations
                 WHERE space_id = p_scope_id
                   AND anchor_node_id = p_subtree_anchor_id
                   AND reason NOT IN (
                       'member_grant', 'grant', 'folder_admin_grant',
                       'inheritance_resume', 'tree_move'
                   )
            ) THEN
                RAISE EXCEPTION 'emit_scope_revoked: no matching revoking drive subtree invalidation'
                    USING ERRCODE = '42501';
            END IF;
        ELSIF p_user_id IS NULL THEN
            RAISE EXCEPTION 'emit_scope_revoked: space-wide revocation without anchor is forbidden'
                USING ERRCODE = '42501';
        ELSE
            IF NOT v_is_privileged THEN
                v_caller_authorized := COALESCE(
                    (v_caller_uid IS NOT NULL AND v_caller_uid = p_user_id)
                    OR (v_caller_uid IS NOT NULL AND (
                        COALESCE(public.drive_space_owner(p_scope_id) = v_caller_uid, FALSE)
                        OR COALESCE(public.drive_member_role(p_scope_id, v_caller_uid) = 'manager', FALSE)
                        OR COALESCE(public.drive_runtime_has_space_root_capability(v_caller_uid, p_scope_id, 'manage_acl'), FALSE)
                        OR EXISTS (
                            SELECT 1
                              FROM public.drive_folder_admins dfa
                             WHERE dfa.space_id = p_scope_id
                               AND dfa.user_id = v_caller_uid
                        )
                        OR EXISTS (
                            SELECT 1
                              FROM public.drive_spaces s
                             WHERE s.id = p_scope_id
                               AND s.chat_channel_id IS NOT NULL
                               AND COALESCE(public.chat_member_role(s.chat_channel_id, v_caller_uid) IN ('owner', 'admin'), FALSE)
                        )
                        OR EXISTS (
                            SELECT 1
                              FROM public.drive_spaces s
                              JOIN public.meetings m
                                ON (m.id = s.meeting_id OR m.chat_channel_id = s.chat_channel_id)
                             WHERE s.id = p_scope_id
                               AND COALESCE(public.meeting_member_role(m.id, v_caller_uid) IN ('host', 'cohost'), FALSE)
                        )
                        OR COALESCE(public.guest_admin_can_reach_with_permission(v_caller_uid, p_user_id, 'guests.manage'), FALSE)
                    )),
                    FALSE
                );
                IF NOT COALESCE(v_caller_authorized, FALSE) THEN
                    RAISE EXCEPTION 'emit_scope_revoked: caller lacks space revocation authority'
                        USING ERRCODE = '42501';
                END IF;
                IF v_is_self_target AND NOT EXISTS (
                    SELECT 1
                      FROM public.drive_spaces
                     WHERE id = p_scope_id
                ) THEN
                    RAISE EXCEPTION 'emit_scope_revoked: target space does not exist'
                        USING ERRCODE = '42501';
                END IF;
            END IF;

            IF v_target_active_usr AND (
                public.drive_space_owner(p_scope_id) = p_user_id
                OR EXISTS (
                    SELECT 1
                      FROM public.drive_space_members
                     WHERE space_id = p_scope_id
                       AND user_id = p_user_id
                )
                OR (
                    public.drive_user_has_space_access(p_user_id, p_scope_id)
                    AND NOT public.drive_has_admin_perm(p_user_id, 'drive.view')
                )
            ) THEN
                RAISE EXCEPTION 'emit_scope_revoked: target user still holds live space access'
                    USING ERRCODE = '42501';
            END IF;
        END IF;
    ELSIF p_scope_kind = 'mailbox' THEN
        IF NOT v_is_privileged THEN
            v_is_mbx_owner_or_cal_admin := COALESCE(
                (v_caller_mbx IS NOT NULL AND v_caller_mbx = p_scope_id)
                OR (v_caller_uid IS NOT NULL AND (
                    EXISTS (
                        SELECT 1
                          FROM public.mailboxes
                         WHERE id = p_scope_id
                           AND user_id = v_caller_uid
                    )
                    OR EXISTS (
                        SELECT 1
                          FROM public.calendars c
                          JOIN public.calendar_acls a ON a.calendar_id = c.id
                         WHERE c.mailbox_id = p_scope_id
                           AND a.user_id = v_caller_uid
                           AND a.permission = 'admin'
                    )
                )),
                FALSE
            );
            v_caller_authorized := v_is_mbx_owner_or_cal_admin OR v_is_self_target;
            IF NOT COALESCE(v_caller_authorized, FALSE) THEN
                RAISE EXCEPTION 'emit_scope_revoked: caller lacks mailbox revocation authority'
                    USING ERRCODE = '42501';
            END IF;
            IF v_is_self_target AND NOT EXISTS (
                SELECT 1
                  FROM public.mailboxes
                 WHERE id = p_scope_id
            ) THEN
                RAISE EXCEPTION 'emit_scope_revoked: target mailbox does not exist'
                    USING ERRCODE = '42501';
            END IF;
        END IF;

        IF p_user_id IS NULL THEN
            IF NOT EXISTS (
                SELECT 1
                  FROM public.mailboxes
                 WHERE id = p_scope_id
                   AND (NOT enabled OR user_id IS NULL)
            ) AND NOT EXISTS (
                SELECT 1
                  FROM public.mailbox_lifecycle
                 WHERE mailbox_id = p_scope_id
                   AND access_state <> 'active'
            ) THEN
                RAISE EXCEPTION 'emit_scope_revoked: mailbox-wide revocation requires suspended or detached mailbox'
                    USING ERRCODE = '42501';
            END IF;
        ELSE
            IF EXISTS (
                SELECT 1
                  FROM public.mailboxes
                 WHERE id = p_scope_id
                   AND user_id = p_user_id
                   AND enabled
            ) THEN
                RAISE EXCEPTION 'emit_scope_revoked: cannot revoke active mailbox owner'
                    USING ERRCODE = '42501';
            END IF;
            IF p_reason = 'calendar_share_revoked' THEN
                IF EXISTS (
                    SELECT 1
                      FROM public.calendars c
                      JOIN public.calendar_acls a ON a.calendar_id = c.id
                     WHERE c.mailbox_id = p_scope_id
                       AND a.user_id = p_user_id
                       AND a.permission <> 'freebusy'
                ) AND NOT (v_is_privileged OR v_is_mbx_owner_or_cal_admin) THEN
                    RAISE EXCEPTION 'emit_scope_revoked: target user still holds calendar share grant'
                        USING ERRCODE = '42501';
                END IF;
            ELSE
                IF EXISTS (
                    SELECT 1
                      FROM public.mailbox_delegates
                     WHERE mailbox_id = p_scope_id
                       AND user_id = p_user_id
                ) THEN
                    RAISE EXCEPTION 'emit_scope_revoked: target user still holds mailbox delegate grant'
                        USING ERRCODE = '42501';
                END IF;
            END IF;
        END IF;
    END IF;

    -- Rate-limit/deduplicate repeated non-privileged self-target emissions
    -- within 5 seconds so a user cannot spam scope_revocations / notify_intents.
    IF v_is_self_target THEN
        SELECT sr.id
          INTO v_existing_id
          FROM public.scope_revocations sr
         WHERE sr.user_id = p_user_id
           AND sr.scope_kind = p_scope_kind
           AND sr.scope_id = p_scope_id
           AND sr.reason = p_reason
           AND sr.subtree_anchor_id IS NOT DISTINCT FROM p_subtree_anchor_id
           AND sr.occurred_at >= now() - interval '5 seconds'
         ORDER BY sr.id DESC
         LIMIT 1;
        IF v_existing_id IS NOT NULL THEN
            RETURN v_existing_id;
        END IF;
    END IF;

    INSERT INTO public.scope_revocations (
        user_id, scope_kind, scope_id, subtree_anchor_id, reason
    )
    VALUES (
        p_user_id, p_scope_kind, p_scope_id, p_subtree_anchor_id, p_reason
    )
    RETURNING id INTO v_id;

    IF COALESCE(current_setting('app.capture_notify', TRUE), '') = 'on' THEN
        INSERT INTO public._test_notify_log (channel, payload, seq)
        VALUES ('scope_revoked', v_id::TEXT, nextval('public._test_notify_log_seq'));
    END IF;

    INSERT INTO public.notify_intents (channel, payload)
    VALUES ('scope_revoked', v_id::TEXT);

    RETURN v_id;
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
            'public.emit_scope_revoked(bigint,text,bigint,text,bigint)'::regprocedure
        );
        IF v_granted_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    ELSE
        REVOKE ALL ON FUNCTION public.emit_scope_revoked(bigint, text, bigint, text, bigint) FROM PUBLIC;
    END IF;
END $$;

-- Worker-only retention pruner for public.scope_revocations.
-- Clamps retention UP via effective_journal_retention_days(GREATEST(COALESCE(p_retention_days, 90), 90))
-- so tombstone retention is NEVER shorter than Drive's 90-day floor or any
-- configured offline window, and atomically advances public.sync_tombstone_floor
-- whenever expired rows are deleted.
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
