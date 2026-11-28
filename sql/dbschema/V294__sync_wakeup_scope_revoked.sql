-- V294__sync_wakeup_scope_revoked.sql — Wave 2.5 (#552): durable
-- public.scope_revocations journal, reserved 'scope_revoked' channel in
-- app_notify_enqueue_intent, authoritative emit_scope_revoked /
-- prune_scope_revocations reducers, O(1) scope-keyed sync wakeups (eliminating
-- O(members) notify_chat_state loops), and transactional revocation emitters.
--
-- Isolation posture (V290/V291 pattern):
--   * public.scope_revocations is ENABLE + FORCE ROW LEVEL SECURITY with ZERO
--     permissive policies (deny-all to setjoin_app).
--   * Ownership sits with setjoin_owner; PUBLIC and setjoin_app have zero table
--     or sequence privileges; setjoin_worker holds SELECT/INSERT/UPDATE/DELETE
--     (reasserted in scripts/provision-roles.sql).
--   * ZERO public.blobs columns and ZERO public.feature_toggles rows.

CREATE TABLE public.scope_revocations (
    id                BIGSERIAL PRIMARY KEY,
    occurred_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id           BIGINT NULL,
    scope_kind        TEXT NOT NULL
        CHECK (scope_kind IN ('mailbox', 'space', 'channel')),
    scope_id          BIGINT NOT NULL,
    subtree_anchor_id BIGINT NULL,
    reason            TEXT NOT NULL
        CHECK (octet_length(reason) <= 128)
);

CREATE INDEX scope_revocations_occurred_at_idx
    ON public.scope_revocations (occurred_at);

CREATE INDEX scope_revocations_user_id_id_idx
    ON public.scope_revocations (user_id, id);

COMMENT ON TABLE public.scope_revocations IS
  'Durable scope revocation journal (V294, #552) for live SyncWakeupHub '
  'detachment, ResyncRequired catch-up, and Wave 2.6 reconnect tombstones. '
  'FORCE RLS deny-all to setjoin_app; worker-readable only.';

ALTER TABLE public.scope_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scope_revocations FORCE ROW LEVEL SECURITY;

REVOKE ALL ON public.scope_revocations FROM PUBLIC;

DO $$
DECLARE
    v_seq TEXT;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
        ALTER TABLE public.scope_revocations OWNER TO setjoin_owner;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE ALL ON public.scope_revocations FROM setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        REVOKE ALL ON public.scope_revocations FROM setjoin_worker;
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.scope_revocations TO setjoin_worker;
    END IF;
    v_seq := pg_get_serial_sequence('public.scope_revocations', 'id');
    IF v_seq IS NOT NULL THEN
        EXECUTE format('REVOKE ALL ON SEQUENCE %s FROM PUBLIC', v_seq);
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
            EXECUTE format('REVOKE ALL ON SEQUENCE %s FROM setjoin_app', v_seq);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
            EXECUTE format('REVOKE ALL ON SEQUENCE %s FROM setjoin_worker', v_seq);
            EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %s TO setjoin_worker', v_seq);
        END IF;
    END IF;
END $$;

-- ── Upgrade-safe verbatim reducer definitions (canonical sources under
--    mailserver/sql/reducers/) so `upgrade.sh` -> `mailctl schema apply --yes`
--    installs every Wave 2.5 reducer atomically alongside V294 DDL while fresh
--    installs remain byte-identical under scripts/check-schema-determinism.sh.

-- [embedded verbatim from reducers/scope_revocations.sql]
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
        PERFORM public.apply_worker_ownership('public.emit_scope_revoked(bigint,text,bigint,text,bigint)'::regprocedure);
        IF v_granted_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    ELSE
        REVOKE ALL ON FUNCTION public.emit_scope_revoked(bigint,text,bigint,text,bigint) FROM PUBLIC;
    END IF;
END $$;

-- [embedded verbatim from reducers/scope_revocations.sql]
CREATE OR REPLACE FUNCTION prune_scope_revocations(
    p_retention_days INT DEFAULT 30
) RETURNS BIGINT
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_offline_days INT;
    v_retain_days  INT;
    v_deleted      BIGINT := 0;
BEGIN
    PERFORM public.work_queue_require_worker();

    SELECT COALESCE(MAX(max_offline_days), 30)
      INTO v_offline_days
      FROM public.offline_policies
     WHERE enabled;

    v_retain_days := GREATEST(COALESCE(p_retention_days, 30), COALESCE(v_offline_days, 30), 30);

    WITH del AS (
        DELETE FROM public.scope_revocations
         WHERE occurred_at < now() - make_interval(days => v_retain_days)
        RETURNING 1
    )
    SELECT count(*) INTO v_deleted FROM del;

    RETURN v_deleted;
END;
$$;

DO $$
BEGIN
    REVOKE ALL ON FUNCTION public.prune_scope_revocations(integer) FROM PUBLIC;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.prune_scope_revocations(integer) TO setjoin_worker;
    END IF;
END $$;

-- [embedded verbatim from reducers/app_notify.sql]
CREATE OR REPLACE FUNCTION app_notify_enqueue_intent(
  p_channel TEXT,
  p_payload TEXT
) RETURNS VOID
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_payload TEXT := COALESCE(p_payload, '');
BEGIN
  IF p_channel IS NULL OR octet_length(p_channel) = 0 OR octet_length(p_channel) > 63
     OR p_channel !~ '^[a-zA-Z0-9_.:-]+$' THEN
    RAISE EXCEPTION 'app_notify_enqueue_intent: invalid channel %', p_channel
      USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalid_notify_channel"}';
  END IF;
  IF p_channel = 'scope_revoked' THEN
    RAISE EXCEPTION 'app_notify_enqueue_intent: channel scope_revoked is reserved for emit_scope_revoked'
      USING ERRCODE = 'BZ040',
            HINT = '{"type":"reserved_notify_channel"}';
  END IF;
  IF octet_length(v_payload) > 7900 THEN
    RAISE EXCEPTION 'app_notify_enqueue_intent: payload exceeds 7900 bytes'
      USING ERRCODE = 'BZ040',
            HINT = '{"type":"notify_payload_too_large"}';
  END IF;

  INSERT INTO public.notify_intents (channel, payload)
  VALUES (p_channel, v_payload);
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
        ALTER FUNCTION public.app_notify_enqueue_intent(text, text) OWNER TO setjoin_worker;
        IF v_granted_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    END IF;
    REVOKE ALL ON FUNCTION public.app_notify_enqueue_intent(text, text) FROM PUBLIC;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        GRANT EXECUTE ON FUNCTION public.app_notify_enqueue_intent(text, text) TO setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.app_notify_enqueue_intent(text, text) TO setjoin_worker;
    END IF;
END $$;

-- [embedded verbatim from reducers/notify_chat_state.sql]
CREATE OR REPLACE FUNCTION notify_chat_state(
    p_channel_id bigint, p_event text,
    p_message_id bigint DEFAULT NULL, p_seq bigint DEFAULT NULL
) RETURNS void AS $$
DECLARE
    v_emit_seq bigint;
BEGIN
    IF p_channel_id IS NULL THEN
        RAISE EXCEPTION 'notify_chat_state requires a channel'
            USING ERRCODE='BZ160', HINT='{"type":"missing_channel"}';
    END IF;
    IF p_event = 'typing' AND p_seq IS NULL THEN
        PERFORM public.app_notify(
            'chat_ephemeral',
            jsonb_build_object(
                'event', p_event,
                'channelId', p_channel_id,
                'messageId', p_message_id,
                'seq', p_seq
            )::text
        );
        RETURN;
    END IF;
    v_emit_seq := CASE
        WHEN p_event IN (
            'message_created', 'message_sent', 'message_edited',
            'message_deleted', 'message_delivered'
        ) THEN COALESCE(p_seq, 0)
        ELSE 0
    END;
    PERFORM public.emit_wakeup_bell(
        'sync',
        'channel:' || p_channel_id || ':' || v_emit_seq
    );
END; $$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/notify_state_change.sql]
CREATE OR REPLACE FUNCTION notify_state_change(
  p_mailbox_id BIGINT,
  p_tag_id     BIGINT,
  p_message_id BIGINT DEFAULT NULL,
  p_op         TEXT   DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
  v_email_state BIGINT;
BEGIN
  IF p_mailbox_id IS NULL THEN
    RAISE EXCEPTION 'notify_state_change requires a mailbox'
      USING ERRCODE = 'BZ034',
            HINT = jsonb_build_object('type', 'missing_mailbox')::TEXT;
  END IF;

  v_email_state := bump_email_state(p_mailbox_id);

  -- Offline #3: id-bearing callers thread (message_id, op) → precise journal row
  -- in the SAME txn as the bump. NULL callers (transition_message_location et al.)
  -- fall to the ELSE and emit a resync sentinel so every state bump has a record.
  -- Task 4 upgrades these sites to precise rows.
  -- ponytail: resync on null-caller path forces BZ011 cannotCalculateChanges for
  -- any spanning delta until Task 4 threads message_id; conservative but correct.
  -- Guard on v_email_state IS NOT NULL: a foreign / non-existent mailbox_id yields
  -- NULL from bump_email_state → skip the append (no-op, not a crash).
  IF v_email_state IS NOT NULL THEN
    IF p_message_id IS NOT NULL AND p_op IS NOT NULL THEN
      PERFORM append_email_change(p_mailbox_id, v_email_state, p_message_id, p_op);
    ELSE
      PERFORM append_email_change(p_mailbox_id, v_email_state, NULL, 'resync');
    END IF;
  END IF;

  IF p_tag_id IS NOT NULL THEN
    PERFORM bump_tag_mailbox_state(p_mailbox_id);
  END IF;

  PERFORM app_notify(
    'tag:' || p_mailbox_id,
    json_build_object(
      'event',  'state_change',
      'tag_id', p_tag_id,
      'state',  v_email_state
    )::TEXT
  );
  PERFORM public.emit_wakeup_bell('sync', 'mailbox:' || p_mailbox_id || ':0:Email');

  RETURN v_email_state;
END;
$$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/jmap_email.sql]
CREATE OR REPLACE FUNCTION jmap_email_set_update(
  p_mailbox_id BIGINT,
  p_updates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_id           BIGINT;
  v_patch        JSONB;
  v_updated      JSONB    := '[]'::JSONB;
  v_notUpdated   JSONB    := '{}'::JSONB;
  v_old_state    BIGINT;
  v_new_state    BIGINT;
  v_folder_id    BIGINT;
  v_old_folder   BIGINT;
  v_is_read      BOOL;
  -- Patchable message fields before/after this message's patch, and whether
  -- anything (fields or labels) actually changed.
  v_fields_before JSONB;
  v_fields_after  JSONB;
  v_changed       BOOL;
  -- ponytail: collect successful ids → ONE bump + N journal rows + ONE push after loop.
  v_updated_ids  BIGINT[] := '{}'::BIGINT[];
BEGIN
  -- Capture oldState before the loop so the batch return is correct.
  SELECT jmap_email_state INTO v_old_state FROM mailboxes WHERE id = p_mailbox_id;
  v_new_state := v_old_state;  -- fallback if no messages are updated

  FOR v_id, v_patch IN SELECT * FROM jsonb_each(p_updates)
  LOOP
    BEGIN
      -- Verify message exists
      SELECT is_read,
             jsonb_build_array(is_read, is_flagged, is_answered, is_draft,
                               flag_due_at, flag_reminder_at, pinned_at)
      INTO v_is_read, v_fields_before
      FROM messages WHERE id = v_id AND mailbox_id = p_mailbox_id FOR UPDATE;
      v_changed := FALSE;

      IF NOT FOUND THEN
        v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound'));
        CONTINUE;
      END IF;
      SELECT tag_id INTO v_old_folder
      FROM message_tags
      WHERE message_id = v_id AND is_primary = TRUE
      LIMIT 1
      FOR UPDATE;

      -- Handle keywords update
      IF v_patch ? 'keywords' THEN
        DECLARE
          v_kw JSONB := v_patch->'keywords';
          v_new_read BOOL;
          v_old_read BOOL;
        BEGIN
          SELECT is_read INTO v_old_read
          FROM messages WHERE id = v_id;

          UPDATE messages SET
            is_read = COALESCE((v_kw->>'$seen')::BOOL, is_read),
            is_flagged = COALESCE((v_kw->>'$flagged')::BOOL, is_flagged),
            is_answered = COALESCE((v_kw->>'$answered')::BOOL, is_answered),
            is_draft = COALESCE((v_kw->>'$draft')::BOOL, is_draft),
            -- Clearing the follow-up flag clears its due/reminder instants so a
            -- stale flag_reminder_at never fires for an un-flagged message (A2).
            flag_due_at = CASE WHEN (v_kw->>'$flagged') = 'false' THEN NULL ELSE flag_due_at END,
            flag_reminder_at = CASE WHEN (v_kw->>'$flagged') = 'false' THEN NULL ELSE flag_reminder_at END
          WHERE id = v_id AND mailbox_id = p_mailbox_id
          RETURNING is_read INTO v_new_read;

          -- Adjust unread count on ALL tags for this message
          IF v_new_read IS DISTINCT FROM v_old_read THEN
            UPDATE tags SET
                unread_count = GREATEST(0, unread_count + CASE WHEN v_new_read THEN -1 ELSE 1 END),
                jmap_state   = jmap_state + 1
            WHERE id IN (
                SELECT tag_id FROM message_tags
                WHERE message_id = v_id
                  AND received_at = (SELECT received_at FROM messages WHERE id = v_id)
            );
          END IF;
        END;
      END IF;

      -- Handle follow-up flag fields (A2). Stored only; A6's scan fires them.
      IF v_patch ? 'flagDueAt' THEN
        UPDATE messages SET flag_due_at = NULLIF(v_patch->>'flagDueAt', '')::TIMESTAMPTZ
        WHERE id = v_id AND mailbox_id = p_mailbox_id;
      END IF;
      IF v_patch ? 'flagReminderAt' THEN
        UPDATE messages SET flag_reminder_at = NULLIF(v_patch->>'flagReminderAt', '')::TIMESTAMPTZ
        WHERE id = v_id AND mailbox_id = p_mailbox_id;
      END IF;

      -- Handle pinned toggle (true → NOW(), null/false → NULL)
      IF v_patch ? 'pinned' THEN
        UPDATE messages SET pinned_at = CASE WHEN (v_patch->>'pinned')::BOOL THEN NOW() ELSE NULL END
        WHERE id = v_id AND mailbox_id = p_mailbox_id;
      END IF;

      -- Handle mailboxIds (tag-based multi-label assignment)
      IF v_patch ? 'mailboxIds' THEN
        DECLARE
          v_new_primary BIGINT := v_old_folder;
          v_tag_id      BIGINT;
          v_msg_received_at TIMESTAMPTZ;
          v_want_tags   BIGINT[] := '{}'::BIGINT[];
        BEGIN
          SELECT received_at INTO v_msg_received_at FROM messages WHERE id = v_id FOR UPDATE;

          -- Validate every tag of the mailboxIds map; first one becomes primary
          FOR v_tag_id IN SELECT key::BIGINT FROM jsonb_each(v_patch->'mailboxIds')
          LOOP
            -- Verify tag belongs to p_mailbox_id's mailbox (R3: ownership check)
            PERFORM 1 FROM tags
            WHERE id = v_tag_id AND mailbox_id = p_mailbox_id;
            IF NOT FOUND THEN
              RAISE EXCEPTION 'Tag not found'
                USING ERRCODE = 'BZ002', HINT = '{"type":"forbidden","tag_id":"' || v_tag_id || '"}';
            END IF;

            IF v_new_primary IS NULL THEN
              v_new_primary := v_tag_id;
            END IF;
            v_want_tags := array_append(v_want_tags, v_tag_id);
          END LOOP;

          -- Re-label only when the requested (tag, primary) set differs from the
          -- current one; an identical set is a no-op (#219).
          IF EXISTS (
            WITH cur AS (
              SELECT mt.tag_id, mt.is_primary
              FROM message_tags mt
              JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
              WHERE mt.message_id = v_id AND mt.received_at = v_msg_received_at
                AND m.mailbox_id = p_mailbox_id
            ), want AS (
              SELECT t AS tag_id, t = v_new_primary AS is_primary
              FROM unnest(v_want_tags) AS t
            )
            (SELECT * FROM cur EXCEPT SELECT * FROM want)
            UNION ALL
            (SELECT * FROM want EXCEPT SELECT * FROM cur)
          ) THEN
            -- Remove all current tags (counters handled by trigger)
            DELETE FROM message_tags
            WHERE message_id = v_id AND received_at = v_msg_received_at
              AND EXISTS (SELECT 1 FROM messages m
                          WHERE m.id = v_id AND m.received_at = v_msg_received_at
                            AND m.mailbox_id = p_mailbox_id);

            FOREACH v_tag_id IN ARRAY v_want_tags
            LOOP
              INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
              VALUES (v_id, v_msg_received_at, v_tag_id, 'user',
                      v_tag_id = v_new_primary);
            END LOOP;

            -- Bump mailbox state
            PERFORM bump_tag_mailbox_state(p_mailbox_id);
            v_changed := TRUE;
          END IF;
        END;
      END IF;

      -- Collect id for the post-loop batch bump (one bump + N journal rows + one
      -- push) only if a field or label actually changed (#219: no-op, no effect).
      IF NOT v_changed THEN
        SELECT jsonb_build_array(is_read, is_flagged, is_answered, is_draft,
                                 flag_due_at, flag_reminder_at, pinned_at)
        INTO v_fields_after
        FROM messages WHERE id = v_id AND mailbox_id = p_mailbox_id;
        v_changed := v_fields_after IS DISTINCT FROM v_fields_before;
      END IF;
      IF v_changed THEN
        v_updated_ids := array_append(v_updated_ids, v_id);
      END IF;
      v_updated := v_updated || to_jsonb(v_id);
    EXCEPTION WHEN OTHERS THEN
      IF SQLSTATE = 'BZ002' THEN
        RAISE;  -- Re-raise security violations (tag ownership)
      END IF;
      v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'Update failed'));
    END;
  END LOOP;

  -- Batch-collapse (offline #3): ONE bump + N precise journal rows at that seq + ONE push.
  -- All N ids land at the same state_seq; jmap_email_changes pages by seq (never splits a group).
  IF array_length(v_updated_ids, 1) IS NOT NULL THEN
    v_new_state := bump_email_state(p_mailbox_id);
    FOREACH v_id IN ARRAY v_updated_ids LOOP
      PERFORM append_email_change(p_mailbox_id, v_new_state, v_id, 'updated');
    END LOOP;
    PERFORM app_notify('tag:' || p_mailbox_id, json_build_object(
      'event', 'state_change', 'tag_id', NULL, 'state', v_new_state)::TEXT);
    PERFORM public.emit_wakeup_bell('sync', 'mailbox:' || p_mailbox_id || ':0:Email');
  END IF;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'updated', v_updated,
    'notUpdated', v_notUpdated
  );
END;
$$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/jmap_email.sql]
CREATE OR REPLACE FUNCTION jmap_email_set_destroy(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[]
) RETURNS JSONB AS $$
DECLARE
  v_destroyed      JSONB    := '[]'::JSONB;
  v_notDestroyed   JSONB    := '{}'::JSONB;
  v_old_state      BIGINT;
  v_new_state      BIGINT;
  v_id             BIGINT;
  v_received_at    TIMESTAMPTZ;
  v_trash_id       BIGINT;
  -- ponytail: collect successful ids → ONE bump + N journal rows + ONE push after loop.
  v_destroyed_ids  BIGINT[] := '{}'::BIGINT[];
  v_primary_tag  BIGINT;
  v_size_bytes   BIGINT;
BEGIN
  SELECT id INTO v_trash_id FROM tags
  WHERE name = 'Trash' AND mailbox_id = p_mailbox_id;

  -- Capture oldState before any per-id bumps (mirrors jmap_email_set_update pattern).
  SELECT jmap_email_state INTO v_old_state FROM mailboxes WHERE id = p_mailbox_id;
  v_new_state := v_old_state;

  FOREACH v_id IN ARRAY p_ids
  LOOP
    BEGIN
      -- Verify message exists and get metadata
      SELECT received_at, size_bytes INTO v_received_at, v_size_bytes
      FROM messages
      WHERE id = v_id AND mailbox_id = p_mailbox_id AND NOT is_deleted;

      IF NOT FOUND THEN
        v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound'));
        CONTINUE;
      END IF;

      -- Find current primary (location) tag
      SELECT tag_id INTO v_primary_tag
      FROM message_tags
      WHERE message_id = v_id AND received_at = v_received_at AND is_primary = TRUE
      LIMIT 1;

      IF v_trash_id IS NOT NULL AND v_primary_tag IS DISTINCT FROM v_trash_id THEN
        -- Move to Trash through the single location seam. p_notify=FALSE: the
        -- per-id notify_state_change below owns the single bump + push per id.
        PERFORM transition_message_location(v_id, v_received_at, 'Trash', p_mailbox_id, 'user', FALSE);
      ELSE
        -- Already in Trash (or no Trash tag exists) → soft-delete
        DELETE FROM message_tags
        WHERE message_id = v_id AND received_at = v_received_at;

        UPDATE messages SET is_deleted = TRUE, deleted_at = NOW()
        WHERE id = v_id AND received_at = v_received_at
          AND mailbox_id = p_mailbox_id;

        -- Adjust quota: soft-deleted messages don't count
        UPDATE mailboxes SET used_bytes = GREATEST(0, used_bytes - v_size_bytes)
        WHERE id = p_mailbox_id;
      END IF;

      -- Collect id for the post-loop batch bump.
      v_destroyed_ids := array_append(v_destroyed_ids, v_id);
      v_destroyed := v_destroyed || to_jsonb(v_id::TEXT);
    EXCEPTION WHEN OTHERS THEN
      v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'Destroy failed'));
    END;
  END LOOP;

  -- Batch-collapse (offline #3): ONE bump + N precise journal rows at that seq + ONE push.
  IF array_length(v_destroyed_ids, 1) IS NOT NULL THEN
    v_new_state := bump_email_state(p_mailbox_id);
    FOREACH v_id IN ARRAY v_destroyed_ids LOOP
      PERFORM append_email_change(p_mailbox_id, v_new_state, v_id, 'destroyed');
    END LOOP;
    PERFORM app_notify('tag:' || p_mailbox_id, json_build_object(
      'event', 'state_change', 'tag_id', NULL, 'state', v_new_state)::TEXT);
    PERFORM public.emit_wakeup_bell('sync', 'mailbox:' || p_mailbox_id || ':0:Email');
  END IF;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'destroyed', v_destroyed,
    'notDestroyed', v_notDestroyed
  );
END;
$$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/notify_calendar_state.sql]
CREATE OR REPLACE FUNCTION notify_calendar_state(
  p_owner_mailbox_id BIGINT,
  p_event_id         BIGINT,
  p_calendar_id      BIGINT,
  p_event            TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_state BIGINT;
BEGIN
  IF p_owner_mailbox_id IS NULL THEN
    RAISE EXCEPTION 'notify_calendar_state requires an owner mailbox'
      USING ERRCODE = 'BZ034',
            HINT = jsonb_build_object('type', 'missing_mailbox')::TEXT;
  END IF;

  UPDATE calendars SET jmap_state = jmap_state + 1, updated_at = now()
  WHERE id = p_calendar_id AND mailbox_id = p_owner_mailbox_id
  RETURNING jmap_state INTO v_state;

  PERFORM app_notify(
    'calendar:' || p_owner_mailbox_id,
    jsonb_build_object(
      'event',       p_event,
      'event_id',    p_event_id,
      'calendar_id', p_calendar_id
    )::TEXT
  );
  PERFORM public.emit_wakeup_bell('sync', 'mailbox:' || p_owner_mailbox_id || ':0:Calendar');

  RETURN v_state;
END;
$$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/notify_contact_state.sql]
CREATE OR REPLACE FUNCTION notify_contact_state(
  p_mailbox_id BIGINT,
  p_event      TEXT,
  p_contact_id BIGINT DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
  v_state BIGINT;
BEGIN
  IF p_mailbox_id IS NULL THEN
    RAISE EXCEPTION 'notify_contact_state requires a mailbox'
      USING ERRCODE = 'BZ034',
            HINT = jsonb_build_object('type', 'missing_mailbox')::TEXT;
  END IF;

  UPDATE addressbooks SET jmap_state = jmap_state + 1
  WHERE mailbox_id = p_mailbox_id;

  SELECT COALESCE(MAX(jmap_state), 0) INTO v_state
  FROM addressbooks WHERE mailbox_id = p_mailbox_id;

  PERFORM app_notify(
    'contact:' || p_mailbox_id,
    jsonb_build_object(
      'event',      p_event,
      'contact_id', p_contact_id
    )::TEXT
  );
  PERFORM public.emit_wakeup_bell('sync', 'mailbox:' || p_mailbox_id || ':0:Contact');

  RETURN v_state;
END;
$$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/notify_task_state.sql]
CREATE OR REPLACE FUNCTION notify_task_state(
  p_mailbox_id BIGINT,
  p_event      TEXT,
  p_task_id    BIGINT DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
  v_state BIGINT;
BEGIN
  IF p_mailbox_id IS NULL THEN
    RAISE EXCEPTION 'notify_task_state requires a mailbox'
      USING ERRCODE = 'BZ034',
            HINT = jsonb_build_object('type', 'missing_mailbox')::TEXT;
  END IF;

  SELECT COALESCE(MAX(jmap_state), 0) INTO v_state
  FROM tasks WHERE mailbox_id = p_mailbox_id;

  PERFORM app_notify(
    'task:' || p_mailbox_id,
    jsonb_build_object(
      'event',   p_event,
      'task_id', p_task_id
    )::TEXT
  );
  PERFORM public.emit_wakeup_bell('sync', 'mailbox:' || p_mailbox_id || ':0:Task');

  RETURN v_state;
END;
$$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/reminders_actions.sql]
CREATE OR REPLACE FUNCTION bump_reminder_state(
    p_mailbox_id BIGINT,
    p_event      TEXT  DEFAULT 'reminder_changed',
    p_detail     JSONB DEFAULT '{}'::JSONB
) RETURNS BIGINT AS $$
DECLARE
    v_state BIGINT;
BEGIN
    UPDATE mailboxes SET jmap_reminder_state = jmap_reminder_state + 1
    WHERE id = p_mailbox_id
    RETURNING jmap_reminder_state INTO v_state;

    PERFORM app_notify(
        'tag:' || p_mailbox_id,
        (COALESCE(p_detail, '{}'::JSONB)
           || jsonb_build_object('event', COALESCE(p_event, 'reminder_changed'),
                                 'state', v_state))::TEXT);
    PERFORM public.emit_wakeup_bell('sync', 'mailbox:' || p_mailbox_id || ':0:Reminder');
    RETURN v_state;
END;
$$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/drive_notify_change.sql]
CREATE OR REPLACE FUNCTION drive_notify_change(
  p_space_id BIGINT, p_node_id BIGINT, p_op TEXT
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_seq BIGINT;
BEGIN
  UPDATE drive_spaces SET change_seq = change_seq + 1
   WHERE id = p_space_id RETURNING change_seq INTO v_seq;
  IF v_seq IS NULL THEN
    RAISE EXCEPTION 'drive space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  INSERT INTO drive_changes (space_id, seq, node_id, op) VALUES (p_space_id, v_seq, p_node_id, p_op);
  PERFORM app_notify('drive', json_build_object('spaceId', p_space_id, 'seq', v_seq)::text);
  PERFORM public.emit_wakeup_bell('sync', 'space:' || p_space_id || ':' || v_seq);
  RETURN v_seq;
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
        PERFORM public.apply_worker_ownership('public.drive_notify_change(bigint,bigint,text)'::regprocedure);
        IF v_granted_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    ELSE
        REVOKE ALL ON FUNCTION public.drive_notify_change(bigint,bigint,text) FROM PUBLIC;
    END IF;
END $$;

-- [embedded verbatim from reducers/mailbox_delegate_revoke.sql]
CREATE OR REPLACE FUNCTION mailbox_delegate_revoke(
  p_actor_user_id   BIGINT,
  p_mailbox_id      BIGINT,
  p_grantee_user_id BIGINT
) RETURNS VOID AS $$
DECLARE
  v_removed JSONB;
BEGIN
  WITH removed AS (
    DELETE FROM mailbox_delegates md
    WHERE md.mailbox_id = p_mailbox_id
      AND md.user_id = p_grantee_user_id
      AND EXISTS (SELECT 1 FROM mailboxes
                   WHERE id = p_mailbox_id AND user_id = p_actor_user_id)
    RETURNING md.permission
  )
  SELECT jsonb_agg(permission) INTO v_removed FROM removed;

  IF v_removed IS NULL THEN
    IF NOT EXISTS (SELECT 1 FROM mailboxes
                    WHERE id = p_mailbox_id AND user_id = p_actor_user_id) THEN
      RAISE EXCEPTION 'Mailbox not found'
        USING ERRCODE = 'BZ114',
              HINT = jsonb_build_object('type','sharing_not_owner',
                                        'mailbox_id', p_mailbox_id)::TEXT;
    END IF;
    RETURN;  -- owner, nothing to revoke: idempotent
  END IF;

  -- D8: one immutable audit row per revoke, tier core.
  PERFORM audit_write(
    p_actor_user_id, 'mailbox_delegate_revoked', 'mailbox_delegate', p_mailbox_id,
    jsonb_build_object('mailbox_id', p_mailbox_id,
                       'grantee_user_id', p_grantee_user_id,
                       'permissions', v_removed),
    NULL,
    NULL, NULL, 'core');
  PERFORM public.emit_scope_revoked(
    p_grantee_user_id, 'mailbox', p_mailbox_id, 'delegate_revoked', NULL
  );
END;
$$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/calendar_sharing.sql]
CREATE OR REPLACE FUNCTION jmap_calendar_share_set(
  p_mailbox_id  BIGINT,
  p_calendar_id BIGINT,
  p_grants      JSONB DEFAULT '[]'::JSONB,
  p_revokes     JSONB DEFAULT '[]'::JSONB
) RETURNS JSONB AS $$
DECLARE
  v_owner_mbox BIGINT;
  v_owner_uid  BIGINT;
  v_caller_uid BIGINT;
  v_is_owner   BOOLEAN := FALSE;
  v_is_admin   BOOLEAN := FALSE;
  v_grant      JSONB;
  v_revoke     JSONB;
  v_target_uid BIGINT;
  v_level      TEXT;
  v_prev_level TEXT;
BEGIN
  SELECT mailbox_id INTO v_owner_mbox FROM calendars WHERE id = p_calendar_id;
  IF v_owner_mbox IS NULL THEN
    RAISE EXCEPTION 'Calendar not found'
      USING ERRCODE = 'BZ001', HINT = '{"type":"forbidden"}';
  END IF;

  -- Owner = the account's mailbox owns the calendar.
  v_is_owner := (v_owner_mbox = p_mailbox_id);

  -- Admin grantee: the caller's user holds an 'admin' grant on this calendar.
  -- Resolve the user behind the caller's mailbox via the one resolver seam
  -- (ADR-003), not a hand-join of `mailboxes`. NULL (shared mailbox) → no admin
  -- grant, identical to the prior hand-join.
  SELECT user_id INTO v_owner_uid FROM mailboxes WHERE id = v_owner_mbox;
  SELECT user_id INTO v_caller_uid FROM account_scope(p_mailbox_id);
  IF v_caller_uid IS NOT NULL THEN
    v_is_admin := EXISTS (
      SELECT 1 FROM calendar_acls
      WHERE calendar_id = p_calendar_id AND user_id = v_caller_uid AND permission = 'admin'
    );
  END IF;

  IF NOT (v_is_owner OR v_is_admin) THEN
    RAISE EXCEPTION 'Not authorized to manage shares on this calendar'
      USING ERRCODE = 'BZ001',
            HINT = '{"type":"forbidden","calendar_id":"' || p_calendar_id || '"}';
  END IF;

  -- Apply grants (upsert).
  IF jsonb_typeof(p_grants) = 'array' THEN
    FOR v_grant IN SELECT * FROM jsonb_array_elements(p_grants)
    LOOP
      v_level := v_grant->>'level';
      IF v_level NOT IN ('freebusy', 'read', 'write', 'admin') THEN
        CONTINUE;  -- ignore unknown levels (enum enforcement is also at the CHECK)
      END IF;
      -- Resolve the grantee address-aware (primary ∪ alias ∪ UPN) through the one
      -- seam (ADR-004) — a grantee addressed by an alias/UPN previously no-op'd.
      SELECT user_id INTO v_target_uid FROM resolve_identity(v_grant->>'userEmail');
      IF v_target_uid IS NULL THEN
        CONTINUE;
      END IF;
      SELECT permission INTO v_prev_level
        FROM calendar_acls
       WHERE calendar_id = p_calendar_id AND user_id = v_target_uid;
      INSERT INTO calendar_acls (calendar_id, user_id, permission)
      VALUES (p_calendar_id, v_target_uid, v_level)
      ON CONFLICT (calendar_id, user_id) DO UPDATE SET permission = EXCLUDED.permission;
      IF v_level = 'freebusy' AND v_prev_level IS NOT NULL AND v_prev_level <> 'freebusy'
         AND (v_owner_uid IS NULL OR v_target_uid <> v_owner_uid) THEN
        PERFORM public.emit_scope_revoked(
          v_target_uid, 'mailbox', v_owner_mbox, 'calendar_share_revoked', NULL
        );
      END IF;
    END LOOP;
  END IF;

  -- Apply revokes.
  IF jsonb_typeof(p_revokes) = 'array' THEN
    FOR v_revoke IN SELECT * FROM jsonb_array_elements(p_revokes)
    LOOP
      -- Revoke grantee resolved address-aware (primary ∪ alias ∪ UPN), one seam.
      SELECT user_id INTO v_target_uid FROM resolve_identity(v_revoke->>'userEmail');
      IF v_target_uid IS NOT NULL THEN
        DELETE FROM calendar_acls WHERE calendar_id = p_calendar_id AND user_id = v_target_uid;
        IF FOUND AND (v_owner_uid IS NULL OR v_target_uid <> v_owner_uid) THEN
          PERFORM public.emit_scope_revoked(
            v_target_uid, 'mailbox', v_owner_mbox, 'calendar_share_revoked', NULL
          );
        END IF;
      END IF;
    END LOOP;
  END IF;

  -- Reflect whether any grant remains on is_shared (the business UPDATE); the
  -- jmap_state bump + push route through the calendar seam (no event) below.
  UPDATE calendars
  SET is_shared = EXISTS (SELECT 1 FROM calendar_acls WHERE calendar_id = p_calendar_id),
      updated_at = now()
  WHERE id = p_calendar_id;

  -- Bump calendars.jmap_state (scoped to the owner mailbox) + push
  -- {event:'calendar_shared', calendar_id} on calendar:{owner_mailbox_id}.
  PERFORM notify_calendar_state(v_owner_mbox, NULL, p_calendar_id, 'calendar_shared');

  RETURN jsonb_build_object(
    'ok', TRUE,
    'calendarId', p_calendar_id::TEXT,
    'newState', (SELECT jmap_state FROM calendars WHERE id = p_calendar_id)::TEXT
  );
END;
$$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/drive_member_revoke.sql]
CREATE OR REPLACE FUNCTION drive_member_revoke(
  p_user_id BIGINT, p_space_id BIGINT, p_grantee BIGINT
) RETURNS VOID AS $$
DECLARE v_role TEXT; v_acl_mode text; v_bump record;
BEGIN
  SELECT acl_mode INTO v_acl_mode FROM public.drive_spaces WHERE id=p_space_id;
  IF NOT public.drive_user_has_space_access(p_user_id,p_space_id) THEN
    RAISE EXCEPTION 'space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  IF NOT public.drive_runtime_has_space_root_capability(
       p_user_id,p_space_id,'manage_acl') AND p_grantee <> p_user_id THEN
    RAISE EXCEPTION 'manager role required' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"manager role required to remove another member"}';
  END IF;
  IF p_grantee = drive_space_owner(p_space_id) THEN
    RAISE EXCEPTION 'the owner row cannot be revoked' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"the owner row cannot be revoked"}';
  END IF;
  PERFORM public.drive_tree_lock(p_space_id);
  IF NOT public.drive_user_has_space_access(p_user_id,p_space_id) THEN
    RAISE EXCEPTION 'space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  IF p_grantee<>p_user_id THEN
    PERFORM public.drive_require_space_root_mutation_capability(
      p_user_id,p_space_id,'manage_acl');
  ELSIF v_acl_mode='acl' THEN
    PERFORM 1 FROM public.drive_acl_generations
     WHERE space_id=p_space_id FOR SHARE;
  END IF;
  DELETE FROM drive_space_members WHERE space_id = p_space_id AND user_id = p_grantee;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'member not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"member not found"}';
  END IF;
  PERFORM drive_access_audit(p_user_id, p_space_id, 'member.revoke', 'member', p_grantee, NULL,
    jsonb_build_object('userId', p_grantee), NULL, NULL);
  IF v_acl_mode='acl' THEN
    SELECT * INTO v_bump FROM public.drive_acl_bump(
      p_space_id,'user',p_grantee,NULL,'member_revoke');
  END IF;
  IF NOT public.drive_user_has_space_access(p_grantee, p_space_id) THEN
    PERFORM public.emit_scope_revoked(p_grantee, 'space', p_space_id, 'member_revoked', NULL);
  END IF;
  PERFORM drive_notify_change(p_space_id, 0, 'member');
END;
$$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/drive_folder_member_revoke.sql]
CREATE OR REPLACE FUNCTION drive_folder_member_revoke(
  p_user_id BIGINT, p_space_id BIGINT, p_folder_node_id BIGINT, p_grantee BIGINT
) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_node_space BIGINT; v_role TEXT;
BEGIN
  IF EXISTS(SELECT 1 FROM public.drive_spaces s
             WHERE s.id=p_space_id AND s.acl_mode='acl') THEN
    PERFORM public.drive_acl_compat_folder_member_revoke(
      p_user_id,p_space_id,p_folder_node_id,p_grantee);
    RETURN;
  END IF;
  IF NOT drive_subtree_admin(p_user_id, p_folder_node_id) THEN
    RAISE EXCEPTION 'folder-admin rights required' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"folder-admin rights required on this folder or an ancestor"}';
  END IF;
  SELECT space_id INTO v_node_space FROM drive_nodes WHERE id = p_folder_node_id;
  IF v_node_space IS NULL OR v_node_space <> p_space_id THEN
    RAISE EXCEPTION 'invalid folder' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"folder must belong to this space"}';
  END IF;
  v_role := drive_member_role(p_space_id, p_grantee);
  IF v_role = 'manager' THEN
    RAISE EXCEPTION 'cannot modify a manager via folder delegation' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"a manager''s membership cannot be changed via folder delegation"}';
  END IF;

  DELETE FROM drive_space_members WHERE space_id = p_space_id AND user_id = p_grantee;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'member not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"member not found"}';
  END IF;

  PERFORM drive_access_audit(p_user_id, p_space_id, 'member.revoke', 'member', p_grantee, NULL,
    jsonb_build_object('userId', p_grantee), NULL, 'folder-admin');
  IF NOT public.drive_user_has_space_access(p_grantee, p_space_id) THEN
    PERFORM public.emit_scope_revoked(p_grantee, 'space', p_space_id, 'member_revoked', NULL);
  END IF;
  PERFORM drive_notify_change(p_space_id, 0, 'member');
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
        PERFORM public.apply_worker_ownership('public.drive_folder_member_revoke(bigint,bigint,bigint,bigint)'::regprocedure);
        IF v_granted_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    ELSE
        REVOKE ALL ON FUNCTION public.drive_folder_member_revoke(bigint,bigint,bigint,bigint) FROM PUBLIC;
    END IF;
END $$;

-- [embedded verbatim from reducers/chat_member_remove.sql]
CREATE OR REPLACE FUNCTION chat_member_remove(
    p_user_id bigint, p_channel_id bigint, p_remove_id bigint
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_role        text;
    v_kind        text;
    v_target_role text;
    v_new_owner   bigint;
    v_bound_space bigint;
BEGIN
    SELECT kind INTO v_kind FROM chat_channels WHERE id = p_channel_id;
    IF v_kind IN ('dm', 'group_dm') THEN
        RAISE EXCEPTION 'cannot remove members from a dm/group_dm'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments"}';
    END IF;
    -- Org-default membership is non-revocable BY THE MEMBER (A3 QoL Task 12,
    -- grill-decided): a self-leave on an org-default channel is rejected —
    -- the UI offers Mute instead. Without this, the idempotent
    -- chat_autojoin_defaults re-provision hook would silently undo a leave
    -- at the user's next AD/LDAP sync, a confusing boomerang. Exits: an
    -- admin unmarks the channel (chat_org_default_set), or admin-initiated
    -- removal (p_user_id <> p_remove_id) still works, e.g. offboarding.
    IF p_user_id = p_remove_id
       AND EXISTS (SELECT 1 FROM org_default_channels WHERE channel_id = p_channel_id) THEN
        RAISE EXCEPTION 'cannot leave an org-default channel'
            USING ERRCODE='BZ163', HINT='{"type":"forbidden","detail":"org-default channel membership is system-maintained; mute instead of leave"}';
    END IF;
    IF p_user_id <> p_remove_id THEN
        SELECT role INTO v_role FROM chat_channel_members
         WHERE channel_id = p_channel_id AND user_id = p_user_id;
        IF v_role IS NULL OR v_role NOT IN ('owner', 'admin') THEN
            RAISE EXCEPTION 'owner/admin required'
                USING ERRCODE='BZ161', HINT='{"type":"forbidden"}';
        END IF;
    END IF;

    SELECT role INTO v_target_role FROM chat_channel_members
     WHERE channel_id = p_channel_id AND user_id = p_remove_id;
    IF v_target_role IS NULL THEN
        RETURN;  -- idempotent: already not a member
    END IF;

    DELETE FROM chat_channel_members
     WHERE channel_id = p_channel_id AND user_id = p_remove_id;
    -- A4a Task 3: member.remove (someone else removed them) vs member.leave
    -- (a self-leave) — same predicate the BZ genre above already used.
    IF COALESCE((SELECT enabled FROM feature_toggles
                 WHERE key = 'feature.chat_compliance'), FALSE) THEN
        PERFORM chat_access_audit(p_user_id, p_channel_id,
          CASE WHEN p_user_id = p_remove_id THEN 'member.leave' ELSE 'member.remove' END,
          'member', p_remove_id, NULL, jsonb_build_object('userId', p_remove_id, 'role', v_target_role), NULL, NULL);
    END IF;

        -- WP3 audit coverage: member.leave vs member.remove, plus the
        -- owner-succession promotion below — chat authority transitions
        -- (core), in the same transaction as the membership delete.
        PERFORM audit_write(
            p_user_id, CASE WHEN p_user_id = p_remove_id
                            THEN 'chat_member_leave' ELSE 'chat_member_remove' END,
            'chat_channel', p_channel_id,
            jsonb_build_object('userId', p_remove_id, 'role', v_target_role),
            NULL,
            NULL, NULL, 'core');
    PERFORM public.emit_scope_revoked(
        p_remove_id,
        'channel',
        p_channel_id,
        CASE WHEN p_user_id = p_remove_id THEN 'member_left' ELSE 'member_removed' END,
        NULL
    );
    FOR v_bound_space IN
        SELECT s.id
          FROM public.drive_spaces s
         WHERE s.chat_channel_id = p_channel_id
    LOOP
        IF NOT public.drive_user_has_space_access(p_remove_id, v_bound_space) THEN
            PERFORM public.emit_scope_revoked(
                p_remove_id, 'space', v_bound_space, 'channel_member_removed', NULL
            );
        END IF;
    END LOOP;
    PERFORM notify_chat_state(p_channel_id, 'member_removed', NULL, NULL);

    -- Owner succession (grill Q7): a channel can never be orphaned. If the
    -- departing member was the LAST owner, auto-promote the longest-tenured
    -- admin, else the longest-tenured member, in the SAME txn — covers
    -- AD/LDAP deprovisioning removals where nobody can be prompted. Explicit
    -- transfer UI is A3. Notified LAST so it is the terminal event on the
    -- affected members' channels (member_removed, then owner_changed).
    IF v_target_role = 'owner' AND NOT EXISTS (
         SELECT 1 FROM chat_channel_members
          WHERE channel_id = p_channel_id AND role = 'owner') THEN
        SELECT user_id INTO v_new_owner FROM chat_channel_members
         WHERE channel_id = p_channel_id AND role = 'admin'
         ORDER BY joined_at ASC LIMIT 1;
        IF v_new_owner IS NULL THEN
            SELECT user_id INTO v_new_owner FROM chat_channel_members
             WHERE channel_id = p_channel_id
             ORDER BY joined_at ASC LIMIT 1;
        END IF;
        IF v_new_owner IS NOT NULL THEN
            UPDATE chat_channel_members SET role = 'owner'
             WHERE channel_id = p_channel_id AND user_id = v_new_owner;
            PERFORM notify_chat_state(p_channel_id, 'owner_changed', NULL, NULL);
            -- WP3 audit coverage: last-owner succession is chat authority —
            -- the promotion that keeps a channel un-orphaned is its own row.
            PERFORM audit_write(
                p_user_id, 'chat_owner_succession', 'chat_channel', p_channel_id,
                jsonb_build_object('userId', p_remove_id, 'role', 'owner'),
                jsonb_build_object('userId', v_new_owner, 'role', 'owner'),
                NULL, NULL, 'core');
        END IF;
    END IF;
END;
$$;

-- [embedded verbatim from reducers/meeting_control.sql]
CREATE OR REPLACE FUNCTION meeting_kick(
    p_user_id bigint, p_meeting_id bigint, p_identity text
) RETURNS text AS $$
DECLARE
    v_target_breakout bigint; v_current_room text; v_parent uuid;
    v_removed_channel bigint; v_removed_user bigint; v_removed_role text;
    v_kicked_user bigint; v_bound_space bigint;
BEGIN
    PERFORM meeting_require_authority(p_meeting_id, p_user_id);

    SELECT room_name INTO v_parent FROM meetings WHERE id = p_meeting_id;

    -- resolve the target's CURRENT (pre-move) room BEFORE the UPDATE below
    -- clears breakout_id — the meeting_breakout_assign COALESCE shape (F1:
    -- Go must evict from where the target actually is, main or a child).
    SELECT breakout_id INTO v_target_breakout
      FROM meeting_participants WHERE meeting_id = p_meeting_id AND identity = p_identity;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'participant % not found in meeting %', p_identity, p_meeting_id
            USING ERRCODE='BZ188', HINT='{"type":"invalidArguments","detail":"participant not found"}';
    END IF;
    SELECT COALESCE(
        (SELECT b.room_name::text FROM meeting_breakouts b
          WHERE b.id = v_target_breakout AND b.state = 'open'),
        v_parent::text) INTO v_current_room;

    -- banned_at is stamped for EVERY identity kind, member and guest alike: it is
    -- the single marker a kick leaves behind, and meeting_participant_event's
    -- participant_joined guard reads it to refuse resurrecting a kicked
    -- participant from a replayed (unordered) LiveKit webhook. Scoping it to u:
    -- left the guest half of that hole open — a kicked guest's revocation lived
    -- only in join_requests.state, which the webhook ingest does not consult.
    -- Every other banned_at consumer (meeting_join, the meeting_set_role and
    -- meeting_admit re-admit clears, meeting_lobby's member arm) is u:-scoped, so
    -- stamping guests here is inert everywhere except closing that hole.
    -- breakout_id is ALSO cleared here (B3): a kick is a full eviction, not a
    -- move — the target must land back at "main" bookkeeping-wise even
    -- though they never rejoin without re-admit.
    UPDATE meeting_participants
       SET left_at = now(),
           banned_at = now(),
           breakout_id = NULL
     WHERE meeting_id = p_meeting_id AND identity = p_identity;

    IF p_identity LIKE 'g:%' THEN
        UPDATE meeting_join_requests
           SET state = 'denied', decided_by = p_user_id, decided_at = now()
         WHERE meeting_id = p_meeting_id
           AND id = substring(p_identity FROM 3)::bigint
           AND state <> 'denied';
    END IF;

    -- D13: a kicked participant must not keep posting into the meeting's
    -- bridged chat/polls/Q&A. meeting_join re-inserts membership on re-admit
    -- + rejoin (meeting_join.sql's ON CONFLICT upsert).
    --
    -- V131-gated (pipeline-review confirmation fix): ONLY for a channel
    -- meeting_create provisioned FOR the meeting (chat_channel_provisioned).
    -- A huddle bound to a PRE-EXISTING channel/DM (provisioned=false) never
    -- reaches this DELETE — per V131's invariant, every member of a
    -- provisioned=false channel is a member who pre-dates the meeting, so
    -- clearing their membership on kick would strip legitimate access they
    -- held before the meeting ever existed, permanently (the re-INSERT paths
    -- in meeting_join/meeting_admit are ALSO provisioned-gated, so nothing
    -- ever restores it). meeting_join's/meeting_admit's re-insert gate and
    -- this DELETE's gate must stay symmetric.
    IF p_identity LIKE 'u:%' THEN
        WITH removed AS (
            DELETE FROM chat_channel_members cm
             USING meetings m
             WHERE m.id = p_meeting_id AND m.chat_channel_id IS NOT NULL
               AND m.chat_channel_provisioned
               AND cm.channel_id = m.chat_channel_id
               AND cm.user_id = substring(p_identity FROM 3)::bigint
            RETURNING cm.channel_id, cm.user_id, cm.role
        )
        SELECT channel_id, user_id, role INTO v_removed_channel, v_removed_user, v_removed_role FROM removed;

        -- Audit-chain coverage (pipeline review fix): a kick removes chat
        -- membership straight from chat_channel_members (never routing
        -- through chat_member_remove), so it bypassed the A4a chain
        -- entirely. Mirror chat_member_remove's member.remove act shape —
        -- only when a row was actually removed (a kick on a channel the
        -- target was never a member of, or a huddle-bound channel they
        -- never joined per V131, writes nothing).
        IF v_removed_channel IS NOT NULL THEN
            PERFORM public.emit_scope_revoked(
                v_removed_user, 'channel', v_removed_channel, 'meeting_kicked', NULL
            );
        END IF;
        IF v_removed_channel IS NOT NULL
           AND COALESCE((SELECT enabled FROM feature_toggles
                         WHERE key = 'feature.chat_compliance'), FALSE) THEN
            PERFORM chat_access_audit(p_user_id, v_removed_channel, 'member.remove',
              'member', v_removed_user, NULL,
              jsonb_build_object('userId', v_removed_user, 'role', v_removed_role), NULL, NULL);
        END IF;
        v_kicked_user := substring(p_identity FROM 3)::bigint;
        FOR v_bound_space IN
            SELECT s.id
              FROM public.drive_spaces s
             WHERE s.meeting_id = p_meeting_id
                OR (v_removed_channel IS NOT NULL AND s.chat_channel_id = v_removed_channel)
        LOOP
            IF NOT public.drive_user_has_space_access(v_kicked_user, v_bound_space) THEN
                PERFORM public.emit_scope_revoked(
                    v_kicked_user, 'space', v_bound_space, 'meeting_kicked', NULL
                );
            END IF;
        END LOOP;
    END IF;

    PERFORM notify_meet_state(p_meeting_id, 'participant_kicked', jsonb_build_object('identity', p_identity));
    RETURN v_current_room;
END;
$$ LANGUAGE plpgsql;

-- [embedded verbatim from reducers/guest_account.sql]
CREATE OR REPLACE FUNCTION guest_set_status(
    p_admin_user_id bigint, p_guest_user_id bigint, p_action text,
    p_new_expires_at timestamptz DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_status         text;
    v_expires        timestamptz;
    v_new_status     text;
    v_channel_id     bigint;
    v_bound_space    bigint;
    v_prior_channels bigint[] := ARRAY[]::bigint[];
    v_prior_spaces   bigint[] := ARRAY[]::bigint[];
    v_revoke_reason  text;
    v_system_expire  boolean := p_admin_user_id IS NULL AND p_action = 'expire';
    v_transition_id  uuid;
    v_eviction_count integer := 0;
    v_revocation_id  bigint;
    v_invite_id      bigint;
    v_federated_identity boolean;
BEGIN
    -- Universal authority lock order: advisory fence before guest/user rows.
    -- The users.enabled trigger takes the same fence reentrantly.
    PERFORM admin_authority_fence();

    IF p_action NOT IN ('disable','enable','expire','extend','reinvite') THEN
        RAISE EXCEPTION 'guest_set_status: invalid action %', p_action
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"action must be disable|enable|expire|extend|reinvite"}';
    END IF;

    -- G5 system expiry is the one actor-less entrance. It is narrowed again
    -- after the target row lock to active+already-due; NULL can never perform
    -- disable/enable/extend or an early expiry.
    IF p_admin_user_id IS NULL AND NOT v_system_expire THEN
        RAISE EXCEPTION 'guests.manage required' USING ERRCODE='BZ002',
            HINT='{"type":"forbidden","detail":"guests.manage required"}';
    END IF;
    IF NOT v_system_expire
       AND NOT guest_admin_has_live_permission(p_admin_user_id, 'guests.manage') THEN
        RAISE EXCEPTION 'guests.manage required' USING ERRCODE='BZ002',
            HINT='{"type":"forbidden","detail":"guests.manage required"}';
    END IF;

    SELECT g.status, g.expires_at,
           (u.sync_source = 'sso'
            OR u.oidc_subject IS NOT NULL OR u.oidc_issuer IS NOT NULL
            OR u.saml_name_id IS NOT NULL OR u.saml_idp_entity_id IS NOT NULL)
      INTO v_status, v_expires, v_federated_identity
     FROM guest_accounts g
     JOIN users u ON u.id = g.user_id
     WHERE g.user_id = p_guest_user_id
       AND (v_system_expire OR guest_admin_can_reach_with_permission(
           p_admin_user_id, g.user_id, 'guests.manage'))
     FOR UPDATE OF g, u;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'guest account % not found', p_guest_user_id
            USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;
    IF v_system_expire AND (
        v_status <> 'active' OR v_expires IS NULL OR v_expires > clock_timestamp()
    ) THEN
        RAISE EXCEPTION 'guest_set_status: system expiry requires an active due guest'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"system expiry requires an active guest whose expiry is due"}';
    END IF;

    CASE p_action
    WHEN 'disable' THEN
        v_new_status := 'disabled';
        -- A disabled invited principal must not retain a usable credential.
        -- Stamp already-elapsed links truthfully at their effective expiry,
        -- then revoke the one remaining live invite under the guest/user lock.
        UPDATE guest_invites
           SET used_at = expires_at,
               terminal_reason = 'expired'
         WHERE guest_user_id = p_guest_user_id
           AND used_at IS NULL
           AND expires_at <= clock_timestamp()
           AND guest_admin_can_reach_with_permission(
               p_admin_user_id, p_guest_user_id, 'guests.manage');

        UPDATE guest_invites
           SET used_at = now(),
               terminal_reason = 'revoked'
         WHERE guest_user_id = p_guest_user_id
           AND used_at IS NULL
           AND expires_at > clock_timestamp()
           AND guest_admin_can_reach_with_permission(
               p_admin_user_id, p_guest_user_id, 'guests.manage')
         RETURNING id INTO v_invite_id;
        IF v_invite_id IS NOT NULL THEN
            PERFORM audit_write(
                p_admin_user_id, 'guest.invite_revoke', 'guest_invite',
                v_invite_id, NULL,
                jsonb_build_object(
                    'terminalReason', 'revoked',
                    'guestUserId', p_guest_user_id::text,
                    'reason', 'guest.disable'
                ), NULL, 'pending guest invite revoked by lifecycle disable', 'core'
            );
        END IF;
        -- P9 DISABLE = clean slate, via the EXISTING removal shape — per
        -- affected channel: delete row + (compliance audit when the toggle is
        -- ON) + notify_chat_state('member_removed'), copied from
        -- chat_member_remove (chat_channel.sql:388–400). Open-coded rather
        -- than calling chat_member_remove because that reducer refuses
        -- dm/group_dm kinds (BZ162) and a guest CAN hold DM memberships (P8).
        -- No separate change_seq bump: the existing member-remove path bumps
        -- none either (notify carries seq NULL for membership events).
        -- Drive derivation arm 2 dies with the channel membership it derives
        -- from. Authenticated Meet admissions and participants are separate
        -- future-grant rails (meeting_guest_join_allowed + Drive arm 3), so
        -- disable invalidates their authority while retaining the rows as
        -- history. G5 still owes live SFU eviction: this transaction prevents
        -- every future DB grant but cannot eject an already-connected client.
        -- ponytail: no owner-succession copy — a guest cannot create channels
        -- (BZ215), so it can only own one via an explicit role promotion; if
        -- G1 opens that path it owes the succession arm here.
        -- Snapshot ALL channels and Drive spaces (direct, chat-bound, meeting-
        -- bound, and ACL-granted) BEFORE mutations so disable emits revocations
        -- for every scope whose access is being terminated.
        SELECT COALESCE(array_agg(DISTINCT cm.channel_id ORDER BY cm.channel_id), ARRAY[]::bigint[])
          INTO v_prior_channels
          FROM chat_channel_members cm
         WHERE cm.user_id = p_guest_user_id;

        SELECT COALESCE(array_agg(DISTINCT s_id ORDER BY s_id), ARRAY[]::bigint[])
          INTO v_prior_spaces
          FROM (
            SELECT dsm.space_id AS s_id
              FROM drive_space_members dsm
             WHERE dsm.user_id = p_guest_user_id
            UNION
            SELECT s.id AS s_id
              FROM drive_spaces s
             WHERE s.owner_user_id = p_guest_user_id
            UNION
            SELECT s.id AS s_id
              FROM drive_spaces s
              JOIN chat_channel_members cm ON cm.channel_id = s.chat_channel_id
             WHERE cm.user_id = p_guest_user_id
            UNION
            SELECT s.id AS s_id
              FROM drive_spaces s
              JOIN meeting_participants mp ON mp.meeting_id = s.meeting_id
             WHERE mp.user_id = p_guest_user_id
            UNION
            SELECT g.space_id AS s_id
              FROM drive_acl_grants g
             WHERE g.subject_kind = 'user'
               AND g.subject_user_id = p_guest_user_id
               AND g.revoked_at IS NULL
          ) all_spaces;

        FOR v_channel_id IN
            SELECT channel_id FROM chat_channel_members
             WHERE user_id = p_guest_user_id
             ORDER BY channel_id
        LOOP
            DELETE FROM chat_channel_members
             WHERE channel_id = v_channel_id AND user_id = p_guest_user_id;
            IF FOUND THEN
                IF COALESCE((SELECT enabled FROM feature_toggles
                             WHERE key = 'feature.chat_compliance'), FALSE) THEN
                    PERFORM chat_access_audit(p_admin_user_id, v_channel_id, 'member.remove',
                        'member', p_guest_user_id, NULL,
                        jsonb_build_object('userId', p_guest_user_id, 'reason', 'guest.disable'),
                        NULL, NULL);
                END IF;
                PERFORM notify_chat_state(v_channel_id, 'member_removed', NULL, NULL);
            END IF;
        END LOOP;

    WHEN 'expire' THEN
        IF v_status <> 'active' THEN
            RAISE EXCEPTION 'guest_set_status: expire requires active status'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"expire is only valid for an active guest"}';
        END IF;
        -- Snapshot ALL channels and Drive spaces before freezing so expire
        -- emits durable scope_revocations for every active guest scope.
        SELECT COALESCE(array_agg(DISTINCT cm.channel_id ORDER BY cm.channel_id), ARRAY[]::bigint[])
          INTO v_prior_channels
          FROM chat_channel_members cm
         WHERE cm.user_id = p_guest_user_id;

        SELECT COALESCE(array_agg(DISTINCT s_id ORDER BY s_id), ARRAY[]::bigint[])
          INTO v_prior_spaces
          FROM (
            SELECT dsm.space_id AS s_id
              FROM drive_space_members dsm
             WHERE dsm.user_id = p_guest_user_id
            UNION
            SELECT s.id AS s_id
              FROM drive_spaces s
             WHERE s.owner_user_id = p_guest_user_id
            UNION
            SELECT s.id AS s_id
              FROM drive_spaces s
              JOIN chat_channel_members cm ON cm.channel_id = s.chat_channel_id
             WHERE cm.user_id = p_guest_user_id
            UNION
            SELECT s.id AS s_id
              FROM drive_spaces s
              JOIN meeting_participants mp ON mp.meeting_id = s.meeting_id
             WHERE mp.user_id = p_guest_user_id
            UNION
            SELECT g.space_id AS s_id
              FROM drive_acl_grants g
             WHERE g.subject_kind = 'user'
               AND g.subject_user_id = p_guest_user_id
               AND g.revoked_at IS NULL
          ) all_spaces;
        v_new_status := 'expired';  -- P9 EXPIRY = freeze: grant rows kept
    WHEN 'enable' THEN
        IF v_status <> 'disabled' THEN
            RAISE EXCEPTION 'guest_set_status: enable requires disabled status'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"enable is only valid for a disabled guest; invited guests must accept their invitation and expired guests must be extended"}';
        END IF;
        IF v_expires IS NOT NULL AND v_expires <= clock_timestamp() THEN
            RAISE EXCEPTION 'guest_set_status: enable requires a future expiry'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"extend the guest to a future expiry before enabling"}';
        END IF;
        v_new_status := 'active';
    WHEN 'extend' THEN
        IF v_status NOT IN ('active','disabled','expired') THEN
            RAISE EXCEPTION 'guest_set_status: extend requires active, disabled, or expired status'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"extend is valid for active, disabled, or expired guests; invited guests must accept their invitation"}';
        END IF;
        IF p_new_expires_at IS NULL OR p_new_expires_at <= clock_timestamp() THEN
            RAISE EXCEPTION 'guest_set_status: extend requires a future p_new_expires_at'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"extend requires a future expiry"}';
        END IF;
        v_new_status := 'active';
    WHEN 'reinvite' THEN
        -- Recovery preserves the identity and whatever grants the prior
        -- lifecycle state intentionally retained. A disabled guest therefore
        -- stays clean-slate; an expired/active guest's grants stay frozen while
        -- status=invited. A due expiry must be replaced atomically so invite
        -- acceptance cannot produce an active-but-still-expired account.
        IF v_federated_identity THEN
            RAISE EXCEPTION 'guest_set_status: federated guest recovery requires identity policy'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"federated guest recovery cannot mint a local password fallback"}';
        END IF;
        IF p_new_expires_at IS NOT NULL AND p_new_expires_at <= clock_timestamp() THEN
            RAISE EXCEPTION 'guest_set_status: re-invite expiry must be in the future'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"re-invite expiry must be in the future"}';
        END IF;
        IF v_expires IS NOT NULL AND v_expires <= clock_timestamp()
           AND p_new_expires_at IS NULL THEN
            RAISE EXCEPTION 'guest_set_status: expired recovery requires a future expiry'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"expired guest recovery requires a future expiry"}';
        END IF;
        v_new_status := 'invited';
    END CASE;

    UPDATE guest_accounts g
       SET status     = v_new_status,
           expires_at = CASE
               WHEN p_action = 'extend' THEN p_new_expires_at
               WHEN p_action = 'reinvite' AND p_new_expires_at IS NOT NULL THEN p_new_expires_at
               ELSE expires_at
           END,
           updated_at = now()
     WHERE g.user_id = p_guest_user_id
       AND (v_system_expire OR guest_admin_can_reach_with_permission(
           p_admin_user_id, g.user_id, 'guests.manage'));
    IF NOT FOUND THEN
        RAISE EXCEPTION 'guest account % not found', p_guest_user_id
            USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;

    -- C-7 atomicity: users.enabled + refresh-family death in the SAME txn.
    -- 47edc4ff made RefreshTokens honor users.enabled, but the guest story
    -- deliberately does not lean on that alone — the revocation is explicit.
    UPDATE users SET enabled = (v_new_status = 'active'), updated_at = now()
     WHERE id = p_guest_user_id
       AND (v_system_expire OR guest_admin_can_reach_with_permission(
               p_admin_user_id, p_guest_user_id, 'guests.manage'));
    IF NOT FOUND THEN
        RAISE EXCEPTION 'guest account % not found', p_guest_user_id
            USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;
    IF p_action IN ('disable','expire','reinvite') THEN
        UPDATE oauth_tokens SET revoked_at = now()
         WHERE user_id = p_guest_user_id AND revoked_at IS NULL
           AND (v_system_expire OR guest_admin_can_reach_with_permission(
                   p_admin_user_id, p_guest_user_id, 'guests.manage'));

        -- G5 live-containment evidence. Snapshot EVERY room belonging to each
        -- non-ended meeting the guest has participated in, not only the room
        -- whose participant row is currently open. A recently-left client can
        -- reconnect with its still-valid token, and a participant moved across
        -- breakouts can retain a token for an earlier room. LiveKit auto-create
        -- is OFF, so ended meetings need no retry; ongoing parent + all child
        -- rooms are the complete stale-token set. Disable closes participant
        -- rows only after this snapshot. Expiry keeps grants frozen but still
        -- ejects the peripheral sessions.
        v_transition_id := gen_random_uuid();
        INSERT INTO guest_live_eviction_intents
            (transition_id, guest_user_id, action, room_name, identity)
        SELECT v_transition_id, p_guest_user_id, p_action, targets.room_name, targets.identity
          FROM (
            SELECT m.id AS meeting_id, m.room_name, p.identity
              FROM meeting_participants p
              JOIN meetings m ON m.id = p.meeting_id
             WHERE p.user_id = p_guest_user_id AND m.state <> 'ended'
            UNION
            SELECT m.id AS meeting_id, b.room_name, p.identity
              FROM meeting_participants p
              JOIN meetings m ON m.id = p.meeting_id
              JOIN meeting_breakouts b ON b.meeting_id = m.id
             WHERE p.user_id = p_guest_user_id AND m.state <> 'ended'
          ) targets
         ORDER BY targets.meeting_id, targets.room_name, targets.identity
        ON CONFLICT (transition_id, room_name, identity) DO NOTHING;
        GET DIAGNOSTICS v_eviction_count = ROW_COUNT;

        -- Existing durable denylist + app_notify rail closes WebSocket and
        -- EventSource sessions and blocks subsequent HTTP use. NULL creator is
        -- the explicit system-expiry actor; both audit tables accept it.
        v_revocation_id := revoke_user_sessions(
            p_guest_user_id, 'all', 'guest.' || p_action,
            p_admin_user_id, NULL, NULL);

        IF p_action = 'disable' THEN
            UPDATE meeting_join_requests
               SET state = 'expired',
                   decided_at = COALESCE(decided_at, now())
             WHERE user_id = p_guest_user_id
               AND state IN ('pending', 'admitted');

            UPDATE meeting_participants
               SET left_at = COALESCE(left_at, now()),
                   banned_at = COALESCE(banned_at, now())
             WHERE user_id = p_guest_user_id;
        END IF;

        -- Wave 2.5 (#552): now that guest_accounts.status and users.enabled are
        -- committed in this tx (and participant rows are closed on disable),
        -- emit durable scope_revocations for EVERY prior channel and Drive
        -- space (direct, chat-bound, meeting-bound, and ACL-granted).
        IF p_action IN ('disable', 'expire') THEN
            v_revoke_reason := CASE WHEN p_action = 'disable' THEN 'guest_disabled' ELSE 'guest_expired' END;
            FOREACH v_channel_id IN ARRAY v_prior_channels
            LOOP
                PERFORM public.emit_scope_revoked(
                    p_guest_user_id, 'channel', v_channel_id, v_revoke_reason, NULL
                );
            END LOOP;
            FOREACH v_bound_space IN ARRAY v_prior_spaces
            LOOP
                IF NOT public.drive_user_has_space_access(p_guest_user_id, v_bound_space) THEN
                    PERFORM public.emit_scope_revoked(
                        p_guest_user_id, 'space', v_bound_space, v_revoke_reason, NULL
                    );
                END IF;
            END LOOP;
        END IF;
    END IF;

    PERFORM audit_write(p_admin_user_id, 'guest.' || p_action, 'user', p_guest_user_id,
        jsonb_build_object('status', v_status, 'expiresAt', v_expires),
        jsonb_build_object('status', v_new_status,
                           'expiresAt', CASE
                               WHEN p_action = 'extend' THEN p_new_expires_at
                               WHEN p_action = 'reinvite' AND p_new_expires_at IS NOT NULL THEN p_new_expires_at
                               ELSE v_expires
                           END,
                           'liveEvictionTargets', v_eviction_count,
                           'sessionRevocationId', v_revocation_id,
                           'system', v_system_expire),
        NULL, NULL, 'core');
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
        PERFORM public.apply_worker_ownership('public.guest_set_status(bigint,bigint,text,timestamptz)'::regprocedure);
        IF v_granted_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    ELSE
        REVOKE ALL ON FUNCTION public.guest_set_status(bigint,bigint,text,timestamptz) FROM PUBLIC;
    END IF;
END $$;

-- [embedded verbatim from reducers/mailbox_lifecycle_transition.sql]
CREATE OR REPLACE FUNCTION mailbox_lifecycle_transition(
  p_actor bigint,p_mailbox_id bigint,p_operation_id uuid,p_action text,
  p_expected_generation bigint,p_request_digest text,p_reason text,
  p_target_user_id bigint DEFAULT NULL,p_evidence_kind text DEFAULT NULL,
  p_identity_link_id bigint DEFAULT NULL,p_link_generation bigint DEFAULT NULL,
  p_source_key_digest text DEFAULT NULL,p_actor_auth_time timestamptz DEFAULT NULL,
  p_delivery_state text DEFAULT NULL,p_redirect_address text DEFAULT NULL
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_l mailbox_lifecycle%ROWTYPE; v_m mailboxes%ROWTYPE; v_existing mailbox_lifecycle_operations%ROWTYPE;
  v_before jsonb; v_after jsonb; v_before_digest text; v_after_digest text; v_result jsonb;
  v_policy mailbox_lifecycle_policies%ROWTYPE; v_old_user bigint; v_event text;
BEGIN
  IF NOT mailbox_lifecycle_enabled() THEN RAISE EXCEPTION 'mailbox lifecycle is disabled' USING ERRCODE='BZ300'; END IF;
  IF p_operation_id IS NULL OR p_expected_generation<1 OR p_request_digest !~ '^[0-9a-f]{64}$'
     OR p_action NOT IN ('suspend','resume','detach_retain','reconnect')
     OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 1 AND 1024 OR p_reason~'[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid mailbox lifecycle command' USING ERRCODE='BZ301';
  END IF;
  SELECT * INTO v_existing FROM mailbox_lifecycle_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.mailbox_id=p_mailbox_id AND v_existing.action=p_action
       AND v_existing.expected_generation=p_expected_generation AND v_existing.request_digest=p_request_digest THEN
      RETURN v_existing.result||'{"replayed":true}'::jsonb;
    END IF;
    RAISE EXCEPTION 'mailbox lifecycle idempotency conflict' USING ERRCODE='BZ303';
  END IF;
  SELECT * INTO v_l FROM mailbox_lifecycle WHERE mailbox_id=p_mailbox_id FOR UPDATE;
  SELECT * INTO v_m FROM mailboxes WHERE id=p_mailbox_id FOR UPDATE;
  IF NOT FOUND OR v_l.mailbox_id IS NULL OR v_m.type<>'personal' OR v_l.binding_state='shared' THEN
    RAISE EXCEPTION 'personal mailbox not found' USING ERRCODE='BZ302';
  END IF;
  IF v_l.generation<>p_expected_generation THEN RAISE EXCEPTION 'mailbox lifecycle generation is stale' USING ERRCODE='BZ304'; END IF;
  IF v_m.user_id IS NOT NULL
     AND NOT admin_can_manage_with_permission(p_actor,v_m.user_id,'users.delete') THEN
    RAISE EXCEPTION 'personal mailbox not found' USING ERRCODE='BZ302';
  END IF;
  v_before:=to_jsonb(v_l); v_before_digest:=encode(digest(v_before::text,'sha256'),'hex'); v_old_user:=v_m.user_id;

  IF p_action='suspend' THEN
    IF v_l.binding_state<>'bound' THEN RAISE EXCEPTION 'only bound mailboxes can be suspended' USING ERRCODE='BZ305'; END IF;
    UPDATE mailbox_lifecycle SET access_state='suspended',generation=generation+1,reason=p_reason,
      updated_by=p_actor,updated_at=statement_timestamp(),last_operation_id=p_operation_id WHERE mailbox_id=p_mailbox_id RETURNING * INTO v_l;
    UPDATE mailboxes SET enabled=false,updated_at=statement_timestamp() WHERE id=p_mailbox_id;
    v_event:='mailbox.suspended';
  ELSIF p_action='resume' THEN
    IF v_l.binding_state<>'bound' THEN RAISE EXCEPTION 'retained mailbox must be reconnected, not resumed' USING ERRCODE='BZ305'; END IF;
    UPDATE mailbox_lifecycle SET access_state='active',generation=generation+1,reason=p_reason,
      updated_by=p_actor,updated_at=statement_timestamp(),last_operation_id=p_operation_id WHERE mailbox_id=p_mailbox_id RETURNING * INTO v_l;
    UPDATE mailboxes SET enabled=true,updated_at=statement_timestamp() WHERE id=p_mailbox_id;
    v_event:='mailbox.resumed';
  ELSIF p_action='detach_retain' THEN
    IF v_l.binding_state<>'bound' OR v_m.user_id IS NULL THEN RAISE EXCEPTION 'mailbox is not actively bound' USING ERRCODE='BZ305'; END IF;
    SELECT p.* INTO v_policy FROM mailbox_lifecycle_policies p
      WHERE (p.domain_id=v_m.domain_id OR p.domain_id IS NULL) AND p.effective_at<=statement_timestamp()
      ORDER BY (p.domain_id IS NOT NULL) DESC,p.effective_at DESC LIMIT 1;
    UPDATE mailbox_lifecycle SET was_primary=v_m.is_primary WHERE mailbox_id=p_mailbox_id;
    UPDATE mailboxes SET user_id=NULL,is_primary=false,enabled=false,updated_at=statement_timestamp() WHERE id=p_mailbox_id;
    UPDATE mailbox_lifecycle SET access_state='detached',binding_state='retained',bound_user_id=NULL,
      delivery_state=COALESCE(p_delivery_state,'accepting'),redirect_address=p_redirect_address,
      retained_at=statement_timestamp(),retention_until=statement_timestamp()+make_interval(days=>v_policy.retention_days),
      policy_generation=v_policy.generation,generation=generation+1,reason=p_reason,updated_by=p_actor,
      updated_at=statement_timestamp(),last_operation_id=p_operation_id WHERE mailbox_id=p_mailbox_id RETURNING * INTO v_l;
    UPDATE mailbox_address_claims SET claim_state='retained',generation=generation+1,released_at=NULL WHERE mailbox_id=p_mailbox_id;
    INSERT INTO mailbox_binding_history(mailbox_id,from_user_id,to_user_id,operation_id,evidence_kind,actor_user_id,actor_auth_time,reason)
      VALUES(p_mailbox_id,v_old_user,NULL,p_operation_id,'initial',p_actor,COALESCE(p_actor_auth_time,statement_timestamp()),p_reason);
    v_event:='mailbox.detached';
  ELSE
    IF v_l.binding_state<>'retained' OR v_m.user_id IS NOT NULL OR p_target_user_id IS NULL THEN
      RAISE EXCEPTION 'mailbox is not retained or target is missing' USING ERRCODE='BZ305';
    END IF;
    IF EXISTS(SELECT 1 FROM mailboxes WHERE user_id=p_target_user_id AND is_primary AND id<>p_mailbox_id) THEN
      RAISE EXCEPTION 'target already has a primary mailbox' USING ERRCODE='BZ306';
    END IF;
    IF p_evidence_kind='identity_link' THEN
      IF NOT EXISTS(SELECT 1 FROM user_identity_links WHERE id=p_identity_link_id AND user_id=p_target_user_id
                    AND state='active' AND generation=p_link_generation) THEN
        RAISE EXCEPTION 'reconnect identity evidence is stale' USING ERRCODE='BZ307'; END IF;
    ELSIF p_evidence_kind='local_user' THEN
      IF NOT EXISTS(SELECT 1 FROM user_lifecycle_authorities WHERE user_id=p_target_user_id AND authority_kind='local') THEN
        RAISE EXCEPTION 'target is not a stable local identity' USING ERRCODE='BZ307'; END IF;
    ELSE RAISE EXCEPTION 'verified reconnect evidence is required' USING ERRCODE='BZ307'; END IF;
    IF NOT admin_can_manage_with_permission(p_actor,p_target_user_id,'users.delete') THEN
      RAISE EXCEPTION 'target user not found' USING ERRCODE='BZ302';
    END IF;
    UPDATE mailboxes SET user_id=p_target_user_id,is_primary=v_l.was_primary,enabled=true,updated_at=statement_timestamp() WHERE id=p_mailbox_id;
    UPDATE mailbox_lifecycle SET access_state='active',binding_state='bound',bound_user_id=p_target_user_id,
      retained_at=NULL,retention_until=NULL,delivery_state='accepting',redirect_address=NULL,
      generation=generation+1,reason=p_reason,updated_by=p_actor,updated_at=statement_timestamp(),
      last_operation_id=p_operation_id WHERE mailbox_id=p_mailbox_id RETURNING * INTO v_l;
    UPDATE mailbox_address_claims SET claim_state='active',generation=generation+1,released_at=NULL WHERE mailbox_id=p_mailbox_id;
    INSERT INTO mailbox_binding_history(mailbox_id,from_user_id,to_user_id,operation_id,evidence_kind,identity_link_id,
      link_generation,source_key_digest,actor_user_id,actor_auth_time,reason)
      VALUES(p_mailbox_id,NULL,p_target_user_id,p_operation_id,p_evidence_kind,p_identity_link_id,p_link_generation,
        p_source_key_digest,p_actor,COALESCE(p_actor_auth_time,statement_timestamp()),p_reason);
    v_event:='mailbox.reconnected';
  END IF;
  v_after:=to_jsonb(v_l); v_after_digest:=encode(digest(v_after::text,'sha256'),'hex');
  v_result:=mailbox_lifecycle_read(p_mailbox_id)||jsonb_build_object('operationId',p_operation_id,'replayed',false);
  INSERT INTO mailbox_lifecycle_operations(operation_id,mailbox_id,action,actor_user_id,expected_generation,
    request_digest,before_digest,after_digest,result) VALUES(p_operation_id,p_mailbox_id,p_action,p_actor,
    p_expected_generation,p_request_digest,v_before_digest,v_after_digest,v_result);
  INSERT INTO mailbox_lifecycle_effects(operation_id,mailbox_id,effect_kind)
    SELECT p_operation_id,p_mailbox_id,x
      FROM unnest(CASE
        WHEN p_action='detach_retain' THEN ARRAY['revoke_sessions','evict_media','revoke_delegates','notify_clients','lifecycle_webhook']
        WHEN p_action='suspend' THEN ARRAY['revoke_sessions','evict_media','notify_clients','lifecycle_webhook']
        ELSE ARRAY['notify_clients','lifecycle_webhook']
      END) x;
  IF p_action IN ('suspend','detach_retain') AND v_old_user IS NOT NULL THEN
    INSERT INTO mailbox_lifecycle_effect_targets(operation_id,room_name,identity)
    SELECT p_operation_id,t.room_name,t.identity
      FROM (
        SELECT m.room_name,p.identity
          FROM meeting_participants p JOIN meetings m ON m.id=p.meeting_id
         WHERE p.user_id=v_old_user AND m.state<>'ended'
        UNION
        SELECT b.room_name,p.identity
          FROM meeting_participants p
          JOIN meetings m ON m.id=p.meeting_id
          JOIN meeting_breakouts b ON b.meeting_id=m.id
         WHERE p.user_id=v_old_user AND m.state<>'ended'
      ) t
    ON CONFLICT DO NOTHING;
    INSERT INTO mailbox_lifecycle_effect_targets(operation_id,room_name,identity,evict_until)
    SELECT p_operation_id,a.room_name,a.identity,a.expires_at
      FROM identity_media_admissions a
     WHERE a.user_id=v_old_user AND a.expires_at>statement_timestamp()
    ON CONFLICT(operation_id,effect_kind,room_name,identity) DO UPDATE
      SET evict_until=GREATEST(mailbox_lifecycle_effect_targets.evict_until,EXCLUDED.evict_until);
  END IF;
  INSERT INTO mailbox_lifecycle_outbox(operation_id,event_kind,dedupe_key,payload)
    VALUES(p_operation_id,v_event,'mailbox-lifecycle:'||p_operation_id::text,
      jsonb_build_object('mailboxId',p_mailbox_id::text,'generation',v_l.generation::text,'event',v_event));
  PERFORM audit_write(p_actor,replace(v_event,'.','_'),'mailbox',p_mailbox_id,v_before,v_after,NULL,p_reason,'core');
  IF p_action IN ('suspend','detach_retain') THEN
    PERFORM public.emit_scope_revoked(
      NULL,
      'mailbox',
      p_mailbox_id,
      CASE WHEN p_action='suspend' THEN 'mailbox_suspended' ELSE 'mailbox_detached' END,
      NULL
    );
  END IF;
  PERFORM app_notify('mailbox_lifecycle',json_build_object('mailbox_id',p_mailbox_id,'generation',v_l.generation)::text);
  RETURN v_result;
END $$;

-- [embedded verbatim from reducers/mailbox_lifecycle_effect_apply.sql]
CREATE OR REPLACE FUNCTION mailbox_lifecycle_effect_apply(p_worker_id text,p_effect_id bigint)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_e mailbox_lifecycle_effects%ROWTYPE; v_o mailbox_lifecycle_operations%ROWTYPE; v_user_id bigint; v_delegate_uid bigint;
BEGIN
  SELECT * INTO v_e FROM mailbox_lifecycle_effects WHERE id=p_effect_id FOR UPDATE;
  IF NOT FOUND OR v_e.state<>'claimed' OR v_e.claimed_by<>p_worker_id OR v_e.lease_until<=statement_timestamp() THEN
    RAISE EXCEPTION 'mailbox lifecycle effect lease lost' USING ERRCODE='55000';
  END IF;
  SELECT * INTO STRICT v_o FROM mailbox_lifecycle_operations WHERE operation_id=v_e.operation_id;
  SELECT COALESCE(
    (SELECT h.from_user_id FROM mailbox_binding_history h WHERE h.operation_id=v_e.operation_id),
    (SELECT m.user_id FROM mailboxes m WHERE m.id=v_e.mailbox_id)
  ) INTO v_user_id;
  IF v_e.effect_kind='revoke_sessions' THEN
    IF v_user_id IS NOT NULL THEN
      PERFORM revoke_user_sessions(v_user_id,'all','mailbox_lifecycle.'||v_o.action,v_o.actor_user_id,NULL,NULL);
    END IF;
  ELSIF v_e.effect_kind='revoke_delegates' THEN
    FOR v_delegate_uid IN
      DELETE FROM mailbox_delegates WHERE mailbox_id=v_e.mailbox_id RETURNING user_id
    LOOP
      PERFORM public.emit_scope_revoked(
        v_delegate_uid, 'mailbox', v_e.mailbox_id, 'mailbox_delegates_revoked', NULL
      );
    END LOOP;
  ELSIF v_e.effect_kind='notify_clients' THEN
    PERFORM app_notify('mailbox_lifecycle',jsonb_build_object('mailbox_id',v_e.mailbox_id,
      'operation_id',v_e.operation_id,'action',v_o.action)::text);
  ELSE
    RAISE EXCEPTION 'mailbox lifecycle effect requires external executor' USING ERRCODE='55000';
  END IF;
  UPDATE mailbox_lifecycle_effects SET state='completed',completed_at=statement_timestamp(),
    lease_until=NULL,claimed_by=NULL,last_error=NULL WHERE id=v_e.id;
END $$;

INSERT INTO schema_migrations (version, applied_at)
VALUES (294, now())
ON CONFLICT (version) DO NOTHING;
