-- guest_profile.sql -- Guest G2 domain-owned profiles and their derived state.

-- Guest G3 runtime policy lookup. The guest/profile join must live behind a
-- worker-owned SECURITY DEFINER helper because both tables are FORCE-RLS and a
-- missing row is the deliberately restrictive answer. Callers name one of the
-- small, closed set of runtime flags; an unknown flag cannot fail open.
CREATE OR REPLACE FUNCTION guest_profile_flag(
    p_user_id bigint, p_flag text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT COALESCE((
        SELECT CASE p_flag
            WHEN 'allow_meet_create' THEN gp.allow_meet_create
            WHEN 'allow_meet_host' THEN gp.allow_meet_host
            WHEN 'allow_download' THEN gp.allow_download
            ELSE false
        END
          FROM guest_accounts ga
          LEFT JOIN guest_profiles gp ON gp.id = ga.profile_id
         WHERE ga.user_id = p_user_id
    ), false);
$$;
SELECT apply_worker_ownership('guest_profile_flag(bigint,text)'::regprocedure);

CREATE OR REPLACE FUNCTION guest_profile_list(p_actor_user_id bigint)
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF NOT (guest_admin_has_live_permission(p_actor_user_id, 'guests.view')
            OR guest_admin_has_live_permission(p_actor_user_id, 'guests.manage')) THEN
        RAISE EXCEPTION 'guests.view required' USING ERRCODE='BZ002', HINT='{"type":"forbidden"}';
    END IF;
    RETURN (
        SELECT COALESCE(jsonb_agg(jsonb_build_object(
            'id', gp.id, 'hostDomainId', gp.host_domain_id, 'name', gp.name,
            'canPost', gp.can_post, 'historyFromJoin', gp.history_from_join,
            'allowDownload', gp.allow_download, 'allowMeetCreate', gp.allow_meet_create,
            'allowMeetHost', gp.allow_meet_host, 'canInitiateDm', gp.can_initiate_dm,
            'allowNativeShell', gp.allow_native_shell,
            'defaultExpiryDays', gp.default_expiry_days, 'apps', gp.apps,
            'assignedCount', (SELECT count(*) FROM guest_accounts ga WHERE ga.profile_id = gp.id),
            'createdAt', gp.created_at, 'updatedAt', gp.updated_at
        ) ORDER BY lower(gp.name), gp.id), '[]'::jsonb)
        FROM guest_profiles gp
        WHERE guest_admin_has_domain_permission(
                  p_actor_user_id, gp.host_domain_id, 'guests.view')
           OR guest_admin_has_domain_permission(
                  p_actor_user_id, gp.host_domain_id, 'guests.manage')
    );
END;
$$;
SELECT apply_worker_ownership('guest_profile_list(bigint)'::regprocedure);

-- The guest console cannot reuse GET /admin/domains: that route is mail-admin
-- scoped. Return only local domains reachable through the caller's live
-- guests.view/manage assignment so the profile editor has no cross-scope
-- domain-enumeration side channel.
CREATE OR REPLACE FUNCTION guest_profile_domain_list(p_actor_user_id bigint)
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF NOT (guest_admin_has_live_permission(p_actor_user_id, 'guests.view')
            OR guest_admin_has_live_permission(p_actor_user_id, 'guests.manage')) THEN
        RAISE EXCEPTION 'guests.view required' USING ERRCODE='BZ002', HINT='{"type":"forbidden"}';
    END IF;
    RETURN (
        SELECT COALESCE(jsonb_agg(jsonb_build_object(
            'id', d.id, 'name', d.name
        ) ORDER BY lower(d.name), d.id), '[]'::jsonb)
          FROM domains d
         WHERE d.is_local
           AND (guest_admin_has_domain_permission(
                    p_actor_user_id, d.id, 'guests.view')
                OR guest_admin_has_domain_permission(
                    p_actor_user_id, d.id, 'guests.manage'))
    );
END;
$$;
SELECT apply_worker_ownership('guest_profile_domain_list(bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION guest_profile_get(p_actor_user_id bigint, p_profile_id bigint)
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_result jsonb;
BEGIN
    IF NOT (guest_admin_has_live_permission(p_actor_user_id, 'guests.view')
            OR guest_admin_has_live_permission(p_actor_user_id, 'guests.manage')) THEN
        RAISE EXCEPTION 'guests.view required' USING ERRCODE='BZ002', HINT='{"type":"forbidden"}';
    END IF;
    SELECT jsonb_build_object(
        'id', gp.id, 'hostDomainId', gp.host_domain_id, 'name', gp.name,
        'canPost', gp.can_post, 'historyFromJoin', gp.history_from_join,
        'allowDownload', gp.allow_download, 'allowMeetCreate', gp.allow_meet_create,
        'allowMeetHost', gp.allow_meet_host, 'canInitiateDm', gp.can_initiate_dm,
        'allowNativeShell', gp.allow_native_shell,
        'defaultExpiryDays', gp.default_expiry_days, 'apps', gp.apps,
        'assignedCount', (SELECT count(*) FROM guest_accounts ga WHERE ga.profile_id = gp.id),
        'createdAt', gp.created_at, 'updatedAt', gp.updated_at
    ) INTO v_result
    FROM guest_profiles gp
    WHERE gp.id = p_profile_id
      AND (guest_admin_has_domain_permission(
               p_actor_user_id, gp.host_domain_id, 'guests.view')
           OR guest_admin_has_domain_permission(
               p_actor_user_id, gp.host_domain_id, 'guests.manage'));
    IF v_result IS NULL THEN
        RAISE EXCEPTION 'guest profile not found' USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;
    RETURN v_result;
END;
$$;
SELECT apply_worker_ownership('guest_profile_get(bigint,bigint)'::regprocedure);

-- Invite-only profile snapshot. The row share lock survives for the caller's
-- transaction, so its default expiry and the later guest_profile_apply policy
-- are one serial profile version. A concurrent profile edit must wait for the
-- invite transaction to finish (or win first, in which case both reads see the
-- edited version).
CREATE OR REPLACE FUNCTION guest_profile_invite_snapshot(
    p_actor_user_id bigint, p_profile_id bigint
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_result jsonb;
BEGIN
    IF NOT guest_admin_has_live_permission(p_actor_user_id, 'guests.manage') THEN
        RAISE EXCEPTION 'guests.manage required' USING ERRCODE='BZ002', HINT='{"type":"forbidden"}';
    END IF;
    SELECT jsonb_build_object('defaultExpiryDays', gp.default_expiry_days)
      INTO v_result
      FROM guest_profiles gp
     WHERE gp.id = p_profile_id
       AND guest_admin_has_domain_permission(
               p_actor_user_id, gp.host_domain_id, 'guests.manage')
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'guest profile not found' USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;
    RETURN v_result;
END;
$$;
SELECT apply_worker_ownership('guest_profile_invite_snapshot(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION guest_profile_set(
    p_actor_user_id bigint, p_profile_id bigint, p_host_domain_id bigint,
    p_name text, p_can_post boolean, p_history_from_join boolean,
    p_allow_download boolean, p_allow_meet_create boolean, p_allow_meet_host boolean,
    p_can_initiate_dm boolean, p_allow_native_shell boolean,
    p_default_expiry_days integer, p_apps text[]
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_apps       text[];
    v_id         bigint;
    v_guest      record;
    v_before     jsonb;
    v_after      jsonb;
BEGIN
    IF NOT guest_admin_has_live_permission(p_actor_user_id, 'guests.manage') THEN
        RAISE EXCEPTION 'guests.manage required' USING ERRCODE='BZ002', HINT='{"type":"forbidden"}';
    END IF;
    SELECT COALESCE(array_agg(DISTINCT v ORDER BY v), '{}'::text[])
      INTO v_apps FROM unnest(COALESCE(p_apps, '{}'::text[])) AS v;
    IF p_host_domain_id IS NULL OR NULLIF(btrim(COALESCE(p_name, '')), '') IS NULL
       OR p_can_post IS NULL OR p_history_from_join IS NULL OR p_allow_download IS NULL
       OR p_allow_meet_create IS NULL OR p_allow_meet_host IS NULL
       OR p_can_initiate_dm IS NULL OR p_allow_native_shell IS NULL
       OR (p_default_expiry_days IS NOT NULL AND p_default_expiry_days <= 0)
       OR cardinality(v_apps) <> cardinality(COALESCE(p_apps, '{}'::text[]))
       OR EXISTS (SELECT 1 FROM unnest(v_apps) a
                   WHERE a IS NULL OR a <> ALL (ARRAY['chat','drive','meet'])) THEN
        RAISE EXCEPTION 'invalid guest profile' USING ERRCODE='BZ224',
            HINT='{"type":"invalidArguments"}';
    END IF;

    IF p_profile_id IS NULL THEN
        -- Lock the qualifying domain before the INSERT. A concurrent local →
        -- non-local flip either commits first (this returns BZ170) or waits
        -- until this create transaction commits; there is no check/insert
        -- window with an unprotected domain row.
        PERFORM 1 FROM domains d
         WHERE d.id = p_host_domain_id
           AND d.is_local
           AND guest_admin_has_domain_permission(
                   p_actor_user_id, p_host_domain_id, 'guests.manage')
         FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'guest profile not found' USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
        END IF;
        BEGIN
            INSERT INTO guest_profiles (
                host_domain_id, name, can_post, history_from_join, allow_download,
                allow_meet_create, allow_meet_host, can_initiate_dm, allow_native_shell,
                default_expiry_days, apps
            ) SELECT
                p_host_domain_id, btrim(p_name), p_can_post, p_history_from_join, p_allow_download,
                p_allow_meet_create, p_allow_meet_host, p_can_initiate_dm, p_allow_native_shell,
                p_default_expiry_days, v_apps
              FROM domains d
             WHERE d.id = p_host_domain_id
               AND d.is_local
               AND guest_admin_has_domain_permission(
                       p_actor_user_id, p_host_domain_id, 'guests.manage')
            RETURNING id INTO v_id;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION 'guest profile name already exists'
                USING ERRCODE='BZ224', HINT='{"type":"invalidArguments","detail":"profile name already exists"}';
        END;
        IF v_id IS NULL THEN
            RAISE EXCEPTION 'guest profile not found' USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
        END IF;
        v_after := jsonb_build_object(
            'hostDomainId', p_host_domain_id, 'name', btrim(p_name),
            'canPost', p_can_post, 'historyFromJoin', p_history_from_join,
            'allowDownload', p_allow_download, 'allowMeetCreate', p_allow_meet_create,
            'allowMeetHost', p_allow_meet_host, 'canInitiateDm', p_can_initiate_dm,
            'allowNativeShell', p_allow_native_shell,
            'defaultExpiryDays', p_default_expiry_days, 'apps', v_apps);
        PERFORM audit_write(p_actor_user_id, 'guest.profile_create', 'guest_profile', v_id,
            NULL, v_after, NULL, NULL, 'core');
        RETURN v_id;
    END IF;

    SELECT gp.id, jsonb_build_object(
               'hostDomainId', gp.host_domain_id, 'name', gp.name,
               'canPost', gp.can_post, 'historyFromJoin', gp.history_from_join,
               'allowDownload', gp.allow_download, 'allowMeetCreate', gp.allow_meet_create,
               'allowMeetHost', gp.allow_meet_host, 'canInitiateDm', gp.can_initiate_dm,
               'allowNativeShell', gp.allow_native_shell,
               'defaultExpiryDays', gp.default_expiry_days, 'apps', gp.apps)
      INTO v_id, v_before
      FROM guest_profiles gp
     WHERE gp.id = p_profile_id
       AND gp.host_domain_id = p_host_domain_id
       AND EXISTS (SELECT 1 FROM domains d
                    WHERE d.id = gp.host_domain_id AND d.is_local)
       AND guest_admin_has_domain_permission(
               p_actor_user_id, gp.host_domain_id, 'guests.manage')
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'guest profile not found' USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;

    PERFORM 1 FROM guest_accounts WHERE profile_id = p_profile_id FOR UPDATE;
    BEGIN
        UPDATE guest_profiles gp SET
            name = btrim(p_name), can_post = p_can_post,
            history_from_join = p_history_from_join, allow_download = p_allow_download,
            allow_meet_create = p_allow_meet_create, allow_meet_host = p_allow_meet_host,
            can_initiate_dm = p_can_initiate_dm, allow_native_shell = p_allow_native_shell,
            default_expiry_days = p_default_expiry_days, apps = v_apps, updated_at = now()
         WHERE gp.id = p_profile_id
           AND gp.host_domain_id = p_host_domain_id
           AND guest_admin_has_domain_permission(
                   p_actor_user_id, gp.host_domain_id, 'guests.manage');
        IF NOT FOUND THEN
            RAISE EXCEPTION 'guest profile not found' USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
        END IF;
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'guest profile name already exists'
            USING ERRCODE='BZ224', HINT='{"type":"invalidArguments","detail":"profile name already exists"}';
    END;
    v_after := jsonb_build_object(
        'hostDomainId', p_host_domain_id, 'name', btrim(p_name),
        'canPost', p_can_post, 'historyFromJoin', p_history_from_join,
        'allowDownload', p_allow_download, 'allowMeetCreate', p_allow_meet_create,
        'allowMeetHost', p_allow_meet_host, 'canInitiateDm', p_can_initiate_dm,
        'allowNativeShell', p_allow_native_shell,
        'defaultExpiryDays', p_default_expiry_days, 'apps', v_apps);
    FOR v_guest IN SELECT user_id FROM guest_accounts WHERE profile_id = p_profile_id LOOP
        PERFORM guest_profile_apply(p_actor_user_id, v_guest.user_id, p_profile_id);
    END LOOP;
    PERFORM audit_write(p_actor_user_id, 'guest.profile_update', 'guest_profile', p_profile_id,
        v_before, v_after, NULL, NULL, 'core');
    RETURN p_profile_id;
END;
$$;
SELECT apply_worker_ownership('guest_profile_set(bigint,bigint,bigint,text,boolean,boolean,boolean,boolean,boolean,boolean,boolean,integer,text[])'::regprocedure);

CREATE OR REPLACE FUNCTION guest_profile_delete(p_actor_user_id bigint, p_profile_id bigint)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_id bigint;
    v_before jsonb;
BEGIN
    IF NOT guest_admin_has_live_permission(p_actor_user_id, 'guests.manage') THEN
        RAISE EXCEPTION 'guests.manage required' USING ERRCODE='BZ002', HINT='{"type":"forbidden"}';
    END IF;
    SELECT gp.id, jsonb_build_object(
               'hostDomainId', gp.host_domain_id, 'name', gp.name,
               'canPost', gp.can_post, 'historyFromJoin', gp.history_from_join,
               'allowDownload', gp.allow_download, 'allowMeetCreate', gp.allow_meet_create,
               'allowMeetHost', gp.allow_meet_host, 'canInitiateDm', gp.can_initiate_dm,
               'allowNativeShell', gp.allow_native_shell,
               'defaultExpiryDays', gp.default_expiry_days, 'apps', gp.apps)
      INTO v_id, v_before FROM guest_profiles gp
     WHERE gp.id = p_profile_id
       AND guest_admin_has_domain_permission(
               p_actor_user_id, gp.host_domain_id, 'guests.manage')
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'guest profile not found' USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;
    IF EXISTS (SELECT 1 FROM guest_accounts WHERE profile_id = p_profile_id) THEN
        RAISE EXCEPTION 'guest profile is assigned' USING ERRCODE='BZ225',
            HINT='{"type":"conflict","detail":"profile is assigned"}';
    END IF;
    DELETE FROM guest_profiles gp
     WHERE gp.id = p_profile_id
       AND guest_admin_has_domain_permission(
               p_actor_user_id, gp.host_domain_id, 'guests.manage');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'guest profile not found' USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;
    PERFORM audit_write(p_actor_user_id, 'guest.profile_delete', 'guest_profile', p_profile_id,
        v_before, NULL, NULL, NULL, 'core');
END;
$$;
SELECT apply_worker_ownership('guest_profile_delete(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION guest_profile_apply(
    p_actor_user_id bigint, p_guest_user_id bigint, p_profile_id bigint
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_host_domain_id bigint;
    v_profile_host_domain_id bigint;
    v_before_profile bigint;
    v_can_post       boolean := false;
    v_chat           boolean := false;
    v_drive          boolean := false;
    v_meet           boolean := false;
    v_rows           integer;
BEGIN
    IF NOT guest_admin_has_live_permission(p_actor_user_id, 'guests.manage') THEN
        RAISE EXCEPTION 'guests.manage required' USING ERRCODE='BZ002', HINT='{"type":"forbidden"}';
    END IF;

    -- One lock order for profile-derived writes: profile, then guest. This
    -- matches guest_profile_set and makes the policy read itself the lock,
    -- so an apply can never carry a pre-update snapshot past a profile edit.
    IF p_profile_id IS NOT NULL THEN
        SELECT gp.host_domain_id, gp.can_post,
               'chat' = ANY(gp.apps), 'drive' = ANY(gp.apps), 'meet' = ANY(gp.apps)
          INTO v_profile_host_domain_id, v_can_post, v_chat, v_drive, v_meet
          FROM guest_profiles gp
         WHERE gp.id = p_profile_id
           AND guest_admin_can_reach_with_permission(
                   p_actor_user_id, p_guest_user_id, 'guests.manage')
         FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'guest profile not found' USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
        END IF;
    END IF;

    SELECT g.host_domain_id, g.profile_id INTO v_host_domain_id, v_before_profile
      FROM guest_accounts g
     WHERE g.user_id = p_guest_user_id
       AND guest_admin_can_reach_with_permission(
               p_actor_user_id, g.user_id, 'guests.manage')
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'guest account not found' USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;

    IF p_profile_id IS NOT NULL AND v_profile_host_domain_id <> v_host_domain_id THEN
        RAISE EXCEPTION 'guest profile not found' USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;

    UPDATE guest_accounts g SET profile_id = p_profile_id, updated_at = now()
     WHERE g.user_id = p_guest_user_id
       AND g.host_domain_id = v_host_domain_id
       AND guest_admin_can_reach_with_permission(
               p_actor_user_id, g.user_id, 'guests.manage');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'guest account not found' USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;
    INSERT INTO user_app_entitlements(user_id, app, enabled, updated_at, updated_by)
    SELECT p_guest_user_id, x.app, x.enabled, now(), p_actor_user_id
    FROM (VALUES
     ('mail',false),('calendar',false),('contacts',false),('tasks',false),
     ('chat',v_chat),('drive',v_drive),('meet',v_meet)
    ) AS x(app,enabled)
    WHERE guest_admin_can_reach_with_permission(
              p_actor_user_id, p_guest_user_id, 'guests.manage')
    ON CONFLICT (user_id,app) DO UPDATE
    SET enabled=excluded.enabled, updated_at=excluded.updated_at, updated_by=excluded.updated_by;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows <> 7 THEN
        RAISE EXCEPTION 'guest account not found' USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;
    UPDATE chat_channel_members
       SET can_post = v_can_post
     WHERE user_id = p_guest_user_id
       AND guest_admin_can_reach_with_permission(
               p_actor_user_id, p_guest_user_id, 'guests.manage');
    IF v_before_profile IS DISTINCT FROM p_profile_id THEN
        PERFORM audit_write(p_actor_user_id, 'guest.profile_set', 'user', p_guest_user_id,
            jsonb_build_object('profileId', v_before_profile),
            jsonb_build_object('profileId', p_profile_id), NULL, NULL, 'core');
    END IF;
END;
$$;
SELECT apply_worker_ownership('guest_profile_apply(bigint,bigint,bigint)'::regprocedure);
