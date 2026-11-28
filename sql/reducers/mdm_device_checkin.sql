-- mdm_device_checkin.sql: B — atomic MDM check-in.
-- Compliance eval + grace computation + wipe FSM transition + UPSERT, all in ONE
-- transaction keyed on (device_id, user_id). Replaces engine.go ProcessCheckin's
-- three unordered queries (getWipeState / processWipeTransitions / upsertDeviceState),
-- which raced (a heartbeat + a launch check-in could read a stale wipe_requested)
-- and could clobber a just-written wipe transition. The compliance verdict and the
-- persisted row are now produced by the SAME transaction (single source of truth;
-- the former Go-side compliance evaluator + version-compare helpers are deleted).
--
-- Ownership (R1/R3): the device row is SELECT ... FOR UPDATE first; if a row
-- already exists under a DIFFERENT user_id, the check-in raises BZ052 (maps to
-- HTTP 403 in the gateway). The first check-in for a NEW device_id legitimately
-- inserts a row for p_user_id.

-- mdm_version_ge: semver-ish compare, mirrors the deleted Go version-compare
-- helpers. Stops at the first non-numeric segment ("17.0-beta" → 17.0), compares
-- the first three components, missing component = 0. Empty/null → TRUE
-- (no constraint).
CREATE OR REPLACE FUNCTION mdm_version_ge(p_cur TEXT, p_min TEXT) RETURNS BOOLEAN AS $$
DECLARE c INT[]; m INT[]; i INT; cv INT; mv INT;
BEGIN
    IF p_cur IS NULL OR p_cur='' OR p_min IS NULL OR p_min='' THEN RETURN TRUE; END IF;
    c := string_to_array(NULLIF(regexp_replace(p_cur, '[^0-9.].*$',''),''),'.')::int[];
    m := string_to_array(NULLIF(regexp_replace(p_min, '[^0-9.].*$',''),''),'.')::int[];
    FOR i IN 1..3 LOOP
        cv := COALESCE(c[i],0); mv := COALESCE(m[i],0);
        IF cv > mv THEN RETURN TRUE; END IF;
        IF cv < mv THEN RETURN FALSE; END IF;
    END LOOP;
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION mdm_device_checkin(
    p_device_id   UUID,
    p_user_id     BIGINT,
    p_report_json JSONB,
    p_policy_json JSONB
) RETURNS JSONB AS $$
DECLARE
    v_cur            mdm_device_state%ROWTYPE;
    v_exists         BOOLEAN := FALSE;
    v_status         TEXT := 'compliant';
    v_reasons        TEXT[] := '{}';
    v_actions        TEXT[] := '{}';
    v_grace_until    TIMESTAMPTZ;
    v_wipe           TEXT := 'none';
    v_wipe_level     TEXT;
    v_wipe_acked_at  TIMESTAMPTZ;
    v_wipe_cmd       JSONB := NULL;
    v_platform       TEXT := p_report_json->>'platform';
    v_min_os         TEXT;
    v_jb_action      TEXT := COALESCE(p_policy_json->>'jailbreak_action','none');
    v_grace_mins     INT := COALESCE((p_policy_json->>'grace_period_mins')::int,0);
    v_now            TIMESTAMPTZ := now();
BEGIN
    IF p_report_json IS NULL THEN p_report_json := '{}'::jsonb; END IF;
    IF p_policy_json IS NULL THEN p_policy_json := '{}'::jsonb; END IF;

    -- R1/R3: lock the device row if present; enforce ownership.
    SELECT * INTO v_cur FROM mdm_device_state WHERE device_id = p_device_id FOR UPDATE;
    IF FOUND THEN
        v_exists := TRUE;
        IF v_cur.user_id <> p_user_id THEN
            RAISE EXCEPTION 'Device owned by another user'
                USING ERRCODE='BZ052',
                      HINT=jsonb_build_object('type','device_not_owned','device_id',p_device_id)::text;
        END IF;
        v_wipe := v_cur.wipe_requested;
        v_wipe_level := v_cur.wipe_level;
        v_wipe_acked_at := v_cur.wipe_acked_at;
    END IF;

    -- ---- Compliance evaluation (ordered: passcode, encryption, os, jailbreak) ----
    -- passcode
    IF COALESCE((p_report_json->>'passcode_set')::bool,FALSE) THEN
        IF NOT COALESCE((p_report_json->>'passcode_compliant')::bool,FALSE) THEN
            v_reasons := array_append(v_reasons, 'Passcode does not meet complexity requirements');
            v_actions := array_append(v_actions, 'set_passcode');
        END IF;
    ELSIF COALESCE(p_policy_json->>'passcode_complexity','none') <> 'none' THEN
        v_reasons := array_append(v_reasons, 'Passcode not set on device');
        v_actions := array_append(v_actions, 'set_passcode');
    END IF;
    -- encryption
    IF COALESCE((p_policy_json->>'require_device_encryption')::bool,FALSE)
       AND NOT COALESCE((p_report_json->>'encryption_enabled')::bool,FALSE) THEN
        v_reasons := array_append(v_reasons, 'Device encryption is not enabled');
        v_actions := array_append(v_actions, 'enable_encryption');
    END IF;
    -- os version
    v_min_os := CASE v_platform WHEN 'ios' THEN p_policy_json->>'min_os_version_ios'
                                WHEN 'android' THEN p_policy_json->>'min_os_version_android' END;
    IF COALESCE(v_min_os,'')<>'' AND COALESCE(p_report_json->>'os_version','')<>''
       AND NOT mdm_version_ge(p_report_json->>'os_version', v_min_os) THEN
        v_reasons := array_append(v_reasons, 'OS version '||(p_report_json->>'os_version')||' is below minimum '||v_min_os);
        v_actions := array_append(v_actions, 'upgrade_os');
    END IF;
    -- jailbreak (block/quarantine short-circuit to quarantined)
    IF COALESCE((p_report_json->>'jailbroken')::bool,FALSE) THEN
        IF v_jb_action='block' THEN
            v_reasons := array_append(v_reasons, 'Jailbroken/rooted device detected: '||COALESCE(p_report_json->>'jailbreak_method',''));
            v_status := 'quarantined'; v_actions := '{}';
        ELSIF v_jb_action='quarantine' THEN
            v_reasons := array_append(v_reasons, 'Jailbroken/rooted device detected: '||COALESCE(p_report_json->>'jailbreak_method',''));
            v_actions := array_append(v_actions, 'remove_jailbreak'); v_status := 'quarantined';
        ELSIF v_jb_action='warn_log' THEN
            v_reasons := array_append(v_reasons, 'Jailbroken/rooted device detected (warn): '||COALESCE(p_report_json->>'jailbreak_method',''));
        END IF;
    END IF;

    -- overall status if not already quarantined by jailbreak
    IF v_status <> 'quarantined' THEN
        IF array_length(v_reasons,1) IS NULL THEN v_status := 'compliant';
        ELSE v_status := 'non_compliant'; END IF;
    END IF;

    -- ---- Grace period (mirrors engine.go) ----
    IF v_status='non_compliant' AND v_grace_mins>0 THEN
        IF v_exists AND v_cur.grace_until IS NOT NULL THEN
            IF v_now < v_cur.grace_until THEN
                v_status := 'grace'; v_grace_until := v_cur.grace_until;
            ELSE
                v_status := 'quarantined';
            END IF;
        ELSE
            v_grace_until := v_now + make_interval(mins => v_grace_mins);
            v_status := 'grace';
        END IF;
    ELSIF v_status='compliant' THEN
        v_grace_until := NULL;
    END IF;

    -- ---- Wipe FSM (mirrors processWipeTransitions) ----
    IF v_exists THEN
        IF v_wipe='pending' THEN
            IF COALESCE((p_report_json->>'wipe_ack')::bool,FALSE) THEN
                v_wipe := 'acknowledged'; v_wipe_acked_at := v_now;
            END IF;
            v_wipe_cmd := jsonb_build_object('level', v_wipe_level);
        ELSIF v_wipe='acknowledged' THEN
            IF COALESCE((p_report_json->>'wipe_ack')::bool,FALSE) THEN
                v_wipe := 'executed'; v_wipe_cmd := NULL;
            ELSE
                v_wipe_cmd := jsonb_build_object('level', v_wipe_level);
            END IF;
        END IF;
    END IF;

    -- ---- Atomic UPSERT (writes compliance + grace + wipe transition together) ----
    INSERT INTO mdm_device_state (
        device_id,user_id,platform,device_name,os_version,app_version,
        passcode_set,passcode_compliant,encryption_enabled,jailbroken,jailbreak_method,
        compliance_status,non_compliance_reasons,grace_until,
        wipe_requested,wipe_level,wipe_acked_at,
        last_checkin_at,updated_at
    ) VALUES (
        p_device_id,p_user_id,v_platform,
        COALESCE(p_report_json->>'device_name',''),COALESCE(p_report_json->>'os_version',''),
        COALESCE(p_report_json->>'app_version',''),
        COALESCE((p_report_json->>'passcode_set')::bool,FALSE),
        COALESCE((p_report_json->>'passcode_compliant')::bool,FALSE),
        COALESCE((p_report_json->>'encryption_enabled')::bool,FALSE),
        COALESCE((p_report_json->>'jailbroken')::bool,FALSE),
        COALESCE(p_report_json->>'jailbreak_method',''),
        v_status,v_reasons,v_grace_until,
        v_wipe,v_wipe_level,v_wipe_acked_at,
        v_now,v_now
    )
    ON CONFLICT (device_id) DO UPDATE SET
        user_id=EXCLUDED.user_id, platform=EXCLUDED.platform, device_name=EXCLUDED.device_name,
        os_version=EXCLUDED.os_version, app_version=EXCLUDED.app_version,
        passcode_set=EXCLUDED.passcode_set, passcode_compliant=EXCLUDED.passcode_compliant,
        encryption_enabled=EXCLUDED.encryption_enabled, jailbroken=EXCLUDED.jailbroken,
        jailbreak_method=EXCLUDED.jailbreak_method,
        compliance_status=EXCLUDED.compliance_status, non_compliance_reasons=EXCLUDED.non_compliance_reasons,
        grace_until=EXCLUDED.grace_until,
        wipe_requested=EXCLUDED.wipe_requested, wipe_acked_at=EXCLUDED.wipe_acked_at,
        last_checkin_at=EXCLUDED.last_checkin_at, updated_at=EXCLUDED.updated_at;

    -- ---- WP3 audit coverage: transitions, not heartbeats ----
    -- A check-in that only refreshes last_checkin_at writes no audit row.
    -- Material transitions do: FIRST check-in (the ownership/compliance
    -- record's creation — including an initial grace/quarantined state; astra
    -- round 1: creation is lifecycle establishment, not a heartbeat), a wipe
    -- FSM step (pending→acknowledged / acknowledged→executed), and a
    -- compliance-verdict CHANGE. Actor is the authenticated device owner the
    -- row is keyed to.
    IF NOT v_exists
       OR (v_exists AND v_wipe IS DISTINCT FROM v_cur.wipe_requested)
       OR (v_exists AND v_status IS DISTINCT FROM v_cur.compliance_status) THEN
        -- target_id is BIGINT while the mdm key is a UUID: follow
        -- mdm_device_wipe_arm's precedent (NULL target, device in the jsonb).
        PERFORM audit_write(
            p_user_id, 'mdm_device_checkin', 'mdm_device', NULL,
            CASE WHEN v_exists THEN jsonb_build_object(
                     'device_id', p_device_id,
                     'wipe_requested', v_cur.wipe_requested,
                     'compliance_status', v_cur.compliance_status)
                ELSE NULL END,
            jsonb_build_object(
                'device_id', p_device_id,
                'wipe_requested', v_wipe,
                'compliance_status', v_status,
                'non_compliance_reasons', to_jsonb(v_reasons),
                'grace_until', v_grace_until),
            NULL, NULL, 'core');
    END IF;

    RETURN jsonb_build_object(
        'policy', p_policy_json,
        'compliance_status', v_status,
        'non_compliance_reasons', to_jsonb(v_reasons),
        'required_actions', to_jsonb(v_actions),
        'heartbeat_interval_secs', COALESCE((p_policy_json->>'heartbeat_interval_secs')::int,0),
        'grace_until', v_grace_until,
        'wipe_command', v_wipe_cmd
    );
END;
$$ LANGUAGE plpgsql;
