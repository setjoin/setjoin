-- mdm_device_wipe_arm.sql: MDM admin wipe arming — the reducer-authoritative
-- destructive-state transition. Replaces engine.go RequestWipe's plain Go
-- UPDATE (state change only, ephemeral slog evidence, no audit, no
-- pg_notify/device_events parity with MAM lock/unlock). Everything the arm
-- means now happens in THIS ONE transaction:
--
--   1. STATE     — the none→pending FSM transition on mdm_device_state, with
--                  the owner-derived domain-scope predicate in the SAME
--                  statement (R1/R3, no check-then-mutate window).
--   2. AUDIT     — a core-tier admin_audit_log row via audit_write (the ONLY
--                  audit path), recording actor, before/after wipe state and
--                  the device uuid. Durable evidence, never just slog.
--   3. EVENTS    — a durable device_events lifecycle row, the same evidence
--                  surface MAM lock/unlock write (device_locked/device_unlocked).
--                  device_events.device_id is the canonical devices.id FK; an
--                  MDM device has no devices row, so the column stays NULL
--                  (FK-honest) and the identifiers ride in details.
--   4. NOTIFY    — one device_policy-channel push via app_notify (the single
--                  pg_notify choke point), the same channel lock/unlock use,
--                  with action 'wipe_armed'.
--
-- Retry semantics are explicit per state (NOT a blind UPSERT; byte-compatible
-- with the former Go contract so the HTTP mapping is unchanged):
--   - none            → armed: one none→pending transition, timestamps written.
--   - pending/acknowledged, same level → idempotent success; NO second
--     transition, NO rewritten timestamps, NO duplicate evidence rows.
--   - pending/acknowledged, different level → BZ054 (already_armed).
--   - executed        → BZ054 (executed) — terminal; attestation honesty: the
--     executed state is a client-reported wipe_ack, not verified destruction.
--   - unknown OR out-of-scope device → BZ053 (not_found), fail-closed and
--     indistinguishable (no existence oracle for scoped callers).
--
-- BZ053/BZ054/BZ057 are the reserved-but-unused codes of the BZ048–BZ057
-- Go-state-machines-to-reducers band (docs/reducer-error-codes.md).
CREATE OR REPLACE FUNCTION mdm_device_wipe_arm(
    p_device_id    UUID,
    p_level        TEXT,
    p_domain_scope BIGINT,
    p_actor        BIGINT,
    p_ip           INET DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
    v_cur         mdm_device_state%ROWTYPE;
    v_now         TIMESTAMPTZ := now();
    v_registry_id BIGINT;
BEGIN
    -- Defense in depth: the gateway validates the level before calling; the
    -- reducer refuses anything outside the FSM's vocabulary anyway (BZ057).
    IF p_level IS NULL OR p_level NOT IN ('account', 'device') THEN
        RAISE EXCEPTION 'wipe level must be ''account'' or ''device'''
            USING ERRCODE = 'BZ057',
                  HINT = jsonb_build_object('type', 'invalid_level',
                                            'device_id', p_device_id)::TEXT;
    END IF;

    -- R1/R3: resolve AND lock the device row under the SAME scope predicate
    -- the arm itself uses. A scoped admin's WHERE carries the owner-derived
    -- predicate (user_id IN users of their domain), so an out-of-scope device
    -- is NOT FOUND — indistinguishable from a missing one (no existence
    -- oracle, and executed/out-of-scope never leaks through error text).
    SELECT * INTO v_cur
      FROM mdm_device_state
     WHERE device_id = p_device_id
       AND (p_domain_scope IS NULL OR p_domain_scope <= 0
            OR user_id IN (SELECT id FROM users WHERE domain_id = p_domain_scope))
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'wipe target not found'
            USING ERRCODE = 'BZ053',
                  HINT = jsonb_build_object('type', 'not_found',
                                            'device_id', p_device_id)::TEXT;
    END IF;

    -- Retry classification under the row lock (the former Go UPDATE + read-only
    -- classify had a TOCTOU window; lock + classify in one tx eliminates it).
    IF v_cur.wipe_requested <> 'none' THEN
        IF v_cur.wipe_requested = 'executed' THEN
            RAISE EXCEPTION 'wipe already executed'
                USING ERRCODE = 'BZ054',
                      HINT = jsonb_build_object('type', 'executed',
                                                'device_id', p_device_id)::TEXT;
        END IF;
        IF COALESCE(v_cur.wipe_level, '') = p_level THEN
            -- Idempotent retry: the wipe is already armed at this level.
            -- No double transition, no timestamp rewrite, no duplicate
            -- audit/event/notify evidence.
            RETURN jsonb_build_object(
                'result',         'already_armed',
                'wipe_requested', v_cur.wipe_requested,
                'wipe_level',     v_cur.wipe_level);
        END IF;
        RAISE EXCEPTION 'wipe already in progress at level ''%''', v_cur.wipe_level
            USING ERRCODE = 'BZ054',
                  HINT = jsonb_build_object('type', 'already_armed',
                                            'device_id', p_device_id,
                                            'reason', v_cur.wipe_level)::TEXT;
    END IF;

    -- ---- 1. STATE: none → pending (row lock held; scope re-checked) ----
    -- R1/R3: the SAME owner-derived domain-scope predicate the scoped SELECT
    -- used guards the MUTATION too. The device row lock freezes wipe_requested
    -- and user_id, but it does NOT freeze the owner's users.domain_id — an
    -- out-of-band domain move between the scoped SELECT and this UPDATE must
    -- abort the arm HERE, before any audit/event/notify effect exists.
    UPDATE mdm_device_state
       SET wipe_requested    = 'pending',
           wipe_level        = p_level,
           wipe_requested_at = v_now,
           updated_at        = v_now
     WHERE device_id = p_device_id
       AND wipe_requested = 'none'
       AND (p_domain_scope IS NULL OR p_domain_scope <= 0
            OR user_id IN (SELECT id FROM users WHERE domain_id = p_domain_scope));
    IF NOT FOUND THEN
        -- Classify the locked-row-stable failure. The owner's user_id cannot
        -- change under the row lock, so a scope mismatch observed NOW means
        -- the owner's domain moved out from under the actor mid-call → BZ053,
        -- indistinguishable from a missing device (no existence oracle once
        -- the target has left the caller's scope). Only a future LOCKING
        -- regression (wipe_requested mutating under the lock) can reach the
        -- remaining case → BZ054 fail-closed, never silently re-classified.
        IF NOT (p_domain_scope IS NULL OR p_domain_scope <= 0
                OR v_cur.user_id IN (SELECT id FROM users
                                      WHERE domain_id = p_domain_scope)) THEN
            RAISE EXCEPTION 'wipe target not found'
                USING ERRCODE = 'BZ053',
                      HINT = jsonb_build_object('type', 'not_found',
                                                'device_id', p_device_id)::TEXT;
        END IF;
        RAISE EXCEPTION 'device state changed concurrently'
            USING ERRCODE = 'BZ054',
                  HINT = jsonb_build_object('type', 'concurrent',
                                            'device_id', p_device_id)::TEXT;
    END IF;

    -- Best-effort MAM console projection: the numeric device_registry id the
    -- console list keys its policy/event actions by, resolved the same way the
    -- console projection joins (device_fingerprint + owning user).
    SELECT id INTO v_registry_id
      FROM device_registry
     WHERE device_fingerprint = p_device_id
       AND user_id = v_cur.user_id
     ORDER BY id
     LIMIT 1;

    -- ---- 2. AUDIT: durable core-tier evidence (never level-gated) ----
    PERFORM audit_write(
        p_actor, 'mdm_device_wipe_arm', 'mdm_device', NULL,
        jsonb_build_object('device_id', p_device_id,
                           'wipe_requested', v_cur.wipe_requested,
                           'wipe_level', v_cur.wipe_level),
        jsonb_build_object('device_id', p_device_id,
                           'wipe_requested', 'pending',
                           'wipe_level', p_level,
                           'owner_user_id', v_cur.user_id),
        p_ip, p_device_id::TEXT, 'core');

    -- ---- 3. EVENTS: durable device_events parity with MAM lock/unlock ----
    INSERT INTO device_events (device_id, event_type, severity, details, occurred_at)
    VALUES (NULL, 'wipe_requested', 'critical',
            jsonb_build_object('mdm_device_id', p_device_id,
                               'wipe_level', p_level,
                               'armed_by', p_actor,
                               'domain_scope', p_domain_scope,
                               'registry_device_id', v_registry_id),
            v_now);

    -- ---- 4. NOTIFY: device_policy push, same channel as lock/unlock ----
    PERFORM app_notify('device_policy',
        jsonb_build_object('device_id', COALESCE(v_registry_id, 0),
                           'version', 0,
                           'action', 'wipe_armed')::TEXT);

    RETURN jsonb_build_object(
        'result',             'armed',
        'wipe_requested',     'pending',
        'wipe_level',         p_level,
        'device_registry_id', COALESCE(v_registry_id, 0));
END;
$$ LANGUAGE plpgsql;
