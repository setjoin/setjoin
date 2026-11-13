-- ca_policy_impact.sql — CA-1 C4: read-only aggregate over ca_signin_log for a policy.
--
-- Returns two shapes depending on p_list:
--   NULL  → {window, window_has_data, matched, would_block, would_step_up, would_notify,
--             distinct_users, would_block_admins}
--   'blocked_users' → {users:[{id,address,is_admin}], shown, total,
--                       admin_users:[{id,address}]}  (admin_users UNCAPPED)
--
-- window_has_data distinguishes NO-DATA (young/empty log) from a true zero so the
-- UI can draw "NO DATA" instead of a confident "0 blocked".
--
-- would_block_admins: COUNT(DISTINCT user_id) among would_block rows whose user_id
-- appears in unexpired admin_role_assignments — mirrors the logic in ca_lockout_guard
-- but as a count, not a gate.
--
-- ponytail: STABLE + SECURITY DEFINER (like ca_lockout_guard) so it can read
--   user_group_members across RLS. No writes, no notify, no audit — read-only.
--
-- No BZ codes: read-only reducer; invalid parameter → standard PG '22023'
--   (invalid_parameter_value). BZ085 is allocated to ca_template_instantiate.

CREATE OR REPLACE FUNCTION ca_policy_impact(
    p_policy_id BIGINT,
    p_window    TEXT,      -- '24h' | '7d' | '30d'
    p_list      TEXT       -- NULL → summary; 'blocked_users' → user list
) RETURNS JSONB AS $$
DECLARE
    v_interval          INTERVAL;
    v_cutoff            TIMESTAMPTZ;
    v_window_has_data   BOOLEAN;
    v_matched           BIGINT;
    v_would_block       BIGINT;
    v_would_step_up     BIGINT;
    v_would_notify      BIGINT;
    v_distinct_users    BIGINT;
    v_would_block_admins BIGINT;
    v_cap               INT := 200;
    v_total             BIGINT;
    v_users             JSONB;
    v_admin_users       JSONB;
BEGIN
    -- Parse window (22023 = invalid_parameter_value; no BZ code for read-only reducers)
    IF p_window = '24h' THEN
        v_interval := INTERVAL '24 hours';
    ELSIF p_window = '7d' THEN
        v_interval := INTERVAL '7 days';
    ELSIF p_window = '30d' THEN
        v_interval := INTERVAL '30 days';
    ELSE
        RAISE EXCEPTION 'unrecognised window %', p_window
            USING ERRCODE = '22023',
                  HINT = 'p_window must be one of: 24h, 7d, 30d';
    END IF;
    v_cutoff := now() - v_interval;

    -- Distinguish no-data from true-zero (Spec: UI uses this for the NO-DATA state)
    SELECT EXISTS(
        SELECT 1 FROM ca_signin_log
        WHERE matched_policy_id = p_policy_id
          AND occurred_at >= v_cutoff
    ) INTO v_window_has_data;

    IF p_list IS NULL THEN
        -- Summary path: aggregate counts
        SELECT
            COUNT(*)                                                         AS matched,
            COUNT(*) FILTER (WHERE would_decision = 'block')                AS would_block,
            COUNT(*) FILTER (WHERE would_decision = 'step_up')              AS would_step_up,
            COUNT(*) FILTER (WHERE would_decision = 'notify')               AS would_notify,
            COUNT(DISTINCT user_id)                                          AS distinct_users,
            -- admins who WOULD be blocked: DISTINCT user_ids with would_block rows
            -- that are also in unexpired admin_role_assignments
            COUNT(DISTINCT CASE
                WHEN would_decision = 'block'
                     AND EXISTS (
                         SELECT 1 FROM admin_role_assignments ara
                         WHERE ara.user_id = l.user_id
                           AND (ara.expires_at IS NULL OR ara.expires_at > now())
                     )
                THEN l.user_id
            END)                                                             AS would_block_admins
        INTO v_matched, v_would_block, v_would_step_up, v_would_notify,
             v_distinct_users, v_would_block_admins
        FROM ca_signin_log l
        WHERE matched_policy_id = p_policy_id
          AND occurred_at >= v_cutoff;

        -- Degrade to zeros if no data (already handled by aggregate returning 0, but be explicit)
        IF NOT v_window_has_data THEN
            v_matched := 0; v_would_block := 0; v_would_step_up := 0;
            v_would_notify := 0; v_distinct_users := 0; v_would_block_admins := 0;
        END IF;

        RETURN jsonb_build_object(
            'window',             p_window,
            'window_has_data',    v_window_has_data,
            'matched',            v_matched,
            'would_block',        v_would_block,
            'would_step_up',      v_would_step_up,
            'would_notify',       v_would_notify,
            'distinct_users',     v_distinct_users,
            'would_block_admins', v_would_block_admins
        );

    ELSIF p_list = 'blocked_users' THEN
        -- Distinct users who would be blocked by this policy in the window
        SELECT COUNT(DISTINCT user_id)
        INTO v_total
        FROM ca_signin_log
        WHERE matched_policy_id = p_policy_id
          AND occurred_at >= v_cutoff
          AND would_decision = 'block';

        -- Capped list with is_admin flag
        SELECT jsonb_agg(row ORDER BY row->>'address')
        INTO v_users
        FROM (
            SELECT jsonb_build_object(
                'id',       u.id,
                'address',  u.email,
                'is_admin', EXISTS (
                    SELECT 1 FROM admin_role_assignments ara
                    WHERE ara.user_id = u.id
                      AND (ara.expires_at IS NULL OR ara.expires_at > now())
                )
            ) AS row
            FROM (
                SELECT DISTINCT l.user_id
                FROM ca_signin_log l
                WHERE l.matched_policy_id = p_policy_id
                  AND l.occurred_at >= v_cutoff
                  AND l.would_decision = 'block'
                ORDER BY l.user_id
                LIMIT v_cap
            ) sub
            JOIN users u ON u.id = sub.user_id
        ) t;

        -- Admin users UNCAPPED (so a 201st admin is never hidden behind the cap)
        SELECT jsonb_agg(jsonb_build_object('id', u.id, 'address', u.email) ORDER BY u.id)
        INTO v_admin_users
        FROM (
            SELECT DISTINCT l.user_id
            FROM ca_signin_log l
            WHERE l.matched_policy_id = p_policy_id
              AND l.occurred_at >= v_cutoff
              AND l.would_decision = 'block'
        ) sub
        JOIN users u ON u.id = sub.user_id
        WHERE EXISTS (
            SELECT 1 FROM admin_role_assignments ara
            WHERE ara.user_id = sub.user_id
              AND (ara.expires_at IS NULL OR ara.expires_at > now())
        );

        RETURN jsonb_build_object(
            'users',       COALESCE(v_users, '[]'::jsonb),
            'shown',       LEAST(v_total, v_cap),
            'total',       v_total,
            'admin_users', COALESCE(v_admin_users, '[]'::jsonb)
        );

    ELSE
        RAISE EXCEPTION 'unrecognised p_list value %', p_list
            USING ERRCODE = '22023',
                  HINT = 'p_list must be NULL or ''blocked_users''';
    END IF;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public;
