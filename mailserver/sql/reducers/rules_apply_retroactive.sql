-- rules_apply_retroactive.sql: enqueue an async "apply rule(s) to existing mail"
-- sweep. The heavy work (batching historical messages through apply_rules) runs
-- later in the scheduled_actions dispatcher via the `rules_retro` handler — this
-- reducer only validates + enqueues, so the HTTP request returns immediately (202).
--
-- p_mailbox_id : the caller's OWN mailbox (resolved from auth in Go — R1/R2).
-- p_rule_id    : NULL = every enabled rule; non-NULL = that single rule, which
--                MUST belong to this mailbox and be a non-transport rule.
-- p_window     : '90d' | '1y' | 'all' — how far back to sweep.
--
-- Dedup (spec): one in-flight sweep per (mailbox, rule). A dedup_key is UNIQUE
-- (partial index scheduled_actions_dedup_idx). If a pending/processing sweep for
-- this key already exists we return it instead of stacking a second; terminal
-- (done/failed) rows for the key are cleared first so a re-run can reuse the key.
CREATE OR REPLACE FUNCTION rules_apply_retroactive(
    p_mailbox_id BIGINT,
    p_rule_id    BIGINT DEFAULT NULL,
    p_window     TEXT DEFAULT '90d'
) RETURNS UUID AS $$
DECLARE
    v_dedup    TEXT;
    v_existing UUID;
    v_id       UUID;
BEGIN
    IF p_mailbox_id IS NULL THEN
        RAISE EXCEPTION 'mailbox is required'
            USING ERRCODE = 'BZ120', HINT = jsonb_build_object('type','mailbox_required')::TEXT;
    END IF;

    IF p_window IS NULL OR p_window NOT IN ('90d','1y','all') THEN
        RAISE EXCEPTION 'invalid retro window %', p_window
            USING ERRCODE = 'BZ120',
                  HINT = jsonb_build_object('type','bad_window','window',p_window)::TEXT;
    END IF;

    -- Single-rule apply: the rule must be owned by this mailbox (R1) and be a
    -- per-mailbox (non-transport) rule — a user cannot retro-apply someone else's
    -- rule nor an org-wide transport rule through this self-service path.
    IF p_rule_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM rules
            WHERE id = p_rule_id
              AND mailbox_id = p_mailbox_id
              AND is_transport_rule = FALSE
        ) THEN
            RAISE EXCEPTION 'rule % not found for mailbox %', p_rule_id, p_mailbox_id
                USING ERRCODE = 'BZ121', HINT = jsonb_build_object('type','rule_not_found')::TEXT;
        END IF;
    END IF;

    v_dedup := 'rules_retro:' || p_mailbox_id || ':' || COALESCE(p_rule_id::TEXT, 'all');

    -- Already in flight for this (mailbox, rule) → hand back the existing action.
    SELECT id INTO v_existing
    FROM scheduled_actions
    WHERE dedup_key = v_dedup
      AND mailbox_id = p_mailbox_id
      AND status IN ('pending','processing')
    LIMIT 1;
    IF v_existing IS NOT NULL THEN
        RETURN v_existing;
    END IF;

    -- Free the unique dedup_key from any prior terminal run so a fresh sweep can enqueue.
    DELETE FROM scheduled_actions
    WHERE dedup_key = v_dedup
      AND mailbox_id = p_mailbox_id
      AND status IN ('done','failed');

    INSERT INTO scheduled_actions (action_kind, fire_at, payload, mailbox_id, dedup_key)
    VALUES ('rules_retro', now(),
            jsonb_build_object('rule_id', p_rule_id, 'window', p_window),
            p_mailbox_id, v_dedup)
    RETURNING id INTO v_id;

    RETURN v_id;
END;
$$ LANGUAGE plpgsql;
