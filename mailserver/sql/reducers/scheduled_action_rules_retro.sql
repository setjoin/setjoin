-- scheduled_action_rules_retro.sql: the `rules_retro` handler. Runs the deferred
-- "apply rule(s) to existing mail" sweep enqueued by rules_apply_retroactive.
-- Batches the mailbox's historical messages in the requested window through
-- apply_rules with p_organize_only=TRUE (send-time actions are suppressed there,
-- so no historical mail is ever re-sent) and, when a single rule was requested,
-- the p_rule_id filter. Caps the batch and reports an honest truncation flag.
--
-- payload = {rule_id (nullable), window '90d'|'1y'|'all'}; mailbox is the owner column.
-- The processed count + truncated flag are written back onto the action's own
-- payload so the Go status endpoint can surface "applied to N messages".
-- Returns the dispatcher status JSON {status:'ok'|..., note, processed, truncated}.
CREATE OR REPLACE FUNCTION scheduled_action_rules_retro(p_action scheduled_actions)
RETURNS JSONB AS $$
DECLARE
    v_mailbox_id BIGINT := p_action.mailbox_id;
    v_rule_id    BIGINT;
    v_window     TEXT;
    v_cutoff     TIMESTAMPTZ;
    v_msg        RECORD;
    v_seen       INT := 0;
    v_processed  INT := 0;
    v_truncated  BOOLEAN := FALSE;
    c_cap CONSTANT INT := 5000;  -- ponytail: fixed cap; make it a system_config knob if a tenant needs deeper sweeps
BEGIN
    IF v_mailbox_id IS NULL THEN
        RETURN jsonb_build_object('status','ok','note','no mailbox','processed',0,'truncated',false);
    END IF;

    v_rule_id := NULLIF(p_action.payload->>'rule_id','')::BIGINT;
    v_window  := COALESCE(p_action.payload->>'window','90d');

    v_cutoff := CASE v_window
        WHEN '90d' THEN now() - interval '90 days'
        WHEN '1y'  THEN now() - interval '1 year'
        WHEN 'all' THEN NULL
        ELSE now() - interval '90 days'
    END;

    -- Sweep newest-first; pull one past the cap to detect truncation honestly.
    FOR v_msg IN
        SELECT id, received_at
        FROM messages
        WHERE mailbox_id = v_mailbox_id
          AND (v_cutoff IS NULL OR received_at >= v_cutoff)
        ORDER BY received_at DESC
        LIMIT c_cap + 1
    LOOP
        v_seen := v_seen + 1;
        IF v_seen > c_cap THEN
            v_truncated := TRUE;
            EXIT;
        END IF;
        -- organize_only=TRUE: send-time actions are no-ops (no mass re-send).
        PERFORM apply_rules(v_msg.id, v_msg.received_at, v_mailbox_id, 'server', TRUE, v_rule_id);
        v_processed := v_processed + 1;
    END LOOP;

    -- Bump email state once so open clients refresh (apply_rules also pushes per
    -- mutating action; this covers the visible-change guarantee even for a 0-action sweep).
    IF v_processed > 0 THEN
        PERFORM notify_state_change(v_mailbox_id, NULL);
    END IF;

    -- Persist the outcome onto the action so the status read path can report it.
    UPDATE scheduled_actions
       SET payload = payload || jsonb_build_object('processed', v_processed, 'truncated', v_truncated)
     WHERE id = p_action.id;

    RETURN jsonb_build_object(
        'status','ok',
        'note', format('applied to %s message(s)%s', v_processed,
                       CASE WHEN v_truncated THEN ' (truncated at cap)' ELSE '' END),
        'processed', v_processed,
        'truncated', v_truncated);
END;
$$ LANGUAGE plpgsql;
