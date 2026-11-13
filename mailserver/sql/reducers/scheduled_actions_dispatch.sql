-- scheduled_actions_dispatch.sql: the kind-agnostic dispatcher. Claims due,
-- pending actions (FOR UPDATE SKIP LOCKED + status='pending' guard), runs the
-- per-kind handler, applies the §5 status machine, and appends scheduled_action_log.
-- NEVER inspects payload; NEVER edited to add a kind (extend run_scheduled_action's
-- switch + add a handler reducer).
--
-- Role model (spec §3): run by the Go cron worker on its privileged connection.
-- NO SECURITY DEFINER / BYPASSRLS — the worker's connection is the privilege
-- boundary; this repo enforces R4 via parameter propagation in user-action
-- reducers, not native RLS, so there are no per-user policies for the dispatcher
-- to bypass.

-- Optimistic claim: losers get zero rows. The status='pending' guard inside the
-- inner SELECT + FOR UPDATE SKIP LOCKED guarantees two concurrent workers never
-- claim the same row (exactly-once claim).
CREATE OR REPLACE FUNCTION claim_scheduled_actions(p_worker_id TEXT, p_batch INT DEFAULT 100)
RETURNS SETOF scheduled_actions AS $$
BEGIN
    RETURN QUERY
    UPDATE scheduled_actions
    SET status = 'processing',
        locked_until = now() + interval '2 minutes',
        locked_by = p_worker_id,
        attempts = attempts + 1,
        updated_at = now()
    WHERE id IN (
        SELECT sa.id FROM scheduled_actions sa
        WHERE sa.status = 'pending' AND sa.fire_at <= now()
        ORDER BY sa.fire_at
        FOR UPDATE SKIP LOCKED
        LIMIT GREATEST(p_batch, 1)
    )
    RETURNING *;
END;
$$ LANGUAGE plpgsql;

-- Crash recovery: a processing row whose lease expired → back to pending (logged).
-- Safe to re-run because the egress handler (send) is idempotent via dedup_key.
CREATE OR REPLACE FUNCTION reclaim_expired_scheduled_actions()
RETURNS SETOF UUID AS $$
DECLARE
    v_row scheduled_actions;
BEGIN
    FOR v_row IN
        UPDATE scheduled_actions
        SET status = 'pending', locked_until = NULL, locked_by = NULL, updated_at = now()
        WHERE status = 'processing' AND locked_until < now()
        RETURNING *
    LOOP
        INSERT INTO scheduled_action_log (action_id, from_status, to_status, worker, outcome, note)
        VALUES (v_row.id, 'processing', 'pending', v_row.locked_by, 'expired',
                'lease expired; reclaimed');
        RETURN NEXT v_row.id;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Thin router: the ONLY place that knows kind→handler. Adding a kind edits this
-- switch + adds a handler reducer. Returns the handler's status JSON ({status,note}).
--
-- Test hook: a payload carrying `_test_outcome` short-circuits to that outcome
-- ('retry' | 'permanent_fail') WITHOUT invoking a handler. This lets the retry /
-- terminal-failure policy be exercised deterministically (scheduled_actions_retry.pg)
-- without coupling the test to any one handler's failure modes. Production payloads
-- never set `_test_outcome`.
CREATE OR REPLACE FUNCTION run_scheduled_action(p_action scheduled_actions)
RETURNS JSONB AS $$
BEGIN
    IF p_action.payload ? '_test_outcome' THEN
        RETURN jsonb_build_object('status', p_action.payload->>'_test_outcome',
                                  'note', 'test hook');
    END IF;

    CASE p_action.action_kind
        WHEN 'send'        THEN RETURN scheduled_action_send(p_action);
        WHEN 'snooze'      THEN RETURN scheduled_action_snooze(p_action);
        WHEN 'remind'      THEN RETURN scheduled_action_remind(p_action);
        WHEN 'dsn'         THEN RETURN scheduled_action_dsn(p_action);
        WHEN 'rules_retro' THEN RETURN scheduled_action_rules_retro(p_action);
        WHEN 'chat_send'   THEN RETURN scheduled_action_chat_send(p_action);
        ELSE RAISE EXCEPTION 'Unknown action_kind %', p_action.action_kind
            USING ERRCODE = 'BZ036',
                  HINT = jsonb_build_object('type','bad_action_kind',
                                            'kind', p_action.action_kind)::TEXT;
    END CASE;
END;
$$ LANGUAGE plpgsql;

-- The cron entry-point: reclaim, claim a batch, run each, apply the §5 status
-- machine. Returns the count of actions that completed (status='done') this tick.
--
-- Retry / terminal-failure policy (spec §5):
--   * handler 'ok'             → terminal done.
--   * handler 'permanent_fail' → terminal failed immediately (no re-queue).
--   * handler 'retry' / raised exception:
--       - attempts >= MAX_ATTEMPTS (5) → terminal failed (exhausted).
--       - else re-pending with fire_at = now() + backoff(attempts), where
--         backoff = LEAST(interval '1 minute' * 2^attempts, interval '1 hour')
--         (exponential, capped). attempts was already incremented by the claim.
CREATE OR REPLACE FUNCTION dispatch_scheduled_actions(p_worker_id TEXT DEFAULT 'cron', p_batch INT DEFAULT 100)
RETURNS INT AS $$
DECLARE
    v_action     scheduled_actions;
    v_result     JSONB;
    v_status     TEXT;
    v_done       INT := 0;
    v_backoff    INTERVAL;
    c_max_attempts CONSTANT INT := 5;
BEGIN
    PERFORM reclaim_expired_scheduled_actions();

    FOR v_action IN SELECT * FROM claim_scheduled_actions(p_worker_id, p_batch) LOOP
        INSERT INTO scheduled_action_log (action_id, from_status, to_status, worker, outcome)
        VALUES (v_action.id, 'pending', 'processing', p_worker_id, 'claimed');

        BEGIN
            v_result := run_scheduled_action(v_action);
        EXCEPTION WHEN OTHERS THEN
            v_result := jsonb_build_object('status', 'retry', 'note', SQLERRM);
        END;

        v_status := v_result->>'status';

        IF v_status = 'ok' THEN
            UPDATE scheduled_actions
               SET status='done', locked_until=NULL, locked_by=NULL, updated_at=now()
             WHERE id = v_action.id;
            INSERT INTO scheduled_action_log (action_id, from_status, to_status, worker, outcome, note)
            VALUES (v_action.id, 'processing', 'done', p_worker_id, 'done', v_result->>'note');
            v_done := v_done + 1;

        ELSIF v_status = 'permanent_fail' OR v_action.attempts >= c_max_attempts THEN
            -- Terminal failure: a permanent error, or retries exhausted.
            UPDATE scheduled_actions
               SET status='failed', last_error = v_result->>'note',
                   locked_until=NULL, locked_by=NULL, updated_at=now()
             WHERE id = v_action.id;
            INSERT INTO scheduled_action_log (action_id, from_status, to_status, worker, outcome, note)
            VALUES (v_action.id, 'processing', 'failed', p_worker_id, 'failed',
                    COALESCE(v_result->>'note',
                             CASE WHEN v_status='permanent_fail' THEN 'permanent failure'
                                  ELSE 'max attempts exhausted' END));

        ELSE
            -- Transient failure: re-queue with exponential, capped backoff.
            v_backoff := LEAST(interval '1 minute' * power(2, v_action.attempts), interval '1 hour');
            UPDATE scheduled_actions
               SET status='pending', fire_at = now() + v_backoff,
                   last_error = v_result->>'note',
                   locked_until=NULL, locked_by=NULL, updated_at=now()
             WHERE id = v_action.id;
            INSERT INTO scheduled_action_log (action_id, from_status, to_status, worker, outcome, note)
            VALUES (v_action.id, 'processing', 'pending', p_worker_id, 'retry', v_result->>'note');
        END IF;
    END LOOP;
    RETURN v_done;
END;
$$ LANGUAGE plpgsql;
