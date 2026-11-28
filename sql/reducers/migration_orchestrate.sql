-- migration_orchestrate.sql: A — atomic migration phase state machine.
-- Replaces ~35 scattered pool.Exec calls in internal/migration/orchestrator.go.
-- Every mutation of a migration_jobs row happens here, in ONE transaction, so a
-- crash can never strand status against cursor/progress/error-log. resume_cursor
-- (a TEXT column holding {"uids":{...},"delta":{...}}) is merged with jsonb
-- operators in SQL — no Go read-modify-write race (pause + delta-save could
-- previously lose a cursor). Go keeps connector/MinIO I/O and webhook dispatch.
--
-- Ownership (R1/R3): the job id IS the ownership key (the gateway resolves the
-- caller's job before invoking the orchestrator); every statement keys on
-- p_job_id and the row is SELECT ... FOR UPDATE first to serialize concurrent
-- pause/progress and lock the transition.
CREATE OR REPLACE FUNCTION migration_orchestrate(
    p_job_id BIGINT,
    p_phase  TEXT,
    p_patch  JSONB
) RETURNS JSONB AS $$
DECLARE
    v_status   TEXT;
    v_cursor   JSONB;
    v_progress JSONB;
    v_errors   JSONB;
    v_new      TEXT;
    v_user_id  BIGINT;
    v_mailbox_id BIGINT;
    v_event_type TEXT;
    v_publication_enrolled BOOLEAN := FALSE;
    v_domain_id BIGINT;
    v_active_domain INTEGER;
BEGIN
    IF p_patch IS NULL THEN p_patch := '{}'::jsonb; END IF;

    -- R1/R3: load + lock the job; ownership is the job id itself (gateway-scoped).
    SELECT status,
           COALESCE(resume_cursor::jsonb, '{}'::jsonb),
           COALESCE(progress, '{}'::jsonb),
           COALESCE(error_log, '[]'::jsonb),
           user_id,target_mailbox_id
      INTO v_status, v_cursor, v_progress, v_errors, v_user_id, v_mailbox_id
      FROM migration_jobs
     WHERE id = p_job_id
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Migration job not found'
            USING ERRCODE='BZ049',
                  HINT = jsonb_build_object('type','job_not_found','job_id',p_job_id)::text;
    END IF;

    -- Merge cursor (uids + delta) — deep, additive (no lost-update).
    IF p_patch ? 'cursor_uids' THEN
        v_cursor := jsonb_set(v_cursor, '{uids}',
            COALESCE(v_cursor->'uids','{}'::jsonb) || (p_patch->'cursor_uids'), TRUE);
    END IF;
    IF p_patch ? 'delta' THEN
        v_cursor := jsonb_set(v_cursor, '{delta}',
            COALESCE(v_cursor->'delta','{}'::jsonb) || (p_patch->'delta'), TRUE);
    END IF;
    IF p_patch ? 'progress' THEN
        v_progress := v_progress || (p_patch->'progress');
    END IF;
    IF p_patch ? 'errors' THEN
        -- cap at 1000 entries (mirrors the old appendError sentinel behaviour).
        IF jsonb_array_length(v_errors) < 1000 THEN
            v_errors := v_errors || (p_patch->'errors');
        END IF;
    END IF;

    -- Resolve target status from (current, phase). Terminal = completed/cancelled/failed.
    v_new := v_status;
    CASE p_phase
        WHEN 'start' THEN
            IF v_status IN ('completed','cancelled','failed') THEN
                RAISE EXCEPTION 'Cannot start a terminal job'
                    USING ERRCODE='BZ048',
                          HINT=jsonb_build_object('from',v_status,'phase',p_phase)::text;
            END IF;
            SELECT COALESCE(m.domain_id, u.domain_id)
              INTO v_domain_id
              FROM migration_jobs j
              JOIN users u ON u.id = j.user_id
              LEFT JOIN mailboxes m ON m.id = j.target_mailbox_id
             WHERE j.id = p_job_id;
            PERFORM pg_advisory_xact_lock(hashtextextended('migration-domain:' || v_domain_id::TEXT, 0));
            SELECT count(*) INTO v_active_domain
              FROM migration_jobs j
              JOIN users u ON u.id = j.user_id
              LEFT JOIN mailboxes m ON m.id = j.target_mailbox_id
             WHERE j.id <> p_job_id
               AND COALESCE(m.domain_id, u.domain_id) = v_domain_id
               AND j.status IN ('fetching','importing');
            IF v_active_domain >= 8 THEN
                RAISE EXCEPTION 'Migration concurrency limit reached'
                    USING ERRCODE='BZ048',
                          HINT=jsonb_build_object('scope','domain','limit',8)::text;
            END IF;
            v_new := 'fetching';
        WHEN 'resume' THEN
            IF v_status <> 'paused' THEN
                RAISE EXCEPTION 'Resume requires paused'
                    USING ERRCODE='BZ048', HINT=jsonb_build_object('from',v_status,'phase',p_phase)::text;
            END IF;
            v_new := 'fetching';
        WHEN 'progress' THEN
            v_new := v_status;       -- no status change
        WHEN 'pause' THEN
            IF v_status NOT IN ('fetching','importing') THEN
                RAISE EXCEPTION 'Pause requires an active phase'
                    USING ERRCODE='BZ048', HINT=jsonb_build_object('from',v_status,'phase',p_phase)::text;
            END IF;
            v_new := 'paused';
        WHEN 'cancel' THEN
            IF v_status IN ('completed','cancelled','failed') THEN
                RAISE EXCEPTION 'Cannot cancel a terminal job'
                    USING ERRCODE='BZ048', HINT=jsonb_build_object('from',v_status,'phase',p_phase)::text;
            END IF;
            v_new := 'cancelled';
        WHEN 'complete' THEN
            IF v_status IN ('completed','cancelled','failed') THEN
                RAISE EXCEPTION 'Cannot complete a terminal job'
                    USING ERRCODE='BZ048', HINT=jsonb_build_object('from',v_status,'phase',p_phase)::text;
            END IF;
            v_new := 'completed';
        WHEN 'fail' THEN
            v_new := 'failed';
        ELSE
            RAISE EXCEPTION 'Unknown phase'
                USING ERRCODE='BZ050', HINT=jsonb_build_object('phase',p_phase)::text;
    END CASE;

    UPDATE migration_jobs SET
        status            = v_new,
        progress          = v_progress,
        error_log         = v_errors,
        resume_cursor     = CASE WHEN v_new='completed' THEN NULL ELSE v_cursor::text END,
        started_at        = CASE WHEN p_phase='start' THEN COALESCE(started_at, now()) ELSE started_at END,
        completed_at      = CASE WHEN v_new='completed' THEN now() ELSE completed_at END,
        source_config_enc = CASE WHEN v_new IN ('completed','cancelled') THEN NULL ELSE source_config_enc END
    WHERE id = p_job_id;

    IF v_new='completed' THEN
        v_event_type := 'migration.completed';
    ELSIF v_new='failed' THEN
        v_event_type := 'migration.failed';
    END IF;
    IF v_event_type IS NOT NULL THEN
        v_publication_enrolled := webhook_migration_terminal_publish(p_job_id,v_event_type);
    END IF;

    RETURN jsonb_build_object('status', v_new, 'resume_cursor',
        CASE WHEN v_new='completed' THEN NULL ELSE v_cursor END,
        'event_type',v_event_type,
        'subject_user_id',v_user_id,
        'subject_mailbox_id',v_mailbox_id,
        'publication_enrolled',v_publication_enrolled);
END;
$$ LANGUAGE plpgsql;

-- Bulk recovery: mark non-terminal jobs failed on gateway restart; return their
-- ids so the Go layer can dispatch migration.failed webhooks AFTER commit.
-- The CTE captures the affected ids in one statement (UPDATE ... RETURNING into a
-- scalar array is impossible across multiple rows).
CREATE OR REPLACE FUNCTION migration_recover_stuck() RETURNS JSONB AS $$
DECLARE
    v_ids BIGINT[] := '{}'::bigint[];
    v_events JSONB := '[]'::jsonb;
    v_row RECORD;
    v_enrolled BOOLEAN;
BEGIN
    FOR v_row IN
        UPDATE migration_jobs
           SET status='failed',
               error_log = COALESCE(error_log,'[]'::jsonb)
                           || '["startup_recovery: gateway restart during migration"]'::jsonb
         WHERE status IN ('fetching','importing','paused')
         RETURNING id,user_id,target_mailbox_id
    LOOP
        v_enrolled := webhook_migration_terminal_publish(v_row.id,'migration.failed');
        v_ids := array_append(v_ids,v_row.id);
        v_events := v_events || jsonb_build_array(jsonb_build_object(
            'job_id',v_row.id,
            'event_type','migration.failed',
            'subject_user_id',v_row.user_id,
            'subject_mailbox_id',v_row.target_mailbox_id,
            'publication_enrolled',v_enrolled
        ));
    END LOOP;
    RETURN jsonb_build_object('ids', to_jsonb(v_ids), 'terminal_events',v_events);
END;
$$ LANGUAGE plpgsql;
