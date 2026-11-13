-- mailserver/sql/reducers/drive_maintenance_sweep.sql
-- pool). P5 Task 6 adds export-grant pruning: the durable e-sig record lives
-- in drive_audit_log forever (export.approve/deny/download), so pruning the
-- operational drive_export_grants row loses nothing. P6 Task 4 adds the
-- two-level trash cadence; P6 Task 5 adds audit-alarm evaluation (no new
-- worker — rides this same tick). Task 10 (C6 part 1) extracted the alarm
-- leg into its own drive_alarm_evaluate() reducer. Task 11 (C6 part 2)
-- measured the remaining legs against the deletion test (CONTEXT.md
-- §Measured duplication): journal/claims/grants are each a single DELETE
-- statement (grants' WHERE just wraps onto multiple lines) — a shallow
-- split, so they stay inline, ponytail-annotated below. The trash cadence
-- (age→destroy) is two loops + a computed retry-until-no-progress pass —
-- a real, independently testable body — so it moved to
-- drive_sweep_age_trash(). WORM retries + tmp-reap stay Go-side (Task 21).
-- Chat A2 Task 6 adds the orphan-chunk reaper leg: trg_drive_chunk_zero_ref_fn
-- (V114) only enqueues onto drive_chunk_gc_queue on an UPDATE OF ref_count,
-- so a chunk that is registered and STAYS at ref_count=0 (an
-- uploaded-but-never-sent chat attachment; a pre-existing drive bug,
-- codebase-review #4) never gets queued and leaks forever, unmetered. This
-- leg enqueues those onto the SAME gc_queue rail once the last
-- proof-of-possession claim has expired — the existing worker-side
-- gcChunks/gcDeleteOne (worker.go, untouched) does the actual DB-row +
-- storage-object delete, re-verifying ref_count=0 atomically. A
-- version-referenced chunk (ref_count>0) is never selected.
CREATE OR REPLACE FUNCTION drive_maintenance_sweep() RETURNS JSONB AS $$
DECLARE
  v_journal INT; v_access_journal INT; v_claims INT; v_grants_pruned INT;
  v_aged INT; v_destroyed INT;
  v_fired INT; v_orphan_chunks INT;
BEGIN
  -- ponytail: 1-line DELETE, inline — its own reducer would be a shallower
  -- interface than the body it wraps.
  DELETE FROM drive_changes WHERE at < now() - interval '90 days';
  GET DIAGNOSTICS v_journal = ROW_COUNT;

  WITH doomed AS MATERIALIZED (
    SELECT space_id,max(cursor) AS floor FROM public.drive_access_invalidations
     WHERE created_at<now()-interval '90 days' GROUP BY space_id
  ), floors AS (
    UPDATE public.drive_acl_generations g
       SET retained_after_cursor=GREATEST(g.retained_after_cursor,d.floor)
      FROM doomed d WHERE g.space_id=d.space_id RETURNING g.space_id
  )
  DELETE FROM public.drive_access_invalidations i
   USING public.drive_acl_generations g
   WHERE i.space_id=g.space_id AND i.cursor<g.retained_after_cursor;
  GET DIAGNOSTICS v_access_journal=ROW_COUNT;

  -- ponytail: single INSERT...SELECT, inline — reuses drive_chunk_gc_queue,
  -- no new deletion path. Order vs. the claims DELETE below doesn't matter:
  -- this only cares whether a NON-expired claim exists, which that DELETE
  -- (it only removes expired ones) never changes.
  INSERT INTO public.drive_chunk_gc_queue (scope_key, sha256)
  SELECT c.scope_key, c.sha256
    FROM public.drive_chunks c
   WHERE c.ref_count = 0
     AND NOT EXISTS (
       SELECT 1 FROM public.drive_upload_claims cl
        WHERE cl.scope_key = c.scope_key AND cl.sha256 = c.sha256
          AND cl.claimed_at >= now() - interval '7 days')
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS v_orphan_chunks = ROW_COUNT;

  -- ponytail: 1-line DELETE, inline (same reasoning).
  DELETE FROM drive_upload_claims WHERE claimed_at < now() - interval '7 days';
  GET DIAGNOSTICS v_claims = ROW_COUNT;
  -- ponytail: still a single DELETE statement (the WHERE just wraps across
  -- lines for the two-branch OR) — extracting it would be a shallow split.
  DELETE FROM drive_export_grants
   WHERE (consumed_at IS NOT NULL AND consumed_at < now() - interval '30 days')
      OR (consumed_at IS NULL AND expires_at < now() - interval '7 days');
  GET DIAGNOSTICS v_grants_pruned = ROW_COUNT;

  -- ── two-level trash cadence (P6 Task 4, spec §3.5) ──────────────────────
  -- Task 11: the age→destroy cadence itself now lives in
  -- drive_sweep_age_trash() — a real, independently testable body (two
  -- loops + a retry-until-no-progress pass), unlike the legs above.
  SELECT p_aged, p_destroyed INTO v_aged, v_destroyed FROM drive_sweep_age_trash();

  -- ── audit-alarm evaluation (P6 Task 5, spec §9.3) ───────────────────────
  -- Task 10: the evaluator itself now lives in drive_alarm_evaluate().
  v_fired := drive_alarm_evaluate();

  RETURN jsonb_build_object('journalPruned', v_journal,
                            'accessJournalPruned',v_access_journal,'claimsPruned', v_claims,
                            'grantsPruned', v_grants_pruned,
                            'trashAged', v_aged, 'trashDestroyed', v_destroyed,
                            'alarmsFired', v_fired, 'orphanChunksQueued', v_orphan_chunks);
END;
$$ LANGUAGE plpgsql;
