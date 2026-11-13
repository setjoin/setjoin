-- migration_checkpoint_commit.sql: publish only a fully applied source checkpoint.
CREATE OR REPLACE FUNCTION migration_checkpoint_commit(
  p_job_id bigint,
  p_scope_key text,
  p_cursor_kind text,
  p_cursor_value jsonb,
  p_source_generation bigint,
  p_committed_count bigint
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_uid bigint;
  v_uid_validity bigint;
  v_resume_cursor jsonb;
  v_resume_uids jsonb;
BEGIN
  IF p_scope_key IS NULL OR p_scope_key = '' THEN
    RAISE EXCEPTION 'Invalid migration checkpoint scope' USING ERRCODE='BZ265';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.migration_source_instances
                  WHERE job_id=p_job_id AND generation=p_source_generation) THEN
    RAISE EXCEPTION 'Migration checkpoint source generation mismatch'
      USING ERRCODE='BZ267';
  END IF;

  -- Current binaries write uid; pre-V209 fixtures and binaries wrote lastUID.
  -- Validate either spelling before publishing it, and reject a mixed payload
  -- unless both fields describe the same checkpoint.
  IF p_cursor_kind = 'imap_uid' THEN
    IF jsonb_typeof(p_cursor_value) IS DISTINCT FROM 'object'
       OR NOT (p_cursor_value ? 'uidValidity')
       OR jsonb_typeof(p_cursor_value->'uidValidity') IS DISTINCT FROM 'number'
       OR (NOT (p_cursor_value ? 'uid') AND NOT (p_cursor_value ? 'lastUID'))
       OR ((p_cursor_value ? 'uid')
           AND jsonb_typeof(p_cursor_value->'uid') IS DISTINCT FROM 'number')
       OR ((p_cursor_value ? 'lastUID')
           AND jsonb_typeof(p_cursor_value->'lastUID') IS DISTINCT FROM 'number') THEN
      RAISE EXCEPTION 'Invalid IMAP checkpoint cursor' USING ERRCODE='BZ265';
    END IF;
    BEGIN
      v_uid := COALESCE(p_cursor_value->>'uid', p_cursor_value->>'lastUID')::bigint;
      v_uid_validity := (p_cursor_value->>'uidValidity')::bigint;
      IF v_uid < 0 OR v_uid > 4294967295
         OR v_uid_validity < 1 OR v_uid_validity > 4294967295
         OR ((p_cursor_value ? 'uid') AND (p_cursor_value ? 'lastUID')
             AND (p_cursor_value->>'uid')::bigint <> (p_cursor_value->>'lastUID')::bigint) THEN
        RAISE EXCEPTION 'Invalid IMAP checkpoint cursor' USING ERRCODE='BZ265';
      END IF;
    EXCEPTION
      WHEN invalid_text_representation OR numeric_value_out_of_range THEN
        RAISE EXCEPTION 'Invalid IMAP checkpoint cursor' USING ERRCODE='BZ265';
    END;

    -- Serialize with migration_orchestrate's resume_cursor deep merge. This
    -- preserves the legacy reader projection in the same transaction as the
    -- durable checkpoint publish, without a Go read-modify-write race.
    SELECT COALESCE(resume_cursor::jsonb, '{}'::jsonb)
      INTO v_resume_cursor
      FROM public.migration_jobs
     WHERE id = p_job_id
       FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Migration checkpoint source generation mismatch'
        USING ERRCODE='BZ267';
    END IF;
  END IF;

  INSERT INTO public.migration_checkpoints
    (job_id,scope_key,cursor_kind,cursor_value,source_generation,committed_count)
  VALUES (p_job_id,p_scope_key,p_cursor_kind,p_cursor_value,p_source_generation,p_committed_count)
  ON CONFLICT (job_id,scope_key,cursor_kind) DO UPDATE SET
    cursor_value=EXCLUDED.cursor_value,
    source_generation=EXCLUDED.source_generation,
    committed_count=GREATEST(public.migration_checkpoints.committed_count,
                             EXCLUDED.committed_count),
    committed_at=now();

  IF p_cursor_kind = 'imap_uid' THEN
    IF jsonb_typeof(v_resume_cursor->'uids') = 'object' THEN
      v_resume_uids := v_resume_cursor->'uids';
    ELSE
      -- An old resume_cursor may be the flat {"folder": uid} form. Fold
      -- those numeric entries into the structured projection before adding
      -- the newly committed scope, so enabling source identity loses none.
      SELECT COALESCE(jsonb_object_agg(entry.key, entry.value), '{}'::jsonb)
        INTO v_resume_uids
        FROM jsonb_each(v_resume_cursor) AS entry
       WHERE jsonb_typeof(entry.value) = 'number';
    END IF;
    UPDATE public.migration_jobs
       SET resume_cursor = jsonb_set(
         v_resume_cursor,
         '{uids}',
         v_resume_uids || jsonb_build_object(p_scope_key, v_uid),
         true
       )::text
     WHERE id = p_job_id;
  END IF;
END;
$$;

SELECT public.apply_worker_ownership('migration_checkpoint_commit(bigint,text,text,jsonb,bigint,bigint)'::regprocedure);

-- Current binaries carry the provider's durable scope separately from the
-- legacy projection scope (notably EWS folder ID versus display name). Keep the
-- six-argument function above for retained binaries; this v2 reducer performs
-- both writes under the same migration_jobs row lock.
CREATE OR REPLACE FUNCTION migration_checkpoint_commit_v2(
  p_job_id bigint,
  p_scope_key text,
  p_legacy_scope_key text,
  p_cursor_kind text,
  p_cursor_value jsonb,
  p_source_generation bigint,
  p_committed_count bigint
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_uid bigint;
  v_uid_validity bigint;
  v_delta text;
  v_resume_cursor jsonb;
  v_resume_values jsonb;
BEGIN
  IF p_scope_key IS NULL OR p_scope_key = ''
     OR p_legacy_scope_key IS NULL OR p_legacy_scope_key = '' THEN
    RAISE EXCEPTION 'Invalid migration checkpoint scope' USING ERRCODE='BZ265';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.migration_source_instances
                  WHERE job_id=p_job_id AND generation=p_source_generation) THEN
    RAISE EXCEPTION 'Migration checkpoint source generation mismatch'
      USING ERRCODE='BZ267';
  END IF;

  IF p_cursor_kind = 'imap_uid' THEN
    IF jsonb_typeof(p_cursor_value) IS DISTINCT FROM 'object'
       OR NOT (p_cursor_value ? 'uidValidity')
       OR jsonb_typeof(p_cursor_value->'uidValidity') IS DISTINCT FROM 'number'
       OR (NOT (p_cursor_value ? 'uid') AND NOT (p_cursor_value ? 'lastUID'))
       OR ((p_cursor_value ? 'uid') AND jsonb_typeof(p_cursor_value->'uid') IS DISTINCT FROM 'number')
       OR ((p_cursor_value ? 'lastUID') AND jsonb_typeof(p_cursor_value->'lastUID') IS DISTINCT FROM 'number') THEN
      RAISE EXCEPTION 'Invalid IMAP checkpoint cursor' USING ERRCODE='BZ265';
    END IF;
    BEGIN
      v_uid := COALESCE(p_cursor_value->>'uid', p_cursor_value->>'lastUID')::bigint;
      v_uid_validity := (p_cursor_value->>'uidValidity')::bigint;
      IF v_uid < 0 OR v_uid > 4294967295
         OR v_uid_validity < 1 OR v_uid_validity > 4294967295
         OR ((p_cursor_value ? 'uid') AND (p_cursor_value ? 'lastUID')
             AND (p_cursor_value->>'uid')::bigint <> (p_cursor_value->>'lastUID')::bigint) THEN
        RAISE EXCEPTION 'Invalid IMAP checkpoint cursor' USING ERRCODE='BZ265';
      END IF;
    EXCEPTION
      WHEN invalid_text_representation OR numeric_value_out_of_range THEN
        RAISE EXCEPTION 'Invalid IMAP checkpoint cursor' USING ERRCODE='BZ265';
    END;
  ELSIF p_cursor_kind IN ('ews_sync_state','m365_delta_link') THEN
    IF jsonb_typeof(p_cursor_value) IS DISTINCT FROM 'string' THEN
      RAISE EXCEPTION 'Invalid delta checkpoint cursor' USING ERRCODE='BZ265';
    END IF;
    v_delta := p_cursor_value #>> '{}';
    IF v_delta IS NULL OR v_delta = '' THEN
      RAISE EXCEPTION 'Invalid delta checkpoint cursor' USING ERRCODE='BZ265';
    END IF;
  ELSE
    RAISE EXCEPTION 'Invalid migration checkpoint kind' USING ERRCODE='BZ265';
  END IF;

  SELECT COALESCE(resume_cursor::jsonb, '{}'::jsonb)
    INTO v_resume_cursor
    FROM public.migration_jobs
   WHERE id = p_job_id
     FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Migration checkpoint source generation mismatch' USING ERRCODE='BZ267';
  END IF;

  INSERT INTO public.migration_checkpoints
    (job_id,scope_key,cursor_kind,cursor_value,source_generation,committed_count)
  VALUES (p_job_id,p_scope_key,p_cursor_kind,p_cursor_value,p_source_generation,p_committed_count)
  ON CONFLICT (job_id,scope_key,cursor_kind) DO UPDATE SET
    cursor_value=EXCLUDED.cursor_value,
    source_generation=EXCLUDED.source_generation,
    committed_count=GREATEST(public.migration_checkpoints.committed_count, EXCLUDED.committed_count),
    committed_at=now();

  IF p_cursor_kind = 'imap_uid' THEN
    IF jsonb_typeof(v_resume_cursor->'uids') = 'object' THEN
      v_resume_values := v_resume_cursor->'uids';
    ELSE
      SELECT COALESCE(jsonb_object_agg(entry.key, entry.value), '{}'::jsonb)
        INTO v_resume_values
        FROM jsonb_each(v_resume_cursor) AS entry
       WHERE jsonb_typeof(entry.value) = 'number';
    END IF;
    v_resume_cursor := jsonb_set(v_resume_cursor, '{uids}',
      v_resume_values || jsonb_build_object(p_legacy_scope_key, v_uid), true);
  ELSE
    IF jsonb_typeof(v_resume_cursor->'delta') = 'object' THEN
      v_resume_values := v_resume_cursor->'delta';
    ELSE
      v_resume_values := '{}'::jsonb;
    END IF;
    v_resume_cursor := jsonb_set(v_resume_cursor, '{delta}',
      v_resume_values || jsonb_build_object(p_legacy_scope_key, v_delta), true);
  END IF;

  UPDATE public.migration_jobs SET resume_cursor=v_resume_cursor::text WHERE id=p_job_id;
END;
$$;

SELECT public.apply_worker_ownership('migration_checkpoint_commit_v2(bigint,text,text,text,jsonb,bigint,bigint)'::regprocedure);
