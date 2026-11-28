-- mailserver/sql/reducers/drive_audit_query.sql
-- the per-space HMAC chain. Powers the admin console AND the CSV export
-- (Go Task 11) — ONE query path so they can never disagree. Session/timeline
-- grouping is UI-ONLY (spec §14 guardrail): this reducer always returns raw
-- per-access rows, never collapsed.
--
-- AUTOPLAN batch-2 #4: the drive.view arm uses drive_has_admin_perm (the
-- V114 §B worker-owned DEFINER helper), not an inline admin-table EXISTS —
-- an inline EXISTS against admin_role_assignments/admin_role_groups fails
-- closed for a non-member admin once FORCE RLS binds (this reducer is
-- invoker rights with no admin-table read policy for arbitrary app-role
-- users). Root governance goes through the canonical compatibility adapter.
CREATE OR REPLACE FUNCTION drive_audit_query(
  p_user_id   bigint,
  p_space_id  bigint,
  p_actor     bigint,
  p_action    text,
  p_from      timestamptz,
  p_to        timestamptz,
  p_q         text,
  p_max       int DEFAULT 500,
  p_before_id bigint DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
  v_cap   int := LEAST(GREATEST(COALESCE(p_max, 500), 1), 1000);
  v_q     text;
  v_items jsonb;
  v_n     int;
BEGIN
  IF p_space_id IS NULL THEN
    RAISE EXCEPTION 'drive: space required' USING ERRCODE = 'BZ141',
      HINT = '{"type":"invalidArguments","detail":"space is required"}';
  END IF;
  -- Canonical view_audit on any visible anchor, or the metadata-only admin arm.
  IF NOT public.drive_runtime_has_space_root_capability(
       p_user_id,p_space_id,'view_audit')
     AND NOT public.drive_has_admin_perm(p_user_id, 'drive.view')
  THEN
    RAISE EXCEPTION 'drive: audit access denied' USING ERRCODE = 'BZ140',
      HINT = '{"type":"forbidden","detail":"manager role or drive.view required"}';
  END IF;

  IF p_q IS NOT NULL AND length(btrim(p_q)) > 0 THEN
    v_q := '%' || replace(replace(replace(btrim(p_q), '\', '\\'), '%', '\%'), '_', '\_') || '%';
  END IF;

  -- keyset page: newest-first on the (space_id, id) chain PK; +1 row probes hasMore
  SELECT COALESCE(jsonb_agg(row_j), '[]'::jsonb), count(*) INTO v_items, v_n FROM (
    SELECT jsonb_build_object(
             'id', a.id, 'occurredAt', a.occurred_at,
             'userId', a.user_id, 'userEmail', COALESCE(u.email, 'system'),
             'ip', COALESCE(a.ip::text, ''), 'action', a.action,
             'targetType', a.target_type, 'targetId', a.target_id,
             'notes', COALESCE(a.notes, '')) AS row_j
      FROM drive_audit_log a
      LEFT JOIN users u ON u.id = a.user_id
     WHERE a.space_id = p_space_id
       AND (p_before_id IS NULL OR a.id < p_before_id)
       AND (p_actor  IS NULL OR a.user_id = p_actor)
       AND (p_action IS NULL OR a.action = p_action)
       AND (p_from   IS NULL OR a.occurred_at >= p_from)
       AND (p_to     IS NULL OR a.occurred_at <  p_to)
       AND (v_q IS NULL OR a.action ILIKE v_q ESCAPE '\'
            OR COALESCE(a.notes, '') ILIKE v_q ESCAPE '\'
            OR COALESCE(u.email, '') ILIKE v_q ESCAPE '\')
     ORDER BY a.id DESC
     LIMIT v_cap + 1
  ) page;

  IF v_n > v_cap THEN
    -- AUTOPLAN batch-2 #10: WITH ORDINALITY + ORDER BY ordinality, not a
    -- bare jsonb_array_elements(...) LIMIT — element order through a bare
    -- subquery is not guaranteed, and this trim must preserve the id DESC
    -- order the outer query already established.
    SELECT jsonb_agg(e ORDER BY ord) INTO v_items
      FROM jsonb_array_elements(v_items) WITH ORDINALITY AS t(e, ord)
     WHERE ord <= v_cap;
    RETURN jsonb_build_object('items', v_items, 'hasMore', true);
  END IF;
  RETURN jsonb_build_object('items', v_items, 'hasMore', false);
END;
$$ LANGUAGE plpgsql STABLE;
