-- mailserver/sql/reducers/drive_space_as_of.sql
-- user decision 2026-07-09): "space as of T" — a pure metadata query over
-- the version DAG + trash timestamps. Read-only; restore rides the P1
-- restore-as-new-version path (re-put of the old manifest) — no new
-- mutating reducer.
--
-- Three honest ceilings (each also a -- ponytail: comment below):
--  1. names/paths are NOT versioned — the view shows temporal *existence* +
--     *content version at T* under CURRENT names/paths.
--  2. deleted_at/purged_at are current flags, not history — a trash->restore
--     round-trip loses the interim deleted window.
--  3. content-at-T = latest MAIN-LINE version (created_at <= T, and
--     branch_id IS NULL AND conflict_of IS NULL) — an ff-resolved head
--     resolves to the pre-fork version. Exact head-at-T needs a
--     head-movement journal — deferred (TODOS.md).
--  4. AUTOPLAN batch-2 #11: this reducer is invoker rights (no SECURITY
--     DEFINER), so once native-RLS binds, drive_nodes_read's USING clause
--     (purged_at IS NULL, V117) hides EVERY tier-2 row unconditionally —
--     including one purged AFTER T, which conceptually should still show
--     as "existed at T, not live now". It drops out of the as-of view while
--     it sits in the admin bin; a drive.manage restore makes it reappear.
--     Pinned by a setjoin_app-probe assert in drive_space_as_of.pg.
CREATE OR REPLACE FUNCTION drive_space_as_of(
  p_user_id  bigint,
  p_space_id bigint,
  p_at       timestamptz
) RETURNS jsonb AS $$
BEGIN
  IF NOT public.drive_user_has_space_access(p_user_id,p_space_id) THEN
    RAISE EXCEPTION 'drive: not found' USING ERRCODE = 'BZ139',
      HINT = '{"type":"notFound","detail":"space not found"}';
  END IF;
  IF p_at IS NULL OR p_at > now() THEN
    RAISE EXCEPTION 'drive: invalid time point' USING ERRCODE = 'BZ141',
      HINT = '{"type":"invalidArguments","detail":"at must be a past or present timestamp"}';
  END IF;

  -- ponytail: names/parents are current-state (not versioned); deleted_at/
  -- purged_at are current flags (a restore clears history); content-at-T is
  -- the latest main-line version — ff-resolved heads resolve to the
  -- pre-fork version. Exact reconstruction needs history tables — deferred.
  RETURN COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
             'id', n.id, 'parentId', n.parent_id, 'kind', n.kind, 'name', n.name,
             'versionId', v.id, 'versionCreatedAt', v.created_at,
             'sizeBytes', v.size_bytes, 'contentType', v.content_type,
             'liveNow', (n.deleted_at IS NULL AND n.purged_at IS NULL))
           ORDER BY n.parent_id NULLS FIRST, lower(n.name))
      FROM drive_nodes n
      LEFT JOIN LATERAL (
        SELECT v.* FROM drive_file_versions v
         WHERE v.file_node_id = n.id AND v.created_at <= p_at
           AND v.conflict_of IS NULL AND v.branch_id IS NULL   -- main line only
         ORDER BY v.id DESC LIMIT 1
      ) v ON n.kind = 'file'
     WHERE n.space_id = p_space_id
       AND (public.drive_runtime_has_node_capability(
              p_user_id,n.id,'read_metadata')
            OR (n.purged_at IS NOT NULL
                AND public.drive_runtime_has_space_root_capability(
                  p_user_id,p_space_id,'read_metadata')))
       AND n.created_at <= p_at
       AND (n.deleted_at IS NULL OR n.deleted_at > p_at)
       AND (n.purged_at  IS NULL OR n.purged_at  > p_at)
       AND (n.kind = 'folder' OR v.id IS NOT NULL)   -- a file with no version at T didn't exist yet
  ), '[]'::jsonb);
END;
$$ LANGUAGE plpgsql STABLE;
