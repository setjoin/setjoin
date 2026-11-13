-- mailserver/sql/reducers/drive_version_prune.sql
-- the drive_maintenance_sweep twin; never routed to a user handler in v1 (no
-- Go route exposes it). gxp spaces are skipped entirely (WORM retention owns
-- their version lifecycle, not the prune cadence). R9's ON DELETE SET NULL on
-- parent_version_id/conflict_of absorbs any dangling ancestry reference —
-- no explicit re-parenting needed here.
-- ponytail: full-table per-space scan; per-file LATERAL if prune latency shows.
--
-- LR-9 / AUTOPLAN batch-1 #6 (P4): drive_file_branches.head_version_id /
-- forked_from_version_id and drive_file_versions.merged_from_version_id are
-- plain refs with no ON DELETE action — pruning a branch-referenced version
-- would 23503. Versions on ANY branch line (branch_id IS NOT NULL) are also
-- excluded: branch rows are never deleted, so their interior versions are
-- deliberately prune-immortal in v1 (ledger-noted cost). A live
-- drive_file_locks.version_id reference is excluded for the same FK reason.
CREATE OR REPLACE FUNCTION drive_version_prune(
  p_space_id BIGINT, p_keep INT
) RETURNS INT AS $$
DECLARE v_class TEXT; v_ids BIGINT[]; v_bytes BIGINT; v_n INT;
BEGIN
  SELECT classification INTO v_class FROM drive_spaces WHERE id = p_space_id;
  IF v_class IS NULL OR v_class = 'gxp' THEN
    RETURN 0;
  END IF;

  SELECT array_agg(ranked.id), COALESCE(SUM(ranked.size_bytes), 0)
    INTO v_ids, v_bytes
    FROM (
      SELECT v.id, v.size_bytes, v.branch_id,
             row_number() OVER (PARTITION BY v.file_node_id ORDER BY v.id DESC) AS rn
        FROM drive_file_versions v WHERE v.space_id = p_space_id
    ) ranked
   WHERE ranked.rn > p_keep
     AND ranked.branch_id IS NULL
     AND NOT EXISTS (SELECT 1 FROM drive_files f WHERE f.head_version_id = ranked.id)
     AND NOT EXISTS (SELECT 1 FROM drive_file_branches b
                      WHERE b.head_version_id = ranked.id OR b.forked_from_version_id = ranked.id)
     AND NOT EXISTS (SELECT 1 FROM drive_file_versions m WHERE m.merged_from_version_id = ranked.id)
     AND NOT EXISTS (SELECT 1 FROM drive_file_locks l WHERE l.version_id = ranked.id)
     -- Chat A2 exclusion (DES-009 D4): a chat-attached version must stay
     -- resolvable forever (the attachment record pins it) — same
     -- prune-immortal treatment as a branch-referenced version.
     AND NOT EXISTS (SELECT 1 FROM chat_message_attachments a WHERE a.version_id = ranked.id)
     -- Meet B2 §E exclusion: a recording-referenced version is a RECORD —
     -- same prune-immortal treatment.
     AND NOT EXISTS (SELECT 1 FROM meeting_recordings r WHERE r.version_id = ranked.id);

  IF v_ids IS NULL THEN
    RETURN 0;
  END IF;

  DELETE FROM drive_file_versions WHERE id = ANY(v_ids);
  GET DIAGNOSTICS v_n = ROW_COUNT;
  PERFORM drive_space_quota_charge(p_space_id, -v_bytes);
  RETURN v_n;
END;
$$ LANGUAGE plpgsql;
