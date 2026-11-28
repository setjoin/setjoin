-- mailserver/sql/reducers/drive_node_destroy_hard.sql
-- Worker-only physical destroy of a SINGLE tier-2 node (P6 two-level trash,
-- V117). Called leaf-first, in a loop, by drive_maintenance_sweep (Task 4)
-- after the 30-day tier-2 grace — never routed from a user request (no
-- p_user_id, no EXECUTE restriction beyond that convention: matches
-- drive_maintenance_sweep.sql, which is likewise never granted/revoked
-- explicitly and relies on the fixed Go route table never naming it). No
-- drive_access_audit row either: the member-visible 'destroy' was already
-- journaled by drive_node_destroy at purge time; this is content-plane
-- cleanup clients never observe.
--
-- Relocated body (AUTOPLAN contradiction #7): the P1 hard-delete FK order
-- (drive_files_head_fk has no ON DELETE action, so head_version_id is
-- cleared before the version DELETE) PLUS the P4 circular/cross-file unlink
-- that used to live in drive_node_destroy.sql (locks reference subtree
-- versions with no ON DELETE action; branch_id/drive_file_branches form a
-- circular FK pair; a keep_both sibling's merged_from_version_id is a
-- cross-file reference) — same logic, single-node scoped since the sweep
-- processes leaves one at a time, not a whole subtree at once — PLUS the P5
-- drive_export_grants FK (also no ON DELETE action).
--
-- gxp-in-retention: refuse by returning false (not raising) so the sweep's
-- loop stays exception-free — a raised BZ145 mid-loop would abort every
-- OTHER space's cleanup in the same sweep transaction. The check mirrors
-- trg_drive_version_worm_fn's own gate (classification='gxp' AND still
-- inside retention) for this node's OWN versions.
-- ponytail: the check is single-node scoped, same as the rest of this
-- function — it does not look for an out-of-subtree gxp-in-retention
-- sibling whose merged_from_version_id points at one of THIS node's
-- versions (a keep_both cross-file edge case). Upgrade to a broader
-- pre-check if that combination is ever exercised in practice; today's
-- I-16 fixture (drive_trash_tiers.pg) and the P4 regression fixture
-- (drive_node_destroy_versioning.pg) are both single-node.
--
-- Returns true when destroyed, false when skipped (children still pending —
-- leaf-first — node already live/never purged, or gxp retention not yet
-- elapsed).
CREATE OR REPLACE FUNCTION drive_node_destroy_hard(p_node_id bigint)
RETURNS boolean AS $$
DECLARE
  v_space_id bigint;
  v_kind     text;
  v_bytes    bigint := 0;
BEGIN
  SELECT space_id, kind INTO v_space_id, v_kind
    FROM drive_nodes WHERE id = p_node_id AND purged_at IS NOT NULL;
  IF NOT FOUND THEN RETURN false; END IF;
  PERFORM drive_tree_lock(v_space_id);

  -- leaf-first: the sweep loops until no progress; a parent with children waits.
  IF EXISTS (SELECT 1 FROM drive_nodes WHERE parent_id = p_node_id) THEN
    RETURN false;
  END IF;

  IF v_kind = 'file' THEN
    IF EXISTS (
      SELECT 1 FROM drive_file_versions v
        JOIN drive_spaces s ON s.id = v.space_id
       WHERE v.file_node_id = p_node_id
         AND s.classification = 'gxp'
         AND v.created_at + make_interval(days => s.retention_days) > now()
    ) THEN RETURN false; END IF;

    -- Meet B2 §E backstop: a recording-referenced node is a RECORD — the
    -- registry row must never be unlinked or destroyed. Skip (never raise:
    -- a raise would abort every OTHER space's cleanup in the same sweep).
    IF EXISTS (SELECT 1 FROM meeting_recordings WHERE file_node_id = p_node_id) THEN
      RETURN false;
    END IF;

    SELECT COALESCE(SUM(size_bytes), 0) INTO v_bytes
      FROM drive_file_versions WHERE file_node_id = p_node_id;

    -- Chat A2 backstop (DES-009 D4/Task 5b): a chat-attached node should
    -- never reach destroy_hard (the immutability guard blocks trash on it
    -- directly) — this unlink is defense in depth only, so an un-handled
    -- FK never 23503s and wedges the sweep loop forever if that guard is
    -- ever bypassed.
    DELETE FROM chat_message_attachments WHERE file_node_id = p_node_id;

    -- P4 unlink order (relocated from the old drive_node_destroy.sql
    -- comment, single-node scoped): drop locks (they hold a NOT NULL,
    -- no-ON-DELETE version_id FK), null branch_id (breaks
    -- versions->branches), delete this node's branch rows (breaks
    -- branches->versions), null any out-of-subtree keep_both sibling's
    -- merged_from_version_id that points into this node's versions.
    DELETE FROM drive_file_locks WHERE node_id = p_node_id;
    UPDATE drive_file_versions SET branch_id = NULL WHERE file_node_id = p_node_id;
    DELETE FROM drive_file_branches WHERE file_node_id = p_node_id;
    UPDATE drive_file_versions SET merged_from_version_id = NULL
     WHERE merged_from_version_id IN (SELECT id FROM drive_file_versions WHERE file_node_id = p_node_id)
       AND file_node_id <> p_node_id;

    -- P1 unlink order: head FK first, then the P5 export-grant FK, then versions.
    UPDATE drive_files SET head_version_id = NULL WHERE node_id = p_node_id;
    DELETE FROM drive_export_grants
     WHERE version_id IN (SELECT id FROM drive_file_versions WHERE file_node_id = p_node_id);
    DELETE FROM drive_file_versions WHERE file_node_id = p_node_id;
      -- drive_version_chunks cascades (ON DELETE CASCADE); the G7 DEFINER
      -- triggers decrement ref_count / queue zero-ref chunks for GC.

    PERFORM drive_space_quota_charge(v_space_id, -v_bytes);   -- P1's DEFINER
      -- choke point (AUTOPLAN batch-2 #7) — never a direct drive_spaces UPDATE.
  END IF;

  DELETE FROM drive_nodes WHERE id = p_node_id;   -- drive_files/drive_watches cascade
  RETURN true;
END;
$$ LANGUAGE plpgsql;
