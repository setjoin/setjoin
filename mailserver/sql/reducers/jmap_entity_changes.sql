-- jmap_entity_changes: real per-(mailbox,datatype) JMAP /changes delta from the
-- shared journal. Byte-for-byte the jmap_email_changes algorithm (collapse per
-- entity, created+destroyed→noop, soft cap at state_seq group boundaries, resync/
-- pruned/future → BZ011), generalized by datatype with entity_state() as the token
-- source. Every satellite *_changes reducer delegates here with its datatype string.
CREATE OR REPLACE FUNCTION jmap_entity_changes(
  p_mailbox_id  BIGINT,
  p_datatype    TEXT,
  p_since_state TEXT,
  p_max_changes INT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_current   BIGINT := entity_state(p_mailbox_id, p_datatype);  -- R1: auth-derived mailbox
  v_since     BIGINT := p_since_state::BIGINT;
  v_oldest    BIGINT;
  v_new_state BIGINT;
  v_count     INT    := 0;
  v_prev_seq  BIGINT;
  v_created   BIGINT[] := '{}';
  v_updated   BIGINT[] := '{}';
  v_destroyed BIGINT[] := '{}';
  v_has_more  BOOLEAN  := FALSE;
  r RECORD;
BEGIN
  IF v_since > v_current THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  -- Pruned: sinceState predates the oldest retained journal row for this datatype.
  -- Guard v_since>0: sinceState=0 always means "full history from start", never pruned.
  SELECT MIN(state_seq) INTO v_oldest
    FROM jmap_changes_journal
   WHERE mailbox_id = p_mailbox_id AND datatype = p_datatype;  -- R1
  IF v_since > 0 AND (v_oldest IS NULL OR v_since < v_oldest - 1) THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  -- Resync sentinel anywhere in (sinceState, currentState] → coarse path → BZ011.
  IF EXISTS (
    SELECT 1 FROM jmap_changes_journal
     WHERE mailbox_id = p_mailbox_id AND datatype = p_datatype
       AND state_seq > v_since AND op = 'resync'  -- R1
  ) THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  v_new_state := v_current;

  -- Collapse per entity_id (latest op; created+destroyed cancels). Walk in state_seq
  -- order; apply the soft cap at state_seq GROUP boundaries only (never split a group).
  FOR r IN
    WITH per_id AS (
      SELECT entity_id,
             (array_agg(op ORDER BY state_seq DESC))[1] AS latest_op,
             bool_or(op = 'created')   AS had_created,
             MAX(state_seq)            AS max_seq
        FROM jmap_changes_journal
       WHERE mailbox_id = p_mailbox_id AND datatype = p_datatype
         AND state_seq > v_since AND op <> 'resync'  -- R1
       GROUP BY entity_id
    )
    SELECT entity_id, latest_op, had_created, max_seq
      FROM per_id
     ORDER BY max_seq, entity_id
  LOOP
    -- RFC 8620 §5.2: created+destroyed since oldState → noop (omit from all lists).
    IF r.had_created AND r.latest_op = 'destroyed' THEN
      CONTINUE;
    END IF;

    -- Soft cap: only trigger at a state_seq GROUP boundary, never mid-group.
    IF p_max_changes IS NOT NULL
       AND v_count >= p_max_changes
       AND v_prev_seq IS NOT NULL
       AND r.max_seq > v_prev_seq
    THEN
      v_has_more  := TRUE;
      v_new_state := v_prev_seq;
      EXIT;
    END IF;

    IF r.latest_op = 'destroyed' THEN
      v_destroyed := v_destroyed || r.entity_id;
    ELSIF r.had_created THEN
      v_created   := v_created   || r.entity_id;
    ELSE
      v_updated   := v_updated   || r.entity_id;
    END IF;
    v_count    := v_count + 1;
    v_prev_seq := r.max_seq;
  END LOOP;

  RETURN jsonb_build_object(
    'accountId',     p_mailbox_id::TEXT,
    'oldState',      p_since_state,
    'newState',      v_new_state::TEXT,
    'hasMoreChanges', v_has_more,
    'created',   COALESCE(to_jsonb(v_created),   '[]'::JSONB),
    'updated',   COALESCE(to_jsonb(v_updated),   '[]'::JSONB),
    'destroyed', COALESCE(to_jsonb(v_destroyed), '[]'::JSONB)
  );
END;
$$ LANGUAGE plpgsql;
