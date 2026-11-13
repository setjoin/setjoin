-- entity_state / bump_entity_state: the per-(mailbox,datatype) monotonic /changes
-- token for the PIM satellites (Task/ContactCard/AddressBook/Calendar/CalendarEvent).
-- Replaces the old MAX(child.jmap_state) derivation, which was not monotonic — an
-- update to a non-max row left MAX unmoved (change silently dropped) and destroying
-- the max row made MAX regress. This is a single atomic counter, mirror of
-- bump_email_state, captured post-bump and used as the journal state_seq AND the
-- reducer newState so token == state_seq holds by construction (kills the
-- Identity/changes spurious-perpetual-delta class). See A4 plan / gauntlet F2.

-- Current token for (mailbox, datatype); 0 when the counter has never been bumped.
CREATE OR REPLACE FUNCTION entity_state(p_mailbox_id BIGINT, p_datatype TEXT)
RETURNS BIGINT AS $$
  SELECT COALESCE((SELECT seq FROM jmap_entity_state
                    WHERE mailbox_id = p_mailbox_id AND datatype = p_datatype), 0);
$$ LANGUAGE sql STABLE;

-- Advance + return the new token. Atomic (UPSERT ... seq+1 RETURNING), monotonic,
-- survives destroys (the counter never regresses — a destroyed row is journaled at
-- a NEW higher seq). Called once per journaled op (from the datatype's trigger).
-- R2: mailbox_id is the reducer's auth-derived p_mailbox_id, never req.*.
CREATE OR REPLACE FUNCTION bump_entity_state(p_mailbox_id BIGINT, p_datatype TEXT)
RETURNS BIGINT AS $$
DECLARE v_seq BIGINT;
BEGIN
  INSERT INTO jmap_entity_state (mailbox_id, datatype, seq)
  VALUES (p_mailbox_id, p_datatype, 1)
  ON CONFLICT (mailbox_id, datatype) DO UPDATE SET seq = jmap_entity_state.seq + 1
  RETURNING seq INTO v_seq;
  RETURN v_seq;
END;
$$ LANGUAGE plpgsql;
