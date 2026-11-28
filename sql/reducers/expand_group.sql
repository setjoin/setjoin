-- Canonical copy of expand_group (originally in V001__baseline.sql).
-- CREATE OR REPLACE replaces the baseline definition on reducer reload.
-- The only change from baseline: fail-closed guard after the SELECT … INTO.
CREATE OR REPLACE FUNCTION expand_group(p_group_id bigint) RETURNS TABLE(mailbox_id bigint)
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
  v_dynamic      BOOL;
  v_filter       JSONB;
BEGIN
  SELECT is_dynamic, dynamic_filter
  INTO v_dynamic, v_filter
  FROM distribution_groups WHERE id = p_group_id;

  IF NOT FOUND THEN
    RETURN;  -- ponytail: missing group → reach nobody, never the whole org (was fail-OPEN)
  END IF;

  IF NOT v_dynamic THEN
    -- Only deliverable members: a disabled or receive-disabled member would later
    -- raise BZ007 ("no mailbox") inside deliver()'s fan-out loop. Filter them here so
    -- one ineligible member can't take down delivery to the whole static list.
    RETURN QUERY
      SELECT m.mailbox_id
      FROM distribution_group_members m
      JOIN mailboxes mb ON mb.id = m.mailbox_id
      WHERE m.group_id = p_group_id
        AND mb.enabled = TRUE
        AND mb.receive_enabled = TRUE;
  ELSE
    -- Dynamic: filter mailboxes by department / domain / enabled status.
    -- Exclude mailboxes that back a distribution group (satellite table is the sole
    -- group signal after the type-refactor; mb.type is no longer a reliable guard).
    RETURN QUERY
      SELECT mb.id
      FROM mailboxes mb
      JOIN users u ON u.id = mb.user_id
      WHERE NOT EXISTS (SELECT 1 FROM distribution_groups dgx WHERE dgx.mailbox_id = mb.id)
        AND mb.enabled = TRUE
        AND mb.receive_enabled = TRUE
        AND (v_filter->>'enabled'  IS NULL OR u.enabled = (v_filter->>'enabled')::BOOL)
        AND (v_filter->>'domain_id' IS NULL OR mb.domain_id = (v_filter->>'domain_id')::BIGINT)
        AND (v_filter->>'department_id' IS NULL
             OR u.department_id = (v_filter->>'department_id')::BIGINT);
  END IF;
END;
$$;
