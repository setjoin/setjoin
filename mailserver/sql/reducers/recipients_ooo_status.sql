-- recipients_ooo_status: compose-time out-of-office advisory (QoL #7). Given a set
-- of recipient email addresses, return the subset that resolve to an INTERNAL
-- mailbox whose owner has an ACTIVE out-of-office (vacation) auto-reply — with the
-- end date only, never the auto-reply subject/body.
--
-- DIRECTORY-ENUMERATION SAFETY (M5, binding): each address is resolved through
-- resolve_identity (the same address→person seam free/busy uses). An external or
-- unknown address yields ZERO rows — IDENTICAL to an internal address whose owner
-- is simply not out of office (also absent). So a caller cannot use this endpoint
-- to distinguish "external/unknown" from "internal-not-OOO": both are absent from
-- the result. Only DATES leave the boundary (an active OOO is org-visible advisory
-- info, like free/busy), never the reply text.
--
-- ACTIVE-WINDOW LOGIC is copied VERBATIM from deliver_group_vacation.sql (the
-- auto-reply trigger, lines 368-372): enabled AND (start_date IS NULL OR
-- start_date <= today) AND (end_date IS NULL OR end_date >= today). An indefinite
-- OOO (end_date IS NULL) returns until=NULL — the UI shows "out of office" with no
-- "until {date}".
--
-- p_mailbox_id: caller's primary mailbox id (parseAccountID) — verified as a real
--   mailbox (R1 authz), mirroring calendar_free_busy_multi's caller-existence check.
--   A bogus/absent caller mailbox returns an empty array (fail-closed, no leak).
-- p_emails: JSONB array of recipient address strings.
-- Returns: JSONB array of {email, until} (until = end_date or null), one entry per
--   DISTINCT active-OOO internal recipient. Empty array when none.
CREATE OR REPLACE FUNCTION recipients_ooo_status(
  p_mailbox_id BIGINT,
  p_emails     JSONB
) RETURNS JSONB AS $$
DECLARE
  v_result JSONB := '[]'::JSONB;
BEGIN
  -- R1: the caller must be a real mailbox (org-scoped advisory, like free/busy).
  PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id;
  IF NOT FOUND THEN
    RETURN v_result;
  END IF;

  IF p_emails IS NULL OR jsonb_typeof(p_emails) <> 'array' THEN
    RETURN v_result;
  END IF;

  SELECT COALESCE(jsonb_agg(row_obj), '[]'::JSONB)
    INTO v_result
  FROM (
    SELECT DISTINCT jsonb_build_object('email', addr.email, 'until', vs.end_date) AS row_obj
    FROM (
      SELECT DISTINCT lower(trim(e.value #>> '{}')) AS email
      FROM jsonb_array_elements(p_emails) e
      WHERE trim(e.value #>> '{}') <> ''
    ) addr
    JOIN LATERAL resolve_identity(addr.email) ri ON TRUE
    JOIN vacation_settings vs ON vs.mailbox_id = ri.primary_mailbox
    WHERE vs.enabled = TRUE
      AND (vs.start_date IS NULL OR vs.start_date <= CURRENT_DATE)
      AND (vs.end_date IS NULL OR vs.end_date >= CURRENT_DATE)
  ) matched;

  RETURN v_result;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION recipients_ooo_status(BIGINT, JSONB) IS
  'Compose OOO advisory (QoL #7): given recipient addresses, return {email, until} '
  'for those resolving to an internal mailbox with an active vacation auto-reply. '
  'Active-window logic verbatim from deliver_group_vacation. Dates only, never the '
  'reply body. External/unknown addresses return zero rows — indistinguishable from '
  'internal-not-OOO (no directory-enumeration oracle).';
