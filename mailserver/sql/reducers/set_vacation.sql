-- set_vacation.sql: self-service Out-of-Office writer + reader (A5).
--
-- vacation_settings is NOT a synced JMAP object (it is device-agnostic user config fetched
-- on demand, not a mailbox-stateful mail object) → no jmap_*_state bump / notify_state_change.
--
-- p_mailbox_id is the owning mailbox id (ADR-003: the account-slot arg is always a mailbox_id;
-- parseAccountID resolves it from the authenticated user). Every statement here is scoped by it,
-- so R2/R3 hold by parameter propagation (this repo enforces R1–R4 by mailbox-id propagation,
-- not native RLS — see docs/standards/DATABASE_SECURITY.md).
--
-- Errors: BZ046 invalid external_audience, BZ047 start_date after end_date.
CREATE OR REPLACE FUNCTION set_vacation(
  p_mailbox_id         BIGINT,
  p_enabled            BOOL,
  p_subject            TEXT,
  p_body_text          TEXT,
  p_body_html          TEXT,
  p_body_external      TEXT,
  p_body_external_html TEXT,
  p_start_date         DATE DEFAULT NULL,
  p_end_date           DATE DEFAULT NULL,
  p_external_audience  TEXT DEFAULT 'all'
) RETURNS VOID AS $$
BEGIN
  -- Validate the external-audience enum: each accepted value is enforced at send time
  -- (deliver_group_vacation.sql); reject anything else before it can reach the row.
  IF p_external_audience IS NOT NULL
     AND p_external_audience NOT IN ('all', 'contacts', 'none') THEN
    RAISE EXCEPTION 'invalid external_audience: %', p_external_audience
      USING ERRCODE = 'BZ046',
            HINT = jsonb_build_object('type', 'invalid_external_audience',
                                      'external_audience', p_external_audience)::TEXT;
  END IF;

  IF p_start_date IS NOT NULL AND p_end_date IS NOT NULL AND p_start_date > p_end_date THEN
    RAISE EXCEPTION 'vacation start_date after end_date'
      USING ERRCODE = 'BZ047',
            HINT = jsonb_build_object('type', 'vacation_date_range',
                                      'start_date', p_start_date, 'end_date', p_end_date)::TEXT;
  END IF;

  INSERT INTO vacation_settings (
    mailbox_id, enabled, subject, body_text, body_html,
    body_external, body_external_html, start_date, end_date,
    external_audience, updated_at)
  VALUES (
    p_mailbox_id, COALESCE(p_enabled, FALSE), COALESCE(p_subject, 'Out of office'),
    COALESCE(p_body_text, ''), p_body_html,
    p_body_external, p_body_external_html, p_start_date, p_end_date,
    COALESCE(p_external_audience, 'all'), now())
  ON CONFLICT (mailbox_id) DO UPDATE SET
    enabled            = COALESCE(EXCLUDED.enabled, FALSE),
    subject            = EXCLUDED.subject,
    body_text          = EXCLUDED.body_text,
    body_html          = EXCLUDED.body_html,
    body_external      = EXCLUDED.body_external,
    body_external_html = EXCLUDED.body_external_html,
    start_date         = EXCLUDED.start_date,
    end_date           = EXCLUDED.end_date,
    external_audience  = EXCLUDED.external_audience,
    updated_at         = now();
END;
$$ LANGUAGE plpgsql;

-- get_vacation: read the OOO config for the owning mailbox (p_mailbox_id-scoped, R1).
CREATE OR REPLACE FUNCTION get_vacation(p_mailbox_id BIGINT)
RETURNS vacation_settings AS $$
  SELECT * FROM vacation_settings WHERE mailbox_id = p_mailbox_id;
$$ LANGUAGE sql STABLE;
