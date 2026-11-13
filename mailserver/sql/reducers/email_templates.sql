-- email_templates.sql — compose templates / Quick Parts: reusable named body
-- snippets a user inserts into a compose window (mirrors the quick_steps /
-- saved_searches per-mailbox user-object rail). Wires the pre-existing (baseline)
-- email_templates table — no migration. body_html is stored VERBATIM: the webmail
-- sanitizes on insert-into-editor, and this is the user's OWN template body.
--
-- R4 / DATABASE_SECURITY: every statement filters by p_mailbox_id from the auth
-- context (R1/R3); the INSERT sets mailbox_id from the parameter, never req.* (R2).
-- No native RLS (matches quick_steps / saved_searches app-layer-only posture — the
-- p_mailbox_id scoping is the R1/R3 guard, verified by check-account-scope).

CREATE OR REPLACE FUNCTION email_template_list(p_mailbox_id BIGINT) RETURNS JSONB AS $$
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'id', id::TEXT, 'name', name, 'subject', subject,
    'bodyHtml', body_html) ORDER BY name, id), '[]'::JSONB)
  FROM email_templates WHERE mailbox_id = p_mailbox_id;            -- R1: filter by mailbox
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION email_template_set(
  p_mailbox_id BIGINT, p_name TEXT, p_subject TEXT, p_body_html TEXT
) RETURNS JSONB AS $$
DECLARE
  v_row email_templates;
BEGIN
  IF p_name IS NULL OR length(trim(p_name)) = 0 THEN
    RAISE EXCEPTION 'email template name required'
      USING ERRCODE = 'BZ040', HINT = '{"type":"invalidArguments"}';
  END IF;

  -- R2: mailbox_id comes from the parameter (auth context), never req.*. Upsert on
  -- the (mailbox_id, name) unique key so re-saving a template by name replaces it
  -- (the conflict target embeds mailbox_id, so a conflict can only be this
  -- mailbox's own row — no cross-mailbox TOCTOU). body_html stored verbatim.
  INSERT INTO email_templates (mailbox_id, name, subject, body_html)
  VALUES (p_mailbox_id, p_name, p_subject, p_body_html)
  ON CONFLICT (mailbox_id, name) DO UPDATE
    SET subject = EXCLUDED.subject, body_html = EXCLUDED.body_html, updated_at = now()
  RETURNING * INTO v_row;

  RETURN jsonb_build_object('id', v_row.id::TEXT, 'name', v_row.name,
                            'subject', v_row.subject, 'bodyHtml', v_row.body_html);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION email_template_delete(p_mailbox_id BIGINT, p_id BIGINT) RETURNS JSONB AS $$
DECLARE
  v_deleted BIGINT;
BEGIN
  DELETE FROM email_templates
   WHERE id = p_id AND mailbox_id = p_mailbox_id                  -- R3: ownership in WHERE
  RETURNING id INTO v_deleted;
  RETURN jsonb_build_object('deleted', v_deleted IS NOT NULL, 'id', p_id::TEXT);
END;
$$ LANGUAGE plpgsql;
