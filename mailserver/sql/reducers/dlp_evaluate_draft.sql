-- dlp_evaluate_draft: compose-time DLP dry-run (Purview policy tips). Wraps the
-- SAME dlp_check() send.sql step 5a enforces — identical argument convention
-- (domain from the sender mailbox, first violation only) — so the tip can
-- never disagree with enforcement. READ ONLY: no dlp_violations insert, no
-- state bump, no notify.
--
-- ponytail: attachments NULL — verbatim what send.sql 5a itself defaults to
-- when there is no p_source_message_id to build real metadata from (send.sql's
-- own bug-fix commit threads real attachments through when a draft id is
-- known; the compose tip has no equivalent server-side draft id at dry-run
-- time — the draft isn't necessarily saved). If a later phase threads real
-- attachment chip metadata through this endpoint, widen this signature in the
-- SAME commit — the pinned parity tests (12-14 below) only pin content-based
-- verdicts today, not attachment-based ones; see reducers/README.md's DLP
-- section for the residual asymmetry this leaves.
--
-- EVASION-ORACLE GUARD: dlp_check's reason embeds the admin's regex/keyword;
-- we return only the policy NAME + action + a coarse reason_kind, never the
-- pattern or matched text — otherwise a user probing compose could reverse-
-- engineer the org's DLP patterns.
CREATE OR REPLACE FUNCTION dlp_evaluate_draft(
  p_mailbox_id BIGINT,
  p_recipients JSONB,           -- reserved: recipient scoping (Phase 5); unused in v1
  p_subject    TEXT,
  p_body_text  TEXT,
  p_body_html  TEXT
) RETURNS JSONB AS $$
DECLARE
  v_domain_id BIGINT;
  v_hit       RECORD;
BEGIN
  -- R1: caller must be a real mailbox; domain drives policy selection exactly
  -- as v_mailbox.domain_id does in send.sql. Bogus caller → clean (fail-closed).
  SELECT domain_id INTO v_domain_id FROM mailboxes WHERE id = p_mailbox_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('violated', FALSE);
  END IF;

  SELECT * INTO v_hit FROM dlp_check(
    p_mailbox_id, v_domain_id, p_subject, p_body_text, p_body_html, NULL
  ) LIMIT 1;

  IF NOT v_hit.violated THEN
    RETURN jsonb_build_object('violated', FALSE);
  END IF;

  RETURN jsonb_build_object(
    'violated', TRUE,
    'policyId', v_hit.policy_id,
    'policyName', (SELECT name FROM dlp_policies WHERE id = v_hit.policy_id),
    'action', v_hit.action,
    'reasonKind', CASE
      WHEN v_hit.reason LIKE 'Matched regex:%'        THEN 'content'
      WHEN v_hit.reason LIKE 'Matched keywords:%'     THEN 'content'
      WHEN v_hit.reason LIKE 'Blocked file type:%'    THEN 'attachment_type'
      WHEN v_hit.reason LIKE 'Oversized attachment:%' THEN 'attachment_size'
      ELSE 'content' END
  );
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION dlp_evaluate_draft(BIGINT, JSONB, TEXT, TEXT, TEXT) IS
  'Compose-time DLP dry-run: same dlp_check seam as send.sql 5a, read-only, '
  'first violation only. Returns policy name/action/reason_kind — never the '
  'pattern or matched text.';
