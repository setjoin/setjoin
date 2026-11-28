-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 047: Consolidate DLP into a single source of truth.
-- Adds is_pattern flag, migrates system_config patterns to dlp_policies rows,
-- and removes the system_config branch from dlp_check().

ALTER TABLE dlp_policies ADD COLUMN IF NOT EXISTS is_pattern BOOL NOT NULL DEFAULT FALSE;

-- Migrate default patterns from 036_dlp_patterns.sql to dlp_policies rows.
-- Each pattern becomes a global policy row (domain_id = NULL, applies_to_all = TRUE).
INSERT INTO dlp_policies (name, enabled, priority, action, regex_patterns, applies_to_all, is_pattern)
SELECT
  p->>'name',
  COALESCE((p->>'enabled')::BOOL, TRUE),
  0,
  CASE p->>'severity'
    WHEN 'critical' THEN 'block'
    WHEN 'high'     THEN 'quarantine'
    WHEN 'medium'   THEN 'notify_admin'
    ELSE 'warn'
  END,
  ARRAY[p->>'regex'],
  TRUE,
  TRUE
FROM system_config, jsonb_array_elements(value) AS p
WHERE key = 'dlp_patterns'
ON CONFLICT DO NOTHING;

-- Remove the now-redundant system_config entry.
DELETE FROM system_config WHERE key = 'dlp_patterns';

-- Update dlp_check() to remove the system_config.dlp_patterns branch.
-- Pattern rows are now included in the dlp_policies loop automatically.
CREATE OR REPLACE FUNCTION dlp_check(
  p_mailbox_id     BIGINT,
  p_domain_id      BIGINT,
  p_subject        TEXT,
  p_body_text      TEXT,
  p_body_html      TEXT,
  p_attachments    JSONB DEFAULT '[]'::JSONB
) RETURNS TABLE(violated BOOL, policy_id BIGINT, action TEXT, reason TEXT) AS $$
DECLARE
  v_policy        RECORD;
  v_content       TEXT;
  v_match_count   INT;
  v_total_count   INT;
  v_att           JSONB;
  v_blocked       BOOL := FALSE;
BEGIN
  SET LOCAL statement_timeout = '5s';
  v_content := lower(coalesce(p_subject,'') || ' ' || coalesce(p_body_text,'') || ' ' || coalesce(p_body_html,''));

  FOR v_policy IN
    SELECT dp.* FROM dlp_policies dp
    WHERE dp.enabled = TRUE
      AND (dp.domain_id IS NULL OR dp.domain_id = p_domain_id)
      AND (dp.applies_to_all = TRUE OR EXISTS (
        SELECT 1 FROM dlp_policy_targets dpt
        WHERE dpt.policy_id = dp.id AND dpt.mailbox_id = p_mailbox_id
      ))
    ORDER BY dp.priority
  LOOP
    -- Regex check
    IF array_length(v_policy.regex_patterns, 1) > 0 THEN
      FOR i IN 1..array_length(v_policy.regex_patterns, 1) LOOP
        IF v_content ~* v_policy.regex_patterns[i] THEN
          v_blocked := TRUE;
          RETURN QUERY SELECT TRUE, v_policy.id, v_policy.action,
            'Matched regex: ' || v_policy.regex_patterns[i];
        END IF;
      END LOOP;
    END IF;

    IF v_blocked THEN CONTINUE; END IF;

    -- Keyword check
    IF array_length(v_policy.keywords, 1) > 0 THEN
      v_match_count := 0;
      v_total_count := array_length(v_policy.keywords, 1);
      FOR i IN 1..v_total_count LOOP
        IF v_content LIKE '%' || lower(v_policy.keywords[i]) || '%' THEN
          v_match_count := v_match_count + 1;
        END IF;
      END LOOP;
      IF v_match_count::REAL / v_total_count >= v_policy.min_confidence THEN
        v_blocked := TRUE;
        RETURN QUERY SELECT TRUE, v_policy.id, v_policy.action,
          'Matched keywords: ' || v_match_count || '/' || v_total_count;
      END IF;
    END IF;

    IF v_blocked THEN CONTINUE; END IF;

    -- Attachment checks
    FOR v_att IN SELECT * FROM jsonb_array_elements(p_attachments) LOOP
      -- File type check
      IF array_length(v_policy.blocked_file_types, 1) > 0 THEN
        FOR i IN 1..array_length(v_policy.blocked_file_types, 1) LOOP
          IF lower(v_att->>'filename') LIKE '%.' || lower(v_policy.blocked_file_types[i]) THEN
            v_blocked := TRUE;
            RETURN QUERY SELECT TRUE, v_policy.id, v_policy.action,
              'Blocked file type: ' || v_att->>'filename';
          END IF;
        END LOOP;
      END IF;

      -- Size check
      IF v_policy.max_attachment_size > 0 AND (v_att->>'size_bytes')::BIGINT > v_policy.max_attachment_size THEN
        v_blocked := TRUE;
        RETURN QUERY SELECT TRUE, v_policy.id, v_policy.action,
          'Oversized attachment: ' || v_att->>'filename';
      END IF;
    END LOOP;
  END LOOP;

  RETURN QUERY SELECT FALSE, NULL::BIGINT, NULL::TEXT, NULL::TEXT;
END;
$$ LANGUAGE plpgsql;
