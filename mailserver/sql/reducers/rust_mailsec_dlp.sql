-- Frozen Go's admin.DLPHandler.UpdatePatterns as a reducer: DELETE every pattern row, then
-- INSERT the submitted rows (priority = position, applies_to_all and is_pattern TRUE, one regex
-- each) in one transaction. Go distinguishes the two failures in its 500 detail, so each is
-- re-raised with its own message. Authority (mail.security, org-wide admin) is checked by the
-- gateway before the call; dlp_policies has no tenant column.
CREATE OR REPLACE FUNCTION rust_mailsec_dlp_patterns_replace(
  p_names text[], p_enabled boolean[], p_actions text[], p_regex text[])
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 BEGIN
  DELETE FROM dlp_policies WHERE is_pattern = TRUE;
 EXCEPTION WHEN OTHERS THEN
  RAISE EXCEPTION 'dlp_clear_failed';
 END;
 BEGIN
  INSERT INTO dlp_policies (name, enabled, priority, action, regex_patterns, applies_to_all, is_pattern)
   SELECT t.n, t.e, (t.i - 1)::int, t.a, ARRAY[t.r], TRUE, TRUE
     FROM unnest(p_names, p_enabled, p_actions, p_regex) WITH ORDINALITY AS t(n, e, a, r, i)
    ORDER BY t.i;
 EXCEPTION WHEN OTHERS THEN
  RAISE EXCEPTION 'dlp_save_failed';
 END;
 RETURN true;
END;
$$;
