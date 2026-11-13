-- Substitute {var}s in one template for one recipient and sanitize the result.
-- SECURITY: every substituted value has '@' stripped BEFORE substitution, so a
-- directory attribute (first_name/last_name/...) cannot inject a second '@' and
-- hijack the rendered domain (which flows to mailboxes.email/users.email/aliases,
-- columns that send.sql trusts for send-as). After the template's own '@' split,
-- the local-part is sanitized to [a-z0-9._-] and the domain to [a-z0-9.-].
CREATE OR REPLACE FUNCTION email_address_policy_render_one(
  p_template TEXT, p_first TEXT, p_last TEXT, p_uname TEXT, p_dept TEXT, p_dom TEXT
) RETURNS TEXT LANGUAGE plpgsql STABLE AS $$
DECLARE
  v_s TEXT; v_lp TEXT; v_dp TEXT;
  v_gn TEXT := regexp_replace(lower(cjk_to_ascii(coalesce(p_first,''))), '@', '', 'g');
  v_sn TEXT := regexp_replace(lower(cjk_to_ascii(coalesce(p_last,''))),  '@', '', 'g');
  v_un TEXT := regexp_replace(lower(coalesce(p_uname,'')),               '@', '', 'g');
  v_dt TEXT := regexp_replace(lower(cjk_to_ascii(coalesce(p_dept,''))),  '@', '', 'g');
  v_dm TEXT := regexp_replace(lower(coalesce(p_dom,'')),                 '@', '', 'g');
BEGIN
  v_s := p_template;
  v_s := replace(v_s, '{given_name}',    v_gn);
  v_s := replace(v_s, '{surname}',       v_sn);
  v_s := replace(v_s, '{first_initial}', left(v_gn, 1));
  v_s := replace(v_s, '{user_name}',     v_un);
  v_s := replace(v_s, '{department}',    v_dt);
  v_s := replace(v_s, '{domain}',        v_dm);
  v_lp := regexp_replace(split_part(v_s,'@',1), '[^a-z0-9._-]', '', 'g');
  v_lp := trim(both '.' from regexp_replace(v_lp, '\.{2,}', '.', 'g'));
  v_dp := regexp_replace(split_part(v_s,'@',2), '[^a-z0-9.-]', '', 'g');
  RETURN v_lp || '@' || v_dp;
END;
$$;
