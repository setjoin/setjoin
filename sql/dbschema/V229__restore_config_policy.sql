-- V229: reducer-owned restore configuration policy. A standalone/embedded-only
-- backup may recover data, but it cannot silently reintroduce credentials,
-- identity providers, outbound endpoints, trust boundaries or unknown settings.
CREATE TABLE public.restore_config_policy_catalog (
  pattern text PRIMARY KEY,
  match_kind text NOT NULL CHECK (match_kind IN ('exact','prefix')),
  disposition text NOT NULL CHECK (disposition IN ('safe','rotate','quarantine','operator_approve')),
  priority integer NOT NULL DEFAULT 100,
  rationale text NOT NULL
);

CREATE TABLE public.restore_config_quarantine (
  id bigserial PRIMARY KEY,
  config_key text NOT NULL,
  config_value jsonb NOT NULL,
  encrypted boolean NOT NULL,
  disposition text NOT NULL,
  source_verified boolean NOT NULL,
  quarantined_at timestamptz NOT NULL DEFAULT now()
);

-- Existing schema-known keys are admitted as safe unless a narrower security
-- rule below overrides them. Future settings must explicitly join this catalog;
-- unknown keys fail closed into quarantine.
INSERT INTO public.restore_config_policy_catalog(pattern, match_kind, disposition, priority, rationale)
SELECT key, 'exact', 'safe', 1000, 'schema-known non-sensitive configuration'
FROM public.system_config
ON CONFLICT (pattern) DO NOTHING;

INSERT INTO public.restore_config_policy_catalog(pattern, match_kind, disposition, priority, rationale) VALUES
  ('feature.', 'prefix', 'safe', 900, 'feature policy carries no credential material'),
  ('ad_', 'prefix', 'quarantine', 10, 'directory endpoint and credential boundary'),
  ('ldap_', 'prefix', 'quarantine', 10, 'directory endpoint and credential boundary'),
  ('saml', 'prefix', 'quarantine', 10, 'external identity trust boundary'),
  ('oidc', 'prefix', 'quarantine', 10, 'external identity trust boundary'),
  ('m365.', 'prefix', 'quarantine', 10, 'external migration credential boundary'),
  ('ews.', 'prefix', 'quarantine', 10, 'external migration credential boundary'),
  ('imap.', 'prefix', 'quarantine', 10, 'external migration credential boundary'),
  ('assist.', 'prefix', 'quarantine', 10, 'external AI endpoint and credential boundary'),
  ('webhook', 'prefix', 'quarantine', 10, 'outbound execution boundary'),
  ('auto_update.', 'prefix', 'operator_approve', 20, 'software supply-chain source boundary'),
  ('trusted_proxy', 'prefix', 'operator_approve', 20, 'network trust boundary'),
  ('ca_break_glass', 'prefix', 'operator_approve', 20, 'authentication lockout boundary'),
  ('identity_source', 'exact', 'operator_approve', 20, 'authentication authority boundary')
ON CONFLICT (pattern) DO UPDATE SET
  match_kind=EXCLUDED.match_kind, disposition=EXCLUDED.disposition,
  priority=EXCLUDED.priority, rationale=EXCLUDED.rationale;

CREATE OR REPLACE FUNCTION public.restore_config_disposition(p_key text, p_encrypted boolean)
RETURNS text AS $$
DECLARE v_disposition text;
BEGIN
  IF p_encrypted THEN RETURN 'rotate'; END IF;
  SELECT disposition INTO v_disposition
    FROM public.restore_config_policy_catalog
   WHERE (match_kind='exact' AND pattern=p_key)
      OR (match_kind='prefix' AND p_key LIKE pattern || '%')
   ORDER BY priority, length(pattern) DESC LIMIT 1;
  RETURN coalesce(v_disposition, 'quarantine');
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION public.restore_config_apply(
  p_key text, p_value jsonb, p_encrypted boolean, p_source_verified boolean
) RETURNS text AS $$
DECLARE v_disposition text;
BEGIN
  v_disposition := public.restore_config_disposition(p_key, p_encrypted);
  IF v_disposition='safe' OR (v_disposition='operator_approve' AND p_source_verified) THEN
    INSERT INTO public.system_config(key,value,encrypted,updated_at)
    VALUES (p_key,p_value,p_encrypted,now())
    ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value,
      encrypted=EXCLUDED.encrypted,updated_at=now();
  ELSE
    INSERT INTO public.restore_config_quarantine(
      config_key,config_value,encrypted,disposition,source_verified
    ) VALUES (p_key,p_value,p_encrypted,v_disposition,p_source_verified);
  END IF;
  RETURN v_disposition;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

REVOKE ALL ON public.restore_config_policy_catalog, public.restore_config_quarantine FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.restore_config_disposition(text,boolean) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.restore_config_apply(text,jsonb,boolean,boolean) FROM PUBLIC;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_app') THEN
    GRANT EXECUTE ON FUNCTION public.restore_config_disposition(text,boolean) TO setjoin_app;
    GRANT EXECUTE ON FUNCTION public.restore_config_apply(text,jsonb,boolean,boolean) TO setjoin_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_worker') THEN
    GRANT EXECUTE ON FUNCTION public.restore_config_disposition(text,boolean) TO setjoin_worker;
    GRANT EXECUTE ON FUNCTION public.restore_config_apply(text,jsonb,boolean,boolean) TO setjoin_worker;
  END IF;
END $$;

INSERT INTO public.schema_migrations(version, applied_at) VALUES (229, now()) ON CONFLICT DO NOTHING;
