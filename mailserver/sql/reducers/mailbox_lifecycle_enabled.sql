-- Mailbox Lifecycle & Retention authority: mailbox_lifecycle_enabled.

CREATE OR REPLACE FUNCTION mailbox_lifecycle_enabled() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
  SELECT COALESCE((SELECT enabled FROM feature_toggles
                    WHERE key='feature.mailbox_lifecycle_retention'),false)
$$;

ALTER FUNCTION mailbox_lifecycle_enabled() OWNER TO setjoin_worker;
