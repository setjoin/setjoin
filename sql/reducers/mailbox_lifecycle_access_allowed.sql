-- Mailbox Lifecycle & Retention authority: mailbox_lifecycle_access_allowed.

CREATE OR REPLACE FUNCTION mailbox_lifecycle_access_allowed(p_mailbox_id bigint)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
  SELECT CASE WHEN NOT mailbox_lifecycle_enabled() THEN COALESCE((SELECT enabled FROM mailboxes WHERE id=p_mailbox_id),false)
              ELSE COALESCE((SELECT binding_state IN ('bound','shared') AND access_state='active' FROM mailbox_lifecycle WHERE mailbox_id=p_mailbox_id),false) END
$$;

ALTER FUNCTION mailbox_lifecycle_access_allowed(bigint) OWNER TO setjoin_worker;
