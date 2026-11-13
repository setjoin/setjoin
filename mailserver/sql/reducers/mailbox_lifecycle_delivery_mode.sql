-- Mailbox Lifecycle & Retention authority: mailbox_lifecycle_delivery_mode.

CREATE OR REPLACE FUNCTION mailbox_lifecycle_delivery_mode(p_mailbox_id bigint)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
  SELECT CASE WHEN NOT mailbox_lifecycle_enabled() THEN
    CASE WHEN COALESCE((SELECT receive_enabled FROM mailboxes WHERE id=p_mailbox_id),false) THEN 'accepting' ELSE 'rejecting' END
  ELSE COALESCE((SELECT delivery_state FROM mailbox_lifecycle WHERE mailbox_id=p_mailbox_id),'rejecting') END
$$;

ALTER FUNCTION mailbox_lifecycle_delivery_mode(bigint) OWNER TO setjoin_worker;
