-- Frozen Go's EmailAddressPolicyHandler.Reorder: one UPDATE per listed id in list
-- order (priority (i+1)*10), so the enabled-priority unique index sees the same
-- intermediate states as Go's loop. A collision raises 23505 for the adapter's 500.
-- Unknown ids update nothing. No audit row, as in Go.
CREATE OR REPLACE FUNCTION rust_admin_eap_reorder(p_order bigint[])
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 FOR i IN 1..COALESCE(cardinality(p_order),0) LOOP
  UPDATE email_address_policies SET priority = i * 10, updated_at = now() WHERE id = p_order[i];
 END LOOP;
END;
$$;
