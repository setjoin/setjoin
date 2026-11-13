-- Frozen Go's `migration.contactStore.remove` (vCard overwrite strategy): one
-- DELETE with the owner-mailbox join in its WHERE (R3). Returns RowsAffected.
CREATE OR REPLACE FUNCTION rust_contacts_import_remove(
 p_owner bigint, p_book bigint, p_uid text
) RETURNS bigint LANGUAGE plpgsql VOLATILE AS $$
DECLARE
 v_rows bigint;
BEGIN
 DELETE FROM contacts c USING addressbooks ab
  WHERE ab.id = c.addressbook_id AND c.addressbook_id = p_book AND c.vcard_uid = p_uid
    AND ab.mailbox_id = p_owner;
 GET DIAGNOSTICS v_rows = ROW_COUNT;
 RETURN v_rows;
END;
$$;
