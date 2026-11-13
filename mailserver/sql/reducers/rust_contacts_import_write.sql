-- Frozen Go's contacts import statements (`migration.contactStore.insert` /
-- `.upsert`): one INSERT .. SELECT whose WHERE re-checks that the gate-verified
-- owner mailbox owns the target book (R3), optionally with the ON CONFLICT
-- upsert that regenerates the etag in the same statement. Returns Go's
-- RowsAffected (0 = the book is not owned by p_owner). Go runs each row on its
-- own pool call without a tenant GUC, so the change journal's best-effort write
-- is skipped under forced RLS exactly as before; the caller mirrors that and
-- carries no receipt. Follow-up: fold into the canonical contact reducer.
CREATE OR REPLACE FUNCTION rust_contacts_import_write(
 p_owner bigint, p_book bigint, p_uid text, p_display text, p_first text, p_last text,
 p_company text, p_title text, p_emails text, p_phones text, p_urls text, p_impps text,
 p_addresses text, p_notes text, p_birthday text, p_anniversary text, p_upsert boolean
) RETURNS bigint LANGUAGE plpgsql VOLATILE AS $$
DECLARE
 v_rows bigint;
BEGIN
 IF p_upsert THEN
  INSERT INTO contacts (addressbook_id, vcard_uid, display_name, first_name, last_name,
    company, job_title, emails, phones, urls, instant_msgs, addresses, notes, birthday, anniversary)
  SELECT p_book, p_uid, p_display, p_first, p_last, p_company, p_title,
         p_emails::jsonb, p_phones::jsonb, p_urls::jsonb, p_impps::jsonb, p_addresses::jsonb,
         p_notes, p_birthday::date, p_anniversary::date
   WHERE EXISTS (SELECT 1 FROM addressbooks ab WHERE ab.id = p_book AND ab.mailbox_id = p_owner)
  ON CONFLICT (addressbook_id, vcard_uid) DO UPDATE SET
    display_name = EXCLUDED.display_name, first_name = EXCLUDED.first_name,
    last_name = EXCLUDED.last_name, company = EXCLUDED.company,
    job_title = EXCLUDED.job_title, emails = EXCLUDED.emails, phones = EXCLUDED.phones,
    urls = EXCLUDED.urls, instant_msgs = EXCLUDED.instant_msgs,
    addresses = EXCLUDED.addresses, notes = EXCLUDED.notes, birthday = EXCLUDED.birthday,
    anniversary = EXCLUDED.anniversary, updated_at = now(),
    etag = encode(digest(contacts.vcard_uid || now()::TEXT, 'md5'), 'hex');
 ELSE
  INSERT INTO contacts (addressbook_id, vcard_uid, display_name, first_name, last_name,
    company, job_title, emails, phones, urls, instant_msgs, addresses, notes, birthday, anniversary)
  SELECT p_book, p_uid, p_display, p_first, p_last, p_company, p_title,
         p_emails::jsonb, p_phones::jsonb, p_urls::jsonb, p_impps::jsonb, p_addresses::jsonb,
         p_notes, p_birthday::date, p_anniversary::date
   WHERE EXISTS (SELECT 1 FROM addressbooks ab WHERE ab.id = p_book AND ab.mailbox_id = p_owner);
 END IF;
 GET DIAGNOSTICS v_rows = ROW_COUNT;
 RETURN v_rows;
END;
$$;
