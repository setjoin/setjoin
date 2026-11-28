-- V077: drop the dead folders.total_count / unread_count / size_bytes counters.
--
-- These were never read on any live path: JMAP Mailbox/get reads tags.*_count
-- (jmap_mailbox.sql), IMAP removed its folders-counter writes, and messages.folder_id
-- holds a TAG id (a legacy denorm mirror written by trg_message_tags_primary_sync),
-- so the only writer (adjust_folder_counters, via enforce_retention) was updating
-- these by the wrong id-space anyway. The live equivalents are
-- tags.total_count/unread_count/size_bytes, maintained by trg_message_tags_counters.
--
-- The one LIVE thing adjust_folder_counters also did — decrement mailboxes.used_bytes
-- and bump JMAP state on retention delete — was silently broken by the same tag-id
-- mismatch (it early-returned). enforce_retention now does that directly by
-- mailbox_id (mirroring jmap_email_purge), so this drop also un-hides + fixes the
-- retention quota-drift. adjust_folder_counters() itself is dropped in utils.sql.
-- See TODOS.md ("dead legacy-folders-counter mechanism").

ALTER TABLE public.folders
  DROP CONSTRAINT IF EXISTS folders_total_count_check,
  DROP CONSTRAINT IF EXISTS folders_unread_count_check,
  DROP CONSTRAINT IF EXISTS folders_size_bytes_check;

ALTER TABLE public.folders
  DROP COLUMN IF EXISTS total_count,
  DROP COLUMN IF EXISTS unread_count,
  DROP COLUMN IF EXISTS size_bytes;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (77, now())
  ON CONFLICT (version) DO NOTHING;
