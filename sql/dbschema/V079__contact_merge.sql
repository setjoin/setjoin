-- V079: Contacts — find & merge duplicates.
--
-- Adds two reducers to reducers/jmap_contact.sql:
--   contact_find_duplicates(p_mailbox_id)          — cluster the caller's contacts
--                                                     by lower(email address).
--   contact_merge(p_mailbox_id, p_keep_id, p_drop_id) — atomic field-union merge of
--                                                     a duplicate into a keeper.
--
-- House style (mirrors V070 approval_engine): reducers are CREATE OR REPLACE in
-- reducers/*.sql (the canonical, glob-loaded source) — NOT inlined here, so there
-- is one source home per reducer and no two-home drift (sql/AGENTS.md schema-truth
-- rule). This migration is a pure reducer addition with NO schema change; it only
-- advances the schema_migrations version so mailserverd's refuse-to-start guard
-- (dbschema.ExpectedVersion) and load-test-schema stay in lock-step. Deploy reloads
-- reducers (reload-reducers.sh) so existing DBs pick up the two new functions.
--
-- New error code BZ112 (contact_merge_not_found) — see docs/reducer-error-codes.md.

INSERT INTO public.schema_migrations (version, applied_at) VALUES (79, now())
  ON CONFLICT (version) DO NOTHING;
