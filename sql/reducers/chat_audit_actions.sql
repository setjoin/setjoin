-- mailserver/sql/reducers/chat_audit_actions.sql
-- Closed act catalog for the per-conversation chain (chat's analog of
-- drive_audit_actions.sql). Chain hashes do NOT depend on the catalog, so
-- adding a member later never invalidates existing rows.
-- Chat A4a Task 2: retired-docs:superpowers/plans/archive/2026-07-12-chat-A4a-records-lifecycle.md
CREATE OR REPLACE FUNCTION chat_audit_actions() RETURNS JSONB
LANGUAGE sql IMMUTABLE AS $$ SELECT jsonb_build_array(
  -- A4a writers:
  'message.edit', 'message.delete', 'pin.add', 'pin.remove',
  'member.add', 'member.remove', 'member.join', 'member.leave',
  'hold.set', 'hold.release', 'classification.change', 'retention.change',
  'purge.execute', 'chain.anchor', 'translate.egress',
  -- Reserved, no writer in A4a:
  --   role.change   : no channel role-change reducer exists yet (A4b/roster work)
  --   rescope.execute: the 'g'→'s<id>' chunk re-scope, DEFERRED to Drive P5 with
  --                    the Object-Lock call that gives per-space scope its meaning
  --                    (gate decision 1). Catalogued now so P5/A4b adds a writer,
  --                    not a migration. NO WRITER EXISTS — do not wire one here.
  'role.change', 'rescope.execute',
  -- A4b-reserved:
  'export.run', 'search.run', 'dlp.block', 'barrier.change',
  'membership.inherit', 'push.emission'
) $$;
