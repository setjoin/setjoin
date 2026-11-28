-- ════════════════════════════════════════════════════════════════════════
-- V090__mailbox_delegates_rls.sql — FORCE-RLS coverage for mailbox_delegates
-- (the V089 deferral: "mailbox_delegates FORCE RLS deferred to its own
-- coverage wave"). Native-RLS backstop W7 follow-up, plan
-- docs/superpowers/plans/archive/2026-06-18-native-rls-backstop.md; spec
-- docs/superpowers/specs/2026-06-27-sharing-delegation-design.md §4.
--
-- Like V004/V017/V089 this is a REAL forcing migration that is INERT for the
-- current superuser/owner pool identity; it engages when the prod DSN switches
-- to setjoin_app (docs/standards/DATABASE_SECURITY.md deploy gate).
--
-- Row model: (mailbox_id, user_id, permission) — "user_id may act on
-- mailbox_id". Two principals therefore have a legitimate tenant view:
--   · the OWNER of the mailbox (grants/revokes/lists their delegates), and
--   · the DELEGATE the row names (send-as identity list, Calendar/delegateList,
--     MailTips send-as check, the jmap_mailbox_get shared-tag join).
-- Both GUC conventions are admitted because both reach this table:
--   · app.current_user_id   — dbscope.RunUserScoped paths;
--   · app.current_mailbox_id — jmap CallScoped reducer paths (jmap_mailbox_get,
--     jmap_calendar_event_set_create delegatedFrom, jmap_calendar_event_rsvp
--     delegate respond), translated to the mailbox's owning user.
-- Admin oversight (admin_sharing.go) and the user sharing surface ride the
-- setjoin_worker BYPASSRLS pool and never consult these policies.
-- Fail-closed: no GUC → no rows (InitPlan NULLIF form, V003 shape).

-- Read: the mailbox owner (either GUC convention) OR the named delegate.
CREATE POLICY mailbox_delegates_read ON public.mailbox_delegates
  FOR SELECT TO public
  USING (
    -- owner arm: the row's mailbox belongs to the GUC principal
    EXISTS (
      SELECT 1 FROM public.mailboxes mb
      WHERE mb.id = mailbox_delegates.mailbox_id
        AND (mb.user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
             OR mb.id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint))
    )
    -- delegate arm: the row names the GUC principal as the delegate
    OR mailbox_delegates.user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
    OR mailbox_delegates.user_id = (SELECT mb2.user_id FROM public.mailboxes mb2
                                    WHERE mb2.id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint))
  );

-- Write: the mailbox OWNER only (grant/revoke). A delegate can see rows naming
-- them but never mutate them; a foreign INSERT fails WITH CHECK (42501) and a
-- foreign DELETE sees zero rows (USING).
CREATE POLICY mailbox_delegates_owner_write ON public.mailbox_delegates
  FOR ALL TO public
  USING (
    EXISTS (
      SELECT 1 FROM public.mailboxes mb
      WHERE mb.id = mailbox_delegates.mailbox_id
        AND (mb.user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
             OR mb.id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint))
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.mailboxes mb
      WHERE mb.id = mailbox_delegates.mailbox_id
        AND (mb.user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
             OR mb.id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint))
    )
  );

ALTER TABLE public.mailbox_delegates ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mailbox_delegates FORCE  ROW LEVEL SECURITY;

INSERT INTO schema_migrations (version, applied_at) VALUES (90, now()) ON CONFLICT DO NOTHING;
