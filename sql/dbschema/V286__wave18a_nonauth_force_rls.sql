-- V286__wave18a_nonauth_force_rls.sql — Wave 1.8 Phase 546b: Wave A FORCE RLS
-- across 20 non-auth user/mailbox-scoped tables (cal/contacts/blobs/approvals/
-- user-settings/email_templates).
--
-- Security model (DATABASE_SECURITY.md R4 + ARCH-018):
--   1. All 20 tables receive ENABLE + FORCE ROW LEVEL SECURITY and least-privilege
--      `TO setjoin_app` policies. Missing/empty GUCs fail closed (NULLIF(..., '')
--      evaluates to NULL -> FALSE).
--   2. Mutual RLS recursion between `calendars` <-> `calendar_acls` (and parent
--      lookups for `calendar_events`, `event_attendees`, `vt_timezone`, `contacts`,
--      `contact_group_members`, plus `UserTx` multi-mailbox CalDAV/CardDAV scope)
--      is broken with narrow `ARCH-018` SECURITY DEFINER helpers owned by
--      `setjoin_worker` (`SET search_path = pg_catalog, public`, REVOKE ALL FROM
--      PUBLIC, GRANT EXECUTE TO setjoin_app).
--   3. Cross-tenant/public reducers (`approval_active_delegate`,
--      `calendar_effective_acl`, `jmap_calendar_*shared*`, `calendar_free_busy*`,
--      `calendar_check_conflict`, `calendar_book_resource`,
--      `jmap_calendar_resource_list`, `calendar_finalize_create_bookings`,
--      `recipients_ooo_status`, `booking_slots/create/confirm/cancel`) are
--      worker-owned SECURITY DEFINER boundaries in `mailserver/sql/reducers/`.
--   4. Locking & PG 15+ non-superuser DDL safety:
--      - `SET LOCAL lock_timeout = '5s'` inside a single transaction.
--      - Tables locked in canonical order (`collections -> items -> leaves`).
--      - Transient `GRANT CREATE ON SCHEMA public TO setjoin_worker` around
--        `apply_worker_ownership(...)` when not already held, revoked before
--        commit so non-superuser `setjoin_owner` never hits SQLSTATE 42501.

BEGIN;

SET LOCAL lock_timeout = '5s';

-- Canonical lock order: collections -> items -> leaves.
LOCK TABLE
  public.calendars,
  public.calendar_acls,
  public.calendar_events,
  public.event_attendees,
  public.vt_timezone,
  public.addressbooks,
  public.contacts,
  public.contact_groups,
  public.contact_group_members,
  public.reminders,
  public.blob_user_usage,
  public.blob_user_charges,
  public.approval_delegations,
  public.signatures,
  public.user_imap_settings,
  public.user_notification_prefs,
  public.user_signatures,
  public.vacation_settings,
  public.vacation_replies,
  public.email_templates
IN ACCESS EXCLUSIVE MODE;

-- ── ARCH-018 SECURITY DEFINER RLS helpers (worker-owned, search_path pinned) ──
-- All helpers return pure BOOLEAN predicates (never raw foreign IDs or permission
-- strings) and read app.current_user_id / app.current_mailbox_id internally.

-- True iff the effective caller role is superuser, BYPASSRLS, or a member of
-- setjoin_worker. Handles both direct connections (current_setting('role')='none')
-- and test-harness `SET LOCAL ROLE setjoin_app` from a superuser session.
CREATE OR REPLACE FUNCTION public.rls_caller_is_privileged()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_roles r
     WHERE r.rolname = COALESCE(NULLIF(current_setting('role', true), 'none'), session_user)
       AND (
         r.rolsuper
         OR r.rolbypassrls
         OR pg_catalog.pg_has_role(r.rolname, 'setjoin_worker', 'USAGE')
       )
  );
$$;

-- Mailbox scope predicate for collections reachable via BOTH MailboxTx
-- (sets app.current_mailbox_id — strict single-mailbox isolation, even under
-- divergent user_id != mailbox_id) AND UserTx (sets only app.current_user_id —
-- multi-mailbox CalDAV/CardDAV/Contacts projections). Unset GUCs fail closed.
CREATE OR REPLACE FUNCTION public.rls_mailbox_in_scope(p_mailbox_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT CASE
    WHEN NULLIF(current_setting('app.current_mailbox_id', true), '') IS NOT NULL THEN
      p_mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint
    WHEN NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL THEN
      EXISTS (
        SELECT 1
          FROM public.mailboxes m
         WHERE m.id = p_mailbox_id
           AND m.user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
      )
    ELSE FALSE
  END;
$$;

-- Pure boolean parent-scope & current-user ACL predicates breaking
-- calendars <-> calendar_acls mutual RLS recursion without exposing foreign IDs.
CREATE OR REPLACE FUNCTION public.rls_calendar_in_scope(p_calendar_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.calendars c
     WHERE c.id = p_calendar_id
       AND public.rls_mailbox_in_scope(c.mailbox_id)
  );
$$;

CREATE OR REPLACE FUNCTION public.rls_calendar_acl_for_current_user(
  p_calendar_id bigint,
  p_levels      text[]
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.calendar_acls a
     WHERE a.calendar_id = p_calendar_id
       AND a.user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
       AND a.permission = ANY(p_levels)
  );
$$;

CREATE OR REPLACE FUNCTION public.rls_calendar_event_in_scope(p_event_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.calendar_events ce
      JOIN public.calendars c ON c.id = ce.calendar_id
     WHERE ce.id = p_event_id
       AND public.rls_mailbox_in_scope(c.mailbox_id)
  );
$$;

CREATE OR REPLACE FUNCTION public.rls_calendar_event_acl_for_current_user(
  p_event_id       bigint,
  p_levels         text[],
  p_require_public boolean DEFAULT false
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.calendar_events ce
      JOIN public.calendar_acls a ON a.calendar_id = ce.calendar_id
     WHERE ce.id = p_event_id
       AND a.user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
       AND a.permission = ANY(p_levels)
       AND (NOT p_require_public OR ce.classification = 'PUBLIC')
  );
$$;

CREATE OR REPLACE FUNCTION public.rls_addressbook_in_scope(p_addressbook_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.addressbooks ab
     WHERE ab.id = p_addressbook_id
       AND public.rls_mailbox_in_scope(ab.mailbox_id)
  );
$$;

CREATE OR REPLACE FUNCTION public.rls_contact_group_in_scope(p_group_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.contact_groups cg
     WHERE cg.id = p_group_id
       AND public.rls_mailbox_in_scope(cg.mailbox_id)
  );
$$;

-- PG 15+ owner-safe worker ownership transfer (transient CREATE on public only
-- when absent, always revoked before leaving the DO block).
DO $$
DECLARE
  v_granted_create boolean := false;
  v_fn regprocedure;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    IF NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
      EXECUTE 'GRANT CREATE ON SCHEMA public TO setjoin_worker';
      v_granted_create := true;
    END IF;
  END IF;

  BEGIN
    FOREACH v_fn IN ARRAY ARRAY[
      'public.rls_caller_is_privileged()'::regprocedure,
      'public.rls_mailbox_in_scope(bigint)'::regprocedure,
      'public.rls_calendar_in_scope(bigint)'::regprocedure,
      'public.rls_calendar_acl_for_current_user(bigint,text[])'::regprocedure,
      'public.rls_calendar_event_in_scope(bigint)'::regprocedure,
      'public.rls_calendar_event_acl_for_current_user(bigint,text[],boolean)'::regprocedure,
      'public.rls_addressbook_in_scope(bigint)'::regprocedure,
      'public.rls_contact_group_in_scope(bigint)'::regprocedure
    ] LOOP
      PERFORM public.apply_worker_ownership(v_fn);
    END LOOP;
  EXCEPTION WHEN OTHERS THEN
    IF v_granted_create THEN
      EXECUTE 'REVOKE CREATE ON SCHEMA public FROM setjoin_worker';
    END IF;
    RAISE;
  END;

  IF v_granted_create THEN
    EXECUTE 'REVOKE CREATE ON SCHEMA public FROM setjoin_worker';
  END IF;
END $$;

-- ── Enable + Force RLS and least-privilege setjoin_app policies (20 tables) ──

-- 1. calendars
ALTER TABLE public.calendars ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.calendars FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS calendars_app_select ON public.calendars;
CREATE POLICY calendars_app_select ON public.calendars
  FOR SELECT TO setjoin_app
  USING (
    public.rls_mailbox_in_scope(mailbox_id)
    OR public.rls_calendar_acl_for_current_user(
         id, ARRAY['freebusy', 'read', 'write', 'admin']
       )
  );
DROP POLICY IF EXISTS calendars_app_insert ON public.calendars;
CREATE POLICY calendars_app_insert ON public.calendars
  FOR INSERT TO setjoin_app
  WITH CHECK (public.rls_mailbox_in_scope(mailbox_id));
DROP POLICY IF EXISTS calendars_app_update ON public.calendars;
CREATE POLICY calendars_app_update ON public.calendars
  FOR UPDATE TO setjoin_app
  USING (public.rls_mailbox_in_scope(mailbox_id))
  WITH CHECK (public.rls_mailbox_in_scope(mailbox_id));
DROP POLICY IF EXISTS calendars_app_delete ON public.calendars;
CREATE POLICY calendars_app_delete ON public.calendars
  FOR DELETE TO setjoin_app
  USING (public.rls_mailbox_in_scope(mailbox_id));

-- 2. calendar_acls
ALTER TABLE public.calendar_acls ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.calendar_acls FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS calendar_acls_app_select ON public.calendar_acls;
CREATE POLICY calendar_acls_app_select ON public.calendar_acls
  FOR SELECT TO setjoin_app
  USING (
    user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
    OR public.rls_calendar_in_scope(calendar_id)
    OR public.rls_calendar_acl_for_current_user(calendar_id, ARRAY['admin'])
  );
DROP POLICY IF EXISTS calendar_acls_app_insert ON public.calendar_acls;
CREATE POLICY calendar_acls_app_insert ON public.calendar_acls
  FOR INSERT TO setjoin_app
  WITH CHECK (
    public.rls_calendar_in_scope(calendar_id)
    OR public.rls_calendar_acl_for_current_user(calendar_id, ARRAY['admin'])
  );
DROP POLICY IF EXISTS calendar_acls_app_update ON public.calendar_acls;
CREATE POLICY calendar_acls_app_update ON public.calendar_acls
  FOR UPDATE TO setjoin_app
  USING (
    public.rls_calendar_in_scope(calendar_id)
    OR public.rls_calendar_acl_for_current_user(calendar_id, ARRAY['admin'])
  )
  WITH CHECK (
    public.rls_calendar_in_scope(calendar_id)
    OR public.rls_calendar_acl_for_current_user(calendar_id, ARRAY['admin'])
  );
DROP POLICY IF EXISTS calendar_acls_app_delete ON public.calendar_acls;
CREATE POLICY calendar_acls_app_delete ON public.calendar_acls
  FOR DELETE TO setjoin_app
  USING (
    public.rls_calendar_in_scope(calendar_id)
    OR public.rls_calendar_acl_for_current_user(calendar_id, ARRAY['admin'])
  );

-- 3. calendar_events
-- Grantees with 'freebusy' or non-PUBLIC events must use jmap_calendar_event_get_shared
-- / calendar_free_busy* which redact titles/locations/descriptions to 'Busy'.
ALTER TABLE public.calendar_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.calendar_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS calendar_events_app_select ON public.calendar_events;
CREATE POLICY calendar_events_app_select ON public.calendar_events
  FOR SELECT TO setjoin_app
  USING (
    public.rls_calendar_in_scope(calendar_id)
    OR (
      classification = 'PUBLIC'
      AND public.rls_calendar_acl_for_current_user(
            calendar_id, ARRAY['read', 'write', 'admin']
          )
    )
  );
DROP POLICY IF EXISTS calendar_events_app_insert ON public.calendar_events;
CREATE POLICY calendar_events_app_insert ON public.calendar_events
  FOR INSERT TO setjoin_app
  WITH CHECK (
    public.rls_calendar_in_scope(calendar_id)
    OR public.rls_calendar_acl_for_current_user(calendar_id, ARRAY['write', 'admin'])
  );
DROP POLICY IF EXISTS calendar_events_app_update ON public.calendar_events;
CREATE POLICY calendar_events_app_update ON public.calendar_events
  FOR UPDATE TO setjoin_app
  USING (
    public.rls_calendar_in_scope(calendar_id)
    OR public.rls_calendar_acl_for_current_user(calendar_id, ARRAY['write', 'admin'])
  )
  WITH CHECK (
    public.rls_calendar_in_scope(calendar_id)
    OR public.rls_calendar_acl_for_current_user(calendar_id, ARRAY['write', 'admin'])
  );
DROP POLICY IF EXISTS calendar_events_app_delete ON public.calendar_events;
CREATE POLICY calendar_events_app_delete ON public.calendar_events
  FOR DELETE TO setjoin_app
  USING (
    public.rls_calendar_in_scope(calendar_id)
    OR public.rls_calendar_acl_for_current_user(calendar_id, ARRAY['write', 'admin'])
  );

-- 4. event_attendees
ALTER TABLE public.event_attendees ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.event_attendees FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS event_attendees_app_select ON public.event_attendees;
CREATE POLICY event_attendees_app_select ON public.event_attendees
  FOR SELECT TO setjoin_app
  USING (
    public.rls_calendar_event_in_scope(event_id)
    OR public.rls_calendar_event_acl_for_current_user(
         event_id, ARRAY['read', 'write', 'admin'], true
       )
  );
DROP POLICY IF EXISTS event_attendees_app_insert ON public.event_attendees;
CREATE POLICY event_attendees_app_insert ON public.event_attendees
  FOR INSERT TO setjoin_app
  WITH CHECK (
    public.rls_calendar_event_in_scope(event_id)
    OR public.rls_calendar_event_acl_for_current_user(
         event_id, ARRAY['write', 'admin'], false
       )
  );
DROP POLICY IF EXISTS event_attendees_app_update ON public.event_attendees;
CREATE POLICY event_attendees_app_update ON public.event_attendees
  FOR UPDATE TO setjoin_app
  USING (
    public.rls_calendar_event_in_scope(event_id)
    OR public.rls_calendar_event_acl_for_current_user(
         event_id, ARRAY['write', 'admin'], false
       )
  )
  WITH CHECK (
    public.rls_calendar_event_in_scope(event_id)
    OR public.rls_calendar_event_acl_for_current_user(
         event_id, ARRAY['write', 'admin'], false
       )
  );
DROP POLICY IF EXISTS event_attendees_app_delete ON public.event_attendees;
CREATE POLICY event_attendees_app_delete ON public.event_attendees
  FOR DELETE TO setjoin_app
  USING (
    public.rls_calendar_event_in_scope(event_id)
    OR public.rls_calendar_event_acl_for_current_user(
         event_id, ARRAY['write', 'admin'], false
       )
  );

-- 5. vt_timezone
ALTER TABLE public.vt_timezone ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vt_timezone FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS vt_timezone_app_select ON public.vt_timezone;
CREATE POLICY vt_timezone_app_select ON public.vt_timezone
  FOR SELECT TO setjoin_app
  USING (
    public.rls_calendar_in_scope(calendar_id)
    OR public.rls_calendar_acl_for_current_user(
         calendar_id, ARRAY['read', 'write', 'admin']
       )
  );
DROP POLICY IF EXISTS vt_timezone_app_insert ON public.vt_timezone;
CREATE POLICY vt_timezone_app_insert ON public.vt_timezone
  FOR INSERT TO setjoin_app
  WITH CHECK (public.rls_calendar_in_scope(calendar_id));
DROP POLICY IF EXISTS vt_timezone_app_update ON public.vt_timezone;
CREATE POLICY vt_timezone_app_update ON public.vt_timezone
  FOR UPDATE TO setjoin_app
  USING (public.rls_calendar_in_scope(calendar_id))
  WITH CHECK (public.rls_calendar_in_scope(calendar_id));
DROP POLICY IF EXISTS vt_timezone_app_delete ON public.vt_timezone;
CREATE POLICY vt_timezone_app_delete ON public.vt_timezone
  FOR DELETE TO setjoin_app
  USING (public.rls_calendar_in_scope(calendar_id));

-- 6. addressbooks
ALTER TABLE public.addressbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.addressbooks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS addressbooks_app_all ON public.addressbooks;
CREATE POLICY addressbooks_app_all ON public.addressbooks
  FOR ALL TO setjoin_app
  USING (public.rls_mailbox_in_scope(mailbox_id))
  WITH CHECK (public.rls_mailbox_in_scope(mailbox_id));

-- 7. contacts
ALTER TABLE public.contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.contacts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS contacts_app_all ON public.contacts;
CREATE POLICY contacts_app_all ON public.contacts
  FOR ALL TO setjoin_app
  USING (public.rls_addressbook_in_scope(addressbook_id))
  WITH CHECK (public.rls_addressbook_in_scope(addressbook_id));

-- 8. contact_groups
ALTER TABLE public.contact_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.contact_groups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS contact_groups_app_all ON public.contact_groups;
CREATE POLICY contact_groups_app_all ON public.contact_groups
  FOR ALL TO setjoin_app
  USING (public.rls_mailbox_in_scope(mailbox_id))
  WITH CHECK (public.rls_mailbox_in_scope(mailbox_id));

-- 9. contact_group_members
ALTER TABLE public.contact_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.contact_group_members FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS contact_group_members_app_all ON public.contact_group_members;
CREATE POLICY contact_group_members_app_all ON public.contact_group_members
  FOR ALL TO setjoin_app
  USING (public.rls_contact_group_in_scope(group_id))
  WITH CHECK (public.rls_contact_group_in_scope(group_id));

-- 10. reminders
ALTER TABLE public.reminders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reminders FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS reminders_app_all ON public.reminders;
CREATE POLICY reminders_app_all ON public.reminders
  FOR ALL TO setjoin_app
  USING (mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint)
  WITH CHECK (mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint);

-- 11. blob_user_usage
ALTER TABLE public.blob_user_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.blob_user_usage FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS blob_user_usage_app_all ON public.blob_user_usage;
CREATE POLICY blob_user_usage_app_all ON public.blob_user_usage
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 12. blob_user_charges
ALTER TABLE public.blob_user_charges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.blob_user_charges FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS blob_user_charges_app_all ON public.blob_user_charges;
CREATE POLICY blob_user_charges_app_all ON public.blob_user_charges
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 13. approval_delegations
ALTER TABLE public.approval_delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.approval_delegations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS approval_delegations_app_select ON public.approval_delegations;
CREATE POLICY approval_delegations_app_select ON public.approval_delegations
  FOR SELECT TO setjoin_app
  USING (
    delegator_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
    OR delegate_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
  );
DROP POLICY IF EXISTS approval_delegations_app_insert ON public.approval_delegations;
CREATE POLICY approval_delegations_app_insert ON public.approval_delegations
  FOR INSERT TO setjoin_app
  WITH CHECK (
    delegator_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
  );
DROP POLICY IF EXISTS approval_delegations_app_update ON public.approval_delegations;
CREATE POLICY approval_delegations_app_update ON public.approval_delegations
  FOR UPDATE TO setjoin_app
  USING (
    delegator_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
  )
  WITH CHECK (
    delegator_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
  );
DROP POLICY IF EXISTS approval_delegations_app_delete ON public.approval_delegations;
CREATE POLICY approval_delegations_app_delete ON public.approval_delegations
  FOR DELETE TO setjoin_app
  USING (
    delegator_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
  );

-- 14. signatures
ALTER TABLE public.signatures ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.signatures FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS signatures_app_all ON public.signatures;
CREATE POLICY signatures_app_all ON public.signatures
  FOR ALL TO setjoin_app
  USING (mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint)
  WITH CHECK (mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint);

-- 15. user_imap_settings
ALTER TABLE public.user_imap_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_imap_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_imap_settings_app_all ON public.user_imap_settings;
CREATE POLICY user_imap_settings_app_all ON public.user_imap_settings
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 16. user_notification_prefs
ALTER TABLE public.user_notification_prefs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_notification_prefs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_notification_prefs_app_all ON public.user_notification_prefs;
CREATE POLICY user_notification_prefs_app_all ON public.user_notification_prefs
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 17. user_signatures
ALTER TABLE public.user_signatures ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_signatures FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_signatures_app_all ON public.user_signatures;
CREATE POLICY user_signatures_app_all ON public.user_signatures
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 18. vacation_settings
ALTER TABLE public.vacation_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vacation_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS vacation_settings_app_all ON public.vacation_settings;
CREATE POLICY vacation_settings_app_all ON public.vacation_settings
  FOR ALL TO setjoin_app
  USING (mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint)
  WITH CHECK (mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint);

-- 19. vacation_replies
ALTER TABLE public.vacation_replies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vacation_replies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS vacation_replies_app_all ON public.vacation_replies;
CREATE POLICY vacation_replies_app_all ON public.vacation_replies
  FOR ALL TO setjoin_app
  USING (mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint)
  WITH CHECK (mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint);

-- 20. email_templates
ALTER TABLE public.email_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_templates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS email_templates_app_all ON public.email_templates;
CREATE POLICY email_templates_app_all ON public.email_templates
  FOR ALL TO setjoin_app
  USING (mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint)
  WITH CHECK (mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint);

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (286, now())
ON CONFLICT (version) DO NOTHING;

COMMIT;
