-- V112__task_lists.sql — shared/team task lists (Phase 1: user-owned + explicit members).
-- Spec: docs/superpowers/plans/archive/2026-07-08-shared-team-task-lists.md.
--
-- task_lists is USER-keyed (owner_user_id), not mailbox-keyed — a list is not
-- mail data; membership rows grant cross-mailbox task visibility the same way
-- mailbox_delegates grants mailbox access. state_seq is the per-list sync token
-- (bumped in-txn by notify_task_list_state, the calendar-seam pattern).

CREATE TABLE public.task_lists (
    id            BIGSERIAL PRIMARY KEY,
    owner_user_id BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL CHECK (name <> '' AND length(name) <= 200),
    color         TEXT,
    state_seq     BIGINT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.task_list_members (
    list_id          BIGINT NOT NULL REFERENCES public.task_lists(id) ON DELETE CASCADE,
    user_id          BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    role             TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner','member')),
    added_by_user_id BIGINT REFERENCES public.users(id) ON DELETE SET NULL,
    added_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (list_id, user_id)
);
CREATE INDEX task_list_members_user_idx ON public.task_list_members (user_id);

-- A shared task stays a tasks row (recurrence/checklist/activity/reminders all
-- keep working). ON DELETE SET NULL: deleting a list re-personalizes its tasks
-- into their creators' mailboxes — no silent cross-user data loss.
ALTER TABLE public.tasks
    ADD COLUMN list_id BIGINT REFERENCES public.task_lists(id) ON DELETE SET NULL;
CREATE INDEX tasks_list_idx     ON public.tasks (list_id)          WHERE list_id IS NOT NULL;
-- tasks_assignee_idx already exists (V001__baseline.sql) — assignee lookups are
-- already indexed; nothing new to add here.

-- ── Latent RLS backstop (V090 shape: INERT for the superuser/worker pools,
--    engages at the setjoin_app DSN flip; fail-closed InitPlan NULLIF form).
--    Only the app.current_user_id GUC — these tables are user-keyed and only
--    reached via workerPool reducer calls today.
--
-- DELIBERATELY NARROWER than the app layer (task_list_get/task_list_get_roster,
-- both BYPASSRLS reads): a member's full "see the lists/rosters I belong to"
-- view requires a task_lists↔task_list_members CROSS-TABLE lookup in BOTH
-- directions, which is a documented Postgres footgun — table A's policy
-- subquery into table B, whose OWN policy subqueries back into table A,
-- "infinite recursion detected in policy for relation" (tried and reverted;
-- a same-table self-join has the identical failure mode, one table sooner).
-- The backstop below breaks the cycle by keeping task_lists' policies as pure
-- column checks (owner_user_id — no reference to task_list_members at all),
-- so only task_list_members' policies look outward (one direction, no loop):
--   · task_lists:        ONLY the owner can SELECT/mutate their list under RLS.
--   · task_list_members: a member sees their OWN row; the owner sees every row
--                          (checked against task_lists — safe, no cycle back).
-- This is strictly conservative (never over-grants) and inert today regardless
-- — every real cross-mailbox read/write rides workerPool/BYPASSRLS via the
-- task_lists.sql / task_list_tasks.sql reducers, never this policy.
-- FOR ALL (not just SELECT) so this one policy covers both the owner's read
-- and write — no separate read-only policy needed (nothing else may read).
CREATE POLICY task_lists_owner_write ON public.task_lists
  FOR ALL TO public
  USING      (owner_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
  WITH CHECK (owner_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint));
ALTER TABLE public.task_lists ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.task_lists FORCE  ROW LEVEL SECURITY;

CREATE POLICY task_list_members_read ON public.task_list_members
  FOR SELECT TO public
  USING (
    user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
    OR EXISTS (SELECT 1 FROM public.task_lists l
               WHERE l.id = task_list_members.list_id
                 AND l.owner_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
  );
CREATE POLICY task_list_members_owner_write ON public.task_list_members
  FOR ALL TO public
  USING (EXISTS (SELECT 1 FROM public.task_lists l
                 WHERE l.id = task_list_members.list_id
                   AND l.owner_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)))
  WITH CHECK (EXISTS (SELECT 1 FROM public.task_lists l
                      WHERE l.id = task_list_members.list_id
                        AND l.owner_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)));
ALTER TABLE public.task_list_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.task_list_members FORCE  ROW LEVEL SECURITY;

-- NOTE: public.tasks deliberately stays RLS-less (its recorded ARCH-006 posture,
-- V102 header) — shared-task isolation is in-reducer membership predicates on
-- workerPool, like every shipped cross-mailbox surface.

INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.shared_task_lists', false,
   'Shared/team task lists + cross-mailbox assigned-to-me. Seeded OFF; flip per-org at rollout.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (112, now()) ON CONFLICT DO NOTHING;
