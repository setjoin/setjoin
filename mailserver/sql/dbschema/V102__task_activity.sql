-- V102__task_activity.sql — task comments + change-history activity feed (QoL #17).
--
-- One combined table for BOTH comments and system change-log entries (single
-- feed, matching Planner/飞书/Asana's unified activity view) — avoids a second
-- table + second reader. `kind` discriminates:
--   comment         — a user-authored note (body set, mentioned_user_ids resolved)
--   status_change   — task.status changed (meta = {old,new})
--   assignee_change — task.assignee changed (meta = {old,new})
--   due_change      — task.due_at changed (meta = {old,new})
--
-- No RLS ENABLE/FORCE — this matches tasks' own posture (app-level ownership
-- only, per ARCH-006). Reducers filter by mailbox_id the same way jmap_task.sql
-- does; the parent task's ON DELETE CASCADE keeps the feed from outliving its task.
CREATE TABLE public.task_activity (
    id                 BIGSERIAL PRIMARY KEY,
    task_id            BIGINT NOT NULL REFERENCES public.tasks(id) ON DELETE CASCADE,
    mailbox_id         BIGINT NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
    author_user_id     BIGINT NOT NULL REFERENCES public.users(id),
    kind               TEXT NOT NULL DEFAULT 'comment'
                         CHECK (kind IN ('comment','status_change','assignee_change','due_change')),
    body               TEXT CHECK (body IS NULL OR length(body) <= 5000),
    meta               JSONB,
    mentioned_user_ids BIGINT[] NOT NULL DEFAULT '{}',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX task_activity_task_idx ON public.task_activity (task_id, created_at);

-- ── Schema migration record ──────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (102, now())
    ON CONFLICT (version) DO NOTHING;
