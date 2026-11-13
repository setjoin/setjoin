-- V120__chat_drive_binding.sql
-- Chat A2 Task 1 — bind Drive spaces to chat channels; membership DERIVED,
-- never mirrored. Plan: docs/superpowers/plans/archive/2026-07-11-chat-A2-storage-on-drive.md
-- Task 1 + "v2 amendments". Governance invariants: docs/adr/DES-009-chat-bound-drive-space-governance.md.
--
-- File sections:
--   §A drive_spaces.chat_channel_id binding column + partial UNIQUE
--   §B chat_message_attachments link table + FORCE-RLS
--   §C drive_member_role v2 (chat-derivation arm, worker-owned)
--   §D governance guards (owner-arm + self-seed-arm chat_channel_id guards;
--      BZ175 belt lives in the drive_member_grant reducer, not here)
--   §E destroy_hard/prune backstops live in the reducer files themselves
--      (mailserver/sql/reducers/drive_node_destroy_hard.sql,
--      drive_version_prune.sql) — reducers are not versioned by migration.

-- ════════════════════════════════════════════════════════════════════════
-- §A — chat_channel_id binding column (Decision Audit #1: ON DELETE SET
-- NULL, not CASCADE — CASCADE would delete the space row out from under its
-- nodes (23503) and violates V114's "spaces are never hard-deleted"; SET
-- NULL unbinds and empties derived membership, matching the plan's own
-- "channel hard-delete unbinds" lifecycle note).
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.drive_spaces
    ADD COLUMN chat_channel_id bigint REFERENCES public.chat_channels(id) ON DELETE SET NULL;
CREATE UNIQUE INDEX drive_spaces_chat_channel_uq ON public.drive_spaces (chat_channel_id)
    WHERE chat_channel_id IS NOT NULL;

-- ════════════════════════════════════════════════════════════════════════
-- §B — chat_message_attachments (spec Data model). channel_id denormalized
-- so RLS can scope via chat_member_role without a join through
-- chat_messages (V119 chat_message_revisions precedent). file_node_id /
-- version_id are plain REFERENCES with NO ON DELETE action: a chat
-- attachment must never silently vanish out from under its message; the
-- Task 5b immutability guard (BZ175, a later task) is what keeps a
-- chat-attached node out of the destroy/prune path in the first place, and
-- the destroy_hard/prune reducer edits below are the defense-in-depth
-- backstop against the 23503 that would otherwise wedge the maintenance
-- worker forever if one ever got there anyway.
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE public.chat_message_attachments (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    channel_id   bigint NOT NULL REFERENCES public.chat_channels(id) ON DELETE CASCADE,
    message_id   bigint NOT NULL REFERENCES public.chat_messages(id) ON DELETE CASCADE,
    file_node_id bigint NOT NULL REFERENCES public.drive_nodes(id),
    version_id   bigint NOT NULL REFERENCES public.drive_file_versions(id),
    filename     text   NOT NULL,
    content_type text,
    size_bytes   bigint NOT NULL,
    ordinal      int    NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX chat_message_attachments_msg_idx ON public.chat_message_attachments (message_id);
CREATE INDEX chat_message_attachments_node_idx ON public.chat_message_attachments (file_node_id);

CREATE POLICY chat_msg_attach_scope ON public.chat_message_attachments
  FOR ALL TO public
  USING (chat_member_role(channel_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
ALTER TABLE public.chat_message_attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_message_attachments FORCE  ROW LEVEL SECURITY;

-- ════════════════════════════════════════════════════════════════════════
-- §C — drive_member_role v2: ONE choke point + the chat-derivation arm.
-- search_path matches the V114 convention (pg_catalog, public). Behavior-
-- identical for non-chat spaces: arm 1 (drive_space_members) is unchanged
-- and checked first via COALESCE; arm 2 joins drive_spaces.chat_channel_id
-- to chat_channel_members.channel_id, which is NULL for every non-chat
-- space, so the join produces no row and arm 2 contributes nothing (Failure
-- Modes Registry #9). ≤1 extra PK-indexed join only when arm 1 misses.
-- ════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION public.drive_member_role(p_space_id bigint, p_user_id bigint)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT COALESCE(
     (SELECT role FROM public.drive_space_members
       WHERE space_id = p_space_id AND user_id = p_user_id),
     (SELECT CASE WHEN m.role IN ('owner','admin') THEN 'manager' ELSE 'editor' END
        FROM public.drive_spaces s
        JOIN public.chat_channel_members m ON m.channel_id = s.chat_channel_id
       WHERE s.id = p_space_id AND m.user_id = p_user_id)
   ) $$;
SELECT apply_worker_ownership('drive_member_role(bigint,bigint)'::regprocedure);
-- M5: CREATE OR REPLACE on a function already owned by setjoin_worker (V114)
-- requires the connecting role to BE the owner or a superuser — this is the
-- first migration to replace (not merely create+transfer) a worker-owned
-- function. Verified empirically below this file's own load: in this repo's
-- dev/test cluster the schema-loading role is the `mail` superuser, so the
-- replace succeeds unconditionally here. In production, `mailctl schema
-- apply` (mailctl/schema.go resolveSchemaDSN) connects via DB_DIRECT_DSN or
-- DB_DSN with NO awareness of DB_OWNER_DSN/setjoin_owner at all — if either
-- of those env vars is ever pointed at the constrained setjoin_app role
-- (NOSUPERUSER, does not own drive_member_role — see
-- scripts/provision-roles.sql), this exact statement fails with "must be
-- owner of function drive_member_role". FLAGGED, not fixed here (out of
-- Task 1's file scope — mailctl/schema.go is untouched by this migration);
-- confirm before merge that whatever runs `mailctl schema apply` in
-- production is setjoin_owner or superuser-equivalent, or teach
-- resolveSchemaDSN about DB_OWNER_DSN.

-- ════════════════════════════════════════════════════════════════════════
-- §D — governance guards (DES-009 D2/D3; Decision Audit #2/#3). Reproduce
-- the EXACT V114 policy bodies (lines ~278-301) and add ONLY the
-- chat_channel_id guard clauses — no other predicate text changes.
-- ════════════════════════════════════════════════════════════════════════

-- D3: owner-read arm is inert on a chat-bound space — visible only via
-- (derived) membership or the drive.view admin override.
DROP POLICY drive_spaces_read ON public.drive_spaces;
CREATE POLICY drive_spaces_read ON public.drive_spaces FOR SELECT TO public
  USING (public.drive_member_role(id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL
     OR (chat_channel_id IS NULL
         AND owner_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) -- self-seed window; owner is otherwise always a manager member; inert on chat-bound spaces (DES-009 D3)
     OR public.drive_has_admin_perm((SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint), 'drive.view'));

-- D2: no ad-hoc drive_space_members rows on a chat-bound space — EVER.
-- Both WITH CHECK arms (the manager arm AND the owner self-seed arm) are
-- guarded: on a chat-bound space drive_member_role('manager') can be TRUE
-- via the §C derivation arm (a channel owner/admin), so the manager arm
-- must be guarded too, not just self-seed, or a channel admin could still
-- mint the exact frozen/invisible grant this ADR exists to forbid. The
-- USING clause (which rows a manager/self can touch) is left UNCHANGED —
-- with WITH CHECK closed, no chat-bound rows can ever exist to touch.
DROP POLICY drive_space_members_write ON public.drive_space_members;
CREATE POLICY drive_space_members_write ON public.drive_space_members FOR ALL TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) = 'manager'
     -- a member may remove THEMSELVES (leave):
     OR user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
  WITH CHECK ((public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) = 'manager'
     AND NOT EXISTS (SELECT 1 FROM public.drive_spaces s WHERE s.id = space_id AND s.chat_channel_id IS NOT NULL))
     -- owner self-seed: brand-new space, owner inserting their own manager row
     OR (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
         AND role = 'manager'
         AND public.drive_space_owner(space_id) = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
         AND EXISTS (SELECT 1 FROM public.drive_spaces s WHERE s.id = space_id AND s.chat_channel_id IS NULL)));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (120, now())
    ON CONFLICT (version) DO NOTHING;
