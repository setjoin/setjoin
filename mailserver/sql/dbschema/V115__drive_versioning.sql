-- V115__drive_versioning.sql
-- setjoin Drive P4: branches, locks, version labels, delegated folder admins
-- (spec §2.2, §5, §6.3). Plan: docs/superpowers/plans/archive/2026-07-09-drive-P4-versioning-locks.md
-- Tasks 0-5 + the drive_node_destroy FK-safe extension (AUTOPLAN batch-3 #1).
--
-- Circular-FK note (batch-3 #1): drive_file_versions.branch_id -> branches,
-- and branches.head_version_id/forked_from_version_id -> versions, both
-- plain NOT NULL refs with no ON DELETE action. drive_node_destroy (below,
-- this migration's companion reducer edit) breaks the cycle in the right
-- order before it deletes version rows. Never add ON DELETE CASCADE/SET NULL
-- here to "fix" that — the reducer-level ordering is the one place that can
-- also enforce the WORM (gxp) immutability contract (BZ145) on the unlink.

CREATE TABLE public.drive_file_branches (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    file_node_id   bigint NOT NULL REFERENCES public.drive_files(node_id) ON DELETE CASCADE,
    space_id       bigint NOT NULL REFERENCES public.drive_spaces(id),      -- denorm for RLS
    name           text   NOT NULL CHECK (name = btrim(name) AND length(name) BETWEEN 1 AND 100),
    head_version_id        bigint NOT NULL REFERENCES public.drive_file_versions(id), -- movable ref
    forked_from_version_id bigint NOT NULL REFERENCES public.drive_file_versions(id), -- merge-base
    status         text   NOT NULL DEFAULT 'open'
                          CHECK (status IN ('open','review','merged','discarded')),
    auto_created   boolean NOT NULL DEFAULT false,                   -- true = born from a conflict
    created_by     bigint NOT NULL REFERENCES public.users(id),
    resolved_by    bigint REFERENCES public.users(id),
    resolved_at    timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now()
);
-- Case-insensitive per-file name uniqueness (AUTOPLAN batch-1 #8 — branch
-- names materialize as sibling filenames on case-insensitive mirrors; the
-- drive_nodes_live_name_uniq precedent, V114). Supersedes a plain UNIQUE
-- (case-insensitive implies case-sensitive) so there is exactly one index.
CREATE UNIQUE INDEX drive_file_branches_ci_name_uniq
    ON public.drive_file_branches (file_node_id, lower(name));
CREATE INDEX drive_file_branches_file_idx
    ON public.drive_file_branches (file_node_id) WHERE status IN ('open','review');

-- "main" stays drive_files.head_version_id (no reserved branch row, zero
-- change to the shipped V114 read paths). branch_id NULL = created on main.
ALTER TABLE public.drive_file_versions
    ADD COLUMN merged_from_version_id bigint REFERENCES public.drive_file_versions(id), -- 2nd parent (resolve verbs)
    ADD COLUMN branch_id bigint REFERENCES public.drive_file_branches(id);
CREATE INDEX drive_file_versions_branch_idx
    ON public.drive_file_versions (branch_id) WHERE branch_id IS NOT NULL;

CREATE TABLE public.drive_version_labels (          -- tags ("Approved", "Sent to client")
    version_id bigint NOT NULL REFERENCES public.drive_file_versions(id) ON DELETE CASCADE,
    label      text   NOT NULL CHECK (length(label) BETWEEN 1 AND 60),
    created_by bigint NOT NULL REFERENCES public.users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (version_id, label)
);

CREATE TABLE public.drive_file_locks (              -- checkout/lock + open-from provenance (§5.3, §5.4)
    node_id      bigint PRIMARY KEY REFERENCES public.drive_nodes(id) ON DELETE CASCADE,
    space_id     bigint NOT NULL REFERENCES public.drive_spaces(id),
    user_id      bigint NOT NULL REFERENCES public.users(id),
    branch_id    bigint REFERENCES public.drive_file_branches(id),   -- NULL = locked on main
    version_id   bigint NOT NULL REFERENCES public.drive_file_versions(id),  -- opened-from version
    device_label text,
    mode         text NOT NULL DEFAULT 'soft' CHECK (mode IN ('soft','hard')),
    acquired_at  timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX drive_file_locks_space_idx ON public.drive_file_locks (space_id);

CREATE TABLE public.drive_folder_admins (           -- CODEOWNERS -> delegated department admin (§5.5)
    node_id    bigint NOT NULL REFERENCES public.drive_nodes(id) ON DELETE CASCADE,
    space_id   bigint NOT NULL REFERENCES public.drive_spaces(id),
    user_id    bigint NOT NULL REFERENCES public.users(id),
    granted_by bigint NOT NULL REFERENCES public.users(id),
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, user_id)
);
CREATE INDEX drive_folder_admins_user_idx ON public.drive_folder_admins (user_id);

-- ════════════════════════════════════════════════════════════════════════
-- Subtree folder-admin probe (walk-to-root). SECURITY DEFINER for the same
-- reason as drive_member_role (P1 R1): policy/DEFINER-reducer evaluation
-- must not be starved by RLS on drive_nodes/drive_folder_admins. Worker-
-- owned, PUBLIC-revoked.
-- ════════════════════════════════════════════════════════════════════════
CREATE FUNCTION public.drive_subtree_admin(p_user_id bigint, p_node_id bigint)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  WITH RECURSIVE up AS (
    SELECT id, parent_id FROM public.drive_nodes WHERE id = p_node_id
    UNION ALL
    SELECT n.id, n.parent_id FROM public.drive_nodes n JOIN up ON n.id = up.parent_id
  )
  SELECT EXISTS (SELECT 1 FROM public.drive_folder_admins fa JOIN up ON up.id = fa.node_id
                 WHERE fa.user_id = p_user_id);
$$;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    ALTER FUNCTION public.drive_subtree_admin(bigint, bigint) OWNER TO setjoin_worker;
  END IF;
  REVOKE EXECUTE ON FUNCTION public.drive_subtree_admin(bigint, bigint) FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
    GRANT EXECUTE ON FUNCTION public.drive_subtree_admin(bigint, bigint) TO setjoin_app; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
    GRANT EXECUTE ON FUNCTION public.drive_subtree_admin(bigint, bigint) TO setjoin_owner; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    GRANT EXECUTE ON FUNCTION public.drive_subtree_admin(bigint, bigint) TO setjoin_worker; END IF;
END $$;

-- ════════════════════════════════════════════════════════════════════════
-- WORM carve (AUTOPLAN batch-1 #2 / batch-3 #2): CREATE OR REPLACE of the
-- V114 trigger fn (legal -- it is a P1/V114 property, not a new object) to
-- exempt branch_id transitioning NULL -> value EXACTLY ONCE (the auto-branch
-- provenance move, §5.2/§5.4) without weakening any other column's WORM
-- lock. merged_from_version_id is deliberately NOT exempted (batch-3 #1) --
-- it stays fully WORM-guarded, including the drive_node_destroy unlink.
-- ════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.trg_drive_version_worm_fn() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_ret int; v_class text; v_core_same boolean;
BEGIN
  SELECT s.classification, s.retention_days INTO v_class, v_ret
    FROM public.drive_spaces s WHERE s.id = OLD.space_id;
  IF v_class = 'gxp' AND OLD.created_at + make_interval(days => v_ret) > now() THEN
    IF TG_OP = 'UPDATE' THEN
      v_core_same := NEW.id = OLD.id AND NEW.file_node_id = OLD.file_node_id
         AND NEW.content_sha256 = OLD.content_sha256 AND NEW.size_bytes = OLD.size_bytes
         AND NEW.parent_version_id IS NOT DISTINCT FROM OLD.parent_version_id
         AND NEW.conflict_of IS NOT DISTINCT FROM OLD.conflict_of
         AND NEW.author_user_id = OLD.author_user_id AND NEW.created_at = OLD.created_at
         AND NEW.note IS NOT DISTINCT FROM OLD.note
         AND NEW.merged_from_version_id IS NOT DISTINCT FROM OLD.merged_from_version_id;
      IF v_core_same AND NEW.branch_id IS NOT DISTINCT FROM OLD.branch_id THEN
        RETURN NEW; -- only preview_sha256/preview_status moved: rendition attach, allowed
      END IF;
      IF v_core_same AND OLD.branch_id IS NULL AND NEW.branch_id IS NOT NULL
         AND NEW.preview_sha256 IS NOT DISTINCT FROM OLD.preview_sha256
         AND NEW.preview_status IS NOT DISTINCT FROM OLD.preview_status THEN
        RETURN NEW; -- auto-branch provenance move: set once from NULL, not a content mutation
      END IF;
    END IF;
    RAISE EXCEPTION 'gxp version immutable inside retention'
      USING ERRCODE='BZ145', HINT='{"type":"immutable","detail":"record is under retention"}';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$;
-- (the trigger itself already exists from V114; replacing the function body
-- is sufficient -- no re-CREATE TRIGGER needed.)

-- ════════════════════════════════════════════════════════════════════════
-- RLS (ENABLE + FORCE x4) -- membership via the P1 R1 DEFINER helpers, never
-- a raw drive_space_members subquery (infinite policy recursion under FORCE).
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.drive_file_branches ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_file_branches FORCE  ROW LEVEL SECURITY;
CREATE POLICY drive_file_branches_read ON public.drive_file_branches FOR SELECT TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
CREATE POLICY drive_file_branches_write ON public.drive_file_branches FOR ALL TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor'))
  WITH CHECK (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor'));

ALTER TABLE public.drive_version_labels ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_version_labels FORCE  ROW LEVEL SECURITY;
-- LR-11: drive_version_labels has no space_id of its own (locked DDL) --
-- join through drive_file_versions, whose own RLS yields the identical row
-- set (a different table, so this is not the disallowed self-referential
-- recursion the R1 helpers exist to avoid).
CREATE POLICY drive_version_labels_read ON public.drive_version_labels FOR SELECT TO public
  USING (EXISTS (SELECT 1 FROM public.drive_file_versions v WHERE v.id = version_id
           AND public.drive_member_role(v.space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));
CREATE POLICY drive_version_labels_write ON public.drive_version_labels FOR ALL TO public
  USING (EXISTS (SELECT 1 FROM public.drive_file_versions v WHERE v.id = version_id
           AND public.drive_member_role(v.space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor')))
  WITH CHECK (EXISTS (SELECT 1 FROM public.drive_file_versions v WHERE v.id = version_id
           AND public.drive_member_role(v.space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor')));

ALTER TABLE public.drive_file_locks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_file_locks FORCE  ROW LEVEL SECURITY;
CREATE POLICY drive_file_locks_read ON public.drive_file_locks FOR SELECT TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
CREATE POLICY drive_file_locks_insert ON public.drive_file_locks FOR INSERT TO public
  WITH CHECK (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
    AND public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor'));
CREATE POLICY drive_file_locks_update ON public.drive_file_locks FOR UPDATE TO public
  USING (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
  WITH CHECK (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
    AND public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor'));
-- DELETE: own row, OR space manager (break), OR ANY member clearing an
-- ALREADY-EXPIRED row (AUTOPLAN batch-1 #1): the lock-acquire takeover path
-- in drive_file_lock runs invoker-rights and must be able to clear a stale
-- row itself. Folder-admin/drive.manage break still rides the LR-12 DEFINER
-- reducer (drive_file_unlock), never this policy -- this arm is strictly
-- narrower (member + already-expired only).
CREATE POLICY drive_file_locks_delete ON public.drive_file_locks FOR DELETE TO public
  USING (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
     OR public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) = 'manager'
     OR (expires_at <= now()
         AND public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));

ALTER TABLE public.drive_folder_admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_folder_admins FORCE  ROW LEVEL SECURITY;
CREATE POLICY drive_folder_admins_read ON public.drive_folder_admins FOR SELECT TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
CREATE POLICY drive_folder_admins_write ON public.drive_folder_admins FOR ALL TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) = 'manager')
  WITH CHECK (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) = 'manager');
-- Table-level GRANTs are NOT repeated here: scripts/provision-roles.sql's
-- ALTER DEFAULT PRIVILEGES already covers every future table/function
-- created by the migration-loading role (V114 precedent -- no per-table
-- GRANT block there either).

INSERT INTO schema_migrations (version, applied_at) VALUES (115, now())
    ON CONFLICT (version) DO NOTHING;
