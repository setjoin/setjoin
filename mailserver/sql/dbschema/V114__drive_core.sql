-- V114__drive_core.sql
-- setjoin Drive P1 core schema: spaces, tree, versions, chunk manifest, sync
-- journal, audit chain. Spec: docs/superpowers/specs/2026-07-09-drive-v1-spec.md
-- §2. Plan: docs/superpowers/plans/archive/2026-07-09-drive-P1-core.md Tasks 1-3.
--
-- File sections (assembled across Tasks 1-3, all in this one migration —
-- unshipped until this branch merges, so editing pre-merge is the repo norm):
--   §A tables + indexes      (Task 1)
--   §B scope + choke-point helpers, SECURITY DEFINER               (Task 1)
--   §C RLS policies                                                (Task 2)
--   §D triggers (no-downgrade, G7 refcount, WORM/audit guards)     (Task 3)
--   §E ENABLE+FORCE, seeds, footer                                 (Task 1, policies land in Task 2)

-- ════════════════════════════════════════════════════════════════════════
-- §A — tables + indexes (spec §2.1, verbatim except the R9 FK amendment on
-- drive_file_versions.parent_version_id / conflict_of: ON DELETE SET NULL so
-- drive_version_prune (P4) can delete a chain-interior version — the bare
-- REFERENCES form would 23503 forever on any row with a child).
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE public.drive_spaces (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name            text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    is_personal     boolean     NOT NULL DEFAULT false,            -- §0.1-1(a); one per user
    classification  text        NOT NULL DEFAULT 'regular'
                                CHECK (classification IN ('regular','secure','gxp')),
    owner_user_id   bigint      NOT NULL REFERENCES public.users(id),
    -- gxp knobs (enforced NOT NULL for gxp by the row CHECK below; NULL otherwise):
    retention_days  integer     CHECK (retention_days > 0),
    worm_mode       text        CHECK (worm_mode IN ('governance','compliance')),
    -- {"export":"approval"|"allow", "print":"approval"|"allow", "share":"approval"|"direct",
    --  "watermark":bool, "audit_reads":bool, "edit_lock":"soft"|"required",
    --  "upload_max_bytes":N, "upload_ext_deny":["exe",…]} — defaults resolved in §9.2
    export_policy   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    quota_bytes     bigint      CHECK (quota_bytes > 0),           -- §0.1-2 server quota; NULL = unlimited
    used_bytes      bigint      NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),  -- Σ version size_bytes (logical, dedup-agnostic)
    vault_quota_mb  integer     CHECK (vault_quota_mb > 0),        -- secure/gxp CLIENT pin quota (D15) — a device-side cap, NOT the server quota
    change_seq      bigint      NOT NULL DEFAULT 0,                -- per-space sync state counter
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT drive_spaces_gxp_knobs
        CHECK (classification <> 'gxp' OR (retention_days IS NOT NULL AND worm_mode IS NOT NULL))
);
CREATE UNIQUE INDEX drive_spaces_personal_uniq
    ON public.drive_spaces (owner_user_id) WHERE is_personal;      -- one personal space per user

CREATE TABLE public.drive_space_members (          -- mirrors mailbox_delegates (V001:3867)
    space_id    bigint      NOT NULL REFERENCES public.drive_spaces(id) ON DELETE CASCADE,
    user_id     bigint      NOT NULL REFERENCES public.users(id),
    role        text        NOT NULL CHECK (role IN ('manager','editor','viewer')),
    granted_by  bigint      NOT NULL REFERENCES public.users(id),
    granted_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (space_id, user_id)
);
CREATE INDEX drive_space_members_user_idx ON public.drive_space_members (user_id);

CREATE TABLE public.drive_nodes (                  -- folder tree (folders AND files)
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    space_id    bigint      NOT NULL REFERENCES public.drive_spaces(id),
    parent_id   bigint      REFERENCES public.drive_nodes(id),   -- NULL = space root level
    kind        text        NOT NULL CHECK (kind IN ('folder','file')),
    name        text        NOT NULL CHECK (
                     name = btrim(name) AND length(name) BETWEEN 1 AND 255
                     AND position('/' IN name) = 0 AND name NOT IN ('.','..')),
    deleted_at  timestamptz,                        -- soft delete: USER trash tier
    -- purged_at/purged_by (ADMIN trash tier) arrive in V117 — §2.4
    created_by  bigint      NOT NULL REFERENCES public.users(id),
    created_at  timestamptz NOT NULL DEFAULT now()
);
-- Live-name uniqueness, case-insensitive (regular spaces mirror onto
-- case-insensitive filesystems); COALESCE(parent_id,0) makes root-level names
-- collide correctly (identity ids start at 1, 0 is never a real node).
CREATE UNIQUE INDEX drive_nodes_live_name_uniq
    ON public.drive_nodes (space_id, COALESCE(parent_id, 0), lower(name))
    WHERE deleted_at IS NULL;
CREATE INDEX drive_nodes_parent_idx
    ON public.drive_nodes (space_id, parent_id) WHERE deleted_at IS NULL;
-- Reducer-enforced invariants (I-3, §10): parent.space_id = child.space_id,
-- parent.kind = 'folder', no cycles (walk-to-root check in drive_node_move).

CREATE TABLE public.drive_files (                  -- 1:1 extension of drive_nodes(kind='file')
    node_id          bigint  PRIMARY KEY REFERENCES public.drive_nodes(id) ON DELETE CASCADE,
    space_id         bigint  NOT NULL REFERENCES public.drive_spaces(id),  -- denormalized for RLS/indexes
    head_version_id  bigint,                        -- FK added after drive_file_versions; "main" ref
    size_bytes       bigint  NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
    content_type     text
);
CREATE INDEX drive_files_space_idx ON public.drive_files (space_id);

CREATE TABLE public.drive_file_versions (          -- the version DAG (metadata-only; git commits)
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    file_node_id       bigint NOT NULL REFERENCES public.drive_files(node_id) ON DELETE CASCADE,
    space_id           bigint NOT NULL REFERENCES public.drive_spaces(id),   -- denormalized for RLS/WORM
    parent_version_id  bigint REFERENCES public.drive_file_versions(id) ON DELETE SET NULL,  -- NULL = v1 (R9)
    conflict_of        bigint REFERENCES public.drive_file_versions(id) ON DELETE SET NULL,  -- conflict sibling (§4.4, R9)
    -- merged_from_version_id + branch_id arrive in V115 — §2.2
    content_sha256     text   NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),  -- whole-file hash
    size_bytes         bigint NOT NULL CHECK (size_bytes >= 0),
    chunk_size         integer NOT NULL DEFAULT 4194304 CHECK (chunk_size > 0),    -- 4 MiB fixed, v1
    content_type       text,
    author_user_id     bigint NOT NULL REFERENCES public.users(id),
    device_label       text,                        -- provenance ("laptop-x","web")
    note               text,                        -- change note (GxP change-control comment)
    preview_sha256     text   CHECK (preview_sha256 ~ '^[0-9a-f]{64}$'),     -- whole-rendition hash (§8.3)
    preview_status     text   NOT NULL DEFAULT 'none'
                              CHECK (preview_status IN ('none','pending','ready','failed','unsupported')),
    created_at         timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.drive_files
    ADD CONSTRAINT drive_files_head_fk FOREIGN KEY (head_version_id)
    REFERENCES public.drive_file_versions(id);
CREATE INDEX drive_file_versions_file_idx  ON public.drive_file_versions (file_node_id, id);
CREATE INDEX drive_file_versions_space_idx ON public.drive_file_versions (space_id);
CREATE INDEX drive_file_versions_sha_idx   ON public.drive_file_versions (content_sha256);

CREATE TABLE public.drive_chunks (                 -- content-addressed 4 MiB chunks (R3)
    scope_key   text        NOT NULL,               -- 'g' (global/regular) | 's<space_id>' (secure/gxp)
    sha256      text        NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes  integer     NOT NULL CHECK (size_bytes BETWEEN 1 AND 4194304),
    ref_count   bigint      NOT NULL DEFAULT 0 CHECK (ref_count >= 0),
    storage_ref text        NOT NULL,               -- object key: 'drive/'||scope_key||'/'||sha256
    retain_until timestamptz,                       -- WORM high-water mark (gxp scopes only; §3.4)
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_key, sha256)
);

CREATE TABLE public.drive_version_chunks (         -- the manifest: ordinal join version→chunks
    version_id   bigint  NOT NULL REFERENCES public.drive_file_versions(id) ON DELETE CASCADE,
    stream       text    NOT NULL DEFAULT 'content' CHECK (stream IN ('content','preview')),
    ordinal      integer NOT NULL CHECK (ordinal >= 0),
    scope_key    text    NOT NULL,
    chunk_sha256 text    NOT NULL,
    PRIMARY KEY (version_id, stream, ordinal),
    FOREIGN KEY (scope_key, chunk_sha256)
        REFERENCES public.drive_chunks(scope_key, sha256)
);
CREATE INDEX drive_version_chunks_chunk_idx
    ON public.drive_version_chunks (scope_key, chunk_sha256);

CREATE TABLE public.drive_upload_claims (          -- anti-oracle upload proof (§3.3, I-4)
    scope_key   text        NOT NULL,
    sha256      text        NOT NULL,
    user_id     bigint      NOT NULL REFERENCES public.users(id),
    claimed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_key, sha256, user_id),
    FOREIGN KEY (scope_key, sha256)
        REFERENCES public.drive_chunks(scope_key, sha256) ON DELETE CASCADE
);

CREATE TABLE public.drive_changes (                -- per-space sync journal (§4.2)
    space_id  bigint      NOT NULL REFERENCES public.drive_spaces(id) ON DELETE CASCADE,
    seq       bigint      NOT NULL,                 -- from drive_spaces.change_seq
    node_id   bigint      NOT NULL,                 -- no FK: journal outlives destroyed nodes
    op        text        NOT NULL CHECK (op IN ('create','update','move','rename',
                                                 'trash','restore','destroy','member','space')),
    at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (space_id, seq)
);

CREATE TABLE public.drive_watches (                -- watch/subscription substrate (P4 notify + P6 UI)
    node_id    bigint  NOT NULL REFERENCES public.drive_nodes(id) ON DELETE CASCADE,
    user_id    bigint  NOT NULL REFERENCES public.users(id),
    ops        text[],                              -- NULL = all ops; else subset of drive_changes.op
                                                    -- + 'branch','lock' event classes (§5.6)
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, user_id)
);

CREATE TABLE public.drive_chunk_gc_queue (         -- zero-ref chunk GC (§3.5)
    scope_key  text        NOT NULL,
    sha256     text        NOT NULL,
    queued_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_key, sha256)
);

CREATE TABLE public.drive_audit_log (              -- per-space tamper-evident chain (§9.3)
    space_id     bigint      NOT NULL REFERENCES public.drive_spaces(id),
    id           bigint      NOT NULL,              -- per-space monotonic
    occurred_at  timestamptz NOT NULL DEFAULT now(),
    user_id      bigint,
    ip           inet,
    action       text        NOT NULL,
    target_type  text,
    target_id    bigint,
    before_state jsonb,
    after_state  jsonb,      -- chain checksum in after_state->>'_checksum' (V037 convention)
    notes        text,
    PRIMARY KEY (space_id, id)
);
CREATE INDEX drive_audit_log_query_idx                 -- the §9.3 query layer's index
    ON public.drive_audit_log (space_id, user_id, action, occurred_at);

-- ════════════════════════════════════════════════════════════════════════
-- §B — scope + choke-point helpers (Locked resolutions R1/R2 of the P1 plan)
-- SECURITY DEFINER, owned by setjoin_worker (BYPASSRLS) where provisioned: the
-- membership lookup must not re-enter drive policies (infinite policy recursion
-- under FORCE; setjoin_owner is NOBYPASSRLS so owner-rights would NOT bypass).
-- Args are always (id, GUC/user) pairs our own policies/reducers pass —
-- EXECUTE is revoked from PUBLIC.
-- ════════════════════════════════════════════════════════════════════════

CREATE FUNCTION public.drive_member_role(p_space_id bigint, p_user_id bigint)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT role FROM public.drive_space_members
    WHERE space_id = p_space_id AND user_id = p_user_id $$;

CREATE FUNCTION public.drive_space_owner(p_space_id bigint)
RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT owner_user_id FROM public.drive_spaces WHERE id = p_space_id $$;

-- V073-shape admin-perm probe (assignment live + JIT-eligibility clause), as a
-- DEFINER so policy evaluation under the flip cannot be starved by the admin
-- tables' own policies.
CREATE FUNCTION public.drive_has_admin_perm(p_user_id bigint, p_perm text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT EXISTS (
     SELECT 1 FROM public.admin_role_assignments ara
     JOIN public.admin_role_groups arg ON arg.id = ara.role_group_id
     WHERE ara.user_id = p_user_id
       AND (ara.expires_at IS NULL OR ara.expires_at > now())
       AND (NOT COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='rbac.jit'), false)
            OR ara.eligible = false
            OR (ara.activated_until IS NOT NULL AND ara.activated_until > now()))
       AND p_perm = ANY(arg.permissions)) $$;

-- Atomic quota check-and-charge (single UPDATE — no read-then-write race; I-14).
-- DEFINER because editors must move used_bytes while spaces-UPDATE policy is
-- manager-only (Locked resolution R2). Negative delta = decrement (never gated).
CREATE FUNCTION public.drive_space_quota_charge(p_space_id bigint, p_delta bigint)
RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ WITH upd AS (
     UPDATE public.drive_spaces
        SET used_bytes = GREATEST(0, used_bytes + p_delta)
      WHERE id = p_space_id
        AND (p_delta <= 0 OR quota_bytes IS NULL OR used_bytes + p_delta <= quota_bytes)
      RETURNING 1)
   SELECT EXISTS (SELECT 1 FROM upd) $$;

-- gxp retain_until high-water mark (§3.4) — chunks have no user UPDATE policy.
CREATE FUNCTION public.drive_chunks_extend_retention(p_scope_key text, p_shas text[], p_until timestamptz)
RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ UPDATE public.drive_chunks
      SET retain_until = GREATEST(COALESCE(retain_until, p_until), p_until)
    WHERE scope_key = p_scope_key AND sha256 = ANY(p_shas) $$;

DO $$
DECLARE v_fn text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    ALTER FUNCTION public.drive_member_role(bigint, bigint) OWNER TO setjoin_worker;
    ALTER FUNCTION public.drive_space_owner(bigint) OWNER TO setjoin_worker;
    ALTER FUNCTION public.drive_has_admin_perm(bigint, text) OWNER TO setjoin_worker;
    ALTER FUNCTION public.drive_space_quota_charge(bigint, bigint) OWNER TO setjoin_worker;
    ALTER FUNCTION public.drive_chunks_extend_retention(text, text[], timestamptz) OWNER TO setjoin_worker;
  END IF;
  FOREACH v_fn IN ARRAY ARRAY[
    'drive_member_role(bigint, bigint)', 'drive_space_owner(bigint)',
    'drive_has_admin_perm(bigint, text)', 'drive_space_quota_charge(bigint, bigint)',
    'drive_chunks_extend_retention(text, text[], timestamptz)'] LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION public.%s FROM PUBLIC', v_fn);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_app') THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION public.%s TO setjoin_app', v_fn); END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_owner') THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION public.%s TO setjoin_owner', v_fn); END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_worker') THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION public.%s TO setjoin_worker', v_fn); END IF;
  END LOOP;
END $$;

-- ════════════════════════════════════════════════════════════════════════
-- §C — RLS policies (spec §2.1.2 matrix; membership via the R1 DEFINER
-- helpers — NOT an inline drive_space_members subquery, which would be
-- infinite policy recursion under FORCE since drive_space_members has its
-- own RLS policies expressed in terms of the same predicate).
-- guc() shorthand used below, written out verbatim each time:
--   (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
-- ════════════════════════════════════════════════════════════════════════

CREATE POLICY drive_spaces_read ON public.drive_spaces FOR SELECT TO public
  USING (public.drive_member_role(id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL
     OR owner_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint) -- self-seed window; owner is otherwise always a manager member
     OR public.drive_has_admin_perm((SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint), 'drive.view'));
CREATE POLICY drive_spaces_insert ON public.drive_spaces FOR INSERT TO public
  WITH CHECK (owner_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint));
  -- drive.space_creation gate lives in the reducer (G6), not in RLS.
CREATE POLICY drive_spaces_update ON public.drive_spaces FOR UPDATE TO public
  USING (public.drive_member_role(id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) = 'manager'
     OR public.drive_has_admin_perm((SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint), 'drive.manage'))
  WITH CHECK (true);
-- no DELETE policy: spaces are never hard-deleted in v1 (FORCE denies).

CREATE POLICY drive_space_members_read ON public.drive_space_members FOR SELECT TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
CREATE POLICY drive_space_members_write ON public.drive_space_members FOR ALL TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) = 'manager'
     -- a member may remove THEMSELVES (leave):
     OR user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
  WITH CHECK (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) = 'manager'
     -- owner self-seed: brand-new space, owner inserting their own manager row
     OR (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
         AND role = 'manager'
         AND public.drive_space_owner(space_id) = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)));

-- Tree/content tables: member read; editor+ write. One macro-shape, five tables.
-- (drive_changes gets NO update/delete policy — append-only journal.)
CREATE POLICY drive_nodes_read ON public.drive_nodes FOR SELECT TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
CREATE POLICY drive_nodes_write ON public.drive_nodes FOR ALL TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor'))
  WITH CHECK (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor'));

CREATE POLICY drive_files_read ON public.drive_files FOR SELECT TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
CREATE POLICY drive_files_write ON public.drive_files FOR ALL TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor'))
  WITH CHECK (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor'));

CREATE POLICY drive_file_versions_read ON public.drive_file_versions FOR SELECT TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
CREATE POLICY drive_file_versions_write ON public.drive_file_versions FOR ALL TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor'))
  WITH CHECK (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor'));

CREATE POLICY drive_changes_read ON public.drive_changes FOR SELECT TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
CREATE POLICY drive_changes_insert ON public.drive_changes FOR INSERT TO public
  WITH CHECK (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor'));

CREATE POLICY drive_version_chunks_read ON public.drive_version_chunks FOR SELECT TO public
  USING (EXISTS (SELECT 1 FROM public.drive_file_versions v WHERE v.id = version_id
           AND public.drive_member_role(v.space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));
CREATE POLICY drive_version_chunks_write ON public.drive_version_chunks FOR ALL TO public
  USING (EXISTS (SELECT 1 FROM public.drive_file_versions v WHERE v.id = version_id
           AND public.drive_member_role(v.space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor')))
  WITH CHECK (EXISTS (SELECT 1 FROM public.drive_file_versions v WHERE v.id = version_id
           AND public.drive_member_role(v.space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor')));

-- drive_chunks: the I-4 anti-oracle read; INSERT scoped by scope_key; NO user
-- UPDATE (G7 DEFINER triggers own ref_count) and NO user DELETE (worker-only).
CREATE POLICY drive_chunks_read ON public.drive_chunks FOR SELECT TO public
  USING (
    EXISTS (SELECT 1 FROM public.drive_upload_claims c
             WHERE c.scope_key = drive_chunks.scope_key AND c.sha256 = drive_chunks.sha256
               AND c.user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
    OR EXISTS (SELECT 1 FROM public.drive_version_chunks vc
               JOIN public.drive_file_versions v ON v.id = vc.version_id
              WHERE vc.scope_key = drive_chunks.scope_key AND vc.chunk_sha256 = drive_chunks.sha256
                AND public.drive_member_role(v.space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));
CREATE POLICY drive_chunks_insert ON public.drive_chunks FOR INSERT TO public
  WITH CHECK (
    (scope_key = 'g' AND EXISTS (SELECT 1 FROM public.drive_space_members m
        JOIN public.drive_spaces s ON s.id = m.space_id AND s.classification = 'regular'
        WHERE m.user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
          AND m.role IN ('manager','editor')))
    OR (scope_key ~ '^s[0-9]+$'
        AND public.drive_member_role(substring(scope_key from 2)::bigint,
              (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor')));

CREATE POLICY drive_upload_claims_own ON public.drive_upload_claims FOR ALL TO public
  USING (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
  WITH CHECK (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint));
  -- DELETE own rows is deliberate: put_version consumes the caller's claims
  -- (Locked resolution R8); the worker prunes stale ones on BYPASSRLS.

CREATE POLICY drive_watches_own_read ON public.drive_watches FOR SELECT TO public
  USING (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint));
CREATE POLICY drive_watches_own_write ON public.drive_watches FOR ALL TO public
  USING (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
  WITH CHECK (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
    AND EXISTS (SELECT 1 FROM public.drive_nodes n WHERE n.id = node_id
          AND public.drive_member_role(n.space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));

CREATE POLICY drive_audit_log_read ON public.drive_audit_log FOR SELECT TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL
     OR public.drive_has_admin_perm((SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint), 'drive.view'));
CREATE POLICY drive_audit_log_insert ON public.drive_audit_log FOR INSERT TO public
  WITH CHECK (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL
     OR public.drive_has_admin_perm((SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint), 'drive.view')
     OR public.drive_has_admin_perm((SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint), 'drive.manage'));
-- no UPDATE/DELETE policies (append-only; the Task 3 trigger is the second lock).

-- drive_chunk_gc_queue: ZERO policies (worker-only; FORCE + none = invisible).

-- ════════════════════════════════════════════════════════════════════════
-- §D — triggers (spec §2.1.1 table, in full): no-downgrade (I-2), G7
-- SECURITY DEFINER refcount movers (I-6), WORM/space-match/audit guards.
-- ════════════════════════════════════════════════════════════════════════

CREATE FUNCTION public.trg_drive_space_no_downgrade_fn() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_rank_old int; v_rank_new int;
BEGIN
  v_rank_old := CASE OLD.classification WHEN 'regular' THEN 0 WHEN 'secure' THEN 1 ELSE 2 END;
  v_rank_new := CASE NEW.classification WHEN 'regular' THEN 0 WHEN 'secure' THEN 1 ELSE 2 END;
  IF v_rank_new < v_rank_old THEN
    RAISE EXCEPTION 'classification downgrade forbidden'
      USING ERRCODE='BZ142', HINT='{"type":"stateMismatch","detail":"classification can never be lowered"}';
  END IF;
  IF OLD.classification = 'gxp' THEN
    IF NEW.retention_days < OLD.retention_days THEN
      RAISE EXCEPTION 'gxp retention may only increase' USING ERRCODE='BZ142',
        HINT='{"type":"stateMismatch","detail":"retention_days may only increase"}';
    END IF;
    IF OLD.worm_mode = 'compliance' AND NEW.worm_mode = 'governance' THEN
      RAISE EXCEPTION 'worm_mode may not relax' USING ERRCODE='BZ142',
        HINT='{"type":"stateMismatch","detail":"compliance may not relax to governance"}';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_drive_space_no_downgrade
  BEFORE UPDATE OF classification, retention_days, worm_mode ON public.drive_spaces
  FOR EACH ROW EXECUTE FUNCTION public.trg_drive_space_no_downgrade_fn();

-- G7: ref_count movers are SECURITY DEFINER (blobs' V075 invoker shape would
-- 42501 under FORCE at the DSN flip — drive_chunks has no user UPDATE policy,
-- and drive_chunk_gc_queue has NO policies at all).
CREATE FUNCTION public.trg_drive_vc_refcount_inc_fn() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  UPDATE public.drive_chunks SET ref_count = ref_count + 1
   WHERE scope_key = NEW.scope_key AND sha256 = NEW.chunk_sha256;
  RETURN NEW;
END $$;
CREATE FUNCTION public.trg_drive_vc_refcount_dec_fn() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  UPDATE public.drive_chunks SET ref_count = ref_count - 1
   WHERE scope_key = OLD.scope_key AND sha256 = OLD.chunk_sha256;
  RETURN OLD;
END $$;
CREATE TRIGGER trg_drive_vc_refcount_inc AFTER INSERT ON public.drive_version_chunks
  FOR EACH ROW EXECUTE FUNCTION public.trg_drive_vc_refcount_inc_fn();
CREATE TRIGGER trg_drive_vc_refcount_dec AFTER DELETE ON public.drive_version_chunks
  FOR EACH ROW EXECUTE FUNCTION public.trg_drive_vc_refcount_dec_fn();

CREATE FUNCTION public.trg_drive_chunk_zero_ref_fn() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  INSERT INTO public.drive_chunk_gc_queue (scope_key, sha256)
  VALUES (NEW.scope_key, NEW.sha256) ON CONFLICT DO NOTHING;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_drive_chunk_zero_ref AFTER UPDATE OF ref_count ON public.drive_chunks
  FOR EACH ROW WHEN (NEW.ref_count = 0) EXECUTE FUNCTION public.trg_drive_chunk_zero_ref_fn();

-- AUTOPLAN batch-3 item 2 (BLOCKER): the three SECURITY DEFINER trigger
-- functions above are useless without an ownership transfer to a BYPASSRLS
-- role — setjoin_owner (the migration-loader identity) is NOBYPASSRLS, so an
-- owner-owned DEFINER function does NOT bypass FORCE RLS post-flip, and the
-- ref_count UPDATE (drive_chunks has no user UPDATE policy) / gc-queue INSERT
-- (drive_chunk_gc_queue has zero policies) would 42501 for the very editor
-- role G7 exists to unblock. Same DO-block genre as §B; kept as its own block
-- here (rather than folded into §B's) because these three functions do not
-- exist until §D — a forward reference would break §B's block at Task-1 time.
DO $$
DECLARE v_fn text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    ALTER FUNCTION public.trg_drive_vc_refcount_inc_fn() OWNER TO setjoin_worker;
    ALTER FUNCTION public.trg_drive_vc_refcount_dec_fn() OWNER TO setjoin_worker;
    ALTER FUNCTION public.trg_drive_chunk_zero_ref_fn() OWNER TO setjoin_worker;
  END IF;
  -- trigger functions are invoked by the trigger mechanism, never called
  -- directly — no EXECUTE grants needed, but revoke PUBLIC for hygiene.
  FOREACH v_fn IN ARRAY ARRAY[
    'trg_drive_vc_refcount_inc_fn()', 'trg_drive_vc_refcount_dec_fn()',
    'trg_drive_chunk_zero_ref_fn()'] LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION public.%s FROM PUBLIC', v_fn);
  END LOOP;
END $$;

-- WORM guard: gxp versions immutable inside retention; rendition-attach columns exempt.
CREATE FUNCTION public.trg_drive_version_worm_fn() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_ret int; v_class text;
BEGIN
  SELECT s.classification, s.retention_days INTO v_class, v_ret
    FROM public.drive_spaces s WHERE s.id = OLD.space_id;
  IF v_class = 'gxp' AND OLD.created_at + make_interval(days => v_ret) > now() THEN
    IF TG_OP = 'UPDATE'
       AND NEW.id = OLD.id AND NEW.file_node_id = OLD.file_node_id
       AND NEW.content_sha256 = OLD.content_sha256 AND NEW.size_bytes = OLD.size_bytes
       AND NEW.parent_version_id IS NOT DISTINCT FROM OLD.parent_version_id
       AND NEW.conflict_of IS NOT DISTINCT FROM OLD.conflict_of
       AND NEW.author_user_id = OLD.author_user_id AND NEW.created_at = OLD.created_at
       AND NEW.note IS NOT DISTINCT FROM OLD.note THEN
      RETURN NEW; -- only preview_sha256/preview_status moved: rendition attach, allowed
    END IF;
    RAISE EXCEPTION 'gxp version immutable inside retention'
      USING ERRCODE='BZ145', HINT='{"type":"immutable","detail":"record is under retention"}';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_drive_version_worm BEFORE UPDATE OR DELETE ON public.drive_file_versions
  FOR EACH ROW EXECUTE FUNCTION public.trg_drive_version_worm_fn();

-- space containment (I-3 insert arm)
CREATE FUNCTION public.trg_drive_version_space_match_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.space_id <> (SELECT f.space_id FROM public.drive_files f WHERE f.node_id = NEW.file_node_id) THEN
    RAISE EXCEPTION 'version space mismatch' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"space_id must match the file node"}';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_drive_version_space_match BEFORE INSERT ON public.drive_file_versions
  FOR EACH ROW EXECUTE FUNCTION public.trg_drive_version_space_match_fn();
CREATE FUNCTION public.trg_drive_file_space_match_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.space_id <> (SELECT n.space_id FROM public.drive_nodes n WHERE n.id = NEW.node_id) THEN
    RAISE EXCEPTION 'file space mismatch' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"space_id must match the node"}';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_drive_file_space_match BEFORE INSERT ON public.drive_files
  FOR EACH ROW EXECUTE FUNCTION public.trg_drive_file_space_match_fn();

-- audit append-only (second lock behind the missing UPDATE/DELETE policies)
CREATE FUNCTION public.trg_drive_audit_immutable_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'drive audit log is append-only'
    USING ERRCODE='BZ145', HINT='{"type":"immutable","detail":"audit rows can never change"}';
END $$;
CREATE TRIGGER trg_drive_audit_immutable BEFORE UPDATE OR DELETE ON public.drive_audit_log
  FOR EACH ROW EXECUTE FUNCTION public.trg_drive_audit_immutable_fn();

-- ════════════════════════════════════════════════════════════════════════
-- §E — ENABLE+FORCE, seeds, footer. FORCE with zero policies is deny-all for
-- the app role, which is the correct fail-closed interim for tables not yet
-- covered above.
-- ════════════════════════════════════════════════════════════════════════

DO $$
DECLARE v_t text;
BEGIN
  FOREACH v_t IN ARRAY ARRAY['drive_spaces','drive_space_members','drive_nodes',
    'drive_files','drive_file_versions','drive_chunks','drive_version_chunks',
    'drive_upload_claims','drive_changes','drive_watches','drive_chunk_gc_queue',
    'drive_audit_log'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', v_t);
    EXECUTE format('ALTER TABLE public.%I FORCE  ROW LEVEL SECURITY', v_t);
  END LOOP;
END $$;

INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.drive',            false, 'setjoin Drive v1 (spaces, sync, versioning)'),
  ('feature.drive_compliance', false, 'Drive gxp compliance spaces (WORM, approval e-sig, retention)'),
  ('drive.space_creation',     true,  'Allow all users to create drive spaces (OFF = drive.manage admins only)')
ON CONFLICT (key) DO NOTHING;

-- drive.view/drive.manage are deliberately OUTSIDE the 等保 (SoD) PermClasses
-- map in P1 (AUTOPLAN batch-3 item 4, closes batch-1 item 6's DECIDE): do NOT
-- touch shared/permissions/classes.go PermClasses or sod_exclusion_guard() here
-- — sod_perm_map_guard_test.go only fails on a PermClasses↔SQL divergence, and
-- feature.drive ships OFF, so being absent from both sides is safe. Classify
-- drive.manage 'security' + re-create the V100-shape guard in the compliance
-- phase (P5). See TODOS.md "Drive P1 — deferred to P5".
INSERT INTO public.admin_permissions (permission_key, category, description, is_sensitive) VALUES
  ('drive.view',   'Drive', 'View drive spaces, membership, locks and audit chains', false),
  ('drive.manage', 'Drive', 'Administer drive spaces, quotas, classification and compliance policy', true)
ON CONFLICT (permission_key) DO NOTHING;

UPDATE public.admin_role_groups
   SET permissions = (SELECT array_agg(DISTINCT p ORDER BY p)
                        FROM unnest(permissions || ARRAY['drive.view','drive.manage']) AS p)
 WHERE id = 1;

INSERT INTO schema_migrations (version, applied_at) VALUES (114, now())
    ON CONFLICT (version) DO NOTHING;
