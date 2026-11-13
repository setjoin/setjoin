-- V184__drive_node_acl_foundation.sql
-- Drive node ACL R1 expand-only foundation. No production read or write path
-- consumes these tables until the separately gated cutover migrations land.
-- Authority: docs/superpowers/specs/2026-08-03-drive-node-acl-access-governance-design.md
-- Plan: docs/superpowers/plans/2026-08-03-drive-node-acl-access-governance.md (A1)

-- R1 stores direct-user grants only. Directory groups and governed requests
-- intentionally receive later, independently releasable migrations.
ALTER TABLE public.drive_spaces
  ADD COLUMN acl_mode text NOT NULL DEFAULT 'legacy'
    CHECK (acl_mode IN ('legacy', 'shadow', 'acl')),
  ADD COLUMN acl_protocol_version integer NOT NULL DEFAULT 1
    CHECK (acl_protocol_version = 1),
  ADD COLUMN acl_irreversible_at timestamptz;

-- Composite target for closure FKs. The existing id PK remains canonical.
ALTER TABLE public.drive_nodes
  ADD CONSTRAINT drive_nodes_space_id_id_uniq UNIQUE (space_id, id);

CREATE TABLE public.drive_acl_grants (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  space_id            bigint NOT NULL REFERENCES public.drive_spaces(id) ON DELETE CASCADE,
  node_id             bigint NOT NULL,
  subject_user_id     bigint NOT NULL REFERENCES public.users(id),
  preset              text NOT NULL
    CHECK (preset IN ('viewer', 'contributor', 'editor', 'folder_manager')),
  capabilities        text[] NOT NULL,
  propagation         text NOT NULL CHECK (propagation IN ('self', 'children', 'subtree')),
  source              text NOT NULL DEFAULT 'direct' CHECK (source IN ('direct')),
  state               text NOT NULL DEFAULT 'active'
    CHECK (state IN ('active', 'revoked', 'expired')),
  starts_at           timestamptz,
  expires_at          timestamptz,
  max_uses            integer CHECK (max_uses > 0),
  used_count          integer NOT NULL DEFAULT 0 CHECK (used_count >= 0),
  created_by          bigint NOT NULL REFERENCES public.users(id),
  created_at          timestamptz NOT NULL DEFAULT now(),
  revoked_by          bigint REFERENCES public.users(id),
  revoked_at          timestamptz,
  reason              text CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 1000),
  idempotency_key     text CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 8 AND 200),
  request_digest      text CHECK (request_digest IS NULL OR request_digest ~ '^[0-9a-f]{64}$'),
  CONSTRAINT drive_acl_grants_node_fk
    FOREIGN KEY (space_id, node_id) REFERENCES public.drive_nodes(space_id, id) ON DELETE CASCADE,
  CONSTRAINT drive_acl_grants_window
    CHECK (expires_at IS NULL OR starts_at IS NULL OR expires_at > starts_at),
  CONSTRAINT drive_acl_grants_use_count
    CHECK (max_uses IS NULL OR used_count <= max_uses),
  CONSTRAINT drive_acl_grants_revocation_shape
    CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
);
CREATE INDEX drive_acl_grants_subject_active_idx
  ON public.drive_acl_grants (subject_user_id, space_id, node_id)
  WHERE state = 'active';
CREATE INDEX drive_acl_grants_anchor_active_idx
  ON public.drive_acl_grants (space_id, node_id, subject_user_id)
  WHERE state = 'active';
CREATE INDEX drive_acl_grants_expiry_idx
  ON public.drive_acl_grants (expires_at, id)
  WHERE state = 'active' AND expires_at IS NOT NULL;
CREATE UNIQUE INDEX drive_acl_grants_idempotency_uniq
  ON public.drive_acl_grants (space_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE TABLE public.drive_acl_breaks (
  space_id          bigint NOT NULL REFERENCES public.drive_spaces(id) ON DELETE CASCADE,
  node_id           bigint NOT NULL,
  created_by        bigint NOT NULL REFERENCES public.users(id),
  created_at        timestamptz NOT NULL DEFAULT now(),
  expected_epoch    bigint NOT NULL CHECK (expected_epoch >= 0),
  PRIMARY KEY (space_id, node_id),
  CONSTRAINT drive_acl_breaks_node_fk
    FOREIGN KEY (space_id, node_id) REFERENCES public.drive_nodes(space_id, id) ON DELETE CASCADE
);

CREATE TABLE public.drive_node_closure (
  space_id       bigint NOT NULL REFERENCES public.drive_spaces(id) ON DELETE CASCADE,
  ancestor_id    bigint NOT NULL,
  descendant_id  bigint NOT NULL,
  depth           integer NOT NULL CHECK (depth BETWEEN 0 AND 1024),
  PRIMARY KEY (space_id, ancestor_id, descendant_id),
  CONSTRAINT drive_node_closure_ancestor_fk
    FOREIGN KEY (space_id, ancestor_id) REFERENCES public.drive_nodes(space_id, id) ON DELETE CASCADE,
  CONSTRAINT drive_node_closure_descendant_fk
    FOREIGN KEY (space_id, descendant_id) REFERENCES public.drive_nodes(space_id, id) ON DELETE CASCADE,
  CONSTRAINT drive_node_closure_self_depth
    CHECK ((ancestor_id = descendant_id) = (depth = 0))
);
CREATE INDEX drive_node_closure_descendant_idx
  ON public.drive_node_closure (space_id, descendant_id, depth, ancestor_id);
CREATE INDEX drive_node_closure_ancestor_idx
  ON public.drive_node_closure (space_id, ancestor_id, depth, descendant_id);

CREATE TABLE public.drive_acl_generations (
  space_id               bigint PRIMARY KEY REFERENCES public.drive_spaces(id) ON DELETE CASCADE,
  epoch                  bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
  retained_after_cursor  bigint NOT NULL DEFAULT 0 CHECK (retained_after_cursor >= 0),
  updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.drive_access_invalidations (
  cursor          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  space_id        bigint NOT NULL REFERENCES public.drive_spaces(id) ON DELETE CASCADE,
  principal_kind  text NOT NULL CHECK (principal_kind IN ('user', 'all')),
  principal_id    bigint REFERENCES public.users(id),
  anchor_node_id  bigint,
  resulting_epoch bigint NOT NULL CHECK (resulting_epoch > 0),
  reason          text NOT NULL CHECK (reason IN (
                    'grant', 'revoke', 'expire', 'inheritance_break',
                    'inheritance_resume', 'tree_move', 'full_reconcile')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT drive_access_invalidations_principal_shape
    CHECK ((principal_kind = 'user') = (principal_id IS NOT NULL)),
  CONSTRAINT drive_access_invalidations_anchor_fk
    FOREIGN KEY (space_id, anchor_node_id)
    REFERENCES public.drive_nodes(space_id, id) ON DELETE SET NULL (anchor_node_id)
);
CREATE INDEX drive_access_invalidations_user_cursor_idx
  ON public.drive_access_invalidations (principal_id, cursor)
  WHERE principal_kind = 'user';
CREATE INDEX drive_access_invalidations_space_cursor_idx
  ON public.drive_access_invalidations (space_id, cursor);
CREATE INDEX drive_access_invalidations_created_idx
  ON public.drive_access_invalidations (created_at, cursor);

-- Closed capability vocabulary. SQL is authoritative at migration time; the
-- repository parity guard introduced with the Go/TypeScript projections fails
-- if any projection differs from this exact catalog or preset map.
CREATE OR REPLACE FUNCTION public.drive_acl_capability_catalog()
RETURNS text[] LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, public AS $$
  SELECT ARRAY[
    'traverse', 'list_children', 'read_metadata', 'preview', 'download',
    'create_child', 'modify_content', 'rename', 'move', 'delete',
    'manage_acl', 'view_audit'
  ]::text[]
$$;

CREATE OR REPLACE FUNCTION public.drive_acl_capabilities_valid(p_capabilities text[])
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, public AS $$
  SELECT p_capabilities IS NOT NULL
     AND cardinality(p_capabilities) > 0
     AND cardinality(p_capabilities) = (
       SELECT count(DISTINCT v) FROM unnest(p_capabilities) AS u(v)
     )
     AND NOT EXISTS (
       SELECT 1 FROM unnest(p_capabilities) AS u(v)
        WHERE v IS NULL OR NOT (v = ANY(public.drive_acl_capability_catalog()))
     )
$$;

ALTER TABLE public.drive_acl_grants
  ADD CONSTRAINT drive_acl_grants_capabilities_valid
  CHECK (public.drive_acl_capabilities_valid(capabilities));

CREATE OR REPLACE FUNCTION public.drive_acl_preset_capabilities(p_preset text)
RETURNS text[] LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, public AS $$
  SELECT CASE p_preset
    WHEN 'viewer' THEN ARRAY[
      'traverse','list_children','read_metadata','preview','download'
    ]::text[]
    WHEN 'contributor' THEN ARRAY[
      'traverse','list_children','read_metadata','preview','download',
      'create_child','modify_content'
    ]::text[]
    WHEN 'editor' THEN ARRAY[
      'traverse','list_children','read_metadata','preview','download',
      'create_child','modify_content','rename','move','delete'
    ]::text[]
    WHEN 'folder_manager' THEN ARRAY[
      'traverse','list_children','read_metadata','preview','download',
      'create_child','modify_content','rename','move','delete',
      'manage_acl','view_audit'
    ]::text[]
    ELSE NULL
  END
$$;

ALTER TABLE public.drive_acl_grants
  ADD CONSTRAINT drive_acl_grants_preset_capabilities_match
  CHECK (capabilities = public.drive_acl_preset_capabilities(preset));

-- Fail the migration rather than materialize an incomplete or cyclic closure.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM public.drive_nodes child
      JOIN public.drive_nodes parent ON parent.id = child.parent_id
     WHERE child.space_id <> parent.space_id
  ) THEN
    RAISE EXCEPTION 'V184 abort: cross-space Drive parent detected'
      USING ERRCODE='BZ252';
  END IF;

  IF EXISTS (
    WITH RECURSIVE walk AS (
      SELECT n.id AS origin_id, n.id, n.parent_id, ARRAY[n.id]::bigint[] AS path,
             false AS cycle, 0 AS depth
        FROM public.drive_nodes n
      UNION ALL
      SELECT w.origin_id, p.id, p.parent_id, w.path || p.id,
             p.id = ANY(w.path), w.depth + 1
        FROM walk w
        JOIN public.drive_nodes p ON p.id = w.parent_id
       WHERE NOT w.cycle AND w.depth < 1024
    )
    SELECT 1 FROM walk WHERE cycle OR (depth = 1024 AND parent_id IS NOT NULL)
  ) THEN
    RAISE EXCEPTION 'V184 abort: cyclic or over-depth Drive tree detected'
      USING ERRCODE='BZ252';
  END IF;
END
$$;

WITH RECURSIVE closure AS (
  SELECT n.space_id, n.id AS ancestor_id, n.id AS descendant_id, 0 AS depth
    FROM public.drive_nodes n
  UNION ALL
  SELECT c.space_id, p.parent_id, c.descendant_id, c.depth + 1
    FROM closure c
    JOIN public.drive_nodes p
      ON p.space_id = c.space_id AND p.id = c.ancestor_id
   WHERE p.parent_id IS NOT NULL AND c.depth < 1024
)
INSERT INTO public.drive_node_closure (space_id, ancestor_id, descendant_id, depth)
SELECT space_id, ancestor_id, descendant_id, depth FROM closure
ON CONFLICT (space_id, ancestor_id, descendant_id) DO UPDATE SET depth = EXCLUDED.depth;

INSERT INTO public.drive_acl_generations (space_id)
SELECT id FROM public.drive_spaces
ON CONFLICT (space_id) DO NOTHING;

CREATE OR REPLACE FUNCTION public.trg_drive_acl_generation_init()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  INSERT INTO public.drive_acl_generations (space_id)
  VALUES (NEW.id)
  ON CONFLICT (space_id) DO NOTHING;
  RETURN NEW;
END;
$$;
SELECT public.apply_worker_ownership('trg_drive_acl_generation_init()'::regprocedure);
DROP TRIGGER IF EXISTS drive_acl_generation_init ON public.drive_spaces;
CREATE TRIGGER drive_acl_generation_init
AFTER INSERT ON public.drive_spaces
FOR EACH ROW EXECUTE FUNCTION public.trg_drive_acl_generation_init();

-- The expand tables are FORCE-RLS immediately. R1 policies deliberately use
-- the legacy root adapter until A2 replaces them with canonical capability
-- facts; this migration itself changes no existing Drive behavior.
ALTER TABLE public.drive_acl_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_acl_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY drive_acl_grants_read ON public.drive_acl_grants FOR SELECT TO public
  USING (
    subject_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
    OR public.drive_member_role(space_id,
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) = 'manager'
  );

ALTER TABLE public.drive_acl_breaks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_acl_breaks FORCE ROW LEVEL SECURITY;
CREATE POLICY drive_acl_breaks_read ON public.drive_acl_breaks FOR SELECT TO public
  USING (public.drive_member_role(space_id,
    (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);

ALTER TABLE public.drive_node_closure ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_node_closure FORCE ROW LEVEL SECURITY;
CREATE POLICY drive_node_closure_read ON public.drive_node_closure FOR SELECT TO public
  USING (public.drive_member_role(space_id,
    (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);

ALTER TABLE public.drive_acl_generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_acl_generations FORCE ROW LEVEL SECURITY;
CREATE POLICY drive_acl_generations_read ON public.drive_acl_generations FOR SELECT TO public
  USING (
    public.drive_member_role(space_id,
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL
    OR EXISTS (
      SELECT 1 FROM public.drive_acl_grants g
       WHERE g.space_id = drive_acl_generations.space_id
         AND g.subject_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
         AND g.state = 'active'
         AND (g.starts_at IS NULL OR g.starts_at <= now())
         AND (g.expires_at IS NULL OR g.expires_at > now())
    )
  );

ALTER TABLE public.drive_access_invalidations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_access_invalidations FORCE ROW LEVEL SECURITY;
CREATE POLICY drive_access_invalidations_read ON public.drive_access_invalidations FOR SELECT TO public
  USING (
    (principal_kind = 'user'
      AND principal_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
    OR (principal_kind = 'all' AND (
      public.drive_member_role(space_id,
        (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL
      OR EXISTS (
        SELECT 1 FROM public.drive_acl_grants g
         WHERE g.space_id = drive_access_invalidations.space_id
           AND g.subject_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
      )
    ))
    OR public.drive_member_role(space_id,
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) = 'manager'
  );

DO $$
DECLARE v_func regprocedure;
BEGIN
  FOREACH v_func IN ARRAY ARRAY[
    'drive_acl_capability_catalog()'::regprocedure,
    'drive_acl_capabilities_valid(text[])'::regprocedure,
    'drive_acl_preset_capabilities(text)'::regprocedure
  ] LOOP
    PERFORM public.apply_worker_ownership(v_func);
  END LOOP;
END
$$;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (184, now())
ON CONFLICT (version) DO NOTHING;
