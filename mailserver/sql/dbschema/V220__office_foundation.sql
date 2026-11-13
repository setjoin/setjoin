-- V220__office_foundation.sql
-- Drive-owned Office broker authority. All behavior remains inert behind
-- feature.drive_history / feature.office_editing / feature.office_local_open.

CREATE INDEX drive_audit_log_file_history_idx
    ON public.drive_audit_log
       (space_id, target_type, target_id, occurred_at DESC, id DESC);

CREATE TABLE public.office_provider_policies (
    provider_id              text PRIMARY KEY CHECK (provider_id ~ '^[a-z][a-z0-9._-]{1,63}$'),
    enabled                  boolean NOT NULL DEFAULT false,
    draining                 boolean NOT NULL DEFAULT false,
    generation               bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    default_modes            jsonb NOT NULL DEFAULT '{}'::jsonb,
    allowed_classifications  text[] NOT NULL DEFAULT ARRAY['regular']::text[],
    allowed_platforms        text[] NOT NULL DEFAULT ARRAY['web','electron']::text[],
    allowed_file_families    text[] NOT NULL DEFAULT ARRAY['word','sheet','presentation']::text[],
    entitlement_state        text NOT NULL DEFAULT 'unknown'
      CHECK (entitlement_state IN ('unknown','evaluation','valid','expiring','expired','build_mismatch','not_permitted')),
    entitlement_ref          text,
    build_id                 text,
    config                   jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_by               bigint REFERENCES public.users(id),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    removed_at               timestamptz
);

CREATE TABLE public.office_user_preferences (
    user_id       bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    device_id     text NOT NULL CHECK (length(device_id) BETWEEN 1 AND 200),
    file_family   text NOT NULL CHECK (file_family IN ('word','sheet','presentation')),
    provider_id   text NOT NULL REFERENCES public.office_provider_policies(provider_id),
    mode          text NOT NULL CHECK (mode IN ('edit_online','open_local','preview','download')),
    last_success_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id, file_family)
);

CREATE TABLE public.office_editor_sessions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    space_id        bigint NOT NULL REFERENCES public.drive_spaces(id),
    file_node_id    bigint NOT NULL REFERENCES public.drive_files(node_id) ON DELETE CASCADE,
    branch_id       bigint REFERENCES public.drive_file_branches(id) ON DELETE SET NULL,
    base_version_id bigint NOT NULL REFERENCES public.drive_file_versions(id),
    provider_id     text NOT NULL REFERENCES public.office_provider_policies(provider_id),
    cohort_key      text NOT NULL CHECK (length(cohort_key) BETWEEN 1 AND 200),
    fence_generation bigint NOT NULL DEFAULT 1 CHECK (fence_generation > 0),
    lock_epoch      bigint NOT NULL DEFAULT 1 CHECK (lock_epoch > 0),
    status          text NOT NULL DEFAULT 'active'
      CHECK (status IN ('launching','active','saving','draining','closed','revoked','expired','failed')),
    terminal_reason text,
    lease_expires_at timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX office_editor_sessions_file_idx
    ON public.office_editor_sessions(file_node_id, status, updated_at DESC);
CREATE UNIQUE INDEX office_editor_sessions_active_cohort_uniq
    ON public.office_editor_sessions(file_node_id, provider_id, cohort_key)
    WHERE status IN ('launching','active','saving','draining');

CREATE TABLE public.office_editor_launches (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id           uuid NOT NULL REFERENCES public.office_editor_sessions(id) ON DELETE CASCADE,
    space_id             bigint NOT NULL REFERENCES public.drive_spaces(id),
    file_node_id         bigint NOT NULL REFERENCES public.drive_files(node_id) ON DELETE CASCADE,
    actor_user_id        bigint NOT NULL REFERENCES public.users(id),
    device_id            text NOT NULL CHECK (length(device_id) BETWEEN 1 AND 200),
    action               text NOT NULL CHECK (action IN ('edit_online','open_local','preview','download')),
    token_hash           text CHECK (token_hash IS NULL OR token_hash ~ '^[0-9a-f]{64}$'),
    fence_generation     bigint NOT NULL CHECK (fence_generation > 0),
    revocation_generation bigint NOT NULL DEFAULT 1 CHECK (revocation_generation > 0),
    provenance_confidence text NOT NULL DEFAULT 'actor'
      CHECK (provenance_confidence IN ('actor','cohort','provider','unknown')),
    expires_at           timestamptz NOT NULL,
    revoked_at           timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX office_editor_launches_session_idx ON public.office_editor_launches(session_id, expires_at);
CREATE UNIQUE INDEX office_editor_launches_token_hash_uniq
    ON public.office_editor_launches(token_hash) WHERE token_hash IS NOT NULL;

CREATE TABLE public.office_wopi_locks (
    session_id       uuid PRIMARY KEY REFERENCES public.office_editor_sessions(id) ON DELETE CASCADE,
    space_id         bigint NOT NULL REFERENCES public.drive_spaces(id),
    file_node_id     bigint NOT NULL REFERENCES public.drive_files(node_id) ON DELETE CASCADE,
    opaque_lock_hash text NOT NULL CHECK (opaque_lock_hash ~ '^[0-9a-f]{64}$'),
    opaque_lock_value text NOT NULL CHECK (length(opaque_lock_value) BETWEEN 1 AND 4096),
    fence_generation bigint NOT NULL CHECK (fence_generation > 0),
    lock_epoch       bigint NOT NULL CHECK (lock_epoch > 0),
    expires_at       timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX office_wopi_locks_file_idx ON public.office_wopi_locks(file_node_id, expires_at);

CREATE TABLE public.office_save_receipts (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id          uuid NOT NULL REFERENCES public.office_editor_sessions(id),
    space_id            bigint NOT NULL REFERENCES public.drive_spaces(id),
    file_node_id        bigint NOT NULL REFERENCES public.drive_files(node_id),
    provider_id         text NOT NULL REFERENCES public.office_provider_policies(provider_id),
    operation_key       text NOT NULL CHECK (length(operation_key) BETWEEN 1 AND 200),
    expected_base_id    bigint NOT NULL REFERENCES public.drive_file_versions(id),
    content_sha256      text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    result_version_id   bigint REFERENCES public.drive_file_versions(id),
    result_branch_id    bigint REFERENCES public.drive_file_branches(id),
    response_class      text NOT NULL CHECK (response_class IN ('accepted','branched','rejected')),
    rejection_facts     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_id, session_id, operation_key)
);
CREATE INDEX office_save_receipts_file_idx
    ON public.office_save_receipts(file_node_id, created_at DESC, id DESC);

-- All Office records are fail-closed under native RLS. Durable mutation tables
-- are reducer-only; policies below grant reads, not direct writes.
ALTER TABLE public.office_provider_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.office_provider_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE public.office_user_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.office_user_preferences FORCE ROW LEVEL SECURITY;
ALTER TABLE public.office_editor_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.office_editor_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.office_editor_launches ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.office_editor_launches FORCE ROW LEVEL SECURITY;
ALTER TABLE public.office_wopi_locks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.office_wopi_locks FORCE ROW LEVEL SECURITY;
ALTER TABLE public.office_save_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.office_save_receipts FORCE ROW LEVEL SECURITY;

CREATE POLICY office_provider_policies_read ON public.office_provider_policies FOR SELECT TO public
  USING (public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id',true),'')::bigint,'office.view')
      OR public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id',true),'')::bigint,'office.manage'));
CREATE POLICY office_user_preferences_read ON public.office_user_preferences FOR SELECT TO public
  USING (user_id = NULLIF(current_setting('app.current_user_id',true),'')::bigint);
CREATE POLICY office_editor_sessions_read ON public.office_editor_sessions FOR SELECT TO public
  USING (public.drive_member_role(space_id,NULLIF(current_setting('app.current_user_id',true),'')::bigint) IS NOT NULL);
CREATE POLICY office_editor_launches_read ON public.office_editor_launches FOR SELECT TO public
  USING (actor_user_id = NULLIF(current_setting('app.current_user_id',true),'')::bigint
      OR public.drive_member_role(space_id,NULLIF(current_setting('app.current_user_id',true),'')::bigint) = 'manager');
-- WOPI requires the current opaque lock value to be echoed on a conflict. The
-- value is not a credential, but the table stays reducer-only so ordinary Drive
-- members cannot enumerate another editor's protocol state.
CREATE POLICY office_wopi_locks_read ON public.office_wopi_locks FOR SELECT TO public
  USING (false);
CREATE POLICY office_save_receipts_read ON public.office_save_receipts FOR SELECT TO public
  USING (public.drive_member_role(space_id,NULLIF(current_setting('app.current_user_id',true),'')::bigint) IS NOT NULL);

-- RequireReason only attaches X-Audit-Reason for registered permission areas.
-- Office removal rejects an empty reason, so this is part of the route-to-
-- reducer contract rather than an optional administrator policy default.
UPDATE public.audit_policy
   SET reason_required_areas=array_append(reason_required_areas,'office')
 WHERE id=1 AND NOT ('office'=ANY(reason_required_areas));

INSERT INTO public.feature_toggles(key,enabled,description) VALUES
  ('feature.drive_history',false,'Drive-owned file History timeline'),
  ('feature.office_editing',false,'Online Office editing through removable providers'),
  ('feature.office_local_open',false,'Desktop-only local Office open and reconnect')
ON CONFLICT (key) DO UPDATE SET description=EXCLUDED.description;

INSERT INTO public.admin_permissions(permission_key,category,description,is_sensitive) VALUES
  ('office.view','Office','View Office provider policy, health, evidence and removal state',false),
  ('office.manage','Office','Configure, drain, disable and remove Office providers',true)
ON CONFLICT (permission_key) DO NOTHING;

UPDATE public.admin_role_groups
   SET permissions=(SELECT array_agg(DISTINCT p ORDER BY p)
                      FROM unnest(permissions || ARRAY['office.view','office.manage']) p)
 WHERE id=1;

INSERT INTO public.schema_migrations(version,applied_at) VALUES (220,now())
ON CONFLICT (version) DO NOTHING;
