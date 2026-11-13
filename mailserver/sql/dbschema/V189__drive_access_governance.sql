-- V189__drive_access_governance.sql
-- A5 adds a Drive consumer to the existing approval engine.  The generic
-- lifecycle remains authoritative; these tables contain only Drive policy,
-- immutable requested/applied payload, and bounded-use lease state.

ALTER TABLE public.approval_policies
  DROP CONSTRAINT approval_policies_consumer_type_check;
ALTER TABLE public.approval_policies
  ADD CONSTRAINT approval_policies_consumer_type_check CHECK (consumer_type IN (
    'rbac.jit_activation','mail.external_send','mail.group_moderation',
    'hr.leave','hr.expense','drive.export','drive.share','guest.invite',
    'identity.transition','system_upgrade','drive.access'
  ));
ALTER TABLE public.approval_requests
  DROP CONSTRAINT approval_requests_consumer_type_check;
ALTER TABLE public.approval_requests
  ADD CONSTRAINT approval_requests_consumer_type_check CHECK (consumer_type IN (
    'rbac.jit_activation','mail.external_send','mail.group_moderation',
    'hr.leave','hr.expense','drive.export','drive.share','guest.invite',
    'identity.transition','system_upgrade','drive.access'
  ));

INSERT INTO public.feature_toggles(key,enabled,description) VALUES
  ('feature.drive_access_governance',false,
   'Drive denied-action requests, approvals, and bounded-use leases. DEFAULT OFF.'),
  ('feature.drive_emergency_access',false,
   'Drive fresh-MFA, SoD-approved emergency access. DEFAULT OFF.')
ON CONFLICT(key) DO NOTHING;

ALTER TABLE public.drive_acl_grants
  ADD COLUMN approval_request_id bigint UNIQUE
  REFERENCES public.approval_requests(id) ON DELETE RESTRICT;

CREATE TABLE public.drive_access_request_policies (
  id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  approval_policy_id    bigint NOT NULL UNIQUE
                        REFERENCES public.approval_policies(id) ON DELETE CASCADE,
  space_id              bigint NOT NULL REFERENCES public.drive_spaces(id) ON DELETE CASCADE,
  anchor_node_id        bigint,
  subject_kind          text NOT NULL DEFAULT 'user'
                        CHECK(subject_kind IN ('user','group','any')),
  capabilities          text[] NOT NULL,
  max_propagation       text NOT NULL
                        CHECK(max_propagation IN ('self','children','subtree')),
  max_duration_minutes  integer NOT NULL
                        CHECK(max_duration_minutes BETWEEN 1 AND 525600),
  max_uses              integer CHECK(max_uses BETWEEN 1 AND 1000000),
  emergency_allowed     boolean NOT NULL DEFAULT false,
  enabled               boolean NOT NULL DEFAULT true,
  created_by            bigint NOT NULL REFERENCES public.users(id),
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT drive_access_request_policies_anchor_fk
    FOREIGN KEY(space_id,anchor_node_id)
    REFERENCES public.drive_nodes(space_id,id) ON DELETE CASCADE,
  CONSTRAINT drive_access_request_policies_capabilities
    CHECK(public.drive_acl_capabilities_valid(capabilities))
);
CREATE INDEX drive_access_request_policies_match_idx
  ON public.drive_access_request_policies(space_id,enabled,anchor_node_id,id);

CREATE TABLE public.drive_access_request_details (
  request_id              bigint PRIMARY KEY
                          REFERENCES public.approval_requests(id) ON DELETE CASCADE,
  requester_user_id       bigint NOT NULL REFERENCES public.users(id),
  policy_id               bigint NOT NULL
                          REFERENCES public.drive_access_request_policies(id),
  space_id                bigint NOT NULL REFERENCES public.drive_spaces(id),
  node_id                 bigint NOT NULL,
  subject_kind            text NOT NULL CHECK(subject_kind IN ('user','group')),
  subject_user_id         bigint REFERENCES public.users(id),
  subject_group_id        bigint REFERENCES public.directory_groups(id),
  requested_capabilities  text[] NOT NULL,
  requested_propagation   text NOT NULL
                          CHECK(requested_propagation IN ('self','children','subtree')),
  requested_expires_at    timestamptz NOT NULL,
  requested_max_uses      integer CHECK(requested_max_uses BETWEEN 1 AND 1000000),
  applied_capabilities    text[],
  applied_propagation     text CHECK(applied_propagation IN ('self','children','subtree')),
  applied_expires_at      timestamptz,
  applied_max_uses        integer CHECK(applied_max_uses BETWEEN 1 AND 1000000),
  emergency               boolean NOT NULL DEFAULT false,
  mfa_session_id          text,
  reason                  text NOT NULL CHECK(
                            reason=btrim(reason) AND octet_length(reason) BETWEEN 8 AND 1000),
  expected_epoch          bigint NOT NULL CHECK(expected_epoch>=0),
  idempotency_key         text NOT NULL CHECK(
                            idempotency_key=btrim(idempotency_key)
                            AND octet_length(idempotency_key) BETWEEN 8 AND 200),
  request_digest          text NOT NULL CHECK(request_digest~'^[0-9a-f]{64}$'),
  grant_id                bigint UNIQUE REFERENCES public.drive_acl_grants(id),
  created_at              timestamptz NOT NULL DEFAULT now(),
  applied_at              timestamptz,
  CONSTRAINT drive_access_request_details_node_fk
    FOREIGN KEY(space_id,node_id) REFERENCES public.drive_nodes(space_id,id),
  CONSTRAINT drive_access_request_details_subject_shape CHECK(
    (subject_kind='user' AND subject_user_id IS NOT NULL AND subject_group_id IS NULL)
    OR (subject_kind='group' AND subject_user_id IS NULL AND subject_group_id IS NOT NULL)
  ),
  CONSTRAINT drive_access_request_details_applied_shape CHECK(
    (grant_id IS NULL AND applied_capabilities IS NULL
      AND applied_propagation IS NULL AND applied_expires_at IS NULL
      AND applied_max_uses IS NULL AND applied_at IS NULL)
    OR (grant_id IS NOT NULL AND public.drive_acl_capabilities_valid(applied_capabilities)
      AND applied_propagation IS NOT NULL AND applied_expires_at IS NOT NULL
      AND applied_at IS NOT NULL)
  ),
  UNIQUE(requester_user_id,idempotency_key)
);
CREATE INDEX drive_access_request_details_subject_idx
  ON public.drive_access_request_details(subject_user_id,request_id)
  WHERE subject_kind='user';

CREATE TABLE public.drive_access_use_leases (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  grant_id         bigint NOT NULL REFERENCES public.drive_acl_grants(id) ON DELETE CASCADE,
  user_id          bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  capability       text NOT NULL CHECK(capability IN (
                     'preview','download','create_child','modify_content','delete')),
  idempotency_key  text NOT NULL CHECK(
                     idempotency_key=btrim(idempotency_key)
                     AND octet_length(idempotency_key) BETWEEN 8 AND 200),
  request_digest   text NOT NULL CHECK(request_digest~'^[0-9a-f]{64}$'),
  state            text NOT NULL DEFAULT 'reserved'
                   CHECK(state IN ('reserved','consumed','abandoned')),
  created_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,
  consumed_at      timestamptz,
  UNIQUE(grant_id,user_id,idempotency_key),
  CHECK(expires_at>created_at AND expires_at<=created_at+interval '15 minutes'),
  CHECK((state='consumed')=(consumed_at IS NOT NULL))
);
CREATE INDEX drive_access_use_leases_expiry_idx
  ON public.drive_access_use_leases(expires_at,id) WHERE state='reserved';

CREATE OR REPLACE FUNCTION public.trg_drive_access_policy_shape()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM public.approval_policies p
                 WHERE p.id=NEW.approval_policy_id
                   AND p.consumer_type='drive.access') THEN
    RAISE EXCEPTION 'Drive access policy must reference drive.access approval policy'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid","field":"approvalPolicyId"}';
  END IF;
  RETURN NEW;
END;
$$;
SELECT public.apply_worker_ownership('trg_drive_access_policy_shape()'::regprocedure);
CREATE TRIGGER drive_access_policy_shape
BEFORE INSERT OR UPDATE OF approval_policy_id ON public.drive_access_request_policies
FOR EACH ROW EXECUTE FUNCTION public.trg_drive_access_policy_shape();

CREATE OR REPLACE FUNCTION public.trg_drive_access_request_immutable()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
BEGIN
  IF ROW(NEW.requester_user_id,NEW.policy_id,NEW.space_id,NEW.node_id,
         NEW.subject_kind,NEW.subject_user_id,NEW.subject_group_id,
         NEW.requested_capabilities,NEW.requested_propagation,
         NEW.requested_expires_at,NEW.requested_max_uses,NEW.emergency,
         NEW.mfa_session_id,NEW.reason,NEW.expected_epoch,NEW.idempotency_key,
         NEW.request_digest)
     IS DISTINCT FROM
     ROW(OLD.requester_user_id,OLD.policy_id,OLD.space_id,OLD.node_id,
         OLD.subject_kind,OLD.subject_user_id,OLD.subject_group_id,
         OLD.requested_capabilities,OLD.requested_propagation,
         OLD.requested_expires_at,OLD.requested_max_uses,OLD.emergency,
         OLD.mfa_session_id,OLD.reason,OLD.expected_epoch,OLD.idempotency_key,
         OLD.request_digest) THEN
    RAISE EXCEPTION 'Drive access requested payload is immutable'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"requestedPayload"}';
  END IF;
  RETURN NEW;
END;
$$;
SELECT public.apply_worker_ownership('trg_drive_access_request_immutable()'::regprocedure);
CREATE TRIGGER drive_access_request_immutable
BEFORE UPDATE ON public.drive_access_request_details
FOR EACH ROW EXECUTE FUNCTION public.trg_drive_access_request_immutable();

-- Keep these declarations literal: the RLS coverage guards derive their
-- inventory from migration source and must see every table independently.
ALTER TABLE public.drive_access_request_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_access_request_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE public.drive_access_request_details ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_access_request_details FORCE ROW LEVEL SECURITY;
ALTER TABLE public.drive_access_use_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_access_use_leases FORCE ROW LEVEL SECURITY;
CREATE POLICY drive_access_request_policies_admin
  ON public.drive_access_request_policies FOR ALL TO public
  USING(public.drive_has_admin_perm((SELECT NULLIF(
    current_setting('app.current_user_id',true),'')::bigint),'drive.manage'))
  WITH CHECK(public.drive_has_admin_perm((SELECT NULLIF(
    current_setting('app.current_user_id',true),'')::bigint),'drive.manage'));
CREATE POLICY drive_access_request_details_via_request
  ON public.drive_access_request_details FOR SELECT TO public
  USING(EXISTS(SELECT 1 FROM public.approval_requests r WHERE r.id=request_id));
CREATE POLICY drive_access_use_leases_self
  ON public.drive_access_use_leases FOR SELECT TO public
  USING(user_id=(SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (189, now())
ON CONFLICT(version) DO NOTHING;
