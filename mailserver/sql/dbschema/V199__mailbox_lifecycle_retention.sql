-- V199__mailbox_lifecycle_retention.sql
-- Expand-only mailbox lifecycle, retained address, operation, purge and
-- retention-domain authority. feature.mailbox_lifecycle_retention remains OFF.

INSERT INTO public.feature_toggles(key,enabled,description) VALUES
  ('feature.mailbox_lifecycle_retention',false,
   'Explicit suspend, detach-retain, reconnect and approved delayed mailbox purge. DEFAULT OFF.')
ON CONFLICT(key) DO NOTHING;

CREATE TABLE public.mailbox_lifecycle (
  mailbox_id bigint PRIMARY KEY REFERENCES public.mailboxes(id) ON DELETE RESTRICT,
  access_state text NOT NULL DEFAULT 'active' CHECK(access_state IN ('active','suspended','detached')),
  delivery_state text NOT NULL DEFAULT 'accepting' CHECK(delivery_state IN ('accepting','redirecting','rejecting')),
  binding_state text NOT NULL DEFAULT 'bound' CHECK(binding_state IN ('bound','retained','shared')),
  bound_user_id bigint REFERENCES public.users(id) ON DELETE RESTRICT,
  was_primary boolean NOT NULL DEFAULT false,
  generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
  policy_generation bigint NOT NULL DEFAULT 1 CHECK(policy_generation>0),
  retained_at timestamptz,
  retention_until timestamptz,
  redirect_address text,
  reason text CHECK(reason IS NULL OR octet_length(reason) BETWEEN 1 AND 1024),
  last_operation_id uuid,
  updated_by bigint REFERENCES public.users(id) ON DELETE SET NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT mailbox_lifecycle_binding_shape CHECK(
    (binding_state='bound' AND bound_user_id IS NOT NULL AND access_state<>'detached')
    OR (binding_state='retained' AND bound_user_id IS NULL AND access_state='detached')
    OR (binding_state='shared' AND bound_user_id IS NULL AND access_state<>'detached')),
  CONSTRAINT mailbox_lifecycle_redirect_shape CHECK(
    (delivery_state='redirecting' AND redirect_address IS NOT NULL)
    OR (delivery_state<>'redirecting' AND redirect_address IS NULL)),
  CONSTRAINT mailbox_lifecycle_retention_shape CHECK(
    (binding_state='retained' AND retained_at IS NOT NULL AND retention_until IS NOT NULL)
    OR (binding_state<>'retained' AND retained_at IS NULL AND retention_until IS NULL))
);
CREATE INDEX mailbox_lifecycle_state_idx ON public.mailbox_lifecycle(binding_state,access_state,delivery_state);

CREATE TABLE public.mailbox_binding_history (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  mailbox_id bigint NOT NULL,
  from_user_id bigint REFERENCES public.users(id) ON DELETE SET NULL,
  to_user_id bigint REFERENCES public.users(id) ON DELETE SET NULL,
  operation_id uuid NOT NULL,
  evidence_kind text NOT NULL CHECK(evidence_kind IN ('initial','local_user','identity_link','operator_recovery')),
  identity_link_id bigint REFERENCES public.user_identity_links(id) ON DELETE RESTRICT,
  link_generation bigint,
  source_key_digest text CHECK(source_key_digest IS NULL OR source_key_digest ~ '^[0-9a-f]{64}$'),
  actor_user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  actor_auth_time timestamptz NOT NULL,
  reason text NOT NULL CHECK(octet_length(reason) BETWEEN 1 AND 1024),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(mailbox_id,operation_id)
);

CREATE TABLE public.mailbox_address_claims (
  normalized_address text PRIMARY KEY CHECK(normalized_address=lower(normalized_address)),
  mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE RESTRICT,
  address_kind text NOT NULL CHECK(address_kind IN ('primary','alias')),
  claim_state text NOT NULL DEFAULT 'active' CHECK(claim_state IN ('active','retained','released')),
  generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
  claimed_at timestamptz NOT NULL DEFAULT now(),
  released_at timestamptz,
  CONSTRAINT mailbox_address_claims_release_shape CHECK((claim_state='released')=(released_at IS NOT NULL))
);
CREATE INDEX mailbox_address_claims_mailbox_idx ON public.mailbox_address_claims(mailbox_id,claim_state);

CREATE TABLE public.mailbox_lifecycle_conflicts (
  normalized_address text NOT NULL,
  mailbox_ids bigint[] NOT NULL,
  conflict_kind text NOT NULL CHECK(conflict_kind IN ('duplicate_address','binding_mismatch')),
  detected_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  PRIMARY KEY(normalized_address,conflict_kind)
);

CREATE TABLE public.mailbox_lifecycle_operations (
  operation_id uuid PRIMARY KEY,
  mailbox_id bigint NOT NULL,
  action text NOT NULL CHECK(action IN ('suspend','resume','detach_retain','reconnect','purge_schedule','purge_cancel','purge_execute')),
  actor_user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  expected_generation bigint NOT NULL CHECK(expected_generation>0),
  request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
  before_digest text NOT NULL CHECK(before_digest ~ '^[0-9a-f]{64}$'),
  after_digest text NOT NULL CHECK(after_digest ~ '^[0-9a-f]{64}$'),
  state text NOT NULL DEFAULT 'completed' CHECK(state IN ('completed','failed')),
  error_code text,
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.mailbox_lifecycle_effects (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES public.mailbox_lifecycle_operations(operation_id) ON DELETE CASCADE,
  mailbox_id bigint NOT NULL,
  effect_kind text NOT NULL CHECK(effect_kind IN ('revoke_sessions','evict_media','revoke_delegates','notify_clients','lifecycle_webhook')),
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','claimed','completed','failed')),
  attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 100),
  claimed_by text,
  lease_until timestamptz,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  UNIQUE(operation_id,effect_kind)
);

CREATE TABLE public.mailbox_lifecycle_effect_targets (
  operation_id uuid NOT NULL REFERENCES public.mailbox_lifecycle_operations(operation_id) ON DELETE CASCADE,
  effect_kind text NOT NULL DEFAULT 'evict_media' CHECK(effect_kind='evict_media'),
  room_name text NOT NULL CHECK(octet_length(room_name) BETWEEN 1 AND 512),
  identity text NOT NULL CHECK(octet_length(identity) BETWEEN 1 AND 512),
  evict_until timestamptz,
  completed_at timestamptz,
  last_error text,
  PRIMARY KEY(operation_id,effect_kind,room_name,identity)
);

CREATE TABLE public.mailbox_purge_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  mailbox_id bigint NOT NULL,
  operation_id uuid NOT NULL UNIQUE,
  lifecycle_generation bigint NOT NULL CHECK(lifecycle_generation>0),
  preview_digest text NOT NULL CHECK(preview_digest ~ '^[0-9a-f]{64}$'),
  requested_by bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  requested_at timestamptz NOT NULL DEFAULT now(),
  eligible_at timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','approved','cancelled','claimed','completed','blocked','failed')),
  approved_by bigint REFERENCES public.users(id) ON DELETE RESTRICT,
  approved_at timestamptz,
  approval_request_id bigint UNIQUE REFERENCES public.approval_requests(id) ON DELETE RESTRICT,
  attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 100),
  claimed_by text,
  lease_until timestamptz,
  execute_operation_id uuid NOT NULL DEFAULT gen_random_uuid(),
  reason text NOT NULL CHECK(octet_length(reason) BETWEEN 1 AND 1024),
  blocker_snapshot jsonb NOT NULL DEFAULT '[]',
  CONSTRAINT mailbox_purge_independent_approval CHECK(approved_by IS NULL OR approved_by<>requested_by)
);
CREATE UNIQUE INDEX mailbox_purge_one_open_idx ON public.mailbox_purge_requests(mailbox_id)
 WHERE state IN ('pending','approved','claimed','blocked');

CREATE TABLE public.mailbox_tombstones (
  mailbox_id bigint PRIMARY KEY,
  purge_request_id uuid NOT NULL UNIQUE REFERENCES public.mailbox_purge_requests(id) ON DELETE RESTRICT,
  address_digests jsonb NOT NULL,
  message_count bigint NOT NULL CHECK(message_count>=0),
  blob_count bigint NOT NULL CHECK(blob_count>=0),
  evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[0-9a-f]{64}$'),
  reason text NOT NULL CHECK(octet_length(reason) BETWEEN 1 AND 1024),
  purged_by bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  purged_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.mailbox_retention_domains (
  domain_key text PRIMARY KEY CHECK(domain_key ~ '^[a-z][a-z0-9_.-]{1,63}$'),
  blocker_function text NOT NULL CHECK(blocker_function ~ '^[a-z_][a-z0-9_]*$'),
  contract_version integer NOT NULL DEFAULT 1 CHECK(contract_version>0),
  owner_component text NOT NULL DEFAULT 'mailbox_lifecycle' CHECK(octet_length(owner_component) BETWEEN 1 AND 128),
  generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
  enabled boolean NOT NULL DEFAULT true,
  registered_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.mailbox_lifecycle_policies (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  domain_id bigint REFERENCES public.domains(id) ON DELETE CASCADE,
  generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
  retention_days integer NOT NULL DEFAULT 30 CHECK(retention_days BETWEEN 0 AND 3650),
  redirect_allowed boolean NOT NULL DEFAULT false,
  approval_policy_id bigint REFERENCES public.approval_policies(id) ON DELETE RESTRICT,
  effective_at timestamptz NOT NULL DEFAULT now(),
  updated_by bigint REFERENCES public.users(id) ON DELETE SET NULL,
  reason text NOT NULL DEFAULT 'initial default' CHECK(octet_length(reason) BETWEEN 1 AND 1024)
);
CREATE UNIQUE INDEX mailbox_lifecycle_policy_default_idx ON public.mailbox_lifecycle_policies((domain_id IS NULL)) WHERE domain_id IS NULL;
CREATE UNIQUE INDEX mailbox_lifecycle_policy_domain_idx ON public.mailbox_lifecycle_policies(domain_id) WHERE domain_id IS NOT NULL;
INSERT INTO public.mailbox_lifecycle_policies(domain_id) VALUES(NULL);

-- Transaction-bound durable effects. Nothing external is dispatched before
-- the lifecycle transaction commits.
CREATE TABLE public.mailbox_lifecycle_outbox (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES public.mailbox_lifecycle_operations(operation_id) ON DELETE CASCADE,
  event_kind text NOT NULL CHECK(event_kind IN ('mailbox.suspended','mailbox.resumed','mailbox.detached','mailbox.reconnected','mailbox.purge_scheduled','mailbox.purge_cancelled','mailbox.purged','user.deleted')),
  dedupe_key text NOT NULL CHECK(octet_length(dedupe_key) BETWEEN 1 AND 256),
  payload_version integer NOT NULL DEFAULT 1 CHECK(payload_version=1),
  payload jsonb NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','claimed','completed','failed')),
  attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 100),
  claimed_by text,
  lease_until timestamptz,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  UNIQUE(dedupe_key)
);

-- Backfill bindings. Shared/resource mailboxes without an owning user are
-- retained, not silently assigned.
INSERT INTO public.mailbox_lifecycle(mailbox_id,access_state,delivery_state,binding_state,bound_user_id,was_primary)
SELECT id,CASE WHEN enabled THEN 'active' ELSE 'suspended' END,
  CASE WHEN receive_enabled THEN 'accepting' ELSE 'rejecting' END,
  CASE WHEN user_id IS NULL THEN 'shared' ELSE 'bound' END,user_id,is_primary
FROM public.mailboxes;

-- Whole-mailbox purge reuses the existing approval engine; the shared decision
-- reducer still cannot apply the payload itself.
ALTER TABLE public.approval_policies DROP CONSTRAINT approval_policies_consumer_type_check;
ALTER TABLE public.approval_policies ADD CONSTRAINT approval_policies_consumer_type_check
  CHECK(consumer_type IN (
    'rbac.jit_activation','mail.external_send','mail.group_moderation',
    'hr.leave','hr.expense','drive.export','drive.share','guest.invite',
    'identity.transition','system_upgrade','drive.access','mailbox.purge'
  ));
ALTER TABLE public.approval_requests DROP CONSTRAINT approval_requests_consumer_type_check;
ALTER TABLE public.approval_requests ADD CONSTRAINT approval_requests_consumer_type_check
  CHECK(consumer_type IN (
    'rbac.jit_activation','mail.external_send','mail.group_moderation',
    'hr.leave','hr.expense','drive.export','drive.share','guest.invite',
    'identity.transition','system_upgrade','drive.access','mailbox.purge'
  ));

WITH addresses AS (
  SELECT lower(email) address,id mailbox_id,'primary' kind FROM public.mailboxes
  UNION ALL SELECT lower(email),mailbox_id,'alias' FROM public.aliases
), grouped AS (
  SELECT address,array_agg(DISTINCT mailbox_id ORDER BY mailbox_id) mailbox_ids,
    min(mailbox_id) mailbox_id,min(kind) kind,count(DISTINCT mailbox_id) owners
  FROM addresses GROUP BY address
)
INSERT INTO public.mailbox_address_claims(normalized_address,mailbox_id,address_kind)
SELECT address,mailbox_id,kind FROM grouped WHERE owners=1;
WITH addresses AS (
  SELECT lower(email) address,id mailbox_id FROM public.mailboxes
  UNION ALL SELECT lower(email),mailbox_id FROM public.aliases
)
INSERT INTO public.mailbox_lifecycle_conflicts(normalized_address,mailbox_ids,conflict_kind)
SELECT address,array_agg(DISTINCT mailbox_id ORDER BY mailbox_id),'duplicate_address'
FROM addresses GROUP BY address HAVING count(DISTINCT mailbox_id)>1;

-- Keep expand/shadow state complete for objects created after the migration.
-- When the feature is OFF, legacy mailbox deletion remains compatible; when it
-- is ON, a retained mailbox can only be removed by the purge reducer (which
-- removes lifecycle/claims first).
CREATE FUNCTION public.mailbox_lifecycle_mailbox_insert_sync() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  INSERT INTO mailbox_lifecycle(mailbox_id,access_state,delivery_state,binding_state,bound_user_id,was_primary)
  VALUES(NEW.id,CASE WHEN NEW.enabled THEN 'active' ELSE 'suspended' END,
    CASE WHEN NEW.receive_enabled THEN 'accepting' ELSE 'rejecting' END,
    CASE WHEN NEW.user_id IS NULL THEN 'shared' ELSE 'bound' END,NEW.user_id,NEW.is_primary);
  INSERT INTO mailbox_address_claims(normalized_address,mailbox_id,address_kind)
  VALUES(lower(NEW.email),NEW.id,'primary');
  RETURN NEW;
END $$;
CREATE TRIGGER mailbox_lifecycle_mailbox_insert AFTER INSERT ON public.mailboxes
FOR EACH ROW EXECUTE FUNCTION public.mailbox_lifecycle_mailbox_insert_sync();

CREATE FUNCTION public.mailbox_lifecycle_mailbox_delete_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.mailbox_lifecycle_retention'),false)
     AND EXISTS(SELECT 1 FROM mailbox_lifecycle WHERE mailbox_id=OLD.id AND binding_state='retained') THEN
    RAISE EXCEPTION 'retained mailbox requires approved purge' USING ERRCODE='BZ313';
  END IF;
  DELETE FROM mailbox_address_claims WHERE mailbox_id=OLD.id;
  DELETE FROM mailbox_lifecycle WHERE mailbox_id=OLD.id;
  RETURN OLD;
END $$;
CREATE TRIGGER mailbox_lifecycle_mailbox_delete BEFORE DELETE ON public.mailboxes
FOR EACH ROW EXECUTE FUNCTION public.mailbox_lifecycle_mailbox_delete_guard();

CREATE FUNCTION public.mailbox_lifecycle_mailbox_update_sync() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_enabled boolean:=COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.mailbox_lifecycle_retention'),false);
BEGIN
  IF lower(OLD.email)<>lower(NEW.email) THEN
    IF v_enabled AND EXISTS(SELECT 1 FROM mailbox_lifecycle WHERE mailbox_id=OLD.id AND binding_state='retained') THEN
      RAISE EXCEPTION 'retained mailbox addresses cannot be changed' USING ERRCODE='BZ314';
    END IF;
    DELETE FROM mailbox_address_claims WHERE normalized_address=lower(OLD.email) AND mailbox_id=OLD.id;
    INSERT INTO mailbox_address_claims(normalized_address,mailbox_id,address_kind)
      VALUES(lower(NEW.email),NEW.id,'primary');
  END IF;
  IF NOT v_enabled THEN
    UPDATE mailbox_lifecycle SET
      access_state=CASE WHEN NEW.enabled THEN 'active' ELSE 'suspended' END,
      delivery_state=CASE WHEN NEW.receive_enabled THEN 'accepting' ELSE 'rejecting' END,
      binding_state=CASE WHEN NEW.user_id IS NULL THEN 'shared' ELSE 'bound' END,
      bound_user_id=NEW.user_id,
      was_primary=NEW.is_primary,
      retained_at=NULL,retention_until=NULL,redirect_address=NULL,
      generation=generation+1,updated_at=statement_timestamp()
    WHERE mailbox_id=NEW.id;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER mailbox_lifecycle_mailbox_update AFTER UPDATE OF email,user_id,enabled,receive_enabled ON public.mailboxes
FOR EACH ROW EXECUTE FUNCTION public.mailbox_lifecycle_mailbox_update_sync();

CREATE FUNCTION public.mailbox_lifecycle_alias_sync() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    IF COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.mailbox_lifecycle_retention'),false)
       AND EXISTS(SELECT 1 FROM mailbox_lifecycle WHERE mailbox_id=OLD.mailbox_id AND binding_state='retained') THEN
      RAISE EXCEPTION 'retained mailbox addresses cannot be released' USING ERRCODE='BZ314';
    END IF;
    DELETE FROM mailbox_address_claims WHERE normalized_address=lower(OLD.email) AND mailbox_id=OLD.mailbox_id;
    RETURN OLD;
  END IF;
  IF TG_OP='UPDATE' AND lower(OLD.email)<>lower(NEW.email) THEN
    DELETE FROM mailbox_address_claims WHERE normalized_address=lower(OLD.email) AND mailbox_id=OLD.mailbox_id;
  END IF;
  INSERT INTO mailbox_address_claims(normalized_address,mailbox_id,address_kind)
  VALUES(lower(NEW.email),NEW.mailbox_id,'alias')
  ON CONFLICT(normalized_address) DO UPDATE SET
    mailbox_id=EXCLUDED.mailbox_id,address_kind='alias',claim_state='active',released_at=NULL,
    generation=mailbox_address_claims.generation+1
  WHERE mailbox_address_claims.mailbox_id=EXCLUDED.mailbox_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'address is reserved by another mailbox' USING ERRCODE='BZ315'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER mailbox_lifecycle_alias_sync AFTER INSERT OR UPDATE OR DELETE ON public.aliases
FOR EACH ROW EXECUTE FUNCTION public.mailbox_lifecycle_alias_sync();

-- All lifecycle tables are worker-mutated and tenant-readable through their
-- mailbox. Admin reads use SECURITY DEFINER projections.
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY[
  'mailbox_lifecycle','mailbox_binding_history','mailbox_address_claims',
  'mailbox_lifecycle_operations','mailbox_lifecycle_effects','mailbox_lifecycle_effect_targets','mailbox_purge_requests',
  'mailbox_lifecycle_outbox'
] LOOP EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t);
       EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t); END LOOP; END $$;
CREATE POLICY mailbox_lifecycle_read ON public.mailbox_lifecycle FOR SELECT TO public
 USING(mailbox_id=NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint);
CREATE POLICY mailbox_binding_history_read ON public.mailbox_binding_history FOR SELECT TO public
 USING(mailbox_id=NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint);
CREATE POLICY mailbox_address_claims_read ON public.mailbox_address_claims FOR SELECT TO public
 USING(mailbox_id=NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint);
CREATE POLICY mailbox_lifecycle_operations_read ON public.mailbox_lifecycle_operations FOR SELECT TO public
 USING(mailbox_id=NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint);
CREATE POLICY mailbox_lifecycle_effects_read ON public.mailbox_lifecycle_effects FOR SELECT TO public
 USING(mailbox_id=NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint);
CREATE POLICY mailbox_lifecycle_effect_targets_read ON public.mailbox_lifecycle_effect_targets FOR SELECT TO public
 USING(EXISTS(SELECT 1 FROM mailbox_lifecycle_effects e
  WHERE e.operation_id=mailbox_lifecycle_effect_targets.operation_id
    AND e.effect_kind=mailbox_lifecycle_effect_targets.effect_kind
    AND e.mailbox_id=NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint));
CREATE POLICY mailbox_purge_requests_read ON public.mailbox_purge_requests FOR SELECT TO public
 USING(mailbox_id=NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint);
CREATE POLICY mailbox_lifecycle_outbox_read ON public.mailbox_lifecycle_outbox FOR SELECT TO public
 USING((payload->>'mailboxId')::bigint=NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint);

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (199, now()) ON CONFLICT (version) DO NOTHING;
