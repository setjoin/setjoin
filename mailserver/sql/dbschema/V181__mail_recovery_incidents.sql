-- V181: client-assisted mail recovery control and quarantine substrate.
-- The ingest feature remains seeded OFF by V178. All mailbox mutations are
-- reducer-only and quarantine bytes are never visible as ordinary mail.

INSERT INTO public.admin_permissions(permission_key,category,description,is_sensitive)
VALUES('system.recovery','System','Open and resolve bounded client-assisted mail recovery incidents',true)
ON CONFLICT(permission_key) DO NOTHING;

UPDATE public.admin_role_groups
   SET permissions=(SELECT array_agg(DISTINCT permission ORDER BY permission)
                      FROM unnest(permissions || ARRAY['system.recovery']) permission)
 WHERE id=1 AND NOT ('system.recovery'=ANY(permissions));

CREATE TABLE public.mail_recovery_incidents (
    id                       uuid PRIMARY KEY,
    installation_id          uuid NOT NULL,
    minimum_timeline         bigint NOT NULL CHECK(minimum_timeline>0),
    maximum_timeline         bigint NOT NULL CHECK(maximum_timeline>=minimum_timeline),
    status                   text NOT NULL DEFAULT 'open'
                             CHECK(status IN ('open','closed','expired')),
    reason                   text NOT NULL CHECK(length(reason) BETWEEN 8 AND 1024 AND reason !~ '[\r\n]'),
    opened_by                bigint NOT NULL REFERENCES public.users(id),
    step_up_binding          bytea NOT NULL CHECK(octet_length(step_up_binding)=32),
    approval_required        boolean NOT NULL DEFAULT false,
    approved_by              bigint REFERENCES public.users(id),
    approved_at              timestamptz,
    expires_at               timestamptz NOT NULL,
    idempotency_key          uuid NOT NULL,
    created_at               timestamptz NOT NULL DEFAULT statement_timestamp(),
    closed_at                timestamptz,
    closed_by                bigint REFERENCES public.users(id),
    close_reason             text CHECK(close_reason IS NULL OR (length(close_reason) BETWEEN 8 AND 1024 AND close_reason !~ '[\r\n]')),
    UNIQUE(opened_by,idempotency_key),
    CHECK(expires_at>created_at AND expires_at<=created_at+interval '7 days'),
    CHECK((approval_required AND approved_by IS NULL AND approved_at IS NULL) OR
          (approval_required AND approved_by IS NOT NULL AND approved_at IS NOT NULL) OR
          (NOT approval_required AND approved_by IS NULL AND approved_at IS NULL))
);

CREATE TABLE public.mail_recovery_incident_accounts (
    incident_id              uuid NOT NULL REFERENCES public.mail_recovery_incidents(id) ON DELETE CASCADE,
    mailbox_id               bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE RESTRICT,
    affected_user_id         bigint REFERENCES public.users(id) ON DELETE RESTRICT,
    evidence_token_sha256    bytea NOT NULL CHECK(octet_length(evidence_token_sha256)=32),
    PRIMARY KEY(incident_id,mailbox_id)
);

CREATE TABLE public.mail_recovery_upload_sessions (
    id                       uuid PRIMARY KEY,
    incident_id              uuid NOT NULL REFERENCES public.mail_recovery_incidents(id) ON DELETE CASCADE,
    mailbox_id               bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE RESTRICT,
    uploading_user_id        bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    device_id                uuid NOT NULL,
    artifact_identity        bytea NOT NULL CHECK(octet_length(artifact_identity)=32),
    lineage_sha256           bytea NOT NULL CHECK(octet_length(lineage_sha256)=32),
    raw_mime_sha256          bytea NOT NULL CHECK(octet_length(raw_mime_sha256)=32),
    eligibility              text NOT NULL CHECK(eligibility IN ('received','sent-terminal')),
    declared_size            bigint NOT NULL CHECK(declared_size BETWEEN 1 AND 52428800),
    total_declared_size      bigint NOT NULL CHECK(total_declared_size BETWEEN declared_size AND 8589934592),
    receipt                  jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object' AND octet_length(receipt::text)<=1048576),
    next_offset              bigint NOT NULL DEFAULT 0 CHECK(next_offset>=0 AND next_offset<=declared_size),
    status                   text NOT NULL DEFAULT 'uploading'
                             CHECK(status IN ('uploading','committing','quarantined','deduplicated','rejected','aborted','expired')),
    consented_at             timestamptz NOT NULL,
    expires_at               timestamptz NOT NULL,
    idempotency_key          uuid NOT NULL,
    created_at               timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at               timestamptz NOT NULL DEFAULT statement_timestamp(),
    terminal_reason          text CHECK(terminal_reason IS NULL OR octet_length(terminal_reason)<=256),
    UNIQUE(uploading_user_id,idempotency_key)
);
CREATE INDEX mail_recovery_sessions_incident_idx
    ON public.mail_recovery_upload_sessions(incident_id,status,expires_at);

CREATE TABLE public.mail_recovery_upload_items (
    session_id               uuid NOT NULL REFERENCES public.mail_recovery_upload_sessions(id) ON DELETE CASCADE,
    item_id                  text NOT NULL CHECK(octet_length(item_id) BETWEEN 1 AND 256 AND item_id !~ '[[:cntrl:]/]'),
    role                     text NOT NULL CHECK(role IN ('raw','attachment','inline')),
    sha256                   bytea NOT NULL CHECK(octet_length(sha256)=32),
    declared_size            bigint NOT NULL CHECK(declared_size BETWEEN 1 AND 8589934592),
    next_offset              bigint NOT NULL DEFAULT 0 CHECK(next_offset>=0 AND next_offset<=declared_size),
    status                   text NOT NULL DEFAULT 'uploading' CHECK(status IN ('uploading','verified','aborted')),
    object_ref               text CHECK(object_ref IS NULL OR object_ref~'^[0-9a-f]{64}$'),
    PRIMARY KEY(session_id,item_id),
    UNIQUE(session_id,role,sha256)
);

CREATE TABLE public.mail_recovery_upload_chunks (
    session_id               uuid NOT NULL REFERENCES public.mail_recovery_upload_sessions(id) ON DELETE CASCADE,
    item_id                  text NOT NULL,
    start_offset             bigint NOT NULL CHECK(start_offset>=0),
    size_bytes               integer NOT NULL CHECK(size_bytes BETWEEN 1 AND 262144),
    sha256                   bytea NOT NULL CHECK(octet_length(sha256)=32),
    object_key               text NOT NULL CHECK(object_key ~ '^recovery-quarantine/[0-9a-f-]{36}/[0-9a-f-]{36}/[0-9a-f]{64}/[0-9]+-[0-9a-f]{64}$'),
    created_at               timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY(session_id,item_id,start_offset),
    UNIQUE(object_key),
    FOREIGN KEY(session_id,item_id) REFERENCES public.mail_recovery_upload_items(session_id,item_id) ON DELETE CASCADE
);

CREATE TABLE public.mail_recovery_quarantine_artifacts (
    id                       uuid PRIMARY KEY,
    session_id               uuid NOT NULL UNIQUE REFERENCES public.mail_recovery_upload_sessions(id) ON DELETE RESTRICT,
    incident_id              uuid NOT NULL REFERENCES public.mail_recovery_incidents(id) ON DELETE CASCADE,
    mailbox_id               bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE RESTRICT,
    uploading_user_id        bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    device_id                uuid NOT NULL,
    artifact_identity        bytea NOT NULL CHECK(octet_length(artifact_identity)=32),
    lineage_sha256           bytea NOT NULL CHECK(octet_length(lineage_sha256)=32),
    raw_mime_sha256          bytea NOT NULL CHECK(octet_length(raw_mime_sha256)=32),
    raw_mime_size            bigint NOT NULL CHECK(raw_mime_size BETWEEN 1 AND 52428800),
    raw_ref                  text NOT NULL CHECK(raw_ref ~ '^[0-9a-f]{64}$'),
    receipt                  jsonb NOT NULL,
    signed_timeline          bigint NOT NULL CHECK(signed_timeline>0),
    signed_boot_epoch        uuid NOT NULL,
    parsed_headers           jsonb NOT NULL CHECK(jsonb_typeof(parsed_headers)='object' AND octet_length(parsed_headers::text)<=262144),
    blob_inventory           jsonb NOT NULL CHECK(jsonb_typeof(blob_inventory)='array' AND octet_length(blob_inventory::text)<=1048576),
    malware_status           text NOT NULL CHECK(malware_status IN ('clean','infected')),
    status                   text NOT NULL DEFAULT 'quarantined'
                             CHECK(status IN ('quarantined','fork_conflict','tampered','accepted','rejected','deduplicated')),
    rejection_reason         text CHECK(rejection_reason IS NULL OR octet_length(rejection_reason)<=256),
    fork_consented_by        bigint REFERENCES public.users(id) ON DELETE RESTRICT,
    fork_consented_at        timestamptz,
    created_at               timestamptz NOT NULL DEFAULT statement_timestamp(),
    terminal_at              timestamptz
);
CREATE INDEX mail_recovery_quarantine_incident_idx
    ON public.mail_recovery_quarantine_artifacts(incident_id,status,created_at);
CREATE INDEX mail_recovery_quarantine_lineage_idx
    ON public.mail_recovery_quarantine_artifacts(lineage_sha256,signed_timeline,signed_boot_epoch);

CREATE TABLE public.mail_recovery_ledger (
    artifact_identity        bytea PRIMARY KEY CHECK(octet_length(artifact_identity)=32),
    incident_id              uuid NOT NULL REFERENCES public.mail_recovery_incidents(id) ON DELETE RESTRICT,
    mailbox_id               bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE RESTRICT,
    quarantine_id            uuid NOT NULL UNIQUE REFERENCES public.mail_recovery_quarantine_artifacts(id) ON DELETE RESTRICT,
    outcome                  text NOT NULL CHECK(outcome IN ('accepted','rejected','deduplicated','tampered','fork_conflict')),
    recovered_message_id     bigint,
    recovered_received_at    timestamptz,
    recorded_at              timestamptz NOT NULL DEFAULT statement_timestamp()
);

-- Global control records are worker/reducer-only. Per-mailbox rows are readable
-- only by the active mailbox GUC; all writes remain worker/reducer-only.
ALTER TABLE public.mail_recovery_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mail_recovery_incidents FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_recovery_incidents_owner ON public.mail_recovery_incidents
  USING(current_user='setjoin_owner') WITH CHECK(current_user='setjoin_owner');

ALTER TABLE public.mail_recovery_incident_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mail_recovery_incident_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_recovery_incident_accounts_read ON public.mail_recovery_incident_accounts FOR SELECT
  USING(mailbox_id=(SELECT NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint));

ALTER TABLE public.mail_recovery_upload_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mail_recovery_upload_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_recovery_upload_sessions_read ON public.mail_recovery_upload_sessions FOR SELECT
  USING(mailbox_id=(SELECT NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint)
        AND uploading_user_id=(SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint));

ALTER TABLE public.mail_recovery_upload_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mail_recovery_upload_chunks FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_recovery_upload_chunks_owner ON public.mail_recovery_upload_chunks
  USING(current_user='setjoin_owner') WITH CHECK(current_user='setjoin_owner');

ALTER TABLE public.mail_recovery_upload_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mail_recovery_upload_items FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_recovery_upload_items_owner ON public.mail_recovery_upload_items
  USING(current_user='setjoin_owner') WITH CHECK(current_user='setjoin_owner');

ALTER TABLE public.mail_recovery_quarantine_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mail_recovery_quarantine_artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_recovery_quarantine_read ON public.mail_recovery_quarantine_artifacts FOR SELECT
  USING(mailbox_id=(SELECT NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint)
        AND uploading_user_id=(SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint));

ALTER TABLE public.mail_recovery_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mail_recovery_ledger FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_recovery_ledger_owner ON public.mail_recovery_ledger
  USING(current_user='setjoin_owner') WITH CHECK(current_user='setjoin_owner');

ALTER TABLE public.mail_recovery_incidents OWNER TO setjoin_owner;
ALTER TABLE public.mail_recovery_incident_accounts OWNER TO setjoin_owner;
ALTER TABLE public.mail_recovery_upload_sessions OWNER TO setjoin_owner;
ALTER TABLE public.mail_recovery_upload_chunks OWNER TO setjoin_owner;
ALTER TABLE public.mail_recovery_upload_items OWNER TO setjoin_owner;
ALTER TABLE public.mail_recovery_quarantine_artifacts OWNER TO setjoin_owner;
ALTER TABLE public.mail_recovery_ledger OWNER TO setjoin_owner;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (181, now())
ON CONFLICT(version) DO NOTHING;
