//! Static typed SQL contract catalog for `setjoin-blobs` (F16).
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};

pub const ABORT_UPLOAD: SqlContract = SqlContract {
    id: "blobs.abort_upload",
    domain: "blobs",
    sql: "SELECT mail_recovery_upload_abort($1,$2::text::uuid)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FORK_CONSENT: SqlContract = SqlContract {
    id: "blobs.fork_consent",
    domain: "blobs",
    sql: "SELECT mail_recovery_fork_consent($1,$2::text::uuid,$3::text::uuid)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UPLOAD_ITEM: SqlContract = SqlContract {
    id: "blobs.upload_item",
    domain: "blobs",
    sql: "SELECT s.incident_id::text,i.next_offset,i.declared_size,(s.status='uploading' AND i.status='uploading' AND s.expires_at>clock_timestamp()) FROM mail_recovery_upload_sessions s JOIN mail_recovery_upload_items i ON i.session_id=s.id WHERE s.id=$1::text::uuid AND s.uploading_user_id=$2 AND i.item_id=$3",
    params: &[Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("next_offset", Type::INT8),
        ColumnSpec::named("declared_size", Type::INT8),
        ColumnSpec::unnamed(Type::BOOL),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHUNK_AT: SqlContract = SqlContract {
    id: "blobs.chunk_at",
    domain: "blobs",
    sql: "SELECT c.size_bytes,encode(c.sha256,'hex'),c.object_key FROM mail_recovery_upload_chunks c JOIN mail_recovery_upload_sessions s ON s.id=c.session_id WHERE c.session_id=$1::text::uuid AND s.uploading_user_id=$2 AND c.item_id=$3 AND c.start_offset=$4",
    params: &[Type::TEXT, Type::INT8, Type::TEXT, Type::INT8],
    columns: &[
        ColumnSpec::named("size_bytes", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("object_key", Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RECORD_CHUNK: SqlContract = SqlContract {
    id: "blobs.record_chunk",
    domain: "blobs",
    sql: "SELECT mail_recovery_upload_chunk_record($1,$2::text::uuid,$3,$4,$5,$6,$7)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::INT4,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_INCIDENTS: SqlContract = SqlContract {
    id: "blobs.user_incidents",
    domain: "blobs",
    sql: "SELECT mail_recovery_user_incident_list($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BLOB_OWNED: SqlContract = SqlContract {
    id: "blobs.blob_owned",
    domain: "blobs",
    sql: "SELECT EXISTS (SELECT 1 FROM message_attachments ma \
         JOIN messages m ON m.id=ma.message_id AND m.received_at=ma.received_at \
         JOIN mailboxes mb ON mb.id=m.mailbox_id \
         WHERE ma.blob_sha256=$1 AND mb.user_id=$2) \
         OR EXISTS (SELECT 1 FROM hr_expense_receipts her \
         JOIN approval_requests ar ON ar.id=her.approval_request_id \
         WHERE her.blob_sha256=$1 AND (ar.requester_user_id=$2 \
         OR (ar.approver_kind='user' AND ar.approver_ref=$2) \
         OR (ar.approver_kind='role_group' AND EXISTS(SELECT 1 FROM admin_role_assignments ara \
             WHERE ara.role_group_id=ar.approver_ref AND ara.user_id=$2 \
             AND (ara.expires_at IS NULL OR ara.expires_at>now()) \
             AND admin_assignment_active(ara.eligible,ara.activated_until))) \
         OR EXISTS(SELECT 1 FROM admin_role_assignments sa \
             WHERE sa.role_group_id=1 AND sa.user_id=$2 \
             AND (sa.expires_at IS NULL OR sa.expires_at>now()) \
             AND admin_assignment_active(sa.eligible,sa.activated_until))))",
    params: &[Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ITEM_FOR_COMMIT: SqlContract = SqlContract {
    id: "blobs.item_for_commit",
    domain: "blobs",
    sql: "SELECT encode(i.sha256,'hex'),i.declared_size,i.role,i.status,COALESCE(i.object_ref,'') FROM mail_recovery_upload_sessions s JOIN mail_recovery_upload_items i ON i.session_id=s.id WHERE s.id=$1::text::uuid AND s.uploading_user_id=$2 AND i.item_id=$3 AND s.status IN ('uploading','quarantined')",
    params: &[Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("declared_size", Type::INT8),
        ColumnSpec::named("role", Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ITEM_CHUNKS: SqlContract = SqlContract {
    id: "blobs.item_chunks",
    domain: "blobs",
    sql: "SELECT c.start_offset,c.size_bytes,encode(c.sha256,'hex'),c.object_key FROM mail_recovery_upload_chunks c JOIN mail_recovery_upload_sessions s ON s.id=c.session_id WHERE c.session_id=$1::text::uuid AND s.uploading_user_id=$2 AND c.item_id=$3 ORDER BY c.start_offset",
    params: &[Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[
        ColumnSpec::named("start_offset", Type::INT8),
        ColumnSpec::named("size_bytes", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("object_key", Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VERIFY_ITEM: SqlContract = SqlContract {
    id: "blobs.verify_item",
    domain: "blobs",
    sql: "SELECT mail_recovery_upload_item_verify($1,$2::text::uuid,$3,$4)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACCOUNT_UPLOAD: SqlContract = SqlContract {
    id: "blobs.account_upload",
    domain: "blobs",
    sql: "SELECT blob_upload_account($1,$2,$3,$4,$5,$6,$7)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::INT4,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ATTACHMENT_METADATA: SqlContract = SqlContract {
    id: "blobs.attachment_metadata",
    domain: "blobs",
    sql: "SELECT b.size_bytes,COALESCE(b.content_type,'application/octet-stream') FROM blobs b WHERE b.sha256=$1 AND b.size_bytes BETWEEN 0 AND 8589934592 AND EXISTS(SELECT 1 FROM message_attachments ma JOIN messages m ON m.id=ma.message_id JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE ma.blob_sha256=b.sha256 AND (mb.user_id=$2 OR mb.id=$3))",
    params: &[Type::TEXT, Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("size_bytes", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BEGIN_UPLOAD: SqlContract = SqlContract {
    id: "blobs.begin_upload",
    domain: "blobs",
    sql: "SELECT mail_recovery_upload_begin($1,$2::text::uuid,$3::text::uuid,$4,$5::text::uuid,$6,$7,$8::text::jsonb,$9::text::jsonb,$10::text::timestamptz,$11::text::uuid)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FINALIZE_ITEM: SqlContract = SqlContract {
    id: "blobs.finalize_item",
    domain: "blobs",
    sql: "SELECT i.object_ref,i.declared_size,s.eligibility,s.status FROM mail_recovery_upload_sessions s JOIN mail_recovery_upload_items i ON i.session_id=s.id AND i.role='raw' WHERE s.id=$1::text::uuid AND s.uploading_user_id=$2",
    params: &[Type::TEXT, Type::INT8],
    columns: &[
        ColumnSpec::named("object_ref", Type::TEXT),
        ColumnSpec::named("declared_size", Type::INT8),
        ColumnSpec::named("eligibility", Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REPLAY_FINALIZE: SqlContract = SqlContract {
    id: "blobs.replay_finalize",
    domain: "blobs",
    sql: "SELECT jsonb_build_object('id',id,'status',status,'replayed',true)::text FROM (SELECT a.id,a.status FROM mail_recovery_quarantine_artifacts a JOIN mail_recovery_upload_sessions s ON s.id=a.session_id WHERE s.id=$1::text::uuid AND s.uploading_user_id=$2 UNION ALL SELECT l.quarantine_id,CASE WHEN s.status='deduplicated' THEN 'deduplicated' ELSE l.outcome END FROM mail_recovery_upload_sessions s JOIN mail_recovery_ledger l ON l.artifact_identity=s.artifact_identity WHERE s.id=$1::text::uuid AND s.uploading_user_id=$2 AND s.status='deduplicated') replay LIMIT 1",
    params: &[Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUARANTINE: SqlContract = SqlContract {
    id: "blobs.quarantine",
    domain: "blobs",
    sql: "SELECT mail_recovery_artifact_quarantine($1,$2::text::uuid,$3::text::uuid,$4::text::jsonb,$5,$6)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    ABORT_UPLOAD,
    FORK_CONSENT,
    UPLOAD_ITEM,
    CHUNK_AT,
    RECORD_CHUNK,
    USER_INCIDENTS,
    BLOB_OWNED,
    ITEM_FOR_COMMIT,
    ITEM_CHUNKS,
    VERIFY_ITEM,
    ACCOUNT_UPLOAD,
    ATTACHMENT_METADATA,
    BEGIN_UPLOAD,
    FINALIZE_ITEM,
    REPLAY_FINALIZE,
    QUARANTINE,
];
