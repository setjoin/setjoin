//! Static typed SQL contract catalog for `setjoin-jmap` (Wave 1.8c, #546c).
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};

macro_rules! email_list_sql {
    ($direction:literal) => {
        concat!(
            "SELECT s.state, \
               (SELECT count(*) FROM messages m WHERE ",
            email_list_sql!(@where),
            ")::int8, \
               ARRAY(SELECT m.id FROM messages m WHERE ",
            email_list_sql!(@where),
            " ORDER BY m.pinned_at IS NOT NULL DESC, m.received_at ",
            $direction,
            ", m.id ",
            $direction,
            " LIMIT $6 OFFSET $5) \
             FROM (SELECT jmap_email_state::int8 AS state FROM mailboxes WHERE id = $1) s"
        )
    };
    (@where) => {
        "m.mailbox_id = $1 AND NOT m.is_deleted \
         AND EXISTS (SELECT 1 FROM message_tags mt \
                      WHERE mt.message_id = m.id AND mt.received_at = m.received_at AND mt.tag_id = $2) \
         AND (NOT EXISTS (SELECT 1 FROM tags t \
                           WHERE t.id = $2 AND t.mailbox_id = $1 AND t.exclusive_group = 'location') \
              OR NOT EXISTS (SELECT 1 FROM message_tags ms JOIN tags ts ON ts.id = ms.tag_id \
                              WHERE ms.message_id = m.id AND ms.received_at = m.received_at \
                                AND ts.mailbox_id = $1 AND ts.exclusive_group = 'snooze')) \
         AND ($3::text IS NULL OR ($3 = 'other') = EXISTS ( \
               SELECT 1 FROM message_tags mo JOIN tags o ON o.id = mo.tag_id \
                WHERE mo.message_id = m.id AND mo.received_at = m.received_at \
                  AND o.mailbox_id = $1 AND o.name = 'Other')) \
         AND ($4::bool IS NULL OR m.is_read = $4)"
    };
}

// ---- blob.rs ----

pub const BLOB_OWNED: SqlContract = SqlContract {
    id: "jmap.blob_owned",
    domain: "jmap",
    sql: "SELECT DISTINCT b.sha256,b.size_bytes,b.content_type FROM blobs b \
          JOIN message_attachments ma ON ma.blob_sha256=b.sha256 \
          JOIN messages m ON m.id=ma.message_id \
          JOIN mailboxes mb ON mb.id=m.mailbox_id \
          WHERE b.sha256=ANY($1) AND mb.user_id=$2",
    params: &[Type::TEXT_ARRAY, Type::INT8],
    columns: &[
        ColumnSpec::named("sha256", Type::TEXT),
        ColumnSpec::named("size_bytes", Type::INT8),
        ColumnSpec::named("content_type", Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- email_batch.rs ----

pub const EMAIL_RECOVER: SqlContract = SqlContract {
    id: "jmap.email_recover",
    domain: "jmap",
    sql: "SELECT jmap_email_recover($1, $2::bigint[])::text",
    params: &[Type::INT8, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EMAIL_PURGE: SqlContract = SqlContract {
    id: "jmap.email_purge",
    domain: "jmap",
    sql: "SELECT jmap_email_purge($1, $2::bigint[])::text",
    params: &[Type::INT8, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EMAIL_NUDGE_DISMISS: SqlContract = SqlContract {
    id: "jmap.email_nudge_dismiss",
    domain: "jmap",
    sql: "SELECT nudge_dismiss($1, $2::text)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EMAIL_DELETED_QUERY: SqlContract = SqlContract {
    id: "jmap.email_deleted_query",
    domain: "jmap",
    sql: "SELECT jmap_email_query_deleted($1, $2, $3)::text",
    params: &[Type::INT8, Type::INT4, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EMAIL_BUNDLES: SqlContract = SqlContract {
    id: "jmap.email_bundles",
    domain: "jmap",
    sql: "SELECT newsletter_bundles_list($1, $2, $3)::text",
    params: &[Type::INT8, Type::INT4, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EMAIL_NUDGES: SqlContract = SqlContract {
    id: "jmap.email_nudges",
    domain: "jmap",
    sql: "SELECT stale_thread_nudges_list($1, $2, $3)::text",
    params: &[Type::INT8, Type::INT4, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- email_changes.rs ----

pub const EMAIL_CHANGES: SqlContract = SqlContract {
    id: "jmap.email_changes",
    domain: "jmap",
    sql: "SELECT jmap_email_changes($1, $2, $3)::text",
    params: &[Type::INT8, Type::TEXT, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- email_get.rs ----

pub const EMAIL_GET: SqlContract = SqlContract {
    id: "jmap.email_get",
    domain: "jmap",
    sql: "WITH r AS MATERIALIZED (SELECT jmap_email_get($1, $3::bigint[], $4::text[]) AS res), \
          a AS (INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id) \
                SELECT $1, $2, 'email_get', NULL FROM r \
                RETURNING 1) \
          SELECT r.res::text, (SELECT count(*) FROM a)::int4 FROM r",
    params: &[Type::INT8, Type::INT8, Type::INT8_ARRAY, Type::TEXT_ARRAY],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::INT4),
    ],
    scope: SqlScope::MailboxAuditedRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- email_list.rs ----

pub const EMAIL_LIST_NEWEST: SqlContract = SqlContract {
    id: "jmap.email_list_newest",
    domain: "jmap",
    sql: email_list_sql!("DESC"),
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[
        ColumnSpec::named("state", Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8_ARRAY),
    ],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EMAIL_LIST_OLDEST: SqlContract = SqlContract {
    id: "jmap.email_list_oldest",
    domain: "jmap",
    sql: email_list_sql!("ASC"),
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[
        ColumnSpec::named("state", Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8_ARRAY),
    ],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- email_query.rs ----

pub const EMAIL_QUERY: SqlContract = SqlContract {
    id: "jmap.email_query",
    domain: "jmap",
    sql: "SELECT jmap_email_query($1, $2::text::jsonb, $3::text::jsonb, $4, $5)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::INT4, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- email_set.rs ----

pub const EMAIL_SET_UPDATE: SqlContract = SqlContract {
    id: "jmap.email_set_update",
    domain: "jmap",
    sql: "WITH audit AS ( \
            INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id, details) \
            VALUES ($1, $2, 'email_set', NULL, jsonb_build_object('operation', $3::text)) RETURNING 1) \
          SELECT r::text FROM jmap_email_set_update($1, $4::text::jsonb) AS r, audit",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EMAIL_SET_DESTROY: SqlContract = SqlContract {
    id: "jmap.email_set_destroy",
    domain: "jmap",
    sql: "WITH audit AS ( \
            INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id, details) \
            VALUES ($1, $2, 'email_set', NULL, jsonb_build_object('operation', $3::text)) RETURNING 1) \
          SELECT r::text FROM jmap_email_set_destroy($1, $4::bigint[]) AS r, audit",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EMAIL_SET_CREATE_PHASE: SqlContract = SqlContract {
    id: "jmap.email_set_create_phase",
    domain: "jmap",
    sql: "SELECT jmap_email_set_create($1, $2::text::jsonb)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EMAIL_SET_UPDATE_PHASE: SqlContract = SqlContract {
    id: "jmap.email_set_update_phase",
    domain: "jmap",
    sql: "SELECT jmap_email_set_update($1, $2::text::jsonb)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EMAIL_SET_DESTROY_PHASE: SqlContract = SqlContract {
    id: "jmap.email_set_destroy_phase",
    domain: "jmap",
    sql: "SELECT jmap_email_set_destroy($1, $2::bigint[])::text",
    params: &[Type::INT8, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EMAIL_SET_AUDIT: SqlContract = SqlContract {
    id: "jmap.email_set_audit",
    domain: "jmap",
    sql: "INSERT INTO mailbox_audit_log \
          (mailbox_id, actor_user_id, action, message_id, details) \
          VALUES ($1, $2, 'email_set', NULL, jsonb_build_object('operation', $3::text))",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EMAIL_SNOOZE: SqlContract = SqlContract {
    id: "jmap.email_snooze",
    domain: "jmap",
    sql: "SELECT message_snooze($1, $2, $3::text::timestamptz)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EMAIL_SET_OWNED_BLOBS: SqlContract = SqlContract {
    id: "jmap.email_set_owned_blobs",
    domain: "jmap",
    sql: "SELECT q.sha \
          FROM unnest($1::text[]) AS q(sha) \
          WHERE EXISTS ( \
              SELECT 1 FROM blob_user_charges bc \
              WHERE bc.blob_sha256 = q.sha AND bc.user_id = $2 \
          ) OR EXISTS ( \
              SELECT 1 FROM message_attachments ma \
              JOIN messages m ON m.id = ma.message_id \
              JOIN mailboxes mb ON mb.id = m.mailbox_id \
              WHERE ma.blob_sha256 = q.sha AND mb.user_id = $2 \
          )",
    params: &[Type::TEXT_ARRAY, Type::INT8],
    columns: &[ColumnSpec::named("sha", Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- http_blob.rs ----

pub const HTTP_BLOB_ACCOUNT_READ: SqlContract = SqlContract {
    id: "jmap.http_blob_account_read",
    domain: "jmap",
    sql: "SELECT EXISTS(SELECT 1 FROM mailbox_delegates WHERE mailbox_id=$1 AND user_id=$2 AND permission IN ('read','send_as','send_on_behalf','full_access'))",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const HTTP_BLOB_ACCOUNT_UPLOAD: SqlContract = SqlContract {
    id: "jmap.http_blob_account_upload",
    domain: "jmap",
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

pub const HTTP_BLOB_METADATA: SqlContract = SqlContract {
    id: "jmap.http_blob_metadata",
    domain: "jmap",
    sql: "SELECT size_bytes,COALESCE(content_type,'application/octet-stream') FROM blobs WHERE sha256=$1",
    params: &[Type::TEXT],
    columns: &[
        ColumnSpec::named("size_bytes", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const HTTP_BLOB_DOWNLOAD_ALLOWED: SqlContract = SqlContract {
    id: "jmap.http_blob_download_allowed",
    domain: "jmap",
    sql: "SELECT EXISTS(SELECT 1 FROM message_attachments ma JOIN messages m ON m.id=ma.message_id JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE ma.blob_sha256=$1 AND (mb.user_id=$2 OR mb.id=$3))",
    params: &[Type::TEXT, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const HTTP_BLOB_RECOVERY_CONTEXT: SqlContract = SqlContract {
    id: "jmap.http_blob_recovery_context",
    domain: "jmap",
    sql: "SELECT continuity_recovery_receipt_context($1,ARRAY[$2],$3::text::uuid)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxAuditedRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const HTTP_BLOB_RECOVERY_RECEIPT_CONTEXTS: SqlContract = SqlContract {
    id: "jmap.http_blob_recovery_receipt_contexts",
    domain: "jmap",
    sql: "SELECT continuity_recovery_receipt_context($1,$2,$3::text::uuid)::text",
    params: &[Type::INT8, Type::INT8_ARRAY, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxAuditedRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const HTTP_BLOB_TRANSFER_DEVICE: SqlContract = SqlContract {
    id: "jmap.http_blob_transfer_device",
    domain: "jmap",
    sql: "SELECT id FROM user_devices WHERE user_id=$1 AND fingerprint_hash=sha256($2::text::bytea) AND platform=$3 AND NOT wipe_requested ORDER BY id ASC LIMIT 1",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const HTTP_BLOB_TRANSFER_POLICY: SqlContract = SqlContract {
    id: "jmap.http_blob_transfer_policy",
    domain: "jmap",
    sql: "SELECT offline_effective_policy_snapshot($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- identity.rs ----

pub const IDENTITY_PRIMARY: SqlContract = SqlContract {
    id: "jmap.identity_primary",
    domain: "jmap",
    sql: "SELECT email::text,display_name::text,first_name::text,last_name::text,avatar_sha256::text FROM users WHERE id=$1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDENTITY_ALIASES: SqlContract = SqlContract {
    id: "jmap.identity_aliases",
    domain: "jmap",
    sql: "SELECT a.id,COALESCE(a.display_name,a.email)::text,a.email::text,a.signature::text,a.reply_to::text FROM aliases a JOIN mailboxes m ON m.id=a.mailbox_id WHERE m.user_id=$1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDENTITY_DELEGATED: SqlContract = SqlContract {
    id: "jmap.identity_delegated",
    domain: "jmap",
    sql: "SELECT mb.id,COALESCE(mb.display_name,mb.email)::text,mb.email::text FROM mailboxes mb JOIN mailbox_delegates md ON md.mailbox_id=mb.id WHERE md.user_id=$1 AND md.permission IN ('send_as','full_access') AND mb.user_id<>$1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDENTITY_STATE: SqlContract = SqlContract {
    id: "jmap.identity_state",
    domain: "jmap",
    sql: "SELECT floor(extract(epoch FROM updated_at))::bigint FROM users WHERE id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDENTITY_SET: SqlContract = SqlContract {
    id: "jmap.identity_set",
    domain: "jmap",
    sql: "SELECT jmap_identity_set_batch($1,$2::text::jsonb,$3::text::jsonb,$4)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- mailbox.rs ----

pub const MAILBOX_THREAD_GET: SqlContract = SqlContract {
    id: "jmap.mailbox_thread_get",
    domain: "jmap",
    sql: "SELECT jmap_thread_get($1,$2)::text",
    params: &[Type::INT8, Type::TEXT_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAILBOX_THREAD_CHANGES: SqlContract = SqlContract {
    id: "jmap.mailbox_thread_changes",
    domain: "jmap",
    sql: "SELECT jmap_thread_changes($1,$2)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAILBOX_SEARCH_SNIPPET: SqlContract = SqlContract {
    id: "jmap.mailbox_search_snippet",
    domain: "jmap",
    sql: "SELECT jmap_search_snippet_get($1,$2::text::jsonb,$3)::text",
    params: &[Type::INT8, Type::TEXT, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAILBOX_GET: SqlContract = SqlContract {
    id: "jmap.mailbox_get",
    domain: "jmap",
    sql: "SELECT jmap_mailbox_get($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8_ARRAY, Type::TEXT_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAILBOX_QUERY: SqlContract = SqlContract {
    id: "jmap.mailbox_query",
    domain: "jmap",
    sql: "SELECT jmap_mailbox_query($1,$2::text::jsonb,$3::text::jsonb,$4,$5)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::INT4, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAILBOX_CHANGES: SqlContract = SqlContract {
    id: "jmap.mailbox_changes",
    domain: "jmap",
    sql: "SELECT jmap_mailbox_changes($1,$2)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAILBOX_QUERY_CHANGES: SqlContract = SqlContract {
    id: "jmap.mailbox_query_changes",
    domain: "jmap",
    sql: "SELECT jmap_mailbox_query_changes($1,$2::text::jsonb,$3::text::jsonb,$4)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- mailbox_set.rs ----

pub const MAILBOX_SET: SqlContract = SqlContract {
    id: "jmap.mailbox_set",
    domain: "jmap",
    sql: "SELECT jmap_mailbox_set_batch($1,$2::text::jsonb,$3::text::jsonb,$4)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- messages.rs ----

pub const MESSAGES_OWNED_MESSAGE: SqlContract = SqlContract {
    id: "jmap.messages_owned_message",
    domain: "jmap",
    sql: "SELECT m.raw_ref, m.mailbox_id, COALESCE(m.subject, 'message') FROM messages m \
          JOIN mailboxes mb ON mb.id = m.mailbox_id WHERE m.id = $1 AND mb.user_id = $2",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("raw_ref", Type::TEXT),
        ColumnSpec::named("mailbox_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MESSAGES_SET_FOCUS: SqlContract = SqlContract {
    id: "jmap.messages_set_focus",
    domain: "jmap",
    sql: "SELECT set_message_focus(m.id, m.received_at, $4::bool, m.mailbox_id)::text FROM messages m \
          JOIN mailboxes mb ON mb.id = m.mailbox_id \
          WHERE m.id = $3::bigint AND mb.user_id = $2::bigint AND m.mailbox_id = $1::bigint",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MESSAGES_ZIP_SOURCE: SqlContract = SqlContract {
    id: "jmap.messages_zip_source",
    domain: "jmap",
    sql: "SELECT ma.blob_sha256, COALESCE(ma.filename, 'attachment'), m.subject \
            FROM message_attachments ma \
            JOIN messages m   ON m.id = ma.message_id AND m.received_at = ma.received_at \
            JOIN mailboxes mb ON mb.id = m.mailbox_id \
           WHERE m.id = $1 AND mb.user_id = $2 AND ma.disposition <> 'inline' \
           ORDER BY ma.id",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("blob_sha256", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("subject", Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MESSAGES_UNSUBSCRIBE_SOURCE: SqlContract = SqlContract {
    id: "jmap.messages_unsubscribe_source",
    domain: "jmap",
    sql: "SELECT COALESCE(m.list_unsubscribe, ''), COALESCE(m.from_addr, '') FROM messages m \
          JOIN mailboxes mb ON mb.id = m.mailbox_id WHERE m.id = $1::text::bigint AND mb.user_id = $2",
    params: &[Type::TEXT, Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MESSAGES_RECORD_UNSUBSCRIBE: SqlContract = SqlContract {
    id: "jmap.messages_record_unsubscribe",
    domain: "jmap",
    sql: "SELECT rust_jmap_unsubscribe_record($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- push_state.rs ----

pub const PUSH_STATE_MAIL: SqlContract = SqlContract {
    id: "jmap.push_state_mail",
    domain: "jmap",
    sql: "SELECT jmap_email_state::int8,jmap_mailbox_state::int8,jmap_thread_state::int8 FROM mailboxes WHERE id=$1 AND user_id=$2",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_STATE_CALENDARS: SqlContract = SqlContract {
    id: "jmap.push_state_calendars",
    domain: "jmap",
    sql: "SELECT coalesce(max(jmap_state),0)::int8 FROM calendars WHERE mailbox_id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_STATE_ADDRESSBOOKS: SqlContract = SqlContract {
    id: "jmap.push_state_addressbooks",
    domain: "jmap",
    sql: "SELECT coalesce(max(jmap_state),0)::int8 FROM addressbooks WHERE mailbox_id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_STATE_TASKS: SqlContract = SqlContract {
    id: "jmap.push_state_tasks",
    domain: "jmap",
    sql: "SELECT coalesce(max(jmap_state),0)::int8 FROM tasks WHERE mailbox_id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- session.rs ----

pub const SESSION_DELEGATED: SqlContract = SqlContract {
    id: "jmap.session_delegated",
    domain: "jmap",
    sql: "SELECT * FROM (WITH delegated AS (SELECT md.mailbox_id,array_agg(DISTINCT md.permission::text ORDER BY md.permission::text) AS grants FROM mailbox_delegates md WHERE md.user_id=$1 AND md.permission IN ('read','send_as','send_on_behalf','full_access') AND md.mailbox_id<>$2 GROUP BY md.mailbox_id) SELECT d.mailbox_id,mb.email::text,d.grants,CASE WHEN d.grants && ARRAY['send_as','full_access']::text[] THEN ARRAY(SELECT a.email::text FROM aliases a WHERE a.mailbox_id=d.mailbox_id AND lower(a.email)<>lower(mb.email) ORDER BY lower(a.email),a.id) ELSE ARRAY[]::text[] END FROM delegated d JOIN mailboxes mb ON mb.id=d.mailbox_id WHERE mb.enabled=TRUE ORDER BY lower(mb.email),d.mailbox_id) AS owned_delegates",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("mailbox_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("grants", Type::TEXT_ARRAY),
        ColumnSpec::unnamed(Type::TEXT_ARRAY),
    ],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_EFFECTIVE_CAPS: SqlContract = SqlContract {
    id: "jmap.session_effective_caps",
    domain: "jmap",
    sql: "SELECT effective_capabilities($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_PURGE_DAYS: SqlContract = SqlContract {
    id: "jmap.session_purge_days",
    domain: "jmap",
    sql: "SELECT COALESCE(mb.deleted_purge_days,COALESCE(NULLIF((SELECT value #>> '{}' FROM system_config WHERE key='deleted_items_purge_days'),'0')::int,30),30), \
          COALESCE(mb.spam_purge_days,COALESCE(NULLIF((SELECT value #>> '{}' FROM system_config WHERE key='spam_purge_days'),'0')::int,30),30) \
          FROM mailboxes mb WHERE mb.id=$1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::INT4),
        ColumnSpec::unnamed(Type::INT4),
    ],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_BRANDING: SqlContract = SqlContract {
    id: "jmap.session_branding",
    domain: "jmap",
    sql: "SELECT COALESCE((SELECT value #>> '{}' FROM system_config WHERE key='brand_name'),'SetJoin'),COALESCE((SELECT value #>> '{}' FROM system_config WHERE key='brand_logo_url'),'')",
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_HELP_EMAIL: SqlContract = SqlContract {
    id: "jmap.session_help_email",
    domain: "jmap",
    sql: "SELECT COALESCE((SELECT value #>> '{}' FROM system_config WHERE key='help_email'),'')",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_APPS_CAPS_STRICT: SqlContract = SqlContract {
    id: "jmap.session_apps_caps_strict",
    domain: "jmap",
    sql: "SELECT COALESCE((SELECT lower(value #>> '{}') FROM system_config WHERE key='apps_caps_strict'),'') IN ('1','true')",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_FEATURE_TOGGLES: SqlContract = SqlContract {
    id: "jmap.session_feature_toggles",
    domain: "jmap",
    sql: "SELECT key,enabled FROM feature_toggles WHERE key=ANY($1::text[])",
    params: &[Type::TEXT_ARRAY],
    columns: &[
        ColumnSpec::named("key", Type::TEXT),
        ColumnSpec::named("enabled", Type::BOOL),
    ],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_SOD_CLASS: SqlContract = SqlContract {
    id: "jmap.session_sod_class",
    domain: "jmap",
    sql: "SELECT DISTINCT rg.sod_class::text FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND rg.sod_class IS NOT NULL",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_REGISTER_DEVICE: SqlContract = SqlContract {
    id: "jmap.session_register_device",
    domain: "jmap",
    sql: "SELECT jmap_session_device_register($1,$2,$3)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_DEVICE_CAPS: SqlContract = SqlContract {
    id: "jmap.session_device_caps",
    domain: "jmap",
    sql: "SELECT effective_capabilities($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_PERMISSIONS: SqlContract = SqlContract {
    id: "jmap.session_permissions",
    domain: "jmap",
    sql: "SELECT rg.permissions FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("permissions", Type::TEXT_ARRAY)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- set_seen.rs ----

pub const SET_SEEN: SqlContract = SqlContract {
    id: "jmap.set_seen",
    domain: "jmap",
    sql: "WITH audit AS ( \
            INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id, details) \
            VALUES ($1, $2, 'email_set', NULL, jsonb_build_object('operation', $3::text)) RETURNING 1) \
          SELECT (r->>'oldState')::bigint, (r->>'newState')::bigint, \
            r->'updated' @> jsonb_build_array($4::bigint), \
            r->'notUpdated'->($4::bigint::text)->>'type', \
            (r->'notUpdated'->($4::bigint::text))::text \
          FROM jmap_email_set_update($1, jsonb_build_object($4::bigint::text, \
            jsonb_build_object('keywords', jsonb_build_object('$seen', $5::text::jsonb)))) AS r, audit",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SET_SEEN_LOOKUP_LOCK: SqlContract = SqlContract {
    id: "jmap.set_seen_lookup_lock",
    domain: "jmap",
    sql: "SELECT 1::int4 FROM (SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))) AS l",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SET_SEEN_LOOKUP: SqlContract = SqlContract {
    id: "jmap.set_seen_lookup",
    domain: "jmap",
    sql: "SELECT EXISTS (SELECT 1 FROM mailbox_audit_log \
          WHERE mailbox_id = $1 AND actor_user_id = $2 AND action = 'email_set' \
          AND details->>'operation' = $3)",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- submission.rs ----

pub const SUBMISSION_GET: SqlContract = SqlContract {
    id: "jmap.submission_get",
    domain: "jmap",
    sql: "SELECT jmap_email_submission_get($1,$2::bigint[])::text",
    params: &[Type::INT8, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMISSION_QUERY: SqlContract = SqlContract {
    id: "jmap.submission_query",
    domain: "jmap",
    sql: "SELECT jmap_email_submission_query($1,$2::text::jsonb,$3,$4)::text",
    params: &[Type::INT8, Type::TEXT, Type::INT4, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMISSION_CANCEL: SqlContract = SqlContract {
    id: "jmap.submission_cancel",
    domain: "jmap",
    sql: "SELECT message_cancel($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMISSION_SET: SqlContract = SqlContract {
    id: "jmap.submission_set",
    domain: "jmap",
    sql: "SELECT jmap_email_submission_set($1,$2,$3::text::jsonb,$4::text::jsonb,$5::text::jsonb)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMISSION_LOCK_DRAFT: SqlContract = SqlContract {
    id: "jmap.submission_lock_draft",
    domain: "jmap",
    sql: "SELECT raw_ref, size_bytes FROM messages WHERE id = $1 AND mailbox_id = $2 FOR UPDATE",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("raw_ref", Type::TEXT),
        ColumnSpec::named("size_bytes", Type::INT8),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMISSION_UPDATE_DRAFT_SIZE: SqlContract = SqlContract {
    id: "jmap.submission_update_draft_size",
    domain: "jmap",
    sql: "UPDATE messages SET size_bytes = $1 WHERE id = $2 AND mailbox_id = $3",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMISSION_SET_WITH_NOT_CREATED: SqlContract = SqlContract {
    id: "jmap.submission_set_with_not_created",
    domain: "jmap",
    sql: "SELECT r.res::text, ARRAY(SELECT jsonb_object_keys(COALESCE(r.res->'notCreated', '{}'::jsonb))) \
          FROM (SELECT jmap_email_submission_set($1,$2,$3::text::jsonb,$4::text::jsonb,$5::text::jsonb) AS res) r",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT_ARRAY),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMISSION_RESTORE_DRAFT_SIZE: SqlContract = SqlContract {
    id: "jmap.submission_restore_draft_size",
    domain: "jmap",
    sql: "UPDATE messages SET size_bytes = $1 WHERE id = $2 AND mailbox_id = $3 AND raw_ref = $4",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMISSION_UNDO: SqlContract = SqlContract {
    id: "jmap.submission_undo",
    domain: "jmap",
    sql: "SELECT undo_send($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMISSION_RECALL_SOURCE: SqlContract = SqlContract {
    id: "jmap.submission_recall_source",
    domain: "jmap",
    sql: "SELECT m.from_addr,m.received_at,m.mailbox_id,m.message_id FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.id=$1 AND mb.user_id=$2",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("from_addr", Type::TEXT),
        ColumnSpec::named("received_at", Type::TIMESTAMPTZ),
        ColumnSpec::named("mailbox_id", Type::INT8),
        ColumnSpec::named("message_id", Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMISSION_SENDER_ALIAS: SqlContract = SqlContract {
    id: "jmap.submission_sender_alias",
    domain: "jmap",
    sql: "SELECT EXISTS(SELECT 1 FROM aliases a JOIN mailboxes mb ON mb.id=a.mailbox_id WHERE mb.user_id=$1 AND a.email=$2)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMISSION_RECALL: SqlContract = SqlContract {
    id: "jmap.submission_recall",
    domain: "jmap",
    sql: "SELECT recall_message($1,$2,$3,'user')::text",
    params: &[Type::TEXT, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMISSION_PRELOCK_USER: SqlContract = SqlContract {
    id: "jmap.submission_prelock_user",
    domain: "jmap",
    sql: "SELECT u.id FROM public.users u JOIN public.mailboxes m ON m.user_id = u.id WHERE m.id = $1 FOR KEY SHARE OF u",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMISSION_PRELOCK_MAILBOX: SqlContract = SqlContract {
    id: "jmap.submission_prelock_mailbox",
    domain: "jmap",
    sql: "SELECT id FROM public.mailboxes WHERE id = $1 FOR UPDATE",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMISSION_HAS_ATTACHMENTS: SqlContract = SqlContract {
    id: "jmap.submission_has_attachments",
    domain: "jmap",
    sql: "SELECT EXISTS(SELECT 1 FROM messages WHERE mailbox_id=$1 AND id=ANY($2::bigint[]) AND has_attachments)",
    params: &[Type::INT8, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    BLOB_OWNED,
    EMAIL_RECOVER,
    EMAIL_PURGE,
    EMAIL_NUDGE_DISMISS,
    EMAIL_DELETED_QUERY,
    EMAIL_BUNDLES,
    EMAIL_NUDGES,
    EMAIL_CHANGES,
    EMAIL_GET,
    EMAIL_LIST_NEWEST,
    EMAIL_LIST_OLDEST,
    EMAIL_QUERY,
    EMAIL_SET_UPDATE,
    EMAIL_SET_DESTROY,
    EMAIL_SET_CREATE_PHASE,
    EMAIL_SET_UPDATE_PHASE,
    EMAIL_SET_DESTROY_PHASE,
    EMAIL_SET_AUDIT,
    EMAIL_SNOOZE,
    EMAIL_SET_OWNED_BLOBS,
    HTTP_BLOB_ACCOUNT_READ,
    HTTP_BLOB_ACCOUNT_UPLOAD,
    HTTP_BLOB_METADATA,
    HTTP_BLOB_DOWNLOAD_ALLOWED,
    HTTP_BLOB_RECOVERY_CONTEXT,
    HTTP_BLOB_RECOVERY_RECEIPT_CONTEXTS,
    HTTP_BLOB_TRANSFER_DEVICE,
    HTTP_BLOB_TRANSFER_POLICY,
    IDENTITY_PRIMARY,
    IDENTITY_ALIASES,
    IDENTITY_DELEGATED,
    IDENTITY_STATE,
    IDENTITY_SET,
    MAILBOX_THREAD_GET,
    MAILBOX_THREAD_CHANGES,
    MAILBOX_SEARCH_SNIPPET,
    MAILBOX_GET,
    MAILBOX_QUERY,
    MAILBOX_CHANGES,
    MAILBOX_QUERY_CHANGES,
    MAILBOX_SET,
    MESSAGES_OWNED_MESSAGE,
    MESSAGES_SET_FOCUS,
    MESSAGES_ZIP_SOURCE,
    MESSAGES_UNSUBSCRIBE_SOURCE,
    MESSAGES_RECORD_UNSUBSCRIBE,
    PUSH_STATE_MAIL,
    PUSH_STATE_CALENDARS,
    PUSH_STATE_ADDRESSBOOKS,
    PUSH_STATE_TASKS,
    SESSION_DELEGATED,
    SESSION_EFFECTIVE_CAPS,
    SESSION_PURGE_DAYS,
    SESSION_BRANDING,
    SESSION_HELP_EMAIL,
    SESSION_APPS_CAPS_STRICT,
    SESSION_FEATURE_TOGGLES,
    SESSION_SOD_CLASS,
    SESSION_REGISTER_DEVICE,
    SESSION_DEVICE_CAPS,
    SESSION_PERMISSIONS,
    SET_SEEN,
    SET_SEEN_LOOKUP_LOCK,
    SET_SEEN_LOOKUP,
    SUBMISSION_GET,
    SUBMISSION_QUERY,
    SUBMISSION_CANCEL,
    SUBMISSION_SET,
    SUBMISSION_PRELOCK_USER,
    SUBMISSION_PRELOCK_MAILBOX,
    SUBMISSION_LOCK_DRAFT,
    SUBMISSION_UPDATE_DRAFT_SIZE,
    SUBMISSION_SET_WITH_NOT_CREATED,
    SUBMISSION_RESTORE_DRAFT_SIZE,
    SUBMISSION_UNDO,
    SUBMISSION_RECALL_SOURCE,
    SUBMISSION_SENDER_ALIAS,
    SUBMISSION_RECALL,
    SUBMISSION_HAS_ATTACHMENTS,
];
