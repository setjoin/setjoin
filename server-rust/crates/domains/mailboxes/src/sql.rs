//! Static typed SQL contract catalog for `setjoin-mailboxes` (F05).
use setjoin_sql_catalog::{
    pg_rfc3339, ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type,
};

macro_rules! mailboxes_select {
    () => {
        concat!(
            "SELECT m.id, m.user_id, COALESCE(u.email, ''), m.email, m.display_name, ",
            "mailbox_effective_type(m.id)::text, m.is_primary, m.quota_bytes, m.used_bytes, ",
            "m.enabled, ",
            pg_rfc3339!("m.created_at"),
            ", d.name FROM mailboxes m LEFT JOIN users u ON u.id = m.user_id ",
            "JOIN domains d ON d.id = m.domain_id"
        )
    };
}

macro_rules! migration_job_select {
    () => {
        "SELECT id, user_id, source_type, status, conflict_strategy, progress::text, error_log::text, \
         to_char(started_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
         to_char(completed_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
         to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
         FROM migration_jobs"
    };
}

const MAILBOX_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::named("user_id", Type::INT8),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("email", Type::TEXT),
    ColumnSpec::named("display_name", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("is_primary", Type::BOOL),
    ColumnSpec::named("quota_bytes", Type::INT8),
    ColumnSpec::named("used_bytes", Type::INT8),
    ColumnSpec::named("enabled", Type::BOOL),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("name", Type::TEXT),
];

const MIGRATION_JOB_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::named("user_id", Type::INT8),
    ColumnSpec::named("source_type", Type::TEXT),
    ColumnSpec::named("status", Type::TEXT),
    ColumnSpec::named("conflict_strategy", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
];

const EXCHANGE_CONTEXT_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("project_id", Type::INT8),
    ColumnSpec::named("domain_id", Type::INT8),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("generation", Type::INT8),
    ColumnSpec::unnamed(Type::TEXT),
];

// ---- lib.rs ----

pub const CONSOLE_DENIED: SqlContract = SqlContract {
    id: "mailboxes.console_denied",
    domain: "mailboxes",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- mailboxes.rs ----

pub const MAILBOXES_LIST: SqlContract = SqlContract {
    id: "mailboxes.list",
    domain: "mailboxes",
    sql: concat!(
        mailboxes_select!(),
        " WHERE ($1::bigint <= 0 OR d.id = $1) \
         AND ($2::bigint IS NULL OR m.user_id = $2) \
         AND ($3::text IS NULL OR u.email ILIKE $3 OR m.display_name ILIKE $3 OR m.email ILIKE $3) \
         ORDER BY m.id DESC LIMIT $4 OFFSET $5"
    ),
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::INT8, Type::INT8],
    columns: MAILBOX_COLUMNS,
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAILBOX_GET: SqlContract = SqlContract {
    id: "mailboxes.get",
    domain: "mailboxes",
    sql: concat!(
        mailboxes_select!(),
        " WHERE m.id = $1 AND ($2::bigint = 0 OR d.id = $2)"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: MAILBOX_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAILBOX_DOMAIN_OF: SqlContract = SqlContract {
    id: "mailboxes.domain_of",
    domain: "mailboxes",
    sql: "SELECT domain_id FROM mailboxes WHERE id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("domain_id", Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAILBOX_FOLDERS: SqlContract = SqlContract {
    id: "mailboxes.folders",
    domain: "mailboxes",
    sql: "SELECT f.id, f.mailbox_id, f.name, f.role, f.path, \
         COALESCE(t.total_count, 0)::bigint, COALESCE(t.unread_count, 0)::bigint \
         FROM folders f LEFT JOIN tags t ON t.mailbox_id = f.mailbox_id AND t.name = f.name \
         WHERE f.mailbox_id = $1 ORDER BY f.path",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("mailbox_id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("role", Type::TEXT),
        ColumnSpec::named("path", Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IS_GUEST_ACCOUNT: SqlContract = SqlContract {
    id: "mailboxes.is_guest_account",
    domain: "mailboxes",
    sql: "SELECT is_guest_account($1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_DOMAIN: SqlContract = SqlContract {
    id: "mailboxes.user_domain",
    domain: "mailboxes",
    sql: "SELECT domain_id FROM users WHERE id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("domain_id", Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAILBOX_CREATE: SqlContract = SqlContract {
    id: "mailboxes.create",
    domain: "mailboxes",
    sql: "INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary, quota_bytes) \
         SELECT u.id, u.domain_id, $2, $3, 'personal', FALSE, $4::bigint FROM users u \
         WHERE u.id = $1 AND ($5::bigint = 0 OR u.domain_id = $5) RETURNING id",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAILBOX_UPDATE: SqlContract = SqlContract {
    id: "mailboxes.update",
    domain: "mailboxes",
    sql: "WITH u AS (UPDATE mailboxes SET display_name = COALESCE($3::text, display_name), \
         quota_bytes = COALESCE($4::bigint, quota_bytes), enabled = COALESCE($5::boolean, enabled), \
         litigation_hold = COALESCE($6::boolean, litigation_hold), deleted_purge_days = $7::integer, \
         spam_purge_days = $8::integer, updated_at = now() \
         WHERE id = $1 AND ($2::bigint = 0 OR domain_id = $2) RETURNING 1) SELECT count(*)::bigint FROM u",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::BOOL,
        Type::BOOL,
        Type::INT4,
        Type::INT4,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LIFECYCLE_ENABLED: SqlContract = SqlContract {
    id: "mailboxes.lifecycle_enabled",
    domain: "mailboxes",
    sql: "SELECT mailbox_lifecycle_enabled()",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAILBOX_DELETE: SqlContract = SqlContract {
    id: "mailboxes.delete",
    domain: "mailboxes",
    sql: "SELECT rust_admin_mailbox_delete($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FOLDER_CREATE: SqlContract = SqlContract {
    id: "mailboxes.folder_create",
    domain: "mailboxes",
    sql: "SELECT rust_admin_folder_create($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FOLDER_UPDATE: SqlContract = SqlContract {
    id: "mailboxes.folder_update",
    domain: "mailboxes",
    sql: "SELECT rust_admin_folder_update($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FOLDER_DELETE: SqlContract = SqlContract {
    id: "mailboxes.folder_delete",
    domain: "mailboxes",
    sql: "SELECT rust_admin_folder_delete($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- lifecycle.rs ----

pub const LIFECYCLE_PREVIEW: SqlContract = SqlContract {
    id: "mailboxes.lifecycle_preview",
    domain: "mailboxes",
    sql: "SELECT mailbox_lifecycle_preview($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LIFECYCLE_RETAINED: SqlContract = SqlContract {
    id: "mailboxes.lifecycle_retained",
    domain: "mailboxes",
    sql: "SELECT mailbox_retained_list($1,$2,200)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LIFECYCLE_PARITY: SqlContract = SqlContract {
    id: "mailboxes.lifecycle_parity",
    domain: "mailboxes",
    sql: "SELECT mailbox_lifecycle_parity_report()::text",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LIFECYCLE_TRANSITION: SqlContract = SqlContract {
    id: "mailboxes.lifecycle_transition",
    domain: "mailboxes",
    sql: "SELECT mailbox_lifecycle_transition($1,$2,$3::text::uuid,$4,$5,$6,$7,$8,$9,$10,$11,$12,to_timestamp($13::bigint),$14,NULL::text)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const LIFECYCLE_PURGE_SCHEDULE: SqlContract = SqlContract {
    id: "mailboxes.lifecycle_purge_schedule",
    domain: "mailboxes",
    sql: "SELECT mailbox_purge_schedule($1,$2,$3::text::uuid,$4,$5,$6,$7,$8)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const LIFECYCLE_PURGE_APPROVAL: SqlContract = SqlContract {
    id: "mailboxes.lifecycle_purge_approval",
    domain: "mailboxes",
    sql: "SELECT mailbox_purge_approval_apply($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LIFECYCLE_PURGE_EXECUTE: SqlContract = SqlContract {
    id: "mailboxes.lifecycle_purge_execute",
    domain: "mailboxes",
    sql: "SELECT mailbox_purge_execute($1,$2::text::uuid,$3::text::uuid,$4)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const LIFECYCLE_PURGE_CANCEL: SqlContract = SqlContract {
    id: "mailboxes.lifecycle_purge_cancel",
    domain: "mailboxes",
    sql: "SELECT mailbox_purge_cancel($1,$2::text::uuid,$3::text::uuid,$4,$5)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- import_export.rs ----

pub const IMPORT_REACH_MAILBOX: SqlContract = SqlContract {
    id: "mailboxes.import_reach_mailbox",
    domain: "mailboxes",
    sql: "SELECT mb.user_id, mb.domain_id FROM mailboxes mb WHERE mb.id = $1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("user_id", Type::INT8),
        ColumnSpec::named("domain_id", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IMPORT_REACH_USER: SqlContract = SqlContract {
    id: "mailboxes.import_reach_user",
    domain: "mailboxes",
    sql: "SELECT admin_can_reach($1, $2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IMPORT_REACH_DOMAIN: SqlContract = SqlContract {
    id: "mailboxes.import_reach_domain",
    domain: "mailboxes",
    sql: "SELECT EXISTS (SELECT 1 FROM admin_effective_authority($1) a WHERE a.scope = $2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IMPORT_REACH_GLOBAL: SqlContract = SqlContract {
    id: "mailboxes.import_reach_global",
    domain: "mailboxes",
    sql: "SELECT a.scope IS NULL AND a.is_unconfined FROM admin_effective_authority($1) a",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FOLDER_TO_TAG: SqlContract = SqlContract {
    id: "mailboxes.folder_to_tag",
    domain: "mailboxes",
    sql:
        "SELECT t.id FROM tags t JOIN folders f ON f.mailbox_id = t.mailbox_id AND f.name = t.name \
         WHERE f.id = $1 AND f.mailbox_id = $2",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IMPORT_MESSAGE: SqlContract = SqlContract {
    id: "mailboxes.import_message",
    domain: "mailboxes",
    sql: "SELECT import_message($1::bigint, $2::bigint, $3::text, $4::text, $5::text, $6::text, \
         $7::text::jsonb, $8::text::jsonb, $9::text::jsonb, $10::text, $11::text, $12::text, $13::text, \
         $14::bigint, FALSE, FALSE, $15::text, \
         (TIMESTAMPTZ 'epoch' + $16::bigint * INTERVAL '1 second' + $17::integer * INTERVAL '1 microsecond'), \
         p_actor_id => $18::bigint, p_domain_scope => $19::bigint)",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::INT4,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_IMPORT: SqlContract = SqlContract {
    id: "mailboxes.audit_import",
    domain: "mailboxes",
    sql: "SELECT audit_write($1::bigint, 'mailbox.import', 'mailbox', $2::bigint, NULL, $3::text::jsonb, NULLIF($4::text, '')::inet, '', 'core')",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXPORT_ROWS: SqlContract = SqlContract {
    id: "mailboxes.export_rows",
    domain: "mailboxes",
    sql: "SELECT m.id, m.message_id, m.raw_ref FROM messages m \
         WHERE m.mailbox_id = $1 AND admin_can_reach_mailbox($2, $3, $1) \
         AND ($4::BIGINT IS NULL OR EXISTS (SELECT 1 FROM message_tags mt \
              WHERE mt.message_id = m.id AND mt.received_at = m.received_at AND mt.tag_id = $4)) \
         ORDER BY m.received_at DESC",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("message_id", Type::TEXT),
        ColumnSpec::named("raw_ref", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- exchange.rs ----

pub const EXCHANGE_REGISTRY: SqlContract = SqlContract {
    id: "mailboxes.exchange_registry",
    domain: "mailboxes",
    sql: "SELECT projection::text FROM exchange_registry_snapshots ORDER BY registry_version DESC LIMIT 1",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXCHANGE_PROJECTS: SqlContract = SqlContract {
    id: "mailboxes.exchange_projects",
    domain: "mailboxes",
    sql: concat!(
        "SELECT jsonb_build_object('id',id,'domainId',domain_id,'name',name,'state',state,'retentionUntil',",
        pg_rfc3339!("retention_until"),
        ",'createdBy',created_by,'createdAt',",
        pg_rfc3339!("created_at"),
        ",'updatedAt',",
        pg_rfc3339!("updated_at"),
        ")::text FROM exchange_assessment_projects WHERE ($1::bigint=0 OR domain_id=$1) AND state<>'deleted' ORDER BY updated_at DESC,id DESC LIMIT 500"
    ),
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXCHANGE_RUNS: SqlContract = SqlContract {
    id: "mailboxes.exchange_runs",
    domain: "mailboxes",
    sql: concat!(
        "SELECT jsonb_build_object('id',r.id,'projectId',r.project_id,'generation',r.generation,'state',r.state,'supportCellId',r.support_cell_id,'supportCellDigest',r.support_cell_digest,'registryVersion',r.registry_version,'registryDigest',r.registry_digest,'catalogVersion',r.catalog_version,'collectorVersion',r.collector_version,'errorCode',r.error_code,'createdAt',",
        pg_rfc3339!("r.created_at"),
        ",'updatedAt',",
        pg_rfc3339!("r.updated_at"),
        ",'completedAt',",
        pg_rfc3339!("r.completed_at"),
        ")::text FROM exchange_assessment_runs r JOIN exchange_assessment_projects p ON p.id=r.project_id WHERE r.project_id=$1 AND ($2::bigint=0 OR p.domain_id=$2) ORDER BY r.id DESC LIMIT 500"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXCHANGE_CREATE_PROJECT: SqlContract = SqlContract {
    id: "mailboxes.exchange_create_project",
    domain: "mailboxes",
    sql: "SELECT exchange_assessment_project_create_idempotent($1,$2::text::uuid,$3,$4,$5,$6::text::timestamptz)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const EXCHANGE_CREATE_RUN: SqlContract = SqlContract {
    id: "mailboxes.exchange_create_run",
    domain: "mailboxes",
    sql: "SELECT exchange_assessment_run_create_idempotent($1,$2::text::uuid,$3,$4,$5,$6,$7::bigint::integer,$8,$9::bigint::integer,$10)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const EXCHANGE_TRANSITION: SqlContract = SqlContract {
    id: "mailboxes.exchange_transition",
    domain: "mailboxes",
    sql: "SELECT exchange_assessment_run_transition($1,$2,$3,$4,$5)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const EXCHANGE_ATTEST: SqlContract = SqlContract {
    id: "mailboxes.exchange_attest",
    domain: "mailboxes",
    sql: "SELECT exchange_assessment_attestation_create($1,$2,$3,$4,$5::text::jsonb)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const EXCHANGE_DECIDE: SqlContract = SqlContract {
    id: "mailboxes.exchange_decide",
    domain: "mailboxes",
    sql:
        "SELECT exchange_assessment_decision_set($1,$2,$3,$4,$5,$6,$7,$8::text::timestamptz)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const EXCHANGE_RESOLVE: SqlContract = SqlContract {
    id: "mailboxes.exchange_resolve",
    domain: "mailboxes",
    sql: "SELECT exchange_assessment_claim_resolve($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const EXCHANGE_REQUEST_DELETION: SqlContract = SqlContract {
    id: "mailboxes.exchange_request_deletion",
    domain: "mailboxes",
    sql: "SELECT exchange_assessment_delete_request($1,$2,$3,$4,$5,$6)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const EXCHANGE_AUDIT: SqlContract = SqlContract {
    id: "mailboxes.exchange_audit",
    domain: "mailboxes",
    sql: "SELECT jsonb_build_object(\
         'claims',COALESCE((SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id DESC) FROM exchange_assessment_claim_snapshots s WHERE s.run_id=r.id),'[]'::jsonb),\
         'attestations',COALESCE((SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id DESC) FROM exchange_assessment_attestations a WHERE a.run_id=r.id),'[]'::jsonb),\
         'evidence',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id DESC) FROM exchange_assessment_evidence e WHERE e.run_id=r.id),'[]'::jsonb),\
         'publications',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.id DESC) FROM exchange_assessment_publications x WHERE x.run_id=r.id),'[]'::jsonb))::text \
         FROM exchange_assessment_runs r JOIN exchange_assessment_projects p ON p.id=r.project_id WHERE r.id=$1 AND ($2::bigint=0 OR p.domain_id=$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXCHANGE_REASON_REQUIRED: SqlContract = SqlContract {
    id: "mailboxes.exchange_reason_required",
    domain: "mailboxes",
    sql: "SELECT reason_required_areas FROM audit_policy WHERE id=1",
    params: &[],
    columns: &[ColumnSpec::named("reason_required_areas", Type::TEXT_ARRAY)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXCHANGE_MISSING_REASON: SqlContract = SqlContract {
    id: "mailboxes.exchange_missing_reason",
    domain: "mailboxes",
    sql: "SELECT audit_write($1,'sensitive_action.reason_missing','',NULL,NULL,NULL,NULLIF($2::text,'')::inet,$3,'core')",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXCHANGE_UPLOAD_CONTEXT: SqlContract = SqlContract {
    id: "mailboxes.exchange_upload_context",
    domain: "mailboxes",
    sql: "SELECT r.project_id,p.domain_id,p.retention_until::text,r.generation,u.installation_id::text \
         FROM exchange_assessment_runs r JOIN exchange_assessment_projects p ON p.id=r.project_id \
         JOIN upgrade_control_state u ON u.singleton \
         WHERE r.id=$1 AND exchange_assessment_domain_authorized($2,p.domain_id,'exchange.assessment.run')",
    params: &[Type::INT8, Type::INT8],
    columns: EXCHANGE_CONTEXT_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXCHANGE_BUNDLE_REPLAY: SqlContract = SqlContract {
    id: "mailboxes.exchange_bundle_replay",
    domain: "mailboxes",
    sql: "SELECT (to_jsonb(a)||jsonb_build_object('replayed',true,'runGeneration',$3::bigint))::text \
         FROM exchange_assessment_artifacts a WHERE a.run_id=$1 AND a.kind='bundle' AND a.sha256=$2",
    params: &[Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXCHANGE_COMMIT_BUNDLE: SqlContract = SqlContract {
    id: "mailboxes.exchange_commit_bundle",
    domain: "mailboxes",
    sql: "SELECT exchange_assessment_artifact_commit($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::text::timestamptz)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::BYTEA,
        Type::BYTEA,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const EXCHANGE_PUBLICATION_CONTEXT: SqlContract = SqlContract {
    id: "mailboxes.exchange_publication_context",
    domain: "mailboxes",
    sql: "SELECT r.project_id,p.domain_id,p.retention_until::text,r.generation,u.installation_id::text \
         FROM exchange_assessment_runs r JOIN exchange_assessment_projects p ON p.id=r.project_id \
         JOIN upgrade_control_state u ON u.singleton \
         WHERE r.id=$1 AND exchange_assessment_domain_authorized($2,p.domain_id,'exchange.assessment.publish')",
    params: &[Type::INT8, Type::INT8],
    columns: EXCHANGE_CONTEXT_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXCHANGE_PUBLICATION_REPLAY: SqlContract = SqlContract {
    id: "mailboxes.exchange_publication_replay",
    domain: "mailboxes",
    sql: "SELECT (to_jsonb(p)||'{\"replayed\":true}'::jsonb)::text \
         FROM exchange_assessment_publications p WHERE p.run_id=$1 AND p.projection_digest=$2 AND p.revoked_at IS NULL",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXCHANGE_PUBLISH: SqlContract = SqlContract {
    id: "mailboxes.exchange_publish",
    domain: "mailboxes",
    sql: "SELECT exchange_assessment_publish_signed($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::text::jsonb,$13,$14,$15)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::BYTEA,
        Type::BYTEA,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BYTEA,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- migration.rs ----

pub const MIGRATION_JOBS_LIST: SqlContract = SqlContract {
    id: "mailboxes.migration_jobs_list",
    domain: "mailboxes",
    sql: concat!(
        migration_job_select!(),
        " WHERE ($1::text = '' OR status = $1) \
         AND ($2::text = '' OR user_id = NULLIF($2::text, '')::bigint) \
         ORDER BY created_at DESC LIMIT 100"
    ),
    params: &[Type::TEXT, Type::TEXT],
    columns: MIGRATION_JOB_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MIGRATION_JOB_GET: SqlContract = SqlContract {
    id: "mailboxes.migration_job_get",
    domain: "mailboxes",
    sql: concat!(migration_job_select!(), " WHERE id = $1"),
    params: &[Type::INT8],
    columns: MIGRATION_JOB_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MIGRATION_JOB_DELETE: SqlContract = SqlContract {
    id: "mailboxes.migration_job_delete",
    domain: "mailboxes",
    sql: "WITH d AS (DELETE FROM migration_jobs WHERE id = $1 RETURNING 1) SELECT count(*)::bigint FROM d",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MIGRATION_HAS_GLOBAL: SqlContract = SqlContract {
    id: "mailboxes.migration_has_global",
    domain: "mailboxes",
    sql: "SELECT EXISTS(SELECT 1 FROM system_config WHERE key = $1)",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MIGRATION_MAILBOX_FOR_EMAIL: SqlContract = SqlContract {
    id: "mailboxes.migration_mailbox_for_email",
    domain: "mailboxes",
    sql: "SELECT m.id FROM mailboxes m JOIN users u ON m.user_id = u.id WHERE u.email = $1 LIMIT 1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MIGRATION_INSERT_JOB: SqlContract = SqlContract {
    id: "mailboxes.migration_insert_job",
    domain: "mailboxes",
    sql: "WITH i AS (INSERT INTO migration_jobs (user_id, source_type, source_config_enc, target_mailbox_id, conflict_strategy, status) \
         VALUES ($1::bigint, $2::text, $3::bytea, $4::bigint, 'skip', 'pending') RETURNING id) SELECT id FROM i",
    params: &[Type::INT8, Type::TEXT, Type::BYTEA, Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MIGRATION_CONFIG_GET: SqlContract = SqlContract {
    id: "mailboxes.migration_config_get",
    domain: "mailboxes",
    sql: "SELECT value::text, encrypted FROM system_config WHERE key = $1",
    params: &[Type::TEXT],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("encrypted", Type::BOOL),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MIGRATION_CONFIG_UPSERT: SqlContract = SqlContract {
    id: "mailboxes.migration_config_upsert",
    domain: "mailboxes",
    sql: "SELECT rust_system_config_upsert($1, $2, $3)",
    params: &[Type::TEXT, Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MIGRATION_CONFIG_DELETE: SqlContract = SqlContract {
    id: "mailboxes.migration_config_delete",
    domain: "mailboxes",
    sql: "SELECT rust_system_config_delete($1)",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MIGRATION_MINT_CONSENT: SqlContract = SqlContract {
    id: "mailboxes.migration_mint_consent",
    domain: "mailboxes",
    sql: "SELECT m365_consent_state_mint($1, $2, $3, $4)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MIGRATION_CONSUME_CONSENT: SqlContract = SqlContract {
    id: "mailboxes.migration_consume_consent",
    domain: "mailboxes",
    sql: "SELECT m365_consent_state_consume($1,$2)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MIGRATION_COMPLETE_CONSENT: SqlContract = SqlContract {
    id: "mailboxes.migration_complete_consent",
    domain: "mailboxes",
    sql: "SELECT m365_consent_complete($1,$2,$3,'routine')::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    CONSOLE_DENIED,
    MAILBOXES_LIST,
    MAILBOX_GET,
    MAILBOX_DOMAIN_OF,
    MAILBOX_FOLDERS,
    IS_GUEST_ACCOUNT,
    USER_DOMAIN,
    MAILBOX_CREATE,
    MAILBOX_UPDATE,
    LIFECYCLE_ENABLED,
    MAILBOX_DELETE,
    FOLDER_CREATE,
    FOLDER_UPDATE,
    FOLDER_DELETE,
    LIFECYCLE_PREVIEW,
    LIFECYCLE_RETAINED,
    LIFECYCLE_PARITY,
    LIFECYCLE_TRANSITION,
    LIFECYCLE_PURGE_SCHEDULE,
    LIFECYCLE_PURGE_APPROVAL,
    LIFECYCLE_PURGE_EXECUTE,
    LIFECYCLE_PURGE_CANCEL,
    IMPORT_REACH_MAILBOX,
    IMPORT_REACH_USER,
    IMPORT_REACH_DOMAIN,
    IMPORT_REACH_GLOBAL,
    FOLDER_TO_TAG,
    IMPORT_MESSAGE,
    AUDIT_IMPORT,
    EXPORT_ROWS,
    EXCHANGE_REGISTRY,
    EXCHANGE_PROJECTS,
    EXCHANGE_RUNS,
    EXCHANGE_CREATE_PROJECT,
    EXCHANGE_CREATE_RUN,
    EXCHANGE_TRANSITION,
    EXCHANGE_ATTEST,
    EXCHANGE_DECIDE,
    EXCHANGE_RESOLVE,
    EXCHANGE_REQUEST_DELETION,
    EXCHANGE_AUDIT,
    EXCHANGE_REASON_REQUIRED,
    EXCHANGE_MISSING_REASON,
    EXCHANGE_UPLOAD_CONTEXT,
    EXCHANGE_BUNDLE_REPLAY,
    EXCHANGE_COMMIT_BUNDLE,
    EXCHANGE_PUBLICATION_CONTEXT,
    EXCHANGE_PUBLICATION_REPLAY,
    EXCHANGE_PUBLISH,
    MIGRATION_JOBS_LIST,
    MIGRATION_JOB_GET,
    MIGRATION_JOB_DELETE,
    MIGRATION_HAS_GLOBAL,
    MIGRATION_MAILBOX_FOR_EMAIL,
    MIGRATION_INSERT_JOB,
    MIGRATION_CONFIG_GET,
    MIGRATION_CONFIG_UPSERT,
    MIGRATION_CONFIG_DELETE,
    MIGRATION_MINT_CONSENT,
    MIGRATION_CONSUME_CONSENT,
    MIGRATION_COMPLETE_CONSENT,
];
