//! Static typed SQL contract catalog for `setjoin-office` (F15).
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};

pub const WOPI_ENABLED: SqlContract = SqlContract {
    id: "office.wopi_enabled",
    domain: "office",
    sql: "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.drive'),false) AND coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.office_editing'),false)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WOPI_FILE_QUERY: SqlContract = SqlContract {
    id: "office.wopi_file_query",
    domain: "office",
    sql: "SELECT office_wopi_file_query($1,$2)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WOPI_CALLBACK_ALLOWED: SqlContract = SqlContract {
    id: "office.wopi_callback_allowed",
    domain: "office",
    sql: "SELECT office_wopi_callback_allowed($1::text::uuid,$2,'modify_content')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WOPI_LOCK_APPLY: SqlContract = SqlContract {
    id: "office.wopi_lock_apply",
    domain: "office",
    sql: "SELECT office_wopi_lock_apply($1::text::uuid,$2,$3,$4,$5,1800)::text",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHUNK_SCOPE_ACL: SqlContract = SqlContract {
    id: "office.chunk_scope_acl",
    domain: "office",
    sql: "SELECT CASE WHEN s.classification='regular' THEN 'g' ELSE 's'||s.id END FROM drive_nodes n JOIN drive_spaces s ON s.id=n.space_id JOIN drive_acl_generations g ON g.space_id=s.id WHERE n.id=$3 AND n.space_id=$2 AND s.acl_mode='acl' AND g.epoch=$4 AND drive_runtime_has_node_capability($1,n.id,CASE WHEN n.kind='folder' THEN 'create_child' ELSE 'modify_content' END)",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHUNK_UPLOAD_REQUIRE: SqlContract = SqlContract {
    id: "office.chunk_upload_require",
    domain: "office",
    sql: "SELECT drive_chunk_upload_require($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHUNK_ADVISORY_LOCK: SqlContract = SqlContract {
    id: "office.chunk_advisory_lock",
    domain: "office",
    sql: "SELECT pg_advisory_xact_lock(hashtextextended('drive-chunk:'||$1||':'||$2,0))",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHUNK_REGISTER_BOUND: SqlContract = SqlContract {
    id: "office.chunk_register_bound",
    domain: "office",
    sql: "SELECT drive_chunk_register_bound($1,$2,$3,$4,$5,$6)",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT4,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHUNK_REGISTER: SqlContract = SqlContract {
    id: "office.chunk_register",
    domain: "office",
    sql: "SELECT drive_chunk_register($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WOPI_SAVE_ACCEPT: SqlContract = SqlContract {
    id: "office.wopi_save_accept",
    domain: "office",
    sql: "SELECT office_save_accept($1::text::uuid,$2,$3,$4,$5,$6,$7,$8::text::jsonb,$9)::text",
    params: &[
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_REASON_REQUIRED: SqlContract = SqlContract {
    id: "office.admin_reason_required",
    domain: "office",
    sql: "SELECT 'office'=ANY(reason_required_areas) FROM audit_policy WHERE id=1",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_LIST: SqlContract = SqlContract {
    id: "office.admin_list",
    domain: "office",
    sql: "SELECT office_admin_list($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_QUALIFICATION_TARGET: SqlContract = SqlContract {
    id: "office.admin_qualification_target",
    domain: "office",
    sql: "SELECT office_provider_qualification_target($1,$2,$3)::text",
    params: &[Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_CONFIGURE: SqlContract = SqlContract {
    id: "office.admin_configure",
    domain: "office",
    sql: "SELECT office_provider_configure($1,$2,$3,$4,$5,$6,$7::text::jsonb,$8)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
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

pub const ADMIN_ACTIVATE: SqlContract = SqlContract {
    id: "office.admin_activate",
    domain: "office",
    sql: "SELECT office_provider_activate($1,$2,$3,$4::text::uuid,$5::text::jsonb,$6)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ADMIN_REMOVE: SqlContract = SqlContract {
    id: "office.admin_remove",
    domain: "office",
    sql: "SELECT office_provider_remove($1,$2,$3)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ADMIN_QUALIFY: SqlContract = SqlContract {
    id: "office.admin_qualify",
    domain: "office",
    sql: "SELECT office_provider_qualify($1,$2,$3,$4,$5,$6::text::jsonb,$7,$8,$9,$10,$11)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
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

pub const CONSOLE_DENIED: SqlContract = SqlContract {
    id: "office.console_denied",
    domain: "office",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REASON_MISSING: SqlContract = SqlContract {
    id: "office.reason_missing",
    domain: "office",
    sql: "SELECT audit_write($1,'sensitive_action.reason_missing','',NULL,NULL,NULL,$2::text::inet,'office.manage','core')",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    WOPI_ENABLED,
    WOPI_FILE_QUERY,
    WOPI_CALLBACK_ALLOWED,
    WOPI_LOCK_APPLY,
    CHUNK_SCOPE_ACL,
    CHUNK_UPLOAD_REQUIRE,
    CHUNK_ADVISORY_LOCK,
    CHUNK_REGISTER_BOUND,
    CHUNK_REGISTER,
    WOPI_SAVE_ACCEPT,
    ADMIN_REASON_REQUIRED,
    ADMIN_LIST,
    ADMIN_QUALIFICATION_TARGET,
    ADMIN_CONFIGURE,
    ADMIN_ACTIVATE,
    ADMIN_REMOVE,
    ADMIN_QUALIFY,
    CONSOLE_DENIED,
    REASON_MISSING,
];
