//! Static typed SQL contract catalog for `setjoin-directory-sync` (F02).
use setjoin_sql_catalog::{
    pg_rfc3339, ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type,
};

// ---- Shared console denial audit ----

pub const CONSOLE_DENIED: SqlContract = SqlContract {
    id: "directory_sync.console_denied",
    domain: "directory-sync",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- AD / LDAP admin reads & writes ----

pub const CONFIG_AD: SqlContract = SqlContract {
    id: "directory_sync.config_ad",
    domain: "directory-sync",
    sql: "SELECT key, value::text, encrypted FROM system_config WHERE key LIKE 'ad_sync_%' OR key LIKE 'enable_%_reset'",
    params: &[],
    columns: &[
        ColumnSpec::named("key", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("encrypted", Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONFIG_LDAP: SqlContract = SqlContract {
    id: "directory_sync.config_ldap",
    domain: "directory-sync",
    sql: "SELECT key, value::text, encrypted FROM system_config WHERE key LIKE 'ldap_sync_%'",
    params: &[],
    columns: &[
        ColumnSpec::named("key", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("encrypted", Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONFIG_KEY_EXISTS: SqlContract = SqlContract {
    id: "directory_sync.config_key_exists",
    domain: "directory-sync",
    sql: "SELECT 1 FROM system_config WHERE key = $1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONFIG_UPSERT_BATCH_ENCRYPTED: SqlContract = SqlContract {
    id: "directory_sync.config_upsert_batch_encrypted",
    domain: "directory-sync",
    sql: "SELECT public.rust_system_config_upsert_batch_encrypted($1::text[], $2::text[], $3::boolean[], $4::text)",
    params: &[
        Type::TEXT_ARRAY,
        Type::TEXT_ARRAY,
        Type::BOOL_ARRAY,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SYNC_LOG: SqlContract = SqlContract {
    id: "directory_sync.sync_log",
    domain: "directory-sync",
    sql: concat!(
        "SELECT l.source, l.users_checked, l.users_created, l.users_updated, l.users_disabled, ",
        "l.fields_skipped, CASE WHEN l.error IS NULL THEN 0 ELSE 1 END, COALESCE(l.duration_ms, 0), ",
        pg_rfc3339!("l.sync_at"),
        ", COALESCE(l.details, '{}'::jsonb)::text ",
        "FROM identity_sync_log l WHERE l.source = $1 ORDER BY l.sync_at DESC LIMIT $2"
    ),
    params: &[Type::TEXT, Type::INT8],
    columns: &[
        ColumnSpec::named("source", Type::TEXT),
        ColumnSpec::named("users_checked", Type::INT4),
        ColumnSpec::named("users_created", Type::INT4),
        ColumnSpec::named("users_updated", Type::INT4),
        ColumnSpec::named("users_disabled", Type::INT4),
        ColumnSpec::named("fields_skipped", Type::INT4),
        ColumnSpec::unnamed(Type::INT4),
        ColumnSpec::unnamed(Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const HEALTH_LAST_SYNC: SqlContract = SqlContract {
    id: "directory_sync.health_last_sync",
    domain: "directory-sync",
    sql: concat!(
        "SELECT ",
        pg_rfc3339!("l.sync_at"),
        ", l.users_checked, l.users_created, l.users_updated, l.users_disabled, l.fields_skipped, ",
        "CASE WHEN l.error IS NULL THEN 0 ELSE 1 END FROM identity_sync_log l WHERE l.source = $1 ",
        "ORDER BY l.sync_at DESC LIMIT 1"
    ),
    params: &[Type::TEXT],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("users_checked", Type::INT4),
        ColumnSpec::named("users_created", Type::INT4),
        ColumnSpec::named("users_updated", Type::INT4),
        ColumnSpec::named("users_disabled", Type::INT4),
        ColumnSpec::named("fields_skipped", Type::INT4),
        ColumnSpec::unnamed(Type::INT4),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const HEALTH_PENDING_CONFLICTS: SqlContract = SqlContract {
    id: "directory_sync.health_pending_conflicts",
    domain: "directory-sync",
    sql: "SELECT COUNT(*) FROM sync_conflicts WHERE resolved_at IS NULL AND source = $1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONFLICTS_LIST: SqlContract = SqlContract {
    id: "directory_sync.conflicts_list",
    domain: "directory-sync",
    sql: concat!(
        "SELECT sc.id, sc.user_id, u.email, sc.field, ",
        "COALESCE(sc.local_value, ''), COALESCE(sc.remote_value, ''), ",
        pg_rfc3339!("sc.detected_at"),
        " FROM sync_conflicts sc JOIN users u ON u.id = sc.user_id ",
        "WHERE sc.resolved_at IS NULL AND sc.source = 'ad' ",
        "AND ($2::boolean OR admin_org_wide_grant($1, '{users.read,identity.write,access.policy_read,access.policy_write}'::text[]) ",
        "     OR admin_can_reach_perm($1, sc.user_id, '{users.read,identity.write,access.policy_read,access.policy_write}'::text[])) ",
        "ORDER BY sc.detected_at DESC LIMIT 200"
    ),
    params: &[Type::INT8, Type::BOOL],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("user_id", Type::INT8),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::named("field", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONFLICT_RESOLVE_ONE: SqlContract = SqlContract {
    id: "directory_sync.conflict_resolve_one",
    domain: "directory-sync",
    sql: "WITH resolved AS ( \
          UPDATE sync_conflicts sc SET resolved_at = now(), resolution = $3 \
          WHERE sc.id = $2 AND sc.resolved_at IS NULL AND sc.source = 'ad' AND $1::bigint > 0 \
            AND ($4::boolean OR admin_org_wide_grant($1, '{identity.write}'::text[]) \
                 OR admin_can_reach_perm($1, sc.user_id, '{identity.write}'::text[])) \
          RETURNING 1) SELECT count(*)::bigint FROM resolved",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONFLICT_RESOLVE_ALL: SqlContract = SqlContract {
    id: "directory_sync.conflict_resolve_all",
    domain: "directory-sync",
    sql: "WITH resolved AS ( \
          UPDATE sync_conflicts sc SET resolved_at = now(), resolution = $2 \
          WHERE sc.resolved_at IS NULL AND sc.source = 'ad' AND $1::bigint > 0 \
            AND ($3::boolean OR admin_org_wide_grant($1, '{identity.write}'::text[]) \
                 OR admin_can_reach_perm($1, sc.user_id, '{identity.write}'::text[])) \
          RETURNING 1) SELECT count(*)::bigint FROM resolved",
    params: &[Type::INT8, Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FIELD_POLICY_GET_PERM: SqlContract = SqlContract {
    id: "directory_sync.field_policy_get_perm",
    domain: "directory-sync",
    sql: "SELECT field, policy FROM field_policy WHERE user_id = $1 \
          AND public.admin_can_reach_perm($2, $1, '{users.read,identity.write,access.policy_read,access.policy_write}'::text[])",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("field", Type::TEXT),
        ColumnSpec::named("policy", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FIELD_POLICY_GET_ANY_GRANT: SqlContract = SqlContract {
    id: "directory_sync.field_policy_get_any_grant",
    domain: "directory-sync",
    sql: "SELECT field, policy FROM field_policy WHERE user_id = $1 AND public.admin_can_reach($2, $1)",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("field", Type::TEXT),
        ColumnSpec::named("policy", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FIELD_POLICY_GET_FOREIGN: SqlContract = SqlContract {
    id: "directory_sync.field_policy_get_foreign",
    domain: "directory-sync",
    sql: "SELECT field, policy FROM field_policy WHERE user_id = $1 AND $2::bigint > 0",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("field", Type::TEXT),
        ColumnSpec::named("policy", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_CAN_REACH: SqlContract = SqlContract {
    id: "directory_sync.admin_can_reach",
    domain: "directory-sync",
    sql: "SELECT public.admin_can_reach($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_CAN_REACH_PERM: SqlContract = SqlContract {
    id: "directory_sync.admin_can_reach_perm",
    domain: "directory-sync",
    sql: "SELECT public.admin_can_reach_perm($1,$2,$3::text[])",
    params: &[Type::INT8, Type::INT8, Type::TEXT_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FIELD_POLICY_DELETE: SqlContract = SqlContract {
    id: "directory_sync.field_policy_delete",
    domain: "directory-sync",
    sql: "WITH removed AS ( \
          DELETE FROM field_policy WHERE user_id = $2 AND field = $3 \
            AND (CASE WHEN $4::boolean THEN public.admin_can_reach($1, $2) \
                      ELSE public.admin_can_reach_perm($1, $2, '{identity.write}'::text[]) END) \
          RETURNING 1) SELECT count(*)::bigint FROM removed",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FIELD_POLICY_UPSERT: SqlContract = SqlContract {
    id: "directory_sync.field_policy_upsert",
    domain: "directory-sync",
    sql: "WITH written AS ( \
          INSERT INTO field_policy (user_id, field, policy) \
          SELECT $2, $3, $4 \
          WHERE (CASE WHEN $5::boolean THEN public.admin_can_reach($1, $2) \
                      ELSE public.admin_can_reach_perm($1, $2, '{identity.write}'::text[]) END) \
          ON CONFLICT (user_id, field) DO UPDATE SET policy = $4, set_at = now() \
          RETURNING 1) SELECT count(*)::bigint FROM written",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRINCIPAL_CURRENT: SqlContract = SqlContract {
    id: "directory_sync.principal_current",
    domain: "directory-sync",
    sql: "SELECT krb5_principal FROM users WHERE id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("krb5_principal", Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRINCIPAL_SET: SqlContract = SqlContract {
    id: "directory_sync.principal_set",
    domain: "directory-sync",
    sql: "SELECT ad_principal_set($1,$2,$3,$4,$5::text::inet)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- SCIM 2.0 (opaque bearer token, source/generation fenced) ----

const SCIM_TOKEN_COLS: &[ColumnSpec] = &[
    ColumnSpec::named("token_id", Type::INT8),
    ColumnSpec::named("name", Type::TEXT),
    ColumnSpec::named("token_hash", Type::TEXT),
    ColumnSpec::named("deletion_policy", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("source_id", Type::INT8),
    ColumnSpec::named("source_generation", Type::INT8),
];

pub const SCIM_TOKEN_BY_HASH: SqlContract = SqlContract {
    id: "directory_sync.scim_token_by_hash",
    domain: "directory-sync",
    sql: "SELECT token_id, name, token_hash, deletion_policy, attribute_mapping::text, source_id, source_generation \
          FROM scim_token_lookup($1)",
    params: &[Type::TEXT],
    columns: SCIM_TOKEN_COLS,
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_LEGACY_TOKENS: SqlContract = SqlContract {
    id: "directory_sync.scim_legacy_tokens",
    domain: "directory-sync",
    sql: "SELECT token_id, name, token_hash, deletion_policy, attribute_mapping::text, source_id, source_generation \
          FROM scim_list_active_tokens()",
    params: &[],
    columns: SCIM_TOKEN_COLS,
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_RECORD_USAGE: SqlContract = SqlContract {
    id: "directory_sync.scim_record_usage",
    domain: "directory-sync",
    sql: "SELECT scim_record_token_usage($1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

const SCIM_USER_COLS: &[ColumnSpec] = &[
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::named("external_subject", Type::TEXT),
    ColumnSpec::named("username", Type::TEXT),
    ColumnSpec::named("email", Type::TEXT),
    ColumnSpec::named("display_name", Type::TEXT),
    ColumnSpec::named("first_name", Type::TEXT),
    ColumnSpec::named("last_name", Type::TEXT),
    ColumnSpec::named("job_title", Type::TEXT),
    ColumnSpec::named("phone", Type::TEXT),
    ColumnSpec::named("enabled", Type::BOOL),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::INT8),
];

const SCIM_FILTER_PREDICATE: &str = "(CASE $2::text \
    WHEN 'userName' THEN CASE $3::text WHEN 'eq' THEN u.username = $4 WHEN 'pr' THEN u.username IS NOT NULL WHEN 'co' THEN u.username ILIKE $4 WHEN 'sw' THEN u.username ILIKE $4 ELSE TRUE END \
    WHEN 'externalId' THEN CASE $3::text WHEN 'eq' THEN l.external_subject = $4 WHEN 'pr' THEN l.external_subject IS NOT NULL WHEN 'co' THEN l.external_subject ILIKE $4 WHEN 'sw' THEN l.external_subject ILIKE $4 ELSE TRUE END \
    WHEN 'displayName' THEN CASE $3::text WHEN 'eq' THEN u.display_name = $4 WHEN 'pr' THEN u.display_name IS NOT NULL WHEN 'co' THEN u.display_name ILIKE $4 WHEN 'sw' THEN u.display_name ILIKE $4 ELSE TRUE END \
    WHEN 'name.givenName' THEN CASE $3::text WHEN 'eq' THEN u.first_name = $4 WHEN 'pr' THEN u.first_name IS NOT NULL WHEN 'co' THEN u.first_name ILIKE $4 WHEN 'sw' THEN u.first_name ILIKE $4 ELSE TRUE END \
    WHEN 'name.familyName' THEN CASE $3::text WHEN 'eq' THEN u.last_name = $4 WHEN 'pr' THEN u.last_name IS NOT NULL WHEN 'co' THEN u.last_name ILIKE $4 WHEN 'sw' THEN u.last_name ILIKE $4 ELSE TRUE END \
    WHEN 'emails' THEN CASE $3::text WHEN 'eq' THEN u.email = $4 WHEN 'pr' THEN u.email IS NOT NULL WHEN 'co' THEN u.email ILIKE $4 WHEN 'sw' THEN u.email ILIKE $4 ELSE TRUE END \
    WHEN 'emails.value' THEN CASE $3::text WHEN 'eq' THEN u.email = $4 WHEN 'pr' THEN u.email IS NOT NULL WHEN 'co' THEN u.email ILIKE $4 WHEN 'sw' THEN u.email ILIKE $4 ELSE TRUE END \
    WHEN 'title' THEN CASE $3::text WHEN 'eq' THEN u.job_title = $4 WHEN 'pr' THEN u.job_title IS NOT NULL WHEN 'co' THEN u.job_title ILIKE $4 WHEN 'sw' THEN u.job_title ILIKE $4 ELSE TRUE END \
    WHEN 'phoneNumbers.value' THEN CASE $3::text WHEN 'eq' THEN u.phone = $4 WHEN 'pr' THEN u.phone IS NOT NULL WHEN 'co' THEN u.phone ILIKE $4 WHEN 'sw' THEN u.phone ILIKE $4 ELSE TRUE END \
    WHEN 'active' THEN CASE $3::text WHEN 'eq' THEN u.enabled = $4::text::boolean WHEN 'pr' THEN u.enabled IS NOT NULL ELSE FALSE END \
    WHEN 'id' THEN CASE $3::text WHEN 'eq' THEN u.id = $4::text::bigint WHEN 'pr' THEN u.id IS NOT NULL ELSE FALSE END \
    ELSE FALSE END)";

pub const SCIM_USERS_FILTER_COUNT: SqlContract = SqlContract {
    id: "directory_sync.scim_users_filter_count",
    domain: "directory-sync",
    sql: concat!(
        "SELECT COUNT(*) FROM user_identity_links l JOIN users u ON u.id=l.user_id ",
        "WHERE l.source_id=$1 AND l.state='active' AND 'provision'=ANY(l.purposes) AND NOT is_guest_account(u.id) AND ",
        "(CASE $2::text \
          WHEN 'userName' THEN CASE $3::text WHEN 'eq' THEN u.username = $4 WHEN 'pr' THEN u.username IS NOT NULL WHEN 'co' THEN u.username ILIKE $4 WHEN 'sw' THEN u.username ILIKE $4 ELSE TRUE END \
          WHEN 'externalId' THEN CASE $3::text WHEN 'eq' THEN l.external_subject = $4 WHEN 'pr' THEN l.external_subject IS NOT NULL WHEN 'co' THEN l.external_subject ILIKE $4 WHEN 'sw' THEN l.external_subject ILIKE $4 ELSE TRUE END \
          WHEN 'displayName' THEN CASE $3::text WHEN 'eq' THEN u.display_name = $4 WHEN 'pr' THEN u.display_name IS NOT NULL WHEN 'co' THEN u.display_name ILIKE $4 WHEN 'sw' THEN u.display_name ILIKE $4 ELSE TRUE END \
          WHEN 'name.givenName' THEN CASE $3::text WHEN 'eq' THEN u.first_name = $4 WHEN 'pr' THEN u.first_name IS NOT NULL WHEN 'co' THEN u.first_name ILIKE $4 WHEN 'sw' THEN u.first_name ILIKE $4 ELSE TRUE END \
          WHEN 'name.familyName' THEN CASE $3::text WHEN 'eq' THEN u.last_name = $4 WHEN 'pr' THEN u.last_name IS NOT NULL WHEN 'co' THEN u.last_name ILIKE $4 WHEN 'sw' THEN u.last_name ILIKE $4 ELSE TRUE END \
          WHEN 'emails' THEN CASE $3::text WHEN 'eq' THEN u.email = $4 WHEN 'pr' THEN u.email IS NOT NULL WHEN 'co' THEN u.email ILIKE $4 WHEN 'sw' THEN u.email ILIKE $4 ELSE TRUE END \
          WHEN 'emails.value' THEN CASE $3::text WHEN 'eq' THEN u.email = $4 WHEN 'pr' THEN u.email IS NOT NULL WHEN 'co' THEN u.email ILIKE $4 WHEN 'sw' THEN u.email ILIKE $4 ELSE TRUE END \
          WHEN 'title' THEN CASE $3::text WHEN 'eq' THEN u.job_title = $4 WHEN 'pr' THEN u.job_title IS NOT NULL WHEN 'co' THEN u.job_title ILIKE $4 WHEN 'sw' THEN u.job_title ILIKE $4 ELSE TRUE END \
          WHEN 'phoneNumbers.value' THEN CASE $3::text WHEN 'eq' THEN u.phone = $4 WHEN 'pr' THEN u.phone IS NOT NULL WHEN 'co' THEN u.phone ILIKE $4 WHEN 'sw' THEN u.phone ILIKE $4 ELSE TRUE END \
          WHEN 'active' THEN CASE $3::text WHEN 'eq' THEN u.enabled = $4::text::boolean WHEN 'pr' THEN u.enabled IS NOT NULL ELSE FALSE END \
          WHEN 'id' THEN CASE $3::text WHEN 'eq' THEN u.id = $4::text::bigint WHEN 'pr' THEN u.id IS NOT NULL ELSE FALSE END \
          ELSE FALSE END)"
    ),
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_USERS_FILTER_LIST: SqlContract = SqlContract {
    id: "directory_sync.scim_users_filter_list",
    domain: "directory-sync",
    sql: concat!(
        "SELECT u.id, l.external_subject, u.username, u.email, u.display_name, u.first_name, u.last_name, ",
        "u.job_title, u.phone, u.enabled, to_char(u.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), ",
        "to_char(u.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), ",
        pg_rfc3339!("u.updated_at"),
        ", (extract(epoch FROM u.updated_at) * 1000000)::bigint ",
        "FROM user_identity_links l JOIN users u ON u.id=l.user_id ",
        "WHERE l.source_id=$1 AND l.state='active' AND 'provision'=ANY(l.purposes) AND NOT is_guest_account(u.id) AND ",
        "(CASE $2::text \
          WHEN 'userName' THEN CASE $3::text WHEN 'eq' THEN u.username = $4 WHEN 'pr' THEN u.username IS NOT NULL WHEN 'co' THEN u.username ILIKE $4 WHEN 'sw' THEN u.username ILIKE $4 ELSE TRUE END \
          WHEN 'externalId' THEN CASE $3::text WHEN 'eq' THEN l.external_subject = $4 WHEN 'pr' THEN l.external_subject IS NOT NULL WHEN 'co' THEN l.external_subject ILIKE $4 WHEN 'sw' THEN l.external_subject ILIKE $4 ELSE TRUE END \
          WHEN 'displayName' THEN CASE $3::text WHEN 'eq' THEN u.display_name = $4 WHEN 'pr' THEN u.display_name IS NOT NULL WHEN 'co' THEN u.display_name ILIKE $4 WHEN 'sw' THEN u.display_name ILIKE $4 ELSE TRUE END \
          WHEN 'name.givenName' THEN CASE $3::text WHEN 'eq' THEN u.first_name = $4 WHEN 'pr' THEN u.first_name IS NOT NULL WHEN 'co' THEN u.first_name ILIKE $4 WHEN 'sw' THEN u.first_name ILIKE $4 ELSE TRUE END \
          WHEN 'name.familyName' THEN CASE $3::text WHEN 'eq' THEN u.last_name = $4 WHEN 'pr' THEN u.last_name IS NOT NULL WHEN 'co' THEN u.last_name ILIKE $4 WHEN 'sw' THEN u.last_name ILIKE $4 ELSE TRUE END \
          WHEN 'emails' THEN CASE $3::text WHEN 'eq' THEN u.email = $4 WHEN 'pr' THEN u.email IS NOT NULL WHEN 'co' THEN u.email ILIKE $4 WHEN 'sw' THEN u.email ILIKE $4 ELSE TRUE END \
          WHEN 'emails.value' THEN CASE $3::text WHEN 'eq' THEN u.email = $4 WHEN 'pr' THEN u.email IS NOT NULL WHEN 'co' THEN u.email ILIKE $4 WHEN 'sw' THEN u.email ILIKE $4 ELSE TRUE END \
          WHEN 'title' THEN CASE $3::text WHEN 'eq' THEN u.job_title = $4 WHEN 'pr' THEN u.job_title IS NOT NULL WHEN 'co' THEN u.job_title ILIKE $4 WHEN 'sw' THEN u.job_title ILIKE $4 ELSE TRUE END \
          WHEN 'phoneNumbers.value' THEN CASE $3::text WHEN 'eq' THEN u.phone = $4 WHEN 'pr' THEN u.phone IS NOT NULL WHEN 'co' THEN u.phone ILIKE $4 WHEN 'sw' THEN u.phone ILIKE $4 ELSE TRUE END \
          WHEN 'active' THEN CASE $3::text WHEN 'eq' THEN u.enabled = $4::text::boolean WHEN 'pr' THEN u.enabled IS NOT NULL ELSE FALSE END \
          WHEN 'id' THEN CASE $3::text WHEN 'eq' THEN u.id = $4::text::bigint WHEN 'pr' THEN u.id IS NOT NULL ELSE FALSE END \
          ELSE FALSE END) ",
        "ORDER BY u.id LIMIT $5 OFFSET $6"
    ),
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
    ],
    columns: SCIM_USER_COLS,
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_USERS_SYNC_LIST: SqlContract = SqlContract {
    id: "directory_sync.scim_users_sync_list",
    domain: "directory-sync",
    sql: concat!(
        "SELECT u.id, l.external_subject, u.username, u.email, u.display_name, u.first_name, u.last_name, ",
        "u.job_title, u.phone, u.enabled, to_char(u.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), ",
        "to_char(u.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), ",
        pg_rfc3339!("u.updated_at"),
        ", (extract(epoch FROM u.updated_at) * 1000000)::bigint ",
        "FROM user_identity_links l JOIN users u ON u.id=l.user_id ",
        "WHERE l.source_id=$1 AND l.state='active' AND 'provision'=ANY(l.purposes) AND NOT is_guest_account(u.id) ",
        "AND u.updated_at > $2::text::timestamptz ORDER BY u.updated_at LIMIT $3"
    ),
    params: &[Type::INT8, Type::TEXT, Type::INT8],
    columns: SCIM_USER_COLS,
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_USERS_ALL_COUNT: SqlContract = SqlContract {
    id: "directory_sync.scim_users_all_count",
    domain: "directory-sync",
    sql: "SELECT COUNT(*) FROM user_identity_links l JOIN users u ON u.id=l.user_id \
          WHERE l.source_id=$1 AND l.state='active' AND 'provision'=ANY(l.purposes) AND NOT is_guest_account(u.id)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_USERS_ALL_LIST: SqlContract = SqlContract {
    id: "directory_sync.scim_users_all_list",
    domain: "directory-sync",
    sql: concat!(
        "SELECT u.id, l.external_subject, u.username, u.email, u.display_name, u.first_name, u.last_name, ",
        "u.job_title, u.phone, u.enabled, to_char(u.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), ",
        "to_char(u.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), ",
        pg_rfc3339!("u.updated_at"),
        ", (extract(epoch FROM u.updated_at) * 1000000)::bigint ",
        "FROM user_identity_links l JOIN users u ON u.id=l.user_id ",
        "WHERE l.source_id=$1 AND l.state='active' AND 'provision'=ANY(l.purposes) AND NOT is_guest_account(u.id) ",
        "ORDER BY u.id LIMIT $2 OFFSET $3"
    ),
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: SCIM_USER_COLS,
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_USER_GET: SqlContract = SqlContract {
    id: "directory_sync.scim_user_get",
    domain: "directory-sync",
    sql: concat!(
        "SELECT u.id, l.external_subject, u.username, u.email, u.display_name, u.first_name, u.last_name, ",
        "u.job_title, u.phone, u.enabled, to_char(u.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), ",
        "to_char(u.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), ",
        pg_rfc3339!("u.updated_at"),
        ", (extract(epoch FROM u.updated_at) * 1000000)::bigint ",
        "FROM user_identity_links l JOIN users u ON u.id=l.user_id ",
        "WHERE l.source_id=$1 AND u.id=$2 AND l.state='active' AND 'provision'=ANY(l.purposes) AND NOT is_guest_account(u.id)"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: SCIM_USER_COLS,
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_SOURCE_SUBJECT: SqlContract = SqlContract {
    id: "directory_sync.scim_source_subject",
    domain: "directory-sync",
    sql: "SELECT l.external_subject FROM user_identity_links l \
          WHERE l.source_id = $1 AND l.user_id = $2 AND l.state = 'active' AND 'provision' = ANY(l.purposes)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::named("external_subject", Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_USER_FOR_PATCH: SqlContract = SqlContract {
    id: "directory_sync.scim_user_for_patch",
    domain: "directory-sync",
    sql: "SELECT l.external_subject,u.username,u.email,u.display_name,u.first_name,u.last_name,\
          u.job_title,u.phone,d.path,u.enabled FROM user_identity_links l JOIN users u ON u.id=l.user_id \
          LEFT JOIN departments d ON d.id=u.department_id WHERE l.source_id=$1 AND u.id=$2 \
          AND l.state='active' AND 'provision'=ANY(l.purposes) AND NOT is_guest_account(u.id)",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("external_subject", Type::TEXT),
        ColumnSpec::named("username", Type::TEXT),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::named("display_name", Type::TEXT),
        ColumnSpec::named("first_name", Type::TEXT),
        ColumnSpec::named("last_name", Type::TEXT),
        ColumnSpec::named("job_title", Type::TEXT),
        ColumnSpec::named("phone", Type::TEXT),
        ColumnSpec::named("path", Type::TEXT),
        ColumnSpec::named("enabled", Type::BOOL),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_USER_APPLY: SqlContract = SqlContract {
    id: "directory_sync.scim_user_apply",
    domain: "directory-sync",
    sql: "SELECT identity_source_scim_apply($1,$2,$3::text::uuid,$4,$5::text::jsonb)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_GROUP_TOTAL: SqlContract = SqlContract {
    id: "directory_sync.scim_group_total",
    domain: "directory-sync",
    sql: "SELECT COUNT(*) FROM distribution_groups WHERE scim_source_id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_GROUP_LIST: SqlContract = SqlContract {
    id: "directory_sync.scim_group_list",
    domain: "directory-sync",
    sql: "SELECT dg.id, dg.scim_external_id, mb.display_name, to_char(dg.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
          FROM distribution_groups dg JOIN mailboxes mb ON mb.id = dg.mailbox_id \
          WHERE dg.scim_source_id=$1 ORDER BY dg.id LIMIT $2 OFFSET $3",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("scim_external_id", Type::TEXT),
        ColumnSpec::named("display_name", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_GROUP_GET: SqlContract = SqlContract {
    id: "directory_sync.scim_group_get",
    domain: "directory-sync",
    sql: "SELECT dg.id, dg.scim_external_id, mb.display_name, to_char(dg.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
          FROM distribution_groups dg JOIN mailboxes mb ON mb.id = dg.mailbox_id \
          WHERE dg.id=$1 AND dg.scim_source_id=$2",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("scim_external_id", Type::TEXT),
        ColumnSpec::named("display_name", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_GROUP_MEMBERS: SqlContract = SqlContract {
    id: "directory_sync.scim_group_members",
    domain: "directory-sync",
    sql: "SELECT l.external_subject, COALESCE(u.display_name, ''), u.id FROM distribution_group_members dgm \
          JOIN mailboxes mb ON mb.id = dgm.mailbox_id JOIN users u ON u.id = mb.user_id \
          JOIN user_identity_links l ON l.user_id=u.id JOIN distribution_groups dg ON dg.id=dgm.group_id \
          WHERE dgm.group_id=$1 AND dg.scim_source_id=$2 AND l.source_id=$2 AND l.state='active' \
          AND 'provision'=ANY(l.purposes) AND NOT is_guest_account(u.id) ORDER BY u.display_name",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("external_subject", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("id", Type::INT8),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_GROUP_EXTERNAL_ID: SqlContract = SqlContract {
    id: "directory_sync.scim_group_external_id",
    domain: "directory-sync",
    sql: "SELECT COALESCE(scim_external_id, '') FROM distribution_groups WHERE id=$1 AND scim_source_id=$2",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_GROUP_CREATE: SqlContract = SqlContract {
    id: "directory_sync.scim_group_create",
    domain: "directory-sync",
    sql: "SELECT g.id FROM (SELECT scim_upsert_group($1,$2,$3,$4) AS id) g, \
          LATERAL (SELECT scim_apply_group_members($1,$2,$3,$5,TRUE) AS applied OFFSET 0) m",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT_ARRAY,
    ],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_GROUP_UPSERT: SqlContract = SqlContract {
    id: "directory_sync.scim_group_upsert",
    domain: "directory-sync",
    sql: "SELECT scim_upsert_group($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_GROUP_REMOVE_MEMBERS: SqlContract = SqlContract {
    id: "directory_sync.scim_group_remove_members",
    domain: "directory-sync",
    sql: "SELECT scim_remove_group_members($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_GROUP_APPLY_MEMBERS: SqlContract = SqlContract {
    id: "directory_sync.scim_group_apply_members",
    domain: "directory-sync",
    sql: "SELECT scim_apply_group_members($1,$2,$3,$4,$5)",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT_ARRAY,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCIM_GROUP_DELETE: SqlContract = SqlContract {
    id: "directory_sync.scim_group_delete",
    domain: "directory-sync",
    sql: "SELECT scim_delete_group($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- Welcome email ----

pub const WELCOME_SENTINEL_EXISTS: SqlContract = SqlContract {
    id: "directory_sync.welcome_sentinel_exists",
    domain: "directory-sync",
    sql: "SELECT EXISTS (SELECT 1 FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id \
          WHERE mb.user_id = $1 AND m.raw_ref = $2)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WELCOME_CONFIG_GET: SqlContract = SqlContract {
    id: "directory_sync.welcome_config_get",
    domain: "directory-sync",
    sql: "SELECT get_system_config('welcome_email')::text",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WELCOME_PRIMARY_MAILBOX: SqlContract = SqlContract {
    id: "directory_sync.welcome_primary_mailbox",
    domain: "directory-sync",
    sql: "SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WELCOME_RECIPIENT_PROFILE: SqlContract = SqlContract {
    id: "directory_sync.welcome_recipient_profile",
    domain: "directory-sync",
    sql: "SELECT u.display_name, u.username, COALESCE(mb.email, u.email) FROM mailboxes mb \
          JOIN users u ON u.id = mb.user_id WHERE mb.id = $1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("display_name", Type::TEXT),
        ColumnSpec::named("username", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WELCOME_DELIVER: SqlContract = SqlContract {
    id: "directory_sync.welcome_deliver",
    domain: "directory-sync",
    sql: "SELECT deliver($1,$2,$3,$4,$5,$6::text::jsonb,$7::text::jsonb,$8::text::jsonb,$9,$10,$11,$12,$13,$14,FALSE,now(),$15,$16,$17,0.0::real,$18::text::jsonb)",
    params: &[
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
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    CONSOLE_DENIED,
    CONFIG_AD,
    CONFIG_LDAP,
    CONFIG_KEY_EXISTS,
    CONFIG_UPSERT_BATCH_ENCRYPTED,
    SYNC_LOG,
    HEALTH_LAST_SYNC,
    HEALTH_PENDING_CONFLICTS,
    CONFLICTS_LIST,
    CONFLICT_RESOLVE_ONE,
    CONFLICT_RESOLVE_ALL,
    FIELD_POLICY_GET_PERM,
    FIELD_POLICY_GET_ANY_GRANT,
    FIELD_POLICY_GET_FOREIGN,
    ADMIN_CAN_REACH,
    ADMIN_CAN_REACH_PERM,
    FIELD_POLICY_DELETE,
    FIELD_POLICY_UPSERT,
    PRINCIPAL_CURRENT,
    PRINCIPAL_SET,
    SCIM_TOKEN_BY_HASH,
    SCIM_LEGACY_TOKENS,
    SCIM_RECORD_USAGE,
    SCIM_USERS_FILTER_COUNT,
    SCIM_USERS_FILTER_LIST,
    SCIM_USERS_SYNC_LIST,
    SCIM_USERS_ALL_COUNT,
    SCIM_USERS_ALL_LIST,
    SCIM_USER_GET,
    SCIM_SOURCE_SUBJECT,
    SCIM_USER_FOR_PATCH,
    SCIM_USER_APPLY,
    SCIM_GROUP_TOTAL,
    SCIM_GROUP_LIST,
    SCIM_GROUP_GET,
    SCIM_GROUP_MEMBERS,
    SCIM_GROUP_EXTERNAL_ID,
    SCIM_GROUP_CREATE,
    SCIM_GROUP_UPSERT,
    SCIM_GROUP_REMOVE_MEMBERS,
    SCIM_GROUP_APPLY_MEMBERS,
    SCIM_GROUP_DELETE,
    WELCOME_SENTINEL_EXISTS,
    WELCOME_CONFIG_GET,
    WELCOME_PRIMARY_MAILBOX,
    WELCOME_RECIPIENT_PROFILE,
    WELCOME_DELIVER,
];

#[allow(dead_code)]
const _SCIM_FILTER_DOC_CHECK: &str = SCIM_FILTER_PREDICATE;
