//! Static typed SQL contract catalog for `setjoin-conditional-access` (F03).
use setjoin_sql_catalog::{
    pg_rfc3339, ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type,
};

// ---- Shared console denial audit ----

pub const CONSOLE_DENIED: SqlContract = SqlContract {
    id: "conditional_access.console_denied",
    domain: "conditional-access",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- Policy reach / priority / list / impact / writes ----

pub const PRIORITY_ALLOWED: SqlContract = SqlContract {
    id: "conditional_access.priority_allowed",
    domain: "conditional-access",
    sql: "SELECT $4::boolean OR (rust_ca_priority_ok($1, $2, '{access.policy_write}'::text[]) \
          AND COALESCE(rust_ca_audit_priority_ok($1, $3, '{access.policy_write}'::text[]), true))",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_GATE_READ: SqlContract = SqlContract {
    id: "conditional_access.policy_gate_read",
    domain: "conditional-access",
    sql: "SELECT CASE WHEN $6::boolean THEN 'ok' \
          WHEN $2::bigint IS NOT NULL AND (rust_ca_policy_row_reach($1, $2, '{access.policy_read,access.policy_write}'::text[]) IS FALSE \
               OR (rust_ca_policy_row_reach($1, $2, '{access.policy_read,access.policy_write}'::text[]) IS NULL \
                   AND NOT admin_org_wide_grant($1, '{access.policy_read,access.policy_write}'::text[]))) THEN 'row' \
          WHEN $3::bigint IS NOT NULL AND rust_ca_policy_audit_reach($1, $3, '{access.policy_read,access.policy_write}'::text[]) IS NOT DISTINCT FROM false THEN 'row' \
          WHEN $4::text IS NOT NULL AND NOT rust_ca_policy_scope_reach($1, $4, $5, '{access.policy_read,access.policy_write}'::text[]) THEN 'scope' \
          ELSE 'ok' END",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_GATE_WRITE: SqlContract = SqlContract {
    id: "conditional_access.policy_gate_write",
    domain: "conditional-access",
    sql: "SELECT CASE WHEN $6::boolean THEN 'ok' \
          WHEN $2::bigint IS NOT NULL AND (rust_ca_policy_row_reach($1, $2, '{access.policy_write}'::text[]) IS FALSE \
               OR (rust_ca_policy_row_reach($1, $2, '{access.policy_write}'::text[]) IS NULL \
                   AND NOT admin_org_wide_grant($1, '{access.policy_write}'::text[]))) THEN 'row' \
          WHEN $3::bigint IS NOT NULL AND rust_ca_policy_audit_reach($1, $3, '{access.policy_write}'::text[]) IS NOT DISTINCT FROM false THEN 'row' \
          WHEN $4::text IS NOT NULL AND NOT rust_ca_policy_scope_reach($1, $4, $5, '{access.policy_write}'::text[]) THEN 'scope' \
          ELSE 'ok' END",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_IN_REACH: SqlContract = SqlContract {
    id: "conditional_access.user_in_reach",
    domain: "conditional-access",
    sql: "SELECT admin_org_wide_grant($1, '{access.policy_read,access.policy_write}'::text[]) \
          OR admin_can_reach_perm($1, $2, '{access.policy_read,access.policy_write}'::text[])",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ORG_WIDE_READ: SqlContract = SqlContract {
    id: "conditional_access.org_wide_read",
    domain: "conditional-access",
    sql: "SELECT admin_org_wide_grant($1, '{access.policy_read,access.policy_write}'::text[])",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ORG_WIDE_WRITE: SqlContract = SqlContract {
    id: "conditional_access.org_wide_write",
    domain: "conditional-access",
    sql: "SELECT admin_org_wide_grant($1, '{access.policy_write}'::text[])",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ORG_WIDE_WRITE_CHECK: SqlContract = SqlContract {
    id: "conditional_access.org_wide_write_check",
    domain: "conditional-access",
    sql: "SELECT $2::boolean OR public.admin_org_wide_grant($1, '{access.policy_write}'::text[])",
    params: &[Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_LIST: SqlContract = SqlContract {
    id: "conditional_access.policy_list",
    domain: "conditional-access",
    sql: "SELECT id, priority, name, description, state, scope_type, scope_target, \
          conditions::text, actions::text, exclude_users::text, exclude_groups::text, \
          session_control::text, created_at::text, updated_at::text, deleted_at::text \
          FROM conditional_access_policies \
          WHERE ($2::boolean OR rust_ca_policy_scope_reach($1, scope_type, scope_target, '{access.policy_read,access.policy_write}'::text[])) \
            AND ($3::boolean OR deleted_at IS NULL) \
          ORDER BY priority ASC",
    params: &[Type::INT8, Type::BOOL, Type::BOOL],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("priority", Type::INT4),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("description", Type::TEXT),
        ColumnSpec::named("state", Type::TEXT),
        ColumnSpec::named("scope_type", Type::TEXT),
        ColumnSpec::named("scope_target", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_SAVE_CHECK: SqlContract = SqlContract {
    id: "conditional_access.policy_save_check",
    domain: "conditional-access",
    sql: "SELECT ($6::boolean OR (rust_ca_policy_scope_reach($1, $3, $4, '{access.policy_write}'::text[]) \
               AND COALESCE(rust_ca_policy_row_reach($1, $2, '{access.policy_write}'::text[]), true))) \
          AND ($7::boolean OR rust_ca_priority_ok($1, $5, '{access.policy_write}'::text[]))",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::BOOL,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_SAVE: SqlContract = SqlContract {
    id: "conditional_access.policy_save",
    domain: "conditional-access",
    sql: "SELECT rust_ca_policy_save($1,$2::text::inet,$3,$4::text::jsonb,$5::text::jsonb,$6::text::jsonb)::text",
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

pub const POLICY_LOCK_FENCE: SqlContract = SqlContract {
    id: "conditional_access.policy_lock_fence",
    domain: "conditional-access",
    sql: "SELECT public.ca_reachability_fence()",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_LOCK_ROW: SqlContract = SqlContract {
    id: "conditional_access.policy_lock_row",
    domain: "conditional-access",
    sql: "SELECT id FROM conditional_access_policies WHERE id = $1 FOR UPDATE",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_LOCK_ROWS: SqlContract = SqlContract {
    id: "conditional_access.policy_lock_rows",
    domain: "conditional-access",
    sql: "SELECT id FROM conditional_access_policies WHERE id = ANY($1::bigint[]) ORDER BY id FOR UPDATE",
    params: &[Type::INT8_ARRAY],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_ROW_REACH_WRITE: SqlContract = SqlContract {
    id: "conditional_access.policy_row_reach_write",
    domain: "conditional-access",
    sql: "SELECT $3::boolean OR COALESCE(rust_ca_policy_row_reach($1, $2, '{access.policy_write}'::text[]), true)",
    params: &[Type::INT8, Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_SOFT_DELETE: SqlContract = SqlContract {
    id: "conditional_access.policy_soft_delete",
    domain: "conditional-access",
    sql: "SELECT public.rust_ca_policy_soft_delete($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const POLICY_RESTORE: SqlContract = SqlContract {
    id: "conditional_access.policy_restore",
    domain: "conditional-access",
    sql: "SELECT public.rust_ca_policy_restore($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const POLICY_RESTORE_FROM_AUDIT_CHECK: SqlContract = SqlContract {
    id: "conditional_access.policy_restore_from_audit_check",
    domain: "conditional-access",
    sql: "SELECT ($3::boolean OR COALESCE(rust_ca_policy_audit_reach($1, $2, '{access.policy_write}'::text[]), true)) \
          AND ($4::boolean OR COALESCE(rust_ca_audit_priority_ok($1, $2, '{access.policy_write}'::text[]), true))",
    params: &[Type::INT8, Type::INT8, Type::BOOL, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_RESTORE_FROM_AUDIT: SqlContract = SqlContract {
    id: "conditional_access.policy_restore_from_audit",
    domain: "conditional-access",
    sql: "SELECT public.rust_ca_policy_restore_from_audit($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const POLICY_REORDER_CHECK: SqlContract = SqlContract {
    id: "conditional_access.policy_reorder_check",
    domain: "conditional-access",
    sql: "SELECT $3::boolean OR NOT EXISTS (SELECT 1 FROM unnest($2::bigint[]) i \
          WHERE rust_ca_policy_row_reach($1, i, '{access.policy_write}'::text[]) IS NOT DISTINCT FROM false)",
    params: &[Type::INT8, Type::INT8_ARRAY, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_REORDER: SqlContract = SqlContract {
    id: "conditional_access.policy_reorder",
    domain: "conditional-access",
    sql: "SELECT rust_ca_policy_reorder($1,$2::text::inet,$3)",
    params: &[Type::INT8, Type::TEXT, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const POLICY_REORDER_MUTANT: SqlContract = SqlContract {
    id: "conditional_access.policy_reorder_mutant",
    domain: "conditional-access",
    sql: "SELECT ca_policy_reorder($1,$2::text::inet,$3)",
    params: &[Type::INT8, Type::TEXT, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const POLICY_IMPACT_7D: SqlContract = SqlContract {
    id: "conditional_access.policy_impact_7d",
    domain: "conditional-access",
    sql: "SELECT ca_policy_impact($1, '7d', $2::text)::text \
          WHERE $4::boolean OR COALESCE(rust_ca_policy_row_reach($3, $1, '{access.policy_read,access.policy_write}'::text[]), true)",
    params: &[Type::INT8, Type::TEXT, Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_PROMOTE: SqlContract = SqlContract {
    id: "conditional_access.policy_promote",
    domain: "conditional-access",
    sql: "SELECT public.rust_ca_policy_promote($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- Named locations ----

pub const LOCATIONS_LIST: SqlContract = SqlContract {
    id: "conditional_access.locations_list",
    domain: "conditional-access",
    sql: concat!(
        "SELECT id, name, description, ip_ranges::text, countries::text, is_trusted, ",
        pg_rfc3339!("created_at"),
        ", ",
        pg_rfc3339!("updated_at"),
        ", CASE WHEN deleted_at IS NULL THEN NULL ELSE ",
        pg_rfc3339!("deleted_at"),
        " END FROM named_locations WHERE ($1::boolean OR deleted_at IS NULL) ORDER BY name ASC"
    ),
    params: &[Type::BOOL],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("description", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("is_trusted", Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOCATION_SET: SqlContract = SqlContract {
    id: "conditional_access.location_set",
    domain: "conditional-access",
    sql: "SELECT public.rust_ca_named_location_set($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT_ARRAY,
        Type::TEXT_ARRAY,
        Type::BOOL,
        Type::BOOL,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const LOCATION_RESTORE: SqlContract = SqlContract {
    id: "conditional_access.location_restore",
    domain: "conditional-access",
    sql: "SELECT public.rust_ca_named_location_restore($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- Authentication strengths ----

pub const STRENGTHS_LIST: SqlContract = SqlContract {
    id: "conditional_access.strengths_list",
    domain: "conditional-access",
    sql: concat!(
        "SELECT id, slug, name, description, requirement::text, min_acr, builtin, ",
        pg_rfc3339!("created_at"),
        ", ",
        pg_rfc3339!("updated_at"),
        " FROM auth_strengths ORDER BY builtin DESC, name ASC"
    ),
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("slug", Type::TEXT),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("description", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("min_acr", Type::TEXT),
        ColumnSpec::named("builtin", Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const STRENGTH_SET: SqlContract = SqlContract {
    id: "conditional_access.strength_set",
    domain: "conditional-access",
    sql: "SELECT public.rust_ca_auth_strength_set($1,$2,$3,$4,$5::text::jsonb,$6,$7,$8)",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- Console reads and writes ----

pub const USERS_BY_IDS: SqlContract = SqlContract {
    id: "conditional_access.users_by_ids",
    domain: "conditional-access",
    sql: "SELECT id, COALESCE(email,''), COALESCE(display_name,'') FROM users WHERE id = ANY($1)",
    params: &[Type::INT8_ARRAY],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const GROUPS_BY_IDS: SqlContract = SqlContract {
    id: "conditional_access.groups_by_ids",
    domain: "conditional-access",
    sql: "SELECT id, name FROM rust_ca_resolve_user_groups($1)",
    params: &[Type::INT8_ARRAY],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BREAK_GLASS_GET: SqlContract = SqlContract {
    id: "conditional_access.break_glass_get",
    domain: "conditional-access",
    sql: "SELECT value::text FROM system_config WHERE key = 'ca_break_glass_user_ids'",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BREAK_GLASS_SET: SqlContract = SqlContract {
    id: "conditional_access.break_glass_set",
    domain: "conditional-access",
    sql: "SELECT ca_break_glass_set($1,$2::text::inet,$3)",
    params: &[Type::INT8, Type::TEXT, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

const SIGNIN_COLS: &[ColumnSpec] = &[
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("user_id", Type::INT8),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("protocol", Type::TEXT),
    ColumnSpec::named("client_type", Type::TEXT),
    ColumnSpec::named("device_fp", Type::TEXT),
    ColumnSpec::named("country", Type::TEXT),
    ColumnSpec::named("matched_policy_id", Type::INT8),
    ColumnSpec::named("decision", Type::TEXT),
    ColumnSpec::named("would_decision", Type::TEXT),
    ColumnSpec::named("report_only", Type::BOOL),
    ColumnSpec::named("correlation_id", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
];

pub const SIGNIN_LOG_BY_CORRELATION: SqlContract = SqlContract {
    id: "conditional_access.signin_log_by_correlation",
    domain: "conditional-access",
    sql: concat!(
        "SELECT id, ",
        pg_rfc3339!("occurred_at"),
        ", user_id, CASE WHEN source_ip IS NULL THEN NULL WHEN masklen(source_ip) = (CASE family(source_ip) WHEN 4 THEN 32 ELSE 128 END) THEN host(source_ip) ELSE source_ip::text END, \
         protocol, client_type, device_fp, country, matched_policy_id, decision, would_decision, report_only, correlation_id, evaluated::text \
         FROM ca_signin_log WHERE correlation_id = $1 ORDER BY occurred_at DESC LIMIT $2"
    ),
    params: &[Type::TEXT, Type::INT8],
    columns: SIGNIN_COLS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SIGNIN_LOG_BY_USER: SqlContract = SqlContract {
    id: "conditional_access.signin_log_by_user",
    domain: "conditional-access",
    sql: concat!(
        "SELECT id, ",
        pg_rfc3339!("occurred_at"),
        ", user_id, CASE WHEN source_ip IS NULL THEN NULL WHEN masklen(source_ip) = (CASE family(source_ip) WHEN 4 THEN 32 ELSE 128 END) THEN host(source_ip) ELSE source_ip::text END, \
         protocol, client_type, device_fp, country, matched_policy_id, decision, would_decision, report_only, correlation_id, evaluated::text \
         FROM ca_signin_log WHERE user_id = $1 ORDER BY occurred_at DESC LIMIT $2"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: SIGNIN_COLS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_EXISTS: SqlContract = SqlContract {
    id: "conditional_access.user_exists",
    domain: "conditional-access",
    sql: "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_ID_BY_EMAIL: SqlContract = SqlContract {
    id: "conditional_access.user_id_by_email",
    domain: "conditional-access",
    sql: "SELECT id FROM users WHERE email = $1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WHY_BY_CORRELATION: SqlContract = SqlContract {
    id: "conditional_access.why_by_correlation",
    domain: "conditional-access",
    sql: concat!(
        "SELECT id, ",
        pg_rfc3339!("occurred_at"),
        ", user_id, CASE WHEN source_ip IS NULL THEN NULL WHEN masklen(source_ip) = (CASE family(source_ip) WHEN 4 THEN 32 ELSE 128 END) THEN host(source_ip) ELSE source_ip::text END, \
         protocol, client_type, device_fp, country, matched_policy_id, decision, would_decision, report_only, correlation_id, evaluated::text \
         FROM ca_signin_log WHERE correlation_id = $1 AND occurred_at >= now() - make_interval(secs => $2::bigint::double precision) ORDER BY occurred_at DESC"
    ),
    params: &[Type::TEXT, Type::INT8],
    columns: SIGNIN_COLS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WHY_BY_USER_AND_CORRELATION: SqlContract = SqlContract {
    id: "conditional_access.why_by_user_and_correlation",
    domain: "conditional-access",
    sql: concat!(
        "SELECT id, ",
        pg_rfc3339!("occurred_at"),
        ", user_id, CASE WHEN source_ip IS NULL THEN NULL WHEN masklen(source_ip) = (CASE family(source_ip) WHEN 4 THEN 32 ELSE 128 END) THEN host(source_ip) ELSE source_ip::text END, \
         protocol, client_type, device_fp, country, matched_policy_id, decision, would_decision, report_only, correlation_id, evaluated::text \
         FROM ca_signin_log WHERE user_id = $1 AND correlation_id = $2 AND occurred_at >= now() - make_interval(secs => $3::bigint::double precision) ORDER BY occurred_at DESC"
    ),
    params: &[Type::INT8, Type::TEXT, Type::INT8],
    columns: SIGNIN_COLS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WHY_BY_USER: SqlContract = SqlContract {
    id: "conditional_access.why_by_user",
    domain: "conditional-access",
    sql: concat!(
        "SELECT id, ",
        pg_rfc3339!("occurred_at"),
        ", user_id, CASE WHEN source_ip IS NULL THEN NULL WHEN masklen(source_ip) = (CASE family(source_ip) WHEN 4 THEN 32 ELSE 128 END) THEN host(source_ip) ELSE source_ip::text END, \
         protocol, client_type, device_fp, country, matched_policy_id, decision, would_decision, report_only, correlation_id, evaluated::text \
         FROM ca_signin_log WHERE user_id = $1 AND occurred_at >= now() - make_interval(secs => $2::bigint::double precision) ORDER BY occurred_at DESC LIMIT 200"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: SIGNIN_COLS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CAN_REACH_PERM: SqlContract = SqlContract {
    id: "conditional_access.can_reach_perm",
    domain: "conditional-access",
    sql: "SELECT admin_can_reach_perm($1, $2, '{access.policy_write}'::text[])",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CAN_REACH_ANY: SqlContract = SqlContract {
    id: "conditional_access.can_reach_any",
    domain: "conditional-access",
    sql: "SELECT admin_can_reach($1, $2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REVOKE_USER_SESSIONS: SqlContract = SqlContract {
    id: "conditional_access.revoke_user_sessions",
    domain: "conditional-access",
    sql: "SELECT public.rust_ca_revoke_user_sessions($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const SESSIONS_LOG: SqlContract = SqlContract {
    id: "conditional_access.sessions_log",
    domain: "conditional-access",
    sql: "SELECT id, user_id, scope, reason, created_by, created_at::text \
          FROM session_revocations \
          WHERE $2::boolean \
             OR admin_org_wide_grant($1, '{access.policy_read,access.policy_write}'::text[]) \
             OR admin_can_reach_perm($1, user_id, '{access.policy_read,access.policy_write}'::text[]) \
          ORDER BY created_at DESC LIMIT 200",
    params: &[Type::INT8, Type::BOOL],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("user_id", Type::INT8),
        ColumnSpec::named("scope", Type::TEXT),
        ColumnSpec::named("reason", Type::TEXT),
        ColumnSpec::named("created_by", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TEMPLATES_LIST: SqlContract = SqlContract {
    id: "conditional_access.templates_list",
    domain: "conditional-access",
    sql: "SELECT id, slug, name, description, scope_type, scope_target, conditions::text, actions::text, \
          suggested_priority, created_at::text FROM ca_templates ORDER BY suggested_priority ASC",
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("slug", Type::TEXT),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("description", Type::TEXT),
        ColumnSpec::named("scope_type", Type::TEXT),
        ColumnSpec::named("scope_target", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("suggested_priority", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TEMPLATE_INSTANTIATE: SqlContract = SqlContract {
    id: "conditional_access.template_instantiate",
    domain: "conditional-access",
    sql: "SELECT public.rust_ca_template_instantiate($1,$2)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const POLICY_INSTANTIATED_GET: SqlContract = SqlContract {
    id: "conditional_access.policy_instantiated_get",
    domain: "conditional-access",
    sql: "SELECT (to_jsonb(c) - 'enabled')::text FROM conditional_access_policies c WHERE id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const COVERAGE_REPORT: SqlContract = SqlContract {
    id: "conditional_access.coverage_report",
    domain: "conditional-access",
    sql: "SELECT ca_coverage_report()::text",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_IMPACT: SqlContract = SqlContract {
    id: "conditional_access.policy_impact",
    domain: "conditional-access",
    sql: "SELECT ca_policy_impact($1, $2, $3::text)::text \
          WHERE $5::boolean OR COALESCE(rust_ca_policy_row_reach($4, $1, '{access.policy_read,access.policy_write}'::text[]), true)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_IMPORT: SqlContract = SqlContract {
    id: "conditional_access.policy_import",
    domain: "conditional-access",
    sql: "SELECT public.rust_ca_policy_import($1,$2::text::jsonb,$3)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const DOCTOR_FEATURE_ON: SqlContract = SqlContract {
    id: "conditional_access.doctor_feature_on",
    domain: "conditional-access",
    sql: "SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.conditional_access'), false)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DOCTOR_BREAK_GLASS: SqlContract = SqlContract {
    id: "conditional_access.doctor_break_glass",
    domain: "conditional-access",
    sql: "SELECT EXISTS (SELECT 1 FROM system_config WHERE key = 'ca_break_glass_user_ids' AND jsonb_array_length(value) > 0)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DOCTOR_REPORT_ONLY: SqlContract = SqlContract {
    id: "conditional_access.doctor_report_only",
    domain: "conditional-access",
    sql: "SELECT EXISTS (SELECT 1 FROM conditional_access_policies WHERE state = 'report_only' AND deleted_at IS NULL)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DOCTOR_STALE_REPORT_ONLY: SqlContract = SqlContract {
    id: "conditional_access.doctor_stale_report_only",
    domain: "conditional-access",
    sql: "SELECT id, name, state, EXTRACT(DAY FROM now() - created_at)::bigint AS days_since \
          FROM conditional_access_policies WHERE state = 'report_only' AND deleted_at IS NULL \
          AND created_at < now() - INTERVAL '30 days' ORDER BY created_at",
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("state", Type::TEXT),
        ColumnSpec::named("days_since", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DOCTOR_TIME_TO_FIRST_POLICY: SqlContract = SqlContract {
    id: "conditional_access.doctor_time_to_first_policy",
    domain: "conditional-access",
    sql: "SELECT CASE WHEN c IS NOT NULL AND p IS NOT NULL AND p > c \
          THEN floor(extract(epoch FROM (p - c)))::bigint END \
          FROM (SELECT (SELECT MIN(occurred_at) FROM admin_audit_log WHERE action = 'ca_policy_create') AS c, \
          (SELECT MIN(occurred_at) FROM admin_audit_log WHERE action = 'ca_policy_promote') AS p) t",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- Exchange (export / diff) ----

pub const EXPORT_POLICIES: SqlContract = SqlContract {
    id: "conditional_access.export_policies",
    domain: "conditional-access",
    sql: "SELECT name, description, priority, scope_type, scope_target, conditions::text, actions::text \
          FROM conditional_access_policies WHERE deleted_at IS NULL ORDER BY priority ASC",
    params: &[],
    columns: &[
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("description", Type::TEXT),
        ColumnSpec::named("priority", Type::INT4),
        ColumnSpec::named("scope_type", Type::TEXT),
        ColumnSpec::named("scope_target", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXPORT_LOCATIONS: SqlContract = SqlContract {
    id: "conditional_access.export_locations",
    domain: "conditional-access",
    sql: "SELECT id, name, ip_ranges::text, countries::text, is_trusted FROM named_locations WHERE deleted_at IS NULL",
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("is_trusted", Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXPORT_STRENGTHS: SqlContract = SqlContract {
    id: "conditional_access.export_strengths",
    domain: "conditional-access",
    sql: "SELECT id, slug, name, builtin, requirement::text, min_acr FROM auth_strengths",
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("slug", Type::TEXT),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("builtin", Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("min_acr", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DIFF_POLICIES: SqlContract = SqlContract {
    id: "conditional_access.diff_policies",
    domain: "conditional-access",
    sql: "SELECT name, conditions::text, actions::text FROM conditional_access_policies WHERE deleted_at IS NULL",
    params: &[],
    columns: &[
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- User risk ----

pub const USER_RISK_LIST: SqlContract = SqlContract {
    id: "conditional_access.user_risk_list",
    domain: "conditional-access",
    sql: "SELECT r.user_id, COALESCE(u.email, ''), r.score::int, r.level, r.signals::text, r.updated_at::text \
          FROM user_risk r JOIN users u ON u.id = r.user_id \
          WHERE r.level != 'none' ORDER BY r.score DESC LIMIT $1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("user_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::INT4),
        ColumnSpec::named("level", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_RISK_RESET: SqlContract = SqlContract {
    id: "conditional_access.user_risk_reset",
    domain: "conditional-access",
    sql: "UPDATE user_risk SET score=0, level='none', signals='[]'::jsonb, \
          remediated_at=now(), updated_at=now() WHERE user_id=$1 RETURNING user_id",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("user_id", Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    CONSOLE_DENIED,
    PRIORITY_ALLOWED,
    POLICY_GATE_READ,
    POLICY_GATE_WRITE,
    USER_IN_REACH,
    ORG_WIDE_READ,
    ORG_WIDE_WRITE,
    ORG_WIDE_WRITE_CHECK,
    POLICY_LIST,
    POLICY_SAVE_CHECK,
    POLICY_SAVE,
    POLICY_LOCK_FENCE,
    POLICY_LOCK_ROW,
    POLICY_LOCK_ROWS,
    POLICY_ROW_REACH_WRITE,
    POLICY_SOFT_DELETE,
    POLICY_RESTORE,
    POLICY_RESTORE_FROM_AUDIT_CHECK,
    POLICY_RESTORE_FROM_AUDIT,
    POLICY_REORDER_CHECK,
    POLICY_REORDER,
    POLICY_REORDER_MUTANT,
    POLICY_IMPACT_7D,
    POLICY_PROMOTE,
    LOCATIONS_LIST,
    LOCATION_SET,
    LOCATION_RESTORE,
    STRENGTHS_LIST,
    STRENGTH_SET,
    USERS_BY_IDS,
    GROUPS_BY_IDS,
    BREAK_GLASS_GET,
    BREAK_GLASS_SET,
    SIGNIN_LOG_BY_CORRELATION,
    SIGNIN_LOG_BY_USER,
    USER_EXISTS,
    USER_ID_BY_EMAIL,
    WHY_BY_CORRELATION,
    WHY_BY_USER_AND_CORRELATION,
    WHY_BY_USER,
    CAN_REACH_PERM,
    CAN_REACH_ANY,
    REVOKE_USER_SESSIONS,
    SESSIONS_LOG,
    TEMPLATES_LIST,
    TEMPLATE_INSTANTIATE,
    POLICY_INSTANTIATED_GET,
    COVERAGE_REPORT,
    POLICY_IMPACT,
    POLICY_IMPORT,
    DOCTOR_FEATURE_ON,
    DOCTOR_BREAK_GLASS,
    DOCTOR_REPORT_ONLY,
    DOCTOR_STALE_REPORT_ONLY,
    DOCTOR_TIME_TO_FIRST_POLICY,
    EXPORT_POLICIES,
    EXPORT_LOCATIONS,
    EXPORT_STRENGTHS,
    DIFF_POLICIES,
    USER_RISK_LIST,
    USER_RISK_RESET,
];
