//! Typed SQL contract catalog for `setjoin-admin-identity` (#546d).
//!
//! Every SQL statement executed by `setjoin-admin-identity` (and its gateway
//! worker-bypass adapter arms) is declared here as a static [`SqlContract`]
//! verified against live PostgreSQL 17 by `scripts/guards/check-rust-sql-contracts.sh`.
use setjoin_sql_catalog::{
    pg_rfc3339, ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type,
};

// ---- lib.rs (users, aliases, quota, app passwords, app access, sessions) ----

pub const CONSOLE_DENIED: SqlContract = SqlContract {
    id: "admin_identity.console_denied",
    domain: "admin-identity",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USERS_LIST: SqlContract = SqlContract {
    id: "admin_identity.users_list",
    domain: "admin-identity",
    sql: concat!(
        "SELECT id, email, display_name, enabled, is_local_admin, department_id, ",
        pg_rfc3339!("created_at"),
        " FROM users WHERE ($1::text IS NULL OR email ILIKE $1 OR display_name ILIKE $1) \
         AND ($2::bigint = 0 OR domain_id = $2) ORDER BY id DESC LIMIT $3 OFFSET $4"
    ),
    params: &[Type::TEXT, Type::INT8, Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::named("display_name", Type::TEXT),
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::named("is_local_admin", Type::BOOL),
        ColumnSpec::named("department_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USERS_FLAGS: SqlContract = SqlContract {
    id: "admin_identity.users_flags",
    domain: "admin-identity",
    sql: "SELECT u.id, (u.id = $2::bigint) AS is_self, \
          CASE WHEN a.is_super THEN true ELSE ea.perms <@ a.perms \
               AND NOT (cardinality(ea.perms) > 0 AND a.scope IS NOT NULL AND ea.scope IS NULL) \
               AND (cardinality(a.perms) = 0 OR admin_can_reach($2, u.id)) END AS manageable, \
          (SELECT m.id FROM mailboxes m WHERE m.user_id=u.id AND m.is_primary ORDER BY m.id LIMIT 1) AS mailbox_id \
          FROM unnest($1::bigint[]) AS u(id) CROSS JOIN LATERAL admin_effective_authority(u.id) AS ea \
          CROSS JOIN (SELECT EXISTS(SELECT 1 FROM admin_role_assignments WHERE user_id=$2 AND role_group_id=1 \
               AND (expires_at IS NULL OR expires_at > now())) AS is_super, a0.perms, a0.scope \
               FROM admin_effective_authority($2) AS a0) a",
    params: &[Type::INT8_ARRAY, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("is_self", Type::BOOL),
        ColumnSpec::named("manageable", Type::BOOL),
        ColumnSpec::named("mailbox_id", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_GET: SqlContract = SqlContract {
    id: "admin_identity.user_get",
    domain: "admin-identity",
    sql: concat!(
        "SELECT id, email, display_name, enabled, is_local_admin, department_id, ",
        pg_rfc3339!("created_at"),
        " FROM users WHERE id = $1 AND ($2::bigint = 0 OR domain_id = $2)"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::named("display_name", Type::TEXT),
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::named("is_local_admin", Type::BOOL),
        ColumnSpec::named("department_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_ALIASES: SqlContract = SqlContract {
    id: "admin_identity.user_aliases",
    domain: "admin-identity",
    sql: "SELECT a.id, a.email, a.is_primary FROM aliases a JOIN mailboxes m ON m.id = a.mailbox_id \
          JOIN users u ON u.id = m.user_id WHERE m.user_id = $1 AND ($2::bigint = 0 OR u.domain_id = $2) \
          ORDER BY a.is_primary DESC, a.email",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::named("is_primary", Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_QUOTA: SqlContract = SqlContract {
    id: "admin_identity.user_quota",
    domain: "admin-identity",
    sql: "SELECT quota_bytes, used_bytes, sending_quota_day, sending_sent_today FROM mailboxes \
          WHERE user_id = $1 AND is_primary = TRUE AND ($2::bigint = 0 OR domain_id = $2) LIMIT 1",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("quota_bytes", Type::INT8),
        ColumnSpec::named("used_bytes", Type::INT8),
        ColumnSpec::named("sending_quota_day", Type::INT4),
        ColumnSpec::named("sending_sent_today", Type::INT4),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_APP_PASSWORDS: SqlContract = SqlContract {
    id: "admin_identity.user_app_passwords",
    domain: "admin-identity",
    sql: concat!(
        "SELECT id, name, ",
        pg_rfc3339!("created_at"),
        ", ",
        pg_rfc3339!("last_used_at"),
        ", ",
        pg_rfc3339!("expires_at"),
        ", ",
        pg_rfc3339!("revoked_at"),
        " FROM app_passwords WHERE user_id = $1 \
         AND ($2::bigint = 0 OR user_id IN (SELECT id FROM users WHERE id = $1 AND domain_id = $2)) \
         ORDER BY revoked_at NULLS FIRST, created_at DESC"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_IS_GUEST_IN_SCOPE: SqlContract = SqlContract {
    id: "admin_identity.user_is_guest_in_scope",
    domain: "admin-identity",
    sql: "SELECT COALESCE((SELECT is_guest_account(u.id) FROM users u WHERE u.id = $1 \
          AND ($2::bigint = 0 OR COALESCE(guest_account_host_domain(u.id), u.domain_id) = $2)), FALSE)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_APP_ENTITLEMENTS: SqlContract = SqlContract {
    id: "admin_identity.user_app_entitlements",
    domain: "admin-identity",
    sql: "SELECT app, enabled FROM user_app_entitlements WHERE user_id = $1 AND ($2::bigint = 0 OR user_id IN \
          (SELECT u.id FROM users u WHERE u.id = $1 AND COALESCE(guest_account_host_domain(u.id), u.domain_id) = $2))",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("app", Type::TEXT),
        ColumnSpec::named("enabled", Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_EXISTS_IN_SCOPE: SqlContract = SqlContract {
    id: "admin_identity.user_exists_in_scope",
    domain: "admin-identity",
    sql: "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND ($2::bigint = 0 OR domain_id = $2))",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_SESSIONS: SqlContract = SqlContract {
    id: "admin_identity.user_sessions",
    domain: "admin-identity",
    sql: "SELECT id, kind, client_id, device, location, \
          to_char(last_used_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), auth_method FROM (\
          SELECT id::text AS id, 'oauth' AS kind, COALESCE(client_id,'') AS client_id, '' AS device, '' AS location, \
          COALESCE(last_used_at, issued_at) AS last_used_at, COALESCE(last_used_protocol,'') AS auth_method FROM oauth_tokens \
          WHERE user_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) AND previous_token_hash IS NULL \
          AND token_type IN ('refresh','xoauth2','app_password') \
          UNION ALL \
          SELECT id, 'web', '', COALESCE(user_agent,''), COALESCE(host(ip),''), last_seen_at, COALESCE(auth_method,'') FROM sessions \
          WHERE user_id = $1 AND expires_at > now()) s ORDER BY s.last_used_at DESC NULLS LAST",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::TEXT),
        ColumnSpec::named("kind", Type::TEXT),
        ColumnSpec::named("client_id", Type::TEXT),
        ColumnSpec::named("device", Type::TEXT),
        ColumnSpec::named("location", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("auth_method", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_QUOTA_SET: SqlContract = SqlContract {
    id: "admin_identity.user_quota_set",
    domain: "admin-identity",
    sql: "SELECT rust_mailbox_admin_set_quota($1, $2, $3, $4)",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_PRIMARY_MAILBOX: SqlContract = SqlContract {
    id: "admin_identity.user_primary_mailbox",
    domain: "admin-identity",
    sql: "SELECT id, domain_id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE \
          AND ($2::bigint = 0 OR domain_id = $2) LIMIT 1",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("domain_id", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ALIAS_DOMAIN_ALLOWED: SqlContract = SqlContract {
    id: "admin_identity.alias_domain_allowed",
    domain: "admin-identity",
    sql: "SELECT EXISTS (SELECT 1 FROM mailboxes m JOIN domains d ON d.id = m.domain_id \
          WHERE m.id = $1 AND m.domain_id = $2 AND lower(d.name) = lower(split_part($3::text, '@', 2)))",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_ALIAS_ADD: SqlContract = SqlContract {
    id: "admin_identity.user_alias_add",
    domain: "admin-identity",
    sql: "SELECT rust_mailbox_alias_add($1, $2, $3, $4, $5)",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_ALIAS_REMOVE: SqlContract = SqlContract {
    id: "admin_identity.user_alias_remove",
    domain: "admin-identity",
    sql: "SELECT rust_mailbox_alias_remove($1, $2, $3)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_APP_ACCESS_SET: SqlContract = SqlContract {
    id: "admin_identity.user_app_access_set",
    domain: "admin-identity",
    sql: "SELECT count(*)::bigint FROM (SELECT set_app_entitlement($1, $2, $3, $4) FROM (SELECT 1 \
          WHERE $5::bigint = 0 OR EXISTS (SELECT 1 FROM users u WHERE u.id = $1 \
                AND COALESCE(guest_account_host_domain(u.id), u.domain_id) = $5)) g) r",
    params: &[Type::INT8, Type::TEXT, Type::BOOL, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- lifecycle.rs ----

pub const PASSWORD_POLICY_LOAD: SqlContract = SqlContract {
    id: "admin_identity.password_policy_load",
    domain: "admin-identity",
    sql: "SELECT \
          COALESCE((SELECT (value->>0)::INT FROM system_config WHERE key = 'password_min_length'), 8), \
          COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key = 'password_require_uppercase'), true), \
          COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key = 'password_require_lowercase'), true), \
          COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key = 'password_require_digit'), true), \
          COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key = 'password_require_special'), true)",
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::INT4),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const COMMON_PASSWORD_EXISTS: SqlContract = SqlContract {
    id: "admin_identity.common_password_exists",
    domain: "admin-identity",
    sql: "SELECT EXISTS(SELECT 1 FROM common_passwords WHERE password_hash = $1)",
    params: &[Type::BYTEA],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_CAN_MANAGE: SqlContract = SqlContract {
    id: "admin_identity.admin_can_manage",
    domain: "admin-identity",
    sql: "SELECT admin_can_manage($1, $2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IS_GUEST_ACCOUNT: SqlContract = SqlContract {
    id: "admin_identity.is_guest_account",
    domain: "admin-identity",
    sql: "SELECT is_guest_account($1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_IN_SCOPE: SqlContract = SqlContract {
    id: "admin_identity.user_in_scope",
    domain: "admin-identity",
    sql: "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND ($2::bigint <= 0 OR domain_id = $2))",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RESET_EMAIL_SCOPED: SqlContract = SqlContract {
    id: "admin_identity.reset_email_scoped",
    domain: "admin-identity",
    sql: "SELECT email FROM users WHERE id = $1 AND COALESCE(guest_account_host_domain(id), domain_id) = $2",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::named("email", Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RESET_EMAIL_GLOBAL: SqlContract = SqlContract {
    id: "admin_identity.reset_email_global",
    domain: "admin-identity",
    sql: "SELECT email FROM users WHERE id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("email", Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LIFECYCLE_ENABLED: SqlContract = SqlContract {
    id: "admin_identity.lifecycle_enabled",
    domain: "admin-identity",
    sql: "SELECT mailbox_lifecycle_enabled()",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_SIGN_INS: SqlContract = SqlContract {
    id: "admin_identity.user_sign_ins",
    domain: "admin-identity",
    sql: "SELECT id, to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), source_ip, location, \
          device_name, platform, client, protocol, auth_method, success, fail_reason \
          FROM rust_admin_user_sign_ins($1, $2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("source_ip", Type::TEXT),
        ColumnSpec::named("location", Type::TEXT),
        ColumnSpec::named("device_name", Type::TEXT),
        ColumnSpec::named("platform", Type::TEXT),
        ColumnSpec::named("client", Type::TEXT),
        ColumnSpec::named("protocol", Type::TEXT),
        ColumnSpec::named("auth_method", Type::TEXT),
        ColumnSpec::named("success", Type::BOOL),
        ColumnSpec::named("fail_reason", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_CREATE: SqlContract = SqlContract {
    id: "admin_identity.user_create",
    domain: "admin-identity",
    sql: "SELECT rust_admin_user_create($1,$2,$3,$4,$5,$6,$7)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const USER_UPDATE: SqlContract = SqlContract {
    id: "admin_identity.user_update",
    domain: "admin-identity",
    sql: "SELECT rust_admin_user_update($1,$2,$3,$4,$5,$6)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_DELETE: SqlContract = SqlContract {
    id: "admin_identity.user_delete",
    domain: "admin-identity",
    sql: "SELECT rust_admin_user_delete($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_PASSWORD_RESET: SqlContract = SqlContract {
    id: "admin_identity.user_password_reset",
    domain: "admin-identity",
    sql: "SELECT admin_reset_password($1,$2,$3,$4,$5)",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const USER_SECURE: SqlContract = SqlContract {
    id: "admin_identity.user_secure",
    domain: "admin-identity",
    sql: "SELECT rust_admin_user_secure($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const APP_PASSWORD_REVOKE: SqlContract = SqlContract {
    id: "admin_identity.app_password_revoke",
    domain: "admin-identity",
    sql: "SELECT rust_admin_app_password_revoke($1,$2,$3,$4,$5,$6)",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const USER_IMPORT_ROW: SqlContract = SqlContract {
    id: "admin_identity.user_import_row",
    domain: "admin-identity",
    sql: "SELECT provision_account(p_email => $1, p_display_name => $2, p_password_hash => $3, p_is_local_admin => $4, \
          p_enabled => TRUE, p_sync_source => 'local', p_department_id => $5, p_quota_bytes => $6, p_create_only => TRUE, \
          p_actor => $7)::text",
    params: &[
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
        Type::INT8,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DEPARTMENT_IN_SCOPE: SqlContract = SqlContract {
    id: "admin_identity.department_in_scope",
    domain: "admin-identity",
    sql: "SELECT admin_scope_within($1, 'ou', $2, $3)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOCAL_DOMAIN: SqlContract = SqlContract {
    id: "admin_identity.local_domain",
    domain: "admin-identity",
    sql: "SELECT id FROM domains WHERE lower(name) = $1 AND is_local = TRUE LIMIT 1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- roles.rs ----

pub const ROLES_LIST: SqlContract = SqlContract {
    id: "admin_identity.roles_list",
    domain: "admin-identity",
    sql: concat!(
        "SELECT ",
        "rg.id, rg.name, rg.description, rg.permissions, rg.domain_scope, rg.is_builtin, \
         COALESCE((SELECT COUNT(*) FROM admin_role_assignments WHERE role_group_id = rg.id), 0)::bigint, \
         rg.created_at::TEXT, rg.updated_at::TEXT",
        " FROM admin_role_groups rg WHERE ($1::bigint <= 0 OR rg.domain_scope = $1::bigint) \
         ORDER BY rg.is_builtin DESC, rg.name ASC"
    ),
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("description", Type::TEXT),
        ColumnSpec::named("permissions", Type::TEXT_ARRAY),
        ColumnSpec::named("domain_scope", Type::INT8),
        ColumnSpec::named("is_builtin", Type::BOOL),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ROLE_GET: SqlContract = SqlContract {
    id: "admin_identity.role_get",
    domain: "admin-identity",
    sql: concat!(
        "SELECT ",
        "rg.id, rg.name, rg.description, rg.permissions, rg.domain_scope, rg.is_builtin, \
         COALESCE((SELECT COUNT(*) FROM admin_role_assignments WHERE role_group_id = rg.id), 0)::bigint, \
         rg.created_at::TEXT, rg.updated_at::TEXT",
        " FROM admin_role_groups rg WHERE rg.id = $1 AND ($2::bigint <= 0 OR rg.domain_scope = $2::bigint)"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("description", Type::TEXT),
        ColumnSpec::named("permissions", Type::TEXT_ARRAY),
        ColumnSpec::named("domain_scope", Type::INT8),
        ColumnSpec::named("is_builtin", Type::BOOL),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ROLE_MEMBERS: SqlContract = SqlContract {
    id: "admin_identity.role_members",
    domain: "admin-identity",
    sql: "SELECT ra.user_id, u.email, u.display_name, ra.domain_override, ra.granted_by, ra.granted_at::TEXT, \
          ra.expires_at::TEXT, \
          CASE WHEN act.is_super THEN true \
               ELSE ea.perms <@ act.perms \
                    AND NOT (cardinality(ea.perms) > 0 AND act.scope IS NOT NULL AND ea.scope IS NULL) \
                    AND (cardinality(act.perms) = 0 OR admin_can_reach($2::bigint, ra.user_id)) \
          END AS manageable, \
          ra.scope_type, ra.scope_id, ss.name \
          FROM admin_role_assignments ra \
          JOIN users u ON u.id = ra.user_id \
          CROSS JOIN LATERAL admin_effective_authority(ra.user_id) AS ea \
          CROSS JOIN (SELECT EXISTS(SELECT 1 FROM admin_role_assignments \
                       WHERE user_id=$2::bigint AND role_group_id=1 \
                       AND (expires_at IS NULL OR expires_at > now())) AS is_super, a0.perms, a0.scope \
                      FROM admin_effective_authority($2::bigint) AS a0) act \
          LEFT JOIN admin_scope_sets ss ON ra.scope_type='set' AND ss.id = ra.scope_id \
          WHERE ra.role_group_id = $1 \
          AND ($3::bigint <= 0 OR EXISTS (SELECT 1 FROM admin_role_groups rg \
                              WHERE rg.id = ra.role_group_id AND rg.domain_scope = $3::bigint)) \
          ORDER BY u.email",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("user_id", Type::INT8),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::named("display_name", Type::TEXT),
        ColumnSpec::named("domain_override", Type::INT8),
        ColumnSpec::named("granted_by", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("manageable", Type::BOOL),
        ColumnSpec::named("scope_type", Type::TEXT),
        ColumnSpec::named("scope_id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PERMISSIONS_CATALOG: SqlContract = SqlContract {
    id: "admin_identity.permissions_catalog",
    domain: "admin-identity",
    sql: "SELECT permission_key, category, description, is_sensitive FROM admin_permissions \
          ORDER BY category COLLATE \"C\", permission_key COLLATE \"C\"",
    params: &[],
    columns: &[
        ColumnSpec::named("permission_key", Type::TEXT),
        ColumnSpec::named("category", Type::TEXT),
        ColumnSpec::named("description", Type::TEXT),
        ColumnSpec::named("is_sensitive", Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_IN_DOMAIN: SqlContract = SqlContract {
    id: "admin_identity.user_in_domain",
    domain: "admin-identity",
    sql: "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND domain_id = $2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EFFECTIVE_AUTHORITY_ROWS: SqlContract = SqlContract {
    id: "admin_identity.effective_authority_rows",
    domain: "admin-identity",
    sql: "SELECT rg.permissions, COALESCE(ra.domain_override, rg.domain_scope) AS effective_scope \
          FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id = ra.role_group_id \
          WHERE ra.user_id = $1 AND (ra.expires_at IS NULL OR ra.expires_at > now()) \
          AND admin_assignment_active(ra.eligible, ra.activated_until)",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("permissions", Type::TEXT_ARRAY),
        ColumnSpec::named("effective_scope", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EFFECTIVE_SOURCES: SqlContract = SqlContract {
    id: "admin_identity.effective_sources",
    domain: "admin-identity",
    sql: "SELECT rg.id, rg.name, rg.permissions, COALESCE(ra.domain_override, rg.domain_scope) \
          FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id = ra.role_group_id \
          WHERE ra.user_id = $1 AND (ra.expires_at IS NULL OR ra.expires_at > now()) \
          ORDER BY rg.name",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("permissions", Type::TEXT_ARRAY),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ROLE_PERMISSIONS: SqlContract = SqlContract {
    id: "admin_identity.role_permissions",
    domain: "admin-identity",
    sql: "SELECT permissions FROM admin_role_groups WHERE id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("permissions", Type::TEXT_ARRAY)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REASON_REQUIRED_AREA: SqlContract = SqlContract {
    id: "admin_identity.reason_required_area",
    domain: "admin-identity",
    sql: "SELECT $1::text=ANY(reason_required_areas) FROM audit_policy WHERE id=1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MISSING_REASON_AUDIT: SqlContract = SqlContract {
    id: "admin_identity.missing_reason_audit",
    domain: "admin-identity",
    sql: "SELECT audit_write($1,'sensitive_action.reason_missing','',NULL,NULL,NULL,NULLIF($2::text,'')::inet,$3::text,'core')",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PROTECTION_DENIED_AUDIT: SqlContract = SqlContract {
    id: "admin_identity.protection_denied_audit",
    domain: "admin-identity",
    sql: "SELECT audit_write($1,'admin_protection.denied','user',$2,NULL,$3::text::jsonb,NULLIF($4::text,'')::inet,'','core')",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ROLE_CREATE: SqlContract = SqlContract {
    id: "admin_identity.role_create",
    domain: "admin-identity",
    sql: "SELECT rust_admin_role_create($1,$2,$3,$4,$5,$6)",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT_ARRAY,
        Type::INT8,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ROLE_UPDATE: SqlContract = SqlContract {
    id: "admin_identity.role_update",
    domain: "admin-identity",
    sql: "SELECT rust_admin_role_update($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::text::jsonb,$12)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT_ARRAY,
        Type::INT8,
        Type::TEXT,
        Type::INT4,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ROLE_DELETE: SqlContract = SqlContract {
    id: "admin_identity.role_delete",
    domain: "admin-identity",
    sql: "SELECT rust_admin_role_delete($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ROLE_ASSIGN: SqlContract = SqlContract {
    id: "admin_identity.role_assign",
    domain: "admin-identity",
    sql: "SELECT rust_admin_role_assign($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT_ARRAY,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
        Type::TEXT,
        Type::INT8,
        Type::BOOL,
        Type::INT4,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ROLE_REMOVE: SqlContract = SqlContract {
    id: "admin_identity.role_remove",
    domain: "admin-identity",
    sql: "SELECT rust_admin_role_remove($1,$2,$3,$4,$5)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ROLE_BULK_ENQUEUE: SqlContract = SqlContract {
    id: "admin_identity.role_bulk_enqueue",
    domain: "admin-identity",
    sql: "INSERT INTO bulk_role_jobs (op, role_id, actor_id, user_ids, expires_at, total, scope_type, scope_id, eligible) \
          VALUES ($1, $2, $3, $4, $5::text::timestamptz, $6, $7, $8, $9) RETURNING id",
    params: &[
        Type::TEXT,
        Type::INT8,
        Type::INT8,
        Type::INT8_ARRAY,
        Type::TEXT,
        Type::INT4,
        Type::TEXT,
        Type::INT8,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- access_reviews.rs ----

pub const ACCESS_REVIEWS_LIST: SqlContract = SqlContract {
    id: "admin_identity.access_reviews_list",
    domain: "admin-identity",
    sql: "SELECT c.id, c.name, c.status, \
          COUNT(i.id) FILTER (WHERE i.decision <> 'undecided')::int, COUNT(i.id)::int, \
          u.email, c.created_at::text, cu.email, c.closed_at::text \
          FROM access_review_campaigns c \
          JOIN users u ON u.id = c.created_by \
          LEFT JOIN users cu ON cu.id = c.closed_by \
          LEFT JOIN access_review_items i ON i.campaign_id = c.id \
          WHERE $1 <= 0 OR c.domain_scope = $1 \
          GROUP BY c.id, u.email, cu.email \
          ORDER BY (c.status='open') DESC, c.created_at DESC",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::unnamed(Type::INT4),
        ColumnSpec::unnamed(Type::INT4),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACCESS_REVIEW_GET: SqlContract = SqlContract {
    id: "admin_identity.access_review_get",
    domain: "admin-identity",
    sql: "SELECT c.id, c.name, c.status, u.email, c.created_at::text, cu.email, c.closed_at::text \
          FROM access_review_campaigns c \
          JOIN users u ON u.id = c.created_by \
          LEFT JOIN users cu ON cu.id = c.closed_by \
          WHERE c.id = $1 AND ($2 <= 0 OR c.domain_scope = $2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACCESS_REVIEW_ITEMS: SqlContract = SqlContract {
    id: "admin_identity.access_review_items",
    domain: "admin-identity",
    sql: "SELECT i.id, u.email, rg.name, COALESCE(i.domain_override, rg.domain_scope), \
          i.granted_at::text, gb.email, i.is_sso, (i.user_id = $2), i.decision, i.applied_at::text \
          FROM access_review_items i \
          LEFT JOIN users u ON u.id = i.user_id \
          LEFT JOIN admin_role_groups rg ON rg.id = i.role_group_id \
          LEFT JOIN users gb ON gb.id = i.granted_by \
          WHERE i.campaign_id = $1 \
          ORDER BY (i.decision='undecided') DESC, u.email",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::named("is_sso", Type::BOOL),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::named("decision", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACCESS_REVIEW_START: SqlContract = SqlContract {
    id: "admin_identity.access_review_start",
    domain: "admin-identity",
    sql: "SELECT access_review_start($1,$2,$3)",
    params: &[Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ACCESS_REVIEW_DECIDE: SqlContract = SqlContract {
    id: "admin_identity.access_review_decide",
    domain: "admin-identity",
    sql: "SELECT access_review_decide($1,$2,$3,$4,$5,$6)",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ACCESS_REVIEW_DECIDE_BULK: SqlContract = SqlContract {
    id: "admin_identity.access_review_decide_bulk",
    domain: "admin-identity",
    sql: "SELECT access_review_decide_bulk($1,$2,$3,$4,$5)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8_ARRAY,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ACCESS_REVIEW_CLOSE: SqlContract = SqlContract {
    id: "admin_identity.access_review_close",
    domain: "admin-identity",
    sql: "SELECT access_review_close($1,$2,$3::text::inet,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- scope_sets.rs ----

pub const SCOPE_SETS_LIST: SqlContract = SqlContract {
    id: "admin_identity.scope_sets_list",
    domain: "admin-identity",
    sql: "SELECT id, name, domain_id, COALESCE(description,''), created_by, created_at::TEXT, updated_at::TEXT \
          FROM admin_scope_sets \
          WHERE ((admin_domain_restriction($1, '{scope_sets.manage}'::text[])) = 0 \
                 OR domain_id = (admin_domain_restriction($1, '{scope_sets.manage}'::text[]))) \
          ORDER BY name",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("domain_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("created_by", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCOPE_SETS_LIST_UNSCOPED: SqlContract = SqlContract {
    id: "admin_identity.scope_sets_list_unscoped",
    domain: "admin-identity",
    sql: "SELECT id, name, domain_id, COALESCE(description,''), created_by, created_at::TEXT, updated_at::TEXT \
          FROM admin_scope_sets ORDER BY name",
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("domain_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("created_by", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCOPE_SET_GET: SqlContract = SqlContract {
    id: "admin_identity.scope_set_get",
    domain: "admin-identity",
    sql: "SELECT id, name, domain_id, COALESCE(description,''), created_by, created_at::TEXT, updated_at::TEXT \
          FROM admin_scope_sets WHERE id = $2 \
          AND ((admin_domain_restriction($1, '{scope_sets.manage}'::text[])) = 0 \
               OR domain_id = (admin_domain_restriction($1, '{scope_sets.manage}'::text[])))",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("domain_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("created_by", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCOPE_SET_GET_UNSCOPED: SqlContract = SqlContract {
    id: "admin_identity.scope_set_get_unscoped",
    domain: "admin-identity",
    sql: "SELECT id, name, domain_id, COALESCE(description,''), created_by, created_at::TEXT, updated_at::TEXT \
          FROM admin_scope_sets WHERE id = $1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("domain_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("created_by", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCOPE_SET_MEMBERS: SqlContract = SqlContract {
    id: "admin_identity.scope_set_members",
    domain: "admin-identity",
    sql: "SELECT m.member_type, m.member_id, m.added_by, m.added_at::TEXT, \
          CASE m.member_type WHEN 'ou' THEN d.name WHEN 'group' THEN mb.display_name WHEN 'user' THEN u.email END AS label \
          FROM admin_scope_set_members m \
          LEFT JOIN departments d ON m.member_type = 'ou' AND d.id = m.member_id \
          LEFT JOIN distribution_groups dg ON m.member_type = 'group' AND dg.id = m.member_id \
          LEFT JOIN mailboxes mb ON m.member_type = 'group' AND mb.id = dg.mailbox_id \
          LEFT JOIN users u ON m.member_type = 'user' AND u.id = m.member_id \
          WHERE m.set_id = $1 ORDER BY m.member_type, m.member_id",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("member_type", Type::TEXT),
        ColumnSpec::named("member_id", Type::INT8),
        ColumnSpec::named("added_by", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("label", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCOPE_SET_CREATE: SqlContract = SqlContract {
    id: "admin_identity.scope_set_create",
    domain: "admin-identity",
    sql: "SELECT rust_admin_scope_set_create($1,$2,$3,$4,$5)",
    params: &[Type::INT8, Type::TEXT, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const SCOPE_SET_UPDATE: SqlContract = SqlContract {
    id: "admin_identity.scope_set_update",
    domain: "admin-identity",
    sql: "SELECT rust_admin_scope_set_update($1,$2,$3,$4,$5)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const SCOPE_SET_DELETE: SqlContract = SqlContract {
    id: "admin_identity.scope_set_delete",
    domain: "admin-identity",
    sql: "SELECT rust_admin_scope_set_delete($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const SCOPE_SET_MEMBER_ADD: SqlContract = SqlContract {
    id: "admin_identity.scope_set_member_add",
    domain: "admin-identity",
    sql: "SELECT rust_admin_scope_set_member_add($1,$2,$3,$4,$5)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const SCOPE_SET_MEMBER_REMOVE: SqlContract = SqlContract {
    id: "admin_identity.scope_set_member_remove",
    domain: "admin-identity",
    sql: "SELECT rust_admin_scope_set_member_remove($1,$2,$3,$4,$5)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- sod.rs ----

pub const MY_ROLES: SqlContract = SqlContract {
    id: "admin_identity.my_roles",
    domain: "admin-identity",
    sql: concat!(
        "SELECT ara.role_group_id, rg.name, ara.eligible, ",
        pg_rfc3339!("ara.activated_until"),
        ", ",
        pg_rfc3339!("ara.expires_at"),
        ", COALESCE(arp.max_duration_minutes, \
         (SELECT (value ->> 0)::int FROM system_config WHERE key = 'jit.default_max_minutes'), 480)::bigint, \
         COALESCE(arp.require_justification, \
         (SELECT (value ->> 0)::bool FROM system_config WHERE key = 'jit.default_require_justification'), false) \
         FROM admin_role_assignments ara \
         JOIN admin_role_groups rg ON rg.id = ara.role_group_id \
         LEFT JOIN admin_role_activation_policy arp ON arp.role_group_id = ara.role_group_id \
         WHERE ara.user_id = $1 ORDER BY rg.name"
    ),
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("role_group_id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("eligible", Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::BOOL),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const JIT_ACTIVATE: SqlContract = SqlContract {
    id: "admin_identity.jit_activate",
    domain: "admin-identity",
    sql: concat!(
        "SELECT ",
        pg_rfc3339!("r.u"),
        " FROM (SELECT admin_role_activate($1, $2, $3, $4) AS u) r"
    ),
    params: &[Type::INT8, Type::INT8, Type::INT4, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const JIT_DEACTIVATE: SqlContract = SqlContract {
    id: "admin_identity.jit_deactivate",
    domain: "admin-identity",
    sql: "SELECT admin_role_deactivate($1, $2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SOD_ROLE_IN_SCOPE: SqlContract = SqlContract {
    id: "admin_identity.sod_role_in_scope",
    domain: "admin-identity",
    sql: "SELECT (admin_domain_restriction($1, '{roles.manage}'::text[]) = 0 \
          OR EXISTS (SELECT 1 FROM admin_role_groups g \
                     WHERE g.id = $2 AND g.domain_scope = admin_domain_restriction($1, '{roles.manage}'::text[])))",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SOD_POLICY_GET: SqlContract = SqlContract {
    id: "admin_identity.sod_policy_get",
    domain: "admin-identity",
    sql: "SELECT max_duration_minutes::bigint, require_justification \
          FROM admin_role_activation_policy WHERE role_group_id = $1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::named("require_justification", Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SOD_POLICY_DEFAULTS: SqlContract = SqlContract {
    id: "admin_identity.sod_policy_defaults",
    domain: "admin-identity",
    sql: "SELECT COALESCE((SELECT (value->>0)::int FROM system_config WHERE key='jit.default_max_minutes'), 480)::bigint, \
          COALESCE((SELECT (value->>0)::bool FROM system_config WHERE key='jit.default_require_justification'), false)",
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SOD_POLICY_PUT: SqlContract = SqlContract {
    id: "admin_identity.sod_policy_put",
    domain: "admin-identity",
    sql: "INSERT INTO admin_role_activation_policy (role_group_id, max_duration_minutes, require_justification) \
          SELECT $2, $3, $4 \
          WHERE (admin_domain_restriction($1, '{roles.manage}'::text[]) = 0 \
                 OR EXISTS (SELECT 1 FROM admin_role_groups g \
                            WHERE g.id = $2 AND g.domain_scope = admin_domain_restriction($1, '{roles.manage}'::text[]))) \
          ON CONFLICT (role_group_id) DO UPDATE \
          SET max_duration_minutes = EXCLUDED.max_duration_minutes, \
              require_justification = EXCLUDED.require_justification \
          RETURNING role_group_id",
    params: &[Type::INT8, Type::INT8, Type::INT4, Type::BOOL],
    columns: &[ColumnSpec::named("role_group_id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SOD_POLICY_PUT_UNSCOPED: SqlContract = SqlContract {
    id: "admin_identity.sod_policy_put_unscoped",
    domain: "admin-identity",
    sql: "INSERT INTO admin_role_activation_policy (role_group_id, max_duration_minutes, require_justification) \
          VALUES ($1, $2, $3) \
          ON CONFLICT (role_group_id) DO UPDATE \
          SET max_duration_minutes = EXCLUDED.max_duration_minutes, \
              require_justification = EXCLUDED.require_justification \
          RETURNING role_group_id",
    params: &[Type::INT8, Type::INT4, Type::BOOL],
    columns: &[ColumnSpec::named("role_group_id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- org_policies.rs ----

pub const DEPARTMENTS_LIST: SqlContract = SqlContract {
    id: "admin_identity.departments_list",
    domain: "admin-identity",
    sql: "SELECT d.id, d.name, d.parent_id, d.path, d.ldap_ou, d.sort_order, \
          (SELECT COUNT(*) FROM users WHERE department_id = d.id) FROM departments d ORDER BY d.path",
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("parent_id", Type::INT8),
        ColumnSpec::named("path", Type::TEXT),
        ColumnSpec::named("ldap_ou", Type::TEXT),
        ColumnSpec::named("sort_order", Type::INT4),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DEPARTMENTS_TREE: SqlContract = SqlContract {
    id: "admin_identity.departments_tree",
    domain: "admin-identity",
    sql: "SELECT d.id, d.name, d.parent_id, d.path, d.ldap_ou, d.sort_order, \
          (SELECT COUNT(*) FROM users WHERE department_id = d.id) FROM departments d ORDER BY d.sort_order, d.name",
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("parent_id", Type::INT8),
        ColumnSpec::named("path", Type::TEXT),
        ColumnSpec::named("ldap_ou", Type::TEXT),
        ColumnSpec::named("sort_order", Type::INT4),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DEPARTMENT_CREATE: SqlContract = SqlContract {
    id: "admin_identity.department_create",
    domain: "admin-identity",
    sql: "SELECT rust_admin_department_create($1,$2,$3,$4,$5)::text",
    params: &[Type::INT8, Type::TEXT, Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DEPARTMENT_UPDATE: SqlContract = SqlContract {
    id: "admin_identity.department_update",
    domain: "admin-identity",
    sql: "SELECT rust_admin_department_update($1,$2,$3,$4,$5,$6,$7)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DEPARTMENT_DELETE: SqlContract = SqlContract {
    id: "admin_identity.department_delete",
    domain: "admin-identity",
    sql: "SELECT rust_admin_department_delete($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DEPARTMENT_ASSIGN_USER: SqlContract = SqlContract {
    id: "admin_identity.department_assign_user",
    domain: "admin-identity",
    sql: "SELECT rust_admin_department_assign_user($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ORG_WIDE_IDENTITY_WRITE: SqlContract = SqlContract {
    id: "admin_identity.org_wide_identity_write",
    domain: "admin-identity",
    sql: "SELECT admin_org_wide_grant($1, '{identity.write}'::text[])",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EAP_LIST: SqlContract = SqlContract {
    id: "admin_identity.eap_list",
    domain: "admin-identity",
    sql: "SELECT id, priority, name, enabled, overwrite_directory_address, \
          cond_department, cond_domain_ids, cond_mailbox_type, cond_ad_ou, \
          primary_template, additional_templates, duplicate_resolution, \
          created_at::text, updated_at::text FROM email_address_policies ORDER BY priority ASC",
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("priority", Type::INT4),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::named("overwrite_directory_address", Type::BOOL),
        ColumnSpec::named("cond_department", Type::TEXT_ARRAY),
        ColumnSpec::named("cond_domain_ids", Type::INT8_ARRAY),
        ColumnSpec::named("cond_mailbox_type", Type::TEXT_ARRAY),
        ColumnSpec::named("cond_ad_ou", Type::TEXT_ARRAY),
        ColumnSpec::named("primary_template", Type::TEXT),
        ColumnSpec::named("additional_templates", Type::TEXT_ARRAY),
        ColumnSpec::named("duplicate_resolution", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EAP_CREATE: SqlContract = SqlContract {
    id: "admin_identity.eap_create",
    domain: "admin-identity",
    sql: "INSERT INTO email_address_policies \
          (priority, name, enabled, overwrite_directory_address, cond_department, cond_domain_ids, \
           cond_mailbox_type, cond_ad_ou, primary_template, additional_templates, duplicate_resolution) \
          VALUES (COALESCE($1::bigint::integer, (SELECT COALESCE(MAX(priority), 0) + 10 FROM email_address_policies)), \
           $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
          RETURNING id, priority, name, enabled, overwrite_directory_address, \
          cond_department, cond_domain_ids, cond_mailbox_type, cond_ad_ou, \
          primary_template, additional_templates, duplicate_resolution, \
          created_at::text, updated_at::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
        Type::BOOL,
        Type::TEXT_ARRAY,
        Type::INT8_ARRAY,
        Type::TEXT_ARRAY,
        Type::TEXT_ARRAY,
        Type::TEXT,
        Type::TEXT_ARRAY,
        Type::TEXT,
    ],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("priority", Type::INT4),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::named("overwrite_directory_address", Type::BOOL),
        ColumnSpec::named("cond_department", Type::TEXT_ARRAY),
        ColumnSpec::named("cond_domain_ids", Type::INT8_ARRAY),
        ColumnSpec::named("cond_mailbox_type", Type::TEXT_ARRAY),
        ColumnSpec::named("cond_ad_ou", Type::TEXT_ARRAY),
        ColumnSpec::named("primary_template", Type::TEXT),
        ColumnSpec::named("additional_templates", Type::TEXT_ARRAY),
        ColumnSpec::named("duplicate_resolution", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EAP_UPDATE: SqlContract = SqlContract {
    id: "admin_identity.eap_update",
    domain: "admin-identity",
    sql: "UPDATE email_address_policies SET \
          priority = COALESCE($2::bigint::integer, priority), \
          name = COALESCE($3, name), \
          enabled = COALESCE($4, enabled), \
          overwrite_directory_address = COALESCE($5, overwrite_directory_address), \
          cond_department = COALESCE($6, cond_department), \
          cond_domain_ids = COALESCE($7, cond_domain_ids), \
          cond_mailbox_type = COALESCE($8, cond_mailbox_type), \
          cond_ad_ou = COALESCE($9, cond_ad_ou), \
          primary_template = COALESCE($10, primary_template), \
          additional_templates = COALESCE($11, additional_templates), \
          duplicate_resolution = COALESCE($12, duplicate_resolution), \
          updated_at = now() \
          WHERE id = $1 \
          RETURNING id, priority, name, enabled, overwrite_directory_address, \
          cond_department, cond_domain_ids, cond_mailbox_type, cond_ad_ou, \
          primary_template, additional_templates, duplicate_resolution, \
          created_at::text, updated_at::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
        Type::BOOL,
        Type::TEXT_ARRAY,
        Type::INT8_ARRAY,
        Type::TEXT_ARRAY,
        Type::TEXT_ARRAY,
        Type::TEXT,
        Type::TEXT_ARRAY,
        Type::TEXT,
    ],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("priority", Type::INT4),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::named("overwrite_directory_address", Type::BOOL),
        ColumnSpec::named("cond_department", Type::TEXT_ARRAY),
        ColumnSpec::named("cond_domain_ids", Type::INT8_ARRAY),
        ColumnSpec::named("cond_mailbox_type", Type::TEXT_ARRAY),
        ColumnSpec::named("cond_ad_ou", Type::TEXT_ARRAY),
        ColumnSpec::named("primary_template", Type::TEXT),
        ColumnSpec::named("additional_templates", Type::TEXT_ARRAY),
        ColumnSpec::named("duplicate_resolution", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EAP_DELETE: SqlContract = SqlContract {
    id: "admin_identity.eap_delete",
    domain: "admin-identity",
    sql: "WITH d AS (DELETE FROM email_address_policies WHERE id = $1 RETURNING 1) SELECT count(*)::bigint FROM d",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EAP_REORDER: SqlContract = SqlContract {
    id: "admin_identity.eap_reorder",
    domain: "admin-identity",
    sql: "SELECT rust_admin_eap_reorder($1::bigint[])",
    params: &[Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EAP_APPLY: SqlContract = SqlContract {
    id: "admin_identity.eap_apply",
    domain: "admin-identity",
    sql: "INSERT INTO eap_apply_jobs (policy_id, status) VALUES ($1, 'queued') RETURNING id",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EAP_APPLY_STATUS: SqlContract = SqlContract {
    id: "admin_identity.eap_apply_status",
    domain: "admin-identity",
    sql: "SELECT status, applied, total, error FROM eap_apply_jobs WHERE id = $1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::named("applied", Type::INT4),
        ColumnSpec::named("total", Type::INT4),
        ColumnSpec::named("error", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EAP_PREVIEW: SqlContract = SqlContract {
    id: "admin_identity.eap_preview",
    domain: "admin-identity",
    sql: "SELECT email_address_policy_render($1, $2, $3)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EAP_MATCH_COUNT: SqlContract = SqlContract {
    id: "admin_identity.eap_match_count",
    domain: "admin-identity",
    sql: "SELECT email_address_policy_match_count($1, $2, $3, $4)",
    params: &[
        Type::TEXT_ARRAY,
        Type::INT8_ARRAY,
        Type::TEXT_ARRAY,
        Type::TEXT_ARRAY,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DISTRIBUTION_GROUPS_LIST: SqlContract = SqlContract {
    id: "admin_identity.distribution_groups_list",
    domain: "admin-identity",
    sql: "SELECT dg.id, mb.display_name, dg.is_dynamic, dg.scim_external_id IS NOT NULL, \
          dg.usable_as_admin_scope, COUNT(dgm.mailbox_id) \
          FROM distribution_groups dg \
          JOIN mailboxes mb ON mb.id = dg.mailbox_id \
          LEFT JOIN distribution_group_members dgm ON dgm.group_id = dg.id \
          GROUP BY dg.id, mb.display_name, dg.is_dynamic, dg.scim_external_id, dg.usable_as_admin_scope \
          ORDER BY mb.display_name",
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("display_name", Type::TEXT),
        ColumnSpec::named("is_dynamic", Type::BOOL),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::named("usable_as_admin_scope", Type::BOOL),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- idv2.rs ----

pub const IDV2_SOURCES_LIST: SqlContract = SqlContract {
    id: "admin_identity.idv2_sources_list",
    domain: "admin-identity",
    sql: concat!(
        "SELECT source_key,display_name,kind,state,generation,mapping_version,capabilities::text,",
        pg_rfc3339!("last_success_at"),
        ",",
        pg_rfc3339!("last_failure_at"),
        ",last_error_code,committed_cursor IS NOT NULL,\
         (SELECT count(*) FROM identity_source_inbox i WHERE i.source_id=s.id AND i.state IN ('pending','quarantined')) \
         FROM identity_sources s \
         WHERE ($2::bigint = 0 OR EXISTS (SELECT 1 FROM user_identity_links scoped_link WHERE scoped_link.source_id=s.id AND admin_can_reach($1,scoped_link.user_id))) \
         AND ($3::text = '' OR s.source_key ILIKE '%' || $3 || '%' OR s.display_name ILIKE '%' || $3 || '%') \
         AND ($4::text = '' OR s.source_key=$4) \
         AND ($5::text = '' OR s.state=$5) \
         AND ($6::text = '' OR s.source_key>$6) \
         ORDER BY s.source_key LIMIT $7"
    ),
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[
        ColumnSpec::named("source_key", Type::TEXT),
        ColumnSpec::named("display_name", Type::TEXT),
        ColumnSpec::named("kind", Type::TEXT),
        ColumnSpec::named("state", Type::TEXT),
        ColumnSpec::named("generation", Type::INT8),
        ColumnSpec::named("mapping_version", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("last_error_code", Type::TEXT),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_PEOPLE_LIST: SqlContract = SqlContract {
    id: "admin_identity.idv2_people_list",
    domain: "admin-identity",
    sql: "SELECT u.id,u.email,u.display_name,u.enabled,a.authority_kind,s.source_key,\
          (count(l.id) FILTER (WHERE l.state='active')::integer)::bigint,\
          (count(l.id) FILTER (WHERE l.state='detached')::integer)::bigint \
          FROM users u \
          JOIN user_lifecycle_authorities a ON a.user_id=u.id \
          LEFT JOIN user_identity_links al ON al.id=a.link_id \
          LEFT JOIN identity_sources s ON s.id=al.source_id \
          LEFT JOIN user_identity_links l ON l.user_id=u.id \
          WHERE NOT is_guest_account(u.id) AND admin_can_reach($1,u.id) \
          AND ($2::text = '' OR u.email ILIKE '%' || $2 || '%' OR COALESCE(u.display_name,'') ILIKE '%' || $2 || '%') \
          AND ($3::text = '' OR s.source_key=$3) \
          AND ($4::text = '' OR ($4='enabled' AND u.enabled) OR ($4='disabled' AND NOT u.enabled)) \
          AND ($5::bigint = 0 OR u.id>$5) \
          GROUP BY u.id,u.email,u.display_name,u.enabled,a.authority_kind,s.source_key \
          ORDER BY u.id LIMIT $6",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::named("display_name", Type::TEXT),
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::named("authority_kind", Type::TEXT),
        ColumnSpec::named("source_key", Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_CONFLICTS_LIST: SqlContract = SqlContract {
    id: "admin_identity.idv2_conflicts_list",
    domain: "admin-identity",
    sql: concat!(
        "SELECT c.id::text,s.source_key,c.evidence_class,c.status,c.generation,",
        pg_rfc3339!("c.created_at"),
        ",",
        pg_rfc3339!("c.expires_at"),
        ",c.redacted_explanation,\
         to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
         FROM identity_match_candidates c JOIN identity_sources s ON s.id=c.source_id \
         WHERE c.status IN ('pending','deferred') \
         AND (($2::bigint = 0 AND c.candidate_user_id IS NULL) OR (c.candidate_user_id IS NOT NULL AND admin_can_reach($1,c.candidate_user_id))) \
         AND ($3::text = '' OR c.redacted_explanation ILIKE '%' || $3 || '%' OR c.evidence_class ILIKE '%' || $3 || '%') \
         AND ($4::text = '' OR s.source_key=$4) \
         AND ($5::text = '' OR c.status=$5) \
         AND ($6::text IS NULL OR (c.created_at,c.id)<($6::text::timestamptz,$7::text::uuid)) \
         ORDER BY c.created_at DESC,c.id DESC LIMIT $8"
    ),
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("source_key", Type::TEXT),
        ColumnSpec::named("evidence_class", Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::named("generation", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("redacted_explanation", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_EVENTS_LIST: SqlContract = SqlContract {
    id: "admin_identity.idv2_events_list",
    domain: "admin-identity",
    sql: concat!(
        "SELECT e.id::text,",
        pg_rfc3339!("e.occurred_at"),
        ",e.user_id::text,s.source_key,e.link_id::text,e.transition_id::text,e.action,e.reason,\
         e.correlation_id::text,e.metadata::text,to_char(e.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
         FROM identity_link_events e LEFT JOIN identity_sources s ON s.id=e.source_id \
         WHERE (($2::bigint = 0 AND e.user_id IS NULL) OR (e.user_id IS NOT NULL AND admin_can_reach($1,e.user_id))) \
         AND ($3::text = '' OR e.action ILIKE '%' || $3 || '%' OR COALESCE(s.source_key,'') ILIKE '%' || $3 || '%') \
         AND ($4::text = '' OR s.source_key=$4) \
         AND ($5::text IS NULL OR (e.occurred_at,e.id)<($5::text::timestamptz,$6::bigint)) \
         ORDER BY e.occurred_at DESC,e.id DESC LIMIT $7"
    ),
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("source_key", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("action", Type::TEXT),
        ColumnSpec::named("reason", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITIONS_LIST: SqlContract = SqlContract {
    id: "admin_identity.idv2_transitions_list",
    domain: "admin-identity",
    sql: concat!(
        "SELECT t.id::text,t.user_id::text,t.kind,t.state,s.source_key,t.protected,t.reason,t.failure_code,",
        pg_rfc3339!("t.created_at"),
        ",",
        pg_rfc3339!("t.updated_at"),
        ",(count(e.effect_kind) FILTER (WHERE e.state<>'completed')::integer)::bigint,\
         to_char(t.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
         FROM identity_transitions t \
         JOIN identity_sources s ON s.id=t.source_id \
         LEFT JOIN identity_transition_effects e ON e.transition_id=t.id \
         WHERE admin_can_reach($1,t.user_id) \
         AND ($2::text = '' OR t.kind ILIKE '%' || $2 || '%' OR t.state ILIKE '%' || $2 || '%' OR s.source_key ILIKE '%' || $2 || '%') \
         AND ($3::text = '' OR s.source_key=$3) \
         AND ($4::text = '' OR t.state=$4) \
         AND ($5::text IS NULL OR (t.created_at,t.id)<($5::text::timestamptz,$6::text::uuid)) \
         GROUP BY t.id,s.source_key \
         ORDER BY t.created_at DESC,t.id DESC LIMIT $7"
    ),
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("kind", Type::TEXT),
        ColumnSpec::named("state", Type::TEXT),
        ColumnSpec::named("source_key", Type::TEXT),
        ColumnSpec::named("protected", Type::BOOL),
        ColumnSpec::named("reason", Type::TEXT),
        ColumnSpec::named("failure_code", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_PERSON_READ: SqlContract = SqlContract {
    id: "admin_identity.idv2_person_read",
    domain: "admin-identity",
    sql: "SELECT identity_person_read($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_CONFLICT_READ: SqlContract = SqlContract {
    id: "admin_identity.idv2_conflict_read",
    domain: "admin-identity",
    sql: r#"SELECT jsonb_build_object( 'id', c.id, 'source', jsonb_build_object( 'sourceKey', s.source_key, 'displayName', s.display_name, 'kind', s.kind, 'state', s.state, 'generation', s.generation::text ), 'subjectFingerprint', substr(encode(digest(c.external_subject,'sha256'),'hex'),1,16), 'evidenceClass', c.evidence_class, 'evidenceDigest', encode(c.evidence_digest,'hex'), 'explanation', c.redacted_explanation, 'state', c.status, 'generation', c.generation::text, 'createdAt', c.created_at, 'expiresAt', c.expires_at, 'decidedAt', c.decided_at, 'candidatePerson', CASE WHEN u.id IS NULL THEN NULL ELSE jsonb_build_object( 'userId', u.id::text, 'email', u.email, 'displayName', u.display_name, 'enabled', u.enabled, 'protected', protection.is_protected ) END, 'allowedDecisions', CASE WHEN c.status NOT IN ('pending','deferred') OR c.expires_at<=statement_timestamp() OR c.generation<>s.generation THEN '[]'::jsonb WHEN c.candidate_user_id IS NULL AND s.state='active' AND source_payload.available THEN '["create","reject","defer"]'::jsonb WHEN c.candidate_user_id IS NULL OR c.evidence_class='soft' OR protection.is_protected OR s.state<>'active' THEN '["reject","defer"]'::jsonb ELSE '["link","reject","defer"]'::jsonb END, 'decisionHistory', COALESCE(( SELECT jsonb_agg(history.row ORDER BY history.occurred_at DESC) FROM ( SELECT d.occurred_at, jsonb_build_object( 'id', d.id::text, 'decision', d.decision, 'reason', d.reason, 'personId', CASE WHEN d.person_id IS NULL THEN NULL ELSE d.person_id::text END, 'linkId', CASE WHEN d.link_id IS NULL THEN NULL ELSE d.link_id::text END, 'decidedBy', d.decided_by::text, 'occurredAt', d.occurred_at ) AS row FROM identity_match_decisions d WHERE d.candidate_id=c.id ORDER BY d.occurred_at DESC,d.id DESC LIMIT 50 ) history ),'[]'::jsonb) )::text FROM identity_match_candidates c JOIN identity_sources s ON s.id=c.source_id LEFT JOIN users u ON u.id=c.candidate_user_id LEFT JOIN LATERAL ( SELECT u.id IS NOT NULL AND ( EXISTS ( SELECT 1 FROM admin_role_assignments ara JOIN admin_role_groups arg ON arg.id=ara.role_group_id WHERE ara.user_id=u.id AND (ara.expires_at IS NULL OR ara.expires_at>statement_timestamp()) AND admin_assignment_active( ara.eligible,ara.activated_until ) AND EXISTS ( SELECT 1 FROM admin_permissions ap WHERE ap.permission_key=ANY(arg.permissions) AND ap.is_sensitive ) ) OR EXISTS ( SELECT 1 FROM system_config cfg, LATERAL jsonb_array_elements_text(cfg.value) x(raw) WHERE cfg.key='ca_break_glass_user_ids' AND x.raw::bigint=u.id ) ) AS is_protected ) protection ON true LEFT JOIN LATERAL ( SELECT false AS available ) source_payload ON true WHERE c.id=$2::text::uuid AND identity_admin_scope_allows( $1,c.candidate_user_id,'users.read' )"#,
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- idv2_ops.rs ----

pub const IDV2_GROUP_MAPPINGS_SAML: SqlContract = SqlContract {
    id: "admin_identity.idv2_group_mappings_saml",
    domain: "admin-identity",
    sql: "SELECT idp_entity_id, COALESCE(group_mappings, '[]'::JSONB)::text FROM saml_sp_registrations WHERE enabled = TRUE",
    params: &[],
    columns: &[
        ColumnSpec::named("idp_entity_id", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_GROUP_MAPPINGS_OIDC: SqlContract = SqlContract {
    id: "admin_identity.idv2_group_mappings_oidc",
    domain: "admin-identity",
    sql: "SELECT key, value::text FROM system_config WHERE key LIKE 'oidc_provider_%_config'",
    params: &[],
    columns: &[
        ColumnSpec::named("key", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_INVENTORY_PEOPLE: SqlContract = SqlContract {
    id: "admin_identity.idv2_inventory_people",
    domain: "admin-identity",
    sql: concat!(
        "SELECT count(*)::bigint, count(*) FILTER (WHERE u.enabled)::bigint, \
         count(*) FILTER (WHERE NOT u.enabled)::bigint, \
         count(*) FILTER (WHERE g.user_id IS NOT NULL)::bigint, \
         count(*) FILTER (WHERE g.user_id IS NULL)::bigint, \
         count(*) FILTER (WHERE g.user_id IS NULL AND NOT EXISTS (SELECT 1 FROM public.mailboxes mb WHERE mb.user_id = u.id AND mb.is_primary))::bigint, \
         count(*) FILTER (WHERE u.oidc_subject IS NOT NULL AND u.oidc_issuer IS NOT NULL)::bigint, \
         count(*) FILTER (WHERE (u.oidc_subject IS NULL) <> (u.oidc_issuer IS NULL))::bigint, \
         count(*) FILTER (WHERE u.saml_name_id IS NOT NULL AND u.saml_idp_entity_id IS NOT NULL)::bigint, \
         count(*) FILTER (WHERE (u.saml_name_id IS NULL) <> (u.saml_idp_entity_id IS NULL))::bigint, ",
        pg_rfc3339!("clock_timestamp()"),
        " FROM public.users u LEFT JOIN public.guest_accounts g ON g.user_id = u.id"
    ),
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_INVENTORY_MAILBOXES: SqlContract = SqlContract {
    id: "admin_identity.idv2_inventory_mailboxes",
    domain: "admin-identity",
    sql: "SELECT count(*) FILTER (WHERE user_id IS NULL AND resource_type IS NULL)::bigint, \
          count(*) FILTER (WHERE user_id IS NULL AND resource_type IS NOT NULL)::bigint FROM public.mailboxes",
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_INVENTORY_LIFECYCLE: SqlContract = SqlContract {
    id: "admin_identity.idv2_inventory_lifecycle",
    domain: "admin-identity",
    sql: "SELECT COALESCE(jsonb_object_agg(source, source_count), '{}'::jsonb)::text FROM (\
          SELECT COALESCE(NULLIF(btrim(sync_source), ''), 'unknown') AS source, count(*)::bigint AS source_count \
          FROM public.users GROUP BY 1) counts",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_INVENTORY_LEGACY: SqlContract = SqlContract {
    id: "admin_identity.idv2_inventory_legacy",
    domain: "admin-identity",
    sql: "SELECT (SELECT count(*)::bigint FROM public.identity_legacy_federation_pair_inventory), \
          (SELECT count(*)::bigint FROM public.sso_distribution_group_legacy_inventory), \
          (SELECT count(*)::bigint FROM public.sso_admin_role_legacy_inventory)",
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_INVENTORY_PROTECTED: SqlContract = SqlContract {
    id: "admin_identity.idv2_inventory_protected",
    domain: "admin-identity",
    sql: "SELECT * FROM (WITH break_glass AS (SELECT DISTINCT elem.raw_user_id::bigint AS user_id FROM public.system_config sc, \
          LATERAL jsonb_array_elements_text(sc.value) AS elem(raw_user_id) WHERE sc.key = 'ca_break_glass_user_ids'), \
          sensitive_holders AS (SELECT DISTINCT ara.user_id FROM public.admin_role_assignments ara \
          JOIN public.admin_role_groups rg ON rg.id = ara.role_group_id WHERE rg.permissions && $1::text[] \
          AND (ara.expires_at IS NULL OR ara.expires_at > now()) AND public.admin_assignment_active(ara.eligible, ara.activated_until)), \
          protected AS (SELECT user_id FROM break_glass UNION SELECT user_id FROM sensitive_holders) \
          SELECT (SELECT count(*)::bigint FROM protected), (SELECT count(*)::bigint FROM break_glass), \
          (SELECT count(*)::bigint FROM sensitive_holders)) q",
    params: &[Type::TEXT_ARRAY],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_INVENTORY_SECRETS: SqlContract = SqlContract {
    id: "admin_identity.idv2_inventory_secrets",
    domain: "admin-identity",
    sql: "SELECT * FROM (WITH secret_rows AS (SELECT CASE WHEN key LIKE 'ad_sync_%' THEN 'ad' WHEN key LIKE 'ldap_sync_%' THEN 'ldap' END AS connector, \
          CASE WHEN value IS NULL OR value = 'null'::jsonb OR value = '\"\"'::jsonb THEN 'unset' \
          WHEN jsonb_typeof(value) = 'object' AND value->>'format' = 'setjoin-config-secret' AND value->>'version' = '1' AND value ? 'ciphertext' THEN 'encrypted' \
          ELSE 'attention_required' END AS state FROM public.system_config \
          WHERE right(key, 4) = '_enc' AND (key LIKE 'ad_sync_%' OR key LIKE 'ldap_sync_%')), \
          connector_states AS (SELECT connector, CASE WHEN bool_or(state = 'attention_required') THEN 'attention_required' \
          WHEN bool_or(state = 'encrypted') THEN 'encrypted' ELSE 'unset' END AS state FROM secret_rows GROUP BY connector) \
          SELECT COALESCE(max(state) FILTER (WHERE connector = 'ad'), 'unset'), COALESCE(max(state) FILTER (WHERE connector = 'ldap'), 'unset') FROM connector_states) q",
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_INVENTORY_EXPORT: SqlContract = SqlContract {
    id: "admin_identity.idv2_inventory_export",
    domain: "admin-identity",
    sql: "SELECT identity_inventory_export()::text",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_JOB_READ: SqlContract = SqlContract {
    id: "admin_identity.idv2_job_read",
    domain: "admin-identity",
    sql: "SELECT identity_job_read($1,$2::text::uuid)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_JOB_RESULTS: SqlContract = SqlContract {
    id: "admin_identity.idv2_job_results",
    domain: "admin-identity",
    sql: "SELECT identity_job_results($1,$2::text::uuid,$3,$4)::text",
    params: &[Type::INT8, Type::TEXT, Type::INT8, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_LOAD_SOURCE: SqlContract = SqlContract {
    id: "admin_identity.idv2_load_source",
    domain: "admin-identity",
    sql: concat!(
        "SELECT id,display_name,kind,state,generation,mapping_version,config_envelope,capabilities::text,",
        pg_rfc3339!("last_success_at"),
        ",",
        pg_rfc3339!("last_failure_at"),
        ",last_error_code FROM identity_sources WHERE source_key=$1"
    ),
    params: &[Type::TEXT],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("display_name", Type::TEXT),
        ColumnSpec::named("kind", Type::TEXT),
        ColumnSpec::named("state", Type::TEXT),
        ColumnSpec::named("generation", Type::INT8),
        ColumnSpec::named("mapping_version", Type::INT8),
        ColumnSpec::named("config_envelope", Type::BYTEA),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("last_error_code", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- idv2_source.rs & idv2_writes.rs ----

pub const IDV2_SOURCE_APPLY: SqlContract = SqlContract {
    id: "admin_identity.idv2_source_apply",
    domain: "admin-identity",
    sql: "SELECT identity_source_config_apply($1,$2,$3,$4,$5::text::jsonb,$6,$7,$8,$9,$10::text::uuid,$11)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BYTEA,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_SOURCE_SECRET_SET: SqlContract = SqlContract {
    id: "admin_identity.idv2_source_secret_set",
    domain: "admin-identity",
    sql: "SELECT identity_source_secret_set($1,$2,$3,$4,$5,$6,$7,$8,$9::text::uuid,$10)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::BYTEA,
        Type::INT8,
        Type::INT8,
        Type::BOOL,
        Type::INT4,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_SOURCE_LIFECYCLE: SqlContract = SqlContract {
    id: "admin_identity.idv2_source_lifecycle",
    domain: "admin-identity",
    sql: "SELECT identity_source_lifecycle($1,$2,$3,$4,$5::text::uuid,$6)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_JOB_CANCEL: SqlContract = SqlContract {
    id: "admin_identity.idv2_job_cancel",
    domain: "admin-identity",
    sql: "SELECT q.s, CASE WHEN q.s = 202 THEN identity_job_cancel($1,$2::text::uuid)::text END \
          FROM (SELECT CASE WHEN j.r IS NULL THEN 404 WHEN NOT (j.r->>'kind' = ANY($3::text[])) THEN 403 ELSE 202 END AS s \
                FROM (SELECT identity_job_read($1,$2::text::uuid) AS r) j) q",
    params: &[Type::INT8, Type::TEXT, Type::TEXT_ARRAY],
    columns: &[
        ColumnSpec::named("s", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_CONFLICT_DECIDE: SqlContract = SqlContract {
    id: "admin_identity.idv2_conflict_decide",
    domain: "admin-identity",
    sql: "SELECT q.s, CASE WHEN q.s = 200 THEN identity_match_decide($1,$2::text::uuid,$3,$4,$5,$6,$7::text::uuid)::text \
                          WHEN q.s = 403 THEN $8::text END \
          FROM (SELECT CASE WHEN c.id IS NULL THEN 404 \
                            WHEN c.candidate_user_id IS NULL AND $8::text <> '' THEN 403 \
                            WHEN c.candidate_user_id IS NOT NULL AND NOT identity_admin_scope_allows($1,c.candidate_user_id,'identity.write') THEN 404 \
                            ELSE 200 END AS s \
                FROM (SELECT 1) one LEFT JOIN identity_match_candidates c ON c.id = $2::text::uuid) q",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[
        ColumnSpec::named("s", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_GROUP_MAPPINGS_PUT: SqlContract = SqlContract {
    id: "admin_identity.idv2_group_mappings_put",
    domain: "admin-identity",
    sql: "SELECT rust_admin_group_mappings_put($1,$2,$3,$4,$5::text[])::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT_ARRAY,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- idv2_transitions.rs ----

pub const IDV2_TRANSITION_REACHABLE: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_reachable",
    domain: "admin-identity",
    sql: "SELECT COALESCE((SELECT admin_can_reach($1,t.user_id) FROM identity_transitions t WHERE t.id=$2::text::uuid),false)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_PERSON_REACHABLE: SqlContract = SqlContract {
    id: "admin_identity.idv2_person_reachable",
    domain: "admin-identity",
    sql: "SELECT admin_can_reach($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITION_READ: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_read",
    domain: "admin-identity",
    sql: "SELECT identity_transition_read($1,$2::text::uuid)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITION_REPORT: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_report",
    domain: "admin-identity",
    sql: "SELECT jsonb_build_object( \
          'schemaVersion',1, \
          'generatedAt',statement_timestamp(), \
          'transition',(to_jsonb(t)-'preview_digest') || jsonb_build_object( \
            'approval_request_id',CASE WHEN t.approval_request_id IS NULL THEN NULL ELSE t.approval_request_id::text END, \
            'rollback_approval_request_id',CASE WHEN t.rollback_approval_request_id IS NULL THEN NULL ELSE t.rollback_approval_request_id::text END \
          ), \
          'effects',COALESCE(( \
            SELECT jsonb_agg(to_jsonb(e) ORDER BY e.effect_kind) \
              FROM identity_transition_effects e WHERE e.transition_id=t.id \
          ),'[]'::jsonb), \
          'events',COALESCE(( \
            SELECT jsonb_agg(ev.row ORDER BY ev.occurred_at,ev.id) \
              FROM ( \
                SELECT occurred_at,id,jsonb_build_object( \
                  'occurredAt',occurred_at,'action',action, \
                  'reason',reason,'correlationId',correlation_id, \
                  'metadata',metadata \
                ) AS row \
                  FROM identity_link_events \
                 WHERE transition_id=t.id \
                 ORDER BY occurred_at,id \
                 LIMIT 100 \
              ) ev \
          ),'[]'::jsonb) \
        )::text \
        FROM identity_transitions t \
        WHERE t.id=$1::text::uuid AND admin_can_reach($2,t.user_id)",
    params: &[Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITION_REQUEST: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_request",
    domain: "admin-identity",
    sql: "SELECT q.s, CASE WHEN q.s = 200 THEN identity_transition_request($1,$2::text::uuid,$3,$4::text::uuid,$5,$6::text::uuid)::text END \
          FROM (SELECT CASE WHEN COALESCE((SELECT admin_can_reach($1,t.user_id) FROM identity_transitions t WHERE t.id=$2::text::uuid),false) THEN 200 ELSE 404 END AS s) q",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[
        ColumnSpec::named("s", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITION_APPROVE: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_approve",
    domain: "admin-identity",
    sql: "SELECT q.s, CASE WHEN q.s = 200 THEN identity_transition_approve($1,$2::text::uuid,$3,$4::text::uuid,$5,$6::text::uuid)::text END \
          FROM (SELECT CASE WHEN COALESCE((SELECT admin_can_reach($1,t.user_id) FROM identity_transitions t WHERE t.id=$2::text::uuid),false) THEN 200 ELSE 404 END AS s) q",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[
        ColumnSpec::named("s", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITION_DENY: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_deny",
    domain: "admin-identity",
    sql: "SELECT q.s, CASE WHEN q.s = 200 THEN identity_transition_deny($1,$2::text::uuid,$3,$4::text::uuid,$5,$6::text::uuid)::text END \
          FROM (SELECT CASE WHEN COALESCE((SELECT admin_can_reach($1,t.user_id) FROM identity_transitions t WHERE t.id=$2::text::uuid),false) THEN 200 ELSE 404 END AS s) q",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[
        ColumnSpec::named("s", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITION_EXECUTE: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_execute",
    domain: "admin-identity",
    sql: "SELECT q.s, CASE WHEN q.s = 200 THEN identity_transition_execute($1,$2::text::uuid,$3,$4::text::uuid,$5::bigint,$6,$7::text::uuid)::text END \
          FROM (SELECT CASE WHEN COALESCE((SELECT admin_can_reach($1,t.user_id) FROM identity_transitions t WHERE t.id=$2::text::uuid),false) THEN 200 ELSE 404 END AS s) q",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[
        ColumnSpec::named("s", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITION_ROLLBACK: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_rollback",
    domain: "admin-identity",
    sql: "SELECT q.s, CASE WHEN q.s = 200 THEN identity_transition_rollback($1,$2::text::uuid,$3,$4::text::uuid,$5::bigint,$6,$7::text::uuid)::text END \
          FROM (SELECT CASE WHEN COALESCE((SELECT admin_can_reach($1,t.user_id) FROM identity_transitions t WHERE t.id=$2::text::uuid),false) THEN 200 ELSE 404 END AS s) q",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[
        ColumnSpec::named("s", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITION_CANCEL: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_cancel",
    domain: "admin-identity",
    sql: "SELECT q.s, CASE WHEN q.s = 200 THEN identity_transition_cancel($1,$2::text::uuid,$3::bigint,$4,$5::text::uuid)::text END \
          FROM (SELECT CASE WHEN COALESCE((SELECT admin_can_reach($1,t.user_id) FROM identity_transitions t WHERE t.id=$2::text::uuid),false) THEN 200 ELSE 404 END AS s) q",
    params: &[Type::INT8, Type::TEXT, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[
        ColumnSpec::named("s", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITION_ROLLBACK_PREVIEW: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_rollback_preview",
    domain: "admin-identity",
    sql: "SELECT q.s, CASE WHEN q.s = 200 THEN identity_transition_rollback_preview($1,$2::text::uuid,$3::bigint,$4,$5::text::uuid)::text END \
          FROM (SELECT CASE WHEN COALESCE((SELECT admin_can_reach($1,t.user_id) FROM identity_transitions t WHERE t.id=$2::text::uuid),false) THEN 200 ELSE 404 END AS s) q",
    params: &[Type::INT8, Type::TEXT, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[
        ColumnSpec::named("s", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITION_RETRY: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_retry",
    domain: "admin-identity",
    sql: "SELECT q.s, CASE WHEN q.s = 200 THEN identity_transition_retry($1,$2::text::uuid,$3::bigint,$4::text::uuid,$5,$6::text::uuid)::text END \
          FROM (SELECT CASE WHEN COALESCE((SELECT admin_can_reach($1,t.user_id) FROM identity_transitions t WHERE t.id=$2::text::uuid),false) THEN 200 ELSE 404 END AS s) q",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[
        ColumnSpec::named("s", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITION_CHALLENGE_ISSUE: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_challenge_issue",
    domain: "admin-identity",
    sql: "SELECT q.s, CASE WHEN q.s = 200 THEN identity_transition_challenge_issue($1,$2::text::uuid,$3,$4::text::uuid)::text END \
          FROM (SELECT CASE WHEN COALESCE((SELECT admin_can_reach($1,t.user_id) FROM identity_transitions t WHERE t.id=$2::text::uuid),false) THEN 200 ELSE 404 END AS s) q",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[
        ColumnSpec::named("s", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITION_CHALLENGE_COMPLETE: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_challenge_complete",
    domain: "admin-identity",
    sql: "SELECT q.s, CASE WHEN q.s = 200 THEN identity_transition_challenge_complete($1,$2::text::uuid,$3::text::uuid,$4,$5::bytea,$6::bytea,$7::text[],$8,$9::text::uuid)::text END \
          FROM (SELECT CASE WHEN COALESCE((SELECT admin_can_reach($1,t.user_id) FROM identity_transitions t WHERE t.id=$2::text::uuid),false) THEN 200 ELSE 404 END AS s) q",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BYTEA,
        Type::BYTEA,
        Type::TEXT_ARRAY,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[
        ColumnSpec::named("s", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITION_PREVIEW: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_preview",
    domain: "admin-identity",
    sql: "SELECT q.s, CASE WHEN q.s = 200 THEN identity_transition_preview($1,$2::bigint,$3,$4::text::uuid)::text END \
          FROM (SELECT CASE WHEN admin_can_reach($1,$2::bigint) THEN 200 ELSE 404 END AS s) q",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[
        ColumnSpec::named("s", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_TRANSITION_REBIND_PREVIEW: SqlContract = SqlContract {
    id: "admin_identity.idv2_transition_rebind_preview",
    domain: "admin-identity",
    sql: "SELECT q.s, CASE WHEN q.s = 200 THEN identity_source_rebind_preview($1,$2::bigint,$3::bigint,$4,$5::text::uuid)::text END \
          FROM (SELECT CASE WHEN admin_can_reach($1,$2::bigint) THEN 200 ELSE 404 END AS s) q",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[
        ColumnSpec::named("s", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- idv2_upgrade.rs ----

pub const IDV2_UPGRADE_STATUS: SqlContract = SqlContract {
    id: "admin_identity.idv2_upgrade_status",
    domain: "admin-identity",
    sql: "SELECT identity_upgrade_status()::text",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_UPGRADE_RETIREMENT_CHECK: SqlContract = SqlContract {
    id: "admin_identity.idv2_upgrade_retirement_check",
    domain: "admin-identity",
    sql: "SELECT identity_upgrade_retirement_check()::text",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_UPGRADE_SHADOW: SqlContract = SqlContract {
    id: "admin_identity.idv2_upgrade_shadow",
    domain: "admin-identity",
    sql: "SELECT identity_upgrade_shadow($1)::text",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_UPGRADE_PREFLIGHT: SqlContract = SqlContract {
    id: "admin_identity.idv2_upgrade_preflight",
    domain: "admin-identity",
    sql: "SELECT identity_upgrade_preflight($1,$2,$3,$4,$5,$6)::text",
    params: &[
        Type::INT4,
        Type::BOOL,
        Type::BOOL,
        Type::BOOL,
        Type::BOOL,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_DOCTOR: SqlContract = SqlContract {
    id: "admin_identity.idv2_doctor",
    domain: "admin-identity",
    sql: "SELECT identity_doctor($1,$2,$3,$4,$5,$6,$7)::text",
    params: &[
        Type::INT4,
        Type::BOOL,
        Type::BOOL,
        Type::BOOL,
        Type::BOOL,
        Type::BOOL,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_UPGRADE_BACKFILL_START: SqlContract = SqlContract {
    id: "admin_identity.idv2_upgrade_backfill_start",
    domain: "admin-identity",
    sql: "SELECT identity_upgrade_backfill_start($1,$2,$3::text::uuid,$4,$5,$6,$7,$8,$9,$10)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT4,
        Type::BOOL,
        Type::BOOL,
        Type::BOOL,
        Type::BOOL,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_UPGRADE_CANARY: SqlContract = SqlContract {
    id: "admin_identity.idv2_upgrade_canary",
    domain: "admin-identity",
    sql: "SELECT identity_upgrade_canary($1,$2,$3,$4,$5,$6)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::BOOL,
        Type::INT8_ARRAY,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_UPGRADE_ROLLBACK: SqlContract = SqlContract {
    id: "admin_identity.idv2_upgrade_rollback",
    domain: "admin-identity",
    sql: "SELECT identity_upgrade_rollback($1,$2)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDV2_DIAGNOSTIC_CREATE: SqlContract = SqlContract {
    id: "admin_identity.idv2_diagnostic_create",
    domain: "admin-identity",
    sql: "SELECT identity_job_create($1,'diagnostics',$2::text::uuid,$3,$4::text::uuid,$5::text::jsonb,$6)::text",
    params: &[
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

pub const IDV2_DIAGNOSTIC_DELETE: SqlContract = SqlContract {
    id: "admin_identity.idv2_diagnostic_delete",
    domain: "admin-identity",
    sql: "SELECT identity_diagnostic_delete($1,$2::text::uuid,$3)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const IDV2_DIAGNOSTIC_DOWNLOAD: SqlContract = SqlContract {
    id: "admin_identity.idv2_diagnostic_download",
    domain: "admin-identity",
    sql: "SELECT artifact, artifact_sha256, manifest_version FROM identity_diagnostic_download($1,$2::text::uuid)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[
        ColumnSpec::named("artifact", Type::BYTEA),
        ColumnSpec::named("artifact_sha256", Type::BYTEA),
        ColumnSpec::named("manifest_version", Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

/// Every SQL contract owned by `setjoin-admin-identity`.
pub const SQL_CONTRACTS: &[SqlContract] = &[
    CONSOLE_DENIED,
    USERS_LIST,
    USERS_FLAGS,
    USER_GET,
    USER_ALIASES,
    USER_QUOTA,
    USER_APP_PASSWORDS,
    USER_IS_GUEST_IN_SCOPE,
    USER_APP_ENTITLEMENTS,
    USER_EXISTS_IN_SCOPE,
    USER_SESSIONS,
    USER_QUOTA_SET,
    USER_PRIMARY_MAILBOX,
    ALIAS_DOMAIN_ALLOWED,
    USER_ALIAS_ADD,
    USER_ALIAS_REMOVE,
    USER_APP_ACCESS_SET,
    PASSWORD_POLICY_LOAD,
    COMMON_PASSWORD_EXISTS,
    ADMIN_CAN_MANAGE,
    IS_GUEST_ACCOUNT,
    USER_IN_SCOPE,
    RESET_EMAIL_SCOPED,
    RESET_EMAIL_GLOBAL,
    LIFECYCLE_ENABLED,
    USER_SIGN_INS,
    USER_CREATE,
    USER_UPDATE,
    USER_DELETE,
    USER_PASSWORD_RESET,
    USER_SECURE,
    APP_PASSWORD_REVOKE,
    USER_IMPORT_ROW,
    DEPARTMENT_IN_SCOPE,
    LOCAL_DOMAIN,
    ROLES_LIST,
    ROLE_GET,
    ROLE_MEMBERS,
    PERMISSIONS_CATALOG,
    USER_IN_DOMAIN,
    EFFECTIVE_AUTHORITY_ROWS,
    EFFECTIVE_SOURCES,
    ROLE_PERMISSIONS,
    REASON_REQUIRED_AREA,
    MISSING_REASON_AUDIT,
    PROTECTION_DENIED_AUDIT,
    ROLE_CREATE,
    ROLE_UPDATE,
    ROLE_DELETE,
    ROLE_ASSIGN,
    ROLE_REMOVE,
    ROLE_BULK_ENQUEUE,
    ACCESS_REVIEWS_LIST,
    ACCESS_REVIEW_GET,
    ACCESS_REVIEW_ITEMS,
    ACCESS_REVIEW_START,
    ACCESS_REVIEW_DECIDE,
    ACCESS_REVIEW_DECIDE_BULK,
    ACCESS_REVIEW_CLOSE,
    SCOPE_SETS_LIST,
    SCOPE_SETS_LIST_UNSCOPED,
    SCOPE_SET_GET,
    SCOPE_SET_GET_UNSCOPED,
    SCOPE_SET_MEMBERS,
    SCOPE_SET_CREATE,
    SCOPE_SET_UPDATE,
    SCOPE_SET_DELETE,
    SCOPE_SET_MEMBER_ADD,
    SCOPE_SET_MEMBER_REMOVE,
    MY_ROLES,
    JIT_ACTIVATE,
    JIT_DEACTIVATE,
    SOD_ROLE_IN_SCOPE,
    SOD_POLICY_GET,
    SOD_POLICY_DEFAULTS,
    SOD_POLICY_PUT,
    SOD_POLICY_PUT_UNSCOPED,
    DEPARTMENTS_LIST,
    DEPARTMENTS_TREE,
    DEPARTMENT_CREATE,
    DEPARTMENT_UPDATE,
    DEPARTMENT_DELETE,
    DEPARTMENT_ASSIGN_USER,
    ORG_WIDE_IDENTITY_WRITE,
    EAP_LIST,
    EAP_CREATE,
    EAP_UPDATE,
    EAP_DELETE,
    EAP_REORDER,
    EAP_APPLY,
    EAP_APPLY_STATUS,
    EAP_PREVIEW,
    EAP_MATCH_COUNT,
    DISTRIBUTION_GROUPS_LIST,
    IDV2_SOURCES_LIST,
    IDV2_PEOPLE_LIST,
    IDV2_CONFLICTS_LIST,
    IDV2_EVENTS_LIST,
    IDV2_TRANSITIONS_LIST,
    IDV2_PERSON_READ,
    IDV2_CONFLICT_READ,
    IDV2_GROUP_MAPPINGS_SAML,
    IDV2_GROUP_MAPPINGS_OIDC,
    IDV2_INVENTORY_PEOPLE,
    IDV2_INVENTORY_MAILBOXES,
    IDV2_INVENTORY_LIFECYCLE,
    IDV2_INVENTORY_LEGACY,
    IDV2_INVENTORY_PROTECTED,
    IDV2_INVENTORY_SECRETS,
    IDV2_INVENTORY_EXPORT,
    IDV2_JOB_READ,
    IDV2_JOB_RESULTS,
    IDV2_LOAD_SOURCE,
    IDV2_SOURCE_APPLY,
    IDV2_SOURCE_SECRET_SET,
    IDV2_SOURCE_LIFECYCLE,
    IDV2_JOB_CANCEL,
    IDV2_CONFLICT_DECIDE,
    IDV2_GROUP_MAPPINGS_PUT,
    IDV2_TRANSITION_REACHABLE,
    IDV2_PERSON_REACHABLE,
    IDV2_TRANSITION_READ,
    IDV2_TRANSITION_REPORT,
    IDV2_TRANSITION_REQUEST,
    IDV2_TRANSITION_APPROVE,
    IDV2_TRANSITION_DENY,
    IDV2_TRANSITION_EXECUTE,
    IDV2_TRANSITION_ROLLBACK,
    IDV2_TRANSITION_CANCEL,
    IDV2_TRANSITION_ROLLBACK_PREVIEW,
    IDV2_TRANSITION_RETRY,
    IDV2_TRANSITION_CHALLENGE_ISSUE,
    IDV2_TRANSITION_CHALLENGE_COMPLETE,
    IDV2_TRANSITION_PREVIEW,
    IDV2_TRANSITION_REBIND_PREVIEW,
    IDV2_UPGRADE_STATUS,
    IDV2_UPGRADE_RETIREMENT_CHECK,
    IDV2_UPGRADE_SHADOW,
    IDV2_UPGRADE_PREFLIGHT,
    IDV2_DOCTOR,
    IDV2_UPGRADE_BACKFILL_START,
    IDV2_UPGRADE_CANARY,
    IDV2_UPGRADE_ROLLBACK,
    IDV2_DIAGNOSTIC_CREATE,
    IDV2_DIAGNOSTIC_DELETE,
    IDV2_DIAGNOSTIC_DOWNLOAD,
];
