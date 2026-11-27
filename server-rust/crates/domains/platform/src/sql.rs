//! Static typed SQL contract catalog for `setjoin-platform` (F08).
use setjoin_sql_catalog::{
    pg_rfc3339, ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type,
};

// ---- Shared platform gates & audit helpers ----

pub const ADMIN_ORG_WIDE_GRANT: SqlContract = SqlContract {
    id: "platform.admin_org_wide_grant",
    domain: "platform",
    sql: "SELECT admin_org_wide_grant($1, $2::text::text[])",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONSOLE_DENIED: SqlContract = SqlContract {
    id: "platform.console_denied",
    domain: "platform",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REASON_REQUIRED: SqlContract = SqlContract {
    id: "platform.reason_required",
    domain: "platform",
    sql: "SELECT $1::text = ANY(reason_required_areas) FROM audit_policy WHERE id = 1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MISSING_REASON: SqlContract = SqlContract {
    id: "platform.missing_reason",
    domain: "platform",
    sql: "SELECT audit_write($1,'sensitive_action.reason_missing','',NULL,NULL,NULL,NULLIF($2::text,'')::inet,$3::text,'core')",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- alerts ----

pub const ALERTS_LIST: SqlContract = SqlContract {
    id: "platform.alerts_list",
    domain: "platform",
    sql: concat!(
        "SELECT name, consecutive, last_checked, details, sent, suppressed FROM (WITH ranked AS (",
        "SELECT check_name, status, checked_at, ",
        "ROW_NUMBER() OVER (PARTITION BY check_name ORDER BY checked_at DESC) as rn ",
        "FROM health_history), ",
        "streaks AS (",
        "SELECT check_name, COUNT(*) as consecutive, MAX(checked_at) as last_checked ",
        "FROM ranked WHERE status = 'error' ",
        "AND rn <= (SELECT COUNT(*) FROM ranked r2 WHERE r2.check_name = ranked.check_name AND r2.rn <= ranked.rn AND r2.status = 'error') ",
        "GROUP BY check_name) ",
        "SELECT s.check_name AS name, s.consecutive::bigint AS consecutive, ",
        pg_rfc3339!("s.last_checked"),
        " AS last_checked, h.details AS details, ",
        pg_rfc3339!("a.alert_sent_at"),
        " AS sent, COALESCE(a.suppressed, false) AS suppressed, s.last_checked AS at ",
        "FROM streaks s ",
        "LEFT JOIN health_history h ON h.check_name = s.check_name AND h.checked_at = s.last_checked ",
        "LEFT JOIN health_alerts a ON a.check_name = s.check_name ",
        "WHERE s.consecutive >= 3) q ORDER BY at DESC"
    ),
    params: &[],
    columns: &[
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("consecutive", Type::INT8),
        ColumnSpec::named("last_checked", Type::TEXT),
        ColumnSpec::named("details", Type::TEXT),
        ColumnSpec::named("sent", Type::TEXT),
        ColumnSpec::named("suppressed", Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ALERTS_CONFIG_GET: SqlContract = SqlContract {
    id: "platform.alerts_config_get",
    domain: "platform",
    sql: "SELECT key, value::text FROM system_config WHERE key LIKE 'hc_%' OR key LIKE 'alert_%' ORDER BY key",
    params: &[],
    columns: &[
        ColumnSpec::named("key", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ALERTS_ACK: SqlContract = SqlContract {
    id: "platform.alerts_ack",
    domain: "platform",
    sql: "INSERT INTO health_alerts (check_name, suppressed, acknowledged_at) \
          VALUES ($1::text, true, now()) \
          ON CONFLICT (check_name) DO UPDATE SET suppressed = true, acknowledged_at = now(), updated_at = now() \
          RETURNING check_name",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::named("check_name", Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ALERTS_UNSUPPRESS: SqlContract = SqlContract {
    id: "platform.alerts_unsuppress",
    domain: "platform",
    sql: "UPDATE health_alerts SET suppressed = false, updated_at = now() WHERE check_name = $1::text RETURNING check_name",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::named("check_name", Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ALERTS_CONFIG_SET: SqlContract = SqlContract {
    id: "platform.alerts_config_set",
    domain: "platform",
    sql: "INSERT INTO system_config (key, value, description) \
          SELECT e.key, e.value, 'Health check configuration' FROM jsonb_each($1::text::jsonb) e \
          ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now() \
          RETURNING key",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::named("key", Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- apps ----

pub const APPS_LIST: SqlContract = SqlContract {
    id: "platform.apps_list",
    domain: "platform",
    sql: "SELECT office_app_admin_list($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const APPS_OPERATION_REQUEST: SqlContract = SqlContract {
    id: "platform.apps_operation_request",
    domain: "platform",
    sql: "SELECT office_app_operation_request($1, $2, $3, $4, $5::text::uuid, $6::text::jsonb, $7)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
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

pub const APPS_OPERATION_RECOVER: SqlContract = SqlContract {
    id: "platform.apps_operation_recover",
    domain: "platform",
    sql: "SELECT office_app_operation_recover_request($1, $2::text::uuid, $3, $4)::text",
    params: &[Type::INT8, Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- auth_methods ----

pub const AUTH_METHODS_LIST: SqlContract = SqlContract {
    id: "platform.auth_methods_list",
    domain: "platform",
    sql: "SELECT slug, name, enabled, priority::bigint, config_json::text FROM auth_methods ORDER BY priority ASC",
    params: &[],
    columns: &[
        ColumnSpec::named("slug", Type::TEXT),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUTH_METHODS_UPDATE: SqlContract = SqlContract {
    id: "platform.auth_methods_update",
    domain: "platform",
    sql: "UPDATE auth_methods SET \
          enabled = COALESCE($1::bool, enabled), \
          priority = COALESCE($2::bigint::int, priority), \
          config_json = COALESCE($3::text::jsonb, config_json) \
          WHERE slug = $4::text RETURNING slug",
    params: &[Type::BOOL, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::named("slug", Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- branding ----

pub const BRANDING_GET: SqlContract = SqlContract {
    id: "platform.branding_get",
    domain: "platform",
    sql: "SELECT COALESCE((SELECT value #>> '{}' FROM system_config WHERE key = 'brand_name'), 'SetJoin'), \
          COALESCE((SELECT value #>> '{}' FROM system_config WHERE key = 'brand_logo_url'), '')",
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BRANDING_SET: SqlContract = SqlContract {
    id: "platform.branding_set",
    domain: "platform",
    sql: "INSERT INTO system_config (key, value, description, updated_at) \
          VALUES ($1::text, $2::text::jsonb, $3::text, now()) \
          ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now() \
          RETURNING key",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::named("key", Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- config ----

pub const CONFIG_LIST_ALL: SqlContract = SqlContract {
    id: "platform.config_list_all",
    domain: "platform",
    sql: "SELECT key, value::text, encrypted FROM system_config ORDER BY key",
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

pub const CONFIG_LIST_PREFIX: SqlContract = SqlContract {
    id: "platform.config_list_prefix",
    domain: "platform",
    sql: "SELECT key, value::text, encrypted FROM system_config WHERE key LIKE $1 ORDER BY key",
    params: &[Type::TEXT],
    columns: &[
        ColumnSpec::named("key", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("encrypted", Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONFIG_GET: SqlContract = SqlContract {
    id: "platform.config_get",
    domain: "platform",
    sql: "SELECT value::text, encrypted FROM system_config WHERE key = $1",
    params: &[Type::TEXT],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("encrypted", Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONFIG_SET: SqlContract = SqlContract {
    id: "platform.config_set",
    domain: "platform",
    sql: "INSERT INTO system_config (key, value, encrypted, updated_at) \
          VALUES ($1::text, $2::text::jsonb, $3::bool, now()) \
          ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = EXCLUDED.encrypted, updated_at = now() \
          RETURNING key",
    params: &[Type::TEXT, Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::named("key", Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONFIG_EXPORT: SqlContract = SqlContract {
    id: "platform.config_export",
    domain: "platform",
    sql: "SELECT key, value::text, encrypted, COALESCE(description,'') FROM system_config ORDER BY key",
    params: &[],
    columns: &[
        ColumnSpec::named("key", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("encrypted", Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONFIG_IMPORT_ITEM: SqlContract = SqlContract {
    id: "platform.config_import_item",
    domain: "platform",
    sql: "INSERT INTO system_config (key, value, description) \
          VALUES ($1::text, $2::text::jsonb, $3::text) \
          ON CONFLICT (key) DO UPDATE SET value = $2::text::jsonb, updated_at = now() \
          RETURNING key",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::named("key", Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- deploy ----

pub const DEPLOY_STEPS_LOAD: SqlContract = SqlContract {
    id: "platform.deploy_steps_load",
    domain: "platform",
    sql: "SELECT step_name,status,COALESCE(output,''),COALESCE(error,'') FROM deployment_steps ORDER BY step_name",
    params: &[],
    columns: &[
        ColumnSpec::named("step_name", Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DEPLOY_FENCE_COUNT: SqlContract = SqlContract {
    id: "platform.deploy_fence_count",
    domain: "platform",
    sql: "SELECT count(*)::bigint FROM deploy_remote_fence",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DEPLOY_FENCE_SET: SqlContract = SqlContract {
    id: "platform.deploy_fence_set",
    domain: "platform",
    sql: "INSERT INTO deploy_remote_fence(id,actor_user_id,detail) \
          VALUES (true,$1::bigint,$2::text) \
          ON CONFLICT(id) DO UPDATE SET detail=EXCLUDED.detail RETURNING 'null'::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DEPLOY_STEP_UPSERT: SqlContract = SqlContract {
    id: "platform.deploy_step_upsert",
    domain: "platform",
    sql: "INSERT INTO deployment_steps(step_name,status,output,error,started_at,completed_at) \
          VALUES ($1::text,$2::text,convert_from($3::bytea,'UTF8'),convert_from($4::bytea,'UTF8'),now(),CASE WHEN $2::text IN ('done','failed') THEN now() END) \
          ON CONFLICT(step_name) DO UPDATE SET status=EXCLUDED.status,output=EXCLUDED.output,error=EXCLUDED.error,\
          started_at=COALESCE(deployment_steps.started_at,EXCLUDED.started_at),\
          completed_at=CASE WHEN EXCLUDED.status IN ('done','failed') THEN now() ELSE deployment_steps.completed_at END \
          RETURNING 'null'::text",
    params: &[Type::TEXT, Type::TEXT, Type::BYTEA, Type::BYTEA],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- dns ----

pub const DNS_SCOPE_NAME: SqlContract = SqlContract {
    id: "platform.dns_scope_name",
    domain: "platform",
    sql: "SELECT name FROM domains WHERE id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("name", Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DNS_SELECTORS_ONE: SqlContract = SqlContract {
    id: "platform.dns_selectors_one",
    domain: "platform",
    sql: "SELECT selector FROM domain_signing_keys WHERE false AND $1::text <> '' LIMIT 1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::named("selector", Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DNS_SELECTORS_ALL: SqlContract = SqlContract {
    id: "platform.dns_selectors_all",
    domain: "platform",
    sql: "SELECT selector FROM domain_signing_keys WHERE false AND $1::text <> ''",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::named("selector", Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DNS_GATEWAY_HOSTNAME: SqlContract = SqlContract {
    id: "platform.dns_gateway_hostname",
    domain: "platform",
    sql: "SELECT value->>'value' FROM system_config WHERE key = 'gateway_hostname'",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DNS_UTC_STAMP: SqlContract = SqlContract {
    id: "platform.dns_utc_stamp",
    domain: "platform",
    sql: "SELECT to_char(now() AT TIME ZONE 'UTC','YYYYMMDD\"T\"HH24MISS\"Z\"')",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- domains ----

const DOMAIN_COLS: &[ColumnSpec] = &[
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::named("name", Type::TEXT),
    ColumnSpec::named("is_primary", Type::BOOL),
    ColumnSpec::named("is_local", Type::BOOL),
    ColumnSpec::named("catch_all_mailbox_id", Type::INT8),
    ColumnSpec::named("dkim_selector", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("spf_record", Type::TEXT),
    ColumnSpec::named("dmarc_policy", Type::TEXT),
    ColumnSpec::named("dmarc_rua", Type::TEXT),
    ColumnSpec::named("dmarc_ruf", Type::TEXT),
    ColumnSpec::named("mta_sts_policy", Type::TEXT),
    ColumnSpec::named("max_message_bytes", Type::INT8),
    ColumnSpec::named("quota_bytes", Type::INT8),
    ColumnSpec::unnamed(Type::TEXT),
];

pub const DOMAINS_LIST: SqlContract = SqlContract {
    id: "platform.domains_list",
    domain: "platform",
    sql: "SELECT id, name, is_primary, is_local, catch_all_mailbox_id, dkim_selector, \
          dkim_key_expires_at::TEXT, spf_record, dmarc_policy, dmarc_rua, dmarc_ruf, mta_sts_policy, \
          max_message_bytes, quota_bytes, created_at::TEXT \
          FROM domains WHERE ($1::bigint = 0 OR id = $1::bigint) ORDER BY is_primary DESC, name ASC",
    params: &[Type::INT8],
    columns: DOMAIN_COLS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DOMAINS_GET: SqlContract = SqlContract {
    id: "platform.domains_get",
    domain: "platform",
    sql: "SELECT id, name, is_primary, is_local, catch_all_mailbox_id, dkim_selector, \
          dkim_key_expires_at::TEXT, spf_record, dmarc_policy, dmarc_rua, dmarc_ruf, mta_sts_policy, \
          max_message_bytes, quota_bytes, created_at::TEXT \
          FROM domains WHERE id = $1::bigint",
    params: &[Type::INT8],
    columns: DOMAIN_COLS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DOMAINS_CREATE: SqlContract = SqlContract {
    id: "platform.domains_create",
    domain: "platform",
    sql: "INSERT INTO domains (name, is_local, is_primary, dmarc_policy, mta_sts_policy, max_message_bytes, quota_bytes) \
          VALUES ($1::text, $2::bool, $3::bool, $4::text, $5::text, $6::bigint, $7::bigint) RETURNING id",
    params: &[
        Type::TEXT,
        Type::BOOL,
        Type::BOOL,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DOMAINS_UPDATE: SqlContract = SqlContract {
    id: "platform.domains_update",
    domain: "platform",
    sql: "UPDATE domains SET \
          name = COALESCE($1::text, name), \
          is_local = COALESCE($2::bool, is_local), \
          is_primary = COALESCE($3::bool, is_primary), \
          catch_all_mailbox_id = COALESCE($4::bigint, catch_all_mailbox_id), \
          dmarc_policy = COALESCE($5::text, dmarc_policy), \
          mta_sts_policy = COALESCE($6::text, mta_sts_policy), \
          max_message_bytes = COALESCE($7::bigint, max_message_bytes), \
          quota_bytes = COALESCE($8::bigint, quota_bytes), \
          updated_at = now() \
          WHERE id = $9::bigint AND ($10::bigint = 0 OR id = $10::bigint) RETURNING id",
    params: &[
        Type::TEXT,
        Type::BOOL,
        Type::BOOL,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DOMAINS_DELETE: SqlContract = SqlContract {
    id: "platform.domains_delete",
    domain: "platform",
    sql: "DELETE FROM domains WHERE id = $1::bigint AND ($2::bigint = 0 OR id = $2::bigint) RETURNING id",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- features ----

pub const FEATURES_LIST: SqlContract = SqlContract {
    id: "platform.features_list",
    domain: "platform",
    sql: "SELECT ft.key, ft.enabled, coalesce(ft.description,''), \
          feature_registry_classify(ft.key), s.mode \
          FROM feature_toggle_registry_state s LEFT JOIN feature_toggles ft ON true \
          WHERE s.singleton ORDER BY ft.key",
    params: &[],
    columns: &[
        ColumnSpec::named("key", Type::TEXT),
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("mode", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FEATURE_TOGGLE_SET: SqlContract = SqlContract {
    id: "platform.feature_toggle_set",
    domain: "platform",
    sql: "SELECT public.feature_toggle_set($1::text, $2::bool, $3::bigint, $4::text::inet, $5::text)::text",
    params: &[Type::TEXT, Type::BOOL, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FEATURE_TOGGLE_DELETE_UNKNOWN: SqlContract = SqlContract {
    id: "platform.feature_toggle_delete_unknown",
    domain: "platform",
    sql: "SELECT public.feature_toggle_delete_unknown($1::text, $2::bigint, $3::text::inet, $4::text)::text",
    params: &[Type::TEXT, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FEATURE_TOGGLE_REGISTRY_MODE_SET: SqlContract = SqlContract {
    id: "platform.feature_toggle_registry_mode_set",
    domain: "platform",
    sql: "SELECT public.feature_toggle_registry_mode_set($1::text, $2::text, $3::bigint, $4::text::inet, $5::text)::text",
    params: &[Type::TEXT, Type::TEXT, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- federation ----

pub const FEDERATION_LIST: SqlContract = SqlContract {
    id: "platform.federation_list",
    domain: "platform",
    sql: "SELECT peer_domain, scope, enabled, created_at::TEXT, updated_at::TEXT \
          FROM federation_allowlist ORDER BY peer_domain",
    params: &[],
    columns: &[
        ColumnSpec::named("peer_domain", Type::TEXT),
        ColumnSpec::named("scope", Type::TEXT),
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FEDERATION_PEER_HEALTH: SqlContract = SqlContract {
    id: "platform.federation_peer_health",
    domain: "platform",
    sql: "SELECT federation_peer_health($1)::text",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FEDERATION_AUDIT_LIST: SqlContract = SqlContract {
    id: "platform.federation_audit_list",
    domain: "platform",
    sql: "SELECT audit_write($1,'federation_peers_list','federation_peer',NULL,NULL,NULL,$2::text::inet,'','core')",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FEDERATION_ANCHOR: SqlContract = SqlContract {
    id: "platform.federation_anchor",
    domain: "platform",
    sql: "SELECT peer_anchor FROM federation_allowlist WHERE peer_domain = $1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::named("peer_anchor", Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FEDERATION_PEER_SET: SqlContract = SqlContract {
    id: "platform.federation_peer_set",
    domain: "platform",
    sql: "SELECT federation_peer_set($1, $2, $3, $4, $5)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const FEDERATION_PEER_DELETE: SqlContract = SqlContract {
    id: "platform.federation_peer_delete",
    domain: "platform",
    sql: "SELECT federation_peer_delete($1, $2)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- health ----

pub const HEALTH_LATEST: SqlContract = SqlContract {
    id: "platform.health_latest",
    domain: "platform",
    sql: concat!(
        "SELECT DISTINCT ON (check_name) check_name, status, value::float8, threshold::float8, details, ",
        pg_rfc3339!("checked_at"),
        " FROM health_history ORDER BY check_name, checked_at DESC"
    ),
    params: &[],
    columns: &[
        ColumnSpec::named("check_name", Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::unnamed(Type::FLOAT8),
        ColumnSpec::unnamed(Type::FLOAT8),
        ColumnSpec::named("details", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- jit ----

pub const JIT_DEFAULTS_GET: SqlContract = SqlContract {
    id: "platform.jit_defaults_get",
    domain: "platform",
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

pub const JIT_DEFAULTS_PUT: SqlContract = SqlContract {
    id: "platform.jit_defaults_put",
    domain: "platform",
    sql: "SELECT (SELECT count(*) FROM public.set_system_config('jit.default_max_minutes', to_jsonb($1::bigint::int))) \
          + (SELECT count(*) FROM public.set_system_config('jit.default_require_justification', to_jsonb($2::bool)))",
    params: &[Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- jobs ----

pub const JOBS_SUMMARY: SqlContract = SqlContract {
    id: "platform.jobs_summary",
    domain: "platform",
    sql: "SELECT active::bigint, failed::bigint, dead::bigint, done::bigint, total::bigint FROM get_queue_summary($1)",
    params: &[Type::TEXT],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const JOBS_LIST: SqlContract = SqlContract {
    id: "platform.jobs_list",
    domain: "platform",
    sql: "SELECT item::text FROM list_queue($1, $2, $3, $4)",
    params: &[Type::TEXT, Type::TEXT, Type::INT4, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const JOBS_RETRY_JOURNAL: SqlContract = SqlContract {
    id: "platform.jobs_retry_journal",
    domain: "platform",
    sql: "SELECT repend_dead_journal_row($1::bigint)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const JOBS_BULK_DETAIL: SqlContract = SqlContract {
    id: "platform.jobs_bulk_detail",
    domain: "platform",
    sql: "SELECT row_to_json(b)::text FROM bulk_role_jobs b WHERE id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const JOBS_BULK_RETRY: SqlContract = SqlContract {
    id: "platform.jobs_bulk_retry",
    domain: "platform",
    sql: "SELECT public.rust_admin_bulk_role_job_retry($1, $2, $3)",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- monitor & reports ----

pub const MONITOR_DMARC_COUNTS: SqlContract = SqlContract {
    id: "platform.monitor_dmarc_counts",
    domain: "platform",
    sql: "SELECT COALESCE(SUM(count_pass),0)::bigint, COALESCE(SUM(count_fail),0)::bigint, \
          COALESCE(SUM(count_none),0)::bigint, COALESCE(SUM(count_temperror),0)::bigint \
          FROM dmarc_reports WHERE end_time = date_trunc('day', now() AT TIME ZONE 'UTC')",
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MONITOR_DMARC_BY_DOMAIN: SqlContract = SqlContract {
    id: "platform.monitor_dmarc_by_domain",
    domain: "platform",
    sql: "SELECT DISTINCT ON (domain) domain, COALESCE(SUM(count_pass),0)::bigint as pass, \
          COALESCE(SUM(count_fail),0)::bigint as fail \
          FROM dmarc_reports WHERE end_time = date_trunc('day', now() AT TIME ZONE 'UTC') \
          GROUP BY domain ORDER BY domain LIMIT 20",
    params: &[],
    columns: &[
        ColumnSpec::named("domain", Type::TEXT),
        ColumnSpec::named("pass", Type::INT8),
        ColumnSpec::named("fail", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MONITOR_DOMAIN_DMARC_POLICY: SqlContract = SqlContract {
    id: "platform.monitor_domain_dmarc_policy",
    domain: "platform",
    sql: "SELECT dmarc_policy FROM domains WHERE name = $1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::named("dmarc_policy", Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MONITOR_QUEUE_COUNTS: SqlContract = SqlContract {
    id: "platform.monitor_queue_counts",
    domain: "platform",
    sql: "SELECT COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0)::bigint, \
          COALESCE(SUM(CASE WHEN status='deferred' THEN 1 ELSE 0 END),0)::bigint, \
          COALESCE(SUM(CASE WHEN status='bounced' THEN 1 ELSE 0 END),0)::bigint \
          FROM outbound_queue",
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

pub const MONITOR_QUARANTINE_ACTIVE: SqlContract = SqlContract {
    id: "platform.monitor_quarantine_active",
    domain: "platform",
    sql: "SELECT COUNT(*) FROM quarantined_messages WHERE released_at IS NULL AND rejected_at IS NULL",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MONITOR_QUARANTINE_TODAY: SqlContract = SqlContract {
    id: "platform.monitor_quarantine_today",
    domain: "platform",
    sql: "SELECT COUNT(*) FROM quarantined_messages WHERE quarantined_at >= date_trunc('day', now() AT TIME ZONE 'UTC')",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MONITOR_QUARANTINE_RELEASED: SqlContract = SqlContract {
    id: "platform.monitor_quarantine_released",
    domain: "platform",
    sql: "SELECT COUNT(*) FROM quarantined_messages WHERE released_at IS NOT NULL",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MONITOR_VOLUME_RECEIVED: SqlContract = SqlContract {
    id: "platform.monitor_volume_received",
    domain: "platform",
    sql: "SELECT COUNT(*) FROM messages WHERE received_at >= now() - interval '24 hours'",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MONITOR_VOLUME_SENT: SqlContract = SqlContract {
    id: "platform.monitor_volume_sent",
    domain: "platform",
    sql: "SELECT COUNT(*) FROM outbound_queue WHERE queued_at >= now() - interval '24 hours'",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MONITOR_VOLUME_BYTES: SqlContract = SqlContract {
    id: "platform.monitor_volume_bytes",
    domain: "platform",
    sql: "SELECT COALESCE(SUM(size_bytes),0)::bigint FROM messages WHERE received_at >= now() - interval '24 hours'",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MONITOR_THREATS_AUTH: SqlContract = SqlContract {
    id: "platform.monitor_threats_auth",
    domain: "platform",
    sql: "SELECT COUNT(*) FROM message_trace WHERE event = 'auth_failure' AND occurred_at >= now() - interval '24 hours'",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MONITOR_THREATS_RBL: SqlContract = SqlContract {
    id: "platform.monitor_threats_rbl",
    domain: "platform",
    sql: "SELECT COUNT(*) FROM message_trace WHERE event = 'rbl_block' AND occurred_at >= now() - interval '24 hours'",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MONITOR_THREATS_VIRUS: SqlContract = SqlContract {
    id: "platform.monitor_threats_virus",
    domain: "platform",
    sql: "SELECT virus_name, COUNT(*)::bigint as cnt FROM quarantined_messages \
          WHERE virus_name IS NOT NULL AND quarantined_at >= now() - interval '7 days' \
          GROUP BY virus_name ORDER BY cnt DESC LIMIT 5",
    params: &[],
    columns: &[
        ColumnSpec::named("virus_name", Type::TEXT),
        ColumnSpec::named("cnt", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REPORTS_SUMMARY_TOTALS: SqlContract = SqlContract {
    id: "platform.reports_summary_totals",
    domain: "platform",
    sql: "SELECT COALESCE(COUNT(*) FILTER (WHERE event IN ('delivered','deferred')), 0)::bigint, \
          COALESCE(COUNT(*) FILTER (WHERE event = 'received'), 0)::bigint, \
          COALESCE(COUNT(*) FILTER (WHERE event = 'bounced'), 0)::bigint, \
          COALESCE(COUNT(*) FILTER (WHERE event = 'spam_filtered'), 0)::bigint \
          FROM message_trace WHERE occurred_at >= (now() - ($1::bigint * 86400) * interval '1 second')",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REPORTS_SUMMARY_DAILY: SqlContract = SqlContract {
    id: "platform.reports_summary_daily",
    domain: "platform",
    sql: "SELECT day::text, sent, received, bounced, spam FROM (\
          SELECT date_trunc('day', occurred_at)::date as day, \
          COALESCE(COUNT(*) FILTER (WHERE event IN ('delivered','deferred')), 0)::bigint as sent, \
          COALESCE(COUNT(*) FILTER (WHERE event = 'received'), 0)::bigint as received, \
          COALESCE(COUNT(*) FILTER (WHERE event = 'bounced'), 0)::bigint as bounced, \
          COALESCE(COUNT(*) FILTER (WHERE event = 'spam_filtered'), 0)::bigint as spam \
          FROM message_trace WHERE occurred_at >= (now() - ($1::bigint * 86400) * interval '1 second') \
          GROUP BY day ORDER BY day) q ORDER BY day",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("sent", Type::INT8),
        ColumnSpec::named("received", Type::INT8),
        ColumnSpec::named("bounced", Type::INT8),
        ColumnSpec::named("spam", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REPORTS_TOP_SENDERS: SqlContract = SqlContract {
    id: "platform.reports_top_senders",
    domain: "platform",
    sql: "SELECT from_addr, COUNT(*)::bigint as cnt FROM message_trace \
          WHERE occurred_at >= (now() - ($1::bigint * 86400) * interval '1 second') \
          AND event IN ('received','delivered','deferred') \
          GROUP BY from_addr ORDER BY cnt DESC LIMIT 10",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("from_addr", Type::TEXT),
        ColumnSpec::named("cnt", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REPORTS_TOP_RECIPIENTS: SqlContract = SqlContract {
    id: "platform.reports_top_recipients",
    domain: "platform",
    sql: "SELECT rcpt_addr, COUNT(*)::bigint as cnt FROM message_trace \
          WHERE occurred_at >= (now() - ($1::bigint * 86400) * interval '1 second') \
          AND event IN ('received','delivered','deferred') \
          GROUP BY rcpt_addr ORDER BY cnt DESC LIMIT 10",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("rcpt_addr", Type::TEXT),
        ColumnSpec::named("cnt", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REPORTS_RULE_TRIGGERS: SqlContract = SqlContract {
    id: "platform.reports_rule_triggers",
    domain: "platform",
    sql: "SELECT COALESCE(details->>'rule_name','unknown') as rule_name, COUNT(*)::bigint as cnt \
          FROM message_trace WHERE occurred_at >= (now() - ($1::bigint * 86400) * interval '1 second') \
          AND event = 'rule_applied' GROUP BY rule_name ORDER BY cnt DESC LIMIT 10",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("rule_name", Type::TEXT),
        ColumnSpec::named("cnt", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- sod ----

pub const SOD_MODE_GET: SqlContract = SqlContract {
    id: "platform.sod_mode_get",
    domain: "platform",
    sql: "SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'dengbao.sod_mode'), false), \
          v.violation_type, v.subject, v.detail FROM (SELECT 1) one LEFT JOIN admin_sod_precheck() v ON true",
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::named("violation_type", Type::TEXT),
        ColumnSpec::named("subject", Type::TEXT),
        ColumnSpec::named("detail", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SOD_MODE_SET: SqlContract = SqlContract {
    id: "platform.sod_mode_set",
    domain: "platform",
    sql: "SELECT public.rust_platform_sod_mode_set($1::bigint, $2::bool, $3::text)::text",
    params: &[Type::INT8, Type::BOOL, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- storage ----

pub const STORAGE_DR_SCAN_LIST: SqlContract = SqlContract {
    id: "platform.storage_dr_scan_list",
    domain: "platform",
    sql: concat!(
        "SELECT id, status, total_scanned, orphaned_count, missing_count, refcount_drift_count, reimported_count, ",
        pg_rfc3339!("started_at"),
        ", ",
        pg_rfc3339!("completed_at"),
        " FROM storage_dr_scans ORDER BY started_at DESC LIMIT 100"
    ),
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::named("total_scanned", Type::INT8),
        ColumnSpec::named("orphaned_count", Type::INT8),
        ColumnSpec::named("missing_count", Type::INT8),
        ColumnSpec::named("refcount_drift_count", Type::INT8),
        ColumnSpec::named("reimported_count", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const STORAGE_DR_SCAN_GET: SqlContract = SqlContract {
    id: "platform.storage_dr_scan_get",
    domain: "platform",
    sql: concat!(
        "SELECT id, status, total_scanned, orphaned_count, missing_count, refcount_drift_count, reimported_count, details::text, ",
        pg_rfc3339!("started_at"),
        ", ",
        pg_rfc3339!("completed_at"),
        " FROM storage_dr_scans WHERE id = $1"
    ),
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::named("total_scanned", Type::INT8),
        ColumnSpec::named("orphaned_count", Type::INT8),
        ColumnSpec::named("missing_count", Type::INT8),
        ColumnSpec::named("refcount_drift_count", Type::INT8),
        ColumnSpec::named("reimported_count", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const STORAGE_MIGRATE_LIST: SqlContract = SqlContract {
    id: "platform.storage_migrate_list",
    domain: "platform",
    sql: concat!(
        "SELECT id, source_driver, target_driver, status, COALESCE(total_blobs, 0), COALESCE(migrated, 0), ",
        pg_rfc3339!("started_at"),
        ", ",
        pg_rfc3339!("completed_at"),
        " FROM storage_migrations ORDER BY started_at DESC LIMIT 20"
    ),
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("source_driver", Type::TEXT),
        ColumnSpec::named("target_driver", Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const STORAGE_MIGRATE_STATUS: SqlContract = SqlContract {
    id: "platform.storage_migrate_status",
    domain: "platform",
    sql: concat!(
        "SELECT status, COALESCE(total_blobs, 0), COALESCE(migrated, 0), last_key, ",
        pg_rfc3339!("started_at"),
        ", ",
        pg_rfc3339!("completed_at"),
        " FROM storage_migrations WHERE id = $1"
    ),
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::named("last_key", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const STORAGE_REIMPORT_BLOB: SqlContract = SqlContract {
    id: "platform.storage_reimport_blob",
    domain: "platform",
    sql: "SELECT public.rust_blob_register_metadata($1, $2, $3, $4)",
    params: &[Type::TEXT, Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const STORAGE_RECONCILE_COUNT: SqlContract = SqlContract {
    id: "platform.storage_reconcile_count",
    domain: "platform",
    sql: "UPDATE storage_dr_scans SET reimported_count = $2 WHERE id = $1",
    params: &[Type::INT8, Type::INT8],
    columns: &[],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const STORAGE_RECONCILE_DETAILS: SqlContract = SqlContract {
    id: "platform.storage_reconcile_details",
    domain: "platform",
    sql: "SELECT status, details::text FROM storage_dr_scans WHERE id = $1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const STORAGE_BEGIN_SCAN: SqlContract = SqlContract {
    id: "platform.storage_begin_scan",
    domain: "platform",
    sql: "INSERT INTO storage_dr_scans(status) VALUES ('running') RETURNING id",
    params: &[],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const STORAGE_BEGIN_MIGRATION: SqlContract = SqlContract {
    id: "platform.storage_begin_migration",
    domain: "platform",
    sql: "INSERT INTO storage_migrations(source_driver,target_driver,status) VALUES ('s3',$1,'dual_write') RETURNING id",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const STORAGE_MIGRATION_ROW_STATUS: SqlContract = SqlContract {
    id: "platform.storage_migration_row_status",
    domain: "platform",
    sql: "SELECT status FROM storage_migrations WHERE id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("status", Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- system ----

pub const SYSTEM_SCHEMA_VERSION: SqlContract = SqlContract {
    id: "platform.system_schema_version",
    domain: "platform",
    sql: "SELECT COALESCE(MAX(version), 0)::bigint FROM schema_migrations",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SYSTEM_BACKUP_LIST: SqlContract = SqlContract {
    id: "platform.system_backup_list",
    domain: "platform",
    sql: concat!(
        "SELECT id, status, blob_count::bigint, blob_total_size, config_size, manifest_timestamp, ",
        "blobs_copied::bigint, blobs_skipped::bigint, ",
        pg_rfc3339!("started_at"),
        ", ",
        pg_rfc3339!("completed_at"),
        ", ",
        pg_rfc3339!("created_at"),
        " FROM backup_runs ORDER BY created_at DESC, id DESC LIMIT 50"
    ),
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::named("blob_total_size", Type::INT8),
        ColumnSpec::named("config_size", Type::INT8),
        ColumnSpec::named("manifest_timestamp", Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SYSTEM_BACKUP_ENQUEUE: SqlContract = SqlContract {
    id: "platform.system_backup_enqueue",
    domain: "platform",
    sql: "INSERT INTO backup_runs (status) VALUES ('pending') RETURNING id",
    params: &[],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- terms ----

pub const TERMS_LIST: SqlContract = SqlContract {
    id: "platform.terms_list",
    domain: "platform",
    sql: "SELECT id, name, version::bigint, body_md, lang, require_scroll, enabled, created_at::text \
          FROM terms_of_use ORDER BY name ASC LIMIT $1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::named("body_md", Type::TEXT),
        ColumnSpec::named("lang", Type::TEXT),
        ColumnSpec::named("require_scroll", Type::BOOL),
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TERMS_CREATE: SqlContract = SqlContract {
    id: "platform.terms_create",
    domain: "platform",
    sql: "SELECT public.rust_platform_tou_create($1::bigint, $2::text, $3::bigint, $4::text, $5::text, $6::bool, $7::bool, $8::text)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
        Type::BOOL,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const TERMS_UPDATE: SqlContract = SqlContract {
    id: "platform.terms_update",
    domain: "platform",
    sql: "SELECT public.rust_platform_tou_update($1::bigint, $2::bigint, $3::text, $4::bigint, $5::text, $6::text, $7::bool, $8::bool, $9::text)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
        Type::BOOL,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const TERMS_DELETE: SqlContract = SqlContract {
    id: "platform.terms_delete",
    domain: "platform",
    sql: "SELECT public.rust_platform_tou_delete($1::bigint, $2::bigint, $3::text)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- updates ----

pub const UPDATES_HISTORY: SqlContract = SqlContract {
    id: "platform.updates_history",
    domain: "platform",
    sql: concat!(
        "SELECT id, from_version, to_version, mode, ddl_classification, status, ",
        pg_rfc3339!("started_at"),
        ", ",
        pg_rfc3339!("completed_at"),
        ", downtime_ms, COALESCE(error_message, '') FROM upgrade_history ORDER BY started_at DESC LIMIT 50"
    ),
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("from_version", Type::TEXT),
        ColumnSpec::named("to_version", Type::TEXT),
        ColumnSpec::named("mode", Type::TEXT),
        ColumnSpec::named("ddl_classification", Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("downtime_ms", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UPDATES_DEVICES_TOTAL: SqlContract = SqlContract {
    id: "platform.updates_devices_total",
    domain: "platform",
    sql: "SELECT COUNT(*)::bigint FROM devices d WHERE ($1::bigint = 0 OR admin_can_reach_perm($1, d.user_id, $2::text[]))",
    params: &[Type::INT8, Type::TEXT_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UPDATES_DEVICES_BY_VERSION: SqlContract = SqlContract {
    id: "platform.updates_devices_by_version",
    domain: "platform",
    sql: "SELECT COALESCE(app_version, 'unknown'), COUNT(*)::bigint FROM devices d \
          WHERE ($1::bigint = 0 OR admin_can_reach_perm($1, d.user_id, $2::text[])) \
          GROUP BY app_version ORDER BY COUNT(*) DESC LIMIT 10",
    params: &[Type::INT8, Type::TEXT_ARRAY],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UPDATES_DEVICES_BY_PLATFORM: SqlContract = SqlContract {
    id: "platform.updates_devices_by_platform",
    domain: "platform",
    sql: "SELECT platform, COUNT(*)::bigint FROM devices d \
          WHERE ($1::bigint = 0 OR admin_can_reach_perm($1, d.user_id, $2::text[])) \
          GROUP BY platform ORDER BY COUNT(*) DESC",
    params: &[Type::INT8, Type::TEXT_ARRAY],
    columns: &[
        ColumnSpec::named("platform", Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UPDATES_DEVICES_LIST: SqlContract = SqlContract {
    id: "platform.updates_devices_list",
    domain: "platform",
    sql: "SELECT d.id, d.device_name, d.platform, d.os_version, d.app_version FROM devices d \
          WHERE ($3::bigint = 0 OR admin_can_reach_perm($3, d.user_id, $4::text[])) \
          ORDER BY d.last_seen DESC NULLS LAST LIMIT $1 OFFSET $2",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT_ARRAY],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("device_name", Type::TEXT),
        ColumnSpec::named("platform", Type::TEXT),
        ColumnSpec::named("os_version", Type::TEXT),
        ColumnSpec::named("app_version", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UPDATES_PUSH_NOTIFY: SqlContract = SqlContract {
    id: "platform.updates_push_notify",
    domain: "platform",
    sql: "SELECT pg_notify('update_available', $1::text)",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- upgrades (release-first control plane) ----

pub const UPGRADE_CONSOLE_READ: SqlContract = SqlContract {
    id: "platform.upgrade_console_read",
    domain: "platform",
    sql: "SELECT upgrade_console_read($1::bigint)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UPGRADE_RECOVERY_CONTEXT_READ: SqlContract = SqlContract {
    id: "platform.upgrade_recovery_context_read",
    domain: "platform",
    sql: "SELECT upgrade_recovery_context_read($1::bigint)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UPGRADE_INTENT_READ: SqlContract = SqlContract {
    id: "platform.upgrade_intent_read",
    domain: "platform",
    sql: "SELECT upgrade_intent_read($1::bigint)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UPGRADE_INTENT_DIAGNOSTICS: SqlContract = SqlContract {
    id: "platform.upgrade_intent_diagnostics",
    domain: "platform",
    sql: "SELECT upgrade_intent_diagnostics($1::bigint,$2::bigint)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UPGRADE_INTENT_PREVIEW: SqlContract = SqlContract {
    id: "platform.upgrade_intent_preview",
    domain: "platform",
    sql: "SELECT upgrade_intent_preview($1::bigint,$2::text,$3::text,CASE WHEN $4::bigint IS NULL THEN NULL ELSE 'epoch'::timestamptz+$4::bigint*interval '1 microsecond' END)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UPGRADE_CHALLENGE_COMPLETE: SqlContract = SqlContract {
    id: "platform.upgrade_challenge_complete",
    domain: "platform",
    sql: "SELECT upgrade_challenge_complete($1::bigint,$2::text::uuid,$3::bytea,$4::bytea,$5::text[],$6::text)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::BYTEA,
        Type::BYTEA,
        Type::TEXT_ARRAY,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const UPGRADE_CHALLENGE_ISSUE: SqlContract = SqlContract {
    id: "platform.upgrade_challenge_issue",
    domain: "platform",
    sql: "SELECT upgrade_challenge_issue($1::bigint,$2::text,$3::text,CASE WHEN $4::bigint IS NULL THEN NULL ELSE 'epoch'::timestamptz+$4::bigint*interval '1 microsecond' END,$5::text,$6::text::uuid)::text",
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

pub const UPGRADE_INTENT_REQUEST: SqlContract = SqlContract {
    id: "platform.upgrade_intent_request",
    domain: "platform",
    sql: "SELECT upgrade_intent_request($1::bigint,$2::text,$3::text,CASE WHEN $4::bigint IS NULL THEN NULL ELSE 'epoch'::timestamptz+$4::bigint*interval '1 microsecond' END,$5::text,$6::text::uuid,$7::text::uuid)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
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

pub const UPGRADE_INTENT_CANCEL: SqlContract = SqlContract {
    id: "platform.upgrade_intent_cancel",
    domain: "platform",
    sql: "SELECT upgrade_intent_cancel($1::bigint,$2::bigint,$3::bigint,$4::text)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const UPGRADE_RECOVERY_SET_RECORD: SqlContract = SqlContract {
    id: "platform.upgrade_recovery_set_record",
    domain: "platform",
    sql: "SELECT upgrade_recovery_set_record($1::bigint,$2::text::uuid,$3::text::uuid,$4::text,$5::int,$6::text,$7::text::jsonb,'epoch'::timestamptz+$8::bigint*interval '1 microsecond','epoch'::timestamptz+$9::bigint*interval '1 microsecond')::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT4,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const UPGRADE_RESTORE_PROOF_RECORD: SqlContract = SqlContract {
    id: "platform.upgrade_restore_proof_record",
    domain: "platform",
    sql: "SELECT upgrade_restore_proof_record($1::bigint,$2::text::uuid,$3::text::uuid,$4::text,$5::text::jsonb,'epoch'::timestamptz+$6::bigint*interval '1 microsecond')::text",
    params: &[
        Type::INT8,
        Type::TEXT,
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

// ---- webhooks ----

pub const WEBHOOKS_LIST: SqlContract = SqlContract {
    id: "platform.webhooks_list",
    domain: "platform",
    sql: concat!(
        "SELECT id, user_id, url, event_types::text, scope, is_active, ",
        pg_rfc3339!("created_at"),
        ", ",
        pg_rfc3339!("updated_at"),
        " FROM webhook_subscriptions ORDER BY created_at DESC"
    ),
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("user_id", Type::INT8),
        ColumnSpec::named("url", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("scope", Type::TEXT),
        ColumnSpec::named("is_active", Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBHOOKS_DELIVERIES: SqlContract = SqlContract {
    id: "platform.webhooks_deliveries",
    domain: "platform",
    sql: concat!(
        "SELECT id, event_id, event_type, response_code, latency_ms, attempt, status, error_message, ",
        pg_rfc3339!("created_at"),
        " FROM webhook_deliveries WHERE subscription_id = $1 ORDER BY created_at DESC LIMIT 200"
    ),
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("event_id", Type::TEXT),
        ColumnSpec::named("event_type", Type::TEXT),
        ColumnSpec::named("response_code", Type::INT4),
        ColumnSpec::named("latency_ms", Type::INT4),
        ColumnSpec::named("attempt", Type::INT4),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::named("error_message", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBHOOKS_CREATE: SqlContract = SqlContract {
    id: "platform.webhooks_create",
    domain: "platform",
    sql: "INSERT INTO webhook_subscriptions (user_id, url, secret_enc, secret_key_id, event_types, scope) \
          VALUES ($1::bigint, $2::text, $3::bytea, $4::text, $5::text::jsonb, $6::text) RETURNING id",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::BYTEA,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBHOOKS_DELETE: SqlContract = SqlContract {
    id: "platform.webhooks_delete",
    domain: "platform",
    sql: "DELETE FROM webhook_subscriptions WHERE id = $1::bigint AND user_id = $2::bigint RETURNING id",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBHOOKS_ROTATE_READ: SqlContract = SqlContract {
    id: "platform.webhooks_rotate_read",
    domain: "platform",
    sql: "SELECT secret, secret_enc, secret_key_id FROM webhook_subscriptions WHERE id = $1 AND user_id = $2",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("secret", Type::TEXT),
        ColumnSpec::named("secret_enc", Type::BYTEA),
        ColumnSpec::named("secret_key_id", Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBHOOKS_ROTATE_UPDATE: SqlContract = SqlContract {
    id: "platform.webhooks_rotate_update",
    domain: "platform",
    sql: "UPDATE webhook_subscriptions \
          SET prev_secret = NULL, prev_secret_enc = $3::bytea, prev_secret_key_id = $4::text, \
              secret = NULL, secret_enc = $5::bytea, secret_key_id = $4::text \
          WHERE id = $1::bigint AND user_id = $2::bigint \
            AND secret IS NOT DISTINCT FROM $6::text \
            AND secret_enc IS NOT DISTINCT FROM $7::bytea \
            AND secret_key_id IS NOT DISTINCT FROM $8::text \
          RETURNING id",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::BYTEA,
        Type::TEXT,
        Type::BYTEA,
        Type::TEXT,
        Type::BYTEA,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- welcome ----

pub const WELCOME_GET: SqlContract = SqlContract {
    id: "platform.welcome_get",
    domain: "platform",
    sql: "SELECT get_system_config('welcome_email')::text",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WELCOME_PUT: SqlContract = SqlContract {
    id: "platform.welcome_put",
    domain: "platform",
    sql: "SELECT key FROM public.set_system_config('welcome_email', $1::text::jsonb, false, $2::bigint)",
    params: &[Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::named("key", Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WELCOME_TEST_SEND: SqlContract = SqlContract {
    id: "platform.welcome_test_send",
    domain: "platform",
    sql: "SELECT public.rust_platform_welcome_test_send($1::bigint, $2::text, $3::text, $4::text)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    ADMIN_ORG_WIDE_GRANT,
    CONSOLE_DENIED,
    REASON_REQUIRED,
    MISSING_REASON,
    ALERTS_LIST,
    ALERTS_CONFIG_GET,
    ALERTS_ACK,
    ALERTS_UNSUPPRESS,
    ALERTS_CONFIG_SET,
    APPS_LIST,
    APPS_OPERATION_REQUEST,
    APPS_OPERATION_RECOVER,
    AUTH_METHODS_LIST,
    AUTH_METHODS_UPDATE,
    BRANDING_GET,
    BRANDING_SET,
    CONFIG_LIST_ALL,
    CONFIG_LIST_PREFIX,
    CONFIG_GET,
    CONFIG_SET,
    CONFIG_EXPORT,
    CONFIG_IMPORT_ITEM,
    DEPLOY_STEPS_LOAD,
    DEPLOY_FENCE_COUNT,
    DEPLOY_FENCE_SET,
    DEPLOY_STEP_UPSERT,
    DNS_SCOPE_NAME,
    DNS_SELECTORS_ONE,
    DNS_SELECTORS_ALL,
    DNS_GATEWAY_HOSTNAME,
    DNS_UTC_STAMP,
    DOMAINS_LIST,
    DOMAINS_GET,
    DOMAINS_CREATE,
    DOMAINS_UPDATE,
    DOMAINS_DELETE,
    FEATURES_LIST,
    FEATURE_TOGGLE_SET,
    FEATURE_TOGGLE_DELETE_UNKNOWN,
    FEATURE_TOGGLE_REGISTRY_MODE_SET,
    FEDERATION_LIST,
    FEDERATION_PEER_HEALTH,
    FEDERATION_AUDIT_LIST,
    FEDERATION_ANCHOR,
    FEDERATION_PEER_SET,
    FEDERATION_PEER_DELETE,
    HEALTH_LATEST,
    JIT_DEFAULTS_GET,
    JIT_DEFAULTS_PUT,
    JOBS_SUMMARY,
    JOBS_LIST,
    JOBS_RETRY_JOURNAL,
    JOBS_BULK_DETAIL,
    JOBS_BULK_RETRY,
    MONITOR_DMARC_COUNTS,
    MONITOR_DMARC_BY_DOMAIN,
    MONITOR_DOMAIN_DMARC_POLICY,
    MONITOR_QUEUE_COUNTS,
    MONITOR_QUARANTINE_ACTIVE,
    MONITOR_QUARANTINE_TODAY,
    MONITOR_QUARANTINE_RELEASED,
    MONITOR_VOLUME_RECEIVED,
    MONITOR_VOLUME_SENT,
    MONITOR_VOLUME_BYTES,
    MONITOR_THREATS_AUTH,
    MONITOR_THREATS_RBL,
    MONITOR_THREATS_VIRUS,
    REPORTS_SUMMARY_TOTALS,
    REPORTS_SUMMARY_DAILY,
    REPORTS_TOP_SENDERS,
    REPORTS_TOP_RECIPIENTS,
    REPORTS_RULE_TRIGGERS,
    SOD_MODE_GET,
    SOD_MODE_SET,
    STORAGE_DR_SCAN_LIST,
    STORAGE_DR_SCAN_GET,
    STORAGE_MIGRATE_LIST,
    STORAGE_MIGRATE_STATUS,
    STORAGE_REIMPORT_BLOB,
    STORAGE_RECONCILE_COUNT,
    STORAGE_RECONCILE_DETAILS,
    STORAGE_BEGIN_SCAN,
    STORAGE_BEGIN_MIGRATION,
    STORAGE_MIGRATION_ROW_STATUS,
    SYSTEM_SCHEMA_VERSION,
    SYSTEM_BACKUP_LIST,
    SYSTEM_BACKUP_ENQUEUE,
    TERMS_LIST,
    TERMS_CREATE,
    TERMS_UPDATE,
    TERMS_DELETE,
    UPDATES_HISTORY,
    UPDATES_DEVICES_TOTAL,
    UPDATES_DEVICES_BY_VERSION,
    UPDATES_DEVICES_BY_PLATFORM,
    UPDATES_DEVICES_LIST,
    UPDATES_PUSH_NOTIFY,
    UPGRADE_CONSOLE_READ,
    UPGRADE_RECOVERY_CONTEXT_READ,
    UPGRADE_INTENT_READ,
    UPGRADE_INTENT_DIAGNOSTICS,
    UPGRADE_INTENT_PREVIEW,
    UPGRADE_CHALLENGE_COMPLETE,
    UPGRADE_CHALLENGE_ISSUE,
    UPGRADE_INTENT_REQUEST,
    UPGRADE_INTENT_CANCEL,
    UPGRADE_RECOVERY_SET_RECORD,
    UPGRADE_RESTORE_PROOF_RECORD,
    WEBHOOKS_LIST,
    WEBHOOKS_DELIVERIES,
    WEBHOOKS_CREATE,
    WEBHOOKS_DELETE,
    WEBHOOKS_ROTATE_READ,
    WEBHOOKS_ROTATE_UPDATE,
    WELCOME_GET,
    WELCOME_PUT,
    WELCOME_TEST_SEND,
];
