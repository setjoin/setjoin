//! Static typed SQL contract catalog for `setjoin-devices` (F07).
use setjoin_sql_catalog::{
    pg_rfc3339, ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type,
};

const MDM_DEVICE_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("user_id", Type::INT8),
    ColumnSpec::named("platform", Type::TEXT),
    ColumnSpec::named("device_name", Type::TEXT),
    ColumnSpec::named("os_version", Type::TEXT),
    ColumnSpec::named("app_version", Type::TEXT),
    ColumnSpec::named("passcode_set", Type::BOOL),
    ColumnSpec::named("passcode_compliant", Type::BOOL),
    ColumnSpec::named("encryption_enabled", Type::BOOL),
    ColumnSpec::named("jailbroken", Type::BOOL),
    ColumnSpec::named("jailbreak_method", Type::TEXT),
    ColumnSpec::named("compliance_status", Type::TEXT),
    ColumnSpec::named("non_compliance_reasons", Type::TEXT_ARRAY),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("wipe_requested", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
];

macro_rules! mdm_device_select {
    () => {
        concat!(
            "SELECT device_id::text, user_id, platform, device_name, os_version, app_version, ",
            "passcode_set, passcode_compliant, encryption_enabled, jailbroken, jailbreak_method, ",
            "compliance_status, non_compliance_reasons, ",
            pg_rfc3339!("grace_until"),
            ", wipe_requested, COALESCE(wipe_level, ''), ",
            pg_rfc3339!("wipe_requested_at"),
            ", ",
            pg_rfc3339!("wipe_acked_at"),
            ", ",
            pg_rfc3339!("last_checkin_at"),
            ", ",
            pg_rfc3339!("created_at"),
            ", ",
            pg_rfc3339!("updated_at"),
            " FROM mdm_device_state"
        )
    };
}

pub const CONSOLE_DENIED: SqlContract = SqlContract {
    id: "devices.console_denied",
    domain: "devices",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

const LOCKDOWN_QUEUE_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::named("user_id", Type::INT8),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("enroll_state", Type::TEXT),
    ColumnSpec::named("enrolled_by", Type::INT8),
    ColumnSpec::named("email", Type::TEXT),
    ColumnSpec::named("approved_by", Type::INT8),
    ColumnSpec::named("email", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
];

pub const LOCKDOWN_QUEUE: SqlContract = SqlContract {
    id: "devices.lockdown_queue",
    domain: "devices",
    sql: concat!(
        "SELECT d.id, d.user_id, COALESCE(u.email,''), COALESCE(u.display_name,''), ",
        "COALESCE(d.device_name,''), COALESCE(d.platform,''), d.enroll_state, ",
        "d.enrolled_by, eb.email, d.approved_by, ab.email, ",
        pg_rfc3339!("d.approved_at"),
        ", ",
        pg_rfc3339!("(SELECT MAX(created_at) FROM device_enroll_events e WHERE e.device_id = d.id)"),
        ", ",
        pg_rfc3339!("(SELECT MIN(created_at) FROM device_enroll_events e WHERE e.device_id = d.id AND e.to_state = d.enroll_state)"),
        ", ",
        pg_rfc3339!("d.revoked_at"),
        " FROM devices d JOIN users u ON u.id = d.user_id ",
        "LEFT JOIN users eb ON eb.id = d.enrolled_by LEFT JOIN users ab ON ab.id = d.approved_by ",
        "WHERE d.enroll_state = $1::text AND ($2::text = '%%' OR u.email ILIKE $2::text OR u.display_name ILIKE $2::text) ",
        "AND (admin_can_reach_perm($4::bigint, d.user_id, ARRAY['mam.read'])) ",
        "ORDER BY (SELECT MIN(created_at) FROM device_enroll_events e WHERE e.device_id = d.id AND e.to_state = d.enroll_state) DESC NULLS LAST, d.id DESC ",
        "LIMIT $3::bigint"
    ),
    params: &[Type::TEXT, Type::TEXT, Type::INT8, Type::INT8],
    columns: LOCKDOWN_QUEUE_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOCKDOWN_QUEUE_MUTANT: SqlContract = SqlContract {
    id: "devices.lockdown_queue_mutant",
    domain: "devices",
    sql: concat!(
        "SELECT d.id, d.user_id, COALESCE(u.email,''), COALESCE(u.display_name,''), ",
        "COALESCE(d.device_name,''), COALESCE(d.platform,''), d.enroll_state, ",
        "d.enrolled_by, eb.email, d.approved_by, ab.email, ",
        pg_rfc3339!("d.approved_at"),
        ", ",
        pg_rfc3339!("(SELECT MAX(created_at) FROM device_enroll_events e WHERE e.device_id = d.id)"),
        ", ",
        pg_rfc3339!("(SELECT MIN(created_at) FROM device_enroll_events e WHERE e.device_id = d.id AND e.to_state = d.enroll_state)"),
        ", ",
        pg_rfc3339!("d.revoked_at"),
        " FROM devices d JOIN users u ON u.id = d.user_id ",
        "LEFT JOIN users eb ON eb.id = d.enrolled_by LEFT JOIN users ab ON ab.id = d.approved_by ",
        "WHERE d.enroll_state = $1::text AND ($2::text = '%%' OR u.email ILIKE $2::text OR u.display_name ILIKE $2::text) ",
        "AND ($4::bigint > 0 OR true) ",
        "ORDER BY (SELECT MIN(created_at) FROM device_enroll_events e WHERE e.device_id = d.id AND e.to_state = d.enroll_state) DESC NULLS LAST, d.id DESC ",
        "LIMIT $3::bigint"
    ),
    params: &[Type::TEXT, Type::TEXT, Type::INT8, Type::INT8],
    columns: LOCKDOWN_QUEUE_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

const LOCKDOWN_DEVICES_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::named("user_id", Type::INT8),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("enroll_state", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
];

pub const LOCKDOWN_DEVICES_OF: SqlContract = SqlContract {
    id: "devices.lockdown_devices_of",
    domain: "devices",
    sql: concat!(
        "SELECT id, user_id, COALESCE(device_name,''), COALESCE(platform,''), enroll_state, ",
        pg_rfc3339!("revoked_at"),
        " FROM devices WHERE user_id = $1 AND (admin_can_reach_perm($2::bigint, user_id, ARRAY['mam.read'])) ORDER BY id"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: LOCKDOWN_DEVICES_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOCKDOWN_DEVICES_OF_MUTANT: SqlContract = SqlContract {
    id: "devices.lockdown_devices_of_mutant",
    domain: "devices",
    sql: concat!(
        "SELECT id, user_id, COALESCE(device_name,''), COALESCE(platform,''), enroll_state, ",
        pg_rfc3339!("revoked_at"),
        " FROM devices WHERE user_id = $1 AND ($2::bigint > 0 OR true) ORDER BY id"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: LOCKDOWN_DEVICES_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOCKDOWN_TRANSITION: SqlContract = SqlContract {
    id: "devices.lockdown_transition",
    domain: "devices",
    sql: "SELECT rust_device_enroll_transition($1::bigint, $2::bigint, $3::text, $4::text, admin_can_reach_perm($1::bigint, (SELECT d.user_id FROM devices d WHERE d.id = $2::bigint), ARRAY['mam.write']))::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOCKDOWN_TRANSITION_MUTANT: SqlContract = SqlContract {
    id: "devices.lockdown_transition_mutant",
    domain: "devices",
    sql: "SELECT rust_device_enroll_transition($1::bigint, $2::bigint, $3::text, $4::text, true)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAM_LIST_POLICIES: SqlContract = SqlContract {
    id: "devices.mam_list_policies",
    domain: "devices",
    sql: concat!(
        "SELECT (SELECT jsonb_agg(jsonb_build_object('id',id,'policy_key',policy_key,'policy_value',policy_value,'updated_at',",
        pg_rfc3339!("updated_at"),
        ") ORDER BY policy_key)::text FROM device_policy WHERE device_id IS NULL), ",
        "(SELECT jsonb_agg(jsonb_build_object('id',id,'policy_key',policy_key,'policy_value',policy_value,'group_type',group_type,'group_id',group_id,'updated_at',",
        pg_rfc3339!("updated_at"),
        ") ORDER BY group_type,group_id,policy_key)::text FROM device_policy_groups)"
    ),
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAM_SET_GLOBAL: SqlContract = SqlContract {
    id: "devices.mam_set_global",
    domain: "devices",
    sql: "SELECT rust_mam_global_policy_set($1::text::jsonb)",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAM_NOTIFY: SqlContract = SqlContract {
    id: "devices.mam_notify",
    domain: "devices",
    sql: "SELECT pg_notify('device_policy',$1::text)",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAM_SET_GROUP: SqlContract = SqlContract {
    id: "devices.mam_set_group",
    domain: "devices",
    sql: "SELECT rust_mam_group_policy_set($1::text,$2::bigint,$3::text::jsonb)",
    params: &[Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAM_DELETE_GROUP: SqlContract = SqlContract {
    id: "devices.mam_delete_group",
    domain: "devices",
    sql: "DELETE FROM device_policy_groups WHERE group_type=$1::text AND group_id=$2::bigint AND policy_key=$3::text RETURNING id",
    params: &[Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAM_LIST_DEVICES: SqlContract = SqlContract {
    id: "devices.mam_list_devices",
    domain: "devices",
    sql: concat!(
        "SELECT r.id,r.user_id,COALESCE(NULLIF(m.platform,''),'unknown'),COALESCE(m.device_name,''),COALESCE(m.os_version,''),COALESCE(m.app_version,''),COALESCE(NULLIF(m.compliance_status,''),'unknown'),",
        pg_rfc3339!("COALESCE(m.last_checkin_at,r.last_seen)"),
        ",(m.wipe_requested IS NOT NULL AND m.wipe_requested NOT IN ('','none')),",
        pg_rfc3339!("COALESCE(m.created_at,r.first_seen)"),
        " FROM device_registry r LEFT JOIN mdm_device_state m ON m.device_id=r.device_fingerprint AND m.user_id=r.user_id ",
        "WHERE ($1::bigint<=0 OR r.user_id IN (SELECT id FROM users WHERE domain_id=$1)) ",
        "ORDER BY COALESCE(m.last_checkin_at,r.last_seen) DESC NULLS LAST,r.id"
    ),
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("user_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAM_RESOLVE: SqlContract = SqlContract {
    id: "devices.mam_resolve",
    domain: "devices",
    sql: "SELECT COALESCE(dev.id,0) FROM device_registry r LEFT JOIN devices dev ON dev.user_id=r.user_id AND dev.fingerprint=r.device_fingerprint::text WHERE r.id=$1 AND ($2::bigint<=0 OR r.user_id IN (SELECT id FROM users WHERE domain_id=$2))",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAM_EVENTS: SqlContract = SqlContract {
    id: "devices.mam_events",
    domain: "devices",
    sql: concat!(
        "SELECT e.device_id,e.event_type,e.severity,e.details::text,",
        pg_rfc3339!("e.occurred_at"),
        " FROM device_events e WHERE e.device_id=$1 AND ($3::bigint<=0 OR EXISTS(SELECT 1 FROM devices dev JOIN users u ON u.id=dev.user_id WHERE dev.id=e.device_id AND u.domain_id=$3)) ORDER BY e.occurred_at DESC LIMIT $2"
    ),
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("device_id", Type::INT8),
        ColumnSpec::named("event_type", Type::TEXT),
        ColumnSpec::named("severity", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAM_LOG_EVENT: SqlContract = SqlContract {
    id: "devices.mam_log_event",
    domain: "devices",
    sql: "INSERT INTO device_events(device_id,event_type,severity,details,occurred_at) SELECT $1::bigint,$2::text,$3::text,$4::text::jsonb,clock_timestamp() WHERE ($5::bigint<=0 OR EXISTS(SELECT 1 FROM devices dev JOIN users u ON u.id=dev.user_id WHERE dev.id=$1 AND u.domain_id=$5)) RETURNING device_id",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::named("device_id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAM_SET_DEVICE: SqlContract = SqlContract {
    id: "devices.mam_set_device",
    domain: "devices",
    sql: "SELECT rust_mam_device_policy_set($1::bigint,$2::bigint,$3::text::jsonb)",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAM_DELETE_DEVICE: SqlContract = SqlContract {
    id: "devices.mam_delete_device",
    domain: "devices",
    sql: "DELETE FROM device_policy dp WHERE dp.device_id=$1::bigint AND dp.policy_key=$2::text AND ($3::bigint<=0 OR EXISTS(SELECT 1 FROM devices dev JOIN users u ON u.id=dev.user_id WHERE dev.id=dp.device_id AND u.domain_id=$3)) RETURNING dp.id",
    params: &[Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MDM_LIST_DEVICES: SqlContract = SqlContract {
    id: "devices.mdm_list_devices",
    domain: "devices",
    sql: concat!(
        mdm_device_select!(),
        " WHERE ($1::bigint <= 0 OR user_id IN (SELECT id FROM users WHERE domain_id = $1)) ORDER BY last_checkin_at DESC LIMIT 100"
    ),
    params: &[Type::INT8],
    columns: MDM_DEVICE_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MDM_GET_DEVICE: SqlContract = SqlContract {
    id: "devices.mdm_get_device",
    domain: "devices",
    sql: concat!(
        mdm_device_select!(),
        " WHERE device_id = $1::text::uuid AND ($2::bigint <= 0 OR user_id IN (SELECT id FROM users WHERE domain_id = $2))"
    ),
    params: &[Type::TEXT, Type::INT8],
    columns: MDM_DEVICE_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MDM_ARM_WIPE: SqlContract = SqlContract {
    id: "devices.mdm_arm_wipe",
    domain: "devices",
    sql: "SELECT mdm_device_wipe_arm($1::text::uuid, $2::text, $3::bigint, $4::bigint, NULLIF($5::text, '')::inet)::text",
    params: &[Type::TEXT, Type::TEXT, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MDM_LIST_POLICIES: SqlContract = SqlContract {
    id: "devices.mdm_list_policies",
    domain: "devices",
    sql: "SELECT id, name, description, priority::bigint, scope_type, COALESCE(scope_id, 0), enabled, \
         passcode_min_length::bigint, passcode_complexity, passcode_max_age_days::bigint, \
         passcode_history_count::bigint, max_failed_attempts::bigint, inactivity_lock_mins::bigint, \
         block_screenshots, block_copy_paste, require_device_encryption, \
         min_os_version_ios, min_os_version_android, jailbreak_action, \
         heartbeat_interval_secs::bigint, grace_period_mins::bigint \
         FROM mdm_policies ORDER BY priority DESC",
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("description", Type::TEXT),
        ColumnSpec::named("priority", Type::INT8),
        ColumnSpec::named("scope_type", Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::named("passcode_min_length", Type::INT8),
        ColumnSpec::named("passcode_complexity", Type::TEXT),
        ColumnSpec::named("passcode_max_age_days", Type::INT8),
        ColumnSpec::named("passcode_history_count", Type::INT8),
        ColumnSpec::named("max_failed_attempts", Type::INT8),
        ColumnSpec::named("inactivity_lock_mins", Type::INT8),
        ColumnSpec::named("block_screenshots", Type::BOOL),
        ColumnSpec::named("block_copy_paste", Type::BOOL),
        ColumnSpec::named("require_device_encryption", Type::BOOL),
        ColumnSpec::named("min_os_version_ios", Type::TEXT),
        ColumnSpec::named("min_os_version_android", Type::TEXT),
        ColumnSpec::named("jailbreak_action", Type::TEXT),
        ColumnSpec::named("heartbeat_interval_secs", Type::INT8),
        ColumnSpec::named("grace_period_mins", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MDM_CREATE_POLICY: SqlContract = SqlContract {
    id: "devices.mdm_create_policy",
    domain: "devices",
    sql: "INSERT INTO mdm_policies (name, description, priority, scope_type, scope_id, enabled, \
         passcode_min_length, passcode_complexity, passcode_max_age_days, passcode_history_count, \
         max_failed_attempts, inactivity_lock_mins, block_screenshots, block_copy_paste, \
         require_device_encryption, min_os_version_ios, min_os_version_android, jailbreak_action, \
         heartbeat_interval_secs, grace_period_mins) \
         VALUES ($1::text, $2::text, $3::bigint::int4, $4::text, $5::bigint, $6::boolean, \
         $7::bigint::int4, $8::text, $9::bigint::int4, $10::bigint::int4, $11::bigint::int4, \
         $12::bigint::int4, $13::boolean, $14::boolean, $15::boolean, $16::text, $17::text, $18::text, \
         $19::bigint::int4, $20::bigint::int4) RETURNING id",
    params: &[
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::BOOL,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::BOOL,
        Type::BOOL,
        Type::BOOL,
        Type::TEXT,
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

pub const MDM_UPDATE_POLICY: SqlContract = SqlContract {
    id: "devices.mdm_update_policy",
    domain: "devices",
    sql: "WITH u AS (UPDATE mdm_policies SET \
         name = COALESCE($2::text, name), description = COALESCE($3::text, description), \
         priority = COALESCE($4::bigint::int4, priority), scope_type = COALESCE($5::text, scope_type), \
         scope_id = $6::bigint, enabled = COALESCE($7::boolean, enabled), \
         passcode_min_length = COALESCE($8::bigint::int4, passcode_min_length), \
         passcode_complexity = COALESCE($9::text, passcode_complexity), \
         passcode_max_age_days = COALESCE($10::bigint::int4, passcode_max_age_days), \
         passcode_history_count = COALESCE($11::bigint::int4, passcode_history_count), \
         max_failed_attempts = COALESCE($12::bigint::int4, max_failed_attempts), \
         inactivity_lock_mins = COALESCE($13::bigint::int4, inactivity_lock_mins), \
         block_screenshots = COALESCE($14::boolean, block_screenshots), \
         block_copy_paste = COALESCE($15::boolean, block_copy_paste), \
         require_device_encryption = COALESCE($16::boolean, require_device_encryption), \
         min_os_version_ios = COALESCE($17::text, min_os_version_ios), \
         min_os_version_android = COALESCE($18::text, min_os_version_android), \
         jailbreak_action = COALESCE($19::text, jailbreak_action), \
         heartbeat_interval_secs = COALESCE($20::bigint::int4, heartbeat_interval_secs), \
         grace_period_mins = COALESCE($21::bigint::int4, grace_period_mins), updated_at = now() \
         WHERE id = $1::bigint RETURNING 1) \
         SELECT count(*)::bigint FROM u",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::BOOL,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::BOOL,
        Type::BOOL,
        Type::BOOL,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MDM_DELETE_POLICY: SqlContract = SqlContract {
    id: "devices.mdm_delete_policy",
    domain: "devices",
    sql: "SELECT (rust_mdm_policy_delete($1::bigint)->>'status')",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MDM_REORDER_POLICIES: SqlContract = SqlContract {
    id: "devices.mdm_reorder_policies",
    domain: "devices",
    sql: "SELECT rust_mdm_policy_reorder($1::bigint[])::text",
    params: &[Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OFFLINE_POLICIES: SqlContract = SqlContract {
    id: "devices.offline_policies",
    domain: "devices",
    sql: "SELECT offline_policy_list()::text",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OFFLINE_POLICY: SqlContract = SqlContract {
    id: "devices.offline_policy",
    domain: "devices",
    sql: "SELECT offline_policy_get($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OFFLINE_ENABLED: SqlContract = SqlContract {
    id: "devices.offline_enabled",
    domain: "devices",
    sql: "SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.offline_mail'),false)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OFFLINE_PENDING: SqlContract = SqlContract {
    id: "devices.offline_pending",
    domain: "devices",
    sql: "SELECT rust_offline_devices_pending($1::bigint)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OFFLINE_PENDING_MUTANT: SqlContract = SqlContract {
    id: "devices.offline_pending_mutant",
    domain: "devices",
    sql: "SELECT offline_devices_pending()::text WHERE $1::bigint > 0",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OFFLINE_COMMAND: SqlContract = SqlContract {
    id: "devices.offline_command",
    domain: "devices",
    sql: "SELECT rust_offline_command($1,$2,$3,$4::text::jsonb,\
         COALESCE(admin_can_reach_perm($1,(SELECT ud.user_id FROM user_devices ud \
         WHERE ud.id=($4::text::jsonb->>'id')::bigint),ARRAY['mam.write']),false))",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OFFLINE_COMMAND_MUTANT: SqlContract = SqlContract {
    id: "devices.offline_command_mutant",
    domain: "devices",
    sql: "SELECT rust_offline_command($1,$2,$3,$4::text::jsonb,true)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OFFLINE_PREVIEW: SqlContract = SqlContract {
    id: "devices.offline_preview",
    domain: "devices",
    sql: "SELECT offline_sync_policy_preview($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OFFLINE_SIZE: SqlContract = SqlContract {
    id: "devices.offline_size",
    domain: "devices",
    sql: "SELECT \
         COUNT(*) FILTER(WHERE received_at >= now()-interval '7 days'),\
         COALESCE(SUM(b) FILTER(WHERE received_at >= now()-interval '7 days'),0),\
         COUNT(*) FILTER(WHERE received_at >= now()-interval '30 days'),\
         COALESCE(SUM(b) FILTER(WHERE received_at >= now()-interval '30 days'),0),\
         COUNT(*) FILTER(WHERE received_at >= now()-interval '90 days'),\
         COALESCE(SUM(b) FILTER(WHERE received_at >= now()-interval '90 days'),0),\
         COUNT(*) FILTER(WHERE received_at >= now()-interval '180 days'),\
         COALESCE(SUM(b) FILTER(WHERE received_at >= now()-interval '180 days'),0),\
         COUNT(*) FILTER(WHERE received_at >= now()-interval '365 days'),\
         COALESCE(SUM(b) FILTER(WHERE received_at >= now()-interval '365 days'),0),\
         COUNT(*),\
         COALESCE(SUM(b),0) \
         FROM(SELECT m.received_at,octet_length(COALESCE(m.body_text,''))+octet_length(COALESCE(m.body_html,'')) AS b \
         FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE mb.user_id=$1 AND NOT m.is_deleted)m",
    params: &[Type::INT8],
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
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    CONSOLE_DENIED,
    LOCKDOWN_QUEUE,
    LOCKDOWN_QUEUE_MUTANT,
    LOCKDOWN_DEVICES_OF,
    LOCKDOWN_DEVICES_OF_MUTANT,
    LOCKDOWN_TRANSITION,
    LOCKDOWN_TRANSITION_MUTANT,
    MAM_LIST_POLICIES,
    MAM_SET_GLOBAL,
    MAM_NOTIFY,
    MAM_SET_GROUP,
    MAM_DELETE_GROUP,
    MAM_LIST_DEVICES,
    MAM_RESOLVE,
    MAM_EVENTS,
    MAM_LOG_EVENT,
    MAM_SET_DEVICE,
    MAM_DELETE_DEVICE,
    MDM_LIST_DEVICES,
    MDM_GET_DEVICE,
    MDM_ARM_WIPE,
    MDM_LIST_POLICIES,
    MDM_CREATE_POLICY,
    MDM_UPDATE_POLICY,
    MDM_DELETE_POLICY,
    MDM_REORDER_POLICIES,
    OFFLINE_POLICIES,
    OFFLINE_POLICY,
    OFFLINE_ENABLED,
    OFFLINE_PENDING,
    OFFLINE_PENDING_MUTANT,
    OFFLINE_COMMAND,
    OFFLINE_COMMAND_MUTANT,
    OFFLINE_PREVIEW,
    OFFLINE_SIZE,
];
