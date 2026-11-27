//! Static typed SQL contract catalog for `setjoin-static` (F20/F22).
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};

pub const ASSIST_GET_CONFIG: SqlContract = SqlContract {
    id: "static.assist_get_config",
    domain: "static",
    sql: "SELECT get_system_config($1) #>> '{}'",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ASSIST_DEPLOYMENT_ID: SqlContract = SqlContract {
    id: "static.assist_deployment_id",
    domain: "static",
    sql: "SELECT get_system_config('identity.deployment_id') #>> '{}'",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const HEALTH_HISTORY: SqlContract = SqlContract {
    id: "static.health_history",
    domain: "static",
    sql: "SELECT DISTINCT ON (check_name) check_name, status FROM health_history ORDER BY check_name, checked_at DESC",
    params: &[],
    columns: &[
        ColumnSpec::named("check_name", Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
    ],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const READY_PING: SqlContract = SqlContract {
    id: "static.ready_ping",
    domain: "static",
    sql: "SELECT 1",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const METRICS_IDENTITY: SqlContract = SqlContract {
    id: "static.metrics_identity",
    domain: "static",
    sql: "SELECT \
 (SELECT count(*) FROM identity_shadow_divergences WHERE state='open' AND divergence_class<>'expected_legacy_ambiguity'), \
 (SELECT count(*) FROM identity_sources WHERE state IN ('error','paused') OR last_error_code IS NOT NULL), \
 (SELECT count(*) FROM identity_source_inbox WHERE state IN ('pending','quarantined')), \
 (SELECT count(*) FROM identity_source_inbox WHERE state='quarantined'), \
 (SELECT count(*) FROM identity_match_candidates WHERE status IN ('pending','deferred')), \
 (SELECT count(*) FROM identity_transitions WHERE state NOT IN ('completed','rolled_back')), \
 (SELECT count(*) FROM identity_transition_effects WHERE state<>'completed'), \
 (SELECT count(*) FROM identity_read_cohort), \
 (SELECT count(*) FROM identity_sync_log WHERE source_id IS NOT NULL), \
 COALESCE((SELECT max(duration_ms)/1000 FROM identity_sync_log WHERE source_id IS NOT NULL),0)::bigint, \
 COALESCE((SELECT max(extract(epoch FROM statement_timestamp()-last_success_at))::bigint FROM identity_sources WHERE last_success_at IS NOT NULL),0), \
 (SELECT count(*) FROM identity_source_inbox WHERE last_error_code='BZ229'), \
 COALESCE((SELECT max(extract(epoch FROM statement_timestamp()-created_at))::bigint FROM identity_transitions WHERE state NOT IN ('completed','rolled_back','cancelled','expired')),0), \
 COALESCE((SELECT max(extract(epoch FROM statement_timestamp()-created_at))::bigint FROM approval_requests WHERE consumer_type='identity.transition' AND status='pending'),0), \
 (SELECT count(*) FROM approval_requests WHERE consumer_type='identity.transition' AND status='pending'), \
 COALESCE((SELECT greatest(0,min(extract(epoch FROM expires_at-statement_timestamp())))::bigint FROM approval_requests WHERE consumer_type='identity.transition' AND status='pending'),0), \
 COALESCE((SELECT max(extract(epoch FROM statement_timestamp()-updated_at))::bigint FROM identity_transition_effects WHERE state<>'completed'),0), \
 COALESCE((SELECT sum(attempt_count)::bigint FROM identity_transition_effects),0), \
 (SELECT count(*) FROM identity_link_events WHERE action IN ('auth_jit_created','auth_linked','auth_resolved')), \
 (SELECT count(*) FROM identity_link_events WHERE action IN ('entitlements_reconciled','authority_changed','transition_committed'))",
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

pub const METRICS_WORK_QUEUE: SqlContract = SqlContract {
    id: "static.metrics_work_queue",
    domain: "static",
    sql: "SELECT pending, leased, dead_letters, oldest_due_age_secs FROM public.work_queue_stats()",
    params: &[],
    columns: &[
        ColumnSpec::named("pending", Type::INT8),
        ColumnSpec::named("leased", Type::INT8),
        ColumnSpec::named("dead_letters", Type::INT8),
        ColumnSpec::named("oldest_due_age_secs", Type::FLOAT8),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WELLKNOWN_LOCAL_DOMAIN: SqlContract = SqlContract {
    id: "static.wellknown_local_domain",
    domain: "static",
    sql: "SELECT 1 FROM domains WHERE lower(name) = $1 AND is_local = TRUE LIMIT 1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBSITE_NEEDS_SETUP: SqlContract = SqlContract {
    id: "static.website_needs_setup",
    domain: "static",
    sql: "SELECT public.system_has_users()",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    ASSIST_GET_CONFIG,
    ASSIST_DEPLOYMENT_ID,
    HEALTH_HISTORY,
    READY_PING,
    METRICS_IDENTITY,
    METRICS_WORK_QUEUE,
    WELLKNOWN_LOCAL_DOMAIN,
    WEBSITE_NEEDS_SETUP,
];
