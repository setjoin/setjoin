//! Static typed SQL contract catalog for `setjoin-compliance` (F04).
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};

// ---- Shared console denial audit ----

pub const CONSOLE_DENIED: SqlContract = SqlContract {
    id: "compliance.console_denied",
    domain: "compliance",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- eDiscovery cases & searches ----

const CASE_COLS: &[ColumnSpec] = &[
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::named("name", Type::TEXT),
    ColumnSpec::named("description", Type::TEXT),
    ColumnSpec::named("status", Type::TEXT),
    ColumnSpec::named("created_by", Type::INT8),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("closed_by", Type::INT8),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::INT8),
];

pub const CASES_LIST: SqlContract = SqlContract {
    id: "compliance.cases_list",
    domain: "compliance",
    sql: "SELECT c.id,c.name,c.description,c.status,c.created_by, \
          to_char(c.closed_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),c.closed_by, \
          to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
          to_char(c.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
          (SELECT count(*) FROM ediscovery_searches s WHERE s.case_id=c.id) \
          FROM ediscovery_cases c ORDER BY c.created_at DESC",
    params: &[],
    columns: CASE_COLS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CASE_GET: SqlContract = SqlContract {
    id: "compliance.case_get",
    domain: "compliance",
    sql: "SELECT c.id,c.name,c.description,c.status,c.created_by, \
          to_char(c.closed_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),c.closed_by, \
          to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
          to_char(c.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
          (SELECT count(*) FROM ediscovery_searches s WHERE s.case_id=c.id) \
          FROM ediscovery_cases c WHERE c.id=$1",
    params: &[Type::INT8],
    columns: CASE_COLS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CASE_SEARCHES: SqlContract = SqlContract {
    id: "compliance.case_searches",
    domain: "compliance",
    sql: "SELECT id,name,status,result_count,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
          FROM ediscovery_searches WHERE case_id=$1 ORDER BY created_at DESC",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::named("result_count", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CASE_CREATE: SqlContract = SqlContract {
    id: "compliance.case_create",
    domain: "compliance",
    sql: "INSERT INTO ediscovery_cases(name,description,created_by) \
          SELECT $2,$3,$1 WHERE $1::bigint>0 RETURNING id",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CASE_UPDATE: SqlContract = SqlContract {
    id: "compliance.case_update",
    domain: "compliance",
    sql: "UPDATE ediscovery_cases SET name=COALESCE(NULLIF($2::text,''),name), \
          description=COALESCE($3::text,description),updated_at=now() \
          WHERE id=$1 RETURNING id",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CASE_DELETE: SqlContract = SqlContract {
    id: "compliance.case_delete",
    domain: "compliance",
    sql: "DELETE FROM ediscovery_cases WHERE id=$1 \
          AND NOT EXISTS(SELECT 1 FROM ediscovery_searches WHERE case_id=$1) RETURNING id",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SEARCH_ASSOCIATE: SqlContract = SqlContract {
    id: "compliance.search_associate",
    domain: "compliance",
    sql: "UPDATE ediscovery_searches SET case_id=$2 WHERE id=$1 AND case_id IS NULL RETURNING id",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CASE_CLOSE: SqlContract = SqlContract {
    id: "compliance.case_close",
    domain: "compliance",
    sql: "SELECT rust_compliance_case_close($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MESSAGE_HOLD: SqlContract = SqlContract {
    id: "compliance.message_hold",
    domain: "compliance",
    sql: "SELECT rust_compliance_message_hold($1,$2,$3,$4,true)::text",
    params: &[Type::INT8, Type::INT8_ARRAY, Type::BOOL, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SEARCH_START: SqlContract = SqlContract {
    id: "compliance.search_start",
    domain: "compliance",
    sql: "INSERT INTO ediscovery_searches(name,created_by,query,status,case_id) \
          SELECT $2,$1,$3::text::jsonb,'pending',$4 WHERE $1::bigint>0 RETURNING id",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SEARCH_GET: SqlContract = SqlContract {
    id: "compliance.search_get",
    domain: "compliance",
    sql: "SELECT id,name,query->>'keywords',query->>'kql',query->>'fromAddr',query->>'dateFrom',query->>'dateTo', \
          query::text,status,result_count,case_id, \
          to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
          FROM ediscovery_searches WHERE id=$1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::named("result_count", Type::INT4),
        ColumnSpec::named("case_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SEARCH_RESULTS: SqlContract = SqlContract {
    id: "compliance.search_results",
    domain: "compliance",
    sql: "SELECT m.id,m.subject,m.from_addr,to_char(m.received_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),mb.email \
          FROM ediscovery_search_results r JOIN messages m ON m.id=r.message_id JOIN mailboxes mb ON mb.id=m.mailbox_id \
          WHERE r.search_id=$1 ORDER BY m.received_at DESC LIMIT 500",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("subject", Type::TEXT),
        ColumnSpec::named("from_addr", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("email", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- Export ----

pub const EXPORT_AUTHORIZE: SqlContract = SqlContract {
    id: "compliance.export_authorize",
    domain: "compliance",
    sql: "SELECT rust_compliance_export_authorize($1,$2,$3,$4::text::jsonb,$5)",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8_ARRAY,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXPORT_MESSAGES: SqlContract = SqlContract {
    id: "compliance.export_messages",
    domain: "compliance",
    sql: "SELECT id,raw_ref,from_addr,subject,to_char(received_at AT TIME ZONE 'UTC','Dy Mon DD HH24:MI:SS YYYY') \
          FROM messages WHERE id=ANY($1) AND $2::bigint>0 ORDER BY id",
    params: &[Type::INT8_ARRAY, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("raw_ref", Type::TEXT),
        ColumnSpec::named("from_addr", Type::TEXT),
        ColumnSpec::named("subject", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- Global audit console ----

pub const AUDIT_POLICY_GET: SqlContract = SqlContract {
    id: "compliance.audit_policy_get",
    domain: "compliance",
    sql: "SELECT level,reason_required_areas FROM audit_policy WHERE id=1",
    params: &[],
    columns: &[
        ColumnSpec::named("level", Type::TEXT),
        ColumnSpec::named("reason_required_areas", Type::TEXT_ARRAY),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_REASON_REQUIRED: SqlContract = SqlContract {
    id: "compliance.audit_reason_required",
    domain: "compliance",
    sql: "SELECT reason_required_areas FROM audit_policy WHERE id=1",
    params: &[],
    columns: &[ColumnSpec::named("reason_required_areas", Type::TEXT_ARRAY)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_MISSING_REASON: SqlContract = SqlContract {
    id: "compliance.audit_missing_reason",
    domain: "compliance",
    sql: "SELECT audit_write($1,'sensitive_action.reason_missing','',NULL,NULL,NULL,$2::text::inet,'audit.export','core')",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_POLICY_SET: SqlContract = SqlContract {
    id: "compliance.audit_policy_set",
    domain: "compliance",
    sql: "SELECT rust_compliance_audit_policy_set($1,$2,$3,$4,$5)",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT_ARRAY,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const AUDIT_LIST_COUNT: SqlContract = SqlContract {
    id: "compliance.audit_list_count",
    domain: "compliance",
    sql: "SELECT count(*) FROM admin_audit_log al LEFT JOIN users u ON u.id=al.user_id \
          WHERE ($1::text = '' OR al.action = $1) \
            AND (CASE WHEN $2::text = '' THEN TRUE ELSE al.user_id = $2::bigint END) \
            AND ($3::text = '' OR al.target_type = $3) \
            AND ($4::text = '' OR al.notes ILIKE $4 OR al.action ILIKE $4)",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_LIST_ROWS: SqlContract = SqlContract {
    id: "compliance.audit_list_rows",
    domain: "compliance",
    sql:
        "SELECT al.id,to_char(al.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
          al.user_id,COALESCE(u.email,'system'),COALESCE(al.ip::text,''),al.action,al.target_type, \
          al.target_id,al.before_state::text,al.after_state::text,COALESCE(al.notes,'') \
          FROM admin_audit_log al LEFT JOIN users u ON u.id=al.user_id \
          WHERE ($1::text = '' OR al.action = $1) \
            AND (CASE WHEN $2::text = '' THEN TRUE ELSE al.user_id = $2::bigint END) \
            AND ($3::text = '' OR al.target_type = $3) \
            AND ($4::text = '' OR al.notes ILIKE $4 OR al.action ILIKE $4) \
          ORDER BY al.occurred_at DESC LIMIT $5 OFFSET $6",
    params: &[
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("user_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("action", Type::TEXT),
        ColumnSpec::named("target_type", Type::TEXT),
        ColumnSpec::named("target_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_CSV: SqlContract = SqlContract {
    id: "compliance.audit_csv",
    domain: "compliance",
    sql: "SELECT al.id,to_char(al.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
          COALESCE(u.email,'system'),COALESCE(al.ip::text,''),al.action,al.target_type,al.target_id,COALESCE(al.notes,'') \
          FROM admin_audit_log al LEFT JOIN users u ON u.id=al.user_id ORDER BY al.occurred_at DESC LIMIT 10000",
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("action", Type::TEXT),
        ColumnSpec::named("target_type", Type::TEXT),
        ColumnSpec::named("target_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_VERIFY: SqlContract = SqlContract {
    id: "compliance.audit_verify",
    domain: "compliance",
    sql: "SELECT row_id,valid,to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),action \
          FROM verify_audit_chain($1::bigint,$2::bigint)",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("row_id", Type::INT8),
        ColumnSpec::named("valid", Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("action", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- Chat compliance ----

pub const CHAT_POLICIES_LIST: SqlContract = SqlContract {
    id: "compliance.chat_policies_list",
    domain: "compliance",
    sql: "SELECT id,name,applies_to,duration_days,enabled,effective_at::text,created_at::text,updated_at::text \
          FROM chat_retention_policies ORDER BY id",
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("applies_to", Type::TEXT),
        ColumnSpec::named("duration_days", Type::INT4),
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHAT_CASES_LIST: SqlContract = SqlContract {
    id: "compliance.chat_cases_list",
    domain: "compliance",
    sql: "SELECT id,name,status FROM ediscovery_cases ORDER BY status,name",
    params: &[],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHAT_HOLDS_LIST: SqlContract = SqlContract {
    id: "compliance.chat_holds_list",
    domain: "compliance",
    sql: "SELECT h.id,h.case_id,h.custodian_user_id,h.channel_id,h.reason,h.created_by,\
          rtrim(rtrim(to_char(h.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'),'0'),'.')||'Z',\
          rtrim(rtrim(to_char(h.released_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'),'0'),'.')||'Z',\
          h.released_by,(SELECT count(*) FROM chat_case_hold_channels hc WHERE hc.hold_id=h.id) \
          FROM chat_case_holds h WHERE h.case_id=$1 ORDER BY h.id DESC",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("case_id", Type::INT8),
        ColumnSpec::named("custodian_user_id", Type::INT8),
        ColumnSpec::named("channel_id", Type::INT8),
        ColumnSpec::named("reason", Type::TEXT),
        ColumnSpec::named("created_by", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("released_by", Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHAT_PURGE_PREVIEW: SqlContract = SqlContract {
    id: "compliance.chat_purge_preview",
    domain: "compliance",
    sql: "SELECT channel_id,purged_count,id_from,id_to,retention_days FROM chat_purge_expired(100000,TRUE)",
    params: &[],
    columns: &[
        ColumnSpec::named("channel_id", Type::INT8),
        ColumnSpec::named("purged_count", Type::INT4),
        ColumnSpec::named("id_from", Type::INT8),
        ColumnSpec::named("id_to", Type::INT8),
        ColumnSpec::named("retention_days", Type::INT4),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHAT_OVERVIEW: SqlContract = SqlContract {
    id: "compliance.chat_overview",
    domain: "compliance",
    sql: "SELECT a::text,b::text,c::text FROM (\
          SELECT \
            COALESCE((SELECT jsonb_agg(jsonb_build_object('id', ch.id, 'kind', ch.kind, 'name', ch.name, \
                        'legalHoldReason', ch.legal_hold_reason, 'caseHolds', ch.case_holds) ORDER BY ch.id) \
              FROM ( \
                SELECT c.id, c.kind, c.name, c.legal_hold_reason, \
                       (SELECT jsonb_agg(jsonb_build_object('caseId', h.case_id, 'holdId', h.id)) \
                          FROM chat_case_hold_channels hc \
                          JOIN chat_case_holds h ON h.id = hc.hold_id AND h.released_at IS NULL \
                         WHERE hc.channel_id = c.id) AS case_holds \
                  FROM chat_channels c \
                 WHERE chat_hold_active(c.id) \
              ) ch), '[]'::jsonb), \
            COALESCE((SELECT jsonb_agg(jsonb_build_object('id', id, 'kind', kind, 'name', name, 'retentionDays', retention_days, 'wormMode', worm_mode) ORDER BY id) \
                        FROM chat_channels WHERE classification = 'gxp'), '[]'::jsonb), \
            COALESCE((SELECT jsonb_agg(jsonb_build_object('id', id, 'kind', kind, 'name', name, 'retentionDays', retention_days) ORDER BY id) \
                        FROM chat_channels WHERE retention_days IS NOT NULL AND classification = 'regular'), '[]'::jsonb)\
          ) AS t(a,b,c)",
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHAT_OVERVIEW_LAST_PURGE: SqlContract = SqlContract {
    id: "compliance.chat_overview_last_purge",
    domain: "compliance",
    sql: "SELECT (after_state->>'channels')::int,(after_state->>'messages')::int,(after_state->>'drained')::boolean,\
          to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
          FROM admin_audit_log WHERE action='chat.purge_run' ORDER BY id DESC LIMIT 1",
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::INT4),
        ColumnSpec::unnamed(Type::INT4),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHAT_POLICY_MUTATE: SqlContract = SqlContract {
    id: "compliance.chat_policy_mutate",
    domain: "compliance",
    sql: "SELECT rust_compliance_chat_policy($1,$2,$3,$4,$5::text::jsonb,$6,$7)::text",
    params: &[
        Type::INT8,
        Type::BOOL,
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

pub const CHAT_HOLDS_AUDIT: SqlContract = SqlContract {
    id: "compliance.chat_holds_audit",
    domain: "compliance",
    sql: "SELECT audit_write($1,'chat_case_hold_list','ediscovery_case',$2,NULL,NULL,NULLIF($3,'')::inet,'','core')",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHAT_COMMAND: SqlContract = SqlContract {
    id: "compliance.chat_command",
    domain: "compliance",
    sql: "SELECT rust_compliance_chat_command($1,$2,$3,$4::text::jsonb,$5)::text",
    params: &[Type::INT8, Type::BOOL, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- Content search & purge ----

pub const CONTENT_SEARCH_FILTERED: SqlContract = SqlContract {
    id: "compliance.content_search_filtered",
    domain: "compliance",
    sql: "SELECT m.id,m.subject,m.from_addr,to_char(m.received_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),mb.email \
          FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id \
          WHERE (m.body_tsv @@ websearch_to_tsquery('simple',$1) \
                 OR m.subject_tsv @@ websearch_to_tsquery('simple',$1) \
                 OR m.from_tsv @@ websearch_to_tsquery('simple',$1)) \
            AND ($2::text = '' OR m.from_addr ILIKE '%' || $2 || '%') \
            AND (CASE WHEN $3::text = '' THEN TRUE ELSE m.received_at >= $3::timestamptz END) \
            AND (CASE WHEN $4::text = '' THEN TRUE ELSE m.received_at <= $4::timestamptz END) \
            AND ($5::bigint[] IS NULL OR m.mailbox_id = ANY($5::bigint[])) \
          ORDER BY m.received_at DESC LIMIT 500",
    params: &[
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8_ARRAY,
    ],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("subject", Type::TEXT),
        ColumnSpec::named("from_addr", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("email", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONTENT_SEARCH_KQL: SqlContract = SqlContract {
    id: "compliance.content_search_kql",
    domain: "compliance",
    sql: "SELECT id,subject,from_addr,received_at,email FROM public.rust_compliance_content_search_kql($1,$2)",
    params: &[Type::TEXT, Type::TEXT_ARRAY],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("subject", Type::TEXT),
        ColumnSpec::named("from_addr", Type::TEXT),
        ColumnSpec::named("received_at", Type::TEXT),
        ColumnSpec::named("email", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONTENT_PURGE: SqlContract = SqlContract {
    id: "compliance.content_purge",
    domain: "compliance",
    sql: "SELECT public.rust_compliance_content_purge($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8_ARRAY, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- Retention policies & log retention ----

pub const RETENTION_POLICIES_LIST: SqlContract = SqlContract {
    id: "compliance.retention_policies_list",
    domain: "compliance",
    sql: "SELECT id,name,description,retain_days,action,is_default,domain_id,\
          to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US') \
          FROM retention_policies WHERE $1::bigint<=0 OR domain_id IS NULL OR domain_id=$1 \
          ORDER BY is_default DESC,id ASC",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("description", Type::TEXT),
        ColumnSpec::named("retain_days", Type::INT4),
        ColumnSpec::named("action", Type::TEXT),
        ColumnSpec::named("is_default", Type::BOOL),
        ColumnSpec::named("domain_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RETENTION_CREATE: SqlContract = SqlContract {
    id: "compliance.retention_create",
    domain: "compliance",
    sql: "SELECT rust_compliance_retention_create($1,$2,$3::text::jsonb,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const RETENTION_UPDATE: SqlContract = SqlContract {
    id: "compliance.retention_update",
    domain: "compliance",
    sql: "SELECT rust_compliance_retention_update($1,$2,$3,$4::text::jsonb,$5)",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const RETENTION_DELETE: SqlContract = SqlContract {
    id: "compliance.retention_delete",
    domain: "compliance",
    sql: "SELECT rust_compliance_retention_delete($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const RETENTION_LOG_GET: SqlContract = SqlContract {
    id: "compliance.retention_log_get",
    domain: "compliance",
    sql: "SELECT value::text FROM system_config WHERE key=$1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RETENTION_LOG_SET: SqlContract = SqlContract {
    id: "compliance.retention_log_set",
    domain: "compliance",
    sql: "SELECT rust_compliance_log_retention_set($1,$2)",
    params: &[Type::INT8, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RETENTION_LOG_PRUNE: SqlContract = SqlContract {
    id: "compliance.retention_log_prune",
    domain: "compliance",
    sql: "SELECT pruned_table,rows_deleted FROM rust_compliance_log_prune($1)",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("pruned_table", Type::TEXT),
        ColumnSpec::named("rows_deleted", Type::INT4),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    CONSOLE_DENIED,
    CASES_LIST,
    CASE_GET,
    CASE_SEARCHES,
    CASE_CREATE,
    CASE_UPDATE,
    CASE_DELETE,
    SEARCH_ASSOCIATE,
    CASE_CLOSE,
    MESSAGE_HOLD,
    SEARCH_START,
    SEARCH_GET,
    SEARCH_RESULTS,
    EXPORT_AUTHORIZE,
    EXPORT_MESSAGES,
    AUDIT_POLICY_GET,
    AUDIT_REASON_REQUIRED,
    AUDIT_MISSING_REASON,
    AUDIT_POLICY_SET,
    AUDIT_LIST_COUNT,
    AUDIT_LIST_ROWS,
    AUDIT_CSV,
    AUDIT_VERIFY,
    CHAT_POLICIES_LIST,
    CHAT_CASES_LIST,
    CHAT_HOLDS_LIST,
    CHAT_HOLDS_AUDIT,
    CHAT_PURGE_PREVIEW,
    CHAT_OVERVIEW,
    CHAT_OVERVIEW_LAST_PURGE,
    CHAT_POLICY_MUTATE,
    CHAT_COMMAND,
    CONTENT_SEARCH_FILTERED,
    CONTENT_SEARCH_KQL,
    CONTENT_PURGE,
    RETENTION_POLICIES_LIST,
    RETENTION_CREATE,
    RETENTION_UPDATE,
    RETENTION_DELETE,
    RETENTION_LOG_GET,
    RETENTION_LOG_SET,
    RETENTION_LOG_PRUNE,
];
