//! Static typed SQL contract catalog for `setjoin-mail-security` (F06).
use setjoin_sql_catalog::{
    pg_go_utc_time, pg_rfc3339, ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type,
};

// ---- Shared console denial audit ----

pub const CONSOLE_DENIED: SqlContract = SqlContract {
    id: "mail_security.console_denied",
    domain: "mail-security",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- DLP, Anti-Phish, and Link-Protect ----

pub const DLP_PATTERNS_GET: SqlContract = SqlContract {
    id: "mail_security.dlp_patterns_get",
    domain: "mail-security",
    sql: "SELECT id, name, COALESCE(regex_patterns[1], ''), action, enabled \
          FROM dlp_policies \
          WHERE is_pattern = TRUE AND ($1::bigint <= 0 OR domain_id IS NULL OR domain_id = $1::bigint) \
          ORDER BY priority, id",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("action", Type::TEXT),
        ColumnSpec::named("enabled", Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DLP_PATTERNS_REPLACE: SqlContract = SqlContract {
    id: "mail_security.dlp_patterns_replace",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_dlp_patterns_replace($1::text[],$2::boolean[],$3::text[],$4::text[])",
    params: &[
        Type::TEXT_ARRAY,
        Type::BOOL_ARRAY,
        Type::TEXT_ARRAY,
        Type::TEXT_ARRAY,
    ],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ANTIPHISH_GET: SqlContract = SqlContract {
    id: "mail_security.antiphish_get",
    domain: "mail-security",
    sql: "SELECT key, value::text FROM system_config WHERE key LIKE 'antiphish_%' ORDER BY key",
    params: &[],
    columns: &[
        ColumnSpec::named("key", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ANTIPHISH_PUT: SqlContract = SqlContract {
    id: "mail_security.antiphish_put",
    domain: "mail-security",
    sql: "SELECT rust_system_config_upsert_batch($1::text[], $2::text[], 'anti-phish config')",
    params: &[Type::TEXT_ARRAY, Type::TEXT_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LINK_PROTECT_AUDIT_LIST: SqlContract = SqlContract {
    id: "mail_security.link_protect_audit_list",
    domain: "mail-security",
    sql: "SELECT id, url_hash, verdict, scanner, message_id, mailbox_id, client_ip, \
          floor(extract(epoch from created_at))::bigint \
          FROM link_protect_audit \
          WHERE (CASE WHEN $1::text IS NULL THEN TRUE ELSE created_at >= $1::text::timestamptz END) \
            AND ($2::text = '' OR url_hash = $2::text) \
          ORDER BY created_at DESC LIMIT $3::bigint",
    params: &[Type::TEXT, Type::TEXT, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("url_hash", Type::TEXT),
        ColumnSpec::named("verdict", Type::TEXT),
        ColumnSpec::named("scanner", Type::TEXT),
        ColumnSpec::named("message_id", Type::INT8),
        ColumnSpec::named("mailbox_id", Type::INT8),
        ColumnSpec::named("client_ip", Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DLP_STRICT_MODE: SqlContract = SqlContract {
    id: "mail_security.dlp_strict_mode",
    domain: "mail-security",
    sql: "SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.link_protect_strict_mode'), true)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DLP_CLICK_AUDIT: SqlContract = SqlContract {
    id: "mail_security.dlp_click_audit",
    domain: "mail-security",
    sql: "SELECT link_protect_check_and_audit($1,$2,$3,$4,$5::text::jsonb,$6,$7,$8)::text",
    params: &[
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
        Type::BOOL,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- DMARC and Auth Log ----

pub const DMARC_DOMAIN_NAME: SqlContract = SqlContract {
    id: "mail_security.dmarc_domain_name",
    domain: "mail-security",
    sql: "SELECT name FROM domains WHERE id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("name", Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DMARC_LIVE_TOTALS: SqlContract = SqlContract {
    id: "mail_security.dmarc_live_totals",
    domain: "mail-security",
    sql: "SELECT COALESCE(SUM(count_pass),0)::bigint, COALESCE(SUM(count_fail),0)::bigint, \
          COALESCE(SUM(count_none),0)::bigint, COALESCE(SUM(count_temperror),0)::bigint \
          FROM dmarc_reports \
          WHERE ($1::text = '' OR domain = $1::text) \
            AND end_time = date_trunc('day', now() AT TIME ZONE 'UTC')",
    params: &[Type::TEXT],
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

pub const DMARC_LIVE_BY_DOMAIN: SqlContract = SqlContract {
    id: "mail_security.dmarc_live_by_domain",
    domain: "mail-security",
    sql: "SELECT q.domain, q.pass, q.fail, \
          COALESCE((SELECT d.dmarc_policy FROM domains d WHERE d.name = q.domain LIMIT 1), '') \
          FROM (SELECT DISTINCT ON (domain) domain, \
          COALESCE(SUM(count_pass),0)::bigint as pass, COALESCE(SUM(count_fail),0)::bigint as fail \
          FROM dmarc_reports \
          WHERE ($1::text = '' OR domain = $1::text) \
            AND end_time = date_trunc('day', now() AT TIME ZONE 'UTC') \
          GROUP BY domain ORDER BY domain LIMIT 20) q ORDER BY q.domain",
    params: &[Type::TEXT],
    columns: &[
        ColumnSpec::named("domain", Type::TEXT),
        ColumnSpec::named("pass", Type::INT8),
        ColumnSpec::named("fail", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DMARC_FAILURES: SqlContract = SqlContract {
    id: "mail_security.dmarc_failures",
    domain: "mail-security",
    sql: "SELECT to_char(m.received_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
          m.from_addr, ''::text, COALESCE(m.spf_result,''), COALESCE(m.dkim_result,''), m.dmarc_result \
          FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id \
          WHERE m.received_at >= now() - interval '24 hours' \
            AND m.dmarc_result = 'fail' \
            AND ($2::bigint <= 0 OR mb.domain_id = $2::bigint) \
          ORDER BY m.received_at DESC LIMIT $1",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("from_addr", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("dmarc_result", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DMARC_TREND: SqlContract = SqlContract {
    id: "mail_security.dmarc_trend",
    domain: "mail-security",
    sql: "SELECT to_char(t.day,'YYYY-MM-DD'), t.pass, t.fail, t.nonec FROM \
          (SELECT begin_time::DATE as day, COALESCE(SUM(count_pass),0)::bigint AS pass, \
          COALESCE(SUM(count_fail),0)::bigint AS fail, COALESCE(SUM(count_none),0)::bigint AS nonec \
          FROM dmarc_reports \
          WHERE ($1::text = '' OR domain = $1::text) \
            AND begin_time >= now() - interval '30 days' \
          GROUP BY day ORDER BY day) t ORDER BY t.day",
    params: &[Type::TEXT],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("pass", Type::INT8),
        ColumnSpec::named("fail", Type::INT8),
        ColumnSpec::named("nonec", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DMARC_AUTH_LOG: SqlContract = SqlContract {
    id: "mail_security.dmarc_auth_log",
    domain: "mail-security",
    sql: concat!(
        "SELECT id, user_id, email, event, provider, COALESCE(host(ip_address::inet), ''), ",
        pg_rfc3339!("occurred_at"),
        " FROM auth_event_log ",
        "WHERE ($1::text = '' OR provider = $1::text) ",
        "AND ($2::text = '' OR event = $2::text) ",
        "AND (CASE WHEN $3::text = '' THEN TRUE ELSE occurred_at > now() - $3::text::interval END) ",
        "AND ($4::text = '' OR email ILIKE '%' || $4::text || '%') ",
        "ORDER BY occurred_at DESC LIMIT $5::text::bigint"
    ),
    params: &[Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("user_id", Type::INT8),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::named("event", Type::TEXT),
        ColumnSpec::named("provider", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- Quarantine ----

pub const QUARANTINE_USER_LIST: SqlContract = SqlContract {
    id: "mail_security.quarantine_user_list",
    domain: "mail-security",
    sql: "SELECT qm.id, qm.message_id, m.subject, m.from_addr, \
          qm.reason, qm.virus_name, qm.preview_token, qm.quarantined_at, \
          qm.released_at, qm.rejected_at, m.size_bytes \
          FROM quarantined_messages qm \
          JOIN messages m ON m.id = qm.message_id \
          JOIN mailboxes mb ON mb.id = qm.mailbox_id \
          WHERE mb.user_id = $1 \
          ORDER BY qm.quarantined_at DESC LIMIT $2 OFFSET $3",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("message_id", Type::INT8),
        ColumnSpec::named("subject", Type::TEXT),
        ColumnSpec::named("from_addr", Type::TEXT),
        ColumnSpec::named("reason", Type::TEXT),
        ColumnSpec::named("virus_name", Type::TEXT),
        ColumnSpec::named("preview_token", Type::TEXT),
        ColumnSpec::named("quarantined_at", Type::TIMESTAMPTZ),
        ColumnSpec::named("released_at", Type::TIMESTAMPTZ),
        ColumnSpec::named("rejected_at", Type::TIMESTAMPTZ),
        ColumnSpec::named("size_bytes", Type::INT8),
    ],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUARANTINE_USER_COUNT: SqlContract = SqlContract {
    id: "mail_security.quarantine_user_count",
    domain: "mail-security",
    sql: "SELECT COUNT(*)::bigint FROM quarantined_messages qm \
          JOIN mailboxes mb ON mb.id = qm.mailbox_id \
          WHERE mb.user_id = $1 AND qm.released_at IS NULL AND qm.rejected_at IS NULL",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUARANTINE_USER_RELEASE: SqlContract = SqlContract {
    id: "mail_security.quarantine_user_release",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_quarantine_release($1, $2, FALSE)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUARANTINE_USER_REJECT: SqlContract = SqlContract {
    id: "mail_security.quarantine_user_reject",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_quarantine_reject($1, $2, FALSE)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUARANTINE_ADMIN_RELEASE: SqlContract = SqlContract {
    id: "mail_security.quarantine_admin_release",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_quarantine_release($1, $2, TRUE)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUARANTINE_ADMIN_REJECT: SqlContract = SqlContract {
    id: "mail_security.quarantine_admin_reject",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_quarantine_reject($1, $2, TRUE)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

const QUARANTINE_ADMIN_LIST_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::named("message_id", Type::INT8),
    ColumnSpec::named("mailbox_id", Type::INT8),
    ColumnSpec::named("subject", Type::TEXT),
    ColumnSpec::named("from_addr", Type::TEXT),
    ColumnSpec::named("original_tag", Type::TEXT),
    ColumnSpec::named("reason", Type::TEXT),
    ColumnSpec::named("reason_type", Type::TEXT),
    ColumnSpec::named("virus_name", Type::TEXT),
    ColumnSpec::named("preview_token", Type::TEXT),
    ColumnSpec::named("quarantined_at", Type::TIMESTAMPTZ),
    ColumnSpec::named("released_at", Type::TIMESTAMPTZ),
    ColumnSpec::named("released_by", Type::INT8),
    ColumnSpec::named("rejected_at", Type::TIMESTAMPTZ),
    ColumnSpec::named("rejected_by", Type::INT8),
    ColumnSpec::named("size_bytes", Type::INT8),
    ColumnSpec::named("recipient", Type::TEXT),
];

pub const QUARANTINE_ADMIN_LIST: SqlContract = SqlContract {
    id: "mail_security.quarantine_admin_list",
    domain: "mail-security",
    sql: "SELECT qm.id, qm.message_id, qm.mailbox_id, m.subject, m.from_addr, \
          qm.original_tag, qm.reason, qm.reason_type, qm.virus_name, qm.preview_token, \
          qm.quarantined_at, qm.released_at, qm.released_by, qm.rejected_at, qm.rejected_by, \
          m.size_bytes, mb.email as recipient \
          FROM quarantined_messages qm \
          JOIN messages m ON m.id = qm.message_id \
          JOIN mailboxes mb ON mb.id = qm.mailbox_id \
          WHERE (($2::text = 'released' AND qm.released_at IS NOT NULL) \
                 OR ($2::text = 'rejected' AND qm.rejected_at IS NOT NULL) \
                 OR ($2::text = 'active' AND qm.released_at IS NULL AND qm.rejected_at IS NULL) \
                 OR ($2::text NOT IN ('released', 'rejected', 'active'))) \
            AND admin_can_reach_perm($1::bigint, (SELECT mb2.user_id FROM mailboxes mb2 WHERE mb2.id = qm.mailbox_id), ARRAY['domains.read','queue.read','reports.read','mail.pipeline','mail.security']) \
            AND ($3::text = '' OR m.from_addr ILIKE '%' || $3::text || '%' OR m.subject ILIKE '%' || $3::text || '%') \
          ORDER BY qm.quarantined_at DESC LIMIT $4 OFFSET $5",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::INT8, Type::INT8],
    columns: QUARANTINE_ADMIN_LIST_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUARANTINE_ADMIN_LIST_MUTANT: SqlContract = SqlContract {
    id: "mail_security.quarantine_admin_list_mutant",
    domain: "mail-security",
    sql: "SELECT qm.id, qm.message_id, qm.mailbox_id, m.subject, m.from_addr, \
          qm.original_tag, qm.reason, qm.reason_type, qm.virus_name, qm.preview_token, \
          qm.quarantined_at, qm.released_at, qm.released_by, qm.rejected_at, qm.rejected_by, \
          m.size_bytes, mb.email as recipient \
          FROM quarantined_messages qm \
          JOIN messages m ON m.id = qm.message_id \
          JOIN mailboxes mb ON mb.id = qm.mailbox_id \
          WHERE (($2::text = 'released' AND qm.released_at IS NOT NULL) \
                 OR ($2::text = 'rejected' AND qm.rejected_at IS NOT NULL) \
                 OR ($2::text = 'active' AND qm.released_at IS NULL AND qm.rejected_at IS NULL) \
                 OR ($2::text NOT IN ('released', 'rejected', 'active'))) \
            AND ($1::bigint IS NOT NULL) \
            AND ($3::text = '' OR m.from_addr ILIKE '%' || $3::text || '%' OR m.subject ILIKE '%' || $3::text || '%') \
          ORDER BY qm.quarantined_at DESC LIMIT $4 OFFSET $5",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::INT8, Type::INT8],
    columns: QUARANTINE_ADMIN_LIST_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUARANTINE_ADMIN_STATS: SqlContract = SqlContract {
    id: "mail_security.quarantine_admin_stats",
    domain: "mail-security",
    sql: "SELECT COUNT(*)::bigint FROM quarantined_messages qm \
          WHERE (($2::text = 'active' AND qm.released_at IS NULL AND qm.rejected_at IS NULL) \
                 OR ($2::text = 'released' AND qm.released_at IS NOT NULL) \
                 OR ($2::text = 'rejected' AND qm.rejected_at IS NOT NULL)) \
            AND admin_can_reach_perm($1::bigint, (SELECT mb.user_id FROM mailboxes mb WHERE mb.id = qm.mailbox_id), ARRAY['domains.read','queue.read','reports.read','mail.pipeline','mail.security'])",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUARANTINE_ADMIN_STATS_MUTANT: SqlContract = SqlContract {
    id: "mail_security.quarantine_admin_stats_mutant",
    domain: "mail-security",
    sql: "SELECT COUNT(*)::bigint FROM quarantined_messages qm \
          WHERE (($2::text = 'active' AND qm.released_at IS NULL AND qm.rejected_at IS NULL) \
                 OR ($2::text = 'released' AND qm.released_at IS NOT NULL) \
                 OR ($2::text = 'rejected' AND qm.rejected_at IS NOT NULL)) \
            AND ($1::bigint IS NOT NULL)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

const QUARANTINE_ADMIN_PREVIEW_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
];

pub const QUARANTINE_ADMIN_PREVIEW: SqlContract = SqlContract {
    id: "mail_security.quarantine_admin_preview",
    domain: "mail-security",
    sql: "SELECT COALESCE(m.body_html,''), COALESCE(m.subject,''), COALESCE(m.from_addr,''), \
          to_char(qm.quarantined_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
          FROM quarantined_messages qm JOIN messages m ON m.id = qm.message_id \
          WHERE qm.id = $1 \
            AND admin_can_reach_perm($2::bigint, (SELECT mb.user_id FROM mailboxes mb WHERE mb.id = qm.mailbox_id), ARRAY['mail.export'])",
    params: &[Type::INT8, Type::INT8],
    columns: QUARANTINE_ADMIN_PREVIEW_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUARANTINE_ADMIN_PREVIEW_MUTANT: SqlContract = SqlContract {
    id: "mail_security.quarantine_admin_preview_mutant",
    domain: "mail-security",
    sql: "SELECT COALESCE(m.body_html,''), COALESCE(m.subject,''), COALESCE(m.from_addr,''), \
          to_char(qm.quarantined_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
          FROM quarantined_messages qm JOIN messages m ON m.id = qm.message_id \
          WHERE qm.id = $1 AND ($2::bigint IS NOT NULL)",
    params: &[Type::INT8, Type::INT8],
    columns: QUARANTINE_ADMIN_PREVIEW_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- Outbound Queue ----

pub const QUEUE_SUMMARY: SqlContract = SqlContract {
    id: "mail_security.queue_summary",
    domain: "mail-security",
    sql: "SELECT COUNT(*) FILTER (WHERE status = 'pending')::bigint, \
          COUNT(*) FILTER (WHERE status = 'deferred')::bigint, \
          COUNT(*) FILTER (WHERE status = 'bounced' AND delivered_at > now() - interval '24 hours')::bigint, \
          COUNT(*) FILTER (WHERE attempt_count >= 10 AND status IN ('deferred','pending'))::bigint, \
          COALESCE(EXTRACT(EPOCH FROM (now() - MIN(queued_at) FILTER (WHERE status IN ('pending','deferred'))))/60, 0)::float8 \
          FROM outbound_queue",
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::FLOAT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

const QUEUE_LIST_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::named("message_id", Type::TEXT),
    ColumnSpec::named("from_addr", Type::TEXT),
    ColumnSpec::named("status", Type::TEXT),
    ColumnSpec::named("rcpt_addrs", Type::TEXT_ARRAY),
    ColumnSpec::named("attempt_count", Type::INT4),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("last_error", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("mailbox_id", Type::INT8),
];

macro_rules! queue_list_select {
    () => {
        concat!(
            "SELECT id, message_id, from_addr, status, rcpt_addrs, attempt_count, ",
            pg_rfc3339!("next_attempt_at"),
            ", last_error, ",
            pg_rfc3339!("queued_at"),
            ", mailbox_id FROM outbound_queue"
        )
    };
}

pub const QUEUE_LIST_ALL: SqlContract = SqlContract {
    id: "mail_security.queue_list_all",
    domain: "mail-security",
    sql: concat!(
        queue_list_select!(),
        " ORDER BY queued_at DESC LIMIT $1 OFFSET $2"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: QUEUE_LIST_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUEUE_LIST_FAILED: SqlContract = SqlContract {
    id: "mail_security.queue_list_failed",
    domain: "mail-security",
    sql: concat!(
        queue_list_select!(),
        " WHERE status = 'bounced' ORDER BY queued_at DESC LIMIT $1 OFFSET $2"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: QUEUE_LIST_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUEUE_LIST_HELD: SqlContract = SqlContract {
    id: "mail_security.queue_list_held",
    domain: "mail-security",
    sql: concat!(
        queue_list_select!(),
        " WHERE attempt_count >= 10 AND status IN ('deferred','pending') ORDER BY queued_at DESC LIMIT $1 OFFSET $2"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: QUEUE_LIST_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUEUE_LIST_STATUS: SqlContract = SqlContract {
    id: "mail_security.queue_list_status",
    domain: "mail-security",
    sql: concat!(
        queue_list_select!(),
        " WHERE status = $1 ORDER BY queued_at DESC LIMIT $2 OFFSET $3"
    ),
    params: &[Type::TEXT, Type::INT8, Type::INT8],
    columns: QUEUE_LIST_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUEUE_RETRY: SqlContract = SqlContract {
    id: "mail_security.queue_retry",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_queue_retry($1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUEUE_BOUNCE: SqlContract = SqlContract {
    id: "mail_security.queue_bounce",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_queue_bounce($1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- S/MIME Trust Anchors ----

pub const SMIME_LIST: SqlContract = SqlContract {
    id: "mail_security.smime_list",
    domain: "mail-security",
    sql: "SELECT id, label, COALESCE(subject_cn,''), fingerprint, domain_id, \
          to_char(not_before AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
          to_char(not_after AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
          to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
          FROM smime_trust_anchors \
          WHERE ($1::bigint = 0 OR domain_id IS NULL OR domain_id = $1::bigint) \
          ORDER BY created_at DESC, id DESC",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("label", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("fingerprint", Type::TEXT),
        ColumnSpec::named("domain_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SMIME_IMPORT: SqlContract = SqlContract {
    id: "mail_security.smime_import",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_smime_anchor_import($1::text,$2::text::jsonb,$3::bigint,$4::bigint)",
    params: &[Type::TEXT, Type::TEXT, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SMIME_DELETE: SqlContract = SqlContract {
    id: "mail_security.smime_delete",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_smime_anchor_delete($1::bigint,$2::bigint)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- Spam, Sender Lists, Sender Control, Trusted Senders, External Sender, Report ----

pub const SPAM_SENDER_CONTROL_ON: SqlContract = SqlContract {
    id: "mail_security.spam_sender_control_on",
    domain: "mail-security",
    sql: "SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.sender_control_center'),false)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_DASHBOARD_ENABLED: SqlContract = SqlContract {
    id: "mail_security.spam_dashboard_enabled",
    domain: "mail-security",
    sql: "SELECT enabled FROM feature_toggles WHERE key = 'feature.ml_spam'",
    params: &[],
    columns: &[ColumnSpec::named("enabled", Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_DASHBOARD_TOTALS: SqlContract = SqlContract {
    id: "mail_security.spam_dashboard_totals",
    domain: "mail-security",
    sql: "SELECT COALESCE(COUNT(*), 0)::bigint, COALESCE(SUM(sample_count), 0)::bigint FROM user_spam_model",
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_DASHBOARD_AVG: SqlContract = SqlContract {
    id: "mail_security.spam_dashboard_avg",
    domain: "mail-security",
    sql: "SELECT COALESCE(AVG(sample_count), 0)::text FROM user_spam_model",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_DASHBOARD_DISABLED: SqlContract = SqlContract {
    id: "mail_security.spam_dashboard_disabled",
    domain: "mail-security",
    sql: "SELECT COALESCE(COUNT(*), 0)::bigint FROM user_spam_model WHERE disabled = TRUE",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_DASHBOARD_ACTIVE: SqlContract = SqlContract {
    id: "mail_security.spam_dashboard_active",
    domain: "mail-security",
    sql: "SELECT COALESCE(COUNT(*), 0)::bigint FROM user_spam_model WHERE trained_at > now() - INTERVAL '7 days'",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_DASHBOARD_COUNTS: SqlContract = SqlContract {
    id: "mail_security.spam_dashboard_counts",
    domain: "mail-security",
    sql: "SELECT COALESCE(SUM(fp_count), 0)::bigint, COALESCE(SUM(fn_count), 0)::bigint, \
          COALESCE(SUM(classified_count), 0)::bigint FROM user_spam_model",
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

pub const SPAM_DASHBOARD_TOP: SqlContract = SqlContract {
    id: "mail_security.spam_dashboard_top",
    domain: "mail-security",
    sql: "SELECT m.user_id, COALESCE(u.email, 'unknown'), m.sample_count, \
          to_char(m.trained_at, 'YYYY-MM-DD HH24:MI') AS trained, \
          (octet_length(m.model_bytes) / 1024)::int4 AS size_kb, m.disabled \
          FROM user_spam_model m LEFT JOIN users u ON u.id = m.user_id \
          ORDER BY m.sample_count DESC LIMIT 10",
    params: &[],
    columns: &[
        ColumnSpec::named("user_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("sample_count", Type::INT4),
        ColumnSpec::named("trained", Type::TEXT),
        ColumnSpec::named("size_kb", Type::INT4),
        ColumnSpec::named("disabled", Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_MODEL_RESET: SqlContract = SqlContract {
    id: "mail_security.spam_model_reset",
    domain: "mail-security",
    sql: "WITH r AS (SELECT admin_can_reach($1, $2) AS ok), \
          d AS (DELETE FROM user_spam_model WHERE user_id = $2 AND (SELECT ok FROM r) RETURNING 1) \
          SELECT ok FROM r",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::named("ok", Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_MODEL_DISABLE: SqlContract = SqlContract {
    id: "mail_security.spam_model_disable",
    domain: "mail-security",
    sql: "WITH r AS (SELECT admin_can_reach($1, $2) AS ok), \
          i AS (INSERT INTO user_spam_model (user_id, model_bytes, sample_count, disabled) \
                SELECT $2, '\\x'::bytea, 0, TRUE FROM r WHERE ok \
                ON CONFLICT (user_id) DO UPDATE SET disabled = TRUE RETURNING 1) \
          SELECT ok FROM r",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::named("ok", Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_MODEL_ENABLE: SqlContract = SqlContract {
    id: "mail_security.spam_model_enable",
    domain: "mail-security",
    sql: "WITH r AS (SELECT admin_can_reach($1, $2) AS ok), \
          u AS (UPDATE user_spam_model SET disabled = FALSE WHERE user_id = $2 AND (SELECT ok FROM r) RETURNING 1) \
          SELECT ok FROM r",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::named("ok", Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_SENDERS_LEGACY: SqlContract = SqlContract {
    id: "mail_security.spam_senders_legacy",
    domain: "mail-security",
    sql: "SELECT sender, list_type FROM user_sender_list WHERE user_id = $1 ORDER BY list_type, sender",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("sender", Type::TEXT),
        ColumnSpec::named("list_type", Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_SENDER_LIST_READ: SqlContract = SqlContract {
    id: "mail_security.spam_sender_list_read",
    domain: "mail-security",
    sql: "SELECT sender_list_read($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_SENDER_LIST_REPLACE_LEGACY: SqlContract = SqlContract {
    id: "mail_security.spam_sender_list_replace_legacy",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_sender_list_replace($1, $2, $3)",
    params: &[Type::INT8, Type::TEXT_ARRAY, Type::TEXT_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_SENDER_LIST_REPLACE: SqlContract = SqlContract {
    id: "mail_security.spam_sender_list_replace",
    domain: "mail-security",
    sql: "SELECT sender_list_replace($1, $2::text::uuid, $3, $4, $5, $6)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT_ARRAY,
        Type::TEXT_ARRAY,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_NEVER_BLOCK: SqlContract = SqlContract {
    id: "mail_security.spam_never_block",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_sender_never_block($1, $2)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_SENDER_CONTROL_READ: SqlContract = SqlContract {
    id: "mail_security.spam_sender_control_read",
    domain: "mail-security",
    sql: "SELECT sender_control_read($1, $2, $3, $4::text::timestamptz)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_SENDER_CONTROL_ACTION: SqlContract = SqlContract {
    id: "mail_security.spam_sender_control_action",
    domain: "mail-security",
    sql: "SELECT sender_control_action($1, $2, $3, $4::text::timestamptz, $5::text::uuid, $6, $7, $8, $9::text::uuid)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
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

pub const SPAM_TRUSTED_LIST: SqlContract = SqlContract {
    id: "mail_security.spam_trusted_list",
    domain: "mail-security",
    sql: "SELECT sender, to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
          FROM user_image_allow WHERE user_id = $1 ORDER BY created_at DESC, sender",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("sender", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_TRUSTED_ADD: SqlContract = SqlContract {
    id: "mail_security.spam_trusted_add",
    domain: "mail-security",
    sql: "INSERT INTO user_image_allow (user_id, sender) VALUES ($1, $2) \
          ON CONFLICT (user_id, sender) DO NOTHING RETURNING true",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_TRUSTED_REMOVE: SqlContract = SqlContract {
    id: "mail_security.spam_trusted_remove",
    domain: "mail-security",
    sql: "DELETE FROM user_image_allow WHERE user_id = $1 AND sender = $2 RETURNING true",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_EXTERNAL_USER: SqlContract = SqlContract {
    id: "mail_security.spam_external_user",
    domain: "mail-security",
    sql: "SELECT COALESCE(external_sender_warning, TRUE), email FROM users WHERE id = $1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::named("email", Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_EXTERNAL_DOMAIN: SqlContract = SqlContract {
    id: "mail_security.spam_external_domain",
    domain: "mail-security",
    sql: "SELECT esc.enabled, esc.warn_text, esc.warn_color FROM domains d \
          JOIN external_sender_config esc ON esc.domain_id = d.id \
          WHERE lower(d.name) = lower($1) AND d.is_local = TRUE",
    params: &[Type::TEXT],
    columns: &[
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::named("warn_text", Type::TEXT),
        ColumnSpec::named("warn_color", Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_EXTERNAL_GLOBAL: SqlContract = SqlContract {
    id: "mail_security.spam_external_global",
    domain: "mail-security",
    sql: "SELECT value::text FROM system_config WHERE key = 'external_sender.enabled'",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_EXTERNAL_PUT: SqlContract = SqlContract {
    id: "mail_security.spam_external_put",
    domain: "mail-security",
    sql: "SELECT rust_user_external_sender_warning_set($1, $2)",
    params: &[Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPAM_REPORT: SqlContract = SqlContract {
    id: "mail_security.spam_report",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_report($1, $2, $3, $4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- Threat Views and IP Rules ----

const THREAT_ATTEMPTS_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("target_username", Type::TEXT),
    ColumnSpec::named("protocol", Type::TEXT),
    ColumnSpec::named("outcome", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
];

pub const THREAT_ATTEMPTS_COUNT: SqlContract = SqlContract {
    id: "mail_security.threat_attempts_count",
    domain: "mail-security",
    sql: concat!(
        "SELECT COUNT(*) FROM auth_attempts ",
        "WHERE (CASE WHEN $1::text = '' THEN TRUE ELSE occurred_at >= now() - $1::text::interval END) ",
        "AND ($2::text = '' OR target_username ILIKE '%' || $2::text || '%' OR source_ip::text ILIKE '%' || $2::text || '%')"
    ),
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

macro_rules! threat_attempts_list {
    ($name:ident, $id:literal, $order:literal) => {
        pub const $name: SqlContract = SqlContract {
            id: $id,
            domain: "mail-security",
            sql: concat!(
                "SELECT host(source_ip::inet), target_username, protocol, outcome, ",
                "COALESCE(failure_reason,''), COALESCE(geo_country,''), ",
                pg_rfc3339!("occurred_at"),
                ", ",
                pg_go_utc_time!("occurred_at"),
                " FROM auth_attempts ",
                "WHERE (CASE WHEN $1::text = '' THEN TRUE ELSE occurred_at >= now() - $1::text::interval END) ",
                "AND ($2::text = '' OR target_username ILIKE '%' || $2::text || '%' OR source_ip::text ILIKE '%' || $2::text || '%') ",
                "ORDER BY ",
                $order,
                " LIMIT $3 OFFSET $4"
            ),
            params: &[Type::TEXT, Type::TEXT, Type::INT8, Type::INT8],
            columns: THREAT_ATTEMPTS_COLUMNS,
            scope: SqlScope::AdminRead,
            rls_check: RlsCheck::PrepareAndExplain,
            audit: SqlAuditPosture::Standard,
        };
    };
}

threat_attempts_list!(
    THREAT_ATTEMPTS_OCCURRED_AT_DESC,
    "mail_security.threat_attempts_occurred_at_desc",
    "occurred_at DESC"
);
threat_attempts_list!(
    THREAT_ATTEMPTS_OCCURRED_AT_ASC,
    "mail_security.threat_attempts_occurred_at_asc",
    "occurred_at ASC"
);
threat_attempts_list!(
    THREAT_ATTEMPTS_SOURCE_IP_DESC,
    "mail_security.threat_attempts_source_ip_desc",
    "source_ip DESC"
);
threat_attempts_list!(
    THREAT_ATTEMPTS_SOURCE_IP_ASC,
    "mail_security.threat_attempts_source_ip_asc",
    "source_ip ASC"
);
threat_attempts_list!(
    THREAT_ATTEMPTS_OUTCOME_DESC,
    "mail_security.threat_attempts_outcome_desc",
    "outcome DESC"
);
threat_attempts_list!(
    THREAT_ATTEMPTS_OUTCOME_ASC,
    "mail_security.threat_attempts_outcome_asc",
    "outcome ASC"
);

const THREAT_FEED_BLOCKS_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("cidr", Type::TEXT),
    ColumnSpec::named("source", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
];

pub const THREAT_FEED_BLOCKS_COUNT: SqlContract = SqlContract {
    id: "mail_security.threat_feed_blocks_count",
    domain: "mail-security",
    sql: "SELECT COUNT(*) FROM threat_feed_blocks \
          WHERE ($1::text = '' OR cidr::text ILIKE '%' || $1::text || '%' OR source ILIKE '%' || $1::text || '%')",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

macro_rules! threat_feed_blocks_list {
    ($name:ident, $id:literal, $order:literal) => {
        pub const $name: SqlContract = SqlContract {
            id: $id,
            domain: "mail-security",
            sql: concat!(
                "SELECT cidr::text AS cidr, source, ",
                pg_rfc3339!("added_at"),
                ", ",
                pg_go_utc_time!("added_at"),
                " FROM threat_feed_blocks ",
                "WHERE ($1::text = '' OR cidr::text ILIKE '%' || $1::text || '%' OR source ILIKE '%' || $1::text || '%') ",
                "ORDER BY ",
                $order,
                " LIMIT $2 OFFSET $3"
            ),
            params: &[Type::TEXT, Type::INT8, Type::INT8],
            columns: THREAT_FEED_BLOCKS_COLUMNS,
            scope: SqlScope::AdminRead,
            rls_check: RlsCheck::PrepareAndExplain,
            audit: SqlAuditPosture::Standard,
        };
    };
}

threat_feed_blocks_list!(
    THREAT_FEED_BLOCKS_ADDED_AT_DESC,
    "mail_security.threat_feed_blocks_added_at_desc",
    "added_at DESC"
);
threat_feed_blocks_list!(
    THREAT_FEED_BLOCKS_ADDED_AT_ASC,
    "mail_security.threat_feed_blocks_added_at_asc",
    "added_at ASC"
);
threat_feed_blocks_list!(
    THREAT_FEED_BLOCKS_SOURCE_DESC,
    "mail_security.threat_feed_blocks_source_desc",
    "source DESC"
);
threat_feed_blocks_list!(
    THREAT_FEED_BLOCKS_SOURCE_ASC,
    "mail_security.threat_feed_blocks_source_asc",
    "source ASC"
);

const THREAT_RATE_COUNTERS_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("key", Type::TEXT),
    ColumnSpec::named("count", Type::INT4),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
];

pub const THREAT_RATE_COUNTERS_COUNT: SqlContract = SqlContract {
    id: "mail_security.threat_rate_counters_count",
    domain: "mail-security",
    sql: "SELECT COUNT(*) FROM rate_limit_counters \
          WHERE ($1::text = '' OR key ILIKE '%' || $1::text || '%')",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

macro_rules! threat_rate_counters_list {
    ($name:ident, $id:literal, $order:literal) => {
        pub const $name: SqlContract = SqlContract {
            id: $id,
            domain: "mail-security",
            sql: concat!(
                "SELECT key, count, ",
                pg_rfc3339!("window_start"),
                ", ",
                pg_go_utc_time!("window_start"),
                ", ",
                pg_rfc3339!("blocked_until"),
                ", ",
                pg_go_utc_time!("blocked_until"),
                " FROM rate_limit_counters ",
                "WHERE ($1::text = '' OR key ILIKE '%' || $1::text || '%') ",
                "ORDER BY ",
                $order,
                " LIMIT $2 OFFSET $3"
            ),
            params: &[Type::TEXT, Type::INT8, Type::INT8],
            columns: THREAT_RATE_COUNTERS_COLUMNS,
            scope: SqlScope::AdminRead,
            rls_check: RlsCheck::PrepareAndExplain,
            audit: SqlAuditPosture::Standard,
        };
    };
}

threat_rate_counters_list!(
    THREAT_RATE_COUNTERS_COUNT_DESC,
    "mail_security.threat_rate_counters_count_desc",
    "count DESC"
);
threat_rate_counters_list!(
    THREAT_RATE_COUNTERS_COUNT_ASC,
    "mail_security.threat_rate_counters_count_asc",
    "count ASC"
);
threat_rate_counters_list!(
    THREAT_RATE_COUNTERS_WINDOW_START_DESC,
    "mail_security.threat_rate_counters_window_start_desc",
    "window_start DESC"
);
threat_rate_counters_list!(
    THREAT_RATE_COUNTERS_WINDOW_START_ASC,
    "mail_security.threat_rate_counters_window_start_asc",
    "window_start ASC"
);
threat_rate_counters_list!(
    THREAT_RATE_COUNTERS_BLOCKED_UNTIL_DESC,
    "mail_security.threat_rate_counters_blocked_until_desc",
    "blocked_until DESC"
);
threat_rate_counters_list!(
    THREAT_RATE_COUNTERS_BLOCKED_UNTIL_ASC,
    "mail_security.threat_rate_counters_blocked_until_asc",
    "blocked_until ASC"
);

pub const THREAT_LOCKOUT_COUNT: SqlContract = SqlContract {
    id: "mail_security.threat_lockout_count",
    domain: "mail-security",
    sql: "SELECT lockout_count($1::text)",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const THREAT_LOCKOUT_LIST: SqlContract = SqlContract {
    id: "mail_security.threat_lockout_list",
    domain: "mail-security",
    sql: concat!(
        "SELECT lockout_key, failed_count, ",
        pg_rfc3339!("locked_until"),
        ", ",
        pg_go_utc_time!("locked_until"),
        ", escalation_level, ",
        pg_rfc3339!("updated_at"),
        ", ",
        pg_go_utc_time!("updated_at"),
        " FROM lockout_list($1::text, $2::int, $3::int, $4::text, $5::text)"
    ),
    params: &[Type::TEXT, Type::INT4, Type::INT4, Type::TEXT, Type::TEXT],
    columns: &[
        ColumnSpec::named("lockout_key", Type::TEXT),
        ColumnSpec::named("failed_count", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("escalation_level", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const THREAT_IP_RULES_COUNT: SqlContract = SqlContract {
    id: "mail_security.threat_ip_rules_count",
    domain: "mail-security",
    sql: "SELECT COUNT(*) FROM ip_rules",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const THREAT_IP_RULES_LIST: SqlContract = SqlContract {
    id: "mail_security.threat_ip_rules_list",
    domain: "mail-security",
    sql: "SELECT id, cidr::text, action, description, \
          to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
          to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
          created_by \
          FROM ip_rules ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("action", Type::TEXT),
        ColumnSpec::named("description", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("created_by", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const THREAT_IP_RULE_CREATE: SqlContract = SqlContract {
    id: "mail_security.threat_ip_rule_create",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_ip_rule_create($1,$2,$3,$4,$5,$6)",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const THREAT_IP_RULE_DELETE: SqlContract = SqlContract {
    id: "mail_security.threat_ip_rule_delete",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_ip_rule_delete($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// ---- TLS Configuration & Policy ----

pub const TLS_STORED_VALUE: SqlContract = SqlContract {
    id: "mail_security.tls_stored_value",
    domain: "mail-security",
    sql: "SELECT value::text FROM system_config WHERE key = $1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TLS_POLICY_SET: SqlContract = SqlContract {
    id: "mail_security.tls_policy_set",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_tls_policy_set($1::text::jsonb,$2::text::jsonb,$3::text::jsonb)",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TLS_CONFIG_GET: SqlContract = SqlContract {
    id: "mail_security.tls_config_get",
    domain: "mail-security",
    sql:
        "SELECT key, value::text, encrypted FROM system_config WHERE key LIKE 'tls_%' ORDER BY key",
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

pub const TLS_CONFIG_KEY_EXISTS: SqlContract = SqlContract {
    id: "mail_security.tls_config_key_exists",
    domain: "mail-security",
    sql: "SELECT 1 FROM system_config WHERE key = $1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TLS_CONFIG_SET: SqlContract = SqlContract {
    id: "mail_security.tls_config_set",
    domain: "mail-security",
    sql: "SELECT rust_mailsec_tls_config_set($1::text[],$2::text[],$3::boolean[],$4::bigint,$5::text,$6::text::jsonb,$7::text)",
    params: &[
        Type::TEXT_ARRAY,
        Type::TEXT_ARRAY,
        Type::BOOL_ARRAY,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TLS_IMPORT_AUDIT: SqlContract = SqlContract {
    id: "mail_security.tls_import_audit",
    domain: "mail-security",
    sql: "SELECT audit_write($1,'tls_cert_import','system_config',NULL,NULL,$2::text::jsonb,NULLIF($3::text,'')::inet,'','core')",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TLS_CONFIG_SCALAR: SqlContract = SqlContract {
    id: "mail_security.tls_config_scalar",
    domain: "mail-security",
    sql: "SELECT COALESCE((SELECT value #>> '{}' FROM system_config WHERE key = $1), '')",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---- Message Trace & Delivery Attempts ----

macro_rules! trace_filter_where {
    () => {
        "WHERE ($1::text = '' OR from_addr ILIKE $1::text) \
         AND ($2::text = '' OR rcpt_addr ILIKE $2::text) \
         AND ($3::text = '' OR event = $3::text) \
         AND ($4::text = '' OR details->>'status' = $4::text) \
         AND ($5::text = '' OR details->>'subject' ILIKE $5::text) \
         AND (CASE WHEN $6::text IS NULL THEN TRUE ELSE occurred_at >= $6::text::timestamptz END) \
         AND (CASE WHEN $7::text IS NULL THEN TRUE ELSE occurred_at <= $7::text::timestamptz END)"
    };
}

pub const TRACE_ADMIN_COUNT: SqlContract = SqlContract {
    id: "mail_security.trace_admin_count",
    domain: "mail-security",
    sql: concat!("SELECT COUNT(*) FROM message_trace ", trace_filter_where!()),
    params: &[
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TRACE_ADMIN_LIST: SqlContract = SqlContract {
    id: "mail_security.trace_admin_list",
    domain: "mail-security",
    sql: concat!(
        "SELECT id, message_id, event, from_addr, rcpt_addr, remote_host, details::text, ",
        pg_rfc3339!("occurred_at"),
        " FROM message_trace ",
        trace_filter_where!(),
        " ORDER BY occurred_at DESC LIMIT $8 OFFSET $9"
    ),
    params: &[
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("message_id", Type::TEXT),
        ColumnSpec::named("event", Type::TEXT),
        ColumnSpec::named("from_addr", Type::TEXT),
        ColumnSpec::named("rcpt_addr", Type::TEXT),
        ColumnSpec::named("remote_host", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TRACE_ADMIN_EXPORT: SqlContract = SqlContract {
    id: "mail_security.trace_admin_export",
    domain: "mail-security",
    sql: concat!(
        "SELECT message_id, event, from_addr, rcpt_addr, remote_host, details::text, ",
        "to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') ",
        "FROM message_trace ",
        trace_filter_where!(),
        " ORDER BY occurred_at DESC LIMIT 10000"
    ),
    params: &[
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[
        ColumnSpec::named("message_id", Type::TEXT),
        ColumnSpec::named("event", Type::TEXT),
        ColumnSpec::named("from_addr", Type::TEXT),
        ColumnSpec::named("rcpt_addr", Type::TEXT),
        ColumnSpec::named("remote_host", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TRACE_TIMELINE_EVENTS: SqlContract = SqlContract {
    id: "mail_security.trace_timeline_events",
    domain: "mail-security",
    sql: concat!(
        "SELECT event, rcpt_addr, from_addr, remote_host, details::text, ",
        pg_rfc3339!("occurred_at"),
        " FROM message_trace WHERE message_id = $1 ORDER BY occurred_at ASC"
    ),
    params: &[Type::TEXT],
    columns: &[
        ColumnSpec::named("event", Type::TEXT),
        ColumnSpec::named("rcpt_addr", Type::TEXT),
        ColumnSpec::named("from_addr", Type::TEXT),
        ColumnSpec::named("remote_host", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TRACE_TIMELINE_QUEUE: SqlContract = SqlContract {
    id: "mail_security.trace_timeline_queue",
    domain: "mail-security",
    sql: concat!(
        "SELECT status, attempt_count, ",
        pg_rfc3339!("next_attempt_at"),
        ", last_error, rcpt_addrs, ",
        pg_rfc3339!("queued_at"),
        ", message_pk FROM outbound_queue WHERE message_id = $1 ORDER BY queued_at DESC LIMIT 1"
    ),
    params: &[Type::TEXT],
    columns: &[
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::named("attempt_count", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("last_error", Type::TEXT),
        ColumnSpec::named("rcpt_addrs", Type::TEXT_ARRAY),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("message_pk", Type::INT8),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

const TRACE_DELIVERY_LATEST_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("recipient_email", Type::TEXT),
    ColumnSpec::named("mx_host", Type::TEXT),
    ColumnSpec::named("smtp_code", Type::INT4),
    ColumnSpec::named("smtp_text", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("outcome", Type::TEXT),
];

const TRACE_DELIVERY_HISTORY_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("recipient_email", Type::TEXT),
    ColumnSpec::named("attempt_number", Type::INT4),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("mx_host", Type::TEXT),
    ColumnSpec::named("smtp_code", Type::INT4),
    ColumnSpec::named("smtp_text", Type::TEXT),
    ColumnSpec::named("outcome", Type::TEXT),
    ColumnSpec::named("tls", Type::BOOL),
];

pub const TRACE_DELIVERY_LATEST_ADMIN: SqlContract = SqlContract {
    id: "mail_security.trace_delivery_latest_admin",
    domain: "mail-security",
    sql: concat!(
        "SELECT DISTINCT ON (recipient_email) recipient_email, mx_host, smtp_code, smtp_text, ",
        pg_rfc3339!("attempted_at"),
        ", outcome FROM delivery_attempts WHERE message_pk = $1 ",
        "ORDER BY recipient_email, attempt_number DESC"
    ),
    params: &[Type::INT8],
    columns: TRACE_DELIVERY_LATEST_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TRACE_DELIVERY_HISTORY_ADMIN: SqlContract = SqlContract {
    id: "mail_security.trace_delivery_history_admin",
    domain: "mail-security",
    sql: concat!(
        "SELECT recipient_email, attempt_number, ",
        pg_rfc3339!("attempted_at"),
        ", mx_host, smtp_code, smtp_text, outcome, tls ",
        "FROM delivery_attempts WHERE message_pk = $1 ",
        "ORDER BY recipient_email, attempt_number ASC"
    ),
    params: &[Type::INT8],
    columns: TRACE_DELIVERY_HISTORY_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TRACE_USER_OWNED: SqlContract = SqlContract {
    id: "mail_security.trace_user_owned",
    domain: "mail-security",
    sql: "SELECT m.raw_ref, m.mailbox_id, m.id, m.received_at, COALESCE(m.subject, 'message') \
          FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id \
          WHERE m.id = $1 AND mb.user_id = $2",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("raw_ref", Type::TEXT),
        ColumnSpec::named("mailbox_id", Type::INT8),
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("received_at", Type::TIMESTAMPTZ),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TRACE_USER_IS_SENT: SqlContract = SqlContract {
    id: "mail_security.trace_user_is_sent",
    domain: "mail-security",
    sql: "SELECT EXISTS (SELECT 1 FROM message_tags mt JOIN tags t ON t.id = mt.tag_id \
          WHERE mt.message_id = $1 AND mt.received_at = $2 AND t.mailbox_id = $3 \
          AND t.name = 'Sent' AND t.tag_type = 'system' AND t.exclusive_group = 'location')",
    params: &[Type::INT8, Type::TIMESTAMPTZ, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TRACE_USER_OUTBOUND_QUEUE: SqlContract = SqlContract {
    id: "mail_security.trace_user_outbound_queue",
    domain: "mail-security",
    sql: concat!(
        "SELECT status, ",
        pg_rfc3339!("next_attempt_at"),
        ", ",
        pg_rfc3339!("delivered_at"),
        ", rcpt_addrs FROM outbound_queue ",
        "WHERE message_pk = $1 AND mailbox_id = $2 ORDER BY queued_at DESC LIMIT 1"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("rcpt_addrs", Type::TEXT_ARRAY),
    ],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TRACE_DELIVERY_LATEST_USER: SqlContract = SqlContract {
    id: "mail_security.trace_delivery_latest_user",
    domain: "mail-security",
    sql: concat!(
        "SELECT DISTINCT ON (recipient_email) recipient_email, mx_host, smtp_code, smtp_text, ",
        pg_rfc3339!("attempted_at"),
        ", outcome FROM delivery_attempts WHERE message_pk = $1 AND mailbox_id = $2 ",
        "ORDER BY recipient_email, attempt_number DESC"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: TRACE_DELIVERY_LATEST_COLUMNS,
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TRACE_DELIVERY_HISTORY_USER: SqlContract = SqlContract {
    id: "mail_security.trace_delivery_history_user",
    domain: "mail-security",
    sql: concat!(
        "SELECT recipient_email, attempt_number, ",
        pg_rfc3339!("attempted_at"),
        ", mx_host, smtp_code, smtp_text, outcome, tls ",
        "FROM delivery_attempts WHERE message_pk = $1 AND mailbox_id = $2 ",
        "ORDER BY recipient_email, attempt_number ASC"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: TRACE_DELIVERY_HISTORY_COLUMNS,
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    CONSOLE_DENIED,
    DLP_PATTERNS_GET,
    DLP_PATTERNS_REPLACE,
    ANTIPHISH_GET,
    ANTIPHISH_PUT,
    LINK_PROTECT_AUDIT_LIST,
    DLP_STRICT_MODE,
    DLP_CLICK_AUDIT,
    DMARC_DOMAIN_NAME,
    DMARC_LIVE_TOTALS,
    DMARC_LIVE_BY_DOMAIN,
    DMARC_FAILURES,
    DMARC_TREND,
    DMARC_AUTH_LOG,
    QUARANTINE_USER_LIST,
    QUARANTINE_USER_COUNT,
    QUARANTINE_USER_RELEASE,
    QUARANTINE_USER_REJECT,
    QUARANTINE_ADMIN_RELEASE,
    QUARANTINE_ADMIN_REJECT,
    QUARANTINE_ADMIN_LIST,
    QUARANTINE_ADMIN_LIST_MUTANT,
    QUARANTINE_ADMIN_STATS,
    QUARANTINE_ADMIN_STATS_MUTANT,
    QUARANTINE_ADMIN_PREVIEW,
    QUARANTINE_ADMIN_PREVIEW_MUTANT,
    QUEUE_SUMMARY,
    QUEUE_LIST_ALL,
    QUEUE_LIST_FAILED,
    QUEUE_LIST_HELD,
    QUEUE_LIST_STATUS,
    QUEUE_RETRY,
    QUEUE_BOUNCE,
    SMIME_LIST,
    SMIME_IMPORT,
    SMIME_DELETE,
    SPAM_SENDER_CONTROL_ON,
    SPAM_DASHBOARD_ENABLED,
    SPAM_DASHBOARD_TOTALS,
    SPAM_DASHBOARD_AVG,
    SPAM_DASHBOARD_DISABLED,
    SPAM_DASHBOARD_ACTIVE,
    SPAM_DASHBOARD_COUNTS,
    SPAM_DASHBOARD_TOP,
    SPAM_MODEL_RESET,
    SPAM_MODEL_DISABLE,
    SPAM_MODEL_ENABLE,
    SPAM_SENDERS_LEGACY,
    SPAM_SENDER_LIST_READ,
    SPAM_SENDER_LIST_REPLACE_LEGACY,
    SPAM_SENDER_LIST_REPLACE,
    SPAM_NEVER_BLOCK,
    SPAM_SENDER_CONTROL_READ,
    SPAM_SENDER_CONTROL_ACTION,
    SPAM_TRUSTED_LIST,
    SPAM_TRUSTED_ADD,
    SPAM_TRUSTED_REMOVE,
    SPAM_EXTERNAL_USER,
    SPAM_EXTERNAL_DOMAIN,
    SPAM_EXTERNAL_GLOBAL,
    SPAM_EXTERNAL_PUT,
    SPAM_REPORT,
    THREAT_ATTEMPTS_COUNT,
    THREAT_ATTEMPTS_OCCURRED_AT_DESC,
    THREAT_ATTEMPTS_OCCURRED_AT_ASC,
    THREAT_ATTEMPTS_SOURCE_IP_DESC,
    THREAT_ATTEMPTS_SOURCE_IP_ASC,
    THREAT_ATTEMPTS_OUTCOME_DESC,
    THREAT_ATTEMPTS_OUTCOME_ASC,
    THREAT_FEED_BLOCKS_COUNT,
    THREAT_FEED_BLOCKS_ADDED_AT_DESC,
    THREAT_FEED_BLOCKS_ADDED_AT_ASC,
    THREAT_FEED_BLOCKS_SOURCE_DESC,
    THREAT_FEED_BLOCKS_SOURCE_ASC,
    THREAT_RATE_COUNTERS_COUNT,
    THREAT_RATE_COUNTERS_COUNT_DESC,
    THREAT_RATE_COUNTERS_COUNT_ASC,
    THREAT_RATE_COUNTERS_WINDOW_START_DESC,
    THREAT_RATE_COUNTERS_WINDOW_START_ASC,
    THREAT_RATE_COUNTERS_BLOCKED_UNTIL_DESC,
    THREAT_RATE_COUNTERS_BLOCKED_UNTIL_ASC,
    THREAT_LOCKOUT_COUNT,
    THREAT_LOCKOUT_LIST,
    THREAT_IP_RULES_COUNT,
    THREAT_IP_RULES_LIST,
    THREAT_IP_RULE_CREATE,
    THREAT_IP_RULE_DELETE,
    TLS_STORED_VALUE,
    TLS_POLICY_SET,
    TLS_CONFIG_GET,
    TLS_CONFIG_KEY_EXISTS,
    TLS_CONFIG_SET,
    TLS_IMPORT_AUDIT,
    TLS_CONFIG_SCALAR,
    TRACE_ADMIN_COUNT,
    TRACE_ADMIN_LIST,
    TRACE_ADMIN_EXPORT,
    TRACE_TIMELINE_EVENTS,
    TRACE_TIMELINE_QUEUE,
    TRACE_DELIVERY_LATEST_ADMIN,
    TRACE_DELIVERY_HISTORY_ADMIN,
    TRACE_USER_OWNED,
    TRACE_USER_IS_SENT,
    TRACE_USER_OUTBOUND_QUEUE,
    TRACE_DELIVERY_LATEST_USER,
    TRACE_DELIVERY_HISTORY_USER,
];
