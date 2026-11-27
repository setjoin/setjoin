//! Static typed SQL contract catalog for `setjoin-rules` (F09).
use setjoin_sql_catalog::{
    pg_rfc3339, ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type,
};

macro_rules! rule_columns {
    () => {
        concat!(
            "id,mailbox_id,name,enabled,priority,run_on,is_transport_rule,conditions::text,actions::text,stop_processing,",
            pg_rfc3339!("created_at"),
            ",",
            pg_rfc3339!("updated_at")
        )
    };
}

macro_rules! template_columns {
    () => {
        "id,name,description,category,conditions::text,actions::text,parameters::text,is_system,sort_order"
    };
}

const RULE_ROW_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::named("mailbox_id", Type::INT8),
    ColumnSpec::named("name", Type::TEXT),
    ColumnSpec::named("enabled", Type::BOOL),
    ColumnSpec::named("priority", Type::INT4),
    ColumnSpec::named("run_on", Type::TEXT),
    ColumnSpec::named("is_transport_rule", Type::BOOL),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("stop_processing", Type::BOOL),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
];

const TEMPLATE_ROW_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::named("name", Type::TEXT),
    ColumnSpec::named("description", Type::TEXT),
    ColumnSpec::named("category", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("is_system", Type::BOOL),
    ColumnSpec::named("sort_order", Type::INT4),
];

const TEMPLATE_DETAIL_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::named("name", Type::TEXT),
    ColumnSpec::named("description", Type::TEXT),
    ColumnSpec::named("category", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("is_system", Type::BOOL),
    ColumnSpec::named("sort_order", Type::INT4),
    ColumnSpec::named("enabled", Type::BOOL),
];

pub const LOCK_MAILBOX: SqlContract = SqlContract {
    id: "rules.lock_mailbox",
    domain: "rules",
    sql: "SELECT id FROM public.mailboxes WHERE id=$1 FOR UPDATE",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PERSONAL_LIST: SqlContract = SqlContract {
    id: "rules.personal_list",
    domain: "rules",
    sql: concat!(
        "SELECT ",
        rule_columns!(),
        " FROM rules WHERE mailbox_id IN(SELECT id FROM mailboxes WHERE user_id=$1) AND is_transport_rule=FALSE ORDER BY priority,id"
    ),
    params: &[Type::INT8],
    columns: RULE_ROW_COLUMNS,
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PERSONAL_COUNT: SqlContract = SqlContract {
    id: "rules.personal_count",
    domain: "rules",
    sql: "SELECT count(*) FROM rules WHERE mailbox_id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PERSONAL_CREATE: SqlContract = SqlContract {
    id: "rules.personal_create",
    domain: "rules",
    sql: "INSERT INTO rules(mailbox_id,name,enabled,priority,run_on,is_transport_rule,conditions,actions,stop_processing) VALUES($1,$2,$3,$4::bigint::int,$5,FALSE,$6::text::jsonb,$7::text::jsonb,$8) RETURNING id::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PERSONAL_UPDATE: SqlContract = SqlContract {
    id: "rules.personal_update",
    domain: "rules",
    sql: "WITH changed AS(UPDATE rules SET name=COALESCE(NULLIF($3,''),name),enabled=$4,priority=$5::bigint::int,run_on=$6,conditions=COALESCE($7::text::jsonb,conditions),actions=COALESCE($8::text::jsonb,actions),stop_processing=$9,updated_at=now() WHERE id=$1 AND mailbox_id IN(SELECT id FROM mailboxes WHERE user_id=$2) AND is_transport_rule=FALSE RETURNING id) SELECT EXISTS(SELECT 1 FROM changed)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PERSONAL_DELETE: SqlContract = SqlContract {
    id: "rules.personal_delete",
    domain: "rules",
    sql: "WITH changed AS(DELETE FROM rules WHERE id=$1 AND mailbox_id IN(SELECT id FROM mailboxes WHERE user_id=$2) AND is_transport_rule=FALSE RETURNING id) SELECT EXISTS(SELECT 1 FROM changed)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACTIVE_SWEEPS: SqlContract = SqlContract {
    id: "rules.active_sweeps",
    domain: "rules",
    sql: "SELECT count(*) FROM scheduled_actions WHERE mailbox_id=$1 AND action_kind='rules_retro' AND status IN('pending','processing')",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const APPLY_RETROACTIVE: SqlContract = SqlContract {
    id: "rules.apply_retroactive",
    domain: "rules",
    sql: "SELECT rules_apply_retroactive($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const APPLY_STATUS: SqlContract = SqlContract {
    id: "rules.apply_status",
    domain: "rules",
    sql: "SELECT status,(payload->>'processed')::bigint,(payload->>'truncated')::boolean FROM scheduled_actions WHERE id=$1::text::uuid AND action_kind='rules_retro' AND mailbox_id IN(SELECT id FROM mailboxes WHERE user_id=$2)",
    params: &[Type::TEXT, Type::INT8],
    columns: &[
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::BOOL),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_LIST_BY_MAILBOX: SqlContract = SqlContract {
    id: "rules.admin_list_by_mailbox",
    domain: "rules",
    sql: concat!(
        "SELECT ",
        rule_columns!(),
        " FROM rules WHERE mailbox_id=$1 ORDER BY priority,id"
    ),
    params: &[Type::INT8],
    columns: RULE_ROW_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_LIST_ALL: SqlContract = SqlContract {
    id: "rules.admin_list_all",
    domain: "rules",
    sql: concat!(
        "SELECT ",
        rule_columns!(),
        " FROM rules ORDER BY is_transport_rule DESC,priority,id"
    ),
    params: &[],
    columns: RULE_ROW_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_GET: SqlContract = SqlContract {
    id: "rules.admin_get",
    domain: "rules",
    sql: concat!("SELECT ", rule_columns!(), " FROM rules WHERE id=$1"),
    params: &[Type::INT8],
    columns: RULE_ROW_COLUMNS,
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MAILBOX_EXISTS: SqlContract = SqlContract {
    id: "rules.mailbox_exists",
    domain: "rules",
    sql: "SELECT EXISTS(SELECT 1 FROM mailboxes WHERE id=$1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_CREATE: SqlContract = SqlContract {
    id: "rules.admin_create",
    domain: "rules",
    sql: "SELECT rule_config_create($1,$2,$3,$4,$5::bigint::int,$6,$7,$8::text::jsonb,$9::text::jsonb,$10)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ADMIN_UPDATE: SqlContract = SqlContract {
    id: "rules.admin_update",
    domain: "rules",
    sql: "SELECT rule_config_update($1,$2,$3,$4,$5,$6::bigint::int,$7,$8,$9::text::jsonb,$10::text::jsonb,$11)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ADMIN_DELETE: SqlContract = SqlContract {
    id: "rules.admin_delete",
    domain: "rules",
    sql: "SELECT rule_config_delete($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ADMIN_TEST_LOOKUP: SqlContract = SqlContract {
    id: "rules.admin_test_lookup",
    domain: "rules",
    sql: "SELECT mailbox_id,conditions::text,actions::text FROM rules WHERE id=$1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("mailbox_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUTHORITY_RESOLVE: SqlContract = SqlContract {
    id: "rules.authority_resolve",
    domain: "rules",
    sql: "SELECT COALESCE((SELECT array_agg(DISTINCT p) FROM public.admin_role_assignments ra JOIN public.admin_role_groups rg ON rg.id=ra.role_group_id CROSS JOIN LATERAL unnest(rg.permissions) p WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND public.admin_assignment_active(ra.eligible,ra.activated_until)),'{}'::text[]), (SELECT MIN(COALESCE(ra.domain_override,rg.domain_scope)) FROM public.admin_role_assignments ra JOIN public.admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND public.admin_assignment_active(ra.eligible,ra.activated_until))",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT_ARRAY),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUTHORITY_DENIED_AUDIT: SqlContract = SqlContract {
    id: "rules.authority_denied_audit",
    domain: "rules",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')::text",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TEMPLATE_LIST_ADMIN: SqlContract = SqlContract {
    id: "rules.template_list_admin",
    domain: "rules",
    sql: concat!(
        "SELECT ",
        template_columns!(),
        " FROM rule_templates WHERE enabled=TRUE ORDER BY category,sort_order"
    ),
    params: &[],
    columns: TEMPLATE_ROW_COLUMNS,
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TEMPLATE_LIST_USER: SqlContract = SqlContract {
    id: "rules.template_list_user",
    domain: "rules",
    sql: concat!(
        "SELECT ",
        template_columns!(),
        " FROM rule_templates t WHERE t.enabled=TRUE AND NOT EXISTS(SELECT 1 FROM rule_template_visibility v WHERE v.template_id=t.id AND v.user_id=$1 AND v.hidden=TRUE) ORDER BY t.category,t.sort_order"
    ),
    params: &[Type::INT8],
    columns: TEMPLATE_ROW_COLUMNS,
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TEMPLATE_GET: SqlContract = SqlContract {
    id: "rules.template_get",
    domain: "rules",
    sql: concat!(
        "SELECT ",
        template_columns!(),
        ",enabled FROM rule_templates WHERE id=$1"
    ),
    params: &[Type::INT8],
    columns: TEMPLATE_DETAIL_COLUMNS,
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TEMPLATE_LOAD: SqlContract = SqlContract {
    id: "rules.template_load",
    domain: "rules",
    sql: "SELECT name,category,conditions::text,actions::text,parameters::text FROM rule_templates WHERE id=$1 AND enabled=TRUE",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("category", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TEMPLATE_LOAD_USER: SqlContract = SqlContract {
    id: "rules.template_load_user",
    domain: "rules",
    sql: "SELECT name,category,conditions::text,actions::text,parameters::text FROM rule_templates WHERE id=$1 AND enabled=TRUE",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("category", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TEMPLATE_CREATE: SqlContract = SqlContract {
    id: "rules.template_create",
    domain: "rules",
    sql: "INSERT INTO rule_templates(name,description,category,conditions,actions,parameters,sort_order) VALUES($1,$2,$3,$4::text::jsonb,$5::text::jsonb,$6::text::jsonb,$7::bigint::int) RETURNING id::text",
    params: &[
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TEMPLATE_UPDATE: SqlContract = SqlContract {
    id: "rules.template_update",
    domain: "rules",
    sql: "WITH changed AS(UPDATE rule_templates SET name=COALESCE(NULLIF($2,''),name),description=COALESCE($3,description),category=COALESCE(NULLIF($4,''),category),conditions=COALESCE($5::text::jsonb,conditions),actions=COALESCE($6::text::jsonb,actions),parameters=COALESCE($7::text::jsonb,parameters),enabled=COALESCE($8,enabled),sort_order=COALESCE($9::bigint::int,sort_order),updated_at=now() WHERE id=$1 RETURNING id) SELECT EXISTS(SELECT 1 FROM changed)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TEMPLATE_DELETE: SqlContract = SqlContract {
    id: "rules.template_delete",
    domain: "rules",
    sql: "WITH changed AS(DELETE FROM rule_templates WHERE id=$1 AND NOT is_system RETURNING id) SELECT EXISTS(SELECT 1 FROM changed)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TEMPLATE_VISIBILITY_LIST: SqlContract = SqlContract {
    id: "rules.template_visibility_list",
    domain: "rules",
    sql: "SELECT user_id,hidden FROM rule_template_visibility WHERE template_id=$1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("user_id", Type::INT8),
        ColumnSpec::named("hidden", Type::BOOL),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TEMPLATE_VISIBILITY_HIDE: SqlContract = SqlContract {
    id: "rules.template_visibility_hide",
    domain: "rules",
    sql: "INSERT INTO rule_template_visibility(template_id,user_id,hidden) VALUES($1,$2,TRUE) ON CONFLICT(template_id,COALESCE(user_id,-1)) DO UPDATE SET hidden=TRUE RETURNING 'true'::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TEMPLATE_VISIBILITY_SHOW: SqlContract = SqlContract {
    id: "rules.template_visibility_show",
    domain: "rules",
    sql: "WITH changed AS(DELETE FROM rule_template_visibility WHERE template_id=$1 AND user_id IS NOT DISTINCT FROM $2 RETURNING template_id) SELECT 'true'::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TEMPLATE_INSTANTIATE: SqlContract = SqlContract {
    id: "rules.template_instantiate",
    domain: "rules",
    sql: "SELECT rule_config_template_create($1,NULLIF($2,0),$3,$4::text::jsonb,$5::text::jsonb)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

// Note: `rule_templates` and `rule_template_visibility` are retired legacy-fixture-only
// tables (`tests/conformance/rules/legacy-fixture.sql`), not present in the active schema.
// Their static SQL constants remain in `sql.rs` (zero `format!` SQL) and are
// excluded from active-schema `SQL_CONTRACTS`; `TEMPLATE_INSTANTIATE` calls the active
// `rule_config_template_create` reducer and IS verified below.
pub const SQL_CONTRACTS: &[SqlContract] = &[
    LOCK_MAILBOX,
    PERSONAL_LIST,
    PERSONAL_COUNT,
    PERSONAL_CREATE,
    PERSONAL_UPDATE,
    PERSONAL_DELETE,
    ACTIVE_SWEEPS,
    APPLY_RETROACTIVE,
    APPLY_STATUS,
    ADMIN_LIST_BY_MAILBOX,
    ADMIN_LIST_ALL,
    ADMIN_GET,
    MAILBOX_EXISTS,
    ADMIN_CREATE,
    ADMIN_UPDATE,
    ADMIN_DELETE,
    ADMIN_TEST_LOOKUP,
    AUTHORITY_RESOLVE,
    AUTHORITY_DENIED_AUDIT,
    TEMPLATE_INSTANTIATE,
];
