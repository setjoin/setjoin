//! Static typed SQL contract catalog for `setjoin-approvals` (F10).
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};

macro_rules! approval_cols {
    () => {
        r#"id,consumer_type,subject,status,requester_user_id,approver_kind,approver_ref,
 to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
 to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
 to_char(decided_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),decided_by_user_id,decision_comment,
 (CASE WHEN consumer_type='drive.access' THEN COALESCE((SELECT jsonb_build_object(
 'nodeId',d.node_id::text,'spaceId',d.space_id::text,'requestedCapabilities',to_jsonb(d.requested_capabilities),
 'requestedPropagation',d.requested_propagation,'requestedExpiresAt',d.requested_expires_at,'requestedMaxUses',d.requested_max_uses,
 'emergency',d.emergency,'reason',d.reason,'expectedEpoch',d.expected_epoch::text,'grantId',CASE WHEN d.grant_id IS NULL THEN NULL ELSE d.grant_id::text END)
 FROM drive_access_request_details d WHERE d.request_id=approval_requests.id),'{}'::jsonb) ELSE payload END)::text"#
    };
}

const ITEM_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::named("consumer_type", Type::TEXT),
    ColumnSpec::named("subject", Type::TEXT),
    ColumnSpec::named("status", Type::TEXT),
    ColumnSpec::named("requester_user_id", Type::INT8),
    ColumnSpec::named("approver_kind", Type::TEXT),
    ColumnSpec::named("approver_ref", Type::INT8),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("decided_by_user_id", Type::INT8),
    ColumnSpec::named("decision_comment", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
];

pub const MY_APPROVALS_PENDING: SqlContract = SqlContract {
    id: "approvals.my_approvals_pending",
    domain: "approvals",
    sql: concat!(
        "SELECT ",
        approval_cols!(),
        " FROM approval_requests WHERE status='pending' AND requester_user_id IS DISTINCT FROM $1 AND (requester_user_id=$1 OR (approver_kind='user' AND approver_ref=$1) OR (approver_kind='role_group' AND EXISTS(SELECT 1 FROM public.admin_role_assignments ara WHERE ara.role_group_id=approval_requests.approver_ref AND ara.user_id=$1 AND (ara.expires_at IS NULL OR ara.expires_at>now()) AND public.admin_assignment_active(ara.eligible,ara.activated_until)))) ORDER BY created_at"
    ),
    params: &[Type::INT8],
    columns: ITEM_COLUMNS,
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareExplainAndRlsDenyProbe,
    audit: SqlAuditPosture::Standard,
};

pub const MY_APPROVALS_MINE: SqlContract = SqlContract {
    id: "approvals.my_approvals_mine",
    domain: "approvals",
    sql: concat!(
        "SELECT ",
        approval_cols!(),
        " FROM approval_requests WHERE requester_user_id=$1 ORDER BY created_at DESC"
    ),
    params: &[Type::INT8],
    columns: ITEM_COLUMNS,
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareExplainAndRlsDenyProbe,
    audit: SqlAuditPosture::Standard,
};

pub const CANCEL_REQUEST: SqlContract = SqlContract {
    id: "approvals.cancel_request",
    domain: "approvals",
    sql: "SELECT approval_request_cancel($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VISIBLE_CONSUMER: SqlContract = SqlContract {
    id: "approvals.visible_consumer",
    domain: "approvals",
    sql: "SELECT consumer_type FROM approval_requests r WHERE r.id=$1 AND (r.requester_user_id=$2 OR (r.approver_kind='user' AND r.approver_ref=$2) OR (r.approver_kind='role_group' AND EXISTS(SELECT 1 FROM public.admin_role_assignments a WHERE a.user_id=$2 AND a.role_group_id=r.approver_ref AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until))) OR EXISTS(SELECT 1 FROM public.admin_role_assignments a JOIN public.admin_role_groups g ON g.id=a.role_group_id WHERE a.user_id=$2 AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until) AND (g.permissions && ARRAY['approvals.view','approvals.manage']::text[])))",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::named("consumer_type", Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareExplainAndRlsDenyProbe,
    audit: SqlAuditPosture::Standard,
};

pub const DECIDE_HR: SqlContract = SqlContract {
    id: "approvals.decide_hr",
    domain: "approvals",
    sql: "SELECT hr_approval_decide($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DECIDE_RBAC: SqlContract = SqlContract {
    id: "approvals.decide_rbac",
    domain: "approvals",
    sql: "SELECT rbac_approval_decide($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DECIDE_DRIVE_EXPORT: SqlContract = SqlContract {
    id: "approvals.decide_drive_export",
    domain: "approvals",
    sql: "SELECT drive_export_approval_decide($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DECIDE_DRIVE_SHARE: SqlContract = SqlContract {
    id: "approvals.decide_drive_share",
    domain: "approvals",
    sql: "SELECT drive_share_approval_decide($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DECIDE_MAIL_EXTERNAL: SqlContract = SqlContract {
    id: "approvals.decide_mail_external",
    domain: "approvals",
    sql: "SELECT mail_external_approval_decide($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DECIDE_GROUP_MODERATION: SqlContract = SqlContract {
    id: "approvals.decide_group_moderation",
    domain: "approvals",
    sql: "SELECT group_moderation_approval_decide($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_AUTHORITY: SqlContract = SqlContract {
    id: "approvals.admin_authority",
    domain: "approvals",
    sql: "SELECT COALESCE(bool_or('approvals.manage'=ANY(g.permissions)),false), COALESCE(bool_or(g.permissions && ARRAY['approvals.view','approvals.manage']::text[]),false), MIN(COALESCE(a.domain_override,g.domain_scope)) FROM public.admin_role_assignments a JOIN public.admin_role_groups g ON g.id=a.role_group_id WHERE a.user_id=$1 AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until)",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICIES_LIST: SqlContract = SqlContract {
    id: "approvals.policies_list",
    domain: "approvals",
    sql: "SELECT id,consumer_type,name,enabled,priority,conditions::text,requires_approval,approver_spec::text,created_at::text,updated_at::text FROM approval_policies WHERE ($1::text='' OR consumer_type=$1) AND EXISTS(SELECT 1 FROM public.admin_role_assignments a JOIN public.admin_role_groups g ON g.id=a.role_group_id WHERE a.user_id=$2 AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until) AND g.permissions && ARRAY['approvals.view','approvals.manage']::text[]) ORDER BY consumer_type,priority",
    params: &[Type::TEXT, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("consumer_type", Type::TEXT),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::named("priority", Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("requires_approval", Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareExplainAndRlsDenyProbe,
    audit: SqlAuditPosture::Standard,
};

pub const CONSOLE_DENIED: SqlContract = SqlContract {
    id: "approvals.console_denied",
    domain: "approvals",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_CREATE: SqlContract = SqlContract {
    id: "approvals.policy_create",
    domain: "approvals",
    sql: "SELECT rust_approval_policy_create($1,$2::text::jsonb)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_POLICY_CREATED: SqlContract = SqlContract {
    id: "approvals.audit_policy_created",
    domain: "approvals",
    sql: "SELECT audit_write($1,'approval_policy_create','approval_policy',$2,NULL,$3::text::jsonb,NULLIF($4,'')::inet,'','core')",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_UPDATE: SqlContract = SqlContract {
    id: "approvals.policy_update",
    domain: "approvals",
    sql: "SELECT rust_approval_policy_update($1,$2,$3::text::jsonb)",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_POLICY_CHANGE: SqlContract = SqlContract {
    id: "approvals.audit_policy_change",
    domain: "approvals",
    sql: "SELECT audit_write($1,$2,'approval_policy',$3,NULL,$4::text::jsonb,NULLIF($5,'')::inet,'','core')",
    params: &[Type::INT8, Type::TEXT, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_DELETE: SqlContract = SqlContract {
    id: "approvals.policy_delete",
    domain: "approvals",
    sql: "SELECT rust_approval_policy_delete($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLICY_REORDER: SqlContract = SqlContract {
    id: "approvals.policy_reorder",
    domain: "approvals",
    sql: "SELECT rust_approval_policy_reorder($1,$2::text::jsonb)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_REQUESTS: SqlContract = SqlContract {
    id: "approvals.audit_requests",
    domain: "approvals",
    sql: "SELECT id,consumer_type,requester_user_id,subject,status,approver_kind,approver_ref,decided_by_user_id,decided_at::text,decision_comment,created_at::text,expires_at::text FROM approval_requests WHERE ($2::bigint<=0 OR domain_id=$2) AND EXISTS(SELECT 1 FROM public.admin_role_assignments a JOIN public.admin_role_groups g ON g.id=a.role_group_id WHERE a.user_id=$1 AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until) AND g.permissions && ARRAY['approvals.view','approvals.manage']::text[]) ORDER BY created_at DESC LIMIT $3 OFFSET $4",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("consumer_type", Type::TEXT),
        ColumnSpec::named("requester_user_id", Type::INT8),
        ColumnSpec::named("subject", Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::named("approver_kind", Type::TEXT),
        ColumnSpec::named("approver_ref", Type::INT8),
        ColumnSpec::named("decided_by_user_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("decision_comment", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareExplainAndRlsDenyProbe,
    audit: SqlAuditPosture::Standard,
};

pub const HR_ENABLED: SqlContract = SqlContract {
    id: "approvals.hr_enabled",
    domain: "approvals",
    sql: "SELECT enabled FROM feature_toggles WHERE key=$1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::named("enabled", Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBMIT_HR: SqlContract = SqlContract {
    id: "approvals.submit_hr",
    domain: "approvals",
    sql: "SELECT hr_request_create($1,$2,$3::text::jsonb)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DECIDE_DRIVE_ACCESS: SqlContract = SqlContract {
    id: "approvals.decide_drive_access",
    domain: "approvals",
    sql: "SELECT (drive_access_approval_decide($1,$2,$3,$4,COALESCE($5::text[],d.requested_capabilities),COALESCE($6,d.requested_propagation),COALESCE($7::text::timestamptz,d.requested_expires_at),COALESCE($8::bigint::integer,d.requested_max_uses),$9))->>'status' FROM drive_access_request_details d WHERE d.request_id=$1 AND EXISTS(SELECT 1 FROM approval_requests r WHERE r.id=d.request_id AND (r.requester_user_id=$2 OR (r.approver_kind='user' AND r.approver_ref=$2) OR (r.approver_kind='role_group' AND EXISTS(SELECT 1 FROM public.admin_role_assignments a WHERE a.user_id=$2 AND a.role_group_id=r.approver_ref AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until))) OR EXISTS(SELECT 1 FROM public.admin_role_assignments a JOIN public.admin_role_groups g ON g.id=a.role_group_id WHERE a.user_id=$2 AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until) AND g.permissions && ARRAY['approvals.view','approvals.manage']::text[])))",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT_ARRAY,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EMAIL_REQUEST: SqlContract = SqlContract {
    id: "approvals.email_request",
    domain: "approvals",
    sql: "SELECT subject,status,consumer_type FROM approval_requests r WHERE id=$1 AND (requester_user_id=$2 OR (approver_kind='user' AND approver_ref=$2) OR (approver_kind='role_group' AND EXISTS(SELECT 1 FROM public.admin_role_assignments a WHERE a.user_id=$2 AND a.role_group_id=r.approver_ref AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until))) OR EXISTS(SELECT 1 FROM public.admin_role_assignments a JOIN public.admin_role_groups g ON g.id=a.role_group_id WHERE a.user_id=$2 AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until) AND g.permissions && ARRAY['approvals.view','approvals.manage']::text[]))",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("subject", Type::TEXT),
        ColumnSpec::named("status", Type::TEXT),
        ColumnSpec::named("consumer_type", Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareExplainAndRlsDenyProbe,
    audit: SqlAuditPosture::Standard,
};

pub const NOTIFY_REQUEST_LOOKUP: SqlContract = SqlContract {
    id: "approvals.notify_request_lookup",
    domain: "approvals",
    sql: "SELECT approver_kind,approver_ref,subject,floor(extract(epoch FROM expires_at))::bigint,to_char(expires_at AT TIME ZONE 'UTC','Dy, DD Mon YYYY HH24:MI:SS')||' UTC' FROM approval_requests WHERE id=$1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("approver_kind", Type::TEXT),
        ColumnSpec::named("approver_ref", Type::INT8),
        ColumnSpec::named("subject", Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const NOTIFY_ROLE_GROUP_USERS: SqlContract = SqlContract {
    id: "approvals.notify_role_group_users",
    domain: "approvals",
    sql: "SELECT user_id FROM admin_role_assignments WHERE role_group_id=$1 AND (expires_at IS NULL OR expires_at>now()) AND admin_assignment_active(eligible,activated_until)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("user_id", Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const NOTIFY_USER_EMAIL: SqlContract = SqlContract {
    id: "approvals.notify_user_email",
    domain: "approvals",
    sql: "SELECT COALESCE(mb.email,u.email) FROM mailboxes mb JOIN users u ON u.id=mb.user_id WHERE mb.user_id=$1 AND mb.is_primary=true LIMIT 1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const NOTIFY_DELIVER: SqlContract = SqlContract {
    id: "approvals.notify_deliver",
    domain: "approvals",
    sql: "SELECT deliver($1,$2,$3,'SetJoin Approvals',$4,$5::text::jsonb,'[]'::jsonb,'[]'::jsonb,$6,'','',$7,$8,$9,FALSE,clock_timestamp(),'none','none','none',0::real,'{}'::jsonb)",
    params: &[
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    MY_APPROVALS_PENDING,
    MY_APPROVALS_MINE,
    CANCEL_REQUEST,
    VISIBLE_CONSUMER,
    DECIDE_HR,
    DECIDE_RBAC,
    DECIDE_DRIVE_EXPORT,
    DECIDE_DRIVE_SHARE,
    DECIDE_MAIL_EXTERNAL,
    DECIDE_GROUP_MODERATION,
    ADMIN_AUTHORITY,
    POLICIES_LIST,
    CONSOLE_DENIED,
    POLICY_CREATE,
    AUDIT_POLICY_CREATED,
    POLICY_UPDATE,
    AUDIT_POLICY_CHANGE,
    POLICY_DELETE,
    POLICY_REORDER,
    AUDIT_REQUESTS,
    HR_ENABLED,
    SUBMIT_HR,
    DECIDE_DRIVE_ACCESS,
    EMAIL_REQUEST,
    NOTIFY_REQUEST_LOOKUP,
    NOTIFY_ROLE_GROUP_USERS,
    NOTIFY_USER_EMAIL,
    NOTIFY_DELIVER,
];
