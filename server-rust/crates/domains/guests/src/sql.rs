//! Static typed SQL contract catalog for `setjoin-guests` (F11).
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};

pub const ENABLED: SqlContract = SqlContract {
    id: "guests.enabled",
    domain: "guests",
    sql: "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
    params: &[],
    columns: &[ColumnSpec::named("enabled", Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const APPROVAL_ENABLED: SqlContract = SqlContract {
    id: "guests.approval_enabled",
    domain: "guests",
    sql: "SELECT enabled FROM feature_toggles WHERE key='approval.guest_invite'",
    params: &[],
    columns: &[ColumnSpec::named("enabled", Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PROFILES_LIST: SqlContract = SqlContract {
    id: "guests.profiles_list",
    domain: "guests",
    sql: "SELECT guest_profile_list($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PROFILE_GET: SqlContract = SqlContract {
    id: "guests.profile_get",
    domain: "guests",
    sql: "SELECT guest_profile_get($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PROFILE_DOMAINS: SqlContract = SqlContract {
    id: "guests.profile_domains",
    domain: "guests",
    sql: "SELECT guest_profile_domain_list($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PROFILE_SAVE: SqlContract = SqlContract {
    id: "guests.profile_save",
    domain: "guests",
    sql: "SELECT rust_guest_profile_save($1,$2,$3::text::jsonb)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const PROFILE_DELETE: SqlContract = SqlContract {
    id: "guests.profile_delete",
    domain: "guests",
    sql: "SELECT guest_profile_delete($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const GUEST_LIST: SqlContract = SqlContract {
    id: "guests.list",
    domain: "guests",
    sql: "SELECT result::text FROM (\n\
SELECT COALESCE(jsonb_agg(jsonb_build_object(\n\
\t\t  'id',g.user_id,'displayName',u.display_name,'invitedEmail',g.invited_email,\n\
\t\t  'status',g.status,'effectiveStatus',CASE WHEN g.expires_at < now() THEN 'expired' ELSE g.status END,\n\
\t\t  'expiresAt',g.expires_at,'sponsorUserId',g.sponsor_user_id,\n\
\t\t  'sponsorDisplayName',s.display_name,\n\
\t\t  'sponsorNeedsReview',(s.id IS NULL OR NOT s.enabled OR is_guest_account(s.id)),\n\
\t\t  'profileId',g.profile_id,'profileName',gp.name,\n\
\t\t  'pendingInvite',EXISTS(SELECT 1 FROM guest_invites gi\n\
\t\t    WHERE gi.guest_user_id=g.user_id AND gi.used_at IS NULL AND gi.expires_at > now()),\n\
\t\t  'channelGrantCount',(SELECT count(*) FROM chat_channel_members cm WHERE cm.user_id=g.user_id),\n\
\t\t  'createdAt',g.created_at,'updatedAt',g.updated_at\n\
\t\t) ORDER BY lower(u.display_name),g.user_id),'[]'::jsonb)\n\
\t\tFROM guest_accounts g JOIN users u ON u.id=g.user_id\n\
\t\tLEFT JOIN users s ON s.id=g.sponsor_user_id\n\
\t\tLEFT JOIN guest_profiles gp ON gp.id=g.profile_id\n\
\t\tWHERE guest_admin_can_reach_with_permission($1,g.user_id,'guests.view')\n\
\t\t   OR guest_admin_can_reach_with_permission($1,g.user_id,'guests.manage')\n\
) AS guests(result)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const GUEST_GET: SqlContract = SqlContract {
    id: "guests.get",
    domain: "guests",
    sql: "SELECT result::text FROM (\n\
SELECT jsonb_build_object(\n\
\t\t  'id',g.user_id,'displayName',u.display_name,'invitedEmail',g.invited_email,\n\
\t\t  'invitedBy',g.invited_by,'invitedByEmail',g.invited_by_email,\n\
\t\t  'status',g.status,'effectiveStatus',CASE WHEN g.expires_at < now() THEN 'expired' ELSE g.status END,\n\
\t\t  'expiresAt',g.expires_at,'sponsorUserId',g.sponsor_user_id,\n\
\t\t  'sponsorDisplayName',s.display_name,\n\
\t\t  'sponsorNeedsReview',(s.id IS NULL OR NOT s.enabled OR is_guest_account(s.id)),\n\
\t\t  'profileId',g.profile_id,'profileName',gp.name,\n\
\t\t  'pendingInvite',(SELECT jsonb_build_object(\n\
\t\t      'inviteId',gi.id::text,'expiresAt',gi.expires_at,'createdAt',gi.created_at,\n\
\t\t      'createdByEmail',CASE WHEN gi.created_by IS NOT NULL\n\
\t\t        AND admin_can_reach($1,gi.created_by) THEN gi.created_by_email ELSE NULL END)\n\
\t\t    FROM guest_invites gi WHERE gi.guest_user_id=g.user_id AND gi.used_at IS NULL\n\
\t\t      AND gi.expires_at > now()\n\
\t\t    ORDER BY gi.created_at DESC LIMIT 1),\n\
\t\t  'inviteHistory',(SELECT COALESCE(jsonb_agg(h.item ORDER BY h.created_at DESC,h.id DESC),'[]'::jsonb)\n\
\t\t    FROM (SELECT gi.id,gi.created_at,jsonb_build_object(\n\
\t\t      'inviteId',gi.id::text,\n\
\t\t      'state',CASE\n\
\t\t        WHEN gi.used_at IS NULL AND gi.expires_at <= now() THEN 'expired'\n\
\t\t        WHEN gi.used_at IS NULL THEN 'pending'\n\
\t\t        WHEN gi.terminal_reason = 'legacy_unknown' THEN 'unknown'\n\
\t\t        ELSE gi.terminal_reason END,\n\
\t\t      'createdAt',gi.created_at,'expiresAt',gi.expires_at,\n\
\t\t      'terminalAt',CASE\n\
\t\t        WHEN gi.used_at IS NULL AND gi.expires_at <= now() THEN gi.expires_at\n\
\t\t        WHEN gi.used_at IS NULL THEN NULL ELSE gi.used_at END,\n\
\t\t      'createdByEmail',CASE WHEN gi.created_by IS NOT NULL\n\
\t\t        AND admin_can_reach($1,gi.created_by) THEN gi.created_by_email ELSE NULL END\n\
\t\t    ) AS item FROM guest_invites gi WHERE gi.guest_user_id=g.user_id\n\
\t\t      ORDER BY gi.created_at DESC,gi.id DESC LIMIT 10) h),\n\
\t\t  'inviteHistoryHasMore',EXISTS(SELECT 1 FROM guest_invites gi\n\
\t\t    WHERE gi.guest_user_id=g.user_id ORDER BY gi.created_at DESC,gi.id DESC OFFSET 10 LIMIT 1),\n\
\t\t  'channelGrantCount',(SELECT count(*) FROM chat_channel_members cm WHERE cm.user_id=g.user_id),\n\
\t\t  'channelGrants',(SELECT COALESCE(jsonb_agg(jsonb_build_object(\n\
\t\t    'channelId',c.id,'kind',c.kind,'name',c.name,'role',cm.role,\n\
\t\t    'canPost',cm.can_post,'historyFloorSeq',cm.history_floor_seq\n\
\t\t  ) ORDER BY c.id),'[]'::jsonb) FROM chat_channel_members cm\n\
\t\t    JOIN chat_channels c ON c.id=cm.channel_id WHERE cm.user_id=g.user_id),\n\
\t\t  'appEntitlements',(SELECT jsonb_object_agg(apps.app,COALESCE(e.enabled,false) ORDER BY apps.app)\n\
\t\t    FROM (VALUES ('mail'),('calendar'),('contacts'),('tasks'),('chat'),('drive'),('meet')) apps(app)\n\
\t\t    LEFT JOIN user_app_entitlements e ON e.user_id=g.user_id AND e.app=apps.app),\n\
\t\t  'createdAt',g.created_at,'updatedAt',g.updated_at\n\
\t\t)\n\
\t\tFROM guest_accounts g JOIN users u ON u.id=g.user_id\n\
\t\tLEFT JOIN users s ON s.id=g.sponsor_user_id\n\
\t\tLEFT JOIN guest_profiles gp ON gp.id=g.profile_id\n\
\t\tWHERE g.user_id=$2\n\
\t\t  AND (guest_admin_can_reach_with_permission($1,g.user_id,'guests.view')\n\
\t\t       OR guest_admin_can_reach_with_permission($1,g.user_id,'guests.manage'))\n\
) AS guests(result)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPONSORS_LIST: SqlContract = SqlContract {
    id: "guests.sponsors_list",
    domain: "guests",
    sql: "SELECT COALESCE(jsonb_agg(jsonb_build_object('id',s.id,'email',s.email,'displayName',s.display_name) ORDER BY lower(s.display_name),s.id),'[]'::jsonb)::text FROM (\n\
SELECT u.id, u.email, u.display_name\n\
\t\t  FROM users u\n\
\t\t WHERE u.enabled\n\
\t\t   AND NOT is_guest_account(u.id)\n\
\t\t   AND guest_admin_can_transfer_to($1,$2,u.id)\n\
\t\t   AND ($3='' OR u.email ILIKE '%'||$3||'%' OR u.display_name ILIKE '%'||$3||'%')\n\
\t\t ORDER BY lower(u.display_name), u.id\n\
\t\t LIMIT 50\n\
) AS s",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SET_STATUS: SqlContract = SqlContract {
    id: "guests.set_status",
    domain: "guests",
    sql: "SELECT rust_guest_status($1,$2,$3,$4::text::timestamptz)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ASSIGN_PROFILE: SqlContract = SqlContract {
    id: "guests.assign_profile",
    domain: "guests",
    sql: "SELECT guest_profile_apply($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TRANSFER: SqlContract = SqlContract {
    id: "guests.transfer",
    domain: "guests",
    sql: "SELECT guest_transfer($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ACTOR_DOMAIN_EMAIL: SqlContract = SqlContract {
    id: "guests.actor_domain_email",
    domain: "guests",
    sql: "SELECT domain_id,email FROM users WHERE id=$1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("domain_id", Type::INT8),
        ColumnSpec::named("email", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SET_DOMAIN: SqlContract = SqlContract {
    id: "guests.set_domain",
    domain: "guests",
    sql: "SELECT guest_invite_domain_set($1,$2,$3,$4,$5)",
    params: &[Type::INT8, Type::TEXT, Type::INT8, Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONSOLE_DENIED: SqlContract = SqlContract {
    id: "guests.console_denied",
    domain: "guests",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REVOKE_INVITE: SqlContract = SqlContract {
    id: "guests.revoke_invite",
    domain: "guests",
    sql: "SELECT rust_guest_invite_revoke($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const SUBMIT_INVITE_REQUEST: SqlContract = SqlContract {
    id: "guests.submit_invite_request",
    domain: "guests",
    sql: "SELECT guest_invite_request_create($1,$2,$3)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const INVITE_CREATE: SqlContract = SqlContract {
    id: "guests.invite_create",
    domain: "guests",
    sql: "SELECT rust_guest_invite($1,$2,$3,$4::text::timestamptz,$5,$6)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const INVITE_REINVITE: SqlContract = SqlContract {
    id: "guests.invite_reinvite",
    domain: "guests",
    sql: "SELECT rust_guest_reinvite($1,$2,$3::text::timestamptz,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const INVITE_APPROVAL_DECIDE: SqlContract = SqlContract {
    id: "guests.invite_approval_decide",
    domain: "guests",
    sql: "SELECT rust_guest_approval_decide($1,$2,$3,$4,$5)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ENQUEUE_OUTBOUND: SqlContract = SqlContract {
    id: "guests.enqueue_outbound",
    domain: "guests",
    sql: "INSERT INTO outbound_queue(message_id,from_addr,rcpt_addrs,raw_ref,status) VALUES($1,$2,ARRAY[$3],$4,'pending') RETURNING id",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    ENABLED,
    APPROVAL_ENABLED,
    PROFILES_LIST,
    PROFILE_GET,
    PROFILE_DOMAINS,
    PROFILE_SAVE,
    PROFILE_DELETE,
    GUEST_LIST,
    GUEST_GET,
    SPONSORS_LIST,
    SET_STATUS,
    ASSIGN_PROFILE,
    TRANSFER,
    ACTOR_DOMAIN_EMAIL,
    SET_DOMAIN,
    CONSOLE_DENIED,
    REVOKE_INVITE,
    SUBMIT_INVITE_REQUEST,
    INVITE_CREATE,
    INVITE_REINVITE,
    INVITE_APPROVAL_DECIDE,
    ENQUEUE_OUTBOUND,
];
