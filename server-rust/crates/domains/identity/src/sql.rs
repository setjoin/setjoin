//! Typed SQL contract catalog for `setjoin-identity` (#546d).
//! Verified against live PostgreSQL 17 by `verify-sql-contracts`.
#![forbid(unsafe_code)]

use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};

pub const BOOTSTRAP_L64: SqlContract = SqlContract {
    id: "identity.bootstrap_l64",
    domain: "identity",
    sql: "SELECT * FROM rust_identity_device_register($1,$2,$3,$4,$5,$6,$7)",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BYTEA,
    ],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::BOOL),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DEVICE_TRUST_L117: SqlContract = SqlContract {
    id: "identity.device_trust_l117",
    domain: "identity",
    sql: "SELECT rust_device_checkin($1,$2::text::jsonb)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DEVICE_TRUST_L85: SqlContract = SqlContract {
    id: "identity.device_trust_l85",
    domain: "identity",
    sql: "SELECT mdm_effective_policy($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const GUEST_INVITE_L105: SqlContract = SqlContract {
    id: "identity.guest_invite_l105",
    domain: "identity",
    sql: "SELECT COALESCE((SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname=current_user),false), to_regprocedure('rust_guest_invite_disclosure(bigint,text)') IS NOT NULL AND to_regprocedure('rust_guest_invite_accept_read(bigint,text,text,boolean,boolean,bytea)') IS NOT NULL AND to_regprocedure('rust_guest_invite_accept_finish(bigint,bigint,text,text,inet)') IS NOT NULL",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const GUEST_INVITE_L147: SqlContract = SqlContract {
    id: "identity.guest_invite_l147",
    domain: "identity",
    sql: "SELECT rust_guest_invite_disclosure($1,$2)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const GUEST_INVITE_L209: SqlContract = SqlContract {
    id: "identity.guest_invite_l209",
    domain: "identity",
    sql: "SELECT rust_guest_invite_accept_read($1,$2,$3,$4,$5,$6)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
        Type::BOOL,
        Type::BYTEA,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const GUEST_INVITE_L237: SqlContract = SqlContract {
    id: "identity.guest_invite_l237",
    domain: "identity",
    sql: "SELECT rust_guest_invite_accept_finish($1,$2,$3,$4,$5::text::inet)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ECHO_TEXT: SqlContract = SqlContract {
    id: "identity.echo_text",
    domain: "identity",
    sql: "SELECT $1::text",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const GUEST_INVITE_L94: SqlContract = SqlContract {
    id: "identity.guest_invite_l94",
    domain: "identity",
    sql: "SELECT guest_user_id FROM guest_invites WHERE token_hash=$1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDENTITY_LINKS_L48: SqlContract = SqlContract {
    id: "identity.identity_links_l48",
    domain: "identity",
    sql: "SELECT rust_identity_unlink($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IDENTITY_LINKS_L69: SqlContract = SqlContract {
    id: "identity.identity_links_l69",
    domain: "identity",
    sql: "SELECT l.id::text,s.kind,s.display_name,l.state,to_char(l.last_seen_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US') FROM user_identity_links l JOIN identity_sources s ON s.id=l.source_id WHERE l.user_id=$1 AND 'authenticate'=ANY(l.purposes) ORDER BY s.kind,s.display_name,l.id LIMIT 8",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IMPERSONATION_L109: SqlContract = SqlContract {
    id: "identity.impersonation_l109",
    domain: "identity",
    sql: "SELECT email,EXISTS(SELECT 1 FROM admin_role_assignments ra WHERE ra.user_id=users.id AND (ra.expires_at IS NULL OR ra.expires_at>now())),EXISTS(SELECT 1 FROM admin_role_assignments ra WHERE ra.user_id=users.id AND ra.role_group_id=1 AND (ra.expires_at IS NULL OR ra.expires_at>now())),domain_id FROM users WHERE id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IS_GUEST_ACCOUNT: SqlContract = SqlContract {
    id: "identity.is_guest_account",
    domain: "identity",
    sql: "SELECT is_guest_account($1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IMPERSONATION_AUDIT_LOG_INSERT: SqlContract = SqlContract {
    id: "identity.impersonation_audit_log_insert",
    domain: "identity",
    sql: "SELECT rust_compliance_audit_log_insert($1,$2,$3,$4)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IMPERSONATION_L73: SqlContract = SqlContract {
    id: "identity.impersonation_l73",
    domain: "identity",
    sql: "SELECT count(*), COALESCE(bool_or(COALESCE(ra.domain_override,rg.domain_scope) IS NULL),false), COALESCE(array_agg(DISTINCT COALESCE(ra.domain_override,rg.domain_scope)) FILTER (WHERE COALESCE(ra.domain_override,rg.domain_scope) IS NOT NULL),'{}'::bigint[]) FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$1 AND 'users.impersonate'=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::INT8_ARRAY)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IMPERSONATION_L98: SqlContract = SqlContract {
    id: "identity.impersonation_l98",
    domain: "identity",
    sql: "SELECT enabled,EXISTS(SELECT 1 FROM admin_role_assignments ra WHERE ra.user_id=users.id AND (ra.expires_at IS NULL OR ra.expires_at>now())),EXISTS(SELECT 1 FROM admin_role_assignments ra WHERE ra.user_id=users.id AND ra.role_group_id=1 AND (ra.expires_at IS NULL OR ra.expires_at>now())) FROM users WHERE id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ISSUANCE_L147: SqlContract = SqlContract {
    id: "identity.issuance_l147",
    domain: "identity",
    sql: "SELECT secret FROM oidc_clients WHERE id=$1 AND enabled=true",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ISSUANCE_L178: SqlContract = SqlContract {
    id: "identity.issuance_l178",
    domain: "identity",
    sql: "SELECT o.user_id,u.email,o.client_id,COALESCE(o.scope,'{}'),extract(epoch FROM o.issued_at)::bigint,extract(epoch FROM o.expires_at)::bigint FROM oauth_tokens o JOIN users u ON u.id=o.user_id AND u.enabled=true WHERE o.token_hash=$1 AND o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at>now())",
    params: &[Type::BYTEA],
    columns: &[ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT_ARRAY), ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ISSUANCE_L243: SqlContract = SqlContract {
    id: "identity.issuance_l243",
    domain: "identity",
    sql: "SELECT user_id FROM oauth_tokens WHERE token_hash=$1 AND revoked_at IS NULL AND (client_id=$2 OR client_id IS NULL)",
    params: &[Type::BYTEA, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ISSUANCE_L258: SqlContract = SqlContract {
    id: "identity.issuance_l258",
    domain: "identity",
    sql: "UPDATE oauth_tokens SET revoked_at=now() WHERE user_id=$1 AND token_hash=$2 AND revoked_at IS NULL AND (client_id=$3 OR client_id IS NULL)",
    params: &[Type::INT8, Type::BYTEA, Type::TEXT],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ISSUANCE_L296: SqlContract = SqlContract {
    id: "identity.issuance_l296",
    domain: "identity",
    sql: "SELECT t.id,t.name,t.version,t.body_md,t.require_scroll FROM terms_of_use t LEFT JOIN terms_of_use_acceptance a ON a.tou_id=t.id AND a.user_id=$1 AND a.version=t.version WHERE t.enabled AND a.user_id IS NULL ORDER BY t.id",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::INT4), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ISSUANCE_L333: SqlContract = SqlContract {
    id: "identity.issuance_l333",
    domain: "identity",
    sql: "SELECT record_tou_acceptance($1,$2,$3::int4,$4::text::inet)",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ISSUANCE_L364: SqlContract = SqlContract {
    id: "identity.issuance_l364",
    domain: "identity",
    sql: "SELECT id FROM users WHERE scim_external_id=$1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ISSUANCE_L388: SqlContract = SqlContract {
    id: "identity.issuance_l388",
    domain: "identity",
    sql: "SELECT revoke_user_sessions($1,'all','token_revoke_all',NULL,NULL,NULL)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ISSUANCE_L414: SqlContract = SqlContract {
    id: "identity.issuance_l414",
    domain: "identity",
    sql: "INSERT INTO push_devices(user_id,push_provider,push_token_enc,device_public_key,device_name) VALUES($1,'webpush',pgp_sym_encrypt($2::text,current_setting('app.encryption_key'))::bytea,NULL,$3) ON CONFLICT DO NOTHING",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ISSUANCE_CLIENT_VERSION_LATEST: SqlContract = SqlContract {
    id: "identity.issuance_client_version_latest",
    domain: "identity",
    sql: "SELECT version,sha256,release_notes,file_path,release_date FROM rust_identity_client_version_latest($1,$2)",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TIMESTAMPTZ)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LIB_L8: SqlContract = SqlContract {
    id: "identity.lib_l8",
    domain: "identity",
    sql: "SELECT COALESCE((SELECT (value->>0)::INT FROM system_config WHERE key='password_min_length'),8), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_uppercase'),true), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_lowercase'),true), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_digit'),true), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_special'),true)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT4), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L112: SqlContract = SqlContract {
    id: "identity.login_l112",
    domain: "identity",
    sql: "SELECT rust_identity_mfa_bootstrap_grant($1,$2,$3,$4)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L137: SqlContract = SqlContract {
    id: "identity.login_l137",
    domain: "identity",
    sql: "SELECT identity_transition_admission_allowed($1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L164: SqlContract = SqlContract {
    id: "identity.login_l164",
    domain: "identity",
    sql: "SELECT MIN(COALESCE(ra.domain_override,rg.domain_scope)) FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$1 AND COALESCE(ra.domain_override,rg.domain_scope) IS NOT NULL AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L186: SqlContract = SqlContract {
    id: "identity.login_l186",
    domain: "identity",
    sql: "SELECT rust_identity_login_mint($1,$2,$3,$4,$5::text::uuid)",
    params: &[Type::INT8, Type::TEXT, Type::BYTEA, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L215: SqlContract = SqlContract {
    id: "identity.login_l215",
    domain: "identity",
    sql: "SELECT EXISTS(SELECT 1 FROM oauth_tokens o JOIN users u ON u.id=o.user_id WHERE o.user_id=$1 AND o.family_id=$2::text::uuid AND u.enabled AND u.password_hash=$3 AND o.revoked_at IS NULL AND o.expires_at>now())",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L234: SqlContract = SqlContract {
    id: "identity.login_l234",
    domain: "identity",
    sql: "INSERT INTO auth_event_log(user_id,event,provider,email,ip_address) VALUES($1,'login','jwt',NULLIF($2,''),NULLIF($3,'')::inet)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L237: SqlContract = SqlContract {
    id: "identity.login_l237",
    domain: "identity",
    sql: "SELECT rust_identity_signin_record($1,true,$2)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L242: SqlContract = SqlContract {
    id: "identity.login_l242",
    domain: "identity",
    sql: "INSERT INTO sessions(id,user_id,token_hash,expires_at,ip,user_agent,auth_method) VALUES($1,$2,$3,now()+make_interval(secs=>$4),NULLIF($5,'')::inet,$6,'password') ON CONFLICT(id) DO NOTHING",
    params: &[Type::TEXT, Type::INT8, Type::BYTEA, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L247: SqlContract = SqlContract {
    id: "identity.login_l247",
    domain: "identity",
    sql: "SELECT id FROM users WHERE lower(email)=lower($1) AND enabled=true",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L258: SqlContract = SqlContract {
    id: "identity.login_l258",
    domain: "identity",
    sql: "INSERT INTO auth_event_log(user_id,event,provider,email,ip_address,details) VALUES(NULL,'login_failed','bcrypt',NULLIF($1,''),NULLIF($2,'')::inet,$3::text::jsonb)",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L261: SqlContract = SqlContract {
    id: "identity.login_l261",
    domain: "identity",
    sql: "SELECT rust_identity_signin_record($1,false,$2)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L270: SqlContract = SqlContract {
    id: "identity.login_l270",
    domain: "identity",
    sql: "SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key=$1),false)",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L344: SqlContract = SqlContract {
    id: "identity.login_l344",
    domain: "identity",
    sql: "SELECT score::int4,level,signals::text FROM user_risk WHERE user_id=$1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::INT4),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L56: SqlContract = SqlContract {
    id: "identity.login_l56",
    domain: "identity",
    sql: "SELECT id,email,password_hash,EXISTS(SELECT 1 FROM admin_role_assignments ara WHERE ara.user_id=users.id AND (ara.expires_at IS NULL OR ara.expires_at>now())), COALESCE(totp_enabled,false),COALESCE(push_mfa_enabled,false),COALESCE(must_change_password,false) FROM users WHERE lower(email)=lower($1) AND enabled=true",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_L96: SqlContract = SqlContract {
    id: "identity.login_l96",
    domain: "identity",
    sql: "SELECT mfa_status($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_L104: SqlContract = SqlContract {
    id: "identity.oidc_l104",
    domain: "identity",
    sql: "INSERT INTO oidc_auth_requests(id,client_id,redirect_uri,state,nonce,code_challenge,code_challenge_method,scopes,user_id,expires_at,done,auth_time,acr,amr) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULL,$9,false,NULL,NULL,'{}')",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT_ARRAY, Type::TIMESTAMPTZ],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_L139: SqlContract = SqlContract {
    id: "identity.oidc_l139",
    domain: "identity",
    sql: "UPDATE oidc_auth_requests SET user_id=$2,done=true,auth_time=$3,acr=$4,amr=$5 WHERE id=$1 AND expires_at>now() AND done=false AND user_id IS NULL AND $2::bigint=current_setting('app.current_user_id')::bigint RETURNING id",
    params: &[Type::TEXT, Type::INT8, Type::TIMESTAMPTZ, Type::TEXT, Type::TEXT_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_L68: SqlContract = SqlContract {
    id: "identity.oidc_l68",
    domain: "identity",
    sql: "SELECT id,redirect_uris,scopes,grant_types,client_type,enabled FROM oidc_clients WHERE id=$1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT_ARRAY), ColumnSpec::unnamed(Type::TEXT_ARRAY), ColumnSpec::unnamed(Type::TEXT_ARRAY), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_CONSUMERS_L177: SqlContract = SqlContract {
    id: "identity.oidc_consumers_l177",
    domain: "identity",
    sql: "SELECT user_id FROM oidc_tokens WHERE (refresh_token_hash=$1 OR id=$2) AND client_id=$3 AND revoked_at IS NULL",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_CONSUMERS_L179: SqlContract = SqlContract {
    id: "identity.oidc_consumers_l179",
    domain: "identity",
    sql: "SELECT user_id FROM rust_identity_oidc_revoke_target($1,$2,$3)",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_CONSUMERS_L186: SqlContract = SqlContract {
    id: "identity.oidc_consumers_l186",
    domain: "identity",
    sql: "UPDATE oidc_tokens SET revoked_at=now() WHERE (refresh_token_hash=$1 OR id=$2) AND client_id=$3 AND user_id=$4 AND revoked_at IS NULL",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT, Type::INT8],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_CONSUMERS_L197: SqlContract = SqlContract {
    id: "identity.oidc_consumers_l197",
    domain: "identity",
    sql: "UPDATE oidc_tokens SET revoked_at=now() WHERE false",
    params: &[],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_CONSUMERS_L258: SqlContract = SqlContract {
    id: "identity.oidc_consumers_l258",
    domain: "identity",
    sql: "UPDATE oidc_tokens SET revoked_at=now() WHERE user_id=$1 AND client_id=$2 AND revoked_at IS NULL",
    params: &[Type::INT8, Type::TEXT],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_CONSUMERS_L49: SqlContract = SqlContract {
    id: "identity.oidc_consumers_l49",
    domain: "identity",
    sql: "SELECT user_id FROM oidc_tokens WHERE id=$1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_CONSUMERS_L51: SqlContract = SqlContract {
    id: "identity.oidc_consumers_l51",
    domain: "identity",
    sql: "SELECT user_id FROM rust_identity_oidc_token_owner($1)",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_CONSUMERS_L64: SqlContract = SqlContract {
    id: "identity.oidc_consumers_l64",
    domain: "identity",
    sql: "SELECT scopes,client_id FROM oidc_tokens WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()",
    params: &[Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT_ARRAY), ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_CONSUMERS_L66: SqlContract = SqlContract {
    id: "identity.oidc_consumers_l66",
    domain: "identity",
    sql:
        "SELECT scopes,client_id FROM oidc_tokens WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL",
    params: &[Type::TEXT, Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT_ARRAY),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_CONSUMERS_L96: SqlContract = SqlContract {
    id: "identity.oidc_consumers_l96",
    domain: "identity",
    sql: "SELECT email,COALESCE(NULLIF(display_name,''),email) FROM users WHERE id=$1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_GRANTS_L145: SqlContract = SqlContract {
    id: "identity.oidc_grants_l145",
    domain: "identity",
    sql: "SELECT user_id,client_id FROM oidc_auth_requests WHERE code_hash=$1 AND expires_at>now() AND done=true",
    params: &[Type::BYTEA],
    columns: &[ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_GRANTS_L159: SqlContract = SqlContract {
    id: "identity.oidc_grants_l159",
    domain: "identity",
    sql: "SELECT * FROM rust_identity_oidc_consume($1,$2,$3)",
    params: &[Type::INT8, Type::BYTEA, Type::TEXT],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT_ARRAY),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::TIMESTAMPTZ),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT_ARRAY),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_GRANTS_L301: SqlContract = SqlContract {
    id: "identity.oidc_grants_l301",
    domain: "identity",
    sql: "INSERT INTO oidc_tokens(id,client_id,user_id,subject,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING id",
    params: &[Type::TEXT, Type::TEXT, Type::INT8, Type::TEXT, Type::TEXT_ARRAY, Type::TIMESTAMPTZ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_GRANTS_L314: SqlContract = SqlContract {
    id: "identity.oidc_grants_l314",
    domain: "identity",
    sql: "UPDATE oidc_tokens SET refresh_token_hash=$3,refresh_expires_at=$4,refresh_family=$1,refresh_family_expires_at=$5 WHERE id=$1 AND user_id=$2",
    params: &[Type::TEXT, Type::INT8, Type::TEXT, Type::TIMESTAMPTZ, Type::TIMESTAMPTZ],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_GRANTS_L430: SqlContract = SqlContract {
    id: "identity.oidc_grants_l430",
    domain: "identity",
    sql: "SELECT id,client_id,user_id,scopes,revoked_at IS NOT NULL,refresh_expires_at>now() AND COALESCE(refresh_family_expires_at,created_at+interval '90 days')>now() FROM oidc_tokens WHERE refresh_token_hash=$1 LIMIT 1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::TEXT_ARRAY), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_GRANTS_L432: SqlContract = SqlContract {
    id: "identity.oidc_grants_l432",
    domain: "identity",
    sql: "SELECT id,client_id,user_id,scopes,spent,live FROM rust_identity_oidc_refresh_anchor($1)",
    params: &[Type::TEXT],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::TEXT_ARRAY),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::BOOL),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_GRANTS_L458: SqlContract = SqlContract {
    id: "identity.oidc_grants_l458",
    domain: "identity",
    sql: "SELECT revoked FROM rust_identity_oidc_reuse($1,$2,$3)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_GRANTS_L505: SqlContract = SqlContract {
    id: "identity.oidc_grants_l505",
    domain: "identity",
    sql: "SELECT expires_at FROM rust_identity_oidc_rotate($1,$2,$3,$4,$5,$6)",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT_ARRAY,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TIMESTAMPTZ)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_OPERATION_LOOKUP: SqlContract = SqlContract {
    id: "identity.user_operation_lookup",
    domain: "identity",
    sql: "SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=substr(encode(digest($2::text || ':' || $1::text,'sha256'),'hex'),1,32)::uuid AND family='F21' AND command=$3) WHERE EXISTS(SELECT 1 FROM users u WHERE u.id=$1 AND u.enabled AND identity_transition_admission_allowed(u.id) AND (COALESCE($4::text::jsonb->>'credential_fence','')='' OR rtrim(translate(encode(digest(u.password_hash,'sha256'),'base64'),'+/','-_'),'=')=$4::text::jsonb->>'credential_fence')) AND NOT EXISTS(SELECT 1 FROM session_revocations WHERE user_id=$1 AND (expires_at IS NULL OR expires_at>now()) AND ((scope='jti' AND jti=COALESCE($4::text::jsonb->>'jti','')) OR (scope='family' AND family_id=COALESCE($4::text::jsonb->>'fam','')) OR (scope='all' AND to_timestamp(COALESCE(($4::text::jsonb->>'iat')::double precision,0))<=not_before)))",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_REQUESTS_L72: SqlContract = SqlContract {
    id: "identity.oidc_requests_l72",
    domain: "identity",
    sql: "SELECT id,client_id,redirect_uri,state,nonce,code_challenge,scopes,user_id,done,COALESCE(auth_time,created_at),COALESCE(acr,''),amr FROM oidc_auth_requests WHERE id=$1 AND expires_at>now()",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT_ARRAY), ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::TIMESTAMPTZ), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT_ARRAY)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OIDC_REQUESTS_L88: SqlContract = SqlContract {
    id: "identity.oidc_requests_l88",
    domain: "identity",
    sql: "UPDATE oidc_auth_requests SET code_hash=$3 WHERE id=$1 AND user_id=$2 AND expires_at>now() AND done=true AND code_hash IS NULL RETURNING id",
    params: &[Type::TEXT, Type::INT8, Type::BYTEA],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PASSWORD_L127: SqlContract = SqlContract {
    id: "identity.password_l127",
    domain: "identity",
    sql: "SELECT EXISTS(SELECT 1 FROM common_passwords WHERE password_hash=$1)",
    params: &[Type::BYTEA],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PASSWORD_L157: SqlContract = SqlContract {
    id: "identity.password_l157",
    domain: "identity",
    sql: "SELECT COALESCE((SELECT (value->>0)::INT FROM system_config WHERE key='password_history_depth'),5)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PASSWORD_L168: SqlContract = SqlContract {
    id: "identity.password_l168",
    domain: "identity",
    sql: "SELECT identity_auth_local_mint_fence($1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PASSWORD_L182: SqlContract = SqlContract {
    id: "identity.password_l182",
    domain: "identity",
    sql: "SELECT password_hash FROM users WHERE email=$2 AND $1>0",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PASSWORD_L184: SqlContract = SqlContract {
    id: "identity.password_l184",
    domain: "identity",
    sql: "SELECT password_hash FROM users WHERE id=$1 AND $2::text IS NOT NULL",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PASSWORD_L205: SqlContract = SqlContract {
    id: "identity.password_l205",
    domain: "identity",
    sql: "SELECT password_hash FROM password_history WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2",
    params: &[Type::INT8, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PASSWORD_L251: SqlContract = SqlContract {
    id: "identity.password_l251",
    domain: "identity",
    sql: "INSERT INTO used_password_reset_tokens(token_hash) VALUES($1) ON CONFLICT DO NOTHING RETURNING true",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PASSWORD_L254: SqlContract = SqlContract {
    id: "identity.password_l254",
    domain: "identity",
    sql: "SELECT EXISTS(SELECT 1 FROM admin_role_assignments ara WHERE ara.user_id=users.id AND (ara.expires_at IS NULL OR ara.expires_at>now())) FROM users WHERE id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PASSWORD_L34: SqlContract = SqlContract {
    id: "identity.password_l34",
    domain: "identity",
    sql: "SELECT validate_password($1,$2)::text",
    params: &[Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PASSWORD_L68: SqlContract = SqlContract {
    id: "identity.password_l68",
    domain: "identity",
    sql: "SELECT rust_identity_password_write($1,$2,$3,$4::text::jsonb,$5,$6,$7)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT4,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POSSESSION_L134: SqlContract = SqlContract {
    id: "identity.possession_l134",
    domain: "identity",
    sql: "SELECT rust_identity_possession_webauthn_read($1,$2::text::jsonb,$3)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POSSESSION_L139: SqlContract = SqlContract {
    id: "identity.possession_l139",
    domain: "identity",
    sql: "SELECT rust_identity_possession_webauthn_finish($1,$2::text::jsonb,$3,$4,$5,$6)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BYTEA,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POSSESSION_L41: SqlContract = SqlContract {
    id: "identity.possession_l41",
    domain: "identity",
    sql: "SELECT rust_identity_possession_webauthn_begin($1,$2::text::jsonb,$3,$4,$5)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POSSESSION_L87: SqlContract = SqlContract {
    id: "identity.possession_l87",
    domain: "identity",
    sql: "SELECT challenge_hash,operation,target_ref FROM webauthn_ceremonies WHERE user_id=$1 AND kind='management_assertion' AND token_scope=$2 AND session_jti=$3 AND expires_at>now() ORDER BY created_at DESC LIMIT 1",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L123: SqlContract = SqlContract {
    id: "identity.push_l123",
    domain: "identity",
    sql: "SELECT rust_identity_possession_totp_read($1,$2::text::jsonb)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L140: SqlContract = SqlContract {
    id: "identity.push_l140",
    domain: "identity",
    sql: "SELECT rust_identity_possession_totp_issue($1,$2::text::jsonb,$3,$4,$5,$6,$7,$8)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
        Type::INT8,
        Type::BYTEA,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L191: SqlContract = SqlContract {
    id: "identity.push_l191",
    domain: "identity",
    sql: "SELECT rust_identity_possession_consume($1,$2::text::jsonb,$3,'recovery.regenerate',false,NULL)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L204: SqlContract = SqlContract {
    id: "identity.push_l204",
    domain: "identity",
    sql: "SELECT rust_identity_backup_generate($1,$2,$3)::text",
    params: &[Type::INT8, Type::TEXT_ARRAY, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L231: SqlContract = SqlContract {
    id: "identity.push_l231",
    domain: "identity",
    sql: "SELECT totp_backup_codes_enc FROM users WHERE id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT_ARRAY)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L276: SqlContract = SqlContract {
    id: "identity.push_l276",
    domain: "identity",
    sql: "UPDATE users SET totp_backup_codes_enc=array_remove(totp_backup_codes_enc,$2) WHERE id=$1 AND $2=ANY(totp_backup_codes_enc) RETURNING id",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L320: SqlContract = SqlContract {
    id: "identity.push_l320",
    domain: "identity",
    sql: "SELECT rust_identity_native_register($1,$2::text::jsonb,$3,$4,$5,$6,$7,$8)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BYTEA,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_AUDIT_WRITE_USER: SqlContract = SqlContract {
    id: "identity.admin_audit_write_user",
    domain: "identity",
    sql: "SELECT audit_write($1,$3,'user',$1,NULL,NULL,NULLIF($2,'')::inet,NULLIF($4,''),'core')",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L365: SqlContract = SqlContract {
    id: "identity.push_l365",
    domain: "identity",
    sql: "SELECT approved_at IS NOT NULL FROM push_mfa_challenges WHERE nonce=decode($1,'hex') AND user_id=$2 ORDER BY created_at DESC LIMIT 1",
    params: &[Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L389: SqlContract = SqlContract {
    id: "identity.push_l389",
    domain: "identity",
    sql: "UPDATE push_mfa_challenges SET session_id=NULL WHERE nonce=decode($1,'hex') AND user_id=$2 AND session_id=$3 AND approved_at IS NOT NULL AND expires_at>now() RETURNING true",
    params: &[Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L508: SqlContract = SqlContract {
    id: "identity.push_l508",
    domain: "identity",
    sql: "SELECT c.user_id FROM push_mfa_challenges c JOIN push_devices d ON d.user_id=c.user_id AND d.id=$2 WHERE c.nonce=$1 AND c.verified_at IS NULL AND c.expires_at>now() AND d.revoked_at IS NULL AND d.device_public_key IS NOT NULL ORDER BY c.created_at DESC LIMIT 1",
    params: &[Type::BYTEA, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L525: SqlContract = SqlContract {
    id: "identity.push_l525",
    domain: "identity",
    sql: "SELECT rust_identity_push_approval_read($1,$2,$3)::text",
    params: &[Type::INT8, Type::BYTEA, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L544: SqlContract = SqlContract {
    id: "identity.push_l544",
    domain: "identity",
    sql: "SELECT rust_identity_push_approval_finish($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L60: SqlContract = SqlContract {
    id: "identity.push_l60",
    domain: "identity",
    sql: "SELECT rust_identity_possession_read($1,$2::text::jsonb)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L628: SqlContract = SqlContract {
    id: "identity.push_l628",
    domain: "identity",
    sql: "SELECT count(*) FROM push_mfa_challenges WHERE user_id=$1 AND created_at>now()-interval '5 minutes'",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L666: SqlContract = SqlContract {
    id: "identity.push_l666",
    domain: "identity",
    sql: "INSERT INTO push_mfa_challenges(user_id,challenge_code,nonce,session_id,expires_at) VALUES($1,$2,$3,$4,to_timestamp($5))",
    params: &[Type::INT8, Type::TEXT, Type::BYTEA, Type::TEXT, Type::FLOAT8],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_L73: SqlContract = SqlContract {
    id: "identity.push_l73",
    domain: "identity",
    sql: "SELECT rust_identity_possession_issue($1,$2::text::jsonb,$3,$4,$5,$6)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_DELIVERY_L66: SqlContract = SqlContract {
    id: "identity.push_delivery_l66",
    domain: "identity",
    sql: "SELECT id,push_provider,push_token_enc,device_public_key FROM push_devices WHERE user_id=$1 AND push_provider IN ('apns','fcm','hms') AND revoked_at IS NULL AND device_public_key IS NOT NULL",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::BYTEA), ColumnSpec::unnamed(Type::BYTEA)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUSH_DELIVERY_L80: SqlContract = SqlContract {
    id: "identity.push_delivery_l80",
    domain: "identity",
    sql: "SELECT pgp_sym_decrypt($1::bytea,current_setting('app.encryption_key'))::text",
    params: &[Type::BYTEA],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RECOVERY_L14: SqlContract = SqlContract {
    id: "identity.recovery_l14",
    domain: "identity",
    sql: "SELECT u.id,u.email,COALESCE(u.totp_enabled,FALSE),COALESCE(u.push_mfa_enabled,FALSE),EXISTS(SELECT 1 FROM passkey_credentials pc WHERE pc.user_id=u.id AND pc.revoked_at IS NULL),COALESCE(array_length(u.totp_backup_codes_enc,1),0)>0 FROM users u WHERE lower(u.email)=lower($1) AND u.enabled=TRUE",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RECOVERY_L165: SqlContract = SqlContract {
    id: "identity.recovery_l165",
    domain: "identity",
    sql: "SELECT rust_identity_recovery_push_read($1,$2)::text",
    params: &[Type::INT8, Type::BYTEA],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RECOVERY_L191: SqlContract = SqlContract {
    id: "identity.recovery_l191",
    domain: "identity",
    sql: "SELECT rust_identity_recovery_push_finish($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RECOVERY_L65: SqlContract = SqlContract {
    id: "identity.recovery_l65",
    domain: "identity",
    sql: "SELECT rust_identity_recovery_budget($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_L327: SqlContract = SqlContract {
    id: "identity.rp_l327",
    domain: "identity",
    sql: "SELECT key,value::text,encrypted FROM system_config WHERE key LIKE 'oidc_provider_%_config' ORDER BY key",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_ACCOUNT_L164: SqlContract = SqlContract {
    id: "identity.rp_account_l164",
    domain: "identity",
    sql: "SELECT identity_auth_resolve($3,$1,$2)::text",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_ACCOUNT_L194: SqlContract = SqlContract {
    id: "identity.rp_account_l194",
    domain: "identity",
    sql: "SELECT id FROM users WHERE saml_name_id=$1 AND saml_idp_entity_id=$2 AND enabled",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_ACCOUNT_L196: SqlContract = SqlContract {
    id: "identity.rp_account_l196",
    domain: "identity",
    sql: "SELECT id FROM users WHERE oidc_subject=$1 AND oidc_issuer=$2 AND enabled",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_ACCOUNT_L218: SqlContract = SqlContract {
    id: "identity.rp_account_l218",
    domain: "identity",
    sql: "SELECT u.id FROM users u WHERE u.enabled AND (lower(u.email)=lower($1) OR lower(u.ad_upn)=lower($1) OR EXISTS(SELECT 1 FROM aliases a JOIN mailboxes mb ON mb.id=a.mailbox_id WHERE mb.user_id=u.id AND lower(a.email)=lower($1))) AND identity_address_claim_count(lower($1))=1 AND NOT identity_address_quarantined(lower($1)) LIMIT 1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_ACCOUNT_L240: SqlContract = SqlContract {
    id: "identity.rp_account_l240",
    domain: "identity",
    sql: "SELECT identity_auth_shadow_observe($9,$1,$2,$3,$4,$5,$6,$7,$8)",
    params: &[
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::JSONB)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_ACCOUNT_L277: SqlContract = SqlContract {
    id: "identity.rp_account_l277",
    domain: "identity",
    sql: "SELECT email,EXISTS(SELECT 1 FROM admin_role_assignments ara WHERE ara.user_id=u.id AND (ara.expires_at IS NULL OR ara.expires_at>now())) FROM users u WHERE u.id=$1 AND u.enabled",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_ACCOUNT_L327: SqlContract = SqlContract {
    id: "identity.rp_account_l327",
    domain: "identity",
    sql: "SELECT identity_source_provider_bind($3,$1,$2)",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::JSONB)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_ACCOUNT_L352: SqlContract = SqlContract {
    id: "identity.rp_account_l352",
    domain: "identity",
    sql: "SELECT rust_identity_rp_settle($1,$2,$3,$4::text::jsonb,$5::text::jsonb,$6,$7)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_ACCOUNT_L449: SqlContract = SqlContract {
    id: "identity.rp_account_l449",
    domain: "identity",
    sql: "SELECT rust_identity_rp_mint($1,$2::text::jsonb,$3,$4,$5::text::uuid)::text",
    params: &[Type::INT8, Type::TEXT, Type::BYTEA, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_ACCOUNT_L484: SqlContract = SqlContract {
    id: "identity.rp_account_l484",
    domain: "identity",
    sql: "SELECT identity_auth_jit($5,$1,$2,$3,$4)::text",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_ACCOUNT_L515: SqlContract = SqlContract {
    id: "identity.rp_account_l515",
    domain: "identity",
    sql: "INSERT INTO users(username,email,display_name,domain_id,sync_source,enabled,oidc_subject,oidc_issuer,saml_name_id,saml_idp_entity_id) SELECT $1,$2,$1,id,'sso',true,CASE WHEN $6='oidc' THEN NULLIF($3,'') END,CASE WHEN $6='oidc' THEN NULLIF($4,'') END,CASE WHEN $6='saml' THEN NULLIF($3,'') END,CASE WHEN $6='saml' THEN NULLIF($4,'') END FROM domains WHERE name=$5 AND is_local ON CONFLICT DO NOTHING RETURNING id",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_MAILBOX_ENSURE_PRIMARY: SqlContract = SqlContract {
    id: "identity.rp_mailbox_ensure_primary",
    domain: "identity",
    sql: "SELECT rust_mailbox_ensure_primary($1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_ACCOUNT_L568: SqlContract = SqlContract {
    id: "identity.rp_account_l568",
    domain: "identity",
    sql: "SELECT identity_auth_mint_fence($1,$2,$3,$4,$5)",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_LINK_L103: SqlContract = SqlContract {
    id: "identity.rp_link_l103",
    domain: "identity",
    sql: "SELECT rust_identity_rp_link_begin($1,$2::text::uuid,$3,$4,$5,$6)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::BYTEA,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_LINK_L182: SqlContract = SqlContract {
    id: "identity.rp_link_l182",
    domain: "identity",
    sql: "SELECT EXISTS(SELECT 1 FROM sessions WHERE user_id=$1 AND token_hash=digest($2,'sha256') AND expires_at>statement_timestamp())",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_LINK_L205: SqlContract = SqlContract {
    id: "identity.rp_link_l205",
    domain: "identity",
    sql: "SELECT rust_identity_rp_link_hold($1,$2::text::uuid,$3,$4,$5,$6::text::jsonb)::text",
    params: &[
        Type::TEXT,
        Type::TEXT,
        Type::BYTEA,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_LINK_L228: SqlContract = SqlContract {
    id: "identity.rp_link_l228",
    domain: "identity",
    sql: "SELECT rust_identity_rp_link_take($1,$2::text::uuid,$3)::text",
    params: &[Type::TEXT, Type::TEXT, Type::BYTEA],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_LINK_L266: SqlContract = SqlContract {
    id: "identity.rp_link_l266",
    domain: "identity",
    sql: "SELECT rust_identity_saml_link_finish($1,$2,$3,$4,$5::text::uuid,$6,$7::text::jsonb,$8::text::jsonb,$9)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::BYTEA, Type::TEXT, Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_LINK_L268: SqlContract = SqlContract {
    id: "identity.rp_link_l268",
    domain: "identity",
    sql: "SELECT rust_identity_rp_link_finish($1,$2,$3,$4,$5::text::uuid,$6,$7::text::jsonb,$8::text::jsonb,$9)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::BYTEA, Type::TEXT, Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_LINK_L98: SqlContract = SqlContract {
    id: "identity.rp_link_l98",
    domain: "identity",
    sql: "SELECT rust_identity_saml_link_begin($1,$2::text::uuid,$3,$4,$5,$6)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::BYTEA,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_SECRET_L15: SqlContract = SqlContract {
    id: "identity.rp_secret_l15",
    domain: "identity",
    sql: "SELECT key,value::text,encrypted FROM system_config WHERE key LIKE 'oidc_provider_%_config' ORDER BY key FOR UPDATE",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RP_SECRET_L36: SqlContract = SqlContract {
    id: "identity.rp_secret_l36",
    domain: "identity",
    sql: "SELECT rust_identity_rp_reseal($1::text::jsonb)",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SAML_L164: SqlContract = SqlContract {
    id: "identity.saml_l164",
    domain: "identity",
    sql: "SELECT id,idp_entity_id,idp_metadata_url,idp_sso_url,pgp_sym_decrypt(idp_cert_enc,$1::text),sp_entity_id,sp_acs_url,attribute_map::text,jit_enabled,enabled,group_attribute,group_mappings::text,allow_idp_initiated FROM saml_sp_registrations WHERE enabled=TRUE",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SAML_FLOW_L108: SqlContract = SqlContract {
    id: "identity.saml_flow_l108",
    domain: "identity",
    sql: "SELECT rust_identity_saml_link_hold($1,$2::text::uuid,$3,$4,$5::text::jsonb)::text",
    params: &[Type::INT8, Type::TEXT, Type::BYTEA, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SAML_FLOW_L133: SqlContract = SqlContract {
    id: "identity.saml_flow_l133",
    domain: "identity",
    sql: "SELECT rust_identity_saml_link_take($1,$2::text::uuid,$3)::text",
    params: &[Type::INT8, Type::TEXT, Type::BYTEA],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SAML_FLOW_L222: SqlContract = SqlContract {
    id: "identity.saml_flow_l222",
    domain: "identity",
    sql: "SELECT rust_identity_saml_consume($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SAML_FLOW_L326: SqlContract = SqlContract {
    id: "identity.saml_flow_l326",
    domain: "identity",
    sql: "SELECT audit_write($1,$2,'saml_registration',$3,NULL,NULL,NULLIF($4,'')::inet,$5,'core')",
    params: &[Type::INT8, Type::TEXT, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L124: SqlContract = SqlContract {
    id: "identity.self_service_l124",
    domain: "identity",
    sql: "SELECT id,email,COALESCE(label,''),source,         to_char(NULLIF(not_before,'0001-01-01T00:00:00Z'::timestamptz) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),         to_char(NULLIF(not_after,'0001-01-01T00:00:00Z'::timestamptz) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),         fingerprint,cert_pem FROM recipient_smime_certs WHERE owner_user_id=$1 ORDER BY last_seen DESC",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L150: SqlContract = SqlContract {
    id: "identity.self_service_l150",
    domain: "identity",
    sql: "INSERT INTO recipient_smime_certs(owner_user_id,email,cert_pem,fingerprint,not_before,not_after,source,label,first_seen,last_seen)              VALUES($1,$2,$3,$4,to_timestamp($5::bigint),to_timestamp($6::bigint),'imported',$7,now(),now())              ON CONFLICT ON CONSTRAINT recipient_smime_certs_dedup_key DO UPDATE SET last_seen=now(),source='imported',              label=COALESCE(NULLIF($7,''),recipient_smime_certs.label) WHERE recipient_smime_certs.owner_user_id=$1",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L164: SqlContract = SqlContract {
    id: "identity.self_service_l164",
    domain: "identity",
    sql: "WITH d AS (DELETE FROM recipient_smime_certs WHERE id=$2 AND owner_user_id=$1 RETURNING id) SELECT EXISTS(SELECT 1 FROM d)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L177: SqlContract = SqlContract {
    id: "identity.self_service_l177",
    domain: "identity",
    sql: "SELECT id,source_type,status,conflict_strategy,progress::text,error_log::text,         to_char(started_at,'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),         to_char(completed_at,'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),         to_char(created_at,'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')          FROM migration_jobs WHERE user_id=$1 AND status!='completed' ORDER BY created_at DESC LIMIT 1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_MIGRATION_HISTORY_DELETE: SqlContract = SqlContract {
    id: "identity.self_migration_history_delete",
    domain: "identity",
    sql: "SELECT rust_migration_history_delete($1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L210: SqlContract = SqlContract {
    id: "identity.self_service_l210",
    domain: "identity",
    sql: "SELECT id FROM mailboxes WHERE user_id=$1 LIMIT 1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L216: SqlContract = SqlContract {
    id: "identity.self_service_l216",
    domain: "identity",
    sql: "SELECT id FROM migration_jobs WHERE user_id=$1 AND status IN ('pending','testing','fetching','importing','paused') ORDER BY created_at DESC LIMIT 1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L221: SqlContract = SqlContract {
    id: "identity.self_service_l221",
    domain: "identity",
    sql: "SELECT id FROM migration_jobs WHERE user_id=$1 AND status IN ('fetching','importing') ORDER BY created_at DESC LIMIT 1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L226: SqlContract = SqlContract {
    id: "identity.self_service_l226",
    domain: "identity",
    sql: "SELECT id FROM migration_jobs WHERE user_id=$1 AND status='paused' ORDER BY created_at DESC LIMIT 1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L232: SqlContract = SqlContract {
    id: "identity.self_service_l232",
    domain: "identity",
    sql: "SELECT id FROM migration_jobs WHERE user_id=$1 AND id=$2",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_MIGRATION_JOB_INSERT: SqlContract = SqlContract {
    id: "identity.self_migration_job_insert",
    domain: "identity",
    sql: "SELECT rust_migration_job_insert($1,$2,$3,$4,$5)",
    params: &[Type::INT8, Type::TEXT, Type::BYTEA, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L255: SqlContract = SqlContract {
    id: "identity.self_service_l255",
    domain: "identity",
    sql: "SELECT count(*) FROM webhook_subscriptions WHERE user_id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_WEBHOOK_LIST: SqlContract = SqlContract {
    id: "identity.self_webhook_list",
    domain: "identity",
    sql: concat!(
        "SELECT id,url,event_types::text,scope,is_active,",
        setjoin_sql_catalog::pg_rfc3339!("created_at"),
        ",",
        setjoin_sql_catalog::pg_rfc3339!("updated_at"),
        " FROM webhook_subscriptions WHERE user_id=$1 ORDER BY created_at DESC"
    ),
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_WEBHOOK_CREATE: SqlContract = SqlContract {
    id: "identity.self_webhook_create",
    domain: "identity",
    sql: "SELECT rust_webhook_self_create($1,$2,$3,$4,$5)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::BYTEA, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_WEBHOOK_DELETE: SqlContract = SqlContract {
    id: "identity.self_webhook_delete",
    domain: "identity",
    sql: "SELECT rust_webhook_self_delete($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_APP_PASSWORD_LIST: SqlContract = SqlContract {
    id: "identity.self_app_password_list",
    domain: "identity",
    sql: concat!(
        "SELECT id,name,",
        setjoin_sql_catalog::pg_rfc3339!("created_at"),
        ",",
        setjoin_sql_catalog::pg_rfc3339!("last_used_at"),
        ",",
        setjoin_sql_catalog::pg_rfc3339!("expires_at"),
        " FROM app_passwords WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC"
    ),
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L418: SqlContract = SqlContract {
    id: "identity.self_service_l418",
    domain: "identity",
    sql: "INSERT INTO app_passwords(user_id,name,label,token_hash) VALUES($1,$2,$3,$4)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L454: SqlContract = SqlContract {
    id: "identity.self_service_l454",
    domain: "identity",
    sql: "UPDATE app_passwords SET revoked_at=now() WHERE id=$2 AND user_id=$1 AND revoked_at IS NULL RETURNING id",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L465: SqlContract = SqlContract {
    id: "identity.self_service_l465",
    domain: "identity",
    sql: "SELECT enabled FROM feature_toggles WHERE key=$1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L47: SqlContract = SqlContract {
    id: "identity.self_service_l47",
    domain: "identity",
    sql: "INSERT INTO user_smime_certs(user_id,label,cert_pem,private_key_enc,issued_at,expires_at,is_default) VALUES($1,$2,$3,pgp_sym_encrypt($4::text,current_setting('app.encryption_key')),to_timestamp($5::bigint),to_timestamp($6::bigint), NOT EXISTS(SELECT 1 FROM user_smime_certs WHERE user_id=$1)) ON CONFLICT(user_id,label) DO UPDATE SET cert_pem=EXCLUDED.cert_pem,private_key_enc=EXCLUDED.private_key_enc, issued_at=EXCLUDED.issued_at,expires_at=EXCLUDED.expires_at WHERE user_smime_certs.user_id=$1 AND user_smime_certs.label=$2",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT, Type::INT8, Type::INT8],
    columns: &[],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L479: SqlContract = SqlContract {
    id: "identity.self_service_l479",
    domain: "identity",
    sql: "SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary=TRUE LIMIT 1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L501: SqlContract = SqlContract {
    id: "identity.self_service_l501",
    domain: "identity",
    sql: "SELECT dlp_evaluate_draft($1,$2::text::jsonb,$3,$4,$5)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L552: SqlContract = SqlContract {
    id: "identity.self_service_l552",
    domain: "identity",
    sql: "SELECT EXISTS(SELECT 1 FROM users a JOIN users t ON t.domain_id=a.domain_id WHERE a.id=$1 AND t.id=$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L559: SqlContract = SqlContract {
    id: "identity.self_service_l559",
    domain: "identity",
    sql: "SELECT org_chart_managers($2)::text WHERE EXISTS(SELECT 1 FROM users a JOIN users t ON t.domain_id=a.domain_id WHERE a.id=$1 AND t.id=$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L560: SqlContract = SqlContract {
    id: "identity.self_service_l560",
    domain: "identity",
    sql: "SELECT org_chart_reports($2,3)::text WHERE EXISTS(SELECT 1 FROM users a JOIN users t ON t.domain_id=a.domain_id WHERE a.id=$1 AND t.id=$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L561: SqlContract = SqlContract {
    id: "identity.self_service_l561",
    domain: "identity",
    sql: "SELECT jsonb_build_object('id',u.id::text,'email',u.email,'displayName',u.display_name,'firstName',u.first_name,'lastName',u.last_name,'jobTitle',u.job_title,'department',d.name,'avatar',CASE WHEN u.avatar_sha256 IS NOT NULL THEN jsonb_build_object('blobId',u.avatar_sha256) END)::text FROM users u JOIN users a ON a.domain_id=u.domain_id LEFT JOIN departments d ON d.id=u.department_id WHERE a.id=$1 AND u.id=$2",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L609: SqlContract = SqlContract {
    id: "identity.self_service_l609",
    domain: "identity",
    sql: "SELECT COALESCE(external_sender_warning,TRUE) FROM users WHERE id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L631: SqlContract = SqlContract {
    id: "identity.self_service_l631",
    domain: "identity",
    sql: "SELECT name FROM domains WHERE name=ANY($1)",
    params: &[Type::TEXT_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L653: SqlContract = SqlContract {
    id: "identity.self_service_l653",
    domain: "identity",
    sql: "SELECT recipients_ooo_status($1,$2::text::jsonb)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L67: SqlContract = SqlContract {
    id: "identity.self_service_l67",
    domain: "identity",
    sql: "SELECT rust_identity_smime_cert_delete($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L678: SqlContract = SqlContract {
    id: "identity.self_service_l678",
    domain: "identity",
    sql: "SELECT EXISTS(SELECT 1 FROM mailbox_delegates md JOIN mailboxes mb ON mb.id=md.mailbox_id WHERE md.user_id=$1 AND mb.email=$2 AND md.permission IN ('send_as','full_access'))",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_READ_RECEIPT_SEND: SqlContract = SqlContract {
    id: "identity.self_read_receipt_send",
    domain: "identity",
    sql: "SELECT send_read_receipt($1::bigint,$2::bigint,$3::text,$4::boolean)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L83: SqlContract = SqlContract {
    id: "identity.self_service_l83",
    domain: "identity",
    sql: "SELECT rust_identity_smime_cert_default($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SELF_SERVICE_L94: SqlContract = SqlContract {
    id: "identity.self_service_l94",
    domain: "identity",
    sql: "SELECT id,label,cert_pem,is_default FROM user_smime_certs WHERE user_id=$1 ORDER BY is_default DESC,created_at DESC",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_L149: SqlContract = SqlContract {
    id: "identity.session_l149",
    domain: "identity",
    sql: "SELECT rust_identity_refresh($1,$2,$3,$4::text::jsonb,$5,$6,$7::text::uuid)::text",
    params: &[
        Type::INT8,
        Type::BYTEA,
        Type::TEXT,
        Type::TEXT,
        Type::BYTEA,
        Type::INT8,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_L151: SqlContract = SqlContract {
    id: "identity.session_l151",
    domain: "identity",
    sql: "INSERT INTO auth_event_log(user_id,event,provider,email) VALUES($1,'login','jwt',NULLIF($2,''))",
    params: &[Type::INT8, Type::TEXT],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_L181: SqlContract = SqlContract {
    id: "identity.session_l181",
    domain: "identity",
    sql: "SELECT EXISTS(SELECT 1 FROM admin_role_assignments ara WHERE ara.user_id=u.id AND (ara.expires_at IS NULL OR ara.expires_at>now())),EXISTS(SELECT 1 FROM mailboxes WHERE user_id=u.id AND is_primary=true LIMIT 1),COALESCE(u.totp_enabled,false),(to_jsonb(u.totp_enabled_at AT TIME ZONE 'UTC')#>>'{}'),COALESCE(u.display_name,''),u.email FROM users u WHERE u.id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_L183: SqlContract = SqlContract {
    id: "identity.session_l183",
    domain: "identity",
    sql: "SELECT mb.id,mb.email,md.permission FROM mailbox_delegates md JOIN mailboxes mb ON mb.id=md.mailbox_id WHERE md.user_id=$1 AND md.permission IN ('send_as','full_access') AND mb.enabled=true ORDER BY lower(mb.email),mb.id",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_L184: SqlContract = SqlContract {
    id: "identity.session_l184",
    domain: "identity",
    sql: "SELECT a.email FROM aliases a JOIN mailboxes m ON m.id=a.mailbox_id JOIN users u ON u.id=m.user_id WHERE m.user_id=$1 AND m.is_primary=true AND m.enabled=true AND lower(a.email)<>lower(u.email) ORDER BY lower(a.email),a.id",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_L92: SqlContract = SqlContract {
    id: "identity.session_l92",
    domain: "identity",
    sql: "SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=$3::text::uuid AND family='F21' AND command='refresh') WHERE EXISTS(SELECT 1 FROM users u JOIN oauth_tokens o ON o.user_id=u.id WHERE u.id=$1 AND u.enabled AND o.user_id=$1 AND o.token_hash=$2 AND o.revoked_at IS NULL AND o.expires_at>now() AND identity_transition_admission_allowed(u.id))",
    params: &[Type::INT8, Type::BYTEA, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L109: SqlContract = SqlContract {
    id: "identity.totp_l109",
    domain: "identity",
    sql: "SELECT rust_identity_totp_remove($1,$2,$3,$4)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L246: SqlContract = SqlContract {
    id: "identity.totp_l246",
    domain: "identity",
    sql: "SELECT * FROM rust_identity_totp_cycle_read($1)",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L283: SqlContract = SqlContract {
    id: "identity.totp_l283",
    domain: "identity",
    sql: "SELECT rust_identity_totp_cycle($1,$2,$3,$4)",
    params: &[Type::INT8, Type::BOOL, Type::INT8, Type::BYTEA],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L341: SqlContract = SqlContract {
    id: "identity.totp_l341",
    domain: "identity",
    sql: "SELECT COALESCE(totp_enabled,false),COALESCE(totp_backup_codes_enc,'{}') FROM users WHERE id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::TEXT_ARRAY)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L353: SqlContract = SqlContract {
    id: "identity.totp_l353",
    domain: "identity",
    sql: "SELECT password_hash FROM users WHERE id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L431: SqlContract = SqlContract {
    id: "identity.totp_l431",
    domain: "identity",
    sql: "DELETE FROM totp_removal_step_ups WHERE user_id=$1",
    params: &[Type::INT8],
    columns: &[],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L435: SqlContract = SqlContract {
    id: "identity.totp_l435",
    domain: "identity",
    sql: "INSERT INTO totp_removal_step_ups(token_hash,user_id,session_jti,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')",
    params: &[Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L483: SqlContract = SqlContract {
    id: "identity.totp_l483",
    domain: "identity",
    sql: "SELECT rust_identity_totp_bootstrap_setup($1,$2::text::jsonb,$3,$4)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L485: SqlContract = SqlContract {
    id: "identity.totp_l485",
    domain: "identity",
    sql: "SELECT rust_identity_totp_setup($1,$2::text::jsonb,$3,$4)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L557: SqlContract = SqlContract {
    id: "identity.totp_l557",
    domain: "identity",
    sql: "SELECT rust_identity_totp_confirm_read($1,$2::text::jsonb,$3,$4,$5)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L582: SqlContract = SqlContract {
    id: "identity.totp_l582",
    domain: "identity",
    sql: "SELECT rust_identity_totp_confirm($1,$2::text::jsonb,$3,$4,$5,$6,$7)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::BYTEA,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L764: SqlContract = SqlContract {
    id: "identity.totp_l764",
    domain: "identity",
    sql: "INSERT INTO login_events(user_id,device_fingerprint,device_name,platform,source_ip,location,success,fail_reason,client,protocol,auth_method,session_id,correlation_id,occurred_at) VALUES($1,NULL,NULL,NULL,NULLIF($2,'')::inet,NULL,true,NULL,'web','http',$3,NULL,NULL,now())",
    params: &[Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L767: SqlContract = SqlContract {
    id: "identity.totp_l767",
    domain: "identity",
    sql: "INSERT INTO sessions(id,user_id,token_hash,expires_at,ip,user_agent,auth_method) VALUES($1,$2,$3,now()+make_interval(secs=>$4),NULLIF($5,'')::inet,$6,$7) ON CONFLICT(id) DO NOTHING",
    params: &[Type::TEXT, Type::INT8, Type::BYTEA, Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L810: SqlContract = SqlContract {
    id: "identity.totp_l810",
    domain: "identity",
    sql: "SELECT rust_identity_mfa_mint($1,$2::text::jsonb,$3,$4,$5::text::uuid)::text",
    params: &[Type::INT8, Type::TEXT, Type::BYTEA, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L856: SqlContract = SqlContract {
    id: "identity.totp_l856",
    domain: "identity",
    sql: "SELECT rust_identity_totp_bootstrap_read($1,$2::text::jsonb,$3,$4,$5)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L862: SqlContract = SqlContract {
    id: "identity.totp_l862",
    domain: "identity",
    sql: "SELECT rust_identity_totp_bootstrap_fail($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TOTP_L866: SqlContract = SqlContract {
    id: "identity.totp_l866",
    domain: "identity",
    sql: "SELECT rust_identity_totp_bootstrap_confirm($1,$2::text::jsonb,$3,$4,$5,$6,$7,$8::text::uuid,$9,$10)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::BYTEA, Type::INT8, Type::TEXT, Type::INT8, Type::BYTEA],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBAUTHN_L1035: SqlContract = SqlContract {
    id: "identity.webauthn_l1035",
    domain: "identity",
    sql: "SELECT rust_identity_webauthn_registration_read($1,$2::text::jsonb)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBAUTHN_L1040: SqlContract = SqlContract {
    id: "identity.webauthn_l1040",
    domain: "identity",
    sql: "SELECT rust_identity_webauthn_finish($1,$2::text::jsonb,$3,$4,$5,$6,$7,$8,$9,$10)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BYTEA,
        Type::BYTEA,
        Type::TEXT,
        Type::INT4,
        Type::BOOL,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBAUTHN_L1069: SqlContract = SqlContract {
    id: "identity.webauthn_l1069",
    domain: "identity",
    sql: "SELECT rust_identity_webauthn_revoke($1,$2::text::jsonb,$3,$4,$5,$6)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BYTEA,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBAUTHN_L1482: SqlContract = SqlContract {
    id: "identity.webauthn_l1482",
    domain: "identity",
    sql: "SELECT COALESCE(totp_enabled,FALSE),COALESCE(push_mfa_enabled,FALSE) FROM users WHERE id=$1 AND enabled",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBAUTHN_L288: SqlContract = SqlContract {
    id: "identity.webauthn_l288",
    domain: "identity",
    sql: "SELECT email,display_name,webauthn_user_handle FROM users WHERE id=$1 AND enabled=TRUE",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::BYTEA),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBAUTHN_L301: SqlContract = SqlContract {
    id: "identity.webauthn_l301",
    domain: "identity",
    sql: "UPDATE users SET webauthn_user_handle=COALESCE(webauthn_user_handle,$1) WHERE id=$2 RETURNING webauthn_user_handle",
    params: &[Type::BYTEA, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BYTEA)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBAUTHN_L309: SqlContract = SqlContract {
    id: "identity.webauthn_l309",
    domain: "identity",
    sql: "SELECT id,public_key,attestation_type,sign_count FROM passkey_credentials WHERE user_id=$1 AND revoked_at IS NULL",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BYTEA), ColumnSpec::unnamed(Type::BYTEA), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBAUTHN_L341: SqlContract = SqlContract {
    id: "identity.webauthn_l341",
    domain: "identity",
    sql: "SELECT id FROM users WHERE email=$1 AND enabled=TRUE",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBAUTHN_L41: SqlContract = SqlContract {
    id: "identity.webauthn_l41",
    domain: "identity",
    sql: "UPDATE passkey_credentials SET device_name=$1 WHERE id=$2 AND user_id=$3 AND revoked_at IS NULL",
    params: &[Type::TEXT, Type::BYTEA, Type::INT8],
    columns: &[],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBAUTHN_L534: SqlContract = SqlContract {
    id: "identity.webauthn_l534",
    domain: "identity",
    sql: "SELECT rust_identity_webauthn_login_claim($1,$2,$3,$4,$5)",
    params: &[
        Type::INT8,
        Type::BYTEA,
        Type::BYTEA,
        Type::INT4,
        Type::BYTEA,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBAUTHN_L746: SqlContract = SqlContract {
    id: "identity.webauthn_l746",
    domain: "identity",
    sql: "SELECT rust_identity_mfa_mint($1,'{}'::jsonb,$2,$3,$4::text::uuid)::text",
    params: &[Type::INT8, Type::BYTEA, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBAUTHN_L798: SqlContract = SqlContract {
    id: "identity.webauthn_l798",
    domain: "identity",
    sql: "SELECT rust_identity_webauthn_begin($1,$2::text::jsonb,$3,$4,$5)::text",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT, Type::BYTEA],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WEBAUTHN_L9: SqlContract = SqlContract {
    id: "identity.webauthn_l9",
    domain: "identity",
    sql: "SELECT id,COALESCE(device_name,''),to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'),uv_capable FROM passkey_credentials WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BYTEA), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::TEXT), ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONTRACTS: &[SqlContract] = &[
    BOOTSTRAP_L64,
    DEVICE_TRUST_L117,
    DEVICE_TRUST_L85,
    GUEST_INVITE_L105,
    GUEST_INVITE_L147,
    GUEST_INVITE_L209,
    GUEST_INVITE_L237,
    ECHO_TEXT,
    GUEST_INVITE_L94,
    IDENTITY_LINKS_L48,
    IDENTITY_LINKS_L69,
    IMPERSONATION_L109,
    IS_GUEST_ACCOUNT,
    IMPERSONATION_AUDIT_LOG_INSERT,
    IMPERSONATION_L73,
    IMPERSONATION_L98,
    ISSUANCE_L147,
    ISSUANCE_L178,
    ISSUANCE_L243,
    ISSUANCE_L258,
    ISSUANCE_L296,
    ISSUANCE_L333,
    ISSUANCE_L364,
    ISSUANCE_L388,
    ISSUANCE_L414,
    ISSUANCE_CLIENT_VERSION_LATEST,
    LIB_L8,
    LOGIN_L112,
    LOGIN_L137,
    LOGIN_L164,
    LOGIN_L186,
    LOGIN_L215,
    LOGIN_L234,
    LOGIN_L237,
    LOGIN_L242,
    LOGIN_L247,
    LOGIN_L258,
    LOGIN_L261,
    LOGIN_L270,
    LOGIN_L344,
    LOGIN_L56,
    LOGIN_L96,
    OIDC_L104,
    OIDC_L139,
    OIDC_L68,
    OIDC_CONSUMERS_L177,
    OIDC_CONSUMERS_L179,
    OIDC_CONSUMERS_L186,
    OIDC_CONSUMERS_L197,
    OIDC_CONSUMERS_L258,
    OIDC_CONSUMERS_L49,
    OIDC_CONSUMERS_L51,
    OIDC_CONSUMERS_L64,
    OIDC_CONSUMERS_L66,
    OIDC_CONSUMERS_L96,
    OIDC_GRANTS_L145,
    OIDC_GRANTS_L159,
    OIDC_GRANTS_L301,
    OIDC_GRANTS_L314,
    OIDC_GRANTS_L430,
    OIDC_GRANTS_L432,
    OIDC_GRANTS_L458,
    OIDC_GRANTS_L505,
    USER_OPERATION_LOOKUP,
    OIDC_REQUESTS_L72,
    OIDC_REQUESTS_L88,
    PASSWORD_L127,
    PASSWORD_L157,
    PASSWORD_L168,
    PASSWORD_L182,
    PASSWORD_L184,
    PASSWORD_L205,
    PASSWORD_L251,
    PASSWORD_L254,
    PASSWORD_L34,
    PASSWORD_L68,
    POSSESSION_L134,
    POSSESSION_L139,
    POSSESSION_L41,
    POSSESSION_L87,
    PUSH_L123,
    PUSH_L140,
    PUSH_L191,
    PUSH_L204,
    PUSH_L231,
    PUSH_L276,
    PUSH_L320,
    ADMIN_AUDIT_WRITE_USER,
    PUSH_L365,
    PUSH_L389,
    PUSH_L508,
    PUSH_L525,
    PUSH_L544,
    PUSH_L60,
    PUSH_L628,
    PUSH_L666,
    PUSH_L73,
    PUSH_DELIVERY_L66,
    PUSH_DELIVERY_L80,
    RECOVERY_L14,
    RECOVERY_L165,
    RECOVERY_L191,
    RECOVERY_L65,
    RP_L327,
    RP_ACCOUNT_L164,
    RP_ACCOUNT_L194,
    RP_ACCOUNT_L196,
    RP_ACCOUNT_L218,
    RP_ACCOUNT_L240,
    RP_ACCOUNT_L277,
    RP_ACCOUNT_L327,
    RP_ACCOUNT_L352,
    RP_ACCOUNT_L449,
    RP_ACCOUNT_L484,
    RP_ACCOUNT_L515,
    RP_MAILBOX_ENSURE_PRIMARY,
    RP_ACCOUNT_L568,
    RP_LINK_L103,
    RP_LINK_L182,
    RP_LINK_L205,
    RP_LINK_L228,
    RP_LINK_L266,
    RP_LINK_L268,
    RP_LINK_L98,
    RP_SECRET_L15,
    RP_SECRET_L36,
    SAML_L164,
    SAML_FLOW_L108,
    SAML_FLOW_L133,
    SAML_FLOW_L222,
    SAML_FLOW_L326,
    SELF_SERVICE_L124,
    SELF_SERVICE_L150,
    SELF_SERVICE_L164,
    SELF_SERVICE_L177,
    SELF_MIGRATION_HISTORY_DELETE,
    SELF_SERVICE_L210,
    SELF_SERVICE_L216,
    SELF_SERVICE_L221,
    SELF_SERVICE_L226,
    SELF_SERVICE_L232,
    SELF_MIGRATION_JOB_INSERT,
    SELF_SERVICE_L255,
    SELF_WEBHOOK_LIST,
    SELF_WEBHOOK_CREATE,
    SELF_WEBHOOK_DELETE,
    SELF_APP_PASSWORD_LIST,
    SELF_SERVICE_L418,
    SELF_SERVICE_L454,
    SELF_SERVICE_L465,
    SELF_SERVICE_L47,
    SELF_SERVICE_L479,
    SELF_SERVICE_L501,
    SELF_SERVICE_L552,
    SELF_SERVICE_L559,
    SELF_SERVICE_L560,
    SELF_SERVICE_L561,
    SELF_SERVICE_L609,
    SELF_SERVICE_L631,
    SELF_SERVICE_L653,
    SELF_SERVICE_L67,
    SELF_SERVICE_L678,
    SELF_READ_RECEIPT_SEND,
    SELF_SERVICE_L83,
    SELF_SERVICE_L94,
    SESSION_L149,
    SESSION_L151,
    SESSION_L181,
    SESSION_L183,
    SESSION_L184,
    SESSION_L92,
    TOTP_L109,
    TOTP_L246,
    TOTP_L283,
    TOTP_L341,
    TOTP_L353,
    TOTP_L431,
    TOTP_L435,
    TOTP_L483,
    TOTP_L485,
    TOTP_L557,
    TOTP_L582,
    TOTP_L764,
    TOTP_L767,
    TOTP_L810,
    TOTP_L856,
    TOTP_L862,
    TOTP_L866,
    WEBAUTHN_L1035,
    WEBAUTHN_L1040,
    WEBAUTHN_L1069,
    WEBAUTHN_L1482,
    WEBAUTHN_L288,
    WEBAUTHN_L301,
    WEBAUTHN_L309,
    WEBAUTHN_L341,
    WEBAUTHN_L41,
    WEBAUTHN_L534,
    WEBAUTHN_L746,
    WEBAUTHN_L798,
    WEBAUTHN_L9,
];
