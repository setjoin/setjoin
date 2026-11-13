//! Shared, fail-closed authorization preconditions for Rust routes.
//!
//! [`authorize`] returns a context only for a verified ES256 access token
//! whose guest, session, primary-mailbox and lifecycle checks all pass.
//! `None` means the untouched request must be handed to Go for its decision.
//! The context can only be created by this chain; request data never supplies
//! its identity. Domain scope and permissions are the signed token claims,
//! not live RBAC grants or a tenant identifier. Active governed role-group
//! IDs are loaded per request for signed admin tokens. Per-target reach
//! checks remain with each route family.

pub mod address;
pub mod clientip;
pub mod csrf;
pub mod es256;
pub mod gates;
pub mod jwks;
pub mod mailbox;
pub mod legacy_jwt;
pub mod password;
pub mod push;
pub mod signing_keys;
pub mod token;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hyper::header::HeaderMap;
use setjoin_pg::ScopedExecutor;
use token::KeySource;

/// Bound each precondition database read; timeout defers to Go.
pub const PRECHECK_TIMEOUT: Duration = Duration::from_secs(1);

/// Environment override for [`precheck_timeout`], in milliseconds (1..=60000).
pub const PRECHECK_TIMEOUT_ENV: &str = "SETJOIN_AUTHZ_PRECHECK_TIMEOUT_MS";

/// The per-read precondition bound: [`PRECHECK_TIMEOUT`] unless the operator or a
/// test harness on a CPU-starved host widens it through [`PRECHECK_TIMEOUT_ENV`].
/// A longer bound only waits longer before deferring to Go; it never admits anything.
pub fn precheck_timeout() -> Duration {
    static BOUND: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *BOUND.get_or_init(|| bound_from(std::env::var(PRECHECK_TIMEOUT_ENV).ok().as_deref()))
}

fn bound_from(value: Option<&str>) -> Duration {
    value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|ms| (1..=60_000).contains(ms))
        .map_or(PRECHECK_TIMEOUT, Duration::from_millis)
}

#[cfg(test)]
mod precheck_bound_tests {
    use super::*;

    #[test]
    fn default_unless_a_sane_override_is_given() {
        assert_eq!(bound_from(None), PRECHECK_TIMEOUT);
        assert_eq!(bound_from(Some("")), PRECHECK_TIMEOUT);
        assert_eq!(bound_from(Some("abc")), PRECHECK_TIMEOUT);
        assert_eq!(bound_from(Some("0")), PRECHECK_TIMEOUT);
        assert_eq!(bound_from(Some("60001")), PRECHECK_TIMEOUT);
        assert_eq!(bound_from(Some(" 15000 ")), Duration::from_secs(15));
        assert_eq!(bound_from(Some("60000")), Duration::from_secs(60));
    }
}

/// Identity established by a verified token and admitted user/mailbox scope.
/// Signed admin and permission claims are not a substitute for live RBAC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthContext {
    guest: bool,
    user_id: i64,
    email: String,
    mailbox_id: i64,
    domain_scope: Option<i64>,
    admin: bool,
    permissions: Vec<String>,
    roles: Vec<i64>,
    auth_time: Option<i64>,
}

impl AuthContext {
    /// Live satellite-derived account classification; never a request field.
    pub fn is_guest(&self) -> bool { self.guest }
    /// Scope for user domains. A mailbox-less proof receives user authority only.
    /// Mailstore callers must continue requiring a real primary MailboxId.
    pub fn database_scope(&self) -> setjoin_pg::MailboxAuthContext {
        use setjoin_pg::MailboxAuthContext;
        let actor=setjoin_contracts::ids::ActorId::new(self.user_id).expect("verified actor");
        let generation=setjoin_contracts::ids::Generation(1);
        match setjoin_contracts::ids::MailboxId::new(self.mailbox_id) {
            Ok(mailbox)=>MailboxAuthContext::from_authenticated_session(actor,mailbox,generation),
            Err(_)=>MailboxAuthContext::from_authenticated_user(actor,generation),
        }
    }

    /// Verified token display metadata for frozen-Go audit envelopes.
    pub fn email(&self) -> &str {
        &self.email
    }
    pub fn user_id(&self) -> i64 {
        self.user_id
    }
    pub fn mailbox_id(&self) -> i64 {
        self.mailbox_id
    }
    /// The signed domain-scope claim, before Go's live RBAC resolution.
    pub fn signed_domain_scope(&self) -> Option<i64> {
        self.domain_scope
    }
    /// The signed admin marker, not proof of any current permission.
    pub fn signed_admin(&self) -> bool {
        self.admin
    }
    /// Signed permission claims, not the current governed RBAC grants.
    pub fn signed_permissions(&self) -> &[String] {
        &self.permissions
    }
    /// Current active governed role-group IDs for this verified user.
    /// Like Go's permission resolver, non-admin tokens carry no admin authority.
    /// Per-target domain/OU/set reach still needs the family's SQL guards.
    pub fn roles(&self) -> &[i64] {
        &self.roles
    }
    /// The signed `auth_time` claim (Go's `claims.SessionAuthTime`), Unix seconds.
    pub fn auth_time(&self) -> Option<i64> {
        self.auth_time
    }
}

/// Admitted identity and the JMAP state already read by the pilot's gate.
pub struct Authorized {
    context: AuthContext,
    state: gates::SessionState,
    issued_at: i64,
    token_id: String,
    token_family: String,
    acr: String,
    amr: Vec<String>,
    device_id: String,
}

impl Authorized {
    pub fn context(&self) -> &AuthContext {
        &self.context
    }
    pub fn session_state(&self) -> gates::SessionState {
        self.state
    }
    /// Revocation identity taken from the verified access token.
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }
    pub fn token_id(&self) -> &str {
        &self.token_id
    }
    pub fn token_family(&self) -> &str {
        &self.token_family
    }
    /// Signed `acr` claim of the verified access token (empty when absent).
    pub fn acr(&self) -> &str {
        &self.acr
    }
    /// Signed `device.id` fingerprint of the access token (empty without a device claim).
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    /// Signed `amr` claim values in token order (empty when absent).
    pub fn amr(&self) -> &[String] {
        &self.amr
    }
}

/// Run the whole precondition chain. No request-owned identity is accepted.
/// `flag` selects the caller's transfer toggle; security gates are always
/// checked alongside it. Failures and unsupported cases defer to Go.
pub async fn authorize(
    exec: &ScopedExecutor,
    keys: &impl KeySource,
    issuer: &str,
    headers: &HeaderMap,
    scheme: &str,
    flag: &str,
) -> Option<Authorized> {
    authorize_with_feature(exec, keys, issuer, headers, scheme, Some(flag),false,true,false).await
}

/// Authenticate an inventory-gated route with no Go feature flag. Security
/// toggles, current guest/session state and mailbox scope still apply.
/// The gateway enforces method-aware CSRF before dispatch, including injected routes.
pub async fn authorize_request(
    exec: &ScopedExecutor,
    keys: &impl KeySource,
    issuer: &str,
    headers: &HeaderMap,
    scheme: &str,
) -> Option<Authorized> {
    authorize_with_feature(exec, keys, issuer, headers, scheme, None,false,true,false).await
}

/// Mailserver user-domain admission. A verified non-guest with no owned
/// mailbox can reach its explicit no-mailbox response; it gains user authority
/// only. Existing mailbox lifecycle failures remain denied.
pub async fn authorize_mailserver_identity_request(exec:&ScopedExecutor,keys:&impl KeySource,
    issuer:&str,headers:&HeaderMap,scheme:&str)->Option<Authorized> {
    authorize_with_feature(exec,keys,issuer,headers,scheme,None,false,true,true).await
}

/// Scoped mirrors authenticate only a Drive path; shared HTTP auth remains unscoped.
pub async fn authorize_drive_request(exec:&ScopedExecutor,keys:&impl KeySource,issuer:&str,headers:&HeaderMap,scheme:&str,path:&str)->Option<Authorized>{
    let drive=path=="/drive"||path.starts_with("/drive/")||path=="/api/drive"||path.starts_with("/api/drive/");
    authorize_with_feature(exec,keys,issuer,headers,scheme,None,drive,true,false).await
}

/// Console permission resolution owns its live authority read. Role IDs are
/// unused here; omitting their redundant read preserves Go's error semantics.
pub async fn authorize_console_request(exec:&ScopedExecutor,keys:&impl KeySource,
    issuer:&str,headers:&HeaderMap,scheme:&str)->Option<Authorized>{
    authorize_with_feature(exec,keys,issuer,headers,scheme,None,false,false,false).await
}

async fn authorize_with_feature(
    exec: &ScopedExecutor,
    keys: &impl KeySource,
    issuer: &str,
    headers: &HeaderMap,
    _scheme: &str,
    flag: Option<&str>,
    drive:bool,
    resolve_roles:bool,
    allow_without_mailbox:bool,
) -> Option<Authorized> {
    if !tokio::time::timeout(precheck_timeout(), gates::admission_allowed(exec, flag))
        .await
        .unwrap_or(false)
    {
        return None;
    }
    let token = if drive{token::presented(headers)}else{token::extract(headers)}?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    let session = if drive{token::verify_drive(&token,issuer,now.as_secs_f64(),keys).await}else{token::verify(&token, issuer, now.as_secs_f64(), keys).await}?;
    let caller = tokio::time::timeout(precheck_timeout(), gates::caller(exec, &session))
        .await
        .unwrap_or(gates::Caller::Defer);
    let (mailbox,state)=match caller {
        gates::Caller::Member {mailbox,state}=>(mailbox,state),
        _ if allow_without_mailbox=>{
            let iat=session.issued_at as f64;
            let rows=tokio::time::timeout(precheck_timeout(),exec.read(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1) \
                 AND NOT EXISTS(SELECT 1 FROM mailboxes WHERE user_id=$1) \
                 AND NOT EXISTS(SELECT 1 FROM guest_account_status($1)) \
                 AND NOT EXISTS(SELECT 1 FROM session_revocations r WHERE r.user_id=$1 AND r.expires_at>now() \
                   AND ((r.scope='all' AND r.not_before>=to_timestamp($2::float8)) \
                     OR (r.scope='jti' AND $3<>'' AND r.jti=$3) \
                     OR (r.scope='family' AND $4<>'' AND r.family_id=$4)))",
                &[(&session.user_id,setjoin_pg::Type::INT8),(&iat,setjoin_pg::Type::FLOAT8),(&session.jti,setjoin_pg::Type::TEXT),(&session.family,setjoin_pg::Type::TEXT)]
            )).await.ok()?.ok()?;
            if !rows.first()?.try_get::<_,bool>(0).ok()? {return None;}
            (0,gates::SessionState {email:0,mailbox:0,thread:0,tag:0,calendar:0,contact:0,task:0,identity:0})
        },
        _=>return None,
    };
    let roles = if session.admin && resolve_roles {
        tokio::time::timeout(precheck_timeout(), gates::roles(exec, session.user_id))
            .await
            .ok()??
    } else {
        Vec::new()
    };
    Some(Authorized {
        context: AuthContext {
            guest: false,
            user_id: session.user_id,
            email: session.email,
            mailbox_id: mailbox,
            domain_scope: session.domain_scope,
            admin: session.admin,
            permissions: session.permissions,
            auth_time: session.auth_time,
            roles,
        },
        state,
        issued_at: session.issued_at,
        token_id: session.jti,
        token_family: session.family,
        acr: session.acr,
        amr: session.amr,
        device_id: session.device_id,
    })
}

/// Verified exact-surface attachment bearer and its signed binding. Identity
/// remains sealed; signed account/device fields still require live checks.
pub struct AuthorizedAttachment {
    pub identity: AuthContext,
    pub claims: serde_json::Value,
}

pub async fn authorize_attachment(
    exec: &ScopedExecutor,
    headers: &HeaderMap,
    _scheme: &str,
    issuer: &str,
    secrets: &[&[u8]],
) -> Option<AuthorizedAttachment> {
    if !gates::admission_allowed(exec, None).await {
        return None;
    }
    let token = token::extract(headers)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs_f64();
    let (session, claims) = token::attachment(&token, issuer, now, secrets)?;
    let gates::Caller::Member { mailbox, .. } =
        tokio::time::timeout(precheck_timeout(), gates::caller(exec, &session))
            .await
            .ok()?
    else {
        return None;
    };
    Some(AuthorizedAttachment {
        identity: AuthContext {
            guest: false,
            user_id: session.user_id,
            email: session.email,
            mailbox_id: mailbox,
            domain_scope: None,
            admin: false,
            permissions: Vec::new(),
            roles: Vec::new(),
            auth_time: None,
        },
        claims,
    })
}

pub mod go_url;
pub mod ssrf;

pub mod auth_chain;

pub mod runtime;

pub mod device;

pub mod dpop;

pub mod geoip;

/// HTTP user domains also admit mailbox-less active guests. The front door's
/// unconditional satellite/program/route belt still owns surface containment.
/// This proof grants no target membership or mailbox authority.
pub async fn authorize_user_request(
    exec: &ScopedExecutor, keys: &impl KeySource, issuer: &str,
    headers: &HeaderMap, scheme: &str,
) -> Option<Authorized> {
    let token=token::presented(headers)?;
    let identity=tokio::time::timeout(precheck_timeout(),
        push::authenticate_detailed(exec,keys,issuer,&token)).await.ok()?.ok()?;
    if !identity.is_guest() {
        return authorize_request(exec,keys,issuer,headers,scheme).await;
    }
    if !tokio::time::timeout(precheck_timeout(),gates::admission_allowed(exec,None)).await.ok()?
        || tokio::time::timeout(precheck_timeout(),push::revoked(exec,&identity)).await.ok()? {
        return None;
    }
    identity.user_authorization()
}

/// Drive user domains retain scope containment and also accept mailbox-less guests.
pub async fn authorize_drive_user_request(exec:&ScopedExecutor,keys:&impl KeySource,
    issuer:&str,headers:&HeaderMap,scheme:&str,path:&str)->Option<Authorized>{
    let drive=path=="/drive"||path.starts_with("/drive/")||path=="/api/drive"||path.starts_with("/api/drive/");
    if !drive{return authorize_user_request(exec,keys,issuer,headers,scheme).await;}
    let token=token::presented(headers)?;
    let identity=tokio::time::timeout(precheck_timeout(),push::authenticate_drive(exec,keys,issuer,&token)).await.ok()?.ok()?;
    if !identity.is_guest(){return authorize_drive_request(exec,keys,issuer,headers,scheme,path).await;}
    if !tokio::time::timeout(precheck_timeout(),gates::admission_allowed(exec,None)).await.ok()?
        || tokio::time::timeout(precheck_timeout(),push::revoked(exec,&identity)).await.ok()? {
        return None;
    }
    identity.user_authorization()
}

impl AuthContext {
    /// Frozen Go resolves governed grants for signed admins on every request;
    /// non-admin signed permissions retain Go's claim semantics.
    pub async fn has_permission(&self,exec:&ScopedExecutor,permission:&str)
        ->Result<bool,setjoin_pg::StatementFailure>{
        if !self.admin{return Ok(self.permissions.iter().any(|p|p==permission));}
        let rows=exec.read("SELECT EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$1 AND $2=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until))",
            &[(&self.user_id,setjoin_pg::Type::INT8),(&permission,setjoin_pg::Type::TEXT)]).await?;
        Ok(rows[0].get(0))
    }
}

pub mod policy;
