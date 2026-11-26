//! Unified 11-surface `PolicyGate` admission seam (#542).
//!
//! Enforces fixed zero-DB-first gate ordering across every user-facing
//! protocol surface in `bins/gateway` and protocol listeners:
//!
//! 0. **Zero-DB cheap rejection:** TLS/STARTTLS & protocol syntax/framing,
//!    atomic `Chain::basic_allowed()` / `Chain::kerberos_allowed()`, CSRF/Origin
//!    on HTTP/JMAP unsafe methods + `DriveNativeToken` + `WebSocket` +
//!    cookie-`Sse` (preserving `#491` CSRF-before-over-budget), and in-memory
//!    `EdgeLimiter`.
//! 1. **Pure crypto / claim verification:** JWT (`Bearer` / cookie) or narrow
//!    HS256+HKDF `AttachmentTransfer` signature, `typ`, `iss`, `aud`, `exp`,
//!    `nbf`, `scp` (zero DB for warm JWKS).
//! 2. **Threat / IP / Lockout + Credential Proof:**
//!    - Two-phase `ThreatAdapter` for Kerberos `Negotiate` (`intercept(&ip_meta)`
//!      -> SPNEGO verify -> principal lookup -> `check_account_lockout(&user_meta)`).
//!    - Single-phase `ThreatAdapter` + constant-time `basic::verify` for
//!      `Imap` / `SmtpSubmission` / `Ldap` / DAV `Basic`.
//! 3. **Live Guest Belt:** live `guest_account_status($1)` overrides JWT `acct`.
//! 4. **Revocation & CAE:** in-memory `DenylistView` + durable
//!    `session_revocations`; cold/unloaded denylist fails closed when
//!    `feature.cae_runtime = true` (staying compatible with `denylist: None`
//!    harnesses when `cae_runtime = false`).
//! 5. **DPoP & `sif`** (JWT surfaces).
//! 6. **Device Trust & Lockdown** (all surfaces unless break-glass;
//!    `device_bound = false` on IMAP/SMTP/LDAP/Basic/Negotiate).
//! 7. **Conditional Access:** `policy::eval::Engine` using shared
//!    [`GroupResolver`] + live JIT-filtered `admin_role_assignments`; `step_up`
//!    rejected on non-HTTP/WS surfaces.
//! 8. **Entitlements & Mailbox Lifecycle:** `check_user_app_entitlement` +
//!    `mailbox_lifecycle_access_allowed`.
//! 9. **Sealed Principal Minting:** [`GateAdmission`] mints [`UserPrincipal`],
//!    [`MailboxPrincipal`], or [`AdminPrincipal`] via [`TxFactory`].

use crate::{
    auth_chain::Chain,
    basic::{self, Accept, GuestAppPasswords, PasswordCache, Policy, TotpAccountPassword, Verdict},
    csrf,
    device::{DeviceRequest, DeviceResolver},
    dpop,
    geoip::CountryDb,
    groups::GroupResolver,
    kerberos::{self, KerberosValidator, PrincipalLookup},
    policy::{
        eval::{text, Context as PolicyContext, Engine},
        store,
    },
    principals::{
        AdminPrincipal, AuditMeta, MailboxPrincipal, PrincipalError, TxFactory, UserPrincipal,
    },
    runtime::Proof,
    token::{self, KeySource},
};
use hyper::HeaderMap;
use serde_json::{Map, Value};
use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
use setjoin_pg::{ScopedExecutor, Type};
use std::{
    collections::BTreeSet,
    fmt,
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Sentinel `iat` used for password / Basic / Kerberos / protocol sessions
/// without a JWT `iat` (matches Go's zero `time.Time` and `authorize_basic_member`).
pub const SENTINEL_NON_JWT_IAT: i64 = -62_135_596_800;

// ---------------------------------------------------------------------------
// Exhaustive 11-variant ProtocolSurface (no wildcards)
// ---------------------------------------------------------------------------

/// Every user-facing protocol surface governed by [`PolicyGate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProtocolSurface {
    Http,
    Jmap,
    CalDav,
    CardDav,
    DriveNativeToken,
    AttachmentTransfer,
    WebSocket,
    Sse,
    Imap,
    SmtpSubmission,
    Ldap,
}

impl ProtocolSurface {
    /// Complete list of all 11 protocol surfaces for exhaustive matrix tests.
    pub const ALL: [ProtocolSurface; 11] = [
        Self::Http,
        Self::Jmap,
        Self::CalDav,
        Self::CardDav,
        Self::DriveNativeToken,
        Self::AttachmentTransfer,
        Self::WebSocket,
        Self::Sse,
        Self::Imap,
        Self::SmtpSubmission,
        Self::Ldap,
    ];

    /// Protocol label passed into Conditional Access and ThreatGate.
    pub const fn protocol_name(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Jmap => "http",
            Self::CalDav => "caldav",
            Self::CardDav => "carddav",
            Self::DriveNativeToken => "http",
            Self::AttachmentTransfer => "http",
            Self::WebSocket => "websocket",
            Self::Sse => "sse",
            Self::Imap => "imap",
            Self::SmtpSubmission => "smtp",
            Self::Ldap => "ldap",
        }
    }

    /// Default app entitlement required on this surface (`None` means route/channel-owned).
    pub const fn default_app_entitlement(self) -> Option<&'static str> {
        match self {
            Self::Http => None,
            Self::Jmap => Some("mail"),
            Self::CalDav => Some("calendar"),
            Self::CardDav => Some("contacts"),
            Self::DriveNativeToken => Some("drive"),
            Self::AttachmentTransfer => Some("mail"),
            Self::WebSocket => Some("mail"),
            Self::Sse => None,
            Self::Imap => Some("mail"),
            Self::SmtpSubmission => Some("mail"),
            Self::Ldap => None,
        }
    }

    /// Whether active guests may ever be admitted on this surface.
    pub const fn allows_guest(self) -> bool {
        match self {
            Self::Http | Self::Sse => true,
            Self::Jmap
            | Self::CalDav
            | Self::CardDav
            | Self::DriveNativeToken
            | Self::AttachmentTransfer
            | Self::WebSocket
            | Self::Imap
            | Self::SmtpSubmission
            | Self::Ldap => false,
        }
    }

    /// Whether unsafe HTTP methods / browser handshakes enforce CSRF/Origin on this surface.
    pub const fn enforces_http_csrf_or_origin(self) -> bool {
        match self {
            Self::Http | Self::Jmap | Self::DriveNativeToken | Self::WebSocket | Self::Sse => true,
            Self::CalDav
            | Self::CardDav
            | Self::AttachmentTransfer
            | Self::Imap
            | Self::SmtpSubmission
            | Self::Ldap => false,
        }
    }

    /// Whether this surface enforces the in-memory edge rate limiter.
    pub const fn enforces_edge_limit(self) -> bool {
        match self {
            Self::Http | Self::Jmap | Self::WebSocket | Self::Sse => true,
            Self::CalDav
            | Self::CardDav
            | Self::DriveNativeToken
            | Self::AttachmentTransfer
            | Self::Imap
            | Self::SmtpSubmission
            | Self::Ldap => false,
        }
    }

    /// Whether a primary mailbox (with `mailbox_lifecycle_access_allowed`) is required.
    pub const fn requires_primary_mailbox(self) -> bool {
        match self {
            Self::Jmap
            | Self::CalDav
            | Self::CardDav
            | Self::AttachmentTransfer
            | Self::WebSocket
            | Self::Imap
            | Self::SmtpSubmission => true,
            Self::Http | Self::DriveNativeToken | Self::Sse | Self::Ldap => false,
        }
    }

    /// Whether Conditional Access `step_up` yields a reauth challenge instead of a hard block.
    pub const fn allows_step_up(self) -> bool {
        match self {
            Self::Http | Self::Jmap | Self::WebSocket => true,
            Self::CalDav
            | Self::CardDav
            | Self::DriveNativeToken
            | Self::AttachmentTransfer
            | Self::Sse
            | Self::Imap
            | Self::SmtpSubmission
            | Self::Ldap => false,
        }
    }

    /// Whether a device-bound JWT (`device` claim present) is permitted on this surface.
    pub const fn allows_device_bound_session(self) -> bool {
        match self {
            Self::DriveNativeToken => false,
            Self::Http
            | Self::Jmap
            | Self::CalDav
            | Self::CardDav
            | Self::AttachmentTransfer
            | Self::WebSocket
            | Self::Sse
            | Self::Imap
            | Self::SmtpSubmission
            | Self::Ldap => true,
        }
    }

    /// Explicit password policy for surfaces accepting Basic / protocol passwords.
    pub const fn basic_policy(self) -> Option<Policy> {
        match self {
            Self::CalDav | Self::CardDav | Self::DriveNativeToken => Some(basic::DAV_POLICY),
            Self::Imap | Self::SmtpSubmission => Some(Policy {
                accept: Accept::AppPasswordThenAccountPassword,
                guest_app_passwords: GuestAppPasswords::Refuse,
                totp_account_password: TotpAccountPassword::Refuse,
            }),
            Self::Ldap => Some(Policy {
                accept: Accept::AccountPassword,
                guest_app_passwords: GuestAppPasswords::Refuse,
                totp_account_password: TotpAccountPassword::Refuse,
            }),
            Self::Http | Self::Jmap | Self::AttachmentTransfer | Self::WebSocket | Self::Sse => {
                None
            }
        }
    }

    /// Whether `scp=drive` JWTs are accepted on this surface.
    pub const fn allows_drive_scope(self) -> bool {
        match self {
            Self::DriveNativeToken => true,
            Self::Http
            | Self::Jmap
            | Self::CalDav
            | Self::CardDav
            | Self::AttachmentTransfer
            | Self::WebSocket
            | Self::Sse
            | Self::Imap
            | Self::SmtpSubmission
            | Self::Ldap => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Zero-cycle adapter traits for gateway / threat / denylist
// ---------------------------------------------------------------------------

/// In-memory edge rate limiter (Stage 0).
pub trait EdgeLimiter: Send + Sync {
    fn allow(&self, client_ip: &str, surface: ProtocolSurface) -> bool;
}

/// In-memory `SessionDenylist` view (Stage 4).
pub trait DenylistView: Send + Sync {
    fn loaded(&self) -> bool;
    fn is_revoked(&self, user_id: i64, jti: &str, family: &str, issued_at: i64) -> bool;
}

/// Device revocation cache view (Stage 6).
pub trait DeviceRevocationView: Send + Sync {
    fn is_device_revoked<'a>(&'a self, device_id: &'a str) -> BoxFuture<'a, bool>;
}

/// HTTP guest allowlist matcher (Stage 3).
pub trait GuestAllowlist: Send + Sync {
    fn allows(&self, method: &str, path: &str) -> bool;
}

/// Normalized ThreatGate verdict (avoids cyclic dep on `setjoin-threat`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateThreatAction {
    Allow,
    Reject,
    Tarpitted,
    RateLimited,
}

/// Metadata passed to [`ThreatAdapter`].
#[derive(Clone, Debug, Default)]
pub struct GateThreatMeta {
    pub source_ip: String,
    pub username: String,
    pub protocol: String,
    pub user_agent: String,
    pub user_id: i64,
    pub app_password: bool,
    pub device_bound: bool,
}

/// Adapter trait implemented by gateway/protocol callers wrapping `setjoin_threat::ThreatGate`.
pub trait ThreatAdapter: Send + Sync {
    fn intercept<'a>(
        &'a self,
        meta: &'a GateThreatMeta,
    ) -> BoxFuture<'a, (GateThreatAction, Duration)>;

    /// Phase-2 targeted account lockout check for Kerberos Negotiate (no double rate-limit burn).
    fn check_account_lockout<'a>(
        &'a self,
        meta: &'a GateThreatMeta,
    ) -> BoxFuture<'a, (GateThreatAction, Duration)>;

    fn record_result<'a>(
        &'a self,
        meta: &'a GateThreatMeta,
        success: bool,
        user_id: i64,
    ) -> BoxFuture<'a, ()>;

    fn record_ip_failure<'a>(&'a self, meta: &'a GateThreatMeta) -> BoxFuture<'a, ()>;

    fn evaluate_post_auth<'a>(
        &'a self,
        meta: &'a mut GateThreatMeta,
    ) -> BoxFuture<'a, (GateThreatAction, String)>;
}

// ---------------------------------------------------------------------------
// Request / Credential Inputs and Typed Denials
// ---------------------------------------------------------------------------

/// Presented credential shape for [`PolicyGate::admit`].
pub enum GateCredential<'a> {
    /// HTTP/JMAP/SSE/WS JWT token with explicit source marker (`from_cookie`).
    Jwt { token: &'a str, from_cookie: bool },
    /// Narrow HS256+HKDF attachment download/transfer token.
    AttachmentToken(&'a str),
    /// Username/email + password (DAV Basic, IMAP, SMTP submission, LDAP).
    Password {
        email: &'a str,
        secret: &'a str,
        /// Test-only switch for `smtp-no-dummy-hash` mutant harness (default `true`).
        run_dummy_hash: bool,
    },
    /// HTTP `Authorization: Negotiate <spnego>` (CalDAV/CardDAV/DriveNativeToken).
    Negotiate { headers: &'a HeaderMap },
}

/// Normalized request envelope presented to [`PolicyGate::admit`].
pub struct GateRequest<'a> {
    pub surface: ProtocolSurface,
    pub credential: GateCredential<'a>,
    pub client_ip: IpAddr,
    pub user_agent: &'a str,
    pub scheme: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub headers: Option<&'a HeaderMap>,
    pub body: &'a [u8],
    /// Whether transport encryption (TLS / STARTTLS) is active.
    pub tls_active: bool,
    /// Whether surface requires TLS before authentication.
    pub require_tls: bool,
    /// Production mode flag for strict WebSocket/cookie-SSE Origin enforcement.
    pub production: bool,
    /// Optional extra allowed origin host (WS/SSE).
    pub allowed_origin_host: &'a str,
    /// Optional explicit app entitlement override (e.g. `"drive"`, `"chat"`, `"meet"` on `Http`).
    pub required_app: Option<&'a str>,
    /// Whether `scp=drive` is permitted on this `Http` request path.
    pub drive_path: bool,
    /// Optional explicit `now` timestamp (defaults to `SystemTime::now()`).
    pub now_secs: Option<f64>,
}

/// Typed admission denial returned by [`PolicyGate`] so each protocol adapter
/// renders its exact wire reply and expected `auth_event_log` rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateDenial {
    /// Stage 0: TLS/STARTTLS required before authentication.
    TlsRequired,
    /// Stage 0: Protocol/header syntax invalid.
    MalformedSyntax(&'static str),
    /// Stage 0: Basic or Kerberos disabled by `auth_chain`.
    AuthMethodDisabled(&'static str),
    /// Stage 0: CSRF or Origin check failed (`#491` CSRF-before-over-budget).
    CsrfOrOriginRejected,
    /// Stage 0: In-memory edge rate limit exceeded.
    EdgeRateLimited,
    /// Stage 1: Missing, malformed, expired, or wrong-scope token/credential.
    InvalidCredential,
    /// Stage 1: Device-bound session refused (e.g. `DriveNativeToken`).
    DeviceBoundRefused,
    /// Stage 2: ThreatGate rejected or tarpitted the attempt.
    ThreatRejected { delay: Duration },
    /// Stage 2: ThreatGate rate-limited the attempt.
    ThreatRateLimited,
    /// Stage 2: Kerberos SPNEGO parsing/validation failed (already audited + IP failure recorded).
    SpnegoFailed,
    /// Stage 2: TOTP account-password or Kerberos-with-TOTP refused.
    TotpRefused,
    /// Stage 3: Live guest row is inactive/expired or JWT claimed guest without active row.
    GuestInactive,
    /// Stage 3: Active guest refused on this surface (e.g. JMAP/DAV/WS/IMAP/SMTP/LDAP).
    GuestRefused,
    /// Stage 3: `feature.guest_accounts` OFF or route not in `guest_allowlist` (404).
    GuestNotFound,
    /// Stage 4: Session revoked (in-memory denylist or durable `session_revocations`).
    SessionRevoked,
    /// Stage 4: `feature.cae_runtime = true` and `DenylistView` is absent or cold/unloaded.
    DenylistUnavailable,
    /// Stage 5: DPoP proof missing, replayed, or thumbprint mismatch.
    TokenBindingFailed,
    /// Stage 5: `sif` (sign-in frequency) window exceeded.
    SignInFrequencyExpired,
    /// Stage 6: Device compliance failure (`device_compliance_unverifiable`, wiped, quarantined).
    DeviceComplianceFailed {
        title: &'static str,
        detail: &'static str,
    },
    /// Stage 6: Device revoked.
    DeviceRevoked,
    /// Stage 6: `feature.device_lockdown` active and caller is not break-glass with an approved bound device (`BZ095`).
    DeviceLockdown,
    /// Stage 7: Conditional Access policy blocked access.
    PolicyBlocked {
        reason: String,
        remediation: String,
        terms_id: i64,
        correlation_id: Option<String>,
    },
    /// Stage 7: Conditional Access requires step-up authentication (HTTP/JMAP/WS only).
    StepUpRequired {
        reason: String,
        correlation_id: Option<String>,
    },
    /// Stage 8: App entitlement denied (`check_user_app_entitlement` returned false).
    EntitlementDenied(String),
    /// Stage 8: No primary mailbox exists for a surface that requires one.
    NoPrimaryMailbox,
    /// Stage 8: Primary mailbox blocked by `mailbox_lifecycle_access_allowed`.
    MailboxBlocked,
    /// Fail-closed database or dependency unavailability (`503`).
    Unavailable(String),
}

impl fmt::Display for GateDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for GateDenial {}

/// Verified authentication method produced by Stage 1/2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthKind {
    JwtBearer,
    AttachmentToken,
    AppPassword,
    AccountPassword,
    Kerberos,
}

impl AuthKind {
    pub const fn as_ca_method(self) -> &'static str {
        match self {
            Self::JwtBearer | Self::AttachmentToken => "jwt_bearer",
            Self::AppPassword | Self::AccountPassword => "basic_auth",
            Self::Kerberos => "kerberos",
        }
    }
}

// ---------------------------------------------------------------------------
// Sealed GateAdmission (pub(crate) constructor — only minted by PolicyGate)
// ---------------------------------------------------------------------------

/// Sealed admission token produced exclusively by [`PolicyGate::admit`].
///
/// External crates cannot construct `GateAdmission`; they pass it to
/// [`Self::mint_user`], [`Self::mint_mailbox`], [`Self::mint_primary_mailbox`],
/// or [`Self::mint_admin`] together with [`TxFactory`] to obtain capability-gated
/// principals.
#[derive(Clone, Debug)]
pub struct GateAdmission {
    surface: ProtocolSurface,
    auth_kind: AuthKind,
    actor: ActorId,
    email: String,
    is_guest: bool,
    primary_mailbox: Option<MailboxId>,
    mailbox_blocked: bool,
    issued_at: i64,
    expires_at: Option<i64>,
    token_id: String,
    token_family: String,
    device_id: String,
    impersonator: Option<ActorId>,
    entitlements: BTreeSet<String>,
    audit_meta: AuditMeta,
    generation: Generation,
}

impl GateAdmission {
    pub const fn surface(&self) -> ProtocolSurface {
        self.surface
    }

    pub const fn auth_kind(&self) -> AuthKind {
        self.auth_kind
    }

    pub const fn actor(&self) -> ActorId {
        self.actor
    }

    pub const fn user_id(&self) -> i64 {
        self.actor.get()
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub const fn is_guest(&self) -> bool {
        self.is_guest
    }

    pub const fn primary_mailbox(&self) -> Option<MailboxId> {
        self.primary_mailbox
    }

    pub const fn mailbox_blocked(&self) -> bool {
        self.mailbox_blocked
    }

    pub const fn issued_at(&self) -> i64 {
        self.issued_at
    }

    pub const fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }

    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    pub fn token_family(&self) -> &str {
        &self.token_family
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub const fn impersonator(&self) -> Option<ActorId> {
        self.impersonator
    }

    pub fn audit_meta(&self) -> &AuditMeta {
        &self.audit_meta
    }

    /// Mint a sealed mailbox-less [`UserPrincipal`].
    pub async fn mint_user(&self, factory: &TxFactory) -> Result<UserPrincipal, PrincipalError> {
        factory
            .mint_user_principal(
                self.actor,
                self.is_guest,
                self.generation,
                self.impersonator,
                self.entitlements.clone(),
                self.audit_meta.clone(),
            )
            .await
    }

    /// Mint a sealed [`MailboxPrincipal`] for an explicit target mailbox (owner or delegate).
    pub async fn mint_mailbox(
        &self,
        factory: &TxFactory,
        target_mailbox: MailboxId,
    ) -> Result<MailboxPrincipal, PrincipalError> {
        factory
            .mint_mailbox_principal(
                self.actor,
                target_mailbox,
                self.is_guest,
                self.generation,
                self.impersonator,
                self.audit_meta.clone(),
            )
            .await
    }

    /// Mint a sealed [`MailboxPrincipal`] for the caller's own primary mailbox.
    pub async fn mint_primary_mailbox(
        &self,
        factory: &TxFactory,
    ) -> Result<MailboxPrincipal, PrincipalError> {
        let mailbox = self
            .primary_mailbox
            .ok_or(PrincipalError::Forbidden("no primary mailbox"))?;
        self.mint_mailbox(factory, mailbox).await
    }

    /// Mint a sealed [`AdminPrincipal`] via a live JIT/SoD-enforced DB query.
    pub async fn mint_admin(&self, factory: &TxFactory) -> Result<AdminPrincipal, PrincipalError> {
        factory
            .mint_admin_principal(
                self.actor,
                self.is_guest,
                self.generation,
                self.impersonator,
                self.audit_meta.clone(),
            )
            .await
    }
}

// ---------------------------------------------------------------------------
// PolicyGate
// ---------------------------------------------------------------------------

struct RuntimeFlags {
    cae_runtime: bool,
    conditional_access: bool,
    device_trust_enforcement: bool,
    device_lockdown: bool,
    token_binding: bool,
    guest_accounts: bool,
    registry_ready: bool,
}

/// Unified multi-protocol admission gate.
pub struct PolicyGate<K: KeySource + 'static> {
    exec: ScopedExecutor,
    keys: Arc<K>,
    issuer: String,
    groups: Arc<GroupResolver>,
    engine: Arc<Engine>,
    passwords: Arc<PasswordCache>,
    chain: Option<Arc<Chain>>,
    kerberos: Option<Arc<dyn KerberosValidator>>,
    threat: Option<Arc<dyn ThreatAdapter>>,
    denylist: Option<Arc<dyn DenylistView>>,
    edge_limiter: Option<Arc<dyn EdgeLimiter>>,
    device_revocation: Option<Arc<dyn DeviceRevocationView>>,
    device_resolver: Option<Arc<DeviceResolver>>,
    guest_allowlist: Option<Arc<dyn GuestAllowlist>>,
    attachment_secrets: Vec<Vec<u8>>,
    replay: Arc<dpop::ReplayCache>,
    geo: Option<Arc<CountryDb>>,
}

impl<K: KeySource + 'static> PolicyGate<K> {
    pub fn new(exec: ScopedExecutor, keys: Arc<K>, issuer: impl Into<String>) -> Self {
        let groups = Arc::new(GroupResolver::from_executor(exec.clone()));
        let engine = Arc::new(Engine::with_group_resolver(exec.clone(), groups.clone()));
        Self {
            exec,
            keys,
            issuer: issuer.into(),
            groups,
            engine,
            passwords: Arc::new(PasswordCache::new()),
            chain: None,
            kerberos: None,
            threat: None,
            denylist: None,
            edge_limiter: None,
            device_revocation: None,
            device_resolver: None,
            guest_allowlist: None,
            attachment_secrets: Vec::new(),
            replay: Arc::new(dpop::ReplayCache::default()),
            geo: None,
        }
    }

    pub fn with_group_resolver(mut self, groups: Arc<GroupResolver>) -> Self {
        self.engine = Arc::new(Engine::with_group_resolver(
            self.exec.clone(),
            groups.clone(),
        ));
        self.groups = groups;
        self
    }

    pub fn with_engine(mut self, engine: Arc<Engine>) -> Self {
        self.groups = engine.group_resolver().clone();
        self.engine = engine;
        self
    }

    pub fn with_password_cache(mut self, passwords: Arc<PasswordCache>) -> Self {
        self.passwords = passwords;
        self
    }

    pub fn with_auth_chain(mut self, chain: Arc<Chain>) -> Self {
        self.chain = Some(chain);
        self
    }

    pub fn with_kerberos(mut self, validator: Arc<dyn KerberosValidator>) -> Self {
        self.kerberos = Some(validator);
        self
    }

    pub fn with_threat(mut self, threat: Arc<dyn ThreatAdapter>) -> Self {
        self.threat = Some(threat);
        self
    }

    pub fn with_denylist(mut self, denylist: Arc<dyn DenylistView>) -> Self {
        self.denylist = Some(denylist);
        self
    }

    pub fn with_edge_limiter(mut self, limiter: Arc<dyn EdgeLimiter>) -> Self {
        self.edge_limiter = Some(limiter);
        self
    }

    pub fn with_device_revocation(mut self, view: Arc<dyn DeviceRevocationView>) -> Self {
        self.device_revocation = Some(view);
        self
    }

    pub fn with_device_resolver(mut self, resolver: Arc<DeviceResolver>) -> Self {
        self.device_resolver = Some(resolver);
        self
    }

    pub fn with_guest_allowlist(mut self, allowlist: Arc<dyn GuestAllowlist>) -> Self {
        self.guest_allowlist = Some(allowlist);
        self
    }

    pub fn with_attachment_secrets(mut self, secrets: Vec<Vec<u8>>) -> Self {
        self.attachment_secrets = secrets;
        self
    }

    pub fn with_geo(mut self, geo: Arc<CountryDb>) -> Self {
        self.geo = Some(geo);
        self
    }

    pub fn group_resolver(&self) -> &Arc<GroupResolver> {
        &self.groups
    }

    pub fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }

    pub fn password_cache(&self) -> &Arc<PasswordCache> {
        &self.passwords
    }

    /// Execute the full 9-stage zero-DB-first admission pipeline.
    pub async fn admit(&self, req: &GateRequest<'_>) -> Result<GateAdmission, GateDenial> {
        // ── Stage 0: Zero-DB cheap rejection ─────────────────────────────────
        if req.require_tls && !req.tls_active {
            return Err(GateDenial::TlsRequired);
        }

        // Atomic auth_chain checks before any DB or ThreatGate I/O.
        match &req.credential {
            GateCredential::Password { .. } => {
                if matches!(
                    req.surface,
                    ProtocolSurface::CalDav
                        | ProtocolSurface::CardDav
                        | ProtocolSurface::DriveNativeToken
                ) && !self.chain.as_ref().is_none_or(|c| c.basic_allowed())
                {
                    return Err(GateDenial::AuthMethodDisabled("basic"));
                }
            }
            GateCredential::Negotiate { headers } => {
                let has_negotiate = headers
                    .get(hyper::header::AUTHORIZATION)
                    .is_some_and(|v| v.as_bytes().starts_with(b"Negotiate "));
                if !has_negotiate {
                    return Err(GateDenial::MalformedSyntax("missing Negotiate header"));
                }
                if !self.chain.as_ref().is_some_and(|c| c.kerberos_allowed()) {
                    return Err(GateDenial::AuthMethodDisabled("kerberos"));
                }
                if self.kerberos.is_none() {
                    return Err(GateDenial::AuthMethodDisabled("kerberos"));
                }
            }
            GateCredential::Jwt { .. } | GateCredential::AttachmentToken(_) => {}
        }

        // CSRF / Origin check BEFORE EdgeLimiter and DB (#491 CSRF-before-over-budget).
        self.check_stage0_csrf_and_origin(req)?;

        // In-memory EdgeLimiter (Stage 0).
        if req.surface.enforces_edge_limit() {
            if let Some(limiter) = &self.edge_limiter {
                let ip = req.client_ip.to_string();
                if !limiter.allow(&ip, req.surface) {
                    return Err(GateDenial::EdgeRateLimited);
                }
            }
        }

        let now = match req.now_secs {
            Some(ts) => ts,
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| GateDenial::Unavailable(e.to_string()))?
                .as_secs_f64(),
        };

        // ── Stage 1 + Stage 2: Crypto / Claim Verification + ThreatGate / Proof ──
        let verified = self.verify_credential(req, now).await?;

        // ── Read runtime feature flags once ──────────────────────────────────
        let flags = self.read_runtime_flags().await?;

        // ── Stage 3: Live Guest Belt ─────────────────────────────────────────
        let is_guest = self
            .check_guest_belt(req, verified.user_id, verified.claimed_guest, &flags)
            .await?;

        // ── Stage 4: Revocation & CAE ────────────────────────────────────────
        self.check_revocation_and_cae(
            verified.user_id,
            &verified.jti,
            &verified.family,
            verified.issued_at,
            flags.cae_runtime,
        )
        .await?;

        // ── Stage 5: DPoP & `sif` (JWT surfaces) ─────────────────────────────
        if matches!(verified.auth_kind, AuthKind::JwtBearer) && flags.cae_runtime {
            self.check_dpop_and_sif(req, &verified.claims, verified.raw_bearer, now, &flags)?;
        }

        // ── Stage 6: Device Trust & Lockdown ─────────────────────────────────
        self.check_device_trust_and_lockdown(req, &verified, &flags)
            .await?;

        // ── Stage 7: Conditional Access (shared GroupResolver + live JIT) ────
        if flags.conditional_access && !is_guest {
            self.check_conditional_access(req, &verified, now).await?;
        }

        // ── Stage 8: App Entitlements & Mailbox Lifecycle ────────────────────
        let mut entitlements = BTreeSet::new();
        let app_to_check = req
            .required_app
            .or_else(|| req.surface.default_app_entitlement());
        if let Some(app) = app_to_check {
            let allowed = check_app_entitlement(&self.exec, verified.user_id, app).await?;
            if !allowed {
                return Err(GateDenial::EntitlementDenied(app.to_owned()));
            }
            entitlements.insert(app.to_owned());
        }

        let (primary_mailbox, mailbox_blocked) = if is_guest {
            (None, false)
        } else {
            let mb = lookup_primary_mailbox_lifecycle(&self.exec, verified.user_id).await?;
            match mb {
                Some((id, true)) => (MailboxId::new(id).ok(), false),
                Some((id, false)) => {
                    if req.surface.requires_primary_mailbox() {
                        return Err(GateDenial::MailboxBlocked);
                    }
                    (MailboxId::new(id).ok(), true)
                }
                None => {
                    if req.surface.requires_primary_mailbox() {
                        return Err(GateDenial::NoPrimaryMailbox);
                    }
                    (None, false)
                }
            }
        };

        // ── Stage 9: Construct sealed GateAdmission ──────────────────────────
        let actor = ActorId::new(verified.user_id).map_err(|_| GateDenial::InvalidCredential)?;
        let mut audit_meta = AuditMeta::new(verified.email.clone(), req.client_ip.to_string());
        audit_meta.user_agent = req.user_agent.to_owned();
        audit_meta.auth_method = verified.auth_kind.as_ca_method().to_owned();
        audit_meta.auth_time = verified.auth_time;

        Ok(GateAdmission {
            surface: req.surface,
            auth_kind: verified.auth_kind,
            actor,
            email: verified.email,
            is_guest,
            primary_mailbox,
            mailbox_blocked,
            issued_at: verified.issued_at,
            expires_at: verified.expires_at,
            token_id: verified.jti,
            token_family: verified.family,
            device_id: verified.device_id,
            impersonator: verified.impersonator,
            entitlements,
            audit_meta,
            generation: Generation(1),
        })
    }

    /// Revalidate a live long-lived WebSocket / SSE session (per-frame or periodic).
    ///
    /// Checks token expiration, in-memory + durable revocations, device revocation,
    /// mailbox lifecycle (for non-guests), and any subscribed app entitlements.
    pub async fn revalidate_push_session(
        &self,
        admission: &GateAdmission,
        subscribed_apps: &[&str],
        now_secs: i64,
    ) -> Result<(), GateDenial> {
        if let Some(exp) = admission.expires_at {
            if now_secs >= exp {
                return Err(GateDenial::SessionRevoked);
            }
        }
        let flags = self.read_runtime_flags().await?;
        self.check_revocation_and_cae(
            admission.user_id(),
            admission.token_id(),
            admission.token_family(),
            admission.issued_at(),
            flags.cae_runtime,
        )
        .await?;
        if !admission.device_id.is_empty() {
            if let Some(view) = &self.device_revocation {
                if view.is_device_revoked(&admission.device_id).await {
                    return Err(GateDenial::DeviceRevoked);
                }
            }
        }
        if !admission.is_guest {
            if let Some(mb) = admission.primary_mailbox {
                let allowed = check_mailbox_lifecycle(&self.exec, mb.get()).await?;
                if !allowed {
                    return Err(GateDenial::MailboxBlocked);
                }
            }
        }
        for app in subscribed_apps {
            if !check_app_entitlement(&self.exec, admission.user_id(), app).await? {
                return Err(GateDenial::EntitlementDenied((*app).to_owned()));
            }
        }
        Ok(())
    }

    fn check_stage0_csrf_and_origin(&self, req: &GateRequest<'_>) -> Result<(), GateDenial> {
        match req.surface {
            ProtocolSurface::Http | ProtocolSurface::Jmap => {
                if is_unsafe_http_method(req.method) {
                    let Some(headers) = req.headers else {
                        return Err(GateDenial::CsrfOrOriginRejected);
                    };
                    if !csrf::allows(headers, req.scheme) {
                        return Err(GateDenial::CsrfOrOriginRejected);
                    }
                }
            }
            ProtocolSurface::DriveNativeToken => {
                let Some(headers) = req.headers else {
                    return Err(GateDenial::CsrfOrOriginRejected);
                };
                if !csrf::allows(headers, req.scheme) {
                    return Err(GateDenial::CsrfOrOriginRejected);
                }
            }
            ProtocolSurface::WebSocket => {
                let Some(headers) = req.headers else {
                    return Err(GateDenial::CsrfOrOriginRejected);
                };
                if !ws_origin_allowed(headers, req.production, req.allowed_origin_host) {
                    return Err(GateDenial::CsrfOrOriginRejected);
                }
            }
            ProtocolSurface::Sse => {
                let from_cookie = matches!(
                    req.credential,
                    GateCredential::Jwt {
                        from_cookie: true,
                        ..
                    }
                );
                if from_cookie {
                    let Some(headers) = req.headers else {
                        return Err(GateDenial::CsrfOrOriginRejected);
                    };
                    if !ws_origin_allowed(headers, req.production, req.allowed_origin_host) {
                        return Err(GateDenial::CsrfOrOriginRejected);
                    }
                }
            }
            ProtocolSurface::CalDav
            | ProtocolSurface::CardDav
            | ProtocolSurface::AttachmentTransfer
            | ProtocolSurface::Imap
            | ProtocolSurface::SmtpSubmission
            | ProtocolSurface::Ldap => {}
        }
        Ok(())
    }

    async fn verify_credential<'a>(
        &self,
        req: &GateRequest<'a>,
        now: f64,
    ) -> Result<VerifiedStep<'a>, GateDenial> {
        match &req.credential {
            GateCredential::Jwt { token, from_cookie } => {
                // WebSocket accepts cookie access_token ONLY (never Bearer header).
                if req.surface == ProtocolSurface::WebSocket && !*from_cookie {
                    return Err(GateDenial::InvalidCredential);
                }
                let claims = tokio::time::timeout(
                    crate::precheck_timeout(),
                    token::decoded_claims(token, &*self.keys),
                )
                .await
                .map_err(|_| GateDenial::Unavailable("jwks verification timed out".into()))?
                .ok_or(GateDenial::InvalidCredential)?;

                token::claims_shape_ok(&claims).ok_or(GateDenial::InvalidCredential)?;
                let str_claim = |k: &str| claims.get(k).and_then(Value::as_str).unwrap_or("");
                if self.issuer.is_empty()
                    || str_claim("iss") != self.issuer
                    || str_claim("typ") != "access"
                {
                    return Err(GateDenial::InvalidCredential);
                }
                let aud_ok = claims.get("aud").is_some_and(|aud| {
                    aud.as_str() == Some(token::AUDIENCE)
                        || aud
                            .as_array()
                            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(token::AUDIENCE)))
                });
                if !aud_ok {
                    return Err(GateDenial::InvalidCredential);
                }
                let exp = claims
                    .get("exp")
                    .and_then(Value::as_i64)
                    .ok_or(GateDenial::InvalidCredential)?;
                if crate::numeric_date::expired(now, exp) {
                    return Err(GateDenial::InvalidCredential);
                }
                if let Some(nbf_val) = claims.get("nbf").filter(|v| !v.is_null()) {
                    let nbf = nbf_val.as_i64().ok_or(GateDenial::InvalidCredential)?;
                    if crate::numeric_date::not_yet_valid(now, nbf) {
                        return Err(GateDenial::InvalidCredential);
                    }
                }
                let scope = str_claim("scp");
                let drive_allowed = req.drive_path || req.surface.allows_drive_scope();
                if !scope.is_empty() && !(drive_allowed && scope == "drive") {
                    return Err(GateDenial::InvalidCredential);
                }
                if !req.surface.allows_device_bound_session()
                    && claims.get("device").is_some_and(|v| !v.is_null())
                {
                    return Err(GateDenial::DeviceBoundRefused);
                }
                let user_id = claims
                    .get("uid")
                    .and_then(Value::as_i64)
                    .filter(|&id| id > 0)
                    .ok_or(GateDenial::InvalidCredential)?;
                let impersonator = match token::actor_id_from(&claims) {
                    Ok(Some(id)) => {
                        Some(ActorId::new(id).map_err(|_| GateDenial::InvalidCredential)?)
                    }
                    Ok(None) => None,
                    Err(_) => return Err(GateDenial::InvalidCredential),
                };
                let issued_at = claims
                    .get("iat")
                    .and_then(Value::as_i64)
                    .ok_or(GateDenial::InvalidCredential)?;
                let email = str_claim("email").to_owned();
                let jti = str_claim("jti").to_owned();
                let family = str_claim("fam").to_owned();
                let device_id = claims
                    .get("device")
                    .and_then(|d| d.get("id"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let claimed_guest = str_claim("acct") == "guest";
                let auth_time = claims.get("auth_time").and_then(Value::as_i64);
                Ok(VerifiedStep {
                    user_id,
                    email,
                    auth_kind: AuthKind::JwtBearer,
                    claimed_guest,
                    issued_at,
                    expires_at: Some(exp),
                    jti,
                    family,
                    device_id,
                    impersonator,
                    auth_time,
                    claims: Value::Object(claims),
                    raw_bearer: (!*from_cookie).then_some(*token),
                    device_bound_possible: true,
                })
            }

            GateCredential::AttachmentToken(raw) => {
                if req.surface != ProtocolSurface::AttachmentTransfer {
                    return Err(GateDenial::InvalidCredential);
                }
                let secret_slices: Vec<&[u8]> =
                    self.attachment_secrets.iter().map(Vec::as_slice).collect();
                let (session, claims) = token::attachment(raw, &self.issuer, now, &secret_slices)
                    .ok_or(GateDenial::InvalidCredential)?;
                let exp = claims.get("exp").and_then(Value::as_i64);
                Ok(VerifiedStep {
                    user_id: session.user_id,
                    email: session.email,
                    auth_kind: AuthKind::AttachmentToken,
                    claimed_guest: false,
                    issued_at: session.issued_at,
                    expires_at: exp,
                    jti: session.jti,
                    family: session.family,
                    device_id: session.device_id,
                    impersonator: None,
                    auth_time: session.auth_time,
                    claims,
                    raw_bearer: Some(*raw),
                    device_bound_possible: true,
                })
            }

            GateCredential::Password {
                email,
                secret,
                run_dummy_hash,
            } => {
                let policy = req
                    .surface
                    .basic_policy()
                    .ok_or(GateDenial::InvalidCredential)?;
                let mut meta = GateThreatMeta {
                    source_ip: req.client_ip.to_string(),
                    username: (*email).to_owned(),
                    protocol: req.surface.protocol_name().to_owned(),
                    user_agent: req.user_agent.to_owned(),
                    ..Default::default()
                };
                if let Some(threat) = &self.threat {
                    let (action, delay) = threat.intercept(&meta).await;
                    match action {
                        GateThreatAction::Reject | GateThreatAction::Tarpitted => {
                            return Err(GateDenial::ThreatRejected { delay });
                        }
                        GateThreatAction::RateLimited => {
                            return Err(GateDenial::ThreatRateLimited);
                        }
                        GateThreatAction::Allow => {}
                    }
                }
                let verdict = basic::verify_with_dummy(
                    &self.exec,
                    &self.passwords,
                    email,
                    secret,
                    policy,
                    *run_dummy_hash,
                )
                .await;
                let (auth_kind, verified) = match verdict {
                    Verdict::AppPassword(u) => {
                        meta.app_password = true;
                        (AuthKind::AppPassword, u)
                    }
                    Verdict::AccountPassword(u) => (AuthKind::AccountPassword, u),
                    Verdict::Refused => {
                        if let Some(threat) = &self.threat {
                            threat.record_result(&meta, false, 0).await;
                        }
                        return Err(GateDenial::InvalidCredential);
                    }
                };
                if let Some(threat) = &self.threat {
                    threat.record_result(&meta, true, verified.user_id).await;
                    meta.user_id = verified.user_id;
                    meta.device_bound = false;
                    let (post_action, reason) = threat.evaluate_post_auth(&mut meta).await;
                    if post_action == GateThreatAction::Reject {
                        return Err(GateDenial::PolicyBlocked {
                            reason,
                            remediation: String::new(),
                            terms_id: 0,
                            correlation_id: None,
                        });
                    }
                }
                Ok(VerifiedStep {
                    user_id: verified.user_id,
                    email: verified.email,
                    auth_kind,
                    claimed_guest: false,
                    issued_at: SENTINEL_NON_JWT_IAT,
                    expires_at: None,
                    jti: String::new(),
                    family: String::new(),
                    device_id: String::new(),
                    impersonator: None,
                    auth_time: None,
                    claims: Proof::basic(verified.user_id).claims().clone(),
                    raw_bearer: None,
                    device_bound_possible: false,
                })
            }

            GateCredential::Negotiate { headers } => {
                // Two-phase ThreatGate for Kerberos Negotiate (no double rate-limit burn):
                // Phase 1: IP-only intercept -> SPNEGO verify -> principal lookup
                // Phase 2: targeted account lockout check (`check_account_lockout`)
                let validator = self
                    .kerberos
                    .as_ref()
                    .ok_or(GateDenial::AuthMethodDisabled("kerberos"))?;
                let client_ip = req.client_ip.to_string();
                let ip_meta = GateThreatMeta {
                    source_ip: client_ip.clone(),
                    username: String::new(),
                    protocol: "http".into(),
                    user_agent: req.user_agent.to_owned(),
                    ..Default::default()
                };
                if let Some(threat) = &self.threat {
                    let (action, delay) = threat.intercept(&ip_meta).await;
                    match action {
                        GateThreatAction::Reject | GateThreatAction::Tarpitted => {
                            return Err(GateDenial::ThreatRejected { delay });
                        }
                        GateThreatAction::RateLimited => {
                            return Err(GateDenial::ThreatRateLimited);
                        }
                        GateThreatAction::Allow => {}
                    }
                }
                let token = match kerberos::parse_negotiate_token(headers) {
                    Ok(t) => t,
                    Err(_) => {
                        kerberos::record_kerberos_event(
                            &self.exec,
                            None,
                            "login_failed",
                            None,
                            Some(&client_ip),
                            Some(r#"{"reason":"spnego_validation_failed"}"#),
                        )
                        .await;
                        if let Some(threat) = &self.threat {
                            threat.record_ip_failure(&ip_meta).await;
                        }
                        return Err(GateDenial::SpnegoFailed);
                    }
                };
                let principal = match validator.validate_spnego(&token).await {
                    Ok(p) => p,
                    Err(_) => {
                        kerberos::record_kerberos_event(
                            &self.exec,
                            None,
                            "login_failed",
                            None,
                            Some(&client_ip),
                            Some(r#"{"reason":"spnego_validation_failed"}"#),
                        )
                        .await;
                        if let Some(threat) = &self.threat {
                            threat.record_ip_failure(&ip_meta).await;
                        }
                        return Err(GateDenial::SpnegoFailed);
                    }
                };
                let (user, totp_required) =
                    match kerberos::lookup_principal(&self.exec, &principal).await {
                        PrincipalLookup::Found(u) => (u, false),
                        PrincipalLookup::TotpRequired(u) => (u, true),
                        PrincipalLookup::Guest(u) => {
                            kerberos::record_kerberos_event(
                                &self.exec,
                                Some(u.user_id),
                                "login_failed",
                                Some(&u.email),
                                Some(&client_ip),
                                Some(r#"{"reason":"guest_refused"}"#),
                            )
                            .await;
                            if let Some(threat) = &self.threat {
                                let guest_meta = GateThreatMeta {
                                    source_ip: client_ip,
                                    username: u.email,
                                    protocol: "http".into(),
                                    user_agent: req.user_agent.to_owned(),
                                    ..Default::default()
                                };
                                threat.record_result(&guest_meta, false, 0).await;
                            }
                            return Err(GateDenial::GuestRefused);
                        }
                        PrincipalLookup::NotFound => {
                            kerberos::record_kerberos_event(
                                &self.exec,
                                None,
                                "login_failed",
                                None,
                                Some(&client_ip),
                                Some(r#"{"reason":"user_not_found"}"#),
                            )
                            .await;
                            if let Some(threat) = &self.threat {
                                let principal_meta = GateThreatMeta {
                                    source_ip: client_ip,
                                    username: principal,
                                    protocol: "http".into(),
                                    user_agent: req.user_agent.to_owned(),
                                    ..Default::default()
                                };
                                threat.record_result(&principal_meta, false, 0).await;
                            }
                            return Err(GateDenial::InvalidCredential);
                        }
                        PrincipalLookup::Unavailable => {
                            return Err(GateDenial::Unavailable(
                                "kerberos principal lookup unavailable".into(),
                            ));
                        }
                    };
                // Phase 2: targeted account lockout check without double rate-limit burn.
                let user_meta = GateThreatMeta {
                    source_ip: client_ip.clone(),
                    username: user.email.clone(),
                    protocol: "http".into(),
                    user_agent: req.user_agent.to_owned(),
                    ..Default::default()
                };
                if let Some(threat) = &self.threat {
                    let (lock_action, lock_delay) = threat.check_account_lockout(&user_meta).await;
                    if lock_action != GateThreatAction::Allow {
                        return Err(GateDenial::ThreatRejected { delay: lock_delay });
                    }
                }
                kerberos::record_kerberos_event(
                    &self.exec,
                    Some(user.user_id),
                    "login",
                    Some(&user.email),
                    Some(&client_ip),
                    None,
                )
                .await;
                if totp_required {
                    return Err(GateDenial::TotpRefused);
                }
                if let Some(threat) = &self.threat {
                    threat.record_result(&user_meta, true, user.user_id).await;
                }
                Ok(VerifiedStep {
                    user_id: user.user_id,
                    email: user.email,
                    auth_kind: AuthKind::Kerberos,
                    claimed_guest: false,
                    issued_at: SENTINEL_NON_JWT_IAT,
                    expires_at: None,
                    jti: String::new(),
                    family: String::new(),
                    device_id: String::new(),
                    impersonator: None,
                    auth_time: None,
                    claims: Proof::kerberos(user.user_id).claims().clone(),
                    raw_bearer: None,
                    device_bound_possible: false,
                })
            }
        }
    }

    async fn read_runtime_flags(&self) -> Result<RuntimeFlags, GateDenial> {
        let keys: Vec<String> = [
            "feature.cae_runtime",
            "feature.conditional_access",
            "feature.device_trust_enforcement",
            "feature.device_lockdown",
            "feature.token_binding",
            "feature.guest_accounts",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let rows = tokio::time::timeout(
            crate::precheck_timeout(),
            self.exec.read(
                "SELECT s.mode::text, ft.key, ft.enabled \
                   FROM feature_toggle_registry_state s \
                   LEFT JOIN feature_toggles ft ON ft.key = ANY($1::text[]) \
                  WHERE s.singleton",
                &[(&keys, Type::TEXT_ARRAY)],
            ),
        )
        .await
        .map_err(|_| GateDenial::Unavailable("runtime flags timed out".into()))?
        .map_err(|e| GateDenial::Unavailable(e.message))?;

        let registry_ready = rows.first().is_some_and(|r| {
            matches!(
                r.get::<_, Option<String>>(0).as_deref(),
                Some("observe" | "enforce")
            )
        });
        let on = |k: &str| {
            rows.iter().any(|r| {
                r.get::<_, Option<String>>(1).as_deref() == Some(k)
                    && r.get::<_, Option<bool>>(2) == Some(true)
            })
        };
        Ok(RuntimeFlags {
            cae_runtime: on("feature.cae_runtime"),
            conditional_access: on("feature.conditional_access"),
            device_trust_enforcement: on("feature.device_trust_enforcement"),
            device_lockdown: on("feature.device_lockdown"),
            token_binding: on("feature.token_binding"),
            guest_accounts: on("feature.guest_accounts"),
            registry_ready,
        })
    }

    async fn check_guest_belt(
        &self,
        req: &GateRequest<'_>,
        user_id: i64,
        claimed_guest: bool,
        flags: &RuntimeFlags,
    ) -> Result<bool, GateDenial> {
        let rows = tokio::time::timeout(
            crate::precheck_timeout(),
            self.exec.read(
                "SELECT status, expires_at IS NOT NULL AND expires_at < now() \
                   FROM guest_account_status($1)",
                &[(&user_id, Type::INT8)],
            ),
        )
        .await
        .map_err(|_| GateDenial::Unavailable("guest status timed out".into()))?
        .map_err(|e| GateDenial::Unavailable(e.message))?;

        let is_live_guest = match rows.first() {
            Some(row) => {
                let status: String = row.get(0);
                let expired: bool = row.get(1);
                if status != "active" || expired {
                    return Err(GateDenial::GuestInactive);
                }
                true
            }
            None if claimed_guest => return Err(GateDenial::GuestInactive),
            None => false,
        };

        if !is_live_guest {
            return Ok(false);
        }
        if !req.surface.allows_guest() {
            return Err(GateDenial::GuestRefused);
        }
        if !flags.registry_ready || !flags.guest_accounts {
            return Err(GateDenial::GuestNotFound);
        }
        if req.surface == ProtocolSurface::Http {
            let allowed = self
                .guest_allowlist
                .as_ref()
                .is_some_and(|a| a.allows(req.method, req.path));
            if !allowed {
                return Err(GateDenial::GuestNotFound);
            }
        }
        Ok(true)
    }

    async fn check_revocation_and_cae(
        &self,
        user_id: i64,
        jti: &str,
        family: &str,
        issued_at: i64,
        cae_runtime: bool,
    ) -> Result<(), GateDenial> {
        if let Some(denylist) = &self.denylist {
            if denylist.is_revoked(user_id, jti, family, issued_at) {
                return Err(GateDenial::SessionRevoked);
            }
        }
        let iat_f64 = issued_at as f64;
        let durable = tokio::time::timeout(
            crate::precheck_timeout(),
            self.exec.read(
                "SELECT EXISTS(SELECT 1 FROM session_revocations \
                  WHERE user_id = $1 AND expires_at > now() \
                    AND ((scope = 'all' AND not_before >= to_timestamp($2::float8)) \
                      OR (scope = 'jti' AND $3 <> '' AND jti = $3) \
                      OR (scope = 'family' AND $4 <> '' AND family_id = $4)))",
                &[
                    (&user_id, Type::INT8),
                    (&iat_f64, Type::FLOAT8),
                    (&jti, Type::TEXT),
                    (&family, Type::TEXT),
                ],
            ),
        )
        .await;
        let revoked = match durable {
            Ok(Ok(rows)) => Some(rows[0].get::<_, bool>(0)),
            _ => None,
        };
        if revoked == Some(true) {
            return Err(GateDenial::SessionRevoked);
        }
        if cae_runtime && self.denylist.as_ref().is_none_or(|d| !d.loaded()) {
            return Err(GateDenial::DenylistUnavailable);
        }
        if revoked.is_none() {
            return Err(GateDenial::Unavailable(
                "durable session_revocations lookup failed".into(),
            ));
        }
        Ok(())
    }

    fn check_dpop_and_sif(
        &self,
        req: &GateRequest<'_>,
        claims: &Value,
        raw_bearer: Option<&str>,
        now: f64,
        flags: &RuntimeFlags,
    ) -> Result<(), GateDenial> {
        if flags.token_binding {
            let jkt = text(&claims["cnf"], "jkt");
            if !jkt.is_empty() {
                let host = req
                    .headers
                    .and_then(|h| h.get("host"))
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let uri = format!("https://{host}{}", req.path);
                let signed = req
                    .headers
                    .and_then(|h| h.get("dpop"))
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if !dpop::verify(
                    signed,
                    req.method,
                    &uri,
                    jkt,
                    now,
                    &self.replay,
                    raw_bearer.unwrap_or(""),
                ) {
                    return Err(GateDenial::TokenBindingFailed);
                }
            }
        }
        if let Some(sif) = claims["sif"].as_i64() {
            let anchor = claims["auth_time"]
                .as_i64()
                .or_else(|| claims["iat"].as_i64());
            if anchor.is_none_or(|anchor| {
                now - anchor as f64 > sif.wrapping_mul(1_000_000_000) as f64 / 1e9
            }) {
                return Err(GateDenial::SignInFrequencyExpired);
            }
        }
        Ok(())
    }

    async fn check_device_trust_and_lockdown(
        &self,
        req: &GateRequest<'_>,
        verified: &VerifiedStep<'_>,
        flags: &RuntimeFlags,
    ) -> Result<(), GateDenial> {
        if flags.device_trust_enforcement {
            let device = &verified.claims["device"];
            if device.is_null() {
                return Err(GateDenial::DeviceComplianceFailed {
                    title: "device_compliance_unverifiable",
                    detail: "Device compliance could not be verified from this token. Sign in again from your device.",
                });
            }
            if device["wipe_requested"] == true {
                return Err(GateDenial::DeviceComplianceFailed {
                    title: "Forbidden",
                    detail: "Device has been wiped. Contact your administrator.",
                });
            }
            if device["trust_tier"] == "quarantined" {
                return Err(GateDenial::DeviceComplianceFailed {
                    title: "Forbidden",
                    detail: "Device is quarantined. Check compliance status in device settings.",
                });
            }
            if !verified.device_id.is_empty() {
                if let Some(view) = &self.device_revocation {
                    if view.is_device_revoked(&verified.device_id).await {
                        return Err(GateDenial::DeviceRevoked);
                    }
                }
            }
        }
        if flags.conditional_access && flags.device_lockdown {
            let bg = store::break_glass(&self.exec)
                .await
                .map_err(|e| GateDenial::Unavailable(e.message))?;
            if !bg.is_empty() && !bg.contains(&verified.user_id) {
                let binding = if verified.device_bound_possible {
                    if let (Some(resolver), Some(headers)) = (&self.device_resolver, req.headers) {
                        let inner = req.path.strip_prefix("/api").unwrap_or(req.path);
                        resolver
                            .resolve_for_user(
                                verified.user_id,
                                DeviceRequest {
                                    headers,
                                    method: req.method,
                                    uri: inner,
                                    body: req.body,
                                },
                            )
                            .await
                    } else {
                        Default::default()
                    }
                } else {
                    Default::default()
                };
                if !binding.bound || binding.enroll_state != "approved" {
                    return Err(GateDenial::DeviceLockdown);
                }
            }
        }
        Ok(())
    }

    async fn check_conditional_access(
        &self,
        req: &GateRequest<'_>,
        verified: &VerifiedStep<'_>,
        now: f64,
    ) -> Result<(), GateDenial> {
        let auth_method = {
            let m = text(&verified.claims, "auth_method");
            if m.is_empty() {
                verified.auth_kind.as_ca_method().to_owned()
            } else {
                m.to_owned()
            }
        };
        let ctx = PolicyContext {
            user_id: verified.user_id,
            source_ip: req.client_ip.to_string(),
            protocol: req.surface.protocol_name().to_owned(),
            auth_method,
            current_acr: text(&verified.claims, "acr").to_owned(),
            user_agent: req.user_agent.to_owned(),
            device_fp: fingerprint(req.user_agent, req.client_ip),
            country: self
                .geo
                .as_ref()
                .map_or_else(String::new, |geo| geo.country(req.client_ip)),
            risk_level: text(&verified.claims["risk"], "level").to_owned(),
            request_time: Some(now as i64),
            device_bound: false,
            ..Default::default()
        };
        let result = self.engine.evaluate(ctx).await;
        match result.decision.as_str() {
            "block" => Err(GateDenial::PolicyBlocked {
                reason: result.reason,
                remediation: result.remediation,
                terms_id: result.terms_id,
                correlation_id: result.correlation_id,
            }),
            "step_up" => {
                if req.surface.allows_step_up() {
                    Err(GateDenial::StepUpRequired {
                        reason: result.reason,
                        correlation_id: result.correlation_id,
                    })
                } else {
                    Err(GateDenial::PolicyBlocked {
                        reason: result.reason,
                        remediation: String::new(),
                        terms_id: 0,
                        correlation_id: result.correlation_id,
                    })
                }
            }
            _ => Ok(()),
        }
    }
}

struct VerifiedStep<'a> {
    user_id: i64,
    email: String,
    auth_kind: AuthKind,
    claimed_guest: bool,
    issued_at: i64,
    expires_at: Option<i64>,
    jti: String,
    family: String,
    device_id: String,
    impersonator: Option<ActorId>,
    auth_time: Option<i64>,
    claims: Value,
    raw_bearer: Option<&'a str>,
    device_bound_possible: bool,
}

// ---------------------------------------------------------------------------
// Shared standalone helpers usable by protocol adapters (IMAP/SMTP/LDAP/WS/SSE)
// ---------------------------------------------------------------------------

/// Shared standalone Basic credential verification + ThreatGate used by
/// `dav_auth.rs` and `PolicyGate::admit`.
#[allow(clippy::too_many_arguments)]
pub async fn verify_basic_with_threat(
    exec: &ScopedExecutor,
    cache: &PasswordCache,
    chain: Option<&Chain>,
    threat: &dyn ThreatAdapter,
    surface: ProtocolSurface,
    email: &str,
    secret: &str,
    client_ip: &str,
    user_agent: &str,
) -> Result<basic::Verified, GateDenial> {
    if !chain.is_none_or(Chain::basic_allowed) {
        return Err(GateDenial::AuthMethodDisabled("basic"));
    }
    let policy = surface
        .basic_policy()
        .ok_or(GateDenial::InvalidCredential)?;
    let meta = GateThreatMeta {
        source_ip: client_ip.to_owned(),
        username: email.to_owned(),
        protocol: "http".into(),
        user_agent: user_agent.to_owned(),
        ..Default::default()
    };
    let (action, delay) = threat.intercept(&meta).await;
    match action {
        GateThreatAction::Reject | GateThreatAction::Tarpitted => {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            return Err(GateDenial::ThreatRejected { delay });
        }
        GateThreatAction::RateLimited => return Err(GateDenial::ThreatRateLimited),
        GateThreatAction::Allow => {}
    }
    let verdict = basic::verify(exec, cache, email, secret, policy).await;
    let (success, user_id, verified) = match verdict {
        Verdict::AppPassword(user) => (true, user.user_id, Some(user)),
        Verdict::AccountPassword(user)
            if matches!(
                policy.accept,
                Accept::AccountPassword | Accept::AppPasswordThenAccountPassword
            ) =>
        {
            (true, user.user_id, Some(user))
        }
        Verdict::AccountPassword(_) | Verdict::Refused => (false, 0, None),
    };
    threat.record_result(&meta, success, user_id).await;
    verified.ok_or(GateDenial::InvalidCredential)
}

/// Shared standalone two-phase Kerberos/SPNEGO Negotiate verification used by
/// `dav_auth.rs` and `PolicyGate::admit` (IP-only `intercept` -> SPNEGO verify
/// -> principal lookup -> targeted `check_account_lockout`, zero double rate-limit burn).
#[allow(clippy::too_many_arguments)]
pub async fn verify_negotiate_two_phase(
    exec: &ScopedExecutor,
    chain: Option<&Chain>,
    validator: Option<&dyn KerberosValidator>,
    threat: &dyn ThreatAdapter,
    headers: &HeaderMap,
    client_ip: &str,
    user_agent: &str,
) -> Result<basic::Verified, GateDenial> {
    let has_negotiate = headers
        .get(hyper::header::AUTHORIZATION)
        .is_some_and(|v| v.as_bytes().starts_with(b"Negotiate "));
    if !has_negotiate {
        return Err(GateDenial::MalformedSyntax("missing Negotiate header"));
    }
    if !chain.is_some_and(Chain::kerberos_allowed) {
        return Err(GateDenial::AuthMethodDisabled("kerberos"));
    }
    let Some(validator) = validator else {
        return Err(GateDenial::AuthMethodDisabled("kerberos"));
    };
    let ip_meta = GateThreatMeta {
        source_ip: client_ip.to_owned(),
        username: String::new(),
        protocol: "http".into(),
        user_agent: user_agent.to_owned(),
        ..Default::default()
    };
    let (action, delay) = threat.intercept(&ip_meta).await;
    match action {
        GateThreatAction::Reject | GateThreatAction::Tarpitted => {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            return Err(GateDenial::ThreatRejected { delay });
        }
        GateThreatAction::RateLimited => return Err(GateDenial::ThreatRateLimited),
        GateThreatAction::Allow => {}
    }
    let token = match kerberos::parse_negotiate_token(headers) {
        Ok(token) => token,
        Err(_) => {
            kerberos::record_kerberos_event(
                exec,
                None,
                "login_failed",
                None,
                Some(client_ip),
                Some(r#"{"reason":"spnego_validation_failed"}"#),
            )
            .await;
            threat.record_ip_failure(&ip_meta).await;
            return Err(GateDenial::SpnegoFailed);
        }
    };
    let principal = match validator.validate_spnego(&token).await {
        Ok(principal) => principal,
        Err(_) => {
            kerberos::record_kerberos_event(
                exec,
                None,
                "login_failed",
                None,
                Some(client_ip),
                Some(r#"{"reason":"spnego_validation_failed"}"#),
            )
            .await;
            threat.record_ip_failure(&ip_meta).await;
            return Err(GateDenial::SpnegoFailed);
        }
    };
    let (user, totp_required) = match kerberos::lookup_principal(exec, &principal).await {
        PrincipalLookup::Found(u) => (u, false),
        PrincipalLookup::TotpRequired(u) => (u, true),
        PrincipalLookup::Guest(u) => {
            kerberos::record_kerberos_event(
                exec,
                Some(u.user_id),
                "login_failed",
                Some(&u.email),
                Some(client_ip),
                Some(r#"{"reason":"guest_refused"}"#),
            )
            .await;
            let guest_meta = GateThreatMeta {
                source_ip: client_ip.to_owned(),
                username: u.email,
                protocol: "http".into(),
                user_agent: user_agent.to_owned(),
                ..Default::default()
            };
            threat.record_result(&guest_meta, false, 0).await;
            return Err(GateDenial::GuestRefused);
        }
        PrincipalLookup::NotFound => {
            kerberos::record_kerberos_event(
                exec,
                None,
                "login_failed",
                None,
                Some(client_ip),
                Some(r#"{"reason":"user_not_found"}"#),
            )
            .await;
            let principal_meta = GateThreatMeta {
                source_ip: client_ip.to_owned(),
                username: principal,
                protocol: "http".into(),
                user_agent: user_agent.to_owned(),
                ..Default::default()
            };
            threat.record_result(&principal_meta, false, 0).await;
            return Err(GateDenial::InvalidCredential);
        }
        PrincipalLookup::Unavailable => {
            return Err(GateDenial::Unavailable(
                "kerberos principal lookup unavailable".into(),
            ));
        }
    };
    let user_meta = GateThreatMeta {
        source_ip: client_ip.to_owned(),
        username: user.email.clone(),
        protocol: "http".into(),
        user_agent: user_agent.to_owned(),
        ..Default::default()
    };
    let (lock_action, lock_delay) = threat.check_account_lockout(&user_meta).await;
    if lock_action != GateThreatAction::Allow {
        if !lock_delay.is_zero() {
            tokio::time::sleep(lock_delay).await;
        }
        return Err(GateDenial::ThreatRejected { delay: lock_delay });
    }
    kerberos::record_kerberos_event(
        exec,
        Some(user.user_id),
        "login",
        Some(&user.email),
        Some(client_ip),
        None,
    )
    .await;
    if totp_required {
        return Err(GateDenial::TotpRefused);
    }
    threat.record_result(&user_meta, true, user.user_id).await;
    Ok(user)
}

/// Shared post-authentication checks for password-based protocols (`Imap`,
/// `SmtpSubmission`, `Ldap`):
/// - durable `session_revocations` (`scope = 'all'`, `expires_at > now()`)
/// - `feature.device_lockdown` (when `feature.conditional_access` is also ON,
///   unless caller is break-glass)
/// - `check_user_app_entitlement` (when `app` is `Some`)
/// - `mailbox_lifecycle_access_allowed` (when `require_mailbox` is `true`, or
///   when a primary mailbox exists on `Ldap`)
pub async fn check_protocol_post_auth(
    exec: &ScopedExecutor,
    surface: ProtocolSurface,
    user_id: i64,
) -> Result<(), GateDenial> {
    let iat = SENTINEL_NON_JWT_IAT as f64;
    let revoked_rows = tokio::time::timeout(
        crate::precheck_timeout(),
        exec.read(
            "SELECT EXISTS(SELECT 1 FROM session_revocations \
              WHERE user_id = $1 AND expires_at > now() \
                AND scope = 'all' AND not_before >= to_timestamp($2::float8))",
            &[(&user_id, Type::INT8), (&iat, Type::FLOAT8)],
        ),
    )
    .await
    .map_err(|_| GateDenial::Unavailable("session_revocations timed out".into()))?
    .map_err(|e| GateDenial::Unavailable(e.message))?;
    if revoked_rows
        .first()
        .is_some_and(|r| r.try_get::<_, bool>(0).unwrap_or(true))
    {
        return Err(GateDenial::SessionRevoked);
    }

    // Device lockdown check across all non-device-bound protocols unless break-glass.
    let keys: Vec<String> = ["feature.conditional_access", "feature.device_lockdown"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let flag_rows = tokio::time::timeout(
        crate::precheck_timeout(),
        exec.read(
            "SELECT key, enabled FROM feature_toggles WHERE key = ANY($1::text[])",
            &[(&keys, Type::TEXT_ARRAY)],
        ),
    )
    .await
    .map_err(|_| GateDenial::Unavailable("lockdown flags timed out".into()))?
    .map_err(|e| GateDenial::Unavailable(e.message))?;
    let on = |k: &str| {
        flag_rows
            .iter()
            .any(|r| r.get::<_, String>(0) == k && r.get::<_, bool>(1))
    };
    if on("feature.conditional_access") && on("feature.device_lockdown") {
        let bg = store::break_glass(exec)
            .await
            .map_err(|e| GateDenial::Unavailable(e.message))?;
        if !bg.is_empty() && !bg.contains(&user_id) {
            return Err(GateDenial::DeviceLockdown);
        }
    }

    if let Some(app) = surface.default_app_entitlement() {
        if !check_app_entitlement(exec, user_id, app).await? {
            return Err(GateDenial::EntitlementDenied(app.to_owned()));
        }
    }

    if surface.requires_primary_mailbox() {
        match lookup_primary_mailbox_lifecycle(exec, user_id).await? {
            Some((_, true)) => {}
            Some((_, false)) => return Err(GateDenial::MailboxBlocked),
            None => return Err(GateDenial::NoPrimaryMailbox),
        }
    } else if surface == ProtocolSurface::Ldap {
        if let Some((_, false)) = lookup_primary_mailbox_lifecycle(exec, user_id).await? {
            return Err(GateDenial::MailboxBlocked);
        }
    }

    Ok(())
}

/// Check `check_user_app_entitlement($1, $2)` fail-closed.
pub async fn check_app_entitlement(
    exec: &ScopedExecutor,
    user_id: i64,
    app: &str,
) -> Result<bool, GateDenial> {
    let rows = tokio::time::timeout(
        crate::precheck_timeout(),
        exec.read(
            "SELECT check_user_app_entitlement($1, $2)",
            &[(&user_id, Type::INT8), (&app, Type::TEXT)],
        ),
    )
    .await
    .map_err(|_| GateDenial::Unavailable("app entitlement timed out".into()))?
    .map_err(|e| GateDenial::Unavailable(e.message))?;
    Ok(rows
        .first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .unwrap_or(false))
}

/// Check `mailbox_lifecycle_access_allowed($1)` fail-closed.
pub async fn check_mailbox_lifecycle(
    exec: &ScopedExecutor,
    mailbox_id: i64,
) -> Result<bool, GateDenial> {
    let rows = tokio::time::timeout(
        crate::precheck_timeout(),
        exec.read(
            "SELECT mailbox_lifecycle_access_allowed($1)",
            &[(&mailbox_id, Type::INT8)],
        ),
    )
    .await
    .map_err(|_| GateDenial::Unavailable("mailbox lifecycle timed out".into()))?
    .map_err(|e| GateDenial::Unavailable(e.message))?;
    Ok(rows
        .first()
        .and_then(|r| r.try_get::<_, Option<bool>>(0).ok().flatten())
        == Some(true))
}

/// Look up a user's primary mailbox ID and `mailbox_lifecycle_access_allowed(id)`.
pub async fn lookup_primary_mailbox_lifecycle(
    exec: &ScopedExecutor,
    user_id: i64,
) -> Result<Option<(i64, bool)>, GateDenial> {
    let rows = tokio::time::timeout(
        crate::precheck_timeout(),
        exec.read(
            "SELECT id, mailbox_lifecycle_access_allowed(id) \
               FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1",
            &[(&user_id, Type::INT8)],
        ),
    )
    .await
    .map_err(|_| GateDenial::Unavailable("primary mailbox lookup timed out".into()))?
    .map_err(|e| GateDenial::Unavailable(e.message))?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let id: i64 = row
        .try_get(0)
        .map_err(|e| GateDenial::Unavailable(e.to_string()))?;
    let allowed = row
        .try_get::<_, Option<bool>>(1)
        .map_err(|e| GateDenial::Unavailable(e.to_string()))?
        == Some(true);
    Ok(Some((id, allowed)))
}

/// Shared check for `SessionAdmission`: check durable `session_revocations` +
/// optional `DenylistView` + `feature.cae_runtime` fail-closed cold-cache rule.
pub async fn check_session_revocation(
    exec: &ScopedExecutor,
    denylist: Option<&dyn DenylistView>,
    user_id: i64,
    jti: &str,
    family: &str,
    iat: f64,
) -> Result<(), GateDenial> {
    let cached = denylist.is_some_and(|d| d.is_revoked(user_id, jti, family, iat as i64));
    let durable = tokio::time::timeout(
        crate::precheck_timeout(),
        exec.read(
            "SELECT EXISTS(SELECT 1 FROM session_revocations \
              WHERE user_id = $1 AND expires_at > now() \
                AND ((scope = 'all' AND not_before >= to_timestamp($2::float8)) \
                  OR (scope = 'jti' AND $3 <> '' AND jti = $3) \
                  OR (scope = 'family' AND $4 <> '' AND family_id = $4)))",
            &[
                (&user_id, Type::INT8),
                (&iat, Type::FLOAT8),
                (&jti, Type::TEXT),
                (&family, Type::TEXT),
            ],
        ),
    )
    .await;
    let revoked = match durable {
        Ok(Ok(rows)) => Some(rows[0].get::<_, bool>(0)),
        _ => None,
    };
    if cached || revoked == Some(true) {
        return Err(GateDenial::SessionRevoked);
    }
    let cae = tokio::time::timeout(
        crate::precheck_timeout(),
        exec.read(
            "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.cae_runtime'),false)",
            &[],
        ),
    )
    .await;
    let cae = match cae {
        Ok(Ok(rows)) => rows[0].get::<_, bool>(0),
        _ => return Err(GateDenial::Unavailable("cae toggle read failed".into())),
    };
    if cae && denylist.is_none_or(|d| !d.loaded()) {
        return Err(GateDenial::DenylistUnavailable);
    }
    if revoked.is_none() {
        return Err(GateDenial::Unavailable("revocation read failed".into()));
    }
    Ok(())
}

/// Mint a sealed [`GateAdmission`] for a trusted internal test / adapter bridge
/// after all stages have passed. Strictly `pub(crate)`.
#[allow(dead_code)]
pub(crate) fn mint_admission_for_claims(
    surface: ProtocolSurface,
    auth_kind: AuthKind,
    claims: &Map<String, Value>,
    is_guest: bool,
    primary_mailbox: Option<MailboxId>,
    mailbox_blocked: bool,
    client_ip: &str,
) -> Option<GateAdmission> {
    let user_id = claims.get("uid").and_then(Value::as_i64)?;
    let actor = ActorId::new(user_id).ok()?;
    let email = claims
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let impersonator = claims
        .get("act")
        .and_then(Value::as_i64)
        .and_then(|id| ActorId::new(id).ok());
    Some(GateAdmission {
        surface,
        auth_kind,
        actor,
        email: email.clone(),
        is_guest,
        primary_mailbox,
        mailbox_blocked,
        issued_at: claims
            .get("iat")
            .and_then(Value::as_i64)
            .unwrap_or(SENTINEL_NON_JWT_IAT),
        expires_at: claims.get("exp").and_then(Value::as_i64),
        token_id: claims
            .get("jti")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        token_family: claims
            .get("fam")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        device_id: claims
            .get("device")
            .and_then(|d| d.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        impersonator,
        entitlements: BTreeSet::new(),
        audit_meta: AuditMeta::new(email, client_ip),
        generation: Generation(1),
    })
}

fn is_unsafe_http_method(method: &str) -> bool {
    !matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

fn ws_origin_allowed(headers: &HeaderMap, production: bool, allowed_host: &str) -> bool {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty());
    match origin {
        None => !production,
        Some(raw) => origin_host(raw).is_some_and(|h| {
            h == host || (!allowed_host.is_empty() && h.eq_ignore_ascii_case(allowed_host))
        }),
    }
}

fn origin_host(raw: &str) -> Option<&str> {
    if raw.trim() != raw || raw.bytes().any(|b| b.is_ascii_control()) {
        return None;
    }
    let parsed = crate::go_url::go_url_parse(raw).ok()?;
    if parsed.host.is_empty() {
        return None;
    }
    let rest = raw
        .split_once("://")
        .map(|(_, rest)| rest)
        .or_else(|| raw.strip_prefix("//"))?;
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?;
    (!host.is_empty()).then_some(host)
}

fn fingerprint(ua: &str, ip: IpAddr) -> String {
    let ip_s = match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| v6.to_string(), |v4| v4.to_string()),
        ip => ip.to_string(),
    };
    let parts: Vec<_> = ip_s.split('.').collect();
    let masked = if parts.len() == 4 {
        format!("{}.{}.{}.0", parts[0], parts[1], parts[2])
    } else {
        let parts: Vec<_> = ip_s.split(':').collect();
        if parts.len() > 3 {
            format!("{}::", parts[..3].join(":"))
        } else {
            ip_s
        }
    };
    format!("{ua}|{masked}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_surface_matrix_invariants() {
        assert_eq!(ProtocolSurface::ALL.len(), 11);
        for surface in ProtocolSurface::ALL {
            assert!(!surface.protocol_name().is_empty());
        }
        assert!(ProtocolSurface::Http.allows_guest());
        assert!(ProtocolSurface::Sse.allows_guest());
        for s in [
            ProtocolSurface::Jmap,
            ProtocolSurface::CalDav,
            ProtocolSurface::CardDav,
            ProtocolSurface::DriveNativeToken,
            ProtocolSurface::AttachmentTransfer,
            ProtocolSurface::WebSocket,
            ProtocolSurface::Imap,
            ProtocolSurface::SmtpSubmission,
            ProtocolSurface::Ldap,
        ] {
            assert!(!s.allows_guest(), "{s:?} must refuse guests");
        }
        assert!(!ProtocolSurface::DriveNativeToken.allows_device_bound_session());
        assert!(ProtocolSurface::Http.allows_step_up());
        assert!(ProtocolSurface::Jmap.allows_step_up());
        assert!(ProtocolSurface::WebSocket.allows_step_up());
        for s in [
            ProtocolSurface::CalDav,
            ProtocolSurface::CardDav,
            ProtocolSurface::DriveNativeToken,
            ProtocolSurface::AttachmentTransfer,
            ProtocolSurface::Sse,
            ProtocolSurface::Imap,
            ProtocolSurface::SmtpSubmission,
            ProtocolSurface::Ldap,
        ] {
            assert!(!s.allows_step_up(), "{s:?} must reject step_up");
        }
        // LDAP must enforce AccountPassword + TotpAccountPassword::Refuse + GuestAppPasswords::Refuse
        let ldap = ProtocolSurface::Ldap.basic_policy().unwrap();
        assert_eq!(ldap.accept, Accept::AccountPassword);
        assert_eq!(ldap.totp_account_password, TotpAccountPassword::Refuse);
        assert_eq!(ldap.guest_app_passwords, GuestAppPasswords::Refuse);
        // IMAP & SMTP must refuse guest app passwords and TOTP account passwords
        for s in [ProtocolSurface::Imap, ProtocolSurface::SmtpSubmission] {
            let p = s.basic_policy().unwrap();
            assert_eq!(p.accept, Accept::AppPasswordThenAccountPassword);
            assert_eq!(p.guest_app_passwords, GuestAppPasswords::Refuse);
            assert_eq!(p.totp_account_password, TotpAccountPassword::Refuse);
        }
    }
}
