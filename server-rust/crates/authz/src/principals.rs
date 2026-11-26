//! Sealed principal minting and capability-gated transaction factory (#542).
//!
//! Every principal and capability token in this module enforces:
//! - private fields with `pub(crate)` constructors only (cannot be constructed
//!   outside `setjoin-authz`);
//! - zero `Deserialize` and zero `Default` implementations;
//! - strict separation of [`MailboxPrincipal`], [`UserPrincipal`], and
//!   [`AdminPrincipal`];
//! - `Gate`-aligned [`MailboxAuthority`] lattice where `send_as`/`send_on_behalf`
//!   yield a narrow [`SubmitCapability`] that **cannot** open a general
//!   mutating `MailboxTx<ReadWrite>` via [`TxFactory::run_mailbox_write`];
//! - narrowest non-NULL `enforced_domain_scope` on [`AdminPrincipal`] (never
//!   widened by `admin_effective_authority`'s broadest reach) plus live JIT and
//!   `dengbao.sod_mode` enforcement.
//!
//! # Compile-fail proofs
//!
//! ## Domain crates cannot forge `MailboxPrincipal`
//! ```compile_fail
//! use setjoin_authz::principals::MailboxPrincipal;
//! fn forge() -> MailboxPrincipal {
//!     MailboxPrincipal { }
//! }
//! ```
//!
//! ## Domain crates cannot forge `UserPrincipal`
//! ```compile_fail
//! use setjoin_authz::principals::UserPrincipal;
//! fn forge() -> UserPrincipal {
//!     UserPrincipal { }
//! }
//! ```
//!
//! ## Domain crates cannot forge `AdminPrincipal`
//! ```compile_fail
//! use setjoin_authz::principals::AdminPrincipal;
//! fn forge() -> AdminPrincipal {
//!     AdminPrincipal { }
//! }
//! ```
//!
//! ## `ReadCapability` cannot open a mutating `MailboxTx<ReadWrite>`
//! ```compile_fail
//! use setjoin_authz::principals::{ReadCapability, TxFactory};
//! use setjoin_contracts::command::CommandEnvelope;
//! use std::time::Instant;
//! async fn escalate(factory: &TxFactory, cap: &ReadCapability, env: &CommandEnvelope<()>) {
//!     let _ = factory.run_mailbox_write(cap, env, Instant::now(), async |_tx| Ok::<_, ()>(())).await;
//! }
//! ```
//!
//! ## `SubmitCapability` (`send_as` / `send_on_behalf`) cannot satisfy `Gate::Mutate` (`run_mailbox_write`)
//! ```compile_fail
//! use setjoin_authz::principals::{SubmitCapability, TxFactory};
//! use setjoin_contracts::command::CommandEnvelope;
//! use std::time::Instant;
//! async fn escalate_submit(factory: &TxFactory, cap: &SubmitCapability, env: &CommandEnvelope<()>) {
//!     let _ = factory.run_mailbox_write(cap, env, Instant::now(), async |_tx| Ok::<_, ()>(())).await;
//! }
//! ```
//!
//! ## `CalendarCapability` (`manage_calendar`) cannot satisfy mail `Read` or `Mutate`
//! ```compile_fail
//! use setjoin_authz::principals::{CalendarCapability, TxFactory};
//! async fn escalate_calendar(factory: &TxFactory, cap: &CalendarCapability) {
//!     let _ = factory.begin_mailbox_read(cap).await;
//! }
//! ```
//!
//! ## Principals cannot be constructed via `Default`
//! ```compile_fail
//! use setjoin_authz::principals::AdminPrincipal;
//! fn forge_default() -> AdminPrincipal {
//!     AdminPrincipal::default()
//! }
//! ```
//!
//! ## `SubmitCapability` cannot call `run_mailbox_effect_write` or `run_mailbox_locked_tx`
//! ```compile_fail
//! use setjoin_authz::principals::{SubmitCapability, TxFactory};
//! use setjoin_contracts::command::CommandEnvelope;
//! use setjoin_pg::ReceiptCommand;
//! use std::time::Instant;
//! async fn escalate_effect(factory: &TxFactory, cap: &SubmitCapability, env: &CommandEnvelope<()>) {
//!     let cmd = ReceiptCommand { family: "t", command: "c" };
//!     let _ = factory.run_mailbox_effect_write(cap, cmd, env, Instant::now(), async |_tx| Ok(())).await;
//! }
//! ```
//!
//! ## `CalendarCapability` cannot call `run_mailbox_locked_tx`
//! ```compile_fail
//! use setjoin_authz::principals::{CalendarCapability, TxFactory};
//! use setjoin_contracts::command::CommandEnvelope;
//! use std::time::Instant;
//! async fn escalate_cal_lock(factory: &TxFactory, cap: &CalendarCapability, env: &CommandEnvelope<()>) {
//!     let _ = factory.run_mailbox_locked_tx(cap, env, Instant::now(), async |_tx| Ok::<_, ()>(())).await;
//! }
//! ```
//!
//! ## `AdminPermissionProof` cannot be forged directly
//! ```compile_fail
//! use setjoin_authz::principals::AdminPermissionProof;
//! fn forge_proof() -> AdminPermissionProof {
//!     AdminPermissionProof { }
//! }
//! ```

use crate::groups::{GroupMembership, GroupResolveError, GroupResolver};
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Generation, MailboxId, OperationId},
};
use setjoin_pg::{
    AdminReadTx, AdminSensitiveRead, AdminWorkerPool, AdminWriteTx, AppPool, AuditEvent,
    CommandOutcome, MailboxTx, OperationLookup, Param, PreAuthReadTx, ReadOnly, ReadWrite,
    ReceiptCommand, Rejection, Row, SqlContract, Standard, StatementFailure, ToSql, Type,
    Unaudited, UserTx, VerifiedAdmin, VerifiedMailbox, VerifiedUser,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
    time::Instant,
};

/// Global-only admin permissions refused to any domain-scoped admin principal.
const GLOBAL_ONLY_PERMISSIONS: [&str; 2] = ["audit.read", "audit.export"];

/// Audit metadata carried from verified session/request state (never grants authority).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditMeta {
    pub email: String,
    pub client_ip: String,
    pub request_id: Option<String>,
    pub user_agent: String,
    pub auth_method: String,
    pub auth_time: Option<i64>,
}

impl AuditMeta {
    pub fn new(email: impl Into<String>, client_ip: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            client_ip: client_ip.into(),
            request_id: None,
            user_agent: String::new(),
            auth_method: String::new(),
            auth_time: None,
        }
    }
}

/// Errors produced when minting or checking a sealed principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrincipalError {
    /// Target user or mailbox ID is invalid.
    InvalidTarget,
    /// Guest accounts are refused on mailbox and admin principals.
    GuestRefused,
    /// Impersonated tokens (`act` claim present) are refused on admin principals.
    ImpersonationRefused,
    /// Target mailbox is blocked by `mailbox_lifecycle_access_allowed`.
    MailboxBlocked,
    /// Caller lacks the required delegation, ownership, or admin role/permission.
    Forbidden(&'static str),
    /// Active admin assignments violate `dengbao.sod_mode` separation of duties.
    SodViolation(&'static str),
    /// Database or group-resolver lookup failed (fail-closed; never falls back to JWT).
    Unavailable(String),
}

impl fmt::Display for PrincipalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTarget => f.write_str("invalid principal target"),
            Self::GuestRefused => f.write_str("guest account refused"),
            Self::ImpersonationRefused => f.write_str("impersonation refused for admin principal"),
            Self::MailboxBlocked => f.write_str("mailbox lifecycle access blocked"),
            Self::Forbidden(reason) => write!(f, "forbidden: {reason}"),
            Self::SodViolation(kind) => write!(f, "separation-of-duties violation: {kind}"),
            Self::Unavailable(msg) => write!(f, "principal lookup unavailable: {msg}"),
        }
    }
}

impl std::error::Error for PrincipalError {}

impl From<StatementFailure> for PrincipalError {
    fn from(value: StatementFailure) -> Self {
        Self::Unavailable(value.message)
    }
}

impl From<GroupResolveError> for PrincipalError {
    fn from(value: GroupResolveError) -> Self {
        Self::Unavailable(value.to_string())
    }
}

// ---------------------------------------------------------------------------
// Mailbox authority lattice (Gate-aligned with jmap/family/mod.rs:81-104)
// ---------------------------------------------------------------------------

/// Stored `mailbox_delegates.permission` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DelegatePermission {
    Read,
    SendAs,
    SendOnBehalf,
    FullAccess,
    ManageCalendar,
}

impl DelegatePermission {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "read" => Some(Self::Read),
            "send_as" => Some(Self::SendAs),
            "send_on_behalf" => Some(Self::SendOnBehalf),
            "full_access" => Some(Self::FullAccess),
            "manage_calendar" => Some(Self::ManageCalendar),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::SendAs => "send_as",
            Self::SendOnBehalf => "send_on_behalf",
            Self::FullAccess => "full_access",
            Self::ManageCalendar => "manage_calendar",
        }
    }
}

/// Live mailbox authority for a verified actor against a target mailbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MailboxAuthority {
    Owner,
    Delegated(BTreeSet<DelegatePermission>),
}

impl MailboxAuthority {
    pub fn is_owner(&self) -> bool {
        matches!(self, Self::Owner)
    }

    pub fn has(&self, perm: DelegatePermission) -> bool {
        match self {
            Self::Owner => true,
            Self::Delegated(set) => set.contains(&perm),
        }
    }

    /// `Gate::Read`: `Owner | full_access | send_as | send_on_behalf | read`.
    /// `manage_calendar` alone is refused on mail reads.
    pub fn can_read(&self) -> bool {
        match self {
            Self::Owner => true,
            Self::Delegated(set) => {
                set.contains(&DelegatePermission::FullAccess)
                    || set.contains(&DelegatePermission::SendAs)
                    || set.contains(&DelegatePermission::SendOnBehalf)
                    || set.contains(&DelegatePermission::Read)
            }
        }
    }

    /// `Gate::Mutate`: `Owner | full_access` ONLY.
    /// `read`, `send_as`, `send_on_behalf`, and `manage_calendar` CANNOT mutate arbitrary mail.
    pub fn can_mutate(&self) -> bool {
        match self {
            Self::Owner => true,
            Self::Delegated(set) => set.contains(&DelegatePermission::FullAccess),
        }
    }

    /// `Gate::Submit` / `Gate::Collaborate`: `Owner | full_access | send_as | send_on_behalf`.
    pub fn can_submit(&self) -> bool {
        match self {
            Self::Owner => true,
            Self::Delegated(set) => {
                set.contains(&DelegatePermission::FullAccess)
                    || set.contains(&DelegatePermission::SendAs)
                    || set.contains(&DelegatePermission::SendOnBehalf)
            }
        }
    }

    /// Send-As identity authority: `Owner | full_access | send_as`.
    pub fn can_send_as(&self) -> bool {
        match self {
            Self::Owner => true,
            Self::Delegated(set) => {
                set.contains(&DelegatePermission::FullAccess)
                    || set.contains(&DelegatePermission::SendAs)
            }
        }
    }

    /// Calendar delegation authority: `Owner | full_access | manage_calendar`.
    pub fn can_manage_calendar(&self) -> bool {
        match self {
            Self::Owner => true,
            Self::Delegated(set) => {
                set.contains(&DelegatePermission::FullAccess)
                    || set.contains(&DelegatePermission::ManageCalendar)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Distinct narrow capability tokens minted from MailboxPrincipal
// ---------------------------------------------------------------------------

/// Capability proof for `Gate::Personal` (`Owner` only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerCapability {
    verified: VerifiedMailbox,
}

impl OwnerCapability {
    pub const fn actor(&self) -> ActorId {
        self.verified.actor()
    }
    pub const fn mailbox(&self) -> MailboxId {
        self.verified.mailbox()
    }
    pub(crate) fn verified(&self) -> &VerifiedMailbox {
        &self.verified
    }
}

/// Capability proof for `Gate::Read` (`Owner | full_access | send_as | send_on_behalf | read`).
/// Can open `MailboxTx<ReadOnly>`, never `MailboxTx<ReadWrite>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadCapability {
    verified: VerifiedMailbox,
}

impl ReadCapability {
    pub const fn actor(&self) -> ActorId {
        self.verified.actor()
    }
    pub const fn mailbox(&self) -> MailboxId {
        self.verified.mailbox()
    }
    pub(crate) fn verified(&self) -> &VerifiedMailbox {
        &self.verified
    }
}

/// Capability proof for `Gate::Mutate` (`Owner | full_access` ONLY).
/// The ONLY token accepted by [`TxFactory::run_mailbox_write`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutateCapability {
    verified: VerifiedMailbox,
}

impl MutateCapability {
    pub const fn actor(&self) -> ActorId {
        self.verified.actor()
    }
    pub const fn mailbox(&self) -> MailboxId {
        self.verified.mailbox()
    }
    pub(crate) fn verified(&self) -> &VerifiedMailbox {
        &self.verified
    }
}

/// Distinct narrow capability proof for `Gate::Submit` / `Gate::Collaborate`
/// (`Owner | full_access | send_as | send_on_behalf`).
///
/// Intentionally a distinct type from [`MutateCapability`] so a `send_as` or
/// `send_on_behalf` delegate cannot accidentally satisfy `Gate::Mutate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitCapability {
    verified: VerifiedMailbox,
    can_send_as: bool,
}

impl SubmitCapability {
    pub const fn actor(&self) -> ActorId {
        self.verified.actor()
    }
    pub const fn mailbox(&self) -> MailboxId {
        self.verified.mailbox()
    }
    pub const fn can_send_as(&self) -> bool {
        self.can_send_as
    }
    pub(crate) fn verified(&self) -> &VerifiedMailbox {
        &self.verified
    }
}

/// Capability proof for Send-As (`Owner | full_access | send_as`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendAsCapability {
    verified: VerifiedMailbox,
}

impl SendAsCapability {
    pub const fn actor(&self) -> ActorId {
        self.verified.actor()
    }
    pub const fn mailbox(&self) -> MailboxId {
        self.verified.mailbox()
    }
}

/// Capability proof for calendar delegation (`Owner | full_access | manage_calendar`).
/// Cannot satisfy any mail gate (`Read`, `Mutate`, `Submit`, `Personal`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CalendarCapability {
    verified: VerifiedMailbox,
}

impl CalendarCapability {
    pub const fn actor(&self) -> ActorId {
        self.verified.actor()
    }
    pub const fn mailbox(&self) -> MailboxId {
        self.verified.mailbox()
    }
    pub(crate) fn verified(&self) -> &VerifiedMailbox {
        &self.verified
    }
}

// ---------------------------------------------------------------------------
// Sealed Principals (private fields, pub(crate) constructors, no Deserialize/Default)
// ---------------------------------------------------------------------------

/// Verified principal scoped to one live target mailbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailboxPrincipal {
    actor: ActorId,
    mailbox: MailboxId,
    authority: MailboxAuthority,
    generation: Generation,
    groups: Arc<GroupMembership>,
    impersonator: Option<ActorId>,
    audit_meta: AuditMeta,
}

impl MailboxPrincipal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        actor: ActorId,
        mailbox: MailboxId,
        authority: MailboxAuthority,
        generation: Generation,
        groups: Arc<GroupMembership>,
        impersonator: Option<ActorId>,
        audit_meta: AuditMeta,
    ) -> Self {
        Self {
            actor,
            mailbox,
            authority,
            generation,
            groups,
            impersonator,
            audit_meta,
        }
    }

    pub const fn actor(&self) -> ActorId {
        self.actor
    }

    pub const fn mailbox(&self) -> MailboxId {
        self.mailbox
    }

    pub fn authority(&self) -> &MailboxAuthority {
        &self.authority
    }

    pub const fn generation(&self) -> Generation {
        self.generation
    }

    pub fn groups(&self) -> &GroupMembership {
        &self.groups
    }

    pub const fn impersonator(&self) -> Option<ActorId> {
        self.impersonator
    }

    pub fn audit_meta(&self) -> &AuditMeta {
        &self.audit_meta
    }

    fn verified_mailbox(&self) -> VerifiedMailbox {
        setjoin_pg::mint::mailbox(self.actor, self.mailbox, self.generation)
    }

    /// `Gate::Personal`: requires `Owner` only.
    pub fn require_owner(&self) -> Result<OwnerCapability, PrincipalError> {
        if self.authority.is_owner() {
            Ok(OwnerCapability {
                verified: self.verified_mailbox(),
            })
        } else {
            Err(PrincipalError::Forbidden("mailbox owner required"))
        }
    }

    /// `Gate::Read`: requires `Owner | full_access | send_as | send_on_behalf | read`.
    pub fn require_read(&self) -> Result<ReadCapability, PrincipalError> {
        if self.authority.can_read() {
            Ok(ReadCapability {
                verified: self.verified_mailbox(),
            })
        } else {
            Err(PrincipalError::Forbidden(
                "mailbox mail-read grant required",
            ))
        }
    }

    /// `Gate::Mutate`: requires `Owner | full_access` ONLY.
    pub fn require_mutate(&self) -> Result<MutateCapability, PrincipalError> {
        if self.authority.can_mutate() {
            Ok(MutateCapability {
                verified: self.verified_mailbox(),
            })
        } else {
            Err(PrincipalError::Forbidden(
                "mailbox owner or full_access grant required",
            ))
        }
    }

    /// `Gate::Submit` / `Gate::Collaborate`: requires `Owner | full_access | send_as | send_on_behalf`.
    /// Returns a distinct [`SubmitCapability`] that cannot satisfy `Gate::Mutate`.
    pub fn require_submit(&self) -> Result<SubmitCapability, PrincipalError> {
        if self.authority.can_submit() {
            Ok(SubmitCapability {
                verified: self.verified_mailbox(),
                can_send_as: self.authority.can_send_as(),
            })
        } else {
            Err(PrincipalError::Forbidden(
                "mailbox submit/send delegation required",
            ))
        }
    }

    /// Send-As identity grant: requires `Owner | full_access | send_as`.
    pub fn require_send_as(&self) -> Result<SendAsCapability, PrincipalError> {
        if self.authority.can_send_as() {
            Ok(SendAsCapability {
                verified: self.verified_mailbox(),
            })
        } else {
            Err(PrincipalError::Forbidden(
                "mailbox owner, full_access, or send_as grant required",
            ))
        }
    }

    /// Calendar delegation grant: requires `Owner | full_access | manage_calendar`.
    pub fn require_manage_calendar(&self) -> Result<CalendarCapability, PrincipalError> {
        if self.authority.can_manage_calendar() {
            Ok(CalendarCapability {
                verified: self.verified_mailbox(),
            })
        } else {
            Err(PrincipalError::Forbidden(
                "mailbox owner, full_access, or manage_calendar grant required",
            ))
        }
    }
}

/// Verified mailbox-less user principal (Chat, Meet, Drive, Guests, User Settings).
/// Intentionally carries no `MailboxId`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserPrincipal {
    user: ActorId,
    is_guest: bool,
    domain_id: Option<i64>,
    groups: Arc<GroupMembership>,
    entitlements: BTreeSet<String>,
    generation: Generation,
    impersonator: Option<ActorId>,
    audit_meta: AuditMeta,
}

impl UserPrincipal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        user: ActorId,
        is_guest: bool,
        domain_id: Option<i64>,
        groups: Arc<GroupMembership>,
        entitlements: BTreeSet<String>,
        generation: Generation,
        impersonator: Option<ActorId>,
        audit_meta: AuditMeta,
    ) -> Self {
        Self {
            user,
            is_guest,
            domain_id,
            groups,
            entitlements,
            generation,
            impersonator,
            audit_meta,
        }
    }

    pub const fn user(&self) -> ActorId {
        self.user
    }

    pub const fn is_guest(&self) -> bool {
        self.is_guest
    }

    pub const fn domain_id(&self) -> Option<i64> {
        self.domain_id
    }

    pub fn groups(&self) -> &GroupMembership {
        &self.groups
    }

    pub fn entitlements(&self) -> &BTreeSet<String> {
        &self.entitlements
    }

    pub fn has_entitlement(&self, app: &str) -> bool {
        self.entitlements.contains(app)
    }

    pub const fn generation(&self) -> Generation {
        self.generation
    }

    pub const fn impersonator(&self) -> Option<ActorId> {
        self.impersonator
    }

    pub fn audit_meta(&self) -> &AuditMeta {
        &self.audit_meta
    }

    pub(crate) fn verified_user(&self) -> VerifiedUser {
        setjoin_pg::mint::user(self.user, self.generation)
    }
}

/// Verified live-RBAC admin principal.
///
/// Security invariants:
/// - Guests and impersonated sessions (`act.is_some()`) are always refused.
/// - `enforced_domain_scope` is the **narrowest non-NULL**
///   `MIN(COALESCE(ra.domain_override, rg.domain_scope))` across active
///   assignments — NEVER widened by `broadest_scope` (`admin_effective_authority`).
/// - Dormant JIT-eligible assignments (`NOT admin_assignment_active(ra.eligible, ra.activated_until)`)
///   are excluded.
/// - When `dengbao.sod_mode` is ON, any unclassified role (`sod_class IS NULL`),
///   unclassifiable permission (`users.impersonate` / unknown perm), Super Admin
///   role spanning >=2 exclusive classes, or principal spanning >1 distinct class
///   is refused fail-closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminPrincipal {
    actor: ActorId,
    generation: Generation,
    role_group_ids: Vec<i64>,
    permissions: BTreeSet<String>,
    global_permissions: BTreeSet<String>,
    /// Narrowest non-NULL domain restriction to ENFORCE on requests
    /// (`MIN(COALESCE(ra.domain_override, rg.domain_scope))`).
    enforced_domain_scope: Option<i64>,
    /// Broadest reach domain (`None` if ANY active assignment is global, else
    /// `MIN(eff_scope)`), used ONLY for target-protection checks.
    broadest_scope: Option<i64>,
    /// Broadest OU reach (`None` if ANY active assignment has `scope_type IS NULL`).
    ou_reach: Option<Vec<String>>,
    /// True iff the actor holds ANY active object-unrestricted (`scope_type IS NULL`) grant.
    is_unconfined: bool,
    sod_enforced: bool,
    active_sod_classes: BTreeSet<String>,
    groups: Arc<GroupMembership>,
    audit_meta: AuditMeta,
}

impl AdminPrincipal {
    pub const fn actor(&self) -> ActorId {
        self.actor
    }

    pub const fn generation(&self) -> Generation {
        self.generation
    }

    pub fn role_group_ids(&self) -> &[i64] {
        &self.role_group_ids
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub fn global_permissions(&self) -> &BTreeSet<String> {
        &self.global_permissions
    }

    /// Narrowest non-NULL domain scope to ENFORCE (exact parity with
    /// `admin-identity::authority` & `platform::authority`). `None` means global.
    pub const fn enforced_domain_scope(&self) -> Option<i64> {
        self.enforced_domain_scope
    }

    /// Broadest domain reach for target-protection checks only.
    pub const fn broadest_scope(&self) -> Option<i64> {
        self.broadest_scope
    }

    /// Broadest OU subtree paths for target-protection checks only.
    pub fn ou_reach(&self) -> Option<&[String]> {
        self.ou_reach.as_deref()
    }

    /// True iff any active assignment has `scope_type IS NULL`.
    pub const fn is_unconfined(&self) -> bool {
        self.is_unconfined
    }

    pub const fn sod_enforced(&self) -> bool {
        self.sod_enforced
    }

    pub fn active_sod_classes(&self) -> &BTreeSet<String> {
        &self.active_sod_classes
    }

    pub fn groups(&self) -> &GroupMembership {
        &self.groups
    }

    pub fn audit_meta(&self) -> &AuditMeta {
        &self.audit_meta
    }

    pub fn has_permission(&self, perm: &str) -> bool {
        self.permissions.contains(perm)
    }

    pub fn allows_any(&self, wanted: &[&str]) -> bool {
        wanted.iter().any(|p| self.permissions.contains(*p))
    }

    pub fn global_any(&self, wanted: &[&str]) -> bool {
        wanted.iter().any(|p| self.global_permissions.contains(*p))
    }

    /// True when the route requires a global-only permission (`audit.read` /
    /// `audit.export`) and this principal has a domain restriction.
    pub fn refused_for_scope(&self, required: &[&str]) -> bool {
        self.enforced_domain_scope.is_some()
            && required.iter().any(|p| GLOBAL_ONLY_PERMISSIONS.contains(p))
    }

    /// Mint a sealed RBAC [`AdminPermissionProof`] after verifying this admin
    /// holds `perm` and satisfies global-only scope restrictions (#546a).
    pub fn require_permission(&self, perm: &str) -> Result<AdminPermissionProof, PrincipalError> {
        self.require_any_permission(&[perm])
    }

    /// Mint a sealed RBAC [`AdminPermissionProof`] after verifying this admin
    /// holds at least one of `required` and satisfies global-only scope rules.
    pub fn require_any_permission(
        &self,
        required: &[&str],
    ) -> Result<AdminPermissionProof, PrincipalError> {
        if required.is_empty() {
            return Err(PrincipalError::Forbidden("admin permission required"));
        }
        if self.refused_for_scope(required) {
            return Err(PrincipalError::Forbidden(
                "global admin scope required for permission",
            ));
        }
        if !self.allows_any(required) {
            return Err(PrincipalError::Forbidden(
                "missing required admin permission",
            ));
        }
        Ok(AdminPermissionProof {
            verified: self.verified_admin(),
            enforced_domain_scope: self.enforced_domain_scope,
            sod_enforced: self.sod_enforced,
        })
    }

    /// Mint a sealed RBAC [`AdminPermissionProof`] requiring an unrestricted
    /// global assignment holding at least one of `required`.
    pub fn require_global_permission(
        &self,
        required: &[&str],
    ) -> Result<AdminPermissionProof, PrincipalError> {
        if required.is_empty() {
            return Err(PrincipalError::Forbidden(
                "global admin permission required",
            ));
        }
        if self.enforced_domain_scope.is_some() || !self.global_any(required) {
            return Err(PrincipalError::Forbidden(
                "unrestricted global admin permission required",
            ));
        }
        Ok(AdminPermissionProof {
            verified: self.verified_admin(),
            enforced_domain_scope: None,
            sod_enforced: self.sod_enforced,
        })
    }

    pub(crate) fn verified_admin(&self) -> VerifiedAdmin {
        setjoin_pg::mint::admin(self.actor, self.generation)
    }
}

/// Sealed RBAC permission proof minted exclusively from [`AdminPrincipal`]
/// (`require_permission` / `require_any_permission` / `require_global_permission`).
///
/// Required by [`TxFactory`] before vending any cross-tenant `AdminReadTx`,
/// `AdminSensitiveRead`, or `AdminWriteTx` over [`AdminWorkerPool`] (#546a).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminPermissionProof {
    verified: VerifiedAdmin,
    enforced_domain_scope: Option<i64>,
    sod_enforced: bool,
}

impl AdminPermissionProof {
    pub const fn actor(&self) -> ActorId {
        self.verified.actor()
    }

    pub const fn generation(&self) -> Generation {
        self.verified.generation()
    }

    pub const fn enforced_domain_scope(&self) -> Option<i64> {
        self.enforced_domain_scope
    }

    pub const fn sod_enforced(&self) -> bool {
        self.sod_enforced
    }

    pub(crate) fn verified(&self) -> &VerifiedAdmin {
        &self.verified
    }
}

// ---------------------------------------------------------------------------
// SoD classification matching mailserver/sql/reducers/admin_sod_precheck.sql
// ---------------------------------------------------------------------------

/// Exact mirror of `perm_class_map` in `mailserver/sql/reducers/admin_sod_precheck.sql`.
/// Empty slice means a no-class (unclassifiable) permission such as `users.impersonate`.
pub(crate) fn perm_sod_classes(perm: &str) -> &'static [&'static str] {
    match perm {
        "users.read" | "exchange.assessment.read" => &["system", "security", "audit"],
        "compliance.read" => &["security", "audit"],
        "users.create"
        | "users.delete"
        | "domains.read"
        | "domains.write"
        | "queue.read"
        | "queue.write"
        | "backup.read"
        | "backup.write"
        | "system.config"
        | "system.upgrade"
        | "mail.pipeline"
        | "reports.read"
        | "mail.offline_policy"
        | "exchange.assessment.run"
        | "exchange.assessment.delete" => &["system"],
        "users.suspend"
        | "users.password_reset"
        | "roles.manage"
        | "security.write"
        | "mail.security"
        | "identity.write"
        | "mam.write"
        | "compliance.write"
        | "scope_sets.manage"
        | "approvals.view"
        | "approvals.manage"
        | "exchange.assessment.decide"
        | "exchange.assessment.publish"
        | "sharing.read"
        | "sharing.manage"
        | "access.policy_read"
        | "access.policy_write" => &["security"],
        "audit.read"
        | "audit.export"
        | "mam.read"
        | "exchange.assessment.attest"
        | "exchange.assessment.audit" => &["audit"],
        _ => &[],
    }
}

fn check_sod_violations(
    roles: &[(i64, Option<String>, Vec<String>)],
) -> Result<BTreeSet<String>, PrincipalError> {
    let mut classes = BTreeSet::new();
    let mut role_level_violation: Option<&'static str> = None;

    for (_role_id, sod_class, perms) in roles {
        let mut has_noclass = false;
        let mut exclusive_classes = BTreeSet::new();
        for p in perms {
            let mapped = perm_sod_classes(p);
            if mapped.is_empty() {
                has_noclass = true;
            } else if mapped.len() == 1 {
                exclusive_classes.insert(mapped[0]);
            }
        }
        // Priority order per admin_sod_precheck.sql:
        // 1. cross_class (checked across all roles below)
        // 2. super_admin_role (exclusive_class_count >= 2)
        // 3. unclassifiable_perm
        // 4. unclassified_role (sod_class IS NULL)
        if exclusive_classes.len() >= 2 {
            role_level_violation = Some("super_admin_role");
        } else if has_noclass && role_level_violation != Some("super_admin_role") {
            role_level_violation = Some("unclassifiable_perm");
        } else if sod_class.as_deref().is_none_or(str::is_empty) && role_level_violation.is_none() {
            role_level_violation = Some("unclassified_role");
        }
        if let Some(c) = sod_class.as_deref().filter(|s| !s.is_empty()) {
            classes.insert(c.to_owned());
        }
    }

    if classes.len() > 1 {
        return Err(PrincipalError::SodViolation("cross_class"));
    }
    if let Some(violation) = role_level_violation {
        return Err(PrincipalError::SodViolation(violation));
    }
    Ok(classes)
}

// ---------------------------------------------------------------------------
// TxFactory (privately owns AppPool, mints #540 handles from sealed principals)
// ---------------------------------------------------------------------------

/// Capability-gated database transaction factory.
///
/// Wraps `#540`'s [`AppPool`] (`setjoin_app`, `NOBYPASSRLS`) for all tenant
/// mailbox/user transactions alongside an encapsulated [`AdminWorkerPool`]
/// (`setjoin_worker`, `BYPASSRLS`) for RBAC-proved cross-tenant admin
/// transactions and private pre-auth credential proofs (#546a).
#[derive(Clone)]
pub struct TxFactory {
    pool: AppPool,
    admin_pool: Option<AdminWorkerPool>,
    groups: Arc<GroupResolver>,
}

impl TxFactory {
    /// Construct a `TxFactory` with its own bounded-LRU [`GroupResolver`] and
    /// no cross-tenant [`AdminWorkerPool`] (admin/pre-auth paths fail closed).
    pub fn new(pool: AppPool) -> Self {
        let groups = Arc::new(GroupResolver::new(pool.clone()));
        Self {
            pool,
            admin_pool: None,
            groups,
        }
    }

    /// Construct a `TxFactory` sharing an externally-managed [`GroupResolver`]
    /// (for example, one subscribed to `group_membership_changed` over `DB_DIRECT_DSN`).
    pub fn with_group_resolver(pool: AppPool, groups: Arc<GroupResolver>) -> Self {
        Self {
            pool,
            admin_pool: None,
            groups,
        }
    }

    /// Canonical composition-root constructor wiring both `AppPool` (`setjoin_app`,
    /// `NOBYPASSRLS`) and encapsulated `AdminWorkerPool` (`setjoin_worker`,
    /// `BYPASSRLS`) plus the shared [`GroupResolver`] (#546a).
    pub fn with_admin_pool(
        pool: AppPool,
        admin_pool: AdminWorkerPool,
        groups: Arc<GroupResolver>,
    ) -> Self {
        Self {
            pool,
            admin_pool: Some(admin_pool),
            groups,
        }
    }

    pub fn has_admin_worker_pool(&self) -> bool {
        self.admin_pool.is_some()
    }

    pub fn group_resolver(&self) -> &Arc<GroupResolver> {
        &self.groups
    }

    /// Run a 1-RTT `BEGIN READ ONLY` public/system contract query (`SqlScope::AuthPreScope`)
    /// on `AppPool` (`setjoin_app`, `NOBYPASSRLS`) with empty tenant GUCs.
    pub async fn run_public_read_contract(
        &self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.pool.run_public_read_contract(contract, values).await
    }

    /// Mint a sealed [`UserPrincipal`] from an already-admitted [`crate::Authorized`] session.
    pub async fn mint_user_from_authorized(
        &self,
        auth: &crate::Authorized,
        client_ip: &str,
    ) -> Result<UserPrincipal, PrincipalError> {
        let ctx = auth.context();
        let actor = ActorId::new(ctx.user_id()).map_err(|_| PrincipalError::InvalidTarget)?;
        let impersonator = ctx.actor_id().and_then(|id| ActorId::new(id).ok());
        self.mint_user_principal(
            actor,
            ctx.is_guest(),
            Generation(1),
            impersonator,
            BTreeSet::new(),
            AuditMeta::new(ctx.email(), client_ip),
        )
        .await
    }

    /// Mint a sealed [`MailboxPrincipal`] for the admitted session's own primary mailbox.
    pub async fn mint_primary_mailbox_from_authorized(
        &self,
        auth: &crate::Authorized,
        client_ip: &str,
    ) -> Result<MailboxPrincipal, PrincipalError> {
        let mailbox = MailboxId::new(auth.context().mailbox_id())
            .map_err(|_| PrincipalError::Forbidden("no primary mailbox"))?;
        self.mint_mailbox_from_authorized(auth, mailbox, client_ip)
            .await
    }

    /// Mint a sealed [`MailboxPrincipal`] for an explicit target mailbox (owner or delegate)
    /// from an already-admitted [`crate::Authorized`] session.
    pub async fn mint_mailbox_from_authorized(
        &self,
        auth: &crate::Authorized,
        mailbox: MailboxId,
        client_ip: &str,
    ) -> Result<MailboxPrincipal, PrincipalError> {
        let ctx = auth.context();
        let actor = ActorId::new(ctx.user_id()).map_err(|_| PrincipalError::InvalidTarget)?;
        let impersonator = ctx.actor_id().and_then(|id| ActorId::new(id).ok());
        self.mint_mailbox_principal(
            actor,
            mailbox,
            ctx.is_guest(),
            Generation(1),
            impersonator,
            AuditMeta::new(ctx.email(), client_ip),
        )
        .await
    }

    /// Mint a sealed [`AdminPrincipal`] from an already-admitted [`crate::Authorized`] session
    /// using live JIT/SoD-enforced DB role assignments.
    pub async fn mint_admin_from_authorized(
        &self,
        auth: &crate::Authorized,
        client_ip: &str,
    ) -> Result<AdminPrincipal, PrincipalError> {
        let ctx = auth.context();
        let actor = ActorId::new(ctx.user_id()).map_err(|_| PrincipalError::InvalidTarget)?;
        let impersonator = ctx.actor_id().and_then(|id| ActorId::new(id).ok());
        self.mint_admin_principal(
            actor,
            ctx.is_guest(),
            Generation(1),
            impersonator,
            AuditMeta::new(ctx.email(), client_ip),
        )
        .await
    }

    /// Mint a sealed [`UserPrincipal`] for a verified non-JWT capability actor
    /// (such as a DB-verified WOPI launch token or HMAC approval-email token).
    pub async fn mint_capability_user(
        &self,
        actor: ActorId,
        email: &str,
        client_ip: &str,
    ) -> Result<UserPrincipal, PrincipalError> {
        self.mint_user_principal(
            actor,
            false,
            Generation(1),
            None,
            BTreeSet::new(),
            AuditMeta::new(email, client_ip),
        )
        .await
    }

    /// Mint a sealed [`MailboxPrincipal`] for a verified non-JWT capability actor's
    /// primary mailbox (e.g., HMAC approval-email link).
    pub async fn mint_capability_primary_mailbox(
        &self,
        actor: ActorId,
        email: &str,
        client_ip: &str,
    ) -> Result<MailboxPrincipal, PrincipalError> {
        let verified_user = setjoin_pg::mint::user(actor, Generation(1));
        let actor_id = actor.get();
        let rows = self
            .pool
            .run_user_read_pipelined(
                &verified_user,
                "SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary LIMIT 1",
                &[(&actor_id, Type::INT8)],
            )
            .await?;
        let mb_id: i64 = rows
            .first()
            .and_then(|r| r.try_get(0).ok())
            .ok_or(PrincipalError::Forbidden("no primary mailbox"))?;
        let mailbox = MailboxId::new(mb_id).map_err(|_| PrincipalError::InvalidTarget)?;
        self.mint_mailbox_principal(
            actor,
            mailbox,
            false,
            Generation(1),
            None,
            AuditMeta::new(email, client_ip),
        )
        .await
    }

    /// Mint a sealed [`MailboxPrincipal`] for a verified non-JWT capability actor
    /// targeting a specific mailbox (e.g., IMAP `SELECT`/`EXAMINE` on a secondary
    /// owned mailbox). Live-verifies ownership/delegation and mailbox lifecycle.
    pub async fn mint_capability_mailbox(
        &self,
        actor: ActorId,
        mailbox: MailboxId,
        email: &str,
        client_ip: &str,
    ) -> Result<MailboxPrincipal, PrincipalError> {
        self.mint_mailbox_principal(
            actor,
            mailbox,
            false,
            Generation(1),
            None,
            AuditMeta::new(email, client_ip),
        )
        .await
    }

    fn require_admin_pool(&self) -> Result<&AdminWorkerPool, StatementFailure> {
        self.admin_pool.as_ref().ok_or_else(|| StatementFailure {
            sqlstate: None,
            hint: None,
            message: "admin worker pool not configured".into(),
        })
    }

    // ---- Internal principal minting helpers (called only by PolicyGate) ----

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn mint_mailbox_principal(
        &self,
        actor: ActorId,
        target_mailbox: MailboxId,
        is_guest: bool,
        generation: Generation,
        impersonator: Option<ActorId>,
        audit_meta: AuditMeta,
    ) -> Result<MailboxPrincipal, PrincipalError> {
        if is_guest {
            return Err(PrincipalError::GuestRefused);
        }
        let verified_user = setjoin_pg::mint::user(actor, generation);
        let mut tx = self.pool.begin_user_read(&verified_user).await?;
        let target_id = target_mailbox.get();
        let actor_id = actor.get();

        // Uncached live check on mailbox existence, owner, and lifecycle status.
        let mb_rows = tx
            .query(
                "SELECT user_id, mailbox_lifecycle_access_allowed(id) \
                   FROM mailboxes WHERE id = $1",
                &[(&target_id, Type::INT8)],
            )
            .await?;
        let Some(mb_row) = mb_rows.first() else {
            let _ = tx.finish().await;
            return Err(PrincipalError::Forbidden("mailbox not found"));
        };
        let owner_user_id: Option<i64> = mb_row
            .try_get(0)
            .map_err(|e| PrincipalError::Unavailable(e.to_string()))?;
        let lifecycle_allowed: Option<bool> = mb_row
            .try_get(1)
            .map_err(|e| PrincipalError::Unavailable(e.to_string()))?;

        let authority = if owner_user_id == Some(actor_id) {
            MailboxAuthority::Owner
        } else {
            // Uncached live read on mailbox_delegates (FORCE RLS uses app.current_user_id = actor).
            let del_rows = tx
                .query(
                    "SELECT permission FROM mailbox_delegates \
                      WHERE mailbox_id = $1 AND user_id = $2",
                    &[(&target_id, Type::INT8), (&actor_id, Type::INT8)],
                )
                .await?;
            let mut perms = BTreeSet::new();
            for row in &del_rows {
                let raw: String = row
                    .try_get(0)
                    .map_err(|e| PrincipalError::Unavailable(e.to_string()))?;
                if let Some(p) = DelegatePermission::parse(&raw) {
                    perms.insert(p);
                }
            }
            if perms.is_empty() {
                let _ = tx.finish().await;
                return Err(PrincipalError::Forbidden("no grant on target mailbox"));
            }
            MailboxAuthority::Delegated(perms)
        };
        tx.finish().await?;

        if lifecycle_allowed != Some(true) {
            return Err(PrincipalError::MailboxBlocked);
        }

        let groups = self.groups.resolve(actor_id).await?;
        Ok(MailboxPrincipal::new(
            actor,
            target_mailbox,
            authority,
            generation,
            groups,
            impersonator,
            audit_meta,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn mint_user_principal(
        &self,
        actor: ActorId,
        is_guest: bool,
        generation: Generation,
        impersonator: Option<ActorId>,
        entitlements: BTreeSet<String>,
        audit_meta: AuditMeta,
    ) -> Result<UserPrincipal, PrincipalError> {
        let verified_user = setjoin_pg::mint::user(actor, generation);
        let actor_id = actor.get();
        let rows = self
            .pool
            .run_user_read_pipelined(
                &verified_user,
                "SELECT domain_id FROM users WHERE id = $1",
                &[(&actor_id, Type::INT8)],
            )
            .await?;
        let domain_id: Option<i64> = rows
            .first()
            .and_then(|r| r.try_get::<_, Option<i64>>(0).ok().flatten());
        let groups = self.groups.resolve(actor_id).await?;
        Ok(UserPrincipal::new(
            actor,
            is_guest,
            domain_id,
            groups,
            entitlements,
            generation,
            impersonator,
            audit_meta,
        ))
    }

    pub(crate) async fn mint_admin_principal(
        &self,
        actor: ActorId,
        is_guest: bool,
        generation: Generation,
        impersonator: Option<ActorId>,
        audit_meta: AuditMeta,
    ) -> Result<AdminPrincipal, PrincipalError> {
        if is_guest {
            return Err(PrincipalError::GuestRefused);
        }
        if impersonator.is_some() {
            return Err(PrincipalError::ImpersonationRefused);
        }

        let verified_user = setjoin_pg::mint::user(actor, generation);
        let actor_id = actor.get();
        // Single live query over active, unexpired, JIT-activated role assignments
        // plus dengbao.sod_mode toggle. Never falls back to JWT claims on error.
        const ADMIN_LIVE_SQL: &str = "\
SELECT ra.role_group_id, \
       rg.permissions, \
       COALESCE(ra.domain_override, rg.domain_scope) AS eff_scope, \
       ra.scope_type, \
       sd.path AS ou_path, \
       rg.sod_class, \
       COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'dengbao.sod_mode'), FALSE) AS sod_mode \
  FROM admin_role_assignments ra \
  JOIN admin_role_groups rg ON rg.id = ra.role_group_id \
  LEFT JOIN departments sd ON ra.scope_type = 'ou' AND sd.id = ra.scope_id \
 WHERE ra.user_id = $1 \
   AND (ra.expires_at IS NULL OR ra.expires_at > now()) \
   AND admin_assignment_active(ra.eligible, ra.activated_until) \
 ORDER BY ra.role_group_id";

        let rows = self
            .pool
            .run_user_read_pipelined(&verified_user, ADMIN_LIVE_SQL, &[(&actor_id, Type::INT8)])
            .await?;

        if rows.is_empty() {
            return Err(PrincipalError::Forbidden(
                "no active governed admin role assignments",
            ));
        }

        let mut role_group_ids = Vec::new();
        let mut seen_roles: BTreeMap<i64, (Option<String>, Vec<String>)> = BTreeMap::new();
        let mut permissions = BTreeSet::new();
        let mut global_permissions = BTreeSet::new();
        let mut min_non_null_domain: Option<i64> = None;
        let mut has_global_domain = false;
        let mut has_unconfined = false;
        let mut ou_paths = BTreeSet::new();
        let mut sod_enforced = false;

        for row in &rows {
            let role_id: i64 = row
                .try_get(0)
                .map_err(|e| PrincipalError::Unavailable(e.to_string()))?;
            let perms: Vec<String> = row
                .try_get(1)
                .map_err(|e| PrincipalError::Unavailable(e.to_string()))?;
            let eff_scope: Option<i64> = row
                .try_get(2)
                .map_err(|e| PrincipalError::Unavailable(e.to_string()))?;
            let scope_type: Option<String> = row
                .try_get(3)
                .map_err(|e| PrincipalError::Unavailable(e.to_string()))?;
            let ou_path: Option<String> = row
                .try_get(4)
                .map_err(|e| PrincipalError::Unavailable(e.to_string()))?;
            let sod_class: Option<String> = row
                .try_get(5)
                .map_err(|e| PrincipalError::Unavailable(e.to_string()))?;
            sod_enforced = row
                .try_get(6)
                .map_err(|e| PrincipalError::Unavailable(e.to_string()))?;

            if let std::collections::btree_map::Entry::Vacant(entry) = seen_roles.entry(role_id) {
                role_group_ids.push(role_id);
                entry.insert((sod_class, perms.clone()));
            }

            let is_global_assignment = eff_scope.is_none() && scope_type.is_none();
            for p in &perms {
                permissions.insert(p.clone());
                if is_global_assignment {
                    global_permissions.insert(p.clone());
                }
            }

            match eff_scope {
                Some(domain) => {
                    min_non_null_domain = Some(match min_non_null_domain {
                        Some(cur) => cur.min(domain),
                        None => domain,
                    });
                }
                None => {
                    has_global_domain = true;
                }
            }

            if scope_type.is_none() {
                has_unconfined = true;
            } else if let Some(path) = ou_path {
                ou_paths.insert(path);
            }
        }

        // Narrowest non-NULL wins for ENFORCEMENT (never widened by global roles!).
        let enforced_domain_scope = min_non_null_domain;
        // Broadest reach for target-protection checks only.
        let broadest_scope = if has_global_domain {
            None
        } else {
            min_non_null_domain
        };
        let ou_reach = if has_unconfined || ou_paths.is_empty() {
            None
        } else {
            Some(ou_paths.into_iter().collect())
        };

        let role_facts: Vec<(i64, Option<String>, Vec<String>)> = seen_roles
            .into_iter()
            .map(|(id, (cls, perms))| (id, cls, perms))
            .collect();
        let active_sod_classes = if sod_enforced {
            check_sod_violations(&role_facts)?
        } else {
            role_facts
                .iter()
                .filter_map(|(_, cls, _)| {
                    cls.as_deref().filter(|s| !s.is_empty()).map(str::to_owned)
                })
                .collect()
        };

        let groups = self.groups.resolve(actor_id).await?;
        Ok(AdminPrincipal {
            actor,
            generation,
            role_group_ids,
            permissions,
            global_permissions,
            enforced_domain_scope,
            broadest_scope,
            ou_reach,
            is_unconfined: has_unconfined,
            sod_enforced,
            active_sod_classes,
            groups,
            audit_meta,
        })
    }

    // ---- Mailbox transactions (strictly capability-gated) ----

    /// Begin a `MailboxTx<ReadOnly>` from a verified [`ReadCapability`].
    pub async fn begin_mailbox_read(
        &self,
        cap: &ReadCapability,
    ) -> Result<MailboxTx<ReadOnly>, StatementFailure> {
        self.pool.begin_mailbox_read(cap.verified()).await
    }

    /// Run a 1-RTT pipelined `BEGIN READ ONLY` mailbox query from a [`ReadCapability`].
    pub async fn run_mailbox_read_pipelined(
        &self,
        cap: &ReadCapability,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.pool
            .run_mailbox_read_pipelined(cap.verified(), sql, params)
            .await
    }

    /// Run a 1-RTT pipelined `BEGIN READ ONLY` mailbox [`SqlContract`] query.
    pub async fn run_mailbox_read_contract(
        &self,
        cap: &ReadCapability,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.pool
            .run_mailbox_read_contract(cap.verified(), contract, values)
            .await
    }

    /// Run a 1-RTT pipelined `BEGIN READ WRITE` mailbox [`SqlContract`] write.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_mailbox_write_contract_pipelined<C, T, P>(
        &self,
        cap: &MutateCapability,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        self.pool
            .run_mailbox_write_contract_pipelined(
                envelope,
                cap.verified(),
                deadline,
                contract,
                values,
                receipt,
                project,
            )
            .await
    }

    /// Run a 1-RTT pipelined `BEGIN READ ONLY` calendar [`SqlContract`] query.
    pub async fn run_calendar_read_contract(
        &self,
        cap: &CalendarCapability,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.pool
            .run_mailbox_read_contract(cap.verified(), contract, values)
            .await
    }

    /// Run a 1-RTT pipelined `BEGIN READ WRITE` calendar [`SqlContract`] write.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_calendar_write_contract_pipelined<C, T, P>(
        &self,
        cap: &CalendarCapability,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        self.pool
            .run_mailbox_write_contract_pipelined(
                envelope,
                cap.verified(),
                deadline,
                contract,
                values,
                receipt,
                project,
            )
            .await
    }

    /// Look up whether a receipted calendar command committed under current authority.
    pub async fn lookup_calendar_command(
        &self,
        cap: &CalendarCapability,
        operation: OperationId,
        command: ReceiptCommand,
    ) -> Result<OperationLookup, StatementFailure> {
        self.pool
            .lookup_mailbox_command(cap.verified(), operation, command)
            .await
    }

    /// Run an interactive `MailboxTx<ReadWrite>` strictly from a [`MutateCapability`]
    /// (`Owner | full_access` ONLY).
    pub async fn run_mailbox_write<C, T, E, F>(
        &self,
        cap: &MutateCapability,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, E>
    where
        F: AsyncFnOnce(&mut MailboxTx<ReadWrite>) -> Result<T, E>,
    {
        self.pool
            .run_mailbox_write(envelope, cap.verified(), deadline, body)
            .await
    }

    /// Run a 1-RTT pipelined mailbox write strictly from a [`MutateCapability`].
    #[allow(clippy::too_many_arguments)]
    pub async fn run_mailbox_write_pipelined<C, T, P>(
        &self,
        cap: &MutateCapability,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        sql: &'static str,
        params: &[Param<'_>],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        self.pool
            .run_mailbox_write_pipelined(
                envelope,
                cap.verified(),
                deadline,
                sql,
                params,
                receipt,
                project,
            )
            .await
    }

    /// Run a 1-RTT pipelined audited-read contract (`email_get` + `mailbox_audit_log`,
    /// `continuity_recovery_receipt_context`) strictly from a [`ReadCapability`]
    /// on `AppPool` (`setjoin_app`, `NOBYPASSRLS`). Preserves the compile-fail
    /// separation preventing [`ReadCapability`] from calling `run_mailbox_write`.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_mailbox_audited_read_contract<C, T, P>(
        &self,
        cap: &ReadCapability,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        self.pool
            .run_mailbox_audited_read_contract_pipelined(
                envelope,
                cap.verified(),
                deadline,
                contract,
                values,
                receipt,
                project,
            )
            .await
    }

    /// Run an interactive `MailboxTx<ReadWrite>` strictly on submission/collaborate
    /// paths using a [`SubmitCapability`] (`Owner | full_access | send_as | send_on_behalf`).
    pub async fn run_mailbox_submit<C, T, E, F>(
        &self,
        cap: &SubmitCapability,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, E>
    where
        F: AsyncFnOnce(&mut MailboxTx<ReadWrite>) -> Result<T, E>,
    {
        self.pool
            .run_mailbox_write(envelope, cap.verified(), deadline, body)
            .await
    }

    /// Run a 1-RTT pipelined submission contract from a [`SubmitCapability`].
    #[allow(clippy::too_many_arguments)]
    pub async fn run_mailbox_submit_contract_pipelined<C, T, P>(
        &self,
        cap: &SubmitCapability,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        self.pool
            .run_mailbox_write_contract_pipelined(
                envelope,
                cap.verified(),
                deadline,
                contract,
                values,
                receipt,
                project,
            )
            .await
    }

    /// Run a 1-RTT pipelined owner-only contract from an [`OwnerCapability`].
    #[allow(clippy::too_many_arguments)]
    pub async fn run_owner_write_contract_pipelined<C, T, P>(
        &self,
        cap: &OwnerCapability,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        self.pool
            .run_mailbox_write_contract_pipelined(
                envelope,
                cap.verified(),
                deadline,
                contract,
                values,
                receipt,
                project,
            )
            .await
    }

    /// Run a 1-RTT pipelined submission write from a [`SubmitCapability`].
    #[allow(clippy::too_many_arguments)]
    pub async fn run_mailbox_submit_pipelined<C, T, P>(
        &self,
        cap: &SubmitCapability,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        sql: &'static str,
        params: &[Param<'_>],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        self.pool
            .run_mailbox_write_pipelined(
                envelope,
                cap.verified(),
                deadline,
                sql,
                params,
                receipt,
                project,
            )
            .await
    }

    /// Begin a `MailboxTx<ReadOnly>` for calendar delegation (`Owner | full_access | manage_calendar`).
    pub async fn begin_calendar_read(
        &self,
        cap: &CalendarCapability,
    ) -> Result<MailboxTx<ReadOnly>, StatementFailure> {
        self.pool.begin_mailbox_read(cap.verified()).await
    }

    /// Run a calendar write transaction from a [`CalendarCapability`].
    pub async fn run_calendar_write<C, T, E, F>(
        &self,
        cap: &CalendarCapability,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, E>
    where
        F: AsyncFnOnce(&mut MailboxTx<ReadWrite>) -> Result<T, E>,
    {
        self.pool
            .run_mailbox_write(envelope, cap.verified(), deadline, body)
            .await
    }

    /// Run an owner-only personal mailbox write from an [`OwnerCapability`].
    pub async fn run_owner_write<C, T, E, F>(
        &self,
        cap: &OwnerCapability,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, E>
    where
        F: AsyncFnOnce(&mut MailboxTx<ReadWrite>) -> Result<T, E>,
    {
        self.pool
            .run_mailbox_write(envelope, cap.verified(), deadline, body)
            .await
    }

    /// Run a receipted mailbox effect write strictly from a [`MutateCapability`]
    /// (`Owner | full_access` ONLY) with `SET LOCAL idle_in_transaction_session_timeout = 8000`,
    /// bounded peripheral timeout (`<= 5s`), bounded concurrency semaphore, and
    /// preamble advisory lock preceding row locks (`#481`, `#546a`).
    pub async fn run_mailbox_effect_write<C, T, F>(
        &self,
        cap: &MutateCapability,
        command: ReceiptCommand,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, StatementFailure>
    where
        F: AsyncFnOnce(&mut MailboxTx<ReadWrite>) -> Result<T, StatementFailure>,
    {
        self.pool
            .run_mailbox_effect_write(command, envelope, cap.verified(), deadline, body)
            .await
    }

    /// Run a receipted mailbox submission effect write strictly from a
    /// [`SubmitCapability`] (`Owner | full_access | send_as | send_on_behalf`),
    /// keeping submission separate from [`MutateCapability`] (#546a).
    pub async fn run_mailbox_submit_effect_write<C, T, F>(
        &self,
        cap: &SubmitCapability,
        command: ReceiptCommand,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, StatementFailure>
    where
        F: AsyncFnOnce(&mut MailboxTx<ReadWrite>) -> Result<T, StatementFailure>,
    {
        self.pool
            .run_mailbox_effect_write(command, envelope, cap.verified(), deadline, body)
            .await
    }

    /// Run a multi-statement locked mailbox transaction strictly from a
    /// [`MutateCapability`] (`Owner | full_access` ONLY), acquiring the
    /// preamble advisory lock (`setjoin-command:...`) before any row locks (`#481`)
    /// without inserting into `rust_operation_receipts` (for domains owning their
    /// own durable receipt such as `mailbox_audit_log`).
    pub async fn run_mailbox_locked_tx<C, T, E, F>(
        &self,
        cap: &MutateCapability,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, E>
    where
        F: AsyncFnOnce(&mut MailboxTx<ReadWrite>) -> Result<T, E>,
    {
        self.pool
            .run_mailbox_write(envelope, cap.verified(), deadline, body)
            .await
    }

    /// Run a multi-statement locked calendar transaction strictly from a
    /// [`CalendarCapability`] (`Owner | full_access | manage_calendar`),
    /// acquiring the preamble advisory lock before any row locks (`#481`).
    pub async fn run_calendar_locked_tx<C, T, E, F>(
        &self,
        cap: &CalendarCapability,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, E>
    where
        F: AsyncFnOnce(&mut MailboxTx<ReadWrite>) -> Result<T, E>,
    {
        self.pool
            .run_mailbox_write(envelope, cap.verified(), deadline, body)
            .await
    }

    /// Resolve whether a receipted mailbox command committed under current
    /// authority, waiting on the same advisory operation lock before reading at
    /// `READ COMMITTED READ ONLY` (#546a).
    pub async fn lookup_mailbox_command(
        &self,
        cap: &ReadCapability,
        operation: OperationId,
        command: ReceiptCommand,
    ) -> Result<OperationLookup, StatementFailure> {
        self.pool
            .lookup_mailbox_command(cap.verified(), operation, command)
            .await
    }

    // ---- Mailbox-less User transactions ----

    pub async fn begin_user_read(
        &self,
        principal: &UserPrincipal,
    ) -> Result<UserTx<ReadOnly>, StatementFailure> {
        self.pool.begin_user_read(&principal.verified_user()).await
    }

    pub async fn run_user_read_pipelined(
        &self,
        principal: &UserPrincipal,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.pool
            .run_user_read_pipelined(&principal.verified_user(), sql, params)
            .await
    }

    pub async fn run_user_read_contract(
        &self,
        principal: &UserPrincipal,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.pool
            .run_user_read_contract(&principal.verified_user(), contract, values)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run_user_write_contract_pipelined<C, T, P>(
        &self,
        principal: &UserPrincipal,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        self.pool
            .run_user_write_contract_pipelined(
                envelope,
                &principal.verified_user(),
                deadline,
                contract,
                values,
                receipt,
                project,
            )
            .await
    }

    pub async fn run_user_write<C, T, E, F>(
        &self,
        principal: &UserPrincipal,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, E>
    where
        F: AsyncFnOnce(&mut UserTx<ReadWrite>) -> Result<T, E>,
    {
        self.pool
            .run_user_write(envelope, &principal.verified_user(), deadline, body)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run_user_write_pipelined<C, T, P>(
        &self,
        principal: &UserPrincipal,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        sql: &'static str,
        params: &[Param<'_>],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        self.pool
            .run_user_write_pipelined(
                envelope,
                &principal.verified_user(),
                deadline,
                sql,
                params,
                receipt,
                project,
            )
            .await
    }

    /// Run a receipted mailbox-less user effect write transaction with
    /// `SET LOCAL idle_in_transaction_session_timeout = 8000`, `<= 5s`
    /// peripheral timeout, bounded concurrency semaphore, and preamble
    /// advisory lock (`#481`, `#546a`).
    pub async fn run_user_effect_write<C, T, F>(
        &self,
        principal: &UserPrincipal,
        command: ReceiptCommand,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, StatementFailure>
    where
        F: AsyncFnOnce(&mut UserTx<ReadWrite>) -> Result<T, StatementFailure>,
    {
        self.pool
            .run_user_effect_write(
                command,
                envelope,
                &principal.verified_user(),
                deadline,
                body,
            )
            .await
    }

    /// Resolve whether a receipted mailbox-less user command committed under
    /// current authority (#546a).
    pub async fn lookup_user_command(
        &self,
        principal: &UserPrincipal,
        operation: OperationId,
        command: ReceiptCommand,
    ) -> Result<OperationLookup, StatementFailure> {
        self.pool
            .lookup_user_command(&principal.verified_user(), operation, command)
            .await
    }

    // ---- Cross-tenant Admin transactions (strictly on AdminWorkerPool + RBAC proof) ----

    pub async fn begin_admin_read(
        &self,
        proof: &AdminPermissionProof,
    ) -> Result<AdminReadTx<Standard>, StatementFailure> {
        self.require_admin_pool()?
            .begin_admin_read(proof.verified())
            .await
    }

    pub async fn run_admin_read_pipelined(
        &self,
        proof: &AdminPermissionProof,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.require_admin_pool()?
            .run_admin_read_pipelined(proof.verified(), sql, params)
            .await
    }

    pub async fn run_admin_read_contract(
        &self,
        proof: &AdminPermissionProof,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.require_admin_pool()?
            .run_admin_read_contract(proof.verified(), contract, values)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run_admin_write_contract_pipelined<C, T, P>(
        &self,
        proof: &AdminPermissionProof,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        audit: &AuditEvent,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        let Some(admin) = self.admin_pool.as_ref() else {
            return CommandOutcome::RolledBack(Rejection::Unavailable);
        };
        admin
            .run_admin_write_contract_pipelined(
                envelope,
                proof.verified(),
                deadline,
                audit,
                contract,
                values,
                receipt,
                project,
            )
            .await
    }

    /// Run a [`SqlAuditPosture::ReducerWritesCoreAudit`] admin reducer contract
    /// inside an [`AdminWriteTx<Unaudited>`], binding `$1` (`p_actor`) from `proof`,
    /// recording optional `receipt` on `Audited`, and rolling back cleanly on `NoOp`.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_admin_audited_reducer_contract<C, T, P>(
        &self,
        proof: &AdminPermissionProof,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        contract: &'static SqlContract,
        rest_values: &[&(dyn ToSql + Sync)],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>, bool) -> Result<T, StatementFailure>,
    {
        let tx = match self.begin_admin_write(proof, envelope, deadline).await {
            Ok(tx) => tx,
            Err(r) => return CommandOutcome::RolledBack(r),
        };
        match tx
            .execute_audited_reducer_contract(contract, rest_values)
            .await
        {
            Ok(setjoin_pg::AdminReducerOutcome::Audited { mut tx, rows }) => {
                let value = match project(rows, true) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = tx.rollback().await;
                        return CommandOutcome::RolledBack(Rejection::Body(e));
                    }
                };
                if let Some(cmd) = receipt {
                    if let Err(e) = tx.record_receipt(cmd).await {
                        let _ = tx.rollback().await;
                        return CommandOutcome::RolledBack(Rejection::Statement(e));
                    }
                }
                match tx.commit().await {
                    CommandOutcome::Committed(()) => CommandOutcome::Committed(value),
                    CommandOutcome::RolledBack(r) => CommandOutcome::RolledBack(r),
                    CommandOutcome::Unknown { operation } => CommandOutcome::Unknown { operation },
                }
            }
            Ok(setjoin_pg::AdminReducerOutcome::NoOp { tx, rows }) => {
                let _ = tx.rollback().await;
                match project(rows, false) {
                    Ok(v) => CommandOutcome::Committed(v),
                    Err(e) => CommandOutcome::RolledBack(Rejection::Body(e)),
                }
            }
            Err(e) => CommandOutcome::RolledBack(Rejection::Statement(e)),
        }
    }

    pub async fn run_admin_sensitive_read(
        &self,
        proof: &AdminPermissionProof,
        audit: &AuditEvent,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.require_admin_pool()?
            .run_admin_sensitive_read(proof.verified(), audit, sql, params)
            .await
    }

    pub async fn run_admin_sensitive_read_with<T, F>(
        &self,
        proof: &AdminPermissionProof,
        audit: &AuditEvent,
        body: F,
    ) -> Result<T, StatementFailure>
    where
        F: AsyncFnOnce(&mut AdminSensitiveRead) -> Result<T, StatementFailure>,
    {
        self.require_admin_pool()?
            .run_admin_sensitive_read_with(proof.verified(), audit, body)
            .await
    }

    pub async fn begin_admin_write<C>(
        &self,
        proof: &AdminPermissionProof,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
    ) -> Result<AdminWriteTx<Unaudited>, Rejection<StatementFailure>> {
        let admin = self.admin_pool.as_ref().ok_or(Rejection::Unavailable)?;
        admin
            .begin_admin_write(envelope, proof.verified(), deadline)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run_admin_write_pipelined<C, T, P>(
        &self,
        proof: &AdminPermissionProof,
        envelope: &CommandEnvelope<C>,
        deadline: Instant,
        audit: &AuditEvent,
        sql: &'static str,
        params: &[Param<'_>],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        let Some(admin) = self.admin_pool.as_ref() else {
            return CommandOutcome::RolledBack(Rejection::Unavailable);
        };
        admin
            .run_admin_write_pipelined(
                envelope,
                proof.verified(),
                deadline,
                audit,
                sql,
                params,
                receipt,
                project,
            )
            .await
    }

    // ---- Private pre-auth credential-proof seam (strictly AdminWorkerPool READ ONLY) ----

    /// Open a read-only pre-authentication credential-proof transaction on the
    /// private [`AdminWorkerPool`] so `setjoin_app` never needs a `users`
    /// password-hash lookup helper (#546a).
    ///
    /// Restricted to `pub(crate)` so domain crates holding `&TxFactory` cannot
    /// obtain a cross-tenant `PreAuthReadTx` without going through `PolicyGate`.
    pub(crate) async fn begin_pre_auth_read(&self) -> Result<PreAuthReadTx, StatementFailure> {
        self.require_admin_pool()?.begin_pre_auth_read().await
    }

    /// Execute a static [`SqlScope::AuthPreScope`] pre-authentication contract
    /// on the private [`AdminWorkerPool`] in `BEGIN READ ONLY` (#546a).
    pub(crate) async fn run_pre_auth_read_contract(
        &self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.require_admin_pool()?
            .run_pre_auth_read_contract(contract, values)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal_with(auth: MailboxAuthority) -> MailboxPrincipal {
        MailboxPrincipal::new(
            ActorId::new(10).unwrap(),
            MailboxId::new(20).unwrap(),
            auth,
            Generation(1),
            Arc::new(GroupMembership::default()),
            None,
            AuditMeta::new("alice@example.test", "127.0.0.1"),
        )
    }

    #[test]
    fn mailbox_authority_lattice_matches_jmap_gates() {
        let owner = principal_with(MailboxAuthority::Owner);
        assert!(owner.require_owner().is_ok());
        assert!(owner.require_read().is_ok());
        assert!(owner.require_mutate().is_ok());
        assert!(owner.require_submit().is_ok());
        assert!(owner.require_send_as().is_ok());
        assert!(owner.require_manage_calendar().is_ok());

        let full = principal_with(MailboxAuthority::Delegated(BTreeSet::from([
            DelegatePermission::FullAccess,
        ])));
        assert!(full.require_owner().is_err());
        assert!(full.require_read().is_ok());
        assert!(full.require_mutate().is_ok());
        assert!(full.require_submit().is_ok());
        assert!(full.require_send_as().is_ok());
        assert!(full.require_manage_calendar().is_ok());

        let send_as = principal_with(MailboxAuthority::Delegated(BTreeSet::from([
            DelegatePermission::SendAs,
        ])));
        assert!(send_as.require_owner().is_err());
        assert!(send_as.require_read().is_ok());
        assert!(send_as.require_mutate().is_err());
        assert!(send_as.require_submit().unwrap().can_send_as());
        assert!(send_as.require_send_as().is_ok());
        assert!(send_as.require_manage_calendar().is_err());

        let send_on_behalf = principal_with(MailboxAuthority::Delegated(BTreeSet::from([
            DelegatePermission::SendOnBehalf,
        ])));
        assert!(send_on_behalf.require_owner().is_err());
        assert!(send_on_behalf.require_read().is_ok());
        assert!(send_on_behalf.require_mutate().is_err());
        assert!(!send_on_behalf.require_submit().unwrap().can_send_as());
        assert!(send_on_behalf.require_send_as().is_err());
        assert!(send_on_behalf.require_manage_calendar().is_err());

        let read = principal_with(MailboxAuthority::Delegated(BTreeSet::from([
            DelegatePermission::Read,
        ])));
        assert!(read.require_owner().is_err());
        assert!(read.require_read().is_ok());
        assert!(read.require_mutate().is_err());
        assert!(read.require_submit().is_err());
        assert!(read.require_send_as().is_err());
        assert!(read.require_manage_calendar().is_err());

        let cal = principal_with(MailboxAuthority::Delegated(BTreeSet::from([
            DelegatePermission::ManageCalendar,
        ])));
        assert!(cal.require_owner().is_err());
        assert!(cal.require_read().is_err());
        assert!(cal.require_mutate().is_err());
        assert!(cal.require_submit().is_err());
        assert!(cal.require_send_as().is_err());
        assert!(cal.require_manage_calendar().is_ok());
    }

    #[test]
    fn sod_checker_enforces_all_four_violation_classes() {
        // Clean single-class security role
        assert_eq!(
            check_sod_violations(&[(
                1,
                Some("security".into()),
                vec!["users.read".into(), "security.write".into()]
            )]),
            Ok(BTreeSet::from(["security".to_owned()]))
        );
        // Unclassified role (sod_class IS NULL)
        assert_eq!(
            check_sod_violations(&[(2, None, vec!["users.read".into()])]),
            Err(PrincipalError::SodViolation("unclassified_role"))
        );
        // Unclassifiable perm (users.impersonate)
        assert_eq!(
            check_sod_violations(&[(3, Some("security".into()), vec!["users.impersonate".into()])]),
            Err(PrincipalError::SodViolation("unclassifiable_perm"))
        );
        // Super admin role spanning >= 2 exclusive classes
        assert_eq!(
            check_sod_violations(&[(
                4,
                Some("system".into()),
                vec!["users.create".into(), "audit.read".into()]
            )]),
            Err(PrincipalError::SodViolation("super_admin_role"))
        );
        // Cross-class across two roles
        assert_eq!(
            check_sod_violations(&[
                (5, Some("system".into()), vec!["users.create".into()]),
                (6, Some("audit".into()), vec!["audit.read".into()]),
            ]),
            Err(PrincipalError::SodViolation("cross_class"))
        );
    }
}
