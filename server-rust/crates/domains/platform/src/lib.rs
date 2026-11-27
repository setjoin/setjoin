//! Platform (F08): the system, features, updates, jobs, webhooks, terms and
//! listener-level routes of the admin console.
//!
//! Foundation dependencies only (`authz`, `contracts`, `db`, `pg`, `schema`, `sql-catalog`).
//! Authority comes from sealed principals (`UserPrincipal`, `AdminPermissionProof`) minted by
//! `TxFactory`; path ids and bodies name targets but never grant authority.
#![forbid(unsafe_code)]
pub mod airgap;
pub mod alerts;
pub mod apps;
pub mod auth_methods;
pub mod branding;
pub mod config;
pub mod deploy;
pub mod dns;
pub mod domains;
pub mod features;
pub mod federation;
pub mod health;
pub mod jit;
pub mod jobs;
pub mod monitor;
mod registry_data;
pub mod sod;
pub mod sql;
pub mod storage;
pub mod system;
pub mod terms;
pub mod updates;
pub mod upgrades;
pub mod webhook_secret;
pub mod webhooks;
pub mod welcome;

pub use sql::SQL_CONTRACTS;

use serde_json::json;
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, StatementFailure};
use sha2::{Digest as _, Sha256};

pub const FAMILY: &str = "F08";

/// Go's `admin.ConsoleScopes[ConsoleSystem]` in registration order (`requireSystemPerm`).
pub const SYSTEM_CONSOLE: [&str; 4] = [
    "system.config",
    "system.upgrade",
    "backup.read",
    "mail.offline_policy",
];
/// `requireSystemConfig`.
pub const SYSTEM_CONFIG: [&str; 1] = ["system.config"];
/// `requireSystemUpgrade`.
pub const SYSTEM_UPGRADE: [&str; 1] = ["system.upgrade"];
/// Go's `admin.ConsoleScopes[ConsoleAuth]` (`requireAuthPerm`).
pub const AUTH_CONSOLE: [&str; 4] = [
    "users.read",
    "identity.write",
    "access.policy_read",
    "access.policy_write",
];
/// `requireIdentityWrite`.
pub const IDENTITY_WRITE: [&str; 1] = ["identity.write"];
/// `requireRolesManage`.
pub const ROLES_MANAGE: [&str; 1] = ["roles.manage"];
/// `requireBackupWrite`.
pub const BACKUP_WRITE: [&str; 1] = ["backup.write"];
/// `requireCAPolicyRead` / `requireCAPolicyWrite` (`RequirePermAudited`).
pub const ACCESS_POLICY_READ: [&str; 1] = ["access.policy_read"];
pub const ACCESS_POLICY_WRITE: [&str; 1] = ["access.policy_write"];
/// `requireMailPerm`: Go's `admin.ConsoleScopes[ConsoleMail]` in registration order (any-of).
pub const MAIL_CONSOLE: [&str; 5] = [
    "domains.read",
    "queue.read",
    "reports.read",
    "mail.pipeline",
    "mail.security",
];
/// `requireLogsPerm`: Go's `admin.ConsoleScopes[ConsoleLogs]` (org-wide only).
pub const LOGS_CONSOLE: [&str; 1] = ["audit.read"];
/// `requireSecurityWrite`.
pub const SECURITY_WRITE: [&str; 1] = ["security.write"];
/// `requireAppsView` (any-of) and `requireAppsManage`.
pub const APPS_VIEW: [&str; 2] = ["apps.view", "apps.manage"];
pub const APPS_MANAGE: [&str; 1] = ["apps.manage"];
/// `requireMailPipeline`.
pub const MAIL_PIPELINE: [&str; 1] = ["mail.pipeline"];
/// `requireDomainsWrite`.
pub const DOMAINS_WRITE: [&str; 1] = ["domains.write"];
/// `requireFederationManage`.
pub const FEDERATION_MANAGE: [&str; 1] = ["federation.manage"];

/// Go's `encoding/json` key folding (ASCII case plus the two Unicode simple folds).
pub(crate) fn fold_key(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            'ſ' => 's',
            'K' => 'k',
            _ => c.to_ascii_lowercase(),
        })
        .collect()
}

pub(crate) fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid platform result".into(),
    }
}

/// Whether the actor holds `system.config` through an organization-wide assignment
/// (`admin_org_wide_grant`: no domain, no OU/set narrowing). Owner-approved security fix
/// 2026-11-05 (#539).
pub async fn storage_org_wide(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    route: &str,
) -> Result<bool, StatementFailure> {
    if setjoin_contracts::mutants::on(&format!("storage-scoped-grant-{route}")) {
        return Ok(true);
    }
    org_wide(factory, admin, &["system.config"]).await
}

/// Whether the actor holds `system.upgrade` through an organization-wide assignment (#542).
pub async fn upgrade_org_wide(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    route: &str,
) -> Result<bool, StatementFailure> {
    if setjoin_contracts::mutants::on(&format!("upgrade-scoped-grant-{route}")) {
        return Ok(true);
    }
    org_wide(factory, admin, &SYSTEM_UPGRADE).await
}

/// Whether the actor holds one of the Mail-console permissions through an organization-wide
/// assignment (#542, review of #537).
pub async fn storage_read_org_wide(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    route: &str,
) -> Result<bool, StatementFailure> {
    if setjoin_contracts::mutants::on(&format!("storage-read-scoped-{route}")) {
        return Ok(true);
    }
    org_wide(factory, admin, &MAIL_CONSOLE).await
}

async fn org_wide(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    perms: &[&str],
) -> Result<bool, StatementFailure> {
    let user = admin.actor().get();
    let list = format!("{{{}}}", perms.join(","));
    let rows = factory
        .run_admin_read_contract(admin, &sql::ADMIN_ORG_WIDE_GRANT, &[&user, &list])
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

pub(crate) fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}

pub(crate) fn envelope(
    actor: ActorId,
    generation: Generation,
    operation: [u8; 16],
    payload: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: AuthorityKey {
            actor,
            scope: ResourceScope::User(actor),
            generation,
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(payload.as_bytes()).into()),
        command: (),
    }
}

pub(crate) fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: FAMILY,
        command: name,
    }
}

/// Go writes the same durable console-denial audit row, best effort.
pub async fn console_denied(
    factory: &TxFactory,
    user: &UserPrincipal,
    path: &str,
    permission: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let before = json!({
        "actor": user.audit_meta().email,
        "target": path,
        "missingPermission": permission
    })
    .to_string();
    let env = envelope(user.user(), user.generation(), operation, &before);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CONSOLE_DENIED,
            &[&before, &path],
            Some(command("console.denied")),
            |rows| {
                if rows.len() == 1 {
                    Ok(())
                } else {
                    Err(invalid())
                }
            },
        )
        .await
}

/// encoding/json HTML escaping of an already rendered document.
pub fn go_escape(text: &str) -> String {
    text.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

pub(crate) fn s(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".into())
}

pub fn done(text: String) -> String {
    go_escape(&text) + "\n"
}

#[allow(dead_code)]
pub(crate) fn first_i64(rows: &[Row]) -> Result<i64, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or_else(invalid)
}

/// Go's `RequireReason(perm)`: whether `area` (the permission's first segment) is a
/// reason-required audit area. A failed policy read fails open, as Go's middleware does.
pub async fn reason_required(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    area: &str,
) -> bool {
    factory
        .run_admin_read_contract(admin, &sql::REASON_REQUIRED, &[&area])
        .await
        .ok()
        .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
        .unwrap_or(false)
}

/// The durable `sensitive_action.reason_missing` row Go writes before its 400 (`perm` is the
/// middleware's permission, kept in the row's notes).
pub async fn missing_reason(
    factory: &TxFactory,
    user: &UserPrincipal,
    ip: &str,
    perm: &str,
    operation: [u8; 16],
) {
    let actor_id = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{ip}:{perm}"),
    );
    let _ = factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MISSING_REASON,
            &[&actor_id, &ip, &perm],
            Some(command("reason_missing")),
            |rows| {
                if rows.len() == 1 {
                    Ok(())
                } else {
                    Err(invalid())
                }
            },
        )
        .await;
}
