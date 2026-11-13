//! Platform (F08): the system, features, updates, jobs, webhooks, terms and
//! listener-level routes of the admin console.
//!
//! Foundation dependencies only (`authz`, `contracts`, `db`, `pg`, `schema`). The actor and
//! mailbox come from the sealed auth context; path ids and bodies name targets but never
//! grant authority. Permissions and domain scope are resolved live per request, as Go's
//! auth chain does for admin tokens. Responses render in `encoding/json` field order
//! (structs) or sorted key order (maps), HTML-escaped, with the trailing newline of Go's
//! `Encoder`. Later Platform slices add modules here; see the crate DOX for the slice map.
#![forbid(unsafe_code)]
pub mod airgap;
pub mod alerts;
pub mod apps;
pub mod auth_methods;
pub mod branding;
pub mod config;
pub mod dns;
pub mod deploy;
pub mod domains;
pub mod features;
pub mod federation;
pub mod health;
pub mod jit;
pub mod jobs;
pub mod monitor;
mod registry_data;
pub mod sod;
pub mod storage;
pub mod system;
pub mod terms;
pub mod updates;
pub mod upgrades;
pub mod webhook_secret;
pub mod webhooks;
pub mod welcome;
use serde_json::json;
use setjoin_authz::AuthContext;
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId, OperationId},
};
use setjoin_pg::{
    CommandOutcome, MailboxAuthContext, ReceiptCommand, Row, ScopedExecutor, StatementFailure, Type,
};
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
/// Go's `DomainGlobalOnlyScopes`: refused to any domain-scoped principal.
const GLOBAL_ONLY: [&str; 2] = ["audit.read", "audit.export"];

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

/// `requireFederationManage`.
pub const FEDERATION_MANAGE: [&str; 1] = ["federation.manage"];

pub fn scope(actor: &AuthContext) -> MailboxAuthContext {
    MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified actor"),
        MailboxId::new(actor.mailbox_id()).expect("verified mailbox"),
        Generation(1),
    )
}
pub(crate) fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid platform result".into(),
    }
}

/// Live request-time projection of governed grants for a verified admin.
/// Non-admin tokens keep their signed claims, as Go's resolver skips them.
pub struct Authority {
    permissions: Vec<String>,
    domain_scope: i64,
}
impl Authority {
    pub fn allows_any(&self, wanted: &[&str]) -> bool {
        wanted
            .iter()
            .any(|w| self.permissions.iter().any(|p| p == w))
    }
    /// 0 is global, as Go's `DomainScopeFromContext`.
    pub fn domain_scope(&self) -> i64 {
        self.domain_scope
    }
    /// Go's `denyDomainScopedForGlobalOnly`: true when the surface names an
    /// organization-wide-only permission and the principal is domain scoped.
    pub fn refused_for_scope(&self, required: &[&str]) -> bool {
        self.domain_scope > 0 && required.iter().any(|p| GLOBAL_ONLY.contains(p))
    }
}
pub async fn authority(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<Authority, StatementFailure> {
    if !actor.signed_admin() {
        return Ok(Authority {
            permissions: actor.signed_permissions().to_vec(),
            domain_scope: actor.signed_domain_scope().unwrap_or(0),
        });
    }
    let user = actor.user_id();
    let rows = exec
        .read(
            "SELECT COALESCE((SELECT array_agg(DISTINCT p) FROM public.admin_role_assignments ra \
             JOIN public.admin_role_groups rg ON rg.id=ra.role_group_id CROSS JOIN LATERAL unnest(rg.permissions) p \
             WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
             AND public.admin_assignment_active(ra.eligible,ra.activated_until)),'{}'::text[]), \
             (SELECT MIN(COALESCE(ra.domain_override,rg.domain_scope)) FROM public.admin_role_assignments ra \
             JOIN public.admin_role_groups rg ON rg.id=ra.role_group_id \
             WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
             AND public.admin_assignment_active(ra.eligible,ra.activated_until))",
            &[(&user, Type::INT8)],
        )
        .await?;
    let row = rows.first().ok_or_else(invalid)?;
    Ok(Authority {
        permissions: row.get(0),
        domain_scope: row.get::<_, Option<i64>>(1).unwrap_or(0),
    })
}

/// Whether the actor holds `system.config` through an organization-wide assignment
/// (`admin_org_wide_grant`: no domain, no OU/set narrowing). Owner-approved security fix
/// 2026-11-05 (#539): the server-wide storage scan, reconciliation and migration routes
/// need it; frozen Go let any domain-scoped `system.config` holder run them.
pub async fn storage_org_wide(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    route: &str,
) -> Result<bool, StatementFailure> {
    // Test-only bug restoration, one id per route: storage-scoped-grant-{scan,reconcile,migrate,cancel}.
    if setjoin_contracts::mutants::on(&format!("storage-scoped-grant-{route}")) {
        return Ok(true);
    }
    org_wide(exec, actor, &["system.config"]).await
}

/// Whether the actor holds `system.upgrade` through an organization-wide assignment.
/// Owner-approved security fix 2026-11-05 (#542): the deploy wizard pushes gateway S3
/// credentials to nodes and opens SSH to any host, and the airgap upload replaces update
/// bytes; frozen Go let a domain-scoped `system.upgrade` holder do both.
pub async fn upgrade_org_wide(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    route: &str,
) -> Result<bool, StatementFailure> {
    // Test-only bug restoration: upgrade-scoped-grant-{deploy-start,deploy-cancel,deploy-status,airgap-upload}.
    if setjoin_contracts::mutants::on(&format!("upgrade-scoped-grant-{route}")) {
        return Ok(true);
    }
    org_wide(exec, actor, &SYSTEM_UPGRADE).await
}

/// Whether the actor holds one of the Mail-console permissions the storage read routes
/// accept through an organization-wide assignment (#542, review of #537): server-wide
/// storage status and scan/migration history are not a domain's to read.
pub async fn storage_read_org_wide(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    route: &str,
) -> Result<bool, StatementFailure> {
    // Test-only bug restoration: storage-read-scoped-{status,scan-list,scan-get,migrate-list,migrate-get}.
    if setjoin_contracts::mutants::on(&format!("storage-read-scoped-{route}")) {
        return Ok(true);
    }
    org_wide(exec, actor, &MAIL_CONSOLE).await
}

async fn org_wide(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    perms: &[&str],
) -> Result<bool, StatementFailure> {
    let user = actor.user_id();
    let list = format!("{{{}}}", perms.join(","));
    let rows = exec
        .read(
            "SELECT admin_org_wide_grant($1, $2::text::text[])",
            &[(&user, Type::INT8), (&list, Type::TEXT)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

pub(crate) fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}
pub(crate) fn envelope(
    auth: &MailboxAuthContext,
    operation: [u8; 16],
    payload: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    path: &str,
    permission: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let before =
        json!({"actor":actor.email(),"target":path,"missingPermission":permission}).to_string();
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("console.denied"),
        &envelope(&auth, operation, &before),
        &auth,
        deadline(),
        "SELECT audit_write(NULL,'console.denied','console',NULL,$4::text::jsonb,NULL,NULL,$5,'core') WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&before, Type::TEXT), (&path, Type::TEXT)],
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
    serde_json::to_string(text).expect("string")
}
pub fn done(text: String) -> String {
    go_escape(&text) + "\n"
}
/// RFC 3339 with Go's trimmed fractional seconds (`time.Time` JSON), UTC.
pub(crate) fn nano(column: &str) -> String {
    format!(
        "to_char({column} AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || CASE WHEN date_part('microseconds', {column} AT TIME ZONE 'UTC')::bigint % 1000000 = 0 THEN '' ELSE regexp_replace(to_char({column} AT TIME ZONE 'UTC','.US'),'0+$','') END || 'Z'"
    )
}
#[allow(dead_code)]
pub(crate) fn first_i64(rows: &[Row]) -> Result<i64, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or_else(invalid)
}

/// Go's `RequireReason(perm)`: whether `area` (the permission's first segment) is a
/// reason-required audit area. A failed policy read fails open, as Go's middleware does.
pub async fn reason_required(exec: &ScopedExecutor, area: &str) -> bool {
    exec.read(
        "SELECT $1::text = ANY(reason_required_areas) FROM audit_policy WHERE id = 1",
        &[(&area, Type::TEXT)],
    )
    .await
    .ok()
    .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
    .unwrap_or(false)
}

/// The durable `sensitive_action.reason_missing` row Go writes before its 400 (`perm` is the
/// middleware's permission, kept in the row's notes).
pub async fn missing_reason(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    perm: &str,
    operation: [u8; 16],
) {
    let auth = scope(actor);
    let _ = setjoin_pg::run_receipted_command(
        exec,
        command("reason_missing"),
        &envelope(&auth, operation, &format!("{ip}:{perm}")),
        &auth,
        deadline(),
        "SELECT count(*)::bigint FROM (SELECT audit_write($2,'sensitive_action.reason_missing','',NULL,NULL,NULL,NULLIF($4::text,'')::inet,$5::text,'core') \
         WHERE $1::bigint > 0 AND $3::text <> '') w",
        &[(&ip, Type::TEXT), (&perm, Type::TEXT)],
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
