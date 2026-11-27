//! Shared least-privilege PostgreSQL role provisioning, `FORCE RLS` preflight,
//! CVE-2026-14666 version checks, and DSN redaction (#545, Wave 1.7).

use crate::{
    operator::{error as pg_error, OperatorConnection},
    pg_version_allows_prepared_rls,
    workers::WorkerConnection,
    ScopedExecutor,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio_postgres::{types::Type, Client};

/// Canonical 8 ARCH-018 `SECURITY DEFINER` scope helpers
/// (`docs/adr/ARCH-018-force-rls-scope-helper-recipe.md`).
///
/// `apply_worker_ownership()` is invoked ONLY on these 8 helpers (and strictly
/// BEFORE Pass 2 of `provision-roles.sql`) so worker-only/updater-only
/// `REVOKE ALL ... FROM setjoin_app` carve-outs always win last.
pub const CANONICAL_ARCH018_SCOPE_HELPERS: &[&str] = &[
    "public.drive_member_role(bigint,bigint)",
    "public.drive_space_owner(bigint)",
    "public.drive_has_admin_perm(bigint,text)",
    "public.chat_member_role(bigint,bigint)",
    "public.meeting_member_role(bigint,bigint)",
    "public.meeting_attendee_role(bigint,bigint)",
    "public.chat_hold_active(bigint)",
    "public.drive_user_can_write_regular(bigint)",
];

/// Expected cluster-global Setjoin database roles.
pub const EXPECTED_ROLES: &[&str] = &[
    "setjoin_app",
    "setjoin_worker",
    "setjoin_owner",
    "setjoin_updater",
];

/// Release N vs Release N+1 enforcement mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Release N (#545): warn loudly and degrade `/health` to `200 {"status":"warn"}`
    /// on privileged `DB_DSN`, vulnerable PG version, or drifted helpers while
    /// keeping hard refusals on `policy_tables_rls_disabled` and non-superuser
    /// `BYPASSRLS` / `owns_forced_rls_tables`.
    WarnReleaseN,
    /// Release N+1 (#547): refuse to start on any warning or hard error.
    FailClosedReleaseNPlus1,
}

/// Caller context for interpreting `current_user` ownership/privilege.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureContext {
    /// Tenant-facing runtime (`setjoin-server` / `setjoin-auth` `DB_DSN`).
    RuntimeApp,
    /// Operator / updater connection (`DB_OWNER_DSN` / `DB_DIRECT_OWNER_DSN`).
    OperatorOwner,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentRolePosture {
    pub name: String,
    pub rolsuper: bool,
    pub rolbypassrls: bool,
    pub rolcreaterole: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolePosture {
    pub name: String,
    pub exists: bool,
    pub rolcanlogin: bool,
    pub rolsuper: bool,
    pub rolbypassrls: bool,
    pub rolcreatedb: bool,
    pub rolcreaterole: bool,
    /// `Some(true/false)` when `pg_catalog.pg_authid` is readable; `None` otherwise.
    pub has_password: Option<bool>,
    pub attributes_ok: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeHelperDrift {
    pub signature: String,
    pub canonical_arch018: bool,
    pub owner: String,
    pub search_path_ok: bool,
    pub public_execute: bool,
    pub reason: String,
}

/// Redacted summary of configured DSN role usernames (never passwords or raw DSNs).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsnRoleSummary {
    pub app_role: Option<String>,
    pub worker_role: Option<String>,
    pub owner_role: Option<String>,
    pub app_role_privileged: Option<bool>,
    pub distinct_roles: bool,
    pub config_env_unreadable: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub worker_dsn_configured: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub owner_dsn_configured: bool,
}

impl DsnRoleSummary {
    /// Build a redacted role summary from optional raw DSNs without retaining any
    /// passwords or raw connection strings.
    pub fn from_dsns(
        app_dsn: Option<&str>,
        worker_dsn: Option<&str>,
        owner_dsn: Option<&str>,
    ) -> Self {
        let app_role = app_dsn.and_then(dsn_username);
        let worker_role = worker_dsn.and_then(dsn_username);
        let owner_role = owner_dsn.and_then(dsn_username);
        let worker_dsn_configured = worker_dsn.is_some_and(|s| !s.trim().is_empty());
        let owner_dsn_configured = owner_dsn.is_some_and(|s| !s.trim().is_empty());
        let distinct_roles = match (&app_role, &worker_role, &owner_role) {
            (Some(a), Some(w), Some(o)) => a != w && a != o && w != o,
            (Some(a), Some(w), None) => a != w,
            (Some(a), None, Some(o)) => a != o,
            _ => false,
        };
        Self {
            app_role,
            worker_role,
            owner_role,
            app_role_privileged: None,
            distinct_roles,
            config_env_unreadable: false,
            worker_dsn_configured,
            owner_dsn_configured,
        }
    }
}

const CONFIG_ENV_UNREADABLE_WARNING: &str =
    "gateway config.env was unreadable (EACCES) — runtime DB_DSN role could not be verified from unit files";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RlsPreflightReport {
    pub context: PostureContext,
    pub server_version_num: u32,
    pub server_version: String,
    pub pg_version_ok: bool,
    pub current_role: CurrentRolePosture,
    pub roles: Vec<RolePosture>,
    pub owner_has_worker_membership: bool,
    pub owns_forced_rls_tables: Vec<String>,
    pub app_owns_forced_rls_tables: Vec<String>,
    pub policy_tables_rls_disabled: Vec<String>,
    pub scope_helpers_drifted: Vec<ScopeHelperDrift>,
    pub other_secdef_drifted: Vec<ScopeHelperDrift>,
    pub dsn_roles: Option<DsnRoleSummary>,
    pub hard_errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl RlsPreflightReport {
    /// Exit code: `0` clean, `2` Release N warning only, `1` hard error (or any
    /// warning under `FailClosedReleaseNPlus1`).
    pub fn exit_code(&self, mode: EnforcementMode) -> i32 {
        if !self.hard_errors.is_empty() {
            return 1;
        }
        if !self.warnings.is_empty() {
            return match mode {
                EnforcementMode::WarnReleaseN => 2,
                EnforcementMode::FailClosedReleaseNPlus1 => 1,
            };
        }
        0
    }

    pub fn is_clean(&self) -> bool {
        self.hard_errors.is_empty() && self.warnings.is_empty()
    }

    pub fn all_roles_exist_with_expected_attrs(&self) -> bool {
        self.roles.len() == EXPECTED_ROLES.len()
            && self.roles.iter().all(|r| r.exists && r.attributes_ok)
            && self.owner_has_worker_membership
    }

    pub fn role(&self, name: &str) -> Option<&RolePosture> {
        self.roles.iter().find(|r| r.name == name)
    }

    /// Single source of truth for Release N+1 (`#547`) fail-closed enforcement
    /// across `boot`, `auth`, `mailctl`, and `updater`.
    ///
    /// When `allow_unreadable_config_env` is `true` (used by `setjoin-updater`
    /// preflight when running without read access to `0600 setjoin:setjoin`
    /// `config.env`), the `EACCES` unreadable-config notice is excluded while
    /// every DB-side error/warning and every readable DSN finding still fails
    /// closed.
    pub fn fail_closed_errors(&self, allow_unreadable_config_env: bool) -> Vec<String> {
        let mut out = self.hard_errors.clone();
        for warning in &self.warnings {
            if allow_unreadable_config_env && warning == CONFIG_ENV_UNREADABLE_WARNING {
                continue;
            }
            out.push(warning.clone());
        }
        out
    }

    fn effective_dsn_roles<'a>(
        &'a self,
        dsn_roles: &'a DsnRoleSummary,
    ) -> (Option<&'a str>, Option<&'a str>, Option<&'a str>) {
        if dsn_roles.config_env_unreadable {
            return (None, None, None);
        }
        let app_role = match self.context {
            PostureContext::RuntimeApp => dsn_roles
                .app_role
                .as_deref()
                .or(Some(self.current_role.name.as_str())),
            PostureContext::OperatorOwner => dsn_roles.app_role.as_deref(),
        };
        // In RuntimeApp, if DB_DSN omitted `user=` and DB_WORKER_DSN / DB_OWNER_DSN
        // was also configured without `user=`, both resolve to the same ambient
        // PostgreSQL role (`current_user`).
        let worker_role = dsn_roles.worker_role.as_deref().or_else(|| {
            (self.context == PostureContext::RuntimeApp
                && dsn_roles.worker_dsn_configured
                && dsn_roles.app_role.is_none())
            .then_some(self.current_role.name.as_str())
        });
        let owner_role = dsn_roles.owner_role.as_deref().or_else(|| {
            (self.context == PostureContext::RuntimeApp
                && dsn_roles.owner_dsn_configured
                && dsn_roles.app_role.is_none())
            .then_some(self.current_role.name.as_str())
        });
        (app_role, worker_role, owner_role)
    }

    fn evaluate_findings(&mut self) {
        self.hard_errors.clear();
        self.warnings.clear();

        // Hard invariant across ALL contexts (even when current_user is superuser):
        // a table with RLS policies attached missing ENABLE or FORCE ROW LEVEL SECURITY.
        if !self.policy_tables_rls_disabled.is_empty() {
            self.hard_errors.push(format!(
                "policy tables missing ENABLE or FORCE ROW LEVEL SECURITY: {}",
                self.policy_tables_rls_disabled.join(", ")
            ));
        }

        match self.context {
            PostureContext::RuntimeApp => {
                // Hard refusal for non-superuser BYPASSRLS or direct/indirect
                // table-owner bypass on FORCE RLS tables.
                if !self.current_role.rolsuper && self.current_role.rolbypassrls {
                    self.hard_errors.push(format!(
                        "runtime role {:?} has BYPASSRLS — tenant FORCE RLS cannot apply",
                        self.current_role.name
                    ));
                }
                if !self.current_role.rolsuper && !self.owns_forced_rls_tables.is_empty() {
                    self.hard_errors.push(format!(
                        "runtime role {:?} owns FORCE-RLS table(s) (directly or via role membership): {}",
                        self.current_role.name,
                        self.owns_forced_rls_tables.join(", ")
                    ));
                }
                if self.current_role.rolsuper {
                    self.warnings.push(format!(
                        "runtime DB_DSN connects as superuser {:?} — FORCE RLS is inert; refusing to start; provision least-privilege roles with 'mailctl schema provision-roles --write-dsns'",
                        self.current_role.name
                    ));
                }
            }
            PostureContext::OperatorOwner => {
                if !self.app_owns_forced_rls_tables.is_empty() {
                    self.hard_errors.push(format!(
                        "setjoin_app owns FORCE-RLS table(s) (directly or via role membership): {}",
                        self.app_owns_forced_rls_tables.join(", ")
                    ));
                }
            }
        }

        if !self.pg_version_ok {
            self.warnings.push(format!(
                "PostgreSQL {} (server_version_num={}) is vulnerable to CVE-2026-14666 (RLS + prepared statements); upgrade to >= 17.11 or >= 18.6",
                self.server_version, self.server_version_num
            ));
        }

        let missing_or_drifted: Vec<String> = self
            .roles
            .iter()
            .filter(|r| !r.exists || !r.attributes_ok)
            .map(|r| {
                if !r.exists {
                    format!("{} (missing)", r.name)
                } else {
                    format!("{} (drifted attributes)", r.name)
                }
            })
            .collect();
        if !missing_or_drifted.is_empty() {
            self.warnings.push(format!(
                "native-RLS role posture incomplete: {} — run 'mailctl schema provision-roles'",
                missing_or_drifted.join(", ")
            ));
        }
        if !self.owner_has_worker_membership {
            self.warnings.push(
                "setjoin_owner lacks setjoin_worker membership (required for apply_worker_ownership) — run 'mailctl schema provision-roles'"
                    .to_owned(),
            );
        }

        if !self.scope_helpers_drifted.is_empty() {
            let names: Vec<&str> = self
                .scope_helpers_drifted
                .iter()
                .map(|d| d.signature.as_str())
                .collect();
            self.warnings.push(format!(
                "ARCH-018 scope helper(s) drifted: {} — run 'mailctl schema provision-roles'",
                names.join(", ")
            ));
        }
        if !self.other_secdef_drifted.is_empty() {
            let names: Vec<&str> = self
                .other_secdef_drifted
                .iter()
                .map(|d| d.signature.as_str())
                .collect();
            self.warnings.push(format!(
                "non-extension SECURITY DEFINER function(s) have PUBLIC EXECUTE or unpinned search_path: {}",
                names.join(", ")
            ));
        }

        if let Some(dsn_roles) = &self.dsn_roles {
            if dsn_roles.config_env_unreadable {
                self.warnings.push(CONFIG_ENV_UNREADABLE_WARNING.to_owned());
            } else {
                let mut dsn_warnings = Vec::new();
                let (effective_app_role, effective_worker_role, effective_owner_role) =
                    self.effective_dsn_roles(dsn_roles);
                if let Some(app_role) = effective_app_role {
                    if dsn_roles.app_role_privileged == Some(true) {
                        dsn_warnings.push(format!(
                            "configured DB_DSN role {:?} is privileged (SUPERUSER or BYPASSRLS) — FORCE RLS is inert; run 'mailctl schema provision-roles --write-dsns'",
                            app_role
                        ));
                    } else if self.context == PostureContext::OperatorOwner
                        && app_role != "setjoin_app"
                    {
                        dsn_warnings.push(format!(
                            "configured DB_DSN role is {:?} (expected 'setjoin_app') — run 'mailctl schema provision-roles --write-dsns'",
                            app_role
                        ));
                    }
                    if effective_worker_role.is_some_and(|w| w == app_role) {
                        dsn_warnings.push(format!(
                            "DB_DSN and DB_WORKER_DSN share role {:?} — worker and app roles must be distinct",
                            app_role
                        ));
                    }
                    if effective_owner_role.is_some_and(|o| o == app_role) {
                        dsn_warnings.push(format!(
                            "DB_DSN and DB_OWNER_DSN share role {:?} — owner and app roles must be distinct",
                            app_role
                        ));
                    }
                }
                self.warnings.extend(dsn_warnings);
            }
        }
    }
}

/// Redacted admin health check row derived from startup posture.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootHealthCheck {
    pub check_name: &'static str,
    pub status: &'static str,
    pub details: String,
}

/// Startup RLS/PG-version posture shared with `/health` and `/admin/health`.
///
/// All strings in [`BootPosture`] are redacted (role names and counts only;
/// zero passwords or raw DSNs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootPosture {
    pub mode: EnforcementMode,
    pub overall_status: &'static str,
    pub report: Option<RlsPreflightReport>,
    pub checks: Vec<BootHealthCheck>,
}

impl BootPosture {
    /// Bare front door (no database configured).
    pub fn bare() -> Self {
        Self {
            mode: EnforcementMode::FailClosedReleaseNPlus1,
            overall_status: "ok",
            report: None,
            checks: Vec::new(),
        }
    }

    pub fn from_report(report: RlsPreflightReport, mode: EnforcementMode) -> Self {
        let mut checks = Vec::with_capacity(3);
        let non_ok_status = match mode {
            EnforcementMode::WarnReleaseN => "warn",
            EnforcementMode::FailClosedReleaseNPlus1 => "error",
        };

        // 1. db_rls_posture
        let rls_has_hard = !report.policy_tables_rls_disabled.is_empty()
            || (report.context == PostureContext::RuntimeApp
                && !report.current_role.rolsuper
                && (report.current_role.rolbypassrls || !report.owns_forced_rls_tables.is_empty()))
            || (report.context == PostureContext::OperatorOwner
                && !report.app_owns_forced_rls_tables.is_empty());
        let (shared_worker, shared_owner) = report
            .dsn_roles
            .as_ref()
            .map(|d| {
                let (app, worker, owner) = report.effective_dsn_roles(d);
                (
                    app.is_some_and(|a| worker == Some(a)),
                    app.is_some_and(|a| owner == Some(a)),
                )
            })
            .unwrap_or((false, false));
        let rls_has_warn = (report.context == PostureContext::RuntimeApp
            && report.current_role.rolsuper)
            || !report.all_roles_exist_with_expected_attrs()
            || shared_worker
            || shared_owner
            || report.dsn_roles.as_ref().is_some_and(|d| {
                d.app_role_privileged == Some(true)
                    || (report.context == PostureContext::OperatorOwner
                        && d.app_role.as_deref().is_some_and(|a| a != "setjoin_app"))
                    || d.config_env_unreadable
            });
        let (rls_status, rls_details) = if rls_has_hard {
            ("error", report.hard_errors.join("; "))
        } else if rls_has_warn {
            let mut parts = Vec::new();
            if report.context == PostureContext::RuntimeApp && report.current_role.rolsuper {
                parts.push(format!(
                    "runtime role {:?} is superuser (FORCE RLS inert)",
                    report.current_role.name
                ));
            }
            if !report.all_roles_exist_with_expected_attrs() {
                parts.push("least-privilege roles incomplete or drifted".to_owned());
            }
            if shared_worker {
                parts.push("DB_DSN and DB_WORKER_DSN share a role".to_owned());
            }
            if shared_owner {
                parts.push("DB_DSN and DB_OWNER_DSN share a role".to_owned());
            }
            if parts.is_empty() {
                parts.push(format!(
                    "runtime role {:?} does not match least-privilege split",
                    report.current_role.name
                ));
            }
            parts.push("remediate: mailctl schema provision-roles --write-dsns".to_owned());
            (non_ok_status, parts.join("; "))
        } else {
            (
                "ok",
                format!(
                    "runtime role {:?} constrained (NOSUPERUSER NOBYPASSRLS, FORCE RLS active)",
                    report.current_role.name
                ),
            )
        };
        checks.push(BootHealthCheck {
            check_name: "db_rls_posture",
            status: rls_status,
            details: rls_details,
        });

        // 2. pg_version_cve_2026_14666
        let (pg_status, pg_details) = if report.pg_version_ok {
            (
                "ok",
                format!(
                    "PostgreSQL {} ({}) includes CVE-2026-14666 fix",
                    report.server_version, report.server_version_num
                ),
            )
        } else {
            (
                non_ok_status,
                format!(
                    "PostgreSQL {} ({}) is vulnerable to CVE-2026-14666; upgrade to >= 17.11 or >= 18.6",
                    report.server_version, report.server_version_num
                ),
            )
        };
        checks.push(BootHealthCheck {
            check_name: "pg_version_cve_2026_14666",
            status: pg_status,
            details: pg_details,
        });

        // 3. rls_scope_helpers
        let helper_drift_count =
            report.scope_helpers_drifted.len() + report.other_secdef_drifted.len();
        let (helper_status, helper_details) = if helper_drift_count == 0 {
            (
                "ok",
                "all ARCH-018 scope helpers worker-owned with pinned search_path and no PUBLIC EXECUTE"
                    .to_owned(),
            )
        } else {
            (
                non_ok_status,
                format!(
                    "{} scope/SECURITY DEFINER helper(s) drifted ({} ARCH-018, {} other); remediate: mailctl schema provision-roles",
                    helper_drift_count,
                    report.scope_helpers_drifted.len(),
                    report.other_secdef_drifted.len()
                ),
            )
        };
        checks.push(BootHealthCheck {
            check_name: "rls_scope_helpers",
            status: helper_status,
            details: helper_details,
        });

        let overall_status = if !report.hard_errors.is_empty() {
            "error"
        } else if !report.warnings.is_empty() {
            non_ok_status
        } else {
            "ok"
        };

        Self {
            mode,
            overall_status,
            report: Some(report),
            checks,
        }
    }

    pub fn public_status(&self) -> &'static str {
        self.overall_status
    }

    pub fn admin_checks(&self) -> &[BootHealthCheck] {
        &self.checks
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionReport {
    pub pass1_executed: bool,
    pub pass1_attempts: u32,
    pub scope_helpers_repaired: Vec<String>,
    pub pass2_executed: bool,
    pub verified: RlsPreflightReport,
}

/// Expected role attribute check per `scripts/provision-roles.sql`.
fn role_attributes_expected(
    name: &str,
    rolcanlogin: bool,
    rolsuper: bool,
    rolbypassrls: bool,
    rolcreatedb: bool,
    rolcreaterole: bool,
) -> bool {
    match name {
        "setjoin_app" | "setjoin_updater" => {
            rolcanlogin && !rolsuper && !rolbypassrls && !rolcreatedb && !rolcreaterole
        }
        "setjoin_worker" => {
            rolcanlogin && !rolsuper && rolbypassrls && !rolcreatedb && !rolcreaterole
        }
        "setjoin_owner" => !rolsuper && !rolbypassrls && !rolcreatedb,
        _ => false,
    }
}

/// Redact passwords from PostgreSQL URIs (`postgres://user:pass@host/db`,
/// `?password=...`) and libpq key=value conninfo (`password='s\'ecret'`),
/// including URIs or kv tokens embedded inside larger error messages.
pub fn redact_dsn(raw: &str) -> String {
    let trimmed = raw.trim();
    let uri_redacted = redact_embedded_uris(trimmed);
    redact_kv_dsn(&uri_redacted)
}

fn redact_embedded_uris(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    while cursor < input.len() {
        let rest = &input[cursor..];
        let next_pos = [rest.find("postgres://"), rest.find("postgresql://")]
            .into_iter()
            .flatten()
            .min();
        let Some(rel_start) = next_pos else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..rel_start]);
        let token_start = cursor + rel_start;
        let after = &input[token_start..];
        let rel_end = after
            .find(|c: char| {
                c.is_whitespace()
                    || matches!(c, '\'' | '"' | ')' | ']' | '}' | ',' | ';' | '<' | '>')
            })
            .unwrap_or(after.len());
        let raw_token = &after[..rel_end];
        let trimmed_uri = raw_token.trim_end_matches([':', '.']);
        let trailing = &raw_token[trimmed_uri.len()..];
        out.push_str(&redact_uri_dsn(trimmed_uri));
        out.push_str(trailing);
        cursor = token_start + rel_end;
    }
    out
}

fn redact_uri_dsn(uri: &str) -> String {
    let Some(scheme_end) = uri.find("://") else {
        return uri.to_owned();
    };
    let scheme = &uri[..scheme_end + 3];
    let rest = &uri[scheme_end + 3..];
    let (authority_and_path, query_part) = match rest.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (rest, None),
    };
    let (authority, path) = match authority_and_path.find('/') {
        Some(idx) => (&authority_and_path[..idx], &authority_and_path[idx..]),
        None => (authority_and_path, ""),
    };
    let redacted_authority = if let Some(at_idx) = authority.rfind('@') {
        let userinfo = &authority[..at_idx];
        let hostport = &authority[at_idx + 1..];
        if let Some(colon_idx) = userinfo.find(':') {
            format!("{}:{}@{hostport}", &userinfo[..colon_idx], "***")
        } else {
            authority.to_owned()
        }
    } else {
        authority.to_owned()
    };
    let redacted_query = query_part.map(|q| {
        q.split('&')
            .map(|pair| match pair.split_once('=') {
                Some((k, _)) if k.eq_ignore_ascii_case("password") => format!("{k}=***"),
                _ => pair.to_owned(),
            })
            .collect::<Vec<_>>()
            .join("&")
    });
    match redacted_query {
        Some(q) => format!("{scheme}{redacted_authority}{path}?{q}"),
        None => format!("{scheme}{redacted_authority}{path}"),
    }
}

fn redact_kv_dsn(kv: &str) -> String {
    let bytes = kv.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n);
    let mut i = 0;
    while i < n {
        while i < n && bytes[i].is_ascii_whitespace() {
            out.push(bytes[i] as char);
            i += 1;
        }
        if i >= n {
            break;
        }
        let k_start = i;
        while i < n && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let key = &kv[k_start..i];
        out.push_str(key);
        while i < n && bytes[i].is_ascii_whitespace() {
            out.push(bytes[i] as char);
            i += 1;
        }
        if i >= n || bytes[i] != b'=' {
            continue;
        }
        out.push('=');
        i += 1;
        while i < n && bytes[i].is_ascii_whitespace() {
            out.push(bytes[i] as char);
            i += 1;
        }
        let v_start = i;
        if i < n && bytes[i] == b'\'' {
            i += 1;
            while i < n {
                if bytes[i] == b'\\' && i + 1 < n {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'\'' {
                    i += 1;
                    break;
                }
                i += 1;
            }
        } else {
            while i < n && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
        }
        if key.eq_ignore_ascii_case("password") {
            out.push_str("***");
        } else {
            out.push_str(&kv[v_start..i]);
        }
    }
    out
}

/// RFC 3986 percent-encode a URI userinfo component (username or password).
pub fn percent_encode_userinfo(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Percent-decode a URI component (invalid `%` sequences pass through verbatim).
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Escape a libpq key=value parameter value (`\` -> `\\`, `'` -> `\'`, single-quoted
/// whenever empty or containing whitespace, quotes, or backslashes).
pub fn escape_libpq_value(input: &str) -> String {
    let needs_quote = input.is_empty()
        || input
            .bytes()
            .any(|b| b.is_ascii_whitespace() || matches!(b, b'\'' | b'\\' | b'='));
    if !needs_quote {
        return input.to_owned();
    }
    let mut out = String::with_capacity(input.len() + 2);
    out.push('\'');
    for ch in input.chars() {
        if ch == '\\' || ch == '\'' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('\'');
    out
}

fn parse_kv_pairs(kv: &str) -> Vec<(String, String)> {
    let bytes = kv.as_bytes();
    let n = bytes.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        while i < n && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= n {
            break;
        }
        let k_start = i;
        while i < n && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let key = kv[k_start..i].to_owned();
        while i < n && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= n || bytes[i] != b'=' {
            continue;
        }
        i += 1;
        while i < n && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let val = if i < n && bytes[i] == b'\'' {
            i += 1;
            let mut buf = Vec::new();
            while i < n {
                if bytes[i] == b'\\' && i + 1 < n {
                    buf.push(bytes[i + 1]);
                    i += 2;
                    continue;
                }
                if bytes[i] == b'\'' {
                    i += 1;
                    break;
                }
                buf.push(bytes[i]);
                i += 1;
            }
            String::from_utf8_lossy(&buf).into_owned()
        } else {
            let v_start = i;
            while i < n && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            kv[v_start..i].to_owned()
        };
        if !key.is_empty() {
            out.push((key, val));
        }
    }
    out
}

/// Extract the role username from a PostgreSQL URI or libpq key=value DSN without
/// exposing any password.
pub fn dsn_username(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("postgres://") || trimmed.starts_with("postgresql://") {
        let rest = trimmed.split_once("://")?.1;
        let (authority_and_path, query) = match rest.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (rest, None),
        };
        let authority = match authority_and_path.find('/') {
            Some(idx) => &authority_and_path[..idx],
            None => authority_and_path,
        };
        if let Some(at_idx) = authority.rfind('@') {
            let userinfo = &authority[..at_idx];
            let user_raw = userinfo.split_once(':').map_or(userinfo, |(u, _)| u);
            let decoded = percent_decode(user_raw);
            if !decoded.is_empty() {
                return Some(decoded);
            }
        }
        if let Some(q) = query {
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if k.eq_ignore_ascii_case("user") && !v.is_empty() {
                        return Some(percent_decode(v));
                    }
                }
            }
        }
        None
    } else {
        parse_kv_pairs(trimmed)
            .into_iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case("user"))
            .map(|(_, v)| v)
            .filter(|v| !v.is_empty())
    }
}

/// Extract and decode the password from a PostgreSQL URI or libpq key=value DSN.
pub fn extract_dsn_password(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("postgres://") || trimmed.starts_with("postgresql://") {
        let rest = trimmed.split_once("://")?.1;
        let (authority_and_path, query) = match rest.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (rest, None),
        };
        let authority = match authority_and_path.find('/') {
            Some(idx) => &authority_and_path[..idx],
            None => authority_and_path,
        };
        if let Some(at_idx) = authority.rfind('@') {
            let userinfo = &authority[..at_idx];
            if let Some((_, pw_raw)) = userinfo.split_once(':') {
                let decoded = percent_decode(pw_raw);
                if !decoded.is_empty() {
                    return Some(decoded);
                }
            }
        }
        if let Some(q) = query {
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if k.eq_ignore_ascii_case("password") && !v.is_empty() {
                        return Some(percent_decode(v));
                    }
                }
            }
        }
        None
    } else {
        parse_kv_pairs(trimmed)
            .into_iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case("password"))
            .map(|(_, v)| v)
            .filter(|v| !v.is_empty())
    }
}

/// Rewrite a base DSN (URI or libpq kv) with a new username and password using
/// RFC 3986 percent-encoding (URI) or libpq quoting/escaping (kv).
pub fn rewrite_dsn_credentials(
    base_dsn: &str,
    new_user: &str,
    new_password: &str,
) -> Result<String, String> {
    let trimmed = base_dsn.trim();
    if trimmed.is_empty() {
        return Err("base DSN is empty".to_owned());
    }
    if trimmed.starts_with("postgres://") || trimmed.starts_with("postgresql://") {
        let scheme_end = trimmed.find("://").ok_or("invalid URI DSN")?;
        let scheme = &trimmed[..scheme_end + 3];
        let rest = &trimmed[scheme_end + 3..];
        let (authority_and_path, query_part) = match rest.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (rest, None),
        };
        let (authority, path) = match authority_and_path.find('/') {
            Some(idx) => (&authority_and_path[..idx], &authority_and_path[idx..]),
            None => (authority_and_path, ""),
        };
        let hostport = match authority.rfind('@') {
            Some(idx) => &authority[idx + 1..],
            None => authority,
        };
        let has_query_host = query_part.is_some_and(|q| {
            q.split('&').any(|pair| {
                pair.split_once('=')
                    .is_some_and(|(k, v)| k.eq_ignore_ascii_case("host") && !v.is_empty())
            })
        });
        if hostport.is_empty() && !has_query_host {
            return Err("URI DSN missing host".to_owned());
        }
        let user_enc = percent_encode_userinfo(new_user);
        let pw_enc = percent_encode_userinfo(new_password);
        let cleaned_query = query_part.map(|q| {
            q.split('&')
                .filter(|pair| {
                    !pair.split_once('=').is_some_and(|(k, _)| {
                        k.eq_ignore_ascii_case("user") || k.eq_ignore_ascii_case("password")
                    })
                })
                .filter(|pair| !pair.is_empty())
                .collect::<Vec<_>>()
                .join("&")
        });
        match cleaned_query.as_deref() {
            Some(q) if !q.is_empty() => {
                Ok(format!("{scheme}{user_enc}:{pw_enc}@{hostport}{path}?{q}"))
            }
            _ => Ok(format!("{scheme}{user_enc}:{pw_enc}@{hostport}{path}")),
        }
    } else {
        let mut pairs = parse_kv_pairs(trimmed);
        if pairs.is_empty() {
            return Err("invalid libpq key=value DSN".to_owned());
        }
        let mut saw_user = false;
        let mut saw_password = false;
        for (k, v) in &mut pairs {
            if k.eq_ignore_ascii_case("user") {
                *v = new_user.to_owned();
                saw_user = true;
            } else if k.eq_ignore_ascii_case("password") {
                *v = new_password.to_owned();
                saw_password = true;
            }
        }
        if !saw_user {
            pairs.push(("user".to_owned(), new_user.to_owned()));
        }
        if !saw_password {
            pairs.push(("password".to_owned(), new_password.to_owned()));
        }
        Ok(pairs
            .into_iter()
            .map(|(k, v)| format!("{k}={}", escape_libpq_value(&v)))
            .collect::<Vec<_>>()
            .join(" "))
    }
}

/// Set a managed Setjoin role's LOGIN password using bound parameters and
/// server-side `format('ALTER ROLE %I WITH LOGIN PASSWORD %L', ...)` so
/// passwords never travel in CLI argv, logs, or unescaped SQL strings.
pub async fn set_role_login_password(
    conn: &mut OperatorConnection,
    role: &str,
    password: &str,
) -> Result<(), String> {
    set_role_login_password_client(conn.client_mut(), role, password).await
}

pub async fn set_role_login_password_client(
    client: &mut Client,
    role: &str,
    password: &str,
) -> Result<(), String> {
    if !EXPECTED_ROLES.contains(&role) {
        return Err(format!(
            "refusing to alter password for unmanaged role {role:?}"
        ));
    }
    if password.is_empty() || password.contains('\0') {
        return Err(format!("invalid password for role {role:?}"));
    }
    let tx = client
        .transaction()
        .await
        .map_err(|e| redact_dsn(&pg_error(e)))?;
    tx.query_typed(
        "SELECT set_config('setjoin.provision_role', $1, true), set_config('setjoin.provision_pw', $2, true)",
        &[(&role, Type::TEXT), (&password, Type::TEXT)],
    )
    .await
    .map_err(|e| redact_dsn(&pg_error(e)))?;
    tx.batch_execute(
        "DO $setjoin_pw$ \
         BEGIN \
           EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L', \
             current_setting('setjoin.provision_role'), \
             current_setting('setjoin.provision_pw')); \
           PERFORM set_config('setjoin.provision_pw', '', true); \
         END \
         $setjoin_pw$;",
    )
    .await
    .map_err(|e| redact_dsn(&pg_error(e)))?;
    tx.commit().await.map_err(|e| redact_dsn(&pg_error(e)))
}

/// Inspect live PostgreSQL RLS posture on an [`OperatorConnection`].
pub async fn inspect_rls_posture_operator(
    conn: &OperatorConnection,
    context: PostureContext,
    dsn_roles: Option<DsnRoleSummary>,
) -> Result<RlsPreflightReport, String> {
    inspect_rls_posture_client(conn.client(), context, dsn_roles).await
}

/// Inspect live PostgreSQL RLS posture on a [`WorkerConnection`].
pub async fn inspect_rls_posture_worker(
    conn: &WorkerConnection,
    context: PostureContext,
    dsn_roles: Option<DsnRoleSummary>,
) -> Result<RlsPreflightReport, String> {
    inspect_rls_posture_client(conn.operator_client(), context, dsn_roles).await
}

/// Inspect live PostgreSQL RLS posture over a pooled [`ScopedExecutor`] (e.g.
/// `setjoin-auth` startup). Uses `SELECT`-only unnamed statements.
pub async fn inspect_rls_posture_executor(
    exec: &ScopedExecutor,
    context: PostureContext,
    mut dsn_roles: Option<DsnRoleSummary>,
) -> Result<RlsPreflightReport, String> {
    let ver_rows = exec
        .read(
            "SELECT current_setting('server_version_num')::int4, current_setting('server_version')",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&e.message))?;
    let server_version_num = u32::try_from(ver_rows[0].get::<_, i32>(0)).unwrap_or(0);
    let server_version: String = ver_rows[0].get(1);

    let role_rows = exec
        .read(
            "SELECT current_user::text, rolsuper, rolbypassrls, rolcreaterole FROM pg_roles WHERE rolname = current_user",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&e.message))?;
    let current_role = CurrentRolePosture {
        name: role_rows[0].get(0),
        rolsuper: role_rows[0].get(1),
        rolbypassrls: role_rows[0].get(2),
        rolcreaterole: role_rows[0].get(3),
    };

    let can_read_authid: bool = exec
        .read(
            "SELECT has_table_privilege('pg_catalog.pg_authid', 'SELECT')",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&e.message))?[0]
        .get(0);

    let expected_vec: Vec<String> = EXPECTED_ROLES.iter().map(|s| (*s).to_owned()).collect();
    let roles_sql = if can_read_authid {
        "SELECT r.rolname::text, r.rolcanlogin, r.rolsuper, r.rolbypassrls, r.rolcreatedb, r.rolcreaterole, \
                (a.rolpassword IS NOT NULL AND a.rolpassword <> '') \
         FROM pg_roles r \
         LEFT JOIN pg_catalog.pg_authid a ON a.oid = r.oid \
         WHERE r.rolname = ANY($1) \
         ORDER BY r.rolname"
    } else {
        "SELECT r.rolname::text, r.rolcanlogin, r.rolsuper, r.rolbypassrls, r.rolcreatedb, r.rolcreaterole, \
                NULL::boolean \
         FROM pg_roles r \
         WHERE r.rolname = ANY($1) \
         ORDER BY r.rolname"
    };
    let role_list_rows = exec
        .read(roles_sql, &[(&expected_vec, Type::TEXT_ARRAY)])
        .await
        .map_err(|e| redact_dsn(&e.message))?;
    let roles = build_role_postures(&role_list_rows);

    let owner_has_worker_membership: bool = exec
        .read(
            "SELECT CASE \
               WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') \
                AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') \
               THEN pg_has_role('setjoin_owner', 'setjoin_worker', 'MEMBER') \
               ELSE false \
             END",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&e.message))?[0]
        .get(0);

    let owns_forced_rls_tables: Vec<String> = exec
        .read(
            "SELECT c.relname::text FROM pg_class c \
             WHERE c.relforcerowsecurity AND c.relkind IN ('r','p') \
               AND pg_has_role(current_user, c.relowner, 'MEMBER') \
             ORDER BY c.relname",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&e.message))?
        .into_iter()
        .map(|r| r.get(0))
        .collect();

    let app_owns_forced_rls_tables: Vec<String> = exec
        .read(
            "SELECT c.relname::text FROM pg_class c \
             WHERE c.relforcerowsecurity AND c.relkind IN ('r','p') \
               AND CASE \
                 WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') \
                 THEN pg_has_role('setjoin_app', c.relowner, 'MEMBER') \
                 ELSE false \
               END \
             ORDER BY c.relname",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&e.message))?
        .into_iter()
        .map(|r| r.get(0))
        .collect();

    let policy_tables_rls_disabled: Vec<String> = exec
        .read(
            "SELECT DISTINCT c.relname::text FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid \
             WHERE c.relkind IN ('r','p') AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity) \
             ORDER BY c.relname::text",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&e.message))?
        .into_iter()
        .map(|r| r.get(0))
        .collect();

    let canonical_vec: Vec<String> = CANONICAL_ARCH018_SCOPE_HELPERS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let fn_rows = exec
        .read(
            SCOPE_HELPER_AUDIT_SQL,
            &[(&canonical_vec, Type::TEXT_ARRAY)],
        )
        .await
        .map_err(|e| redact_dsn(&e.message))?;
    let (scope_helpers_drifted, other_secdef_drifted) = classify_secdef_rows(&fn_rows);

    if let Some(summary) = dsn_roles.as_mut() {
        if let Some(app_role) = summary.app_role.as_deref() {
            let priv_rows = exec
                .read(
                    "SELECT (rolsuper OR rolbypassrls) FROM pg_roles WHERE rolname = $1",
                    &[(&app_role, Type::TEXT)],
                )
                .await
                .map_err(|e| redact_dsn(&e.message))?;
            summary.app_role_privileged = priv_rows.first().map(|r| r.get::<_, bool>(0));
        }
    }

    let mut report = RlsPreflightReport {
        context,
        server_version_num,
        server_version,
        pg_version_ok: pg_version_allows_prepared_rls(server_version_num),
        current_role,
        roles,
        owner_has_worker_membership,
        owns_forced_rls_tables,
        app_owns_forced_rls_tables,
        policy_tables_rls_disabled,
        scope_helpers_drifted,
        other_secdef_drifted,
        dsn_roles,
        hard_errors: Vec::new(),
        warnings: Vec::new(),
    };
    report.evaluate_findings();
    Ok(report)
}

const SCOPE_HELPER_AUDIT_SQL: &str = "\
SELECT p.oid::regprocedure::text AS sig, \
       r.rolname::text AS owner, \
       p.prosecdef, \
       coalesce(p.proconfig @> ARRAY['search_path=pg_catalog, public'], false) AS strict_search_path, \
       EXISTS ( \
         SELECT 1 FROM unnest(coalesce(p.proconfig, ARRAY[]::text[])) cfg \
         WHERE cfg LIKE 'search_path=%' \
       ) AS any_search_path, \
       has_function_privilege('public', p.oid, 'EXECUTE') AS pub_exec, \
       (p.oid = ANY( \
         ARRAY( \
           SELECT to_regprocedure(sig)::oid \
           FROM unnest($1::text[]) AS sig \
           WHERE to_regprocedure(sig) IS NOT NULL \
         ) \
       )) AS is_canonical \
FROM pg_proc p \
JOIN pg_namespace n ON n.oid = p.pronamespace \
JOIN pg_roles r ON r.oid = p.proowner \
WHERE n.nspname = 'public' \
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e') \
  AND ( \
    p.prosecdef \
    OR p.oid = ANY( \
      ARRAY( \
        SELECT to_regprocedure(sig)::oid \
        FROM unnest($1::text[]) AS sig \
        WHERE to_regprocedure(sig) IS NOT NULL \
      ) \
    ) \
  ) \
ORDER BY sig";

fn build_role_postures(rows: &[tokio_postgres::Row]) -> Vec<RolePosture> {
    let mut out = Vec::with_capacity(EXPECTED_ROLES.len());
    for &expected in EXPECTED_ROLES {
        if let Some(row) = rows.iter().find(|r| r.get::<_, String>(0) == expected) {
            let rolcanlogin: bool = row.get(1);
            let rolsuper: bool = row.get(2);
            let rolbypassrls: bool = row.get(3);
            let rolcreatedb: bool = row.get(4);
            let rolcreaterole: bool = row.get(5);
            let has_password: Option<bool> = row.get(6);
            let attributes_ok = role_attributes_expected(
                expected,
                rolcanlogin,
                rolsuper,
                rolbypassrls,
                rolcreatedb,
                rolcreaterole,
            );
            out.push(RolePosture {
                name: expected.to_owned(),
                exists: true,
                rolcanlogin,
                rolsuper,
                rolbypassrls,
                rolcreatedb,
                rolcreaterole,
                has_password,
                attributes_ok,
            });
        } else {
            out.push(RolePosture {
                name: expected.to_owned(),
                exists: false,
                rolcanlogin: false,
                rolsuper: false,
                rolbypassrls: false,
                rolcreatedb: false,
                rolcreaterole: false,
                has_password: None,
                attributes_ok: false,
            });
        }
    }
    out
}

fn classify_secdef_rows(
    rows: &[tokio_postgres::Row],
) -> (Vec<ScopeHelperDrift>, Vec<ScopeHelperDrift>) {
    let mut canonical_drifted = Vec::new();
    let mut other_drifted = Vec::new();
    for row in rows {
        let sig: String = row.get(0);
        let owner: String = row.get(1);
        let prosecdef: bool = row.get(2);
        let strict_search_path: bool = row.get(3);
        let any_search_path: bool = row.get(4);
        let pub_exec: bool = row.get(5);
        let is_canonical: bool = row.get(6);

        if is_canonical {
            let mut reasons = Vec::new();
            if !prosecdef {
                reasons.push("not SECURITY DEFINER");
            }
            if owner != "setjoin_worker" {
                reasons.push("owner != setjoin_worker");
            }
            if !strict_search_path {
                reasons.push("search_path != 'pg_catalog, public'");
            }
            if pub_exec {
                reasons.push("PUBLIC has EXECUTE");
            }
            if !reasons.is_empty() {
                canonical_drifted.push(ScopeHelperDrift {
                    signature: sig,
                    canonical_arch018: true,
                    owner,
                    search_path_ok: strict_search_path,
                    public_execute: pub_exec,
                    reason: reasons.join(", "),
                });
            }
        } else {
            let mut reasons = Vec::new();
            if !any_search_path {
                reasons.push("unpinned search_path");
            }
            if pub_exec {
                reasons.push("PUBLIC has EXECUTE");
            }
            if !reasons.is_empty() {
                other_drifted.push(ScopeHelperDrift {
                    signature: sig,
                    canonical_arch018: false,
                    owner,
                    search_path_ok: any_search_path,
                    public_execute: pub_exec,
                    reason: reasons.join(", "),
                });
            }
        }
    }
    (canonical_drifted, other_drifted)
}

/// Inspect live PostgreSQL RLS posture on a raw [`tokio_postgres::Client`].
pub async fn inspect_rls_posture_client(
    client: &Client,
    context: PostureContext,
    mut dsn_roles: Option<DsnRoleSummary>,
) -> Result<RlsPreflightReport, String> {
    let ver_rows = client
        .query_typed(
            "SELECT current_setting('server_version_num')::int4, current_setting('server_version')",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&pg_error(e)))?;
    let server_version_num = u32::try_from(ver_rows[0].get::<_, i32>(0)).unwrap_or(0);
    let server_version: String = ver_rows[0].get(1);

    let role_rows = client
        .query_typed(
            "SELECT current_user::text, rolsuper, rolbypassrls, rolcreaterole FROM pg_roles WHERE rolname = current_user",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&pg_error(e)))?;
    let current_role = CurrentRolePosture {
        name: role_rows[0].get(0),
        rolsuper: role_rows[0].get(1),
        rolbypassrls: role_rows[0].get(2),
        rolcreaterole: role_rows[0].get(3),
    };

    let can_read_authid: bool = client
        .query_typed(
            "SELECT has_table_privilege('pg_catalog.pg_authid', 'SELECT')",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&pg_error(e)))?[0]
        .get(0);

    let expected_vec: Vec<String> = EXPECTED_ROLES.iter().map(|s| (*s).to_owned()).collect();
    let roles_sql = if can_read_authid {
        "SELECT r.rolname::text, r.rolcanlogin, r.rolsuper, r.rolbypassrls, r.rolcreatedb, r.rolcreaterole, \
                (a.rolpassword IS NOT NULL AND a.rolpassword <> '') \
         FROM pg_roles r \
         LEFT JOIN pg_catalog.pg_authid a ON a.oid = r.oid \
         WHERE r.rolname = ANY($1) \
         ORDER BY r.rolname"
    } else {
        "SELECT r.rolname::text, r.rolcanlogin, r.rolsuper, r.rolbypassrls, r.rolcreatedb, r.rolcreaterole, \
                NULL::boolean \
         FROM pg_roles r \
         WHERE r.rolname = ANY($1) \
         ORDER BY r.rolname"
    };
    let role_list_rows = client
        .query_typed(roles_sql, &[(&expected_vec, Type::TEXT_ARRAY)])
        .await
        .map_err(|e| redact_dsn(&pg_error(e)))?;
    let roles = build_role_postures(&role_list_rows);

    let owner_has_worker_membership: bool = client
        .query_typed(
            "SELECT CASE \
               WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') \
                AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') \
               THEN pg_has_role('setjoin_owner', 'setjoin_worker', 'MEMBER') \
               ELSE false \
             END",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&pg_error(e)))?[0]
        .get(0);

    let owns_forced_rls_tables: Vec<String> = client
        .query_typed(
            "SELECT c.relname::text FROM pg_class c \
             WHERE c.relforcerowsecurity AND c.relkind IN ('r','p') \
               AND pg_has_role(current_user, c.relowner, 'MEMBER') \
             ORDER BY c.relname",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&pg_error(e)))?
        .into_iter()
        .map(|r| r.get(0))
        .collect();

    let app_owns_forced_rls_tables: Vec<String> = client
        .query_typed(
            "SELECT c.relname::text FROM pg_class c \
             WHERE c.relforcerowsecurity AND c.relkind IN ('r','p') \
               AND CASE \
                 WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') \
                 THEN pg_has_role('setjoin_app', c.relowner, 'MEMBER') \
                 ELSE false \
               END \
             ORDER BY c.relname",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&pg_error(e)))?
        .into_iter()
        .map(|r| r.get(0))
        .collect();

    let policy_tables_rls_disabled: Vec<String> = client
        .query_typed(
            "SELECT DISTINCT c.relname::text FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid \
             WHERE c.relkind IN ('r','p') AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity) \
             ORDER BY c.relname::text",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&pg_error(e)))?
        .into_iter()
        .map(|r| r.get(0))
        .collect();

    let canonical_vec: Vec<String> = CANONICAL_ARCH018_SCOPE_HELPERS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let fn_rows = client
        .query_typed(
            SCOPE_HELPER_AUDIT_SQL,
            &[(&canonical_vec, Type::TEXT_ARRAY)],
        )
        .await
        .map_err(|e| redact_dsn(&pg_error(e)))?;
    let (scope_helpers_drifted, other_secdef_drifted) = classify_secdef_rows(&fn_rows);

    if let Some(summary) = dsn_roles.as_mut() {
        if let Some(app_role) = summary.app_role.as_deref() {
            let priv_rows = client
                .query_typed(
                    "SELECT (rolsuper OR rolbypassrls) FROM pg_roles WHERE rolname = $1",
                    &[(&app_role, Type::TEXT)],
                )
                .await
                .map_err(|e| redact_dsn(&pg_error(e)))?;
            summary.app_role_privileged = priv_rows.first().map(|r| r.get::<_, bool>(0));
        }
    }

    let mut report = RlsPreflightReport {
        context,
        server_version_num,
        server_version,
        pg_version_ok: pg_version_allows_prepared_rls(server_version_num),
        current_role,
        roles,
        owner_has_worker_membership,
        owns_forced_rls_tables,
        app_owns_forced_rls_tables,
        policy_tables_rls_disabled,
        scope_helpers_drifted,
        other_secdef_drifted,
        dsn_roles,
        hard_errors: Vec::new(),
        warnings: Vec::new(),
    };
    report.evaluate_findings();
    Ok(report)
}

/// Split-pass role/grant provisioner on an [`OperatorConnection`].
pub async fn provision_roles_and_verify_operator(
    conn: &mut OperatorConnection,
    dsn_roles: Option<DsnRoleSummary>,
) -> Result<ProvisionReport, String> {
    provision_roles_and_verify_client(conn.client_mut(), dsn_roles).await
}

/// Split-pass role/grant provisioner safe for BOTH superuser/CREATEROLE admins
/// and non-superuser `setjoin_owner` (e.g. `setjoin-updater` `apply_migrations`):
///
/// 1. **Pass 1 (Cluster-global role DDL):** runs `PROVISION_ROLES_CLUSTER_SQL`
///    with bounded retry on `42710`/`XX000` when caller is superuser (or roles
///    are missing/drifted and caller has `CREATEROLE`). When caller is non-super
///    (e.g. `setjoin_owner`) and all 4 roles already exist with expected
///    attributes + `setjoin_worker` membership, Pass 1 is **verify-only** (never
///    fails with `42501`).
/// 2. **ARCH-018 scope-helper repair (BEFORE Pass 2):** invokes
///    `public.apply_worker_ownership(...)` **only** on the 8 canonical ARCH-018
///    scope helpers (and re-pins `search_path = pg_catalog, public` if drifted)
///    **before** Pass 2 runs so Pass 2's ~30 worker-only/updater-only
///    `REVOKE ALL ... FROM setjoin_app` carve-outs always win last!
/// 3. **Pass 2 (Owner-safe DB-local pass):** runs `PROVISION_ROLES_DB_LOCAL_SQL`.
/// 4. **Post-verify:** re-runs `inspect_rls_posture_client` and verifies no hard
///    errors or role/ARCH-018 drift remain.
pub async fn provision_roles_and_verify_client(
    client: &mut Client,
    dsn_roles: Option<DsnRoleSummary>,
) -> Result<ProvisionReport, String> {
    let pre = inspect_rls_posture_client(client, PostureContext::OperatorOwner, dsn_roles.clone())
        .await?;
    let (cluster_sql, db_local_sql) = setjoin_schema::provision_roles_passes();

    // Pass 1: cluster-global role DDL (superuser or CREATEROLE when needed;
    // verify-only for non-superuser setjoin_owner when roles already match).
    let mut pass1_executed = false;
    let mut pass1_attempts = 0u32;
    let roles_ready = pre.all_roles_exist_with_expected_attrs();
    if pre.current_role.rolsuper || (!roles_ready && pre.current_role.rolcreaterole) {
        const MAX_ATTEMPTS: u32 = 6;
        for attempt in 1..=MAX_ATTEMPTS {
            pass1_attempts = attempt;
            match client.batch_execute(cluster_sql).await {
                Ok(()) => {
                    pass1_executed = true;
                    break;
                }
                Err(err) => {
                    let code = err.code().map(|c| c.code()).unwrap_or("");
                    let retryable = code == "42710" || code == "XX000";
                    if retryable && attempt < MAX_ATTEMPTS {
                        let backoff_ms = 50u64 * u64::from(attempt);
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        continue;
                    }
                    return Err(format!(
                        "role provisioning pass 1 failed on attempt {attempt}: {}",
                        redact_dsn(&pg_error(err))
                    ));
                }
            }
        }
    } else if !roles_ready {
        let missing: Vec<&str> = pre
            .roles
            .iter()
            .filter(|r| !r.exists || !r.attributes_ok)
            .map(|r| r.name.as_str())
            .collect();
        return Err(format!(
            "cannot provision missing/drifted cluster roles ({}) as non-privileged role {:?}; run 'mailctl schema provision-roles' as a superuser or CREATEROLE admin first",
            missing.join(", "),
            pre.current_role.name
        ));
    }

    // Step 2 (atomic transaction): repair ONLY the 8 canonical ARCH-018 scope
    // helpers BEFORE Pass 2 of `provision-roles.sql` so Pass 2's ~30 worker-only
    // and updater-only `REVOKE ALL ... FROM setjoin_app` carve-outs always win
    // last. On PG 15+, a non-superuser schema owner transferring object ownership
    // (`ALTER FUNCTION/MATERIALIZED VIEW ... OWNER TO setjoin_worker`) requires
    // the target role to hold `CREATE` on schema `public` during the statement;
    // granting and immediately revoking it within the same transaction keeps
    // `CREATE` invisible to all other backends (MVCC) and absent after COMMIT.
    let mut scope_helpers_repaired = Vec::new();
    let tx = client.transaction().await.map_err(|e| {
        format!(
            "begin role provisioning pass 2 tx: {}",
            redact_dsn(&pg_error(e))
        )
    })?;
    let worker_already_has_create: bool = tx
        .query_typed(
            "SELECT has_schema_privilege('setjoin_worker', 'public', 'CREATE')",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&pg_error(e)))?[0]
        .get(0);
    let caller_owns_public: bool = tx
        .query_typed(
            "SELECT EXISTS ( \
               SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner \
               WHERE n.nspname = 'public' AND r.rolname = current_user \
             )",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&pg_error(e)))?[0]
        .get(0);
    let granted_transient_create =
        !pre.current_role.rolsuper && !worker_already_has_create && caller_owns_public;
    if granted_transient_create {
        tx.batch_execute("GRANT CREATE ON SCHEMA public TO setjoin_worker")
            .await
            .map_err(|e| {
                format!(
                    "granting transient schema CREATE for ownership transfer: {}",
                    redact_dsn(&pg_error(e))
                )
            })?;
    }

    let has_applicator: bool = tx
        .query_typed(
            "SELECT to_regprocedure('public.apply_worker_ownership(regprocedure)') IS NOT NULL",
            &[],
        )
        .await
        .map_err(|e| redact_dsn(&pg_error(e)))?[0]
        .get(0);
    if has_applicator {
        for &sig in CANONICAL_ARCH018_SCOPE_HELPERS {
            let exists_rows = tx
                .query_typed(
                    "SELECT p.oid::regprocedure::text, r.rolname::text, \
                            coalesce(p.proconfig @> ARRAY['search_path=pg_catalog, public'], false), \
                            has_function_privilege('public', p.oid, 'EXECUTE') \
                     FROM pg_proc p \
                     JOIN pg_roles r ON r.oid = p.proowner \
                     WHERE p.oid = to_regprocedure($1)",
                    &[(&sig, Type::TEXT)],
                )
                .await
                .map_err(|e| redact_dsn(&pg_error(e)))?;
            let Some(row) = exists_rows.first() else {
                continue;
            };
            let regproc: String = row.get(0);
            let owner: String = row.get(1);
            let search_path_ok: bool = row.get(2);
            let pub_exec: bool = row.get(3);
            if owner != "setjoin_worker" || !search_path_ok || pub_exec {
                if !search_path_ok {
                    // `sig` comes from the compile-time static CANONICAL_ARCH018_SCOPE_HELPERS allowlist.
                    let alter_sql =
                        format!("ALTER FUNCTION {sig} SET search_path = pg_catalog, public");
                    tx.batch_execute(&alter_sql).await.map_err(|e| {
                        format!("pinning search_path on {sig}: {}", redact_dsn(&pg_error(e)))
                    })?;
                }
                tx.query_typed(
                    "SELECT public.apply_worker_ownership(to_regprocedure($1))",
                    &[(&sig, Type::TEXT)],
                )
                .await
                .map_err(|e| {
                    format!(
                        "apply_worker_ownership({sig}) failed: {}",
                        redact_dsn(&pg_error(e))
                    )
                })?;
                scope_helpers_repaired.push(regproc);
            }
        }
    }

    // Step 2b: owner-safe DB-local pass (carve-outs run LAST and always win).
    tx.batch_execute(db_local_sql).await.map_err(|e| {
        format!(
            "role provisioning pass 2 failed: {}",
            redact_dsn(&pg_error(e))
        )
    })?;

    if granted_transient_create {
        tx.batch_execute("REVOKE CREATE ON SCHEMA public FROM setjoin_worker")
            .await
            .map_err(|e| {
                format!(
                    "revoking transient schema CREATE after ownership transfer: {}",
                    redact_dsn(&pg_error(e))
                )
            })?;
    }
    tx.commit().await.map_err(|e| {
        format!(
            "commit role provisioning pass 2: {}",
            redact_dsn(&pg_error(e))
        )
    })?;

    // Post-verification.
    let verified =
        inspect_rls_posture_client(client, PostureContext::OperatorOwner, dsn_roles).await?;
    if !verified.hard_errors.is_empty() {
        return Err(format!(
            "post-provisioning verification failed hard invariants: {}",
            verified.hard_errors.join("; ")
        ));
    }
    if !verified.all_roles_exist_with_expected_attrs() {
        return Err(
            "post-provisioning verification failed: one or more roles still missing or drifted"
                .to_owned(),
        );
    }
    if !verified.scope_helpers_drifted.is_empty() {
        let names: Vec<&str> = verified
            .scope_helpers_drifted
            .iter()
            .map(|d| d.signature.as_str())
            .collect();
        return Err(format!(
            "post-provisioning verification failed: ARCH-018 scope helper(s) still drifted: {}",
            names.join(", ")
        ));
    }

    Ok(ProvisionReport {
        pass1_executed,
        pass1_attempts,
        scope_helpers_repaired,
        pass2_executed: true,
        verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_version_cve_2026_14666_boundaries() {
        assert!(!pg_version_allows_prepared_rls(160004));
        assert!(!pg_version_allows_prepared_rls(170000));
        assert!(!pg_version_allows_prepared_rls(170010));
        assert!(pg_version_allows_prepared_rls(170011));
        assert!(pg_version_allows_prepared_rls(170012));
        assert!(pg_version_allows_prepared_rls(179999));
        assert!(!pg_version_allows_prepared_rls(180000));
        assert!(!pg_version_allows_prepared_rls(180005));
        assert!(pg_version_allows_prepared_rls(180006));
        assert!(pg_version_allows_prepared_rls(190000));
    }

    #[test]
    fn redact_dsn_strips_uri_and_kv_passwords() {
        assert_eq!(
            redact_dsn(
                "postgres://setjoin_app:supersecret@127.0.0.1:5432/mailserver?sslmode=disable"
            ),
            "postgres://setjoin_app:***@127.0.0.1:5432/mailserver?sslmode=disable"
        );
        assert_eq!(
            redact_dsn("postgresql://user:p%40ss%3Aword@db.internal:5432/mail?password=also_secret&sslmode=require"),
            "postgresql://user:***@db.internal:5432/mail?password=***&sslmode=require"
        );
        assert_eq!(
            redact_dsn("postgres://mail@127.0.0.1:15432/mailserver_test?sslmode=disable"),
            "postgres://mail@127.0.0.1:15432/mailserver_test?sslmode=disable"
        );
        assert_eq!(
            redact_dsn("host=127.0.0.1 port=5432 user=setjoin_app password='s\\'ec\\\\ret' dbname=mailserver"),
            "host=127.0.0.1 port=5432 user=setjoin_app password=*** dbname=mailserver"
        );
        assert_eq!(
            redact_dsn("host=127.0.0.1 user=mail password=plainsecret dbname=mailserver"),
            "host=127.0.0.1 user=mail password=*** dbname=mailserver"
        );
    }

    #[test]
    fn uri_and_kv_password_escape_roundtrip() {
        let tricky = "p@ss:w/rd?a#b%20'quote\\slash = &+";
        let uri_base = "postgres://mail:old@127.0.0.1:5432/mailserver?sslmode=require";
        let rewritten_uri = rewrite_dsn_credentials(uri_base, "setjoin_app", tricky).unwrap();
        assert!(!rewritten_uri.contains(tricky));
        assert_eq!(dsn_username(&rewritten_uri).as_deref(), Some("setjoin_app"));
        assert_eq!(
            extract_dsn_password(&rewritten_uri).as_deref(),
            Some(tricky)
        );
        assert!(redact_dsn(&rewritten_uri)
            .contains("setjoin_app:***@127.0.0.1:5432/mailserver?sslmode=require"));

        let kv_base = "host=127.0.0.1 port=5432 user=mail password='old' dbname=mailserver";
        let rewritten_kv = rewrite_dsn_credentials(kv_base, "setjoin_worker", tricky).unwrap();
        assert_eq!(
            dsn_username(&rewritten_kv).as_deref(),
            Some("setjoin_worker")
        );
        assert_eq!(extract_dsn_password(&rewritten_kv).as_deref(), Some(tricky));
        assert!(!redact_dsn(&rewritten_kv).contains("quote"));

        // Unix-socket URI DSN with empty hostport and ?host=/var/run/postgresql.
        let unix_base = "postgres:///mailserver?host=/var/run/postgresql&sslmode=disable";
        let rewritten_unix = rewrite_dsn_credentials(unix_base, "setjoin_app", "unix_pw!").unwrap();
        assert_eq!(
            rewritten_unix,
            "postgres://setjoin_app:unix_pw%21@/mailserver?host=/var/run/postgresql&sslmode=disable"
        );
        assert_eq!(
            extract_dsn_password(&rewritten_unix).as_deref(),
            Some("unix_pw!")
        );
        // Empty hostport without ?host=... is still rejected.
        assert!(rewrite_dsn_credentials("postgres:///mailserver", "setjoin_app", "pw").is_err());
    }

    #[test]
    fn redact_dsn_redacts_embedded_uris_in_error_messages() {
        let err = "connecting to postgres://setjoin_app:SECRET@127.0.0.1:5432/mail: failed";
        let redacted = redact_dsn(err);
        assert!(!redacted.contains("SECRET"), "{redacted}");
        assert_eq!(
            redacted,
            "connecting to postgres://setjoin_app:***@127.0.0.1:5432/mail: failed"
        );

        let multi = "primary (postgresql://u:PW1@h1/db?password=PW2) fallback host=h2 password=PW3";
        let redacted_multi = redact_dsn(multi);
        assert!(!redacted_multi.contains("PW1"), "{redacted_multi}");
        assert!(!redacted_multi.contains("PW2"), "{redacted_multi}");
        assert!(!redacted_multi.contains("PW3"), "{redacted_multi}");
        assert_eq!(
            redacted_multi,
            "primary (postgresql://u:***@h1/db?password=***) fallback host=h2 password=***"
        );
    }

    #[test]
    fn boot_posture_redacts_and_tracks_modes() {
        let mut report = RlsPreflightReport {
            context: PostureContext::RuntimeApp,
            server_version_num: 170010,
            server_version: "17.10".to_owned(),
            pg_version_ok: false,
            current_role: CurrentRolePosture {
                name: "mail".to_owned(),
                rolsuper: true,
                rolbypassrls: true,
                rolcreaterole: true,
            },
            roles: Vec::new(),
            owner_has_worker_membership: true,
            owns_forced_rls_tables: Vec::new(),
            app_owns_forced_rls_tables: Vec::new(),
            policy_tables_rls_disabled: Vec::new(),
            scope_helpers_drifted: Vec::new(),
            other_secdef_drifted: Vec::new(),
            dsn_roles: None,
            hard_errors: Vec::new(),
            warnings: Vec::new(),
        };
        report.evaluate_findings();
        assert_eq!(report.exit_code(EnforcementMode::WarnReleaseN), 2);
        assert_eq!(
            report.exit_code(EnforcementMode::FailClosedReleaseNPlus1),
            1
        );
        let warn_posture = BootPosture::from_report(report.clone(), EnforcementMode::WarnReleaseN);
        assert_eq!(warn_posture.public_status(), "warn");
        assert_eq!(warn_posture.admin_checks().len(), 3);
        assert_eq!(warn_posture.admin_checks()[0].check_name, "db_rls_posture");
        assert_eq!(warn_posture.admin_checks()[0].status, "warn");
        assert_eq!(
            warn_posture.admin_checks()[1].check_name,
            "pg_version_cve_2026_14666"
        );
        assert_eq!(warn_posture.admin_checks()[1].status, "warn");
        assert_eq!(
            warn_posture.admin_checks()[2].check_name,
            "rls_scope_helpers"
        );
        assert_eq!(warn_posture.admin_checks()[2].status, "ok");

        let strict_posture =
            BootPosture::from_report(report, EnforcementMode::FailClosedReleaseNPlus1);
        assert_eq!(strict_posture.public_status(), "error");
        assert_eq!(strict_posture.admin_checks()[0].status, "error");
        assert_eq!(strict_posture.admin_checks()[1].status, "error");
        assert_eq!(strict_posture.admin_checks()[2].status, "ok");
        assert_eq!(
            BootPosture::bare().mode,
            EnforcementMode::FailClosedReleaseNPlus1
        );
    }

    fn clean_roles() -> Vec<RolePosture> {
        vec![
            RolePosture {
                name: "setjoin_app".to_owned(),
                exists: true,
                rolcanlogin: true,
                rolsuper: false,
                rolbypassrls: false,
                rolcreatedb: false,
                rolcreaterole: false,
                has_password: Some(true),
                attributes_ok: true,
            },
            RolePosture {
                name: "setjoin_owner".to_owned(),
                exists: true,
                rolcanlogin: false,
                rolsuper: false,
                rolbypassrls: false,
                rolcreatedb: false,
                rolcreaterole: false,
                has_password: Some(false),
                attributes_ok: true,
            },
            RolePosture {
                name: "setjoin_updater".to_owned(),
                exists: true,
                rolcanlogin: true,
                rolsuper: false,
                rolbypassrls: false,
                rolcreatedb: false,
                rolcreaterole: false,
                has_password: Some(true),
                attributes_ok: true,
            },
            RolePosture {
                name: "setjoin_worker".to_owned(),
                exists: true,
                rolcanlogin: true,
                rolsuper: false,
                rolbypassrls: true,
                rolcreatedb: false,
                rolcreaterole: false,
                has_password: Some(true),
                attributes_ok: true,
            },
        ]
    }

    #[test]
    fn fail_closed_catches_missing_username_shared_dsn_and_respects_context_policy() {
        // 1. RuntimeApp with username-less DB_DSN and DB_WORKER_DSN naming the same role:
        //    must fall back to current_role.name and reject shared app/worker role.
        let dsn_roles = DsnRoleSummary::from_dsns(
            Some("postgres:///mailserver?host=/var/run/postgresql"),
            Some("postgres://setjoin_app:pw@127.0.0.1:5432/mailserver"),
            None,
        );
        let mut report = RlsPreflightReport {
            context: PostureContext::RuntimeApp,
            server_version_num: 170012,
            server_version: "17.12".to_owned(),
            pg_version_ok: true,
            current_role: CurrentRolePosture {
                name: "setjoin_app".to_owned(),
                rolsuper: false,
                rolbypassrls: false,
                rolcreaterole: false,
            },
            roles: clean_roles(),
            owner_has_worker_membership: true,
            owns_forced_rls_tables: Vec::new(),
            app_owns_forced_rls_tables: Vec::new(),
            policy_tables_rls_disabled: Vec::new(),
            scope_helpers_drifted: Vec::new(),
            other_secdef_drifted: Vec::new(),
            dsn_roles: Some(dsn_roles),
            hard_errors: Vec::new(),
            warnings: Vec::new(),
        };
        report.evaluate_findings();
        let errors = report.fail_closed_errors(false);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("DB_DSN and DB_WORKER_DSN share role")),
            "{errors:?}"
        );
        let posture =
            BootPosture::from_report(report.clone(), EnforcementMode::FailClosedReleaseNPlus1);
        assert_eq!(posture.public_status(), "error");
        assert_eq!(posture.admin_checks()[0].status, "error");

        // 2. RuntimeApp with BOTH DB_DSN and DB_WORKER_DSN omitting username:
        //    still caught as shared role!
        report.dsn_roles = Some(DsnRoleSummary::from_dsns(
            Some("postgres:///mailserver?host=/var/run/postgresql"),
            Some("postgres:///mailserver?host=/var/run/postgresql"),
            None,
        ));
        report.evaluate_findings();
        assert!(report
            .fail_closed_errors(false)
            .iter()
            .any(|e| e.contains("DB_DSN and DB_WORKER_DSN share role")));

        // 3. Synthetic non-privileged test role in RuntimeApp with distinct worker role:
        //    allowed in RuntimeApp, rejected only in OperatorOwner.
        report.current_role.name = "synthetic_app".to_owned();
        report.dsn_roles = Some(DsnRoleSummary::from_dsns(
            Some("postgres://synthetic_app:pw@127.0.0.1:5432/mailserver"),
            Some("postgres://setjoin_worker:pw@127.0.0.1:5432/mailserver"),
            None,
        ));
        report.evaluate_findings();
        assert!(
            report.fail_closed_errors(false).is_empty(),
            "{:?}",
            report.fail_closed_errors(false)
        );
        let ok_posture =
            BootPosture::from_report(report.clone(), EnforcementMode::FailClosedReleaseNPlus1);
        assert_eq!(ok_posture.public_status(), "ok");

        report.context = PostureContext::OperatorOwner;
        report.evaluate_findings();
        assert!(report
            .fail_closed_errors(false)
            .iter()
            .any(|e| e.contains("expected 'setjoin_app'")));

        // 4. Updater allow_unreadable_config_env=true skips ONLY EACCES notice,
        //    while still failing closed on DB-side findings (e.g. PG version).
        let unreadable = DsnRoleSummary {
            config_env_unreadable: true,
            ..Default::default()
        };
        report.dsn_roles = Some(unreadable);
        report.evaluate_findings();
        assert_eq!(report.fail_closed_errors(false).len(), 1);
        assert!(report.fail_closed_errors(true).is_empty());

        report.pg_version_ok = false;
        report.evaluate_findings();
        assert_eq!(report.fail_closed_errors(true).len(), 1);
    }
}
