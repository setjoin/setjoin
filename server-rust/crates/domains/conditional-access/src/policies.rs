//! Conditional access (F03) slice `policies`: the policy lifecycle routes. Reads repeat Go's
//! queries; every write calls the reducer Go calls, inside one receipted command. Create and
//! update go through `rust_ca_policy_save` (Go's upsert plus optional `set_session_control`
//! transaction); the other writes call `ca_policy_soft_delete|restore|restore_from_audit|
//! reorder|promote` unchanged (they already commit data, audit and the single
//! `ca_notify_policy_change` together). A reducer `BZ0xx` exception rolls the command back
//! and is projected by [`project`] like Go's `caErrorStatus`/`caErrorDetail`.
use super::{deadline, done, envelope, invalid, s};
use setjoin_authz::AuthContext;
use setjoin_pg::{
    CommandOutcome, ReceiptCommand, Rejection, ScopedExecutor, StatementFailure, Type,
};

/// One refusal as Go's `httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projected {
    pub status: u16,
    pub detail: String,
}

/// Go's `caErrorStatus`/`caErrorDetail` over a database failure: a CHECK violation (23514)
/// is a 400 carrying the HINT (else the message); a classified CA reducer code carries the
/// status of its reducer class and the HINT (else the message); anything else is a 500
/// with the fixed `request failed`.
pub fn project(error: &StatementFailure) -> Projected {
    let text = |hint: &Option<String>| match hint {
        Some(h) if !h.is_empty() => h.clone(),
        _ => error.message.clone(),
    };
    let code = error.sqlstate.as_deref().unwrap_or("");
    if code == "23514" {
        return Projected {
            status: 400,
            detail: text(&error.hint),
        };
    }
    let status = match code {
        // ClassConflict: lockout guard, restore priority clash, location name clash,
        // device state conflict.
        "BZ080" | "BZ087" | "BZ093" | "BZ095" => 409,
        // ClassNotFound: CA entity, restore audit row, import slug.
        "BZ081" | "BZ086" | "BZ091" => 404,
        // ClassInvalidArguments: empty break-glass, template slug, built-in strength,
        // revocation scope, session-control arguments.
        "BZ082" | "BZ085" | "BZ094" | "BZ097" | "BZ098" => 400,
        // ClassUnprocessable: import schema version, shape, mode.
        "BZ088" | "BZ090" | "BZ092" => 422,
        _ => {
            return Projected {
                status: 500,
                detail: "request failed".into(),
            }
        }
    };
    Projected {
        status,
        detail: text(&error.hint),
    }
}

/// The projection of a rejected command or read, `None` for a failure with no database error.
pub fn project_rejection(error: &Rejection<StatementFailure>) -> Projected {
    match error {
        Rejection::Statement(e) | Rejection::Body(e) => project(e),
        _ => Projected {
            status: 500,
            detail: "request failed".into(),
        },
    }
}

/// Whitespace outside strings removed: `json.Marshal` of a `RawMessage` compacts it.
pub fn compact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let (mut quoted, mut escaped) = (false, false);
    for c in text.chars() {
        if quoted {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
        } else if c == '"' {
            quoted = true;
            out.push(c);
        } else if !c.is_ascii_whitespace() {
            out.push(c);
        }
    }
    out
}

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: super::FAMILY,
        command: name,
    }
}

/// Owner-approved security fix 2026-11-05 (#467): a domain-scoped admin reaches only the
/// policies scoped to users it reaches; organization-wide policies (global, role, guests)
/// need an organization-wide `access.policy_*` grant, which is checked in the same SQL
/// statement as every read or write (`rust_ca_policy_*_reach`, mailserver/sql/reducers).
pub(crate) const READ_PERMS: &str = "'{access.policy_read,access.policy_write}'::text[]";
const WRITE_PERMS: &str = "'{access.policy_write}'::text[]";

/// Test-only: restores frozen Go's missing tenant filter (feature `oracle-mutants`).
pub(crate) fn open() -> &'static str {
    if setjoin_contracts::mutants::on("ca-policy-foreign") {
        "true"
    } else {
        "false"
    }
}

/// Test-only: restores the missing priority floor (a scoped admin ahead of org-wide policies).
fn ahead() -> &'static str {
    if setjoin_contracts::mutants::on("ca-priority-ahead") {
        "true"
    } else {
        "false"
    }
}

/// Owner decision 2026-11-06 (#467, #510): whether the caller may give a policy `priority` (or
/// rebuild the `audit` snapshot's priority). A domain-limited admin's policies must come after
/// every policy outside its reach; org-wide admins are unchanged. The statements repeat it.
pub async fn priority_allowed(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    priority: Option<i64>,
    audit: Option<i64>,
) -> Result<bool, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read(
            &format!(
                "SELECT {ahead} OR (rust_ca_priority_ok($1, $2, {WRITE_PERMS}) \
                 AND COALESCE(rust_ca_audit_priority_ok($1, $3, {WRITE_PERMS}), true))",
                ahead = ahead()
            ),
            &[(&user, Type::INT8), (&priority, Type::INT8), (&audit, Type::INT8)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// The refusal of an unreachable policy or scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Allowed,
    /// The stored policy is outside the caller's reach: indistinguishable from missing.
    NotFound,
    /// The policy about to be written is scoped outside the caller's reach.
    Forbidden,
}

/// Read-side check run before a mutation to choose 404 or 403; the mutation repeats the same
/// predicate inside its own statement, so a grant revoked in between cannot slip through.
pub async fn gate(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: Option<i64>,
    audit: Option<i64>,
    scope: Option<(&str, &str)>,
    read: bool,
) -> Result<Gate, StatementFailure> {
    let user = actor.user_id();
    let perms = if read { READ_PERMS } else { WRITE_PERMS };
    let (scope_type, scope_target) = scope.map_or((None, None), |(a, b)| (Some(a), Some(b)));
    let rows = exec
        .read(
            &format!(
                "SELECT CASE WHEN {open} THEN 'ok' \
                 WHEN $2::bigint IS NOT NULL AND (rust_ca_policy_row_reach($1, $2, {perms}) IS FALSE \
                      OR (rust_ca_policy_row_reach($1, $2, {perms}) IS NULL AND NOT admin_org_wide_grant($1, {perms}))) THEN 'row' \
                 WHEN $3::bigint IS NOT NULL AND rust_ca_policy_audit_reach($1, $3, {perms}) IS NOT DISTINCT FROM false THEN 'row' \
                 WHEN $4::text IS NOT NULL AND NOT rust_ca_policy_scope_reach($1, $4, $5, {perms}) THEN 'scope' \
                 ELSE 'ok' END",
                open = open()
            ),
            &[
                (&user, Type::INT8),
                (&id, Type::INT8),
                (&audit, Type::INT8),
                (&scope_type, Type::TEXT),
                (&scope_target, Type::TEXT),
            ],
        )
        .await?;
    match rows.first().and_then(|r| r.try_get::<_, String>(0).ok()).as_deref() {
        Some("ok") => Ok(Gate::Allowed),
        Some("row") => Ok(Gate::NotFound),
        Some("scope") => Ok(Gate::Forbidden),
        _ => Err(invalid()),
    }
}

/// The 404 Go's reducers give a missing policy (BZ081), reused for an unreachable one.
pub fn not_found() -> Projected {
    Projected {
        status: 404,
        detail: "no conditional_access_policy row with the given id".into(),
    }
}

/// Whether the caller reaches `user` for the policy-console reads: an organization-wide
/// `access.policy_*` grant, or reach through a grant that carries one of those permissions
/// (permission-aware `admin_can_reach_perm`, not any grant). Owner-approved security fix
/// 2026-11-05 (#467, #510).
pub async fn user_in_reach(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    user: i64,
) -> Result<bool, StatementFailure> {
    if setjoin_contracts::mutants::on("ca-policy-foreign") {
        return Ok(true);
    }
    let admin = actor.user_id();
    let rows = exec
        .read(
            &format!("SELECT admin_org_wide_grant($1, {READ_PERMS}) OR admin_can_reach_perm($1, $2, {READ_PERMS})"),
            &[(&admin, Type::INT8), (&user, Type::INT8)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// Whether the caller holds `access.policy_write` (or, for `read`, `access.policy_read`)
/// organization-wide; the bulk routes (export, import, diff, template instantiate) touch
/// every policy and need it.
pub async fn org_wide(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    read: bool,
) -> Result<bool, StatementFailure> {
    if setjoin_contracts::mutants::on("ca-policy-foreign") {
        return Ok(true);
    }
    let user = actor.user_id();
    let perms = if read { READ_PERMS } else { WRITE_PERMS };
    let rows = exec
        .read(
            &format!("SELECT admin_org_wide_grant($1, {perms})"),
            &[(&user, Type::INT8)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// `GET /admin/conditional-access/policies`: live policies by priority, tombstones too with
/// `?include_deleted=1`. A row that fails to scan is skipped by Go (none can here). Only the
/// policies in the caller's reach are listed.
pub async fn list(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    include_deleted: bool,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let sql = format!(
        "SELECT id, priority, name, description, state, scope_type, scope_target, \
         conditions::text, actions::text, exclude_users::text, exclude_groups::text, \
         session_control::text, created_at::text, updated_at::text, deleted_at::text \
         FROM conditional_access_policies WHERE ({open} OR rust_ca_policy_scope_reach($1, scope_type, scope_target, {READ_PERMS})){} \
         ORDER BY priority ASC",
        if include_deleted {
            ""
        } else {
            " AND deleted_at IS NULL"
        },
        open = open()
    );
    let rows = exec.read(&sql, &[(&user, Type::INT8)]).await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for r in &rows {
        let raw = |index: usize| -> Result<String, StatementFailure> {
            Ok(compact(&r.try_get::<_, String>(index).map_err(bad)?))
        };
        let deleted: Option<String> = r.try_get(14).map_err(bad)?;
        out.push(format!(
            "{{\"id\":{},\"priority\":{},\"name\":{},\"description\":{},\"state\":{},\"scope_type\":{},\"scope_target\":{},\"conditions\":{},\"actions\":{},\"exclude_users\":{},\"exclude_groups\":{},\"session_control\":{},\"created_at\":{},\"updated_at\":{},\"deleted_at\":{}}}",
            r.try_get::<_, i64>(0).map_err(bad)?,
            r.try_get::<_, i32>(1).map_err(bad)?,
            s(&r.try_get::<_, String>(2).map_err(bad)?),
            s(&r.try_get::<_, String>(3).map_err(bad)?),
            s(&r.try_get::<_, String>(4).map_err(bad)?),
            s(&r.try_get::<_, String>(5).map_err(bad)?),
            s(&r.try_get::<_, String>(6).map_err(bad)?),
            raw(7)?,
            raw(8)?,
            raw(9)?,
            raw(10)?,
            raw(11)?,
            s(&r.try_get::<_, String>(12).map_err(bad)?),
            s(&r.try_get::<_, String>(13).map_err(bad)?),
            deleted.map(|d| s(&d)).unwrap_or_else(|| "null".into()),
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// The create/update request after Go's decoding: `name` and the raw documents are the
/// request's own text, never an identity field.
pub struct Policy<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub state: &'a str,
    pub scope_type: &'a str,
    pub scope_target: &'a str,
    pub priority: Option<i64>,
    /// Raw JSON texts (`json.RawMessage`), `None` when the field was absent.
    pub conditions: Option<&'a str>,
    pub actions: Option<&'a str>,
    pub exclude_users: Option<&'a str>,
    pub exclude_groups: Option<&'a str>,
    pub session_control: Option<&'a str>,
}

const DEFAULT_ACTIONS: &str = r#"{"action":"allow"}"#;

fn first_non_empty<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.is_empty() {
        default
    } else {
        value
    }
}

impl Policy<'_> {
    /// Go's `buildPolicyJSON`: `json.Marshal` of a map, so keys are sorted and the
    /// raw documents are compacted. `state` defaults to `off`, never `enabled`.
    fn document(&self) -> String {
        let raw = |value: Option<&str>, default: &str| compact(value.unwrap_or(default));
        let priority = self
            .priority
            .map(|p| format!("\"priority\":{p},"))
            .unwrap_or_default();
        format!(
            "{{\"actions\":{},\"conditions\":{},\"description\":{},\"exclude_groups\":{},\"exclude_users\":{},\"name\":{},{priority}\"scope_target\":{},\"scope_type\":{},\"state\":{}}}",
            raw(self.actions, DEFAULT_ACTIONS),
            raw(self.conditions, "{}"),
            s(self.description),
            raw(self.exclude_groups, "[]"),
            raw(self.exclude_users, "[]"),
            s(self.name),
            s(self.scope_target),
            s(first_non_empty(self.scope_type, "global")),
            s(first_non_empty(self.state, "off")),
        )
    }
}

/// `POST|PUT /admin/conditional-access/policies[/{id}]`: the reducer's persisted row, jsonb
/// text verbatim (no newline).
pub async fn save(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    id: Option<i64>,
    policy: &Policy<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = super::scope(actor);
    let document = policy.document();
    let actions = compact(policy.actions.unwrap_or(DEFAULT_ACTIONS));
    let session = policy.session_control.map(compact);
    let scope_type = first_non_empty(policy.scope_type, "global");
    setjoin_pg::run_receipted_command(
        exec,
        command(if id.is_some() {
            "ca_policy_update"
        } else {
            "ca_policy_create"
        }),
        &envelope(
            &auth,
            operation,
            &format!("{id:?}:{ip}:{document}:{actions}:{session:?}"),
        ),
        &auth,
        deadline(),
        &format!(
            "SELECT rust_ca_policy_save($2,$4::text::inet,$5,$6::text::jsonb,$7::text::jsonb,$8::text::jsonb)::text \
             WHERE $1::bigint > 0 AND $3::text <> '' \
             AND ({open} OR (rust_ca_policy_scope_reach($2, $9, $10, {WRITE_PERMS}) \
                  AND COALESCE(rust_ca_policy_row_reach($2, $5, {WRITE_PERMS}), true))) \
             AND ({ahead} OR rust_ca_priority_ok($2, $11, {WRITE_PERMS}))",
            open = open(),
            ahead = ahead()
        ),
        &[
            (&ip, Type::TEXT),
            (&id, Type::INT8),
            (&document, Type::TEXT),
            (&actions, Type::TEXT),
            (&session, Type::TEXT),
            (&scope_type, Type::TEXT),
            (&policy.scope_target, Type::TEXT),
            (&policy.priority, Type::INT8),
        ],
        |rows| match rows {
            [row] => row.try_get::<_, String>(0).map_err(|_| invalid()),
            _ => Err(invalid()),
        },
    )
    .await
}

/// `DELETE .../policies/{id}` (soft delete) and `POST .../policies/{id}/restore`: Go calls
/// the reducer and answers 204.
pub async fn soft_delete(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    policy: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("ca_policy_soft_delete"),
        &envelope(&auth, operation, &policy.to_string()),
        &auth,
        deadline(),
        &format!(
            "SELECT count(*)::bigint FROM (SELECT ca_policy_soft_delete($4,$2) \
             WHERE $1::bigint > 0 AND $3::text <> '' \
             AND ({open} OR COALESCE(rust_ca_policy_row_reach($2, $4, {WRITE_PERMS}), true))) w",
            open = open()
        ),
        &[(&policy, Type::INT8)],
        count,
    )
    .await
}

pub async fn restore(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    policy: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("ca_policy_restore"),
        &envelope(&auth, operation, &policy.to_string()),
        &auth,
        deadline(),
        &format!(
            "SELECT count(*)::bigint FROM (SELECT ca_policy_restore($4,$2) \
             WHERE $1::bigint > 0 AND $3::text <> '' \
             AND ({open} OR COALESCE(rust_ca_policy_row_reach($2, $4, {WRITE_PERMS}), true))) w",
            open = open()
        ),
        &[(&policy, Type::INT8)],
        count,
    )
    .await
}

fn count(rows: &[setjoin_pg::Row]) -> Result<(), StatementFailure> {
    match rows {
        [row] if row.try_get::<_, i64>(0).is_ok_and(|n| n == 1) => Ok(()),
        _ => Err(invalid()),
    }
}

/// `POST .../policies/restore-from-audit`: the rebuilt policy's new id.
pub async fn restore_from_audit(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    audit: i64,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("ca_policy_restore_from_audit"),
        &envelope(&auth, operation, &audit.to_string()),
        &auth,
        deadline(),
        &format!(
            "SELECT ca_policy_restore_from_audit($4,$2) WHERE $1::bigint > 0 AND $3::text <> '' \
             AND ({open} OR COALESCE(rust_ca_policy_audit_reach($2, $4, {WRITE_PERMS}), true)) \
             AND ({ahead} OR COALESCE(rust_ca_audit_priority_ok($2, $4, {WRITE_PERMS}), true))",
            open = open(),
            ahead = ahead()
        ),
        &[(&audit, Type::INT8)],
        |rows| match rows {
            [row] => row.try_get::<_, i64>(0).map_err(|_| invalid()),
            _ => Err(invalid()),
        },
    )
    .await
}

/// `POST .../policies/reorder`: priorities restepped by ten in the supplied order.
pub async fn reorder(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    ids: &Vec<i64>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("ca_policy_reorder"),
        &envelope(&auth, operation, &format!("{ip}:{ids:?}")),
        &auth,
        deadline(),
        &format!(
            "SELECT count(*)::bigint FROM (SELECT {reorder}($2,$4::text::inet,$5) \
             WHERE $1::bigint > 0 AND $3::text <> '' \
             AND ({open} OR NOT EXISTS (SELECT 1 FROM unnest($5::bigint[]) i \
                  WHERE rust_ca_policy_row_reach($2, i, {WRITE_PERMS}) IS NOT DISTINCT FROM false))) w",
            open = open(),
            // A scoped admin's reorder is restepped from the priority floor (behind org-wide policies).
            reorder = if setjoin_contracts::mutants::on("ca-priority-ahead") {
                "ca_policy_reorder"
            } else {
                "rust_ca_policy_reorder"
            }
        ),
        &[(&ip, Type::TEXT), (ids, Type::INT8_ARRAY)],
        count,
    )
    .await
}

/// `ca_policy_impact(id, '7d', list)` as jsonb text; the reducer is STABLE and read-only.
/// `list` is `None` for the summary, `Some("blocked_users")` for the list.
pub async fn impact(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    policy: i64,
    list: Option<&str>,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read(
            &format!(
                "SELECT ca_policy_impact($1, '7d', $2::text)::text \
                 WHERE {open} OR COALESCE(rust_ca_policy_row_reach($3, $1, {READ_PERMS}), true)",
                open = open()
            ),
            &[(&policy, Type::INT8), (&list, Type::TEXT), (&user, Type::INT8)],
        )
        .await?;
    match rows.as_slice() {
        [row] => row.try_get::<_, String>(0).map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

/// `ca_policy_promote`: the promoted policy's jsonb text, verbatim.
pub async fn promote(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    policy: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("ca_policy_promote"),
        &envelope(&auth, operation, &policy.to_string()),
        &auth,
        deadline(),
        &format!(
            "SELECT ca_policy_promote($4,$2)::text WHERE $1::bigint > 0 AND $3::text <> '' \
             AND ({open} OR COALESCE(rust_ca_policy_row_reach($2, $4, {WRITE_PERMS}), true))",
            open = open()
        ),
        &[(&policy, Type::INT8)],
        |rows| match rows {
            [row] => row.try_get::<_, String>(0).map_err(|_| invalid()),
            _ => Err(invalid()),
        },
    )
    .await
}

/// The promote dialog's blast-radius body (Go's `promotePreviewResponse`): `blocked` and
/// `admins` are the impact list's `users` and `admin_users` arrays, rendered field for field.
pub struct Preview {
    pub would_block_users: i64,
    pub would_block_admins: i64,
    pub self_locked_out: bool,
    pub blocked: Vec<(i64, String, bool)>,
    pub admins: Vec<(i64, String)>,
    pub shown: i64,
    pub total: i64,
    pub window: String,
}

impl Preview {
    pub fn zeroed(window: String) -> Self {
        Self {
            would_block_users: 0,
            would_block_admins: 0,
            self_locked_out: false,
            blocked: Vec::new(),
            admins: Vec::new(),
            shown: 0,
            total: 0,
            window,
        }
    }
    pub fn render(&self) -> String {
        let blocked: Vec<String> = self
            .blocked
            .iter()
            .map(|(id, address, admin)| {
                format!(
                    "{{\"id\":{id},\"address\":{},\"is_admin\":{admin}}}",
                    s(address)
                )
            })
            .collect();
        let admins: Vec<String> = self
            .admins
            .iter()
            .map(|(id, address)| format!("{{\"id\":{id},\"address\":{}}}", s(address)))
            .collect();
        done(format!(
            "{{\"would_block_users\":{},\"would_block_admins\":{},\"self_locked_out\":{},\"blocked_users\":[{}],\"admin_users\":[{}],\"shown\":{},\"total\":{},\"window\":{}}}",
            self.would_block_users,
            self.would_block_admins,
            self.self_locked_out,
            blocked.join(","),
            admins.join(","),
            self.shown,
            self.total,
            s(&self.window),
        ))
    }
}

/// The impact summary fields the promote handler reads (`json.Unmarshal` into int64/string:
/// a missing key stays zero, a wrong type is Go's 500 "impact read failed").
pub fn parse_summary(text: &str) -> Option<(i64, i64, String)> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;
    let int = |key: &str| match object.get(key) {
        None | Some(serde_json::Value::Null) => Some(0),
        Some(v) => v.as_i64(),
    };
    let window = match object.get("window") {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::String(w)) => w.clone(),
        Some(_) => return None,
    };
    Some((int("would_block")?, int("would_block_admins")?, window))
}

/// The impact list (`blocked_users`) the promote handler reads.
pub fn parse_list(text: &str) -> Option<Preview> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;
    let int = |key: &str| match object.get(key) {
        None | Some(serde_json::Value::Null) => Some(0),
        Some(v) => v.as_i64(),
    };
    let address = |v: &serde_json::Value| match v.get("address") {
        None | Some(serde_json::Value::Null) => Some(String::new()),
        Some(serde_json::Value::String(a)) => Some(a.clone()),
        Some(_) => None,
    };
    let id = |v: &serde_json::Value| match v.get("id") {
        None | Some(serde_json::Value::Null) => Some(0),
        Some(i) => i.as_i64(),
    };
    let mut preview = Preview::zeroed(String::new());
    for user in object
        .get("users")
        .and_then(|u| u.as_array())
        .into_iter()
        .flatten()
    {
        let admin = match user.get("is_admin") {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::Bool(b)) => *b,
            Some(_) => return None,
        };
        preview.blocked.push((id(user)?, address(user)?, admin));
    }
    for user in object
        .get("admin_users")
        .and_then(|u| u.as_array())
        .into_iter()
        .flatten()
    {
        preview.admins.push((id(user)?, address(user)?));
    }
    preview.shown = int("shown")?;
    preview.total = int("total")?;
    Some(preview)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(code: &str, hint: Option<&str>, message: &str) -> StatementFailure {
        StatementFailure {
            sqlstate: Some(code.into()),
            hint: hint.map(Into::into),
            message: message.into(),
        }
    }

    #[test]
    fn reducer_codes_project_like_go() {
        for (code, status) in [
            ("BZ080", 409),
            ("BZ081", 404),
            ("BZ086", 404),
            ("BZ087", 409),
            ("BZ098", 400),
            ("23514", 400),
        ] {
            assert_eq!(
                project(&failure(code, Some("do this"), "msg")).status,
                status
            );
        }
        assert_eq!(
            project(&failure("BZ087", Some("do this"), "msg")).detail,
            "do this"
        );
        assert_eq!(project(&failure("BZ087", None, "msg")).detail, "msg");
        assert_eq!(project(&failure("BZ087", Some(""), "msg")).detail, "msg");
        let other = project(&failure("22003", None, "integer out of range"));
        assert_eq!(
            (other.status, other.detail.as_str()),
            (500, "request failed")
        );
    }

    #[test]
    fn document_is_go_marshal_of_the_map() {
        let policy = Policy {
            name: "n<&>",
            description: "",
            state: "",
            scope_type: "",
            scope_target: "",
            priority: Some(5),
            conditions: Some("{ \"a\": 1 }"),
            actions: None,
            exclude_users: None,
            exclude_groups: Some("[1, 2]"),
            session_control: None,
        };
        assert_eq!(
            policy.document(),
            "{\"actions\":{\"action\":\"allow\"},\"conditions\":{\"a\":1},\"description\":\"\",\"exclude_groups\":[1,2],\"exclude_users\":[],\"name\":\"n<&>\",\"priority\":5,\"scope_target\":\"\",\"scope_type\":\"global\",\"state\":\"off\"}"
        );
    }

    #[test]
    fn summary_and_list_parse_like_go() {
        assert_eq!(
            parse_summary(r#"{"window":"7d","would_block":3,"would_block_admins":1}"#),
            Some((3, 1, "7d".into()))
        );
        assert_eq!(parse_summary(r#"{"would_block":"x"}"#), None);
        let list = parse_list(
            r#"{"users":[{"id":4,"address":"a@x","is_admin":true}],"shown":1,"total":1,"admin_users":[{"id":4,"address":"a@x"}]}"#,
        )
        .unwrap();
        assert_eq!(list.blocked, vec![(4, "a@x".to_string(), true)]);
        assert_eq!(list.admins, vec![(4, "a@x".to_string())]);
        assert_eq!((list.shown, list.total), (1, 1));
    }
}
