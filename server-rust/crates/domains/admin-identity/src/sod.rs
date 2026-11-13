//! Admin identity (F01) slice `sod`: just-in-time role activation and the
//! activation policy.
//!
//! Go calls the existing reducers (`admin_role_activate`, `admin_role_deactivate`)
//! straight from the handler, so Rust calls the same reducers: the effects are
//! identical by construction. The policy write is Go's single `INSERT .. ON
//! CONFLICT` with no audit, state bump or notify, so it stays one Rust statement.
//! The actor of every self-service command is the verified token's user, never a
//! request field. Each command and its commit receipt share one transaction.
use super::{deadline, done, envelope, invalid, nano, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ReceiptCommand, ScopedExecutor, StatementFailure, Type};

/// `roles.manage`: the gate of the two policy routes (Go's `requireRolesManage`).
pub use crate::roles::ROLES_MANAGE;

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: "F01",
        command: name,
    }
}

/// `GET /admin/me/roles`: every assignment of the caller, with the resolved policy.
/// Go lists them all (eligible, dormant and expired) on purpose; a scan failure is a 500.
pub async fn my_roles(exec: &ScopedExecutor, actor: i64) -> Result<String, StatementFailure> {
    let sql = format!(
        "SELECT ara.role_group_id, rg.name, ara.eligible, {}, {}, \
         COALESCE(arp.max_duration_minutes, \
                  (SELECT (value ->> 0)::int FROM system_config WHERE key = 'jit.default_max_minutes'), 480)::bigint, \
         COALESCE(arp.require_justification, \
                  (SELECT (value ->> 0)::bool FROM system_config WHERE key = 'jit.default_require_justification'), false) \
         FROM admin_role_assignments ara \
         JOIN admin_role_groups rg ON rg.id = ara.role_group_id \
         LEFT JOIN admin_role_activation_policy arp ON arp.role_group_id = ara.role_group_id \
         WHERE ara.user_id = $1 ORDER BY rg.name",
        nano("ara.activated_until"),
        nano("ara.expires_at"),
    );
    let rows = exec.read(&sql, &[(&actor, Type::INT8)]).await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for row in &rows {
        let until = row.try_get::<_, Option<String>>(3).map_err(bad)?;
        let expires = row.try_get::<_, Option<String>>(4).map_err(bad)?;
        out.push(format!(
            "{{\"roleGroupId\":{},\"name\":{},\"eligible\":{}{}{},\"policy\":{{\"maxDurationMinutes\":{},\"requireJustification\":{}}}}}",
            row.try_get::<_, i64>(0).map_err(bad)?,
            s(&row.try_get::<_, String>(1).map_err(bad)?),
            row.try_get::<_, bool>(2).map_err(bad)?,
            until
                .map(|t| format!(",\"activatedUntil\":{}", s(&t)))
                .unwrap_or_default(),
            expires
                .map(|t| format!(",\"expiresAt\":{}", s(&t)))
                .unwrap_or_default(),
            row.try_get::<_, i64>(5).map_err(bad)?,
            row.try_get::<_, bool>(6).map_err(bad)?,
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// `POST /admin/me/roles/{id}/activate`: Go's `activatedUntil`. The reducer answers
/// NULL when it parked an approval request. Go's handler then cannot scan the NULL
/// and, running its pool unscoped, never gets the request past the row-level
/// security of `approval_requests` either, so the observed outcome is a 500 with
/// nothing committed. Here the NULL rolls the whole command back: the same 500,
/// no parked request, no audit row (see `activate-approval` golden).
pub async fn activate(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    role: i64,
    minutes: i32,
    justification: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    let sql = format!(
        "SELECT {} FROM (SELECT admin_role_activate($2, $4, $5, $6) AS u WHERE $1::bigint > 0 AND $3::text <> '') r",
        nano("r.u")
    );
    setjoin_pg::run_receipted_command(
        exec,
        command("jit_activate"),
        &envelope(
            &auth,
            operation,
            &format!("{role}:{minutes}:{justification:?}"),
        ),
        &auth,
        deadline(),
        &sql,
        &[
            (&role, Type::INT8),
            (&minutes, Type::INT4),
            (&justification, Type::TEXT),
        ],
        |rows| match rows {
            [row] => row
                .try_get::<_, Option<String>>(0)
                .map_err(|_| invalid())?
                .ok_or(StatementFailure {
                    sqlstate: Some("42501".into()),
                    hint: None,
                    message: "approval-gated activation is refused as in Go".into(),
                }),
            _ => Err(invalid()),
        },
    )
    .await
}

/// `POST /admin/me/roles/{id}/deactivate`: ends the caller's own window. A caller
/// with no eligible assignment changes nothing and still succeeds, as in Go.
pub async fn deactivate(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    role: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("jit_deactivate"),
        &envelope(&auth, operation, &role.to_string()),
        &auth,
        deadline(),
        "SELECT count(*)::bigint FROM (SELECT admin_role_deactivate($2, $4) WHERE $1::bigint > 0 AND $3::text <> '') r",
        &[(&role, Type::INT8)],
        |rows| if rows.len() == 1 { Ok(()) } else { Err(invalid()) },
    )
    .await
}

/// SQL predicate on role `$role` for actor `$actor`: owner-approved security fix 2026-11-05
/// (#393, #510). A caller whose live `roles.manage` grants include an organization-wide one is
/// unrestricted; otherwise it reads and writes the activation policy only of roles owned by the
/// narrowest domain of its `roles.manage` grants (a global role or another domain's role is
/// refused, and so is a caller with no domain-scoped grant: an OU/set-confined holder of a
/// domain-less role group). The role's domain comes from its row, never the request.
fn role_guard(actor: &str, role: &str) -> String {
    if setjoin_contracts::mutants::on("jit-policy-foreign-role") {
        return "true".into();
    }
    format!(
        "(admin_domain_restriction({actor}, '{{roles.manage}}'::text[]) = 0 OR EXISTS (SELECT 1 FROM admin_role_groups g \
         WHERE g.id = {role} AND g.domain_scope = admin_domain_restriction({actor}, '{{roles.manage}}'::text[])))"
    )
}

/// Whether the caller may touch the role's activation policy (see [`role_guard`]).
pub async fn role_in_scope(exec: &ScopedExecutor, actor: &AuthContext, role: i64) -> bool {
    let user = actor.user_id();
    exec.read(
        &format!("SELECT {}", role_guard("$1", "$2")),
        &[(&user, Type::INT8), (&role, Type::INT8)],
    )
    .await
    .ok()
    .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
    .unwrap_or(false)
}

/// `GET /admin/roles/{id}/activation-policy`: the role's override, else the global
/// defaults (also for a role that does not exist, as in Go).
pub async fn policy(exec: &ScopedExecutor, role: i64) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT max_duration_minutes::bigint, require_justification \
             FROM admin_role_activation_policy WHERE role_group_id = $1",
            &[(&role, Type::INT8)],
        )
        .await?;
    let (minutes, justification) = match rows.first() {
        Some(row) => (
            row.try_get::<_, i64>(0).map_err(|_| invalid())?,
            row.try_get::<_, bool>(1).map_err(|_| invalid())?,
        ),
        None => {
            let rows = exec
                .read(
                    "SELECT COALESCE((SELECT (value->>0)::int FROM system_config WHERE key='jit.default_max_minutes'), 480)::bigint, \
                     COALESCE((SELECT (value->>0)::bool FROM system_config WHERE key='jit.default_require_justification'), false)",
                    &[],
                )
                .await?;
            let row = rows.first().ok_or_else(invalid)?;
            (
                row.try_get::<_, i64>(0).map_err(|_| invalid())?,
                row.try_get::<_, bool>(1).map_err(|_| invalid())?,
            )
        }
    };
    Ok(render_policy(role, minutes, justification))
}

fn render_policy(role: i64, minutes: i64, justification: bool) -> String {
    done(format!(
        "{{\"roleGroupId\":{role},\"maxDurationMinutes\":{minutes},\"requireJustification\":{justification}}}"
    ))
}

/// `PUT /admin/roles/{id}/activation-policy` after the edge validation. A role
/// that does not exist violates the foreign key (SQLSTATE 23503, Go's 500).
pub async fn put_policy(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    role: i64,
    minutes: i32,
    require_justification: bool,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("jit_policy_put"),
        &envelope(
            &auth,
            operation,
            &format!("{role}:{minutes}:{require_justification}"),
        ),
        &auth,
        deadline(),
&format!(
            "INSERT INTO admin_role_activation_policy (role_group_id, max_duration_minutes, require_justification) \
             SELECT $4, $5, $6 WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' \
             AND {} \
             ON CONFLICT (role_group_id) DO UPDATE \
             SET max_duration_minutes = EXCLUDED.max_duration_minutes, \
                 require_justification = EXCLUDED.require_justification \
             RETURNING role_group_id",
            role_guard("$2", "$4")
        ),
        &[
            (&role, Type::INT8),
            (&minutes, Type::INT4),
            (&require_justification, Type::BOOL),
        ],
        move |rows| {
            if rows.len() == 1 {
                Ok(render_policy(role, i64::from(minutes), require_justification))
            } else {
                Err(invalid())
            }
        },
    )
    .await
}
