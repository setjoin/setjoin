//! Admin identity (F01) slice `sod`: just-in-time role activation and the
//! activation policy.
use super::{deadline, done, envelope, invalid, s, sql, FAMILY};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, ReceiptCommand, StatementFailure};

/// `roles.manage`: the gate of the two policy routes (Go's `requireRolesManage`).
pub use crate::roles::ROLES_MANAGE;

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: FAMILY,
        command: name,
    }
}

/// `GET /admin/me/roles`: every assignment of the caller, with the resolved policy.
pub async fn my_roles(
    factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::MY_ROLES, &[&actor])
        .await?;
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

/// Result of `POST /admin/me/roles/{id}/activate` (#175).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activation {
    /// Immediate activation: the window is open until this RFC 3339 UTC timestamp.
    Active(String),
    /// Approval-gated activation: `admin_role_activate` parked a `rbac.jit_activation`
    /// row in `approval_requests`; the window opens once approved.
    PendingApproval,
}

/// `POST /admin/me/roles/{id}/activate`: opens the window or parks an approval request.
pub async fn activate(
    factory: &TxFactory,
    user: &UserPrincipal,
    role: i64,
    minutes: i32,
    justification: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<Activation, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{role}:{minutes}:{justification:?}"),
    );
    let op_id = env.operation;
    let justification_owned = justification.map(str::to_owned);
    factory
        .run_user_write(user, &env, deadline(), async move |tx| {
            let rows = tx
                .query_contract(
                    &sql::JIT_ACTIVATE,
                    &[&actor, &role, &minutes, &justification_owned],
                )
                .await?;
            let outcome = match rows.as_slice() {
                [row] => match row.try_get::<_, Option<String>>(0).map_err(|_| invalid())? {
                    Some(until) => Activation::Active(until),
                    None => Activation::PendingApproval,
                },
                _ => return Err(invalid()),
            };
            tx.record_receipt(op_id, command("jit_activate")).await?;
            Ok(outcome)
        })
        .await
}

/// `POST /admin/me/roles/{id}/deactivate`: ends the caller's own window.
pub async fn deactivate(
    factory: &TxFactory,
    user: &UserPrincipal,
    role: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    let env = envelope(user.user(), user.generation(), operation, &role.to_string());
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::JIT_DEACTIVATE,
            &[&actor, &role],
            Some(command("jit_deactivate")),
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

/// Whether the caller may touch the role's activation policy (#393, #510).
pub async fn role_in_scope(factory: &TxFactory, admin: &AdminPermissionProof, role: i64) -> bool {
    if setjoin_contracts::mutants::on("jit-policy-foreign-role") {
        return true;
    }
    let user = admin.actor().get();
    factory
        .run_admin_read_contract(admin, &sql::SOD_ROLE_IN_SCOPE, &[&user, &role])
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
        .unwrap_or(false)
}

/// `GET /admin/roles/{id}/activation-policy`: the role's override, else global defaults.
pub async fn policy(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    role: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::SOD_POLICY_GET, &[&role])
        .await?;
    let (minutes, justification) = match rows.first() {
        Some(row) => (
            row.try_get::<_, i64>(0).map_err(|_| invalid())?,
            row.try_get::<_, bool>(1).map_err(|_| invalid())?,
        ),
        None => {
            let rows = factory
                .run_admin_read_contract(admin, &sql::SOD_POLICY_DEFAULTS, &[])
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

/// `PUT /admin/roles/{id}/activation-policy` after the edge validation.
#[allow(clippy::too_many_arguments)]
pub async fn put_policy(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    role: i64,
    minutes: i32,
    require_justification: bool,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{role}:{minutes}:{require_justification}"),
    );
    // Interactive 2-RTT write: foreign roles return 0 rows and must roll back cleanly
    // (1-RTT pipelined writes cannot roll back on post-commit decoder Err).
    let unscoped = setjoin_contracts::mutants::on("jit-policy-foreign-role");
    factory
        .run_user_write(user, &env, deadline(), async move |tx| {
            let rows = if unscoped {
                tx.query_contract(
                    &sql::SOD_POLICY_PUT_UNSCOPED,
                    &[
                        &role as &(dyn setjoin_pg::ToSql + Sync),
                        &minutes,
                        &require_justification,
                    ],
                )
                .await?
            } else {
                tx.query_contract(
                    &sql::SOD_POLICY_PUT,
                    &[
                        &actor as &(dyn setjoin_pg::ToSql + Sync),
                        &role,
                        &minutes,
                        &require_justification,
                    ],
                )
                .await?
            };
            if rows.len() == 1 {
                tx.record_receipt(
                    setjoin_contracts::ids::OperationId(operation),
                    command("jit_policy_put"),
                )
                .await?;
                Ok(render_policy(
                    role,
                    i64::from(minutes),
                    require_justification,
                ))
            } else {
                Err(invalid())
            }
        })
        .await
}
