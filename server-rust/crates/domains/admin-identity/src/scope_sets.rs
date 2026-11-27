//! Admin identity (F01) slice `scope-sets`: named governed scope containers.
use super::{count as _count, deadline, done, envelope, invalid, s, sql, FAMILY};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Rejection, Row, StatementFailure};

/// `scope_sets.manage`: the only gate of every route in this slice.
pub const SCOPE_SETS_MANAGE: [&str; 1] = ["scope_sets.manage"];

/// A refusal decided by a reducer, carried through the executor as a rolled-back body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub status: u16,
    pub detail: String,
}

pub fn problem_of(error: &Rejection<StatementFailure>) -> Option<Problem> {
    let (Rejection::Statement(e) | Rejection::Body(e)) = error else {
        return None;
    };
    if e.sqlstate.is_some() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&e.message).ok()?;
    Some(Problem {
        status: v["status"].as_u64()? as u16,
        detail: v["detail"].as_str()?.to_owned(),
    })
}

/// Go's `%q` for the duplicate-name message: a double-quoted Go string literal.
pub fn go_quote(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            '\u{fffd}' => out.push('\u{fffd}'),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if is_printable(c) => out.push(c),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push('"');
    out
}

fn is_printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    let u = c as u32;
    !matches!(
        u,
        0x80..=0x9f
            | 0xad
            | 0x600..=0x605
            | 0x61c
            | 0x6dd
            | 0x70f
            | 0x8e2
            | 0x180e
            | 0x200b..=0x200f
            | 0x202a..=0x202e
            | 0x2060..=0x206f
            | 0xe000..=0xf8ff
            | 0xfeff
            | 0xfff9..=0xfffb
            | 0xf0000..=0x10ffff
    )
}

fn set_json(row: &Row) -> Result<String, StatementFailure> {
    let bad = |_| invalid();
    let domain = row.try_get::<_, Option<i64>>(2).map_err(bad)?;
    let by = row.try_get::<_, Option<i64>>(4).map_err(bad)?;
    Ok(format!(
        "{{\"id\":{},\"name\":{}{},\"description\":{}{},\"createdAt\":{},\"updatedAt\":{}}}",
        row.try_get::<_, i64>(0).map_err(bad)?,
        s(&row.try_get::<_, String>(1).map_err(bad)?),
        domain
            .map(|d| format!(",\"domainId\":{d}"))
            .unwrap_or_default(),
        s(&row.try_get::<_, String>(3).map_err(bad)?),
        by.map(|d| format!(",\"createdBy\":{d}"))
            .unwrap_or_default(),
        s(&row.try_get::<_, String>(5).map_err(bad)?),
        s(&row.try_get::<_, String>(6).map_err(bad)?),
    ))
}

/// `GET /admin/scope-sets`: a scan failure is Go's 500.
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let user = admin.actor().get();
    let rows = if setjoin_contracts::mutants::on("scopeset-unscoped") {
        factory
            .run_admin_read_contract(admin, &sql::SCOPE_SETS_LIST_UNSCOPED, &[])
            .await?
    } else {
        factory
            .run_admin_read_contract(admin, &sql::SCOPE_SETS_LIST, &[&user])
            .await?
    };
    let out = rows.iter().map(set_json).collect::<Result<Vec<_>, _>>()?;
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/scope-sets/{id}`; `None` is Go's 404.
pub async fn get(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let user = admin.actor().get();
    let rows = if setjoin_contracts::mutants::on("scopeset-unscoped") {
        factory
            .run_admin_read_contract(admin, &sql::SCOPE_SET_GET_UNSCOPED, &[&id])
            .await?
    } else {
        factory
            .run_admin_read_contract(admin, &sql::SCOPE_SET_GET, &[&user, &id])
            .await?
    };
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let set = set_json(row)?;
    let members = factory
        .run_admin_read_contract(admin, &sql::SCOPE_SET_MEMBERS, &[&id])
        .await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for m in &members {
        let by = m.try_get::<_, Option<i64>>(2).map_err(bad)?;
        let label = m.try_get::<_, Option<String>>(4).map_err(bad)?;
        out.push(format!(
            "{{\"memberType\":{},\"memberId\":{}{},\"addedAt\":{}{}}}",
            s(&m.try_get::<_, String>(0).map_err(bad)?),
            m.try_get::<_, i64>(1).map_err(bad)?,
            by.map(|b| format!(",\"addedBy\":{b}")).unwrap_or_default(),
            s(&m.try_get::<_, String>(3).map_err(bad)?),
            label
                .map(|l| format!(",\"label\":{}", s(&l)))
                .unwrap_or_default(),
        ));
    }
    Ok(Some(done(format!(
        "{{\"members\":[{}],\"set\":{set}}}",
        out.join(",")
    ))))
}

/// Go's `RequireReason`: whether `scope_sets` is a reason-required audit area.
pub async fn reason_required(factory: &TxFactory, admin: &AdminPermissionProof) -> bool {
    let area = "scope_sets";
    factory
        .run_admin_read_contract(admin, &sql::REASON_REQUIRED_AREA, &[&area])
        .await
        .ok()
        .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
        .unwrap_or(false)
}

/// The durable `sensitive_action.reason_missing` row Go writes before its 400.
pub async fn missing_reason(
    factory: &TxFactory,
    user: &UserPrincipal,
    ip: &str,
    operation: [u8; 16],
) {
    let actor = user.user().get();
    let perm = "scope_sets.manage";
    let env = envelope(user.user(), user.generation(), operation, ip);
    let _ = factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MISSING_REASON_AUDIT,
            &[&actor, &ip, &perm],
            Some(ReceiptCommand {
                family: FAMILY,
                command: "reason_missing",
            }),
            |rows| _count(&rows).map(|_| ()),
        )
        .await;
}

fn verdict(rows: &[Row], success: &[u64]) -> Result<u16, StatementFailure> {
    let text: String = rows
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| invalid())?;
    match v["status"].as_u64() {
        Some(status) if success.contains(&status) => Ok(status as u16),
        Some(_) if v["detail"].is_string() => Err(StatementFailure {
            sqlstate: None,
            hint: None,
            message: text,
        }),
        _ => Err(invalid()),
    }
}

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: FAMILY,
        command: name,
    }
}

/// `POST /admin/scope-sets` after the edge validation; the new set id.
pub async fn create(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    name: &str,
    domain: Option<i64>,
    description: &str,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{name}:{domain:?}:{description}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::SCOPE_SET_CREATE,
            &[&name, &domain, &description, &ip],
            Some(command("scope_set_create")),
            |rows, _audited| match rows.as_slice() {
                [row] => match row.try_get::<_, Option<i64>>(0).map_err(|_| invalid())? {
                    Some(id) => Ok(id),
                    None => Err(StatementFailure {
                        sqlstate: None,
                        hint: None,
                        message: "{\"status\":403,\"detail\":\"scope set domain is outside your administrative scope\"}".into(),
                    }),
                },
                _ => Err(invalid()),
            },
        )
        .await
}

/// `PUT /admin/scope-sets/{id}`: a missing set is Go's 404.
pub async fn update(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
    name: Option<&str>,
    description: Option<&str>,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{id}:{name:?}:{description:?}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::SCOPE_SET_UPDATE,
            &[&id, &name, &description, &ip],
            Some(command("scope_set_update")),
            |rows, _audited| match rows.as_slice() {
                [row] => {
                    if row.try_get::<_, bool>(0).map_err(|_| invalid())? {
                        Ok(())
                    } else {
                        Err(StatementFailure {
                            sqlstate: None,
                            hint: None,
                            message: "{\"status\":404,\"detail\":\"scope set not found\"}".into(),
                        })
                    }
                }
                _ => Err(invalid()),
            },
        )
        .await
}

pub async fn delete(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &id.to_string(),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::SCOPE_SET_DELETE,
            &[&id, &ip],
            Some(command("scope_set_delete")),
            |rows, _audited| verdict(&rows, &[204]).map(|_| ()),
        )
        .await
}

/// `POST /admin/scope-sets/{id}/members`: 201 added, 200 already a member.
#[allow(clippy::too_many_arguments)]
pub async fn add_member(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    set: i64,
    member_type: &str,
    member: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<u16, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{set}:{member_type}:{member}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::SCOPE_SET_MEMBER_ADD,
            &[&set, &member_type, &member, &ip],
            Some(command("scope_set_member_add")),
            |rows, _audited| verdict(&rows, &[200, 201]),
        )
        .await
}

#[allow(clippy::too_many_arguments)]
pub async fn remove_member(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    set: i64,
    member_type: &str,
    member: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{set}:{member_type}:{member}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::SCOPE_SET_MEMBER_REMOVE,
            &[&set, &member_type, &member, &ip],
            Some(command("scope_set_member_remove")),
            |rows, _audited| verdict(&rows, &[204]).map(|_| ()),
        )
        .await
}
