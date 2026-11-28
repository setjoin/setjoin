//! Frozen template queries; legacy fixtures and missing active tables are both qualified.
use super::{admin_envelope, deadline, done, invalid, project_text0, s, user_envelope};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, StatementFailure};

pub(super) fn raw(text: &str) -> String {
    let (mut out, mut quoted, mut escaped) = (String::new(), false, false);
    for c in text.chars() {
        if quoted {
            out.push(c);
            if escaped {
                escaped = false
            } else if c == '\\' {
                escaped = true
            } else if c == '"' {
                quoted = false
            }
        } else if !matches!(c, ' ' | '\t' | '\r' | '\n') {
            out.push(c);
            if c == '"' {
                quoted = true
            }
        }
    }
    out
}

fn item(r: &Row, detail: bool) -> Result<String, StatementFailure> {
    let enabled = if detail {
        format!(
            ",\"enabled\":{}",
            r.try_get::<_, bool>(9).map_err(|_| invalid())?
        )
    } else {
        String::new()
    };
    let id: i64 = r.try_get(0).map_err(|_| invalid())?;
    Ok(format!(
        "{{\"actions\":{},\"category\":{},\"conditions\":{},\"description\":{}{enabled},\"id\":{id},\"isSystem\":{},\"name\":{},\"parameters\":{},\"sortOrder\":{}}}",
        raw(r.try_get(5).map_err(|_| invalid())?),
        s(r.try_get(3).map_err(|_| invalid())?),
        raw(r.try_get(4).map_err(|_| invalid())?),
        s(r.try_get(2).map_err(|_| invalid())?),
        r.try_get::<_, bool>(7).map_err(|_| invalid())?,
        s(r.try_get(1).map_err(|_| invalid())?),
        raw(r.try_get(6).map_err(|_| invalid())?),
        r.try_get::<_, i32>(8).map_err(|_| invalid())?
    ))
}

pub async fn list(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    admin_view: bool,
) -> Result<String, StatementFailure> {
    let mut tx = tx_factory.begin_user_read(user).await?;
    let rows = if admin_view {
        tx.query_iterated_contract(&crate::sql::TEMPLATE_LIST_ADMIN, &[])
            .await?
    } else {
        let uid = user.user().get();
        tx.query_iterated_contract(&crate::sql::TEMPLATE_LIST_USER, &[&uid])
            .await?
    };
    tx.finish().await?;
    Ok(done(format!(
        "[{}]",
        rows.iter()
            .map_while(|r| item(r, false).ok())
            .collect::<Vec<_>>()
            .join(",")
    )))
}

pub async fn get(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::TEMPLATE_GET, &[&id])
        .await?;
    rows.first().map(|r| item(r, true).map(done)).transpose()
}

pub struct Resolved {
    pub name: String,
    pub category: String,
    pub conditions: String,
    pub actions: String,
    pub parameters: String,
}

fn decode_resolved(rows: &[Row]) -> Result<Option<Resolved>, StatementFailure> {
    let Some(r) = rows.first() else {
        return Ok(None);
    };
    Ok(Some(Resolved {
        name: r.try_get(0).map_err(|_| invalid())?,
        category: r.try_get(1).map_err(|_| invalid())?,
        conditions: r.try_get(2).map_err(|_| invalid())?,
        actions: r.try_get(3).map_err(|_| invalid())?,
        parameters: r.try_get(4).map_err(|_| invalid())?,
    }))
}

pub async fn load(
    tx_factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
) -> Result<Option<Resolved>, StatementFailure> {
    let rows = tx_factory
        .run_admin_read_contract(proof, &crate::sql::TEMPLATE_LOAD, &[&id])
        .await?;
    decode_resolved(&rows)
}

pub async fn resolve(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::TEMPLATE_LOAD_USER, &[&id])
        .await?;
    Ok(decode_resolved(&rows)?.map(|t| {
        done(format!(
            "{{\"actions\":{},\"category\":{},\"conditions\":{},\"id\":{id},\"name\":{},\"parameters\":{}}}",
            raw(&t.actions),
            s(&t.category),
            raw(&t.conditions),
            s(&t.name),
            raw(&t.parameters)
        ))
    }))
}

pub async fn create(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    t: &super::input::Template,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let sort = t.sort.unwrap_or(0);
    let digest = format!(
        "{}:{:?}:{}:{:?}:{:?}:{:?}:{sort}",
        t.name, t.description, t.category, t.conditions.0, t.actions.0, t.parameters.0
    );
    let envelope = user_envelope(user, op, "template.create", &digest);
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &envelope,
            deadline(),
            &crate::sql::TEMPLATE_CREATE,
            &[
                &t.name,
                &t.description,
                &t.category,
                &t.conditions.0,
                &t.actions.0,
                &t.parameters.0,
                &sort,
            ],
            Some(ReceiptCommand {
                family: "F09",
                command: "template.create",
            }),
            project_text0,
        )
        .await
}

pub async fn update(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    t: &super::input::Template,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let digest = format!(
        "{id}:{}:{:?}:{}:{:?}:{:?}:{:?}:{:?}:{:?}",
        t.name,
        t.description,
        t.category,
        t.conditions.0,
        t.actions.0,
        t.parameters.0,
        t.enabled,
        t.sort
    );
    let envelope = user_envelope(user, op, "template.update", &digest);
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &envelope,
            deadline(),
            &crate::sql::TEMPLATE_UPDATE,
            &[
                &id,
                &t.name,
                &t.description,
                &t.category,
                &t.conditions.0,
                &t.actions.0,
                &t.parameters.0,
                &t.enabled,
                &t.sort,
            ],
            Some(ReceiptCommand {
                family: "F09",
                command: "template.update",
            }),
            project_text0,
        )
        .await
}

pub async fn delete(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let envelope = user_envelope(user, op, "template.delete", &id.to_string());
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &envelope,
            deadline(),
            &crate::sql::TEMPLATE_DELETE,
            &[&id],
            Some(ReceiptCommand {
                family: "F09",
                command: "template.delete",
            }),
            project_text0,
        )
        .await
}

pub async fn visibility(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
) -> Result<String, StatementFailure> {
    let mut tx = tx_factory.begin_user_read(user).await?;
    let rows = tx
        .query_iterated_contract(&crate::sql::TEMPLATE_VISIBILITY_LIST, &[&id])
        .await?;
    tx.finish().await?;
    let items = rows
        .iter()
        .filter_map(|r| {
            let user = r
                .try_get::<_, Option<i64>>(0)
                .ok()?
                .map(|v| v.to_string())
                .unwrap_or("null".into());
            let hidden = r.try_get::<_, bool>(1).ok()?;
            Some(format!("{{\"hidden\":{hidden},\"userId\":{user}}}"))
        })
        .collect::<Vec<_>>();
    Ok(done(format!("[{}]", items.join(","))))
}

pub async fn set_visibility(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    t: &super::input::Visibility,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let contract = if t.hidden {
        &crate::sql::TEMPLATE_VISIBILITY_HIDE
    } else {
        &crate::sql::TEMPLATE_VISIBILITY_SHOW
    };
    let envelope = user_envelope(
        user,
        op,
        "template.visibility",
        &format!("{id}:{:?}:{}", t.user_id, t.hidden),
    );
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &envelope,
            deadline(),
            contract,
            &[&id, &t.user_id],
            Some(ReceiptCommand {
                family: "F09",
                command: "template.visibility",
            }),
            project_text0,
        )
        .await
}

pub async fn instantiate(
    tx_factory: &TxFactory,
    proof: &AdminPermissionProof,
    mailbox_id: i64,
    t: &Resolved,
    params: &std::collections::HashMap<String, Option<String>>,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let mut conditions = t.conditions.clone();
    let mut actions = t.actions.clone();
    for (key, value) in params {
        let needle = "\"{{".to_owned() + key + "}}\"";
        let encoded = s(value.as_deref().unwrap_or_default());
        conditions = conditions.replace(&needle, &encoded);
        actions = actions.replace(&needle, &encoded);
    }
    let digest = format!("{mailbox_id}:{}:{conditions}:{actions}", t.name);
    let envelope = admin_envelope(proof, op, "admin.from-template", &digest);
    tx_factory
        .run_admin_audited_reducer_contract(
            proof,
            &envelope,
            deadline(),
            &crate::sql::TEMPLATE_INSTANTIATE,
            &[&mailbox_id, &t.name, &conditions, &actions],
            Some(ReceiptCommand {
                family: "F09",
                command: "admin.from-template",
            }),
            |rows, _| project_text0(rows),
        )
        .await
}
