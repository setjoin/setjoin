//! Frozen template queries; legacy fixtures and missing active tables are both qualified.
use super::{done, invalid, s};
use setjoin_authz::AuthContext;
use setjoin_pg::{Row, ScopedExecutor, StatementFailure, Type};
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
    Ok(format!("{{\"actions\":{},\"category\":{},\"conditions\":{},\"description\":{}{enabled},\"id\":{id},\"isSystem\":{},\"name\":{},\"parameters\":{},\"sortOrder\":{}}}",raw(r.try_get(5).map_err(|_|invalid())?),s(r.try_get(3).map_err(|_|invalid())?),raw(r.try_get(4).map_err(|_|invalid())?),s(r.try_get(2).map_err(|_|invalid())?),r.try_get::<_,bool>(7).map_err(|_|invalid())?,s(r.try_get(1).map_err(|_|invalid())?),raw(r.try_get(6).map_err(|_|invalid())?),r.try_get::<_,i32>(8).map_err(|_|invalid())?))
}
pub async fn list(exec: &ScopedExecutor, a: &AuthContext) -> Result<String, StatementFailure> {
    let rows = if a.signed_admin() {
        exec.read_iterated(crate::sql::TEMPLATE_LIST_ADMIN.sql, &[])
            .await?
    } else {
        let user = a.user_id();
        exec.read_iterated(crate::sql::TEMPLATE_LIST_USER.sql, &[(&user, Type::INT8)])
            .await?
    };
    Ok(done(format!(
        "[{}]",
        rows.iter()
            .map_while(|r| item(r, false).ok())
            .collect::<Vec<_>>()
            .join(",")
    )))
}

pub async fn get(exec: &ScopedExecutor, id: i64) -> Result<Option<String>, StatementFailure> {
    let rows = exec
        .read(crate::sql::TEMPLATE_GET.sql, &[(&id, Type::INT8)])
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
pub async fn load(exec: &ScopedExecutor, id: i64) -> Result<Option<Resolved>, StatementFailure> {
    let rows = exec
        .read(crate::sql::TEMPLATE_LOAD.sql, &[(&id, Type::INT8)])
        .await?;
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
pub async fn resolve(exec: &ScopedExecutor, id: i64) -> Result<Option<String>, StatementFailure> {
    Ok(load(exec,id).await?.map(|t|done(format!("{{\"actions\":{},\"category\":{},\"conditions\":{},\"id\":{id},\"name\":{},\"parameters\":{}}}",raw(&t.actions),s(&t.category),raw(&t.conditions),s(&t.name),raw(&t.parameters)))))
}
pub async fn create(
    exec: &ScopedExecutor,
    a: &AuthContext,
    t: &super::input::Template,
    op: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let sort = t.sort.unwrap_or(0);
    super::write(
        exec,
        a,
        op,
        "template.create",
        crate::sql::TEMPLATE_CREATE.sql,
        &[
            (&t.name, Type::TEXT),
            (&t.description, Type::TEXT),
            (&t.category, Type::TEXT),
            (&t.conditions.0, Type::TEXT),
            (&t.actions.0, Type::TEXT),
            (&t.parameters.0, Type::TEXT),
            (&sort, Type::INT8),
        ],
    )
    .await
}
pub async fn update(
    exec: &ScopedExecutor,
    a: &AuthContext,
    id: i64,
    t: &super::input::Template,
    op: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    super::write(
        exec,
        a,
        op,
        "template.update",
        crate::sql::TEMPLATE_UPDATE.sql,
        &[
            (&id, Type::INT8),
            (&t.name, Type::TEXT),
            (&t.description, Type::TEXT),
            (&t.category, Type::TEXT),
            (&t.conditions.0, Type::TEXT),
            (&t.actions.0, Type::TEXT),
            (&t.parameters.0, Type::TEXT),
            (&t.enabled, Type::BOOL),
            (&t.sort, Type::INT8),
        ],
    )
    .await
}
pub async fn delete(
    exec: &ScopedExecutor,
    a: &AuthContext,
    id: i64,
    op: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    super::write(
        exec,
        a,
        op,
        "template.delete",
        crate::sql::TEMPLATE_DELETE.sql,
        &[(&id, Type::INT8)],
    )
    .await
}
pub async fn visibility(exec: &ScopedExecutor, id: i64) -> Result<String, StatementFailure> {
    let rows = exec
        .read_iterated(
            crate::sql::TEMPLATE_VISIBILITY_LIST.sql,
            &[(&id, Type::INT8)],
        )
        .await?;
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
    exec: &ScopedExecutor,
    a: &AuthContext,
    id: i64,
    t: &super::input::Visibility,
    op: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let sql = if t.hidden {
        crate::sql::TEMPLATE_VISIBILITY_HIDE.sql
    } else {
        crate::sql::TEMPLATE_VISIBILITY_SHOW.sql
    };
    super::write(
        exec,
        a,
        op,
        "template.visibility",
        sql,
        &[(&id, Type::INT8), (&t.user_id, Type::INT8)],
    )
    .await
}
pub async fn instantiate(
    exec: &ScopedExecutor,
    a: &AuthContext,
    t: &Resolved,
    params: &std::collections::HashMap<String, Option<String>>,
    op: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let mut conditions = t.conditions.clone();
    let mut actions = t.actions.clone();
    for (key, value) in params {
        let needle = "\"{{".to_owned() + key + "}}\"";
        let encoded = s(value.as_deref().unwrap_or_default());
        conditions = conditions.replace(&needle, &encoded);
        actions = actions.replace(&needle, &encoded);
    }
    super::write(
        exec,
        a,
        op,
        "admin.from-template",
        crate::sql::TEMPLATE_INSTANTIATE.sql,
        &[
            (&t.name, Type::TEXT),
            (&conditions, Type::TEXT),
            (&actions, Type::TEXT),
        ],
    )
    .await
}
