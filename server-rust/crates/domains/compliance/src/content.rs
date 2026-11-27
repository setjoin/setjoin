//! Organization-wide content search and purge via `TxFactory` (`AdminReadTx` / `AdminWriteTx`).
use super::{command, deadline, envelope, finish, invalid, quote, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{CommandOutcome, StatementFailure};

pub struct Query {
    pub keywords: String,
    pub kql: String,
    pub from: String,
    pub date_from: String,
    pub date_to: String,
    pub mailboxes: Option<Vec<i64>>,
}

pub async fn search(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    q: &Query,
) -> Result<String, StatementFailure> {
    let mut tx = factory.begin_admin_read(admin).await?;
    let rows = if !q.kql.is_empty() {
        let p = super::kql::parse(&q.kql).map_err(|error| StatementFailure {
            sqlstate: None,
            hint: Some("kql-validation".into()),
            message: format!("invalid KQL query: {error}"),
        })?;
        tx.query_contract(&sql::CONTENT_SEARCH_KQL, &[&p.sql, &p.values])
            .await
    } else {
        let mailboxes: Option<Vec<i64>> = q.mailboxes.as_ref().filter(|xs| !xs.is_empty()).cloned();
        tx.query_iterated_contract(
            &sql::CONTENT_SEARCH_FILTERED,
            &[&q.keywords, &q.from, &q.date_from, &q.date_to, &mailboxes],
        )
        .await
    };
    let _ = tx.finish().await;
    // pgx describes the statement before binding parameter data. These errors
    // surface as ignored Rows.Err in Go, even when the unnamed Rust plan fails
    // before RowDescription (for example an invalid timestamp array element).
    let rows = match rows {
        Ok(rows) => rows,
        Err(e) if e.sqlstate.as_deref().is_some_and(|s| s.starts_with("22")) => Vec::new(),
        Err(e) => return Err(e),
    };
    let mut results = Vec::new();
    for r in rows {
        let (Ok(id), Ok(subject), Ok(from), Ok(time), Ok(mailbox)) = (
            r.try_get::<_, i64>(0),
            r.try_get::<_, String>(1),
            r.try_get::<_, String>(2),
            r.try_get::<_, String>(3),
            r.try_get::<_, String>(4),
        ) else {
            break;
        };
        results.push(format!(
            "{{\"from\":{},\"id\":{id},\"mailbox\":{},\"receivedAt\":{},\"subject\":{}}}",
            quote(&from),
            quote(&mailbox),
            quote(&time),
            quote(&subject)
        ));
    }
    Ok(finish(format!(
        "{{\"results\":[{}],\"total\":{}}}",
        results.join(","),
        results.len()
    )))
}

pub async fn purge(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    email: &str,
    ids: &[i64],
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let ids_vec = ids.to_vec();
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &serde_json::json!([ids, email, reason]).to_string(),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::CONTENT_PURGE,
            &[&ids_vec, &email, &reason],
            Some(command("content.purge")),
            |rows, audited| {
                if !audited {
                    return Err(invalid());
                }
                let raw: String = rows
                    .first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)?;
                let trimmed = raw
                    .strip_prefix('(')
                    .and_then(|s| s.strip_suffix(')'))
                    .ok_or_else(invalid)?;
                let mut parts = trimmed.split(',');
                let deleted: i32 = parts
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(invalid)?;
                let held: i32 = parts
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(invalid)?;
                let missing: i32 = parts
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(invalid)?;
                Ok(format!(
                    "{{\"deleted\":{deleted},\"held\":{held},\"notFound\":{missing}}}\n"
                ))
            },
        )
        .await
}
