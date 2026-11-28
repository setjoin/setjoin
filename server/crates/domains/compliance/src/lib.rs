//! Compliance (F04), foundation dependencies only. See DOX.md.
#![forbid(unsafe_code)]
pub mod audit;
pub mod chat;
pub mod chat_export;
pub mod content;
pub mod export;
pub mod kql;
pub mod retention;
pub mod search;
pub mod sql;

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

pub const FAMILY: &str = "F04";

/// Go's `admin.ConsoleScopes[ConsoleMail]`, in registration order
/// (`requireMailPerm`, any-of).
pub const MAIL_CONSOLE: [&str; 5] = [
    "domains.read",
    "queue.read",
    "reports.read",
    "mail.pipeline",
    "mail.security",
];

pub(crate) fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid compliance result".into(),
    }
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

fn quote(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".into())
}

pub fn finish(text: String) -> String {
    text.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
        + "\n"
}

fn case_json(r: &Row) -> Result<String, StatementFailure> {
    let id: i64 = r.try_get(0).map_err(|_| invalid())?;
    let name: String = r.try_get(1).map_err(|_| invalid())?;
    let description: String = r.try_get(2).map_err(|_| invalid())?;
    let status: String = r.try_get(3).map_err(|_| invalid())?;
    let user: i64 = r.try_get(4).map_err(|_| invalid())?;
    let closed: Option<String> = r.try_get(5).map_err(|_| invalid())?;
    let closer: Option<i64> = r.try_get(6).map_err(|_| invalid())?;
    let created: String = r.try_get(7).map_err(|_| invalid())?;
    let updated: String = r.try_get(8).map_err(|_| invalid())?;
    let count: i64 = r.try_get(9).map_err(|_| invalid())?;
    Ok(format!(
        "{{\"id\":{id},\"name\":{}{description},\"status\":{},\"createdBy\":{user}{closed}{closer},\"searchCount\":{count},\"createdAt\":{},\"updatedAt\":{}}}",
        quote(&name),
        quote(&status),
        quote(&created),
        quote(&updated),
        description = if description.is_empty() {
            String::new()
        } else {
            format!(",\"description\":{}", quote(&description))
        },
        closed = closed
            .map(|s| format!(",\"closedAt\":{}", quote(&s)))
            .unwrap_or_default(),
        closer = closer
            .map(|i| format!(",\"closedBy\":{i}"))
            .unwrap_or_default()
    ))
}

pub async fn list_cases(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::CASES_LIST, &[])
        .await?;
    let entries = rows.iter().map(case_json).collect::<Result<Vec<_>, _>>()?;
    Ok(finish(format!("[{}]", entries.join(","))))
}

pub async fn get_case(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::CASE_GET, &[&id])
        .await?;
    let case = case_json(rows.first().ok_or_else(invalid)?)?;
    let mut tx = factory.begin_admin_read(admin).await?;
    let rows = tx
        .query_iterated_contract(&sql::CASE_SEARCHES, &[&id])
        .await
        .unwrap_or_default();
    let _ = tx.finish().await;
    let searches = rows
        .iter()
        .filter_map(|r| {
            let id: i64 = r.try_get(0).ok()?;
            let name: String = r.try_get(1).ok()?;
            let status: String = r.try_get(2).ok()?;
            let count: Option<i32> = r.try_get(3).ok()?;
            let created: String = r.try_get(4).ok()?;
            Some(format!(
                "{{\"id\":{id},\"name\":{},\"status\":{}{count},\"createdAt\":{}}}",
                quote(&name),
                quote(&status),
                quote(&created),
                count = count
                    .map(|n| format!(",\"resultCount\":{n}"))
                    .unwrap_or_default()
            ))
        })
        .collect::<Vec<_>>();
    Ok(finish(format!(
        "{{\"case\":{case},\"searches\":[{}]}}",
        searches.join(",")
    )))
}

pub async fn create_case(
    factory: &TxFactory,
    user: &UserPrincipal,
    admin: &AdminPermissionProof,
    name: &str,
    description: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let actor_id = admin.actor().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &json!([name, description]).to_string(),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CASE_CREATE,
            &[&actor_id, &name, &description],
            Some(command("case.create")),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

pub async fn update_case(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    id: i64,
    name: Option<&str>,
    description: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &json!([id, name, description]).to_string(),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CASE_UPDATE,
            &[&id, &name, &description],
            Some(command("case.update")),
            |rows| Ok(!rows.is_empty()),
        )
        .await
}

pub async fn delete_case(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(user.user(), user.generation(), operation, &id.to_string());
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CASE_DELETE,
            &[&id],
            Some(command("case.delete")),
            |rows| Ok(!rows.is_empty()),
        )
        .await
}

pub async fn associate_search(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    search: i64,
    case: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &json!([search, case]).to_string(),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::SEARCH_ASSOCIATE,
            &[&search, &case],
            Some(command("search.associate")),
            |rows| Ok(!rows.is_empty()),
        )
        .await
}

pub async fn close_case(
    factory: &TxFactory,
    user: &UserPrincipal,
    admin: &AdminPermissionProof,
    id: i64,
    reason: &str,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let actor_id = admin.actor().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &json!([id, reason]).to_string(),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CASE_CLOSE,
            &[&actor_id, &id, &reason, &ip],
            Some(command("case.close")),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct HeldMessage {
    pub id: i64,
    pub received_at: String,
}

/// Decode JSON returned by `sql::MESSAGE_HOLD`.
pub fn decode_held_messages(raw: &str) -> Result<Vec<HeldMessage>, StatementFailure> {
    serde_json::from_str::<Vec<HeldMessage>>(raw).map_err(|_| invalid())
}

/// Read persisted eDiscovery search metadata and bound results via `AdminReadTx`
/// on `AdminWorkerPool`.
pub async fn get_search(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::SEARCH_GET, &[&id])
        .await?;
    let r = rows.first().ok_or_else(invalid)?;
    let id: i64 = r.try_get(0).map_err(|_| invalid())?;
    let name: String = r.try_get(1).map_err(|_| invalid())?;
    let keywords: String = r.try_get(2).map_err(|_| invalid())?;
    let kql: String = r.try_get(3).map_err(|_| invalid())?;
    if !kql.is_empty() {
        kql::parse(&kql).map_err(|error| StatementFailure {
            sqlstate: None,
            hint: Some("kql-validation".into()),
            message: format!("invalid KQL query: {error}"),
        })?;
    }

    let from: String = r.try_get(4).map_err(|_| invalid())?;
    let date_from: String = r.try_get(5).map_err(|_| invalid())?;
    let date_to: String = r.try_get(6).map_err(|_| invalid())?;
    let query: String = r.try_get(7).map_err(|_| invalid())?;
    let status: String = r.try_get(8).map_err(|_| invalid())?;
    let count: Option<i32> = r.try_get(9).map_err(|_| invalid())?;
    let case: Option<i64> = r.try_get(10).map_err(|_| invalid())?;
    let created: String = r.try_get(11).map_err(|_| invalid())?;
    let provenance: Option<String> = r.try_get(12).ok().flatten();
    let mut search = format!(
        "{{\"id\":{id},\"name\":{},\"keywords\":{}",
        quote(&name),
        quote(&keywords)
    );
    for (key, value) in [
        ("kql", kql),
        ("fromAddr", from),
        ("dateFrom", date_from),
        ("dateTo", date_to),
    ] {
        if !value.is_empty() {
            search += &format!(",\"{key}\":{}", quote(&value));
        }
    }
    let query: serde_json::Value = serde_json::from_str(&query).map_err(|_| invalid())?;
    let ids = query["mailboxIds"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_f64())
        .map(|f| {
            if f >= i64::MAX as f64 || f < i64::MIN as f64 {
                i64::MIN
            } else {
                f as i64
            }
        })
        .collect::<Vec<_>>();
    if !ids.is_empty() {
        search += &format!(
            ",\"mailboxIds\":{}",
            serde_json::to_string(&ids).unwrap_or_else(|_| "[]".into())
        );
    }
    if let Some(case) = case {
        search += &format!(",\"caseId\":{case}");
    }
    search += &format!(",\"status\":{}", quote(&status));
    if let Some(count) = count {
        search += &format!(",\"resultCount\":{count}");
    }
    if let Some(prov) = provenance.as_deref().filter(|s| !s.is_empty()) {
        search += &format!(",\"searchProvenance\":{prov}");
    }
    search += &format!(",\"createdAt\":{}}}", quote(&created));
    let mut results = Vec::new();
    if status == "complete" && count.is_some_and(|n| n > 0) && case.is_some() {
        let mut tx = factory.begin_admin_read(admin).await?;
        let rows = tx
            .query_iterated_contract(&sql::SEARCH_RESULTS, &[&id])
            .await
            .unwrap_or_default();
        let _ = tx.finish().await;
        for r in rows {
            let fields = (
                r.try_get::<_, i64>(0),
                r.try_get::<_, String>(1),
                r.try_get::<_, String>(2),
                r.try_get::<_, String>(3),
                r.try_get::<_, String>(4),
            );
            if let (Ok(id), Ok(subject), Ok(from), Ok(received), Ok(mailbox)) = fields {
                results.push(format!(
                    "{{\"from\":{},\"id\":{id},\"mailbox\":{},\"receivedAt\":{},\"subject\":{}}}",
                    quote(&from),
                    quote(&mailbox),
                    quote(&received),
                    quote(&subject)
                ));
            }
        }
    }
    let results = if results.is_empty() {
        "null".into()
    } else {
        format!("[{}]", results.join(","))
    };
    Ok(finish(format!(
        "{{\"results\":{results},\"search\":{search}}}"
    )))
}
