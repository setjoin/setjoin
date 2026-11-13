//! Compliance (F04), foundation dependencies only. See DOX.md.
#![forbid(unsafe_code)]
pub mod audit;
pub mod chat;
pub mod content;
pub mod export;
pub mod kql;
pub mod retention;
pub mod search;
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
        message: "invalid compliance result".into(),
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
        ReceiptCommand {
            family: FAMILY,
            command: "console.denied",
        },
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

fn quote(text: &str) -> String {
    serde_json::to_string(text).expect("string")
}
pub fn finish(text: String) -> String {
    text.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
        + "\n"
}
fn case_select() -> &'static str {
    "SELECT c.id,c.name,c.description,c.status,c.created_by, \
    to_char(c.closed_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),c.closed_by, \
    to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
    to_char(c.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
    (SELECT count(*) FROM ediscovery_searches s WHERE s.case_id=c.id) FROM ediscovery_cases c"
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
    Ok(format!("{{\"id\":{id},\"name\":{}{description},\"status\":{},\"createdBy\":{user}{closed}{closer},\"searchCount\":{count},\"createdAt\":{},\"updatedAt\":{}}}",
        quote(&name),quote(&status),quote(&created),quote(&updated),
        description=if description.is_empty(){String::new()}else{format!(",\"description\":{}",quote(&description))},
        closed=closed.map(|s|format!(",\"closedAt\":{}",quote(&s))).unwrap_or_default(),
        closer=closer.map(|i|format!(",\"closedBy\":{i}")).unwrap_or_default()))
}
pub async fn list_cases(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            &format!("{} ORDER BY c.created_at DESC", case_select()),
            &[],
        )
        .await?;
    let entries = rows.iter().map(case_json).collect::<Result<Vec<_>, _>>()?;
    Ok(finish(format!("[{}]", entries.join(","))))
}

pub async fn get_case(exec: &ScopedExecutor, id: i64) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            &format!("{} WHERE c.id=$1", case_select()),
            &[(&id, Type::INT8)],
        )
        .await?;
    let case = case_json(rows.first().ok_or_else(invalid)?)?;
    let rows=exec.read_iterated("SELECT id,name,status,result_count,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM ediscovery_searches WHERE case_id=$1 ORDER BY created_at DESC",&[(&id,Type::INT8)]).await.unwrap_or_default();
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &str,
    description: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(exec,ReceiptCommand{family:FAMILY,command:"case.create"},&envelope(&auth,operation,&json!([name,description]).to_string()),&auth,deadline(),
        "INSERT INTO ediscovery_cases(name,description,created_by) SELECT $4,$5,$2 WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' RETURNING id",
        &[(&name,Type::TEXT),(&description,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
}

pub async fn update_case(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    name: Option<&str>,
    description: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(exec,ReceiptCommand{family:FAMILY,command:"case.update"},&envelope(&auth,operation,&json!([id,name,description]).to_string()),&auth,deadline(),
        "UPDATE ediscovery_cases SET name=COALESCE(NULLIF($5::text,''),name),description=COALESCE($6::text,description),updated_at=now() WHERE id=$4 AND $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' RETURNING id",
        &[(&id,Type::INT8),(&name,Type::TEXT),(&description,Type::TEXT)],|rows|Ok(!rows.is_empty())).await
}

pub async fn delete_case(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(exec,ReceiptCommand{family:FAMILY,command:"case.delete"},&envelope(&auth,operation,&id.to_string()),&auth,deadline(),
        "DELETE FROM ediscovery_cases WHERE id=$4 AND NOT EXISTS(SELECT 1 FROM ediscovery_searches WHERE case_id=$4) AND $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' RETURNING id",
        &[(&id,Type::INT8)],|rows|Ok(!rows.is_empty())).await
}

pub async fn associate_search(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    search: i64,
    case: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(exec,ReceiptCommand{family:FAMILY,command:"search.associate"},&envelope(&auth,operation,&json!([search,case]).to_string()),&auth,deadline(),
        "UPDATE ediscovery_searches SET case_id=$5 WHERE id=$4 AND case_id IS NULL AND $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' RETURNING id",
        &[(&search,Type::INT8),(&case,Type::INT8)],|rows|Ok(!rows.is_empty())).await
}

pub async fn close_case(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    reason: &str,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(exec,ReceiptCommand{family:FAMILY,command:"case.close"},&envelope(&auth,operation,&json!([id,reason]).to_string()),&auth,deadline(),
        "SELECT rust_compliance_case_close($2,$4,$5,$6) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&id,Type::INT8),(&reason,Type::TEXT),(&ip,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
}

pub async fn hold(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ids: &Option<Vec<i64>>,
    on: bool,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Vec<i64>, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(exec,ReceiptCommand{family:FAMILY,command:if on{"message.hold"}else{"message.release"}},&envelope(&auth,operation,&json!([ids,on]).to_string()),&auth,deadline(),
        "SELECT rust_compliance_message_hold($2,$4,$5,$6) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(ids,Type::INT8_ARRAY),(&on,Type::BOOL),(&ip,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
}

/// Go's GetSearch uses the worker credential and only reads persisted bindings.
pub async fn get_search(exec: &ScopedExecutor, id: i64) -> Result<String, StatementFailure> {
    let rows=exec.read("SELECT id,name,query->>'keywords',query->>'kql',query->>'fromAddr',query->>'dateFrom',query->>'dateTo',query::text,status,result_count,case_id,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM ediscovery_searches WHERE id=$1",&[(&id,Type::INT8)]).await?;
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
            serde_json::to_string(&ids).expect("ids")
        );
    }
    if let Some(case) = case {
        search += &format!(",\"caseId\":{case}");
    }
    search += &format!(",\"status\":{}", quote(&status));
    if let Some(count) = count {
        search += &format!(",\"resultCount\":{count}");
    }
    search += &format!(",\"createdAt\":{}}}", quote(&created));
    let mut results = Vec::new();
    if status == "complete" && count.is_some_and(|n| n > 0) && case.is_some() {
        let rows=exec.read_iterated("SELECT m.id,m.subject,m.from_addr,to_char(m.received_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),mb.email FROM ediscovery_search_results r JOIN messages m ON m.id=r.message_id JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE r.search_id=$1 ORDER BY m.received_at DESC LIMIT 500",&[(&id,Type::INT8)]).await.unwrap_or_default();
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

pub mod chat_export;
