//! Organization-wide content search and purge, on the explicit worker credential.
use super::{finish, invalid, quote};
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};
pub struct Query {
    pub keywords: String,
    pub kql: String,
    pub from: String,
    pub date_from: String,
    pub date_to: String,
    pub mailboxes: Option<Vec<i64>>,
}
pub async fn search(exec: &ScopedExecutor, q: &Query) -> Result<String, StatementFailure> {
    let (predicate, values) = if !q.kql.is_empty() {
        let p = super::kql::parse(&q.kql).map_err(|error| StatementFailure {
            sqlstate: None,
            hint: Some("kql-validation".into()),
            message: format!("invalid KQL query: {error}"),
        })?;
        (p.sql, p.values)
    } else {
        let mut values = vec![q.keywords.clone()];
        let mut predicate="(m.body_tsv @@ websearch_to_tsquery('simple',($1::text[])[1]) OR m.subject_tsv @@ websearch_to_tsquery('simple',($1::text[])[1]) OR m.from_tsv @@ websearch_to_tsquery('simple',($1::text[])[1]))".to_owned();
        if !q.from.is_empty() {
            values.push(q.from.clone());
            predicate += &format!(
                " AND m.from_addr ILIKE '%' || ($1::text[])[{}] || '%'",
                values.len()
            );
        }
        for (op, date) in [(">=", &q.date_from), ("<=", &q.date_to)] {
            if !date.is_empty() {
                values.push(date.clone());
                predicate += &format!(
                    " AND m.received_at {op} (($1::text[])[{}])::timestamptz",
                    values.len()
                );
            }
        }
        if let Some(ids) = q.mailboxes.as_ref().filter(|xs| !xs.is_empty()) {
            values.push(format!(
                "{{{}}}",
                ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",")
            ));
            predicate += &format!(
                " AND m.mailbox_id=ANY((($1::text[])[{}])::bigint[])",
                values.len()
            );
        }
        (predicate, values)
    };
    let rows=exec.read_iterated(&format!("SELECT m.id,m.subject,m.from_addr,to_char(m.received_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),mb.email FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE {predicate} ORDER BY m.received_at DESC LIMIT 500"),&[(&values,Type::TEXT_ARRAY)]).await;
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
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    ids: &[i64],
    reason: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let auth = super::scope(actor);
    let email = actor.email();
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"content.purge"},&super::envelope(&auth,operation,&serde_json::json!([ids,email,reason]).to_string()),&auth,super::deadline(),
 "SELECT deleted_count,held_count,not_found_count FROM content_purge_messages($4,$5,$6,$2) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
 &[(&ids,Type::INT8_ARRAY),(&email,Type::TEXT),(&reason,Type::TEXT)],|rows|{let row=rows.first().ok_or_else(invalid)?;let deleted:i32=row.try_get(0).map_err(|_|invalid())?;let held:i32=row.try_get(1).map_err(|_|invalid())?;let missing:i32=row.try_get(2).map_err(|_|invalid())?;Ok(format!("{{\"deleted\":{deleted},\"held\":{held},\"notFound\":{missing}}}\n"))}).await
}
