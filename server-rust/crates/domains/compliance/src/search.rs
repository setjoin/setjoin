//! Request-owned search jobs: one INSERT, then Go's running/completion/failure.
use super::{deadline, envelope, invalid, scope, FAMILY};
use setjoin_authz::AuthContext;
use setjoin_pg::{
    workers::WorkerDatabase, CommandOutcome, ReceiptCommand, ScopedExecutor, StatementFailure, Type,
};

pub async fn start(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &str,
    query: &serde_json::Value,
    case: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    let query = query.to_string();
    setjoin_pg::run_receipted_command(exec,ReceiptCommand{family:FAMILY,command:"search.start"},&envelope(&auth,operation,&serde_json::json!([name,query,case]).to_string()),&auth,deadline(),
        "INSERT INTO ediscovery_searches(name,created_by,query,status,case_id) SELECT $4,$2,$5::text::jsonb,'pending',$6 WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' RETURNING id",
        &[(&name,Type::TEXT),(&query,Type::TEXT),(&case,Type::INT8)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
}

/// Uses a configured worker connection, not the short request pool deadline.
/// Failure marking uses a fresh connection, as Go's h.pool.Exec does, even
/// after a lost completion result. No automatic job retry occurs.
pub async fn execute(database: &WorkerDatabase, actor: i64, id: i64) -> Result<(), String> {
    let result=async {
        let c=database.connect().await.map_err(|e|e.to_string())?;
        let rows=c.query("UPDATE ediscovery_searches SET status='running',started_at=now() WHERE id=$1 AND created_by=$2 RETURNING query::text",&[(&id,Type::INT8),(&actor,Type::INT8)]).await?;
        let text=rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).ok_or("missing search query")?;
        let query:serde_json::Value=serde_json::from_str(&text).map_err(|e|e.to_string())?;
        let (predicate,values)=if let Some(kql)=query["kql"].as_str().filter(|s|!s.is_empty()) {
            let parsed=super::kql::parse(kql)?;(parsed.sql,parsed.values)
        } else {
        let mut values=vec![query["keywords"].as_str().unwrap_or("").to_owned()];
        let mut predicate="(m.body_tsv @@ websearch_to_tsquery('simple',($1::text[])[1]) OR m.subject_tsv @@ websearch_to_tsquery('simple',($1::text[])[1]) OR m.from_tsv @@ websearch_to_tsquery('simple',($1::text[])[1]))".to_owned();
        if let Some(from)=query["fromAddr"].as_str().filter(|s|!s.is_empty()){
            values.push(from.to_owned());predicate+=&format!(" AND m.from_addr ILIKE '%' || ($1::text[])[{}] || '%'",values.len());
        }
        if let Some(date)=query["dateFrom"].as_str().filter(|s|!s.is_empty()){
            values.push(date.to_owned());predicate+=&format!(" AND m.received_at >= (($1::text[])[{}])::timestamptz",values.len());
        }
        if let Some(date)=query["dateTo"].as_str().filter(|s|!s.is_empty()){
            values.push(date.to_owned());predicate+=&format!(" AND m.received_at <= (($1::text[])[{}])::timestamptz",values.len());
        }
        if let Some(ids)=query["mailboxIds"].as_array().filter(|ids|!ids.is_empty()){
            let ids=ids.iter().map(|v|v.as_f64().map_or(0,|f|if f>=i64::MAX as f64||f<i64::MIN as f64{i64::MIN}else{f as i64})).map(|n|n.to_string()).collect::<Vec<_>>();
            values.push(format!("{{{}}}",ids.join(",")));predicate+=&format!(" AND m.mailbox_id = ANY((($1::text[])[{}])::bigint[])",values.len());
        }
            (predicate,values)
        };
        c.query("SELECT rust_compliance_search_complete($1,$2,$3,$4)",&[(&actor,Type::INT8),(&id,Type::INT8),(&predicate,Type::TEXT),(&values,Type::TEXT_ARRAY)]).await?;
        Ok::<_,String>(())
    }.await;
    if result.is_err() {
        if let Ok(c) = database.connect().await {
            let _=c.execute("UPDATE ediscovery_searches SET status='failed',completed_at=now() WHERE id=$1 AND created_by=$2",&[(&id,Type::INT8),(&actor,Type::INT8)]).await;
        }
    }
    result
}
