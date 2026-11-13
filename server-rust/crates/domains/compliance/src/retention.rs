//! Retention policy scope and frozen-Go representation.
use super::{finish, invalid, quote};
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};
pub async fn policies(exec: &ScopedExecutor, scope: i64) -> Result<String, StatementFailure> {
    let rows=exec.read("SELECT id,name,description,retain_days,action,is_default,domain_id,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US') FROM retention_policies WHERE $1::bigint<=0 OR domain_id IS NULL OR domain_id=$1 ORDER BY is_default DESC,id ASC",&[(&scope,Type::INT8)]).await?;
    let mut entries = Vec::new();
    for r in rows {
        let description: String = r.try_get(2).map_err(|_| invalid())?;
        let days: Option<i32> = r.get(3);
        let domain: Option<i64> = r.get(6);
        let time: String = r.get(7);
        let time = format!("{}Z", time.trim_end_matches('0').trim_end_matches('.'));
        entries.push(format!("{{\"id\":{},\"name\":{}{description},\"retainDays\":{},\"action\":{},\"isDefault\":{}{domain},\"createdAt\":{}}}",r.get::<_,i64>(0),quote(&r.get::<_,String>(1)),days.map_or("null".into(),|n|n.to_string()),quote(&r.get::<_,String>(4)),r.get::<_,bool>(5),quote(&time),description=if description.is_empty(){String::new()}else{format!(",\"description\":{}",quote(&description))},domain=domain.map_or(String::new(),|n|format!(",\"domainId\":{n}"))));
    }
    Ok(finish(format!("[{}]", entries.join(","))))
}
pub async fn create(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    scope: i64,
    patch: &str,
    ip: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"retention.create"},&super::envelope(&auth,operation,patch),&auth,super::deadline(),
 "SELECT rust_compliance_retention_create($2,$4,$5::text::jsonb,$6) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
 &[(&scope,Type::INT8),(&patch,Type::TEXT),(&ip,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
}
pub async fn update(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    scope: i64,
    id: i64,
    patch: &str,
    ip: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<bool, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"retention.update"},&super::envelope(&auth,operation,&format!("{scope}:{id}:{patch}:{ip}")),&auth,super::deadline(),
 "SELECT rust_compliance_retention_update($2,$4,$5,$6::text::jsonb,$7) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
 &[(&scope,Type::INT8),(&id,Type::INT8),(&patch,Type::TEXT),(&ip,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
}
pub async fn delete(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    scope: i64,
    id: i64,
    ip: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<bool, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"retention.delete"},&super::envelope(&auth,operation,&format!("{scope}:{id}:{ip}")),&auth,super::deadline(),
 "SELECT rust_compliance_retention_delete($2,$4,$5,$6) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
 &[(&scope,Type::INT8),(&id,Type::INT8),(&ip,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
}

/// Each setting is an independent best-effort lookup in frozen Go.
pub async fn log_get(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let mut values = Vec::new();
    for key in [
        "message_trace",
        "mailbox_audit",
        "auth_event",
        "webhook_delivery",
    ] {
        let key = format!("log_retention_{key}_days");
        let value = exec
            .read(
                "SELECT value::text FROM system_config WHERE key=$1",
                &[(&key, Type::TEXT)],
            )
            .await
            .ok()
            .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, String>(0).ok()))
            .and_then(|s| serde_json::from_str::<i64>(&s).ok())
            .filter(|n| *n > 0);
        values.push(value.map_or("null".into(), |n| n.to_string()));
    }
    Ok(format!("{{\"messageTraceDays\":{},\"mailboxAuditLogDays\":{},\"authEventDays\":{},\"webhookDeliveryDays\":{}}}\n",values[0],values[1],values[2],values[3]))
}
pub async fn log_set(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    values: &[i64],
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"retention.logs.set"},&super::envelope(&auth,operation,&format!("{values:?}")),&auth,super::deadline(),
 "SELECT rust_compliance_log_retention_set($2,$4) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
 &[(&values,Type::INT8_ARRAY)],|rows|if rows.len()==1{Ok(())}else{Err(invalid())}).await
}
pub async fn prune(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"retention.prune"},&super::envelope(&auth,operation,"prune_log_tables"),&auth,super::deadline(),
 "SELECT pruned_table,rows_deleted FROM rust_compliance_log_prune($2) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",&[],
 |rows|{let values=rows.iter().filter_map(|r|Some(format!("{{\"deleted\":{},\"table\":{}}}",r.try_get::<_,i32>(1).ok()?,quote(&r.try_get::<_,String>(0).ok()?)))).collect::<Vec<_>>();Ok(finish(format!("[{}]",values.join(","))))}).await
}
