//! Case-bound organization-wide export: gate+audit reducer, then read-only rows.
use super::{deadline, envelope, invalid, scope, FAMILY};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ReceiptCommand, ScopedExecutor, StatementFailure, Type};
pub async fn authorize(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    case: i64,
    ids: &Vec<i64>,
    original: &[String],
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    let original = serde_json::to_string(original).expect("strings");
    setjoin_pg::run_receipted_command(exec,ReceiptCommand{family:FAMILY,command:"export.authorize"},&envelope(&auth,operation,&serde_json::json!([case,ids,original]).to_string()),&auth,deadline(),
 "SELECT rust_compliance_export_authorize($2,$4,$5,$6::text::jsonb,$7) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
 &[(&case,Type::INT8),(ids,Type::INT8_ARRAY),(&original,Type::TEXT),(&ip,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
}
pub async fn messages(
    exec: &ScopedExecutor,
    ids: &Vec<i64>,
    actor: i64,
) -> Vec<(i64, String, String, String, String)> {
    let rows=exec.read_iterated("SELECT id,raw_ref,from_addr,subject,to_char(received_at AT TIME ZONE 'UTC','Dy Mon DD HH24:MI:SS YYYY') FROM messages WHERE id=ANY($1) AND $2::bigint>0 ORDER BY id",&[(ids,Type::INT8_ARRAY),(&actor,Type::INT8)]).await.unwrap_or_default();
    rows.iter()
        .filter_map(|r| {
            Some((
                r.try_get(0).ok()?,
                r.try_get(1).ok()?,
                r.try_get(2).ok()?,
                r.try_get(3).ok()?,
                r.try_get(4).ok()?,
            ))
        })
        .collect()
}
