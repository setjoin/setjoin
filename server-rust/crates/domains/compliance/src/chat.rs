//! F04 chat-compliance, organization-wide authority rather than channel membership.
use setjoin_pg::{ScopedExecutor, StatementFailure};
pub async fn policies(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows=exec.read("SELECT id,name,applies_to,duration_days,enabled,effective_at::text,created_at::text,updated_at::text FROM chat_retention_policies ORDER BY id",&[]).await?;
    let mut entries = Vec::with_capacity(rows.len());
    for r in rows {
        entries.push(format!("{{\"id\":{},\"name\":{},\"appliesTo\":{},\"durationDays\":{},\"enabled\":{},\"effectiveAt\":{},\"createdAt\":{},\"updatedAt\":{}}}",r.get::<_,i64>(0),super::quote(&r.get::<_,String>(1)),super::quote(&r.get::<_,String>(2)),r.get::<_,i32>(3),r.get::<_,bool>(4),super::quote(&r.get::<_,String>(5)),super::quote(&r.get::<_,String>(6)),super::quote(&r.get::<_,String>(7))));
    }
    Ok(super::finish(format!("[{}]", entries.join(","))))
}
pub async fn cases(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT id,name,status FROM ediscovery_cases ORDER BY status,name",
            &[],
        )
        .await?;
    let entries = rows
        .iter()
        .map(|r| {
            format!(
                "{{\"id\":{},\"name\":{},\"status\":{}}}",
                r.get::<_, i64>(0),
                super::quote(&r.get::<_, String>(1)),
                super::quote(&r.get::<_, String>(2))
            )
        })
        .collect::<Vec<_>>();
    Ok(super::finish(format!("[{}]", entries.join(","))))
}
fn time(column: &str) -> String {
    format!("rtrim(rtrim(to_char({column} AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'),'0'),'.')||'Z'")
}
pub async fn holds(exec: &ScopedExecutor, case: i64) -> Result<String, StatementFailure> {
    use setjoin_pg::Type;
    let rows=exec.read(&format!("SELECT h.id,h.case_id,h.custodian_user_id,h.channel_id,h.reason,h.created_by,{}, {},h.released_by,(SELECT count(*) FROM chat_case_hold_channels hc WHERE hc.hold_id=h.id) FROM chat_case_holds h WHERE h.case_id=$1 ORDER BY h.id DESC",time("h.created_at"),time("h.released_at")),&[(&case,Type::INT8)]).await?;
    let mut out = Vec::new();
    for r in rows {
        let mut fields = format!(
            "{{\"id\":{},\"caseId\":{}",
            r.get::<_, i64>(0),
            r.get::<_, i64>(1)
        );
        for (i, key) in [(2, "custodianUserId"), (3, "channelId")] {
            if let Some(n) = r.get::<_, Option<i64>>(i) {
                fields += &format!(",\"{key}\":{n}");
            }
        }
        fields += &format!(
            ",\"reason\":{},\"createdBy\":{},\"createdAt\":{}",
            super::quote(&r.get::<_, String>(4)),
            r.get::<_, i64>(5),
            super::quote(&r.get::<_, String>(6))
        );
        if let Some(t) = r.get::<_, Option<String>>(7) {
            fields += &format!(",\"releasedAt\":{}", super::quote(&t));
        }
        if let Some(n) = r.get::<_, Option<i64>>(8) {
            fields += &format!(",\"releasedBy\":{n}");
        }
        fields += &format!(",\"channels\":{}}}", r.get::<_, i64>(9));
        out.push(fields);
    }
    Ok(super::finish(format!("[{}]", out.join(","))))
}
pub async fn audit(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    action: &str,
    kind: &str,
    target: i64,
    ip: &str,
    operation: [u8; 16],
) {
    use setjoin_pg::{ReceiptCommand, Type};
    let auth = super::scope(actor);
    let _=setjoin_pg::run_receipted_command(exec,ReceiptCommand{family:super::FAMILY,command:"chat.audit"},&super::envelope(&auth,operation,action),&auth,super::deadline(),
 "SELECT audit_write($2,$4,$5,$6,NULL,NULL,NULLIF($7,'')::inet,'','core') WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
 &[(&action,Type::TEXT),(&kind,Type::TEXT),(&target,Type::INT8),(&ip,Type::TEXT)],|_|Ok::<_,StatementFailure>(())).await;
}
pub async fn preview(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows=exec.read("SELECT channel_id,purged_count,id_from,id_to,retention_days FROM chat_purge_expired(100000,TRUE)",&[]).await?;
    let mut total = 0i64;
    let mut out = Vec::new();
    for r in rows {
        let count = r.get::<_, i32>(1);
        total += i64::from(count);
        out.push(format!("{{\"channelId\":{},\"purgedCount\":{count},\"idFrom\":{},\"idTo\":{},\"retentionDays\":{}}}",r.get::<_,i64>(0),r.get::<_,i64>(2),r.get::<_,i64>(3),r.get::<_,i32>(4)));
    }
    Ok(super::finish(format!(
        "{{\"channels\":[{}],\"totalChannels\":{},\"totalMessages\":{total}}}",
        out.join(","),
        out.len()
    )))
}

const OVERVIEW: &str = r#"
SELECT
  COALESCE((SELECT jsonb_agg(jsonb_build_object('id', ch.id, 'kind', ch.kind, 'name', ch.name,
              'legalHoldReason', ch.legal_hold_reason, 'caseHolds', ch.case_holds) ORDER BY ch.id)
    FROM (
      SELECT c.id, c.kind, c.name, c.legal_hold_reason,
             (SELECT jsonb_agg(jsonb_build_object('caseId', h.case_id, 'holdId', h.id))
                FROM chat_case_hold_channels hc
                JOIN chat_case_holds h ON h.id = hc.hold_id AND h.released_at IS NULL
               WHERE hc.channel_id = c.id) AS case_holds
        FROM chat_channels c
       WHERE chat_hold_active(c.id)          -- REPOINTED (A4b spec §2.3)
       -- ponytail: chat_hold_active(c.id) per row over all channels — a
       -- per-row DEFINER call at admin-console frequency; inline the
       -- two-arm predicate as a set query if a 100k-channel org ever drags.
    ) ch), '[]'::jsonb),
  COALESCE((SELECT jsonb_agg(jsonb_build_object('id', id, 'kind', kind, 'name', name, 'retentionDays', retention_days, 'wormMode', worm_mode) ORDER BY id)
              FROM chat_channels WHERE classification = 'gxp'), '[]'::jsonb),
  COALESCE((SELECT jsonb_agg(jsonb_build_object('id', id, 'kind', kind, 'name', name, 'retentionDays', retention_days) ORDER BY id)
              FROM chat_channels WHERE retention_days IS NOT NULL AND classification = 'regular'), '[]'::jsonb)"#;
pub async fn overview(exec: &ScopedExecutor, next: &str) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            &format!("SELECT a::text,b::text,c::text FROM ({OVERVIEW}) AS t(a,b,c)"),
            &[],
        )
        .await?;
    let r = rows.first().ok_or_else(super::invalid)?;
    let last=exec.read("SELECT (after_state->>'channels')::int,(after_state->>'messages')::int,(after_state->>'drained')::boolean,to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM admin_audit_log WHERE action='chat.purge_run' ORDER BY id DESC LIMIT 1",&[]).await?;
    let last = if let Some(r) = last.first() {
        format!(
            "{{\"channels\":{},\"drained\":{},\"messages\":{},\"occurredAt\":{}}}",
            r.try_get::<_, i32>(0).map_err(|_| super::invalid())?,
            r.try_get::<_, bool>(2).map_err(|_| super::invalid())?,
            r.try_get::<_, i32>(1).map_err(|_| super::invalid())?,
            super::quote(&r.get::<_, String>(3))
        )
    } else {
        "null".into()
    };
    Ok(super::finish(format!("{{\"channelsUnderHold\":{},\"channelsWithOverrides\":{},\"gxpChannels\":{},\"lastPurgeRun\":{last},\"nextRunAt\":{}}}",r.get::<_,String>(0),r.get::<_,String>(2),r.get::<_,String>(1),super::quote(next))))
}

/// One reducer owns policy data and Go's best-effort core audit.
pub async fn policy(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    action: &str,
    id: i64,
    data: &serde_json::Value,
    confirm: &str,
    ip: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    use setjoin_pg::{ReceiptCommand, Type};
    let auth = super::scope(actor);
    let signed = !actor.signed_admin();
    let data = data.to_string();
    setjoin_pg::run_receipted_command(exec,ReceiptCommand{family:super::FAMILY,command:"chat.policy"},&super::envelope(&auth,operation,&serde_json::json!([action,id,data,confirm]).to_string()),&auth,super::deadline(),
 "SELECT rust_compliance_chat_policy($2,$4,$5,$6,$7::text::jsonb,$8,$9)::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
 &[(&signed,Type::BOOL),(&action,Type::TEXT),(&id,Type::INT8),(&data,Type::TEXT),(&confirm,Type::TEXT),(&ip,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).and_then(|raw|serde_json::from_str(&raw).ok()).ok_or_else(super::invalid)).await
}

pub async fn command(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    action: &str,
    data: &serde_json::Value,
    ip: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    use setjoin_pg::{ReceiptCommand, Type};
    let auth = super::scope(actor);
    let signed = !actor.signed_admin();
    let data = data.to_string();
    setjoin_pg::run_receipted_command(exec,ReceiptCommand{family:super::FAMILY,command:"chat.oversight"},&super::envelope(&auth,operation,&serde_json::json!([action,data]).to_string()),&auth,super::deadline(),
 "SELECT rust_compliance_chat_command($2,$4,$5,$6::text::jsonb,$7)::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
 &[(&signed,Type::BOOL),(&action,Type::TEXT),(&data,Type::TEXT),(&ip,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).and_then(|raw|serde_json::from_str(&raw).ok()).ok_or_else(super::invalid)).await
}
