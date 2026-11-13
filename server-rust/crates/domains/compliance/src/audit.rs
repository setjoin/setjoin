//! Frozen-Go global audit console reads and policy changes.
use super::{finish, invalid, quote};
use setjoin_pg::{ScopedExecutor, StatementFailure};
pub async fn policy(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT level,reason_required_areas FROM audit_policy WHERE id=1",
            &[],
        )
        .await?;
    let row = rows.first().ok_or_else(invalid)?;
    let level: String = row.try_get(0).map_err(|_| invalid())?;
    let areas: Option<Vec<String>> = row.try_get(1).map_err(|_| invalid())?;
    Ok(finish(format!(
        "{{\"level\":{},\"reasonRequiredAreas\":{}}}",
        quote(&level),
        serde_json::to_string(&areas.unwrap_or_default()).expect("areas")
    )))
}
pub async fn reason_required(exec: &ScopedExecutor) -> bool {
    exec.read(
        "SELECT reason_required_areas FROM audit_policy WHERE id=1",
        &[],
    )
    .await
    .ok()
    .and_then(|rows| {
        rows.first()
            .and_then(|r| r.try_get::<_, Option<Vec<String>>>(0).ok())
            .flatten()
    })
    .is_some_and(|areas| areas.iter().any(|s| s == "audit"))
}
pub async fn missing_reason(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    ip: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    use setjoin_pg::Type;
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"audit.reason_missing"},&super::envelope(&auth,operation,"audit.export"),&auth,super::deadline(),
 "SELECT audit_write($2,'sensitive_action.reason_missing','',NULL,NULL,NULL,$4::text::inet,'audit.export','core') WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",&[(&ip,Type::TEXT)],|rows|if rows.len()==1{Ok(())}else{Err(invalid())}).await
}
pub async fn put(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    level: &str,
    areas: &Vec<String>,
    reason: &str,
    ip: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<bool, StatementFailure> {
    use setjoin_pg::Type;
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"audit.policy.set"},&super::envelope(&auth,operation,&serde_json::json!([level,areas,reason,ip]).to_string()),&auth,super::deadline(),
 "SELECT rust_compliance_audit_policy_set($2,$4,$5,$6,$7) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
 &[(&level,Type::TEXT),(areas,Type::TEXT_ARRAY),(&reason,Type::TEXT),(&ip,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
}
pub fn policy_body(level: &str, areas: &[String]) -> String {
    finish(format!(
        "{{\"level\":{},\"reasonRequiredAreas\":{}}}",
        quote(level),
        serde_json::to_string(areas).expect("areas")
    ))
}

/// PostgreSQL jsonb text is valid JSON. Compact outside strings while retaining
/// its key order, as Go's json.RawMessage encoder does.
fn compact(raw: &str) -> String {
    let (mut quoted, mut escape) = (false, false);
    let mut out = String::new();
    for c in raw.chars() {
        if quoted {
            out.push(c);
            if escape {
                escape = false
            } else if c == '\\' {
                escape = true
            } else if c == '"' {
                quoted = false
            }
        } else if c == '"' {
            quoted = true;
            out.push(c)
        } else if !c.is_ascii_whitespace() {
            out.push(c)
        }
    }
    out
}
pub struct Query {
    pub action: String,
    pub user: String,
    pub target: String,
    pub text: String,
    pub limit: i64,
    pub offset: i64,
}
pub async fn list(exec: &ScopedExecutor, q: &Query) -> Result<String, StatementFailure> {
    use setjoin_pg::Type;
    let mut values = Vec::new();
    let mut predicate = "1=1".to_owned();
    for (column, value) in [
        ("al.action", &q.action),
        ("al.user_id", &q.user),
        ("al.target_type", &q.target),
    ] {
        if !value.is_empty() {
            values.push(value.clone());
            predicate += &format!(
                " AND {column}=(($1::text[])[{}]){}",
                values.len(),
                if column == "al.user_id" {
                    "::bigint"
                } else {
                    ""
                }
            );
        }
    }
    if !q.text.is_empty() {
        values.push(format!("%{}%", q.text));
        predicate += &format!(
            " AND (al.notes ILIKE ($1::text[])[{n}] OR al.action ILIKE ($1::text[])[{n}])",
            n = values.len()
        );
    }
    let from = "FROM admin_audit_log al LEFT JOIN users u ON u.id=al.user_id";
    let count = exec
        .read(
            &format!("SELECT count(*) {from} WHERE {predicate}"),
            &[(&values, Type::TEXT_ARRAY)],
        )
        .await?;
    let total: i64 = count
        .first()
        .ok_or_else(invalid)?
        .try_get(0)
        .map_err(|_| invalid())?;
    let rows=exec.read_iterated(&format!("SELECT al.id,to_char(al.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),al.user_id,COALESCE(u.email,'system'),COALESCE(al.ip::text,''),al.action,al.target_type,al.target_id,al.before_state::text,al.after_state::text,COALESCE(al.notes,'') {from} WHERE {predicate} ORDER BY al.occurred_at DESC LIMIT $2 OFFSET $3"),&[(&values,Type::TEXT_ARRAY),(&q.limit,Type::INT8),(&q.offset,Type::INT8)]).await?;
    let mut items = Vec::new();
    for r in rows {
        let entry = (|| {
            let id: i64 = r.try_get(0).ok()?;
            let time: String = r.try_get(1).ok()?;
            let user: Option<i64> = r.try_get(2).ok()?;
            let email: String = r.try_get(3).ok()?;
            let ip: String = r.try_get(4).ok()?;
            let action: String = r.try_get(5).ok()?;
            let target: Option<String> = r.try_get(6).ok()?;
            let target_id: Option<i64> = r.try_get(7).ok()?;
            let before: Option<String> = r.try_get(8).ok()?;
            let after: Option<String> = r.try_get(9).ok()?;
            let notes: String = r.try_get(10).ok()?;
            let mut entry = format!("{{\"id\":{id},\"occurredAt\":{}", quote(&time));
            if let Some(n) = user {
                entry += &format!(",\"userId\":{n}");
            }
            entry += &format!(
                ",\"userEmail\":{},\"ip\":{},\"action\":{}",
                quote(&email),
                quote(&ip),
                quote(&action)
            );
            if let Some(s) = target {
                entry += &format!(",\"targetType\":{}", quote(&s));
            }
            if let Some(n) = target_id {
                entry += &format!(",\"targetId\":{n}");
            }
            if let Some(s) = before {
                entry += &format!(",\"beforeState\":{}", compact(&s));
            }
            if let Some(s) = after {
                entry += &format!(",\"afterState\":{}", compact(&s));
            }
            if !notes.is_empty() {
                entry += &format!(",\"notes\":{}", quote(&notes));
            }
            entry.push('}');
            Some(entry)
        })();
        if let Some(entry) = entry {
            items.push(entry)
        }
    }
    Ok(finish(format!(
        "{{\"items\":{},\"total\":{total}}}",
        if items.is_empty() {
            "null".into()
        } else {
            format!("[{}]", items.join(","))
        }
    )))
}
pub async fn csv(exec: &ScopedExecutor) -> String {
    let Ok(rows)=exec.read_iterated("SELECT al.id,to_char(al.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),COALESCE(u.email,'system'),COALESCE(al.ip::text,''),al.action,al.target_type,al.target_id,COALESCE(al.notes,'') FROM admin_audit_log al LEFT JOIN users u ON u.id=al.user_id ORDER BY al.occurred_at DESC LIMIT 10000",&[]).await else{return String::new();};
    let mut out = setjoin_contracts::csv::record(
        &[
            "ID",
            "Timestamp",
            "User",
            "IP",
            "Action",
            "Target Type",
            "Target ID",
            "Notes",
        ]
        .map(str::to_owned),
    );
    for row in rows {
        let cells = (|| {
            let id: i64 = row.try_get(0).ok()?;
            let time: String = row.try_get(1).ok()?;
            let user: String = row.try_get(2).ok()?;
            let ip: String = row.try_get(3).ok()?;
            let action: String = row.try_get(4).ok()?;
            // Go scans target_type into string, so a SQL NULL skips the entire row.
            let target: String = row.try_get(5).ok()?;
            let target_id: Option<i64> = row.try_get(6).ok()?;
            let notes: String = row.try_get(7).ok()?;
            Some([
                id.to_string(),
                time,
                user,
                ip,
                action,
                target,
                target_id.unwrap_or(0).to_string(),
                notes,
            ])
        })();
        if let Some(cells) = cells {
            let cells = cells
                .iter()
                .map(|s| setjoin_contracts::csv::escape_formula(s))
                .collect::<Vec<_>>();
            out += &setjoin_contracts::csv::record(&cells);
        } else {
            break;
        }
    }
    out
}
pub async fn verify(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    from: Option<i64>,
    to: Option<i64>,
) -> Result<String, StatementFailure> {
    use setjoin_pg::Type;
    let rows=exec.read_scoped(&super::scope(actor),"SELECT row_id,valid,to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),action FROM verify_audit_chain($1::bigint,$2::bigint)",&[(&from,Type::INT8),(&to,Type::INT8)]).await?;
    let mut chain = Vec::new();
    for r in rows {
        let (Ok(id), Ok(valid), Ok(time), Ok(action)) = (
            r.try_get::<_, i64>(0),
            r.try_get::<_, bool>(1),
            r.try_get::<_, String>(2),
            r.try_get::<_, String>(3),
        ) else {
            break;
        };
        chain.push(format!(
            "{{\"id\":{id},\"valid\":{valid},\"occurredAt\":{},\"action\":{}}}",
            quote(&time),
            quote(&action)
        ));
    }
    Ok(finish(format!(
        "{{\"chain\":{}}}",
        if chain.is_empty() {
            "null".into()
        } else {
            format!("[{}]", chain.join(","))
        }
    )))
}
