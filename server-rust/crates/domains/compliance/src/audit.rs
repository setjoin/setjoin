//! Global audit console reads and policy changes via `TxFactory` (`AdminReadTx` / `AdminWriteTx`).
use super::{command, deadline, envelope, finish, invalid, quote, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

pub async fn policy(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::AUDIT_POLICY_GET, &[])
        .await?;
    let row = rows.first().ok_or_else(invalid)?;
    let level: String = row.try_get(0).map_err(|_| invalid())?;
    let areas: Option<Vec<String>> = row.try_get(1).map_err(|_| invalid())?;
    Ok(finish(format!(
        "{{\"level\":{},\"reasonRequiredAreas\":{}}}",
        quote(&level),
        serde_json::to_string(&areas.unwrap_or_default()).unwrap_or_else(|_| "[]".into())
    )))
}

pub async fn reason_required(factory: &TxFactory, admin: &AdminPermissionProof) -> bool {
    factory
        .run_admin_read_contract(admin, &sql::AUDIT_REASON_REQUIRED, &[])
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
    factory: &TxFactory,
    user: &UserPrincipal,
    admin: &AdminPermissionProof,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor_id = admin.actor().get();
    let env = envelope(user.user(), user.generation(), operation, "audit.export");
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::AUDIT_MISSING_REASON,
            &[&actor_id, &ip],
            Some(command("audit.reason_missing")),
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

pub async fn put(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    level: &str,
    areas: &Vec<String>,
    reason: &str,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &serde_json::json!([level, areas, reason, ip]).to_string(),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::AUDIT_POLICY_SET,
            &[&level, areas, &reason, &ip],
            Some(command("audit.policy.set")),
            |rows, audited| {
                if audited {
                    rows.first()
                        .and_then(|r| r.try_get(0).ok())
                        .ok_or_else(invalid)
                } else {
                    Ok(false)
                }
            },
        )
        .await
}

pub fn policy_body(level: &str, areas: &[String]) -> String {
    finish(format!(
        "{{\"level\":{},\"reasonRequiredAreas\":{}}}",
        quote(level),
        serde_json::to_string(areas).unwrap_or_else(|_| "[]".into())
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
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                quoted = false;
            }
        } else if c == '"' {
            quoted = true;
            out.push(c);
        } else if !c.is_ascii_whitespace() {
            out.push(c);
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

pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    q: &Query,
) -> Result<String, StatementFailure> {
    let pattern = if q.text.is_empty() {
        String::new()
    } else {
        format!("%{}%", q.text)
    };
    let count = factory
        .run_admin_read_contract(
            admin,
            &sql::AUDIT_LIST_COUNT,
            &[&q.action, &q.user, &q.target, &pattern],
        )
        .await?;
    let total: i64 = count
        .first()
        .ok_or_else(invalid)?
        .try_get(0)
        .map_err(|_| invalid())?;
    let mut tx = factory.begin_admin_read(admin).await?;
    let rows = tx
        .query_iterated_contract(
            &sql::AUDIT_LIST_ROWS,
            &[&q.action, &q.user, &q.target, &pattern, &q.limit, &q.offset],
        )
        .await?;
    tx.finish().await?;
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
            items.push(entry);
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

pub async fn csv(factory: &TxFactory, admin: &AdminPermissionProof) -> String {
    let Ok(mut tx) = factory.begin_admin_read(admin).await else {
        return String::new();
    };
    let Ok(rows) = tx.query_iterated_contract(&sql::AUDIT_CSV, &[]).await else {
        let _ = tx.finish().await;
        return String::new();
    };
    let _ = tx.finish().await;
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
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    from: Option<i64>,
    to: Option<i64>,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::AUDIT_VERIFY, &[&from, &to])
        .await?;
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
