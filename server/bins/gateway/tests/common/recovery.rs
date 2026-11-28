//! Complete rows for recovery mutations with stable row sets. Audit and outbound
//! effects are observed separately by each HTTP oracle. Every column participates.
pub static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn rows(
    owner: &tokio_postgres::Client,
    session: &str,
    mailbox: i64,
) -> Result<serde_json::Value, super::BoxError> {
    let mut tables = serde_json::Map::new();
    for (table,predicate,order) in [
        ("mail_recovery_upload_sessions","id=$1::text::uuid AND $2::bigint IS NOT NULL","id"),
        ("mail_recovery_upload_items","session_id=$1::text::uuid AND $2::bigint IS NOT NULL","item_id"),
        ("mail_recovery_upload_chunks","session_id=$1::text::uuid AND $2::bigint IS NOT NULL","item_id,start_offset"),
        ("mail_recovery_quarantine_artifacts","session_id=$1::text::uuid AND $2::bigint IS NOT NULL","id"),
        ("mail_recovery_incidents","id=(SELECT incident_id FROM mail_recovery_upload_sessions WHERE id=$1::text::uuid) AND $2::bigint IS NOT NULL","id"),
        ("mailboxes","id=$2 AND $1::text IS NOT NULL","id"),
        ("messages","mailbox_id=$2 AND $1::text IS NOT NULL","id,received_at"),
        ("tags","mailbox_id=$2 AND $1::text IS NOT NULL","id"),
        ("jmap_changes_journal","mailbox_id=$2 AND $1::text IS NOT NULL","state_seq,entity_id"),
    ] {
        let sql = format!("SELECT to_jsonb(t)::text FROM {table} t WHERE {predicate} ORDER BY {order}");
        let mut rows = Vec::new();
        for row in owner.query(&sql,&[&session,&mailbox]).await? {
            rows.push(serde_json::from_str::<serde_json::Value>(&row.get::<_,String>(0))?);
        }
        tables.insert(table.into(),serde_json::json!(rows));
    }
    Ok(tables.into())
}

pub fn diff(
    before: &serde_json::Value,
    after: &serde_json::Value,
    actor: i64,
) -> Result<serde_json::Value, super::BoxError> {
    let mut effects = Vec::new();
    for (table, old) in before.as_object().ok_or("invalid row snapshot")? {
        let old = old.as_array().ok_or("invalid row array")?;
        let new = after[table].as_array().ok_or("missing row array")?;
        if old.len() != new.len() {
            return Err(format!(
                "recovery command changed {table} row cardinality: {} -> {}",
                old.len(),
                new.len()
            )
            .into());
        }
        for (index, (old, new)) in old.iter().zip(new).enumerate() {
            let mut columns = serde_json::Map::new();
            for (name, left) in old.as_object().ok_or("invalid old row")? {
                let right = &new[name];
                if left != right {
                    if name == "fork_consented_by" && right.as_i64() != Some(actor) {
                        return Err("fork consent actor differs from verified caller".into());
                    }
                    let normalize = |value: &serde_json::Value| {
                        if matches!(name.as_str(), "updated_at" | "fork_consented_at")
                            && value.is_string()
                        {
                            serde_json::json!("<timestamp>")
                        } else if name == "fork_consented_by" && value.is_i64() {
                            serde_json::json!("<actor>")
                        } else {
                            value.clone()
                        }
                    };
                    columns.insert(
                        name.clone(),
                        serde_json::json!({"before":normalize(left),"after":normalize(right)}),
                    );
                }
            }
            if !columns.is_empty() {
                effects.push(serde_json::json!({"table":table,"row":index,"change":"update","columns":columns}));
            }
        }
    }
    Ok(effects.into())
}
