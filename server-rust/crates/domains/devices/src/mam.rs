//! MAM console. Registry ids and authoritative device ids are distinct namespaces.
use super::{done, invalid, nano, scope, StatementFailure};
use serde_json::{json, Value};
use setjoin_authz::AuthContext;
use setjoin_pg::ScopedExecutor;

/// Both Posture C policy layers under the authenticated admin GUC.
pub async fn list_policies(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let sql=format!("SELECT (SELECT jsonb_agg(jsonb_build_object('id',id,'policy_key',policy_key,'policy_value',policy_value,'updated_at',{}) ORDER BY policy_key)::text FROM device_policy WHERE device_id IS NULL), (SELECT jsonb_agg(jsonb_build_object('id',id,'policy_key',policy_key,'policy_value',policy_value,'group_type',group_type,'group_id',group_id,'updated_at',{}) ORDER BY group_type,group_id,policy_key)::text FROM device_policy_groups)",nano("updated_at"),nano("updated_at"));
    let rows = exec.read_scoped(&scope(actor), &sql, &[]).await?;
    let row = rows.first().ok_or_else(invalid)?;
    let parse = |i| -> Result<Value, StatementFailure> {
        let text: Option<String> = row.try_get(i).map_err(|_| invalid())?;
        text.map(|s| serde_json::from_str(&s).map_err(|_| invalid()))
            .unwrap_or(Ok(Value::Null))
    };
    Ok(done(
        json!({"global":parse(0)?,"groups":parse(1)?}).to_string(),
    ))
}

use super::{command, deadline, envelope};
use setjoin_pg::{CommandOutcome, Type};

/// Go's map[string]string decoder: first JSON value, case-folded field name,
/// null map/values, and duplicate fields retain encoding/json's map merge.
pub fn policies(body: &[u8]) -> Result<Option<serde_json::Map<String, Value>>, String> {
    use super::gojson::{self, J};
    let value = gojson::first(body)?;
    let fields = match value {
        J::Null => return Ok(None),
        J::Obj(fields) => fields,
        _ => return Err("invalid JSON".into()),
    };
    let mut out = None;
    for (key, value) in fields {
        if gojson::fold(&key) != "policies" {
            continue;
        }
        match value {
            J::Null => out = None,
            J::Obj(pairs) => {
                let map = out.get_or_insert_with(serde_json::Map::new);
                for (k, v) in pairs {
                    match v {
                        J::Str(s) => {
                            map.insert(k, Value::String(s));
                        }
                        J::Null => {
                            map.insert(k, Value::String(String::new()));
                        }
                        _ => return Err("invalid JSON".into()),
                    }
                }
            }
            _ => return Err("invalid JSON".into()),
        }
    }
    Ok(out)
}

pub async fn set_global(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    policies: &Option<serde_json::Map<String, Value>>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    let payload = json!(policies.as_ref().cloned().unwrap_or_default()).to_string();
    setjoin_pg::run_receipted_command(exec,command("mam_global_policy_set"),&envelope(&auth,operation,&payload),&auth,deadline(),
        "SELECT rust_mam_global_policy_set($4::text::jsonb) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&payload,Type::TEXT)],|rows|rows.first().ok_or_else(invalid)?.try_get(0).map_err(|_|invalid())).await
}
/// A separate transaction, matching Go's checked post-commit notification.
pub async fn notify(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    device: i64,
    version: i64,
    action: &str,
    mut operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    operation[15] ^= 0x80;
    let auth = scope(actor);
    let payload = format!(
        "{{\"device_id\":{device},\"version\":{version},\"action\":{}}}",
        super::s(action)
    );
    setjoin_pg::run_receipted_command(exec,command("mam_policy_notify"),&envelope(&auth,operation,&payload),&auth,deadline(),
        "SELECT pg_notify('device_policy',$4::text) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&payload,Type::TEXT)],|rows|if rows.len()==1 {Ok(())}else{Err(invalid())}).await
}

pub fn group(body: &[u8]) -> Result<(String, i64, Option<serde_json::Map<String, Value>>), String> {
    use super::gojson::{self, Kind, V};
    // Go ignores null for these non-pointer scalar fields, retaining an
    // earlier duplicate's value. Keep the policy-map decoder on the original body.
    let mut value = gojson::first(body)?;
    if let gojson::J::Obj(ref mut fields) = value {
        fields.retain(|(_, v)| !matches!(v, gojson::J::Null));
    }
    let fields = gojson::fields(
        &value,
        &[("group_type", Kind::Str), ("group_id", Kind::Int64)],
        "",
        "",
    )?;
    let group = match &fields[0] {
        Some(V::Str(s)) => s.clone(),
        _ => String::new(),
    };
    let id = match fields[1] {
        Some(V::Int(n)) => n,
        _ => 0,
    };
    Ok((group, id, policies(body)?))
}
pub async fn set_group(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    group: &str,
    id: i64,
    policies: &Option<serde_json::Map<String, Value>>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    let payload = json!(policies.as_ref().cloned().unwrap_or_default()).to_string();
    setjoin_pg::run_receipted_command(exec,command("mam_group_policy_set"),&envelope(&auth,operation,&format!("{group}\n{id}\n{payload}")),&auth,deadline(),
        "SELECT rust_mam_group_policy_set($4::text,$5::bigint,$6::text::jsonb) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&group,Type::TEXT),(&id,Type::INT8),(&payload,Type::TEXT)],|rows|if rows.len()==1 {Ok(())}else{Err(invalid())}).await
}

pub async fn delete_group(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    group: &str,
    id: i64,
    key: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(exec,command("mam_group_policy_delete"),&envelope(&auth,operation,&format!("{group}\n{id}\n{key}")),&auth,deadline(),
        "DELETE FROM device_policy_groups WHERE group_type=$4::text AND group_id=$5::bigint AND policy_key=$6::text AND $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' RETURNING id",
        &[(&group,Type::TEXT),(&id,Type::INT8),(&key,Type::TEXT)],|rows|Ok(!rows.is_empty())).await
}

/// Stable registry ids, enriched only by state with the same owner/fingerprint.
pub async fn list_devices(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    domain_scope: i64,
) -> Result<String, StatementFailure> {
    let sql=format!("SELECT r.id,r.user_id,COALESCE(NULLIF(m.platform,''),'unknown'),COALESCE(m.device_name,''),COALESCE(m.os_version,''),COALESCE(m.app_version,''),COALESCE(NULLIF(m.compliance_status,''),'unknown'),{},(m.wipe_requested IS NOT NULL AND m.wipe_requested NOT IN ('','none')),{} FROM device_registry r LEFT JOIN mdm_device_state m ON m.device_id=r.device_fingerprint AND m.user_id=r.user_id WHERE ($1::bigint<=0 OR r.user_id IN (SELECT id FROM users WHERE domain_id=$1)) ORDER BY COALESCE(m.last_checkin_at,r.last_seen) DESC NULLS LAST,r.id",nano("COALESCE(m.last_checkin_at,r.last_seen)"),nano("COALESCE(m.created_at,r.first_seen)"));
    let rows = exec
        .read_scoped(&scope(actor), &sql, &[(&domain_scope, Type::INT8)])
        .await?;
    let mut devices = vec![];
    for row in &rows {
        let text =
            |i| -> Result<String, StatementFailure> { row.try_get(i).map_err(|_| invalid()) };
        let date = |i| -> Result<String, StatementFailure> {
            let v: Option<String> = row.try_get(i).map_err(|_| invalid())?;
            Ok(v.as_deref().map(super::s).unwrap_or_else(|| "null".into()))
        };
        let id: i64 = row.try_get(0).map_err(|_| invalid())?;
        let user: i64 = row.try_get(1).map_err(|_| invalid())?;
        let wipe: bool = row.try_get(8).map_err(|_| invalid())?;
        devices.push(format!("{{\"id\":{id},\"user_id\":{user},\"platform\":{},\"device_name\":{},\"os_version\":{},\"app_version\":{},\"compliance_status\":{},\"last_checkin_at\":{},\"wipe_requested\":{wipe},\"created_at\":{}}}",super::s(&text(2)?),super::s(&text(3)?),super::s(&text(4)?),super::s(&text(5)?),super::s(&text(6)?),date(7)?,date(9)?));
    }
    Ok(done(format!(
        "{{\"devices\":[{}],\"total\":{}}}",
        devices.join(","),
        devices.len()
    )))
}

/// None hides missing/out-of-scope registry ids alike; Some(0) is registry-only.
pub async fn resolve(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    registry: i64,
    domain_scope: i64,
) -> Result<Option<i64>, StatementFailure> {
    let rows=exec.read_scoped(&scope(actor),
        "SELECT COALESCE(dev.id,0) FROM device_registry r LEFT JOIN devices dev ON dev.user_id=r.user_id AND dev.fingerprint=r.device_fingerprint::text WHERE r.id=$1 AND ($2::bigint<=0 OR r.user_id IN (SELECT id FROM users WHERE domain_id=$2))",
        &[(&registry,Type::INT8),(&domain_scope,Type::INT8)]).await?;
    rows.first()
        .map(|row| row.try_get(0).map_err(|_| invalid()))
        .transpose()
}
pub async fn events(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    device: i64,
    limit: i64,
    domain_scope: i64,
) -> Result<String, StatementFailure> {
    if device == 0 {
        return Ok("{\"events\":[],\"total\":0}\n".into());
    }
    let sql=format!("SELECT e.device_id,e.event_type,e.severity,e.details::text,{} FROM device_events e WHERE e.device_id=$1 AND ($3::bigint<=0 OR EXISTS(SELECT 1 FROM devices dev JOIN users u ON u.id=dev.user_id WHERE dev.id=e.device_id AND u.domain_id=$3)) ORDER BY e.occurred_at DESC LIMIT $2",nano("e.occurred_at"));
    let rows = exec
        .read_scoped(
            &scope(actor),
            &sql,
            &[
                (&device, Type::INT8),
                (&limit, Type::INT8),
                (&domain_scope, Type::INT8),
            ],
        )
        .await?;
    let mut events = vec![];
    for row in &rows {
        let id: i64 = row.try_get(0).map_err(|_| invalid())?;
        let text =
            |i| -> Result<String, StatementFailure> { row.try_get(i).map_err(|_| invalid()) };
        let mut out = format!(
            "{{\"device_id\":{id},\"event_type\":{},\"severity\":{}",
            super::s(&text(1)?),
            super::s(&text(2)?)
        );
        let details: Option<String> = row.try_get(3).map_err(|_| invalid())?;
        if let Some(details) = details {
            let value: Value = serde_json::from_str(&details).map_err(|_| invalid())?;
            if let Value::Object(ref map) = value {
                if !map.is_empty() {
                    out.push_str(&format!(",\"details\":{}", event_details_json(&value)?));
                }
            } else if !value.is_null() {
                return Err(invalid());
            }
        }
        out.push_str(&format!(",\"occurred_at\":{}}}", super::s(&text(4)?)));
        events.push(out);
    }
    Ok(done(format!(
        "{{\"events\":[{}],\"total\":{}}}",
        events.join(","),
        events.len()
    )))
}

/// One evidence INSERT transaction, separately acknowledged before notification.
/// Domain scope is re-derived in this statement; it never trusts stale resolution.
pub async fn log_event(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    device: i64,
    domain_scope: i64,
    event: &str,
    severity: &str,
    details: &Value,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    let details = details.to_string();
    setjoin_pg::run_receipted_command(exec,command("mam_device_event"),&envelope(&auth,operation,&format!("{device}\n{domain_scope}\n{event}\n{severity}\n{details}")),&auth,deadline(),
        "INSERT INTO device_events(device_id,event_type,severity,details,occurred_at) SELECT $4::bigint,$5::text,$6::text,$7::text::jsonb,clock_timestamp() WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' AND ($8::bigint<=0 OR EXISTS(SELECT 1 FROM devices dev JOIN users u ON u.id=dev.user_id WHERE dev.id=$4 AND u.domain_id=$8)) RETURNING device_id",
        &[(&device,Type::INT8),(&event,Type::TEXT),(&severity,Type::TEXT),(&details,Type::TEXT),(&domain_scope,Type::INT8)],|rows|Ok(!rows.is_empty())).await
}

pub async fn set_device(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    device: i64,
    domain_scope: i64,
    policies: &Option<serde_json::Map<String, Value>>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    let payload = json!(policies.as_ref().cloned().unwrap_or_default()).to_string();
    setjoin_pg::run_receipted_command(exec,command("mam_device_policy_set"),&envelope(&auth,operation,&format!("{device}\n{domain_scope}\n{payload}")),&auth,deadline(),
        "SELECT rust_mam_device_policy_set($4::bigint,$5::bigint,$6::text::jsonb) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&device,Type::INT8),(&domain_scope,Type::INT8),(&payload,Type::TEXT)],|rows|if rows.len()==1 {Ok(())}else{Err(invalid())}).await
}
pub fn out_of_scope(error: &setjoin_pg::Rejection<StatementFailure>) -> bool {
    matches!(error,setjoin_pg::Rejection::Statement(e)|setjoin_pg::Rejection::Body(e) if e.sqlstate.as_deref()==Some("BZ081"))
}

pub async fn delete_device(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    device: i64,
    domain_scope: i64,
    key: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(exec,command("mam_device_policy_delete"),&envelope(&auth,operation,&format!("{device}\n{domain_scope}\n{key}")),&auth,deadline(),
        "DELETE FROM device_policy dp WHERE dp.device_id=$4::bigint AND dp.policy_key=$5::text AND ($6::bigint<=0 OR EXISTS(SELECT 1 FROM devices dev JOIN users u ON u.id=dev.user_id WHERE dev.id=dp.device_id AND u.domain_id=$6)) AND $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' RETURNING dp.id",
        &[(&device,Type::INT8),(&key,Type::TEXT),(&domain_scope,Type::INT8)],|rows|Ok(!rows.is_empty())).await
}

/// pgx decodes `map[string]any` numbers as float64 before encoding/json writes
/// the response. Use libstd's shortest float formatting with Go's fixed versus
/// exponent thresholds, including its explicit positive exponent sign.
fn event_details_json(value: &Value) -> Result<String, StatementFailure> {
    Ok(match value {
        Value::Number(number) => {
            let number = number
                .as_f64()
                .filter(|n| n.is_finite())
                .ok_or_else(invalid)?;
            let absolute = number.abs();
            if absolute != 0.0 && !(1e-6..1e21).contains(&absolute) {
                let text = format!("{number:e}");
                let (mantissa, exponent) = text.split_once('e').ok_or_else(invalid)?;
                let exponent: i32 = exponent.parse().map_err(|_| invalid())?;
                format!("{mantissa}e{exponent:+}")
            } else {
                format!("{number}")
            }
        }
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(event_details_json)
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| Ok(format!("{}:{}", super::s(key), event_details_json(value)?)))
                .collect::<Result<Vec<_>, StatementFailure>>()?
                .join(",")
        ),
        _ => value.to_string(),
    })
}
