//! MAM console. Registry ids and authoritative device ids are distinct namespaces.
use super::{command, deadline, done, envelope, invalid, sql, StatementFailure};
use serde_json::{json, Value};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, Rejection};

/// Both Posture C policy layers under the verified admin proof.
pub async fn list_policies(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::MAM_LIST_POLICIES, &[])
        .await?;
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
    factory: &TxFactory,
    user: &UserPrincipal,
    policies: &Option<serde_json::Map<String, Value>>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let payload = json!(policies.as_ref().cloned().unwrap_or_default()).to_string();
    let env = envelope(user.user(), user.generation(), operation, &payload);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MAM_SET_GLOBAL,
            &[&payload],
            Some(command("mam_global_policy_set")),
            |rows| {
                rows.first()
                    .ok_or_else(invalid)?
                    .try_get(0)
                    .map_err(|_| invalid())
            },
        )
        .await
}

/// A separate transaction, matching Go's checked post-commit notification.
pub async fn notify(
    factory: &TxFactory,
    user: &UserPrincipal,
    device: i64,
    version: i64,
    action: &str,
    mut operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    operation[15] ^= 0x80;
    let payload = format!(
        "{{\"device_id\":{device},\"version\":{version},\"action\":{}}}",
        super::s(action)
    );
    let env = envelope(user.user(), user.generation(), operation, &payload);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MAM_NOTIFY,
            &[&payload],
            Some(command("mam_policy_notify")),
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

#[allow(clippy::type_complexity)]
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
    factory: &TxFactory,
    user: &UserPrincipal,
    group: &str,
    id: i64,
    policies: &Option<serde_json::Map<String, Value>>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let payload = json!(policies.as_ref().cloned().unwrap_or_default()).to_string();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{group}\n{id}\n{payload}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MAM_SET_GROUP,
            &[&group, &id, &payload],
            Some(command("mam_group_policy_set")),
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

pub async fn delete_group(
    factory: &TxFactory,
    user: &UserPrincipal,
    group: &str,
    id: i64,
    key: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{group}\n{id}\n{key}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MAM_DELETE_GROUP,
            &[&group, &id, &key],
            Some(command("mam_group_policy_delete")),
            |rows| Ok(!rows.is_empty()),
        )
        .await
}

/// Stable registry ids, enriched only by state with the same owner/fingerprint.
pub async fn list_devices(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    domain_scope: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::MAM_LIST_DEVICES, &[&domain_scope])
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
        devices.push(format!(
            "{{\"id\":{id},\"user_id\":{user},\"platform\":{},\"device_name\":{},\"os_version\":{},\"app_version\":{},\"compliance_status\":{},\"last_checkin_at\":{},\"wipe_requested\":{wipe},\"created_at\":{}}}",
            super::s(&text(2)?),
            super::s(&text(3)?),
            super::s(&text(4)?),
            super::s(&text(5)?),
            super::s(&text(6)?),
            date(7)?,
            date(9)?
        ));
    }
    Ok(done(format!(
        "{{\"devices\":[{}],\"total\":{}}}",
        devices.join(","),
        devices.len()
    )))
}

/// None hides missing/out-of-scope registry ids alike; Some(0) is registry-only.
pub async fn resolve(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    registry: i64,
    domain_scope: i64,
) -> Result<Option<i64>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::MAM_RESOLVE, &[&registry, &domain_scope])
        .await?;
    rows.first()
        .map(|row| row.try_get(0).map_err(|_| invalid()))
        .transpose()
}

pub async fn events(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    device: i64,
    limit: i64,
    domain_scope: i64,
) -> Result<String, StatementFailure> {
    if device == 0 {
        return Ok("{\"events\":[],\"total\":0}\n".into());
    }
    let rows = factory
        .run_admin_read_contract(proof, &sql::MAM_EVENTS, &[&device, &limit, &domain_scope])
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
#[allow(clippy::too_many_arguments)]
pub async fn log_event(
    factory: &TxFactory,
    user: &UserPrincipal,
    device: i64,
    domain_scope: i64,
    event: &str,
    severity: &str,
    details: &Value,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let details = details.to_string();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{device}\n{domain_scope}\n{event}\n{severity}\n{details}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MAM_LOG_EVENT,
            &[&device, &event, &severity, &details, &domain_scope],
            Some(command("mam_device_event")),
            |rows| Ok(!rows.is_empty()),
        )
        .await
}

pub async fn set_device(
    factory: &TxFactory,
    user: &UserPrincipal,
    device: i64,
    domain_scope: i64,
    policies: &Option<serde_json::Map<String, Value>>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let payload = json!(policies.as_ref().cloned().unwrap_or_default()).to_string();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{device}\n{domain_scope}\n{payload}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MAM_SET_DEVICE,
            &[&device, &domain_scope, &payload],
            Some(command("mam_device_policy_set")),
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

pub fn out_of_scope(error: &Rejection<StatementFailure>) -> bool {
    matches!(error, Rejection::Statement(e) | Rejection::Body(e) if e.sqlstate.as_deref() == Some("BZ081"))
}

pub async fn delete_device(
    factory: &TxFactory,
    user: &UserPrincipal,
    device: i64,
    domain_scope: i64,
    key: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{device}\n{domain_scope}\n{key}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MAM_DELETE_DEVICE,
            &[&device, &key, &domain_scope],
            Some(command("mam_device_policy_delete")),
            |rows| Ok(!rows.is_empty()),
        )
        .await
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
