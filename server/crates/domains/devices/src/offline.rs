//! Offline governance: the frozen Go handler's reducer and wire contracts.
use super::{invalid, sql, StatementFailure};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, Row};

pub async fn policies(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::OFFLINE_POLICIES, &[])
        .await?;
    rows.first()
        .ok_or_else(invalid)?
        .try_get(0)
        .map_err(|_| invalid())
}

pub async fn policy(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::OFFLINE_POLICY, &[&id])
        .await?;
    rows.first()
        .ok_or_else(invalid)?
        .try_get(0)
        .map_err(|_| invalid())
}

pub async fn enabled(
    factory: &TxFactory,
    _proof: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_public_read_contract(&sql::OFFLINE_ENABLED, &[])
        .await?;
    let value: bool = rows
        .first()
        .ok_or_else(invalid)?
        .try_get(0)
        .map_err(|_| invalid())?;
    Ok(format!("{{\"enabled\":{value}}}\n"))
}

/// The approval queue. Owner-approved security fix 2026-11-05 (#440): confined to the
/// devices of users inside the caller's `mam.read` reach (`rust_offline_devices_pending`);
/// frozen Go listed every domain's devices. The restored-bug mutant
/// (`offline-foreign-device`, test builds only) calls Go's unscoped reducer.
pub async fn pending(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let user = proof.actor().get();
    let contract = if setjoin_contracts::mutants::on("offline-foreign-device") {
        &sql::OFFLINE_PENDING_MUTANT
    } else {
        &sql::OFFLINE_PENDING
    };
    let rows = factory
        .run_admin_read_contract(proof, contract, &[&user])
        .await?;
    rows.first()
        .ok_or_else(invalid)?
        .try_get(0)
        .map_err(|_| invalid())
}

/// Preserve Go's duplicate non-pointer nulls, pointer resets and field folding.
fn decode(
    body: &[u8],
    schema: &[(&str, super::gojson::Kind)],
    strict: bool,
    one: bool,
    pointers: &[&str],
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    use super::gojson::{self, J, V};
    let mut value = if one {
        gojson::one(body)?
    } else {
        gojson::first(body)?
    };
    if let J::Obj(ref mut fields) = value {
        if strict
            && fields.iter().any(|(k, _)| {
                !schema
                    .iter()
                    .any(|(name, _)| gojson::fold(k) == gojson::fold(name))
            })
        {
            return Err("invalid JSON".into());
        }
        fields.retain(|(k, v)| {
            !matches!(v, J::Null) || pointers.iter().any(|p| gojson::fold(k) == *p)
        });
    }
    let fields = gojson::fields(&value, schema, "", "")?;
    let mut out = serde_json::Map::new();
    for ((name, _), v) in schema.iter().zip(fields) {
        if let Some(v) = v {
            out.insert(
                (*name).into(),
                match v {
                    V::Str(s) => s.into(),
                    V::Bool(b) => b.into(),
                    V::Int(n) => n.into(),
                },
            );
        }
    }
    Ok(out)
}

pub fn policy_input(body: &[u8]) -> Result<serde_json::Value, String> {
    use super::gojson::Kind::*;
    let schema = [
        ("name", Str),
        ("scope_type", Str),
        ("scope_id", Int64),
        ("enabled", Bool),
        ("max_offline_days", Int),
        ("require_approval", Bool),
        ("wipe_on_logout", Str),
        ("priority", Int),
        ("background_sync_allowed", Bool),
        ("automatic_network_max", Str),
        ("attachment_prefetch_max", Str),
        ("opportunistic_requires_charging", Bool),
        ("connectivity_sync_mode", Str),
    ];
    let mut out = decode(
        body,
        &schema,
        true,
        true,
        &[
            "scope_id",
            "background_sync_allowed",
            "opportunistic_requires_charging",
        ],
    )?;
    let connectivity = [
        "background_sync_allowed",
        "automatic_network_max",
        "attachment_prefetch_max",
        "opportunistic_requires_charging",
        "connectivity_sync_mode",
    ];
    let present = |key: &&str| {
        out.get(*key)
            .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
    };
    let any = connectivity.iter().any(present);
    let all = connectivity.iter().all(present);
    if any && !all {
        return Err("invalid JSON".into());
    }
    out.insert("connectivity_fields_provided".into(), all.into());
    for (k, default) in [
        ("name", ""),
        ("scope_type", ""),
        ("wipe_on_logout", "admin_default"),
        ("automatic_network_max", "unmetered"),
        ("attachment_prefetch_max", "never"),
        ("connectivity_sync_mode", "off"),
    ] {
        if out
            .get(k)
            .and_then(|v| v.as_str())
            .is_none_or(|s| s.is_empty())
        {
            out.insert(k.into(), default.into());
        }
    }
    for (k, v) in [
        ("enabled", false),
        ("require_approval", false),
        ("background_sync_allowed", true),
        ("opportunistic_requires_charging", true),
    ] {
        out.entry(k).or_insert(v.into());
    }
    for k in ["max_offline_days", "priority"] {
        out.entry(k).or_insert(0.into());
    }
    Ok(serde_json::Value::Object(out))
}

pub async fn command(
    factory: &TxFactory,
    user: &UserPrincipal,
    mailbox_id: i64,
    action: &str,
    payload: serde_json::Value,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor = user.user().get();
    let payload = payload.to_string();
    let contract = if setjoin_contracts::mutants::on("offline-foreign-device") {
        &sql::OFFLINE_COMMAND_MUTANT
    } else {
        &sql::OFFLINE_COMMAND
    };
    let env = super::envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{action}:{payload}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            super::deadline(),
            contract,
            &[&actor, &mailbox_id, &action, &payload],
            Some(super::command("offline.command")),
            |rows| {
                rows.first()
                    .ok_or_else(invalid)?
                    .try_get(0)
                    .map_err(|_| invalid())
            },
        )
        .await
}

pub fn toggle_input(body: &[u8]) -> Result<serde_json::Value, String> {
    let mut out = decode(
        body,
        &[("enabled", super::gojson::Kind::Bool)],
        false,
        false,
        &[],
    )?;
    out.entry("enabled").or_insert(false.into());
    Ok(out.into())
}

pub fn preview_input(body: &[u8]) -> Result<(i64, i64), String> {
    let out = decode(
        body,
        &[
            ("targetUserId", super::gojson::Kind::Str),
            ("deviceId", super::gojson::Kind::Str),
        ],
        true,
        true,
        &[],
    )?;
    let parse = |key: &str, detail: &str| {
        out.get(key)
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|n| *n > 0)
            .ok_or_else(|| detail.to_owned())
    };
    Ok((
        parse("targetUserId", "invalid targetUserId")?,
        parse("deviceId", "invalid deviceId")?,
    ))
}

pub async fn preview(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    target: i64,
    device: i64,
) -> Result<String, StatementFailure> {
    let actor = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(proof, &sql::OFFLINE_PREVIEW, &[&actor, &target, &device])
        .await?;
    rows.first()
        .ok_or_else(invalid)?
        .try_get(0)
        .map_err(|_| invalid())
}

pub fn ack_input(body: &[u8]) -> Result<serde_json::Value, String> {
    let out = decode(
        body,
        &[("device_id", super::gojson::Kind::Int64)],
        false,
        false,
        &[],
    )?;
    if out.get("device_id").and_then(|v| v.as_i64()).unwrap_or(0) == 0 {
        return Err("device_id required".into());
    }
    Ok(out.into())
}

/// Format the 6-window aggregate row returned by [`sql::OFFLINE_SIZE`] (executed
/// on the gateway worker pool for Go's cross-mailbox one-user estimate).
pub fn format_size_buckets(row: &Row) -> Result<String, StatementFailure> {
    let windows = ["7d", "30d", "90d", "180d", "365d", "all"];
    let mut buckets = Vec::with_capacity(windows.len());
    for (i, window) in windows.iter().enumerate() {
        let count: i64 = row.try_get(i * 2).map_err(|_| invalid())?;
        let bytes: i64 = row.try_get(i * 2 + 1).map_err(|_| invalid())?;
        buckets.push(format!(
            "{{\"window\":\"{window}\",\"messageCount\":{count},\"bodyBytes\":{bytes}}}"
        ));
    }
    Ok(format!("{{\"buckets\":[{}]}}\n", buckets.join(",")))
}
