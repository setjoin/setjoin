//! Offline governance: the frozen Go handler's reducer and wire contracts.
use super::{invalid, StatementFailure};
use setjoin_pg::ScopedExecutor;

pub async fn policies(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec.read("SELECT offline_policy_list()::text", &[]).await?;
    rows.first()
        .ok_or_else(invalid)?
        .try_get(0)
        .map_err(|_| invalid())
}

pub async fn policy(exec: &ScopedExecutor, id: i64) -> Result<Option<String>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT offline_policy_get($1)::text",
            &[(&id, setjoin_pg::Type::INT8)],
        )
        .await?;
    rows.first()
        .ok_or_else(invalid)?
        .try_get(0)
        .map_err(|_| invalid())
}
pub async fn enabled(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows=exec.read("SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.offline_mail'),false)",&[]).await?;
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
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let sql = if setjoin_contracts::mutants::on("offline-foreign-device") {
        "SELECT offline_devices_pending()::text WHERE $1::bigint > 0"
    } else {
        "SELECT rust_offline_devices_pending($1::bigint)::text"
    };
    let rows = exec.read(sql, &[(&user, setjoin_pg::Type::INT8)]).await?;
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
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    action: &str,
    payload: serde_json::Value,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let auth = super::scope(actor);
    let payload = payload.to_string();
    setjoin_pg::run_receipted_command(
        exec,
        super::command("offline.command"),
        &super::envelope(&auth, operation, &format!("{action}:{payload}")),
        &auth,
        super::deadline(),
        // The reach of the target device is computed here, in the mutating statement,
        // from the owner stored on the row (#440); only the four device transitions use it.
        if setjoin_contracts::mutants::on("offline-foreign-device") {
            "SELECT rust_offline_command($2,$1,$4,$5::text::jsonb,true) WHERE $3::text<>''"
        } else {
            "SELECT rust_offline_command($2,$1,$4,$5::text::jsonb,\
             COALESCE(admin_can_reach_perm($2,(SELECT ud.user_id FROM user_devices ud \
             WHERE ud.id=($5::text::jsonb->>'id')::bigint),ARRAY['mam.write']),false)) WHERE $3::text<>''"
        },
        &[
            (&action, setjoin_pg::Type::TEXT),
            (&payload, setjoin_pg::Type::TEXT),
        ],
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
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    target: i64,
    device: i64,
) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT offline_sync_policy_preview($1,$2,$3)::text",
            &[
                (&actor.user_id(), setjoin_pg::Type::INT8),
                (&target, setjoin_pg::Type::INT8),
                (&device, setjoin_pg::Type::INT8),
            ],
        )
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
/// Go uses the worker credential for this cross-mailbox, one-user aggregate.
/// No request-owned user or mailbox field can widen the predicate.
pub async fn size(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
) -> Result<String, StatementFailure> {
    let windows = [
        ("7d", Some(7)),
        ("30d", Some(30)),
        ("90d", Some(90)),
        ("180d", Some(180)),
        ("365d", Some(365)),
        ("all", None),
    ];
    let columns = windows
        .iter()
        .map(|(_, days)| {
            let filter = days
                .map(|d| format!(" FILTER(WHERE received_at >= now()-interval '{d} days')"))
                .unwrap_or_default();
            format!("COUNT(*){filter},COALESCE(SUM(b){filter},0)")
        })
        .collect::<Vec<_>>()
        .join(",");
    let sql=format!("SELECT {columns} FROM(SELECT m.received_at,octet_length(COALESCE(m.body_text,''))+octet_length(COALESCE(m.body_html,'')) AS b FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE mb.user_id=$1 AND NOT m.is_deleted)m");
    let rows = exec
        .read(&sql, &[(&actor.user_id(), setjoin_pg::Type::INT8)])
        .await?;
    let row = rows.first().ok_or_else(invalid)?;
    let mut buckets = Vec::new();
    for (i, (window, _)) in windows.iter().enumerate() {
        let count: i64 = row.try_get(i * 2).map_err(|_| invalid())?;
        let bytes: i64 = row.try_get(i * 2 + 1).map_err(|_| invalid())?;
        buckets.push(format!(
            "{{\"window\":\"{window}\",\"messageCount\":{count},\"bodyBytes\":{bytes}}}"
        ));
    }
    Ok(format!("{{\"buckets\":[{}]}}\n", buckets.join(",")))
}
