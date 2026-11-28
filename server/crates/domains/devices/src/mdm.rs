//! MDM console (Go's `admin.MDMHandler` and `mdm.Engine`): device state reads,
//! the wipe arm and the policy CRUD.
use super::{command, deadline, done, envelope, gojson, invalid, opt, s, sql, StatementFailure};
use gojson::{Kind, V};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, Rejection, Row};

/// `DeviceState.MarshalJSON`: Go's field order, `omitempty` on the optional
/// fields, and the attestation marker once a wipe is armed.
fn device_json(row: &Row) -> Result<String, StatementFailure> {
    let g =
        |i: usize| -> Result<String, StatementFailure> { row.try_get(i).map_err(|_| invalid()) };
    let b = |i: usize| -> Result<bool, StatementFailure> { row.try_get(i).map_err(|_| invalid()) };
    let o = |i: usize| -> Result<Option<String>, StatementFailure> {
        row.try_get(i).map_err(|_| invalid())
    };
    let reasons: Vec<String> = row.try_get(12).map_err(|_| invalid())?;
    let user: i64 = row.try_get(1).map_err(|_| invalid())?;
    let wipe = g(14)?;
    let mut out = format!(
        "{{\"device_id\":{},\"user_id\":{user},\"platform\":{},\"device_name\":{},\"os_version\":{},\"app_version\":{},\"passcode_set\":{},\"passcode_compliant\":{},\"encryption_enabled\":{},\"jailbroken\":{},\"jailbreak_method\":{},\"compliance_status\":{},\"non_compliance_reasons\":[{}]",
        s(&g(0)?),
        s(&g(2)?),
        s(&g(3)?),
        s(&g(4)?),
        s(&g(5)?),
        b(6)?,
        b(7)?,
        b(8)?,
        b(9)?,
        s(&g(10)?),
        s(&g(11)?),
        reasons.iter().map(|r| s(r)).collect::<Vec<_>>().join(",")
    );
    if let Some(v) = opt(&o(13)?) {
        out.push_str(&format!(",\"grace_until\":{v}"));
    }
    out.push_str(&format!(",\"wipe_requested\":{}", s(&wipe)));
    let level = g(15)?;
    if !level.is_empty() {
        out.push_str(&format!(",\"wipe_level\":{}", s(&level)));
    }
    if let Some(v) = opt(&o(16)?) {
        out.push_str(&format!(",\"wipe_requested_at\":{v}"));
    }
    if let Some(v) = opt(&o(17)?) {
        out.push_str(&format!(",\"wipe_acked_at\":{v}"));
    }
    out.push_str(&format!(
        ",\"last_checkin_at\":{},\"created_at\":{},\"updated_at\":{}",
        s(&g(18)?),
        s(&g(19)?),
        s(&g(20)?)
    ));
    if matches!(wipe.as_str(), "pending" | "acknowledged" | "executed") {
        out.push_str(",\"completion\":\"client-attested\"");
    }
    out.push('}');
    Ok(out)
}

/// `GET /admin/mdm/devices`: up to 100 devices, newest check-in first.
pub async fn list_devices(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    domain_scope: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::MDM_LIST_DEVICES, &[&domain_scope])
        .await?;
    let devices = rows
        .iter()
        .map(device_json)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(done(format!(
        "{{\"devices\":[{}],\"total\":{}}}",
        devices.join(","),
        devices.len()
    )))
}

/// `GET /admin/mdm/devices/{device_id}`: `None` for a missing or out-of-scope
/// device and for any read failure, which Go answers alike with 404.
pub async fn get_device(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    device: &str,
    domain_scope: i64,
) -> Option<String> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::MDM_GET_DEVICE, &[&device, &domain_scope])
        .await
        .ok()?;
    device_json(rows.first()?).ok().map(done)
}

/// What the wipe arm's reducer answered, as `Engine.mapWipeArmError` projects it.
#[derive(Debug, PartialEq, Eq)]
pub enum WipeRefusal {
    /// BZ053: unknown or out-of-scope device (404, no existence oracle).
    NotFound,
    /// BZ054: a state conflict on an in-scope device (409 `{error, field}`).
    Conflict {
        field: &'static str,
        message: String,
    },
    /// Anything else: Go's 500.
    Failed,
}

pub fn wipe_refusal(error: &Rejection<StatementFailure>) -> WipeRefusal {
    let (Rejection::Statement(e) | Rejection::Body(e)) = error else {
        return WipeRefusal::Failed;
    };
    match e.sqlstate.as_deref() {
        Some("BZ053") => WipeRefusal::NotFound,
        Some("BZ054") => {
            let hint: serde_json::Value = e
                .hint
                .as_deref()
                .and_then(|h| serde_json::from_str(h).ok())
                .unwrap_or(serde_json::Value::Null);
            match hint["type"].as_str() {
                Some("executed") => WipeRefusal::Conflict {
                    field: "wipe",
                    message: "wipe already executed".into(),
                },
                Some("already_armed") => WipeRefusal::Conflict {
                    field: "wipe_level",
                    message: format!(
                        "wipe already in progress at level '{}'",
                        hint["reason"].as_str().unwrap_or("")
                    ),
                },
                Some("concurrent") => WipeRefusal::Conflict {
                    field: "device_id",
                    message: "device state changed concurrently; retry".into(),
                },
                _ => WipeRefusal::Failed,
            }
        }
        _ => WipeRefusal::Failed,
    }
}

/// `POST /admin/mdm/devices/{device_id}/wipe`: `mdm_device_wipe_arm` (state, core
/// audit row, `device_events` row and `device_policy` notify in one transaction)
/// with the admin and client IP from the verified request.
pub async fn arm_wipe(
    factory: &TxFactory,
    user: &UserPrincipal,
    device: &str,
    level: &str,
    domain_scope: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{device}\n{level}\n{domain_scope}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MDM_ARM_WIPE,
            &[&device, &level, &domain_scope, &actor, &ip],
            Some(command("mdm_wipe_arm")),
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

// ---- policies ----

/// `GET /admin/mdm/policies`: Go's `policyRow` (the outer fields shadow the
/// embedded `mdm.Policy`'s `id` and `name`), highest priority first.
pub async fn list_policies(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::MDM_LIST_POLICIES, &[])
        .await?;
    let mut items = Vec::new();
    for row in &rows {
        let i =
            |n: usize| -> Result<i64, StatementFailure> { row.try_get(n).map_err(|_| invalid()) };
        let t = |n: usize| -> Result<String, StatementFailure> {
            row.try_get(n).map_err(|_| invalid())
        };
        let b =
            |n: usize| -> Result<bool, StatementFailure> { row.try_get(n).map_err(|_| invalid()) };
        items.push(format!(
            "{{\"id\":{},\"name\":{},\"description\":{},\"priority\":{},\"scope_type\":{},\"scope_id\":{},\"enabled\":{},\"passcode_min_length\":{},\"passcode_complexity\":{},\"passcode_max_age_days\":{},\"passcode_history_count\":{},\"max_failed_attempts\":{},\"inactivity_lock_mins\":{},\"block_screenshots\":{},\"block_copy_paste\":{},\"require_device_encryption\":{},\"min_os_version_ios\":{},\"min_os_version_android\":{},\"jailbreak_action\":{},\"heartbeat_interval_secs\":{},\"grace_period_mins\":{}}}",
            i(0)?, s(&t(1)?), s(&t(2)?), i(3)?, s(&t(4)?), i(5)?, b(6)?, i(7)?, s(&t(8)?), i(9)?, i(10)?,
            i(11)?, i(12)?, b(13)?, b(14)?, b(15)?, s(&t(16)?), s(&t(17)?), s(&t(18)?), i(19)?, i(20)?
        ));
    }
    Ok(done(format!(
        "{{\"policies\":[{}],\"total\":{}}}",
        items.join(","),
        items.len()
    )))
}

/// Go's `policyRequest`: every field optional.
#[derive(Default, Debug)]
pub struct PolicyFields {
    pub name: Option<String>,
    pub description: Option<String>,
    pub priority: Option<i64>,
    pub scope_type: Option<String>,
    pub scope_id: Option<i64>,
    pub enabled: Option<bool>,
    pub passcode_min_length: Option<i64>,
    pub passcode_complexity: Option<String>,
    pub passcode_max_age_days: Option<i64>,
    pub passcode_history_count: Option<i64>,
    pub max_failed_attempts: Option<i64>,
    pub inactivity_lock_mins: Option<i64>,
    pub block_screenshots: Option<bool>,
    pub block_copy_paste: Option<bool>,
    pub require_device_encryption: Option<bool>,
    pub min_os_version_ios: Option<String>,
    pub min_os_version_android: Option<String>,
    pub jailbreak_action: Option<String>,
    pub heartbeat_interval_secs: Option<i64>,
    pub grace_period_mins: Option<i64>,
}

const SCHEMA: [(&str, Kind); 20] = [
    ("name", Kind::Str),
    ("description", Kind::Str),
    ("priority", Kind::Int),
    ("scope_type", Kind::Str),
    ("scope_id", Kind::Int64),
    ("enabled", Kind::Bool),
    ("passcode_min_length", Kind::Int),
    ("passcode_complexity", Kind::Str),
    ("passcode_max_age_days", Kind::Int),
    ("passcode_history_count", Kind::Int),
    ("max_failed_attempts", Kind::Int),
    ("inactivity_lock_mins", Kind::Int),
    ("block_screenshots", Kind::Bool),
    ("block_copy_paste", Kind::Bool),
    ("require_device_encryption", Kind::Bool),
    ("min_os_version_ios", Kind::Str),
    ("min_os_version_android", Kind::Str),
    ("jailbreak_action", Kind::Str),
    ("heartbeat_interval_secs", Kind::Int),
    ("grace_period_mins", Kind::Int),
];

impl PolicyFields {
    /// Go's `Decode(&policyRequest)`: `Err` is the decoder's error text.
    pub fn decode(body: &[u8]) -> Result<PolicyFields, String> {
        let value = gojson::first(body)?;
        let mut v = gojson::fields(&value, &SCHEMA, "policyRequest", "admin.")?;
        let mut take = |i: usize| std::mem::take(&mut v[i]);
        let str_of = |x: Option<V>| match x {
            Some(V::Str(s)) => Some(s),
            _ => None,
        };
        let int_of = |x: Option<V>| match x {
            Some(V::Int(n)) => Some(n),
            _ => None,
        };
        let bool_of = |x: Option<V>| match x {
            Some(V::Bool(b)) => Some(b),
            _ => None,
        };
        Ok(PolicyFields {
            name: str_of(take(0)),
            description: str_of(take(1)),
            priority: int_of(take(2)),
            scope_type: str_of(take(3)),
            scope_id: int_of(take(4)),
            enabled: bool_of(take(5)),
            passcode_min_length: int_of(take(6)),
            passcode_complexity: str_of(take(7)),
            passcode_max_age_days: int_of(take(8)),
            passcode_history_count: int_of(take(9)),
            max_failed_attempts: int_of(take(10)),
            inactivity_lock_mins: int_of(take(11)),
            block_screenshots: bool_of(take(12)),
            block_copy_paste: bool_of(take(13)),
            require_device_encryption: bool_of(take(14)),
            min_os_version_ios: str_of(take(15)),
            min_os_version_android: str_of(take(16)),
            jailbreak_action: str_of(take(17)),
            heartbeat_interval_secs: int_of(take(18)),
            grace_period_mins: int_of(take(19)),
        })
    }

    /// `policyRequest.validate`: the `(field, message)` Go answers with.
    pub fn validate(&self) -> Option<(&'static str, &'static str)> {
        if self.name.as_deref() == Some("") {
            return Some(("name", "name cannot be empty"));
        }
        if let Some(t) = &self.scope_type {
            if !matches!(t.as_str(), "global" | "group" | "user") {
                return Some(("scope_type", "must be 'global', 'group', or 'user'"));
            }
        }
        if let Some(c) = &self.passcode_complexity {
            if !matches!(c.as_str(), "none" | "numeric" | "alphanumeric" | "complex") {
                return Some((
                    "passcode_complexity",
                    "must be 'none', 'numeric', 'alphanumeric', or 'complex'",
                ));
            }
        }
        if let Some(a) = &self.jailbreak_action {
            if !matches!(a.as_str(), "block" | "quarantine" | "warn_log" | "none") {
                return Some((
                    "jailbreak_action",
                    "must be 'block', 'quarantine', 'warn_log', or 'none'",
                ));
            }
        }
        if self.passcode_min_length.is_some_and(|n| n < 0) {
            return Some(("passcode_min_length", "must be >= 0"));
        }
        None
    }
}

/// `POST /admin/mdm/policies`: Go's INSERT with the defaults applied, one statement.
pub async fn create_policy(
    factory: &TxFactory,
    user: &UserPrincipal,
    p: &PolicyFields,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let name = p.name.clone().unwrap_or_default();
    let description = p.description.clone().unwrap_or_default();
    let priority = p.priority.unwrap_or(0);
    let scope_type = p.scope_type.clone().unwrap_or_else(|| "global".into());
    let enabled = p.enabled.unwrap_or(true);
    let min_length = p.passcode_min_length.unwrap_or(6);
    let complexity = p
        .passcode_complexity
        .clone()
        .unwrap_or_else(|| "numeric".into());
    let max_age = p.passcode_max_age_days.unwrap_or(90);
    let history = p.passcode_history_count.unwrap_or(5);
    let failed = p.max_failed_attempts.unwrap_or(10);
    let lock = p.inactivity_lock_mins.unwrap_or(5);
    let screenshots = p.block_screenshots.unwrap_or(false);
    let copy_paste = p.block_copy_paste.unwrap_or(false);
    let encryption = p.require_device_encryption.unwrap_or(true);
    let ios = p.min_os_version_ios.clone().unwrap_or_default();
    let android = p.min_os_version_android.clone().unwrap_or_default();
    let jailbreak = p
        .jailbreak_action
        .clone()
        .unwrap_or_else(|| "quarantine".into());
    let heartbeat = p.heartbeat_interval_secs.unwrap_or(3600);
    let grace = p.grace_period_mins.unwrap_or(60);
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{name}\n{scope_type}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MDM_CREATE_POLICY,
            &[
                &name,
                &description,
                &priority,
                &scope_type,
                &p.scope_id,
                &enabled,
                &min_length,
                &complexity,
                &max_age,
                &history,
                &failed,
                &lock,
                &screenshots,
                &copy_paste,
                &encryption,
                &ios,
                &android,
                &jailbreak,
                &heartbeat,
                &grace,
            ],
            Some(command("mdm_policy_create")),
            |rows| match rows.as_slice() {
                [row] => row.try_get(0).map_err(|_| invalid()),
                _ => Err(invalid()),
            },
        )
        .await
}

/// `PUT /admin/mdm/policies/{id}`: Go's dynamic UPDATE (absent fields keep their
/// value, but `scope_id` is always written). `true` when a row matched.
pub async fn update_policy(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    p: &PolicyFields,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(user.user(), user.generation(), operation, &id.to_string());
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MDM_UPDATE_POLICY,
            &[
                &id,
                &p.name,
                &p.description,
                &p.priority,
                &p.scope_type,
                &p.scope_id,
                &p.enabled,
                &p.passcode_min_length,
                &p.passcode_complexity,
                &p.passcode_max_age_days,
                &p.passcode_history_count,
                &p.max_failed_attempts,
                &p.inactivity_lock_mins,
                &p.block_screenshots,
                &p.block_copy_paste,
                &p.require_device_encryption,
                &p.min_os_version_ios,
                &p.min_os_version_android,
                &p.jailbreak_action,
                &p.heartbeat_interval_secs,
                &p.grace_period_mins,
            ],
            Some(command("mdm_policy_update")),
            |rows| match rows.as_slice() {
                [row] => row
                    .try_get::<_, i64>(0)
                    .map(|n| n > 0)
                    .map_err(|_| invalid()),
                _ => Err(invalid()),
            },
        )
        .await
}

/// The reducer verdict `rust_mdm_policy_delete` carries.
#[derive(Debug, PartialEq, Eq)]
pub enum Deleted {
    Done,
    LastGlobal,
    Missing,
}

/// `DELETE /admin/mdm/policies/{id}`: the last-global probe and the DELETE as one
/// transaction (`rust_mdm_policy_delete`).
pub async fn delete_policy(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<Deleted, StatementFailure> {
    let env = envelope(user.user(), user.generation(), operation, &id.to_string());
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MDM_DELETE_POLICY,
            &[&id],
            Some(command("mdm_policy_delete")),
            |rows| match rows.as_slice() {
                [row] => match row.try_get::<_, String>(0).map_err(|_| invalid())?.as_str() {
                    "200" => Ok(Deleted::Done),
                    "409" => Ok(Deleted::LastGlobal),
                    "404" => Ok(Deleted::Missing),
                    _ => Err(invalid()),
                },
                _ => Err(invalid()),
            },
        )
        .await
}

/// `PUT /admin/mdm/policies/reorder`: one UPDATE per id, highest priority first
/// (`rust_mdm_policy_reorder`), atomically.
pub async fn reorder_policies(
    factory: &TxFactory,
    user: &UserPrincipal,
    ids: &[i64],
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let list: Vec<i64> = ids.to_vec();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{ids:?}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MDM_REORDER_POLICIES,
            &[&list],
            Some(command("mdm_policy_reorder")),
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
