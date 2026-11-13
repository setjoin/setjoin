//! MDM console (Go's `admin.MDMHandler` and `mdm.Engine`): device state reads,
//! the wipe arm and the policy CRUD. Reads run in a `READ ONLY` transaction with
//! the admin actor GUC (Go's `dbscope.RunUserScoped`); the domain-scope predicate
//! rides in the same SELECT (R1). Writes are receipted commands: the wipe arm and
//! the policy delete/reorder call reducers (several statements in Go's
//! transaction), policy create and update are one statement each.
use super::{
    command, deadline, done, envelope, gojson, invalid, nano, opt, s, scope, StatementFailure,
};
use gojson::{Kind, V};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, Param, Rejection, ScopedExecutor, Type};

const UUID_FIELDS: &str =
    "device_id::text, user_id, platform, device_name, os_version, app_version, \
     passcode_set, passcode_compliant, encryption_enabled, jailbroken, jailbreak_method, \
     compliance_status, non_compliance_reasons, ";

fn device_select() -> String {
    format!(
        "SELECT {UUID_FIELDS}{}, wipe_requested, COALESCE(wipe_level, ''), {}, {}, {}, {}, {} FROM mdm_device_state",
        nano("grace_until"),
        nano("wipe_requested_at"),
        nano("wipe_acked_at"),
        nano("last_checkin_at"),
        nano("created_at"),
        nano("updated_at"),
    )
}

/// `DeviceState.MarshalJSON`: Go's field order, `omitempty` on the optional
/// fields, and the attestation marker once a wipe is armed.
fn device_json(row: &setjoin_pg::Row) -> Result<String, StatementFailure> {
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    domain_scope: i64,
) -> Result<String, StatementFailure> {
    let mut sql = device_select();
    let mut params: Vec<Param<'_>> = Vec::new();
    if domain_scope > 0 {
        params.push((&domain_scope, Type::INT8));
        sql.push_str(" WHERE user_id IN (SELECT id FROM users WHERE domain_id = $1)");
    }
    sql.push_str(" ORDER BY last_checkin_at DESC LIMIT 100");
    let rows = exec.read_scoped(&scope(actor), &sql, &params).await?;
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    device: &str,
    domain_scope: i64,
) -> Option<String> {
    let mut sql = format!("{} WHERE device_id = $1::text::uuid", device_select());
    let mut params: Vec<Param<'_>> = vec![(&device, Type::TEXT)];
    if domain_scope > 0 {
        params.push((&domain_scope, Type::INT8));
        sql.push_str(" AND user_id IN (SELECT id FROM users WHERE domain_id = $2)");
    }
    let rows = exec.read_scoped(&scope(actor), &sql, &params).await.ok()?;
    device_json(rows.first()?).ok().map(|d| done(d))
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    device: &str,
    level: &str,
    domain_scope: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("mdm_wipe_arm"),
        &envelope(&auth, operation, &format!("{device}\n{level}\n{domain_scope}")),
        &auth,
        deadline(),
        "SELECT mdm_device_wipe_arm($4::text::uuid, $5::text, $6::bigint, $2::bigint, NULLIF($7::text, '')::inet)::text \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&device, Type::TEXT),
            (&level, Type::TEXT),
            (&domain_scope, Type::INT8),
            (&ip, Type::TEXT),
        ],
        |rows| if rows.len() == 1 { Ok(()) } else { Err(invalid()) },
    )
    .await
}

// ---- policies ----

/// `GET /admin/mdm/policies`: Go's `policyRow` (the outer fields shadow the
/// embedded `mdm.Policy`'s `id` and `name`), highest priority first.
pub async fn list_policies(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT id, name, description, priority::bigint, scope_type, COALESCE(scope_id, 0), enabled, \
             passcode_min_length::bigint, passcode_complexity, passcode_max_age_days::bigint, \
             passcode_history_count::bigint, max_failed_attempts::bigint, inactivity_lock_mins::bigint, \
             block_screenshots, block_copy_paste, require_device_encryption, \
             min_os_version_ios, min_os_version_android, jailbreak_action, \
             heartbeat_interval_secs::bigint, grace_period_mins::bigint \
             FROM mdm_policies ORDER BY priority DESC",
            &[],
        )
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    p: &PolicyFields,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
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
    let params: [Param<'_>; 20] = [
        (&name, Type::TEXT),
        (&description, Type::TEXT),
        (&priority, Type::INT8),
        (&scope_type, Type::TEXT),
        (&p.scope_id, Type::INT8),
        (&enabled, Type::BOOL),
        (&min_length, Type::INT8),
        (&complexity, Type::TEXT),
        (&max_age, Type::INT8),
        (&history, Type::INT8),
        (&failed, Type::INT8),
        (&lock, Type::INT8),
        (&screenshots, Type::BOOL),
        (&copy_paste, Type::BOOL),
        (&encryption, Type::BOOL),
        (&ios, Type::TEXT),
        (&android, Type::TEXT),
        (&jailbreak, Type::TEXT),
        (&heartbeat, Type::INT8),
        (&grace, Type::INT8),
    ];
    setjoin_pg::run_receipted_command(
        exec,
        command("mdm_policy_create"),
        &envelope(&auth, operation, &format!("{name}\n{scope_type}")),
        &auth,
        deadline(),
        "INSERT INTO mdm_policies (name, description, priority, scope_type, scope_id, enabled, \
         passcode_min_length, passcode_complexity, passcode_max_age_days, passcode_history_count, \
         max_failed_attempts, inactivity_lock_mins, block_screenshots, block_copy_paste, \
         require_device_encryption, min_os_version_ios, min_os_version_android, jailbreak_action, \
         heartbeat_interval_secs, grace_period_mins) \
         SELECT $4::text, $5::text, $6::bigint::int4, $7::text, $8::bigint, $9::boolean, \
         $10::bigint::int4, $11::text, $12::bigint::int4, $13::bigint::int4, $14::bigint::int4, \
         $15::bigint::int4, $16::boolean, $17::boolean, $18::boolean, $19::text, $20::text, $21::text, \
         $22::bigint::int4, $23::bigint::int4 \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING id",
        &params,
        |rows| match rows {
            [row] => row.try_get(0).map_err(|_| invalid()),
            _ => Err(invalid()),
        },
    )
    .await
}

/// `PUT /admin/mdm/policies/{id}`: Go's dynamic UPDATE (absent fields keep their
/// value, but `scope_id` is always written). `true` when a row matched.
pub async fn update_policy(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    p: &PolicyFields,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    let params: [Param<'_>; 21] = [
        (&id, Type::INT8),
        (&p.name, Type::TEXT),
        (&p.description, Type::TEXT),
        (&p.priority, Type::INT8),
        (&p.scope_type, Type::TEXT),
        (&p.scope_id, Type::INT8),
        (&p.enabled, Type::BOOL),
        (&p.passcode_min_length, Type::INT8),
        (&p.passcode_complexity, Type::TEXT),
        (&p.passcode_max_age_days, Type::INT8),
        (&p.passcode_history_count, Type::INT8),
        (&p.max_failed_attempts, Type::INT8),
        (&p.inactivity_lock_mins, Type::INT8),
        (&p.block_screenshots, Type::BOOL),
        (&p.block_copy_paste, Type::BOOL),
        (&p.require_device_encryption, Type::BOOL),
        (&p.min_os_version_ios, Type::TEXT),
        (&p.min_os_version_android, Type::TEXT),
        (&p.jailbreak_action, Type::TEXT),
        (&p.heartbeat_interval_secs, Type::INT8),
        (&p.grace_period_mins, Type::INT8),
    ];
    setjoin_pg::run_receipted_command(
        exec,
        command("mdm_policy_update"),
        &envelope(&auth, operation, &id.to_string()),
        &auth,
        deadline(),
        "WITH u AS (UPDATE mdm_policies SET \
         name = COALESCE($5::text, name), description = COALESCE($6::text, description), \
         priority = COALESCE($7::bigint::int4, priority), scope_type = COALESCE($8::text, scope_type), \
         scope_id = $9::bigint, enabled = COALESCE($10::boolean, enabled), \
         passcode_min_length = COALESCE($11::bigint::int4, passcode_min_length), \
         passcode_complexity = COALESCE($12::text, passcode_complexity), \
         passcode_max_age_days = COALESCE($13::bigint::int4, passcode_max_age_days), \
         passcode_history_count = COALESCE($14::bigint::int4, passcode_history_count), \
         max_failed_attempts = COALESCE($15::bigint::int4, max_failed_attempts), \
         inactivity_lock_mins = COALESCE($16::bigint::int4, inactivity_lock_mins), \
         block_screenshots = COALESCE($17::boolean, block_screenshots), \
         block_copy_paste = COALESCE($18::boolean, block_copy_paste), \
         require_device_encryption = COALESCE($19::boolean, require_device_encryption), \
         min_os_version_ios = COALESCE($20::text, min_os_version_ios), \
         min_os_version_android = COALESCE($21::text, min_os_version_android), \
         jailbreak_action = COALESCE($22::text, jailbreak_action), \
         heartbeat_interval_secs = COALESCE($23::bigint::int4, heartbeat_interval_secs), \
         grace_period_mins = COALESCE($24::bigint::int4, grace_period_mins), updated_at = now() \
         WHERE id = $4::bigint AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING 1) \
         SELECT count(*)::bigint FROM u",
        &params,
        |rows| match rows {
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<Deleted, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("mdm_policy_delete"),
        &envelope(&auth, operation, &id.to_string()),
        &auth,
        deadline(),
        "SELECT (rust_mdm_policy_delete($4::bigint)->>'status') WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[(&id, Type::INT8)],
        |rows| match rows {
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ids: &[i64],
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    let list: Vec<i64> = ids.to_vec();
    setjoin_pg::run_receipted_command(
        exec,
        command("mdm_policy_reorder"),
        &envelope(&auth, operation, &format!("{ids:?}")),
        &auth,
        deadline(),
        "SELECT rust_mdm_policy_reorder($4::bigint[])::text WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[(&list, Type::INT8_ARRAY)],
        |rows| if rows.len() == 1 { Ok(()) } else { Err(invalid()) },
    )
    .await
}
