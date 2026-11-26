//! Platform slice `system-features`, group `config`: `system_config` list, read, write and
//! export (`/admin/system/config*`).
use super::{command, deadline, done, envelope, invalid, s, sql};
use serde_json::Value;
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

/// Go's `redactedConfigValue`.
pub const REDACTED: &str = "[ENCRYPTED]";

/// Go's `allowedConfigKeys`: the keys the admin API may write.
pub const WRITABLE: [&str; 18] = [
    "identity_source",
    "deleted_items_purge_days",
    "spam_purge_days",
    "smtp_retry_max",
    "greylist_duration",
    "max_message_bytes",
    "dkim_selector",
    "vacation_default_subject",
    "password_min_length",
    "password_require_uppercase",
    "password_require_lowercase",
    "password_require_digit",
    "password_require_special",
    "mfa_enforcement_mode",
    "worm_retention_days",
    "worm_mode",
    "worm_legal_hold_enabled",
    "apps_caps_strict",
];

/// Go's `isSecretConfigKey`: named bearer credentials and the `_enc` suffix.
pub fn is_secret_key(key: &str) -> bool {
    key == "assist.api_key" || key.ends_with("_enc")
}

/// Go's `validConfigValue`: boolean keys admit the JSON strings `1|true|0|false` in any case
/// and JSON booleans; every other writable key is unconstrained.
pub fn valid_value(key: &str, raw: &str) -> bool {
    if key != "apps_caps_strict" {
        return true;
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::String(text)) => {
            matches!(text.to_lowercase().as_str(), "1" | "true" | "0" | "false")
        }
        Ok(Value::Bool(_)) => true,
        _ => false,
    }
}

/// `encoding/json` rendering of a float64 (Go's fixed versus exponent thresholds, explicit
/// positive exponent sign).
pub(crate) fn go_f64(number: f64) -> String {
    let number = if number.is_finite() { number } else { 0.0 };
    let absolute = number.abs();
    if absolute != 0.0 && !(1e-6..1e21).contains(&absolute) {
        let text = format!("{number:e}");
        let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
        let exponent: i32 = exponent.parse().unwrap_or(0);
        format!("{mantissa}e{exponent:+}")
    } else {
        format!("{number}")
    }
}

/// `encoding/json` rendering of a value Go decoded into `any`: numbers are float64,
/// object keys sorted.
pub fn go_any(value: &Value) -> String {
    match value {
        Value::Number(number) => go_f64(number.as_f64().unwrap_or(0.0)),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(go_any).collect::<Vec<_>>().join(",")
        ),
        Value::Object(values) => {
            let mut keys: Vec<&String> = values.keys().collect();
            keys.sort();
            format!(
                "{{{}}}",
                keys.iter()
                    .map(|k| format!("{}:{}", s(k), go_any(&values[*k])))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        other => other.to_string(),
    }
}

fn shown(key: &str, text: &str, encrypted: bool) -> String {
    if encrypted || is_secret_key(key) {
        return s(REDACTED);
    }
    serde_json::from_str::<Value>(text).map_or("null".into(), |v| go_any(&v))
}

/// `GET /admin/system/config[?prefix=]`.
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    prefix: &str,
) -> Result<String, StatementFailure> {
    let rows = if prefix.is_empty() {
        factory
            .run_admin_read_contract(admin, &sql::CONFIG_LIST_ALL, &[])
            .await?
    } else {
        let like = format!("{prefix}%");
        factory
            .run_admin_read_contract(admin, &sql::CONFIG_LIST_PREFIX, &[&like])
            .await?
    };
    let mut out = Vec::new();
    for row in &rows {
        let (Ok(key), Ok(value), Ok(encrypted)) = (
            row.try_get::<_, String>(0),
            row.try_get::<_, String>(1),
            row.try_get::<_, bool>(2),
        ) else {
            continue;
        };
        out.push(format!(
            "{{\"encrypted\":{encrypted},\"key\":{},\"value\":{}}}",
            s(&key),
            shown(&key, &value, encrypted)
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/system/config/{key}`: `None` is Go's 404.
pub async fn get(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    key: &str,
) -> Result<Option<String>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::CONFIG_GET, &[&key])
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let value: String = row.try_get(0).map_err(|_| invalid())?;
    let encrypted: bool = row.try_get(1).map_err(|_| invalid())?;
    Ok(Some(done(format!(
        "{{\"encrypted\":{encrypted},\"key\":{},\"value\":{}}}",
        s(key),
        shown(key, &value, encrypted)
    ))))
}

/// `PUT /admin/system/config/{key}` after the edge validation.
pub async fn set(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    key: &str,
    value: Option<&str>,
    encrypted: bool,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{key}:{value:?}:{encrypted}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CONFIG_SET,
            &[&key, &value, &encrypted],
            Some(command("config_set")),
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

/// Whitespace outside strings removed: `json.Marshal` of a `RawMessage` compacts it.
pub fn compact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let (mut in_string, mut escaped) = (false, false);
    for c in text.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if !c.is_ascii_whitespace() {
            out.push(c);
        }
    }
    out
}

/// `GET /admin/system/config/export`: every row, secrets redacted, values verbatim.
pub async fn export(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::CONFIG_EXPORT, &[])
        .await?;
    let mut out = Vec::new();
    for row in &rows {
        let (Ok(key), Ok(value), Ok(encrypted), Ok(description)) = (
            row.try_get::<_, String>(0),
            row.try_get::<_, String>(1),
            row.try_get::<_, bool>(2),
            row.try_get::<_, String>(3),
        ) else {
            continue;
        };
        let value = if encrypted || is_secret_key(&key) {
            s(REDACTED)
        } else {
            compact(&value)
        };
        out.push(format!(
            "{{\"description\":{},\"key\":{},\"value\":{value}}}",
            s(&description),
            s(&key)
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// One element of `POST /admin/system/config/import`.
pub async fn import_item(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    key: &str,
    value: &str,
    description: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{key}:{value}:{description:?}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CONFIG_IMPORT_ITEM,
            &[&key, &value, &description],
            Some(command("config_import_item")),
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
