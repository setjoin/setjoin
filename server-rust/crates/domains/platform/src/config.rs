//! Platform slice `system-features`, group `config`: `system_config` list, read, write and
//! export (`/admin/system/config*`).
//!
//! Go's `ConfigHandler` and `ConfigBackupHandler`. Secret rows (the `encrypted` column, a
//! `_enc` suffix or a named secret) are redacted on every read path. The write is Go's whole
//! transaction (one `INSERT .. ON CONFLICT`; the table's own trigger raises
//! `config_changed`), so it is one receipted statement with the foreign-key-free actor
//! guard.
use super::{command, deadline, done, envelope, invalid, s, scope};
use serde_json::Value;
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

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

/// A stored value as the read routes show it: redacted, else Go's re-marshal of the
/// decoded value (`null` when decoding fails, as Go ignores that error).
fn shown(key: &str, text: &str, encrypted: bool) -> String {
    if encrypted || is_secret_key(key) {
        return s(REDACTED);
    }
    serde_json::from_str::<Value>(text).map_or("null".into(), |v| go_any(&v))
}

/// `GET /admin/system/config[?prefix=]`.
pub async fn list(exec: &ScopedExecutor, prefix: &str) -> Result<String, StatementFailure> {
    let like = format!("{prefix}%");
    let rows = if prefix.is_empty() {
        exec.read(
            "SELECT key, value::text, encrypted FROM system_config ORDER BY key",
            &[],
        )
        .await?
    } else {
        exec.read(
            "SELECT key, value::text, encrypted FROM system_config WHERE key LIKE $1 ORDER BY key",
            &[(&like, Type::TEXT)],
        )
        .await?
    };
    let mut out = Vec::new();
    for row in &rows {
        // Go skips a row it cannot scan.
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
pub async fn get(exec: &ScopedExecutor, key: &str) -> Result<Option<String>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT value::text, encrypted FROM system_config WHERE key = $1",
            &[(&key, Type::TEXT)],
        )
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

/// `PUT /admin/system/config/{key}` after the edge validation. A missing `value` binds NULL
/// and violates the column's NOT NULL (Go's 500).
pub async fn set(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    key: &str,
    value: Option<&str>,
    encrypted: bool,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("config_set"),
        &envelope(&auth, operation, &format!("{key}:{value:?}:{encrypted}")),
        &auth,
        deadline(),
        "INSERT INTO system_config (key, value, encrypted, updated_at) \
         SELECT $4::text, $5::text::jsonb, $6::bool, now() \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = EXCLUDED.encrypted, updated_at = now() \
         RETURNING key",
        &[(&key, Type::TEXT), (&value, Type::TEXT), (&encrypted, Type::BOOL)],
        |rows| if rows.len() == 1 { Ok(()) } else { Err(invalid()) },
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
pub async fn export(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT key, value::text, encrypted, COALESCE(description,'') FROM system_config ORDER BY key",
            &[],
        )
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

/// One element of `POST /admin/system/config/import`: Go's `INSERT .. ON CONFLICT` run on
/// its own transaction per item. The caller counts any rolled-back item as skipped, as Go
/// does for every `Exec` error (bad JSON text, a description pgx cannot encode).
pub async fn import_item(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    key: &str,
    value: &str,
    description: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("config_import_item"),
        &envelope(&auth, operation, &format!("{key}:{value}:{description:?}")),
        &auth,
        deadline(),
        "INSERT INTO system_config (key, value, description) \
         SELECT $4::text, $5::text::jsonb, $6::text \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' \
         ON CONFLICT (key) DO UPDATE SET value = $5::text::jsonb, updated_at = now() \
         RETURNING key",
        &[
            (&key, Type::TEXT),
            (&value, Type::TEXT),
            (&description, Type::TEXT),
        ],
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
