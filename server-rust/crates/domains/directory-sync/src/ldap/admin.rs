//! LDAP admin route bodies (`admin.LDAPHandler`): config write, health,
//! preview and result documents. HTTP translation stays in the gateway adapter.
use super::engine::{PreviewRow, SyncResult};
use super::runtime::is_secret_key;
use crate::{deadline, envelope, go_escape, go_json, scope, TIMESTAMP};
use serde_json::{json, Map, Value};
use setjoin_authz::AuthContext;
use setjoin_config_secret::ConfigSecretCodec;
use setjoin_pg::{CommandOutcome, ReceiptCommand, ScopedExecutor, StatementFailure, Type};
use std::sync::Arc;

pub const REDACTED: &str = "[ENCRYPTED]";

/// The two directory families sharing the config write.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ldap,
    Ad,
}
impl Kind {
    fn prefix(self) -> &'static str {
        match self {
            Kind::Ldap => "ldap_sync_",
            Kind::Ad => "ad_sync_",
        }
    }
    fn description(self) -> &'static str {
        match self {
            Kind::Ldap => "LDAP sync config",
            Kind::Ad => "AD sync config",
        }
    }
    fn command(self) -> &'static str {
        match self {
            Kind::Ldap => "ldap_config_set",
            Kind::Ad => "ad_config_set",
        }
    }
}

/// Go `validatePrefixedStringConfig(req, "ldap_sync_")`.
pub fn validate_config(raw: &Map<String, Value>) -> bool {
    validate_prefixed(raw, Kind::Ldap)
}

/// Go `validatePrefixedStringConfig(req, "ad_sync_" or "ldap_sync_")`.
pub fn validate_prefixed(raw: &Map<String, Value>, kind: Kind) -> bool {
    if raw.len() > 64 {
        return false;
    }
    raw.iter().all(|(key, value)| {
        key.starts_with(kind.prefix())
            && key.len() <= 128
            && !key.contains('\0')
            && matches!(value, Value::String(text) if text.len() <= 64 << 10 && !text.contains('\0'))
    })
}

/// Why the write could not start; every case answers `500 failed to save LDAP config`.
#[derive(Debug)]
pub enum PutError {
    Prepare(String),
    Outcome(CommandOutcome<i64, StatementFailure>),
}

/// Go `ConfigStore.BatchSet`: secret keys are sealed (or preserved when the
/// console echoes the redaction sentinel), then every key is upserted in one
/// statement. The caller reloads the worker afterwards.
pub async fn put_config(
    codec: Option<Arc<ConfigSecretCodec>>,
    kind: Kind,
    exec: &ScopedExecutor,
    actor: &AuthContext,
    values: &Map<String, Value>,
    operation: [u8; 16],
) -> Result<(), PutError> {
    let (mut keys, mut texts, mut flags) = (vec![], vec![], vec![]);
    let mut ordered: Vec<(&String, &Value)> = values.iter().collect();
    ordered.sort_by(|a, b| a.0.cmp(b.0));
    for (key, value) in ordered {
        // Go json.Marshal of the string value.
        let marshalled =
            serde_json::to_string(value).map_err(|e| PutError::Prepare(e.to_string()))?;
        if is_secret_key(key) {
            if value.as_str() == Some(REDACTED) {
                let present = exec
                    .read(
                        "SELECT 1 FROM system_config WHERE key = $1",
                        &[(key, Type::TEXT)],
                    )
                    .await
                    .map_err(|e| PutError::Prepare(e.message))?;
                if present.is_empty() {
                    return Err(PutError::Prepare(format!(
                        "cannot preserve absent config secret {key:?}"
                    )));
                }
                continue;
            }
            let codec = codec.as_ref().ok_or_else(|| {
                PutError::Prepare(format!(
                    "encrypt config secret {key:?}: codec is not configured"
                ))
            })?;
            let sealed = codec
                .encrypt(key, marshalled.as_bytes())
                .map_err(|e| PutError::Prepare(e.to_string()))?;
            texts.push(String::from_utf8(sealed).map_err(|e| PutError::Prepare(e.to_string()))?);
            flags.push(true);
        } else {
            texts.push(marshalled);
            flags.push(false);
        }
        keys.push(key.clone());
    }
    if keys.is_empty() {
        return Ok(());
    }
    let auth = scope(actor);
    let description = kind.description();
    let payload = format!(
        "{}:{}",
        kind.command().trim_end_matches("_set"),
        keys.join(",")
    );
    let outcome = setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand { family: "F02", command: kind.command() },
        &envelope(&auth, operation, &payload),
        &auth,
        deadline(),
        "WITH w AS (INSERT INTO system_config (key, value, encrypted, description, updated_at) \
         SELECT t.k, t.v::jsonb, t.e, $7::text, now() \
         FROM unnest($4::text[], $5::text[], $6::boolean[]) AS t(k, v, e) \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = EXCLUDED.encrypted, updated_at = now() \
         RETURNING 1) SELECT count(*)::bigint FROM w",
        &[(&keys, Type::TEXT_ARRAY), (&texts, Type::TEXT_ARRAY), (&flags, Type::BOOL_ARRAY), (&description, Type::TEXT)],
        |rows| rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()).ok_or_else(crate::invalid),
    )
    .await;
    match outcome {
        CommandOutcome::Committed(_) => Ok(()),
        other => Err(PutError::Outcome(other)),
    }
}

/// Go `ldapConnErrorMessage`.
pub fn conn_error_message(class: Option<super::ConnClass>) -> &'static str {
    match class {
        Some(super::ConnClass::BindAuth) => "Bind failed. Check the bind DN and password.",
        Some(super::ConnClass::Network) => {
            "Could not reach the directory server. Check the host, port, and network path."
        }
        None => "Could not connect to directory server. Check the server address and try again.",
    }
}

pub fn dry_run_json(checked: i64) -> String {
    format!("{{\"checked\":{checked}}}\n")
}

pub fn preview_json(total: usize, rows: &[PreviewRow]) -> String {
    let rows_json = if rows.is_empty() {
        Value::Null
    } else {
        Value::Array(
            rows.iter()
                .map(|r| {
                    let mut o = Map::new();
                    o.insert("email".into(), json!(r.email));
                    o.insert("displayName".into(), json!(r.display_name));
                    o.insert("action".into(), json!(r.action));
                    if !r.reason.is_empty() {
                        o.insert("reason".into(), json!(r.reason));
                    }
                    Value::Object(o)
                })
                .collect(),
        )
    };
    // Go field order: total, rows (struct order, not sorted).
    go_escape(&format!(
        "{{\"total\":{total},\"rows\":{}}}",
        serde_json::to_string(&rows_json).expect("rows")
    )) + "\n"
}

pub fn sync_json(result: &SyncResult) -> String {
    go_escape(&result.json())
}

/// Go `Health`: last LDAP sync summary and the pending conflict count.
pub async fn health(exec: &ScopedExecutor, configured: bool) -> String {
    health_for(exec, configured, "ldap").await
}

/// `Health` for one `identity_sync_log.source` and `sync_conflicts.source`.
pub async fn health_for(exec: &ScopedExecutor, configured: bool, source: &str) -> String {
    let mut status = "unknown";
    let mut last: Option<String> = None;
    let mut numbers = [0i32; 6];
    let mut pending = 0i64;
    if configured {
        let sql = format!(
            "SELECT {TIMESTAMP}, l.users_checked, l.users_created, l.users_updated, l.users_disabled, l.fields_skipped, \
             CASE WHEN l.error IS NULL THEN 0 ELSE 1 END FROM identity_sync_log l WHERE l.source = $1 \
             ORDER BY l.sync_at DESC LIMIT 1"
        );
        if let Ok(rows) = exec.read(&sql, &[(&source, Type::TEXT)]).await {
            if let Some(row) = rows.first() {
                last = Some(row.get::<_, String>(0));
                for (i, n) in numbers.iter_mut().enumerate() {
                    *n = row.get::<_, i32>(i + 1);
                }
                status = if numbers[5] > 0 { "error" } else { "healthy" };
            }
        }
        if let Ok(rows) = exec
            .read(
                "SELECT COUNT(*) FROM sync_conflicts WHERE resolved_at IS NULL AND source = $1",
                &[(&source, Type::TEXT)],
            )
            .await
        {
            pending = rows.first().map(|r| r.get::<_, i64>(0)).unwrap_or(0);
        }
    }
    let body = format!(
        "{{\"lastSync\":{},\"status\":{},\"checked\":{},\"created\":{},\"updated\":{},\"disabled\":{},\"skipped\":{},\"errors\":{},\"pendingConflicts\":{pending}}}",
        last.map_or("null".to_owned(), |t| serde_json::to_string(&t).expect("time")),
        serde_json::to_string(status).expect("status"),
        numbers[0], numbers[1], numbers[2], numbers[3], numbers[4], numbers[5],
    );
    go_json_line(&body)
}

fn go_json_line(body: &str) -> String {
    // Parsing only normalises; the text is already Go-shaped.
    let _ = go_json;
    go_escape(body) + "\n"
}

#[allow(dead_code)]
fn _typecheck(_: &StatementFailure) {}
