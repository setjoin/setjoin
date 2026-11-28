//! LDAP/AD admin route bodies (`admin.LDAPHandler`): config preparation, health,
//! preview and result documents. HTTP translation and worker-only config writes stay
//! in the gateway adapter.
use super::{is_secret_key, PreviewRow, SyncResult};
use crate::{go_escape, go_json, sql};
use serde_json::{json, Map, Value};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_config_secret::ConfigSecretCodec;
use setjoin_pg::StatementFailure;
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
    pub fn description(self) -> &'static str {
        match self {
            Kind::Ldap => "LDAP sync config",
            Kind::Ad => "AD sync config",
        }
    }
    pub fn command(self) -> &'static str {
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

/// Encrypted/marshalled config batch ready for `sql::CONFIG_UPSERT_BATCH_ENCRYPTED`.
#[derive(Debug, Clone)]
pub struct PreparedConfig {
    pub keys: Vec<String>,
    pub texts: Vec<String>,
    pub flags: Vec<bool>,
    pub description: &'static str,
    pub command: &'static str,
}

/// Seal secrets (or verify preserved redacted secrets via `AdminReadTx`) and prepare
/// arrays for the worker-only `rust_system_config_upsert_batch_encrypted` reducer.
pub async fn prepare_config(
    codec: Option<Arc<ConfigSecretCodec>>,
    kind: Kind,
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    values: &Map<String, Value>,
) -> Result<PreparedConfig, String> {
    let (mut keys, mut texts, mut flags) = (vec![], vec![], vec![]);
    let mut ordered: Vec<(&String, &Value)> = values.iter().collect();
    ordered.sort_by(|a, b| a.0.cmp(b.0));
    for (key, value) in ordered {
        let marshalled = serde_json::to_string(value).map_err(|e| e.to_string())?;
        if is_secret_key(key) {
            if value.as_str() == Some(REDACTED) {
                let present = factory
                    .run_admin_read_contract(admin, &sql::CONFIG_KEY_EXISTS, &[key])
                    .await
                    .map_err(|e| e.message)?;
                if present.is_empty() {
                    return Err(format!("cannot preserve absent config secret {key:?}"));
                }
                continue;
            }
            let codec = codec
                .as_ref()
                .ok_or_else(|| format!("encrypt config secret {key:?}: codec is not configured"))?;
            let sealed = codec
                .encrypt(key, marshalled.as_bytes())
                .map_err(|e| e.to_string())?;
            texts.push(String::from_utf8(sealed).map_err(|e| e.to_string())?);
            flags.push(true);
        } else {
            texts.push(marshalled);
            flags.push(false);
        }
        keys.push(key.clone());
    }
    Ok(PreparedConfig {
        keys,
        texts,
        flags,
        description: kind.description(),
        command: kind.command(),
    })
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
    go_escape(&format!(
        "{{\"total\":{total},\"rows\":{}}}",
        serde_json::to_string(&rows_json).unwrap_or_else(|_| "null".into())
    )) + "\n"
}

pub fn sync_json(result: &SyncResult) -> String {
    go_escape(&result.json())
}

/// Go `Health`: last LDAP sync summary and the pending conflict count.
pub async fn health(factory: &TxFactory, admin: &AdminPermissionProof, configured: bool) -> String {
    health_for(factory, admin, configured, "ldap").await
}

/// `Health` for one `identity_sync_log.source` and `sync_conflicts.source`.
pub async fn health_for(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    configured: bool,
    source: &str,
) -> String {
    let mut status = "unknown";
    let mut last: Option<String> = None;
    let mut numbers = [0i32; 6];
    let mut pending = 0i64;
    if configured {
        if let Ok(rows) = factory
            .run_admin_read_contract(admin, &sql::HEALTH_LAST_SYNC, &[&source])
            .await
        {
            if let Some(row) = rows.first() {
                if let Ok(ts) = row.try_get::<_, String>(0) {
                    last = Some(ts);
                }
                for (i, n) in numbers.iter_mut().enumerate() {
                    if let Ok(v) = row.try_get::<_, i32>(i + 1) {
                        *n = v;
                    }
                }
                status = if numbers[5] > 0 { "error" } else { "healthy" };
            }
        }
        if let Ok(rows) = factory
            .run_admin_read_contract(admin, &sql::HEALTH_PENDING_CONFLICTS, &[&source])
            .await
        {
            pending = rows
                .first()
                .and_then(|r| r.try_get::<_, i64>(0).ok())
                .unwrap_or(0);
        }
    }
    let body = format!(
        "{{\"lastSync\":{},\"status\":{},\"checked\":{},\"created\":{},\"updated\":{},\"disabled\":{},\"skipped\":{},\"errors\":{},\"pendingConflicts\":{pending}}}",
        last.map_or("null".to_owned(), |t| serde_json::to_string(&t).unwrap_or_else(|_| "null".into())),
        serde_json::to_string(status).unwrap_or_else(|_| "\"unknown\"".into()),
        numbers[0],
        numbers[1],
        numbers[2],
        numbers[3],
        numbers[4],
        numbers[5],
    );
    go_json_line(&body)
}

fn go_json_line(body: &str) -> String {
    let _ = go_json;
    go_escape(body) + "\n"
}

#[allow(dead_code)]
fn _typecheck(_: &StatementFailure) {}
