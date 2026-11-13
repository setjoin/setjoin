//! Platform slice `system-features`, group `features`: the feature-toggle registry admin
//! surface (`/admin/features*`).
//!
//! Go's `FeaturesHandler`. The compiled registry (`shared/toggle` definitions, operator
//! semantics and the registry digest) is ported here; mutation authority stays in the V183
//! reducers `feature_toggle_set`, `feature_toggle_delete_unknown` and
//! `feature_toggle_registry_mode_set`, each one receipted statement.
use super::{command, deadline, done, envelope, invalid, s, scope};
use crate::registry_data::DEFINITIONS;
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

/// Go's `SodModeToggleKey`: only the dedicated SoD endpoint may flip it.
pub const SOD_MODE_KEY: &str = "dengbao.sod_mode";

/// The compiled default of a registered key (Go's `toggle.Lookup`).
pub fn lookup(key: &str) -> Option<bool> {
    DEFINITIONS.iter().find(|(k, _)| *k == key).map(|(_, d)| *d)
}

/// Go's `toggle.RegistryDigest`: SHA-256 of `json.Marshal(definitions)`.
pub fn registry_digest() -> String {
    let body: Vec<String> = DEFINITIONS
        .iter()
        .map(|(key, default)| format!("{{\"key\":{},\"defaultEnabled\":{default}}}", s(key)))
        .collect();
    let digest = Sha256::digest(format!("[{}]", body.join(",")).as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Go's `featureKeyPattern` `^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$`.
fn dotted_key(key: &str) -> bool {
    let segments: Vec<&str> = key.split('.').collect();
    segments.len() >= 2
        && segments.iter().all(|segment| {
            let bytes = segment.as_bytes();
            bytes.first().is_some_and(|b| b.is_ascii_lowercase())
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
        })
}

/// Go's `validFeatureKey`.
pub fn valid_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 128 {
        return false;
    }
    dotted_key(key) || lookup(key).is_some()
}

/// One operator-semantics row (Go's `operatorSemantics`).
struct Semantics {
    change_mode: &'static str,
    disable_behavior: &'static str,
    dependencies: &'static [&'static str],
    confirmation_required: bool,
}
const DISCONNECT: Semantics = Semantics {
    change_mode: "disconnect-live-clients",
    disable_behavior: "immediate",
    dependencies: &[],
    confirmation_required: false,
};
const CONFIRMED: Semantics = Semantics {
    change_mode: "live",
    disable_behavior: "immediate",
    dependencies: &[],
    confirmation_required: true,
};
fn drain(dependencies: &'static [&'static str]) -> Semantics {
    Semantics {
        change_mode: "live",
        disable_behavior: "stop-admission-drain-existing",
        dependencies,
        confirmation_required: false,
    }
}
fn semantics(key: &str) -> Option<Semantics> {
    Some(match key {
        "feature.imap"
        | "feature.smtp_inbound"
        | "feature.smtp_submission"
        | "feature.ldap_gal"
        | "feature.caldav"
        | "feature.carddav" => DISCONNECT,
        "feature.conditional_access"
        | "feature.device_trust_enforcement"
        | "feature.cae_runtime"
        | "feature.device_lockdown"
        | "feature.require_mfa"
        | "feature.disable_basic_auth"
        | "feature.token_binding"
        | "feature.user_risk" => CONFIRMED,
        "feature.meet_recording"
        | "feature.meet_captions"
        | "feature.meet_semantic_recording"
        | "feature.meet_local_recording" => drain(&["feature.meet"]),
        "feature.meet_document_presentation" => drain(&["feature.meet", "feature.drive"]),
        "feature.webhook_publication_outbox" => drain(&[]),
        _ => return None,
    })
}

/// The four toggles Go's gateway pins from its process configuration
/// (`toggleOverrides`): read from the environment as the config loader does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overrides {
    pub kerberos: bool,
    pub ad_sync: bool,
    pub dnssec: bool,
    pub cert_rollout: bool,
}
impl Default for Overrides {
    fn default() -> Self {
        Self {
            kerberos: false,
            ad_sync: false,
            dnssec: true,
            cert_rollout: false,
        }
    }
}
impl Overrides {
    pub fn from_env(env: &dyn Fn(&str) -> Option<String>) -> Self {
        let parse = |name: &str, default: bool| match env(name).filter(|v| !v.is_empty()) {
            None => default,
            Some(v) => matches!(v.as_str(), "1" | "t" | "T" | "TRUE" | "true" | "True"),
        };
        let base = Self::default();
        Self {
            kerberos: parse("KERBEROS_ENABLED", base.kerberos),
            ad_sync: parse("AD_SYNC_ENABLED", base.ad_sync),
            dnssec: parse("DNSSEC_ENABLED", base.dnssec),
            cert_rollout: parse("TLS_AUTOCERT_ROLLOUT", base.cert_rollout),
        }
    }
    fn get(&self, key: &str) -> Option<bool> {
        match key {
            "feature.kerberos" => Some(self.kerberos),
            "feature.ad_sync" => Some(self.ad_sync),
            "feature.dnssec" => Some(self.dnssec),
            "feature.cert_rollout" => Some(self.cert_rollout),
            _ => None,
        }
    }
}

/// Go's `FeatureFlags.Resolve` over the database snapshot the gateway holds: the
/// environment override, then the stored row, then the compiled default; an unregistered
/// key is dropped from the snapshot in enforce mode.
fn resolve(
    key: &str,
    stored: Option<bool>,
    enforce: bool,
    overrides: &Overrides,
) -> (bool, &'static str) {
    let registered = lookup(key);
    if let Some(v) = overrides.get(key) {
        if !enforce || registered.is_some() {
            return (v, "environment");
        }
    }
    if let Some(v) = stored {
        if !enforce || registered.is_some() {
            return (v, "database");
        }
    }
    if let Some(v) = registered {
        return (v, "default");
    }
    (!enforce, "default")
}

struct Row {
    key: String,
    stored: Option<bool>,
    default: bool,
    description: String,
    classification: String,
}

/// `GET /admin/features`. `Err(None)` is the missing registry-state row (Go's internal
/// problem); `Err(Some(_))` a failed query.
pub async fn list(
    exec: &ScopedExecutor,
    overrides: &Overrides,
) -> Result<String, Option<StatementFailure>> {
    let rows = exec
        .read(
            "SELECT ft.key, ft.enabled, coalesce(ft.description,''), \
             feature_registry_classify(ft.key), s.mode \
             FROM feature_toggle_registry_state s LEFT JOIN feature_toggles ft ON true \
             WHERE s.singleton ORDER BY ft.key",
            &[],
        )
        .await
        .map_err(Some)?;
    let mut by_key: BTreeMap<String, Row> = BTreeMap::new();
    let mut mode = "observe".to_owned();
    let mut saw_state = false;
    for row in &rows {
        let key: Option<String> = row.try_get(0).map_err(|_| None)?;
        let stored: Option<bool> = row.try_get(1).map_err(|_| None)?;
        let description: Option<String> = row.try_get(2).map_err(|_| None)?;
        let classification: Option<String> = row.try_get(3).map_err(|_| None)?;
        mode = row.try_get(4).map_err(|_| None)?;
        saw_state = true;
        let (Some(key), Some(stored)) = (key, stored) else {
            continue;
        };
        let default = lookup(&key).unwrap_or(true);
        by_key.insert(
            key.clone(),
            Row {
                key,
                stored: Some(stored),
                default,
                description: description.unwrap_or_default(),
                classification: classification.unwrap_or_default(),
            },
        );
    }
    if !saw_state {
        return Err(None);
    }
    for (key, default) in DEFINITIONS {
        by_key.entry(key.to_owned()).or_insert_with(|| Row {
            key: key.to_owned(),
            stored: None,
            default,
            description: String::new(),
            classification: "known".into(),
        });
    }
    let enforce = mode == "enforce";
    let out: Vec<String> = by_key
        .values()
        .map(|row| render_row(row, &mode, enforce, overrides))
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

fn render_row(row: &Row, mode: &str, enforce: bool, overrides: &Overrides) -> String {
    let (effective, source) = resolve(&row.key, row.stored, enforce, overrides);
    let sem = semantics(&row.key);
    let (change, disable, deps, confirm) = match &sem {
        Some(x) => (
            x.change_mode,
            x.disable_behavior,
            x.dependencies
                .iter()
                .map(|d| s(d))
                .collect::<Vec<_>>()
                .join(","),
            x.confirmation_required,
        ),
        None => ("", "", String::new(), false),
    };
    format!(
        "{{\"key\":{},\"enabled\":{},\"storedEnabled\":{},\"defaultEnabled\":{},\"description\":{},\"classification\":{},\"registryMode\":{},\"gatewayEffective\":{effective},\"gatewaySource\":{},\"authserverEffective\":null,\"authserverSource\":\"not_reported\",\"changeMode\":{},\"disableBehavior\":{},\"dependencies\":[{deps}],\"confirmationRequired\":{confirm}}}",
        s(&row.key),
        row.stored.unwrap_or(row.default),
        row.stored.map_or("null".to_owned(), |v| v.to_string()),
        row.default,
        s(&row.description),
        s(&row.classification),
        s(mode),
        s(source),
        s(change),
        s(disable),
    )
}

/// Reducer statement shape: the verified-actor guard first, as every Platform command.
const GUARD: &str = "WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''";

fn one_jsonb(rows: &[setjoin_pg::Row]) -> Result<String, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .filter(|_| rows.len() == 1)
        .ok_or_else(invalid)
}

/// `PUT /admin/features/{key}`: `feature_toggle_set`.
pub async fn set(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    key: &str,
    enabled: bool,
    ip: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("feature_toggle_set"),
        &envelope(&auth, operation, &format!("{key}:{enabled}:{reason}")),
        &auth,
        deadline(),
        &format!(
            "SELECT public.feature_toggle_set($4::text, $5::bool, $2::bigint, $6::text::inet, $7::text)::text {GUARD}"
        ),
        &[
            (&key, Type::TEXT),
            (&enabled, Type::BOOL),
            (&ip, Type::TEXT),
            (&reason, Type::TEXT),
        ],
        |rows| one_jsonb(rows).map(|_| ()),
    )
    .await
}

/// `DELETE /admin/features/{key}`: `feature_toggle_delete_unknown`.
pub async fn delete_unknown(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    key: &str,
    ip: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("feature_toggle_delete_unknown"),
        &envelope(&auth, operation, &format!("{key}:{reason}")),
        &auth,
        deadline(),
        &format!(
            "SELECT public.feature_toggle_delete_unknown($4::text, $2::bigint, $5::text::inet, $6::text)::text {GUARD}"
        ),
        &[(&key, Type::TEXT), (&ip, Type::TEXT), (&reason, Type::TEXT)],
        |rows| one_jsonb(rows).map(|_| ()),
    )
    .await
}

/// `PUT /admin/features/registry-mode`: `feature_toggle_registry_mode_set` with the
/// compiled digest. The committed result is the reducer's jsonb text.
pub async fn set_registry_mode(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    mode: &str,
    ip: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    let digest = registry_digest();
    setjoin_pg::run_receipted_command(
        exec,
        command("feature_toggle_registry_mode_set"),
        &envelope(&auth, operation, &format!("{mode}:{digest}:{reason}")),
        &auth,
        deadline(),
        &format!(
            "SELECT public.feature_toggle_registry_mode_set($4::text, $5::text, $2::bigint, $6::text::inet, $7::text)::text {GUARD}"
        ),
        &[
            (&mode, Type::TEXT),
            (&digest, Type::TEXT),
            (&ip, Type::TEXT),
            (&reason, Type::TEXT),
        ],
        one_jsonb,
    )
    .await
}

/// Go's `featureToggleRow`-independent mapping of a reducer refusal: the HINT's `type`
/// picks the status (400 for the three malformed-input types, else 409), the SQLSTATE's
/// class picks the detail (`invalidArguments` for BZ261, `conflict` for BZ262/BZ263).
/// `None` is an unclassified failure (Go's internal problem).
pub struct ReducerProblem {
    pub status: u16,
    pub kind: String,
    pub detail: &'static str,
}
pub fn reducer_problem(failure: &StatementFailure) -> Option<ReducerProblem> {
    let code = failure.sqlstate.as_deref()?;
    let detail = match code {
        "BZ261" => "invalidArguments",
        "BZ262" | "BZ263" => "conflict",
        _ => return None,
    };
    let kind = match failure.hint.as_deref() {
        Some(hint) if !hint.is_empty() => {
            let value: serde_json::Value = serde_json::from_str(hint).ok()?;
            if !value.is_object() && !value.is_null() {
                return None;
            }
            // `json.Unmarshal` into the typed struct: a non-string `type` is a parse error.
            match value.get("type") {
                None | Some(serde_json::Value::Null) => code.to_owned(),
                Some(serde_json::Value::String(t)) if !t.is_empty() => t.clone(),
                Some(serde_json::Value::String(_)) => code.to_owned(),
                Some(_) => return None,
            }
        }
        _ => code.to_owned(),
    };
    let status = if matches!(
        kind.as_str(),
        "invalid_feature_key" | "invalid_audit_reason" | "invalid_registry_mode"
    ) {
        400
    } else {
        409
    };
    Some(ReducerProblem {
        status,
        kind,
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_matches_newest_snapshot() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../shared/toggle/testdata");
        let mut newest: Option<(u32, std::path::PathBuf)> = None;
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(version) = name
                .strip_prefix("registry-v")
                .and_then(|n| n.strip_suffix(".json"))
                .and_then(|n| n.parse::<u32>().ok())
            {
                if newest.as_ref().is_none_or(|(v, _)| version > *v) {
                    newest = Some((version, entry.path()));
                }
            }
        }
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(newest.unwrap().1).unwrap()).unwrap();
        let expected: Vec<(String, bool)> = doc["definitions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                (
                    d["key"].as_str().unwrap().to_owned(),
                    d["defaultEnabled"].as_bool().unwrap(),
                )
            })
            .collect();
        let compiled: Vec<(String, bool)> = DEFINITIONS
            .iter()
            .map(|(k, d)| ((*k).to_owned(), *d))
            .collect();
        assert_eq!(compiled, expected);
        assert_eq!(registry_digest(), doc["registryDigest"].as_str().unwrap());
    }

    #[test]
    fn key_shape_follows_go() {
        assert!(valid_key("feature.imap"));
        assert!(
            valid_key("device_telemetry"),
            "registered legacy keys are valid"
        );
        assert!(valid_key("a.b.c_1"));
        assert!(!valid_key("nodots"));
        assert!(!valid_key("Feature.x"));
        assert!(!valid_key("a..b"));
        assert!(!valid_key(&format!("a.{}", "b".repeat(127))));
    }

    #[test]
    fn resolution_follows_go() {
        let o = Overrides::default();
        assert_eq!(
            resolve("feature.dnssec", None, false, &o),
            (true, "environment")
        );
        assert_eq!(
            resolve("feature.imap", Some(false), false, &o),
            (false, "database")
        );
        assert_eq!(
            resolve("nope.x", Some(false), false, &o),
            (false, "database")
        );
        assert_eq!(resolve("nope.x", Some(false), true, &o), (false, "default"));
        assert_eq!(resolve("nope.x", None, false, &o), (true, "default"));
    }
}
