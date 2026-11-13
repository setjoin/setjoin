//! The conditional-access policy document model: the allow-list that decides which
//! `conditions` and `actions` shapes a policy may carry. This is the Rust twin of frozen
//! Go's `shared/threat/policyschema.go` (`ValidatePolicyDocument`), kept in this family
//! crate so the admin write path, the import path (slice 2) and the runtime gate
//! (`RequireRuntimeAccess`, ticket #405) share one definition.
//!
//! API for later callers:
//! - [`validate_document`] rejects an unknown condition key, a wrong-typed value or an
//!   out-of-domain enum before persist, returning a [`SchemaError`] whose `Display` is
//!   Go's message byte for byte (the admin API sends it as the 400 detail).
//! - [`parse_object`] is Go's `json.Unmarshal` into `map[string]interface{}` (nil for
//!   `null`, an error for any non-object).
//! - [`allowed_condition_keys`], [`allowed_action_names`], [`allowed_operator_names`] and
//!   [`allowed_client_type_values`] expose the sorted allow-lists.
//! - [`grant_discriminator`] is Go's `grantDiscriminator` (a grant's `type`/`action`).
//!
//! [`eval`] is the shared runtime/simulator evaluator; grant dispatch reuses this
//! module's vocabulary and discriminator.
use serde_json::{Map, Value};
use std::fmt;

/// A JSON object as Go decodes it into `map[string]interface{}`.
pub type Object = Map<String, Value>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Enum(&'static [&'static str]),
    Str,
    Int,
    TimeRange,
    Bool,
    StringArray,
}

/// The `client_type` domain: exactly what Go's `clientTypeFromProtocol` can emit.
const CLIENT_TYPES: [&str; 6] = ["web", "mobile", "imap", "smtp", "caldav", "legacy"];
const TIERS: [&str; 4] = ["low", "medium", "high", "critical"];

/// Every permitted condition key. A key outside this list is rejected, never ignored.
const CONDITIONS: [(&str, Kind); 13] = [
    (
        "device_trust",
        Kind::Enum(&["managed", "known", "unknown", "risky"]),
    ),
    ("ip_reputation", Kind::Enum(&TIERS)),
    ("geo_risk_tier", Kind::Enum(&TIERS)),
    ("user_group", Kind::Int),
    ("auth_method", Kind::Str),
    ("client_type", Kind::Enum(&CLIENT_TYPES)),
    ("time_of_day", Kind::TimeRange),
    ("location_in", Kind::Int),
    ("location_trusted", Kind::Bool),
    (
        "device_platform",
        Kind::Enum(&["windows", "ios", "android", "macos", "linux", "unknown"]),
    ),
    ("country_in", Kind::StringArray),
    ("device_bound", Kind::Bool),
    ("require_approved_client_app", Kind::Bool),
];

/// Grant action verbs (top-level `action`/`type` and nested grants).
const ACTIONS: [&str; 9] = [
    "allow",
    "block",
    "step_up",
    "notify",
    "require_acr",
    "require_strength",
    "limited_web",
    "require_terms",
    "require_risk_remediation",
];
const OPERATORS: [&str; 2] = ["all", "one"];

fn spec(key: &str) -> Option<Kind> {
    CONDITIONS
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, kind)| *kind)
}

fn sorted(mut list: Vec<&'static str>) -> Vec<&'static str> {
    list.sort_unstable();
    list
}
/// Sorted condition-key allow-list (Go `AllowedConditionKeys`).
pub fn allowed_condition_keys() -> Vec<&'static str> {
    sorted(CONDITIONS.iter().map(|(name, _)| *name).collect())
}
/// Sorted grant-action allow-list (Go `AllowedActionNames`).
pub fn allowed_action_names() -> Vec<&'static str> {
    sorted(ACTIONS.to_vec())
}
/// Sorted operator allow-list (Go `AllowedOperatorNames`).
pub fn allowed_operator_names() -> Vec<&'static str> {
    sorted(OPERATORS.to_vec())
}
/// Sorted `client_type` condition domain (Go `AllowedClientTypeValues`).
pub fn allowed_client_type_values() -> Vec<&'static str> {
    sorted(CLIENT_TYPES.to_vec())
}

/// Go's `*threat.PolicySchemaError`: the offending key and value, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError {
    pub key: String,
    pub value: String,
    pub reason: String,
    pub allowed: Vec<&'static str>,
}
impl SchemaError {
    fn new(key: &str, reason: impl Into<String>) -> Self {
        Self {
            key: key.to_owned(),
            value: String::new(),
            reason: reason.into(),
            allowed: Vec::new(),
        }
    }
    fn with_value(key: &str, value: &str, reason: impl Into<String>) -> Self {
        Self {
            value: value.to_owned(),
            ..Self::new(key, reason)
        }
    }
}
impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid policy document: {} [key={}",
            self.reason, self.key
        )?;
        if !self.value.is_empty() {
            write!(f, " value={}", self.value)?;
        }
        f.write_str("]")?;
        if !self.allowed.is_empty() {
            write!(f, " allowed: {}", self.allowed.join(","))?;
        }
        Ok(())
    }
}
impl std::error::Error for SchemaError {}

/// Go's `json.Unmarshal(raw, &map[string]interface{})` for a raw JSON value: `null` leaves
/// the map nil (`Ok(None)`), an object decodes, anything else is an error.
#[allow(clippy::result_unit_err)]
pub fn parse_object(raw: &str) -> Result<Option<Object>, ()> {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Null) => Ok(None),
        Ok(Value::Object(map)) => Ok(Some(map)),
        _ => Err(()),
    }
}

/// Go's `ValidatePolicyDocument`: conditions first, then the grant. A missing document is
/// valid (no constraints, a pure allow). Keys are checked in sorted order, so a document
/// with several faults always reports the same one (Go's map iteration order is random).
pub fn validate_document(
    conditions: Option<&Object>,
    actions: Option<&Object>,
) -> Result<(), SchemaError> {
    if let Some(conditions) = conditions {
        for (key, raw) in conditions {
            let Some(kind) = spec(key) else {
                return Err(SchemaError {
                    allowed: allowed_condition_keys(),
                    ..SchemaError::new(key, "unknown condition key")
                });
            };
            validate_kind(key, kind, raw)?;
        }
    }
    match actions {
        Some(actions) => validate_grant(actions),
        None => Ok(()),
    }
}

fn validate_kind(key: &str, kind: Kind, raw: &Value) -> Result<(), SchemaError> {
    match kind {
        Kind::Enum(domain) => {
            let Some(text) = raw.as_str() else {
                return Err(SchemaError::new(key, "want a string enum value"));
            };
            if !domain.contains(&text) {
                return Err(SchemaError::with_value(
                    key,
                    text,
                    "value out of enum domain",
                ));
            }
        }
        Kind::Str => {
            if !raw.is_string() {
                return Err(SchemaError::new(key, "want a string"));
            }
        }
        Kind::Int => {
            // JSON numbers decode to float64; an integral value is required.
            let Some(number) = raw.as_f64().filter(|_| raw.is_number()) else {
                return Err(SchemaError::new(key, "want an integer (numeric group ID)"));
            };
            // Go compares with float64(int64(f)); amd64 overflows to MinInt64.
            let integral = number.is_finite()
                && (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&number)
                && number == (number as i64) as f64;
            if !integral {
                return Err(SchemaError::new(
                    key,
                    format!("want an integer, got non-integral float64 {}", go_g(number)),
                ));
            }
        }
        Kind::TimeRange => {
            let Some(object) = raw.as_object() else {
                return Err(SchemaError::new(
                    key,
                    "want a {start,end[,tz]} time-range object",
                ));
            };
            for field in ["start", "end"] {
                let Some(text) = object.get(field).and_then(Value::as_str) else {
                    return Err(SchemaError::new(
                        key,
                        format!("time-range missing string '{field}'"),
                    ));
                };
                // The empty string is the deliberate no-bound case.
                if !text.is_empty() && !is_valid_time_of_day(text) {
                    return Err(SchemaError::with_value(
                        key,
                        text,
                        format!(
                            "time-range '{field}' must be strict 24-hour HH:MM (or empty for no bound)"
                        ),
                    ));
                }
            }
        }
        Kind::Bool => {
            if !raw.is_boolean() {
                return Err(SchemaError::new(key, "want a boolean (true/false)"));
            }
        }
        Kind::StringArray => {
            let Some(items) = raw.as_array() else {
                return Err(SchemaError::new(key, "want an array of strings"));
            };
            if items.iter().any(|item| !item.is_string()) {
                return Err(SchemaError::new(key, "array elements must be strings"));
            }
        }
    }
    Ok(())
}

/// Strict 24-hour `HH:MM` (00:00-23:59).
fn is_valid_time_of_day(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() == 5
        && b[2] == b':'
        && [0, 1, 3, 4].iter().all(|i| b[*i].is_ascii_digit())
        && &text[..2] <= "23"
        && &text[3..] <= "59"
}

/// Go's `grantDiscriminator`: the grant's verb from `type` or `action`; `invalid` when
/// either is present but not a non-empty string, or when both are set and differ.
pub fn grant_discriminator(grant: &Object) -> (String, bool) {
    let part = |key: &str| -> Result<String, ()> {
        match grant.get(key) {
            None => Ok(String::new()),
            Some(Value::String(text)) if !text.is_empty() => Ok(text.clone()),
            Some(_) => Err(()),
        }
    };
    let (Ok(kind), Ok(action)) = (part("type"), part("action")) else {
        return (String::new(), true);
    };
    if !kind.is_empty() && !action.is_empty() && kind != action {
        return (String::new(), true);
    }
    if kind.is_empty() {
        (action, false)
    } else {
        (kind, false)
    }
}

fn validate_grant(actions: &Object) -> Result<(), SchemaError> {
    if let Some(value) = actions.get("require_compliant_device") {
        if !value.is_boolean() {
            return Err(SchemaError::new(
                "require_compliant_device",
                "want a boolean (true/false)",
            ));
        }
    }
    for key in ["action", "type"] {
        if let Some(value) = actions.get(key) {
            let Some(text) = value.as_str() else {
                return Err(SchemaError::new(key, "want a string"));
            };
            if !ACTIONS.contains(&text) {
                return Err(SchemaError::with_value(
                    key,
                    text,
                    "value out of grant-action domain",
                ));
            }
        }
    }
    if let (Some(Value::String(kind)), Some(Value::String(action))) =
        (actions.get("type"), actions.get("action"))
    {
        if !kind.is_empty() && !action.is_empty() && kind != action {
            return Err(SchemaError::with_value(
                "type/action",
                &format!("{kind}/{action}"),
                "conflicting non-empty grant discriminators",
            ));
        }
    }
    if let Some(value) = actions.get("operator") {
        let Some(text) = value.as_str() else {
            return Err(SchemaError::new("operator", "want a string"));
        };
        if !OPERATORS.contains(&text) {
            return Err(SchemaError::with_value(
                "operator",
                text,
                "value out of operator domain",
            ));
        }
    }
    if let Some(grants) = actions.get("grants") {
        let Some(items) = grants.as_array() else {
            return Err(SchemaError::new("grants", "want an array of grant objects"));
        };
        if items.is_empty() {
            return Err(SchemaError::new("grants", "grants array must not be empty"));
        }
        for item in items {
            let Some(grant) = item.as_object() else {
                return Err(SchemaError::new("grants", "grant element is not an object"));
            };
            let (verb, invalid) = grant_discriminator(grant);
            if invalid {
                return Err(SchemaError::new(
                    "type/action",
                    "conflicting or malformed grant discriminators",
                ));
            }
            if verb.is_empty() {
                return Err(SchemaError::new(
                    "grants",
                    "grant element is missing a non-empty type or action discriminator",
                ));
            }
            if verb == "require_terms" || verb == "require_risk_remediation" {
                return Err(SchemaError::with_value(
                    "type/action",
                    &verb,
                    format!(
                        "{verb} is a top-level action verb and must not appear in a grants array"
                    ),
                ));
            }
            validate_grant(grant)?;
        }
    }
    Ok(())
}

/// Go's `%v` of a float64: `%g` with the shortest digits, exponent form when the decimal
/// exponent is below -4 or at least 6 (`1e+06`; the 21 cutoff belongs to `encoding/json`).
fn go_g(f: f64) -> String {
    if f == 0.0 {
        return if f.is_sign_negative() { "-0" } else { "0" }.into();
    }
    let text = format!("{f:e}");
    let (mantissa, exp) = text.split_once('e').expect("exponent");
    let exp: i32 = exp.parse().expect("exponent digits");
    if (-4..6).contains(&exp) {
        return format!("{f}");
    }
    let sign = if exp < 0 { '-' } else { '+' };
    format!("{mantissa}e{sign}{:02}", exp.abs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(text: &str) -> Option<Object> {
        parse_object(text).expect("object")
    }
    fn check(conditions: &str, actions: &str) -> Result<(), String> {
        validate_document(object(conditions).as_ref(), object(actions).as_ref())
            .map_err(|e| e.to_string())
    }

    #[test]
    fn missing_documents_are_valid() {
        assert_eq!(validate_document(None, None), Ok(()));
        assert_eq!(check("{}", r#"{"action":"allow"}"#), Ok(()));
    }

    #[test]
    fn unknown_condition_key_lists_the_allow_list() {
        let message = check(r#"{"auth_strength":"x"}"#, "null").unwrap_err();
        assert!(message.starts_with(
            "invalid policy document: unknown condition key [key=auth_strength] allowed: auth_method,client_type,country_in,device_bound,"
        ));
        assert!(message.ends_with("user_group"));
    }

    #[test]
    fn enum_and_type_errors_match_go() {
        assert_eq!(
            check(r#"{"client_type":"browser"}"#, "null").unwrap_err(),
            "invalid policy document: value out of enum domain [key=client_type value=browser]"
        );
        assert_eq!(
            check(r#"{"device_trust":3}"#, "null").unwrap_err(),
            "invalid policy document: want a string enum value [key=device_trust]"
        );
        assert_eq!(
            check(r#"{"user_group":1.5}"#, "null").unwrap_err(),
            "invalid policy document: want an integer, got non-integral float64 1.5 [key=user_group]"
        );
        assert_eq!(
            check(r#"{"user_group":2.0,"location_in":7}"#, "null"),
            Ok(())
        );
        assert_eq!(
            check(r#"{"country_in":["KP",1]}"#, "null").unwrap_err(),
            "invalid policy document: array elements must be strings [key=country_in]"
        );
        assert_eq!(
            check(r#"{"device_bound":"yes"}"#, "null").unwrap_err(),
            "invalid policy document: want a boolean (true/false) [key=device_bound]"
        );
    }

    #[test]
    fn integer_overflow_is_not_integral() {
        assert!(check(r#"{"user_group":9223372036854775808}"#, "null").is_err());
        assert_eq!(
            check(r#"{"user_group":-9223372036854775808}"#, "null"),
            Ok(())
        );
        assert!(check(r#"{"user_group":1e30}"#, "null")
            .unwrap_err()
            .contains("float64 1e+30"));
    }

    #[test]
    fn time_range_is_strict() {
        assert_eq!(
            check(r#"{"time_of_day":{"start":"09:00","end":""}}"#, "null"),
            Ok(())
        );
        assert_eq!(
            check(r#"{"time_of_day":{"start":"9am","end":"10:00"}}"#, "null").unwrap_err(),
            "invalid policy document: time-range 'start' must be strict 24-hour HH:MM (or empty for no bound) [key=time_of_day value=9am]"
        );
        assert!(check(r#"{"time_of_day":{"start":"25:00","end":"10:00"}}"#, "null").is_err());
        assert_eq!(
            check(r#"{"time_of_day":{"start":"09:00"}}"#, "null").unwrap_err(),
            "invalid policy document: time-range missing string 'end' [key=time_of_day]"
        );
    }

    #[test]
    fn grants_follow_the_discriminator_rules() {
        assert_eq!(
            check("{}", r#"{"operator":"all","grants":[{"type":"allow"}]}"#),
            Ok(())
        );
        assert_eq!(
            check("{}", r#"{"action":"nope"}"#).unwrap_err(),
            "invalid policy document: value out of grant-action domain [key=action value=nope]"
        );
        assert_eq!(
            check("{}", r#"{"type":"allow","action":"block"}"#).unwrap_err(),
            "invalid policy document: conflicting non-empty grant discriminators [key=type/action value=allow/block]"
        );
        assert_eq!(
            check("{}", r#"{"grants":[]}"#).unwrap_err(),
            "invalid policy document: grants array must not be empty [key=grants]"
        );
        assert_eq!(
            check("{}", r#"{"grants":[{"type":"require_terms"}]}"#).unwrap_err(),
            "invalid policy document: require_terms is a top-level action verb and must not appear in a grants array [key=type/action value=require_terms]"
        );
        assert_eq!(
            check("{}", r#"{"grants":[{}]}"#).unwrap_err(),
            "invalid policy document: grant element is missing a non-empty type or action discriminator [key=grants]"
        );
        assert_eq!(
            check("{}", r#"{"grants":[{"type":""}]}"#).unwrap_err(),
            "invalid policy document: conflicting or malformed grant discriminators [key=type/action]"
        );
        assert_eq!(
            check("{}", r#"{"operator":"any"}"#).unwrap_err(),
            "invalid policy document: value out of operator domain [key=operator value=any]"
        );
        assert_eq!(
            check("{}", r#"{"require_compliant_device":1}"#).unwrap_err(),
            "invalid policy document: want a boolean (true/false) [key=require_compliant_device]"
        );
    }

    #[test]
    fn parse_object_matches_unmarshal_into_a_map() {
        assert_eq!(parse_object("null"), Ok(None));
        assert!(parse_object("[]").is_err());
        assert!(parse_object("\"x\"").is_err());
        assert!(parse_object("{\"a\":1}").unwrap().is_some());
    }

    #[test]
    fn go_g_matches_percent_v() {
        assert_eq!(go_g(1.5), "1.5");
        assert_eq!(go_g(1234567.5), "1.2345675e+06");
        assert_eq!(go_g(0.00001), "1e-05");
        assert_eq!(go_g(0.0001), "0.0001");
    }
}

pub mod eval;

mod grants;

pub mod store;

mod runtime;

fn s(text: &str) -> String { serde_json::to_string(text).expect("string") }
fn invalid() -> setjoin_pg::StatementFailure { setjoin_pg::StatementFailure { sqlstate:None,hint:None,message:"invalid conditional access result".into() } }
