//! Frozen-Go conditional-access document validation used by the CLI's offline seam.
use crate::client::{go_value, Failure};
use serde_json::Value;
const CONDITIONS: &[&str] = &[
    "auth_method",
    "client_type",
    "country_in",
    "device_bound",
    "device_platform",
    "device_trust",
    "geo_risk_tier",
    "ip_reputation",
    "location_in",
    "location_trusted",
    "require_approved_client_app",
    "time_of_day",
    "user_group",
];
const ACTIONS: &[&str] = &[
    "allow",
    "block",
    "limited_web",
    "notify",
    "require_acr",
    "require_risk_remediation",
    "require_strength",
    "require_terms",
    "step_up",
];
fn shape() -> String {
    format!("{{\"grants\":[{{\"type\":\"<{}>\"}}]}}", ACTIONS.join("|"))
}
fn policy_error(key: &str, value: &str, reason: &str, allowed: bool) -> String {
    format!(
        "invalid policy document: {reason} [key={key}{}]{}",
        if value.is_empty() {
            String::new()
        } else {
            format!(" value={value}")
        },
        if allowed {
            format!(" allowed: {}", CONDITIONS.join(","))
        } else {
            String::new()
        }
    )
}
fn condition(key: &str, v: &Value) -> Result<(), String> {
    let domain = match key {
        "device_trust" => Some(&["managed", "known", "unknown", "risky"][..]),
        "ip_reputation" | "geo_risk_tier" => Some(&["low", "medium", "high", "critical"][..]),
        "client_type" => Some(&["web", "mobile", "imap", "smtp", "caldav", "legacy"][..]),
        "device_platform" => Some(&["windows", "ios", "android", "macos", "linux", "unknown"][..]),
        _ => None,
    };
    let bad = |value: &str, reason: &str| Err(policy_error(key, value, reason, false));
    if let Some(domain) = domain {
        let Some(s) = v.as_str() else {
            return bad("", "want a string enum value");
        };
        if !domain.contains(&s) {
            return bad(s, "value out of enum domain");
        }
        return Ok(());
    }
    match key {
        "auth_method" => {
            if !v.is_string() {
                return bad("", "want a string");
            }
        }
        "user_group" | "location_in" => {
            let Some(n) = v.as_f64() else {
                return bad("", "want an integer (numeric group ID)");
            };
            if n.fract() != 0.0 {
                return bad(
                    "",
                    &format!("want an integer, got non-integral float64 {}", go_value(v)),
                );
            }
        }
        "location_trusted" | "device_bound" | "require_approved_client_app" => {
            if !v.is_boolean() {
                return bad("", "want a boolean (true/false)");
            }
        }
        "country_in" => {
            let Some(a) = v.as_array() else {
                return bad("", "want an array of strings");
            };
            if a.iter().any(|x| !x.is_string()) {
                return bad("", "array elements must be strings");
            }
        }
        "time_of_day" => {
            let Some(o) = v.as_object() else {
                return bad("", "want a {start,end[,tz]} time-range object");
            };
            for key2 in ["start", "end"] {
                let Some(s) = o.get(key2).and_then(Value::as_str) else {
                    return bad("", &format!("time-range missing string '{key2}'"));
                };
                let b = s.as_bytes();
                if !s.is_empty()
                    && (b.len() != 5
                        || b[2] != b':'
                        || !b[..2].iter().chain(&b[3..]).all(u8::is_ascii_digit)
                        || b[..2] > b"23"[..]
                        || b[3..] > b"59"[..])
                {
                    return bad(s,&format!("time-range '{key2}' must be strict 24-hour HH:MM (or empty for no bound)"));
                }
            }
        }
        _ => return Err(policy_error(key, "", "unknown condition key", true)),
    }
    Ok(())
}
fn grants(v: &Value) -> Result<(), String> {
    let Some(o) = v.as_object() else {
        return Ok(());
    };
    let fail = |key: &str, value: &str, reason: &str| Err(policy_error(key, value, reason, false));
    if o.get("require_compliant_device")
        .is_some_and(|v| !v.is_boolean())
    {
        return fail(
            "require_compliant_device",
            "",
            "want a boolean (true/false)",
        );
    }
    for key in ["action", "type"] {
        if let Some(v) = o.get(key) {
            let Some(s) = v.as_str() else {
                return fail(key, "", "want a string");
            };
            if !ACTIONS.contains(&s) {
                return fail(key, s, "value out of grant-action domain");
            }
        }
    }
    let t = v["type"].as_str().unwrap_or("");
    let a = v["action"].as_str().unwrap_or("");
    if !t.is_empty() && !a.is_empty() && t != a {
        return fail(
            "type/action",
            &format!("{t}/{a}"),
            "conflicting non-empty grant discriminators",
        );
    }
    if let Some(op) = o.get("operator") {
        let Some(op) = op.as_str() else {
            return fail("operator", "", "want a string");
        };
        if !["all", "one"].contains(&op) {
            return fail("operator", op, "value out of operator domain");
        }
    }
    if let Some(g) = o.get("grants") {
        let Some(g) = g.as_array() else {
            return fail("grants", "", "want an array of grant objects");
        };
        if g.is_empty() {
            return fail("grants", "", "grants array must not be empty");
        }
        for e in g {
            let Some(o) = e.as_object() else {
                return fail("grants", "", "grant element is not an object");
            };
            let t = e["type"].as_str().unwrap_or("");
            let a = e["action"].as_str().unwrap_or("");
            if o.get("type").is_some_and(|v| !v.is_string())
                || o.get("action").is_some_and(|v| !v.is_string())
                || (!t.is_empty() && !a.is_empty() && t != a)
            {
                return fail(
                    "type/action",
                    "",
                    "conflicting or malformed grant discriminators",
                );
            }
            let d = if t.is_empty() { a } else { t };
            if d.is_empty() {
                return fail(
                    "grants",
                    "",
                    "grant element is missing a non-empty type or action discriminator",
                );
            }
            if ["require_terms", "require_risk_remediation"].contains(&d) {
                return fail(
                    "type/action",
                    d,
                    &format!(
                        "{d} is a top-level action verb and must not appear in a grants array"
                    ),
                );
            }
            grants(e)?;
        }
    }
    Ok(())
}
pub fn validate(doc: &Value) -> Result<Vec<String>, Failure> {
    if !doc.is_object() && !doc.is_null() {
        let ty = if doc.is_array() {
            "array"
        } else if doc.is_string() {
            "string"
        } else if doc.is_boolean() {
            "bool"
        } else {
            "number"
        };
        return Err(format!("BZ085: invalid JSON: json: cannot unmarshal {ty} into Go value of type map[string]interface {{}}").into());
    }
    if let Some(v) = doc.get("schemaVersion") {
        if v.as_f64().unwrap_or(0.0) as i64 != 1 {
            return Err(format!(
                "BZ085: schemaVersion {} is not supported; want 1",
                go_value(v)
            )
            .into());
        }
    }
    let mut warnings = Vec::new();
    for (i, p) in doc["policies"].as_array().into_iter().flatten().enumerate() {
        if !p.is_object() {
            return Err(format!("BZ085: policy[{i}] is not an object").into());
        }
        if !p["conditions"].is_null() {
            let Some(conds) = p["conditions"].as_object() else {
                return Err(format!("BZ085: policy[{i}].conditions must be an object").into());
            };
            for (k, v) in conds {
                condition(k, v).map_err(|e| {
                    format!(
                        "BZ085: policy[{i}]: {e}; allowed condition keys: {}; actions shape: {}",
                        CONDITIONS.join(", "),
                        shape()
                    )
                })?;
            }
        }
        if !p["actions"].is_null() {
            if !p["actions"].is_object() {
                return Err(format!("BZ085: policy[{i}].actions must be an object").into());
            }
            grants(&p["actions"]).map_err(|e| {
                format!(
                    "BZ085: policy[{i}].actions: {e}; valid types: {}; canonical shape: {}",
                    ACTIONS.join(", "),
                    shape()
                )
            })?;
            let mut block = false;
            for (j, g) in p["actions"]["grants"]
                .as_array()
                .into_iter()
                .flatten()
                .enumerate()
            {
                let t = g["type"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .or(g["action"].as_str())
                    .unwrap_or("");
                if t == "allow" && block {
                    warnings.push(format!("policy[{i}].actions.grants[{j}]: allow is shadowed by an earlier block grant (unreachable)"));
                }
                if t == "block" {
                    block = true;
                }
            }
        }
    }
    Ok(warnings)
}
