use super::eval::{text, Context, Result, Snapshot};
use serde_json::{json, Value};

pub(super) fn parse(actions: &Value) -> (String, Vec<Value>) {
    let op = if text(actions, "operator").is_empty() {
        "all"
    } else {
        text(actions, "operator")
    }
    .to_owned();
    if let Some(array) = actions["grants"].as_array() {
        return (
            op,
            array
                .iter()
                .filter_map(|g| {
                    let m = g.as_object()?;
                    let (kind, invalid) = super::grant_discriminator(m);
                    let mut v = json!({"type":if invalid{""}else{&kind}});
                    if !text(g, "acr").is_empty() {
                        v["acr"] = g["acr"].clone();
                    }
                    if let Some(n) = g["strength_id"].as_i64().filter(|n| *n != 0) {
                        v["strength_id"] = json!(n);
                    }
                    Some(v)
                })
                .collect(),
        );
    }
    if !text(actions, "action").is_empty() {
        let mut g = json!({"type":actions["action"]});
        if !text(actions, "acr").is_empty() {
            g["acr"] = actions["acr"].clone();
        }
        return ("all".into(), vec![g]);
    }
    (op, vec![])
}
pub(super) fn acr_satisfies(token: &str, required: &str) -> bool {
    if required.is_empty() {
        return true;
    }
    let rank = |s| match s {
        "aal1" => 1,
        "aal2" => 2,
        _ => 0,
    };
    if rank(required) > 0 {
        rank(token) >= rank(required)
    } else {
        token == required
    }
}
fn grant(g: &Value, c: &Context, s: &Snapshot) -> &'static str {
    match text(g, "type") {
        "allow" | "limited_web" => "allow",
        "block" => "block",
        "step_up" => "step_up",
        "notify" => "notify",
        "require_acr" => {
            let required = if text(g, "acr").is_empty() {
                "aal2"
            } else {
                text(g, "acr")
            };
            if acr_satisfies(&c.current_acr, required) {
                "allow"
            } else {
                "step_up"
            }
        }
        "require_strength" => {
            let Some(strength) = s.strengths.iter().find(|v| v["id"] == g["strength_id"]) else {
                return "block";
            };
            if c.current_acr.is_empty() && c.completed_factors.is_none() {
                return "block";
            }
            let factors = c.completed_factors.as_deref().unwrap_or_default();
            let satisfied = strength
                .get("requirement")
                .or_else(|| strength.get("combinations"))
                .and_then(Value::as_array)
                .is_some_and(|a| {
                    a.iter().any(|combo| {
                        combo.as_array().is_some_and(|a| {
                            a.iter()
                                .all(|v| v.as_str().is_some_and(|s| factors.iter().any(|f| f == s)))
                        })
                    })
                });
            if acr_satisfies(&c.current_acr, text(strength, "min_acr")) && satisfied {
                "allow"
            } else {
                "step_up"
            }
        }
        _ => "block",
    }
}
fn priority(d: &str) -> u8 {
    match d {
        "block" => 3,
        "step_up" => 2,
        "notify" => 1,
        _ => 0,
    }
}
pub(super) fn dispatch(p: &Value, c: &Context, s: &Snapshot) -> Result {
    let a = &p["actions"];
    let name = text(p, "name");
    let mut r = Result {
        policy_id: p["id"].as_i64().unwrap_or(0),
        reason: text(a, "reason").into(),
        ..Result::default()
    };
    if a["require_compliant_device"] == true {
        if c.device_bound && c.enroll_state == "approved" {
            r.reason = "compliant device (bound + approved)".into();
        } else {
            r.decision = "block".into();
            r.reason = "device not enrolled/approved under lockdown".into();
        }
        return r;
    }
    match text(a, "action") {
        "require_terms" => {
            r.decision = "block".into();
            r.remediation = "terms".into();
            r.terms_id = a["tou_id"].as_i64().unwrap_or(0);
            r.reason = "terms of use acceptance required".into();
            return r;
        }
        "require_risk_remediation" => {
            if matches!(c.risk_level.as_str(), "medium" | "high") {
                r.decision = "block".into();
                r.remediation = "risk".into();
                r.reason = "risk remediation required (re-authenticate)".into();
            } else {
                r.reason = "require_risk_remediation: user risk not elevated".into();
            }
            return r;
        }
        _ => {}
    }
    let (op, grants) = parse(a);
    r.grants = grants.clone();
    if grants.is_empty() {
        r.decision = "block".into();
        r.reason = format!("policy {name:?} blocked (empty grants — fail-closed)");
        return r;
    }
    for g in &grants {
        let d = grant(g, c, s);
        if op == "one" && d == "allow" {
            r.decision = "allow".into();
            if r.reason.is_empty() {
                r.reason = format!(
                    "policy {name:?} matched (operator=one, grant {:?} satisfied)",
                    text(g, "type")
                );
            }
            r.limited_web = g["type"] == "limited_web";
            return r;
        }
        if d == "block" && op != "one" {
            r.decision = "block".into();
            if r.reason.is_empty() {
                r.reason = format!("policy {name:?} blocked (grant type={:?})", text(g, "type"));
            }
            return r;
        }
        if priority(d) > priority(&r.decision) {
            r.decision = d.into();
        }
    }
    if r.reason.is_empty() {
        r.reason = format!("policy {name:?} matched (operator={op})");
    }
    r.limited_web = r.decision == "allow" && grants.iter().any(|g| g["type"] == "limited_web");
    r
}
