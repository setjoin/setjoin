//! Frozen Go's ordered conditional-access evaluation. HTTP runtime and the
//! uncached admin simulator share this public seam and the parent vocabulary.
use chrono::{TimeZone, Timelike};
use serde_json::{json, Value};

#[derive(Clone, Default)]
pub struct Context {
    pub feed_hits: i32,
    pub vpn_score: i32,
    pub user_id: i64,
    pub group_ids: Vec<i64>,
    pub role_group_ids: Vec<i64>,
    pub is_guest: bool,
    pub source_ip: String,
    pub country: String,
    pub auth_method: String,
    pub protocol: String,
    pub client_type: String,
    pub user_agent: String,
    pub device_fp: String,
    pub current_acr: String,
    pub completed_factors: Option<Vec<String>>,
    pub device_bound: bool,
    pub enroll_state: String,
    pub risk_level: String,
    pub trust_tier: String,
    pub score_band: String,
    pub geo_tier: String,
    /// Unix seconds; absent means now, as in the HTTP simulator.
    pub request_time: Option<i64>,
}
#[derive(Clone)]
pub struct Policy(pub Value);
impl Policy {
    pub fn from_document(value: Value) -> Self {
        Self(value)
    }
}
#[derive(Clone, Default)]
pub struct Snapshot {
    pub policies: Vec<Policy>,
    pub locations: Option<Vec<Value>>,
    pub strengths: Vec<Value>,
    pub break_glass: Vec<i64>,
}
#[derive(Clone, Debug)]
pub struct Result {
    pub decision: String,
    pub policy_id: i64,
    pub reason: String,
    pub evaluated: Vec<Value>,
    pub remediation: String,
    pub terms_id: i64,
    pub limited_web: bool,
    pub grants: Vec<Value>,
}
impl Default for Result {
    fn default() -> Self {
        Self {
            decision: "allow".into(),
            policy_id: 0,
            reason: "no matching policy (default allow)".into(),
            evaluated: vec![],
            remediation: String::new(),
            terms_id: 0,
            limited_web: false,
            grants: vec![],
        }
    }
}
pub fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("")
}
fn ids(v: &Value, id: i64) -> bool {
    v.as_array()
        .is_some_and(|a| a.iter().any(|v| v.as_i64() == Some(id)))
}
fn scope(p: &Value, c: &Context) -> bool {
    let id = text(p, "scope_target").parse::<i64>().ok();
    match text(p, "scope_type") {
        "global" => true,
        "user" => id == Some(c.user_id),
        "group" => id.is_some_and(|id| c.group_ids.contains(&id)),
        "role" => id.is_some_and(|id| c.role_group_ids.contains(&id)),
        "guests" => text(p, "scope_target").is_empty() && c.is_guest,
        _ => false,
    }
}
fn platform(ua: &str) -> &'static str {
    let ua = ua.to_lowercase();
    for (names, result) in [
        (&["iphone", "ipad", "ipod"][..], "ios"),
        (&["android"][..], "android"),
        (&["windows"][..], "windows"),
        (&["mac os x", "macintosh"][..], "macos"),
        (&["linux"][..], "linux"),
    ] {
        if names.iter().any(|n| ua.contains(n)) {
            return result;
        }
    }
    "unknown"
}
fn in_location(l: &Value, c: &Context) -> bool {
    if !c.country.is_empty()
        && l["countries"].as_array().is_some_and(|a| {
            a.iter().any(|v| {
                v.as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case(&c.country))
            })
        })
    {
        return true;
    }
    let Ok(ip) = c.source_ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    l.get("ip_ranges")
        .or_else(|| l.get("cidrs"))
        .and_then(Value::as_array)
        .is_some_and(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .filter_map(|s| s.parse::<ipnet::IpNet>().ok())
                .any(|n| n.contains(&ip))
        })
}
fn time_matches(v: &Value, c: &Context) -> bool {
    let (start, end) = (text(v, "start"), text(v, "end"));
    if start.is_empty() || end.is_empty() {
        return true;
    }
    let tz = text(v, "tz")
        .parse::<chrono_tz::Tz>()
        .unwrap_or(chrono_tz::UTC);
    let now = c
        .request_time
        .unwrap_or_else(|| chrono::Utc::now().timestamp());
    let Some(t) = tz.timestamp_opt(now, 0).single() else {
        return false;
    };
    let minute = (t.hour() * 60 + t.minute()) as i64;
    let parse = |s: &str| {
        let Some((h, m)) = s.split_once(':') else {
            return minute;
        };
        (h.parse::<i64>().unwrap_or(0) * 60 + m.parse::<i64>().unwrap_or(0)).rem_euclid(1440)
    };
    let (s, e) = (parse(start), parse(end));
    if s <= e {
        minute >= s && minute < e
    } else {
        minute >= s || minute < e
    }
}
fn first_failed(p: &Value, c: &Context, s: &Snapshot) -> Option<&'static str> {
    let cond = &p["conditions"];
    let absent = |key: &str| cond.get(key).is_none_or(|v| v.is_null() || v == "");
    for (key, actual) in [
        (
            "device_trust",
            if c.trust_tier.is_empty() {
                "unknown"
            } else {
                &c.trust_tier
            },
        ),
        (
            "ip_reputation",
            if c.score_band.is_empty() {
                "low"
            } else {
                &c.score_band
            },
        ),
        (
            "geo_risk_tier",
            if c.geo_tier.is_empty() {
                "low"
            } else {
                &c.geo_tier
            },
        ),
    ] {
        if !absent(key) && cond[key].as_str() != Some(actual) {
            return Some(key);
        }
    }
    if !cond["user_group"].is_null()
        && !cond["user_group"]
            .as_i64()
            .is_some_and(|id| c.group_ids.contains(&id))
    {
        return Some("user_group");
    }
    if !absent("auth_method") && cond["auth_method"].as_str() != Some(&c.auth_method) {
        return Some("auth_method");
    }
    if !cond["time_of_day"].is_null()
        && (!cond["time_of_day"].is_object() || !time_matches(&cond["time_of_day"], c))
    {
        return Some("time_of_day");
    }
    if !absent("client_type") && cond["client_type"].as_str() != Some(&c.client_type) {
        return Some("client_type");
    }
    if !cond["location_in"].is_null()
        && !s.locations.as_ref().is_some_and(|ls| {
            ls.iter()
                .any(|l| l["id"] == cond["location_in"] && in_location(l, c))
        })
    {
        return Some("location_in");
    }
    if !cond["location_trusted"].is_null() {
        let Some(locs) = s.locations.as_ref() else {
            return Some("location_in");
        };
        let trusted = locs.iter().any(|l| {
            l["is_trusted"].as_bool().or(l["trusted"].as_bool()) == Some(true) && in_location(l, c)
        });
        if trusted != cond["location_trusted"].as_bool().unwrap_or(false) {
            return Some("location_in");
        }
    }
    if !absent("device_platform")
        && cond["device_platform"].as_str() != Some(platform(&c.user_agent))
    {
        return Some("device_platform");
    }
    if !cond["country_in"].is_null()
        && !cond["country_in"].as_array().is_some_and(|a| {
            a.iter().any(|v| {
                v.as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case(&c.country))
            })
        })
    {
        return Some("country_in");
    }
    if !cond["device_bound"].is_null() && cond["device_bound"].as_bool() != Some(c.device_bound) {
        return Some("device_bound");
    }
    if cond["require_approved_client_app"] == true && !c.device_bound {
        return Some("require_approved_client_app");
    }
    None
}
pub fn evaluate(snapshot: &Snapshot, ctx: &Context) -> Result {
    let mut result = Result::default();
    for Policy(p) in &snapshot.policies {
        let excluded = ids(&p["exclude_users"], ctx.user_id)
            || snapshot.break_glass.contains(&ctx.user_id)
            || ctx
                .group_ids
                .iter()
                .any(|id| ids(&p["exclude_groups"], *id));
        let mut trace = json!({"policy_id":p["id"],"name":p["name"],"priority":p["priority"],"scope":p["scope_type"],"outcome":"skipped"});
        if excluded {
            trace["outcome"] = json!("excluded");
        } else if !scope(p, ctx) {
            trace["first_failed"] = json!(format!("scope:{}", text(p, "scope_type")));
        } else if let Some(key) = first_failed(p, ctx, snapshot) {
            trace["first_failed"] = json!(key);
        } else {
            let decided = super::grants::dispatch(p, ctx, snapshot);
            let decision = &decided.decision;
            if p["state"] == "report_only" {
                trace["outcome"] = json!(format!("would_{decision}"));
            } else if result.policy_id == 0 {
                let trace_so_far = std::mem::take(&mut result.evaluated);
                result = decided;
                result.evaluated = trace_so_far;
                trace["outcome"] = json!("applied");
            }
        }
        result.evaluated.push(trace);
    }
    result
}

/// Frozen Go's `simulateResponse` struct order (unlike sorted map problems).
/// A read-only evaluation never stamps correlation IDs or writes sign-in/audit rows.
pub fn simulate_json(snapshot: &Snapshot, context: &Context) -> String {
    let r = evaluate(snapshot, context);
    let id = if r.policy_id == 0 {
        "null".into()
    } else {
        r.policy_id.to_string()
    };
    let decision = if r.policy_id == 0 {
        "applied"
    } else {
        &r.decision
    };
    let mut body = format!(
        "{{\"matched_policy\":{id},\"decision\":{}",
        super::s(decision)
    );
    if let Some(Policy(p)) = snapshot
        .policies
        .iter()
        .find(|Policy(p)| p["id"].as_i64() == Some(r.policy_id))
    {
        let (_, grants) = super::grants::parse(&p["actions"]);
        if !grants.is_empty() {
            let grants: Vec<_> = grants
                .iter()
                .map(|g| {
                    let mut out = format!("{{\"type\":{}", super::s(text(g, "type")));
                    if !text(g, "acr").is_empty() {
                        out += &format!(",\"acr\":{}", super::s(text(g, "acr")));
                    }
                    if let Some(id) = g["strength_id"].as_i64().filter(|id| *id != 0) {
                        out += &format!(",\"strength_id\":{id}");
                    }
                    out + "}"
                })
                .collect();
            body += &format!(",\"grants\":[{}]", grants.join(","));
        }
    }
    let traces: Vec<_> = r
        .evaluated
        .iter()
        .map(|v| {
            let mut out = format!(
                "{{\"policy_id\":{},\"name\":{},\"priority\":{},\"scope\":{},\"outcome\":{}",
                v["policy_id"],
                super::s(text(v, "name")),
                v["priority"],
                super::s(text(v, "scope")),
                super::s(text(v, "outcome"))
            );
            if !text(v, "first_failed").is_empty() {
                out += &format!(",\"first_failed\":{}", super::s(text(v, "first_failed")));
            }
            out + "}"
        })
        .collect();
    body + &format!(",\"evaluated\":[{}]}}\n", traces.join(","))
}

pub use super::runtime::{risk_score, Engine};
