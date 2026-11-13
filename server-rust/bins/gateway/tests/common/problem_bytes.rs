//! Byte-level check of every `application/problem+json` body a replay reads
//! (#364). Recorded observations hold parsed JSON, which hides key order, so
//! this inspects the raw wire text: Go's `json.Encoder` writes struct field
//! order and a trailing newline, and a title that is not `http.StatusText`
//! for a struct `about:blank` problem is a divergence. Runtime middleware maps
//! have separate frozen machine titles and sorted key shapes, checked explicitly.
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use setjoin_gateway::problem::{title, KEY_ORDER};

struct Keys(Vec<String>);

impl<'de> serde::Deserialize<'de> for Keys {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Keys;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Keys, A::Error> {
                let mut keys = Vec::new();
                while let Some(key) = m.next_key::<String>()? {
                    m.next_value::<IgnoredAny>()?;
                    keys.push(key);
                }
                Ok(Keys(keys))
            }
        }
        d.deserialize_map(V)
    }
}

/// Panics (test code) when `raw` is not byte-for-byte shaped like Go's problem.
pub fn assert_go_problem_bytes(raw: &[u8]) {
    let text = String::from_utf8_lossy(raw);
    assert!(
        raw.ends_with(b"}\n") && !raw[..raw.len() - 1].contains(&b'\n'),
        "problem body must be one line ending in a newline: {text:?}"
    );
    let Keys(keys) = serde_json::from_slice(raw)
        .unwrap_or_else(|e| panic!("problem body is not a JSON object ({e}): {text:?}"));
    let value: serde_json::Value = serde_json::from_slice(raw).unwrap();
    // shared/middleware.denyJSON and denyJSONRemediation encode maps, rather
    // than httputil.Problem structs. These exact runtime shapes are frozen Go.
    let runtime_status = match value["title"].as_str().unwrap_or("") {
        "session_revoked" | "sign_in_frequency" | "step_up_required" | "token_binding_failed" => Some(401),
        "access_blocked" | "device_compliance_unverifiable" | "csrf_failed" => Some(403),
        "Forbidden" if matches!(value["detail"].as_str(), Some("Device has been wiped. Contact your administrator." | "Device is quarantined. Check compliance status in device settings.")) => Some(403),
        _ => None,
    };
    if let Some(status) = runtime_status {
        assert_eq!(value["status"], status);
        assert_eq!(value["type"], "about:blank");
        let expected = if value["title"] == "access_blocked" {
            assert!(value["remediation"].is_string());
            if value.get("remediation_tou_id").is_some() {
                assert!(value["remediation_tou_id"].as_i64().is_some_and(|n| n != 0));
                vec!["detail", "remediation", "remediation_tou_id", "status", "title", "type"]
            } else { vec!["detail", "remediation", "status", "title", "type"] }
        } else if value["title"] == "token_binding_failed" {
            assert_eq!(value["code"], "dpop_admission");
            vec!["code", "detail", "status", "title", "type"]
        } else { vec!["detail", "status", "title", "type"] };
        assert_eq!(keys, expected, "runtime map keys: {text:?}");
        assert!(value["detail"].is_string());
        if keys == ["detail", "status", "title", "type"] {
            assert_eq!(text, setjoin_gateway::problem::middleware(
                status as u16, value["title"].as_str().unwrap(), value["detail"].as_str().unwrap(),
            ));
        }
        return;
    }
    let mut last = None;
    for key in &keys {
        let rank = KEY_ORDER
            .iter()
            .position(|k| k == key)
            .unwrap_or_else(|| panic!("unknown problem key {key:?}: {text:?}"));
        assert!(
            last.is_none_or(|l| l < rank),
            "problem keys out of Go order ({keys:?}): {text:?}"
        );
        last = Some(rank);
    }
    let value: serde_json::Value = serde_json::from_slice(raw).unwrap();
    if value["type"] == "about:blank" {
        let status = value["status"].as_u64().unwrap_or(0) as u16;
        assert_eq!(
            value["title"],
            title(status),
            "about:blank title is not Go's http.StatusText({status}): {text:?}"
        );
    }
}

/// Check `bytes` when the response declared a problem body.
pub fn check_if_problem(content_type: Option<&str>, bytes: &[u8]) {
    // A HEAD answer carries the problem headers and no body.
    if bytes.is_empty() {
        return;
    }
    if content_type.is_some_and(|c| c.starts_with("application/problem+json")) {
        assert_go_problem_bytes(bytes);
    }
}
