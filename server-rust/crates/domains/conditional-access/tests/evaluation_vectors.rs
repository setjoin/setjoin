//! Independent observations recorded by the frozen-Go evaluation overlay.
use serde_json::{json, Value};
use setjoin_conditional_access::policy::eval::{evaluate, Context, Policy, Snapshot};

#[test]
fn frozen_go_evaluation_vectors() {
    let cases: Vec<Value> = serde_json::from_str(include_str!(
        "../../../../tests/conformance/authzgates/evaluation-cases.json"
    ))
    .unwrap();
    let goldens: Vec<Value> = serde_json::from_str(include_str!(
        "../../../../tests/conformance/authzgates/evaluation-golden.json"
    ))
    .unwrap();
    assert_eq!(cases.len(), goldens.len());
    for (case, golden) in cases.iter().zip(&goldens) {
        let v = &case["context"];
        let t = |k: &str| v[k].as_str().unwrap_or("").to_owned();
        let ids = |k: &str| {
            v[k].as_array()
                .map_or_else(Vec::new, |a| a.iter().filter_map(Value::as_i64).collect())
        };
        let c = Context {
            user_id: v["user_id"].as_i64().unwrap_or(0),
            group_ids: ids("group_ids"),
            role_group_ids: ids("role_group_ids"),
            is_guest: v["is_guest"] == true,
            source_ip: t("source_ip"),
            country: t("country"),
            auth_method: t("auth_method"),
            protocol: t("protocol"),
            client_type: t("client_type"),
            user_agent: t("user_agent"),
            device_fp: t("device_fp"),
            current_acr: t("current_acr"),
            completed_factors: v["completed_factors"].as_array().map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            }),
            device_bound: v["device_bound"] == true,
            enroll_state: t("enroll_state"),
            risk_level: t("risk_level"),
            trust_tier: t("trust_tier_override"),
            request_time: Some(
                chrono::DateTime::parse_from_rfc3339(v["request_time"].as_str().unwrap())
                    .unwrap()
                    .timestamp(),
            ),
            ..Default::default()
        };
        let s = Snapshot {
            policies: case["policies"]
                .as_array()
                .unwrap()
                .iter()
                .cloned()
                .map(Policy::from_document)
                .collect(),
            locations: case["locations"].as_array().cloned(),
            strengths: case["strengths"].as_array().unwrap().clone(),
            break_glass: case["break_glass"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_i64)
                .collect(),
        };
        let r = evaluate(&s, &c);
        let simulated: Value = serde_json::from_str(
            &setjoin_conditional_access::policy::eval::simulate_json(&s, &c),
        )
        .unwrap();
        assert_eq!(
            simulated, golden["simulation"],
            "simulation {}",
            case["name"]
        );
        let observed = json!({"name":case["name"],"decision":r.decision,"reason":r.reason,"remediation":r.remediation,"terms_id":r.terms_id,"limited_web":r.limited_web});
        let mut expected = golden.clone();
        expected.as_object_mut().unwrap().remove("simulation");
        assert_eq!(observed, expected, "{}", case["name"]);
        assert_eq!(
            json!(r.evaluated),
            golden["simulation"]["evaluated"],
            "trace {}",
            case["name"]
        );
    }
}
