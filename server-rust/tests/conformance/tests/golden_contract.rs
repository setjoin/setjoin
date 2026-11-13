//! Public contract for recorded observations and their comparison.
use serde_json::json;
use setjoin_conformance::golden::{compare, compare_reviewed, normalize, record};

#[test]
fn changed_response_and_effects_report_precise_differences() {
    let golden = json!({"response": {"status": 200, "body": "ok"}, "effects": {"state": 1}});
    let replay = json!({"response": {"status": 500, "body": "error"}, "effects": {"state": 2}});
    let diff = compare(&golden, &replay).unwrap_err();
    assert!(diff.contains("/response/status"), "{diff}");
    assert!(diff.contains("/response/body"), "{diff}");
    assert!(diff.contains("/effects/state"), "{diff}");
    assert!(diff.contains("200") && diff.contains("500"), "{diff}");
}

#[test]
fn divergence_requires_review_and_only_accepts_its_recorded_difference() {
    let golden = json!({"audit": [{"action": "email_set", "details": null}]});
    let replay =
        json!({"audit": [{"action": "email_set", "details": {"operation": "<operation>"}}]});
    let mut records = json!([{
        "route": "POST /jmap Email/set", "case": "mark-read", "field": "/audit/0/details",
        "reason": "fixture reason", "reviewer": "", "from": null,
        "to": {"operation": "<operation>"}
    }]);
    assert!(compare_reviewed(
        "POST /jmap Email/set",
        "mark-read",
        &golden,
        &replay,
        &records
    )
    .unwrap_err()
    .contains("reviewer"));
    records[0]["reviewer"] = json!("fixture reviewer");
    assert!(compare_reviewed(
        "POST /jmap Email/set",
        "mark-read",
        &golden,
        &replay,
        &records
    )
    .unwrap_err()
    .contains("reviewed"));
    records[0]["reviewed"] = json!(false);
    assert!(compare_reviewed(
        "POST /jmap Email/set",
        "mark-read",
        &golden,
        &replay,
        &records
    )
    .unwrap_err()
    .contains("reviewed"));
    records[0]["reviewed"] = json!(true);
    assert!(compare_reviewed(
        "POST /jmap Email/set",
        "mark-read",
        &golden,
        &replay,
        &records
    )
    .is_ok());
    let changed = json!({"audit": [{"action": "other", "details": {"operation": "<operation>"}}]});
    let diff = compare_reviewed(
        "POST /jmap Email/set",
        "mark-read",
        &golden,
        &changed,
        &records,
    )
    .unwrap_err();
    assert!(diff.contains("/audit/0/action"), "{diff}");
}

#[test]
fn declared_volatile_fields_are_normalized_without_hiding_effects() {
    let observation = json!({
        "response": {"body": {"accountId": "48", "newState": "2"}},
        "audit": [{"id": 942, "occurred_at": "2026-10-31T03:00:00Z", "action": "email_set"}]
    });
    let rules = json!([
        {"field": "/response/body/accountId", "kind": "id", "placeholder": "<mailbox>"},
        {"field": "/audit/0/id", "kind": "id", "placeholder": "<audit-id>"},
        {"field": "/audit/0/occurred_at", "kind": "timestamp", "placeholder": "<time>"}
    ]);
    assert_eq!(
        normalize(&observation, &rules).unwrap(),
        json!({
            "response": {"body": {"accountId": "<mailbox>", "newState": "2"}},
            "audit": [{"id": "<audit-id>", "occurred_at": "<time>", "action": "email_set"}]
        })
    );
    let missing = json!([{"field": "/audit/0/unknown", "kind": "id", "placeholder": "<id>"}]);
    assert!(normalize(&observation, &missing)
        .unwrap_err()
        .contains("/audit/0/unknown"));
}

#[test]
fn recorded_goldens_cannot_be_overwritten() {
    let dir = std::env::temp_dir().join(format!("gofree-t2-golden-test-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("case.json");
    let original = json!({"request": {"method": "POST", "path": "/jmap"},
        "response": {"status": 200}, "effects": [], "audit": [], "notify": []});
    record(&path, &original).unwrap();
    assert!(record(&path, &json!({"response": {"status": 500}})).is_err());
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(saved, original);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(dir).unwrap();
}
