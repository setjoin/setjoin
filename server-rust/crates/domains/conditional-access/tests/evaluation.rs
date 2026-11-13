use serde_json::json;
use setjoin_conditional_access::policy::eval::{evaluate, Context, Policy, Snapshot};

#[test]
fn first_enforcing_match_does_not_let_report_only_shadow_a_block() {
    let snapshot = Snapshot {
        policies: vec![
            Policy::from_document(
                json!({"id":1,"name":"observe","priority":1,"state":"report_only","scope_type":"global","conditions":{},"actions":{"action":"allow"}}),
            ),
            Policy::from_document(
                json!({"id":2,"name":"deny","priority":2,"state":"on","scope_type":"user","scope_target":"7","conditions":{},"actions":{"action":"block","reason":"denied by policy"}}),
            ),
        ],
        ..Default::default()
    };
    let result = evaluate(
        &snapshot,
        &Context {
            user_id: 7,
            ..Default::default()
        },
    );
    assert_eq!(result.decision, "block");
    assert_eq!(result.policy_id, 2);
    assert_eq!(result.reason, "denied by policy");
    assert_eq!(result.evaluated[0]["outcome"], "would_allow");
}

#[test]
fn scope_exclusions_and_conditions_explain_the_first_miss() {
    let mut snapshot = Snapshot {
        policies: vec![Policy::from_document(
            json!({"id":3,"name":"network","priority":3,"state":"on","scope_type":"global","exclude_users":[9],"conditions":{"country_in":["US"],"device_bound":true},"actions":{"action":"block"}}),
        )],
        ..Default::default()
    };
    let ctx = Context {
        user_id: 7,
        country: "CA".into(),
        ..Default::default()
    };
    let r = evaluate(&snapshot, &ctx);
    assert_eq!(r.decision, "allow");
    assert_eq!(r.evaluated[0]["first_failed"], "country_in");
    let r = evaluate(
        &snapshot,
        &Context {
            country: "us".into(),
            ..ctx.clone()
        },
    );
    assert_eq!(r.evaluated[0]["first_failed"], "device_bound");
    let r = evaluate(
        &snapshot,
        &Context {
            country: "us".into(),
            device_bound: true,
            ..ctx.clone()
        },
    );
    assert_eq!(r.decision, "block");
    snapshot.break_glass = vec![7];
    assert_eq!(
        evaluate(&snapshot, &ctx).evaluated[0]["outcome"],
        "excluded"
    );
}

#[test]
fn grants_combine_assurance_and_preserve_remediation() {
    let p = |actions| {
        Policy::from_document(
            json!({"id":4,"name":"assurance","priority":1,"state":"on","scope_type":"global","conditions":{},"actions":actions}),
        )
    };
    let mut s = Snapshot {
        policies: vec![p(
            json!({"operator":"all","grants":[{"type":"allow"},{"action":"require_acr","acr":"aal2"}]}),
        )],
        ..Default::default()
    };
    assert_eq!(evaluate(&s, &Context::default()).decision, "step_up");
    assert_eq!(
        evaluate(
            &s,
            &Context {
                current_acr: "aal2".into(),
                ..Default::default()
            }
        )
        .decision,
        "allow"
    );
    s.policies = vec![p(json!({"action":"require_terms","tou_id":12}))];
    let r = evaluate(&s, &Context::default());
    assert_eq!(r.decision, "block");
    assert_eq!(r.remediation, "terms");
    assert_eq!(r.terms_id, 12);
    s.policies = vec![p(
        json!({"operator":"one","grants":[{"type":"block"},{"type":"limited_web"}]}),
    )];
    let r = evaluate(&s, &Context::default());
    assert_eq!(r.decision, "allow");
    assert!(r.limited_web);
}
