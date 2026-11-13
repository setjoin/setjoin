//! Group `apps` cases for the `terms-remaining` oracle: `/admin/apps*`. One provider
//! (`collabora`) is seeded; operation ids are fixed so recovery targets are stable and the
//! reducers' generated ids are masked as `<uuid>`.
use super::terms::Case;

const EFFECTS: &str = "SELECT j FROM (SELECT 1 k, created_at c, jsonb_build_object('kind',kind,'state',state,'generation',state_generation,'phase',phase,'reason',reason,'by_someone',requested_by IS NOT NULL,'request',request,'progress',progress)::text j FROM office_app_operations UNION ALL SELECT 2, created_at, jsonb_build_object('revision',revision,'state',state,'provider',provider_id)::text FROM office_app_revisions) x ORDER BY k, c, j";
const PROVIDER: &str = "INSERT INTO office_provider_policies(provider_id,generation,route_state,config,config_sha256,updated_at) VALUES ('collabora',3,'connected_inactive','{\"wopiPublicBaseUrl\":\"https://setjoin.example\"}',repeat('a',64),'2026-10-01 10:00:00+00')";
const REVISION: &str = "INSERT INTO office_app_revisions(id,app_id,revision,provider_id,state,image_reference,image_digest,artifact_receipt,runtime_config,created_at,updated_at) VALUES ('00000000-0000-4000-8000-0000000000a1','collabora-code',1,'collabora','installed_inactive','registry.example/code:1','sha256:0000000000000000000000000000000000000000000000000000000000000001','{}','{}',now() - interval '2 days',now() - interval '2 days')";
const KEY: &str = "6f1c1c0e-5b7e-4c3a-9d0a-1d2f3a4b5c6d";
const OP: &str = "11111111-2222-4333-8444-555555555555";
const DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const PAUSED: &str = "INSERT INTO office_app_operations(id,app_id,kind,state,state_generation,requested_by,reason,idempotency_key,request_digest,request,phase,executor_id,lease_id,lease_expires_at,last_heartbeat_at,created_at,updated_at) VALUES ('11111111-2222-4333-8444-555555555555','collabora-code','install','paused_recoverable',2,{a_user},'seed','7f1c1c0e-5b7e-4c3a-9d0a-1d2f3a4b5c6d','0000000000000000000000000000000000000000000000000000000000000001','{\"providerId\":\"collabora\"}','paused','exec','22222222-2222-4222-8222-222222222222',now() + interval '1 hour',now() - interval '1 minute',now() - interval '1 hour',now() - interval '1 hour')";
const REQUESTED: &str = "INSERT INTO office_app_operations(id,app_id,kind,state,state_generation,requested_by,reason,idempotency_key,request_digest,request,phase,created_at,updated_at) VALUES ('11111111-2222-4333-8444-555555555555','collabora-code','install','requested',2,{a_user},'seed','7f1c1c0e-5b7e-4c3a-9d0a-1d2f3a4b5c6d','0000000000000000000000000000000000000000000000000000000000000001','{\"providerId\":\"collabora\"}','requested',now() - interval '1 hour',now() - interval '1 hour')";

fn base(method: &'static str, pattern: &'static str, perm: &'static str, status: u16) -> Case {
    Case {
        method,
        pattern,
        fill: vec![],
        query: String::new(),
        perm,
        body: String::new(),
        headers: vec![],
        seed: vec![],
        cleanup: vec![
            "UPDATE feature_toggles SET enabled=true WHERE key='feature.office_managed_delivery'".into(),
            "UPDATE audit_policy SET reason_required_areas=array_remove(reason_required_areas,'apps') WHERE id=1".into(),
            "DELETE FROM office_app_revisions WHERE app_id='collabora-code'".into(),
            "DELETE FROM office_app_operations WHERE app_id='collabora-code'".into(),
            "DELETE FROM office_provider_policies WHERE provider_id='collabora'".into(),
        ],
        effects: EFFECTS,
        table: "office_app_operations",
        channels: vec!["office_app_operation_changed"],
        status,
        replace: vec![],
        unshift: vec![],
    }
}

fn install(request: &str) -> String {
    format!("{{\"kind\":\"install\",\"providerId\":\"collabora\",\"expectedProviderGeneration\":3,\"idempotencyKey\":\"{KEY}\",\"request\":{request}}}")
}
const REQUEST: &str = r#"{"profile":"managed-wildcard","ingress":{"hostname":"office.example"},"catalogRevision":"code-v1"}"#;

pub fn specs(action: &str, label: &str) -> Option<Case> {
    let mut c = match action {
        "apps-list" => base("GET", "/admin/apps", "apps.view", 200),
        "apps-request" => base("POST", "/admin/apps/{appId}/operations", "apps.manage", 202),
        "apps-recover" => base(
            "POST",
            "/admin/apps/{appId}/operations/{operationId}/recover",
            "apps.manage",
            202,
        ),
        _ => return None,
    };
    match action {
        "apps-list" => {
            match label {
            "success" | "denied" | "scoped" => {
                c.seed = vec![PROVIDER.into(), REVISION.into(), PAUSED.into()];
            }
            "empty" => {}
            "provider-only" => c.seed = vec![PROVIDER.into()],
            "manage-only" => {
                c.seed = vec![PROVIDER.into()];
                c.perm = "apps.manage";
            }
            "not-ready" => c.seed = vec!["INSERT INTO office_provider_policies(provider_id,generation,route_state,updated_at) VALUES ('collabora',1,'disconnected','2026-10-01 10:00:00+00')".into()],
            "delivery-off" => c.seed = vec![PROVIDER.into(), "UPDATE feature_toggles SET enabled=false WHERE key='feature.office_managed_delivery'".into()],
            "active-operation" => c.seed = vec![PROVIDER.into(), PAUSED.into()],
            "installed" => c.seed = vec![PROVIDER.into(), REVISION.into()],
            "ignored-query" => {
                c.seed = vec![PROVIDER.into()];
                c.query = "?x=%zz".into();
            }
            _ => return None,
            }
        }
        "apps-request" => {
            c.fill = vec!["collabora-code".into()];
            c.seed = vec![PROVIDER.into()];
            c.headers = vec![("idempotency-key", KEY.into()), ("x-audit-reason", "install it".into())];
            c.body = install(REQUEST);
            match label {
                "success" | "denied" | "scoped" => {}
                "repeat" => {}
                "no-reason-not-required" => c.headers.retain(|(n, _)| *n != "x-audit-reason"),
                "reason-required" => {
                    c.seed.push("UPDATE audit_policy SET reason_required_areas=array_append(reason_required_areas,'apps') WHERE id=1".into());
                    c.headers.retain(|(n, _)| *n != "x-audit-reason");
                }
                "reason-required-present" => c.seed.push("UPDATE audit_policy SET reason_required_areas=array_append(reason_required_areas,'apps') WHERE id=1".into()),
                "unknown-app" => c.fill = vec!["other-app".into()],
                "unknown-app-bad-body" => {
                    c.fill = vec!["other-app".into()];
                    c.body = "{".into();
                }
                "bad-json" => c.body = "{\"kind\":".into(),
                "empty-body" => c.body = String::new(),
                "null-body" => c.body = "null".into(),
                "array-body" => c.body = "[1]".into(),
                "unknown-field" => c.body = install(REQUEST).replace("\"kind\"", "\"extra\":1,\"kind\""),
                "folded-keys" => c.body = install(REQUEST).replace("\"kind\"", "\"KIND\"").replace("\"providerId\"", "\"PROVIDERID\""),
                "trailing-data" => c.body = format!("{} {{\"x\":1}}", install(REQUEST)),
                "trailing-space" => c.body = format!("{}  \n", install(REQUEST)),
                "oversize" => c.body = format!("{{\"kind\":\"{}\"}}", "a".repeat(70_000)),
                "kind-number" => c.body = install(REQUEST).replace("\"install\"", "5"),
                "generation-float" => c.body = install(REQUEST).replace("3,", "3.5,"),
                "generation-string" => c.body = install(REQUEST).replace(":3,", ":\"3\","),
                "key-mismatch" => c.headers = vec![("idempotency-key", "00000000-0000-4000-8000-000000000000".into()), ("x-audit-reason", "r".into())],
                "key-missing-header" => c.headers = vec![("x-audit-reason", "r".into())],
                "key-uppercase" => {
                    let upper = KEY.to_uppercase();
                    c.body = install(REQUEST).replace(KEY, &upper);
                    c.headers = vec![("idempotency-key", upper), ("x-audit-reason", "r".into())];
                }
                "key-urn" => {
                    let urn = format!("urn:uuid:{KEY}");
                    c.body = install(REQUEST).replace(KEY, &urn);
                    c.headers = vec![("idempotency-key", urn), ("x-audit-reason", "r".into())];
                }
                "key-empty" => c.body = install(REQUEST).replace(KEY, ""),
                "request-missing" => c.body = format!("{{\"kind\":\"install\",\"providerId\":\"collabora\",\"expectedProviderGeneration\":3,\"idempotencyKey\":\"{KEY}\"}}"),
                "request-null" => c.body = install("null"),
                "request-array" => c.body = install("[1]"),
                "request-string" => c.body = install("\"x\""),
                "request-extra-key" => c.body = install(r#"{"profile":"managed-wildcard","ingress":{},"command":"sh"}"#),
                "request-bad-profile" => c.body = install(r#"{"profile":"bogus","ingress":{}}"#),
                "request-no-ingress" => c.body = install(r#"{"profile":"managed-wildcard"}"#),
                "request-spaced" => c.body = install("{ \"profile\" : \"managed-wildcard\" ,  \"ingress\":{ } }"),
                "bad-kind" => c.body = install(REQUEST).replace("\"install\"", "\"uninstall\""),
                "missing-kind" => c.body = install(REQUEST).replace("\"kind\":\"install\",", ""),
                "provider-missing" => c.seed.clear(),
                "provider-other" => c.body = install(REQUEST).replace("\"collabora\"", "\"other\""),
                "generation-mismatch" => c.body = install(REQUEST).replace(":3,", ":9,"),
                "provider-active" => c.seed = vec!["INSERT INTO office_provider_policies(provider_id,generation,route_state,config,config_sha256,updated_at) VALUES ('collabora',3,'active_for_scope','{}',repeat('a',64),'2026-10-01 10:00:00+00')".into()],
                "already-installed" => c.seed.push(REVISION.into()),
                "operation-active" => c.seed.push(PAUSED.into()),
                "delivery-off" => c.seed.push("UPDATE feature_toggles SET enabled=false WHERE key='feature.office_managed_delivery'".into()),
                "replay-changed-input" => {
                    c.seed.push(format!("INSERT INTO office_app_operations(id,app_id,kind,state,state_generation,requested_by,reason,idempotency_key,request_digest,request,phase,created_at,updated_at) VALUES ('{OP}','collabora-code','install','completed',1,{{a_user}},'seed','{KEY}','different','{{}}','done',now() - interval '1 hour',now() - interval '1 hour')").replace("'different'", &format!("'{DIGEST}'")).replace("'completed'", "'removed'"));
                }
                "reason-whitespace" => c.headers = vec![("idempotency-key", KEY.into()), ("x-audit-reason", "   ".into())],
                _ => return None,
            }
        }
        "apps-recover" => {
            c.fill = vec!["collabora-code".into(), OP.into()];
            c.seed = vec![PROVIDER.into(), PAUSED.into()];
            c.headers = vec![("x-audit-reason", "recover it".into())];
            c.body = r#"{"expectedGeneration":2}"#.into();
            match label {
                "success" | "denied" | "scoped" | "repeat" => {}
                "operation-upper" => c.fill[1] = OP.to_uppercase(),
                "operation-plain" => c.fill[1] = OP.replace('-', ""),
                "operation-urn" => c.fill[1] = format!("urn:uuid:{OP}"),
                "operation-braced" => c.fill[1] = format!("%7B{OP}%7D"),
                "operation-bad" => c.fill[1] = "not-a-uuid".into(),
                "operation-bad-bad-body" => {
                    c.fill[1] = "not-a-uuid".into();
                    c.body = "{".into();
                }
                "unknown-app" => c.fill[0] = "other-app".into(),
                "unknown-app-bad-operation" => {
                    c.fill = vec!["other-app".into(), "bad".into()];
                }
                "no-reason-not-required" => c.headers.clear(),
                "reason-required" => {
                    c.seed.push("UPDATE audit_policy SET reason_required_areas=array_append(reason_required_areas,'apps') WHERE id=1".into());
                    c.headers.clear();
                }
                "bad-json" => c.body = "{\"expectedGeneration\":".into(),
                "empty-body" => c.body = String::new(),
                "null-body" => c.body = "null".into(),
                "array-body" => c.body = "[1]".into(),
                "empty-object" => c.body = "{}".into(),
                "unknown-field" => c.body = r#"{"expectedGeneration":2,"kind":"install"}"#.into(),
                "folded" => c.body = r#"{"EXPECTEDGENERATION":2}"#.into(),
                "generation-float" => c.body = r#"{"expectedGeneration":2.5}"#.into(),
                "generation-string" => c.body = r#"{"expectedGeneration":"2"}"#.into(),
                "generation-null" => c.body = r#"{"expectedGeneration":null}"#.into(),
                "generation-zero" => c.body = r#"{"expectedGeneration":0}"#.into(),
                "generation-negative" => c.body = r#"{"expectedGeneration":-1}"#.into(),
                "generation-mismatch" => c.body = r#"{"expectedGeneration":9}"#.into(),
                "trailing-data" => c.body = r#"{"expectedGeneration":2} {"x":1}"#.into(),
                "trailing-space" => c.body = "{\"expectedGeneration\":2}  \n".into(),
                "operation-missing" => c.fill[1] = "99999999-9999-4999-8999-999999999999".into(),
                "not-recoverable" => {
                    c.seed = vec![PROVIDER.into(), REQUESTED.into()];
                }
                "failed-rollback" => {
                    c.seed = vec![PROVIDER.into(), "INSERT INTO office_app_operations(id,app_id,kind,state,state_generation,requested_by,reason,idempotency_key,request_digest,request,phase,error,executor_id,lease_id,created_at,updated_at) VALUES ('11111111-2222-4333-8444-555555555555','collabora-code','install','failed_terminal',2,{a_user},'seed','7f1c1c0e-5b7e-4c3a-9d0a-1d2f3a4b5c6d','0000000000000000000000000000000000000000000000000000000000000001','{}','failed','{\"code\":\"ROLLBACK_FAILED\"}','exec','22222222-2222-4222-8222-222222222222',now() - interval '1 hour',now() - interval '1 hour')".into()];
                }
                _ => return None,
            }
        }
        _ => return None,
    }
    c.status = if label == "denied" { 403 } else { 0 };
    Some(c)
}
