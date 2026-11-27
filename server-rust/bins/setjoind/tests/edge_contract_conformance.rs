//! Live `setjoind` HTTP conformance test against `contracts/edge/openapi/edge.v1.yaml` (#561).
//!
//! Spawns a real `setjoind --subsystems=all` instance on an ephemeral loopback
//! port against live PostgreSQL (`TEST_DB_DSN` / `DB_DSN`), exercises every
//! contracted pilot endpoint (health, rules CRUD + partial PUT + retro-apply,
//! populated inbound AND outbound message traces, offline size estimate,
//! mailbox quota, view preferences GET/PUT, plus 401/400/404 RFC 9457
//! `ProblemDetails`), and validates:
//! 1. Response status code & `Content-Type` against committed OpenAPI 3.1 YAML.
//! 2. Full recursive JSON schema conformance (including `anyOf`/`oneOf`
//!    variant required-field and nested-property validation).
//! 3. Exact JSON round-trip equality (`live JSON Value == DTO -> JSON Value`)
//!    through `setjoin_edge_contract::generated::*` plain `serde` DTOs.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use setjoin_edge_contract::{
    ApplyJobStatus, ApplyRetroRequest, ApplyRetroResult, ApplyStatus, CreateRuleResponse,
    HealthStatus, MailboxQuota, MessageTrace, OfflineSizeEstimate, OkStatus, OutboundDirection,
    ProblemDetails, ReadyStatus, ReadyVerdict, RetroWindowInput, RuleAction, RuleCondition,
    RuleInput, RuleUpdateInput, RunOn, UserRule, ViewPreferences, CONTRACTED_OPERATIONS,
    OPENAPI_VERSION,
};
use tokio_postgres::NoTls;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("canonical repo root")
}

fn load_edge_openapi() -> Value {
    let spec_path = repo_root().join("contracts/edge/openapi/edge.v1.yaml");
    let raw = std::fs::read_to_string(&spec_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", spec_path.display()));
    serde_saphyr::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse OpenAPI YAML {}: {e}", spec_path.display()))
}

fn resolve_schema<'a>(doc: &'a Value, schema: &'a Value) -> &'a Value {
    if let Some(ref_str) = schema.get("$ref").and_then(Value::as_str) {
        if let Some(name) = ref_str.strip_prefix("#/components/schemas/") {
            return doc
                .pointer(&format!("/components/schemas/{name}"))
                .unwrap_or_else(|| panic!("unresolved $ref: {ref_str}"));
        }
    }
    schema
}

/// Full recursive OpenAPI 3.1 value validator (returns Err on any mismatch,
/// enabling full structural validation of `anyOf`/`oneOf` union variants).
fn check_value_against_schema(
    doc: &Value,
    schema: &Value,
    value: &Value,
    path: &str,
) -> Result<(), String> {
    let resolved = resolve_schema(doc, schema);

    if let Some(branches) = resolved.get("oneOf").and_then(Value::as_array) {
        let mut matches = 0usize;
        let mut branch_errors = Vec::new();
        for (i, branch) in branches.iter().enumerate() {
            match check_value_against_schema(doc, branch, value, &format!("{path}|oneOf[{i}]")) {
                Ok(()) => matches += 1,
                Err(err) => branch_errors.push(err),
            }
        }
        if matches != 1 {
            return Err(format!(
                "OpenAPI oneOf mismatch at {path}: expected exactly 1 matching variant, got {matches} (value={value}, errors={})",
                branch_errors.join("; ")
            ));
        }
        return Ok(());
    }

    if let Some(branches) = resolved.get("anyOf").and_then(Value::as_array) {
        let mut branch_errors = Vec::new();
        for (i, branch) in branches.iter().enumerate() {
            match check_value_against_schema(doc, branch, value, &format!("{path}|anyOf[{i}]")) {
                Ok(()) => return Ok(()),
                Err(err) => branch_errors.push(err),
            }
        }
        return Err(format!(
            "OpenAPI anyOf mismatch at {path}: value {value} matched no variant ({})",
            branch_errors.join("; ")
        ));
    }

    if let Some(enum_vals) = resolved.get("enum").and_then(Value::as_array) {
        if !enum_vals.contains(value) {
            return Err(format!(
                "OpenAPI enum mismatch at {path}: {value} not in {enum_vals:?}"
            ));
        }
    }

    let expected_type = resolved.get("type").and_then(Value::as_str);
    match expected_type {
        Some("null") => {
            if !value.is_null() {
                return Err(format!("{path}: expected null, got {value}"));
            }
        }
        Some("string") => {
            if !value.is_string() {
                return Err(format!("{path}: expected string, got {value}"));
            }
        }
        Some("boolean") => {
            if !value.is_boolean() {
                return Err(format!("{path}: expected boolean, got {value}"));
            }
        }
        Some("integer") => {
            if value.as_i64().is_none() && value.as_u64().is_none() {
                return Err(format!("{path}: expected integer, got {value}"));
            }
        }
        Some("number") => {
            if !value.is_number() {
                return Err(format!("{path}: expected number, got {value}"));
            }
        }
        Some("array") => {
            let Some(arr) = value.as_array() else {
                return Err(format!("{path}: expected array, got {value}"));
            };
            if let Some(items_schema) = resolved.get("items") {
                for (i, elem) in arr.iter().enumerate() {
                    check_value_against_schema(doc, items_schema, elem, &format!("{path}[{i}]"))?;
                }
            }
        }
        Some("object") => {
            let Some(obj) = value.as_object() else {
                return Err(format!("{path}: expected object, got {value}"));
            };
            if let Some(req) = resolved.get("required").and_then(Value::as_array) {
                for key_val in req {
                    let key = key_val
                        .as_str()
                        .ok_or_else(|| format!("{path}: non-string required key"))?;
                    if !obj.contains_key(key) {
                        return Err(format!(
                            "{path}: missing required OpenAPI property `{key}` in {value}"
                        ));
                    }
                }
            }
            if let Some(props) = resolved.get("properties").and_then(Value::as_object) {
                for (prop_name, prop_schema) in props {
                    if let Some(prop_val) = obj.get(prop_name) {
                        check_value_against_schema(
                            doc,
                            prop_schema,
                            prop_val,
                            &format!("{path}.{prop_name}"),
                        )?;
                    }
                }
            }
            if let Some(addl) = resolved
                .get("additionalProperties")
                .and_then(Value::as_object)
            {
                if !addl.is_empty() {
                    let known = resolved.get("properties").and_then(Value::as_object);
                    for (k, v) in obj {
                        if known.is_none_or(|m| !m.contains_key(k)) {
                            check_value_against_schema(
                                doc,
                                resolved
                                    .get("additionalProperties")
                                    .expect("additionalProperties"),
                                v,
                                &format!("{path}.{k}"),
                            )?;
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn assert_openapi_response(
    doc: &Value,
    path_template: &str,
    method: &str,
    status: u16,
    content_type: Option<&str>,
    body_text: &str,
) {
    let method_lc = method.to_ascii_lowercase();
    let op = doc
        .get("paths")
        .and_then(|p| p.get(path_template))
        .and_then(|pi| pi.get(&method_lc))
        .unwrap_or_else(|| panic!("OpenAPI missing operation {method} {path_template}"));

    let status_key = status.to_string();
    let resp_spec = op
        .get("responses")
        .and_then(|r| r.get(&status_key))
        .unwrap_or_else(|| {
            panic!("OpenAPI {method} {path_template} does not declare status {status_key}")
        });

    if status == 204 {
        assert!(
            body_text.is_empty(),
            "{method} {path_template} 204 expected empty body, got {body_text:?}"
        );
        return;
    }

    let content_map = resp_spec
        .get("content")
        .and_then(Value::as_object)
        .unwrap_or_else(|| {
            panic!("OpenAPI {method} {path_template} {status_key} missing content map")
        });

    let actual_ct = content_type
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let media_spec = content_map.get(&actual_ct).unwrap_or_else(|| {
        panic!(
            "OpenAPI {method} {path_template} {status_key}: Content-Type `{actual_ct}` not in declared {:?}",
            content_map.keys().collect::<Vec<_>>()
        )
    });

    if actual_ct.contains("json") {
        let parsed: Value = serde_json::from_str(body_text).unwrap_or_else(|e| {
            panic!("{method} {path_template} {status_key} invalid JSON ({e}): {body_text}")
        });
        if let Some(schema) = media_spec.get("schema") {
            if let Err(err) = check_value_against_schema(
                doc,
                schema,
                &parsed,
                &format!("{method} {path_template} [{status_key}]"),
            ) {
                panic!("{err}");
            }
        }
    }
}

/// Deserialize `body` into DTO `T` and assert exact `serde_json::Value` equality
/// between the live server JSON and the re-serialized DTO (proving zero dropped
/// keys, zero altered nulls, and lossless wire fidelity).
fn assert_dto_roundtrip_matches_live<T: DeserializeOwned + Serialize>(
    label: &str,
    live_body: &str,
) -> T {
    let live_val: Value = serde_json::from_str(live_body)
        .unwrap_or_else(|e| panic!("{label}: live body is not valid JSON ({e}): {live_body}"));
    let dto: T = serde_json::from_str(live_body)
        .unwrap_or_else(|e| panic!("{label}: DTO deserialization failed ({e}): {live_body}"));
    let reserialized =
        serde_json::to_value(&dto).unwrap_or_else(|e| panic!("{label}: DTO serialize failed: {e}"));
    assert_eq!(
        reserialized, live_val,
        "{label}: DTO round-trip drifted from live response JSON"
    );
    dto
}

/// Seed both an inbound message and an outbound Sent message (with an
/// `outbound_queue` entry so `GET /api/messages/{outbound_id}/trace` returns a
/// populated `OutboundDeliveryTrace` with recipients).
async fn seed_inbound_and_outbound_messages(dsn: &str, user_id: i64) -> (i64, i64) {
    let (client, conn) = tokio_postgres::connect(dsn, NoTls)
        .await
        .expect("connect test DB");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mailbox_id: i64 = client
        .query_one(
            "SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1",
            &[&user_id],
        )
        .await
        .expect("primary mailbox")
        .get(0);

    let inbound_id: i64 = client
        .query_one(
            "INSERT INTO messages (mailbox_id, folder_id, imap_uid, message_id, subject, from_addr, to_addrs, cc_addrs, body_text, size_bytes, thread_id, raw_ref, received_at, is_read)
             VALUES ($1, 0, 1, '<edge-inbound-561@example.test>', 'Edge Inbound Trace', 'sender@example.test', '[\"edge561@example.test\"]'::jsonb, '[]'::jsonb, 'hello inbound', 128, 'thr-edge-in', 'blob-edge-in', now(), FALSE)
             RETURNING id",
            &[&mailbox_id],
        )
        .await
        .expect("seed inbound message")
        .get(0);

    let sent_tag_id: i64 = match client
        .query_opt(
            "SELECT id FROM tags WHERE mailbox_id = $1 AND name = 'Sent' AND tag_type = 'system' AND exclusive_group = 'location' LIMIT 1",
            &[&mailbox_id],
        )
        .await
        .expect("lookup Sent tag")
    {
        Some(r) => r.get(0),
        None => client
            .query_one(
                "INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group)
                 VALUES ($1, 'Sent', 'system', 'location') RETURNING id",
                &[&mailbox_id],
            )
            .await
            .expect("create Sent tag")
            .get(0),
    };

    let out_row = client
        .query_one(
            "INSERT INTO messages (mailbox_id, folder_id, imap_uid, message_id, subject, from_addr, to_addrs, cc_addrs, body_text, size_bytes, thread_id, raw_ref, received_at, is_read)
             VALUES ($1, 0, 2, '<edge-outbound-561@example.test>', 'Edge Outbound Trace', 'edge561@example.test', '[\"rcpt@example.test\"]'::jsonb, '[]'::jsonb, 'hello outbound', 256, 'thr-edge-out', 'blob-edge-out', now(), TRUE)
             RETURNING id, received_at",
            &[&mailbox_id],
        )
        .await
        .expect("seed outbound message");
    let outbound_id: i64 = out_row.get(0);
    let outbound_received_at: std::time::SystemTime = out_row.get(1);

    client
        .execute(
            "INSERT INTO message_tags (message_id, received_at, tag_id, is_primary, imap_uid)
             VALUES ($1, $2, $3, TRUE, 2)",
            &[&outbound_id, &outbound_received_at, &sent_tag_id],
        )
        .await
        .expect("tag outbound message as Sent");

    client
        .execute(
            "INSERT INTO outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status, mailbox_id, message_pk)
             VALUES ('<edge-outbound-561@example.test>', 'edge561@example.test', ARRAY['rcpt@example.test']::text[], 'blob-edge-out', 'deferred', $1, $2)",
            &[&mailbox_id, &outbound_id],
        )
        .await
        .expect("seed outbound_queue entry");

    client
        .execute(
            "INSERT INTO delivery_attempts (message_pk, mailbox_id, recipient_email, attempt_number, attempted_at, mx_host, smtp_code, smtp_text, outcome, tls)
             VALUES ($1, $2, 'rcpt@example.test', 1, now(), 'mx.example.test', 451, 'try again later', 'deferred', TRUE)",
            &[&outbound_id, &mailbox_id],
        )
        .await
        .expect("seed delivery_attempts entry");

    (inbound_id, outbound_id)
}

#[tokio::test]
async fn live_setjoind_conforms_to_edge_openapi_3_1_and_serde_dtos() {
    let doc = load_edge_openapi();
    assert_eq!(
        doc.get("openapi").and_then(Value::as_str),
        Some(OPENAPI_VERSION),
        "committed OpenAPI spec must be 3.1.0"
    );
    for (method, path) in CONTRACTED_OPERATIONS {
        assert!(
            doc.get("paths")
                .and_then(|p| p.get(*path))
                .and_then(|pi| pi.get(method.to_ascii_lowercase()))
                .is_some(),
            "generated CONTRACTED_OPERATIONS entry ({method}, {path}) missing from edge.v1.yaml"
        );
    }

    let dsn = common::test_db_dsn();
    let email = "edge561@example.test";
    let password = "EdgeContractPassword123!";
    let user_id = common::seed_test_user(&dsn, email, password).await;
    let (inbound_msg_id, outbound_msg_id) = seed_inbound_and_outbound_messages(&dsn, user_id).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg_path = common::temp_config_file(tmp.path());
    let (notify_path, notify_sock) = common::bind_notify_socket(tmp.path());
    let http_addr = common::free_addr();

    let mut cmd = Command::new(common::setjoind_bin());
    cmd.env_clear()
        .arg("--subsystems=all")
        .env("DB_DSN", &dsn)
        .env("DB_DIRECT_DSN", &dsn)
        .env("CONFIG_PATH", &cfg_path)
        .env("NOTIFY_SOCKET", &notify_path)
        .env("GATEWAY_LISTEN", http_addr.to_string())
        .env("JWT_SECRET", common::TEST_JWT_SECRET)
        .env("JWT_SIGNING_ALG", "ES256")
        .env("DB_ENCRYPTION_KEY", common::TEST_DB_ENC_KEY)
        .env("INTERNAL_API_KEY", common::TEST_INTERNAL_KEY);

    let mut proc = common::OwnedChild::spawn(&mut cmd);
    common::wait_notify(&notify_sock, &mut proc, "READY=1", Duration::from_secs(20));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http client");
    let base = format!("http://{http_addr}");

    // 1. Health & readiness endpoints (unauthenticated)
    for (path, template) in [
        ("/health", "/health"),
        ("/healthz", "/healthz"),
        ("/_gateway/healthz", "/_gateway/healthz"),
        ("/ready", "/ready"),
    ] {
        let resp = client
            .get(format!("{base}{path}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path} failed: {e}"));
        let status = resp.status().as_u16();
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = resp.text().await.expect("health body");
        if path == "/health" {
            assert!(
                status == 200 || status == 503,
                "GET /health expected 200 or 503, got {status}, body={body}"
            );
        } else {
            assert_eq!(status, 200, "GET {path} expected 200, body={body}");
        }
        assert_openapi_response(&doc, template, "GET", status, ct.as_deref(), &body);

        if path == "/health" {
            let _dto: HealthStatus = assert_dto_roundtrip_matches_live("GET /health", &body);
        } else if path == "/ready" {
            let dto: ReadyStatus = assert_dto_roundtrip_matches_live("GET /ready", &body);
            assert_eq!(dto.status, ReadyVerdict::Ok);
        } else {
            assert_eq!(body, "ok\n");
        }
    }

    // 2. Unauthenticated 401 RFC 9457 ProblemDetails conformance
    let unauth = client
        .get(format!("{base}/api/settings/rules-list"))
        .send()
        .await
        .expect("unauth rules-list");
    let unauth_status = unauth.status().as_u16();
    let unauth_ct = unauth
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let unauth_body = unauth.text().await.expect("unauth body");
    assert_eq!(unauth_status, 401);
    assert_openapi_response(
        &doc,
        "/api/settings/rules-list",
        "GET",
        unauth_status,
        unauth_ct.as_deref(),
        &unauth_body,
    );
    let unauth_problem: ProblemDetails =
        assert_dto_roundtrip_matches_live("401 /api/settings/rules-list", &unauth_body);
    assert_eq!(unauth_problem.status, 401);

    // Login to acquire a real ES256 Bearer token.
    let login_resp = client
        .post(format!("{base}/auth/login"))
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(serde_json::json!({ "email": email, "password": password }).to_string())
        .send()
        .await
        .expect("login request");
    assert_eq!(login_resp.status(), 200);
    let login_json: Value = login_resp.json().await.expect("login json");
    let token = login_json["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    let auth_header = format!("Bearer {token}");

    // 3. 400 RFC 9457 ProblemDetails on invalid RuleInput
    let bad_rule = client
        .post(format!("{base}/api/settings/rules"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(r#"{"name":"","enabled":true,"priority":1,"runOn":"server","conditions":[],"actions":[],"stopProcessing":false}"#)
        .send()
        .await
        .expect("invalid rule create");
    let bad_status = bad_rule.status().as_u16();
    let bad_ct = bad_rule
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bad_body = bad_rule.text().await.expect("bad rule body");
    assert_eq!(bad_status, 400);
    assert_openapi_response(
        &doc,
        "/api/settings/rules",
        "POST",
        bad_status,
        bad_ct.as_deref(),
        &bad_body,
    );
    let bad_problem: ProblemDetails =
        assert_dto_roundtrip_matches_live("400 POST /api/settings/rules", &bad_body);
    assert_eq!(bad_problem.status, 400);

    // 4. Rules CRUD + partial PUT + retro-apply lifecycle
    let mut action_params = BTreeMap::new();
    action_params.insert("flag".to_owned(), "true".to_owned());
    let create_input = RuleInput {
        name: "Edge Contract Rule".to_owned(),
        enabled: true,
        priority: 10,
        run_on: RunOn::Server,
        conditions: Some(vec![RuleCondition {
            field: "subject".to_owned(),
            op: "contains".to_owned(),
            value: "invoice".to_owned(),
        }]),
        actions: Some(vec![RuleAction {
            r#type: "mark_read".to_owned(),
            params: Some(action_params),
        }]),
        stop_processing: false,
    };

    let created = client
        .post(format!("{base}/api/settings/rules"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(serde_json::to_string(&create_input).expect("serialize RuleInput"))
        .send()
        .await
        .expect("POST /api/settings/rules");
    let created_status = created.status().as_u16();
    let created_ct = created
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let created_body = created.text().await.expect("create rule body");
    assert_eq!(created_status, 201, "body={created_body}");
    assert_openapi_response(
        &doc,
        "/api/settings/rules",
        "POST",
        created_status,
        created_ct.as_deref(),
        &created_body,
    );
    let created_dto: CreateRuleResponse =
        assert_dto_roundtrip_matches_live("POST /api/settings/rules", &created_body);
    let rule_id = created_dto.id;
    assert!(rule_id > 0);

    let list_resp = client
        .get(format!("{base}/api/settings/rules-list"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/settings/rules-list");
    let list_status = list_resp.status().as_u16();
    let list_ct = list_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let list_body = list_resp.text().await.expect("rules-list body");
    assert_eq!(list_status, 200, "body={list_body}");
    assert_openapi_response(
        &doc,
        "/api/settings/rules-list",
        "GET",
        list_status,
        list_ct.as_deref(),
        &list_body,
    );
    let rules_dto: Vec<UserRule> =
        assert_dto_roundtrip_matches_live("GET /api/settings/rules-list", &list_body);
    assert!(rules_dto.iter().any(|r| r.id == rule_id));

    // Partial PUT matching RuleUpdateInput contract
    let update_input = RuleUpdateInput {
        name: Some("Edge Contract Rule Updated".to_owned()),
        enabled: Some(true),
        priority: Some(20),
        run_on: Some(RunOn::Server),
        conditions: None,
        actions: None,
        stop_processing: Some(true),
    };
    let updated = client
        .put(format!("{base}/api/settings/rules/{rule_id}"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(serde_json::to_string(&update_input).expect("serialize RuleUpdateInput"))
        .send()
        .await
        .expect("PUT /api/settings/rules/{id}");
    let updated_status = updated.status().as_u16();
    let updated_body = updated.text().await.expect("update rule body");
    assert_eq!(updated_status, 204, "body={updated_body}");
    assert_openapi_response(
        &doc,
        "/api/settings/rules/{id}",
        "PUT",
        updated_status,
        None,
        &updated_body,
    );

    let apply_req = ApplyRetroRequest {
        window: Some(RetroWindowInput::V90d),
    };
    let applied = client
        .post(format!("{base}/api/settings/rules/{rule_id}/apply"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(serde_json::to_string(&apply_req).expect("serialize ApplyRetroRequest"))
        .send()
        .await
        .expect("POST /api/settings/rules/{id}/apply");
    let applied_status = applied.status().as_u16();
    let applied_ct = applied
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let applied_body = applied.text().await.expect("apply body");
    assert_eq!(applied_status, 202, "body={applied_body}");
    assert_openapi_response(
        &doc,
        "/api/settings/rules/{id}/apply",
        "POST",
        applied_status,
        applied_ct.as_deref(),
        &applied_body,
    );
    let apply_dto: ApplyRetroResult =
        assert_dto_roundtrip_matches_live("POST /api/settings/rules/{id}/apply", &applied_body);
    assert_eq!(apply_dto.status, "queued");

    let poll = client
        .get(format!(
            "{base}/api/settings/rules/apply/{}",
            apply_dto.action_id
        ))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/settings/rules/apply/{actionId}");
    let poll_status = poll.status().as_u16();
    let poll_ct = poll
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let poll_body = poll.text().await.expect("apply status body");
    assert_eq!(poll_status, 200, "body={poll_body}");
    assert_openapi_response(
        &doc,
        "/api/settings/rules/apply/{actionId}",
        "GET",
        poll_status,
        poll_ct.as_deref(),
        &poll_body,
    );
    let poll_dto: ApplyStatus =
        assert_dto_roundtrip_matches_live("GET /api/settings/rules/apply/{actionId}", &poll_body);
    assert!(matches!(
        poll_dto.status,
        ApplyJobStatus::Pending
            | ApplyJobStatus::Processing
            | ApplyJobStatus::Done
            | ApplyJobStatus::Failed
    ));

    let deleted = client
        .delete(format!("{base}/api/settings/rules/{rule_id}"))
        .header("authorization", &auth_header)
        .header("sec-fetch-site", "same-origin")
        .send()
        .await
        .expect("DELETE /api/settings/rules/{id}");
    let deleted_status = deleted.status().as_u16();
    let deleted_body = deleted.text().await.expect("delete rule body");
    assert_eq!(deleted_status, 204, "body={deleted_body}");
    assert_openapi_response(
        &doc,
        "/api/settings/rules/{id}",
        "DELETE",
        deleted_status,
        None,
        &deleted_body,
    );

    // 5. Delivery trace endpoint: inbound (required nulls preserved), populated outbound, and missing 404
    let trace_in = client
        .get(format!("{base}/api/messages/{inbound_msg_id}/trace"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET inbound /api/messages/{emailId}/trace");
    let tin_status = trace_in.status().as_u16();
    let tin_ct = trace_in
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let tin_body = trace_in.text().await.expect("inbound trace body");
    assert_eq!(tin_status, 200, "body={tin_body}");
    assert_openapi_response(
        &doc,
        "/api/messages/{emailId}/trace",
        "GET",
        tin_status,
        tin_ct.as_deref(),
        &tin_body,
    );
    let tin_dto: MessageTrace = assert_dto_roundtrip_matches_live("GET inbound trace", &tin_body);
    assert!(
        matches!(tin_dto, MessageTrace::InboundDeliveryTrace(_)),
        "expected InboundDeliveryTrace variant, got {tin_dto:?}"
    );

    let trace_out = client
        .get(format!("{base}/api/messages/{outbound_msg_id}/trace"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET outbound /api/messages/{emailId}/trace");
    let tout_status = trace_out.status().as_u16();
    let tout_ct = trace_out
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let tout_body = trace_out.text().await.expect("outbound trace body");
    assert_eq!(tout_status, 200, "body={tout_body}");
    assert_openapi_response(
        &doc,
        "/api/messages/{emailId}/trace",
        "GET",
        tout_status,
        tout_ct.as_deref(),
        &tout_body,
    );
    let tout_dto: MessageTrace =
        assert_dto_roundtrip_matches_live("GET outbound trace", &tout_body);
    match tout_dto {
        MessageTrace::OutboundDeliveryTrace(t) => {
            assert_eq!(t.direction, OutboundDirection::Outbound);
            assert_eq!(t.recipients.len(), 1);
            assert_eq!(t.recipients[0].email, "rcpt@example.test");
            assert_eq!(t.recipients[0].attempts.len(), 1);
            assert_eq!(
                t.recipients[0].attempts[0].mx_host.as_deref(),
                Some("mx.example.test")
            );
            assert_eq!(t.recipients[0].attempts[0].smtp_code, Some(451));
            assert!(t.recipients[0].attempts[0].tls);
        }
        other => panic!("expected populated OutboundDeliveryTrace, got {other:?}"),
    }

    // Validate populated multi-hop InboundDeliveryTrace emitted by production `received::parse_trace`.
    let sample_rfc5322 = concat!(
        "Received: from relay.partner.test (relay.partner.test [203.0.113.10])\r\n",
        "\tby mail.example.test with ESMTPS id abc123; Fri, 27 Nov 2026 00:00:05 +0000\r\n",
        "Received: from sender.partner.test (sender.partner.test [203.0.113.9])\r\n",
        "\tby relay.partner.test with ESMTPS id def456; Fri, 27 Nov 2026 00:00:00 +0000\r\n",
        "Subject: Multi-hop trace\r\n\r\nhello\r\n",
    );
    let identity =
        setjoin_mail_security::received::Identity::from_config("mail.example.test", "example.test");
    let populated_inbound =
        setjoin_mail_security::received::parse_trace(sample_rfc5322.as_bytes(), &identity)
            .expect("parse_trace should produce populated inbound trace");
    assert_openapi_response(
        &doc,
        "/api/messages/{emailId}/trace",
        "GET",
        200,
        Some("application/json"),
        &populated_inbound,
    );
    let populated_in_dto: MessageTrace =
        assert_dto_roundtrip_matches_live("populated InboundDeliveryTrace", &populated_inbound);
    match populated_in_dto {
        MessageTrace::InboundDeliveryTrace(t) => {
            assert_eq!(t.hop_count, 2);
            assert_eq!(t.hops.len(), 2);
            assert_eq!(t.total_transit_ms, Some(5000));
            assert_eq!(t.slowest_hop_index, Some(1));
        }
        other => panic!("expected populated InboundDeliveryTrace, got {other:?}"),
    }

    let trace_missing = client
        .get(format!("{base}/api/messages/999999999/trace"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET missing trace");
    let tm_status = trace_missing.status().as_u16();
    let tm_ct = trace_missing
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let tm_body = trace_missing.text().await.expect("missing trace body");
    assert_eq!(tm_status, 404, "body={tm_body}");
    assert_openapi_response(
        &doc,
        "/api/messages/{emailId}/trace",
        "GET",
        tm_status,
        tm_ct.as_deref(),
        &tm_body,
    );
    let tm_problem: ProblemDetails = assert_dto_roundtrip_matches_live("404 GET trace", &tm_body);
    assert_eq!(tm_problem.status, 404);

    // 6. Offline size estimate, mailbox quota, and view preferences GET/PUT
    let est_resp = client
        .get(format!("{base}/api/offline/size-estimate"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/offline/size-estimate");
    let est_status = est_resp.status().as_u16();
    let est_ct = est_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let est_body = est_resp.text().await.expect("size-estimate body");
    assert_eq!(est_status, 200, "body={est_body}");
    assert_openapi_response(
        &doc,
        "/api/offline/size-estimate",
        "GET",
        est_status,
        est_ct.as_deref(),
        &est_body,
    );
    let est_dto: OfflineSizeEstimate =
        assert_dto_roundtrip_matches_live("GET /api/offline/size-estimate", &est_body);
    assert_eq!(est_dto.buckets.len(), 6);

    let quota_resp = client
        .get(format!("{base}/api/user/quota"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/user/quota");
    let quota_status = quota_resp.status().as_u16();
    let quota_ct = quota_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let quota_body = quota_resp.text().await.expect("quota body");
    assert_eq!(quota_status, 200, "body={quota_body}");
    assert_openapi_response(
        &doc,
        "/api/user/quota",
        "GET",
        quota_status,
        quota_ct.as_deref(),
        &quota_body,
    );
    let quota_dto: MailboxQuota =
        assert_dto_roundtrip_matches_live("GET /api/user/quota", &quota_body);
    assert!(quota_dto.used_bytes >= 0);

    let view_get = client
        .get(format!("{base}/api/settings/view"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/settings/view");
    let vg_status = view_get.status().as_u16();
    let vg_ct = view_get
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let vg_body = view_get.text().await.expect("view get body");
    assert_eq!(vg_status, 200, "body={vg_body}");
    assert_openapi_response(
        &doc,
        "/api/settings/view",
        "GET",
        vg_status,
        vg_ct.as_deref(),
        &vg_body,
    );
    let mut prefs_dto: ViewPreferences =
        assert_dto_roundtrip_matches_live("GET /api/settings/view", &vg_body);
    prefs_dto.offline_window = Some(Some("90d".to_owned()));

    let view_put = client
        .put(format!("{base}/api/settings/view"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(serde_json::to_string(&prefs_dto).expect("serialize ViewPreferences"))
        .send()
        .await
        .expect("PUT /api/settings/view");
    let vp_status = view_put.status().as_u16();
    let vp_ct = view_put
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let vp_body = view_put.text().await.expect("view put body");
    assert_eq!(vp_status, 200, "body={vp_body}");
    assert!(
        vp_ct.as_deref().unwrap_or("").starts_with("text/plain"),
        "PUT /api/settings/view expected text/plain Content-Type, got {vp_ct:?}"
    );
    assert_openapi_response(
        &doc,
        "/api/settings/view",
        "PUT",
        vp_status,
        vp_ct.as_deref(),
        &vp_body,
    );
    let ack: OkStatus = assert_dto_roundtrip_matches_live("PUT /api/settings/view ack", &vp_body);
    assert_eq!(ack.status, "ok");

    let view_get2 = client
        .get(format!("{base}/api/settings/view"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/settings/view after PUT");
    assert_eq!(view_get2.status(), 200);
    let vg2_body = view_get2.text().await.expect("view get2 body");
    let prefs2: ViewPreferences =
        assert_dto_roundtrip_matches_live("GET /api/settings/view after PUT", &vg2_body);
    assert_eq!(prefs2.offline_window, Some(Some("90d".to_owned())));

    // Clean graceful shutdown
    proc.send_sigterm();
    common::wait_notify(
        &notify_sock,
        &mut proc,
        "STOPPING=1",
        Duration::from_secs(10),
    );
    let exit = proc
        .wait_exit(Duration::from_secs(15))
        .expect("clean shutdown exit");
    assert!(exit.success(), "expected exit 0, got {exit}");
}
