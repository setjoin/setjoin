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

use crate::common;

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use setjoin_edge_contract::{
    AccessReviewCampaign, AccessReviewCreateRequest, AccessReviewDetail, AdminCreatedIdResponse,
    AdminRole, AdminRoleCreateRequest, AdminRoleUpdateRequest, ApplyJobStatus, ApplyRetroRequest,
    ApplyRetroResult, ApplyStatus, AuthAccountType, AuthLoginForbiddenBody, AuthLoginRequest,
    AuthMeResponse, AuthMfaChallengeResponse, AuthRefreshRequest, AuthTokenResponse,
    CreateRuleResponse, DriveChangesResult, DriveCreateNodeRequest, DriveCreateSpaceRequest,
    DriveHistoryResult, DriveIdResponse, DriveManifestChunk, DriveNode, DriveNodeKind,
    DriveNodeMeta, DrivePutVersionRequest, DriveSpace, DriveVersion, DriveWatchRow, EffectivePerms,
    GuestInviteDeliveryUnconfirmedBody, GuestInviteInput, GuestInviteMutationResult, GuestProfile,
    GuestProfileDomain, GuestSummary, HealthStatus, MailboxQuota, MessageTrace, MfaReauthOperation,
    MfaReauthRequest, MfaReauthResponse, OfflineSizeEstimate, OkStatus, OutboundDirection,
    PasskeyCredentialsListResponse, PasswordPolicyResponse, PermissionCatalogEntry, ProblemDetails,
    PutVersionResult, ReadyStatus, ReadyVerdict, RetroWindowInput, RoleDetail, RuleAction,
    RuleCondition, RuleInput, RuleUpdateInput, RunOn, SharingOverview, SodModeConflictBody,
    SodModeSetRequest, SodModeStatus, UserRule, ViewPreferences, CONTRACTED_OPERATIONS,
    OPENAPI_VERSION,
};
use tokio::net::TcpListener;
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

    if status == 204 || resp_spec.get("content").is_none() {
        assert!(
            body_text.is_empty(),
            "{method} {path_template} {status_key} expected empty body, got {body_text:?}"
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
    let media_spec = content_map
        .get(&actual_ct)
        .or_else(|| content_map.get("*/*"))
        .unwrap_or_else(|| {
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
            "INSERT INTO delivery_attempts (message_pk, received_at, mailbox_id, recipient_email, attempt_number, attempted_at, mx_host, smtp_code, smtp_text, outcome, tls)
             VALUES ($1, $2, $3, 'rcpt@example.test', 1, now(), 'mx.example.test', 451, 'try again later', 'deferred', TRUE)",
            &[&outbound_id, &outbound_received_at, &mailbox_id],
        )
        .await
        .expect("seed delivery_attempts entry");

    (inbound_id, outbound_id)
}

/// Grant `user_id` full admin permissions and enable `feature.drive` so live
/// Admin and Drive endpoints can be exercised end-to-end.
async fn seed_admin_and_drive_features(dsn: &str, user_id: i64) {
    let (client, conn) = tokio_postgres::connect(dsn, NoTls)
        .await
        .expect("connect test DB");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    client
        .execute(
            "UPDATE users SET is_admin = TRUE WHERE id = $1",
            &[&user_id],
        )
        .await
        .expect("mark user admin");

    let role_id: i64 = client
        .query_one(
            "SELECT id FROM admin_role_groups WHERE name = 'Super Admin' LIMIT 1",
            &[],
        )
        .await
        .expect("lookup Super Admin role")
        .get(0);

    client
        .execute(
            "INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
             VALUES ($1, $2, $1)
             ON CONFLICT DO NOTHING",
            &[&user_id, &role_id],
        )
        .await
        .expect("assign admin role");

    client
        .execute(
            "INSERT INTO feature_toggles (key, enabled)
             VALUES ('feature.drive', TRUE), ('feature.guest_accounts', TRUE)
             ON CONFLICT (key) DO UPDATE SET enabled = TRUE",
            &[],
        )
        .await
        .expect("enable feature.drive and feature.guest_accounts");
}

/// Lightweight in-process S3 mock supporting PUT, HEAD, GET, and single-range
/// `Range: bytes=lo-hi` (HTTP 206) for live Drive chunk upload & Range content tests.
/// `fail_invite_put` lets tests deterministically trigger guest-invite 503
/// (`invite_delivery_unconfirmed`) without retry delays.
async fn spawn_mock_s3() -> (SocketAddr, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock S3");
    let addr = listener.local_addr().expect("mock S3 addr");
    let objects: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let fail_invite_put = Arc::new(AtomicBool::new(false));
    let fail_invite_flag = fail_invite_put.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let objects = objects.clone();
            let fail_invite_flag = fail_invite_flag.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let objects = objects.clone();
                    let fail_invite_flag = fail_invite_flag.clone();
                    async move {
                        let method = req.method().clone();
                        let path = req.uri().path().to_owned();
                        let query = req.uri().query().map(str::to_owned);
                        let range_hdr = req
                            .headers()
                            .get("range")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        let copy_source = req
                            .headers()
                            .get("x-amz-copy-source")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        let body_bytes = req
                            .into_body()
                            .collect()
                            .await
                            .map(|c| c.to_bytes())
                            .unwrap_or_default();

                        if query.as_deref() == Some("location=") {
                            return Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(200)
                                    .body(Full::new(Bytes::from_static(
                                        b"<LocationConstraint>us-east-1</LocationConstraint>",
                                    )))
                                    .expect("location resp"),
                            );
                        }

                        match method.as_str() {
                            "POST" => {
                                if query
                                    .as_deref()
                                    .is_some_and(|q| q == "uploads" || q.starts_with("uploads="))
                                {
                                    let xml = format!(
                                        "<InitiateMultipartUploadResult><Bucket>mailblobs</Bucket><Key>{}</Key><UploadId>mock-upload-1</UploadId></InitiateMultipartUploadResult>",
                                        path.trim_start_matches("/mailblobs/")
                                    );
                                    return Ok(Response::builder()
                                        .status(200)
                                        .header("content-type", "application/xml")
                                        .body(Full::new(Bytes::from(xml)))
                                        .expect("init multipart"));
                                }
                                if query.as_deref().is_some_and(|q| q.contains("uploadId=")) {
                                    let xml = format!(
                                        "<CompleteMultipartUploadResult><Location>http://mock{path}</Location><Bucket>mailblobs</Bucket><Key>{}</Key><ETag>\"mock-etag\"</ETag></CompleteMultipartUploadResult>",
                                        path.trim_start_matches("/mailblobs/")
                                    );
                                    return Ok(Response::builder()
                                        .status(200)
                                        .header("content-type", "application/xml")
                                        .body(Full::new(Bytes::from(xml)))
                                        .expect("complete multipart"));
                                }
                                Ok(Response::builder()
                                    .status(200)
                                    .body(Full::new(Bytes::new()))
                                    .expect("post ok"))
                            }
                            "PUT" => {
                                if fail_invite_flag.load(Ordering::SeqCst)
                                    && path.contains("/invite/")
                                {
                                    return Ok(Response::builder()
                                        .status(403)
                                        .body(Full::new(Bytes::from_static(b"invite put denied")))
                                        .expect("put 403"));
                                }
                                if let Some(src) = copy_source {
                                    let src_path = if src.starts_with('/') {
                                        src
                                    } else {
                                        format!("/{src}")
                                    };
                                    let mut map = objects.lock().expect("lock mock S3");
                                    let Some(bytes) = map.get(&src_path).cloned() else {
                                        return Ok(Response::builder()
                                            .status(404)
                                            .body(Full::new(Bytes::from_static(
                                                b"missing copy src",
                                            )))
                                            .expect("copy 404"));
                                    };
                                    map.insert(path, bytes);
                                    return Ok(Response::builder()
                                        .status(200)
                                        .header("content-type", "application/xml")
                                        .header("etag", "\"mock-etag\"")
                                        .body(Full::new(Bytes::from_static(
                                            b"<CopyObjectResult><ETag>\"mock-etag\"</ETag></CopyObjectResult>",
                                        )))
                                        .expect("copy resp"));
                                }
                                objects
                                    .lock()
                                    .expect("lock mock S3")
                                    .insert(path, body_bytes.to_vec());
                                Ok(Response::builder()
                                    .status(200)
                                    .header("etag", "\"mock-etag\"")
                                    .body(Full::new(Bytes::new()))
                                    .expect("put resp"))
                            }
                            "DELETE" => {
                                objects.lock().expect("lock mock S3").remove(&path);
                                Ok(Response::builder()
                                    .status(204)
                                    .body(Full::new(Bytes::new()))
                                    .expect("delete resp"))
                            }
                            "HEAD" => {
                                let len = objects
                                    .lock()
                                    .expect("lock mock S3")
                                    .get(&path)
                                    .map(Vec::len);
                                match len {
                                    Some(n) => Ok(Response::builder()
                                        .status(200)
                                        .header("content-length", n.to_string())
                                        .header("etag", "\"mock-etag\"")
                                        .body(Full::new(Bytes::new()))
                                        .expect("head 200")),
                                    None => Ok(Response::builder()
                                        .status(404)
                                        .body(Full::new(Bytes::new()))
                                        .expect("head 404")),
                                }
                            }
                            "GET" => {
                                let data =
                                    objects.lock().expect("lock mock S3").get(&path).cloned();
                                let Some(data) = data else {
                                    return Ok(Response::builder()
                                        .status(404)
                                        .body(Full::new(Bytes::from_static(b"missing")))
                                        .expect("get 404"));
                                };
                                if let Some(raw_range) = range_hdr {
                                    if let Some((lo_s, hi_s)) = raw_range
                                        .strip_prefix("bytes=")
                                        .and_then(|r| r.split_once('-'))
                                    {
                                        if let (Ok(lo), Ok(hi)) =
                                            (lo_s.parse::<usize>(), hi_s.parse::<usize>())
                                        {
                                            if lo <= hi && hi < data.len() {
                                                let slice = data[lo..=hi].to_vec();
                                                return Ok(Response::builder()
                                                    .status(206)
                                                    .header(
                                                        "last-modified",
                                                        "Fri, 27 Nov 2026 00:00:00 GMT",
                                                    )
                                                    .header("etag", "\"mock-etag\"")
                                                    .header(
                                                        "content-range",
                                                        format!("bytes {lo}-{hi}/{}", data.len()),
                                                    )
                                                    .header(
                                                        "content-length",
                                                        slice.len().to_string(),
                                                    )
                                                    .body(Full::new(Bytes::from(slice)))
                                                    .expect("get 206"));
                                            }
                                        }
                                    }
                                }
                                Ok(Response::builder()
                                    .status(200)
                                    .header("last-modified", "Fri, 27 Nov 2026 00:00:00 GMT")
                                    .header("etag", "\"mock-etag\"")
                                    .header("content-length", data.len().to_string())
                                    .body(Full::new(Bytes::from(data)))
                                    .expect("get 200"))
                            }
                            _ => Ok(Response::builder()
                                .status(405)
                                .body(Full::new(Bytes::new()))
                                .expect("405")),
                        }
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    (addr, fail_invite_put)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    seed_admin_and_drive_features(&dsn, user_id).await;

    let (s3_addr, fail_invite_put) = spawn_mock_s3().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg_path = common::temp_config_file(tmp.path());
    let (notify_path, notify_sock) = common::bind_notify_socket(tmp.path());
    let http_addr = common::free_addr();

    let app_dsn = common::app_db_dsn();
    let worker_dsn = common::worker_db_dsn();
    let mut cmd = Command::new(common::setjoind_bin());
    cmd.env_clear()
        .arg("--subsystems=all")
        .env("DB_DSN", &app_dsn)
        .env("DB_WORKER_DSN", &worker_dsn)
        .env("DB_DIRECT_DSN", &worker_dsn)
        .env("CONFIG_PATH", &cfg_path)
        .env("NOTIFY_SOCKET", &notify_path)
        .env("GATEWAY_LISTEN", http_addr.to_string())
        .env("JWT_SECRET", common::TEST_JWT_SECRET)
        .env("JWT_SIGNING_ALG", "ES256")
        .env("DB_ENCRYPTION_KEY", common::TEST_DB_ENC_KEY)
        .env("INTERNAL_API_KEY", common::TEST_INTERNAL_KEY)
        .env("S3_ENDPOINT", format!("http://{s3_addr}"))
        .env("S3_BUCKET", "mailblobs")
        .env("S3_ACCESS_KEY", "test-access")
        .env("S3_SECRET_KEY", "test-secret");

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

    // 7. Wave 3.7 (#562) Auth/Identity conformance: /auth/login, /auth/me,
    //    /auth/password-policy, /auth/webauthn/credentials, /auth/mfa/reauth
    let login_req = AuthLoginRequest {
        email: email.to_owned(),
        password: password.to_owned(),
        stay_signed_in: Some(false),
        remember_device: Some(false),
        dpop_jwk: None,
    };
    let login_check = client
        .post(format!("{base}/auth/login"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&login_req).expect("serialize AuthLoginRequest"))
        .send()
        .await
        .expect("POST /auth/login conformance");
    let lc_status = login_check.status().as_u16();
    let lc_ct = login_check
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let lc_body = login_check.text().await.expect("login conformance body");
    assert_eq!(lc_status, 200, "body={lc_body}");
    assert_openapi_response(
        &doc,
        "/auth/login",
        "POST",
        lc_status,
        lc_ct.as_deref(),
        &lc_body,
    );
    let login_dto: AuthTokenResponse =
        assert_dto_roundtrip_matches_live("POST /auth/login", &lc_body);
    assert!(!login_dto.access_token.is_empty());
    assert!(!login_dto.refresh_token.is_empty());

    // POST /auth/refresh live 200 rotation FIRST (before triggering failed-auth threat counters)
    let refresh_ok = client
        .post(format!("{base}/auth/refresh"))
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(
            serde_json::to_string(&AuthRefreshRequest {
                refresh_token: Some(login_dto.refresh_token.clone()),
            })
            .expect("serialize live refresh"),
        )
        .send()
        .await
        .expect("POST /auth/refresh live rotation");
    let rok_status = refresh_ok.status().as_u16();
    let rok_ct = refresh_ok
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let rok_body = refresh_ok.text().await.expect("refresh 200 body");
    assert_eq!(rok_status, 200, "body={rok_body}");
    assert_openapi_response(
        &doc,
        "/auth/refresh",
        "POST",
        rok_status,
        rok_ct.as_deref(),
        &rok_body,
    );
    let rotated_dto: AuthTokenResponse =
        assert_dto_roundtrip_matches_live("200 POST /auth/refresh", &rok_body);
    assert!(!rotated_dto.access_token.is_empty());

    // POST /auth/login challenge branches: 403 force_password_change and 202 mfa_required (totp)
    let force_email = "force562@example.test";
    let mfa_email = "mfa562@example.test";
    let force_uid = common::seed_test_user(&dsn, force_email, password).await;
    let mfa_uid = common::seed_test_user(&dsn, mfa_email, password).await;
    {
        let (pg, conn) = tokio_postgres::connect(&dsn, NoTls)
            .await
            .expect("connect test DB for auth challenge fixtures");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        pg.execute(
            "UPDATE users SET must_change_password = TRUE WHERE id = $1",
            &[&force_uid],
        )
        .await
        .expect("set must_change_password");
        pg.execute(
            "UPDATE users SET totp_enabled = TRUE WHERE id = $1",
            &[&mfa_uid],
        )
        .await
        .expect("set totp_enabled");
    }

    let force_login = client
        .post(format!("{base}/auth/login"))
        .header("content-type", "application/json")
        .body(
            serde_json::to_string(&AuthLoginRequest {
                email: force_email.to_owned(),
                password: password.to_owned(),
                stay_signed_in: None,
                remember_device: None,
                dpop_jwk: None,
            })
            .expect("serialize force login"),
        )
        .send()
        .await
        .expect("POST /auth/login force_password_change");
    let fl_status = force_login.status().as_u16();
    let fl_ct = force_login
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let fl_body = force_login.text().await.expect("force login body");
    assert_eq!(fl_status, 403, "body={fl_body}");
    assert_openapi_response(
        &doc,
        "/auth/login",
        "POST",
        fl_status,
        fl_ct.as_deref(),
        &fl_body,
    );
    let fl_dto: AuthLoginForbiddenBody =
        assert_dto_roundtrip_matches_live("403 force_password_change POST /auth/login", &fl_body);
    assert_eq!(fl_dto.status.as_deref(), Some("force_password_change"));
    assert_eq!(fl_dto.force_password_change, Some(true));
    assert!(fl_dto.force_token.as_deref().is_some_and(|t| !t.is_empty()));

    let mfa_login = client
        .post(format!("{base}/auth/login"))
        .header("content-type", "application/json")
        .body(
            serde_json::to_string(&AuthLoginRequest {
                email: mfa_email.to_owned(),
                password: password.to_owned(),
                stay_signed_in: None,
                remember_device: None,
                dpop_jwk: None,
            })
            .expect("serialize mfa login"),
        )
        .send()
        .await
        .expect("POST /auth/login mfa_required");
    let ml_status = mfa_login.status().as_u16();
    let ml_ct = mfa_login
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let ml_body = mfa_login.text().await.expect("mfa login body");
    assert_eq!(ml_status, 202, "body={ml_body}");
    assert_openapi_response(
        &doc,
        "/auth/login",
        "POST",
        ml_status,
        ml_ct.as_deref(),
        &ml_body,
    );
    let ml_dto: AuthMfaChallengeResponse =
        assert_dto_roundtrip_matches_live("202 mfa_required POST /auth/login", &ml_body);
    assert_eq!(ml_dto.status.as_deref(), Some("mfa_required"));
    assert!(!ml_dto.mfa_token.is_empty());

    let me_resp = client
        .get(format!("{base}/auth/me"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /auth/me");
    let me_status = me_resp.status().as_u16();
    let me_ct = me_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let me_body = me_resp.text().await.expect("auth/me body");
    assert_eq!(me_status, 200, "body={me_body}");
    assert_openapi_response(
        &doc,
        "/auth/me",
        "GET",
        me_status,
        me_ct.as_deref(),
        &me_body,
    );
    let me_dto: AuthMeResponse = assert_dto_roundtrip_matches_live("GET /auth/me", &me_body);
    assert_eq!(me_dto.email, email);
    assert!(me_dto.is_admin);
    assert_eq!(me_dto.account_type, AuthAccountType::Member);

    let policy_resp = client
        .get(format!("{base}/auth/password-policy"))
        .send()
        .await
        .expect("GET /auth/password-policy");
    let pol_status = policy_resp.status().as_u16();
    let pol_ct = policy_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let pol_body = policy_resp.text().await.expect("password-policy body");
    assert_eq!(pol_status, 200, "body={pol_body}");
    assert_openapi_response(
        &doc,
        "/auth/password-policy",
        "GET",
        pol_status,
        pol_ct.as_deref(),
        &pol_body,
    );
    let pol_dto: PasswordPolicyResponse =
        assert_dto_roundtrip_matches_live("GET /auth/password-policy", &pol_body);
    assert!(pol_dto.min_length >= 1);

    let creds_resp = client
        .get(format!("{base}/auth/webauthn/credentials"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /auth/webauthn/credentials");
    let cr_status = creds_resp.status().as_u16();
    let cr_ct = creds_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let cr_body = creds_resp.text().await.expect("credentials body");
    assert_eq!(cr_status, 200, "body={cr_body}");
    assert_openapi_response(
        &doc,
        "/auth/webauthn/credentials",
        "GET",
        cr_status,
        cr_ct.as_deref(),
        &cr_body,
    );
    let cr_dto: PasskeyCredentialsListResponse =
        assert_dto_roundtrip_matches_live("GET /auth/webauthn/credentials", &cr_body);
    assert!(cr_dto.credentials.is_empty());

    let reauth_req = MfaReauthRequest {
        password: Some(password.to_owned()),
        operation: Some(MfaReauthOperation::TotpEnroll),
        target_ref: None,
    };
    let reauth_resp = client
        .post(format!("{base}/auth/mfa/reauth"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(serde_json::to_string(&reauth_req).expect("serialize MfaReauthRequest"))
        .send()
        .await
        .expect("POST /auth/mfa/reauth");
    let ra_status = reauth_resp.status().as_u16();
    let ra_ct = reauth_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let ra_body = reauth_resp.text().await.expect("reauth body");
    assert_eq!(ra_status, 200, "body={ra_body}");
    assert_openapi_response(
        &doc,
        "/auth/mfa/reauth",
        "POST",
        ra_status,
        ra_ct.as_deref(),
        &ra_body,
    );
    let ra_dto: MfaReauthResponse =
        assert_dto_roundtrip_matches_live("POST /auth/mfa/reauth", &ra_body);
    assert!(!ra_dto.reauth_token.is_empty());

    // 8. Wave 3.7 (#562) Admin console conformance: Permissions, Roles CRUD,
    //    Effective Permissions, SoD Mode, Access Reviews, Guests & Profiles
    let perms_resp = client
        .get(format!("{base}/api/admin/permissions"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/admin/permissions");
    let p_status = perms_resp.status().as_u16();
    let p_ct = perms_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let p_body = perms_resp.text().await.expect("permissions body");
    assert_eq!(p_status, 200, "body={p_body}");
    assert_openapi_response(
        &doc,
        "/api/admin/permissions",
        "GET",
        p_status,
        p_ct.as_deref(),
        &p_body,
    );
    let perms_dto: Vec<PermissionCatalogEntry> =
        assert_dto_roundtrip_matches_live("GET /api/admin/permissions", &p_body);
    assert!(!perms_dto.is_empty());

    let create_role_req = AdminRoleCreateRequest {
        name: "Edge562TempRole".to_owned(),
        description: "Temporary conformance role".to_owned(),
        permissions: vec!["users.read".to_owned()],
        domain_scope: None,
    };
    let created_role = client
        .post(format!("{base}/api/admin/roles"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(serde_json::to_string(&create_role_req).expect("serialize AdminRoleCreateRequest"))
        .send()
        .await
        .expect("POST /api/admin/roles");
    let crl_status = created_role.status().as_u16();
    let crl_ct = created_role
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let crl_body = created_role.text().await.expect("create role body");
    assert_eq!(crl_status, 201, "body={crl_body}");
    assert_openapi_response(
        &doc,
        "/api/admin/roles",
        "POST",
        crl_status,
        crl_ct.as_deref(),
        &crl_body,
    );
    let role_created_dto: AdminCreatedIdResponse =
        assert_dto_roundtrip_matches_live("POST /api/admin/roles", &crl_body);
    let created_role_id = role_created_dto.id;

    let roles_resp = client
        .get(format!("{base}/api/admin/roles"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/admin/roles");
    let rl_status = roles_resp.status().as_u16();
    let rl_ct = roles_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let rl_body = roles_resp.text().await.expect("roles list body");
    assert_eq!(rl_status, 200, "body={rl_body}");
    assert_openapi_response(
        &doc,
        "/api/admin/roles",
        "GET",
        rl_status,
        rl_ct.as_deref(),
        &rl_body,
    );
    let roles_dto: Vec<AdminRole> =
        assert_dto_roundtrip_matches_live("GET /api/admin/roles", &rl_body);
    assert!(roles_dto.iter().any(|r| r.id == created_role_id));

    let role_detail_resp = client
        .get(format!("{base}/api/admin/roles/{created_role_id}"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/admin/roles/{id}");
    let rd_status = role_detail_resp.status().as_u16();
    let rd_ct = role_detail_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let rd_body = role_detail_resp.text().await.expect("role detail body");
    assert_eq!(rd_status, 200, "body={rd_body}");
    assert_openapi_response(
        &doc,
        "/api/admin/roles/{id}",
        "GET",
        rd_status,
        rd_ct.as_deref(),
        &rd_body,
    );
    let role_detail_dto: RoleDetail =
        assert_dto_roundtrip_matches_live("GET /api/admin/roles/{id}", &rd_body);
    assert_eq!(role_detail_dto.role.name, "Edge562TempRole");

    let update_role_req = AdminRoleUpdateRequest {
        name: Some("Edge562TempRoleUpdated".to_owned()),
        description: None,
        permissions: None,
        domain_scope: None,
    };
    let upd_role = client
        .put(format!("{base}/api/admin/roles/{created_role_id}"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(serde_json::to_string(&update_role_req).expect("serialize AdminRoleUpdateRequest"))
        .send()
        .await
        .expect("PUT /api/admin/roles/{id}");
    let ur_status = upd_role.status().as_u16();
    let ur_body = upd_role.text().await.expect("update role body");
    assert_eq!(ur_status, 204, "body={ur_body}");
    assert_openapi_response(
        &doc,
        "/api/admin/roles/{id}",
        "PUT",
        ur_status,
        None,
        &ur_body,
    );

    let del_role = client
        .delete(format!("{base}/api/admin/roles/{created_role_id}"))
        .header("authorization", &auth_header)
        .header("sec-fetch-site", "same-origin")
        .send()
        .await
        .expect("DELETE /api/admin/roles/{id}");
    let dr_status = del_role.status().as_u16();
    let dr_body = del_role.text().await.expect("delete role body");
    assert_eq!(dr_status, 204, "body={dr_body}");
    assert_openapi_response(
        &doc,
        "/api/admin/roles/{id}",
        "DELETE",
        dr_status,
        None,
        &dr_body,
    );

    let eff_resp = client
        .get(format!(
            "{base}/api/admin/users/{user_id}/effective-permissions"
        ))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET effective-permissions");
    let eff_status = eff_resp.status().as_u16();
    let eff_ct = eff_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let eff_body = eff_resp.text().await.expect("effective-permissions body");
    assert_eq!(eff_status, 200, "body={eff_body}");
    assert_openapi_response(
        &doc,
        "/api/admin/users/{id}/effective-permissions",
        "GET",
        eff_status,
        eff_ct.as_deref(),
        &eff_body,
    );
    let eff_dto: EffectivePerms = assert_dto_roundtrip_matches_live(
        "GET /api/admin/users/{id}/effective-permissions",
        &eff_body,
    );
    assert!(!eff_dto.permissions.is_empty());

    let sod_resp = client
        .get(format!("{base}/api/admin/dengbao/sod-mode"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/admin/dengbao/sod-mode");
    let sod_status = sod_resp.status().as_u16();
    let sod_ct = sod_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let sod_body = sod_resp.text().await.expect("sod-mode body");
    assert_eq!(sod_status, 200, "body={sod_body}");
    assert_openapi_response(
        &doc,
        "/api/admin/dengbao/sod-mode",
        "GET",
        sod_status,
        sod_ct.as_deref(),
        &sod_body,
    );
    let _sod_dto: SodModeStatus =
        assert_dto_roundtrip_matches_live("GET /api/admin/dengbao/sod-mode", &sod_body);

    // PUT /api/admin/dengbao/sod-mode -> 409 JSON conflict (Super Admin spans SoD classes)
    let sod_conflict = client
        .put(format!("{base}/api/admin/dengbao/sod-mode"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(
            serde_json::to_string(&SodModeSetRequest { enabled: true })
                .expect("serialize SodModeSetRequest"),
        )
        .send()
        .await
        .expect("PUT /api/admin/dengbao/sod-mode");
    let scf_status = sod_conflict.status().as_u16();
    let scf_ct = sod_conflict
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let scf_body = sod_conflict.text().await.expect("sod conflict body");
    assert_eq!(scf_status, 409, "body={scf_body}");
    assert_openapi_response(
        &doc,
        "/api/admin/dengbao/sod-mode",
        "PUT",
        scf_status,
        scf_ct.as_deref(),
        &scf_body,
    );
    let sod_conflict_dto: SodModeConflictBody =
        assert_dto_roundtrip_matches_live("409 PUT /api/admin/dengbao/sod-mode", &scf_body);
    assert!(!sod_conflict_dto.violations.is_empty());

    let ar_create_req = AccessReviewCreateRequest {
        name: "Edge562 Campaign".to_owned(),
    };
    let ar_created = client
        .post(format!("{base}/api/admin/access-reviews"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(serde_json::to_string(&ar_create_req).expect("serialize AccessReviewCreateRequest"))
        .send()
        .await
        .expect("POST /api/admin/access-reviews");
    let arc_status = ar_created.status().as_u16();
    let arc_ct = ar_created
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let arc_body = ar_created.text().await.expect("create access review body");
    assert_eq!(arc_status, 201, "body={arc_body}");
    assert_openapi_response(
        &doc,
        "/api/admin/access-reviews",
        "POST",
        arc_status,
        arc_ct.as_deref(),
        &arc_body,
    );
    let ar_id_dto: AdminCreatedIdResponse =
        assert_dto_roundtrip_matches_live("POST /api/admin/access-reviews", &arc_body);
    let ar_id = ar_id_dto.id;

    let ar_list = client
        .get(format!("{base}/api/admin/access-reviews"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/admin/access-reviews");
    let arl_status = ar_list.status().as_u16();
    let arl_ct = ar_list
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let arl_body = ar_list.text().await.expect("access reviews list body");
    assert_eq!(arl_status, 200, "body={arl_body}");
    assert_openapi_response(
        &doc,
        "/api/admin/access-reviews",
        "GET",
        arl_status,
        arl_ct.as_deref(),
        &arl_body,
    );
    let ar_list_dto: Vec<AccessReviewCampaign> =
        assert_dto_roundtrip_matches_live("GET /api/admin/access-reviews", &arl_body);
    assert!(ar_list_dto.iter().any(|c| c.id == ar_id));

    let ar_detail = client
        .get(format!("{base}/api/admin/access-reviews/{ar_id}"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/admin/access-reviews/{id}");
    let ard_status = ar_detail.status().as_u16();
    let ard_ct = ar_detail
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let ard_body = ar_detail.text().await.expect("access review detail body");
    assert_eq!(ard_status, 200, "body={ard_body}");
    assert_openapi_response(
        &doc,
        "/api/admin/access-reviews/{id}",
        "GET",
        ard_status,
        ard_ct.as_deref(),
        &ard_body,
    );
    let _ar_detail_dto: AccessReviewDetail =
        assert_dto_roundtrip_matches_live("GET /api/admin/access-reviews/{id}", &ard_body);

    let ar_close = client
        .post(format!("{base}/api/admin/access-reviews/{ar_id}/close"))
        .header("authorization", &auth_header)
        .header("sec-fetch-site", "same-origin")
        .send()
        .await
        .expect("POST /api/admin/access-reviews/{id}/close");
    let arcl_status = ar_close.status().as_u16();
    let arcl_body = ar_close.text().await.expect("close access review body");
    assert_eq!(arcl_status, 204, "body={arcl_body}");
    assert_openapi_response(
        &doc,
        "/api/admin/access-reviews/{id}/close",
        "POST",
        arcl_status,
        None,
        &arcl_body,
    );

    for (path, label) in [
        ("/api/admin/guests", "GET /api/admin/guests"),
        ("/api/admin/guest-profiles", "GET /api/admin/guest-profiles"),
        (
            "/api/admin/guest-profile-domains",
            "GET /api/admin/guest-profile-domains",
        ),
    ] {
        let resp = client
            .get(format!("{base}{path}"))
            .header("authorization", &auth_header)
            .send()
            .await
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        let status = resp.status().as_u16();
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = resp.text().await.expect("guest admin body");
        assert_eq!(status, 200, "{label} body={body}");
        assert_openapi_response(&doc, path, "GET", status, ct.as_deref(), &body);
        match path {
            "/api/admin/guests" => {
                let _: Vec<GuestSummary> = assert_dto_roundtrip_matches_live(label, &body);
            }
            "/api/admin/guest-profiles" => {
                let _: Vec<GuestProfile> = assert_dto_roundtrip_matches_live(label, &body);
            }
            _ => {
                let _: Vec<GuestProfileDomain> = assert_dto_roundtrip_matches_live(label, &body);
            }
        }
    }

    // POST /api/admin/guests -> deterministic 202 accepted (mock S3 delivery succeeds)
    {
        let (pg, conn) = tokio_postgres::connect(&dsn, NoTls)
            .await
            .expect("connect test DB for guest invite config");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        pg.execute(
            "INSERT INTO system_config(key, value) VALUES ('authserver.public_url', '\"https://auth.example.test\"') ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            &[],
        )
        .await
        .expect("seed authserver.public_url");
    }
    fail_invite_put.store(false, Ordering::SeqCst);
    let guest_invite_resp = client
        .post(format!("{base}/api/admin/guests"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(
            serde_json::to_string(&GuestInviteInput {
                email: "partner562@external.test".to_owned(),
                display_name: "Partner Guest 562".to_owned(),
                profile_id: None,
                expires_at: None,
            })
            .expect("serialize GuestInviteInput"),
        )
        .send()
        .await
        .expect("POST /api/admin/guests 202");
    let gi_status = guest_invite_resp.status().as_u16();
    let gi_ct = guest_invite_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let gi_body = guest_invite_resp
        .text()
        .await
        .expect("guest invite 202 body");
    assert_eq!(
        gi_status, 202,
        "POST /api/admin/guests expected 202, body={gi_body}"
    );
    assert_openapi_response(
        &doc,
        "/api/admin/guests",
        "POST",
        gi_status,
        gi_ct.as_deref(),
        &gi_body,
    );
    let gi_dto: GuestInviteMutationResult =
        assert_dto_roundtrip_matches_live("202 POST /api/admin/guests", &gi_body);
    assert_eq!(
        gi_dto.invited_email.as_deref(),
        Some("partner562@external.test")
    );

    // POST /api/admin/guests -> deterministic 503 invite_delivery_unconfirmed (mock S3 rejects invite PUT)
    fail_invite_put.store(true, Ordering::SeqCst);
    let guest_unconfirmed_resp = client
        .post(format!("{base}/api/admin/guests"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(
            serde_json::to_string(&GuestInviteInput {
                email: "partner562-unconfirmed@external.test".to_owned(),
                display_name: "Partner Unconfirmed 562".to_owned(),
                profile_id: None,
                expires_at: None,
            })
            .expect("serialize unconfirmed GuestInviteInput"),
        )
        .send()
        .await
        .expect("POST /api/admin/guests 503");
    fail_invite_put.store(false, Ordering::SeqCst);
    let gu_status = guest_unconfirmed_resp.status().as_u16();
    let gu_ct = guest_unconfirmed_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let gu_body = guest_unconfirmed_resp
        .text()
        .await
        .expect("guest invite 503 body");
    assert_eq!(
        gu_status, 503,
        "POST /api/admin/guests expected 503, body={gu_body}"
    );
    assert_openapi_response(
        &doc,
        "/api/admin/guests",
        "POST",
        gu_status,
        gu_ct.as_deref(),
        &gu_body,
    );
    let unconfirmed: GuestInviteDeliveryUnconfirmedBody =
        assert_dto_roundtrip_matches_live("503 POST /api/admin/guests", &gu_body);
    assert_eq!(unconfirmed.code, "invite_delivery_unconfirmed");
    assert!(unconfirmed.retryable);

    // 9. Wave 3.7 (#562) Drive metadata + Range (206 Partial Content / Content-Range / 416)
    let space_req = DriveCreateSpaceRequest {
        name: "Edge562 Space".to_owned(),
        classification: None,
        is_personal: Some(false),
        retention_days: None,
        worm_mode: None,
        export_policy: None,
    };
    let space_created = client
        .post(format!("{base}/api/drive/spaces"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(serde_json::to_string(&space_req).expect("serialize DriveCreateSpaceRequest"))
        .send()
        .await
        .expect("POST /api/drive/spaces");
    let sc_status = space_created.status().as_u16();
    let sc_ct = space_created
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let sc_body = space_created.text().await.expect("create space body");
    assert_eq!(sc_status, 201, "body={sc_body}");
    assert_openapi_response(
        &doc,
        "/api/drive/spaces",
        "POST",
        sc_status,
        sc_ct.as_deref(),
        &sc_body,
    );
    let space_id_dto: DriveIdResponse =
        assert_dto_roundtrip_matches_live("POST /api/drive/spaces", &sc_body);
    let space_id = space_id_dto.id;

    let spaces_resp = client
        .get(format!("{base}/api/drive/spaces"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/drive/spaces");
    let sp_status = spaces_resp.status().as_u16();
    let sp_ct = spaces_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let sp_body = spaces_resp.text().await.expect("spaces body");
    assert_eq!(sp_status, 200, "body={sp_body}");
    assert_openapi_response(
        &doc,
        "/api/drive/spaces",
        "GET",
        sp_status,
        sp_ct.as_deref(),
        &sp_body,
    );
    let spaces_dto: Vec<DriveSpace> =
        assert_dto_roundtrip_matches_live("GET /api/drive/spaces", &sp_body);
    assert!(spaces_dto.iter().any(|s| s.id == space_id));

    let node_req = DriveCreateNodeRequest {
        space_id,
        parent_id: None,
        kind: DriveNodeKind::File,
        name: "range-test.txt".to_owned(),
        content_type: Some(Some("text/plain".to_owned())),
    };
    let node_created = client
        .post(format!("{base}/api/drive/nodes"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(serde_json::to_string(&node_req).expect("serialize DriveCreateNodeRequest"))
        .send()
        .await
        .expect("POST /api/drive/nodes");
    let nc_status = node_created.status().as_u16();
    let nc_ct = node_created
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let nc_body = node_created.text().await.expect("create node body");
    assert_eq!(nc_status, 201, "body={nc_body}");
    assert_openapi_response(
        &doc,
        "/api/drive/nodes",
        "POST",
        nc_status,
        nc_ct.as_deref(),
        &nc_body,
    );
    let node_id_dto: DriveIdResponse =
        assert_dto_roundtrip_matches_live("POST /api/drive/nodes", &nc_body);
    let file_node_id = node_id_dto.id;

    // Upload a real Drive chunk (`"Hello Setjoin Drive Range 206!"`, 30 bytes)
    let payload: &[u8] = b"Hello Setjoin Drive Range 206!";
    let chunk_sha = "7fc00af2eb9b4c31e78661b5975716e9996e0e794713be75b1b649f41c23d5d9";

    let head_before = client
        .head(format!(
            "{base}/api/drive/chunks/{chunk_sha}?space={space_id}"
        ))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("HEAD chunk before upload");
    assert_eq!(head_before.status(), 404);

    let put_chunk = client
        .put(format!(
            "{base}/api/drive/chunks/{chunk_sha}?space={space_id}"
        ))
        .header("authorization", &auth_header)
        .header("content-type", "application/octet-stream")
        .header("sec-fetch-site", "same-origin")
        .body(payload.to_vec())
        .send()
        .await
        .expect("PUT /api/drive/chunks/{sha256}");
    let pc_status = put_chunk.status().as_u16();
    let pc_body = put_chunk.text().await.expect("put chunk body");
    assert!(
        pc_status == 201 || pc_status == 204,
        "PUT chunk expected 201 or 204, got {pc_status} body={pc_body}"
    );
    assert_openapi_response(
        &doc,
        "/api/drive/chunks/{sha256}",
        "PUT",
        pc_status,
        None,
        &pc_body,
    );

    let head_after = client
        .head(format!(
            "{base}/api/drive/chunks/{chunk_sha}?space={space_id}"
        ))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("HEAD chunk after upload");
    assert_eq!(head_after.status(), 200);

    let put_ver_req = DrivePutVersionRequest {
        content_sha256: chunk_sha.to_owned(),
        size: payload.len() as i64,
        content_type: Some(Some("text/plain".to_owned())),
        base_version_id: None,
        manifest: vec![DriveManifestChunk {
            sha256: chunk_sha.to_owned(),
            size: payload.len() as i64,
        }],
        note: Some("initial range test version".to_owned()),
        device_label: Some("conformance".to_owned()),
        branch_id: None,
    };
    let ver_created = client
        .post(format!("{base}/api/drive/files/{file_node_id}/versions"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(serde_json::to_string(&put_ver_req).expect("serialize DrivePutVersionRequest"))
        .send()
        .await
        .expect("POST /api/drive/files/{id}/versions");
    let vc_status = ver_created.status().as_u16();
    let vc_ct = ver_created
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let vc_body = ver_created.text().await.expect("put version body");
    assert_eq!(vc_status, 201, "body={vc_body}");
    assert_openapi_response(
        &doc,
        "/api/drive/files/{id}/versions",
        "POST",
        vc_status,
        vc_ct.as_deref(),
        &vc_body,
    );
    let ver_dto: PutVersionResult =
        assert_dto_roundtrip_matches_live("POST /api/drive/files/{id}/versions", &vc_body);
    let version_id = ver_dto.version_id;

    // Drive metadata reads: tree, batch nodes meta, versions, history, changes, watches, audit-actions
    let tree_resp = client
        .get(format!("{base}/api/drive/spaces/{space_id}/tree"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/drive/spaces/{id}/tree");
    let tr_status = tree_resp.status().as_u16();
    let tr_ct = tree_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let tr_body = tree_resp.text().await.expect("tree body");
    assert_eq!(tr_status, 200, "body={tr_body}");
    assert_openapi_response(
        &doc,
        "/api/drive/spaces/{id}/tree",
        "GET",
        tr_status,
        tr_ct.as_deref(),
        &tr_body,
    );
    let tree_dto: Vec<DriveNode> =
        assert_dto_roundtrip_matches_live("GET /api/drive/spaces/{id}/tree", &tr_body);
    assert!(tree_dto.iter().any(|n| n.id == file_node_id));

    let meta_resp = client
        .get(format!("{base}/api/drive/nodes?ids={file_node_id}"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/drive/nodes");
    let nm_status = meta_resp.status().as_u16();
    let nm_ct = meta_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let nm_body = meta_resp.text().await.expect("nodes meta body");
    assert_eq!(nm_status, 200, "body={nm_body}");
    assert_openapi_response(
        &doc,
        "/api/drive/nodes",
        "GET",
        nm_status,
        nm_ct.as_deref(),
        &nm_body,
    );
    let meta_dto: Vec<DriveNodeMeta> =
        assert_dto_roundtrip_matches_live("GET /api/drive/nodes", &nm_body);
    assert_eq!(meta_dto.len(), 1);
    assert_eq!(meta_dto[0].head_version_id, Some(version_id));

    let vers_resp = client
        .get(format!("{base}/api/drive/files/{file_node_id}/versions"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/drive/files/{id}/versions");
    let vs_status = vers_resp.status().as_u16();
    let vs_ct = vers_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let vs_body = vers_resp.text().await.expect("versions body");
    assert_eq!(vs_status, 200, "body={vs_body}");
    assert_openapi_response(
        &doc,
        "/api/drive/files/{id}/versions",
        "GET",
        vs_status,
        vs_ct.as_deref(),
        &vs_body,
    );
    let vers_dto: Vec<DriveVersion> =
        assert_dto_roundtrip_matches_live("GET /api/drive/files/{id}/versions", &vs_body);
    assert_eq!(vers_dto.len(), 1);

    let hist_resp = client
        .get(format!("{base}/api/drive/files/{file_node_id}/history"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/drive/files/{id}/history");
    let hi_status = hist_resp.status().as_u16();
    let hi_ct = hist_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let hi_body = hist_resp.text().await.expect("history body");
    assert_eq!(hi_status, 200, "body={hi_body}");
    assert_openapi_response(
        &doc,
        "/api/drive/files/{id}/history",
        "GET",
        hi_status,
        hi_ct.as_deref(),
        &hi_body,
    );
    let _hist_dto: DriveHistoryResult =
        assert_dto_roundtrip_matches_live("GET /api/drive/files/{id}/history", &hi_body);

    let chg_resp = client
        .get(format!("{base}/api/drive/changes?space={space_id}&since=0"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/drive/changes");
    let ch_status = chg_resp.status().as_u16();
    let ch_ct = chg_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let ch_body = chg_resp.text().await.expect("changes body");
    assert_eq!(ch_status, 200, "body={ch_body}");
    assert_openapi_response(
        &doc,
        "/api/drive/changes",
        "GET",
        ch_status,
        ch_ct.as_deref(),
        &ch_body,
    );
    let _chg_dto: DriveChangesResult =
        assert_dto_roundtrip_matches_live("GET /api/drive/changes", &ch_body);

    let watches_resp = client
        .get(format!("{base}/api/drive/watches"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/drive/watches");
    let wa_status = watches_resp.status().as_u16();
    let wa_ct = watches_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let wa_body = watches_resp.text().await.expect("watches body");
    assert_eq!(wa_status, 200, "body={wa_body}");
    assert_openapi_response(
        &doc,
        "/api/drive/watches",
        "GET",
        wa_status,
        wa_ct.as_deref(),
        &wa_body,
    );
    let _watches_dto: Vec<DriveWatchRow> =
        assert_dto_roundtrip_matches_live("GET /api/drive/watches", &wa_body);

    let actions_resp = client
        .get(format!("{base}/api/drive/audit-actions"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/drive/audit-actions");
    let aa_status = actions_resp.status().as_u16();
    let aa_ct = actions_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let aa_body = actions_resp.text().await.expect("audit-actions body");
    assert_eq!(aa_status, 200, "body={aa_body}");
    assert_openapi_response(
        &doc,
        "/api/drive/audit-actions",
        "GET",
        aa_status,
        aa_ct.as_deref(),
        &aa_body,
    );
    let actions_dto: Vec<String> =
        assert_dto_roundtrip_matches_live("GET /api/drive/audit-actions", &aa_body);
    assert!(!actions_dto.is_empty());

    // Drive Content: Full 200 + Partial 206 Range + 416 Range Not Satisfiable
    let full_resp = client
        .get(format!("{base}/api/drive/versions/{version_id}/content"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET full /api/drive/versions/{id}/content");
    let full_status = full_resp.status().as_u16();
    let full_ct = full_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    assert_eq!(
        full_resp
            .headers()
            .get("accept-ranges")
            .and_then(|v| v.to_str().ok()),
        Some("bytes")
    );
    let full_bytes = full_resp.bytes().await.expect("full content bytes");
    assert_eq!(full_status, 200);
    assert_eq!(full_bytes.as_ref(), payload);
    assert_openapi_response(
        &doc,
        "/api/drive/versions/{id}/content",
        "GET",
        full_status,
        full_ct.as_deref(),
        "",
    );

    let range_resp = client
        .get(format!("{base}/api/drive/versions/{version_id}/content"))
        .header("authorization", &auth_header)
        .header("range", "bytes=0-4")
        .send()
        .await
        .expect("GET Range 206 /api/drive/versions/{id}/content");
    let range_status = range_resp.status().as_u16();
    let range_ct = range_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let content_range = range_resp
        .headers()
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let accept_ranges = range_resp
        .headers()
        .get("accept-ranges")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let range_bytes = range_resp.bytes().await.expect("range content bytes");
    assert_eq!(range_status, 206);
    assert_eq!(content_range.as_deref(), Some("bytes 0-4/30"));
    assert_eq!(accept_ranges.as_deref(), Some("bytes"));
    assert_eq!(range_bytes.as_ref(), b"Hello");
    assert_openapi_response(
        &doc,
        "/api/drive/versions/{id}/content",
        "GET",
        range_status,
        range_ct.as_deref(),
        "",
    );

    let bad_range = client
        .get(format!("{base}/api/drive/versions/{version_id}/content"))
        .header("authorization", &auth_header)
        .header("range", "bytes=999-1000")
        .send()
        .await
        .expect("GET 416 /api/drive/versions/{id}/content");
    let br_status = bad_range.status().as_u16();
    let br_ct = bad_range
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let br_body = bad_range.text().await.expect("416 body");
    assert_eq!(br_status, 416, "body={br_body}");
    assert_openapi_response(
        &doc,
        "/api/drive/versions/{id}/content",
        "GET",
        br_status,
        br_ct.as_deref(),
        &br_body,
    );
    let br_prob: ProblemDetails =
        assert_dto_roundtrip_matches_live("416 GET Drive version content", &br_body);
    assert_eq!(br_prob.status, 416);

    // Drive Preview: upload an Office MIME version so preview_status='pending'
    // -> 404 (detail contains status=pending) -> seed ready preview rendition
    // -> 200 full PDF, 206 Partial Content Range, and 416 Range Not Satisfiable
    let office_ver_req = DrivePutVersionRequest {
        content_sha256: chunk_sha.to_owned(),
        size: payload.len() as i64,
        content_type: Some(Some(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document".to_owned(),
        )),
        base_version_id: Some(version_id),
        manifest: vec![DriveManifestChunk {
            sha256: chunk_sha.to_owned(),
            size: payload.len() as i64,
        }],
        note: Some("office preview conformance version".to_owned()),
        device_label: Some("conformance".to_owned()),
        branch_id: None,
    };
    let office_ver_resp = client
        .post(format!("{base}/api/drive/files/{file_node_id}/versions"))
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(
            serde_json::to_string(&office_ver_req)
                .expect("serialize office DrivePutVersionRequest"),
        )
        .send()
        .await
        .expect("POST office version for preview");
    let ov_status = office_ver_resp.status().as_u16();
    let ov_body = office_ver_resp.text().await.expect("office version body");
    assert_eq!(ov_status, 201, "body={ov_body}");
    let office_ver_dto: PutVersionResult =
        assert_dto_roundtrip_matches_live("POST office Drive version", &ov_body);
    let preview_version_id = office_ver_dto.version_id;

    let preview_pending = client
        .get(format!(
            "{base}/api/drive/versions/{preview_version_id}/preview"
        ))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET pending /api/drive/versions/{id}/preview");
    let pp_status = preview_pending.status().as_u16();
    let pp_ct = preview_pending
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let pp_body = preview_pending.text().await.expect("preview 404 body");
    assert_eq!(pp_status, 404, "body={pp_body}");
    assert_openapi_response(
        &doc,
        "/api/drive/versions/{id}/preview",
        "GET",
        pp_status,
        pp_ct.as_deref(),
        &pp_body,
    );
    let pp_prob: ProblemDetails =
        assert_dto_roundtrip_matches_live("404 pending GET Drive preview", &pp_body);
    assert_eq!(pp_prob.status, 404);
    assert!(
        pp_prob
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("status=pending")),
        "expected preview 404 detail to contain status=pending, got {:?}",
        pp_prob.detail
    );

    // Mark rendition ready pointing to our already-staged mock S3 chunk.
    {
        let (pg, conn) = tokio_postgres::connect(&dsn, NoTls)
            .await
            .expect("connect test DB to seed preview rendition");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        pg.execute(
            "INSERT INTO drive_version_chunks (version_id, stream, ordinal, scope_key, chunk_sha256)
             SELECT version_id, 'preview', ordinal, scope_key, chunk_sha256
               FROM drive_version_chunks
              WHERE version_id = $1 AND stream = 'content'",
            &[&preview_version_id],
        )
        .await
        .expect("seed preview stream chunk");
        pg.execute(
            "UPDATE drive_file_versions SET preview_status = 'ready' WHERE id = $1",
            &[&preview_version_id],
        )
        .await
        .expect("mark preview_status ready");
    }

    let prev_full = client
        .get(format!(
            "{base}/api/drive/versions/{preview_version_id}/preview"
        ))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET 200 /api/drive/versions/{id}/preview");
    let pf_status = prev_full.status().as_u16();
    let pf_ct = prev_full
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    assert_eq!(
        prev_full
            .headers()
            .get("accept-ranges")
            .and_then(|v| v.to_str().ok()),
        Some("bytes")
    );
    let pf_bytes = prev_full.bytes().await.expect("preview full bytes");
    assert_eq!(pf_status, 200);
    assert_eq!(pf_bytes.as_ref(), payload);
    assert_openapi_response(
        &doc,
        "/api/drive/versions/{id}/preview",
        "GET",
        pf_status,
        pf_ct.as_deref(),
        "",
    );

    let prev_range = client
        .get(format!(
            "{base}/api/drive/versions/{preview_version_id}/preview"
        ))
        .header("authorization", &auth_header)
        .header("range", "bytes=0-4")
        .send()
        .await
        .expect("GET 206 /api/drive/versions/{id}/preview");
    let pr_status = prev_range.status().as_u16();
    let pr_ct = prev_range
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let pr_cr = prev_range
        .headers()
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let pr_ar = prev_range
        .headers()
        .get("accept-ranges")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let pr_bytes = prev_range.bytes().await.expect("preview range bytes");
    assert_eq!(pr_status, 206);
    assert_eq!(pr_cr.as_deref(), Some("bytes 0-4/30"));
    assert_eq!(pr_ar.as_deref(), Some("bytes"));
    assert_eq!(pr_bytes.as_ref(), b"Hello");
    assert_openapi_response(
        &doc,
        "/api/drive/versions/{id}/preview",
        "GET",
        pr_status,
        pr_ct.as_deref(),
        "",
    );

    let prev_bad_range = client
        .get(format!(
            "{base}/api/drive/versions/{preview_version_id}/preview"
        ))
        .header("authorization", &auth_header)
        .header("range", "bytes=999-1000")
        .send()
        .await
        .expect("GET 416 /api/drive/versions/{id}/preview");
    let pbr_status = prev_bad_range.status().as_u16();
    let pbr_ct = prev_bad_range
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    assert_eq!(
        prev_bad_range
            .headers()
            .get("accept-ranges")
            .and_then(|v| v.to_str().ok()),
        Some("bytes")
    );
    assert_eq!(
        prev_bad_range
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok()),
        Some("inline")
    );
    let pbr_body = prev_bad_range.text().await.expect("preview 416 body");
    assert_eq!(pbr_status, 416, "body={pbr_body}");
    assert_openapi_response(
        &doc,
        "/api/drive/versions/{id}/preview",
        "GET",
        pbr_status,
        pbr_ct.as_deref(),
        &pbr_body,
    );
    let pbr_prob: ProblemDetails =
        assert_dto_roundtrip_matches_live("416 GET Drive version preview", &pbr_body);
    assert_eq!(pbr_prob.status, 416);

    // 10. Wave 3.7 (#562) Sharing conformance: GET /api/me/sharing
    let sharing_resp = client
        .get(format!("{base}/api/me/sharing"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("GET /api/me/sharing");
    let sh_status = sharing_resp.status().as_u16();
    let sh_ct = sharing_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let sh_body = sharing_resp.text().await.expect("sharing body");
    assert_eq!(sh_status, 200, "body={sh_body}");
    assert_openapi_response(
        &doc,
        "/api/me/sharing",
        "GET",
        sh_status,
        sh_ct.as_deref(),
        &sh_body,
    );
    let _sh_dto: SharingOverview =
        assert_dto_roundtrip_matches_live("GET /api/me/sharing", &sh_body);

    // 11. Failed-auth conformance checks LAST so loopback threat counters never
    //     interfere with earlier /auth/* (e.g. POST /auth/mfa/reauth) or API calls.
    let bad_login = client
        .post(format!("{base}/auth/login"))
        .header("content-type", "application/json")
        .body(
            serde_json::to_string(&AuthLoginRequest {
                email: email.to_owned(),
                password: "WrongPassword999!".to_owned(),
                stay_signed_in: None,
                remember_device: None,
                dpop_jwk: None,
            })
            .expect("serialize bad login"),
        )
        .send()
        .await
        .expect("POST /auth/login wrong password");
    let bl_status = bad_login.status().as_u16();
    let bl_ct = bad_login
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bl_body = bad_login.text().await.expect("bad login body");
    assert_eq!(bl_status, 401, "body={bl_body}");
    assert_openapi_response(
        &doc,
        "/auth/login",
        "POST",
        bl_status,
        bl_ct.as_deref(),
        &bl_body,
    );
    let _: ProblemDetails = assert_dto_roundtrip_matches_live("401 POST /auth/login", &bl_body);

    let refresh_bad_json = client
        .post(format!("{base}/auth/refresh"))
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body("{not-json")
        .send()
        .await
        .expect("POST /auth/refresh invalid json");
    let rbj_status = refresh_bad_json.status().as_u16();
    let rbj_ct = refresh_bad_json
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let rbj_body = refresh_bad_json.text().await.expect("refresh 400 body");
    assert_eq!(rbj_status, 400, "body={rbj_body}");
    assert_openapi_response(
        &doc,
        "/auth/refresh",
        "POST",
        rbj_status,
        rbj_ct.as_deref(),
        &rbj_body,
    );
    let _: ProblemDetails = assert_dto_roundtrip_matches_live("400 POST /auth/refresh", &rbj_body);

    let refresh_bad_tok = client
        .post(format!("{base}/auth/refresh"))
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(
            serde_json::to_string(&AuthRefreshRequest {
                refresh_token: Some("not-a-valid-jwt".to_owned()),
            })
            .expect("serialize invalid refresh"),
        )
        .send()
        .await
        .expect("POST /auth/refresh invalid token");
    let rbt_status = refresh_bad_tok.status().as_u16();
    let rbt_ct = refresh_bad_tok
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let rbt_body = refresh_bad_tok.text().await.expect("refresh 401 body");
    assert_eq!(rbt_status, 401, "body={rbt_body}");
    assert_openapi_response(
        &doc,
        "/auth/refresh",
        "POST",
        rbt_status,
        rbt_ct.as_deref(),
        &rbt_body,
    );
    let _: ProblemDetails = assert_dto_roundtrip_matches_live("401 POST /auth/refresh", &rbt_body);

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
