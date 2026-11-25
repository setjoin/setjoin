//! #359 Part A integration suite: verifies every former `deny.rs:100` refusal class
//! (impersonation `act`, `Guest`, `MailboxBlocked`, `NoPrimaryMailbox`, `AlternativeCredential`),
//! the `deploy_remote_fence` R2 fix, the `rule_config_template_create` NULLIF fix,
//! Drive `b.rs` guest defense-in-depth without `SessionAdmission`, and guest malformed `act <= 0`.
mod common;
#[allow(dead_code, unused_imports)]
mod platform_oracle;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures_util::FutureExt;
use http_body_util::BodyExt;
use hyper::{Method, Request, Response};
use serde_json::{json, Value};
use setjoin_authz::jwks::Jwks;
use setjoin_authz::legacy_jwt::{sign_hs256, LegacyKeys};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::calendar::CalendarRoute;
use setjoin_gateway::drive::DriveRoute;
use setjoin_gateway::jmap::transfer::Signer as AttachmentSigner;
use setjoin_gateway::jmap::{JmapCommands, JmapRoute, JmapServices};
use setjoin_gateway::offline::OfflineRoute;
use setjoin_gateway::platform_updates::PlatformUpdatesRoute;
use setjoin_gateway::recovery_worker::S3Store;
use setjoin_gateway::rules::RulesRoute;
use setjoin_gateway::{ClientIdentity, Intercept, RequestContext};
use sha2::{Digest, Sha256};

use common::BoxError;

const SECRET: &[u8] = b"authz-deny-final-test-secret-32-bytes!";
const ISSUER: &str = "mailserver";

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn keys() -> Arc<Jwks> {
    Arc::new(
        Jwks::with_fetch(Box::new(|| {
            Box::pin(async { Err::<Vec<u8>, String>("HS256 must not fetch JWKS".into()) })
        }))
        .with_legacy_keys(LegacyKeys::new(SECRET, &["authserver-hmac-1"], None).unwrap()),
    )
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn token(uid: i64, extra: Value) -> String {
    let mut c = json!({
        "uid": uid,
        "email": format!("final359-{uid}@example.test"),
        "typ": "access",
        "jti": format!("final359-jti-{uid}"),
        "fam": format!("final359-fam-{uid}"),
        "iss": ISSUER,
        "aud": ["mailserver-gateway"],
        "iat": now() - 10,
        "exp": now() + 600,
    });
    if let (Some(dst), Some(src)) = (c.as_object_mut(), extra.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    sign_hs256(SECRET, &c.to_string())
}

fn req_ctx() -> RequestContext {
    RequestContext {
        identity: ClientIdentity {
            client_ip: "127.0.0.1".parse().unwrap(),
            proto: "http",
        },
        // Unreachable port: proves zero Go forwarding occurs on any test case.
        upstream: setjoin_gateway::proxy::Upstream::new("http://127.0.0.1:9".parse().unwrap())
            .unwrap(),
    }
}

async fn invoke(
    route: &impl Intercept,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    body: impl Into<Bytes>,
) -> (u16, hyper::HeaderMap, Bytes) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "mail.test")
        .header("origin", "http://mail.test")
        .header("content-type", "application/json");
    if let Some(a) = auth {
        builder = builder.header("authorization", a);
    }
    let req = builder.body(common::full(body)).unwrap();
    assert!(route.matches(&req), "route did not match {method} {uri}");
    let resp = route.handle(req, req_ctx()).await;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, bytes)
}

async fn uniq(c: &tokio_postgres::Client) -> Result<String, BoxError> {
    Ok(
        c.query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[])
            .await?
            .get(0),
    )
}

async fn create_domain(c: &tokio_postgres::Client, prefix: &str) -> Result<i64, BoxError> {
    let u = uniq(c).await?;
    Ok(c.query_one(
        "INSERT INTO domains(name,is_local) VALUES($1,true) RETURNING id",
        &[&format!("{prefix}-{u}.test")],
    )
    .await?
    .get(0))
}

async fn create_mailboxless_user(
    c: &tokio_postgres::Client,
    domain: i64,
    prefix: &str,
) -> Result<i64, BoxError> {
    let u = uniq(c).await?;
    let name = format!("{prefix}.nomb.{u}");
    Ok(c.query_one(
        "INSERT INTO users(username,domain_id,email,display_name,password_hash) \
         VALUES($1,$2,$3,'final359 nomb','x') RETURNING id",
        &[&name, &domain, &format!("{name}@example.test")],
    )
    .await?
    .get(0))
}

async fn create_active_guest(
    c: &tokio_postgres::Client,
    host_domain: i64,
    prefix: &str,
) -> Result<i64, BoxError> {
    let u = uniq(c).await?;
    let name = format!("{prefix}.guest.{u}");
    let email = format!("{name}@example.test");
    let user: i64 = c
        .query_one(
            "INSERT INTO users(username,domain_id,email,display_name,password_hash) \
             VALUES($1,(SELECT id FROM domains WHERE name='guest.invalid'),$2,'final359 guest','x') RETURNING id",
            &[&name, &email],
        )
        .await?
        .get(0);
    c.execute(
        "INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) \
         VALUES($1,$2,'inviter@example.test',$3,'active')",
        &[&user, &email, &host_domain],
    )
    .await?;
    Ok(user)
}

/// Minimal in-memory fake S3 server supporting PUT, HEAD, GET (with Range), COPY, DELETE.
async fn fake_s3() -> (std::net::SocketAddr, Arc<Mutex<HashMap<String, Bytes>>>) {
    let objects: Arc<Mutex<HashMap<String, Bytes>>> = Arc::new(Mutex::new(HashMap::new()));
    let store = objects.clone();
    let addr = common::fake_upstream(move |mut req: Request<hyper::body::Incoming>| {
        let store = store.clone();
        async move {
            if req.uri().query() == Some("location=") {
                return Response::new(common::full(
                    "<LocationConstraint>us-east-1</LocationConstraint>",
                ));
            }
            let norm = |p: &str| {
                let p = p.trim_start_matches('/');
                p.strip_prefix("mailblobs/").unwrap_or(p).to_owned()
            };
            let lookup = |map: &HashMap<String, Bytes>, key: &str| -> Option<Bytes> {
                map.get(key)
                    .or_else(|| key.rsplit('/').next().and_then(|leaf| map.get(leaf)))
                    .cloned()
            };
            let key = norm(req.uri().path());
            let method = req.method().clone();
            if method == Method::PUT {
                if let Some(src) = req
                    .headers()
                    .get("x-amz-copy-source")
                    .and_then(|v| v.to_str().ok())
                {
                    let src_key = norm(src);
                    let data = lookup(&store.lock().unwrap(), &src_key);
                    if let Some(data) = data {
                        store.lock().unwrap().insert(key, data);
                        return Response::builder()
                            .status(200)
                            .header("etag", "\"ok\"")
                            .body(common::full(
                                "<CopyObjectResult><ETag>\"ok\"</ETag></CopyObjectResult>",
                            ))
                            .unwrap();
                    }
                    return Response::builder()
                        .status(404)
                        .body(common::full(""))
                        .unwrap();
                }
                let body = req.body_mut().collect().await.unwrap().to_bytes();
                store.lock().unwrap().insert(key, body);
                return Response::builder()
                    .status(200)
                    .header("etag", "\"ok\"")
                    .body(common::full(""))
                    .unwrap();
            }
            if method == Method::HEAD {
                if key.is_empty() {
                    return Response::builder()
                        .status(200)
                        .body(common::full(""))
                        .unwrap();
                }
                let len = lookup(&store.lock().unwrap(), &key).map(|b| b.len());
                return match len {
                    Some(n) => Response::builder()
                        .status(200)
                        .header("content-type", "application/octet-stream")
                        .header("content-length", n.to_string())
                        .header("etag", "\"ok\"")
                        .header("last-modified", "Sat, 31 Oct 2026 00:00:00 GMT")
                        .body(common::full(""))
                        .unwrap(),
                    None => Response::builder()
                        .status(404)
                        .header("content-type", "application/xml")
                        .body(common::full("<Error><Code>NoSuchKey</Code></Error>"))
                        .unwrap(),
                };
            }
            if method == Method::GET {
                let data = lookup(&store.lock().unwrap(), &key);
                return match data {
                    Some(b) => {
                        if let Some(range) = req
                            .headers()
                            .get("range")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.strip_prefix("bytes="))
                        {
                            let (s, e) = range.split_once('-').unwrap_or(("0", ""));
                            let start = s.parse::<usize>().unwrap_or(0);
                            let end = if e.is_empty() {
                                b.len().saturating_sub(1)
                            } else {
                                e.parse::<usize>().unwrap_or(b.len().saturating_sub(1))
                            };
                            let part = b.slice(start..=end.min(b.len().saturating_sub(1)));
                            return Response::builder()
                                .status(206)
                                .header("content-type", "application/octet-stream")
                                .header("content-length", part.len().to_string())
                                .header("content-range", format!("bytes {start}-{end}/{}", b.len()))
                                .header("etag", "\"ok\"")
                                .header("last-modified", "Sat, 31 Oct 2026 00:00:00 GMT")
                                .body(common::full(part))
                                .unwrap();
                        }
                        Response::builder()
                            .status(200)
                            .header("content-type", "application/octet-stream")
                            .header("content-length", b.len().to_string())
                            .header("etag", "\"ok\"")
                            .header("last-modified", "Sat, 31 Oct 2026 00:00:00 GMT")
                            .body(common::full(b))
                            .unwrap()
                    }
                    None => Response::builder()
                        .status(404)
                        .header("content-type", "application/xml")
                        .body(common::full("<Error><Code>NoSuchKey</Code></Error>"))
                        .unwrap(),
                };
            }
            if method == Method::DELETE {
                store.lock().unwrap().remove(&key);
                return Response::builder()
                    .status(204)
                    .body(common::full(""))
                    .unwrap();
            }
            Response::builder()
                .status(405)
                .body(common::full(""))
                .unwrap()
        }
    })
    .await;
    (addr, objects)
}

/// Required Test 1: `deploy_remote_fence` mailbox-less admin persists
/// `actor_user_id == admin.user_id()` (not `0` or `mailbox_id`).
#[tokio::test]
async fn deploy_remote_fence_persists_mailboxless_admin_user_id() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("final359-deploy-fence") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let domain = create_domain(&owner, "final359-fence").await?;
    let admin = create_mailboxless_user(&owner, domain, "final359-fence").await?;
    let role = format!("final359-fence-role-{admin}");
    owner
        .batch_execute(
            "DELETE FROM deploy_remote_fence; \
             DELETE FROM deployment_steps WHERE step_name IN('ssh_check','install_packages','configure_replication','configure_pgpool','configure_seaweedfs','start_services','verify');",
        )
        .await?;
    owner
        .execute(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,NULL)",
            &[&role, &vec!["system.upgrade".to_owned()]],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) \
             SELECT $1,id,$1,false FROM admin_role_groups WHERE name=$2",
            &[&admin, &role],
        )
        .await?;

    let outcome = std::panic::AssertUnwindSafe(async {
        let peer = platform_oracle::deploy::Peer::start("hold").await?;
        let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?
            .with_audit_keys("22".repeat(32), String::new());
        let deploy = setjoin_platform::deploy::Config::fixed(
            peer.host_key.clone(),
            "a".repeat(64),
            ("test-access".into(), "test-secret".into()),
        );
        let route = PlatformUpdatesRoute::new(exec, keys(), ISSUER.into())
            .with_deploy(common::patient_exec(&db.dsn, 4)?, deploy)
            .await;

        let bearer = format!("Bearer {}", token(admin, json!({"admin": true})));
        let body = json!({
            "nodes": (0..3).map(|i| json!({
                "host": peer.addresses[i],
                "role": if i == 0 { "primary" } else { "standby" },
                "ssh_user": "root",
                "ssh_key": peer.private_key,
                "password": "final359-node-password"
            })).collect::<Vec<_>>()
        })
        .to_string();

        let (status, _, bytes) = invoke(
            &route,
            "POST",
            "/api/admin/deploy/start",
            Some(&bearer),
            body,
        )
        .await;
        assert_eq!(
            status,
            202,
            "mailbox-less admin deploy start failed: {}",
            String::from_utf8_lossy(&bytes)
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while peer.command_count() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "deploy run never reached SSH peer"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let (status, _, _) = invoke(
            &route,
            "POST",
            "/api/admin/deploy/cancel",
            Some(&bearer),
            "",
        )
        .await;
        assert_eq!(status, 204);

        let persisted: Option<i64> = owner
            .query_one(
                "SELECT actor_user_id FROM deploy_remote_fence WHERE id = true",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(
            persisted,
            Some(admin),
            "deploy_remote_fence.actor_user_id must equal admin.user_id(), not 0 or mailbox_id"
        );
        Ok::<(), BoxError>(())
    })
    .catch_unwind()
    .await;

    let _ = owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; \
             DELETE FROM deploy_remote_fence; \
             DELETE FROM deployment_steps WHERE step_name IN('ssh_check','install_packages','configure_replication','configure_pgpool','configure_seaweedfs','start_services','verify'); \
             DELETE FROM admin_audit_log WHERE user_id={admin}; \
             DELETE FROM admin_role_assignments WHERE user_id={admin}; \
             DELETE FROM admin_role_groups WHERE name='{role}'; \
             DELETE FROM users WHERE id={admin}; \
             DELETE FROM domains WHERE id={domain}; COMMIT;"
        ))
        .await;
    match outcome {
        Ok(res) => res,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Required Test 2: `POST /api/admin/rules?from_template={id}` with a mailbox-less
/// admin returns `201` and persists `rules.mailbox_id IS NULL` (not 500 FK error).
#[tokio::test]
async fn rule_template_apply_allows_mailboxless_admin_with_null_mailbox() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("final359-rule-template") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let domain = create_domain(&owner, "final359-ruletpl").await?;
    let admin = create_mailboxless_user(&owner, domain, "final359-ruletpl").await?;
    let role = format!("final359-ruletpl-role-{admin}");
    owner
        .execute(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,NULL)",
            &[&role, &vec!["mail.pipeline".to_owned()]],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) \
             SELECT $1,id,$1,false FROM admin_role_groups WHERE name=$2",
            &[&admin, &role],
        )
        .await?;
    let created_tpl_tables = !owner
        .query_one(
            "SELECT to_regclass('public.rule_templates') IS NOT NULL",
            &[],
        )
        .await?
        .get::<_, bool>(0);
    if created_tpl_tables {
        owner
            .batch_execute(concat!(
                "BEGIN;",
                include_str!("../../../tests/conformance/rules/legacy-fixture.sql"),
                "COMMIT;"
            ))
            .await?;
    }
    let template_id: i64 = owner
        .query_one(
            "INSERT INTO rule_templates(name,description,category,conditions,actions,parameters,sort_order) \
             VALUES($1,'test','organization','{\"match\":\"all\",\"rules\":[]}'::jsonb,'[]'::jsonb,'[]'::jsonb,999) RETURNING id",
            &[&format!("final359-tpl-{admin}")],
        )
        .await?
        .get(0);

    let mut created_rule: Option<i64> = None;
    let outcome = std::panic::AssertUnwindSafe(async {
        let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?;
        let worker = common::patient_exec(&db.dsn, 4)?;
        let route = RulesRoute {
            exec,
            worker,
            keys: keys(),
            issuer: ISSUER.into(),
        };
        let bearer = format!("Bearer {}", token(admin, json!({"admin": true})));
        let (status, _, bytes) = invoke(
            &route,
            "POST",
            &format!("/api/admin/rules?from_template={template_id}"),
            Some(&bearer),
            "{}",
        )
        .await;
        assert_eq!(
            status,
            201,
            "template instantiate failed: {}",
            String::from_utf8_lossy(&bytes)
        );
        let body: Value = serde_json::from_slice(&bytes)?;
        let rule_id = body["id"].as_i64().ok_or("missing rule id")?;
        created_rule = Some(rule_id);
        let mailbox_id: Option<i64> = owner
            .query_one("SELECT mailbox_id FROM rules WHERE id = $1", &[&rule_id])
            .await?
            .get(0);
        assert_eq!(
            mailbox_id, None,
            "mailbox-less admin rule must have rules.mailbox_id IS NULL"
        );
        Ok::<(), BoxError>(())
    })
    .catch_unwind()
    .await;

    if let Some(rid) = created_rule {
        let _ = owner
            .execute("DELETE FROM rules WHERE id = $1", &[&rid])
            .await;
    }
    if created_tpl_tables {
        let _ = owner
            .batch_execute("DROP TABLE IF EXISTS public.rule_template_visibility; DROP TABLE IF EXISTS public.rule_templates;")
            .await;
    } else {
        let _ = owner
            .execute("DELETE FROM rule_templates WHERE id = $1", &[&template_id])
            .await;
    }
    let _ = owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; \
             DELETE FROM admin_audit_log WHERE user_id={admin}; \
             DELETE FROM admin_role_assignments WHERE user_id={admin}; \
             DELETE FROM admin_role_groups WHERE name='{role}'; \
             DELETE FROM users WHERE id={admin}; \
             DELETE FROM domains WHERE id={domain}; COMMIT;"
        ))
        .await;
    match outcome {
        Ok(res) => res,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Required Test 3: Mailbox-less JMAP / HTTP / Messages / Offline / Calendar / Rules suite.
#[tokio::test]
async fn mailboxless_jmap_http_messages_and_handlers_match_go() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("final359-mailboxless-jmap") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let domain = create_domain(&owner, "final359-jmap").await?;
    let nomb = create_mailboxless_user(&owner, domain, "final359-jmap").await?;
    let delegator = fixture::account(&owner, "final359-delegator").await?;
    let stranger = fixture::account(&owner, "final359-stranger").await?;

    // Grant mailbox-less user full_access delegate on `delegator.mailbox`.
    owner
        .execute(
            "INSERT INTO mailbox_delegates(mailbox_id,user_id,permission,granted_by) \
             VALUES($1,$2,'full_access',$3)",
            &[&delegator.mailbox, &nomb, &delegator.user],
        )
        .await?;

    // Seed a real attachment blob in `delegator.mailbox` and store it in fake S3.
    let (s3_addr, s3_objects) = fake_s3().await;
    let blob_bytes = Bytes::from_static(b"hello-delegated-blob");
    let blob_sha = format!("{:x}", Sha256::digest(&blob_bytes));
    let blob_ref = format!("blobs/{}/{}/{}", &blob_sha[..2], &blob_sha[2..4], blob_sha);
    s3_objects
        .lock()
        .unwrap()
        .insert(blob_sha.clone(), blob_bytes.clone());
    s3_objects
        .lock()
        .unwrap()
        .insert(blob_ref.clone(), blob_bytes.clone());
    owner
        .execute(
            "INSERT INTO blobs(sha256,size_bytes,minio_ref,content_type) VALUES($1,$2,$3,'text/plain') ON CONFLICT DO NOTHING",
            &[&blob_sha, &(blob_bytes.len() as i64), &blob_ref],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO message_attachments(message_id,received_at,blob_sha256,filename,content_type,size_bytes) \
             SELECT id,received_at,$1,'hello.txt','text/plain',$2 FROM messages WHERE id=$3",
            &[&blob_sha, &(blob_bytes.len() as i64), &delegator.inbox_only],
        )
        .await?;

    // Save & enable feature flags needed for attachment-transfer-token, recovery-raw, booking, caldav.
    let toggle_keys = [
        "feature.offline_mail",
        "feature.connectivity_aware_sync",
        "feature.client_recovery_receipts",
        "feature.booking_pages",
        "feature.caldav",
    ];
    let saved_toggles = owner
        .query(
            "SELECT key, enabled FROM feature_toggles WHERE key = ANY($1)",
            &[&toggle_keys.as_slice()],
        )
        .await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled = true WHERE key = ANY($1)",
            &[&toggle_keys.as_slice()],
        )
        .await?;

    let outcome = std::panic::AssertUnwindSafe(async {
        let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?;
        let worker = common::patient_exec(&db.dsn, 4)?;
        let store = Arc::new(S3Store::new(
            &format!("http://{s3_addr}"),
            "mailblobs",
            "test-access",
            "test-secret",
        )?);
        let mut services = JmapServices::new(worker.clone(), "mail.test".into(), 10 << 20);
        services.store = Some(store.clone());
        services.continuity_boot = Some("00000000-0000-0000-0000-000000000001".into());
        services.attachment_signer = Some(Arc::new(
            AttachmentSigner::from_master(SECRET).expect("attachment signer"),
        ));
        let jmap = JmapRoute(Arc::new(JmapCommands {
            services: Some(Arc::new(services)),
            exec: exec.clone(),
            worker: Some(worker.clone()),
            keys: keys(),
            issuer: ISSUER.into(),
            denylist: None,
        }));
        let bearer = format!("Bearer {}", token(nomb, json!({})));

        // 1. GET /.well-known/jmap -> 500 about:blank "internal error"
        let (status, headers, bytes) =
            invoke(&jmap, "GET", "/.well-known/jmap", Some(&bearer), "").await;
        assert_eq!(status, 500, "body={}", String::from_utf8_lossy(&bytes));
        assert_eq!(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/problem+json")
        );
        let v: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(v["type"], json!("about:blank"));
        assert_eq!(v["detail"], json!("internal error"));

        // 2. POST /jmap: Core/echo (200), own/unowned account (accountNotFound), delegated account (200)
        let batch = json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [
                ["Core/echo", {"hello": "world"}, "c0"],
                ["Mailbox/get", {"accountId": stranger.mailbox.to_string()}, "c1"],
                ["Mailbox/get", {"accountId": delegator.mailbox.to_string()}, "c2"]
            ]
        })
        .to_string();
        let (status, _, bytes) = invoke(&jmap, "POST", "/jmap", Some(&bearer), batch).await;
        assert_eq!(status, 200, "body={}", String::from_utf8_lossy(&bytes));
        let resp: Value = serde_json::from_slice(&bytes)?;
        let mr = resp["methodResponses"].as_array().ok_or("methodResponses")?;
        assert_eq!(mr[0][0], json!("Core/echo"));
        assert_eq!(mr[0][1]["hello"], json!("world"));
        assert_eq!(mr[1][0], json!("error"));
        assert_eq!(
            mr[1][1]["type"],
            json!("urn:ietf:params:jmap:error:accountNotFound")
        );
        assert_eq!(
            mr[1][1]["detail"],
            json!("accountId does not match authenticated user")
        );
        assert_eq!(mr[2][0], json!("Mailbox/get"), "delegated Mailbox/get: {mr:?}");

        // 3. GET /jmap/download/{delegated}/{blob}/{name} -> 200 (zero panic in can_read/download_allowed)
        let (status, _, bytes) = invoke(
            &jmap,
            "GET",
            &format!("/jmap/download/{}/{blob_sha}/hello.txt", delegator.mailbox),
            Some(&bearer),
            "",
        )
        .await;
        assert_eq!(status, 200, "delegated download failed");
        assert_eq!(bytes, blob_bytes);
        // Non-delegated -> 404 blobNotFound
        let (status, _, bytes) = invoke(
            &jmap,
            "GET",
            &format!("/jmap/download/{}/{blob_sha}/hello.txt", stranger.mailbox),
            Some(&bearer),
            "",
        )
        .await;
        assert_eq!(status, 404, "non-delegated download: {}", String::from_utf8_lossy(&bytes));

        // 4. POST /jmap/upload/{delegated} -> 201, non-delegated -> 403 accountNotFound
        let (status, _, bytes) = invoke(
            &jmap,
            "POST",
            &format!("/jmap/upload/{}", delegator.mailbox),
            Some(&bearer),
            "uploaded-by-mailboxless-delegate",
        )
        .await;
        assert_eq!(
            status,
            201,
            "delegated upload failed: {}",
            String::from_utf8_lossy(&bytes)
        );
        let (status, _, bytes) = invoke(
            &jmap,
            "POST",
            &format!("/jmap/upload/{}", stranger.mailbox),
            Some(&bearer),
            "nope",
        )
        .await;
        assert_eq!(status, 403, "non-delegated upload: {}", String::from_utf8_lossy(&bytes));
        assert!(String::from_utf8_lossy(&bytes).contains("accountNotFound"));

        // 5. GET /jmap/recovery-raw/{accountId}/{messageId} -> 403 forbidden
        let (status, _, bytes) = invoke(
            &jmap,
            "GET",
            &format!("/jmap/recovery-raw/{}/{}", stranger.mailbox, stranger.inbox_only),
            Some(&bearer),
            "",
        )
        .await;
        assert_eq!(status, 403, "recovery-raw: {}", String::from_utf8_lossy(&bytes));
        assert!(String::from_utf8_lossy(&bytes).contains("recovery account access denied"));

        // 6. /api/messages/{id}/{recall,focus,unsubscribe,download,attachments.zip} -> 404 (not 500)
        for (method, path, body) in [
            ("POST", "/api/messages/999999/recall", ""),
            ("POST", "/api/messages/999999/focus", "{\"focused\":true}"),
            ("POST", "/api/messages/999999/unsubscribe", ""),
            ("GET", "/api/messages/999999/download", ""),
            ("GET", "/api/messages/999999/attachments.zip", ""),
        ] {
            let (status, _, bytes) = invoke(&jmap, method, path, Some(&bearer), body).await;
            assert_eq!(
                status,
                404,
                "{method} {path} gave {status}: {}",
                String::from_utf8_lossy(&bytes)
            );
        }

        // 7. POST /api/messages/{id}/undo -> 404 "mailbox not found"
        let (status, _, bytes) =
            invoke(&jmap, "POST", "/api/messages/999999/undo", Some(&bearer), "").await;
        assert_eq!(status, 404, "undo: {}", String::from_utf8_lossy(&bytes));
        assert!(String::from_utf8_lossy(&bytes).contains("mailbox not found"));

        // 8. POST /api/mail/attachment-transfer-token: 403 -> 400 -> 404 ordering!
        let (status, _, bytes) = invoke(
            &jmap,
            "POST",
            "/api/mail/attachment-transfer-token",
            Some(&bearer),
            "{}",
        )
        .await;
        assert_eq!(status, 403, "no device claim must be 403 before mailbox check");
        assert!(String::from_utf8_lossy(&bytes).contains("normal native access session required"));

        let device_bearer = format!(
            "Bearer {}",
            token(
                nomb,
                json!({"device": {"id": "fp-1", "platform": "desktop"}})
            )
        );
        let (status, _, bytes) = invoke(
            &jmap,
            "POST",
            "/api/mail/attachment-transfer-token",
            Some(&device_bearer),
            "{\"accountId\":\"bad\"}",
        )
        .await;
        assert_eq!(status, 400, "invalid body must be 400 before mailbox check");
        assert!(String::from_utf8_lossy(&bytes).contains("invalid attachment transfer request"));

        let (status, _, bytes) = invoke(
            &jmap,
            "POST",
            "/api/mail/attachment-transfer-token",
            Some(&device_bearer),
            json!({"accountId": delegator.mailbox.to_string(), "sha256": blob_sha}).to_string(),
        )
        .await;
        assert_eq!(status, 404, "valid body with mailbox_id == 0 must be plain 404");
        assert_eq!(bytes.as_ref(), b"404 page not found\n");

        // 9. Offline wipe-ack, Calendar booking/free-busy/subscriptions, Rules create/apply
        let offline = OfflineRoute {
            exec: exec.clone(),
            worker: worker.clone(),
            keys: keys(),
            issuer: ISSUER.into(),
        };
        let (status, _, bytes) = invoke(
            &offline,
            "POST",
            "/api/offline/wipe-ack",
            Some(&bearer),
            "{\"device_id\":1}",
        )
        .await;
        assert_eq!(status, 404, "wipe-ack: {}", String::from_utf8_lossy(&bytes));
        assert!(String::from_utf8_lossy(&bytes).contains("mailbox not found"));

        let calendar = CalendarRoute {
            exec: exec.clone(),
            worker: worker.clone(),
            queue: None,
            keys: keys(),
            issuer: ISSUER.into(),
            store: None,
            public_base: "https://mail.test".into(),
            kick: None,
        };
        let (status, _, bytes) =
            invoke(&calendar, "GET", "/api/booking/pages", Some(&bearer), "").await;
        assert_eq!(status, 404, "booking pages: {}", String::from_utf8_lossy(&bytes));
        assert!(String::from_utf8_lossy(&bytes).contains("mailbox not found"));

        let (status, _, bytes) = invoke(
            &calendar,
            "POST",
            "/api/calendar/free-busy",
            Some(&bearer),
            json!({
                "user_ids": [delegator.user],
                "start": "2026-01-01T00:00:00Z",
                "end": "2026-01-02T00:00:00Z"
            })
            .to_string(),
        )
        .await;
        assert_eq!(status, 403, "free-busy: {}", String::from_utf8_lossy(&bytes));
        assert_eq!(
            String::from_utf8_lossy(&bytes),
            "{\"error\":\"no primary mailbox for caller\"}\n"
        );

        let (status, _, bytes) = invoke(
            &calendar,
            "POST",
            "/api/calendar/subscriptions",
            Some(&bearer),
            "{\"url\":\"https://example.com/cal.ics\",\"name\":\"Test\"}",
        )
        .await;
        assert_eq!(status, 404, "subscriptions: {}", String::from_utf8_lossy(&bytes));
        assert!(String::from_utf8_lossy(&bytes).contains("mailbox not found"));

        let rules = RulesRoute {
            exec: exec.clone(),
            worker: worker.clone(),
            keys: keys(),
            issuer: ISSUER.into(),
        };
        let (status, _, bytes) = invoke(
            &rules,
            "POST",
            "/api/settings/rules",
            Some(&bearer),
            "{\"name\":\"r\",\"conditions\":[{\"field\":\"subject\",\"op\":\"contains\",\"value\":\"x\"}],\"actions\":[{\"type\":\"mark_read\"}]}",
        )
        .await;
        assert_eq!(status, 500, "rules create: {}", String::from_utf8_lossy(&bytes));
        assert!(String::from_utf8_lossy(&bytes).contains("mailbox not found"));

        let (status, _, bytes) = invoke(
            &rules,
            "POST",
            "/api/settings/rules/1/apply",
            Some(&bearer),
            "{\"window\":\"90d\"}",
        )
        .await;
        assert_eq!(status, 500, "rules apply: {}", String::from_utf8_lossy(&bytes));
        assert!(String::from_utf8_lossy(&bytes).contains("mailbox not found"));
        assert!(String::from_utf8_lossy(&bytes).contains("https://setjoin.com/errors/internal-error"));

        Ok::<(), BoxError>(())
    })
    .catch_unwind()
    .await;

    for row in saved_toggles {
        let _ = owner
            .execute(
                "UPDATE feature_toggles SET enabled = $2 WHERE key = $1",
                &[&row.get::<_, String>(0), &row.get::<_, bool>(1)],
            )
            .await;
    }
    let _ = owner
        .execute(
            "DELETE FROM message_attachments WHERE message_id = $1 AND blob_sha256 = $2",
            &[&delegator.inbox_only, &blob_sha],
        )
        .await;
    let _ = owner
        .execute("DELETE FROM mailbox_delegates WHERE user_id = $1", &[&nomb])
        .await;
    let _ = owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; \
             DELETE FROM blob_uploads WHERE user_id={nomb}; \
             DELETE FROM users WHERE id={nomb}; \
             DELETE FROM domains WHERE id={domain}; COMMIT;"
        ))
        .await;
    let _ = fixture::remove(&owner, &delegator).await;
    let _ = fixture::remove(&owner, &stranger).await;
    match outcome {
        Ok(res) => res,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Required Test 4 + 5: Drive `b.rs` guest defense-in-depth WITHOUT `SessionAdmission`
/// (`GET /api/drive/versions/{id}/content` -> 200; `HEAD .../content`, `GET /api/drive/audit-actions`,
/// `GET /api/drive/export/{token}` -> 404), PLUS guest + malformed `act <= 0` -> 401 on
/// `Scope::User` and `Scope::DriveUser`.
#[tokio::test]
async fn drive_b_guest_defense_in_depth_and_malformed_act() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("final359-drive-b-guest") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let host_owner = fixture::account(&owner, "final359-drive-owner").await?;
    let guest = create_active_guest(&owner, host_owner.domain, "final359-drive").await?;

    let toggle_keys = ["feature.drive", "feature.guest_accounts"];
    let saved_toggles = owner
        .query(
            "SELECT key, enabled FROM feature_toggles WHERE key = ANY($1)",
            &[&toggle_keys.as_slice()],
        )
        .await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled = true WHERE key = ANY($1)",
            &[&toggle_keys.as_slice()],
        )
        .await?;
    let profile_id: i64 = owner
        .query_one(
            "INSERT INTO guest_profiles(host_domain_id,name,allow_download,apps) \
             VALUES($1,$2,true,ARRAY['drive']::text[]) RETURNING id",
            &[&host_owner.domain, &format!("final359-dl-{guest}")],
        )
        .await?
        .get(0);
    owner
        .execute(
            "UPDATE guest_accounts SET profile_id = $1 WHERE user_id = $2",
            &[&profile_id, &guest],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO user_app_entitlements(user_id,app,enabled) VALUES($1,'drive',true) \
             ON CONFLICT (user_id,app) DO UPDATE SET enabled = true",
            &[&guest],
        )
        .await?;

    let space: i64 = owner
        .query_one(
            "SELECT drive_space_create($1,'GuestDepth','regular')",
            &[&host_owner.user],
        )
        .await?
        .get(0);
    let node: i64 = owner
        .query_one(
            "SELECT drive_node_create($1,$2,NULL,'file','readme.txt')",
            &[&host_owner.user, &space],
        )
        .await?
        .get(0);
    let chunk_bytes = Bytes::from_static(b"0123456789");
    let chunk_sha = format!("{:x}", Sha256::digest(&chunk_bytes));
    let chunk_key: String = owner
        .query_one(
            "SELECT drive_chunk_register($1,$2,$3,$4)::text",
            &[
                &host_owner.user,
                &space,
                &chunk_sha,
                &(chunk_bytes.len() as i32),
            ],
        )
        .await?
        .get(0);
    let chunk_key = serde_json::from_str::<Value>(&chunk_key)
        .ok()
        .and_then(|v| v["storageKey"].as_str().map(str::to_owned))
        .unwrap_or_else(|| {
            format!(
                "drive/chunks/{}/{}/{}",
                &chunk_sha[..2],
                &chunk_sha[2..4],
                chunk_sha
            )
        });
    let manifest = json!([{"sha256": chunk_sha, "size": chunk_bytes.len()}]).to_string();
    let ver_raw: String = owner
        .query_one(
            "SELECT drive_file_put_version($1,$2,$3,$4,'text/plain',NULL,$5::text::jsonb,'v1','test')::text",
            &[
                &host_owner.user,
                &node,
                &chunk_sha,
                &(chunk_bytes.len() as i64),
                &manifest,
            ],
        )
        .await?
        .get(0);
    let version = serde_json::from_str::<Value>(&ver_raw)?["versionId"]
        .as_i64()
        .ok_or("versionId")?;
    owner
        .execute(
            "INSERT INTO drive_space_members(space_id,user_id,role,granted_by) VALUES($1,$2,'viewer',$3)",
            &[&space, &guest, &host_owner.user],
        )
        .await?;

    let stored_key: String = owner
        .query_one(
            "SELECT storage_key FROM drive_chunks WHERE sha256 = $1 LIMIT 1",
            &[&chunk_sha],
        )
        .await
        .ok()
        .map(|r| r.get(0))
        .unwrap_or(chunk_key);
    let (s3_addr, s3_objects) = fake_s3().await;
    s3_objects
        .lock()
        .unwrap()
        .insert(stored_key.clone(), chunk_bytes.clone());
    s3_objects
        .lock()
        .unwrap()
        .insert(chunk_sha.clone(), chunk_bytes.clone());

    let outcome = std::panic::AssertUnwindSafe(async {
        let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?;
        let worker = common::patient_exec(&db.dsn, 4)?;
        let store = Arc::new(S3Store::new(
            &format!("http://{s3_addr}"),
            "mailblobs",
            "test-access",
            "test-secret",
        )?);
        let drive = DriveRoute {
            exec: exec.clone(),
            worker: worker.clone(),
            store: Some(store),
            keys: keys(),
            issuer: ISSUER.into(),
        };
        let jmap = JmapRoute(Arc::new(JmapCommands {
            services: Some(Arc::new(JmapServices::new(
                worker.clone(),
                "mail.test".into(),
                10 << 20,
            ))),
            exec: exec.clone(),
            worker: Some(worker),
            keys: keys(),
            issuer: ISSUER.into(),
            denylist: None,
        }));
        let guest_bearer = format!("Bearer {}", token(guest, json!({"acct": "guest"})));

        // Defense-in-depth WITHOUT SessionAdmission:
        // GET /api/drive/versions/{id}/content -> 200 for guest
        let content_path = format!("/api/drive/versions/{version}/content");
        let (status, _, bytes) =
            invoke(&drive, "GET", &content_path, Some(&guest_bearer), "").await;
        assert_eq!(
            status,
            200,
            "guest GET content must succeed: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert_eq!(bytes, chunk_bytes);

        // HEAD /api/drive/versions/{id}/content -> 404 (Scope::Drive refuses guest)
        let (status, _, bytes) =
            invoke(&drive, "HEAD", &content_path, Some(&guest_bearer), "").await;
        assert_eq!(status, 404, "guest HEAD content must be refused as 404");
        assert_eq!(bytes.as_ref(), b"404 page not found\n");

        // GET /api/drive/audit-actions -> 404 (Scope::Drive refuses guest)
        let (status, _, bytes) = invoke(
            &drive,
            "GET",
            "/api/drive/audit-actions",
            Some(&guest_bearer),
            "",
        )
        .await;
        assert_eq!(status, 404, "guest audit-actions must be refused as 404");
        assert_eq!(bytes.as_ref(), b"404 page not found\n");

        // GET /api/drive/export/{token} -> 404 (Scope::Drive refuses guest)
        let (status, _, bytes) = invoke(
            &drive,
            "GET",
            "/api/drive/export/some-token",
            Some(&guest_bearer),
            "",
        )
        .await;
        assert_eq!(status, 404, "guest export must be refused as 404");
        assert_eq!(bytes.as_ref(), b"404 page not found\n");

        // Required Test 5: Guest + malformed act <= 0 -> 401 (InvalidToken) on Scope::User & Scope::DriveUser
        for bad_act in [json!(0), json!(-1), json!("admin")] {
            let bad_bearer = format!(
                "Bearer {}",
                token(guest, json!({"acct": "guest", "act": bad_act}))
            );
            let (status, headers, _) =
                invoke(&jmap, "GET", "/.well-known/jmap", Some(&bad_bearer), "").await;
            assert_eq!(status, 401, "Scope::User guest act={bad_act} must be 401");
            assert_eq!(
                headers
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok()),
                Some("Negotiate, Bearer realm=\"mailserver\"")
            );
            let (status, headers, _) =
                invoke(&drive, "GET", &content_path, Some(&bad_bearer), "").await;
            assert_eq!(
                status, 401,
                "Scope::DriveUser guest act={bad_act} must be 401"
            );
            assert_eq!(
                headers
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok()),
                Some("Negotiate, Bearer realm=\"mailserver\"")
            );
        }

        Ok::<(), BoxError>(())
    })
    .catch_unwind()
    .await;

    for row in saved_toggles {
        let _ = owner
            .execute(
                "UPDATE feature_toggles SET enabled = $2 WHERE key = $1",
                &[&row.get::<_, String>(0), &row.get::<_, bool>(1)],
            )
            .await;
    }
    let _ = owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; \
             DELETE FROM drive_audit_log WHERE space_id={space}; \
             DELETE FROM drive_space_members WHERE space_id={space}; \
             DELETE FROM drive_nodes WHERE space_id={space}; \
             DELETE FROM drive_spaces WHERE id={space}; \
             DELETE FROM user_app_entitlements WHERE user_id={guest}; \
             DELETE FROM guest_accounts WHERE user_id={guest}; \
             DELETE FROM guest_profiles WHERE id={profile_id}; \
             DELETE FROM users WHERE id={guest}; COMMIT;"
        ))
        .await;
    let _ = fixture::remove(&owner, &host_owner).await;
    match outcome {
        Ok(res) => res,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Required Test 7 (Part A): Impersonation `act > 0`, `mailbox_blocked` JMAP 403 (`about:blank`)
/// + non-JMAP 200, and `AlternativeCredential` non-DAV challenged 401.
#[tokio::test]
async fn impersonation_suspended_and_alternative_credential_native_answers() -> Result<(), BoxError>
{
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("final359-native-refusals") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let member = fixture::account(&owner, "final359-member").await?;
    let suspended = fixture::account(&owner, "final359-suspended").await?;
    owner
        .execute(
            "UPDATE mailboxes SET enabled = false WHERE id = $1",
            &[&suspended.mailbox],
        )
        .await?;
    owner
        .execute(
            "UPDATE mailbox_lifecycle SET access_state = 'suspended' WHERE mailbox_id = $1",
            &[&suspended.mailbox],
        )
        .await?;

    let outcome = std::panic::AssertUnwindSafe(async {
        let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?;
        let worker = common::patient_exec(&db.dsn, 4)?;
        let jmap = JmapRoute(Arc::new(JmapCommands {
            services: Some(Arc::new(JmapServices::new(
                worker.clone(),
                "mail.test".into(),
                10 << 20,
            ))),
            exec: exec.clone(),
            worker: Some(worker.clone()),
            keys: keys(),
            issuer: ISSUER.into(),
            denylist: None,
        }));
        let rules = RulesRoute {
            exec: exec.clone(),
            worker: worker.clone(),
            keys: keys(),
            issuer: ISSUER.into(),
        };

        // 1. Positive `act` impersonation JWT is admitted natively like Go.
        let imp_bearer = format!("Bearer {}", token(member.user, json!({"act": 42})));
        let (status, _, bytes) =
            invoke(&jmap, "GET", "/.well-known/jmap", Some(&imp_bearer), "").await;
        assert_eq!(status, 200, "impersonation /.well-known/jmap: {}", String::from_utf8_lossy(&bytes));
        let (status, _, bytes) = invoke(
            &jmap,
            "POST",
            "/jmap",
            Some(&imp_bearer),
            r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{"ok":true},"c0"]]}"#,
        )
        .await;
        assert_eq!(status, 200, "impersonation /jmap: {}", String::from_utf8_lossy(&bytes));

        // 2. Suspended mailbox (`mailbox_blocked`):
        //    - GET /.well-known/jmap -> 403 about:blank "mailbox access is suspended"
        //    - POST /jmap Mailbox/get -> 200 with per-call JMAP forbidden
        //    - Non-JMAP route GET /api/settings/rules-list -> 200!
        let susp_bearer = format!("Bearer {}", token(suspended.user, json!({})));
        let (status, headers, bytes) =
            invoke(&jmap, "GET", "/.well-known/jmap", Some(&susp_bearer), "").await;
        assert_eq!(status, 403, "suspended /.well-known/jmap: {}", String::from_utf8_lossy(&bytes));
        assert_eq!(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/problem+json")
        );
        let body: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(body["type"], json!("about:blank"));
        assert_eq!(body["detail"], json!("mailbox access is suspended"));

        let (status, _, bytes) = invoke(
            &jmap,
            "POST",
            "/jmap",
            Some(&susp_bearer),
            json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
                "methodCalls": [["Mailbox/get", {"accountId": suspended.mailbox.to_string()}, "c0"]]
            })
            .to_string(),
        )
        .await;
        assert_eq!(status, 200);
        let resp: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(resp["methodResponses"][0][0], json!("error"));
        assert_eq!(
            resp["methodResponses"][0][1]["type"],
            json!("urn:ietf:params:jmap:error:forbidden")
        );
        assert_eq!(
            resp["methodResponses"][0][1]["detail"],
            json!("mailbox access is suspended or detached")
        );

        let (status, _, bytes) =
            invoke(&rules, "GET", "/api/settings/rules-list", Some(&susp_bearer), "").await;
        assert_eq!(
            status,
            200,
            "suspended mailbox must stay admitted on non-JMAP REST routes: {}",
            String::from_utf8_lossy(&bytes)
        );

        // 3. AlternativeCredential on non-DAV REST routes -> 401 with WWW-Authenticate challenge
        for alt in ["Basic Zm9vOmJhcg==", "Negotiate YII="] {
            let (status, headers, bytes) =
                invoke(&rules, "GET", "/api/settings/rules-list", Some(alt), "").await;
            assert_eq!(status, 401, "{alt} on rules-list: {}", String::from_utf8_lossy(&bytes));
            assert_eq!(
                headers.get("www-authenticate").and_then(|v| v.to_str().ok()),
                Some("Negotiate, Bearer realm=\"mailserver\"")
            );
            let (status, headers, _) =
                invoke(&jmap, "GET", "/.well-known/jmap", Some(alt), "").await;
            assert_eq!(status, 401, "{alt} on /.well-known/jmap");
            assert_eq!(
                headers.get("www-authenticate").and_then(|v| v.to_str().ok()),
                Some("Negotiate, Bearer realm=\"mailserver\"")
            );
        }

        Ok::<(), BoxError>(())
    })
    .catch_unwind()
    .await;

    let _ = owner
        .execute(
            "UPDATE mailboxes SET enabled = true WHERE id = $1",
            &[&suspended.mailbox],
        )
        .await;
    let _ = owner
        .execute(
            "UPDATE mailbox_lifecycle SET access_state = 'active' WHERE mailbox_id = $1",
            &[&suspended.mailbox],
        )
        .await;
    let _ = fixture::remove(&owner, &member).await;
    let _ = fixture::remove(&owner, &suspended).await;
    match outcome {
        Ok(res) => res,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
