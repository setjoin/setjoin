//! F01 slice `user-lifecycle`: a create, update or delete that Go would deliver to a
//! webhook subscription after the commit is delivered by Rust's shared dispatcher
//! (Platform webhooks, #302): organization subscriptions and the subject's own self
//! subscription receive one signed CloudEvent. With the outbox on (the reducer enrolled
//! the publication), no matching subscription, an inactive one, or another user's self
//! subscription, nothing is sent.
mod common;
use common::{body_bytes, full, send, BoxError};
use hyper::{Request, Response};
use serde_json::json;
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    admin_users_lifecycle::AdminUsersLifecycleRoute, Config, Gateway, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::{Arc, Mutex};

const ROLE: i64 = 950101;

async fn token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// `(path, signature header, body)` of every request the fake receiver saw.
type Seen = Arc<Mutex<Vec<(String, String, String)>>>;

async fn receiver(seen: Seen) -> std::net::SocketAddr {
    use http_body_util::BodyExt;
    common::fake_upstream(move |request| {
        let seen = seen.clone();
        async move {
            let path = request.uri().path().to_owned();
            let signature = request
                .headers()
                .get("x-webhook-signature")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let content_type = request
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            assert_eq!(content_type, "application/json");
            let body = request.into_body().collect().await.unwrap().to_bytes();
            seen.lock()
                .unwrap()
                .push((path, signature, String::from_utf8(body.to_vec()).unwrap()));
            Response::builder().status(200).body(full("ok")).unwrap()
        }
    })
    .await
}

/// The v1 signature: HMAC-SHA256 of "<t>.<body>" under the subscription secret.
fn signature_ok(header: &str, body: &str) -> bool {
    use hmac::{Hmac, Mac};
    let Some(rest) = header.strip_prefix("v1,t=") else {
        return false;
    };
    let Some((t, sig)) = rest.split_once(",sig=") else {
        return false;
    };
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(format!("{t}.{body}").as_bytes());
    let expected: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    expected == sig
}

#[tokio::test]
async fn lifecycle_events_are_delivered_by_rust_to_matching_subscriptions() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("admin6-delivery") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "admin6-dlv-admin").await?;
    let peer = fixture::account(&owner, "admin6-dlv-peer").await?;
    let domain: String = owner
        .query_one("SELECT name FROM domains WHERE id=$1", &[&a.domain])
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_groups(id,name,permissions) OVERRIDING SYSTEM VALUE VALUES($1,'admin6-dlv-role','{users.create,users.suspend,users.delete}')",
            &[&ROLE],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) VALUES($1,$2,$1,false)",
            &[&a.user, &ROLE],
        )
        .await?;
    let outbox_before: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.webhook_publication_outbox'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    let seen: Seen = Arc::default();
    let hook = receiver(seen.clone()).await;
    let subscribe = |path: &'static str, event: &'static str, scope: &'static str, user: Option<i64>, active: bool| {
        let owner = &owner;
        let url = format!("http://{hook}{path}");
        async move {
            owner
                .execute(
                    "INSERT INTO webhook_subscriptions(url,secret,event_types,scope,is_active,user_id) VALUES($1,$2,jsonb_build_array($3::text),$4,$5,$6)",
                    &[&url, &SECRET, &event, &scope, &active, &user],
                )
                .await
        }
    };
    let result = async {
        subscribe("/created-org", "user.created", "organization", None, true).await?;
        subscribe("/updated-org", "user.updated", "organization", None, true).await?;
        subscribe("/updated-peer", "user.updated", "self", Some(peer.user), true).await?;
        subscribe("/updated-admin", "user.updated", "self", Some(a.user), true).await?;
        subscribe("/updated-inactive", "user.updated", "organization", None, false).await?;
        subscribe("/deleted-org", "user.deleted", "organization", None, true).await?;
        let patient = std::time::Duration::from_secs(30);
        let mk = |dsn: &str| -> Result<ScopedExecutor, BoxError> {
            Ok(ScopedExecutor::from_dsn_with(
                dsn,
                4,
                setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient },
            )
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new()))
        };
        let dispatcher = setjoin_gateway::webhook::Dispatcher::unguarded_for_tests(
            setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?,
            Some(setjoin_platform::webhook_secret::SecretCodec::new(
                b"gofree-delivery-master",
                setjoin_config_secret::CryptoProfile::Standard,
            )),
        );
        let route = AdminUsersLifecycleRoute {
            exec: mk(db.app.as_deref().unwrap_or(&db.dsn))?,
            worker: mk(&db.dsn)?,
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            authserver_url: String::new(),
            internal_key: String::new(),
            dispatcher: dispatcher.clone(),
        };
        let go_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = go_calls.clone();
        let go = common::fake_upstream(move |_| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Response::builder().status(218).body(full("go")).unwrap()
            }
        })
        .await;
        let mut inventory: serde_json::Value =
            serde_json::from_str(include_str!("../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F01" && r["slice"] == "user-lifecycle" {
                r["state"] = json!("ON");
                r["upstream"] = json!("local-rust");
                r["oracle_commands"] = json!([""]);
            }
        }
        let gateway = Gateway::new(
            Config {
                upstream: Some(format!("http://{go}").parse()?),
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            RouteTable::proxy_all().with(route),
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let bearer = token(a.user).await;
        let call = |method: &'static str, path: String, body: String| {
            let bearer = bearer.clone();
            async move {
                let request = Request::builder()
                    .method(method)
                    .uri(format!("/api{path}"))
                    .header("host", "mail.test")
                    .header("origin", "http://mail.test")
                    .header("content-type", "application/json")
                    .header("x-request-id", "gofree-admin6-delivery")
                    .header("authorization", format!("Bearer {bearer}"));
                let response = send(address, request.body(full(body)).unwrap()).await;
                let status = response.status().as_u16();
                let _ = body_bytes(response).await;
                status
            }
        };
        let taken = |seen: &Seen| std::mem::take(&mut *seen.lock().unwrap());

        // Create: the organization subscription of user.created, nothing else.
        let email = format!("admin6-dlv-new@{domain}");
        let status = call(
            "POST",
            "/admin/users".into(),
            json!({"email": email, "password": "Str0ng!Passw0rd-xyz-91"}).to_string(),
        )
        .await;
        assert_eq!(status, 201, "create");
        dispatcher.quiesce().await;
        let created = taken(&seen);
        assert_eq!(created.len(), 1, "{created:?}");
        assert_eq!(created[0].0, "/created-org");
        assert!(signature_ok(&created[0].1, &created[0].2), "signature");
        let event: serde_json::Value = serde_json::from_str(&created[0].2)?;
        assert_eq!(event["type"], "user.created");
        assert_eq!(event["source"], "mailserver/auth");
        assert_eq!(event["data"]["email"], email.as_str());
        assert_eq!(event["data"]["created_by"].as_str().map(str::len) > Some(0), true);
        assert!(event["data"]["user_id"].as_i64().is_some_and(|n| n > 0));
        assert!(event["id"].as_str().is_some_and(|id| id.len() == 17 && id.starts_with("evt_")));

        // Update: the organization subscription and the subject's own, not the admin's
        // self subscription and not the inactive one.
        let status = call(
            "PUT",
            format!("/admin/users/{}", peer.user),
            json!({"displayName": "Peer Renamed"}).to_string(),
        )
        .await;
        assert_eq!(status, 204, "update");
        dispatcher.quiesce().await;
        let mut paths: Vec<String> = taken(&seen).into_iter().map(|r| r.0).collect();
        paths.sort();
        assert_eq!(paths, ["/updated-org", "/updated-peer"]);

        // Outbox on: the reducer enrolls the publication; this process sends nothing.
        owner
            .execute(
                "INSERT INTO feature_toggles(key,enabled) VALUES('feature.webhook_publication_outbox',true) ON CONFLICT(key) DO UPDATE SET enabled=true",
                &[],
            )
            .await?;
        let status = call(
            "PUT",
            format!("/admin/users/{}", peer.user),
            json!({"displayName": "Peer Again"}).to_string(),
        )
        .await;
        assert_eq!(status, 204, "update with the outbox on");
        dispatcher.quiesce().await;
        assert!(taken(&seen).is_empty(), "outbox on: no direct delivery");
        let queued: i64 = owner
            .query_one("SELECT count(*) FROM webhook_publications WHERE subject_user_id=$1 AND event_type='user.updated'", &[&peer.user])
            .await?
            .get(0);
        assert_eq!(queued, 1, "the publication is durable");
        owner
            .execute("DELETE FROM webhook_publications WHERE subject_user_id=$1", &[&peer.user])
            .await?;
        owner
            .execute("UPDATE feature_toggles SET enabled=false WHERE key='feature.webhook_publication_outbox'", &[])
            .await?;

        // Delete.
        let status = call("DELETE", format!("/admin/users/{}", peer.user), String::new()).await;
        assert_eq!(status, 204, "delete");
        dispatcher.quiesce().await;
        let deleted = taken(&seen);
        assert_eq!(deleted.len(), 1, "{deleted:?}");
        assert_eq!(deleted[0].0, "/deleted-org");
        let event: serde_json::Value = serde_json::from_str(&deleted[0].2)?;
        assert_eq!(event["data"], json!({"user_id": peer.user}));
        assert_eq!(go_calls.load(std::sync::atomic::Ordering::SeqCst), 0, "Go is never involved");

        // The legacy log row of one delivery: attempt 1, success, the receiver's answer.
        let row = owner
            .query_one(
                "SELECT status,attempt,response_code,response_body FROM webhook_deliveries d JOIN webhook_subscriptions s ON s.id=d.subscription_id WHERE s.url LIKE '%/deleted-org' ORDER BY d.id DESC LIMIT 1",
                &[],
            )
            .await?;
        assert_eq!(
            (row.get::<_, String>(0), row.get::<_, i32>(1), row.get::<_, i32>(2), row.get::<_, String>(3)),
            ("success".to_string(), 1, 200, "ok".to_string())
        );
        server.abort();
        dispatcher.shutdown().await;
        Ok::<_, BoxError>(())
    }
    .await;
    owner
        .execute("DELETE FROM webhook_subscriptions WHERE url LIKE $1", &[&format!("http://{hook}/%")])
        .await?;
    owner
        .execute("DELETE FROM webhook_publications WHERE subject_user_id IN ($1,$2)", &[&a.user, &peer.user])
        .await?;
    match outbox_before {
        Some(value) => owner.execute("UPDATE feature_toggles SET enabled=$1 WHERE key='feature.webhook_publication_outbox'", &[&value]).await?,
        None => owner.execute("DELETE FROM feature_toggles WHERE key='feature.webhook_publication_outbox'", &[]).await?,
    };
    owner.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE role_group_id=$1", &[&ROLE]).await?;
    owner
        .execute("DELETE FROM admin_role_assignments WHERE role_group_id=$1", &[&ROLE])
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&ROLE])
        .await?;
    // The account the create route made: remove everything it left, FK-safe.
    owner
        .batch_execute(
            "DELETE FROM login_events WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'admin6-dlv-new@%');
             DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'admin6-dlv-new@%');
             BEGIN; SET LOCAL session_replication_role=replica;
             DELETE FROM mailbox_audit_log WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'admin6-dlv-new@%');
             COMMIT;
             DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'admin6-dlv-new@%');
             DO $$ DECLARE r record; BEGIN FOR r IN SELECT id FROM users WHERE email LIKE 'admin6-dlv-new@%' LOOP
               DELETE FROM mailboxes WHERE user_id=r.id; DELETE FROM users WHERE id=r.id; END LOOP; END $$;",
        )
        .await?;
    for account in [&a, &peer] {
        common::remove_blob_account(&owner, account).await?;
    }
    result
}
