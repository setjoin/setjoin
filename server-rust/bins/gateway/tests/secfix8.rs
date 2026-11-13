//! Owner-approved security fixes of 2026-11-06 (#529 admin-scope residuals, #531 follow-ups of
//! #512). Each test states the secure behaviour at the real seam; the mutants (feature
//! `oracle-mutants`, `SETJOIN_SECFIX3_MUTANT`, scripts/test-secfix8-mutants.py) restore frozen
//! Go's behaviour and must make these tests fail.
mod common;
use common::BoxError;
use serde_json::json;
use setjoin_conformance::{fixture, harness::Db};
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use tokio_postgres::Client;

fn op() -> [u8; 16] {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&nanos.to_be_bytes());
    out[8..].copy_from_slice(&NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst).to_be_bytes());
    out
}

async fn actor(exec: &ScopedExecutor, user: i64) -> Result<setjoin_authz::Authorized, BoxError> {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", "mail.test".parse()?);
    headers.insert("origin", "http://mail.test".parse()?);
    let token = common::recovery_token_with(user, json!({"admin": true}));
    headers.insert("authorization", format!("Bearer {token}").parse()?);
    Ok(
        setjoin_authz::authorize_request(exec, &common::recovery_keys(), "mailserver", &headers, "http")
            .await
            .ok_or("verified actor")?,
    )
}

async fn grant(owner: &Client, user: i64, perms: &[&str], domain: Option<i64>) -> Result<(), BoxError> {
    let name = format!("secfix8-{user}-{}-{}", perms.join("+"), domain.unwrap_or(0));
    let perms: Vec<String> = perms.iter().map(|p| p.to_string()).collect();
    let role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3) RETURNING id",
            &[&name, &perms, &domain],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&user, &role],
        )
        .await?;
    Ok(())
}

async fn cleanup(owner: &Client) -> Result<(), BoxError> {
    owner.batch_execute(
        "BEGIN; SET LOCAL session_replication_role=replica; \
         DELETE FROM admin_role_assignments WHERE role_group_id IN (SELECT id FROM admin_role_groups WHERE name LIKE 'secfix8-%'); \
         DELETE FROM admin_role_groups WHERE name LIKE 'secfix8-%'; \
         DELETE FROM field_policy WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix8-%'); \
         DELETE FROM m365_consent_states WHERE actor_user_id IN (SELECT id FROM users WHERE email LIKE 'secfix8-%'); \
         CREATE TEMP TABLE secfix8_domains ON COMMIT DROP AS SELECT DISTINCT domain_id FROM users WHERE email LIKE 'secfix8-%'; \
         DELETE FROM mailbox_audit_log WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix8-%'); \
         DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix8-%'); \
         DELETE FROM message_trace WHERE details->>'mailbox_id' IN (SELECT id::text FROM mailboxes WHERE email LIKE 'secfix8-%'); \
         DELETE FROM meetings WHERE title='secfix8-meeting'; \
         DELETE FROM message_tags WHERE tag_id IN (SELECT id FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix8-%')); \
         DELETE FROM imap_membership_uid_ledger WHERE tag_id IN (SELECT id FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix8-%')); \
         DELETE FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix8-%'); \
         DELETE FROM folders WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix8-%'); \
         DELETE FROM jmap_changes_journal WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix8-%'); \
         DELETE FROM jmap_entity_state WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix8-%'); \
         DELETE FROM mailbox_address_claims WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix8-%'); \
         DELETE FROM mailbox_lifecycle WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix8-%') OR bound_user_id IN (SELECT id FROM users WHERE email LIKE 'secfix8-%'); \
         DELETE FROM sender_control_state WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix8-%'); \
         DELETE FROM user_lifecycle_authorities WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix8-%'); \
         DELETE FROM mailboxes WHERE email LIKE 'secfix8-%'; \
         DELETE FROM users WHERE email LIKE 'secfix8-%'; \
         DELETE FROM domains WHERE id IN (SELECT domain_id FROM secfix8_domains); \
         COMMIT;",
    )
    .await?;
    Ok(())
}

struct World {
    owner: Client,
    exec: ScopedExecutor,
    a: fixture::Account,
    b: fixture::Account,
    scoped: fixture::Account,
    global: fixture::Account,
}

async fn world(case: &str) -> Result<Option<World>, BoxError> {
    let Some(db) = Db::for_case(case) else { return Ok(None) };
    let owner = db.connect().await?;
    cleanup(&owner).await?;
    let a = fixture::account(&owner, "secfix8-a").await?;
    let b = fixture::account(&owner, "secfix8-b").await?;
    let scoped = fixture::account(&owner, "secfix8-scoped").await?;
    let global = fixture::account(&owner, "secfix8-global").await?;
    let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?
        .with_audit_keys("22".repeat(32), String::new());
    Ok(Some(World { owner, exec, a, b, scoped, global }))
}
impl World {
    async fn finish(self) -> Result<(), BoxError> {
        cleanup(&self.owner).await?;
        for account in [&self.a, &self.b, &self.scoped, &self.global] {
            fixture::remove(&self.owner, account).await?;
        }
        Ok(())
    }
}

/// #529: the session-revoke reach check follows the route's permission. The caller holds
/// `access.policy_write` over domain A only and an unrelated `users.read` over domain B; the
/// any-grant reach let the unrelated grant extend the revoke to B's users.
/// The cases share one database, fixed fixtures and reducers: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn session_revoke_reach_uses_the_route_permission() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix8-revoke").await? else { return Ok(()) };
    let result = async {
        grant(&w.owner, w.scoped.user, &["access.policy_write"], Some(w.a.domain)).await?;
        grant(&w.owner, w.scoped.user, &["users.read"], Some(w.b.domain)).await?;
        grant(&w.owner, w.global.user, &["access.policy_write"], None).await?;
        let reach = |who: &fixture::Account, target: i64| {
            let exec = w.exec.clone();
            let who = who.user;
            async move {
                let auth = actor(&exec, who).await?;
                setjoin_conditional_access::console::can_reach(&exec, auth.context().user_id(), target)
                    .await
                    .map_err(|e| BoxError::from(e.message))
            }
        };
        assert!(reach(&w.scoped, w.a.user).await?, "own-domain target refused");
        assert!(!reach(&w.scoped, w.b.user).await?, "an unrelated grant extended the session revoke to another domain");
        assert!(reach(&w.global, w.a.user).await? && reach(&w.global, w.b.user).await?, "org-wide admin refused");
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}

/// #529: the AD field-policy read and write follow the route permission (Auth-console read
/// list / `identity.write`), not any grant over the target's domain.
#[tokio::test]
async fn field_policy_reach_uses_the_route_permission() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix8-field-policy").await? else { return Ok(()) };
    let result = async {
        // users.read over A (read list) + identity.write over A; only an unrelated mam.read
        // over B (read) and users.read over B (not identity.write: the write).
        grant(&w.owner, w.scoped.user, &["identity.write"], Some(w.a.domain)).await?;
        grant(&w.owner, w.scoped.user, &["users.read"], Some(w.b.domain)).await?;
        let reader = w.global.user;
        grant(&w.owner, reader, &["mam.read"], Some(w.b.domain)).await?;
        grant(&w.owner, reader, &["users.read"], Some(w.a.domain)).await?;
        for user in [w.a.user, w.b.user] {
            w.owner.execute("INSERT INTO field_policy(user_id,field,policy) VALUES($1,'title','local_only')", &[&user]).await?;
        }
        let scoped = actor(&w.exec, w.scoped.user).await?;
        let reading = actor(&w.exec, reader).await?;
        let read = |auth: &setjoin_authz::Authorized, user: i64| {
            let (exec, ctx) = (w.exec.clone(), auth.context().clone());
            async move { setjoin_directory_sync::field_policy(&exec, &ctx, user).await.map_err(|e| e.message) }
        };
        let reach = |auth: &setjoin_authz::Authorized, user: i64, perms: &'static [&'static str]| {
            let (exec, ctx) = (w.exec.clone(), auth.context().clone());
            async move { setjoin_directory_sync::reach_perm(&exec, &ctx, user, perms).await.map_err(|e| e.message) }
        };
        // Read: an unrelated mam.read grant over B does not open B's policies.
        assert!(!reach(&reading, w.b.user, &setjoin_directory_sync::AUTH_CONSOLE).await?, "unrelated grant reaches B for the read");
        assert_eq!(read(&reading, w.b.user).await?.trim(), "{}", "field policy of another domain read through an unrelated grant");
        assert!(read(&reading, w.a.user).await?.contains("local_only"), "own-domain policy hidden");
        // Write: users.read over B is not identity.write over B.
        assert!(reach(&scoped, w.a.user, &setjoin_directory_sync::IDENTITY_WRITE).await?, "own-domain write refused");
        assert!(!reach(&scoped, w.b.user, &setjoin_directory_sync::IDENTITY_WRITE).await?, "users.read extended the identity.write reach to B");
        let rows = |user: i64| {
            let owner = &w.owner;
            async move {
                Ok::<String, BoxError>(owner.query_one("SELECT policy FROM field_policy WHERE user_id=$1 AND field='title'", &[&user]).await?.get(0))
            }
        };
        let write = |user: i64| {
            let (exec, ctx) = (w.exec.clone(), scoped.context().clone());
            async move { setjoin_directory_sync::set_field_policy(&exec, &ctx, user, "title", "ad_managed", op()).await }
        };
        // `ad_managed` clears the row; the statement itself repeats the permission-aware reach.
        let foreign = write(w.b.user).await;
        assert!(matches!(foreign, CommandOutcome::Committed(0)), "write reached a foreign domain: {foreign:?}");
        assert_eq!(rows(w.b.user).await?, "local_only", "foreign policy was cleared");
        let own = write(w.a.user).await;
        assert!(matches!(own, CommandOutcome::Committed(1)), "own-domain write refused: {own:?}");
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}

/// #531 F2: M365 connect refuses (503) when the public host is unset, empty or `localhost`
/// instead of building a consent redirect to https://localhost.
#[tokio::test]
async fn m365_connect_needs_a_real_public_host() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use hyper::Request;
    use setjoin_gateway::{migration::MigrationRoute, Config, Gateway, RouteTable, TrustedProxies};
    let Some(w) = world("secfix8-m365").await? else { return Ok(()) };
    let result = async {
        grant(&w.owner, w.global.user, &["mail.pipeline"], None).await?;
        let mut statuses = Vec::new();
        for host in ["", "localhost", "LocalHost.", " localhost ", "mail.test"] {
            let route = MigrationRoute {
                exec: w.exec.clone(),
                keys: std::sync::Arc::new(common::recovery_keys()),
                issuer: "mailserver".into(),
                encryption_key: String::new(),
                public_host: host.into(),
                runner: None,
            };
            let mut inventory: serde_json::Value = serde_json::from_str(include_str!("../route-inventory.json"))?;
            for r in inventory["routes"].as_array_mut().ok_or("routes")? {
                if r["family"] == "F05" && r["slice"] == "migration" {
                    r["state"] = json!("ON");
                    r["upstream"] = json!("local-rust");
                    r["oracle_commands"] = json!([""]);
                }
            }
            let gateway = Gateway::new(
                Config {
                    upstream: None,
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
            let token = common::recovery_token_with(w.global.user, json!({"admin": true}));
            let request = Request::builder()
                .method("GET")
                .uri("/api/admin/migration/m365/connect")
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("authorization", format!("Bearer {token}"));
            let response = common::send(address, request.body(common::full(""))?).await;
            let status = response.status().as_u16();
            let location = response.headers().get("location").and_then(|v| v.to_str().ok()).map(str::to_owned);
            server.abort();
            statuses.push((host, status, location));
        }
        for (host, status, location) in &statuses[..4] {
            assert_eq!(*status, 503, "connect with HOSTNAME={host:?} must be refused, got {status} {location:?}");
            assert!(location.is_none());
        }
        // A real host passes the guard (the unsealed config is absent here, which is its own 400).
        assert_eq!(statuses[4].1, 400, "control: a configured host reaches the config check: {:?}", statuses[4]);
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}

/// #531 F3: the blob-cleanup worker refuses to run on a credential that row security filters.
#[tokio::test]
async fn blob_cleanup_refuses_a_credential_without_bypassrls() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use setjoin_gateway::{blob_cleanup::BlobCleanup, recovery_worker::S3Store};
    use setjoin_pg::workers::WorkerDatabase;
    use std::sync::Arc;
    let Some(db) = Db::for_case("secfix8-blob-cleanup") else { return Ok(()) };
    let store = |_: ()| {
        Arc::new(S3Store::new("http://127.0.0.1:1", "mailblobs", "test-access", "test-secret").unwrap())
    };
    let app = db.app.clone().ok_or("the app (non-BYPASSRLS) DSN is required")?;
    let filtered = BlobCleanup::new(WorkerDatabase::new(&app)?, store(()));
    assert!(!filtered.worker_bypasses_rls().await?, "the request-pool role must not count as BYPASSRLS");
    let returned = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        filtered.run_until(std::future::pending::<()>()),
    )
    .await;
    assert!(returned.is_ok(), "the worker kept running on a credential without BYPASSRLS");
    let privileged = BlobCleanup::new(WorkerDatabase::new(&db.dsn)?, store(()));
    assert!(privileged.worker_bypasses_rls().await?, "the worker credential has BYPASSRLS");
    let still = tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        privileged.run_until(std::future::pending::<()>()),
    )
    .await;
    assert!(still.is_err(), "the worker refused to run on a BYPASSRLS credential");
    Ok(())
}

/// #531 F1: an unrelated caller's meeting projection carries no chat-channel or calendar-event
/// id (like roomName and ownerUserId since #378); the owner still gets them.
#[tokio::test]
async fn meeting_projection_hides_channel_and_event_ids_from_unrelated_callers() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix8-meet").await? else { return Ok(()) };
    let result = async {
        // Dangling ids are fine here: the projection copies the columns, it never follows them.
        let id: i64 = {
            let tx = w.owner.query_one(
                "WITH r AS (SELECT set_config('session_replication_role','replica',true)) \
                 INSERT INTO meetings(title,owner_user_id,chat_channel_id,calendar_event_id) \
                 SELECT 'secfix8-meeting',$1,987654321,987654322 FROM r RETURNING id",
                &[&w.a.user],
            ).await?;
            tx.get(0)
        };
        let project = |user: i64| {
            let exec = w.exec.clone();
            async move {
                let auth = actor(&exec, user).await?;
                let text = setjoin_meet::get(&exec, auth.context(), id)
                    .await
                    .map_err(|e| BoxError::from(e.message))?;
                Ok::<serde_json::Value, BoxError>(serde_json::from_str(&text)?)
            }
        };
        let owner_view = project(w.a.user).await?;
        assert_eq!(owner_view["chatChannelId"], 987654321, "the owner lost the channel id");
        assert_eq!(owner_view["calendarEventId"], 987654322, "the owner lost the event id");
        let stranger = project(w.b.user).await?;
        assert!(stranger["chatChannelId"].is_null(), "unrelated caller got chatChannelId: {stranger}");
        assert!(stranger["calendarEventId"].is_null(), "unrelated caller got calendarEventId: {stranger}");
        assert!(stranger["roomName"].is_null() && stranger["ownerUserId"].is_null());
        assert_eq!(stranger["title"], "secfix8-meeting", "the pre-join facts stay visible");
        Ok::<_, BoxError>(())
    }
    .await;
    w.owner.execute("DELETE FROM meetings WHERE title='secfix8-meeting'", &[]).await?;
    w.finish().await?;
    result
}
