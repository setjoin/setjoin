//! Owner-approved security fixes of 2026-11-05 (#542): the deploy wizard and airgap upload
//! (#455 review). Each test drives the real Rust route (a gateway with the updates-deploy
//! adapter, a real SSH peer for the wizard) and states the secure behaviour. The mutants
//! (feature `oracle-mutants`, `SETJOIN_SECFIX3_MUTANT`, scripts/test-secfix11-mutants.py)
//! restore frozen Go's behaviour and must make these tests fail.
//! Airgap tests need `GOFREE_AIRGAP_FIXTURE_ROOT=/dev/shm` on the shared host.
mod common;
mod platform_oracle;
use common::BoxError;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    platform_updates::PlatformUpdatesRoute, Config, Gateway, RouteTable, TrustedProxies,
};
use std::{net::SocketAddr, sync::Arc};
use tokio_postgres::Client;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct World {
    db: Db,
    owner: Client,
    scoped: fixture::Account,
    org: fixture::Account,
    other: fixture::Account,
}

async fn world(case: &str) -> Result<Option<World>, BoxError> {
    let Some(db) = Db::for_case(case) else { return Ok(None) };
    let owner = db.connect().await?;
    purge(&owner).await?;
    let scoped = fixture::account(&owner, "secfix11-scoped").await?;
    let org = fixture::account(&owner, "secfix11-org").await?;
    let other = fixture::account(&owner, "secfix11-other").await?;
    for (user, domain, name) in [(scoped.user, Some(other.domain), "scoped"), (org.user, None, "org")] {
        let role = format!("secfix11-{name}");
        owner
            .execute(
                "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3)",
                &[&role, &vec!["system.upgrade".to_owned()], &domain],
            )
            .await?;
        owner.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) SELECT $1,id,$1,false FROM admin_role_groups WHERE name=$2", &[&user, &role]).await?;
    }
    Ok(Some(World { db, owner, scoped, org, other }))
}

async fn purge(owner: &Client) -> Result<(), BoxError> {
    owner.batch_execute(
        "DELETE FROM deploy_remote_fence; \
         DELETE FROM deployment_steps WHERE step_name IN('ssh_check','install_packages','configure_replication','configure_pgpool','configure_seaweedfs','start_services','verify'); \
         DELETE FROM admin_role_assignments WHERE role_group_id IN (SELECT id FROM admin_role_groups WHERE name LIKE 'secfix11-%'); \
         DELETE FROM admin_role_groups WHERE name LIKE 'secfix11-%'",
    )
    .await?;
    Ok(())
}

impl World {
    async fn finish(self) -> Result<(), BoxError> {
        purge(&self.owner).await?;
        for account in [&self.scoped, &self.org, &self.other] {
            fixture::remove(&self.owner, account).await?;
        }
        Ok(())
    }
    fn bearer(&self, account: &fixture::Account) -> String {
        common::recovery_token_with(account.user, json!({"admin": true}))
    }
}

/// A gateway serving the updates-deploy adapter over the database (a fresh wizard each call,
/// as a gateway restart builds one).
async fn serve(
    world: &World,
    peer: Option<&platform_oracle::deploy::Peer>,
    airgap: Option<&platform_oracle::airgap::Fixture>,
) -> Result<SocketAddr, BoxError> {
    let exec = common::patient_exec(world.db.app.as_deref().unwrap_or(&world.db.dsn), 4)?
        .with_audit_keys("22".repeat(32), String::new());
    let deploy = setjoin_platform::deploy::Config::fixed(
        peer.map(|p| p.host_key.clone()).unwrap_or_default(),
        "a".repeat(64),
        ("test-access".into(), "test-secret".into()),
    );
    let adapter = PlatformUpdatesRoute::new(exec, Arc::new(common::recovery_keys()), "mailserver".into())
        .with_deploy(common::patient_exec(&world.db.dsn, 4)?, deploy)
        .await
        .with_airgap(
            airgap
                .map(|f| setjoin_platform::airgap::Store::load(f.root.join("store"), f.root.join("trust.json")).map(Arc::new))
                .transpose()?,
        );
    let mut inventory: Value = serde_json::from_str(include_str!("../route-inventory.json"))?;
    for r in inventory["routes"].as_array_mut().ok_or("routes")? {
        if r["family"] == "F08" && r["slice"] == "updates-deploy" {
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
        RouteTable::proxy_all().with(adapter),
    )?
    .with_inventory(&inventory.to_string())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(gateway.serve(listener));
    Ok(address)
}

async fn call(
    address: SocketAddr,
    method: &str,
    path: &str,
    bearer: &str,
    content_type: &str,
    body: impl Into<bytes::Bytes>,
) -> Result<(u16, String), BoxError> {
    let response = common::send(
        address,
        Request::builder()
            .method(method)
            .uri(path)
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("content-type", content_type)
            .header("authorization", format!("Bearer {bearer}"))
            .body(common::full(body))?,
    )
    .await;
    let status = response.status().as_u16();
    Ok((status, String::from_utf8(common::body_bytes(response).await.to_vec())?))
}

fn nodes(peer: &platform_oracle::deploy::Peer, key: &str) -> Value {
    json!({"nodes": (0..3).map(|i| json!({
        "host": peer.addresses[i], "role": if i == 0 {"primary"} else {"standby"},
        "ssh_user": "root", "ssh_key": key, "password": "secfix11-node-password"
    })).collect::<Vec<_>>()})
}

async fn denied_rows(owner: &Client, path: &str) -> Result<i64, BoxError> {
    let notes = path.strip_prefix("/api").unwrap_or(path).to_owned();
    Ok(owner
        .query_one("SELECT count(*) FROM admin_audit_log WHERE action='console.denied' AND notes=$1", &[&notes])
        .await?
        .get(0))
}

async fn finished(address: SocketAddr, bearer: &str) -> Result<Value, BoxError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let (_, body) = call(address, "GET", "/api/admin/deploy/status", bearer, "", "").await?;
        let state: Value = serde_json::from_str(&body)?;
        if matches!(state["status"].as_str(), Some("done" | "failed")) {
            return Ok(state);
        }
        if std::time::Instant::now() > deadline {
            return Err("deployment did not finish".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// Finding 1: a domain-scoped `system.upgrade` holder cannot start, cancel or read the deploy
/// wizard or upload an airgap update; an organization-wide holder can.
#[tokio::test]
async fn scoped_system_upgrade_cannot_deploy_or_upload() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix11_scope").await? else { return Ok(()) };
    let peer = platform_oracle::deploy::Peer::start("success").await?;
    let address = serve(&w, Some(&peer), None).await?;
    let (scoped, org) = (w.bearer(&w.scoped), w.bearer(&w.org));
    let body = nodes(&peer, &peer.private_key).to_string();
    for (method, path, content_type, payload) in [
        ("POST", "/api/admin/deploy/start", "application/json", body.as_str()),
        ("POST", "/api/admin/deploy/cancel", "application/json", ""),
        ("GET", "/api/admin/deploy/status", "", ""),
        ("POST", "/api/admin/updates/airgap/upload", "multipart/form-data; boundary=x", ""),
    ] {
        let before = denied_rows(&w.owner, path).await?;
        let (status, text) = call(address, method, path, &scoped, content_type, payload.to_owned()).await?;
        assert_eq!(status, 403, "scoped holder on {method} {path}");
        assert!(text.contains("\"detail\":\"Forbidden\""), "bare 403: {text}");
        assert_eq!(denied_rows(&w.owner, path).await?, before + 1, "console.denied row for {path}");
    }
    assert_eq!(peer.command_count(), 0, "a refused start must not reach any node");
    let (status, text) = call(address, "GET", "/api/admin/deploy/status", &org, "", "").await?;
    assert_eq!(status, 200, "{text}");
    let (status, _) = call(address, "POST", "/api/admin/deploy/start", &org, "application/json", json!({"nodes":[]}).to_string()).await?;
    assert_eq!(status, 400, "the organization-wide holder passes the gate");
    w.finish().await
}

/// Finding 3: the start body is capped at 1 MiB and parsed once.
#[tokio::test]
async fn deploy_body_is_capped() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix11_body").await? else { return Ok(()) };
    let address = serve(&w, None, None).await?;
    let org = w.bearer(&w.org);
    let small = json!({"nodes": []}).to_string();
    let (status, text) = call(address, "POST", "/api/admin/deploy/start", &org, "application/json", small).await?;
    assert_eq!((status, text.contains("exactly 3 nodes")), (400, true), "{text}");
    let huge = json!({"nodes": [], "pad": "x".repeat(2 << 20)}).to_string();
    let (status, text) = call(address, "POST", "/api/admin/deploy/start", &org, "application/json", huge).await?;
    assert_eq!(status, 400);
    assert!(text.contains("invalid JSON body"), "an oversize body is refused unparsed: {text}");
    w.finish().await
}

/// Finding 4: node hosts and users are validated before anything runs.
#[tokio::test]
async fn deploy_node_fields_are_validated() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix11_nodes").await? else { return Ok(()) };
    let peer = platform_oracle::deploy::Peer::start("success").await?;
    let address = serve(&w, Some(&peer), None).await?;
    let org = w.bearer(&w.org);
    for (field, value) in [("host", "10.0.0.2; touch /tmp/secfix11"), ("host", "$(id)"), ("ssh_user", "root; id")] {
        let mut body = nodes(&peer, &peer.private_key);
        body["nodes"][1][field] = json!(value);
        let (status, text) = call(address, "POST", "/api/admin/deploy/start", &org, "application/json", body.to_string()).await?;
        assert_eq!(status, 400, "{field}={value:?} must be refused: {text}");
    }
    assert_eq!(peer.command_count(), 0, "a refused node must never be contacted");
    let (_, status) = call(address, "GET", "/api/admin/deploy/status", &org, "", "").await?;
    assert_eq!(serde_json::from_str::<Value>(&status)?["status"], json!(""), "no run was started");
    w.finish().await
}

/// Finding 4: an `ssh_key` naming a local file is never read.
#[tokio::test]
async fn deploy_key_path_is_never_read() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix11_key").await? else { return Ok(()) };
    let peer = platform_oracle::deploy::Peer::start("success").await?;
    let address = serve(&w, Some(&peer), None).await?;
    let org = w.bearer(&w.org);
    let path = std::path::PathBuf::from(std::env::var_os("GOFREE_AIRGAP_FIXTURE_ROOT").unwrap_or("/dev/shm".into()))
        .join(format!("gofree-secfix11-key-{}", std::process::id()));
    std::fs::write(&path, &peer.private_key)?;
    let result = async {
        let (status, text) = call(address, "POST", "/api/admin/deploy/start", &org, "application/json", nodes(&peer, path.to_str().unwrap()).to_string()).await?;
        assert_eq!(status, 202, "{text}");
        let state = finished(address, &org).await?;
        assert_eq!(state["status"], json!("failed"), "a path is not key material");
        assert_eq!(peer.command_count(), 0, "the gateway must not authenticate with a file it read");
        Ok::<_, BoxError>(())
    }
    .await;
    let _ = std::fs::remove_file(&path);
    result?;
    w.finish().await
}

/// Finding 5: the unresolved remote-command fence survives a restart, until an operator
/// deletes it.
#[tokio::test]
async fn deploy_fence_survives_restart() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix11_fence").await? else { return Ok(()) };
    let peer = platform_oracle::deploy::Peer::start("hold").await?;
    let org = w.bearer(&w.org);
    let body = nodes(&peer, &peer.private_key).to_string();
    let first = serve(&w, Some(&peer), None).await?;
    let (status, text) = call(first, "POST", "/api/admin/deploy/start", &org, "application/json", body.clone()).await?;
    assert_eq!(status, 202, "{text}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while peer.command_count() == 0 {
        assert!(std::time::Instant::now() < deadline, "the run never reached a node");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let (status, _) = call(first, "POST", "/api/admin/deploy/cancel", &org, "application/json", "").await?;
    assert_eq!(status, 204);
    let rows: i64 = w.owner.query_one("SELECT count(*) FROM deploy_remote_fence", &[]).await?.get(0);
    assert_eq!(rows, 1, "the fence must be persisted when the remote command's end is unconfirmed");
    // A restart: a new wizard over the same database still refuses a run.
    let second = serve(&w, Some(&peer), None).await?;
    let (status, text) = call(second, "POST", "/api/admin/deploy/start", &org, "application/json", body.clone()).await?;
    assert_eq!((status, text.contains("Deploy failed")), (500, true), "{text}");
    // The operator resolves it; the same process then admits a run again.
    w.owner.execute("DELETE FROM deploy_remote_fence", &[]).await?;
    let (status, text) = call(second, "POST", "/api/admin/deploy/start", &org, "application/json", body).await?;
    assert_eq!(status, 202, "a resolved fence admits a run: {text}");
    let _ = call(second, "POST", "/api/admin/deploy/cancel", &org, "application/json", "").await?;
    w.finish().await
}

/// Finding 6: the per-slug rollback floor survives pruning of old sidecars and a restart,
/// and never decreases.
#[tokio::test]
async fn airgap_rollback_floor_survives_pruning_and_restart() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let fixture = platform_oracle::airgap::Fixture::new(4242, "success")?;
    let store = || setjoin_platform::airgap::Store::load(fixture.root.join("store"), fixture.root.join("trust.json"));
    let upload = |store: &setjoin_platform::airgap::Store| {
        store.upload(
            "linux-amd64".into(),
            fixture.upload_metadata.clone(),
            Some(("bundle-v2.bin".into(), platform_oracle::airgap::UPLOADED.to_vec())),
        )
    };
    let first = store()?;
    upload(&first).map_err(|f| format!("upload v2: {} {}", f.status, f.detail))?;
    assert!(fixture.root.join("store.floor").exists(), "the floor is persisted next to the store");
    // Prune: every sidecar disappears (the retained-targets limit does this; so can an operator).
    for entry in std::fs::read_dir(fixture.root.join("store"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "json") {
            std::fs::remove_file(path)?;
        }
    }
    let restarted = store()?;
    let refused = upload(&restarted).err().ok_or("a replayed older-or-equal target was accepted after pruning")?;
    assert_eq!(refused.status, 409, "{}", refused.detail);
    let floor: Value = serde_json::from_slice(&std::fs::read(fixture.root.join("store.floor"))?)?;
    assert_eq!(floor["linux-amd64"], json!(2), "the floor never decreases");
    Ok(())
}

/// Review fix: a failed publish after the floor was raised on disk must not leave memory
/// behind it, or a later upload would rewrite the disk floor down.
#[tokio::test]
async fn airgap_floor_holds_after_a_failed_publish() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let fixture = platform_oracle::airgap::Fixture::new(4243, "success")?;
    let store = setjoin_platform::airgap::Store::load(fixture.root.join("store"), fixture.root.join("trust.json"))?;
    let upload = || {
        store.upload(
            "linux-amd64".into(),
            fixture.upload_metadata.clone(),
            Some(("bundle-v2.bin".into(), platform_oracle::airgap::UPLOADED.to_vec())),
        )
    };
    // Make the sidecar publish fail: a directory sits where the sidecar must be renamed.
    let sidecar = fixture.root.join("store/linux-amd64.json");
    let saved = std::fs::read(&sidecar)?;
    std::fs::remove_file(&sidecar)?;
    std::fs::create_dir(&sidecar)?;
    assert!(upload().is_err(), "the publish must fail");
    std::fs::remove_dir(&sidecar)?;
    std::fs::write(&sidecar, saved)?;
    let refused = upload().err().ok_or("the floor was lowered after a failed publish")?;
    assert_eq!(refused.status, 409, "{}", refused.detail);
    let floor: Value = serde_json::from_slice(&std::fs::read(fixture.root.join("store.floor"))?)?;
    assert_eq!(floor["linux-amd64"], json!(2));
    Ok(())
}

/// Review fix: the app role may set the fence but never delete it; clearing it is an owner action.
#[tokio::test]
async fn app_role_cannot_delete_the_deploy_fence() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix11_grants").await? else { return Ok(()) };
    w.owner.execute("INSERT INTO deploy_remote_fence(detail) VALUES('t') ON CONFLICT DO NOTHING", &[]).await?;
    let app = w.db.connect_command().await?;
    if w.db.app.is_some() {
        assert!(app.execute("DELETE FROM deploy_remote_fence", &[]).await.is_err(), "app role must not delete the fence");
        assert!(app.query("SELECT 1 FROM deploy_remote_fence", &[]).await.is_ok());
    }
    let worker_ok: bool = w.owner.query_one("SELECT NOT has_table_privilege('setjoin_worker','deploy_remote_fence','DELETE') AND has_table_privilege('setjoin_worker','deploy_remote_fence','INSERT')", &[]).await?.get(0);
    assert!(worker_ok, "worker: set but not delete");
    w.finish().await
}
