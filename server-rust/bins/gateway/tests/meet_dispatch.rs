//! Executable F13 golden registration, both rollback switches and proxy metrics.
use crate::common::boot::CommandBootExt;
use crate::common::boot::Child;
mod common;
#[path = "common/meet_fixture.rs"]
mod meet_fixture;
use common::BoxError;
use futures_util::FutureExt;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use meet_fixture::{ledger, token};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use std::{
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

#[tokio::test]
async fn executable_serves_all_seven_golden_routes_without_go() -> Result<(), BoxError> {
    run(false, false, true, false).await
}
#[tokio::test]
async fn executable_global_kill_preserves_all_seven_requests() -> Result<(), BoxError> {
    run(true, false, true, false).await
}
#[tokio::test]
async fn executable_inventory_rollback_preserves_all_seven_requests() -> Result<(), BoxError> {
    run(false, true, true, false).await
}
/// Go's third gate leg: LiveKit not provisioned answers 503 before any reducer.
#[tokio::test]
async fn executable_without_livekit_answers_service_unavailable() -> Result<(), BoxError> {
    run(false, false, false, false).await
}
/// Go's RequireApp denial and audit are native with Go absent (#406).
#[tokio::test]
async fn executable_denies_entitlement_without_go() -> Result<(), BoxError> {
    run(false, false, true, true).await
}

struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            // The unreaped Child owns this PID; it cannot be reused by another task.
            unsafe {
                libc::kill(self.0.id() as i32, libc::SIGTERM);
            }
            for _ in 0..50 {
                if self.0.try_wait().ok().flatten().is_some() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

/// Every case shares the `meet1-executable` DB case and the global `feature.meet` toggle.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn run(kill: bool, rollback: bool, livekit: bool, denied: bool) -> Result<(), BoxError> {
    use std::os::unix::process::CommandExt;
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("meet1-executable") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let a = fixture::account(&c, "meet1-exec-owner").await?;
    let b = fixture::account(&c, "meet1-exec-member").await?;
    let toggle: Option<bool> = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.meet'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    if denied {
        c.execute(
            "INSERT INTO user_app_entitlements(user_id,app,enabled) VALUES($1,'meet',false)",
            &[&a.user],
        )
        .await?;
    }
    c.execute(
        "INSERT INTO feature_toggles(key,enabled) VALUES('feature.meet',true) ON CONFLICT (key) DO UPDATE SET enabled=true",
        &[],
    )
    .await?;
    let result = std::panic::AssertUnwindSafe(async {
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = hits.clone();
        let go = common::fake_upstream(move |mut request| {
            let observed = observed.clone();
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
                let bytes = request.body_mut().collect().await.unwrap().to_bytes();
                Response::builder()
                    .status(218)
                    .body(common::full(
                        json!({"method":request.method().as_str(),"uri":request.uri().to_string(),
                            "body":String::from_utf8_lossy(&bytes),
                            "probe":request.headers()["x-meet-probe"].to_str().unwrap()})
                        .to_string(),
                    ))
                    .unwrap()
            }
        })
        .await;
        let jwks = common::fake_upstream(|_| async {
            Response::builder()
                .header("content-type", "application/json")
                .body(common::full(
                    include_bytes!("../../../tests/conformance/jmap/test-jwks.json").as_slice(),
                ))
                .unwrap()
        })
        .await;
        let reserved = setjoin_conformance::ports::listener().await;
        let address = reserved.local_addr()?;
        drop(reserved);
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../test-results/gofree-meet1");
        std::fs::create_dir_all(&dir)?;
        let log = std::fs::File::create(dir.join(format!(
            "gofree-meet1-exec-{}-{kill}-{rollback}-{livekit}-{denied}.log",
            a.user
        )))?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
        command.arg0("gofree-meet1-gateway").env_clear();
        for (key, value) in [
            ("GATEWAY_LISTEN", address.to_string()),
            ("GATEWAY_ENABLED", (!kill).to_string()),
            ("GATEWAY_AUTH_UPSTREAM", format!("http://{jwks}")),
            ("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn).to_owned()),
            ("DB_WORKER_DSN", db.dsn.clone()),
            ("DB_DIRECT_DSN", db.direct.clone()),
            ("DB_ENCRYPTION_KEY", "22".repeat(32)),
            ("AUTHSERVER_JWKS_URL", format!("http://{jwks}/.well-known/jwks.json")),
            ("CORE_RATE_LIMIT", "100000".into()),
            ("ADMIN_RATE_LIMIT", "100000".into()),
        ] {
            command.env(key, value);
        }
        if livekit {
            for (key, value) in [
                ("LIVEKIT_API_KEY", "meet1-key"),
                ("LIVEKIT_API_SECRET", "meet1-secret"),
                ("LIVEKIT_URL", "ws://127.0.0.1:1"),
            ] {
                command.env(key, value);
            }
        }
        if kill || rollback {
            command.env("GATEWAY_UPSTREAM", format!("http://{go}"));
        }
        if rollback {
            let mut inventory: Value = serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;
            for row in inventory["routes"].as_array_mut().unwrap() {
                if row["family"] == "F13" && row["slice"] == "golden-routes" {
                    row["state"] = "OFF".into();
                    row["upstream"] = "go-mail".into();
                }
            }
            let file = dir.join(format!("gofree-meet1-rollback-{}.json", a.user));
            std::fs::write(&file, inventory.to_string())?;
            command.env("GATEWAY_ROUTE_INVENTORY", file);
        }
        if let Ok(path) = std::env::var("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", path);
        }
        ledger(&format!("Plan gofree-meet1-gateway executable at {address}, assigned DB only"))?;
        let mut child = Owned(
            command
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn_boot()?,
        );
        ledger(&format!("Started gofree-meet1-gateway PID {}", child.0.id()))?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait()? {
                return Err(format!("gateway exited: {status}").into());
            }
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                return Err("gateway startup timeout".into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let call = |index: usize, method: &'static str, path: String, body: String| {
            let user = a.user;
            async move {
                let uri = format!("{path}?probe={index}");
                let response = common::send(
                    address,
                    Request::builder()
                        .method(method)
                        .uri(&uri)
                        .header("host", "mail.test")
                        .header("origin", "http://mail.test")
                        .header("authorization", format!("Bearer {}", token(user, "meet1-exec")))
                        .header("x-meet-probe", index.to_string())
                        .header("content-type", "application/json")
                        .body(common::full(body.clone()))
                        .unwrap(),
                )
                .await;
                let status = response.status().as_u16();
                (uri, status, common::body_bytes(response).await)
            }
        };
        let forwarding = kill || rollback;
        // Create first: native replies carry the id and slug later routes use.
        let (uri, status, bytes) =
            call(0, "POST", "/api/meet".into(), json!({"title":"Executable"}).to_string()).await;
        let (meeting, slug) = if forwarding || !livekit || denied {
            (424242, "executable-slug".to_owned())
        } else {
            let created: Value = serde_json::from_slice(&bytes)?;
            (
                created["meetingId"].as_i64().ok_or("created meeting id")?,
                created["slug"].as_str().ok_or("created slug")?.to_owned(),
            )
        };
        if !forwarding && livekit && !denied {
            c.execute(
                "INSERT INTO meeting_participants(meeting_id,user_id,identity,role) VALUES($1,$2,'u:'||$2::bigint::text,'member')",
                &[&meeting, &b.user],
            )
            .await?;
        }
        let mut seen = vec![(uri, status, bytes, "POST", json!({"title":"Executable"}).to_string(), 201)];
        for (index, (method, path, body, expect)) in [
            ("GET", "/api/meet".to_owned(), String::new(), 200),
            ("GET", format!("/api/meet/{meeting}"), String::new(), 200),
            ("GET", format!("/api/meet/by-slug/{slug}"), String::new(), 200),
            ("POST", format!("/api/meet/{meeting}/lock"), json!({"locked":true}).to_string(), 204),
            ("POST", format!("/api/meet/{meeting}/settings"), json!({"guestAllowed":true}).to_string(), 204),
            ("POST", format!("/api/meet/{meeting}/role"), json!({"identity":format!("u:{}",b.user),"role":"cohost"}).to_string(), 204),
        ]
        .into_iter()
        .enumerate()
        {
            let (uri, status, bytes) = call(index + 1, method, path, body.clone()).await;
            seen.push((uri, status, bytes, method, body, expect));
        }
        for (index, (uri, status, bytes, method, body, expect)) in seen.iter().enumerate() {
            if forwarding {
                if *status != 218 {
                    return Err(format!("rollback {uri}: {status}").into());
                }
                let echoed: Value = serde_json::from_slice(bytes)?;
                if echoed != json!({"method":method,"uri":uri,"body":body,"probe":index.to_string()}) {
                    return Err(format!("changed rollback request: {echoed}").into());
                }
            } else if denied {
                let problem:Value=serde_json::from_slice(bytes)?;
                if *status!=403 || problem["detail"]!="Access to this application is not permitted for your account." {
                    return Err(format!("entitlement {uri}: {status} {problem}").into());
                }
            } else if !livekit {
                let problem: Value = serde_json::from_slice(bytes)?;
                if *status != 503 || problem["type"] != "https://setjoin.com/errors/service-unavailable" {
                    return Err(format!("unconfigured {uri}: {status} {problem}").into());
                }
            } else if status != expect {
                return Err(format!("native {uri}: {status} {}", String::from_utf8_lossy(bytes)).into());
            }
        }
        if !kill {
            let response = common::send(
                address,
                Request::builder().uri("/_gateway/metrics").body(common::full(""))?,
            )
            .await;
            let text = String::from_utf8(common::body_bytes(response).await.to_vec())?;
            let n = if rollback { 7 } else { 0 };
            if !text.contains(&format!("setjoin_gateway_proxied_to_go_total {n}\n"))
                || !text.contains(&format!(
                    "setjoin_gateway_proxied_to_go_by_family_total{{family=\"F13\"}} {n}\n"
                ))
            {
                return Err(format!("proxy counters: {text}").into());
            }
        }
        if hits.load(Ordering::SeqCst) != if forwarding { 7 } else { 0 } {
            return Err("unexpected Go request count".into());
        }
        let (rows, locked): (i64, bool) = {
            let r = c
                .query_one(
                    "SELECT count(*), coalesce(bool_or(locked),false) FROM meetings WHERE owner_user_id=$1",
                    &[&a.user],
                )
                .await?;
            (r.get(0), r.get(1))
        };
        if (rows, locked) != if forwarding || !livekit || denied { (0, false) } else { (1, true) } {
            return Err(format!("meetings written unexpectedly: {rows} {locked}").into());
        }
        let pid = child.0.id();
        drop(child);
        ledger(&format!("Stopped/reaped gofree-meet1-gateway PID {pid}"))?;
        Ok::<_, BoxError>(())
    })
    .catch_unwind()
    .await;
    c.execute(
        "DELETE FROM user_app_entitlements WHERE user_id=$1",
        &[&a.user],
    )
    .await?;
    meet_fixture::cleanup(&c, &[&a, &b]).await?;
    match toggle {
        Some(v) => {
            c.execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.meet'",
                &[&v],
            )
            .await?;
        }
        None => {
            c.execute("DELETE FROM feature_toggles WHERE key='feature.meet'", &[])
                .await?;
        }
    }
    match result {
        Ok(r) => r,
        Err(p) => std::panic::resume_unwind(p),
    }
}
