//! Executable F13 sub-router-c registration: the local-capture, semantic-read
//! and admin registry routes answer natively with Go out of the path, and both
//! rollback switches return the unchanged request to Go.
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

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn executable_serves_sub_router_c_without_go() -> Result<(), BoxError> {
    run(false, false).await
}
#[tokio::test]
async fn executable_global_kill_preserves_sub_router_c_requests() -> Result<(), BoxError> {
    run(true, false).await
}
#[tokio::test]
async fn executable_inventory_rollback_preserves_sub_router_c_requests() -> Result<(), BoxError> {
    run(false, true).await
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

const PROBED: usize = 7;

async fn run(kill: bool, rollback: bool) -> Result<(), BoxError> {
    use std::os::unix::process::CommandExt;
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("meet4-executable") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let a = fixture::account(&c, "meet4-exec-owner").await?;
    let toggle: Option<bool> = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.meet'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
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
            .join("../../../test-results/gofree-meet4");
        std::fs::create_dir_all(&dir)?;
        let log = std::fs::File::create(dir.join(format!(
            "gofree-meet4-exec-{}-{kill}-{rollback}.log",
            a.user
        )))?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
        command.arg0("gofree-meet4-gateway").env_clear();
        for (key, value) in [
            ("GATEWAY_LISTEN", address.to_string()),
            ("GATEWAY_ENABLED", (!kill).to_string()),
            ("GATEWAY_AUTH_UPSTREAM", format!("http://{jwks}")),
            ("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn).to_owned()),
            ("DB_WORKER_DSN", db.dsn.clone()),
            ("DB_DIRECT_DSN", db.direct.clone()),
            ("DB_ENCRYPTION_KEY", "22".repeat(32)),
            (
                "AUTHSERVER_JWKS_URL",
                format!("http://{jwks}/.well-known/jwks.json"),
            ),
            ("CORE_RATE_LIMIT", "100000".into()),
            ("ADMIN_RATE_LIMIT", "100000".into()),
            ("LIVEKIT_API_KEY", "meet4-key".into()),
            (
                "LIVEKIT_API_SECRET",
                "meet4-secret-meet4-secret-meet4-secret".into(),
            ),
            ("LIVEKIT_URL", "ws://127.0.0.1:1".into()),
        ] {
            command.env(key, value);
        }
        if kill || rollback {
            command.env("GATEWAY_UPSTREAM", format!("http://{go}"));
        }
        if rollback {
            let mut inventory: Value = serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;
            for row in inventory["routes"].as_array_mut().unwrap() {
                if row["family"] == "F13" && row["slice"] == "sub-router-c" && row["state"] == "ON"
                {
                    row["state"] = "OFF".into();
                    row["upstream"] = "go-mail".into();
                }
            }
            let file = dir.join(format!("gofree-meet4-rollback-{}.json", a.user));
            std::fs::write(&file, inventory.to_string())?;
            command.env("GATEWAY_ROUTE_INVENTORY", file);
        }
        if let Ok(path) = std::env::var("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", path);
        }
        ledger(&format!(
            "Plan gofree-meet4-gateway executable at {address}, assigned DB only"
        ))?;
        let mut child = Owned(
            command
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn_boot()?,
        );
        ledger(&format!(
            "Started gofree-meet4-gateway PID {}",
            child.0.id()
        ))?;
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
        let created: Value = serde_json::from_str(
            &c.query_one(
                "SELECT meeting_create($1,'Meet4 executable',NULL,NULL,NULL,NULL,true)::text",
                &[&a.user],
            )
            .await?
            .get::<_, String>(0),
        )?;
        let meeting = created["meetingId"].as_i64().unwrap();
        let calls: Vec<(&str, String, String, bool, Vec<(&str, String)>, u16)> = vec![
            // feature.meet_local_recording is OFF by default: a plain 404.
            (
                "POST",
                format!("/api/meet/{meeting}/local/lease"),
                "{}".into(),
                true,
                vec![],
                404,
            ),
            (
                "POST",
                format!("/api/meet/{meeting}/local/1/heartbeat"),
                "{}".into(),
                true,
                vec![],
                404,
            ),
            (
                "POST",
                format!("/api/meet/{meeting}/local/1/stop"),
                "{}".into(),
                true,
                vec![],
                404,
            ),
            (
                "POST",
                format!("/api/meet/{meeting}/local/1/register"),
                "{}".into(),
                true,
                vec![],
                404,
            ),
            // The reads are never flag-gated; an unknown recording is the reducer's BZ278.
            (
                "GET",
                format!("/api/meet/{meeting}/semantic/1/package"),
                String::new(),
                true,
                vec![],
                409,
            ),
            (
                "GET",
                format!("/api/meet/{meeting}/semantic/1/replay"),
                String::new(),
                true,
                vec![],
                409,
            ),
            // An ordinary token holds no drive.view: the console denial is native.
            (
                "GET",
                "/api/admin/meet/recordings".into(),
                String::new(),
                true,
                vec![],
                403,
            ),
        ];
        assert_eq!(calls.len(), PROBED);
        let mut seen = Vec::new();
        for (index, (method, path, body, authed, headers, expect)) in calls.into_iter().enumerate()
        {
            let uri = format!("{path}?probe={index}");
            let mut request = Request::builder()
                .method(method)
                .uri(&uri)
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("x-meet-probe", index.to_string())
                .header("content-type", "application/json");
            if authed {
                request = request.header(
                    "authorization",
                    format!("Bearer {}", token(a.user, "meet4-exec")),
                );
            }
            for (k, v) in &headers {
                request = request.header(*k, v.as_str());
            }
            let response =
                common::send(address, request.body(common::full(body.clone())).unwrap()).await;
            let status = response.status().as_u16();
            seen.push((
                uri,
                status,
                common::body_bytes(response).await,
                method,
                body,
                expect,
            ));
        }
        let forwarding = kill || rollback;
        for (index, (uri, status, bytes, method, body, expect)) in seen.iter().enumerate() {
            if forwarding {
                if *status != 218 {
                    return Err(format!("rollback {uri}: {status}").into());
                }
                let echoed: Value = serde_json::from_slice(bytes)?;
                if echoed
                    != json!({"method":method,"uri":uri,"body":body,"probe":index.to_string()})
                {
                    return Err(format!("changed rollback request: {echoed}").into());
                }
            } else if status != expect {
                return Err(
                    format!("native {uri}: {status} {}", String::from_utf8_lossy(bytes)).into(),
                );
            }
        }
        if !kill {
            let response = common::send(
                address,
                Request::builder()
                    .uri("/_gateway/metrics")
                    .body(common::full(""))?,
            )
            .await;
            let text = String::from_utf8(common::body_bytes(response).await.to_vec())?;
            let n = if rollback { PROBED } else { 0 };
            if !text.contains(&format!("setjoin_gateway_proxied_to_go_total {n}\n"))
                || !text.contains(&format!(
                    "setjoin_gateway_proxied_to_go_by_family_total{{family=\"F13\"}} {n}\n"
                ))
            {
                return Err(format!("proxy counters: {text}").into());
            }
        }
        if hits.load(Ordering::SeqCst) != if forwarding { PROBED } else { 0 } {
            return Err("unexpected Go request count".into());
        }
        let pid = child.0.id();
        drop(child);
        ledger(&format!("Stopped/reaped gofree-meet4-gateway PID {pid}"))?;
        Ok::<_, BoxError>(())
    })
    .catch_unwind()
    .await;
    meet_fixture::cleanup(&c, &[&a]).await?;
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
