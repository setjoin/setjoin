//! Executable `/rtc` registration (#410): with LiveKit configured the SFU
//! signal proxy answers natively at Go's fixed `127.0.0.1:7880` with Go out of
//! the path. Without LiveKit configuration Go registers no `/rtc` handler, so
//! the root mux answers natively (`404 page not found` without a website, #357).
//! The global kill switch and the inventory rollback hand the unchanged request
//! to Go; an unverified credential still proxies natively to Go's SFU.
use crate::common::boot::Child;
use crate::common::boot::CommandBootExt;
mod common;
#[path = "common/meet_fixture.rs"]
mod meet_fixture;
use common::BoxError;
use futures_util::FutureExt;
use hyper::{Request, Response};
use meet_fixture::ledger;
use serde_json::Value;
use setjoin_conformance::harness::Db;
use std::{
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Native,
    Kill,
    Rollback,
    Unconfigured,
    ForeignCredential,
    ActiveGuest,
}

#[tokio::test]
async fn executable_proxies_rtc_without_go() -> Result<(), BoxError> {
    run(Mode::Native).await
}
#[tokio::test]
async fn executable_global_kill_returns_rtc_to_go() -> Result<(), BoxError> {
    run(Mode::Kill).await
}
#[tokio::test]
async fn executable_inventory_rollback_returns_rtc_to_go() -> Result<(), BoxError> {
    run(Mode::Rollback).await
}
#[tokio::test]
async fn executable_without_livekit_answers_the_root_mux_natively() -> Result<(), BoxError> {
    run(Mode::Unconfigured).await
}
#[tokio::test]
async fn executable_unverified_credential_proxies_natively() -> Result<(), BoxError> {
    run(Mode::ForeignCredential).await
}
#[tokio::test]
async fn executable_active_guest_proxies_rtc_natively() -> Result<(), BoxError> {
    run(Mode::ActiveGuest).await
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

async fn run(mode: Mode) -> Result<(), BoxError> {
    use std::os::unix::process::CommandExt;
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("meet5-rtc-executable") else {
        return Ok(());
    };
    let to_go = matches!(mode, Mode::Kill | Mode::Rollback);
    struct GuestCleanup {
        saved_toggle: Option<Option<bool>>,
        domain: Option<i64>,
        users: Vec<i64>,
    }
    let owner = if mode == Mode::ActiveGuest {
        Some(db.connect().await?)
    } else {
        None
    };
    let mut guest_cleanup = GuestCleanup {
        saved_toggle: None,
        domain: None,
        users: Vec::new(),
    };
    let result = std::panic::AssertUnwindSafe(async {
        let mut active_user = None;
        let mut inactive_user = None;
        if let Some(owner) = &owner {
            let prev: Option<bool> = owner
                .query_opt(
                    "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
                    &[],
                )
                .await?
                .map(|r| r.get(0));
            guest_cleanup.saved_toggle = Some(prev);
            owner
                .execute(
                    "INSERT INTO feature_toggles(key,enabled) VALUES('feature.guest_accounts',true) ON CONFLICT(key) DO UPDATE SET enabled=true",
                    &[],
                )
                .await?;
            let domain: i64 = owner
                .query_one(
                    "INSERT INTO domains(name,is_local) VALUES('meet5-guest-'||gen_random_uuid()::text||'.test',true) RETURNING id",
                    &[],
                )
                .await?
                .get(0);
            guest_cleanup.domain = Some(domain);
            for (slot, status) in [(&mut active_user, "active"), (&mut inactive_user, "expired")] {
                let row = owner
                    .query_one(
                        "INSERT INTO users(username,domain_id,email,display_name,password_hash) VALUES('meet5-guest-'||gen_random_uuid()::text,(SELECT id FROM domains WHERE name='guest.invalid'),'meet5-guest-'||gen_random_uuid()::text||'@example.test','meet5 guest','x') RETURNING id, email",
                        &[],
                    )
                    .await?;
                let user: i64 = row.get(0);
                let guest_email: String = row.get(1);
                guest_cleanup.users.push(user);
                owner
                    .execute(
                        "INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) VALUES($1,$2,'inviter@example.test',$3,$4)",
                        &[&user, &guest_email, &domain, &status],
                    )
                    .await?;
                *slot = Some(user);
            }
        }
        let go_hits = Arc::new(AtomicUsize::new(0));
        let observed = go_hits.clone();
        let go = common::fake_upstream(move |_| {
            let observed = observed.clone();
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
                Response::builder().status(218).body(common::full("from go")).unwrap()
            }
        })
        .await;
        // Go's hard-coded SFU signal address; a busy port is a test failure.
        let sfu_hits = Arc::new(AtomicUsize::new(0));
        let seen = sfu_hits.clone();
        // The previous case's SFU task may still be unwinding its listener: wait briefly for
        // the port, then fail (a port held by something else stays a failure).
        let mut attempts = 0;
        let listener = loop {
            match tokio::net::TcpListener::bind("127.0.0.1:7880").await {
                Ok(listener) => break listener,
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse && attempts < 100 => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => return Err(error.into()),
            }
        };
        let sfu = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let seen = seen.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |_req| {
                        let seen = seen.clone();
                        async move {
                            seen.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, std::convert::Infallible>(
                                Response::builder().status(200).body(common::full("success")).unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
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
            .join("../../../test-results/gofree-meet5");
        std::fs::create_dir_all(&dir)?;
        let tag = format!("{}", std::process::id());
        let log = std::fs::File::create(dir.join(format!("gofree-meet5-rtc-exec-{tag}.log")))?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
        command.arg0("gofree-meet5-gateway").env_clear();
        for (key, value) in [
            ("GATEWAY_LISTEN", address.to_string()),
            ("GATEWAY_ENABLED", (mode != Mode::Kill).to_string()),
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
        if mode != Mode::Unconfigured {
            command
                .env("LIVEKIT_API_KEY", "meet5-key")
                .env("LIVEKIT_API_SECRET", "meet5-secret-meet5-secret-meet5-secret")
                .env("LIVEKIT_URL", "ws://127.0.0.1:7880");
        }
        if to_go {
            command.env("GATEWAY_UPSTREAM", format!("http://{go}"));
        }
        if mode == Mode::Rollback {
            let mut inventory: Value = serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;
            let mut flipped = 0;
            for row in inventory["routes"].as_array_mut().unwrap() {
                if row["family"] == "F13"
                    && row["state"] == "ON"
                    && row["path"].as_str().is_some_and(|p| p == "/rtc" || p == "/rtc/")
                {
                    row["state"] = "OFF".into();
                    row["upstream"] = "go-mail".into();
                    flipped += 1;
                }
            }
            assert_eq!(flipped, 2, "both /rtc rows are ON in the bundled inventory");
            let file = dir.join(format!("gofree-meet5-rollback-{tag}.json"));
            std::fs::write(&file, inventory.to_string())?;
            command.env("GATEWAY_ROUTE_INVENTORY", file);
        }
        if let Ok(path) = std::env::var("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", path);
        }
        ledger(&format!("Plan gofree-meet5-gateway executable at {address}, assigned DB only; fake SFU on 127.0.0.1:7880"))?;
        let mut child = Owned(
            command
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn_boot()?,
        );
        ledger(&format!("Started gofree-meet5-gateway PID {}", child.0.id()))?;
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
        let probes: Vec<(&str, &str, Vec<(&str, String)>, u16, Option<&str>)> = match mode {
            Mode::ForeignCredential => vec![(
                "GET",
                "/rtc/rtc/validate?access_token=good",
                vec![("authorization", "Bearer not-a-token".to_owned())],
                200,
                Some("success"),
            )],
            Mode::ActiveGuest => {
                let active_auth = format!("Bearer {}", common::recovery_token(active_user.unwrap()));
                let inactive_auth = format!("Bearer {}", common::recovery_token(inactive_user.unwrap()));
                vec![
                    (
                        "GET",
                        "/rtc/rtc/validate?access_token=good",
                        vec![("authorization", active_auth.clone())],
                        200,
                        Some("success"),
                    ),
                    (
                        "GET",
                        "/rtc",
                        vec![("authorization", active_auth.clone())],
                        200,
                        Some("success"),
                    ),
                    (
                        "POST",
                        "/rtc",
                        vec![("authorization", active_auth)],
                        404,
                        Some("404 page not found\n"),
                    ),
                    (
                        "GET",
                        "/rtc",
                        vec![("authorization", inactive_auth)],
                        401,
                        None,
                    ),
                ]
            }
            Mode::Unconfigured => vec![
                ("GET", "/rtc/rtc/validate?access_token=good", vec![], 404, Some("404 page not found\n")),
                ("GET", "/rtc", vec![], 404, Some("404 page not found\n")),
            ],
            Mode::Native => vec![
                ("GET", "/rtc/rtc/validate?access_token=good", vec![], 200, Some("success")),
                ("GET", "/rtc", vec![], 200, Some("success")),
            ],
            Mode::Kill | Mode::Rollback => vec![
                ("GET", "/rtc/rtc/validate?access_token=good", vec![], 218, Some("from go")),
                ("GET", "/rtc", vec![], 218, Some("from go")),
            ],
        };
        let mut count = 0;
        let mut expected_sfu = 0;
        for (method, uri, headers, want, text) in &probes {
            let mut request = Request::builder()
                .method(*method)
                .uri(*uri)
                .header("host", "mail.test");
            for (k, v) in headers {
                request = request.header(*k, v.as_str());
            }
            let response = common::send(address, request.body(common::full(""))?).await;
            let status = response.status().as_u16();
            let body = common::body_bytes(response).await;
            let body_ok = match text {
                Some(exact) => body == exact.as_bytes(),
                None => String::from_utf8_lossy(&body).contains("Unauthorized"),
            };
            if status != *want || !body_ok {
                return Err(format!("{method} {uri}: {status} {}", String::from_utf8_lossy(&body)).into());
            }
            if *want == 200 {
                expected_sfu += 1;
            }
            count += 1;
        }
        if mode != Mode::Kill {
            let metrics = common::send(
                address,
                Request::builder().uri("/_gateway/metrics").body(common::full(""))?,
            )
            .await;
            let text = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            let n = if to_go { count } else { 0 };
            if !text.contains(&format!("setjoin_gateway_proxied_to_go_total {n}\n")) {
                return Err(format!("proxy counters: {text}").into());
            }
        }
        if go_hits.load(Ordering::SeqCst) != if to_go { count } else { 0 } {
            return Err("unexpected Go request count".into());
        }
        if sfu_hits.load(Ordering::SeqCst) != expected_sfu {
            return Err("unexpected SFU request count".into());
        }
        let pid = child.0.id();
        drop(child);
        sfu.abort();
        let _ = sfu.await;
        ledger(&format!("Stopped/reaped gofree-meet5-gateway PID {pid}; fake SFU closed"))?;
        Ok::<_, BoxError>(())
    })
    .catch_unwind()
    .await;
    if let Some(owner) = &owner {
        if let Some(saved_toggle) = guest_cleanup.saved_toggle {
            if let Some(prev) = saved_toggle {
                owner
                    .execute(
                        "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'",
                        &[&prev],
                    )
                    .await?;
            } else {
                owner
                    .execute(
                        "DELETE FROM feature_toggles WHERE key='feature.guest_accounts'",
                        &[],
                    )
                    .await?;
            }
        }
        for user in &guest_cleanup.users {
            owner
                .execute("DELETE FROM guest_accounts WHERE user_id=$1", &[user])
                .await?;
            owner
                .execute("DELETE FROM users WHERE id=$1", &[user])
                .await?;
        }
        if let Some(domain) = guest_cleanup.domain {
            owner
                .execute("DELETE FROM domains WHERE id=$1", &[&domain])
                .await?;
        }
    }
    match result {
        Ok(r) => r,
        Err(p) => std::panic::resume_unwind(p),
    }
}
