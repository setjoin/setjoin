//! The IMAP swap's activation contract (#345): sockets handed over by systemd,
//! Go's listener off, the threat gate required, TLS and limits wired, and a real
//! login through the gateway's wiring on the constrained database role.
use crate::common::boot::CommandBootExt;
mod common;

use futures_util::future::BoxFuture;
use setjoin_gateway::imap_runtime;
use setjoin_imap::{ConnectionMeta, ThreatAction, ThreatGate};
use std::{
    collections::HashMap,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

/// A test double standing in for the #420 gate: it admits everything, which is
/// exactly why it exists only in this test file.
struct TestGate;
impl ThreatGate for TestGate {
    fn intercept<'a>(&'a self, _: &'a ConnectionMeta) -> BoxFuture<'a, (ThreatAction, Duration)> {
        Box::pin(async { (ThreatAction::Allow, Duration::ZERO) })
    }
    fn record_result<'a>(&'a self, _: &'a ConnectionMeta, _: bool, _: i64) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
    fn evaluate_post_auth<'a>(
        &'a self,
        _: &'a mut ConnectionMeta,
    ) -> BoxFuture<'a, (ThreatAction, String)> {
        Box::pin(async { (ThreatAction::Allow, String::new()) })
    }
}

/// The shared webhook dispatcher the daemon builds; nothing here delivers.
fn hooks() -> Option<setjoin_gateway::webhook::Dispatcher> {
    Some(setjoin_gateway::webhook::Dispatcher::new(
        setjoin_pg::workers::WorkerDatabase::new("postgres://nobody@127.0.0.1:9/none").unwrap(),
        None,
    ))
}

fn gate() -> Option<Arc<dyn ThreatGate>> {
    Some(Arc::new(TestGate))
}

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |name| map.get(name).cloned()
}

async fn listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

/// The cases seed and clean the same fixed IMAP fixture ids on one database: libtest's
/// parallel threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn activation_is_refused_without_go_off_or_the_threat_gate() {
    let _serial = SERIAL.lock().await;
    let dsn = "postgres://nobody@127.0.0.1:9/none";
    let base = [("DB_DSN", dsn), ("GO_LISTENERS_OFF", "imap")];
    // No sockets handed over: Go still owns IMAP, nothing starts.
    assert!(imap_runtime::start(None, None, &env(&base), None, hooks())
        .unwrap()
        .is_none());
    // Go's copy still on.
    let err = imap_runtime::start(
        Some(listener().await),
        None,
        &env(&[("DB_DSN", dsn)]),
        gate(),
        hooks(),
    )
    .err()
    .unwrap();
    assert!(err.contains("GO_LISTENERS_OFF"), "{err}");
    let err = imap_runtime::start(
        Some(listener().await),
        None,
        &env(&[("DB_DSN", dsn), ("GO_LISTENERS_OFF", "imaps,smtp")]),
        gate(),
        hooks(),
    )
    .err()
    .unwrap();
    assert!(err.contains("GO_LISTENERS_OFF"), "{err}");
    // No threat gate (#420 is absent): refused, never an allow-all fallback.
    let err = imap_runtime::start(Some(listener().await), None, &env(&base), None, hooks())
        .err()
        .unwrap();
    assert!(err.contains("#420"), "{err}");
    // No webhook dispatcher: Rust IMAP would drop auth.login events, so it is refused.
    let err = imap_runtime::start(Some(listener().await), None, &env(&base), gate(), None)
        .err()
        .unwrap();
    assert!(err.contains("webhook dispatcher"), "{err}");
    // imaps needs TLS material; a public plain socket needs it too.
    let err = imap_runtime::start(None, Some(listener().await), &env(&base), gate(), hooks())
        .err()
        .unwrap();
    assert!(err.contains("certificate"), "{err}");
    let public = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let err = imap_runtime::start(Some(public), None, &env(&base), gate(), hooks())
        .err()
        .unwrap();
    assert!(err.contains("beyond loopback"), "{err}");
    let err = imap_runtime::start(
        Some(listener().await),
        None,
        &env(&[("GO_LISTENERS_OFF", "imap")]),
        gate(),
        hooks(),
    )
    .err()
    .unwrap();
    assert!(err.contains("DB_DSN"), "{err}");
    let err = imap_runtime::start(
        Some(listener().await),
        None,
        &env(&[
            ("DB_DSN", dsn),
            ("GO_LISTENERS_OFF", "imap"),
            ("IMAP_TLS_CERT_FILE", "/x"),
        ]),
        gate(),
        hooks(),
    )
    .err()
    .unwrap();
    assert!(err.contains("both a certificate and a key"), "{err}");
}

/// The executable, given the three named descriptors, refuses to start while the
/// policy subscription is unavailable or Go's copy is on; neither can serve auth.
#[test]
fn executable_refuses_imap_sockets_without_go_off_and_live_admission() {
    use std::os::fd::AsRawFd;
    for (go_off, needle) in [
        (None, "GO_LISTENERS_OFF"),
        (Some("imap"), "setjoin-gateway: error connecting to server"),
    ] {
        let sockets: Vec<std::net::TcpListener> = (0..3)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let fds: Vec<i32> = sockets.iter().map(|s| s.as_raw_fd()).collect();
        let mut command = Command::new("bash");
        command
            .env_clear()
            .env("GATEWAY_ENABLED", "false")
            .env("DB_DSN", &std::env::var("TEST_DB_DSN").expect("disposable boot database"))
            // BOOT needs a live request database. The independent direct
            // connection must still refuse IMAP without policy notifications.
            .env("DB_DIRECT_DSN", "postgres://nobody@127.0.0.1:9/none")
            .env("LISTEN_FDNAMES", "http:imap:imaps")
            .arg("-c")
            .arg("export LISTEN_PID=$$ LISTEN_FDS=3; exec -a gofree-authrt-gateway \"$1\"")
            .arg("gofree-authrt-launcher")
            .arg(env!("CARGO_BIN_EXE_setjoin-gateway"))
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if let Some(go_off) = go_off {
            command.env("GO_LISTENERS_OFF", go_off);
        }
        unsafe {
            command.pre_exec(move || {
                unsafe extern "C" {
                    fn dup2(oldfd: i32, newfd: i32) -> i32;
                }
                // Stage descriptors 3, 4 and 5 as systemd does (descriptors above
                // 5 are never in the way: the sources are numbered later).
                for (i, fd) in fds.iter().enumerate() {
                    let target = 100 + i as i32;
                    if dup2(*fd, target) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                for i in 0..3 {
                    if dup2(100 + i, 3 + i) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let output = command.output_boot().unwrap();
        assert!(!output.status.success(), "go_off={go_off:?} started");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("server boot checks completed"), "{stderr}");
        assert!(stderr.contains(needle), "go_off={go_off:?}: {stderr}");
    }
}

#[tokio::test]
async fn gateway_wiring_serves_logins_on_the_request_role_and_enforces_limits() {
    let _serial = SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case("imap-activation-wiring") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let fixture = |name: &str| {
        std::fs::read_to_string(format!(
            "{}/../../crates/protocols/imap/oracle/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    for sql in [fixture("session-cleanup.sql"), fixture("session-seed.sql")] {
        owner.batch_execute(&sql).await.unwrap();
    }
    let dsn = db.app.clone().unwrap_or_else(|| db.dsn.clone());
    let plain = listener().await;
    let addr = plain.local_addr().unwrap();
    let runtime = imap_runtime::start(
        Some(plain),
        None,
        &env(&[
            ("DB_DSN", &dsn),
            ("GO_LISTENERS_OFF", "imap"),
            ("IMAP_MAX_CONNS", "2"),
            ("IMAP_PER_USER_MAX_CONNS", "1"),
        ]),
        gate(),
        hooks(),
    )
    .unwrap()
    .unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(runtime.run(rx));

    async fn say(socket: &mut TcpStream, text: &str, until: &str) -> String {
        socket.write_all(text.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buf))
                .await
                .expect("reply")
                .unwrap();
            assert!(n > 0, "closed: {}", String::from_utf8_lossy(&out));
            out.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&out).to_string();
            if text.lines().any(|l| l.starts_with(until)) {
                return text;
            }
        }
    }
    let login = "l1 LOGIN \"alice@imap3.test\" \"imap3-app-token-alice\"\r\n";
    let mut first = TcpStream::connect(addr).await.unwrap();
    let reply = say(&mut first, login, "l1 ").await;
    assert!(reply.contains("l1 OK [CAPABILITY"), "{reply}");
    let reply = say(&mut first, "s1 SELECT Inbox\r\n", "s1 ").await;
    assert!(reply.contains("* 6 EXISTS"), "{reply}");
    // Per-user cap 1: the same account on a second connection is refused.
    let mut second = TcpStream::connect(addr).await.unwrap();
    let reply = say(&mut second, login, "l1 ").await;
    assert!(
        reply.contains("l1 NO Too many connections from this account"),
        "{reply}"
    );
    // Listener cap 2: a third connection is accepted by the OS but queued unserved.
    let mut third = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(400), third.read(&mut buf))
            .await
            .is_err(),
        "a connection beyond IMAP_MAX_CONNS was served"
    );
    drop(second);
    let n = tokio::time::timeout(Duration::from_secs(5), third.read(&mut buf))
        .await
        .expect("queued connection is served once a slot frees")
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("* OK [CAPABILITY"));
    drop((first, third));
    stop.send(true).unwrap();
    task.await.unwrap();
    owner
        .batch_execute(&fixture("session-cleanup.sql"))
        .await
        .unwrap();
}

/// systemd names an unnamed socket after its unit: the existing HTTP socket must
/// keep working now that `LISTEN_FDNAMES` is read.
#[tokio::test]
async fn http_descriptor_named_after_its_unit_is_still_served() {
    let _serial = SERIAL.lock().await;
    use common::{body_bytes, fake_upstream, full, send};
    use hyper::{Request, Response};
    use std::os::fd::AsRawFd;
    let mail = fake_upstream(|_| async { Response::new(full("mail")) }).await;
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let fd = socket.as_raw_fd();
    let mut command = Command::new("bash");
    command
        .env_clear()
        .env("GATEWAY_ENABLED", "false")
        .env("GATEWAY_UPSTREAM", format!("http://{mail}"))
        .env("LISTEN_FDNAMES", "setjoin-gateway")
        .arg("-c")
        .arg("export LISTEN_PID=$$ LISTEN_FDS=1; exec -a gofree-authrt-gateway \"$1\"")
        .arg("gofree-authrt-launcher")
        .arg(env!("CARGO_BIN_EXE_setjoin-gateway"))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            unsafe extern "C" {
                fn dup2(oldfd: i32, newfd: i32) -> i32;
            }
            if dup2(fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    struct Reaped(crate::common::boot::Child);
    impl Drop for Reaped {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _child = Reaped(command.spawn_boot().unwrap());
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        send(addr, Request::get("/").body(full("")).unwrap()),
    )
    .await
    .expect("named HTTP descriptor was not served");
    assert_eq!(body_bytes(response).await, "mail");
}

#[tokio::test]
async fn runtime_revocation_feed_closes_only_the_revoked_imap_principal() {
    let _serial = SERIAL.lock().await;
    use futures_util::FutureExt;
    let db = setjoin_conformance::harness::Db::for_case("AUTHRT-IMAP-revocations").unwrap();
    let owner = db.connect().await.unwrap();
    let root = format!(
        "{}/../../crates/protocols/imap/oracle",
        env!("CARGO_MANIFEST_DIR")
    );
    let cleanup = std::fs::read_to_string(format!("{root}/session-cleanup.sql")).unwrap();
    owner.batch_execute(&cleanup).await.unwrap();
    owner
        .batch_execute(&std::fs::read_to_string(format!("{root}/session-seed.sql")).unwrap())
        .await
        .unwrap();
    let direct = format!(
        "{}{}application_name=gofree-authrt-imap-revocations",
        db.dsn,
        if db.dsn.contains('?') { "&" } else { "?" }
    );
    let listener = listener().await;
    let addr = listener.local_addr().unwrap();
    let runtime = imap_runtime::start(
        Some(listener),
        None,
        &env(&[
            ("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn)),
            ("DB_WORKER_DSN", &db.dsn),
            ("DB_DIRECT_DSN", &direct),
            ("GO_LISTENERS_OFF", "imap"),
        ]),
        gate(),
        hooks(),
    )
    .unwrap()
    .unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(runtime.run(rx));
    let outcome=std::panic::AssertUnwindSafe(async{
  async fn login(addr:std::net::SocketAddr,who:&str)->tokio::io::BufReader<TcpStream>{
   use tokio::io::AsyncBufReadExt;
   let mut socket=tokio::io::BufReader::new(TcpStream::connect(addr).await.unwrap());let mut greeting=String::new();socket.read_line(&mut greeting).await.unwrap();
   socket.write_all(format!("a LOGIN {who}@imap3.test imap3-app-token-{who}\r\n").as_bytes()).await.unwrap();let mut response=String::new();socket.read_line(&mut response).await.unwrap();assert!(response.starts_with("a OK"),"{response}");socket
  }
  let mut alice=login(addr,"alice").await;let mut bob=login(addr,"bob").await;
  tokio::time::timeout(Duration::from_secs(5),async{loop{
   let ready:bool=owner.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-authrt-imap-revocations' AND query LIKE 'LISTEN%')",&[]).await.unwrap().get(0);
   if ready{break}tokio::time::sleep(Duration::from_millis(10)).await;
  }}).await.unwrap();
  owner.batch_execute("INSERT INTO session_revocations(user_id,scope,not_before,reason,expires_at) VALUES(9345011,'all',now()+interval '1 second','authrt',now()+interval '1 hour'); SELECT pg_notify('session_revoke',jsonb_build_object('user_id',9345011,'scope','all','not_before',now()+interval '1 second','expires_at',now()+interval '1 hour')::text)").await.unwrap();
  let mut byte=[0];let count=tokio::time::timeout(Duration::from_secs(5),alice.read(&mut byte)).await.unwrap().unwrap();assert_eq!(count,0,"revoked IMAP connection stayed usable");
  use tokio::io::AsyncBufReadExt;
  bob.write_all(b"b NOOP\r\n").await.unwrap();let mut reply=String::new();tokio::time::timeout(Duration::from_secs(5),bob.read_line(&mut reply)).await.unwrap().unwrap();assert!(reply.starts_with("b OK"),"foreign principal was revoked: {reply}");
 }).catch_unwind().await;
    stop.send(true).unwrap();
    task.await.unwrap();
    owner.batch_execute(&cleanup).await.unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic)
    }
}

#[tokio::test]
async fn runtime_waits_for_first_successful_revocation_snapshot() {
    let _serial = SERIAL.lock().await;
    let db = setjoin_conformance::harness::Db::for_case("AUTHRT-IMAP-cold").unwrap();
    let owner = db.connect().await.unwrap();
    // Force the first worker snapshot to fail, then allow a later retry.
    owner
        .batch_execute("BEGIN; LOCK TABLE session_revocations IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let worker = format!(
        "{}{}options=-c%20statement_timeout%3D100",
        db.dsn,
        if db.dsn.contains('?') { "&" } else { "?" }
    );
    let listener = listener().await;
    let addr = listener.local_addr().unwrap();
    let runtime = imap_runtime::start(
        Some(listener),
        None,
        &env(&[
            ("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn)),
            ("DB_WORKER_DSN", &worker),
            ("DB_DIRECT_DSN", &db.dsn),
            ("GO_LISTENERS_OFF", "imap"),
        ]),
        gate(),
        hooks(),
    )
    .unwrap()
    .unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(runtime.run(rx));
    let mut socket = TcpStream::connect(addr).await.unwrap();
    let mut byte = [0];
    let cold = tokio::time::timeout(Duration::from_millis(500), socket.read_exact(&mut byte)).await;
    owner.batch_execute("ROLLBACK").await.unwrap();
    let warm = tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut byte)).await;
    stop.send(true).unwrap();
    task.await.unwrap();
    assert!(
        cold.is_err(),
        "IMAP served before loading its revocation snapshot: {cold:?}"
    );
    assert!(
        warm.is_ok_and(|r| r.is_ok()),
        "IMAP did not start after snapshot recovery"
    );
}

#[tokio::test]
async fn cold_snapshot_retries_and_shutdown_leave_no_blocked_database_drivers() {
    let _serial = SERIAL.lock().await;
    let db = setjoin_conformance::harness::Db::for_case("AUTHRT-IMAP-cancel-snapshot").unwrap();
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute("BEGIN; LOCK TABLE session_revocations IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let worker = format!(
        "{}{}application_name=gofree-authrt-cold-snapshot",
        db.dsn,
        if db.dsn.contains('?') { "&" } else { "?" }
    );
    let runtime = imap_runtime::start(
        Some(listener().await),
        None,
        &env(&[
            ("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn)),
            ("DB_WORKER_DSN", &worker),
            ("DB_DIRECT_DSN", &db.dsn),
            ("GO_LISTENERS_OFF", "imap"),
        ]),
        gate(),
        hooks(),
    )
    .unwrap()
    .unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(runtime.run(rx));
    let count = || async {
        owner
            .batch_execute("SELECT pg_stat_clear_snapshot()")
            .await
            .unwrap();
        owner.query_one("SELECT count(*)::bigint FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-authrt-cold-snapshot'", &[]).await.unwrap().get::<_,i64>(0)
    };
    let reached = tokio::time::timeout(Duration::from_secs(3), async {
        while count().await == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    // Allow one client timeout and a second attempt while the table stays locked.
    tokio::time::sleep(Duration::from_millis(4500)).await;
    let retry_count = count().await;
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    let cleaned = tokio::time::timeout(Duration::from_secs(5), async {
        while count().await != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok();
    owner.batch_execute("ROLLBACK").await.unwrap();
    assert!(reached.is_ok(), "snapshot fault was never reached");
    assert!(
        retry_count <= 1,
        "timed-out snapshots leaked database drivers: {retry_count}"
    );
    assert!(cleaned, "runtime shutdown left a blocked snapshot driver");
}
