//! Federation whole-listener startup seam: systemd's named descriptor is native.
use crate::common::boot::CommandBootExt;
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[test]
fn systemd_names_select_federation_separately_from_http_and_imap() {
    let slots =
        setjoin_gateway::activation::plan(5, Some("http:imap:imaps:acme:federation")).unwrap();
    assert_eq!(
        format!("{slots:?}"),
        "[Http, Imap, Imaps, Acme, Federation]"
    );
    assert!(setjoin_gateway::activation::plan(2, Some("federation:federation")).is_err());
}

use setjoin_federation::{
    stream::{dial, PeerEndpoint},
    trust::{Anchor, Identity},
    wire::{Frame, Hello},
};
use std::{
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Command, Stdio},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
fn resource_prefix() -> String {
    std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_| "gofree-fed2".into())
}
fn oracle() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/protocols/federation/oracle")
}
fn identity(name: &str) -> Identity {
    Identity::load(
        oracle().join(format!("certs/{name}.crt")).to_str().unwrap(),
        oracle().join(format!("certs/{name}.key")).to_str().unwrap(),
    )
    .unwrap()
}
fn anchor(name: &str) -> String {
    std::fs::read_to_string(oracle().join(format!("certs/ca-{name}.crt"))).unwrap()
}
struct Process(crate::common::boot::Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn assert_running(process: &mut Process, reason: &str) {
    if let Some(status) = process.0.try_wait().unwrap() {
        use std::io::Read;
        let mut stderr = String::new();
        if let Some(mut pipe) = process.0.stderr.take() {
            pipe.read_to_string(&mut stderr).unwrap();
        }
        panic!("{reason}: {status}; {stderr}");
    }
}
fn launch(
    db: &setjoin_conformance::harness::Db,
    off: &str,
    worker: &str,
) -> (Process, std::net::SocketAddr) {
    let (process, federation, _) = launch_configured(db, off, worker, &db.direct, true, &db.dsn);
    (process, federation)
}
fn launch_configured(
    db: &setjoin_conformance::harness::Db,
    off: &str,
    worker: &str,
    direct: &str,
    with_federation: bool,
    worker_dsn: &str,
) -> (Process, std::net::SocketAddr, std::net::SocketAddr) {
    let count = if with_federation { 2 } else { 1 };
    let sockets: Vec<_> = (0..count)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let http = sockets[0].local_addr().unwrap();
    let address = sockets.last().unwrap().local_addr().unwrap();
    let fds: Vec<_> = sockets.iter().map(|s| s.as_raw_fd()).collect();
    let mut command = Command::new("bash");
    command
        .env_clear()
        .env("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:9")
        .env("DB_DSN", &db.dsn)
        .env("DB_WORKER_DSN", worker_dsn)
        .env("DB_DIRECT_DSN", direct)
        .env("GO_WORKERS_OFF", off)
        .env("RUST_WORKERS_ON", worker)
        .env("FEDERATION_LOCAL_DOMAIN", "zulu.test")
        .env("FEDERATION_CERT", oracle().join("certs/zulu.crt"))
        .env("FEDERATION_KEY", oracle().join("certs/zulu.key"))
        .env(
            "LISTEN_FDNAMES",
            if with_federation {
                "http:federation"
            } else {
                "http"
            },
        )
        .env("LISTEN_FDS", count.to_string())
        .arg("-c")
        .arg("export LISTEN_PID=$$; exec -a \"$2-gateway\" \"$1\"")
        .arg("gofree-fed2-launcher")
        .arg(env!("CARGO_BIN_EXE_setjoin-gateway"))
        .arg(resource_prefix())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            for (i, fd) in fds.iter().enumerate() {
                if libc::dup2(*fd, 100 + i as i32) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            for i in 0..count {
                if libc::dup2(100 + i, 3 + i) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(100 + i);
            }
            Ok(())
        });
    }
    (Process(command.spawn_boot().unwrap()), address, http)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executable_uses_inherited_socket_for_recorded_delivery_and_graceful_shutdown() {
    let _serial = SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case("federation-activated") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute(&std::fs::read_to_string(oracle().join("cleanup.sql")).unwrap())
        .await
        .unwrap();
    let prior: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.federation'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=true WHERE key='feature.federation'",
            &[],
        )
        .await
        .unwrap();
    owner.execute("INSERT INTO federation_allowlist(peer_domain,peer_anchor,enabled) VALUES('alpha.test',$1,true)",&[&anchor("alpha")]).await.unwrap();
    let (mut process, address) = launch(&db, "federation-service", "");
    let ctx = CancellationToken::new();
    let outcome = std::panic::AssertUnwindSafe(async {
        let endpoint = PeerEndpoint {
            domain: "zulu.test".into(),
            target: "127.0.0.1".into(),
            port: address.port(),
        };
        let peer = tokio::time::timeout(
            Duration::from_secs(15),
            dial(
                &ctx,
                &std::sync::atomic::AtomicBool::new(true),
                &endpoint,
                &identity("alpha"),
                Anchor::from_pem(&anchor("zulu")).unwrap(),
                &Hello::new("alpha.test"),
                Duration::from_secs(10),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        // Reuse immutable frozen-Go transcript inputs and expected wire frames.
        let requests: serde_json::Value =
            serde_json::from_slice(&std::fs::read(oracle().join("v2-requests.json")).unwrap())
                .unwrap();
        let recordings: serde_json::Value =
            serde_json::from_slice(&std::fs::read(oracle().join("v2-go-sessions.json")).unwrap())
                .unwrap();
        let case = requests["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "unknown_content_type_redacted")
            .unwrap();
        let golden = recordings["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == case["name"])
            .unwrap();
        peer.write_frame(
            &Frame::decode(case["steps"][2]["body"].as_str().unwrap().as_bytes()).unwrap(),
        )
        .await
        .unwrap();
        let ack = tokio::time::timeout(Duration::from_secs(5), peer.read_frame())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            String::from_utf8(ack.encode()).unwrap(),
            golden["results"][1]["frames"][0].as_str().unwrap()
        );
        unsafe {
            libc::kill(process.0.id() as i32, libc::SIGTERM);
        }
        assert!(
            tokio::time::timeout(Duration::from_secs(5), peer.read_frame())
                .await
                .unwrap()
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = process.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    });
    use futures_util::FutureExt;
    let result = outcome.catch_unwind().await;
    drop(process);
    ctx.cancel();
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.federation'",
            &[&prior],
        )
        .await
        .unwrap();
    owner
        .batch_execute(&std::fs::read_to_string(oracle().join("cleanup.sql")).unwrap())
        .await
        .unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic)
    }
}

#[tokio::test]
async fn executable_refuses_a_duplicate_worker_and_a_duplicate_federation_service() {
    let _serial = SERIAL.lock().await;
    use std::io::Read;
    let Some(db) = setjoin_conformance::harness::Db::for_case("federation-startup-guards") else {
        return;
    };
    for (off, worker, needle) in [
        ("", "", "GO_WORKERS_OFF=federation-service"),
        (
            "federation-service",
            "federation-residue-reap",
            "GO_WORKERS_OFF=federation-residue-reap",
        ),
    ] {
        let (mut child, _) = launch(&db, off, worker);
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    assert!(!status.success());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let mut stderr = String::new();
        child
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(stderr.contains(needle), "{stderr}");
    }
}

mod common;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_http_typing_crosses_native_peer_once_and_denies_foreign_users(
) -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
    use std::sync::Arc;
    let Some(db) = setjoin_conformance::harness::Db::for_case("federation-http-typing") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    owner
        .batch_execute(&std::fs::read_to_string(oracle().join("cleanup.sql"))?)
        .await?;
    let old_chat: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.chat'",
            &[],
        )
        .await?
        .get(0);
    let old_fed: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.federation'",
            &[],
        )
        .await?
        .get(0);
    owner.execute("UPDATE feature_toggles SET enabled=true WHERE key IN ('feature.chat','feature.federation')",&[]).await?;
    owner.execute("INSERT INTO federation_allowlist(peer_domain,peer_anchor,enabled) VALUES('alpha.test',$1,true)",&[&anchor("alpha")]).await?;
    let account = setjoin_conformance::fixture::account(&owner, "fed2-typing").await?;
    let foreign = setjoin_conformance::fixture::account(&owner, "fed2-foreign").await?;
    let channel:i64=owner.query_one("INSERT INTO chat_channels(kind,visibility,created_by,federated_peer_domain,federated_remote_id) VALUES('dm','private',$1,'alpha.test','bob@alpha.test') RETURNING id",&[&account.user]).await?.get(0);
    owner
        .execute(
            "INSERT INTO chat_channel_members(channel_id,user_id,role) VALUES($1,$2,'owner')",
            &[&channel, &account.user],
        )
        .await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let cert = oracle().join("certs/zulu.crt");
    let key = oracle().join("certs/zulu.key");
    let get = |name: &str| match name {
        "FEDERATION_LOCAL_DOMAIN" => Some("zulu.test".into()),
        "FEDERATION_CERT" => Some(cert.to_str().unwrap().into()),
        "FEDERATION_KEY" => Some(key.to_str().unwrap().into()),
        "DB_DSN" => Some(db.dsn.clone()),
        "DB_DIRECT_DSN" => Some(db.direct.clone()),
        "GO_WORKERS_OFF" => Some("federation-service".into()),
        _ => None,
    };
    let runtime = setjoin_federation::runtime::Runtime::prepare(Some(listener), &get)?.unwrap();
    let typing = Arc::new(setjoin_gateway::federation_typing::Typing::new(
        runtime.service.clone(),
    ));
    let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?;
    let adapter = setjoin_gateway::chat_channels::ChannelRoute {
        unfurl: None,
        exec,
        keys: Arc::new(common::recovery_keys()),
        issuer: "mailserver".into(),
        federation_local_domain: "zulu.test".into(),
        federation_typing: Some(typing),
    };
    let gateway = Gateway::new(
        Config {
            upstream: None,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: Duration::from_secs(10),
            edge_limit: None,
        },
        RouteTable::proxy_all().with(adapter),
    )?;
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let http_addr = http.local_addr()?;
    let http_task = tokio::spawn(gateway.serve(http));
    let ctx = CancellationToken::new();
    let fed_task = tokio::spawn(runtime.run(ctx.clone()));
    use futures_util::FutureExt;
    let result = std::panic::AssertUnwindSafe(async {
        let endpoint = PeerEndpoint {
            domain: "zulu.test".into(),
            target: "127.0.0.1".into(),
            port: address.port(),
        };
        let peer = tokio::time::timeout(
            Duration::from_secs(10),
            dial(
                &ctx,
                &std::sync::atomic::AtomicBool::new(true),
                &endpoint,
                &identity("alpha"),
                Anchor::from_pem(&anchor("zulu"))?,
                &Hello::new("alpha.test"),
                Duration::from_secs(5),
            ),
        )
        .await??;
        let request = |user| {
            hyper::Request::post(format!("/api/chat/channels/{channel}/typing"))
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header(
                    "authorization",
                    format!(
                        "Bearer {}",
                        common::recovery_token_with(
                            user,
                            serde_json::json!({"email":"alice@zulu.test"})
                        )
                    ),
                )
                .body(common::full(""))
        };
        let response = common::send(http_addr, request(foreign.user)?).await;
        assert_eq!(response.status(), 403);
        assert!(
            tokio::time::timeout(Duration::from_millis(150), peer.read_frame())
                .await
                .is_err()
        );
        // Go stamps even a refused signal before the reducer, so let that stamp expire.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let response = common::send(http_addr, request(account.user)?).await;
        assert_eq!(response.status(), 204);
        let frame = tokio::time::timeout(Duration::from_secs(5), peer.read_frame()).await??;
        let golden: serde_json::Value =
            serde_json::from_slice(&std::fs::read(oracle().join("typing-go.json"))?)?;
        assert_eq!(
            String::from_utf8(frame.encode())?,
            golden["frames"]["dm"].as_str().unwrap()
        );
        let response = common::send(http_addr, request(account.user)?).await;
        assert_eq!(response.status(), 204);
        assert!(
            tokio::time::timeout(Duration::from_millis(250), peer.read_frame())
                .await
                .is_err()
        );
        let outbox: i64 = owner
            .query_one(
                "SELECT count(*) FROM federation_outbox WHERE peer_domain='alpha.test'",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(outbox, 0);
        Ok::<_, common::BoxError>(())
    })
    .catch_unwind()
    .await;
    http_task.abort();
    let _ = http_task.await;
    ctx.cancel();
    fed_task.await?;
    owner
        .execute("DELETE FROM chat_channels WHERE id=$1", &[&channel])
        .await?;
    common::remove_blob_account(&owner, &account).await?;
    common::remove_blob_account(&owner, &foreign).await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.chat'",
            &[&old_chat],
        )
        .await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.federation'",
            &[&old_fed],
        )
        .await?;
    owner
        .batch_execute(&std::fs::read_to_string(oracle().join("cleanup.sql"))?)
        .await?;
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test]
async fn residue_worker_runs_without_peering_configuration_and_matches_go_effects() {
    let _serial = SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case("fed2-independent-reaper") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute(&std::fs::read_to_string(oracle().join("reap-seed.sql")).unwrap())
        .await
        .unwrap();
    let mut command = Command::new("bash");
    command
        .env_clear()
        .env("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:9")
        .env("GATEWAY_LISTEN", "127.0.0.1:0")
        .env("DB_DIRECT_DSN", &db.direct)
        .env("DB_DSN", &db.dsn)
        .env("RUST_WORKERS_ON", "federation-residue-reap")
        .env("GO_WORKERS_OFF", "federation-residue-reap")
        .arg("-c")
        .arg("exec -a \"$2-reaper\" \"$1\"")
        .arg("gofree-fed2-launcher")
        .arg(env!("CARGO_BIN_EXE_setjoin-gateway"))
        .arg(resource_prefix())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut process = Process(command.spawn_boot().unwrap());
    use futures_util::FutureExt;
    let result = std::panic::AssertUnwindSafe(async {
        let sql = format!(
            "{}::text",
            std::fs::read_to_string(oracle().join("reap-observe.sql"))
                .unwrap()
                .trim()
                .trim_end_matches(';')
        );
        let golden: serde_json::Value =
            serde_json::from_slice(&std::fs::read(oracle().join("reap-go.json")).unwrap()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let raw: String = owner.query_one(&sql, &[]).await.unwrap().get(0);
                if serde_json::from_str::<serde_json::Value>(&raw).unwrap() == golden["after"] {
                    break;
                }
                assert_running(
                    &mut process,
                    "worker process exited before its initial tick",
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        unsafe {
            libc::kill(process.0.id() as i32, libc::SIGTERM);
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = process.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    })
    .catch_unwind()
    .await;
    drop(process);
    owner
        .batch_execute(&std::fs::read_to_string(oracle().join("reap-cleanup.sql")).unwrap())
        .await
        .unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_notification_outage_serves_http_and_starts_dormant_federation_with_logged_retries()
{
    let _serial = SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case("fed2-initial-notify-outage") else {
        return;
    };
    let (mut process, federation, http) = launch_configured(
        &db,
        "federation-service",
        "",
        "postgres://nobody@127.0.0.1:9/none",
        true,
        &db.dsn,
    );
    assert_http_healthy(&mut process, http).await;
    // The feature is OFF until an authoritative post-LISTEN snapshot exists.
    let ctx = CancellationToken::new();
    let endpoint = PeerEndpoint {
        domain: "zulu.test".into(),
        target: "127.0.0.1".into(),
        port: federation.port(),
    };
    assert!(tokio::time::timeout(
        Duration::from_millis(1300),
        dial(
            &ctx,
            &std::sync::atomic::AtomicBool::new(true),
            &endpoint,
            &identity("alpha"),
            Anchor::from_pem(&anchor("zulu")).unwrap(),
            &Hello::new("alpha.test"),
            Duration::from_secs(5),
        ),
    )
    .await
    .is_err());
    ctx.cancel();
    let stderr = stop_and_read_logs(&mut process);
    assert!(stderr.contains("federation: service starting"), "{stderr}");
    assert!(
        stderr
            .matches("Warn federation: subscribe config_changed failed")
            .count()
            >= 2,
        "{stderr}"
    );
    assert!(stderr.contains("retry_in="), "{stderr}");
}

async fn assert_http_healthy(process: &mut Process, address: std::net::SocketAddr) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert_running(process, "gateway exited before health probe");
            if let Ok(response) = reqwest::get(format!("http://{address}/_gateway/healthz")).await {
                assert_eq!(response.status(), 200);
                assert_eq!(response.text().await.unwrap(), "ok\n");
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}
fn stop_and_read_logs(process: &mut Process) -> String {
    use std::io::Read;
    process.0.kill().unwrap();
    process.0.wait().unwrap();
    let mut stderr = String::new();
    process
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    stderr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_federation_socket_keeps_http_available_and_logs_the_disabled_leg() {
    let _serial = SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case("fed2-missing-socket") else {
        return;
    };
    let (mut process, _, http) =
        launch_configured(&db, "federation-service", "", &db.direct, false, &db.dsn);
    assert_http_healthy(&mut process, http).await;
    let stderr = stop_and_read_logs(&mut process);
    assert!(
        stderr.contains(
            "Error federation: activated socket named federation missing — service not started"
        ),
        "{stderr}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_first_feature_snapshot_starts_outbound_reconcile_without_waiting_for_the_ticker() {
    let _serial = SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case("fed2-initial-feature-snapshot")
    else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let prior: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.federation'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=true WHERE key='feature.federation'",
            &[],
        )
        .await
        .unwrap();
    owner.execute("INSERT INTO federation_allowlist(peer_domain,peer_anchor,enabled) VALUES('zz-fed2.invalid',$1,true)", &[&anchor("alpha")]).await.unwrap();
    // Gate only the federation worker's initial snapshot. The shared HTTP
    // basic/runtime gates must still read public.feature_toggles at startup.
    let schema = format!("gofree_chat4_delayed_{}", std::process::id());
    let gate = 418_347_020_001i64;
    eprintln!("owned delayed-snapshot schema {schema}, advisory gate {gate}; assigned DB only");
    owner.batch_execute(&format!("CREATE SCHEMA {schema}; CREATE VIEW {schema}.feature_toggles AS SELECT f.* FROM public.feature_toggles f CROSS JOIN pg_advisory_xact_lock({gate}) AS held")).await.unwrap();
    owner
        .query_one("SELECT pg_advisory_lock($1)", &[&gate])
        .await
        .unwrap();
    let separator = if db.dsn.contains('?') { '&' } else { '?' };
    let worker_dsn = format!(
        "{}{separator}options=-csearch_path%3D{schema}%2Cpublic",
        db.dsn
    );
    let (mut process, _, http) =
        launch_configured(&db, "federation-service", "", &db.direct, true, &worker_dsn);
    use futures_util::FutureExt;
    let result = std::panic::AssertUnwindSafe(async {
        assert_http_healthy(&mut process, http).await;
        tokio::time::timeout(Duration::from_secs(2),async {
            loop {
                let waiting:bool=owner.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT granted AND classid::bigint=$1 AND objid::bigint=$2)",&[&(gate>>32),&(gate & 0xffff_ffff)]).await.unwrap().get(0);
                if waiting {break}
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.expect("the actual federation snapshot must reach the advisory barrier");
        tokio::time::sleep(Duration::from_millis(300)).await;
        owner.query_one("SELECT pg_advisory_unlock($1)",&[&gate]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let stderr = stop_and_read_logs(&mut process);
        assert!(
            stderr.contains("federation: reconcile: started dial loop peer=zz-fed2.invalid"),
            "{stderr}"
        );
    })
    .catch_unwind()
    .await;
    drop(process);
    owner
        .query_one("SELECT pg_advisory_unlock($1)", &[&gate])
        .await
        .unwrap();
    owner
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    owner
        .execute(
            "DELETE FROM federation_allowlist WHERE peer_domain='zz-fed2.invalid'",
            &[],
        )
        .await
        .unwrap();
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.federation'",
            &[&prior],
        )
        .await
        .unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
