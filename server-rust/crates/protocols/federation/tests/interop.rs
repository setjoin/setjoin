//! Real Go fedharness peer, both connection roles and bidirectional delivery. Go runs only in the CI image; replay.rs needs no Go at all.
mod common;
use common::*;
use futures_util::FutureExt;
use serde_json::Value;
use setjoin_federation::{
    db::WorkerPool,
    discover::NameServerResolver,
    log::Logger,
    service::{Config, Service},
};
use setjoin_pg::workers::WorkerDatabase;
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_postgres::Client;
use tokio_util::sync::CancellationToken;

const IMAGE: &str = "setjoin-ci-linux-tc:local-amd64";

struct GoPeer {
    name: String,
    child: Option<Child>,
    log: PathBuf,
}
impl Drop for GoPeer {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let result = Command::new("docker")
                .args(["stop", "--time", "5", &self.name])
                .output();
            let _ = child.wait();
            if let Ok(result) = result {
                assert!(result.status.success(), "stop owned {}", self.name);
            }
        }
        if std::thread::panicking() {
            eprintln!(
                "Go peer log: {}",
                std::fs::read_to_string(&self.log).unwrap_or_default()
            );
        }
        let _ = std::fs::remove_file(&self.log);
    }
}

struct BuildDir(PathBuf);
impl Drop for BuildDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn resource_prefix() -> String {
    std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_| "gofree-fed2".into())
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .canonicalize()
        .unwrap()
}
fn free_tcp() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn build_peer() -> BuildDir {
    let dir = BuildDir(std::env::temp_dir().join(format!(
        "{}-peer-{}",
        resource_prefix(),
        std::process::id()
    )));
    std::fs::create_dir(&dir.0).unwrap();
    let cache = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.0.clone())
        .join("go-build");
    std::fs::create_dir_all(&cache).unwrap();
    let name = format!("{}-build-{}", resource_prefix(), std::process::id());
    eprintln!(
        "owned Go build container {name}; temporary output {}",
        dir.0.display()
    );
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--name",
            &name,
            "--label",
            &format!("org.setjoin.task={}", resource_prefix()),
            "--network",
            "host",
            "-v",
            &format!("{}:/src:ro", root().display()),
            "-w",
            "/src/mailserver",
            "-v",
            &gofree_go_mod_mount(),
            "-v",
            &format!("{}:/root/.cache/go-build", cache.display()),
            "-v",
            &format!("{}:/output", dir.0.display()),
            "-e",
            "GOMAXPROCS=2",
            IMAGE,
            "go",
            "build",
            "-p=2",
            "-o",
            "/output/fedharness",
            "./internal/federation/testharness/cmd/fedharness",
        ])
        .output()
        .expect("Docker and the CI image are required for fedharness interop");
    assert!(
        output.status.success(),
        "fedharness build: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    dir
}

struct Ports {
    listen: u16,
    control: u16,
    dns: u16,
    rust: u16,
}

fn start_peer(dir: &BuildDir, domain: &str, peer: &str, ports: &Ports, dsn: &str) -> GoPeer {
    let who = domain.strip_suffix(".test").unwrap();
    let name = format!("{}-interop-{}-{who}", resource_prefix(), std::process::id());
    let log = dir.0.join(format!("{who}.log"));
    let out = std::fs::File::create(&log).unwrap();
    let args = [
        "run".into(),
        "--rm".into(),
        "--name".into(),
        name.clone(),
        "--label".into(),
        format!("org.setjoin.task={}", resource_prefix()),
        "--network".into(),
        "host".into(),
        "-v".into(),
        format!("{}:/src:ro", root().display()),
        "-v".into(),
        format!("{}:/output:ro", dir.0.display()),
        IMAGE.into(),
        "/output/fedharness".into(),
        format!("--local-domain={domain}"),
        format!("--peers={peer}"),
        format!("--listen=127.0.0.1:{}", ports.listen),
        format!("--control=127.0.0.1:{}", ports.control),
        format!("--srv-stub=127.0.0.1:{}", ports.dns),
        format!(
            "--stub-a-records={peer}=localhost:{},{domain}=localhost:{}",
            ports.rust, ports.listen
        ),
        format!("--cert=/src/server-rust/crates/protocols/federation/oracle/certs/{who}.crt"),
        format!("--key=/src/server-rust/crates/protocols/federation/oracle/certs/{who}.key"),
        format!("--db={dsn}"),
        format!("--direct-db={dsn}"),
    ];
    eprintln!("owned interop container {name}");
    let child = Command::new("docker")
        .args(args)
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .spawn()
        .unwrap();
    GoPeer {
        name,
        child: Some(child),
        log,
    }
}

async fn http(port: u16, method: &str, path: &str) -> Result<Value, String> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut c = TcpStream::connect(("127.0.0.1", port))
            .await
            .map_err(|e| e.to_string())?;
        c.write_all(
            format!("{method} {path} HTTP/1.0\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
                .as_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        c.read_to_end(&mut bytes).await.map_err(|e| e.to_string())?;
        let response = String::from_utf8(bytes).map_err(|e| e.to_string())?;
        let (head, body) = response
            .split_once("\r\n\r\n")
            .ok_or_else(|| response.clone())?;
        if !head.starts_with("HTTP/1.0 200") && !head.starts_with("HTTP/1.1 200") {
            return Err(response);
        }
        serde_json::from_str(body).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

async fn wait_cursors(control: u16, peer: &str, n: i64) {
    let mut last = Value::Null;
    for _ in 0..200 {
        if let Ok(v) = http(control, "GET", &format!("/cursors?peer={peer}")).await {
            if v["lastAckedSeq"] == n && v["lastAppliedSeq"] == n {
                return;
            }
            last = v;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("both directions must be durably acked at {n}: {last}");
}
async fn enqueue(owner: &Client, peer: &str, from: i64, to: i64) {
    owner.query("SELECT federation_enqueue($1,'interop-'||g,'application/json','{\"body\":\"Rust to Go <&>\"}'::jsonb) FROM generate_series($2::bigint,$3::bigint) g", &[&peer,&from,&to]).await.unwrap();
}

async fn scenario(
    db: &setjoin_conformance::harness::Db,
    owner: &Client,
    dir: &BuildDir,
    rust_domain: &str,
    go_domain: &str,
) {
    let cleanup = std::fs::read_to_string(oracle_dir().join("cleanup.sql")).unwrap();
    owner.batch_execute(&cleanup).await.unwrap();
    owner
        .batch_execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.federation'")
        .await
        .unwrap();
    for domain in [rust_domain, go_domain] {
        let ca = ca_pem(domain.strip_suffix(".test").unwrap());
        owner.execute("INSERT INTO federation_allowlist(peer_domain,peer_anchor,scope,enabled) VALUES($1,$2,'room',true)", &[&domain,&ca]).await.unwrap();
    }
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rust_port = ln.local_addr().unwrap().port();
    let go_port = free_tcp().port();
    let control = free_tcp().port();
    let dns = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut cfg = Config::new(rust_domain);
    cfg.direct_dsn = Some(db.direct.clone());
    cfg.resolver = Some(Arc::new(NameServerResolver(
        format!("127.0.0.1:{dns}").parse().unwrap(),
    )));
    let service = Service::new(
        cfg,
        Arc::new(WorkerPool::new(WorkerDatabase::new(&db.dsn).unwrap())),
        Arc::new(AtomicBool::new(true)),
        identity(rust_domain.strip_suffix(".test").unwrap()),
        Logger::stderr(),
    )
    .unwrap();
    let ctx = CancellationToken::new();
    let run = tokio::spawn(service.clone().run_with_listener(ctx.clone(), ln));
    let go = start_peer(
        dir,
        go_domain,
        rust_domain,
        &Ports {
            listen: go_port,
            control,
            dns,
            rust: rust_port,
        },
        &db.dsn,
    );
    let mut typing_fixture = None;
    let outcome = std::panic::AssertUnwindSafe(async {
        for _ in 0..200 {
            if http(control, "GET", "/healthz").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        http(control, "GET", "/healthz").await.unwrap();
        // More than the 256-frame window; each side must drain using real acks.
        let r = http(
            control,
            "POST",
            &format!("/enqueue?peer={rust_domain}&n=300&size=200"),
        )
        .await
        .unwrap();
        assert_eq!(r["maxSeq"], 300);
        enqueue(owner, go_domain, 1, 300).await;
        wait_cursors(control, rust_domain, 300).await;
        let inbox = http(control, "GET", &format!("/inbox?peer={rust_domain}"))
            .await
            .unwrap();
        assert_eq!(inbox["count"], 300);
        assert_eq!(inbox["minSeq"], 1);
        assert_eq!(inbox["maxSeq"], 300);
        assert_eq!(inbox["gaps"], Value::Null); // Go's nil gaps slice

        // #418: the actual Go fedharness consumes native typing on both TLS roles.
        // Its canonical reducer must emit the same ephemeral notification as the
        // immutable Go HTTP typing recording, without adding durable messages.
        typing_fixture = Some(setjoin_conformance::fixture::account(owner, "chat4-fed-typing").await.unwrap());
        let recipient = typing_fixture.as_ref().unwrap();
        let to: String = owner.query_one("SELECT email FROM users WHERE id=$1", &[&recipient.user]).await.unwrap().get(0);
        let from = format!("alice@{rust_domain}");
        let channel: i64 = owner.query_one(
            "INSERT INTO chat_channels(kind,visibility,created_by,federated_peer_domain,federated_remote_id,federated_local_key) VALUES('dm','private',$1,$2,$3,encode(digest(least($3::text,$4::text)||':'||greatest($3::text,$4::text),'sha256'),'hex')) RETURNING id",
            &[&recipient.user,&rust_domain,&from,&to]).await.unwrap().get(0);
        owner.execute("INSERT INTO chat_channel_members(channel_id,user_id,role) VALUES($1,$2,'owner')", &[&channel,&recipient.user]).await.unwrap();
        let mut notifications = db.listen(&format!("chat:{}", recipient.user)).await.unwrap();
        service.send_typing(&ctx, &setjoin_federation::service::TypingChannel {
            peer_domain: go_domain.into(), local_user_email: from, remote_id: to,
            ..Default::default()
        }).await;
        let mut seen = Vec::new();
        for _ in 0..100 {
            seen.extend(notifications.drain(owner).await.unwrap());
            if !seen.is_empty() { break }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut actual: Vec<Value> = seen.iter().map(|v|serde_json::from_str(v).unwrap()).collect();
        for event in &mut actual { assert_eq!(event["channelId"], channel); event["channelId"] = "<channel>".into(); }
        let recorded: Value = serde_json::from_str(include_str!("../../../../tests/conformance/chat/goldens/channels-typing-success.json")).unwrap();
        assert_eq!(actual, vec![recorded["observation"]["notify"][0]["payload"].clone()]);
        let after = http(control, "GET", &format!("/inbox?peer={rust_domain}")).await.unwrap();
        assert_eq!(after["count"], 300, "typing must not persist a stanza");
        let queued: i64 = owner.query_one("SELECT count(*) FROM federation_outbox WHERE peer_domain=$1", &[&go_domain]).await.unwrap().get(0);
        assert_eq!(queued, 300, "typing must not create an outbox row");
        owner.execute("DELETE FROM chat_channels WHERE id=$1 AND created_by=$2", &[&channel,&recipient.user]).await.unwrap();
        setjoin_conformance::fixture::remove(owner, &recipient).await.unwrap();
    })
    .catch_unwind()
    .await;
    drop(go);
    ctx.cancel();
    tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .unwrap()
        .unwrap();
    owner.batch_execute(&cleanup).await.unwrap();
    if let Some(recipient) = typing_fixture {
        setjoin_conformance::fixture::remove(owner, &recipient)
            .await
            .unwrap();
    }
    if let Err(p) = outcome {
        std::panic::resume_unwind(p);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fedharness_go_peer_interoperates_with_rust_dialer_and_acceptor() {
    let Some(db) = setjoin_conformance::harness::Db::for_case("federation_fedharness_interop")
    else {
        return;
    };
    let dir = build_peer();
    let owner = db.connect().await.unwrap();
    // One assigned disposable database suffices: peer-domain keys keep the
    // opposite directions separate. No second DB or shared cluster mutation.
    scenario(&db, &owner, &dir, "zulu.test", "alpha.test").await;
    scenario(&db, &owner, &dir, "alpha.test", "zulu.test").await;
}

/// Host Go module cache for the Go recorder container (GOFREE_GO_MOD_CACHE, default $HOME/go/pkg/mod).
#[allow(dead_code)]
fn gofree_go_mod_mount() -> String {
    let host = std::env::var("GOFREE_GO_MOD_CACHE").unwrap_or_else(|_| {
        format!(
            "{}/go/pkg/mod",
            std::env::var("HOME").unwrap_or_else(|_| "/root".into())
        )
    });
    format!("{host}:/root/go/pkg/mod")
}
