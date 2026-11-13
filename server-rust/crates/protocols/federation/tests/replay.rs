//! The frozen Go federation listener's recorded sessions, replayed byte for
//! byte against the Rust service at its TCP boundary, with the recorded
//! database effects compared per case. No Go participates in replay.
mod common;
use common::*;
use serde_json::Value;
use setjoin_federation::{
    db::{FedDb, WorkerPool},
    flags::Flags,
    log::Logger,
    service::{Config, Service},
};
use setjoin_pg::workers::WorkerDatabase;
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout_at, Instant},
};
use tokio_postgres::Client;
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_util::sync::CancellationToken;

type Conn = TlsStream<TcpStream>;

fn groups(name: &str) -> [bool; 4] {
    [
        name.starts_with("hs_"),
        name.starts_with("chat_")
            || name.starts_with("unknown_")
            || name.starts_with("room_")
            || name.starts_with("eph_")
            || name.starts_with("bad_")
            || name.ends_with("_ignored")
            || name.starts_with("ack_"),
        name.starts_with("out_"),
        name.starts_with("dyn_"),
    ]
}

#[test]
fn every_script_has_one_recorded_session_and_replay_group() {
    use std::collections::BTreeSet;
    let read = |name: &str| -> Value {
        serde_json::from_slice(&std::fs::read(oracle_dir().join(name)).unwrap()).unwrap()
    };
    let requests = read("v2-requests.json");
    let goldens = read("v2-go-sessions.json");
    let mut names = BTreeSet::new();
    let mut recorded = BTreeSet::new();
    for request in requests["cases"].as_array().unwrap() {
        let name = request["name"].as_str().unwrap();
        assert!(names.insert(name.to_string()), "duplicate script {name}");
        assert_eq!(
            groups(name).into_iter().filter(|v| *v).count(),
            1,
            "{name}: replay group"
        );
        let golden = goldens["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["name"] == name)
            .unwrap_or_else(|| panic!("missing Go recording {name}"));
        let steps: Vec<usize> = request["steps"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .filter(|(_, s)| matches!(s["op"].as_str(), Some("read" | "quiet" | "connect_timeout")))
            .map(|(i, _)| i)
            .collect();
        let recorded_steps: Vec<usize> = golden["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["step"].as_u64().unwrap() as usize)
            .collect();
        assert_eq!(steps, recorded_steps, "{name}: missing observation");
    }
    for golden in goldens["cases"].as_array().unwrap() {
        assert!(recorded.insert(golden["name"].as_str().unwrap().to_string()));
    }
    assert_eq!(names, recorded);
    // The stabilized revision retains every original session scenario.
    for old in read("requests.json")["cases"].as_array().unwrap() {
        assert!(names.contains(old["name"].as_str().unwrap()));
    }
}

struct Peer {
    conn: Option<Conn>,
}

async fn dial(
    addr: &str,
    id: &setjoin_federation::trust::Identity,
    wait: Duration,
) -> Option<Conn> {
    let connect = async {
        let tcp = TcpStream::connect(addr).await.ok()?;
        TlsConnector::from(client_config(id))
            .connect(
                rustls_pki_types::ServerName::try_from("zulu.test").unwrap(),
                tcp,
            )
            .await
            .ok()
    };
    tokio::time::timeout(wait, connect).await.ok().flatten()
}

enum Read {
    Frame(String),
    Timeout,
    Eof,
}

async fn read_frame(conn: &mut Conn, deadline: Instant) -> Read {
    let mut hdr = [0u8; 4];
    match timeout_at(deadline, conn.read_exact(&mut hdr)).await {
        Err(_) => return Read::Timeout,
        Ok(Err(_)) => return Read::Eof,
        Ok(Ok(_)) => {}
    }
    let mut body = vec![0u8; u32::from_be_bytes(hdr) as usize];
    match timeout_at(deadline, conn.read_exact(&mut body)).await {
        Err(_) => Read::Timeout,
        Ok(Err(_)) => Read::Eof,
        Ok(Ok(_)) => Read::Frame(String::from_utf8(body).expect("utf-8 server frame")),
    }
}

async fn exec_all(owner: &Client, sql: &str) {
    owner
        .batch_execute(sql)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
}

async fn run_case(
    db: &setjoin_conformance::harness::Db,
    owner: &Client,
    observe: &[(String, String)],
    cleanup: &str,
    req: &Value,
    golden: &Value,
) {
    let name = req["name"].as_str().unwrap();
    exec_all(owner, cleanup).await;
    for s in req["sql"].as_array().unwrap() {
        exec_all(owner, s.as_str().unwrap()).await;
    }
    for a in req["allow"].as_array().unwrap() {
        let pem = ca_pem(a["ca"].as_str().unwrap());
        owner
            .execute(
                "INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled) VALUES ($1,$2,$3,$4)",
                &[&a["domain"].as_str().unwrap(), &pem, &a["scope"].as_str().unwrap(), &a["enabled"].as_bool().unwrap()],
            )
            .await
            .unwrap();
    }
    exec_all(
        owner,
        "UPDATE feature_toggles SET enabled = true WHERE key = 'feature.federation'",
    )
    .await;

    let flag_on = req["flag_initial"].as_bool().unwrap_or(true);
    let flags = Arc::new(AtomicBool::new(flag_on));
    let pool: Arc<dyn FedDb> = Arc::new(WorkerPool::new(WorkerDatabase::new(&db.dsn).unwrap()));
    let mut cfg = Config::new("zulu.test");
    cfg.direct_dsn = Some(db.direct.clone());
    let svc = Service::new(
        cfg,
        pool,
        flags.clone() as Arc<dyn Flags>,
        identity("zulu"),
        Logger::discard(),
    )
    .unwrap();
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    let ctx = CancellationToken::new();
    let run = tokio::spawn(svc.clone().run_with_listener(ctx.clone(), ln));

    let id = identity(req["identity"].as_str().unwrap());
    let mut peers: std::collections::HashMap<usize, Peer> = Default::default();
    let mut results: Vec<Value> = Vec::new();
    let steps = req["steps"].as_array().unwrap();
    for (i, s) in steps.iter().enumerate() {
        let conn_ix = s["conn"].as_u64().unwrap_or(0) as usize;
        let op = s["op"].as_str().unwrap();
        macro_rules! peer {
            () => {{
                if !peers.contains_key(&conn_ix) {
                    let c = dial(&addr, &id, Duration::from_secs(5)).await;
                    peers.insert(conn_ix, Peer { conn: c });
                }
                peers.get_mut(&conn_ix).unwrap()
            }};
        }
        match op {
            "send" | "raw_hex" => {
                let raw = if op == "send" {
                    let b = s["body"].as_str().unwrap().as_bytes();
                    let mut v = (b.len() as u32).to_be_bytes().to_vec();
                    v.extend_from_slice(b);
                    v
                } else {
                    unhex(s["hex"].as_str().unwrap())
                };
                let p = peer!();
                if let Some(c) = p.conn.as_mut() {
                    if tokio::time::timeout(Duration::from_secs(5), c.write_all(&raw))
                        .await
                        .map(|r| r.is_err())
                        .unwrap_or(true)
                    {
                        p.conn = None;
                    }
                }
            }
            "read" | "quiet" => {
                let (n, wait) = if op == "quiet" {
                    (usize::MAX, s["ms"].as_u64().unwrap())
                } else {
                    (
                        s["n"].as_u64().unwrap() as usize,
                        s["timeout_ms"].as_u64().unwrap(),
                    )
                };
                // The recorded window is how long frozen Go waited for the frames it got. A step
                // that records frames waits for exactly those frames, with a generous bound, so a
                // busy host cannot turn a late delivery into a missing one; a step that records
                // none keeps the recorded window (the silence is the assertion).
                let recorded = golden["results"]
                    .as_array()
                    .and_then(|rs| rs.iter().find(|r| r["step"].as_u64() == Some(i as u64)))
                    .and_then(|r| r["frames"].as_array().map(Vec::len))
                    .unwrap_or(0);
                let (n, wait) = if op == "read" && recorded > 0 {
                    (recorded.min(n), wait.max(20_000))
                } else {
                    (n, wait)
                };
                let p = peer!();
                let mut frames = Vec::new();
                let mut eof = p.conn.is_none();
                let deadline = Instant::now() + Duration::from_millis(wait);
                while frames.len() < n && p.conn.is_some() {
                    match read_frame(p.conn.as_mut().unwrap(), deadline).await {
                        Read::Frame(f) => frames.push(f),
                        Read::Timeout => break,
                        Read::Eof => {
                            p.conn = None;
                            eof = true;
                        }
                    }
                }
                let mut r = serde_json::json!({"step": i});
                if !frames.is_empty() {
                    r["frames"] = frames.into();
                }
                if eof || p.conn.is_none() {
                    r["eof"] = true.into();
                }
                results.push(r);
            }
            "sql" => exec_all(owner, s["sql"].as_str().unwrap()).await,
            "sleep" => tokio::time::sleep(Duration::from_millis(s["ms"].as_u64().unwrap())).await,
            "reconnect" => {
                peers.remove(&0);
                tokio::time::sleep(Duration::from_millis(300)).await;
                let c = dial(&addr, &id, Duration::from_secs(5)).await;
                peers.insert(0, Peer { conn: c });
            }
            "open" => {
                peers.remove(&conn_ix);
                let c = dial(&addr, &id, Duration::from_secs(5)).await;
                peers.insert(conn_ix, Peer { conn: c });
            }
            "flag" => {
                flags.store(
                    s["value"].as_bool().unwrap(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                svc.wake();
            }
            "connect_timeout" => {
                let c = dial(&addr, &id, Duration::from_millis(s["ms"].as_u64().unwrap())).await;
                let res = if c.is_some() { "ok" } else { "timeout" };
                peers.insert(0, Peer { conn: c });
                results.push(serde_json::json!({"step": i, "connect": res}));
            }
            other => panic!("{name}: unknown op {other}"),
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(peers);
    tokio::time::sleep(Duration::from_millis(200)).await;
    ctx.cancel();
    tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .unwrap_or_else(|_| panic!("{name}: service did not stop"))
        .unwrap();

    assert_eq!(
        Value::Array(results.clone()),
        golden["results"],
        "{name}: wire transcript differs from frozen Go"
    );
    for (key, sql) in observe {
        let row = owner.query_one(sql.as_str(), &[]).await.unwrap();
        let got: Value = serde_json::from_str(row.get::<_, String>(0).as_str()).unwrap();
        assert_eq!(
            got, golden["observed"][key],
            "{name}: effect `{key}` differs from frozen Go"
        );
    }
}

/// The cases share fixed ids and one database: libtest's parallel threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn replay(filter: impl Fn(&str) -> bool, case: &str, variant: &str) {
    let _serial = SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case(case) else {
        return;
    };
    let dir = oracle_dir();
    let read = |f: &str| std::fs::read_to_string(dir.join(format!("{variant}{f}"))).unwrap();
    let reqs: Value = serde_json::from_str(&read("requests.json")).unwrap();
    let goldens: Value = serde_json::from_str(&read("go-sessions.json")).unwrap();
    let observe: Vec<(String, String)> = serde_json::from_str::<Vec<[String; 2]>>(
        &std::fs::read_to_string(dir.join("observe.json")).unwrap(),
    )
    .unwrap()
    .into_iter()
    .map(|[a, b]| (a, b))
    .collect();
    let cleanup = std::fs::read_to_string(dir.join("cleanup.sql")).unwrap();
    let owner = db.connect().await.unwrap();
    let mut ran = 0;
    let outcome = {
        use futures_util::FutureExt;
        std::panic::AssertUnwindSafe(async {
            for req in reqs["cases"].as_array().unwrap() {
                let name = req["name"].as_str().unwrap();
                if !filter(name) {
                    continue;
                }
                let golden = goldens["cases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|g| g["name"] == name)
                    .unwrap_or_else(|| panic!("{name}: no recorded Go session"));
                run_case(&db, &owner, &observe, &cleanup, req, golden).await;
                ran += 1;
            }
        })
        .catch_unwind()
        .await
    };
    exec_all(&owner, &cleanup).await;
    if let Err(p) = outcome {
        std::panic::resume_unwind(p)
    }
    assert!(ran > 0, "no federation case ran for {case}");
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_sessions_replay_identically() {
    replay(|n| groups(n)[0], "federation_handshake", "v2-").await
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_sessions_replay_identically() {
    replay(|n| groups(n)[1], "federation_inbound", "v2-").await
}

#[tokio::test(flavor = "multi_thread")]
async fn outbound_sessions_replay_identically() {
    replay(|n| groups(n)[2], "federation_outbound", "v2-").await
}

#[tokio::test(flavor = "multi_thread")]
async fn dynamic_sessions_replay_identically() {
    replay(|n| groups(n)[3], "federation_dynamic", "v2-").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn immediate_revocation_survives_slow_initial_notification_connection() {
    let _serial = SERIAL.lock().await;
    use futures_util::FutureExt;
    let Some(mut db) = setjoin_conformance::harness::Db::for_case("federation_slow_listen") else {
        return;
    };
    // Delay the real PostgreSQL connection, rather than a private service
    // method. The protocol transcript and committed effects stay unchanged.
    let mut dsn = url::Url::parse(&db.direct).expect("test direct DSN is a PostgreSQL URL");
    let target = (
        dsn.host_str().unwrap().to_string(),
        dsn.port().unwrap_or(5432),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    dsn.set_host(Some("127.0.0.1")).unwrap();
    dsn.set_port(Some(listener.local_addr().unwrap().port()))
        .unwrap();
    db.direct = dsn.into();
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let proxy = tokio::spawn(async move {
        let mut sockets = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = stop.cancelled() => break,
                connection = listener.accept() => {
                    let (mut downstream, _) = connection.unwrap();
                    let target = target.clone();
                    sockets.spawn(async move {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        let mut upstream = TcpStream::connect(target).await.unwrap();
                        let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                    });
                }
            }
        }
        sockets.abort_all();
        while sockets.join_next().await.is_some() {}
    });
    let read = |name: &str| -> Value {
        serde_json::from_slice(&std::fs::read(oracle_dir().join(name)).unwrap()).unwrap()
    };
    let requests = read("v2-requests.json");
    let goldens = read("v2-go-sessions.json");
    let name = "dyn_evict_on_disable";
    let req = requests["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap();
    let golden = goldens["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap();
    let observe = serde_json::from_slice::<Vec<(String, String)>>(
        &std::fs::read(oracle_dir().join("observe.json")).unwrap(),
    )
    .unwrap();
    let cleanup = std::fs::read_to_string(oracle_dir().join("cleanup.sql")).unwrap();
    let owner = db.connect().await.unwrap();
    let outcome =
        std::panic::AssertUnwindSafe(run_case(&db, &owner, &observe, &cleanup, req, golden))
            .catch_unwind()
            .await;
    cancel.cancel();
    proxy.await.unwrap();
    exec_all(&owner, &cleanup).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
