//! Frozen-Go seed + one tick, including actual remote SMTP wire receipts.
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::future::BoxFuture;
use serde_json::{json, Value};
use setjoin_pg::workers::WorkerDatabase;
use setjoin_smtp::outbound::{Network, OutboundWorker, RawSource};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{watch, Mutex},
    task::JoinSet,
};

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
type BoxStream = Box<dyn Stream>;
fn tls_server(case: &Value) -> Arc<tokio_rustls::rustls::ServerConfig> {
    use tokio_rustls::rustls::{
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
        ServerConfig,
    };
    // `cert` selects a DANE fixture (secure-behaviour cases); absent means the LDAP fixture.
    let (chain, key): (Vec<&[u8]>, &[u8]) = match case["cert"].as_str() {
        Some("self") => (
            vec![include_bytes!("../../oracle/dane-fixture/self-leaf.pem")],
            include_bytes!("../../oracle/dane-fixture/self-leaf.p8"),
        ),
        Some("ta-chain") => (
            vec![include_bytes!("../../oracle/dane-fixture/ta-chain.pem")],
            include_bytes!("../../oracle/dane-fixture/ta-leaf.p8"),
        ),
        Some("rogue-with-ta-extra") => (
            vec![
                include_bytes!("../../oracle/dane-fixture/rogue-leaf.pem"),
                include_bytes!("../../oracle/dane-fixture/ta-ca.pem"),
            ],
            include_bytes!("../../oracle/dane-fixture/rogue-leaf.p8"),
        ),
        _ => (
            vec![include_bytes!(
                "../../../../../tests/conformance/directory-sync/ldap-fixture/server.pem"
            )],
            include_bytes!(
                "../../../../../tests/conformance/directory-sync/ldap-fixture/server.p8"
            ),
        ),
    };
    let cert = chain
        .iter()
        .flat_map(|pem| CertificateDer::pem_slice_iter(pem))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key).unwrap();
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert, key)
            .unwrap(),
    )
}
struct NoBlobs;
impl RawSource for NoBlobs {
    fn get<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<Vec<u8>, String>> {
        Box::pin(async { panic!("inline fixture must not fetch a blob") })
    }
}
struct Peers {
    mx: Value,
    addresses: HashMap<String, std::net::SocketAddr>,
}
impl Network for Peers {
    fn mx<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Result<Vec<String>, String>> {
        Box::pin(async move {
            Ok(self.mx[domain]
                .as_array()
                .map(|v| v.iter().map(|s| s.as_str().unwrap().to_owned()).collect())
                .unwrap_or_default())
        })
    }
    fn connect<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<TcpStream, String>> {
        Box::pin(async move {
            TcpStream::connect(self.addresses[host])
                .await
                .map_err(|e| e.to_string())
        })
    }
}
pub async fn replay(corpus: &str, name: &str) {
    replay_with(corpus, name, None, &|worker, _| worker).await
}
pub type SourceFactory = dyn Fn(std::net::SocketAddr) -> Arc<dyn RawSource> + Send + Sync;
pub async fn replay_with(
    corpus: &str,
    name: &str,
    source: Option<&SourceFactory>,
    configure: &(dyn Fn(OutboundWorker, &Value) -> OutboundWorker + Sync),
) {
    replay_fixture(corpus, name, source, configure, "").await
}
/// Database-boundary faults qualify the observer; no product mutant switches.
#[allow(dead_code)] // Also compiled by the gateway's independent native-store replay.
pub async fn replay_mutant(corpus: &str, name: &str, install: &str) {
    replay_fixture(corpus, name, None, &|worker, _| worker, install).await
}
async fn replay_fixture(
    corpus: &str,
    name: &str,
    source: Option<&SourceFactory>,
    configure: &(dyn Fn(OutboundWorker, &Value) -> OutboundWorker + Sync),
    install: &str,
) {
    let _serial = SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case("smtp3-outbound") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let corpus: Value = serde_json::from_str(corpus).unwrap();
    let recorded = corpus
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["case"]["name"] == name)
        .expect("recorded case");
    let case = &recorded["case"];
    owner
        .batch_execute(include_str!("../../oracle/outbound-cleanup.sql"))
        .await
        .unwrap();
    owner
        .batch_execute(include_str!("../../oracle/seed.sql"))
        .await
        .unwrap();
    owner
        .batch_execute(case["sql"].as_str().unwrap())
        .await
        .unwrap();
    owner.batch_execute(install).await.unwrap();
    let mut admin = if case["backlog"] == true {
        Some(
            setjoin_pg::workers::DirectListener::connect(
                &std::env::var("DB_DIRECT_DSN").expect("direct listener DSN"),
                "admin:alert",
            )
            .await
            .unwrap(),
        )
    } else {
        None
    };
    let receipts = Arc::new(Mutex::new(Vec::<Value>::new()));
    let (stop, rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    let s3 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s3_addr = s3.local_addr().unwrap();
    let blob_requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let s3_seen = blob_requests.clone();
    let objects = case["blobs"].clone();
    let extra_headers = case["blob_headers"]
        .as_object()
        .map(|map| {
            map.iter()
                .map(|(key, value)| format!("{key}: {}\r\n", value.as_str().unwrap()))
                .collect::<String>()
        })
        .unwrap_or_default();
    let mut s3_stop = rx.clone();
    tasks.spawn(async move {
        loop {
            let socket = tokio::select! {
                _ = s3_stop.changed() => break,
                accepted = s3.accept() => accepted.unwrap().0,
            };
            serve_object(socket, &objects, &extra_headers, &s3_seen).await;
        }
    });

    let mut addresses = HashMap::new();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let gate = Arc::new(tokio::sync::Notify::new());
    for hosts in case["mx"].as_object().unwrap().values() {
        for host in hosts.as_array().unwrap() {
            let host = host.as_str().unwrap().to_owned();
            if addresses.contains_key(&host) {
                continue;
            }
            let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
            addresses.insert(host.clone(), ln.local_addr().unwrap());
            let mut rx = rx.clone();
            let accepted_count = accepted.clone();
            let gate = gate.clone();
            let case = case.clone();
            let receipts = receipts.clone();
            tasks.spawn(async move {
                let mut sessions = JoinSet::new();
                loop {
                    let socket = tokio::select! {
                        _ = rx.changed() => break,
                        accepted = ln.accept() => accepted.unwrap().0,
                    };
                    let count =
                        accepted_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    if count == case["barrier"].as_u64().unwrap_or(0) as usize {
                        gate.notify_waiters();
                    }
                    sessions.spawn(serve_mta(
                        socket,
                        host.clone(),
                        case.clone(),
                        receipts.clone(),
                        accepted_count.clone(),
                        gate.clone(),
                    ));
                }
                while let Some(result) = sessions.join_next().await {
                    result.unwrap();
                }
            });
        }
    }
    let worker = OutboundWorker::new(
        WorkerDatabase::new(&db.dsn).unwrap(),
        source
            .map(|factory| factory(s3_addr))
            .unwrap_or_else(|| Arc::new(NoBlobs)),
        Arc::new(Peers {
            mx: case["mx"].clone(),
            addresses,
        }),
        "fixture.local".into(),
    );
    let worker = if case["tls"] == true {
        use tokio_rustls::rustls::pki_types::{pem::PemObject, CertificateDer};
        let anchors = match case["roots"].as_array() {
            // Secure-behaviour cases name their own PKIX anchors ("" is the LDAP CA).
            Some(names) => names
                .iter()
                .map(|n| match n.as_str().unwrap() {
                    "ta-ca.pem" => &include_bytes!("../../oracle/dane-fixture/ta-ca.pem")[..],
                    "rogue-ca.pem" => &include_bytes!("../../oracle/dane-fixture/rogue-ca.pem")[..],
                    other => panic!("unknown anchor {other}"),
                })
                .map(|pem| CertificateDer::from_pem_slice(pem).unwrap())
                .collect(),
            None => vec![CertificateDer::from_pem_slice(include_bytes!(
                "../../../../../tests/conformance/directory-sync/ldap-fixture/ca.pem"
            ))
            .unwrap()],
        };
        worker.with_tls_roots(anchors)
    } else {
        worker
    };
    let worker = if let Some(ms) = case["timeout_ms"].as_u64().filter(|ms| *ms > 0) {
        worker.with_timeouts(setjoin_smtp::outbound::Timeouts {
            command: std::time::Duration::from_millis(ms),
            data: std::time::Duration::from_millis(case["data_timeout_ms"].as_u64().unwrap()),
            ..Default::default()
        })
    } else {
        worker
    };
    let worker = configure(worker, case);
    for tick in 0..case["ticks"].as_u64().unwrap_or(0).max(1) {
        worker.tick().await.unwrap();
        if let Some(sql) = case["between_ticks_sql"]
            .get(tick as usize)
            .and_then(Value::as_str)
        {
            owner.batch_execute(sql).await.unwrap();
        }
    }
    worker.close().await;
    stop.send(true).unwrap();
    while let Some(r) = tasks.join_next().await {
        r.unwrap()
    }
    let mut alerts = Vec::new();
    if let Some(mut listener) = admin.take() {
        while let Ok(Some(notification)) =
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.recv()).await
        {
            alerts.push(notification.payload().to_owned());
        }
        listener.close().await.unwrap();
    }
    let observe = if case["observe_file"] == "transport-report-observe.sql" {
        include_str!("../../oracle/transport-report-observe.sql")
    } else if case["observe_file"] == "transport-observe.sql" {
        include_str!("../../oracle/transport-observe.sql")
    } else if case["observe_file"] == "outbound-backlog-observe.sql" {
        include_str!("../../oracle/outbound-backlog-observe.sql")
    } else {
        include_str!("../../oracle/outbound-observe.sql")
    };
    let observation_sql = format!("SELECT ({})::text", observe.trim().trim_end_matches(';'));
    let observed: Value = serde_json::from_str(
        &owner
            .query_one(&observation_sql, &[])
            .await
            .unwrap()
            .get::<_, String>(0),
    )
    .unwrap();
    let mut actual = receipts.lock().await.clone();
    actual.sort_by_key(Value::to_string);
    let mut expected = recorded["receipts"].as_array().unwrap().clone();
    expected.sort_by_key(Value::to_string);
    if let Some(sql) = case["teardown_sql"].as_str().filter(|s| !s.is_empty()) {
        owner.batch_execute(sql).await.unwrap();
    }
    owner
        .batch_execute(include_str!("../../oracle/outbound-cleanup.sql"))
        .await
        .unwrap();
    if case["backlog"] == true {
        let expected = recorded["admin_alerts"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .map(|x| x.as_str().unwrap().to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        assert_eq!(alerts, expected, "{name}: admin backlog alerts");
    }
    assert_eq!(actual, expected, "{name}: remote SMTP wire");
    assert_eq!(
        *blob_requests.lock().await,
        recorded["blob_requests"]
            .as_array()
            .map(|v| v
                .iter()
                .map(|x| x.as_str().unwrap().to_owned())
                .collect::<Vec<_>>())
            .unwrap_or_default(),
        "{name}: object-store I/O"
    );
    fn normalize(value: &mut Value) {
        match value {
            Value::String(s) => {
                if let (Some(start), Some(end)) = (s.find(" tcp "), s.find(": i/o timeout")) {
                    if start < end {
                        s.replace_range(start + 1..end, "tcp <local>-><peer>");
                    }
                }
            }
            Value::Array(v) => {
                for x in v {
                    normalize(x)
                }
            }
            Value::Object(v) => {
                for x in v.values_mut() {
                    normalize(x)
                }
            }
            _ => {}
        }
    }
    let mut observed = observed;
    normalize(&mut observed);
    let mut expected_effects = recorded["effects"].clone();
    for value in [&mut observed, &mut expected_effects] {
        value["traces"]
            .as_array_mut()
            .unwrap()
            .sort_by_key(Value::to_string)
    }
    assert_eq!(observed, expected_effects, "{name}: committed effects");
}

// Go's httptest handler records URL.Path, after percent decoding, rather than
// RequestURI. Keep that same object-key observation boundary in the Rust peer.
fn decoded_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut output = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(a), Some(b)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                output.push((a * 16 + b) as u8);
                i += 3;
                continue;
            }
        }
        output.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(output).unwrap()
}

async fn serve_object(
    socket: TcpStream,
    objects: &Value,
    headers: &str,
    seen: &Mutex<Vec<String>>,
) {
    let mut io = BufReader::new(socket);
    let mut first = String::new();
    io.read_line(&mut first).await.unwrap();
    loop {
        let mut line = String::new();
        assert!(io.read_line(&mut line).await.unwrap() > 0);
        if line == "\r\n" {
            break;
        }
    }
    let parts = first.split_whitespace().collect::<Vec<_>>();
    let path = decoded_path(parts[1].split('?').next().unwrap());
    seen.lock().await.push(format!("{} {path}", parts[0]));
    let key = path.strip_prefix("/mail/").unwrap();
    let (status, body) = if let Some(encoded) = objects[key].as_str() {
        ("200 OK", STANDARD.decode(encoded).unwrap())
    } else {
        ("404 Not Found", b"<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Resource>/mail/missing</Resource><RequestId>smtp3</RequestId></Error>".to_vec())
    };
    io.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nETag: \"smtp3\"\r\n{headers}Connection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
    io.write_all(&body).await.unwrap();
}
async fn serve_mta(
    socket: TcpStream,
    host: String,
    case: Value,
    receipts: Arc<Mutex<Vec<Value>>>,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
    gate: Arc<tokio::sync::Notify>,
) {
    let mut io = BufReader::new(Box::new(socket) as BoxStream);
    let mut commands = vec![];
    let mut data = vec![];
    let default = |key: &str, value: &str| {
        case[key]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(value)
            .to_owned()
    };
    if case["hang_at"] != "greeting" {
        io.write_all(format!("{}\r\n", default("greeting", "220 fake ready")).as_bytes())
            .await
            .unwrap();
    }
    loop {
        let mut line = String::new();
        if !matches!(io.read_line(&mut line).await, Ok(n) if n > 0) {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        commands.push(
            if line.starts_with("EHLO ") {
                "EHLO <hostname>"
            } else {
                line
            }
            .to_owned(),
        );
        if (line.starts_with("EHLO ") && case["hang_at"] == "ehlo")
            || (line == "DATA" && case["hang_at"] == "data")
        {
            continue;
        }
        let reply = if line.starts_with("EHLO ") {
            let barrier = case["barrier"].as_u64().unwrap_or(0) as usize;
            loop {
                let ready = gate.notified();
                if accepted.load(std::sync::atomic::Ordering::SeqCst) >= barrier {
                    break;
                }
                ready.await;
            }
            "250-fake\r\n".to_owned()
                + if case["advertise_tls"] == true {
                    "250-STARTTLS\r\n"
                } else {
                    ""
                }
                + if case["tls_final"] == true {
                    "250 STARTTLS"
                } else {
                    "250 PIPELINING"
                }
        } else if line == "STARTTLS" {
            let reply = default("starttls_reply", "220 go ahead");
            io.write_all(format!("{reply}\r\n").as_bytes())
                .await
                .unwrap();
            if reply.starts_with("220") {
                // A client that rejects the certificate (DANE/PKIX) aborts the handshake.
                let Ok(upgraded) = tokio_rustls::TlsAcceptor::from(tls_server(&case))
                    .accept(io.into_inner())
                    .await
                else {
                    break;
                };
                io = BufReader::new(Box::new(upgraded) as BoxStream);
            }
            continue;
        } else if line.starts_with("RCPT TO:") {
            case["replies"][line]
                .as_str()
                .or_else(|| case["replies"][&host].as_str())
                .unwrap_or("250 recipient ok")
                .to_owned()
        } else if line == "DATA" {
            let reply = default("data_reply", "354 send body");
            io.write_all(format!("{reply}\r\n").as_bytes())
                .await
                .unwrap();
            if !reply.starts_with("354") {
                continue;
            }
            let mut body = Vec::new();
            loop {
                let mut part = Vec::new();
                assert!(io.read_until(b'\n', &mut part).await.unwrap() > 0);
                body.extend_from_slice(&part);
                if part == b".\r\n" {
                    break;
                }
            }
            data.push(STANDARD.encode(body));
            if case["hang_at"] == "final" {
                continue;
            }
            default("final_reply", "250 queued")
        } else {
            "250 ok".to_owned()
        };
        if io
            .write_all(format!("{reply}\r\n").as_bytes())
            .await
            .is_err()
        {
            break;
        }
    }
    receipts
        .lock()
        .await
        .push(json!({"host":host,"commands":commands,"data":data}));
}

/// The cases share one database and fixed fixtures: libtest's threads must take turns.
#[allow(dead_code)] // Also shared by the gateway's independent process-level case.
pub static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
