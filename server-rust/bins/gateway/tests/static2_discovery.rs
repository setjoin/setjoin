//! #417: HTTP discovery against controlled DNS and a certificate-verified peer.
mod common;
use common::BoxError;
use hickory_resolver::proto::{
    op::Message,
    rr::{
        rdata::{A, MX, SRV},
        Name, RData, Record, RecordType,
    },
};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};
use tokio_rustls::{
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
    TlsAcceptor,
};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const DNS: &str = "127.0.0.82:53";
const PEER: &str = "127.0.0.83:443";

struct Zone {
    task: JoinHandle<()>,
    seen: Arc<Mutex<Vec<String>>>,
}
impl Drop for Zone {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Zone {
    async fn start(case: &str) -> Result<Self, BoxError> {
        let socket = UdpSocket::bind(DNS).await?;
        let seen = Arc::new(Mutex::new(vec![]));
        let log = seen.clone();
        let case = case.to_owned();
        let task = tokio::spawn(async move {
            let mut buffer = [0; 65535];
            while let Ok((len, addr)) = socket.recv_from(&mut buffer).await {
                let Ok(request) = Message::from_vec(&buffer[..len]) else {
                    continue;
                };
                let mut response = Message::response(request.metadata.id, request.metadata.op_code);
                response.metadata.authoritative = true;
                response.metadata.recursion_available = true;
                response.metadata.recursion_desired = request.metadata.recursion_desired;
                response.edns = request.edns.clone();
                for query in &request.queries {
                    let name = query.name().to_utf8().to_ascii_lowercase();
                    let ty = query.query_type();
                    if matches!(ty, RecordType::SRV | RecordType::MX) {
                        log.lock().unwrap().push(format!("{ty}:{name}"));
                    }
                    let data = match (name.as_str(), ty) {
                        (name, RecordType::SRV)
                            if name == format!("_jmap._tcp.{case}.static2.test.")
                                && case != "mx" =>
                        {
                            Some(RData::SRV(SRV::new(
                                0,
                                0,
                                443,
                                Name::from_ascii(if case == "numeric" {
                                    "0x7f000053."
                                } else {
                                    "peer.static2.test."
                                })
                                .unwrap(),
                            )))
                        }
                        ("mx.static2.test.", RecordType::MX) => Some(RData::MX(MX::new(
                            10,
                            Name::from_ascii("peer.static2.test.").unwrap(),
                        ))),
                        ("peer.static2.test.", RecordType::A) => {
                            Some(RData::A(A(if case == "private" {
                                Ipv4Addr::new(127, 0, 0, 83)
                            } else {
                                Ipv4Addr::new(93, 184, 216, 34)
                            })))
                        }
                        _ => None,
                    };
                    response.queries.push(query.clone());
                    if let Some(data) = data {
                        response
                            .answers
                            .push(Record::from_rdata(query.name().clone(), 0, data));
                    }
                }
                if let Ok(bytes) = response.to_vec() {
                    let _ = socket.send_to(&bytes, addr).await;
                }
            }
        });
        Ok(Self { task, seen })
    }
}
struct Files(PathBuf);
impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Peer {
    task: JoinHandle<()>,
    seen: Arc<Mutex<Vec<Value>>>,
    ca: Vec<u8>,
    accepts: Arc<std::sync::atomic::AtomicUsize>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Peer {
    async fn start(files: &Files, case: &str) -> Result<Self, BoxError> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["peer.static2.test".into()])?;
        let ca = cert.pem().into_bytes();
        std::fs::write(files.0.join("ca.pem"), &ca)?;
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(PEER).await?;
        let seen = Arc::new(Mutex::new(vec![]));
        let log = seen.clone();
        let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted = accepts.clone();
        let case = case.to_owned();
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (acceptor, seen, case) = (acceptor.clone(), log.clone(), case.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(socket).await else {
                        return;
                    };
                    let service = hyper::service::service_fn(
                        move |r: Request<hyper::body::Incoming>| {
                            let (seen, case) = (seen.clone(), case.clone());
                            async move {
                                seen.lock().unwrap().push(json!({"method":r.method().as_str(),"path":r.uri().path(),"host":r.headers().get("host").and_then(|h|h.to_str().ok()).unwrap_or("")}));
                                let body = match case.as_str() { "no-jmap" => r#"{"features":["mail"]}"#.to_owned(), "oversize" => format!(r#"{{"padding":"{}","features":["jmap"]}}"#, "a".repeat(65536)), _ => r#"{"login_field":"email","login_domain_hint":"corp<&>.test","features":["jmap","calendar"]}"#.to_owned() };
                                let body = if case == "compressed" {
                                    use std::io::Write;
                                    let mut encoder = flate2::write::GzEncoder::new(
                                        Vec::new(),
                                        flate2::Compression::default(),
                                    );
                                    encoder.write_all(body.as_bytes()).unwrap();
                                    encoder.finish().unwrap()
                                } else {
                                    body.into_bytes()
                                };
                                let mut response = Response::builder();
                                if case == "compressed" {
                                    response = response.header("content-encoding", "gzip");
                                }
                                Ok::<_, std::convert::Infallible>(
                                    response
                                        .status(if case == "redirect" { 302 } else { 200 })
                                        .header("location", "/redirected")
                                        .header("content-type", "application/json")
                                        .body(common::full(body))
                                        .unwrap(),
                                )
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        Ok(Self {
            task,
            seen,
            ca,
            accepts,
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_srv_matches_frozen_go() -> Result<(), BoxError> {
    run("srv").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_mx_matches_frozen_go() -> Result<(), BoxError> {
    run("mx").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_private_matches_frozen_go() -> Result<(), BoxError> {
    run("private").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_numeric_matches_frozen_go() -> Result<(), BoxError> {
    run("numeric").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_no_jmap_matches_frozen_go() -> Result<(), BoxError> {
    run("no-jmap").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_oversize_matches_frozen_go() -> Result<(), BoxError> {
    run("oversize").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_redirect_matches_frozen_go() -> Result<(), BoxError> {
    run("redirect").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_cache_matches_frozen_go() -> Result<(), BoxError> {
    run("cache").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_compressed_matches_frozen_go() -> Result<(), BoxError> {
    run("compressed").await
}

async fn run(name: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("static2-discovery") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    let config: String = owner
        .query_one(
            "SELECT coalesce(jsonb_agg(to_jsonb(s)),'[]'::jsonb)::text FROM system_config s",
            &[],
        )
        .await?
        .get(0);
    let actor = fixture::account(&owner, "static2-discover").await?;
    let result = observe(&db, name, record).await;
    if record {
        owner
            .batch_execute("BEGIN; DELETE FROM system_config")
            .await?;
        owner.execute("INSERT INTO system_config SELECT r.* FROM jsonb_populate_recordset(NULL::system_config,$1::text::jsonb) r",&[&config]).await?;
        owner.batch_execute("COMMIT").await?;
    }
    fixture::remove(&owner, &actor).await?;
    result
}

async fn observe(db: &Db, name: &str, record: bool) -> Result<(), BoxError> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let folder = root.join(format!(
        "test-results/gofree-static2/discovery-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(folder.parent().expect("discovery artifact parent"))?;
    std::fs::create_dir(&folder)?;
    let files = Files(folder);
    std::fs::write(
        files.0.join("resolv.conf"),
        "nameserver 127.0.0.82\noptions timeout:1 attempts:1 ndots:1\n",
    )?;
    let zone = Zone::start(name).await?;
    let peer = Peer::start(&files, name).await?;
    let s3=common::fake_upstream(|_|async{Response::builder().header("content-type","application/xml").body(common::full("<ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>mailblobs</Bucket><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>")).unwrap()}).await;
    let oracle = if record {
        std::env::set_var("GOFREE_ORACLE_RESOLV_CONF", files.0.join("resolv.conf"));
        let dir = files.0.file_name().unwrap().to_str().unwrap();
        std::env::set_var("GOFREE_ORACLE_EXTRA_ENV",format!("SSL_CERT_FILE=/evidence/{dir}/ca.pem\nGOFREE_STATIC2_PEER={PEER}\nGODEBUG=netdns=go"));
        let result = common::go_oracle::start_named(db, s3, None, "gofree-static2-discovery").await;
        std::env::remove_var("GOFREE_ORACLE_RESOLV_CONF");
        std::env::remove_var("GOFREE_ORACLE_EXTRA_ENV");
        result?
    } else {
        None
    };
    let table = if record {
        RouteTable::proxy_all()
    } else {
        let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 2)?;
        use hickory_resolver::{
            config::{LookupIpStrategy, NameServerConfig, ResolverConfig},
            net::runtime::TokioRuntimeProvider,
        };
        let mut server = NameServerConfig::udp("127.0.0.82".parse()?);
        for connection in &mut server.connections {
            connection.port = 53;
        }
        let mut resolver = hickory_resolver::Resolver::builder_with_config(
            ResolverConfig::from_name_servers(vec![server]),
            TokioRuntimeProvider::default(),
        );
        resolver.options_mut().cache_size = 0;
        resolver.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        let discovery = setjoin_gateway::discovery::Discovery::for_tests(
            resolver.build()?,
            "peer.static2.test",
            PEER.parse::<SocketAddr>()?,
            &peer.ca,
        )?;
        RouteTable::proxy_all().with(setjoin_gateway::surface::SurfaceRoute {
            discovery: Some(Arc::new(discovery)),
            exec,
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            config: Arc::new(setjoin_gateway::surface::SurfaceConfig::from_env()),
            health: Arc::new(setjoin_static::health::HealthGate::new(false)),
            fallback: None,
        })
    };
    let gateway = Gateway::new(
        Config {
            upstream: oracle
                .as_ref()
                .map(|g| format!("http://{}", g.address).parse())
                .transpose()?,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        table,
    )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(gateway.serve(listener));
    zone.seen.lock().unwrap().clear();
    peer.seen.lock().unwrap().clear();
    let response = common::send(
        address,
        Request::builder()
            .uri(format!("/api/discover?domain={name}.static2.test"))
            .header("host", "mail.test")
            .header("x-request-id", format!("static2-{name}"))
            .body(common::full(""))?,
    )
    .await;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body = String::from_utf8(common::body_bytes(response).await.to_vec())?;
    if name == "cache" {
        let response = common::send(
            address,
            Request::builder()
                .uri(format!("/api/discover?domain={name}.static2.test"))
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(common::body_bytes(response).await.as_ref(), body.as_bytes());
    }
    let metrics = common::send(
        address,
        Request::builder()
            .uri("/_gateway/metrics")
            .body(common::full(""))?,
    )
    .await;
    let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
    task.abort();
    let _ = task.await;
    drop(oracle);
    let mut dns = zone.seen.lock().unwrap().clone();
    dns.sort();
    let mut observation = json!({"request":{"method":"GET","path":"/api/discover"},"response":{"status":status,"headers":{"content-type":content_type},"body_text":body},"effects":{},"audit":[],"notify":[],"dns":dns,"peer":peer.seen.lock().unwrap().clone()});
    if !matches!(name, "srv" | "mx") {
        observation["tcp_accepts"] = json!(peer.accepts.load(std::sync::atomic::Ordering::SeqCst));
    }
    let path = root.join(format!(
        "server-rust/tests/conformance/static2/discovery-{name}.json"
    ));
    if record {
        if status
            != if matches!(name, "srv" | "mx" | "cache" | "compressed") {
                200
            } else {
                404
            }
        {
            return Err(format!("expected live Go discovery success, got {observation}").into());
        }
        golden::record(
            &path,
            &json!({"format":1,"route":"GET /api/discover","case":name,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
        )?;
    } else {
        let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        golden::compare(&expected["observation"], &observation)?;
        if !metrics
            .lines()
            .any(|l| l == "setjoin_gateway_proxied_to_go_total 0")
        {
            return Err(format!("discovery forwarded: {metrics}").into());
        }
        println!("GOLDEN-REPLAY: GET /api/discover :: {name}");
    }
    let _ = &peer.ca;
    Ok(())
}
