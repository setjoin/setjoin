// Shared OP HTTP harness; synthetic keys only.
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::harness::Db;
use setjoin_gateway::{Gateway, RouteTable, TrustedProxies};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
type Err = Box<dyn std::error::Error + Send + Sync>;
struct Server {
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    addr: std::net::SocketAddr,
}
impl Server {
    async fn close(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn auth_server(server: Arc<AuthServer>, mutant: bool) -> Server {
    auth_server_armed(server, Arc::new(std::sync::atomic::AtomicBool::new(mutant))).await
}
async fn auth_server_armed(
    server: Arc<AuthServer>,
    mutant: Arc<std::sync::atomic::AtomicBool>,
) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        tokio::pin!(rx);
        loop {
            tokio::select! {
             _=&mut rx=>break,
             accepted=listener.accept()=>{
              let (stream,peer)=accepted.unwrap();let server=server.clone();let mutant=mutant.clone();
              connections.spawn(async move {
               let service=hyper::service::service_fn(move |mut req:Request<hyper::body::Incoming>|{
                let server=server.clone();let mutant=mutant.clone();req.extensions_mut().insert(setjoin_auth::ConnectionMeta{peer,tls:false});
                async move {
                 let mut response=server.handle(req.map(|b|b.map_err(std::io::Error::other).boxed())).await;
                 if mutant.load(std::sync::atomic::Ordering::SeqCst) {*response.status_mut()=hyper::StatusCode::from_u16(599).unwrap();}
                 Ok::<_,std::convert::Infallible>(response)
                }
               });
               let _=hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection(hyper_util::rt::TokioIo::new(stream),service).await;
              });
             }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    });
    Server {
        stop: Some(tx),
        task,
        addr,
    }
}
async fn gateway(auth: std::net::SocketAddr, record: Option<String>) -> Server {
    gateway_mode(auth, record, false).await
}
async fn gateway_mode(auth: std::net::SocketAddr, record: Option<String>, public: bool) -> Server {
    let mut inventory: Value = serde_json::from_str(setjoin_gateway::inventory::BUNDLED).unwrap();
    inventory["routes"]
        .as_array_mut()
        .unwrap()
        .retain(|r| public || r["listener"] == "auth");
    for r in inventory["routes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .filter(|r| r["slice"].as_str().is_some_and(|s| s == "federation-rp"))
    {
        if record.is_some() {
            r["state"] = json!("OFF");
            r["upstream"] = json!("go-auth");
        }
    }
    let gw = Gateway::new(
        setjoin_gateway::Config {
            upstream: record.as_ref().map(|u| u.parse().unwrap()),
            upstream_header_timeout: std::time::Duration::from_secs(30),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            edge_limit: Some(setjoin_gateway::jmap::limit::EdgeLimit::for_front_door(
                setjoin_gateway::jmap::limit::Limiter::new(60000, 60),
            )),
        },
        RouteTable::proxy_all(),
    )
    .unwrap()
    .with_inventory(&inventory.to_string())
    .unwrap();
    let gw = if let Some(url) = record {
        gw.with_auth_upstream(url.parse().unwrap()).unwrap()
    } else {
        gw.with_rust_auth_upstream(format!("http://{auth}").parse().unwrap())
            .unwrap()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let task = tokio::spawn(gw.serve_until(listener, async {
        let _ = rx.await;
    }));
    Server {
        stop: Some(tx),
        task,
        addr,
    }
}
async fn request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    payload: String,
    headers: &[(&str, &str)],
) -> Result<(u16, Value, String), Err> {
    let client: hyper_util::client::legacy::Client<_, setjoin_auth::Body> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let mut req = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"))
        .header("host", "auth.idfed2.test")
        .header("user-agent", "IDFED2 oracle");
    if !headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        req = req.header("content-type", "application/json");
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = client.request(req.body(body(payload))?).await?;
    let status = resp.status().as_u16();
    let mut hs = serde_json::Map::new();
    let cookies = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    if !cookies.is_empty() {
        hs.insert("set-cookie".into(), json!(cookies));
    }
    for name in [
        "content-type",
        "cache-control",
        "pragma",
        "x-content-type-options",
        "www-authenticate",
        "allow",
        "location",
        "vary",
        "access-control-allow-origin",
        "access-control-expose-headers",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-allow-credentials",
        "x-operation-id",
    ] {
        if let Some(v) = resp.headers().get(name) {
            hs.insert(name.into(), json!(v.to_str()?));
        }
    }
    if method == "HEAD" {
        if let Some(v) = resp.headers().get("content-length") {
            hs.insert("content-length".into(), json!(v.to_str()?));
        }
    }
    let raw = String::from_utf8(resp.into_body().collect().await?.to_bytes().to_vec())?;
    Ok((status, Value::Object(hs), raw))
}

const SOURCE: &str = "61e9cff379b4087b970c7637ab8af5c4c252af67";
fn corpus() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/identity-rp")
}
