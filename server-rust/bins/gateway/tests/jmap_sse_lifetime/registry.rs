//! Public connection-registry lifecycle and named unported Identity ownership.
use crate::common::boot::CommandBootExt;
use crate::{common, rows, BoxError, Frames, SERIAL};
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    jmap::{push::WebSocketRoute, sse::EventSourceRoute, JmapCommands},
    Config, Gateway, RouteTable, TrustedProxies,
};
use std::{sync::Arc, time::Duration};

fn inventory() -> Result<String, BoxError> {
    let d: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
    if !d["routes"].as_array().unwrap().iter().any(|r| {
        r["path"] == "/jmap/eventsource" && r["state"] == "ON" && r["upstream"] == "local-rust"
    }) {
        return Err("bundled SSE route is not ON".into());
    }
    Ok(d.to_string())
}
fn service(db: &Db) -> Result<WebSocketRoute<setjoin_gateway::jmap::jwks::Jwks>, BoxError> {
    let commands = Arc::new(JmapCommands {
        services: None,
        exec: common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?,
        worker: None,
        keys: common::recovery_keys(),
        issuer: "mailserver".into(),
        denylist: None,
    });
    Ok(WebSocketRoute::new(commands, db.direct.clone()))
}
async fn open(address: std::net::SocketAddr, user: i64) -> Result<Frames, BoxError> {
    let response = common::send(
        address,
        Request::builder()
            .uri(format!("http://{address}/jmap/eventsource"))
            .header(
                "authorization",
                format!("Bearer {}", common::recovery_token(user)),
            )
            .body(common::full(""))?,
    )
    .await;
    if response.status() != 200 {
        return Err(format!("SSE connect failed {}", response.status()).into());
    }
    let mut stream = Frames {
        body: response.into_body(),
        buffer: Vec::new(),
    };
    stream.next().await?;
    Ok(stream)
}
pub async fn eviction() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sse-public-registry") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "sse-registry").await?;
    let b = fixture::account(&owner, "sse-registry-other").await?;
    let result = async {
        let mut ws = service(&db)?;
        ws.max_clients = 2;
        let registry = ws.registry.clone();
        let routes = RouteTable::proxy_all()
            .with(EventSourceRoute::new(&ws))
            .with(ws);
        let gateway = Gateway::new(
            Config {
                upstream: None,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: Duration::from_secs(10),
                edge_limit: None,
            },
            routes,
        )?
        .with_inventory(&inventory()?)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let observed = async {
            let before = rows(&owner, &a, &b).await?;
            let mut first = open(address, a.user).await?;
            let mut other = open(address, b.user).await?;
            if !registry.is_online(a.user) || !registry.is_online(b.user) {
                return Err("SSE did not use public presence registry".into());
            }
            let denied = common::send(
                address,
                Request::builder()
                    .uri(format!(
                        "http://{address}/jmap/eventsource?closeafter=state"
                    ))
                    .header(
                        "authorization",
                        format!("Bearer {}", common::recovery_token(a.user)),
                    )
                    .body(common::full(""))?,
            )
            .await;
            if denied.status() != 503 {
                return Err("configured shared budget was bypassed".into());
            }
            let _ = common::body_bytes(denied).await;
            registry.evict_mailbox(a.mailbox);
            first.ended(Duration::from_secs(5)).await?;
            if registry.is_online(a.user) || !registry.is_online(b.user) {
                return Err("mailbox eviction removed wrong presence".into());
            }
            owner
                .query(
                    "SELECT pg_notify($1,$2)",
                    &[&format!("chat:{}", b.user), &r#"{"marker":"untargeted"}"#],
                )
                .await?;
            if !other.next().await?.contains("untargeted") {
                return Err("untargeted stream stopped".into());
            }
            let mut first = open(address, a.user).await?;
            registry.evict_user(a.user);
            first.ended(Duration::from_secs(5)).await?;
            let first = open(address, a.user).await?;
            drop(first);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while registry.is_online(a.user) {
                if tokio::time::Instant::now() >= deadline {
                    return Err("body drop leaked registry or budget".into());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let mut first = open(address, a.user).await?;
            registry.shutdown();
            first.ended(Duration::from_secs(5)).await?;
            other.ended(Duration::from_secs(5)).await?;
            if registry.is_online(a.user) || registry.is_online(b.user) {
                return Err("shutdown retained presence".into());
            }
            let denied = common::send(
                address,
                Request::builder()
                    .uri(format!(
                        "http://{address}/jmap/eventsource?closeafter=state"
                    ))
                    .header(
                        "authorization",
                        format!("Bearer {}", common::recovery_token(a.user)),
                    )
                    .body(common::full(""))?,
            )
            .await;
            if denied.status() != 401 {
                return Err("shutdown registry admitted a new stream".into());
            }
            let _ = common::body_bytes(denied).await;
            if rows(&owner, &a, &b).await? != before {
                return Err("registry lifecycle wrote database data".into());
            }
            Ok::<_, BoxError>(())
        }
        .await;
        server.abort();
        let _ = server.await;
        observed
    }
    .await;
    fixture::remove(&owner, &a).await?;
    fixture::remove(&owner, &b).await?;
    result
}
pub async fn legacy() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sse-identity331") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "sse-identity").await?;
    let b = fixture::account(&owner, "sse-identity-other").await?;
    let result = async {
        // Shape inspection grants no authority; #331's upstream verifies this key profile.
        let legacy = "eyJhbGciOiJIUzI1NiJ9.e30.unverified";
        let upstream = common::fake_upstream(move |request| async move {
            let uri = request.uri().to_string();
            let auth = request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let cookie = request.headers().get("cookie").cloned();
            let body = request.into_body().collect().await.unwrap().to_bytes();
            if uri != "/jmap/eventsource?types=Email&opaque=%ZZ"
                || auth != format!("Bearer {legacy}")
                || cookie.is_none()
                || body.as_ref() != b"unmodified-body"
            {
                return Response::builder()
                    .status(400)
                    .body(common::full("handoff changed request"))
                    .unwrap();
            }
            Response::builder()
                .status(202)
                .body(common::full("Identity #331 owns this profile"))
                .unwrap()
        })
        .await;
        let ws = service(&db)?;
        let routes = RouteTable::proxy_all().with(EventSourceRoute::new(&ws));
        let gateway = Gateway::new(
            Config {
                upstream: Some(format!("http://{upstream}").parse()?),
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: Duration::from_secs(10),
                edge_limit: None,
            },
            routes,
        )?
        .with_inventory(&inventory()?)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let observed = async {
            let before = rows(&owner, &a, &b).await?;
            let response = common::send(
                address,
                Request::builder()
                    .uri(format!(
                        "http://{address}/jmap/eventsource?types=Email&opaque=%ZZ"
                    ))
                    .header("authorization", format!("Bearer {legacy}"))
                    .header(
                        "cookie",
                        format!("access_token={}", common::recovery_token(a.user)),
                    )
                    .body(common::full("unmodified-body"))?,
            )
            .await;
            let status = response.status();
            let body = common::body_bytes(response).await;
            if status != 202 || body.as_ref() != b"Identity #331 owns this profile" {
                return Err(format!("named profile not forwarded intact: {status}").into());
            }
            // An unused legacy cookie cannot redirect an ordinary verified Bearer stream.
            let response = common::send(
                address,
                Request::builder()
                    .uri(format!(
                        "http://{address}/jmap/eventsource?closeafter=state"
                    ))
                    .header(
                        "authorization",
                        format!("Bearer {}", common::recovery_token(a.user)),
                    )
                    .header("cookie", format!("access_token={legacy}"))
                    .body(common::full(""))?,
            )
            .await;
            if response.status() != 200 {
                return Err("unused legacy cookie stole Bearer authority".into());
            }
            let _ = common::body_bytes(response).await;
            if rows(&owner, &a, &b).await? != before {
                return Err("deferred profile wrote data".into());
            }
            let response = common::send(
                address,
                Request::builder()
                    .uri(format!("http://{address}/_gateway/metrics"))
                    .body(common::full(""))?,
            )
            .await;
            let metrics = String::from_utf8(common::body_bytes(response).await.to_vec())?;
            if !metrics.contains("setjoin_gateway_proxied_to_go_total 1\n") {
                return Err(format!("wrong profile proxy attribution {metrics}").into());
            }
            Ok::<_, BoxError>(())
        }
        .await;
        server.abort();
        let _ = server.await;
        observed
    }
    .await;
    fixture::remove(&owner, &a).await?;
    fixture::remove(&owner, &b).await?;
    result
}

pub async fn executable() -> Result<(), BoxError> {
    use std::{
        io::Read,
        os::unix::process::CommandExt,
        process::{Command, Stdio},
    };
    struct Process(crate::common::boot::Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let pid = self.0.id();
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while self.0.try_wait().ok().flatten().is_none() {
                if std::time::Instant::now() >= deadline {
                    let _ = self.0.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = self.0.wait();
            if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
                use std::io::Write;
                if let Ok(mut ledger) = std::fs::OpenOptions::new().append(true).open(path) {
                    let _ = writeln!(
                        ledger,
                        "Stopped and reaped gofree-jmap5-executable PID {pid}"
                    );
                }
            }
        }
    }
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sse-executable") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "sse-executable").await?;
    let result=async {
  let jwks=common::fake_upstream(|_|async {Response::builder().header("content-type","application/json").body(common::full(include_bytes!("../../../../tests/conformance/jmap/test-jwks.json").as_slice())).unwrap()}).await;
  let reserved = setjoin_conformance::ports::listener().await;let address=reserved.local_addr()?;drop(reserved);
  if let Ok(path)=std::env::var("GOFREE_RESOURCE_LEDGER") {
   use std::io::Write;writeln!(std::fs::OpenOptions::new().append(true).open(path)?,"Planned process gofree-jmap5-executable, assigned DB only, Go upstream unset, listener {address}")?;
  }
  let mut command=Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
  command.arg0("gofree-jmap5-executable").env_clear().env("GATEWAY_LISTEN",address.to_string()).env("GATEWAY_AUTH_UPSTREAM","http://127.0.0.1:1").env("DB_DSN",db.app.as_deref().unwrap_or(&db.dsn)).env("DB_WORKER_DSN",&db.dsn).env("DB_DIRECT_DSN",&db.direct).env("DB_ENCRYPTION_KEY","22".repeat(32)).env("AUTHSERVER_JWKS_URL",format!("http://{jwks}/.well-known/jwks.json")).env("GATEWAY_DB_POOL","4").env("SETJOIN_AUTHZ_PRECHECK_TIMEOUT_MS","15000").env("SETJOIN_PG_DEADLINE_MS","30000").stdout(Stdio::null()).stderr(Stdio::piped());
  let mut process=Process(command.spawn_boot()?);
  if let Ok(path)=std::env::var("GOFREE_RESOURCE_LEDGER") {
   use std::io::Write;writeln!(std::fs::OpenOptions::new().append(true).open(path)?,"Started gofree-jmap5-executable PID {}",process.0.id())?;
  }
  let deadline=tokio::time::Instant::now()+Duration::from_secs(15);
  loop {
   if process.0.try_wait()?.is_some(){let mut log=String::new();if let Some(mut e)=process.0.stderr.take(){let _=e.read_to_string(&mut log);}return Err(format!("SSE executable exited: {log}").into())}
   if tokio::net::TcpStream::connect(address).await.is_ok(){break}
   if tokio::time::Instant::now()>=deadline{return Err("SSE executable did not bind".into())}tokio::time::sleep(Duration::from_millis(20)).await;
  }
  let response=common::send(address,Request::builder().uri(format!("http://{address}/jmap/eventsource?closeafter=state")).header("authorization",format!("Bearer {}",common::recovery_token(a.user))).body(common::full(""))?).await;
  let status=response.status();let body=String::from_utf8(common::body_bytes(response).await.to_vec())?.replace(&format!("\"{}\"",a.mailbox),"\"<mailbox>\"");
  let expected:Value=serde_json::from_str(include_str!("../../../../tests/conformance/jmap/sse/initial-state.json"))?;
  if status!=200||body!=expected["observation"]["response"]["body"]{return Err(format!("executable did not serve SSE natively: {status} {body}").into())}
  let metrics=common::send(address,Request::builder().uri(format!("http://{address}/_gateway/metrics")).body(common::full(""))?).await;
  if !String::from_utf8(common::body_bytes(metrics).await.to_vec())?.contains("setjoin_gateway_proxied_to_go_total 0\n"){return Err("executable SSE counted a Go proxy".into())}
  drop(process);Ok::<_,BoxError>(())
 }.await;
    fixture::remove(&owner, &a).await?;
    result
}
