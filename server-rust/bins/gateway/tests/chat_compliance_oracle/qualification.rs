//! Planted mutations at the running production adapter and real COMMIT seam.
use super::*;
use setjoin_gateway::{Body, BoxFuture, Intercept, RequestContext};
pub struct Status<I> {
    pub inner: I,
    pub change: bool,
}
impl<I: Intercept> Intercept for Status<I> {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let future = self.inner.handle(r, c);
        let change = self.change;
        Box::pin(async move {
            let mut response = future.await;
            if change {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}
pub async fn mutant(action: &str) -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {
        return Err("mutants require native replay".into());
    }
    let error = super::run(action, "success", "status")
        .await
        .err()
        .ok_or("planted status mutant survived")?;
    if !error.to_string().contains("/response/status:") {
        return Err(format!("mutant failed outside its intended field: {error}").into());
    }
    let (method, path) = route(action);
    eprintln!("MUTANT-REJECTED: {method} {path} :: status");
    Ok(())
}

pub async fn commit_check(
    db: &Db,
    actor: i64,
    action: &str,
    mode: &str,
    observation: &Value,
) -> Result<(), BoxError> {
    let committed = mode == "commit-after";
    if observation["response"]["status"] != 503 {
        return Err("ambiguous COMMIT reported success".into());
    }
    let operation = observation["response"]["headers"]["x-operation-id"][0]
        .as_str()
        .ok_or("unknown command lacks operation ID")?;
    if operation.len() != 32 || !operation.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid unknown operation ID".into());
    }
    let mut bytes = [0; 16];
    for (i, value) in bytes.iter_mut().enumerate() {
        *value = u8::from_str_radix(&operation[i * 2..i * 2 + 2], 16)?;
    }
    let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 1)
        .map_err(|e| e.0)?;
    let mut headers = hyper::HeaderMap::new();
    headers.insert("authorization", format!("Bearer {}", token(actor)).parse()?);
    let keys = std::sync::Arc::new(common::recovery_keys());
    let verified = setjoin_authz::authorize_request(&exec, &keys, "mailserver", &headers, "http")
        .await
        .ok_or("receipt lookup authority")?;
    let command = if matches!(action, "create" | "update" | "delete") {
        "chat.policy"
    } else {
        "chat.oversight"
    };
    let result = setjoin_pg::lookup_command(
        &exec,
        &setjoin_compliance::scope(verified.context()),
        setjoin_contracts::ids::OperationId(bytes),
        setjoin_pg::ReceiptCommand {
            family: "F04",
            command,
        },
    )
    .await
    .map_err(|e| format!("receipt lookup failed: {e:?}"))?;
    let wanted = if committed {
        setjoin_pg::OperationLookup::Committed
    } else {
        setjoin_pg::OperationLookup::Absent
    };
    if result != wanted {
        return Err(format!("incorrect receipt resolution: {result:?}").into());
    }
    if committed {
        let file = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../tests/conformance/chat-compliance/goldens/{action}-success.json"
        ));
        let expected: Value = serde_json::from_slice(&std::fs::read(file)?)?;
        for key in ["effects", "audit", "notify"] {
            golden::compare(&expected["observation"][key], &observation[key])?;
        }
    } else {
        golden::compare(
            &observation["effects"][0]["before"],
            &observation["effects"][0]["after"],
        )?;
        golden::compare(&json!([]), &observation["audit"])?;
        golden::compare(&json!([]), &observation["notify"])?;
    }
    if action == "export"
        && observation["response"]["headers"]["content-type"][0] == "application/zip"
    {
        return Err("ambiguous export emitted archive headers".into());
    }
    eprintln!("COMMIT-FAULT: {action} :: {mode}, authenticated receipt lookup, no replay");
    Ok(())
}

pub struct Wire {
    pub task: tokio::task::JoinHandle<std::io::Result<common::commit::CommitCut>>,
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn kill_switch() -> Result<(), BoxError> {
    use http_body_util::BodyExt;
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("compl3-switch").ok_or("DB required")?;
    let owner = db.connect().await?;
    let actor = fixture::account(&owner, "compl3-switch").await?;
    let result=async {
 let before=snapshot(&owner,actor.mailbox,true).await?;
 for mode in ["global","inventory","auth"]{
  let global=mode=="global";let off=mode=="inventory";
  let calls=std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));let capture=calls.clone();
  let upstream=common::fake_upstream(move |r|{let capture=capture.clone();async move{
   let(method,uri,headers)=(r.method().to_string(),r.uri().to_string(),r.headers().clone());let body=r.into_body().collect().await.unwrap().to_bytes();
   capture.lock().unwrap().push(json!({"method":method,"uri":uri,"content-type":headers.get("content-type").and_then(|v|v.to_str().ok()),"authorization":headers.get("authorization").and_then(|v|v.to_str().ok()),"request-id":headers.get("x-request-id").and_then(|v|v.to_str().ok()),"body":body.as_ref()}));
   Response::builder().status(299).body(common::full("switch\n")).unwrap()
  }}).await;
  let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;let mut routes=Vec::new();
  for row in inventory["routes"].as_array_mut().unwrap(){if row["family"]=="F04" && row["slice"]=="chat-compliance"{routes.push((row["method"].as_str().unwrap().to_owned(),format!("/api{}?sentinel=%FF&caseId=970001",row["path"].as_str().unwrap().replace("{id}","961001"))));row["state"]=json!(if off{"OFF"}else{"ON"});row["upstream"]=json!(if off{"go-mail"}else{"local-rust"});}}
  if routes.len()!=13{return Err("switch route coverage changed".into());}
  let adapter=setjoin_gateway::chat_compliance::ChatComplianceRoute{exec:setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),1).map_err(|e|e.0)?,worker:setjoin_pg::ScopedExecutor::from_dsn(&db.dsn,1).map_err(|e|e.0)?,database:setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?,store:None,keys:std::sync::Arc::new(common::recovery_keys()),issuer:"mailserver".into()};
  let gateway=Gateway::new(Config{upstream:Some(format!("http://{upstream}").parse()?),trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(adapter))?.with_inventory(&inventory.to_string())?.with_enabled(!global);
  let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let server=tokio::spawn(gateway.serve(listener));
  let bytes=b"{\n\"original\":true,\"opaque\":\"\xff\"\n}".to_vec();let mut expected=Vec::new();
  for(method,uri)in &routes{
   let reply=common::send(address,Request::builder().method(method.as_str()).uri(uri).header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json; original=yes").header("authorization","Bearer original.invalid.token").header("x-request-id","compl3-switch-original").body(common::full(bytes.clone()))?).await;
   if reply.status().as_u16()!=299 || common::body_bytes(reply).await.as_ref()!=b"switch\n"{server.abort();return Err("switch did not return Go reply".into());}
   expected.push(json!({"method":method,"uri":uri,"content-type":"application/json; original=yes","authorization":"Bearer original.invalid.token","request-id":"compl3-switch-original","body":bytes}));
  }
  golden::compare(&json!(expected),&json!(calls.lock().unwrap().clone()))?;
  if !global {
   let reply=common::send(address,Request::get("/_gateway/metrics").body(common::full(""))?).await;let metrics=String::from_utf8(common::body_bytes(reply).await.to_vec())?;
   for expected in ["setjoin_gateway_proxied_to_go_total 13","setjoin_gateway_proxied_to_go_by_family_total{family=\"F04\"} 13"]{if !metrics.lines().any(|line|line==expected){server.abort();return Err(format!("switch counter mismatch: {metrics}").into());}}
  }
  server.abort();let _=server.await;golden::compare(&before,&snapshot(&owner,actor.mailbox,true).await?)?;
 }
 Ok::<_,BoxError>(())}.await;
    fixture::remove(&owner, &actor).await?;
    result
}
