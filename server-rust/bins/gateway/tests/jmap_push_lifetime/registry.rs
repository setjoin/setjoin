use crate::common::boot::CommandBootExt;
use super::*;
use http_body_util::BodyExt;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
async fn connect(address: std::net::SocketAddr, user: i64) -> Result<Socket, BoxError> {
    let mut request = format!("ws://{address}/jmap/ws").into_client_request()?;
    request.headers_mut().insert(
        "cookie",
        format!(
            "access_token={}",
            common::recovery_token_with(user, json!({}))
        )
        .parse()?,
    );
    let mut socket = tokio_tungstenite::connect_async(request).await?.0;
    ready(&mut socket).await?;
    Ok(socket)
}
async fn ready(socket: &mut Socket) -> Result<(), BoxError> {
    socket
        .send(Message::Text(r#"{"@type":"ready"}"#.into()))
        .await?;
    loop {
        match tokio::time::timeout(Duration::from_secs(10), socket.next())
            .await?
            .ok_or("closed socket")??
        {
            Message::Text(text) if text.contains("unknownType") => return Ok(()),
            Message::Ping(_) => socket.flush().await?,
            other => return Err(format!("unexpected ready {other:?}").into()),
        }
    }
}
async fn closed(socket: &mut Socket) -> Result<(), BoxError> {
    match tokio::time::timeout(Duration::from_secs(5), socket.next()).await? {
        None | Some(Err(_)) | Some(Ok(Message::Close(_))) => Ok(()),
        other => Err(format!("connection remained open {other:?}").into()),
    }
}
fn routes(
    db: &Db,
) -> Result<(RouteTable, setjoin_jmap::connections::ConnectionRegistry), BoxError> {
    let commands = Arc::new(JmapCommands {
        services: Some(Arc::new(setjoin_gateway::jmap::JmapServices::new(
            common::patient_exec(&db.dsn, 4)?,
            "localhost".into(),
            52428800,
        ))),
        worker: Some(common::patient_exec(&db.dsn, 4)?),
        exec: common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?,
        keys: common::recovery_keys(),
        issuer: "mailserver".into(),
        denylist: None,
    });
    let ws = WebSocketRoute::new(commands.clone(), db.direct.clone());
    let registry = ws.registry.clone();
    Ok((
        RouteTable::proxy_all()
            .with(ws)
            .with(setjoin_gateway::jmap::presence::PresenceRoute {
                commands,
                registry: registry.clone(),
            }),
        registry,
    ))
}
fn inventory() -> String {
    let value: Value = serde_json::from_str(include_str!("../../route-inventory.json")).unwrap();
    for path in ["/jmap/ws", "/chat/presence"] {
        assert!(value["routes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["path"] == path && r["state"] == "ON" && r["upstream"] == "local-rust"));
    }
    value.to_string()
}
#[tokio::test]
async fn deferred_batch_forwards_whole_before_any_native_write() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("push-deferred") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "jmap4-deferred").await?;
    let result=async {
        owner.execute("UPDATE messages SET has_attachments=true WHERE mailbox_id=$1 AND id=$2", &[&a.mailbox, &a.two_labels]).await?;
        let before=snapshot(&owner,&a).await?;
        let batch=json!({"@type":"Request","id":"deferred","using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail","urn:ietf:params:jmap:submission"],"methodCalls":[["Email/set",{"accountId":a.mailbox.to_string(),"update":{a.two_labels.to_string():{"keywords":{"$seen":true}}}},"write"],["EmailSubmission/set",{"accountId":a.mailbox.to_string(),"create":{"attachment":{"emailId":a.two_labels.to_string()}}},"later"]]}).to_string();
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let upstream=listener.local_addr()?;
        let expected=batch.clone();let go=tokio::spawn(async move{
            let (stream,_)=listener.accept().await?;
            let mut socket=tokio_tungstenite::accept_async(stream).await?;
            let actual=socket.next().await.ok_or("no deferred frame")??;
            if actual.into_data().as_ref()!=expected.as_bytes(){return Err("deferred frame changed".into())}
            socket.send(Message::Text(r#"{"@type":"Response","requestId":"deferred","sessionState":"upstream","methodResponses":[]}"#.into())).await?;
            Ok::<_,BoxError>(())
        });
        let (routes,_)=routes(&db)?;
        let gateway=Gateway::new(Config{upstream:Some(format!("http://{upstream}").parse()?),trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:Duration::from_secs(10),edge_limit:None},routes)?.with_inventory(&inventory())?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
        let (stop,stopped)=tokio::sync::oneshot::channel();let server=tokio::spawn(gateway.serve_until(listener,async{let _=stopped.await;}));
        let result=async {
            let mut socket=connect(address,a.user).await?;socket.send(Message::Text(batch.into())).await?;
            let frame=tokio::time::timeout(Duration::from_secs(10),socket.next()).await?.ok_or("no deferred response")??;
            if !frame.to_text()?.contains("\"sessionState\":\"upstream\""){return Err(format!("batch was not deferred: {frame}").into())}
            if snapshot(&owner,&a).await?!=before{return Err("native command ran before whole-batch handoff".into())}
            ready(&mut socket).await?;
            let response=common::send(address,hyper::Request::builder().uri(format!("http://{address}/_gateway/metrics")).body(common::full(""))?).await;
            let metrics=String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
            if !metrics.contains("setjoin_gateway_proxied_to_go_total 1\n"){return Err(format!("incorrect deferred attribution {metrics}").into())}
            socket.close(None).await?;Ok::<_,BoxError>(())
        }.await;
        let _=stop.send(());server.await?;
        if result.is_ok(){go.await??;}else{go.abort();let _=go.await;}
        result
    }.await;
    fixture::remove(&owner, &a).await?;
    result
}
#[tokio::test]
async fn merged_mailbox_and_submission_batch_keeps_created_ids() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("push-merged-methods") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "jmap4-merged-methods").await?;
    let result = async {
        let (routes, _) = routes(&db)?;
        let gateway = Gateway::new(Config {
            upstream: None,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: Duration::from_secs(10),
            edge_limit: None,
        }, routes)?.with_inventory(&inventory())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(gateway.serve_until(listener, async { let _ = stopped.await; }));
        let result = async {
            let mut socket = connect(address, a.user).await?;
            socket.send(Message::Text(json!({
                "@type":"Request", "id":"merged",
                "using":["urn:ietf:params:jmap:mail","urn:ietf:params:jmap:submission"],
                "methodCalls":[
                    ["Mailbox/set",{"accountId":a.mailbox.to_string(),"create":{"work":{"name":"Work"}}},"create"],
                    ["Mailbox/get",{"accountId":a.mailbox.to_string()},"read"],
                    ["EmailSubmission/query",{"accountId":a.mailbox.to_string()},"submission"]
                ]
            }).to_string().into())).await?;
            let response: Value = loop {
                match tokio::time::timeout(Duration::from_secs(10), socket.next()).await?
                    .ok_or("closed merged-method socket")?? {
                    Message::Ping(_) => socket.flush().await?,
                    Message::Text(text) => {
                        let frame: Value = serde_json::from_str(&text)?;
                        if frame["@type"] == "Response" { break frame; }
                        if frame["@type"] != "StateChange" { return Err(format!("unexpected frame {frame}").into()); }
                    }
                    other => return Err(format!("unexpected frame {other:?}").into()),
                }
            };
            let calls = response["methodResponses"].as_array().ok_or("missing responses")?;
            let id = calls[0][1]["created"]["work"]["id"].as_str().ok_or("missing created mailbox")?;
            // Frozen-Go mailbox-set.json records this transport-level accumulation.
            if response["createdIds"] != json!({"work":id}) {
                return Err(format!("createdIds missing from WebSocket response: {response}").into());
            }
            if calls[1][0] != "Mailbox/get" || !calls[1][1]["list"].as_array()
                .is_some_and(|list| list.iter().any(|mailbox| mailbox["id"] == id))
                || calls[2][0] != "EmailSubmission/query" {
                return Err(format!("merged methods did not execute in order: {response}").into());
            }
            let metrics = common::send(address, hyper::Request::builder()
                .uri(format!("http://{address}/_gateway/metrics")).body(common::full(""))?).await;
            let metrics = String::from_utf8(metrics.into_body().collect().await?.to_bytes().to_vec())?;
            if !metrics.contains("setjoin_gateway_proxied_to_go_total 0\n") {
                return Err(format!("merged native methods attempted Go: {metrics}").into());
            }
            socket.close(None).await?;
            Ok::<_, BoxError>(())
        }.await;
        let _ = stop.send(());
        server.await?;
        result
    }.await;
    fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test]
async fn shared_registry_evicts_only_matching_sockets_and_shutdown_closes_all(
) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("push-registry") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "jmap4-registry").await?;
    let b = fixture::account(&owner, "jmap4-registry-other").await?;
    let result = async {
        let (routes, registry) = routes(&db)?;
        let gateway = Gateway::new(
            Config {
                upstream: None,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: Duration::from_secs(10),
                edge_limit: None,
            },
            routes,
        )?
        .with_inventory(&inventory())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(gateway.serve_until(listener, async {
            let _ = stopped.await;
        }));
        let result = async {
            let mut first = connect(address, a.user).await?;
            let mut second = connect(address, a.user).await?;
            let mut other = connect(address, b.user).await?;
            registry.evict_user(a.user);
            closed(&mut first).await?;
            closed(&mut second).await?;
            ready(&mut other).await?;
            let mut again = connect(address, a.user).await?;
            registry.evict_mailbox(a.mailbox);
            closed(&mut again).await?;
            ready(&mut other).await?;
            Ok::<_, BoxError>(other)
        }
        .await;
        let _ = stop.send(());
        server.await?;
        let mut other = result?;
        closed(&mut other).await?;
        if registry.is_online(a.user) || registry.is_online(b.user) {
            return Err("shutdown left online registry entries".into());
        }
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let tx = std::sync::Mutex::new(Some(closed_tx));
        let _late = registry.register(
            a.user,
            Some(a.mailbox),
            true,
            Arc::new(move || {
                if let Some(tx) = tx.lock().unwrap().take() {
                    let _ = tx.send(());
                }
            }),
        );
        tokio::time::timeout(Duration::from_secs(1), closed_rx).await??;
        Ok::<_, BoxError>(())
    }
    .await;
    fixture::remove(&owner, &a).await?;
    fixture::remove(&owner, &b).await?;
    result
}

#[tokio::test]
async fn legacy_algorithm_shapes_are_verified_natively_never_forwarded() -> Result<(), BoxError> {
    use base64::Engine;
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("push-identity-owner") else {
        return Ok(());
    };
    // #356a: a forward would surface this marker status.
    let marker = common::fake_upstream(|_| async {
        Response::builder()
            .status(218)
            .body(common::full("Go must not be reached"))
            .unwrap()
    })
    .await;
    let (routes, _) = routes(&db)?;
    let gateway = Gateway::new(
        Config {
            upstream: Some(format!("http://{marker}").parse()?),
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: Duration::from_secs(10),
            edge_limit: None,
        },
        routes,
    )?
    .with_inventory(&inventory())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(gateway.serve(listener));
    let result = async {
        for alg in ["HS256", "SM2"] {
            let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(json!({"alg":alg,"kid":"unported-key"}).to_string());
            let token = format!("{header}.e30.c2lnbmF0dXJl");
            let mut request = format!("ws://{address}/jmap/ws").into_client_request()?;
            request
                .headers_mut()
                .insert("cookie", format!("access_token={token}").parse()?);
            match tokio_tungstenite::connect_async(request).await {
                Err(tokio_tungstenite::tungstenite::Error::Http(response))
                    if response.status().as_u16() == 401
                        && response.body().as_deref() == Some(b"invalid token\n".as_slice()) => {}
                result => {
                    return Err(format!("{alg} push credential was not refused natively: {result:?}").into())
                }
            }
            let response = common::send(
                address,
                hyper::Request::builder()
                    .uri(format!("http://{address}/api/chat/presence?userIds=1"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(common::full(""))?,
            )
            .await;
            if response.status().as_u16() != 401 {
                return Err(format!(
                    "{alg} presence credential was not refused natively: {}",
                    response.status()
                )
                .into());
            }
        }
        let response = common::send(
            address,
            hyper::Request::builder()
                .uri(format!("http://{address}/_gateway/metrics"))
                .body(common::full(""))?,
        )
        .await;
        let metrics = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        if !metrics.contains("setjoin_gateway_proxied_to_go_total 0\n") {
            return Err(format!("legacy shape reached Go: {metrics}").into());
        }
        Ok::<_, BoxError>(())
    }
    .await;
    server.abort();
    let _ = server.await;
    result
}

#[tokio::test]
async fn executable_installs_native_push_and_the_same_presence_registry() -> Result<(), BoxError> {
    use std::os::unix::process::CommandExt;
    struct Process(crate::common::boot::Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("push-main") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "jmap4-executable").await?;
    let chat: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.chat'",
            &[],
        )
        .await?
        .get(0);
    let result=async{
        owner.execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.chat'",&[]).await?;
        let keys=common::fake_upstream(|_|async{Response::builder().header("content-type","application/json").body(common::full(include_str!("../../../../tests/conformance/jmap/test-jwks.json"))).unwrap()}).await;
        let listener = setjoin_conformance::ports::listener().await;let address=listener.local_addr()?;drop(listener);
        if let Ok(path)=std::env::var("GOFREE_RESOURCE_LEDGER"){
            use std::io::Write;
            writeln!(std::fs::OpenOptions::new().create(true).append(true).open(path)?,"Planned owned gofree-jmap4-gateway-test process, address {address}, assigned DB only; Drop kills/reaps")?;
        }
        let mut command=std::process::Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
        command.arg0("gofree-jmap4-gateway-test").env_clear()
            .env("GATEWAY_LISTEN",address.to_string()).env("GATEWAY_AUTH_UPSTREAM",format!("http://{keys}"))
            .env("AUTHSERVER_JWKS_URL",format!("http://{keys}/jwks")).env("DB_DSN",db.app.as_deref().unwrap_or(&db.dsn))
            .env("DB_WORKER_DSN",&db.dsn).env("DB_DIRECT_DSN",&db.direct).env("JWT_ISSUER","mailserver")
            .env("CORE_RATE_LIMIT","10000").env("SETJOIN_AUTHZ_PRECHECK_TIMEOUT_MS","15000").env("SETJOIN_PG_DEADLINE_MS","30000")
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        let mut process=Process(command.spawn_boot()?);
        let deadline=tokio::time::Instant::now()+Duration::from_secs(15);
        loop {
            if process.0.try_wait()?.is_some(){return Err("native gateway exited before listening".into())}
            if tokio::net::TcpStream::connect(address).await.is_ok(){break}
            if tokio::time::Instant::now()>=deadline{return Err("native gateway never listened".into())}
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut socket=connect(address,a.user).await?;
        if !super::presence(address,a.user).await?{return Err("executable presence did not share the websocket registry".into())}
        let response=common::send(address,hyper::Request::builder().uri(format!("http://{address}/_gateway/metrics")).body(common::full(""))?).await;
        let metrics=String::from_utf8(common::body_bytes(response).await.to_vec())?;
        if !metrics.contains("setjoin_gateway_proxied_to_go_total 0\n"){return Err(format!("executable forwarded native routes {metrics}").into())}
        socket.close(None).await?;
        Ok::<_,BoxError>(())
    }.await;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.chat'",
            &[&chat],
        )
        .await?;
    fixture::remove(&owner, &a).await?;
    result
}
