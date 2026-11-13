//! Recorded socket lifetime behavior. Cases own their processes, DB fixtures,
//! clients and temporary feature state; no Go process is used during replay.
use crate::common::{self, BoxError};
use futures_util::{FutureExt, SinkExt, StreamExt};
use http_body_util::BodyExt;
use hyper::Response;
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    jmap::{push::WebSocketRoute, JmapCommands},
    Config, Gateway, RouteTable, TrustedProxies,
};
use std::{sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn connect(address: std::net::SocketAddr, token: &str) -> Result<Socket, BoxError> {
    let mut request = format!("ws://{address}/jmap/ws").into_client_request()?;
    request
        .headers_mut()
        .insert("cookie", format!("access_token={token}").parse()?);
    Ok(tokio_tungstenite::connect_async(request).await?.0)
}
async fn ready(socket: &mut Socket) -> Result<String, BoxError> {
    socket
        .send(Message::Text(r#"{"@type":"ready"}"#.into()))
        .await?;
    loop {
        match tokio::time::timeout(Duration::from_secs(10), socket.next())
            .await?
            .ok_or("socket ended")??
        {
            Message::Ping(_) => socket.flush().await?,
            Message::Text(text) => return Ok(text.to_string()),
            other => return Err(format!("unexpected ready reply {other:?}").into()),
        }
    }
}
async fn terminal(socket: &mut Socket, strict: Option<u16>) -> Result<String, BoxError> {
    loop {
        match tokio::time::timeout(Duration::from_secs(340), socket.next()).await? {
            Some(Ok(Message::Ping(_))) => {
                let _ = socket.flush().await;
            }
            Some(Ok(Message::Text(text)))
                if serde_json::from_str::<Value>(&text)
                    .ok()
                    .is_some_and(|v| v["@type"] == "SessionRevoked") => {}
            Some(Ok(Message::Close(frame))) => {
                if let Some(code) = strict {
                    let frame = frame.ok_or("missing close payload")?;
                    if u16::from(frame.code) != code {
                        return Err(format!("wrong close {frame:?}").into());
                    }
                    return Ok(
                        json!({"closed":true,"code":code,"reason":frame.reason.as_str()})
                            .to_string(),
                    );
                }
                return Ok("closed".into());
            }
            None | Some(Err(_)) if strict.is_none() => return Ok("closed".into()),
            other => return Err(format!("unexpected terminal frame {other:?}").into()),
        }
    }
}

pub async fn run(case: &str) -> Result<(), BoxError> {
    let _serial = super::SERIAL.lock().await;
    let Some(db) = Db::for_case(case) else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = if case == "guest-no-mailbox" {
        super::mailboxless_fixture(&owner).await?
    } else {
        fixture::account(&owner, "jmap4-lifetime").await?
    };
    let b = fixture::account(&owner, "jmap4-lifetime-foreign").await?;
    let keys = vec![
        "feature.chat".to_owned(),
        "feature.guest_accounts".to_owned(),
        "feature.device_trust_enforcement".to_owned(),
    ];
    let saved: Vec<(String, bool)> = owner
        .query(
            "SELECT key,enabled FROM feature_toggles WHERE key=ANY($1)",
            &[&keys],
        )
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let result=std::panic::AssertUnwindSafe(async {
        owner.execute("UPDATE feature_toggles SET enabled=(key='feature.chat') WHERE key=ANY($1)",&[&keys]).await?;
        if case.starts_with("guest-") {
            owner.execute("INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) VALUES($1,'guest@test','inviter@test',$2,'active')",&[&a.user,&a.domain]).await?;
            owner.execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.guest_accounts'",&[]).await?;
        }
        if case=="device" {
            use sha2::Digest;
            let fingerprint=sha2::Sha256::digest(b"jmap4-device").to_vec();
            owner.execute("INSERT INTO user_devices(user_id,device_name,platform,fingerprint_hash,wipe_requested) VALUES($1,'JMAP4','web',$2,true)",&[&a.user,&fingerprint]).await?;
            owner.execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.device_trust_enforcement'",&[]).await?;
        }
        let unused=common::fake_upstream(|_|async {Response::new(common::full("unused"))}).await;
        let go_env=if case.starts_with("prod-") {vec![("HTTP_MODE","proxy".to_owned())]} else {vec![]};
        let oracle=common::go_oracle::start_named_with_env(&db,unused,"gofree-jmap4",&go_env).await?;
        let recording=oracle.is_some();
        let routes=if recording {RouteTable::proxy_all()} else {
            let commands=Arc::new(JmapCommands { services: None, worker: None,exec:common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn),4)?,keys:common::recovery_keys(),issuer:"mailserver".into(),denylist:None});
            let mut ws=WebSocketRoute::new(commands,db.direct.clone());
            ws.production=case.starts_with("prod-");ws.allowed_host=if ws.production {"mail.test".into()} else {String::new()};
            ws.worker=Some(setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?);
            RouteTable::proxy_all().with(ws)
        };
        let inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;
        if !recording && !inventory["routes"].as_array().unwrap().iter().any(|r|r["path"]=="/jmap/ws" && r["state"]=="ON" && r["upstream"]=="local-rust") {return Err("bundled websocket route is not ON".into())}
        let gateway=Gateway::new(Config {upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse().unwrap()),trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:Duration::from_secs(30),edge_limit:None},routes)?.with_inventory(&inventory.to_string())?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address=listener.local_addr()?;let _server=Server(tokio::spawn(gateway.serve(listener)));
        let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let extra=match case {"device"=>json!({"device":{"id":"jmap4-device"}}),"expiry"=>json!({"exp":now+10}),_=>json!({})};
        let token=common::recovery_token_with(a.user,extra);
        let mut request=format!("ws://{address}/jmap/ws").into_client_request()?;
        request.headers_mut().insert("cookie",format!("access_token={token}").parse()?);
        if case=="bad-key" {request.headers_mut().insert("sec-websocket-key","invalid".parse()?);}
        if case=="prod-pin" {request.headers_mut().insert("origin","https://mail.test".parse()?);}
        let mut frames=Vec::new();
        let response=match tokio_tungstenite::connect_async(request).await {
            Err(tokio_tungstenite::tungstenite::Error::Http(response))=>{
                let body=response.body().clone().unwrap_or_default();
                common::problem_bytes::check_if_problem(response.headers().get("content-type").and_then(|v|v.to_str().ok()),&body);
                let headers:std::collections::BTreeMap<_,_>=response.headers().iter().filter(|(k,_)|!matches!(k.as_str(),"date"|"content-length"|"x-request-id"|"connection")).map(|(k,v)|(k.to_string(),v.to_str().unwrap().to_owned())).collect();
                json!({"status":response.status().as_u16(),"headers":headers,"body":String::from_utf8(body)?})
            }
            Err(error)=>return Err(error.into()),
            Ok((mut socket,_))=>{
                if !matches!(case,"device"|"guest-no-mailbox") {ready(&mut socket).await?;}
                match case {
                    "guest-no-mailbox"=>frames.push(terminal(&mut socket,None).await?),
                    "device"=>{socket.send(Message::Text(r#"{"@type":"ready"}"#.into())).await?;frames.push(terminal(&mut socket,Some(1008)).await?);},
                    "guest-topology"=>{
                        owner.query("SELECT pg_notify($1,$2)",&[&format!("chat:{}",a.user),&r#"{"secret":"denied"}"#]).await?;
                        let quiet=tokio::time::timeout(Duration::from_millis(500),socket.next()).await.is_err();
                        frames.push(quiet.to_string());frames.push(ready(&mut socket).await?);
                    }
                    c if c.starts_with("revoke-")=>{
                        let scope=&c[7..];
                        let second_user=if scope=="all" {b.user} else {a.user};
                        let mut other=connect(address,&common::recovery_token_with(second_user,json!({"jti":"untargeted","fam":"untargeted"}))).await?;
                        ready(&mut other).await?;
                        let bait=json!({"user_id":b.user,"scope":"jti","jti":"blobs1-test"}).to_string();
                        owner.query("SELECT pg_notify('session_revoke',$1)",&[&bait]).await?;
                        ready(&mut socket).await?;
                        let jti=(scope=="jti").then_some("blobs1-test");let family=(scope=="family").then_some("blobs1-test");
                        owner.execute("INSERT INTO session_revocations(user_id,scope,reason,jti,family_id,not_before,expires_at) VALUES($1,$2,'jmap4',$3,$4,now(),now()+interval '10 minutes')",&[&a.user,&scope,&jti,&family]).await?;
                        let before:String=owner.query_one("SELECT to_jsonb(now())::text",&[]).await?.get(0);
                        let payload=json!({"user_id":a.user,"scope":scope,"jti":"blobs1-test","family_id":"blobs1-test","not_before":serde_json::from_str::<String>(&before)?}).to_string();
                        owner.query("SELECT pg_notify('session_revoke',$1)",&[&payload]).await?;
                        frames.push(tokio::time::timeout(Duration::from_secs(10),terminal(&mut socket,None)).await??);
                        frames.push(ready(&mut other).await?);let _=other.close(None).await;
                    }
                    "size"=>{let _=socket.send(Message::Binary(vec![0;10*1024*1024+1].into())).await;frames.push(tokio::time::timeout(Duration::from_secs(10),terminal(&mut socket,None)).await??);},
                    "ping"=>{
                        if !recording {tokio::time::pause();tokio::time::advance(Duration::from_secs(31)).await;tokio::time::resume();}
                        let frame=tokio::time::timeout(Duration::from_secs(35),socket.next()).await?.ok_or("missing keepalive")??;
                        match frame {Message::Ping(payload)=>{frames.push(format!("ping:{:?}",payload.to_vec()));socket.flush().await?;},other=>return Err(format!("expected ping, got {other:?}").into())}
                        frames.push(ready(&mut socket).await?);
                    }
                    "idle"=>{
                        if recording {tokio::time::sleep(Duration::from_secs(73)).await;} else {tokio::time::pause();tokio::time::advance(Duration::from_secs(73)).await;tokio::time::resume();}
                        frames.push(tokio::time::timeout(Duration::from_secs(10),terminal(&mut socket,None)).await??);
                    }
                    "expiry"=>{
                        if recording {frames.push(terminal(&mut socket,Some(1008)).await?);} else {
                            tokio::time::sleep(Duration::from_secs(11)).await;
                            for step in 0..6 {
                                tokio::time::pause();tokio::time::advance(Duration::from_secs(50)).await;tokio::time::resume();
                                if step<5 {ready(&mut socket).await?;} else {frames.push(terminal(&mut socket,Some(1008)).await?);}
                            }
                        }
                    }
                    "limit"=>{
                        let (stop,receive)=tokio::sync::watch::channel(false);
                        let mut clients=tokio::task::JoinSet::new();
                        for _ in 0..999 {
                            let mut client=connect(address,&token).await?;
                            ready(&mut client).await?;
                            let mut receive=receive.clone();
                            clients.spawn(async move {
                                loop {
                                    tokio::select! {
                                        _=receive.changed()=>{let _=client.close(None).await;return},
                                        message=client.next()=>match message {
                                            Some(Ok(Message::Ping(_)))=>{let _=client.flush().await;},
                                            Some(Ok(Message::Close(_)))|Some(Err(_))|None=>return,
                                            _=>{},
                                        }
                                    }
                                }
                            });
                        }
                        let mut request=format!("ws://{address}/jmap/ws").into_client_request()?;request.headers_mut().insert("cookie",format!("access_token={token}").parse()?);
                        let denied=tokio_tungstenite::connect_async(request).await;
                        let _=stop.send(true);
                        while clients.join_next().await.is_some() {}
                        match denied {Err(tokio_tungstenite::tungstenite::Error::Http(response))=>frames.push(format!("{}:{}",response.status().as_u16(),String::from_utf8(response.body().clone().unwrap_or_default())?)),_=>return Err("connection limit did not reject connection 1001".into())}
                    }
                    _=>frames.push(ready(&mut socket).await?),
                }
                let _=socket.close(None).await;
                json!({"status":101,"frames":frames})
            }
        };
        if !recording {
            let response=common::send(address,hyper::Request::builder().uri(format!("http://{address}/_gateway/metrics")).body(common::full("")).unwrap()).await;
            let body=String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
            if !body.contains("setjoin_gateway_proxied_to_go_total 0\n") {return Err(format!("native socket forwarded to Go: {body}").into())}
        }
        let observation=json!({"request":{"method":"GET","path":"/jmap/ws"},"response":response,"effects":{},"audit":[],"notify":[]});
        let name=format!("lifetime-{case}");let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/jmap/push/{name}.json"));
        if recording {golden::record(&path,&json!({"format":1,"route":"GET /jmap/ws","case":name,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"normalization":["best-effort SessionRevoked/transport EOF reduced to terminal closure","native clock advances preserve Go's 30s/70s/300s intervals; token wall expiry remains real"],"observation":observation}))?;}
        else {let expected:Value=serde_json::from_slice(&std::fs::read(path)?)?;golden::compare(&expected["observation"],&observation)?;println!("GOLDEN-REPLAY: GET /jmap/ws :: {name}");}
        Ok::<_,BoxError>(())
    }).catch_unwind().await;
    for (key, value) in saved {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                &[&key, &value],
            )
            .await?;
    }
    fixture::remove(&owner, &a).await?;
    fixture::remove(&owner, &b).await?;
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
