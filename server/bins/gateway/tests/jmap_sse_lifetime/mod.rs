pub mod registry;
pub mod resources;
// One real Go revalidation window; native replay advances the runtime clock.
use super::{common, mailboxless, rows, BoxError, Frames, SERIAL};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    jmap::{push::WebSocketRoute, sse::EventSourceRoute, JmapCommands},
    Config, Gateway, RouteTable, TrustedProxies,
};
use std::{sync::Arc, time::Duration};

pub async fn run() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sse-periodic-authorization") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let member = fixture::account(&owner, "sse-expiry").await?;
    let admin = fixture::account(&owner, "sse-admin").await?;
    let guest = mailboxless(&owner).await?;
    let saved_chat: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.chat'",
            &[],
        )
        .await?
        .get(0);
    let saved: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?
        .get(0);
    let group:i64=owner.query_one("INSERT INTO admin_role_groups(name,permissions) VALUES($1,ARRAY['drive.view']) RETURNING id",&[&format!("jmap5-drive-{}",admin.user)]).await?.get(0);
    let result=async {
  owner.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",&[&admin.user,&group]).await?;
  owner.execute("INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) VALUES($1,'guest@test','inviter@test',$2,'active')",&[&guest.user,&guest.domain]).await?;
  owner.execute("INSERT INTO user_app_entitlements(user_id,app,enabled) VALUES($1,'chat',true)",&[&guest.user]).await?;
  owner.execute("UPDATE feature_toggles SET enabled=true WHERE key=ANY($1)",&[&vec!["feature.guest_accounts","feature.chat"]]).await?;
  let unused=common::fake_upstream(|_|async{Response::new(common::full("unused"))}).await;
  let oracle=common::go_oracle::start_named(&db,unused,None,"gofree-jmap5").await?;
  let recording=oracle.is_some();
  let routes=if recording {RouteTable::proxy_all()}else{
   let commands=Arc::new(JmapCommands{services:None,exec:common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn),4)?,worker:None,keys:common::recovery_keys(),issuer:"mailserver".into(),denylist:None});
   let ws=WebSocketRoute::new(commands,db.direct.clone());
   let presence=setjoin_gateway::jmap::presence::PresenceRoute{commands:ws.commands.clone(),registry:ws.registry.clone()};
   RouteTable::proxy_all().with(EventSourceRoute::new(&ws)).with(presence)
  };
  let inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;
  if !recording&&!inventory["routes"].as_array().unwrap().iter().any(|r|r["path"]=="/jmap/eventsource"&&r["state"]=="ON"&&r["upstream"]=="local-rust"){return Err("bundled SSE route is not ON".into())}
  let gateway=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse().unwrap()),trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:Duration::from_secs(30),edge_limit:None},routes)?.with_inventory(&inventory.to_string())?;
  let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
  let server=tokio::spawn(gateway.serve(listener));
  let observed=async {
   let mut frames=Vec::new();let mut streams=Vec::new();
   for (account,extra,query) in [(&member,json!({"exp":chrono::Utc::now().timestamp()+3}),""),(&admin,json!({}),""),(&guest,json!({"acct":"guest"}),"")] {
    let response=common::send(address,Request::builder().uri(format!("http://{address}/jmap/eventsource?{query}")).header("authorization",format!("Bearer {}",common::recovery_token_with(account.user,extra))).body(common::full(""))?).await;
    if response.status()!=200{return Err(format!("revalidation stream failed: {}",response.status()).into())}
    let mut stream=Frames{body:response.into_body(),buffer:Vec::new()};
    let frame=if account.user==guest.user {
      let deadline=tokio::time::Instant::now()+Duration::from_secs(10);
      loop {let response=common::send(address,Request::builder().uri(format!("http://{address}/api/chat/presence?userIds={}",guest.user)).header("authorization",format!("Bearer {}",common::recovery_token(member.user))).body(common::full(""))?).await;let value:Value=serde_json::from_slice(&common::body_bytes(response).await)?;if value[guest.user.to_string()]==true{break}
       if tokio::time::Instant::now()>=deadline{return Err("guest did not become present".into())}tokio::time::sleep(Duration::from_millis(10)).await;}
      String::new()
    }else{stream.next().await?};
    let frame=frame.replace(&format!("\"{}\"",member.mailbox),"\"<member-mailbox>\"").replace(&format!("\"{}\"",admin.mailbox),"\"<admin-mailbox>\"");
    frames.push(frame);streams.push(stream);
   }
   // Each transport proved its subscription ready. These are fixture inputs,
   // not effects of an HTTP request. No session-revocation row is inserted.
   owner.execute("UPDATE admin_role_groups SET permissions='{}' WHERE id=$1",&[&group]).await?;
   owner.execute("UPDATE user_app_entitlements SET enabled=false WHERE user_id=$1 AND app='chat'",&[&guest.user]).await?;
   let before=rows(&owner,&member,&admin).await?;
   if !recording {
    tokio::time::sleep(Duration::from_secs(4)).await;
    tokio::time::pause();tokio::time::advance(Duration::from_secs(301)).await;tokio::time::resume();
   }
   let deadline=if recording{Duration::from_secs(340)}else{Duration::from_secs(5)};
   let mut terminal=Vec::new();for stream in &mut streams {terminal.push(stream.terminal_kind(deadline).await?);}
   if rows(&owner,&member,&admin).await?!=before{return Err("revalidation wrote mailbox data".into())}
   if !recording {
    let metrics=common::send(address,Request::builder().uri(format!("http://{address}/_gateway/metrics")).body(common::full(""))?).await;
    let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
    if !metrics.contains("setjoin_gateway_proxied_to_go_total 0\n"){return Err("revalidation used Go".into())}
   }
   Ok::<_,BoxError>(json!({"request":{"method":"GET","path":"/jmap/eventsource"},"response":{"status":200,"frames":frames,"closed":terminal},"effects":{},"audit":[],"notify":[]}))
  }.await;
  server.abort();let _=server.await;
  let observed=observed?;
  let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/jmap/sse/periodic-authorization.json");
  if recording {golden::record(&path,&json!({"format":1,"route":"GET /jmap/eventsource","case":"periodic-authorization","go_source":std::env::var("GOFREE_GO_SOURCE")?,"normalization":["fixture mailbox IDs","guest readiness is observed through HTTP presence; all idle streams must close with the recorded chunk termination"],"observation":observed}))?;}
  else {let expected:Value=serde_json::from_slice(&std::fs::read(path)?)?;golden::compare(&expected["observation"],&observed)?;println!("GOLDEN-REPLAY: GET /jmap/eventsource :: periodic-authorization");}
  Ok::<_,BoxError>(())
 }.await;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&group],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&group])
        .await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'",
            &[&saved],
        )
        .await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.chat'",
            &[&saved_chat],
        )
        .await?;
    fixture::remove(&owner, &member).await?;
    fixture::remove(&owner, &admin).await?;
    fixture::remove(&owner, &guest).await?;
    result
}
