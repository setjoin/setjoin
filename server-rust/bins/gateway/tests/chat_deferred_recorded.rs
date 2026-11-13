//! Original frozen-Go presence floors, now replayed natively with Go unset (#418).
mod common;
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
use common::BoxError;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
#[tokio::test]
async fn presence_success_is_native() -> Result<(), BoxError> {
    run("presence", "success").await
}
#[tokio::test]
async fn presence_foreign_is_native() -> Result<(), BoxError> {
    run("presence", "foreign").await
}
#[tokio::test]
async fn presence_invalid_is_native() -> Result<(), BoxError> {
    run("presence", "invalid").await
}
async fn run(route: &str, case: &str) -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("chat3-deferred") else {
        return Ok(());
    };
    let owner = std::sync::Arc::new(db.connect().await?);
    let actor = setjoin_conformance::fixture::account(&owner, "chat3-deferred").await?;
    let foreign = setjoin_conformance::fixture::account(&owner, "chat3-foreign").await?;
    let channel:i64=owner.query_one("INSERT INTO chat_channels(kind,name,visibility,created_by) VALUES('channel',$1,'private',$2) RETURNING id",&[&format!("gofree-chat3-deferred-{}",actor.user),&actor.user]).await?.get(0);
    owner
        .execute(
            "INSERT INTO chat_channel_members(channel_id,user_id,role) VALUES($1,$2,'owner')",
            &[&channel, &actor.user],
        )
        .await?;
    let raw:String=owner.query_one("SELECT chat_message_send($1,$2,'Translate this message',NULL,'{}',NULL,'[]','text',NULL)::text",&[&actor.user,&channel]).await?.get(0);
    let message = serde_json::from_str::<Value>(&raw)?["messageId"]
        .as_i64()
        .ok_or("message ID")?;
    let toggles = ["feature.chat", "feature.assist", "feature.chat_compliance"];
    let mut previous = Vec::new();
    for key in toggles {
        previous.push(
            owner
                .query_opt("SELECT enabled FROM feature_toggles WHERE key=$1", &[&key])
                .await?
                .map(|r| r.get::<_, bool>(0)),
        );
        owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES($1,true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[&key]).await?;
    }
    let provider_seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let seen = provider_seen.clone();
    let c = owner.clone();
    let user = actor.user;
    let provider=common::fake_upstream(move|request|{let seen=seen.clone();let c=c.clone();async move{
  let uri=request.uri().to_string();let method=request.method().to_string();let bytes=request.into_body().collect().await.unwrap().to_bytes();let body:Value=serde_json::from_slice(&bytes).unwrap();
  let audited:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM chat_audit_log WHERE channel_id=$1 AND user_id=$2 AND action='translate.egress')",&[&channel,&user]).await.unwrap().get(0);
  seen.lock().unwrap().push(json!({"uri":uri,"method":method,"body":body,"auditedBeforeEgress":audited}));
  Response::builder().header("content-type","application/json").body(common::full(r#"{"choices":[{"message":{"content":"Chat3 translated"}}]}"#)).unwrap()
 }}).await;
    let config = [
        ("assist.provider_url", format!("http://{provider}/v1")),
        ("assist.model", "chat3-oracle".into()),
    ];
    let mut old_config = Vec::new();
    for (key, value) in &config {
        old_config.push(
            owner
                .query_opt("SELECT value::text FROM system_config WHERE key=$1", &[key])
                .await?
                .map(|r| r.get::<_, String>(0)),
        );
        owner.execute("INSERT INTO system_config(key,value) VALUES($1,to_jsonb($2::text)) ON CONFLICT(key) DO UPDATE SET value=excluded.value",&[key,value]).await?;
    }
    let before = deferred_state(&owner, channel, message).await?;
    let mut notifications = db.listen(&format!("chat:{}", actor.user)).await?;
    let result=async{
  let registration=if route=="presence"{"GET /chat/presence"}else{"POST /chat/messages/{id}/translate"};let method=if route=="presence"{"GET"}else{"POST"};
  let uri=if route=="presence"{if case=="invalid"{"/api/chat/presence?userIds=bad".into()}else{format!("/api/chat/presence?userIds={},{}",actor.user,foreign.user)}}else{format!("/api/chat/messages/{message}/translate")};
  let body=if route=="translate"{if case=="invalid"{"{"}else{r#"{"targetLocale":"fr","userId":0}"#}}else{""};
  let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/chat-b/goldens/deferred-{route}-{case}.json"));
  let recording=std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
  let expected=if recording{None}else{Some(serde_json::from_slice::<Value>(&std::fs::read(&path)?)?)};
  let s3=common::fake_upstream(|_|async{Response::builder().header("content-type","application/xml").body(common::full("<ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>mailblobs</Bucket><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>")).unwrap()}).await;
  let oracle=common::go_oracle::start_named(&db,s3,None,"gofree-chat3-deferred").await?;
  let routes=if oracle.is_some(){RouteTable::proxy_all()}else{
   let commands=std::sync::Arc::new(setjoin_gateway::jmap::JmapCommands{services:None,worker:None,exec:common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn),2)?,keys:common::recovery_keys(),issuer:"mailserver".into(),denylist:None});
   RouteTable::proxy_all().with(setjoin_gateway::jmap::presence::PresenceRoute{commands,registry:setjoin_jmap::connections::ConnectionRegistry::default()})
  };
  let gateway=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},routes)?.with_inventory(include_str!("../route-inventory.json"))?;
  let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let task=tokio::spawn(gateway.serve(listener));
  let response=common::send(address,Request::builder().method(method).uri(&uri).header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("x-request-id","chat3-deferred").header("authorization",format!("Bearer {}",token(if case=="foreign"{foreign.user}else{actor.user}))).body(common::full(body))?).await;
  let status=response.status().as_u16();let headers=response.headers().iter().filter(|(k,_)|!matches!(k.as_str(),"date"|"content-length"|"transfer-encoding")).map(|(k,v)|Ok((k.as_str().to_owned(),Value::String(v.to_str()?.to_owned())))).collect::<Result<serde_json::Map<_,_>,BoxError>>()?;
  let mut body_value:Value=serde_json::from_slice(&common::body_bytes(response).await)?; // checks Go problem bytes before parsing native responses
  if route=="presence"{if let Some(map)=body_value.as_object_mut(){for(id,alias)in[(actor.user,"<actor>"),(foreign.user,"<foreign>")]{if let Some(value)=map.remove(&id.to_string()){map.insert(alias.into(),value);}}}}
  if let Some(instance)=body_value.get_mut("instance"){if instance.as_str()==Some(&format!("/chat/messages/{message}/translate")){*instance="/chat/messages/{id}/translate".into();}}
  if !recording{let response=common::send(address,Request::builder().uri("/_gateway/metrics").body(common::full(""))?).await;let metrics=String::from_utf8(common::body_bytes(response).await.to_vec())?;assert!(metrics.lines().any(|s|s=="setjoin_gateway_proxied_to_go_total 0"));assert!(metrics.lines().any(|s|s=="setjoin_gateway_proxied_to_go_by_family_total{family=\"F12\"} 0"));}
  task.abort();let _=task.await;drop(oracle);
  let after=deferred_state(&owner,channel,message).await?;
  let audit=owner.query("SELECT jsonb_build_object('action',action,'after',after_state-'_checksum'-'_prev_checksum','targetType',target_type)::text FROM chat_audit_log WHERE channel_id=$1 ORDER BY id",&[&channel]).await?.into_iter().map(|r|serde_json::from_str::<Value>(r.get::<_,&str>(0))).collect::<Result<Vec<_>,_>>()?;
  let notify=notifications.drain(&owner).await?;
  let observed=json!({"effects":{"before":before,"after":after},"audit":audit,"notify":notify,"request":{"method":method,"path":registration.split_once(' ').unwrap().1},"response":{"status":status,"headers":headers,"body":body_value},"provider":provider_seen.lock().unwrap().clone()});
  if recording{
   let expected_status=if case=="invalid"{400}else if route=="translate"&&case=="foreign"{422}else{200};if status!=expected_status{return Err(format!("unexpected deferred Go response: {observed}").into());}
   if route=="translate"&&case=="success"&&observed["provider"].as_array().unwrap().len()!=1{return Err("missing real provider exchange".into());}
   setjoin_conformance::golden::record(&path,&json!({"format":1,"route":registration,"case":format!("deferred-{route}-{case}"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observed}))?;
  }else{setjoin_conformance::golden::compare(&expected.as_ref().unwrap()["observation"]["response"],&observed["response"])?;}
  Ok::<_,BoxError>(())
 }.await;
    for ((key, _), previous) in config.iter().zip(old_config) {
        if let Some(v) = previous {
            owner
                .execute(
                    "UPDATE system_config SET value=$2::text::jsonb WHERE key=$1",
                    &[key, &v],
                )
                .await?;
        } else {
            owner
                .execute("DELETE FROM system_config WHERE key=$1", &[key])
                .await?;
        }
    }
    for (key, previous) in toggles.iter().zip(previous) {
        if let Some(v) = previous {
            owner
                .execute(
                    "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                    &[key, &v],
                )
                .await?;
        } else {
            owner
                .execute("DELETE FROM feature_toggles WHERE key=$1", &[key])
                .await?;
        }
    }
    owner.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM chat_audit_log WHERE channel_id={channel};COMMIT")).await?;
    owner
        .execute("DELETE FROM chat_messages WHERE channel_id=$1", &[&channel])
        .await?;
    owner
        .execute(
            "DELETE FROM chat_channels WHERE id=$1 AND created_by=$2",
            &[&channel, &actor.user],
        )
        .await?;
    setjoin_conformance::fixture::remove(&owner, &actor).await?;
    setjoin_conformance::fixture::remove(&owner, &foreign).await?;
    result
}

fn token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let header =
        URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":"test-es256-1","typ":"JWT"}).to_string());
    let claims=URL_SAFE_NO_PAD.encode(json!({"uid":user,"email":"chat-oracle@test","admin":true,"perms":["chat.compliance_manage"],"typ":"access","jti":"chat3-test","fam":"chat3-test","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600}).to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let sig: p256::ecdsa::Signature = key.sign(format!("{header}.{claims}").as_bytes());
    format!(
        "{header}.{claims}.{}",
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    )
}

async fn deferred_state(
    c: &tokio_postgres::Client,
    channel: i64,
    message: i64,
) -> Result<Value, BoxError> {
    let raw:String=c.query_one("SELECT jsonb_build_object('body',body,'payload',payload,'seq',seq,'changeSeq',(SELECT change_seq FROM chat_channels WHERE id=$2),'chainValid',(SELECT coalesce(bool_and(valid),true) FROM verify_chat_audit_chain($2)))::text FROM chat_messages WHERE id=$1 AND channel_id=$2",&[&message,&channel]).await?.get(0);
    Ok(serde_json::from_str(&raw)?)
}
