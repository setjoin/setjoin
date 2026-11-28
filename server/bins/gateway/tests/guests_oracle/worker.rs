//! Recorded frozen worker ticks, real SQL and authenticated SFU HTTP.
use super::mutations::{normalize, snapshot, Fixture};
use crate::common::{self, BoxError};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use std::sync::{Arc, Mutex};
pub async fn run(kind: &str) -> Result<(), BoxError> {
    let Some(db) = Db::for_case("guests-worker") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let a = fixture::account(&c, "guests1-worker").await?;
    let b = fixture::account(&c, "guests1-foreign").await?;
    let (guest, email) = super::seed_guest(&c, &a).await?;
    let expiry = kind == "expiry";
    if expiry {
        c.execute(
            "UPDATE guest_accounts SET expires_at='2020-01-01T00:00:00Z' WHERE user_id=$1",
            &[&guest],
        )
        .await?;
    }
    let enabled: bool = c
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?
        .get(0);
    c.execute(
        "UPDATE feature_toggles SET enabled=false WHERE key='feature.guest_accounts'",
        &[],
    )
    .await?;
    let intent = if expiry {
        0
    } else {
        c.query_one("INSERT INTO guest_live_eviction_intents(transition_id,guest_user_id,action,room_name,identity,transition_at,retry_until,next_attempt_at,attempt_count) VALUES(gen_random_uuid(),$1::bigint,'disable','11111111-1111-4111-8111-111111111111','u:'||($1::bigint)::text,now()-make_interval(secs=>$2::integer),now()+make_interval(secs=>$3::integer),now()-interval '1 second',$4) RETURNING id",&[&guest,&if kind=="early"{60}else{600},&if kind=="complete"{-1}else{3600},&if kind=="deadletter"{59}else{0}]).await?.get::<_,i64>(0)
    };
    let last: i64 = c
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let result=async{
  let calls=Arc::new(Mutex::new(vec![]));let capture=calls.clone();let case=kind.to_owned();let endpoint=common::fake_upstream(move|r|{let capture=capture.clone();let case=case.clone();async move{
   use http_body_util::BodyExt;use base64::{engine::general_purpose::URL_SAFE_NO_PAD,Engine};use hmac::{Hmac,Mac};
   assert_eq!(r.method(),hyper::Method::POST);assert_eq!(r.uri().path(),"/twirp/livekit.RoomService/RemoveParticipant");assert_eq!(r.headers()["content-type"],"application/protobuf");
   let token=r.headers()["authorization"].to_str().unwrap().strip_prefix("Bearer ").unwrap();let parts=token.split('.').collect::<Vec<_>>();assert_eq!(parts.len(),3);let mut mac=Hmac::<sha2::Sha256>::new_from_slice(b"test-secret").unwrap();mac.update(format!("{}.{}",parts[0],parts[1]).as_bytes());mac.verify_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
   let mut claims:Value=serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();assert_eq!(claims["iss"],"test-key");assert_eq!(claims["exp"].as_i64().unwrap()-claims["iat"].as_i64().unwrap(),21600);assert_eq!(claims["iat"],claims["nbf"]);let now=chrono::Utc::now().timestamp();assert!((claims["iat"].as_i64().unwrap()-now).abs()<5);for key in ["iat","nbf","exp"]{claims[key]=json!("<timestamp>");}
   let bytes=r.into_body().collect().await.unwrap().to_bytes();let mut rest=bytes.as_ref();let mut fields=vec![];while !rest.is_empty(){let tag=rest[0];let length=rest[1]as usize;let text=std::str::from_utf8(&rest[2..2+length]).unwrap().to_owned();fields.push((tag,text));rest=&rest[2+length..];}assert_eq!(fields.len(),2);assert_eq!(fields[0],(10,"11111111-1111-4111-8111-111111111111".into()));assert_eq!(fields[1],(18,format!("u:{guest}")));capture.lock().unwrap().push(json!({"method":"POST","path":"/twirp/livekit.RoomService/RemoveParticipant","claims":claims,"room":fields[0].1,"identity":"u:<guest>"}));
   if matches!(case.as_str(),"failure"|"deadletter"){hyper::Response::builder().status(503).header("content-type","application/json").body(common::full("{\"code\":\"unavailable\",\"msg\":\"SFU unavailable\"}")).unwrap()}else if case=="absent"{hyper::Response::builder().status(404).header("content-type","application/json").body(common::full("{\"code\":\"not_found\",\"msg\":\"participant missing\"}")).unwrap()}else{hyper::Response::builder().header("content-type","application/protobuf").body(common::full("")).unwrap()}
  }}).await;
  let mut before=snapshot(&c,guest).await?;let mut revoked=db.listen("session_revoke").await?;
  let recording=std::env::var_os("GOFREE_RECORD_GUEST_WORKER_BINARY").is_some();
  if let Some(binary)=std::env::var_os("GOFREE_RECORD_GUEST_WORKER_BINARY"){
   let binary=std::fs::canonicalize(binary)?;let parent=binary.parent().ok_or("binary parent")?;let name=format!("gofree-guests1-worker-{}",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos());
   use std::io::Write;if let Ok(path)=std::env::var("GOFREE_RESOURCE_LEDGER"){writeln!(std::fs::OpenOptions::new().append(true).open(path)?,"Planned {name}: one frozen worker tick, assigned fixture DB; --rm.")?;}
   let coverage=std::env::var("GOFREE_GO_COVERAGE_DIR").unwrap_or_else(|_|parent.join("worker-coverage").to_string_lossy().into_owned());std::fs::create_dir_all(&coverage)?;
   let mut command=std::process::Command::new("docker");command.args(["run","--rm","--name",&name,"--label","org.setjoin.task=gofree-guests1","--network","host","-v",&format!("{coverage}:/coverage"),"-e","GOCOVERDIR=/coverage","-v",&format!("{}:/oracle:ro",parent.display()),"-e",&format!("DB_DSN={}",db.dsn),"-e","REQUIRE_DB=1","-e",&format!("GOFREE_GUEST_WORKER_UID={guest}"),"-e",&format!("GOFREE_GUEST_SFU_URL=http://{endpoint}"),"-e",&format!("GOFREE_GUEST_WORKER_MODE={}",if expiry{"expire"}else{"drain"}),"setjoin-ci-linux-tc:local-amd64",&format!("/oracle/{}",binary.file_name().unwrap().to_str().unwrap()),"-test.run=^TestRecordGuestLifecycleTick$","-test.v","-test.gocoverdir=/coverage"]);let result=tokio::task::spawn_blocking(move||command.output()).await??;
   if !result.status.success(){return Err(format!("worker recorder: {}",String::from_utf8_lossy(&result.stdout)).into())}
  }else{let worker=setjoin_gateway::guest_worker::GuestLifecycle{db:setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?.with_audit_keys("22".repeat(32),String::new()),endpoint:Some(format!("http://{endpoint}")),key:"test-key".into(),secret:"test-secret".into()};if expiry{worker.expire().await?}else{worker.drain(Some(guest)).await?}}
  let mut after=snapshot(&c,guest).await?;
  if !expiry{let row=c.query_one("SELECT attempt_count,completed_at IS NOT NULL,extract(epoch FROM next_attempt_at-last_attempt_at)::float8,next_attempt_at='infinity'::timestamptz FROM guest_live_eviction_intents WHERE id=$1",&[&intent]).await?;if true{assert_eq!(row.get::<_,i32>(0),if kind=="deadletter"{60}else{1});assert_eq!(row.get::<_,bool>(1),kind=="complete");assert_eq!(row.get::<_,bool>(3),kind=="deadletter");if !matches!(kind,"deadletter"|"complete"){let delay=row.get::<_,f64>(2);let expected=if kind=="early"{10.0}else if kind=="failure"{1.0}else{60.0};assert!((delay-expected).abs()<1.0,"retry delay {delay}");}}}
  let mut audit=c.query("SELECT to_jsonb(t)::text FROM admin_audit_log t WHERE id>$1 ORDER BY id",&[&last]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?;
  let mut notify=revoked.drain(&c).await?.iter().map(|s|serde_json::from_str::<Value>(s)).collect::<Result<Vec<_>,_>>()?;
  let mut f=Fixture{a:&a,b:&b,guest,email:&email,domain:c.query_one("SELECT id FROM domains WHERE name='guest.invalid'",&[]).await?.get(0),profile:0,invite:0,invites:vec![],approval:0,fixed_expiry:false,revocations:vec![],domain_names:[c.query_one("SELECT name FROM domains WHERE id=$1",&[&a.domain]).await?.get(0),c.query_one("SELECT name FROM domains WHERE id=$1",&[&b.domain]).await?.get(0)]};
  for rows in [&before["session_revocations"],&after["session_revocations"]]{for row in rows{f.revocations.push(row["id"].as_i64().unwrap());}}
  let mut effects=vec![];for table in before.keys().cloned().collect::<Vec<_>>(){let mut old=json!(before.remove(&table).unwrap());let mut new=json!(after.remove(&table).unwrap());normalize(&mut old,&table,&f)?;normalize(&mut new,&table,&f)?;worker_normalize(&mut old,"",intent,guest)?;worker_normalize(&mut new,"",intent,guest)?;effects.push(json!({"table":table,"before":old,"after":new}));}
  for v in &mut audit{normalize(v,"audit",&f)?;}for v in &mut notify{normalize(v,"notify",&f)?;}
  let mut observation=json!({"effects":effects,"audit":audit,"notify":notify,"sfu":calls.lock().unwrap().clone()});super::mail::replace(&mut observation,&f.domain_names[0],"host.test");
  let file=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/guests/goldens/worker-{kind}.json"));if recording{super::record(&file,&json!({"format":1,"worker":"guest-lifecycle","case":kind,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}))?;}else{let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;golden::compare(&expected["observation"],&observation)?;eprintln!("GOLDEN-WORKER-REPLAY: guest-lifecycle :: {kind}");}Ok::<_,BoxError>(())
 }.await;
    c.batch_execute("BEGIN;SET LOCAL session_replication_role=replica")
        .await?;
    c.execute("DELETE FROM admin_audit_log WHERE id>$1", &[&last])
        .await?;
    c.batch_execute("COMMIT").await?;
    c.execute("DELETE FROM users WHERE id=$1", &[&guest])
        .await?;
    c.execute(
        "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'",
        &[&enabled],
    )
    .await?;
    common::remove_blob_account(&c, &b).await?;
    common::remove_blob_account(&c, &a).await?;
    result
}
fn worker_normalize(v: &mut Value, key: &str, intent: i64, guest: i64) -> Result<(), BoxError> {
    match v {
        Value::Object(xs) => {
            let is_intent = xs.contains_key("transition_id");
            for (k, v) in xs {
                if k == "id" && is_intent {
                    if *v != intent {
                        return Err("unknown intent".into());
                    }
                    *v = json!("<intent>");
                } else {
                    worker_normalize(v, k, intent, guest)?;
                }
            }
        }
        Value::Array(xs) => {
            for v in xs {
                worker_normalize(v, key, intent, guest)?;
            }
        }
        Value::String(s) => {
            if key == "transition_id" {
                if s.len() != 36 {
                    return Err("transition UUID".into());
                }
                *s = "<transition>".into();
            } else if key == "identity" {
                if s != &format!("u:{guest}") {
                    return Err("wrong identity".into());
                }
                *s = "u:<guest>".into();
            } else if key == "completed_at" {
                chrono::DateTime::parse_from_rfc3339(s)?;
                *s = "<timestamp>".into();
            }
        }
        _ => {}
    }
    Ok(())
}
