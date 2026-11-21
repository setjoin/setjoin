//! Frozen-Go push/possession HTTP and committed-effect oracle.
mod common;
#[path="common/webauthn_commit.rs"] mod commit;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, golden, harness::Db};
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
              let (stream,peer)=accepted.unwrap();let server=server.clone();
              connections.spawn(async move {
               let service=hyper::service::service_fn(move |mut req:Request<hyper::body::Incoming>|{
                let server=server.clone();req.extensions_mut().insert(setjoin_auth::ConnectionMeta{peer,tls:false});
                async move {
                 let mut response=server.handle(req.map(|b|b.map_err(std::io::Error::other).boxed())).await;
                 if mutant {*response.status_mut()=hyper::StatusCode::from_u16(599).unwrap();}
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
    let mut inventory: Value = serde_json::from_str(setjoin_gateway::inventory::BUNDLED).unwrap();
    inventory["routes"].as_array_mut().unwrap().retain(|r| {
        r["listener"] == "auth" || r["path"] == "/auth/push/" || r["path"] == "/auth/backup-codes/"
    });
    for r in inventory["routes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .filter(|_| record.is_some())
    {
        r["state"] = json!(if record.is_some() { "OFF" } else { "ON" });
        r["upstream"] = json!(if record.is_some() {
            "go-auth"
        } else {
            "rust-auth"
        });
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
        .header("host", "auth.idmfa3.test")
        .header("user-agent", "IDMFA3 oracle");
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
    for name in [
        "content-type",
        "cache-control",
        "set-cookie",
        "x-content-type-options",
        "www-authenticate",
        "allow",
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

const SOURCE: &str = "e6af2a7f075f5d6b86d33fdb3dbedd794e3158ec";
const VAPID: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
fn corpus() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/identity-push/goldens")
}
async fn run(route: &str, kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA3").expect("assigned DB required");
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    // Public key derivation uses the exact frozen-Go startup key.
    cfg.vapid_private_key = if kind=="absent-key"{String::new()}else{VAPID.into()};
    cfg.signing_alg = "ES256".into();
    cfg.dsn = db.dsn.clone();
    let server = auth_server(
        Arc::new(
            AuthServer::load(
                setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
                    .unwrap(),
                cfg,
            )
            .await?,
        ),
        mutant,
    )
    .await;
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none());
    let gw = gateway(server.addr, record.clone()).await;
    let path = match route {
        "vapid" => "/auth/push/vapid-key",
        "push-subtree"=>if kind=="invalid-input"{"/auth/push/vapid-key"}else{"/auth/push/unknown"},
        "backup-subtree"=>if kind=="invalid-input"{"/auth/backup-codes/verify"}else{"/auth/backup-codes/unknown"},
        _ => unreachable!(),
    };
    let method = if kind=="head"{"HEAD"}else if route.ends_with("-subtree")&&kind=="invalid-input"{"DELETE"}else{"GET"};
    let registration=match route{"push-subtree"=>"* /auth/push/".to_owned(),"backup-subtree"=>"* /auth/backup-codes/".to_owned(),_=>format!("GET {path}")};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let foreign=format!("Bearer {}",setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(), &json!({"uid":336999,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600}).to_string()));
    let payload = if kind == "invalid-input" { "{" } else { "" };
    let headers = match kind {
        "cross-tenant" => vec![("authorization", foreign.as_str())],
        "invalid-input" => vec![("authorization", "Bearer broken")],
        _ => vec![],
    };
    let response = request(gw.addr, method, path, payload.into(), &headers).await?;
    let actual = json!({"format":1,"go_source":SOURCE,"route":registration,"case":format!("{route}-{kind}"),"observation":{"request":{"method":method,"path":path,"body":payload},"response":{"status":response.0,"headers":response.1,"body":response.2},"audit":[],"notify":[],"effects":[]}});
    assert_go_recording(gw.addr, record.is_some()).await?;
    let file = corpus().join(format!("{route}-{kind}.json"));
    let canonical=route.ends_with("-subtree")||method=="HEAD";
    let qualified=corpus().parent().unwrap().join("qualified").join(format!("{route}-{kind}.json"));
    let result = (|| -> Result<(), Err> {
        if record.is_some() && !file.exists() {
            std::fs::create_dir_all(corpus())?;
            golden::record(&file, &actual)?;
        }
        let expected: Value = serde_json::from_str(&std::fs::read_to_string(file)?)?;
        if mutant {
            assert!(
                golden::compare(&expected, &actual).is_err(),
                "mutant survived"
            );
        } else {
            golden::compare(&expected, &actual)?;
        }
        if canonical {
            let normalized=registration_observation(&actual);
            if record.is_some()&&!qualified.exists(){golden::record(&qualified,&normalized)?;}
            let expected:Value=serde_json::from_str(&std::fs::read_to_string(&qualified)?)?;
            if mutant{assert!(golden::compare(&expected,&normalized).unwrap_err().contains("/observation/response/status"));}else{golden::compare(&expected,&normalized)?;}
        }
        oracle_receipt(&actual,mutant);
        Ok(())
    })();
    if record.is_none() {
        let (_, _, metrics) =
            request(gw.addr, "GET", "/_gateway/metrics", String::new(), &[]).await?;
        assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));
    }
    gw.close().await;
    server.close().await;
    result
}
#[tokio::test]
async fn vapid_success() {
    run("vapid", "success", false).await.unwrap();
}

#[tokio::test]
async fn vapid_cross_tenant() {
    run("vapid", "cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn vapid_invalid_input() {
    run("vapid", "invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn vapid_status_mutant() {
    run("vapid", "success", true).await.unwrap();
}

async fn grant_rows(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, Err> {
    let mut users = vec![];
    let mut grants = vec![];
    let mut audit = vec![];
    for (uid, label) in [(a.user, "actor"), (b.user, "foreign")] {
        let r=c.query_one("SELECT possession_password_failed_attempts,possession_password_locked_until>now(),totp_failed_attempts,totp_locked_until>now(),last_totp_used_at IS NOT NULL,factor_generation FROM users WHERE id=$1",&[&uid]).await?;
        users.push(json!({"owner":label,"password_failures":r.get::<_,i32>(0),"password_locked":r.get::<_,Option<bool>>(1).unwrap_or(false),"totp_failures":r.get::<_,i32>(2),"totp_locked":r.get::<_,Option<bool>>(3).unwrap_or(false),"totp_used":r.get::<_,bool>(4),"generation":r.get::<_,i64>(5)}));
        for r in c.query("SELECT session_jti,operation,target_ref,proof_method,encode(proving_factor_id,'hex'),bound_factor_generation,token_scope,refresh_family_id,expires_at>now() FROM mfa_reauth_step_ups WHERE user_id=$1 ORDER BY token_hash",&[&uid]).await?{
   grants.push(json!({"owner":label,"jti":r.get::<_,String>(0),"operation":r.get::<_,String>(1),"target":r.get::<_,Option<String>>(2),"method":r.get::<_,String>(3),"factor":r.get::<_,Option<String>>(4),"generation":r.get::<_,i64>(5),"scope":r.get::<_,String>(6),"family":r.get::<_,Option<String>>(7),"live":r.get::<_,bool>(8)}));
  }
        for r in c.query("SELECT action,notes,ip::text,target_type,target_id FROM admin_audit_log WHERE user_id=$1 ORDER BY id",&[&uid]).await?{
   assert_eq!(r.get::<_,Option<i64>>(4),Some(uid));
   audit.push(json!({"owner":label,"action":r.get::<_,String>(0),"notes":r.get::<_,Option<String>>(1),"ip":r.get::<_,Option<String>>(2),"target_type":r.get::<_,Option<String>>(3)}));
  }
    }
    Ok(json!({"users":users,"grants":grants,"audit":audit}))
}
async fn run_grant(kind: &str, mutant: bool) -> Result<(), Err> {
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA3-grant").unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idmfa3-actor").await?;
    let b = fixture::account(&c, "idmfa3-foreign").await?;
    let rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    for (uid, password) in [(a.user, "Password1!"), (b.user, "Foreign1!")] {
        c.execute(
            "UPDATE users SET password_hash=$2,factor_generation=2 WHERE id=$1",
            &[&uid, &bcrypt::hash(password, 4)?],
        )
        .await?;
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at) VALUES(encode(digest(($1::bigint)::text,'sha256'),'hex'),$1,'prior','totp.enroll','password',2,'session',now()+interval '5 minutes')",&[&uid]).await?;
    }
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    cfg.dsn = db.dsn.clone();
    cfg.signing_alg = "ES256".into();
    cfg.db_encryption_key = "2".repeat(64);
    cfg.vapid_private_key = VAPID.into();
    let operation=setjoin_identity::totp::Operation::PasswordGrant;
    let command="mfa-password-grant";
    let (executor,mut wire)=fault_executor(&db,kind,command).await?;
    let server = auth_server(
        Arc::new(
            AuthServer::load(
                executor,
                cfg,
            )
            .await?,
        ),
        mutant,
    )
    .await;
    let gw = gateway(server.addr, record.clone()).await;
    let result=async {
  let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();let uid=if kind=="cross-tenant"{b.user}else{a.user};
  let claims=json!({"uid":uid,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600,"jti":"idmfa3-actor"});
  let bearer=format!("Bearer {}",setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&claims.to_string()));
  let path="/auth/mfa/reauth";
  let payload=if kind=="invalid-input"{"{}".into()}else{json!({"password":"Password1!","operation":"totp.enroll","user_id":b.user}).to_string()};
  let mut listener=db.listen("session_revoke").await?;
  let before=grant_rows(&c,&a,&b).await?;
  let (status,headers,mut raw)=request(gw.addr,"POST",path,payload.clone(),&[("authorization",&bearer)]).await?;
  if !mutant&&matches!(kind,"success"|"repeat")&&status!=200{return Err(format!("expected success status {}, got {status}",200).into());}
  if let Ok(v)=serde_json::from_str::<Value>(&raw){if let Some(token)=v["reauth_token"].as_str(){
   use sha2::{Digest,Sha256};assert_eq!(token.len(),64);assert!(token.bytes().all(|b|b.is_ascii_hexdigit()));
   let hash=format!("{:x}",Sha256::digest(token.as_bytes()));
   let bound:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM mfa_reauth_step_ups WHERE user_id=$1 AND token_hash=$2 AND session_jti='idmfa3-actor' AND operation='totp.enroll' AND proof_method='password' AND token_scope='session' AND refresh_family_id IS NULL AND bound_factor_generation=2 AND expires_at>now()+interval '290 seconds' AND expires_at<now()+interval '301 seconds')",&[&a.user,&hash]).await?.get(0);assert!(bound,"returned secret must match full persisted grant before masking");raw=raw.replace(token,"<reauth>");
  }}
  let repeat=if kind=="repeat" {
   let (status,headers,mut raw)=request(gw.addr,"POST",path,payload.clone(),&[("authorization",&bearer)]).await?;
   let v:Value=serde_json::from_str(&raw)?;let token=v["reauth_token"].as_str().ok_or("repeat grant missing")?;
   use sha2::{Digest,Sha256};let hash=format!("{:x}",Sha256::digest(token.as_bytes()));
   assert_eq!(token.len(),64);let bound:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM mfa_reauth_step_ups WHERE user_id=$1 AND token_hash=$2 AND session_jti='idmfa3-actor' AND operation='totp.enroll' AND proof_method='password' AND token_scope='session' AND bound_factor_generation=2 AND expires_at>now()+interval '290 seconds')",&[&a.user,&hash]).await?.get(0);assert!(bound);raw=raw.replace(token,"<reauth>");
   Some(json!({"status":status,"headers":headers,"body":raw}))
  }else{None};
  let after=grant_rows(&c,&a,&b).await?;let notifications=listener.drain(&c).await?;
  if kind.starts_with("commit-") {
      fault_probe(&db,&c,&a,&b,&keys,kind,operation,&mut wire,status,&headers,&raw).await?;
      if kind=="commit-before" {golden::compare(&before,&after)?;}else{assert_ne!(before,after,"committed transaction must publish its domain effects");}
      return Ok::<(),Err>(());
  }
  let mut actual=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("reauth-{kind}"),"observation":{"request":{"method":"POST","path":path,"body":payload.replace(&b.user.to_string(),"<foreign>")},"response":{"status":status,"headers":headers,"body":raw},"effects":after,"audit":after["audit"],"notify":notifications}});
  if let Some(repeat)=repeat{actual["observation"]["repeat_response"]=repeat;}
  let effects=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("reauth-{kind}-row-effects"),"effects":[{"table":"possession","before":before,"after":after}]});
  assert_go_recording(gw.addr,record.is_some()).await?;
  let file=corpus().join(format!("reauth-{kind}.json"));let rowfile=corpus().join(format!("reauth-{kind}-rows.json"));
  if record.is_some()&&!file.exists(){golden::record(&file,&actual)?;let mut tracer=effects.clone();tracer["case"]=json!(format!("reauth-{kind}-rows"));golden::record(&rowfile,&tracer)?;}
  let qualified=corpus().parent().unwrap().join("qualified").join(format!("reauth-{kind}-rows.json"));
  if record.is_some()&&!qualified.exists(){std::fs::create_dir_all(qualified.parent().unwrap())?;golden::record(&qualified,&effects)?;}
  let expected:Value=serde_json::from_str(&std::fs::read_to_string(&file)?)?;
  if mutant{assert!(golden::compare(&expected,&actual).is_err(),"mutant survived");}else{golden::compare(&expected,&actual)?;let old:Value=serde_json::from_str(&std::fs::read_to_string(rowfile)?)?;
  let mut tracer=effects.clone();tracer["case"]=json!(format!("reauth-{kind}-rows"));
  golden::compare(&old,&tracer)?;
  golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(qualified)?)?,&effects)?;}
  if record.is_none(){let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));}else{let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;let hops=metrics.lines().find_map(|line|line.strip_prefix("setjoin_gateway_proxied_to_go_total ")).ok_or("Go-hop metric missing")?.parse::<u64>()?;assert!(hops>0,"recordings must traverse frozen Go");}
  oracle_receipt(&actual,mutant);
  Ok::<(),Err>(())
 }.await;
    gw.close().await;
    server.close().await;
    for uid in [a.user, b.user] {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT")).await?;
        c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&uid])
            .await?;
    }
    common::restore_receipts(&c, &receipts).await;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if let Some(rate) = rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&rate],
        )
        .await?;
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?;
    }
    result
}
#[tokio::test]
async fn reauth_success() {
    run_grant("success", false).await.unwrap();
}
#[tokio::test]
async fn reauth_cross_tenant() {
    run_grant("cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn reauth_invalid_input() {
    run_grant("invalid-input", false).await.unwrap();
}

#[tokio::test]
async fn reauth_repeat() {
    run_grant("repeat", false).await.unwrap();
}
#[tokio::test]
async fn reauth_status_mutant() {
    run_grant("success", true).await.unwrap();
}

async fn run_totp_grant(kind: &str, mutant: bool) -> Result<(), Err> {
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA3-totp-grant").unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idmfa3-actor").await?;
    let b = fixture::account(&c, "idmfa3-foreign").await?;
    let rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    for (uid, password) in [(a.user, "Password1!"), (b.user, "Foreign1!")] {
        c.execute(
            "UPDATE users SET password_hash=$2,factor_generation=2 WHERE id=$1",
            &[&uid, &bcrypt::hash(password, 4)?],
        )
        .await?;
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at) VALUES(encode(digest(($1::bigint)::text,'sha256'),'hex'),$1,'prior','totp.enroll','password',2,'session',now()+interval '5 minutes')",&[&uid]).await?;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let actor_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let mut foreign_secret = "JBSWY3DPEHPK3PXP".to_owned();
    while [-30, 0, 30].iter().any(|offset| {
        setjoin_identity::totp::validate(
            &setjoin_identity::totp::code(actor_secret, stamp + offset).unwrap(),
            &foreign_secret,
            stamp,
        )
    }) {
        foreign_secret.push_str("ABCD2345");
    }
    for (uid, secret) in [(a.user, actor_secret), (b.user, foreign_secret.as_str())] {
        c.execute(
            "UPDATE users SET totp_enabled=true,totp_secret_enc=pgp_sym_encrypt($2,$3) WHERE id=$1",
            &[&uid, &secret, &"2".repeat(64)],
        )
        .await?;
    }
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    cfg.dsn = db.dsn.clone();
    cfg.signing_alg = "ES256".into();
    cfg.db_encryption_key = "2".repeat(64);
    cfg.vapid_private_key = VAPID.into();
    let operation=setjoin_identity::totp::Operation::TotpGrant;
    let command="mfa-totp-grant";
    let (executor,mut wire)=fault_executor(&db,kind,command).await?;
    let server = auth_server(
        Arc::new(
            AuthServer::load(
                executor,
                cfg,
            )
            .await?,
        ),
        mutant,
    )
    .await;
    let gw = gateway(server.addr, record.clone()).await;
    let result=async {
  let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();let uid=if kind=="cross-tenant"{b.user}else{a.user};
  let claims=json!({"uid":uid,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600,"jti":"idmfa3-actor"});
  let bearer=format!("Bearer {}",setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&claims.to_string()));
  let path="/auth/mfa/possession/totp";
  let code=if kind=="lockout"{"invalid".into()}else{setjoin_identity::totp::code(actor_secret,now as i64).unwrap()};
  if kind=="lockout"{c.execute("UPDATE users SET totp_failed_attempts=4 WHERE id=$1",&[&a.user]).await?;}
  let payload=if kind=="invalid-input"{"{}".into()}else{json!({"code":code,"operation":"recovery.regenerate","user_id":b.user}).to_string()};
  let mut listener=db.listen("session_revoke").await?;
  let before=grant_rows(&c,&a,&b).await?;
  let (status,headers,mut raw)=request(gw.addr,"POST",path,payload.clone(),&[("authorization",&bearer)]).await?;
  if !mutant&&matches!(kind,"success"|"repeat")&&status!=200{return Err(format!("expected success status {}, got {status}",200).into());}
  if let Ok(v)=serde_json::from_str::<Value>(&raw){if let Some(token)=v["reauth_token"].as_str(){
   use sha2::{Digest,Sha256};assert_eq!(token.len(),64);assert!(token.bytes().all(|b|b.is_ascii_hexdigit()));
   let hash=format!("{:x}",Sha256::digest(token.as_bytes()));
   let bound:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM mfa_reauth_step_ups WHERE user_id=$1 AND token_hash=$2 AND session_jti='idmfa3-actor' AND operation='recovery.regenerate' AND proof_method='totp' AND token_scope='session' AND refresh_family_id IS NULL AND bound_factor_generation=2 AND expires_at>now()+interval '290 seconds' AND expires_at<now()+interval '301 seconds')",&[&a.user,&hash]).await?.get(0);assert!(bound,"returned secret must match full persisted grant before masking");raw=raw.replace(token,"<reauth>");
  }}
  let repeat=if kind=="repeat"||kind=="lockout" {
   let (status,headers,raw)=request(gw.addr,"POST",path,payload.clone(),&[("authorization",&bearer)]).await?;
   Some(json!({"status":status,"headers":headers,"body":raw}))
  }else{None};
  let after=grant_rows(&c,&a,&b).await?;let notifications=listener.drain(&c).await?;
  if kind.starts_with("commit-") {
      fault_probe(&db,&c,&a,&b,&keys,kind,operation,&mut wire,status,&headers,&raw).await?;
      if kind=="commit-before" {golden::compare(&before,&after)?;}else{assert_ne!(before,after,"committed transaction must publish its domain effects");}
      return Ok::<(),Err>(());
  }
  let mut actual=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("possession-totp-{kind}"),"observation":{"request":{"method":"POST","path":path,"body":payload.replace(&code,"<totp-code>").replace(&b.user.to_string(),"<foreign>")},"response":{"status":status,"headers":headers,"body":raw},"effects":after,"audit":after["audit"],"notify":notifications}});
  if let Some(repeat)=repeat{actual["observation"]["repeat_response"]=repeat;}
  let effects=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("possession-totp-{kind}-row-effects"),"effects":[{"table":"possession","before":before,"after":after}]});
  assert_go_recording(gw.addr,record.is_some()).await?;
  let file=corpus().join(format!("possession-totp-{kind}.json"));let rowfile=corpus().join(format!("possession-totp-{kind}-rows.json"));
  if record.is_some()&&!file.exists(){golden::record(&file,&actual)?;let mut tracer=effects.clone();tracer["case"]=json!(format!("possession-totp-{kind}-rows"));golden::record(&rowfile,&tracer)?;}
  let qualified=corpus().parent().unwrap().join("qualified").join(format!("possession-totp-{kind}-rows.json"));
  if record.is_some()&&!qualified.exists(){std::fs::create_dir_all(qualified.parent().unwrap())?;golden::record(&qualified,&effects)?;}
  let expected:Value=serde_json::from_str(&std::fs::read_to_string(&file)?)?;
  if mutant{assert!(golden::compare(&expected,&actual).is_err(),"mutant survived");}else{golden::compare(&expected,&actual)?;let old:Value=serde_json::from_str(&std::fs::read_to_string(rowfile)?)?;
  let mut tracer=effects.clone();tracer["case"]=json!(format!("possession-totp-{kind}-rows"));
  golden::compare(&old,&tracer)?;
  golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(qualified)?)?,&effects)?;}
  if record.is_none(){let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));}else{let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;let hops=metrics.lines().find_map(|line|line.strip_prefix("setjoin_gateway_proxied_to_go_total ")).ok_or("Go-hop metric missing")?.parse::<u64>()?;assert!(hops>0,"recordings must traverse frozen Go");}
  oracle_receipt(&actual,mutant);
  Ok::<(),Err>(())
 }.await;
    gw.close().await;
    server.close().await;
    for uid in [a.user, b.user] {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT")).await?;
        c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&uid])
            .await?;
    }
    common::restore_receipts(&c, &receipts).await;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if let Some(rate) = rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&rate],
        )
        .await?;
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?;
    }
    result
}

#[tokio::test]
async fn possession_totp_success() {
    run_totp_grant("success", false).await.unwrap();
}
#[tokio::test]
async fn possession_totp_invalid_input() {
    run_totp_grant("invalid-input", false).await.unwrap();
}

#[tokio::test]
async fn possession_totp_cross_tenant() {
    run_totp_grant("cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn possession_totp_repeat() {
    run_totp_grant("repeat", false).await.unwrap();
}
#[tokio::test]
async fn possession_totp_status_mutant() {
    run_totp_grant("success", true).await.unwrap();
}

#[tokio::test]
async fn possession_totp_lockout() {
    run_totp_grant("lockout", false).await.unwrap();
}

async fn backup_rows(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, Err> {
    let mut value = grant_rows(c, a, b).await?;
    let mut codes = vec![];
    for (uid, label) in [(a.user, "actor"), (b.user, "foreign")] {
        let hashes: Option<Vec<String>> = c
            .query_one(
                "SELECT totp_backup_codes_enc FROM users WHERE id=$1",
                &[&uid],
            )
            .await?
            .get(0);
        if let Some(hashes) = &hashes {
            if hashes.len() == 1 {
                assert!(bcrypt::verify("fixture-backup", &hashes[0])?);
            }
        }
        codes.push(json!({"owner":label,"hashes":hashes.map(|hs|hs.iter().map(|h|h.chars().take(7).collect::<String>()).collect::<Vec<_>>())}));
    }
    value["backups"] = json!(codes);
    Ok(value)
}
async fn run_generate(kind: &str, mutant: bool) -> Result<(), Err> {
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA3-backup-generate").unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idmfa3-actor").await?;
    let b = fixture::account(&c, "idmfa3-foreign").await?;
    let rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    for (uid, password) in [(a.user, "Password1!"), (b.user, "Foreign1!")] {
        c.execute(
            "UPDATE users SET password_hash=$2,factor_generation=2 WHERE id=$1",
            &[&uid, &bcrypt::hash(password, 4)?],
        )
        .await?;
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at) VALUES(encode(digest(($1::bigint)::text,'sha256'),'hex'),$1,'prior','totp.enroll','password',2,'session',now()+interval '5 minutes')",&[&uid]).await?;
    }
    for uid in [a.user, b.user] {
        c.execute(
            "UPDATE users SET totp_backup_codes_enc=$2 WHERE id=$1",
            &[&uid, &vec![bcrypt::hash("fixture-backup", 4)?]],
        )
        .await?;
    }
    c.execute("UPDATE mfa_reauth_step_ups SET token_hash=encode(digest('idmfa3-backup-proof','sha256'),'hex'),session_jti='idmfa3-actor',operation='recovery.regenerate' WHERE user_id=$1",&[&a.user]).await?;
    if kind == "unused-target" {
        c.execute(
            "UPDATE mfa_reauth_step_ups SET target_ref='unused-target' WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    }
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    cfg.dsn = db.dsn.clone();
    cfg.signing_alg = "ES256".into();
    cfg.db_encryption_key = "2".repeat(64);
    cfg.vapid_private_key = VAPID.into();
    let operation=setjoin_identity::totp::Operation::BackupGenerate;
    let command="mfa-backup-generate";
    let (executor,mut wire)=fault_executor(&db,kind,command).await?;
    let server = auth_server(
        Arc::new(
            AuthServer::load(
                executor,
                cfg,
            )
            .await?,
        ),
        mutant,
    )
    .await;
    let gw = gateway(server.addr, record.clone()).await;
    let result=async {
  let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();let uid=if kind=="cross-tenant"{b.user}else{a.user};
  let claims=json!({"uid":uid,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600,"jti":"idmfa3-actor"});
  let bearer=format!("Bearer {}",setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&claims.to_string()));
  let path="/auth/backup-codes/generate";
  let payload=if kind=="invalid-input"{"{}".into()}else{json!({"reauth_token":"idmfa3-backup-proof","user_id":b.user}).to_string()};
  let mut listener=db.listen("session_revoke").await?;
  let before=backup_rows(&c,&a,&b).await?;
  let (status,headers,mut raw)=request(gw.addr,"POST",path,payload.clone(),&[("authorization",&bearer)]).await?;
  if !mutant&&matches!(kind,"success"|"repeat")&&status!=200{return Err(format!("expected success status {}, got {status}",200).into());}
  if let Ok(v)=serde_json::from_str::<Value>(&raw){if let Some(codes)=v["backup_codes"].as_array(){
   assert_eq!(codes.len(),10);let hashes:Vec<String>=c.query_one("SELECT totp_backup_codes_enc FROM users WHERE id=$1",&[&a.user]).await?.get(0);assert_eq!(hashes.len(),10);
   for (index,(value,hash)) in codes.iter().zip(&hashes).enumerate(){let code=value.as_str().ok_or("backup code type")?;assert_eq!(code.len(),8);assert!(code.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)));assert!(hash.starts_with("$2a$10$"));assert!(bcrypt::verify(code,hash)?);raw=raw.replace(code,&format!("<backup-{}>",index+1));}
  }}
  let repeat=if kind=="repeat" {
   let (status,headers,raw)=request(gw.addr,"POST",path,payload.clone(),&[("authorization",&bearer)]).await?;
   Some(json!({"status":status,"headers":headers,"body":raw}))
  }else{None};
  let after=backup_rows(&c,&a,&b).await?;let notifications=listener.drain(&c).await?;
  if kind.starts_with("commit-") {
      fault_probe(&db,&c,&a,&b,&keys,kind,operation,&mut wire,status,&headers,&raw).await?;
      if kind=="commit-before" {golden::compare(&before,&after)?;}else{assert_ne!(before,after,"committed transaction must publish its domain effects");}
      return Ok::<(),Err>(());
  }
  let mut actual=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("backup-generate-{kind}"),"observation":{"request":{"method":"POST","path":path,"body":payload.replace(&b.user.to_string(),"<foreign>")},"response":{"status":status,"headers":headers,"body":raw},"effects":after,"audit":after["audit"],"notify":notifications}});
  if let Some(repeat)=repeat{actual["observation"]["repeat_response"]=repeat;}
  let effects=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("backup-generate-{kind}-row-effects"),"effects":[{"table":"possession","before":before,"after":after}]});
  assert_go_recording(gw.addr,record.is_some()).await?;
  let file=corpus().join(format!("backup-generate-{kind}.json"));let rowfile=corpus().join(format!("backup-generate-{kind}-rows.json"));
  if record.is_some()&&!file.exists(){golden::record(&file,&actual)?;let mut tracer=effects.clone();tracer["case"]=json!(format!("backup-generate-{kind}-rows"));golden::record(&rowfile,&tracer)?;}
  let qualified=corpus().parent().unwrap().join("qualified").join(format!("backup-generate-{kind}-rows.json"));
  if record.is_some()&&!qualified.exists(){std::fs::create_dir_all(qualified.parent().unwrap())?;golden::record(&qualified,&effects)?;}
  let expected:Value=serde_json::from_str(&std::fs::read_to_string(&file)?)?;
  if mutant{assert!(golden::compare(&expected,&actual).is_err(),"mutant survived");}else{golden::compare(&expected,&actual)?;let old:Value=serde_json::from_str(&std::fs::read_to_string(rowfile)?)?;
  let mut tracer=effects.clone();tracer["case"]=json!(format!("backup-generate-{kind}-rows"));
  golden::compare(&old,&tracer)?;
  golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(qualified)?)?,&effects)?;}
  if record.is_none(){let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));}else{let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;let hops=metrics.lines().find_map(|line|line.strip_prefix("setjoin_gateway_proxied_to_go_total ")).ok_or("Go-hop metric missing")?.parse::<u64>()?;assert!(hops>0,"recordings must traverse frozen Go");}
  oracle_receipt(&actual,mutant);
  Ok::<(),Err>(())
 }.await;
    gw.close().await;
    server.close().await;
    for uid in [a.user, b.user] {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT")).await?;
        c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&uid])
            .await?;
    }
    common::restore_receipts(&c, &receipts).await;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if let Some(rate) = rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&rate],
        )
        .await?;
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?;
    }
    result
}

#[tokio::test]
async fn backup_generate_success() {
    run_generate("success", false).await.unwrap();
}
#[tokio::test]
async fn backup_generate_cross_tenant() {
    run_generate("cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn backup_generate_invalid_input() {
    run_generate("invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn backup_generate_repeat() {
    run_generate("repeat", false).await.unwrap();
}
#[tokio::test]
async fn backup_generate_status_mutant() {
    run_generate("success", true).await.unwrap();
}

#[tokio::test]
async fn backup_generate_unused_target() {
    run_generate("unused-target", false).await.unwrap();
}

async fn issued(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    keys: &setjoin_authz::signing_keys::KeySet,
    fixture: &Value,
    headers: &mut Value,
    raw: &mut String,
) -> Result<Value, Err> {
    use sha2::{Digest, Sha256};
    let v: Value = serde_json::from_str(raw)?;
    assert_eq!(v["expires_in"], 3600);
    let legacy = setjoin_authz::legacy_jwt::LegacyKeys::new(
        fixture["secret"].as_str().unwrap().as_bytes(),
        &["authserver-hmac-1"],
        None,
    )?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs_f64();
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    let mut out = json!({});
    let mut family = String::new();
    for (field, typ, ttl) in [
        ("access_token", "access", 3600),
        ("refresh_token", "refresh", 2592000),
    ] {
        let token = v[field].as_str().ok_or("missing token")?;
        use base64::Engine;
        let header: Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token.split('.').next().ok_or("JWT header")?)?,
        )?;
        assert_eq!(header["alg"], "ES256");
        assert_eq!(
            header["kid"], fixture["kid"],
            "issuance must keep the existing Go key"
        );
        let proof =
            setjoin_identity::session::Session::verify(token, Some(keys), &legacy, "mailserver")
                .ok_or("invalid issued signature/claims")?;
        assert_eq!(proof.user(), a.user);
        assert_eq!(proof.text("email"), email);
        assert_eq!(proof.text("typ"), typ);
        if let Ok(upstream) = std::env::var("GOFREE_MFA_SWAP_UPSTREAM") {
            let addr = upstream
                .strip_prefix("http://")
                .ok_or("loopback Go HTTP URL required")?
                .parse()?;
            let (status, _, reply) = request(
                addr,
                "GET",
                "/auth/me",
                String::new(),
                &[("authorization", &format!("Bearer {token}"))],
            )
            .await?;
            assert_eq!(
                status,
                if typ == "access" { 200 } else { 403 },
                "Go must validate Rust {typ}: {reply}"
            );
            println!("SWAP-VERIFIED: frozen Go accepts Rust {typ} signature and claims");
        }

        let claims = proof.claims();
        let iat = claims["iat"].as_i64().unwrap();
        assert!((iat as f64 - now).abs() < 10.);
        assert_eq!(claims["exp"].as_i64().unwrap() - iat, ttl);
        assert_eq!(claims["nbf"], iat);
        let jti = proof.text("jti");
        assert_eq!(jti.len(), 32);
        assert!(jti.bytes().all(|c| c.is_ascii_hexdigit()));
        let fam = proof.text("fam");
        uuid::Uuid::parse_str(fam)?;
        if typ == "access" {
            family = fam.into();
            let row = c
                .query_one(
                    "SELECT token_hash FROM sessions WHERE id=$1 AND user_id=$2",
                    &[&jti, &a.user],
                )
                .await?;
            assert_eq!(
                row.get::<_, Vec<u8>>(0),
                Sha256::digest(token.as_bytes()).to_vec()
            );
        } else {
            assert_eq!(fam, family);
            let hash = Sha256::digest(token.as_bytes()).to_vec();
            let valid:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM oauth_tokens WHERE user_id=$1 AND token_hash=$2 AND family_id=$3::text::uuid AND token_type='refresh' AND client_id IS NULL)",&[&a.user,&hash,&fam]).await?.get(0);
            assert!(valid);
        }
        let mut normalized = Value::Object(claims.clone());
        for key in ["iat", "nbf"] {
            normalized[key] = json!(0);
        }
        normalized["exp"] = json!(ttl);
        normalized["uid"] = json!("<actor>");
        normalized["sub"] = json!("<actor>");
        normalized["email"] = json!("actor@idmfa3.test");
        normalized["jti"] = json!(format!("<{typ}-jti>"));
        normalized["fam"] = json!("<family>");
        out[typ] = normalized;
        *raw = raw.replace(token, &format!("<{field}>"));
        if let Some(cookie) = headers.get_mut("set-cookie") {
            *cookie = json!(cookie
                .as_str()
                .unwrap()
                .replace(token, &format!("<{field}>")));
        }
    }
    Ok(out)
}
async fn token_stores(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, Err> {
    let mut out = json!({});
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    let foreign: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&b.user])
        .await?
        .get(0);
    for table in ["oauth_tokens", "sessions", "login_events", "auth_event_log"] {
        let sql=format!("SELECT to_jsonb(t)::text FROM {table} t WHERE user_id=ANY($1::bigint[]) ORDER BY user_id,id");
        let mut rows = Vec::new();
        let records = if table == "auth_event_log" {
            c.query("SELECT to_jsonb(t)::text FROM auth_event_log t WHERE user_id=ANY($1::bigint[]) OR email=ANY($2::text[]) ORDER BY user_id,id",&[&vec![a.user,b.user],&vec![email.clone(),foreign.clone()]]).await?
        } else {
            c.query(&sql,&[&vec![a.user,b.user]]).await?
        };
        for (idx, row) in records.iter().enumerate() {
            let mut v: Value = serde_json::from_str(&row.get::<_, String>(0))?;
            if !v["user_id"].is_null(){
                v["user_id"] = json!(if v["user_id"] == a.user { "actor" } else { "foreign" });
            }
            if let Some(e) = v.get_mut("email").filter(|v| v.is_string()) {
                let text = e.as_str().unwrap();
                *e = json!(text
                    .replace(&email, "actor@idmfa3.test")
                    .replace(&foreign, "foreign@idmfa3.test"));
            }
            v["id"] = json!(format!("<{table}-{}>", idx + 1));
            for field in [
                "created_at",
                "expires_at",
                "issued_at",
                "last_used_at",
                "rotated_at",
                "revoked_at",
                "occurred_at",
                "last_seen_at",
            ] {
                if let Some(t) = v.get_mut(field).filter(|v| !v.is_null()) {
                    *t = json!("<time>");
                }
            }
            for field in ["token_hash", "previous_token_hash"] {
                if let Some(t) = v.get_mut(field).filter(|v| !v.is_null()) {
                    *t = json!("<SHA256>");
                }
            }
            if let Some(f) = v.get_mut("family_id").filter(|v| !v.is_null()) {
                *f = json!("<family>");
            }
            rows.push(v);
        }
        out[table] = json!(rows);
    }
    Ok(out)
}

async fn completion_rows(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, Err> {
    let mut value = grant_rows(c, a, b).await?;
    let mut codes = vec![];
    for (uid, label, code) in [
        (a.user, "actor", "fixture-backup"),
        (b.user, "foreign", "foreign-backup"),
    ] {
        let hashes: Option<Vec<String>> = c
            .query_one(
                "SELECT totp_backup_codes_enc FROM users WHERE id=$1",
                &[&uid],
            )
            .await?
            .get(0);
        if let Some(hashes) = &hashes {
            if hashes.len() == 1 {
                assert!(bcrypt::verify(code, &hashes[0])?);
            }
        }
        codes.push(json!({"owner":label,"hashes":hashes.map(|hs|hs.iter().map(|h|h.chars().take(7).collect::<String>()).collect::<Vec<_>>())}));
    }
    value["backups"] = json!(codes);
    value["token_stores"] = token_stores(c, a, b).await?;
    Ok(value)
}
async fn run_backup_verify(kind: &str, mutant: bool) -> Result<(), Err> {
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA3-backup-verify").unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idmfa3-actor").await?;
    let b = fixture::account(&c, "idmfa3-foreign").await?;
    let rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    for (uid, password) in [(a.user, "Password1!"), (b.user, "Foreign1!")] {
        c.execute(
            "UPDATE users SET password_hash=$2,factor_generation=2 WHERE id=$1",
            &[&uid, &bcrypt::hash(password, 4)?],
        )
        .await?;
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at) VALUES(encode(digest(($1::bigint)::text,'sha256'),'hex'),$1,'prior','totp.enroll','password',2,'session',now()+interval '5 minutes')",&[&uid]).await?;
    }
    for (uid, code) in [(a.user, "fixture-backup"), (b.user, "foreign-backup")] {
        c.execute(
            "UPDATE users SET totp_backup_codes_enc=$2 WHERE id=$1",
            &[&uid, &vec![bcrypt::hash(code, 4)?]],
        )
        .await?;
    }
    c.execute("UPDATE mfa_reauth_step_ups SET token_hash=encode(digest('idmfa3-backup-proof','sha256'),'hex'),session_jti='idmfa3-actor',operation='recovery.regenerate' WHERE user_id=$1",&[&a.user]).await?;
    if kind == "unused-target" {
        c.execute(
            "UPDATE mfa_reauth_step_ups SET target_ref='unused-target' WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    }
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    cfg.dsn = db.dsn.clone();
    cfg.signing_alg = "ES256".into();
    cfg.db_encryption_key = "2".repeat(64);
    cfg.vapid_private_key = VAPID.into();
    let key_exec =
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap();
    let signature_keys = setjoin_authz::signing_keys::KeySet::load(
        &key_exec,
        keys["secret"].as_str().unwrap().as_bytes(),
        setjoin_config_secret::CryptoProfile::Standard,
    )
    .await?;
    let operation=setjoin_identity::totp::Operation::BackupConsume;
    let command="mfa-backup-consume";
    let (executor,mut wire)=fault_executor(&db,kind,command).await?;
    let server = auth_server(
        Arc::new(
            AuthServer::load(
                executor,
                cfg,
            )
            .await?,
        ),
        mutant,
    )
    .await;
    let gw = gateway(server.addr, record.clone()).await;
    let result=async {
  let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();let uid=if kind=="cross-tenant"{b.user}else{a.user};
  let claims=json!({"uid":uid,"typ":"mfa_pending","amr":["pwd"],"iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600,"jti":"idmfa3-actor"});
  let bearer=format!("Bearer {}",setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&claims.to_string()));
  let path="/auth/backup-codes/verify";
  let payload=if kind=="invalid-input"{"{}".into()}else{json!({"mfa_token":bearer.strip_prefix("Bearer ").unwrap(),"code":"fixture-backup","user_id":b.user}).to_string()};
  let mut listener=db.listen("session_revoke").await?;
  let before=completion_rows(&c,&a,&b).await?;
  let (status,mut headers,mut raw)=request(gw.addr,"POST",path,payload.clone(),&[]).await?;
  if !mutant&&matches!(kind,"success"|"repeat")&&status!=200{return Err(format!("expected success status {}, got {status}",200).into());}
  let issued=if serde_json::from_str::<Value>(&raw).ok().is_some_and(|v|v.get("access_token").is_some()) {Some(issued(&c,&a,&signature_keys,&keys,&mut headers,&mut raw).await?)}else{None};
  let repeat=if kind=="repeat" {
   let (status,headers,raw)=request(gw.addr,"POST",path,payload.clone(),&[]).await?;
   Some(json!({"status":status,"headers":headers,"body":raw}))
  }else{None};
  let after=completion_rows(&c,&a,&b).await?;let notifications=listener.drain(&c).await?;
  if kind.starts_with("commit-") {
      fault_probe(&db,&c,&a,&b,&keys,kind,operation,&mut wire,status,&headers,&raw).await?;
      if kind=="commit-before" {golden::compare(&before,&after)?;}else{assert_ne!(before,after,"committed transaction must publish its domain effects");}
      return Ok::<(),Err>(());
  }
  let mut actual=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("backup-verify-{kind}"),"observation":{"request":{"method":"POST","path":path,"body":payload.replace(bearer.strip_prefix("Bearer ").unwrap(),"<mfa-token>").replace(&b.user.to_string(),"<foreign>")},"response":{"status":status,"headers":headers,"body":raw},"effects":after,"audit":after["audit"],"notify":notifications}});
  if let Some(issued)=issued{actual["observation"]["issued_claims"]=issued;}
  if let Some(repeat)=repeat{actual["observation"]["repeat_response"]=repeat;}
  let effects=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("backup-verify-{kind}-row-effects"),"effects":[{"table":"possession","before":before,"after":after}]});
  assert_go_recording(gw.addr,record.is_some()).await?;
  let file=corpus().join(format!("backup-verify-{kind}.json"));let rowfile=corpus().join(format!("backup-verify-{kind}-rows.json"));
  if record.is_some()&&!file.exists(){golden::record(&file,&actual)?;let mut tracer=effects.clone();tracer["case"]=json!(format!("backup-verify-{kind}-rows"));golden::record(&rowfile,&tracer)?;}
  let qualified=corpus().parent().unwrap().join("qualified").join(format!("backup-verify-{kind}-rows.json"));
  if record.is_some()&&!qualified.exists(){std::fs::create_dir_all(qualified.parent().unwrap())?;golden::record(&qualified,&effects)?;}
  let expected:Value=serde_json::from_str(&std::fs::read_to_string(&file)?)?;
  if mutant{assert!(golden::compare(&expected,&actual).is_err(),"mutant survived");}else{golden::compare(&expected,&actual)?;let old:Value=serde_json::from_str(&std::fs::read_to_string(rowfile)?)?;
  let mut tracer=effects.clone();tracer["case"]=json!(format!("backup-verify-{kind}-rows"));
  golden::compare(&old,&tracer)?;
  golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(qualified)?)?,&effects)?;}
  if record.is_none(){let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));}else{let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;let hops=metrics.lines().find_map(|line|line.strip_prefix("setjoin_gateway_proxied_to_go_total ")).ok_or("Go-hop metric missing")?.parse::<u64>()?;assert!(hops>0,"recordings must traverse frozen Go");}
  oracle_receipt(&actual,mutant);
  Ok::<(),Err>(())
 }.await;
    gw.close().await;
    server.close().await;
    for uid in [a.user, b.user] {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT")).await?;
        c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&uid])
            .await?;
    }
    for uid in [a.user, b.user] {
        for table in ["auth_event_log", "login_events", "sessions", "oauth_tokens"] {
            c.execute(&format!("DELETE FROM {table} WHERE user_id=$1"), &[&uid])
                .await?;
        }
    }
    common::restore_receipts(&c, &receipts).await;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if let Some(rate) = rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&rate],
        )
        .await?;
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?;
    }
    result
}

#[tokio::test]
async fn backup_verify_success() {
    run_backup_verify("success", false).await.unwrap();
}
#[tokio::test]
async fn backup_verify_cross_tenant() {
    run_backup_verify("cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn backup_verify_invalid_input() {
    run_backup_verify("invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn backup_verify_repeat() {
    run_backup_verify("repeat", false).await.unwrap();
}
#[tokio::test]
async fn backup_verify_status_mutant() {
    run_backup_verify("success", true).await.unwrap();
}

fn device_key_hex() -> String {
    use base64::Engine;
    let bytes=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("BG_wO5SSQc4drdQ1GeaWDgqFtBppoFwygQOqK84VlMoWPE91OlW_AdxT9sCwx-7ni0DG_30lqW4igrmJzvccFEo").unwrap();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
async fn native_rows(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, Err> {
    let mut out = grant_rows(c, a, b).await?;
    let mut devices = vec![];
    for (uid, label) in [(a.user, "actor"), (b.user, "foreign")] {
        for r in c.query("SELECT push_provider,pgp_sym_decrypt(push_token_enc,$2),encode(device_public_key,'hex'),device_name,revoked_at IS NOT NULL,last_used_at IS NOT NULL FROM push_devices WHERE user_id=$1 ORDER BY id",&[&uid,&"2".repeat(64)]).await?{
   devices.push(json!({"owner":label,"provider":r.get::<_,String>(0),"token":r.get::<_,String>(1),"key":r.get::<_,Option<String>>(2),"name":r.get::<_,Option<String>>(3),"revoked":r.get::<_,bool>(4),"used":r.get::<_,bool>(5)}));
  }
    }
    out["devices"] = json!(devices);
    Ok(out)
}
async fn run_native_register(kind: &str, mutant: bool) -> Result<(), Err> {
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA3-native-register").unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idmfa3-actor").await?;
    let b = fixture::account(&c, "idmfa3-foreign").await?;
    let rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    for (uid, password) in [(a.user, "Password1!"), (b.user, "Foreign1!")] {
        c.execute(
            "UPDATE users SET password_hash=$2,factor_generation=2 WHERE id=$1",
            &[&uid, &bcrypt::hash(password, 4)?],
        )
        .await?;
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at) VALUES(encode(digest(($1::bigint)::text,'sha256'),'hex'),$1,'prior','totp.enroll','password',2,'session',now()+interval '5 minutes')",&[&uid]).await?;
    }
    for uid in [a.user, b.user] {
        c.execute(
            "UPDATE users SET totp_backup_codes_enc=$2 WHERE id=$1",
            &[&uid, &vec![bcrypt::hash("fixture-backup", 4)?]],
        )
        .await?;
    }
    c.execute("UPDATE mfa_reauth_step_ups SET token_hash=encode(digest('idmfa3-backup-proof','sha256'),'hex'),session_jti='idmfa3-actor',operation='device.register.native' WHERE user_id=$1",&[&a.user]).await?;
    if kind == "unused-target" {
        c.execute(
            "UPDATE mfa_reauth_step_ups SET target_ref='unused-target' WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    }
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    cfg.dsn = db.dsn.clone();
    cfg.signing_alg = "ES256".into();
    cfg.db_encryption_key = "2".repeat(64);
    cfg.vapid_private_key = VAPID.into();
    let operation=setjoin_identity::totp::Operation::NativeRegister;
    let command="mfa-native-register";
    let (executor,mut wire)=fault_executor(&db,kind,command).await?;
    let server = auth_server(
        Arc::new(
            AuthServer::load(
                executor,
                cfg,
            )
            .await?,
        ),
        mutant,
    )
    .await;
    let gw = gateway(server.addr, record.clone()).await;
    let result=async {
  let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();let uid=if kind=="cross-tenant"{b.user}else{a.user};
  let claims=json!({"uid":uid,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600,"jti":"idmfa3-actor"});
  let bearer=format!("Bearer {}",setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&claims.to_string()));
  let path="/auth/device/register";
  let payload=if kind=="invalid-input"{"{}".into()}else{json!({"provider":"fcm","push_token":"idmfa3-device-token","device_public_key":device_key_hex(),"device_name":"IDMFA3 device","reauth_token":"idmfa3-backup-proof","user_id":b.user}).to_string()};
  let mut listener=db.listen("session_revoke").await?;
  let before=native_rows(&c,&a,&b).await?;
  let (status,headers,raw)=request(gw.addr,"POST",path,payload.clone(),&[("authorization",&bearer)]).await?;
  if !mutant&&matches!(kind,"success"|"repeat")&&status!=204{return Err(format!("expected success status {}, got {status}",204).into());}
  let repeat=if kind=="repeat" {
   let old:Vec<Vec<u8>>=c.query("SELECT push_token_enc FROM push_devices WHERE user_id=$1 ORDER BY id",&[&a.user]).await?.iter().map(|r|r.get(0)).collect();
   let (status,headers,raw)=request(gw.addr,"POST",path,payload.clone(),&[("authorization",&bearer)]).await?;
   let current:Vec<Vec<u8>>=c.query("SELECT push_token_enc FROM push_devices WHERE user_id=$1 ORDER BY id",&[&a.user]).await?.iter().map(|r|r.get(0)).collect();assert_eq!(old,current,"replay must preserve the exact encrypted device row");
   Some(json!({"status":status,"headers":headers,"body":raw}))
  }else{None};
  let after=native_rows(&c,&a,&b).await?;let notifications=listener.drain(&c).await?;
  if kind.starts_with("commit-") {
      fault_probe(&db,&c,&a,&b,&keys,kind,operation,&mut wire,status,&headers,&raw).await?;
      if kind=="commit-before" {golden::compare(&before,&after)?;}else{assert_ne!(before,after,"committed transaction must publish its domain effects");}
      return Ok::<(),Err>(());
  }
  let mut actual=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("native-register-{kind}"),"observation":{"request":{"method":"POST","path":path,"body":payload.replace(&b.user.to_string(),"<foreign>")},"response":{"status":status,"headers":headers,"body":raw},"effects":after,"audit":after["audit"],"notify":notifications}});
  if let Some(repeat)=repeat{actual["observation"]["repeat_response"]=repeat;}
  let effects=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("native-register-{kind}-row-effects"),"effects":[{"table":"possession","before":before,"after":after}]});
  assert_go_recording(gw.addr,record.is_some()).await?;
  let file=corpus().join(format!("native-register-{kind}.json"));let rowfile=corpus().join(format!("native-register-{kind}-rows.json"));
  if record.is_some()&&!file.exists(){golden::record(&file,&actual)?;let mut tracer=effects.clone();tracer["case"]=json!(format!("native-register-{kind}-rows"));golden::record(&rowfile,&tracer)?;}
  let qualified=corpus().parent().unwrap().join("qualified").join(format!("native-register-{kind}-rows.json"));
  if record.is_some()&&!qualified.exists(){std::fs::create_dir_all(qualified.parent().unwrap())?;golden::record(&qualified,&effects)?;}
  let expected:Value=serde_json::from_str(&std::fs::read_to_string(&file)?)?;
  if mutant{assert!(golden::compare(&expected,&actual).is_err(),"mutant survived");}else{golden::compare(&expected,&actual)?;let old:Value=serde_json::from_str(&std::fs::read_to_string(rowfile)?)?;
  let mut tracer=effects.clone();tracer["case"]=json!(format!("native-register-{kind}-rows"));
  golden::compare(&old,&tracer)?;
  golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(qualified)?)?,&effects)?;}
  if record.is_none(){let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));}else{let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;let hops=metrics.lines().find_map(|line|line.strip_prefix("setjoin_gateway_proxied_to_go_total ")).ok_or("Go-hop metric missing")?.parse::<u64>()?;assert!(hops>0,"recordings must traverse frozen Go");}
  oracle_receipt(&actual,mutant);
  Ok::<(),Err>(())
 }.await;
    gw.close().await;
    server.close().await;
    for uid in [a.user, b.user] {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT")).await?;
        c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&uid])
            .await?;
    }
    c.execute(
        "DELETE FROM push_devices WHERE user_id=ANY($1::bigint[])",
        &[&vec![a.user, b.user]],
    )
    .await?;
    common::restore_receipts(&c, &receipts).await;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if let Some(rate) = rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&rate],
        )
        .await?;
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?;
    }
    result
}

#[tokio::test]
async fn native_register_success() {
    run_native_register("success", false).await.unwrap();
}

async fn assert_go_recording(addr: std::net::SocketAddr, recording: bool) -> Result<(), Err> {
    if recording {
        let (_, _, metrics) = request(addr, "GET", "/_gateway/metrics", String::new(), &[]).await?;
        let hops = metrics
            .lines()
            .find_map(|line| line.strip_prefix("setjoin_gateway_proxied_to_go_total "))
            .ok_or("Go-hop metric missing")?
            .parse::<u64>()?;
        assert!(hops > 0, "a Go golden must traverse the frozen Go upstream");
    }
    Ok(())
}

#[tokio::test]
async fn native_register_cross_tenant() {
    run_native_register("cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn native_register_invalid_input() {
    run_native_register("invalid-input", false).await.unwrap();
}

#[tokio::test]
async fn native_register_repeat() {
    run_native_register("repeat", false).await.unwrap();
}
#[tokio::test]
async fn native_register_status_mutant() {
    run_native_register("success", true).await.unwrap();
}

async fn push_rows(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, Err> {
    let mut out = grant_rows(c, a, b).await?;
    out["token_stores"] = token_stores(c, a, b).await?;
    let mut challenges = vec![];
    for (uid, label) in [(a.user, "actor"), (b.user, "foreign")] {
        for row in c.query("SELECT encode(nonce,'hex'),challenge_code,session_id IS NOT NULL,expires_at>now(),verified_at IS NOT NULL,approved_at IS NOT NULL,failed_attempts FROM push_mfa_challenges WHERE user_id=$1 ORDER BY id",&[&uid]).await?{
   challenges.push(json!({"owner":label,"nonce":row.get::<_,String>(0),"code":row.get::<_,String>(1),"bound":row.get::<_,bool>(2),"live":row.get::<_,bool>(3),"verified":row.get::<_,bool>(4),"approved":row.get::<_,bool>(5),"failures":row.get::<_,i32>(6)}));
  }
    }
    out["challenges"] = json!(challenges);
    Ok(out)
}
async fn run_push_verify(kind: &str, mutant: bool) -> Result<(), Err> {
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA3-push-verify").unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idmfa3-actor").await?;
    let b = fixture::account(&c, "idmfa3-foreign").await?;
    let rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    for (uid, password) in [(a.user, "Password1!"), (b.user, "Foreign1!")] {
        c.execute(
            "UPDATE users SET password_hash=$2,factor_generation=2 WHERE id=$1",
            &[&uid, &bcrypt::hash(password, 4)?],
        )
        .await?;
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at) VALUES(encode(digest(($1::bigint)::text,'sha256'),'hex'),$1,'prior','totp.enroll','password',2,'session',now()+interval '5 minutes')",&[&uid]).await?;
    }
    for (uid, code) in [(a.user, "fixture-backup"), (b.user, "foreign-backup")] {
        c.execute(
            "UPDATE users SET totp_backup_codes_enc=$2 WHERE id=$1",
            &[&uid, &vec![bcrypt::hash(code, 4)?]],
        )
        .await?;
    }
    c.execute("UPDATE mfa_reauth_step_ups SET token_hash=encode(digest('idmfa3-backup-proof','sha256'),'hex'),session_jti='idmfa3-actor',operation='recovery.regenerate' WHERE user_id=$1",&[&a.user]).await?;
    if kind == "unused-target" {
        c.execute(
            "UPDATE mfa_reauth_step_ups SET target_ref='unused-target' WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    }
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    cfg.dsn = db.dsn.clone();
    cfg.signing_alg = "ES256".into();
    cfg.db_encryption_key = "2".repeat(64);
    cfg.vapid_private_key = VAPID.into();
    let server = auth_server(
        Arc::new(
            AuthServer::load(
                setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
                    .unwrap(),
                cfg,
            )
            .await?,
        ),
        mutant,
    )
    .await;
    let gw = gateway(server.addr, record.clone()).await;
    let result=async {
  let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();let uid=if kind=="cross-tenant"{b.user}else{a.user};
  let claims=json!({"uid":uid,"typ":"mfa_pending","amr":["pwd"],"iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600,"jti":"idmfa3-actor"});
  let bearer=format!("Bearer {}",setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&claims.to_string()));
  let path="/auth/push/verify";
  let payload=if kind=="invalid-input"{"{}".into()}else{json!({"mfa_token":bearer.strip_prefix("Bearer ").unwrap(),"nonce":"11".repeat(32),"answer":"42","user_id":b.user}).to_string()};
  let mut actor_claims=claims.clone();actor_claims["uid"]=json!(a.user);
  let actor_token=setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&actor_claims.to_string());
  c.execute("INSERT INTO push_mfa_challenges(user_id,challenge_code,nonce,session_id,expires_at) VALUES($1,'42',decode($2,'hex'),$3,now()+interval '120 seconds')",&[&a.user,&"11".repeat(32),&actor_token]).await?;
  let mut listener=db.listen("session_revoke").await?;
  let before=push_rows(&c,&a,&b).await?;
  let exact:Vec<String>=c.query("SELECT to_jsonb(t)::text FROM push_mfa_challenges t WHERE user_id=$1 ORDER BY id",&[&a.user]).await?.iter().map(|r|r.get(0)).collect();
  let (status,headers,raw)=request(gw.addr,"POST",path,payload.clone(),&[]).await?;
  if !mutant&&matches!(kind,"success"|"repeat")&&status!=410{return Err(format!("expected success status {}, got {status}",410).into());}
  let repeat=if kind=="repeat" {
   let (status,headers,raw)=request(gw.addr,"POST",path,payload.clone(),&[]).await?;
   Some(json!({"status":status,"headers":headers,"body":raw}))
  }else{None};
  let untouched:Vec<String>=c.query("SELECT to_jsonb(t)::text FROM push_mfa_challenges t WHERE user_id=$1 ORDER BY id",&[&a.user]).await?.iter().map(|r|r.get(0)).collect();assert_eq!(exact,untouched,"in-band answers must not touch the challenge or its binding");
  let after=push_rows(&c,&a,&b).await?;let notifications=listener.drain(&c).await?;
  let mut actual=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("push-verify-{kind}"),"observation":{"request":{"method":"POST","path":path,"body":payload.replace(bearer.strip_prefix("Bearer ").unwrap(),"<mfa-token>").replace(&b.user.to_string(),"<foreign>")},"response":{"status":status,"headers":headers,"body":raw},"effects":after,"audit":after["audit"],"notify":notifications}});
  if let Some(repeat)=repeat{actual["observation"]["repeat_response"]=repeat;}
  let effects=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("push-verify-{kind}-row-effects"),"effects":[{"table":"possession","before":before,"after":after}]});
  assert_go_recording(gw.addr,record.is_some()).await?;
  let file=corpus().join(format!("push-verify-{kind}.json"));let rowfile=corpus().join(format!("push-verify-{kind}-rows.json"));
  if record.is_some()&&!file.exists(){golden::record(&file,&actual)?;let mut tracer=effects.clone();tracer["case"]=json!(format!("push-verify-{kind}-rows"));golden::record(&rowfile,&tracer)?;}
  let qualified=corpus().parent().unwrap().join("qualified").join(format!("push-verify-{kind}-rows.json"));
  if record.is_some()&&!qualified.exists(){std::fs::create_dir_all(qualified.parent().unwrap())?;golden::record(&qualified,&effects)?;}
  let expected:Value=serde_json::from_str(&std::fs::read_to_string(&file)?)?;
  if mutant{assert!(golden::compare(&expected,&actual).is_err(),"mutant survived");}else{golden::compare(&expected,&actual)?;let old:Value=serde_json::from_str(&std::fs::read_to_string(rowfile)?)?;
  let mut tracer=effects.clone();tracer["case"]=json!(format!("push-verify-{kind}-rows"));
  golden::compare(&old,&tracer)?;
  golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(qualified)?)?,&effects)?;}
  if record.is_none(){let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));}else{let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;let hops=metrics.lines().find_map(|line|line.strip_prefix("setjoin_gateway_proxied_to_go_total ")).ok_or("Go-hop metric missing")?.parse::<u64>()?;assert!(hops>0,"recordings must traverse frozen Go");}
  oracle_receipt(&actual,mutant);
  Ok::<(),Err>(())
 }.await;
    gw.close().await;
    server.close().await;
    for uid in [a.user, b.user] {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT")).await?;
        c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&uid])
            .await?;
    }
    for uid in [a.user, b.user] {
        for table in ["auth_event_log", "login_events", "sessions", "oauth_tokens"] {
            c.execute(&format!("DELETE FROM {table} WHERE user_id=$1"), &[&uid])
                .await?;
        }
    }
    c.execute(
        "DELETE FROM push_mfa_challenges WHERE user_id=ANY($1::bigint[])",
        &[&vec![a.user, b.user]],
    )
    .await?;
    common::restore_receipts(&c, &receipts).await;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if let Some(rate) = rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&rate],
        )
        .await?;
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?;
    }
    result
}

#[tokio::test]
async fn push_verify_success() {
    run_push_verify("success", false).await.unwrap();
}

#[tokio::test]
async fn push_verify_cross_tenant() {
    run_push_verify("cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn push_verify_invalid_input() {
    run_push_verify("invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn push_verify_repeat() {
    run_push_verify("repeat", false).await.unwrap();
}
#[tokio::test]
async fn push_verify_status_mutant() {
    run_push_verify("success", true).await.unwrap();
}

async fn run_push_status(kind: &str, mutant: bool) -> Result<(), Err> {
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA3-push-status").unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idmfa3-actor").await?;
    let b = fixture::account(&c, "idmfa3-foreign").await?;
    let rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    for (uid, password) in [(a.user, "Password1!"), (b.user, "Foreign1!")] {
        c.execute(
            "UPDATE users SET password_hash=$2,factor_generation=2 WHERE id=$1",
            &[&uid, &bcrypt::hash(password, 4)?],
        )
        .await?;
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at) VALUES(encode(digest(($1::bigint)::text,'sha256'),'hex'),$1,'prior','totp.enroll','password',2,'session',now()+interval '5 minutes')",&[&uid]).await?;
    }
    for (uid, code) in [(a.user, "fixture-backup"), (b.user, "foreign-backup")] {
        c.execute(
            "UPDATE users SET totp_backup_codes_enc=$2 WHERE id=$1",
            &[&uid, &vec![bcrypt::hash(code, 4)?]],
        )
        .await?;
    }
    c.execute("UPDATE mfa_reauth_step_ups SET token_hash=encode(digest('idmfa3-backup-proof','sha256'),'hex'),session_jti='idmfa3-actor',operation='recovery.regenerate' WHERE user_id=$1",&[&a.user]).await?;
    if kind == "unused-target" {
        c.execute(
            "UPDATE mfa_reauth_step_ups SET target_ref='unused-target' WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    }
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    cfg.dsn = db.dsn.clone();
    cfg.signing_alg = "ES256".into();
    cfg.db_encryption_key = "2".repeat(64);
    cfg.vapid_private_key = VAPID.into();
    let key_exec =
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap();
    let signature_keys = setjoin_authz::signing_keys::KeySet::load(
        &key_exec,
        keys["secret"].as_str().unwrap().as_bytes(),
        setjoin_config_secret::CryptoProfile::Standard,
    )
    .await?;
    let operation=setjoin_identity::totp::Operation::PushHarvest;
    let command="mfa-push-harvest";
    let (executor,mut wire)=fault_executor(&db,kind,command).await?;
    let server = auth_server(
        Arc::new(
            AuthServer::load(
                executor,
                cfg,
            )
            .await?,
        ),
        mutant,
    )
    .await;
    let gw = gateway(server.addr, record.clone()).await;
    let result=async {
  let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();let uid=if kind=="cross-tenant"{b.user}else{a.user};
  let claims=json!({"uid":uid,"typ":"mfa_pending","amr":["pwd"],"iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600,"jti":"idmfa3-actor"});
  let mut claims=claims; if kind=="legacy"{claims.as_object_mut().unwrap().remove("amr");}
  let bearer=format!("Bearer {}",setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&claims.to_string()));
  let path="/auth/push/status";
  let payload=if kind=="invalid-input"{"{}".into()}else{json!({"mfa_token":bearer.strip_prefix("Bearer ").unwrap(),"nonce":"11".repeat(32),"user_id":b.user}).to_string()};
  let mut actor_claims=claims.clone();actor_claims["uid"]=json!(a.user);
  let actor_token=setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&actor_claims.to_string());
  c.execute("INSERT INTO push_mfa_challenges(user_id,challenge_code,nonce,session_id,expires_at,verified_at,approved_at) VALUES($1,'42',decode($2,'hex'),$3,now()+interval '120 seconds',now(),now())",&[&a.user,&"11".repeat(32),&actor_token]).await?;
  match kind{
   "expired"=>{c.execute("UPDATE push_mfa_challenges SET expires_at=now()-interval '1 second' WHERE user_id=$1",&[&a.user]).await?;},
   "foreign-session"=>{c.execute("UPDATE push_mfa_challenges SET session_id='another-signed-pending-session' WHERE user_id=$1",&[&a.user]).await?;},
   "unapproved"=>{c.execute("UPDATE push_mfa_challenges SET approved_at=NULL,failed_attempts=3 WHERE user_id=$1",&[&a.user]).await?;},
   _=>{}
  }
  let mut listener=db.listen("session_revoke").await?;
  let before=push_rows(&c,&a,&b).await?;
  let (status,mut headers,mut raw)=request(gw.addr,"POST",path,payload.clone(),&[]).await?;
  if !mutant&&matches!(kind,"success"|"repeat")&&status!=200{return Err(format!("expected success status {}, got {status}",200).into());}
  let issued=if serde_json::from_str::<Value>(&raw).ok().is_some_and(|v|v.get("access_token").is_some()) {Some(issued(&c,&a,&signature_keys,&keys,&mut headers,&mut raw).await?)}else{None};
  let repeat=if kind=="repeat" {
   let (status,headers,raw)=request(gw.addr,"POST",path,payload.clone(),&[]).await?;
   Some(json!({"status":status,"headers":headers,"body":raw}))
  }else{None};
  let after=push_rows(&c,&a,&b).await?;let notifications=listener.drain(&c).await?;
  if kind.starts_with("commit-") {
      fault_probe(&db,&c,&a,&b,&keys,kind,operation,&mut wire,status,&headers,&raw).await?;
      if kind=="commit-before" {golden::compare(&before,&after)?;}else{assert_ne!(before,after,"committed transaction must publish its domain effects");}
      return Ok::<(),Err>(());
  }
  let mut actual=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("push-status-{kind}"),"observation":{"request":{"method":"POST","path":path,"body":payload.replace(bearer.strip_prefix("Bearer ").unwrap(),"<mfa-token>").replace(&b.user.to_string(),"<foreign>")},"response":{"status":status,"headers":headers,"body":raw},"effects":after,"audit":after["audit"],"notify":notifications}});
  if let Some(issued)=issued{actual["observation"]["issued_claims"]=issued;}
  if let Some(repeat)=repeat{actual["observation"]["repeat_response"]=repeat;}
  let effects=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("push-status-{kind}-row-effects"),"effects":[{"table":"possession","before":before,"after":after}]});
  assert_go_recording(gw.addr,record.is_some()).await?;
  let file=corpus().join(format!("push-status-{kind}.json"));let rowfile=corpus().join(format!("push-status-{kind}-rows.json"));
  if record.is_some()&&!file.exists(){golden::record(&file,&actual)?;let mut tracer=effects.clone();tracer["case"]=json!(format!("push-status-{kind}-rows"));golden::record(&rowfile,&tracer)?;}
  let qualified=corpus().parent().unwrap().join("qualified").join(format!("push-status-{kind}-rows.json"));
  if record.is_some()&&!qualified.exists(){std::fs::create_dir_all(qualified.parent().unwrap())?;golden::record(&qualified,&effects)?;}
  let expected:Value=serde_json::from_str(&std::fs::read_to_string(&file)?)?;
  if mutant{assert!(golden::compare(&expected,&actual).is_err(),"mutant survived");}else{golden::compare(&expected,&actual)?;let old:Value=serde_json::from_str(&std::fs::read_to_string(rowfile)?)?;
  let mut tracer=effects.clone();tracer["case"]=json!(format!("push-status-{kind}-rows"));
  golden::compare(&old,&tracer)?;
  golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(qualified)?)?,&effects)?;}
  if record.is_none(){let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));}else{let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;let hops=metrics.lines().find_map(|line|line.strip_prefix("setjoin_gateway_proxied_to_go_total ")).ok_or("Go-hop metric missing")?.parse::<u64>()?;assert!(hops>0,"recordings must traverse frozen Go");}
  oracle_receipt(&actual,mutant);
  Ok::<(),Err>(())
 }.await;
    gw.close().await;
    server.close().await;
    for uid in [a.user, b.user] {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT")).await?;
        c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&uid])
            .await?;
    }
    for uid in [a.user, b.user] {
        for table in ["auth_event_log", "login_events", "sessions", "oauth_tokens"] {
            c.execute(&format!("DELETE FROM {table} WHERE user_id=$1"), &[&uid])
                .await?;
        }
    }
    c.execute(
        "DELETE FROM push_mfa_challenges WHERE user_id=ANY($1::bigint[])",
        &[&vec![a.user, b.user]],
    )
    .await?;
    common::restore_receipts(&c, &receipts).await;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if let Some(rate) = rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&rate],
        )
        .await?;
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?;
    }
    result
}
#[tokio::test]
async fn push_status_success() {
    run_push_status("success", false).await.unwrap();
}
#[tokio::test]
async fn push_status_cross_tenant() {
    run_push_status("cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn push_status_invalid_input() {
    run_push_status("invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn push_status_repeat() {
    run_push_status("repeat", false).await.unwrap();
}
#[tokio::test]
async fn push_status_expired() {
    run_push_status("expired", false).await.unwrap();
}
#[tokio::test]
async fn push_status_foreign_session() {
    run_push_status("foreign-session", false).await.unwrap();
}
#[tokio::test]
async fn push_status_unapproved() {
    run_push_status("unapproved", false).await.unwrap();
}
#[tokio::test]
async fn push_status_legacy() {
    run_push_status("legacy", false).await.unwrap();
}
#[tokio::test]
async fn push_status_status_mutant() {
    run_push_status("success", true).await.unwrap();
}

async fn run_push_approve(kind: &str, mutant: bool) -> Result<(), Err> {
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA3-push-approve").unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idmfa3-actor").await?;
    let b = fixture::account(&c, "idmfa3-foreign").await?;
    let rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    for (uid, password) in [(a.user, "Password1!"), (b.user, "Foreign1!")] {
        c.execute(
            "UPDATE users SET password_hash=$2,factor_generation=2 WHERE id=$1",
            &[&uid, &bcrypt::hash(password, 4)?],
        )
        .await?;
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at) VALUES(encode(digest(($1::bigint)::text,'sha256'),'hex'),$1,'prior','totp.enroll','password',2,'session',now()+interval '5 minutes')",&[&uid]).await?;
    }
    for (uid, code) in [(a.user, "fixture-backup"), (b.user, "foreign-backup")] {
        c.execute(
            "UPDATE users SET totp_backup_codes_enc=$2 WHERE id=$1",
            &[&uid, &vec![bcrypt::hash(code, 4)?]],
        )
        .await?;
    }
    c.execute("UPDATE mfa_reauth_step_ups SET token_hash=encode(digest('idmfa3-backup-proof','sha256'),'hex'),session_jti='idmfa3-actor',operation='recovery.regenerate' WHERE user_id=$1",&[&a.user]).await?;
    if kind == "unused-target" {
        c.execute(
            "UPDATE mfa_reauth_step_ups SET target_ref='unused-target' WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    }
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    cfg.dsn = db.dsn.clone();
    cfg.signing_alg = "ES256".into();
    cfg.db_encryption_key = "2".repeat(64);
    cfg.vapid_private_key = VAPID.into();
    let operation=setjoin_identity::totp::Operation::PushApprove;
    let command="mfa-push-approve";
    let (executor,mut wire)=fault_executor(&db,kind,command).await?;
    let server = auth_server(
        Arc::new(
            AuthServer::load(
                executor,
                cfg,
            )
            .await?,
        ),
        mutant,
    )
    .await;
    let rng = ring::rand::SystemRandom::new();
    let private = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .unwrap();
    let signing = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        private.as_ref(),
        &rng,
    )
    .unwrap();
    use ring::signature::KeyPair;
    let public = signing.public_key().as_ref().to_vec();
    let device:i64=c.query_one("INSERT INTO push_devices(user_id,push_provider,push_token_enc,device_public_key) VALUES($1,'fcm',pgp_sym_encrypt('fixture-native',$2),$3) RETURNING id",&[&a.user,&"2".repeat(64),&public]).await?.get(0);
    let foreign_device:i64=c.query_one("INSERT INTO push_devices(user_id,push_provider,push_token_enc,device_public_key) VALUES($1,'fcm',pgp_sym_encrypt('foreign-native',$2),$3) RETURNING id",&[&b.user,&"2".repeat(64),&public]).await?.get(0);
    let gw = gateway(server.addr, record.clone()).await;
    let result=async {
  let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
  let path="/auth/mfa/approve";
  let nonce="11".repeat(32);let session="native-pending-session";
  let code=if matches!(kind,"wrong-code"|"lockout"){ "99" }else{"42"};
  let device=if kind=="cross-tenant"{foreign_device}else{device};
  let issued_at=if kind=="stale"{now as i64-240}else{now as i64};let expires_at=now as i64+60;
  let canonical=json!({"code":code,"decision":"approve","device_id":device,"expires_at":expires_at,"issued_at":issued_at,"nonce":nonce,"protocol":"setjoin.push-approval.v1","session_id":session,"user_id":a.user}).to_string();
  use base64::Engine;
  let signature=signing.sign(&rng,canonical.as_bytes()).unwrap();let mut signature=signature.as_ref().to_vec();if kind=="bad-signature"{signature[0]^=1;}
  let signature=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);
  let mut fields=json!({"nonce":nonce,"code":code,"device_id":device,"decision":"approve","issued_at":issued_at,"expires_at":expires_at,"signature":signature});
  if kind=="unknown-field"{fields["user_id"]=json!("caller-cannot-supply-identity");}
  let payload=if kind=="invalid-input"{"{}".to_owned()}else{fields.to_string()};
  let observed=if kind=="invalid-input"{json!({})}else{let mut v=fields.clone();v["device_id"]=json!(if kind=="cross-tenant"{"<foreign-device>"}else{"<device>"});v["signature"]=json!("<signature>");v["issued_at"]=json!(if kind=="stale"{"<stale>"}else{"<now>"});v["expires_at"]=json!("<expires>");v};
  c.execute("INSERT INTO push_mfa_challenges(user_id,challenge_code,nonce,session_id,expires_at,failed_attempts) VALUES($1,'42',decode($2,'hex'),$3,now()+interval '120 seconds',$4)",&[&a.user,&nonce,&session,&if kind=="lockout"{2i32}else{0i32}]).await?;
  let mut listener=db.listen("session_revoke").await?;
  let before=push_rows(&c,&a,&b).await?;
  let (status,headers,raw)=request(gw.addr,"POST",path,payload.clone(),&[]).await?;
  if !mutant&&matches!(kind,"success"|"repeat")&&status!=204{return Err(format!("expected success status {}, got {status}",204).into());}
  let repeat=if matches!(kind,"repeat"|"lockout") {
   let (status,headers,raw)=request(gw.addr,"POST",path,payload.clone(),&[]).await?;
   Some(json!({"status":status,"headers":headers,"body":raw}))
  }else{None};
  let after=push_rows(&c,&a,&b).await?;let notifications=listener.drain(&c).await?;
  if kind.starts_with("commit-") {
      fault_probe(&db,&c,&a,&b,&keys,kind,operation,&mut wire,status,&headers,&raw).await?;
      if kind=="commit-before" {golden::compare(&before,&after)?;}else{assert_ne!(before,after,"committed transaction must publish its domain effects");}
      return Ok::<(),Err>(());
  }
  let mut actual=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("push-approve-{kind}"),"observation":{"request":{"method":"POST","path":path,"body":observed.to_string()},"response":{"status":status,"headers":headers,"body":raw},"effects":after,"audit":after["audit"],"notify":notifications}});
  if let Some(repeat)=repeat{actual["observation"]["repeat_response"]=repeat;}
  let effects=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("push-approve-{kind}-row-effects"),"effects":[{"table":"possession","before":before,"after":after}]});
  assert_go_recording(gw.addr,record.is_some()).await?;
  let file=corpus().join(format!("push-approve-{kind}.json"));let rowfile=corpus().join(format!("push-approve-{kind}-rows.json"));
  if record.is_some()&&!file.exists(){golden::record(&file,&actual)?;let mut tracer=effects.clone();tracer["case"]=json!(format!("push-approve-{kind}-rows"));golden::record(&rowfile,&tracer)?;}
  let qualified=corpus().parent().unwrap().join("qualified").join(format!("push-approve-{kind}-rows.json"));
  if record.is_some()&&!qualified.exists(){std::fs::create_dir_all(qualified.parent().unwrap())?;golden::record(&qualified,&effects)?;}
  let expected:Value=serde_json::from_str(&std::fs::read_to_string(&file)?)?;
  if mutant{assert!(golden::compare(&expected,&actual).is_err(),"mutant survived");}else{golden::compare(&expected,&actual)?;let old:Value=serde_json::from_str(&std::fs::read_to_string(rowfile)?)?;
  let mut tracer=effects.clone();tracer["case"]=json!(format!("push-approve-{kind}-rows"));
  golden::compare(&old,&tracer)?;
  golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(qualified)?)?,&effects)?;}
  if record.is_none(){let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));}else{let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;let hops=metrics.lines().find_map(|line|line.strip_prefix("setjoin_gateway_proxied_to_go_total ")).ok_or("Go-hop metric missing")?.parse::<u64>()?;assert!(hops>0,"recordings must traverse frozen Go");}
  oracle_receipt(&actual,mutant);
  Ok::<(),Err>(())
 }.await;
    gw.close().await;
    server.close().await;
    for uid in [a.user, b.user] {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT")).await?;
        c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&uid])
            .await?;
    }
    for uid in [a.user, b.user] {
        for table in ["auth_event_log", "login_events", "sessions", "oauth_tokens"] {
            c.execute(&format!("DELETE FROM {table} WHERE user_id=$1"), &[&uid])
                .await?;
        }
    }
    c.execute(
        "DELETE FROM push_mfa_challenges WHERE user_id=ANY($1::bigint[])",
        &[&vec![a.user, b.user]],
    )
    .await?;
    c.execute(
        "DELETE FROM push_devices WHERE user_id=ANY($1::bigint[])",
        &[&vec![a.user, b.user]],
    )
    .await?;
    common::restore_receipts(&c, &receipts).await;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if let Some(rate) = rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&rate],
        )
        .await?;
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?;
    }
    result
}
#[tokio::test]
async fn push_approve_success() {
    run_push_approve("success", false).await.unwrap();
}
#[tokio::test]
async fn push_approve_cross_tenant() {
    run_push_approve("cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn push_approve_invalid_input() {
    run_push_approve("invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn push_approve_repeat() {
    run_push_approve("repeat", false).await.unwrap();
}
#[tokio::test]
async fn push_approve_wrong_code() {
    run_push_approve("wrong-code", false).await.unwrap();
}
#[tokio::test]
async fn push_approve_lockout() {
    run_push_approve("lockout", false).await.unwrap();
}
#[tokio::test]
async fn push_approve_stale() {
    run_push_approve("stale", false).await.unwrap();
}
#[tokio::test]
async fn push_approve_bad_signature() {
    run_push_approve("bad-signature", false).await.unwrap();
}
#[tokio::test]
async fn push_approve_unknown_field() {
    run_push_approve("unknown-field", false).await.unwrap();
}
#[tokio::test]
async fn push_approve_status_mutant() {
    run_push_approve("success", true).await.unwrap();
}

async fn normalize_send(c:&tokio_postgres::Client,user:i64,token:&str,raw:&mut String)->Result<(),Err>{
 let Ok(mut v)=serde_json::from_str::<Value>(raw)else{return Ok(());};let Some(nonce)=v["nonce"].as_str().map(str::to_owned)else{return Ok(());};
 assert_eq!(nonce.len(),64);assert!(nonce.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)));assert_eq!(v["challenge_id"],user.to_string());
 assert!(v.get("code").is_none()&&v.get("answer").is_none(),"correct number-match answer must stay out of band");
 let row=c.query_one("SELECT challenge_code,session_id,expires_at>now()+interval '115 seconds' AND expires_at<now()+interval '121 seconds' FROM push_mfa_challenges WHERE user_id=$1 AND nonce=decode($2,'hex')",&[&user,&nonce]).await?;
 let code:String=row.get(0);assert_eq!(code.len(),2);assert!(code.bytes().all(|b|b.is_ascii_digit()));assert_eq!(row.get::<_,String>(1),token);assert!(row.get::<_,bool>(2));
 v["nonce"]=json!("<nonce>");v["challenge_id"]=json!("<signed-owner>");*raw=v.to_string()+"\n";Ok(())
}
async fn sent_rows(c:&tokio_postgres::Client,a:&fixture::Account,b:&fixture::Account)->Result<Value,Err>{
 let mut v=push_rows(c,a,b).await?;for row in v["challenges"].as_array_mut().unwrap(){let code=row["code"].as_str().unwrap();assert_eq!(code.len(),2);assert!(code.bytes().all(|b|b.is_ascii_digit()));assert_eq!(row["nonce"].as_str().unwrap().len(),64);row["code"]=json!("<out-of-band-code>");row["nonce"]=json!("<nonce>");}Ok(v)
}
async fn run_push_send(kind: &str, mutant: bool) -> Result<(), Err> {
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA3-push-send").unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idmfa3-actor").await?;
    let b = fixture::account(&c, "idmfa3-foreign").await?;
    let rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    for (uid, password) in [(a.user, "Password1!"), (b.user, "Foreign1!")] {
        c.execute(
            "UPDATE users SET password_hash=$2,factor_generation=2 WHERE id=$1",
            &[&uid, &bcrypt::hash(password, 4)?],
        )
        .await?;
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at) VALUES(encode(digest(($1::bigint)::text,'sha256'),'hex'),$1,'prior','totp.enroll','password',2,'session',now()+interval '5 minutes')",&[&uid]).await?;
    }
    for (uid, code) in [(a.user, "fixture-backup"), (b.user, "foreign-backup")] {
        c.execute(
            "UPDATE users SET totp_backup_codes_enc=$2 WHERE id=$1",
            &[&uid, &vec![bcrypt::hash(code, 4)?]],
        )
        .await?;
    }
    c.execute("UPDATE mfa_reauth_step_ups SET token_hash=encode(digest('idmfa3-backup-proof','sha256'),'hex'),session_jti='idmfa3-actor',operation='recovery.regenerate' WHERE user_id=$1",&[&a.user]).await?;
    if kind == "unused-target" {
        c.execute(
            "UPDATE mfa_reauth_step_ups SET target_ref='unused-target' WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    }
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    cfg.dsn = db.dsn.clone();
    cfg.signing_alg = "ES256".into();
    cfg.db_encryption_key = "2".repeat(64);
    cfg.vapid_private_key = VAPID.into();
    let operation=setjoin_identity::totp::Operation::PushSend;
    let command="mfa-push-send";
    let (executor,mut wire)=fault_executor(&db,kind,command).await?;
    let server = auth_server(
        Arc::new(
            AuthServer::load(
                executor,
                cfg,
            )
            .await?,
        ),
        mutant,
    )
    .await;
    let gw = gateway(server.addr, record.clone()).await;
    let result=async {
  let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();let uid=if kind=="cross-tenant"{b.user}else{a.user};
  let claims=json!({"uid":uid,"typ":"mfa_pending","amr":["pwd"],"iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600,"jti":"idmfa3-actor"});
  let bearer=format!("Bearer {}",setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&claims.to_string()));
  let path="/auth/mfa/push/send";
  let payload=if kind=="invalid-input"{"{}".into()}else{json!({"mfa_token":bearer.strip_prefix("Bearer ").unwrap(),"user_id":if kind=="cross-tenant"{a.user}else{b.user}}).to_string()};
  if kind=="user-limit"{for i in 1i64..=3{c.execute("INSERT INTO push_mfa_challenges(user_id,challenge_code,nonce,session_id,expires_at) VALUES($1,'42',decode(lpad(to_hex($2::bigint),64,'0'),'hex'),'prior',now()+interval '120 seconds')",&[&a.user,&i]).await?;}}
  let mut listener=db.listen("session_revoke").await?;
  let before=sent_rows(&c,&a,&b).await?;
  let (status,headers,mut raw)=request(gw.addr,"POST",path,payload.clone(),&[]).await?;
  if !mutant&&matches!(kind,"success"|"repeat")&&status!=200{return Err(format!("expected success status {}, got {status}",200).into());}
  normalize_send(&c,uid,bearer.strip_prefix("Bearer ").unwrap(),&mut raw).await?;
  let repeat=if kind=="repeat" {
   let (status,headers,mut raw)=request(gw.addr,"POST",path,payload.clone(),&[]).await?;
   normalize_send(&c,uid,bearer.strip_prefix("Bearer ").unwrap(),&mut raw).await?;
   Some(json!({"status":status,"headers":headers,"body":raw}))
  }else if kind=="ip-limit"{
   let mut replies=vec![];for _ in 0..10{let (status,headers,mut raw)=request(gw.addr,"POST",path,payload.clone(),&[]).await?;normalize_send(&c,uid,bearer.strip_prefix("Bearer ").unwrap(),&mut raw).await?;replies.push(json!({"status":status,"headers":headers,"body":raw}));}Some(json!(replies))
  }else{None};
  let after=sent_rows(&c,&a,&b).await?;let notifications=listener.drain(&c).await?;
  if kind.starts_with("commit-") {
      fault_probe(&db,&c,&a,&b,&keys,kind,operation,&mut wire,status,&headers,&raw).await?;
      if kind=="commit-before" {golden::compare(&before,&after)?;}else{assert_ne!(before,after,"committed transaction must publish its domain effects");}
      return Ok::<(),Err>(());
  }
  let mut actual=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("push-send-{kind}"),"observation":{"request":{"method":"POST","path":path,"body":payload.replace(bearer.strip_prefix("Bearer ").unwrap(),"<mfa-token>").replace(&b.user.to_string(),"<foreign>").replace(&a.user.to_string(),"<actor>")},"response":{"status":status,"headers":headers,"body":raw},"effects":after,"audit":after["audit"],"notify":notifications}});
  if let Some(repeat)=repeat{actual["observation"]["repeat_response"]=repeat;}
  let effects=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("push-send-{kind}-row-effects"),"effects":[{"table":"possession","before":before,"after":after}]});
  assert_go_recording(gw.addr,record.is_some()).await?;
  let file=corpus().join(format!("push-send-{kind}.json"));let rowfile=corpus().join(format!("push-send-{kind}-rows.json"));
  if record.is_some()&&!file.exists(){golden::record(&file,&actual)?;let mut tracer=effects.clone();tracer["case"]=json!(format!("push-send-{kind}-rows"));golden::record(&rowfile,&tracer)?;}
  let qualified=corpus().parent().unwrap().join("qualified").join(format!("push-send-{kind}-rows.json"));
  if record.is_some()&&!qualified.exists(){std::fs::create_dir_all(qualified.parent().unwrap())?;golden::record(&qualified,&effects)?;}
  let expected:Value=serde_json::from_str(&std::fs::read_to_string(&file)?)?;
  if mutant{assert!(golden::compare(&expected,&actual).is_err(),"mutant survived");}else{golden::compare(&expected,&actual)?;let old:Value=serde_json::from_str(&std::fs::read_to_string(rowfile)?)?;
  let mut tracer=effects.clone();tracer["case"]=json!(format!("push-send-{kind}-rows"));
  golden::compare(&old,&tracer)?;
  golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(qualified)?)?,&effects)?;}
  if record.is_none(){let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));}else{let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;let hops=metrics.lines().find_map(|line|line.strip_prefix("setjoin_gateway_proxied_to_go_total ")).ok_or("Go-hop metric missing")?.parse::<u64>()?;assert!(hops>0,"recordings must traverse frozen Go");}
  oracle_receipt(&actual,mutant);
  Ok::<(),Err>(())
 }.await;
    gw.close().await;
    server.close().await;
    for uid in [a.user, b.user] {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT")).await?;
        c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&uid])
            .await?;
    }
    for uid in [a.user, b.user] {
        for table in ["auth_event_log", "login_events", "sessions", "oauth_tokens"] {
            c.execute(&format!("DELETE FROM {table} WHERE user_id=$1"), &[&uid])
                .await?;
        }
    }
    c.execute(
        "DELETE FROM push_mfa_challenges WHERE user_id=ANY($1::bigint[])",
        &[&vec![a.user, b.user]],
    )
    .await?;
    common::restore_receipts(&c, &receipts).await;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if let Some(rate) = rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&rate],
        )
        .await?;
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?;
    }
    result
}

#[tokio::test]async fn push_send_success(){run_push_send("success",false).await.unwrap();}
#[tokio::test]async fn push_send_cross_tenant(){run_push_send("cross-tenant",false).await.unwrap();}
#[tokio::test]async fn push_send_invalid_input(){run_push_send("invalid-input",false).await.unwrap();}
#[tokio::test]async fn push_send_repeat(){run_push_send("repeat",false).await.unwrap();}
#[tokio::test]async fn push_send_user_limit(){run_push_send("user-limit",false).await.unwrap();}
#[tokio::test]async fn push_send_status_mutant(){run_push_send("success",true).await.unwrap();}

#[tokio::test]async fn push_send_ip_limit(){run_push_send("ip-limit",false).await.unwrap();}

async fn run_push_login(kind: &str, mutant: bool) -> Result<(), Err> {
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA3-push-login").unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idmfa3-actor").await?;
    let b = fixture::account(&c, "idmfa3-foreign").await?;
    let rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    for (uid, password) in [(a.user, "Password1!"), (b.user, "Foreign1!")] {
        c.execute(
            "UPDATE users SET password_hash=$2,factor_generation=2 WHERE id=$1",
            &[&uid, &bcrypt::hash(password, 4)?],
        )
        .await?;
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at) VALUES(encode(digest(($1::bigint)::text,'sha256'),'hex'),$1,'prior','totp.enroll','password',2,'session',now()+interval '5 minutes')",&[&uid]).await?;
    }
    for (uid, code) in [(a.user, "fixture-backup"), (b.user, "foreign-backup")] {
        c.execute(
            "UPDATE users SET totp_backup_codes_enc=$2 WHERE id=$1",
            &[&uid, &vec![bcrypt::hash(code, 4)?]],
        )
        .await?;
    }
    c.execute("UPDATE mfa_reauth_step_ups SET token_hash=encode(digest('idmfa3-backup-proof','sha256'),'hex'),session_jti='idmfa3-actor',operation='recovery.regenerate' WHERE user_id=$1",&[&a.user]).await?;
    if kind == "unused-target" {
        c.execute(
            "UPDATE mfa_reauth_step_ups SET target_ref='unused-target' WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    }
    c.execute("UPDATE users SET push_mfa_enabled=true,totp_enabled=$2 WHERE id=$1",&[&a.user,&(!kind.starts_with("push-only"))]).await?;
    let actor_email:String=c.query_one("SELECT email FROM users WHERE id=$1",&[&a.user]).await?.get(0);
    let foreign_email:String=c.query_one("SELECT email FROM users WHERE id=$1",&[&b.user]).await?.get(0);
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    cfg.dsn = db.dsn.clone();
    cfg.signing_alg = "ES256".into();
    cfg.db_encryption_key = "2".repeat(64);
    cfg.vapid_private_key = VAPID.into();
    let signature_exec=setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).unwrap();
    let signature_keys=setjoin_authz::signing_keys::KeySet::load(&signature_exec,keys["secret"].as_str().unwrap().as_bytes(),setjoin_config_secret::CryptoProfile::Standard).await?;
    let server = auth_server(
        Arc::new(
            AuthServer::load(
                setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
                    .unwrap(),
                cfg,
            )
            .await?
            .with_threat_gate(&db.dsn)
            .await?,
        ),
        mutant,
    )
    .await;
    let gw = gateway(server.addr, record.clone()).await;
    let result=async {
  let path="/auth/login";
  let payload=if kind=="invalid-input"{"{}".into()}else{json!({"email":if kind=="cross-tenant"{&foreign_email}else{&actor_email},"password":"Password1!","user_id":b.user}).to_string()};
  if matches!(kind,"fallback-user-limit"|"push-only-user-limit"){for i in 1i64..=3{c.execute("INSERT INTO push_mfa_challenges(user_id,challenge_code,nonce,session_id,expires_at) VALUES($1,'42',decode(lpad(to_hex($2::bigint),64,'0'),'hex'),'prior',now()+interval '120 seconds')",&[&a.user,&i]).await?;}}
  let mut listener=db.listen("session_revoke").await?;
  let before=sent_rows(&c,&a,&b).await?;
  let (status,headers,mut raw)=request(gw.addr,"POST",path,payload.clone(),&[]).await?;
  if !mutant&&matches!(kind,"success"|"repeat")&&status!=202{return Err(format!("expected success status {}, got {status}",202).into());}
  let challenge=if serde_json::from_str::<Value>(&raw).ok().is_some_and(|v|v.get("mfa_token").is_some()){Some(login_challenge(&c,&a,&signature_keys,&keys,&mut raw).await?)}else{None};
  let after=sent_rows(&c,&a,&b).await?;let notifications=listener.drain(&c).await?;
  let mut actual=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("push-login-{kind}"),"observation":{"request":{"method":"POST","path":path,"body":payload.replace(&actor_email,"actor@idmfa3.test").replace(&foreign_email,"foreign@idmfa3.test").replace(&b.user.to_string(),"<foreign>")},"response":{"status":status,"headers":headers,"body":raw},"effects":after,"audit":after["audit"],"notify":notifications}});
  if let Some(challenge)=challenge{actual["observation"]["pending_claims"]=challenge;}
  let effects=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("push-login-{kind}-row-effects"),"effects":[{"table":"possession","before":before,"after":after}]});
  assert_go_recording(gw.addr,record.is_some()).await?;
  let file=corpus().join(format!("push-login-{kind}.json"));let rowfile=corpus().join(format!("push-login-{kind}-rows.json"));
  if record.is_some()&&!file.exists(){golden::record(&file,&actual)?;let mut tracer=effects.clone();tracer["case"]=json!(format!("push-login-{kind}-rows"));golden::record(&rowfile,&tracer)?;}
  let qualified=corpus().parent().unwrap().join("qualified").join(format!("push-login-{kind}-rows.json"));
  if record.is_some()&&!qualified.exists(){std::fs::create_dir_all(qualified.parent().unwrap())?;golden::record(&qualified,&effects)?;}
  let expected:Value=serde_json::from_str(&std::fs::read_to_string(&file)?)?;
  if mutant{assert!(golden::compare(&expected,&actual).is_err(),"mutant survived");}else{golden::compare(&expected,&actual)?;let old:Value=serde_json::from_str(&std::fs::read_to_string(rowfile)?)?;
  let mut tracer=effects.clone();tracer["case"]=json!(format!("push-login-{kind}-rows"));
  golden::compare(&old,&tracer)?;
  golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(qualified)?)?,&effects)?;}
  if record.is_none(){let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));}else{let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;let hops=metrics.lines().find_map(|line|line.strip_prefix("setjoin_gateway_proxied_to_go_total ")).ok_or("Go-hop metric missing")?.parse::<u64>()?;assert!(hops>0,"recordings must traverse frozen Go");}
  oracle_receipt(&actual,mutant);
  Ok::<(),Err>(())
 }.await;
    gw.close().await;
    server.close().await;
    for uid in [a.user, b.user] {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT")).await?;
        c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&uid])
            .await?;
    }
    for uid in [a.user, b.user] {
        for table in ["auth_event_log", "login_events", "sessions", "oauth_tokens"] {
            c.execute(&format!("DELETE FROM {table} WHERE user_id=$1"), &[&uid])
                .await?;
        }
    }
    c.execute(
        "DELETE FROM push_mfa_challenges WHERE user_id=ANY($1::bigint[])",
        &[&vec![a.user, b.user]],
    )
    .await?;
    c.execute("DELETE FROM auth_event_log WHERE email=ANY($1::text[])",&[&vec![actor_email,foreign_email]]).await?;
    common::restore_receipts(&c, &receipts).await;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if let Some(rate) = rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&rate],
        )
        .await?;
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?;
    }
    result
}

#[tokio::test]async fn push_login_success(){run_push_login("success",false).await.unwrap();}

async fn login_challenge(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    keys: &setjoin_authz::signing_keys::KeySet,
    fixture: &Value,
    raw: &mut String,
) -> Result<Value, Err> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let v: Value = serde_json::from_str(raw)?;
    let token = v["mfa_token"].as_str().ok_or("missing challenge")?;
    let legacy = setjoin_authz::legacy_jwt::LegacyKeys::new(
        fixture["secret"].as_str().unwrap().as_bytes(),
        &["authserver-hmac-1"],
        None,
    )?;
    let proof =
        setjoin_identity::session::Session::verify(token, Some(keys), &legacy, "mailserver")
            .ok_or("invalid challenge signature")?;
    assert_eq!(proof.user(), a.user);
    assert_eq!(proof.text("typ"), "mfa_pending");
    assert_eq!(proof.text("jti").len(), 32);
    let row = c
        .query_one(
            "SELECT email,password_hash FROM users WHERE id=$1",
            &[&a.user],
        )
        .await?;
    assert_eq!(proof.text("email"), row.get::<_, String>(0));
    let cf = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(row.get::<_, String>(1).as_bytes()));
    assert_eq!(proof.text("credential_fence"), cf);
    let mut claims = Value::Object(proof.claims().clone());
    let iat = claims["iat"].as_i64().unwrap();
    assert_eq!(claims["exp"].as_i64().unwrap() - iat, 300);
    assert_eq!(claims["nbf"], iat);
    if let Some(nonce)=v["nonce"].as_str(){
        assert_eq!(nonce.len(),64);assert!(v.get("code").is_none()&&v.get("answer").is_none());
        let good:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM push_mfa_challenges WHERE user_id=$1 AND nonce=decode($2,'hex') AND session_id=$3 AND length(challenge_code)=2 AND expires_at>now()+interval '115 seconds' AND expires_at<now()+interval '121 seconds')",&[&a.user,&nonce,&token]).await?.get(0);assert!(good,"push nonce must bind the exact issued pending token");
        *raw=raw.replace(nonce,"<nonce>");
    }
    for k in ["iat", "nbf"] {
        claims[k] = json!(0);
    }
    claims["exp"] = json!(300);
    claims["uid"] = json!("<actor>");
    claims["sub"] = json!("<actor>");
    claims["email"] = json!("actor@idmfa3.test");
    claims["jti"] = json!("<pending-jti>");
    claims["credential_fence"] = json!("<credential-version>");
    *raw = raw.replace(token, "<mfa_token>");
    Ok(claims)
}
#[tokio::test]async fn push_login_push_only(){run_push_login("push-only",false).await.unwrap();}

#[tokio::test]async fn push_login_fallback_user_limit(){run_push_login("fallback-user-limit",false).await.unwrap();}

#[tokio::test]async fn push_login_cross_tenant(){run_push_login("cross-tenant",false).await.unwrap();}

#[tokio::test]async fn push_login_invalid_input(){run_push_login("invalid-input",false).await.unwrap();}

#[tokio::test]async fn push_login_status_mutant(){run_push_login("success",true).await.unwrap();}

#[tokio::test]async fn push_login_push_only_user_limit(){run_push_login("push-only-user-limit",false).await.unwrap();}

async fn recovery_rows(c:&tokio_postgres::Client,a:&fixture::Account,b:&fixture::Account)->Result<Value,Err>{
 let mut v=sent_rows(c,a,b).await?;let mut budgets=vec![];
 for (user,label) in [(a.user,"actor"),(b.user,"foreign")]{
  for prefix in ["recovery_user:","push_user:"]{let key=format!("{prefix}{user}");
   if let Some(row)=c.query_opt("SELECT failed_count,locked_until>now(),locked_until>now()+interval '890 seconds' AND locked_until<now()+interval '901 seconds',updated_at>now()-interval '10 seconds' FROM auth_lockouts WHERE lockout_key=$1",&[&key]).await?{budgets.push(json!({"owner":label,"kind":prefix,"count":row.get::<_,i32>(0),"active":row.get::<_,bool>(1),"fifteen_minutes":row.get::<_,bool>(2),"updated":row.get::<_,bool>(3)}));}
  }
 }v["budgets"]=json!(budgets);Ok(v)
}
async fn run_recovery(kind: &str, verify: bool, mutant: bool) -> Result<(), Err> {
    let prefix=if verify{"recovery-verify"}else{"recovery-begin"};
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA3-recovery-begin").unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    // Only this disposable fixture's loopback IP key; shared threat policy is
    // a separate #420 seam and must not obscure a recovery-specific refusal.
    c.execute("DELETE FROM auth_lockouts WHERE lockout_key='ip:127.0.0.1'",&[]).await?;
    // #420 owns shared threat policy; this corpus qualifies recovery's own
    // enumeration/account budgets with the outer policy controls disabled.
    let threat_flags=c.query("SELECT key,enabled FROM feature_toggles WHERE key IN ('feature.threat_feed','feature.geo_block','feature.spray_detect','feature.captcha','feature.tarpit')",&[]).await?;
    c.execute("UPDATE feature_toggles SET enabled=false WHERE key IN ('feature.threat_feed','feature.geo_block','feature.spray_detect','feature.captcha','feature.tarpit')",&[]).await?;
    let receipts = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idmfa3-actor").await?;
    let b = fixture::account(&c, "idmfa3-foreign").await?;
    let rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    for (uid, password) in [(a.user, "Password1!"), (b.user, "Foreign1!")] {
        c.execute(
            "UPDATE users SET password_hash=$2,factor_generation=2 WHERE id=$1",
            &[&uid, &bcrypt::hash(password, 4)?],
        )
        .await?;
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at) VALUES(encode(digest(($1::bigint)::text,'sha256'),'hex'),$1,'prior','totp.enroll','password',2,'session',now()+interval '5 minutes')",&[&uid]).await?;
    }
    for (uid, code) in [(a.user, "fixture-backup"), (b.user, "foreign-backup")] {
        c.execute(
            "UPDATE users SET totp_backup_codes_enc=$2 WHERE id=$1",
            &[&uid, &vec![bcrypt::hash(code, 4)?]],
        )
        .await?;
    }
    c.execute("UPDATE mfa_reauth_step_ups SET token_hash=encode(digest('idmfa3-backup-proof','sha256'),'hex'),session_jti='idmfa3-actor',operation='recovery.regenerate' WHERE user_id=$1",&[&a.user]).await?;
    if kind == "unused-target" {
        c.execute(
            "UPDATE mfa_reauth_step_ups SET target_ref='unused-target' WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    }
    c.execute("UPDATE users SET push_mfa_enabled=true,totp_enabled=$2 WHERE id=$1",&[&a.user,&(!kind.starts_with("push-only"))]).await?;
    let actor_email:String=c.query_one("SELECT email FROM users WHERE id=$1",&[&a.user]).await?.get(0);
    let foreign_email:String=c.query_one("SELECT email FROM users WHERE id=$1",&[&b.user]).await?.get(0);
    if verify {
        c.execute("UPDATE users SET totp_secret_enc=pgp_sym_encrypt('JBSWY3DPEHPK3PXP',$2),totp_enabled=true WHERE id=$1",&[&a.user,&"2".repeat(64)]).await?;
    }
    match kind {
      "disabled"=>{c.execute("UPDATE users SET enabled=false WHERE id=$1",&[&a.user]).await?;},
      "no-factor"=>{c.execute("UPDATE users SET totp_enabled=false,push_mfa_enabled=false WHERE id=$1",&[&a.user]).await?;},
      "totp-corrupt"=>{c.execute("UPDATE users SET totp_secret_enc=decode('deadbeef','hex') WHERE id=$1",&[&a.user]).await?;},
      "totp-locked"=>{c.execute("UPDATE users SET totp_failed_attempts=5,totp_locked_until=now()+interval '15 minutes' WHERE id=$1",&[&a.user]).await?;},
      _=>{}
    }
    let fixed_horizon=if kind.starts_with("budget-") {
      let count=if kind=="budget-expired"{50}else{30};let interval=if kind=="budget-expired"{"-1 second"}else{"15 minutes"};
      c.batch_execute(&format!("BEGIN;SELECT recovery_budget_acquire({});SELECT recovery_budget_record({},{count},now()+interval '{interval}');COMMIT",a.user,a.user)).await?;
      Some(c.query_one("SELECT locked_until::text FROM auth_lockouts WHERE lockout_key=$1",&[&format!("recovery_user:{}",a.user)]).await?.get::<_,String>(0))
    }else{None};
    if kind=="fault-budget" {c.batch_execute(&format!("CREATE FUNCTION gofree_idmfa3_budget_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.lockout_key='recovery_user:{}' THEN RAISE EXCEPTION 'gofree-idmfa3 budget fault';END IF;RETURN NEW;END$$;CREATE TRIGGER gofree_idmfa3_budget_fault BEFORE INSERT OR UPDATE ON auth_lockouts FOR EACH ROW EXECUTE FUNCTION gofree_idmfa3_budget_fault()",a.user)).await?;}
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    cfg.dsn = db.dsn.clone();
    cfg.worker_dsn=Some(db.dsn.clone());
    cfg.signing_alg = "ES256".into();
    cfg.db_encryption_key = "2".repeat(64);
    cfg.vapid_private_key = VAPID.into();
    let cut_kind=kind.strip_prefix("push-").unwrap_or(kind);
    let worker_cut=kind.starts_with("push-commit-");
    let operation=if worker_cut{setjoin_identity::totp::Operation::RecoveryPush}else{setjoin_identity::totp::Operation::Cycle};
    let (executor,mut wire)=if worker_cut{
      assert!(record.is_none());
      let cut=if cut_kind=="commit-before"{commit::CommitCut::BeforeCommit}else{commit::CommitCut::AfterCommit};
      let(dsn,task)=commit::multiplex_commit_cut_proxy(&db.dsn,cut,"mfa-recovery-push").await;
      cfg.worker_dsn=Some(dsn);
      (setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,Some(FaultWire(task)))
    }else{fault_executor(&db,cut_kind,"mfa-cycle").await?};
    let server = auth_server(
        Arc::new(
            AuthServer::load(
                executor,
                cfg,
            )
            .await?
            .with_threat_gate(&db.dsn)
            .await?,
        ),
        mutant,
    )
    .await;
    let gw = gateway(server.addr, record.clone()).await;
    let result=async {
  let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
  let path=if verify{"/auth/forgot-password/verify"}else{"/auth/forgot-password/begin"};
  if verify&&kind.starts_with("push-"){
   c.execute("INSERT INTO push_mfa_challenges(user_id,challenge_code,nonce,session_id,expires_at) VALUES($1,'42',decode($2,'hex'),'forgot-password',now()+interval '120 seconds')",&[&a.user,&"11".repeat(32)]).await?;
  }
  if verify&&kind.starts_with("push-") {
    let sql=match kind {"push-foreign"=>Some("UPDATE push_mfa_challenges SET user_id=$2 WHERE user_id=$1"),"push-purpose"=>Some("UPDATE push_mfa_challenges SET session_id='login' WHERE user_id=$1 AND $2::bigint>0"),"push-expired"=>Some("UPDATE push_mfa_challenges SET expires_at=now()-interval '1 second' WHERE user_id=$1 AND $2::bigint>0"),"push-burn"=>Some("UPDATE push_mfa_challenges SET failed_attempts=3 WHERE user_id=$1 AND $2::bigint>0"),"push-spent"=>Some("UPDATE push_mfa_challenges SET verified_at=now() WHERE user_id=$1 AND $2::bigint>0"),_=>None};
    if let Some(sql)=sql{c.execute(sql,&[&a.user,&b.user]).await?;}
  }
  if verify&&kind=="push-lockout"{
   c.execute("INSERT INTO auth_lockouts(lockout_key,failed_count,locked_until,updated_at) VALUES($1,4,now(),now())",&[&format!("push_user:{}",a.user)]).await?;
  }
  let mut code=setjoin_identity::totp::code("JBSWY3DPEHPK3PXP",now as i64).unwrap();
  if kind=="totp-wrong"{code.replace_range(0..1,if code.starts_with('0'){"1"}else{"0"});}
  let input_email=if kind=="unknown"{"missing@idmfa3.test"}else{&actor_email};
  let payload=if verify&&kind.starts_with("push-"){json!({"email":actor_email,"nonce":"11".repeat(32),"answer":if matches!(kind,"push-wrong"|"push-lockout"){"99"}else{"42"},"user_id":b.user}).to_string()}else if verify&&(matches!(kind,"success"|"repeat")||kind.starts_with("totp-")||kind.starts_with("budget-")||kind.starts_with("commit-")){json!({"email":actor_email,"code":code,"user_id":b.user}).to_string()}else if kind=="invalid-input"{"{}".into()}else{json!({"email":if kind=="cross-tenant"{&foreign_email}else{input_email},"user_id":b.user}).to_string()};
  let mut listener=db.listen("session_revoke").await?;
  let before=recovery_rows(&c,&a,&b).await?;
  let started=std::time::Instant::now();
  let (status,headers,mut raw)=request(gw.addr,"POST",path,payload.clone(),&[]).await?;
  if record.is_some()&&serde_json::from_str::<Value>(&raw).ok().is_some_and(|v|v.get("captcha_prompt").is_some()){return Err("unexpected outer #420 threat fixture; no recovery capture written".into());}
  if record.is_some()&&matches!(status,502|503){return Err("frozen Go recorder is unavailable; refuse to capture transport failure".into());}
  if !mutant&&matches!(kind,"success"|"repeat"|"push-success")&&status!=200{return Err(format!("expected success status {}, got {status}",200).into());}
  if !verify&&!mutant&&kind=="success"{assert!(started.elapsed()>=std::time::Duration::from_millis(90),"real TOTP begin must share the enumeration floor");}
  if !verify {
    if let Ok(value)=serde_json::from_str::<Value>(&raw){if let Some(nonce)=value["nonce"].as_str(){
      assert_eq!(nonce.len(),64);assert!(nonce.bytes().all(|b|b.is_ascii_hexdigit()));
      let valid:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM push_mfa_challenges WHERE user_id=$1 AND encode(nonce,'hex')=$2 AND session_id='forgot-password' AND verified_at IS NULL AND expires_at>now()+interval '110 seconds' AND expires_at<=now()+interval '121 seconds')",&[&a.user,&nonce]).await?.get(0);assert!(valid);raw=raw.replace(nonce,"<nonce>");
    }}
    if !mutant&&!matches!(kind,"invalid-input"){assert!(started.elapsed()>=std::time::Duration::from_millis(90));}
  }
  let issued=if let Ok(mut value)=serde_json::from_str::<Value>(&raw){
    if let Some(token)=value["reset_token"].as_str(){
      let signature_keys=setjoin_authz::signing_keys::KeySet::load(&setjoin_pg::ScopedExecutor::from_dsn(&db.dsn,2).unwrap(),keys["secret"].as_str().unwrap().as_bytes(),setjoin_config_secret::CryptoProfile::Standard).await?;
      let claims=signature_keys.validate(token,"mailserver",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs_f64()).ok_or("invalid reset signature")?;
      assert_eq!(claims["uid"],a.user);assert_eq!(claims["email"],actor_email);assert_eq!(claims["typ"],"password_reset");assert_eq!(claims["sub"],a.user.to_string());
      assert_eq!(claims["exp"].as_i64().unwrap()-claims["iat"].as_i64().unwrap(),300);
      assert_eq!(claims["jti"].as_str().unwrap().len(),64);
      let mut normalized=Value::Object(claims);for k in ["iat","nbf"]{normalized[k]=json!(0);}normalized["exp"]=json!(300);normalized["uid"]=json!("<actor>");normalized["sub"]=json!("<actor>");normalized["email"]=json!("actor@idmfa3.test");normalized["jti"]=json!("<reset-jti>");
      value["reset_token"]=json!("<reset-token>");raw=value.to_string()+"\n";Some(normalized)
    }else{None}
  }else{None};
  let repeat=if matches!(kind,"repeat"|"push-lockout"|"push-replay"|"budget-refused"){
    let mut repeat_payload=payload.clone();
    let horizon=if kind=="push-lockout"{
      if status!=401{return Err(format!("fifth answer must remain401, got {status}").into());}
      let mut value:Value=serde_json::from_str(&repeat_payload)?;value["answer"]=json!("42");repeat_payload=value.to_string();
      Some(c.query_one("SELECT locked_until::text FROM auth_lockouts WHERE lockout_key=$1",&[&format!("push_user:{}",a.user)]).await?.get::<_,String>(0))
    }else{None};
    let (status,headers,body)=request(gw.addr,"POST",path,repeat_payload,&[]).await?;
    if let Some(horizon)=horizon{assert_eq!(status,429,"locked account must refuse the correct answer");assert_eq!(horizon,c.query_one("SELECT locked_until::text FROM auth_lockouts WHERE lockout_key=$1",&[&format!("push_user:{}",a.user)]).await?.get::<_,String>(0),"refusals must not extend lock horizon");}
    Some(json!({"status":status,"headers":headers,"body":body}))
  }else{None};
  if let Some(horizon)=&fixed_horizon{if kind!="budget-expired"{assert_eq!(horizon,&c.query_one("SELECT locked_until::text FROM auth_lockouts WHERE lockout_key=$1",&[&format!("recovery_user:{}",a.user)]).await?.get::<_,String>(0),"refused budget cannot slide its horizon");}}
  let after=recovery_rows(&c,&a,&b).await?;let notifications=listener.drain(&c).await?;
  if cut_kind.starts_with("commit-") {
    fault_probe(&db,&c,&a,&b,&keys,cut_kind,operation,&mut wire,status,&headers,&raw).await?;
    let(mut domain_before,mut domain_after)=(before.clone(),after.clone());
    domain_before.as_object_mut().unwrap().remove("budgets");domain_after.as_object_mut().unwrap().remove("budgets");
    if cut_kind=="commit-before"{golden::compare(&domain_before,&domain_after)?;}else{assert_ne!(domain_before,domain_after);}
    let tails:i64=c.query_one("SELECT (SELECT count(*) FROM sessions WHERE user_id=$1)+(SELECT count(*) FROM oauth_tokens WHERE user_id=$1)",&[&a.user]).await?.get(0);assert_eq!(tails,0,"unknown recovery cannot publish a login tail");
    return Ok::<(),Err>(());
  }
  let mut actual=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("{prefix}-{kind}"),"observation":{"request":{"method":"POST","path":path,"body":payload.replace(&code,"<totp-code>").replace(&actor_email,"actor@idmfa3.test").replace(&foreign_email,"foreign@idmfa3.test").replace(&b.user.to_string(),"<foreign>")},"response":{"status":status,"headers":headers,"body":raw},"effects":after,"audit":after["audit"],"notify":notifications}});

  if let Some(repeat)=repeat{actual["observation"]["repeat_response"]=repeat;}
  if let Some(issued)=issued{actual["observation"]["issued"]=issued;}
  let effects=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("{prefix}-{kind}-row-effects"),"effects":[{"table":"possession","before":before,"after":after}]});
  assert_go_recording(gw.addr,record.is_some()).await?;
  let file=corpus().join(format!("{prefix}-{kind}.json"));let rowfile=corpus().join(format!("{prefix}-{kind}-rows.json"));
  if record.is_some()&&!file.exists(){golden::record(&file,&actual)?;let mut tracer=effects.clone();tracer["case"]=json!(format!("{prefix}-{kind}-rows"));golden::record(&rowfile,&tracer)?;}
  let qualified=corpus().parent().unwrap().join("qualified").join(format!("{prefix}-{kind}-rows.json"));
  if record.is_some()&&!qualified.exists(){std::fs::create_dir_all(qualified.parent().unwrap())?;golden::record(&qualified,&effects)?;}
  let expected:Value=serde_json::from_str(&std::fs::read_to_string(&file)?)?;
  if mutant{assert!(golden::compare(&expected,&actual).is_err(),"mutant survived");}else{golden::compare(&expected,&actual)?;let old:Value=serde_json::from_str(&std::fs::read_to_string(rowfile)?)?;
  let mut tracer=effects.clone();tracer["case"]=json!(format!("{prefix}-{kind}-rows"));
  golden::compare(&old,&tracer)?;
  golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(qualified)?)?,&effects)?;}
  if record.is_none(){let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));}else{let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;let hops=metrics.lines().find_map(|line|line.strip_prefix("setjoin_gateway_proxied_to_go_total ")).ok_or("Go-hop metric missing")?.parse::<u64>()?;assert!(hops>0,"recordings must traverse frozen Go");}
  oracle_receipt(&actual,mutant);
  Ok::<(),Err>(())
 }.await;
    if kind=="fault-budget"{c.batch_execute("DROP TRIGGER IF EXISTS gofree_idmfa3_budget_fault ON auth_lockouts;DROP FUNCTION IF EXISTS gofree_idmfa3_budget_fault()").await?;}
    gw.close().await;
    server.close().await;
    for uid in [a.user, b.user] {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT")).await?;
        c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&uid])
            .await?;
    }
    for uid in [a.user, b.user] {
        for table in ["auth_event_log", "login_events", "sessions", "oauth_tokens"] {
            c.execute(&format!("DELETE FROM {table} WHERE user_id=$1"), &[&uid])
                .await?;
        }
    }
    c.execute(
        "DELETE FROM push_mfa_challenges WHERE user_id=ANY($1::bigint[])",
        &[&vec![a.user, b.user]],
    )
    .await?;
    c.execute("DELETE FROM auth_event_log WHERE email=ANY($1::text[])",&[&vec![actor_email,foreign_email]]).await?;
    c.execute("DELETE FROM auth_lockouts WHERE lockout_key=ANY($1::text[])",&[&vec![format!("recovery_user:{}",a.user),format!("recovery_user:{}",b.user),format!("push_user:{}",a.user),format!("push_user:{}",b.user)]]).await?;
    common::restore_receipts(&c, &receipts).await;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if let Some(rate) = rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&rate],
        )
        .await?;
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?;
    }
    c.execute("DELETE FROM auth_lockouts WHERE lockout_key='ip:127.0.0.1'",&[]).await?;
    for row in threat_flags{let key:String=row.get(0);let enabled:bool=row.get(1);c.execute("UPDATE feature_toggles SET enabled=$2 WHERE key=$1",&[&key,&enabled]).await?;}
    result
}

#[tokio::test]async fn recovery_begin_success(){run_recovery_begin("success",false).await.unwrap();}
#[tokio::test]async fn recovery_begin_cross_tenant(){run_recovery_begin("cross-tenant",false).await.unwrap();}
#[tokio::test]async fn recovery_begin_invalid_input(){run_recovery_begin("invalid-input",false).await.unwrap();}
#[tokio::test]async fn recovery_begin_status_mutant(){run_recovery_begin("success",true).await.unwrap();}

async fn run_recovery_begin(kind:&str,mutant:bool)->Result<(),Err>{run_recovery(kind,false,mutant).await}

#[tokio::test]async fn recovery_begin_repeat(){run_recovery_begin("repeat",false).await.unwrap();}
#[tokio::test]async fn recovery_verify_success(){run_recovery("success",true,false).await.unwrap();}

#[tokio::test]async fn recovery_verify_cross_tenant(){run_recovery("cross-tenant",true,false).await.unwrap();}
#[tokio::test]async fn recovery_verify_invalid_input(){run_recovery("invalid-input",true,false).await.unwrap();}
#[tokio::test]async fn recovery_verify_repeat(){run_recovery("repeat",true,false).await.unwrap();}
#[tokio::test]async fn recovery_verify_status_mutant(){run_recovery("success",true,true).await.unwrap();}

#[tokio::test]async fn recovery_verify_push_success(){run_recovery("push-success",true,false).await.unwrap();}

#[tokio::test]async fn recovery_verify_push_wrong(){run_recovery("push-wrong",true,false).await.unwrap();}

#[tokio::test]async fn recovery_verify_push_lockout(){run_recovery("push-lockout",true,false).await.unwrap();}

async fn run_webauthn_possession(kind: &str, finish:bool, mutant: bool) -> Result<(), Err> {
    let prefix=if finish{"possession-webauthn-finish"}else{"possession-webauthn-begin"};
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA3-recovery-begin").unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idmfa3-actor").await?;
    let b = fixture::account(&c, "idmfa3-foreign").await?;
    let rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    for (uid, password) in [(a.user, "Password1!"), (b.user, "Foreign1!")] {
        c.execute(
            "UPDATE users SET password_hash=$2,factor_generation=2 WHERE id=$1",
            &[&uid, &bcrypt::hash(password, 4)?],
        )
        .await?;
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at) VALUES(encode(digest(($1::bigint)::text,'sha256'),'hex'),$1,'prior','totp.enroll','password',2,'session',now()+interval '5 minutes')",&[&uid]).await?;
    }
    for (uid, code) in [(a.user, "fixture-backup"), (b.user, "foreign-backup")] {
        c.execute(
            "UPDATE users SET totp_backup_codes_enc=$2 WHERE id=$1",
            &[&uid, &vec![bcrypt::hash(code, 4)?]],
        )
        .await?;
    }
    c.execute("UPDATE mfa_reauth_step_ups SET token_hash=encode(digest('idmfa3-backup-proof','sha256'),'hex'),session_jti='idmfa3-actor',operation='recovery.regenerate' WHERE user_id=$1",&[&a.user]).await?;
    if kind == "unused-target" {
        c.execute(
            "UPDATE mfa_reauth_step_ups SET target_ref='unused-target' WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    }
    c.execute("UPDATE users SET push_mfa_enabled=true,totp_enabled=$2 WHERE id=$1",&[&a.user,&(!kind.starts_with("push-only"))]).await?;
    let actor_email:String=c.query_one("SELECT email FROM users WHERE id=$1",&[&a.user]).await?.get(0);
    let foreign_email:String=c.query_one("SELECT email FROM users WHERE id=$1",&[&b.user]).await?.get(0);
    use base64::Engine;
    let vectors:Value=serde_json::from_str(include_str!("../../../tests/conformance/identity-webauthn/vectors.json"))?;
    let vector=&vectors["cases"][0];
    let id=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(vector["id"].as_str().unwrap())?;
    let handle=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(vector["handle"].as_str().unwrap())?;
    let hex=vector["key"].as_str().unwrap();let key:Vec<u8>=(0..hex.len()).step_by(2).map(|i|u8::from_str_radix(&hex[i..i+2],16).unwrap()).collect();
    c.execute("UPDATE users SET webauthn_user_handle=$2 WHERE id=$1",&[&a.user,&handle]).await?;
    for (uid,id)in [(a.user,id.clone()),(b.user,b"foreign-uv-key".to_vec())]{
        c.execute("INSERT INTO passkey_credentials(id,user_id,public_key,attestation_type,sign_count,uv_capable) VALUES($1,$2,$3,'none',7,true)",&[&id,&uid,&key]).await?;
    }
    if finish {
      use sha2::{Digest,Sha256};let hash=format!("{:x}",Sha256::digest(vector["challenge"].as_str().unwrap().as_bytes()));
      c.execute("INSERT INTO webauthn_ceremonies(challenge_hash,user_id,kind,operation,session_jti,token_scope,expires_at) VALUES($1,$2,'management_assertion','recovery.regenerate','idmfa3-actor','session',now()+interval '5 minutes')",&[&hash,&a.user]).await?;
    }
    if kind=="pending" {c.execute("UPDATE webauthn_ceremonies SET operation='bootstrap.totp.enroll',token_scope='mfa_pending' WHERE user_id=$1",&[&a.user]).await?;}
    match kind {
      "locked"=>{c.execute("UPDATE users SET possession_webauthn_failed_attempts=5,possession_webauthn_locked_until=now()+interval '15 minutes' WHERE id=$1",&[&a.user]).await?;},
      "near-lock"=>{c.execute("UPDATE users SET possession_webauthn_failed_attempts=4 WHERE id=$1",&[&a.user]).await?;},
      "non-uv"=>{c.execute("UPDATE passkey_credentials SET uv_capable=false WHERE user_id=$1",&[&a.user]).await?;},
      "expired-ceremony"=>{c.execute("UPDATE webauthn_ceremonies SET expires_at=now()-interval '1 second' WHERE user_id=$1",&[&a.user]).await?;},
      "wrong-jti"=>{c.execute("UPDATE webauthn_ceremonies SET session_jti='another-session' WHERE user_id=$1",&[&a.user]).await?;},
      "wrong-scope"=>{c.execute("UPDATE webauthn_ceremonies SET token_scope='mfa_pending' WHERE user_id=$1",&[&a.user]).await?;},
      "target-revoked"=>{c.execute("UPDATE webauthn_ceremonies SET operation='webauthn.revoke',target_ref=$2 WHERE user_id=$1",&[&a.user,&vector["id"].as_str().unwrap()]).await?;c.execute("UPDATE passkey_credentials SET revoked_at=now() WHERE user_id=$1",&[&a.user]).await?;},
      _=>{}
    }
    let fault_table=match kind{"fault-grant"=>Some("mfa_reauth_step_ups"),"fault-ceremony"=>Some("webauthn_ceremonies"),_=>None};
    if let Some(table)=fault_table{c.batch_execute(&format!("CREATE FUNCTION gofree_idmfa3_possession_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.user_id={} THEN RAISE EXCEPTION 'gofree-idmfa3 possession fault';END IF;RETURN NEW;END$$;CREATE TRIGGER gofree_idmfa3_possession_fault BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION gofree_idmfa3_possession_fault()",a.user)).await?;}
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    cfg.dsn = db.dsn.clone();
    cfg.worker_dsn=Some(db.dsn.clone());
    cfg.signing_alg = "ES256".into();
    cfg.db_encryption_key = "2".repeat(64);
    cfg.vapid_private_key = VAPID.into();
    let operation=if finish{setjoin_identity::totp::Operation::WebauthnPossessionFinish}else{setjoin_identity::totp::Operation::WebauthnPossessionBegin};
    let command=if finish{"mfa-webauthn-possession-finish"}else{"mfa-webauthn-possession-begin"};
    let (executor,mut wire)=fault_executor(&db,kind,command).await?;
    let server = auth_server(
        Arc::new(
            AuthServer::load(
                executor,
                cfg,
            )
            .await?,
        ),
        mutant,
    )
    .await;
    let gw = gateway(server.addr, record.clone()).await;
    let result=async {
      let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
      let mut claims=json!({"uid":if kind=="cross-tenant"{b.user}else{a.user},"typ":if kind=="pending"{"mfa_pending"}else{"access"},"jti":"idmfa3-actor","iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600});
      let sign=|v:&Value|setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&v.to_string());
      let token=sign(&claims);let bearer=format!("Bearer {token}");
      claims["typ"]=json!("mfa_pending");claims["uid"]=json!(b.user);
      let pending_token=if kind=="access-wins"{sign(&claims)}else{token.clone()};
      let path=if finish{"/auth/mfa/possession/webauthn/finish"}else{"/auth/mfa/possession/webauthn/begin"};
      let payload=if finish&&kind=="invalid-input"{"{".into()}else if finish{let mut value=vector["assertions"]["success"]["request"].clone();value["operation"]=json!("recovery.regenerate");value["user_id"]=json!(if kind=="cross-tenant"{a.user}else{b.user});value.to_string()}else if kind=="invalid-input"{"{}".into()}else if kind=="cross-tenant"{json!({"operation":"webauthn.revoke","target_ref":vector["id"],"user_id":a.user}).to_string()}else{json!({"operation":"recovery.regenerate","user_id":b.user}).to_string()};
      let payload=if !matches!(kind,"invalid-input"){
        let mut value:Value=serde_json::from_str(&payload)?;
        if matches!(kind,"pending"|"access-wins"){value["mfa_token"]=json!(pending_token);}
        if kind=="pending"{value["operation"]=json!("bootstrap.totp.enroll");}
        if kind=="operation"{value["operation"]=json!("totp.enroll");}
        if kind=="target-revoked"{value["operation"]=json!("webauthn.revoke");value["target_ref"]=vector["id"].clone();}
        if finish&&matches!(kind,"wrong-origin"|"near-lock"){
          let mut client:Value=serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value["response"]["clientDataJSON"].as_str().unwrap())?)?;
          client["origin"]=json!("https://foreign.invalid");value["response"]["clientDataJSON"]=json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client.to_string()));
        }
        if kind=="malformed-assertion"{value["response"]["authenticatorData"]=json!("!");}
        value.to_string()
      }else{payload};
      let cookie=if matches!(kind,"cookie"|"csrf"){format!("access_token={token}")}else{String::new()};
      let authorization=if kind=="pending"||kind=="csrf"{""}else if kind=="cookie"{"Bearer invalid"}else{&bearer};
      let request_headers=[("authorization",authorization),("cookie",cookie.as_str()),("origin",if kind=="csrf"{"https://foreign.invalid"}else{""}),("content-type",if kind=="media"{"text/plain"}else{"application/json"})];
      let before=webauthn_possession_rows(&c,&a,&b).await?;
      let mut listener=db.listen("session_revoke").await?;
      // The front door itself terminates cookie CSRF before proxying. Record
      // the controller's exact response from real Go/native auth HTTP seams;
      // also assert the front door refuses it without proxying. Every ordinary
      // management capture still proves a Go hop.
      let destination=if kind=="csrf" {if let Some(url)=&record {url.parse::<hyper::Uri>()?.authority().ok_or("Go authority")?.as_str().parse()?}else{server.addr}}else{gw.addr};
      let (status,headers,mut raw)=request(destination,"POST",path,payload.clone(),&request_headers).await?;
      if kind=="csrf"&&record.is_none(){let(edge_status,edge_headers,edge_body)=request(gw.addr,"POST",path,payload.clone(),&request_headers).await?;assert_eq!(edge_status,403);assert_eq!(edge_body,raw);assert_eq!(edge_headers["cache-control"],"no-store");assert_eq!(edge_headers["x-content-type-options"],"nosniff");}
      if !mutant&&matches!(kind,"success"|"repeat")&&status!=200{return Err(format!("expected management begin200, got {status}: {raw}").into());}
      if serde_json::from_str::<Value>(&raw).ok().is_some_and(|v|v["publicKey"].is_object()){normalize_management_begin(&c,a.user,&id,&mut raw,kind=="pending").await?;}
      if finish{normalize_management_grant(&c,a.user,&id,&mut raw).await?;}
      if kind=="pending"&&finish&&status==200{
        use sha2::{Digest,Sha256};assert_eq!(serde_json::from_str::<Value>(&raw)?["granted"],true);
        let hash=format!("{:x}",Sha256::digest(token.as_bytes()));
        let valid:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM mfa_reauth_step_ups WHERE user_id=$1 AND token_hash=$2 AND operation='bootstrap.totp.enroll' AND token_scope='mfa_pending' AND session_jti='idmfa3-actor' AND refresh_family_id IS NULL AND proving_factor_id=$3 AND bound_factor_generation=2)",&[&a.user,&hash,&id]).await?.get(0);assert!(valid);
      }
      let repeat=if kind=="near-lock"{
        assert_eq!(status,403);let horizon:String=c.query_one("SELECT possession_webauthn_locked_until::text FROM users WHERE id=$1",&[&a.user]).await?.get(0);
        let mut value=vector["assertions"]["success"]["request"].clone();value["operation"]=json!("recovery.regenerate");
        let (status,headers,raw)=request(gw.addr,"POST",path,value.to_string(),&request_headers).await?;assert_eq!(status,429);
        assert_eq!(horizon,c.query_one("SELECT possession_webauthn_locked_until::text FROM users WHERE id=$1",&[&a.user]).await?.get::<_,String>(0));Some(json!({"status":status,"headers":headers,"body":raw}))
      }else if kind=="repeat"{let (status,headers,mut raw)=request(gw.addr,"POST",path,payload.clone(),&[("authorization",&bearer)]).await?;if finish{normalize_management_grant(&c,a.user,&id,&mut raw).await?;}else{normalize_management_begin(&c,a.user,&id,&mut raw,kind=="pending").await?;}Some(json!({"status":status,"headers":headers,"body":raw}))}else{None};
      let after=webauthn_possession_rows(&c,&a,&b).await?;let notify=listener.drain(&c).await?;
      if kind.starts_with("commit-") {
      fault_probe(&db,&c,&a,&b,&keys,kind,operation,&mut wire,status,&headers,&raw).await?;
      if kind=="commit-before" {golden::compare(&before,&after)?;}else{assert_ne!(before,after,"committed transaction must publish its domain effects");}
      return Ok::<(),Err>(());
  }
  let mut actual=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("{prefix}-{kind}"),"observation":{"request":{"method":"POST","path":path,"body":payload.replace(&pending_token,"<pending-token>").replace(&b.user.to_string(),"<foreign>").replace(&a.user.to_string(),"<actor>")},"response":{"status":status,"headers":headers,"body":raw},"effects":after,"audit":after["audit"],"notify":notify}});
      if let Some(repeat)=repeat{actual["observation"]["repeat_response"]=repeat;}
      let effects=json!({"format":1,"go_source":SOURCE,"route":format!("POST {path}"),"case":format!("{prefix}-{kind}-row-effects"),"effects":[{"table":"possession","before":before,"after":after}]});
      if kind=="csrf"{assert_eq!(status,403);assert_go_recording(gw.addr,false).await?;}else{assert_go_recording(gw.addr,record.is_some()).await?;}
      let file=corpus().join(format!("{prefix}-{kind}.json"));let rowfile=corpus().join(format!("{prefix}-{kind}-rows.json"));let qualified=corpus().parent().unwrap().join("qualified").join(format!("{prefix}-{kind}-rows.json"));
      if record.is_some()&&!file.exists(){golden::record(&file,&actual)?;let mut old=effects.clone();old["case"]=json!(format!("{prefix}-{kind}-rows"));golden::record(&rowfile,&old)?;}
      if record.is_some()&&!qualified.exists(){golden::record(&qualified,&effects)?;}
      let expected:Value=serde_json::from_str(&std::fs::read_to_string(&file)?)?;
      if mutant{assert!(golden::compare(&expected,&actual).unwrap_err().contains("/observation/response/status"),"management begin mutant must detect the status change");}else{golden::compare(&expected,&actual)?;golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(qualified)?)?,&effects)?;}
      if record.is_none(){let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));}
      oracle_receipt(&actual,mutant);
  Ok::<(),Err>(())
    }.await;
    if let Some(table)=fault_table{c.batch_execute(&format!("DROP TRIGGER IF EXISTS gofree_idmfa3_possession_fault ON {table};DROP FUNCTION IF EXISTS gofree_idmfa3_possession_fault()")).await?;}
    gw.close().await;
    server.close().await;
    for uid in [a.user, b.user] {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT")).await?;
        c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&uid])
            .await?;
    }
    for uid in [a.user, b.user] {
        for table in ["auth_event_log", "login_events", "sessions", "oauth_tokens"] {
            c.execute(&format!("DELETE FROM {table} WHERE user_id=$1"), &[&uid])
                .await?;
        }
    }
    c.execute(
        "DELETE FROM push_mfa_challenges WHERE user_id=ANY($1::bigint[])",
        &[&vec![a.user, b.user]],
    )
    .await?;
    c.execute("DELETE FROM auth_event_log WHERE email=ANY($1::text[])",&[&vec![actor_email,foreign_email]]).await?;
    c.execute("DELETE FROM auth_lockouts WHERE lockout_key=ANY($1::text[])",&[&vec![format!("recovery_user:{}",a.user),format!("recovery_user:{}",b.user),format!("push_user:{}",a.user),format!("push_user:{}",b.user)]]).await?;
    for table in ["webauthn_ceremonies","passkey_credentials"]{c.execute(&format!("DELETE FROM {table} WHERE user_id=ANY($1::bigint[])"),&[&vec![a.user,b.user]]).await?;}
    common::restore_receipts(&c, &receipts).await;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if let Some(rate) = rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&rate],
        )
        .await?;
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?;
    }
    result
}

async fn webauthn_possession_rows(c:&tokio_postgres::Client,a:&fixture::Account,b:&fixture::Account)->Result<Value,Err>{
 let mut v=grant_rows(c,a,b).await?;let mut ceremonies=vec![];let mut credentials=vec![];let mut budgets=vec![];
 for (user,label)in [(a.user,"actor"),(b.user,"foreign")]{
  for row in c.query("SELECT challenge_hash,kind,operation,target_ref,session_jti,token_scope,refresh_family_id,expires_at>now() FROM webauthn_ceremonies WHERE user_id=$1 ORDER BY created_at",&[&user]).await?{
   let hash:String=row.get(0);assert_eq!(hash.len(),64);
   ceremonies.push(json!({"owner":label,"hash":"<challenge-hash>","kind":row.get::<_,String>(1),"operation":row.get::<_,String>(2),"target":row.get::<_,Option<String>>(3),"jti":row.get::<_,String>(4),"scope":row.get::<_,String>(5),"family":row.get::<_,Option<String>>(6),"live":row.get::<_,bool>(7)}));
  }
  for row in c.query("SELECT encode(id,'hex'),encode(public_key,'hex'),attestation_type,sign_count,uv_capable,revoked_at IS NOT NULL,last_used_at IS NOT NULL FROM passkey_credentials WHERE user_id=$1 ORDER BY id",&[&user]).await?{
   credentials.push(json!({"owner":label,"id":row.get::<_,String>(0),"key":row.get::<_,String>(1),"attestation":row.get::<_,String>(2),"count":row.get::<_,i32>(3),"uv":row.get::<_,bool>(4),"revoked":row.get::<_,bool>(5),"used":row.get::<_,bool>(6)}));
  }
  let row=c.query_one("SELECT possession_webauthn_failed_attempts,COALESCE(possession_webauthn_locked_until>now(),false) FROM users WHERE id=$1",&[&user]).await?;
  budgets.push(json!({"owner":label,"count":row.get::<_,i32>(0),"locked":row.get::<_,bool>(1)}));
 }
 v["ceremonies"]=json!(ceremonies);v["credentials"]=json!(credentials);v["webauthn_budgets"]=json!(budgets);Ok(v)
}
async fn normalize_management_begin(c:&tokio_postgres::Client,user:i64,id:&[u8],raw:&mut String,pending:bool)->Result<(),Err>{
 use base64::Engine;use sha2::{Digest,Sha256};
 let value:Value=serde_json::from_str(raw)?;let options=&value["publicKey"];let challenge=options["challenge"].as_str().ok_or("missing challenge")?;
 assert_eq!(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(challenge)?.len(),32);assert_eq!(options["userVerification"],"required");assert_eq!(options["rpId"],"localhost");
 assert_eq!(options["allowCredentials"],json!([{"type":"public-key","id":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id)}]));
 let hash=format!("{:x}",Sha256::digest(challenge.as_bytes()));
 let valid:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM webauthn_ceremonies WHERE user_id=$1 AND challenge_hash=$2 AND kind='management_assertion' AND operation=$3 AND session_jti='idmfa3-actor' AND token_scope=$4 AND refresh_family_id IS NULL AND expires_at>now()+interval '290 seconds' AND expires_at<now()+interval '301 seconds')",&[&user,&hash,&if pending{"bootstrap.totp.enroll"}else{"recovery.regenerate"},&if pending{"mfa_pending"}else{"session"}]).await?.get(0);
 assert!(valid,"challenge must bind the owned complete ceremony tuple before masking");*raw=raw.replace(challenge,"<challenge>");Ok(())
}
#[tokio::test]async fn possession_webauthn_begin_success(){run_webauthn_possession_begin("success",false).await.unwrap();}

#[tokio::test]async fn possession_webauthn_begin_cross_tenant(){run_webauthn_possession_begin("cross-tenant",false).await.unwrap();}
#[tokio::test]async fn possession_webauthn_begin_invalid_input(){run_webauthn_possession_begin("invalid-input",false).await.unwrap();}
#[tokio::test]async fn possession_webauthn_begin_repeat(){run_webauthn_possession_begin("repeat",false).await.unwrap();}
#[tokio::test]async fn possession_webauthn_begin_status_mutant(){run_webauthn_possession_begin("success",true).await.unwrap();}

async fn run_webauthn_possession_begin(kind:&str,mutant:bool)->Result<(),Err>{run_webauthn_possession(kind,false,mutant).await}
async fn normalize_management_grant(c:&tokio_postgres::Client,user:i64,id:&[u8],raw:&mut String)->Result<(),Err>{
 use sha2::{Digest,Sha256};
 let Ok(value)=serde_json::from_str::<Value>(raw)else{return Ok(());};let Some(token)=value["reauth_token"].as_str()else{return Ok(());};
 assert_eq!(token.len(),64);assert!(token.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)));assert_eq!(value["expires_in"],300);
 let hash=format!("{:x}",Sha256::digest(token.as_bytes()));
 let valid:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM mfa_reauth_step_ups WHERE user_id=$1 AND token_hash=$2 AND session_jti='idmfa3-actor' AND operation='recovery.regenerate' AND target_ref IS NULL AND proof_method='webauthn_uv' AND proving_factor_id=$3 AND bound_factor_generation=2 AND token_scope='session' AND refresh_family_id IS NULL AND expires_at>now()+interval '290 seconds' AND expires_at<now()+interval '301 seconds')",&[&user,&hash,&id]).await?.get(0);
 assert!(valid,"UV proof must bind the complete stored grant before masking");*raw=raw.replace(token,"<reauth>");Ok(())
}
#[tokio::test]async fn possession_webauthn_finish_success(){run_webauthn_possession("success",true,false).await.unwrap();}

#[tokio::test]async fn possession_webauthn_finish_cross_tenant(){run_webauthn_possession("cross-tenant",true,false).await.unwrap();}
#[tokio::test]async fn possession_webauthn_finish_invalid_input(){run_webauthn_possession("invalid-input",true,false).await.unwrap();}
#[tokio::test]async fn possession_webauthn_finish_repeat(){run_webauthn_possession("repeat",true,false).await.unwrap();}
#[tokio::test]async fn possession_webauthn_finish_status_mutant(){run_webauthn_possession("success",true,true).await.unwrap();}

#[tokio::test]async fn push_subtree_success(){run("push-subtree","success",false).await.unwrap();}
#[tokio::test]async fn push_subtree_invalid_input(){run("push-subtree","invalid-input",false).await.unwrap();}
#[tokio::test]async fn push_subtree_cross_tenant(){run("push-subtree","cross-tenant",false).await.unwrap();}
#[tokio::test]async fn push_subtree_head(){run("push-subtree","head",false).await.unwrap();}
#[tokio::test]async fn push_subtree_status_mutant(){run("push-subtree","success",true).await.unwrap();}
#[tokio::test]async fn backup_subtree_success(){run("backup-subtree","success",false).await.unwrap();}
#[tokio::test]async fn backup_subtree_cross_tenant(){run("backup-subtree","cross-tenant",false).await.unwrap();}
#[tokio::test]async fn backup_subtree_invalid_input(){run("backup-subtree","invalid-input",false).await.unwrap();}
#[tokio::test]async fn backup_subtree_head(){run("backup-subtree","head",false).await.unwrap();}
#[tokio::test]async fn backup_subtree_status_mutant(){run("backup-subtree","success",true).await.unwrap();}
#[tokio::test]async fn vapid_head(){run("vapid","head",false).await.unwrap();}

#[tokio::test]async fn vapid_absent_key(){run("vapid","absent-key",false).await.unwrap();}

fn oracle_receipt(actual:&Value,mutant:bool){
 println!("{}: {} :: {}",if mutant{"MUTANT-REJECTED"}else{"GOLDEN-REPLAY"},actual["route"].as_str().unwrap(),if mutant{"status"}else{actual["case"].as_str().unwrap()});
}
fn registration_observation(actual:&Value)->Value{
 let mut normalized=actual.clone();let route=normalized["route"].as_str().unwrap().to_owned();let (method,path)=route.split_once(' ').unwrap();
 let request=&mut normalized["observation"]["request"];request["actual_method"]=request["method"].clone();request["actual_path"]=request["path"].clone();request["method"]=json!(method);request["path"]=json!(path);normalized
}

struct FaultWire(tokio::task::JoinHandle<std::io::Result<commit::CommitCut>>);
impl Drop for FaultWire{fn drop(&mut self){self.0.abort();}}
async fn fault_executor(db:&Db,kind:&str,command:&'static str)->Result<(setjoin_pg::ScopedExecutor,Option<FaultWire>),Err>{
    let base=db.app.as_deref().unwrap_or(&db.dsn);
    if !kind.starts_with("commit-"){return Ok((setjoin_pg::ScopedExecutor::from_dsn(base,4).map_err(|e|e.0)?,None));}
    assert!(std::env::var("GOFREE_RECORD_UPSTREAM").is_err(),"faults cannot record");
    let cut=if kind=="commit-before"{commit::CommitCut::BeforeCommit}else{commit::CommitCut::AfterCommit};
    let (dsn,task)=commit::commit_cut_proxy(base,cut,command).await;
    Ok((setjoin_pg::ScopedExecutor::from_dsn(&dsn,1).map_err(|e|e.0)?,Some(FaultWire(task))))
}
#[allow(clippy::too_many_arguments)]
async fn fault_probe(db:&Db,c:&tokio_postgres::Client,a:&fixture::Account,b:&fixture::Account,keys:&Value,kind:&str,operation:setjoin_identity::totp::Operation,wire:&mut Option<FaultWire>,status:u16,headers:&Value,raw:&str)->Result<(),Err>{
    use setjoin_identity::{session::Session,totp};
    assert_eq!(status,503,"{kind}: {raw}");assert!(headers.get("set-cookie").is_none());
    let response:Value=serde_json::from_str(raw)?;
    for field in ["access_token","refresh_token","reset_token","reauth_token","codes","nonce","publicKey"]{assert!(response.get(field).is_none(),"Unknown leaked {field}");}
    let id=headers["x-operation-id"].as_str().ok_or("missing operation ID")?;
    let op=setjoin_contracts::ids::OperationId(*uuid::Uuid::parse_str(id)?.as_bytes());
    let mut wire=wire.take().expect("owned wire cut");
    let cut=tokio::time::timeout(std::time::Duration::from_secs(10),&mut wire.0).await???;
    assert_eq!(cut,if kind=="commit-before"{commit::CommitCut::BeforeCommit}else{commit::CommitCut::AfterCommit});
    let exec=setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),2).map_err(|e|e.0)?;
    let legacy=setjoin_authz::legacy_jwt::LegacyKeys::new(keys["secret"].as_str().unwrap().as_bytes(),&["authserver-hmac-1"],None)?;
    let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let proof=|uid|{let claims=json!({"uid":uid,"typ":"access","jti":"idmfa3-fresh-lookup","iat":now,"exp":now+3600,"iss":"mailserver","aud":["mailserver-gateway"]});let token=setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&claims.to_string());Session::verify(&token,None,&legacy,"mailserver").unwrap()};
    let actor=proof(a.user);let foreign=proof(b.user);
    assert_eq!(totp::lookup_operation(&exec,&actor,op,operation).await.map_err(|e|e.message)?,kind=="commit-after");
    assert!(!totp::lookup_operation(&exec,&foreign,op,operation).await.map_err(|e|e.message)?);
    c.execute("UPDATE users SET enabled=false WHERE id=$1",&[&a.user]).await?;
    let disabled=totp::lookup_operation(&exec,&actor,op,operation).await;
    c.execute("UPDATE users SET enabled=true WHERE id=$1",&[&a.user]).await?;assert!(disabled.is_err());
    c.execute("INSERT INTO session_revocations(user_id,scope,jti,reason,expires_at) VALUES($1,'jti','idmfa3-fresh-lookup','fixture',now()+interval '1 hour')",&[&a.user]).await?;
    let revoked=totp::lookup_operation(&exec,&actor,op,operation).await;
    c.execute("DELETE FROM session_revocations WHERE user_id=$1 AND jti='idmfa3-fresh-lookup'",&[&a.user]).await?;assert!(revoked.is_err());
    println!("COMMIT-CUT: {kind}; fresh actor lookup, foreign/disabled/revoked refusal; no credential or success output");
    Ok(())
}

#[tokio::test]async fn commit_grant(){for kind in ["commit-before","commit-after"]{run_grant(kind,false).await.unwrap();}}

#[tokio::test]async fn commit_totp_grant(){for kind in ["commit-before","commit-after"]{run_totp_grant(kind,false).await.unwrap();}}

#[tokio::test]async fn commit_generate(){for kind in ["commit-before","commit-after"]{run_generate(kind,false).await.unwrap();}}

#[tokio::test]async fn commit_backup_verify(){for kind in ["commit-before","commit-after"]{run_backup_verify(kind,false).await.unwrap();}}

#[tokio::test]async fn commit_native_register(){for kind in ["commit-before","commit-after"]{run_native_register(kind,false).await.unwrap();}}

#[tokio::test]async fn commit_push_status(){for kind in ["commit-before","commit-after"]{run_push_status(kind,false).await.unwrap();}}

#[tokio::test]async fn commit_push_approve(){for kind in ["commit-before","commit-after"]{run_push_approve(kind,false).await.unwrap();}}

#[tokio::test]async fn commit_push_send(){for kind in ["commit-before","commit-after"]{run_push_send(kind,false).await.unwrap();}}

#[tokio::test]async fn commit_webauthn_possession_begin(){for kind in ["commit-before","commit-after"]{run_webauthn_possession(kind,false,false).await.unwrap();}}

#[tokio::test]async fn commit_webauthn_possession_finish(){for kind in ["commit-before","commit-after"]{run_webauthn_possession(kind,true,false).await.unwrap();}}

#[tokio::test]async fn recovery_edge_begin_unknown(){run_recovery("unknown",false,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_begin_disabled(){run_recovery("disabled",false,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_begin_no_factor(){run_recovery("no-factor",false,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_begin_push_only(){run_recovery("push-only",false,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_begin_budget_refused(){run_recovery("budget-refused",false,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_begin_budget_expired(){run_recovery("budget-expired",false,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_begin_fault_budget(){run_recovery("fault-budget",false,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_verify_totp_wrong(){run_recovery("totp-wrong",true,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_verify_totp_locked(){run_recovery("totp-locked",true,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_verify_totp_corrupt(){run_recovery("totp-corrupt",true,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_verify_budget_refused(){run_recovery("budget-refused",true,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_verify_budget_expired(){run_recovery("budget-expired",true,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_verify_push_replay(){run_recovery("push-replay",true,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_verify_push_foreign(){run_recovery("push-foreign",true,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_verify_push_purpose(){run_recovery("push-purpose",true,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_verify_push_expired(){run_recovery("push-expired",true,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_verify_push_burn(){run_recovery("push-burn",true,false).await.unwrap();}

#[tokio::test]async fn recovery_edge_verify_push_spent(){run_recovery("push-spent",true,false).await.unwrap();}

#[tokio::test]async fn possession_edge_begin_pending(){run_webauthn_possession("pending",false,false).await.unwrap();}

#[tokio::test]async fn possession_edge_begin_access_wins(){run_webauthn_possession("access-wins",false,false).await.unwrap();}

#[tokio::test]async fn possession_edge_begin_cookie(){run_webauthn_possession("cookie",false,false).await.unwrap();}

#[tokio::test]async fn possession_edge_begin_csrf(){run_webauthn_possession("csrf",false,false).await.unwrap();}

#[tokio::test]async fn possession_edge_begin_media(){run_webauthn_possession("media",false,false).await.unwrap();}

#[tokio::test]async fn possession_edge_begin_locked(){run_webauthn_possession("locked",false,false).await.unwrap();}

#[tokio::test]async fn possession_edge_begin_fault_ceremony(){run_webauthn_possession("fault-ceremony",false,false).await.unwrap();}

#[tokio::test]async fn possession_edge_finish_pending(){run_webauthn_possession("pending",true,false).await.unwrap();}

#[tokio::test]async fn possession_edge_finish_access_wins(){run_webauthn_possession("access-wins",true,false).await.unwrap();}

#[tokio::test]async fn possession_edge_finish_cookie(){run_webauthn_possession("cookie",true,false).await.unwrap();}

#[tokio::test]async fn possession_edge_finish_operation(){run_webauthn_possession("operation",true,false).await.unwrap();}

#[tokio::test]async fn possession_edge_finish_locked(){run_webauthn_possession("locked",true,false).await.unwrap();}

#[tokio::test]async fn possession_edge_finish_near_lock(){run_webauthn_possession("near-lock",true,false).await.unwrap();}

#[tokio::test]async fn possession_edge_finish_non_uv(){run_webauthn_possession("non-uv",true,false).await.unwrap();}

#[tokio::test]async fn possession_edge_finish_malformed_assertion(){run_webauthn_possession("malformed-assertion",true,false).await.unwrap();}

#[tokio::test]async fn possession_edge_finish_expired_ceremony(){run_webauthn_possession("expired-ceremony",true,false).await.unwrap();}

#[tokio::test]async fn possession_edge_finish_wrong_jti(){run_webauthn_possession("wrong-jti",true,false).await.unwrap();}

#[tokio::test]async fn possession_edge_finish_wrong_scope(){run_webauthn_possession("wrong-scope",true,false).await.unwrap();}

#[tokio::test]async fn possession_edge_finish_target_revoked(){run_webauthn_possession("target-revoked",true,false).await.unwrap();}

#[tokio::test]async fn possession_edge_finish_fault_grant(){run_webauthn_possession("fault-grant",true,false).await.unwrap();}

#[tokio::test]async fn commit_recovery_totp(){for kind in ["commit-before","commit-after"]{run_recovery(kind,true,false).await.unwrap();}}
#[tokio::test]async fn commit_recovery_push(){for kind in ["push-commit-before","push-commit-after"]{run_recovery(kind,true,false).await.unwrap();}}
