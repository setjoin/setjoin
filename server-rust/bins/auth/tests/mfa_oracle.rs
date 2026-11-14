//! Frozen-Go TOTP HTTP and committed-effect oracle.
mod common;
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

/// #353: new captures stamp the dispatching commit (R0 provenance); replays read it back.
fn recorded_source(golden: &std::path::Path, recording: bool) -> Result<String, Err> {
    if golden.exists() {
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(golden)?)?;
        return Ok(doc["go_source"].as_str().ok_or("golden without go_source")?.to_owned());
    }
    if !recording {
        return Err(format!("missing golden {}", golden.display()).into());
    }
    let source = std::env::var("GOFREE_GO_SOURCE")?;
    if source.len() != 40 || !source.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err("GOFREE_GO_SOURCE must be 40 lowercase hex".into());
    }
    Ok(source)
}

/// Fable 353-2: no case (and above all no Go recording) may run against a
/// replaced is_guest_account. Restore from the reducer source, or fail hard.
async fn guest_function_pristine(c: &tokio_postgres::Client) -> Result<(), Err> {
    async fn def(c: &tokio_postgres::Client) -> Result<String, tokio_postgres::Error> {
        c.query_one("SELECT pg_get_functiondef('is_guest_account(bigint)'::regprocedure)", &[])
            .await
            .map(|r| r.get::<_, String>(0))
    }
    let ok = |d: &str| d.contains("SECURITY DEFINER") && d.contains("public.guest_accounts") && !d.contains("gofree_");
    if ok(&def(c).await?) {
        return Ok(());
    }
    c.batch_execute(include_str!("../../../../mailserver/sql/reducers/guest_account.sql")).await?;
    c.batch_execute("DROP SEQUENCE IF EXISTS gofree_idmfa1_guest_calls; DROP SEQUENCE IF EXISTS gofree_guest353_calls").await?;
    if ok(&def(c).await?) {
        Ok(())
    } else {
        Err("is_guest_account is not pristine after restore; refusing to run".into())
    }
}
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
    inventory["routes"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["listener"] == "auth" || r["path"] == "/auth/totp/");
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
        .header("host", "auth.idmfa1.test")
        .header("user-agent", "IDMFA1 oracle");
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

const GO_SOURCE: &str = "db12f37ffe98dae62a06c60050dce0ae90a6b983";
const ENC: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const STAGED: &str = "JBSWY3DPEHPK3PXP";
const ENROLLMENT: &str = "00000000-0000-4000-8000-000000000334";
const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
fn corpus() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/identity-mfa/qualified")
}
async fn run_remove(kind: &str, mutant: bool) -> Result<(), Err> {
    run("remove", kind, mutant).await
}
async fn run(route: &str, kind: &str, mutant: bool) -> Result<(), Err> {
    run_security(route,kind,mutant,false).await
}
async fn run_security(route: &str, kind: &str, mutant: bool, bug: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA1-remove").expect("assigned DB required");
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    let counter_security=matches!(kind,"elapsed-code-replay"|"rolling-replay");
    let secure_sql=if counter_security{include_str!("../../../../mailserver/sql/reducers/rust_identity_totp_cycle.sql")}else{include_str!("../../../../mailserver/sql/reducers/rust_identity_mfa_mint.sql")};
    if bug {
        assert!(std::env::var("GOFREE_RECORD_UPSTREAM").is_err());
        let (begin,end)=if counter_security{("-- SECURITY-COUNTER-BEGIN","-- SECURITY-COUNTER-END")}else{("-- SECURITY-REVOCATION-BEGIN","-- SECURITY-REVOCATION-END")};
        let mut restored=secure_sql.to_owned();
        while let Some(start)=restored.find(begin){let finish=start+restored[start..].find(end).unwrap()+end.len();restored.replace_range(start..finish,"");}
        c.batch_execute(&restored).await?;
    }
    guest_function_pristine(&c).await?;
    common::signing_key(&c).await;
    let receipt_ids = common::receipt_ids(&c).await;
    let saved_rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    let a = fixture::account(&c, "idmfa1-actor").await?;
    let b = fixture::account(&c, "idmfa1-foreign").await?;
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    if route == "begin" || route.starts_with("login-") {
        for (uid, password) in [(a.user, "Password1!"), (b.user, "Foreign1!")] {
            c.execute(
                "UPDATE users SET password_hash=$2 WHERE id=$1",
                &[&uid, &bcrypt::hash(password, 4)?],
            )
            .await?;
        }
    }
    for uid in [a.user, b.user] {
        c.execute("UPDATE users SET totp_enabled=true,totp_secret_enc=pgp_sym_encrypt($2,$3),totp_enabled_at=now(),totp_backup_codes_enc=ARRAY['fixture-backup'],factor_generation=2 WHERE id=$1",&[&uid,&SECRET,&ENC]).await?;
    }
    if route == "login-bootstrap" || route.starts_with("bootstrap-") {
        c.execute("UPDATE users SET totp_enabled=false,totp_secret_enc=NULL,totp_enabled_at=NULL,mfa_exempt=false,push_mfa_enabled=false WHERE id=ANY($1::bigint[])",&[&vec![a.user,b.user]]).await?;
    }
    use sha2::{Digest, Sha256};
    let hash = format!("{:x}", Sha256::digest(b"idmfa1-removal-token"));
    c.execute("INSERT INTO totp_removal_step_ups(token_hash,user_id,session_jti,expires_at) VALUES($1,$2,'idmfa1-actor',now()+interval '5 minutes')",&[&hash,&a.user]).await?;
    if matches!(route, "setup" | "confirm") {
        let grant_hash = format!("{:x}", Sha256::digest(b"idmfa1-reauth"));
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at) VALUES($1,$2,'idmfa1-actor','totp.replace','totp',2,'session',now()+interval '5 minutes')",&[&grant_hash,&a.user]).await?;
    }
    if route == "confirm" {
        c.execute("INSERT INTO totp_pending_enrollments(id,user_id,secret_enc,staged_by_jti,staged_via,expires_at) VALUES($1::text::uuid,$2,pgp_sym_encrypt($3,$4),'idmfa1-actor','totp_setup',now()+interval '15 minutes')",&[&ENROLLMENT,&a.user,&STAGED,&ENC]).await?;
        c.execute(
            "UPDATE mfa_reauth_step_ups SET target_ref=$2 WHERE user_id=$1",
            &[&a.user, &ENROLLMENT],
        )
        .await?;
    }
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    cfg.db_encryption_key = ENC.into();
    if route.starts_with("login-") || matches!(route, "verify" | "bootstrap-confirm") {
        cfg.signing_alg = "ES256".into();
    }
    let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
        .map_err(|e| e.0)?;
    let signature_keys = setjoin_authz::signing_keys::KeySet::load(
        &exec,
        keys["secret"].as_str().unwrap().as_bytes(),
        setjoin_config_secret::CryptoProfile::Standard,
    )
    .await?;
    let auth = auth_server(Arc::new(AuthServer::load(exec, cfg).await?), mutant).await;
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none());
    let gw = gateway(auth.addr, record.clone()).await;
    let fault = fault_plan(route, kind, a.user);
    let guest_body = match kind {
        "guest-scope-unavailable" => Some("RAISE EXCEPTION 'gofree-idmfa1 guest scope fault';"),
        "guest-account-type-unavailable" => Some("IF nextval('gofree_idmfa1_guest_calls')>1 THEN RAISE EXCEPTION 'gofree-idmfa1 account type fault'; END IF; RETURN true;"),
        _ => None,
    };
    let guest_original: Option<String> = match guest_body {
        Some(branch) => {
            let original: String = c.query_one("SELECT pg_get_functiondef('is_guest_account(bigint)'::regprocedure)", &[]).await?.get(0);
            c.batch_execute("DROP SEQUENCE IF EXISTS gofree_idmfa1_guest_calls;CREATE SEQUENCE gofree_idmfa1_guest_calls;GRANT USAGE ON SEQUENCE gofree_idmfa1_guest_calls TO setjoin_app").await?;
            c.batch_execute(&format!("CREATE OR REPLACE FUNCTION is_guest_account(p_user_id bigint) RETURNS boolean LANGUAGE plpgsql AS $$BEGIN {branch} END$$")).await?;
            Some(original)
        }
        None => None,
    };
    let result=async {
  let actor_email:String=c.query_one("SELECT email FROM users WHERE id=$1",&[&a.user]).await?.get(0);
  let foreign_email:String=c.query_one("SELECT email FROM users WHERE id=$1",&[&b.user]).await?.get(0);
  if kind=="rolling-replay" {
    let second=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()%30;
    if second>=20 {tokio::time::sleep(std::time::Duration::from_secs(31-second)).await;}
  }
  let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
  let uid=if kind=="cross-tenant" {b.user} else {a.user};
  let mut claims=json!({"uid":uid,"email":"actor@idmfa1.test","typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600,"jti":"idmfa1-actor"});
  if route=="verify"||route.starts_with("bootstrap-"){claims["typ"]=json!("mfa_pending");claims["amr"]=json!(["pwd"]);}
  match kind {
    "wrong-type"=>claims["typ"]=json!(if route.starts_with("bootstrap-")||route=="verify"{"access"}else{"refresh"}),
    "expired-token"=>claims["exp"]=json!(now-1),
    "impersonated"=>claims["act"]=json!(b.user),
    _=>{}
  }
  if kind=="legacy-amr"{claims.as_object_mut().unwrap().remove("amr");}
  if kind=="stale-credential"{claims["credential_fence"]=json!("stale");}
  if kind=="malformed-amr"{claims["amr"]=json!(["pwd",42]);}
  if kind=="malformed-fence"{claims["identity_fence"]=json!(42);}
  if kind=="identity-stale"{claims["identity_fence"]=json!({"source_id":999999,"source_generation":1,"link_id":999999,"link_generation":1});}
  let mut actor_claims=claims.clone();actor_claims["uid"]=json!(a.user);actor_claims["jti"]=json!("idmfa1-actor");
  let actor_token=setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&actor_claims.to_string());
  if route.starts_with("bootstrap-") {
    let token_hash=format!("{:x}",Sha256::digest(actor_token.as_bytes()));
    c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at) VALUES($1,$2,'idmfa1-actor','bootstrap.totp.enroll','password',2,'mfa_pending',now()+interval '5 minutes')",&[&token_hash,&a.user]).await?;
  }
  if route=="bootstrap-confirm" {
    c.execute("INSERT INTO totp_pending_enrollments(id,user_id,secret_enc,staged_by_jti,staged_via,expires_at) VALUES($1::text::uuid,$2,pgp_sym_encrypt($3,$4),'idmfa1-actor','enroll_setup',now()+interval '15 minutes')",&[&ENROLLMENT,&a.user,&STAGED,&ENC]).await?;
    c.execute("UPDATE mfa_reauth_step_ups SET target_ref=$2 WHERE user_id=$1",&[&a.user,&ENROLLMENT]).await?;
  }
  let bearer=format!("Bearer {}",setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&claims.to_string()));
  let mut foreign_seed=None;
  if route=="verify"&&kind=="cross-tenant" {
    let code=setjoin_identity::totp::code(SECRET,now as i64).unwrap();let mut secret=STAGED.to_owned();
    while [0,30,60].iter().any(|offset|setjoin_identity::totp::validate(&code,&secret,now as i64+offset)){secret.push_str("ABCD2345");}
    c.execute("UPDATE users SET totp_secret_enc=pgp_sym_encrypt($2,$3) WHERE id=$1",&[&b.user,&secret,&ENC]).await?;foreign_seed=Some(secret);
  }
  seed_mode(&c,&a,route,kind,&claims).await?;
  let path=match route{"subtree"=>if kind=="invalid-input"{"/auth/totp/verify"}else{"/auth/totp/unknown"},"begin"=>"/auth/totp/remove/begin","setup"=>"/auth/totp/setup","confirm"=>"/auth/totp/confirm","bootstrap-setup"=>"/auth/totp/enroll/setup","verify"=>"/auth/totp/verify","bootstrap-confirm"=>"/auth/totp/enroll/confirm","login-totp"|"login-bootstrap"=>"/auth/login",_=>"/auth/totp/remove"};let method=if route=="subtree"{if kind=="invalid-input"{"DELETE"}else{"GET"}}else if route=="setup"{"GET"}else{"POST"};
  let mut payload=if kind=="invalid-input" {"{}".into()}else if route.starts_with("login-"){json!({"email":actor_email,"password":"Password1!","user_id":b.user}).to_string()}else if route=="bootstrap-confirm"{json!({"mfa_token":bearer.strip_prefix("Bearer ").unwrap(),"code":setjoin_identity::totp::code(STAGED,now as i64).unwrap(),"enrollment_id":ENROLLMENT,"user_id":b.user}).to_string()}else if route=="verify"{json!({"mfa_token":bearer.strip_prefix("Bearer ").unwrap(),"code":setjoin_identity::totp::code(SECRET,now as i64).unwrap(),"user_id":b.user}).to_string()}else if route=="bootstrap-setup"{json!({"mfa_token":bearer.strip_prefix("Bearer ").unwrap(),"user_id":b.user}).to_string()}else if route=="confirm"{json!({"code":setjoin_identity::totp::code(STAGED,now as i64).unwrap(),"enrollment_id":ENROLLMENT,"reauth_token":"idmfa1-reauth","user_id":b.user}).to_string()}else if route=="begin"{json!({"password":"Password1!","code":setjoin_identity::totp::code(SECRET,now as i64).unwrap(),"user_id":b.user}).to_string()}else{json!({"step_up_token":"idmfa1-removal-token","confirm":"REMOVE","user_id":b.user}).to_string()};
  payload=case_input(payload,route,kind,now as i64);
  let auth_header=if matches!(kind,"unauthenticated"|"cookie"|"csrf"){String::new()}else{bearer.clone()};
  let reauth=if kind=="missing-proof"||(route=="setup"&&matches!(kind,"invalid-input"|"malformed")){""}else{"idmfa1-reauth"};
  let cookie=if matches!(kind,"cookie"|"csrf"){format!("access_token={}",bearer.strip_prefix("Bearer ").unwrap())}else{String::new()};
  let origin=if kind=="csrf"{"https://foreign.idmfa1.test"}else{""};
  let headers_in=[("authorization",auth_header.as_str()),("x-mfa-reauth",reauth),("cookie",cookie.as_str()),("origin",origin)];
  if let Some(fault)=&fault{install_fault(&c,fault).await?;}
  let mut revocations=db.listen("session_revoke").await?;
  let mut actor_notifications=db.listen(&format!("tag:{}",a.mailbox)).await?;
  let mut foreign_notifications=db.listen(&format!("tag:{}",b.mailbox)).await?;
  let state_before=mailbox_states(&c,&a,&b).await?;
  let before=route_rows(&c,&a,&b,route).await?;
  let (status,mut headers,mut raw)=request(gw.addr,method,path,payload.clone(),&headers_in).await?;
  if kind.starts_with("fault-") {let expected=if kind=="fault-audit"&&matches!(route,"setup"|"begin"){200}else{500};assert_eq!(status,expected,"fault must hit its intended wire branch");}
  let first_plain=raw.clone();
  if route=="begin" && serde_json::from_str::<Value>(&raw).ok().is_some_and(|v|v.get("step_up_token").is_some()) {
   let v:Value=serde_json::from_str(&raw)?;let token=v["step_up_token"].as_str().ok_or("missing stepup")?;
   let token_hash=format!("{:x}",Sha256::digest(token.as_bytes()));
   let valid:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM totp_removal_step_ups WHERE user_id=$1 AND session_jti='idmfa1-actor' AND token_hash=$2 AND expires_at>now()+interval '290 seconds' AND expires_at<now()+interval '301 seconds')",&[&a.user,&token_hash]).await?.get(0);assert!(valid,"step-up hash/session/TTL must bind before masking");
   raw=raw.replace(token,"<step-up>");
  }
  if matches!(route,"setup"|"bootstrap-setup") && serde_json::from_str::<Value>(&raw).ok().is_some_and(|v|v.get("provisioning_uri").is_some()) {
   let v:Value=serde_json::from_str(&raw)?;let id=v["enrollment_id"].as_str().ok_or("no enrollment")?;
   let uri=v["provisioning_uri"].as_str().ok_or("no URI")?;let secret=uri.split("secret=").nth(1).unwrap().split('&').next().unwrap();
   assert_eq!(secret.len(),52);let stored:String=c.query_one("SELECT pgp_sym_decrypt(secret_enc::bytea,$2) FROM totp_pending_enrollments WHERE user_id=$1 AND id=$3::text::uuid AND staged_by_jti='idmfa1-actor' AND expires_at>now()+interval '890 seconds'",&[&a.user,&ENC,&id]).await?.get(0);assert_eq!(stored,secret);
   let bound:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM mfa_reauth_step_ups WHERE user_id=$1 AND target_ref=$2)",&[&a.user,&id]).await?.get(0);assert!(bound);
   raw=raw.replace(id,"<enrollment>").replace(secret,"<pending-secret>");
  }
  let issued_claims=if matches!(route,"verify"|"bootstrap-confirm")&&serde_json::from_str::<Value>(&raw).ok().is_some_and(|v|v.get("access_token").is_some()) {Some(issued(&c,&a,&signature_keys,&keys,&mut headers,&mut raw).await?)}else{None};
  let challenge=if route.starts_with("login-")&&serde_json::from_str::<Value>(&raw).ok().is_some_and(|v|v.get("mfa_token").is_some()){Some(challenge(&c,&a,&signature_keys,&keys,&mut raw,route=="login-bootstrap").await?)}else{None};
  let repeat=if matches!(kind,"repeat"|"elapsed-code-replay"|"guest-scope-unavailable"|"guest-account-type-unavailable") {
    if kind=="elapsed-code-replay"{c.execute("UPDATE users SET last_totp_used_at=now()-interval '31 seconds' WHERE id=$1",&[&a.user]).await?;}
    let pending_before=if matches!(route,"setup"|"bootstrap-setup"){Some(pending_exact(&c,a.user).await?)}else{None};
    let (status,mut headers,mut raw_repeat)=request(gw.addr,method,path,payload.clone(),&headers_in).await?;
    if kind=="elapsed-code-replay"&&record.is_none()&&!bug&&status!=401{return Err(format!("same accepted TOTP replayed after the elapsed guard: expected401, got{status}").into());}
    if kind=="elapsed-code-replay"&&record.is_none()&&!bug{let rows=c.query("SELECT last_counter,octet_length(secret_hash) FROM totp_counter_claims WHERE user_id=$1",&[&a.user]).await?;assert_eq!(rows.len(),1,"one counter claim for the accepted code");let (counter,hash):(i64,i32)=(rows[0].get(0),rows[0].get(1));assert_eq!(hash,32);let step=(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()/30) as i64;assert!((step-1..=step).contains(&counter),"claim records the verified time-step");let foreign:i64=c.query_one("SELECT count(*) FROM totp_counter_claims WHERE user_id=$1",&[&b.user]).await?.get(0);assert_eq!(foreign,0);}
    if kind=="elapsed-code-replay"&&status==200{let claims=issued(&c,&a,&signature_keys,&keys,&mut headers,&mut raw_repeat).await?;assert_eq!(Some(&claims),issued_claims.as_ref());}
    if matches!(route,"setup"|"bootstrap-setup") {assert_eq!(raw_repeat,first_plain,"resume must return the identical target/secret");assert_eq!(pending_before,Some(pending_exact(&c,a.user).await?),"resume must preserve envelope and expiry");raw_repeat=raw.clone();}
    Some(json!({"status":status,"headers":headers,"body":raw_repeat}))
  }else{None};
  let after=route_rows(&c,&a,&b,route).await?;
  let mut actual=json!({"format":1,"go_source":"db12f37ff","route":format!("{method} {path}"),"case":format!("{route}-{kind}"),"observation":{"response":{"status":status,"headers":headers,"body":raw},"effects":after}});
  if let Some(issued)=issued_claims {actual["observation"]["issued_claims"]=issued;}
  if let Some(challenge)=challenge{actual["observation"]["challenge_claims"]=challenge;}
  if let Some(repeat)=repeat{actual["observation"]["repeat_response"]=repeat;}
  let mut effects=json!({"format":1,"go_source":"db12f37ff","route":format!("{method} {path}"),"case":format!("{route}-{kind}-row-effects"),"effects":[{"table":"totp","before":before,"after":after}]});
  // Retain and strictly replay the immutable tracer records before adding
  // qualification metadata. New records are captured independently from Go.
  let legacy=corpus().parent().unwrap().join("goldens");
  let legacy_file=legacy.join(format!("{route}-{kind}.json"));
  if legacy_file.exists()&&!mutant {
    golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(&legacy_file)?)?,&actual)?;
    golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(legacy.join(format!("{route}-{kind}-rows.json")))?)?,&effects)?;
  }
  let source=if kind.starts_with("guest"){recorded_source(&corpus().join(format!("{route}-{kind}.json")),record.is_some())?}else if kind=="elapsed-code-replay"{"e6af2a7f075f5d6b86d33fdb3dbedd794e3158ec".to_owned()}else{GO_SOURCE.to_owned()};
  actual["go_source"]=json!(source);effects["go_source"]=json!(source);
  if route=="subtree"{actual["route"]=json!("* /auth/totp/");effects["route"]=json!("* /auth/totp/");}
  actual["observation"]["request"]=json!({"method":method,"path":path,"body":normalize_input(&payload,&bearer,&a,&b).replace(&actor_email,"actor@idmfa1.test").replace(&foreign_email,"foreign@idmfa1.test")});
  if route=="subtree"{actual["observation"]["request"]["actual_method"]=json!(method);actual["observation"]["request"]["actual_path"]=json!(path);actual["observation"]["request"]["method"]=json!("*");actual["observation"]["request"]["path"]=json!("/auth/totp/");}
  let mut audit=after["audit"].as_array().unwrap().iter().map(|r|json!({"table":"admin_audit_log","row":r})).collect::<Vec<_>>();
  if let Some(events)=after.get("token_stores").and_then(|s|s.get("auth_event_log")).and_then(Value::as_array){audit.extend(events.iter().map(|r|json!({"table":"auth_event_log","row":r})));}
  actual["observation"]["audit"]=json!(audit);
  let mut notify=Vec::new();
  for payload in revocations.drain(&c).await? {notify.push(json!({"channel":"session_revoke","payload":payload}));}
  for payload in actor_notifications.drain(&c).await? {notify.push(json!({"channel":"tag:<actor>","payload":payload}));}
  for payload in foreign_notifications.drain(&c).await? {notify.push(json!({"channel":"tag:<foreign>","payload":payload}));}
  actual["observation"]["notify"]=json!(notify);
  actual["observation"]["mailbox_state"]=json!({"before":state_before,"after":mailbox_states(&c,&a,&b).await?});
  actual["observation"]["factor_store"]=factor_store(&c,&a,&b,foreign_seed.as_deref(),kind).await?;
  std::fs::create_dir_all(corpus())?;
  let file=corpus().join(format!("{route}-{kind}.json"));let rowfile=corpus().join(format!("{route}-{kind}-rows.json"));
  if record.is_some()&&!file.exists(){golden::record(&file,&actual)?;golden::record(&rowfile,&effects)?;}
  let protected=route=="verify"&&matches!(kind,"revoked-challenge"|"elapsed-code-replay"|"rolling-replay")&&record.is_none();
  let mut expected:Value=if protected&&!bug {common::security_expectation(&file)} else {serde_json::from_str(&std::fs::read_to_string(&file)?)?};
  // The original trailing-input capture retained a clock-derived code. Apply
  // the same code placeholder to both request observations at replay time;
  // response, signature, accepted-window and effect comparisons stay exact.
  if let Some(input)=expected["observation"]["request"]["body"].as_str(){
    expected["observation"]["request"]["body"]=json!(normalize_input(input,"",&a,&b));
  }
  if bug {let err=golden::compare(&common::security_expectation(&file),&actual).unwrap_err();let status=if kind=="elapsed-code-replay"{"/observation/repeat_response/status"}else{"/observation/response/status"};assert!(err.contains(status),"{err}");}
  if mutant {let err=golden::compare(&expected,&actual).err().ok_or("mutant survived")?;assert!(err.contains("/observation/response/status"));}
  else {golden::compare(&expected,&actual)?;let expected_rows=if protected&&!bug {common::security_expectation(&rowfile)}else{serde_json::from_str::<Value>(&std::fs::read_to_string(rowfile)?)?};golden::compare(&expected_rows,&effects)?;}
  println!("{}: {} :: {}",if mutant{"MUTANT-REJECTED"}else{"GOLDEN-REPLAY"},actual["route"].as_str().unwrap(),if mutant{"status".to_owned()}else{format!("{route}-{kind}")});
  if record.is_none() {let(_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));}
  Ok::<(),Err>(())
 }.await;
    if bug {c.batch_execute(secure_sql).await?;}
    gw.close().await;
    auth.close().await;
    if let Some(fault) = &fault {
        remove_fault(&c, fault).await?;
    }
    if let Some(original) = &guest_original {
        c.batch_execute(original).await?;
        c.batch_execute("DROP SEQUENCE IF EXISTS gofree_idmfa1_guest_calls").await?;
    }
    guest_function_pristine(&c).await?;
    for uid in [a.user, b.user] {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT")).await?;
        c.execute(
            "DELETE FROM totp_removal_step_ups WHERE user_id=$1",
            &[&uid],
        )
        .await?;
        c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&uid])
            .await?;
        c.execute(
            "DELETE FROM totp_pending_enrollments WHERE user_id=$1",
            &[&uid],
        )
        .await?;
    }
    for uid in [a.user, b.user] {
        c.execute("DELETE FROM guest_accounts WHERE user_id=$1", &[&uid]).await?;
        c.execute("DELETE FROM auth_event_log WHERE user_id=$1", &[&uid])
            .await?;
        c.execute("DELETE FROM login_events WHERE user_id=$1", &[&uid])
            .await?;
        c.execute("DELETE FROM sessions WHERE user_id=$1", &[&uid])
            .await?;
        c.execute("DELETE FROM oauth_tokens WHERE user_id=$1", &[&uid])
            .await?;
    }
    c.execute(
        "DELETE FROM session_revocations WHERE user_id=ANY($1::bigint[])",
        &[&vec![a.user, b.user]],
    )
    .await?;
    common::restore_receipts(&c, &receipt_ids).await;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if let Some(enabled) = saved_rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&enabled],
        )
        .await?;
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?;
    }
    c.query_one(
        "SELECT pg_advisory_unlock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    result
}
async fn rows(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, Err> {
    let mut users = Vec::new();
    let mut audit = Vec::new();
    let mut grants = Vec::new();
    for (uid, label) in [(a.user, "actor"), (b.user, "foreign")] {
        let r=c.query_one("SELECT totp_enabled,totp_secret_enc IS NOT NULL,totp_backup_codes_enc,totp_failed_attempts,totp_locked_until IS NOT NULL,last_totp_used_at IS NOT NULL,factor_generation FROM users WHERE id=$1",&[&uid]).await?;
        users.push(json!({"owner":label,"enabled":r.get::<_,bool>(0),"secret":r.get::<_,bool>(1),"backups":r.get::<_,Option<Vec<String>>>(2),"failures":r.get::<_,i32>(3),"locked":r.get::<_,bool>(4),"used":r.get::<_,bool>(5),"generation":r.get::<_,i64>(6)}));
        for r in c.query("SELECT action,notes,ip::text,target_type,target_id FROM admin_audit_log WHERE user_id=$1 ORDER BY id",&[&uid]).await? {let target:Option<i64>=r.get(4);assert!(target.is_none()||target==Some(uid));audit.push(json!({"owner":label,"action":r.get::<_,String>(0),"notes":r.get::<_,Option<String>>(1),"ip":r.get::<_,Option<String>>(2),"target_type":r.get::<_,Option<String>>(3)}));}
        let n: i64 = c
            .query_one(
                "SELECT count(*) FROM totp_removal_step_ups WHERE user_id=$1",
                &[&uid],
            )
            .await?
            .get(0);
        grants.push(json!({"owner":label,"stepups":n}));
    }
    Ok(json!({"users":users,"audit":audit,"grants":grants}))
}
#[tokio::test]
async fn remove_success() {
    run_remove("success", false).await.unwrap();
}

#[tokio::test]
async fn begin_success() {
    run("begin", "success", false).await.unwrap();
}

async fn route_rows(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
    route: &str,
) -> Result<Value, Err> {
    let mut out = rows(c, a, b).await?;
    if matches!(
        route,
        "setup" | "confirm" | "bootstrap-setup" | "bootstrap-confirm" | "login-bootstrap"
    ) {
        for table in ["mfa_reauth_step_ups", "totp_pending_enrollments"] {
            let sql=format!("SELECT to_jsonb(t)::text FROM {table} t WHERE user_id=ANY($1::bigint[]) ORDER BY user_id");
            let mut entries = Vec::new();
            for r in c.query(&sql, &[&vec![a.user, b.user]]).await? {
                let mut v: Value = serde_json::from_str(&r.get::<_, String>(0))?;
                v["user_id"] = json!(if v["user_id"] == a.user {
                    "actor"
                } else {
                    "foreign"
                });
                for field in ["created_at", "expires_at"] {
                    if let Some(t) = v.get_mut(field).filter(|v| !v.is_null()) {
                        *t = json!("<time>");
                    }
                }
                if (route == "login-bootstrap" || route.starts_with("bootstrap-"))
                    && table == "mfa_reauth_step_ups"
                {
                    v["token_hash"] = json!("<MFA token SHA256>");
                }
                if route == "login-bootstrap" && table == "mfa_reauth_step_ups" {
                    v["session_jti"] = json!("<pending-jti>");
                }
                if table == "totp_pending_enrollments" {
                    v["id"] = json!("<enrollment>");
                    v["secret_enc"] = json!("<encrypted pending secret>");
                }
                if v.get("target_ref").is_some_and(|v| !v.is_null()) {
                    v["target_ref"] = json!("<enrollment>");
                }
                entries.push(v);
            }
            out[table] = json!(entries);
        }
    }
    if matches!(route, "confirm" | "bootstrap-confirm") {
        let mut active = Vec::new();
        for (uid, label) in [(a.user, "actor"), (b.user, "foreign")] {
            let secret: Option<String> = c
                .query_one(
                    "SELECT pgp_sym_decrypt(totp_secret_enc::bytea,$2) FROM users WHERE id=$1",
                    &[&uid, &ENC],
                )
                .await?
                .get(0);
            active.push(json!({"owner":label,"secret":secret}));
        }
        out["active_secrets"] = json!(active);
    }
    if route.starts_with("login-") || matches!(route, "verify" | "bootstrap-confirm") {
        out["token_stores"] = token_stores(c, a, b).await?;
    }
    Ok(out)
}
#[tokio::test]
async fn setup_success() {
    run("setup", "success", false).await.unwrap();
}

#[tokio::test]
async fn confirm_success() {
    run("confirm", "success", false).await.unwrap();
}

#[tokio::test]
async fn bootstrap_setup_success() {
    run("bootstrap-setup", "success", false).await.unwrap();
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
        normalized["email"] = json!("actor@idmfa1.test");
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
        for (idx, row) in c
            .query(&sql, &[&vec![a.user, b.user]])
            .await?
            .iter()
            .enumerate()
        {
            let mut v: Value = serde_json::from_str(&row.get::<_, String>(0))?;
            v["user_id"] = json!(if v["user_id"] == a.user {
                "actor"
            } else {
                "foreign"
            });
            if let Some(e) = v.get_mut("email").filter(|v| v.is_string()) {
                let text = e.as_str().unwrap();
                *e = json!(text
                    .replace(&email, "actor@idmfa1.test")
                    .replace(&foreign, "foreign@idmfa1.test"));
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
#[tokio::test]
async fn verify_success() {
    run("verify", "success", false).await.unwrap();
}

#[tokio::test]
async fn bootstrap_confirm_success() {
    run("bootstrap-confirm", "success", false).await.unwrap();
}

fn normalize_input(
    payload: &str,
    bearer: &str,
    a: &fixture::Account,
    b: &fixture::Account,
) -> String {
    if payload.len() > 1 << 20 {
        use sha2::{Digest, Sha256};
        return format!(
            "<oversized body: {} bytes SHA256{:x}>",
            payload.len(),
            Sha256::digest(payload.as_bytes())
        );
    }

    let mut s = payload
        .replace(
            bearer.strip_prefix("Bearer ").unwrap_or("not-a-token"),
            "<mfa_token>",
        )
        .replace(ENROLLMENT, "<enrollment>");
    if let Some(Ok(v)) = serde_json::Deserializer::from_str(payload)
        .into_iter::<Value>()
        .next()
    {
        if let Some(code) = v
            .as_object()
            .and_then(|m| {
                m.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("code"))
                    .map(|(_, v)| v)
            })
            .and_then(Value::as_str)
            .filter(|s| s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit()))
        {
            s = s.replace(code, "<TOTP code>");
        }
    }
    for (id, label) in [(a.user, "<actor>"), (b.user, "<foreign>")] {
        for end in [",", "}"] {
            s = s.replace(
                &format!("\"user_id\":{id}{end}"),
                &format!("\"user_id\":\"{label}\"{end}"),
            );
        }
    }
    s
}
async fn mailbox_states(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, Err> {
    let mut out = json!({});
    for (account, label) in [(a, "actor"), (b, "foreign")] {
        let raw: String = c
            .query_one(
                "SELECT to_jsonb(m)::text FROM mailboxes m WHERE id=$1 AND user_id=$2",
                &[&account.mailbox, &account.user],
            )
            .await?
            .get(0);
        let mut v: Value = serde_json::from_str(&raw)?;
        v.as_object_mut()
            .unwrap()
            .retain(|k, _| k.starts_with("jmap_"));
        out[label] = v;
    }
    Ok(out)
}
async fn factor_store(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
    foreign_seed: Option<&str>,
    kind: &str,
) -> Result<Value, Err> {
    let mut out = json!({});
    for (account, label) in [(a, "actor"), (b, "foreign")] {
        let row=c.query_one("SELECT pgp_sym_decrypt(totp_secret_enc::bytea,$2),totp_enabled_at IS NOT NULL FROM users WHERE id=$1",&[&account.user,&ENC]).await;
        match row {
            Ok(row) => {
                let mut secret: Option<String> = row.get(0);
                if label == "foreign" && foreign_seed.is_some_and(|s| secret.as_deref() == Some(s))
                {
                    secret = Some("<distinct foreign secret>".into());
                }
                out[label] = json!({"active_secret":secret,"enabled_at":row.get::<_,bool>(1)});
            }
            Err(e)
                if label == "actor"
                    && kind == "corrupt-secret"
                    && e.as_db_error().is_some_and(|e| e.code().code() == "39000") =>
            {
                out[label] = json!({"active_secret":"<corrupt ciphertext>","enabled_at":true})
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(out)
}

async fn challenge(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    keys: &setjoin_authz::signing_keys::KeySet,
    fixture: &Value,
    raw: &mut String,
    bootstrap: bool,
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
    if bootstrap {
        let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        let sid = proof.text("jti");
        let good:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM mfa_reauth_step_ups WHERE user_id=$1 AND token_hash=$2 AND session_jti=$3 AND token_scope='mfa_pending' AND operation='bootstrap.totp.enroll' AND proof_method='password' AND target_ref IS NULL AND refresh_family_id IS NULL AND expires_at>now()+interval '290 seconds')",&[&a.user,&hash,&sid]).await?.get(0);
        assert!(good);
    }
    for k in ["iat", "nbf"] {
        claims[k] = json!(0);
    }
    claims["exp"] = json!(300);
    claims["uid"] = json!("<actor>");
    claims["sub"] = json!("<actor>");
    claims["email"] = json!("actor@idmfa1.test");
    claims["jti"] = json!("<pending-jti>");
    claims["credential_fence"] = json!("<credential-version>");
    *raw = raw.replace(token, "<mfa_token>");
    Ok(claims)
}
#[tokio::test]
async fn login_totp_success() {
    run("login-totp", "success", false).await.unwrap();
}
#[tokio::test]
async fn login_bootstrap_success() {
    run("login-bootstrap", "success", false).await.unwrap();
}

async fn pending_exact(
    c: &tokio_postgres::Client,
    user: i64,
) -> Result<Option<(String, Vec<u8>)>, Err> {
    Ok(c.query_opt("SELECT (to_jsonb(t)-'secret_enc')::text,secret_enc FROM totp_pending_enrollments t WHERE user_id=$1",&[&user]).await?.map(|r|(r.get(0),r.get(1))))
}
async fn seed_mode(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    route: &str,
    kind: &str,
    claims: &Value,
) -> Result<(), Err> {
    let uid = a.user;
    match kind {
        "disabled" => {
            c.execute("UPDATE users SET enabled=false WHERE id=$1", &[&uid])
                .await?;
        }
        "not-enabled" => {
            c.execute("UPDATE users SET totp_enabled=false WHERE id=$1", &[&uid])
                .await?;
        }
        "locked" => {
            c.execute("UPDATE users SET totp_failed_attempts=5,totp_locked_until=now()+interval '15 minutes' WHERE id=$1",&[&uid]).await?;
        }
        "fault-reset" => {
            c.execute(
                "UPDATE users SET totp_failed_attempts=2 WHERE id=$1",
                &[&uid],
            )
            .await?;
        }
        "near-lock" => {
            c.execute(
                "UPDATE users SET totp_failed_attempts=4 WHERE id=$1",
                &[&uid],
            )
            .await?;
        }
        "replayed" => {
            c.execute(
                "UPDATE users SET last_totp_used_at=now() WHERE id=$1",
                &[&uid],
            )
            .await?;
        }
        "rolling-replay" => {
            c.execute(
                "UPDATE users SET last_totp_used_at=now()-interval '31 seconds' WHERE id=$1",
                &[&uid],
            )
            .await?;
        }
        "corrupt-secret" => {
            c.execute(
                "UPDATE users SET totp_secret_enc=decode('deadbeef','hex') WHERE id=$1",
                &[&uid],
            )
            .await?;
        }
        "secret-whitespace" => {
            c.execute(
                "UPDATE users SET totp_secret_enc=pgp_sym_encrypt($2,$3) WHERE id=$1",
                &[&uid, &format!("  {}  ", SECRET.to_lowercase()), &ENC],
            )
            .await?;
        }
        "no-grant" => {
            c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&uid])
                .await?;
        }
        "proof-session" => {
            c.execute(
                "UPDATE mfa_reauth_step_ups SET session_jti='another-session' WHERE user_id=$1",
                &[&uid],
            )
            .await?;
        }
        "proof-expired" => {
            c.execute("UPDATE mfa_reauth_step_ups SET expires_at=now()-interval '1 minute' WHERE user_id=$1",&[&uid]).await?;
        }
        "proof-generation" => {
            c.execute(
                "UPDATE mfa_reauth_step_ups SET bound_factor_generation=3 WHERE user_id=$1",
                &[&uid],
            )
            .await?;
        }
        "proof-operation" => {
            c.execute(
                "UPDATE mfa_reauth_step_ups SET operation='recovery.regenerate' WHERE user_id=$1",
                &[&uid],
            )
            .await?;
        }
        "proof-family" => {
            c.execute("UPDATE mfa_reauth_step_ups SET refresh_family_id='another-family' WHERE user_id=$1",&[&uid]).await?;
        }
        "bound-dead" => {
            c.execute(
                "UPDATE mfa_reauth_step_ups SET target_ref=$2 WHERE user_id=$1",
                &[&uid, &ENROLLMENT],
            )
            .await?;
        }
        "pending-expired" => {
            c.execute("UPDATE totp_pending_enrollments SET expires_at=now()-interval '1 minute' WHERE user_id=$1",&[&uid]).await?;
        }
        "pending-session" => {
            c.execute("UPDATE totp_pending_enrollments SET staged_by_jti='another-session' WHERE user_id=$1",&[&uid]).await?;
        }
        "pending-missing" => {
            c.execute(
                "DELETE FROM totp_pending_enrollments WHERE user_id=$1",
                &[&uid],
            )
            .await?;
        }
        "pending-corrupt" => {
            c.execute("UPDATE totp_pending_enrollments SET secret_enc=decode('deadbeef','hex') WHERE user_id=$1",&[&uid]).await?;
        }
        "revoked-challenge" => {
            let sid = claims["jti"].as_str().unwrap();
            c.execute("INSERT INTO session_revocations(user_id,scope,jti,reason,not_before,expires_at) VALUES($1,'jti',$2,'fixture',now(),now()+interval '1 hour')",&[&uid,&sid]).await?;
        }
        "guest" | "guest-scope-unavailable" | "guest-account-type-unavailable" => {
            c.execute("INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) SELECT id,email,'inviter@idmfa1.test',$2,'active' FROM users WHERE id=$1",&[&uid,&a.domain]).await?;
        }
        "optional-policy" => {
            c.execute("UPDATE users SET mfa_exempt=true WHERE id=$1", &[&uid])
                .await?;
        }
        _ => {}
    }
    let _ = route;
    Ok(())
}
fn case_input(normal: String, route: &str, kind: &str, now: i64) -> String {
    if kind == "malformed" {
        return "{bad-json".into();
    }
    if kind == "null" {
        return "null".into();
    }
    if kind == "oversized" {
        return json!({"ignored":"a".repeat((1<<20)+100)}).to_string();
    }
    if kind == "trailing" {
        return normal + " trailing invalid bytes";
    }
    if kind == "folded" {
        return normal
            .replace("\"mfa_token\"", "\"MFA_TOKEN\"")
            .replace("\"code\"", "\"CoDe\"")
            .replace("\"enrollment_id\"", "\"ENROLLMENT_ID\"");
    }
    let mut v: Value = serde_json::from_str(&normal).unwrap_or(json!({}));
    match kind {
        "bad-code" | "near-lock" | "fault-counter" => v["code"] = json!("invalid"),
        "rolling-replay" => {
            v["code"] = json!(setjoin_identity::totp::code(SECRET, now - 30).unwrap())
        }
        "missing-proof" => {
            v.as_object_mut().unwrap().remove("reauth_token");
        }
        "json-type" => {
            if route.starts_with("bootstrap-") {
                v["mfa_token"] = json!(42);
            } else {
                v["code"] = json!(42);
            }
        }
        _ => {}
    }
    v.to_string()
}

#[tokio::test]
async fn remove_cross_tenant() {
    run("remove", "cross-tenant", false).await.unwrap();
}

#[tokio::test]
async fn remove_invalid_input() {
    run("remove", "invalid-input", false).await.unwrap();
}

#[tokio::test]
async fn remove_repeat() {
    run("remove", "repeat", false).await.unwrap();
}

#[tokio::test]
async fn remove_status_mutant() {
    run("remove", "success", true).await.unwrap();
}

#[tokio::test]
async fn begin_cross_tenant() {
    run("begin", "cross-tenant", false).await.unwrap();
}

#[tokio::test]
async fn begin_invalid_input() {
    run("begin", "invalid-input", false).await.unwrap();
}

#[tokio::test]
async fn begin_repeat() {
    run("begin", "repeat", false).await.unwrap();
}

#[tokio::test]
async fn begin_status_mutant() {
    run("begin", "success", true).await.unwrap();
}

#[tokio::test]
async fn setup_cross_tenant() {
    run("setup", "cross-tenant", false).await.unwrap();
}

#[tokio::test]
async fn setup_invalid_input() {
    run("setup", "invalid-input", false).await.unwrap();
}

#[tokio::test]
async fn setup_repeat() {
    run("setup", "repeat", false).await.unwrap();
}

#[tokio::test]
async fn setup_status_mutant() {
    run("setup", "success", true).await.unwrap();
}

#[tokio::test]
async fn confirm_cross_tenant() {
    run("confirm", "cross-tenant", false).await.unwrap();
}

#[tokio::test]
async fn confirm_invalid_input() {
    run("confirm", "invalid-input", false).await.unwrap();
}

#[tokio::test]
async fn confirm_repeat() {
    run("confirm", "repeat", false).await.unwrap();
}

#[tokio::test]
async fn confirm_status_mutant() {
    run("confirm", "success", true).await.unwrap();
}

#[tokio::test]
async fn verify_cross_tenant() {
    run("verify", "cross-tenant", false).await.unwrap();
}

#[tokio::test]
async fn verify_invalid_input() {
    run("verify", "invalid-input", false).await.unwrap();
}

#[tokio::test]
async fn verify_repeat() {
    run("verify", "repeat", false).await.unwrap();
}

#[tokio::test]
async fn verify_status_mutant() {
    run("verify", "success", true).await.unwrap();
}

#[tokio::test]
async fn bootstrap_setup_cross_tenant() {
    run("bootstrap-setup", "cross-tenant", false).await.unwrap();
}

#[tokio::test]
async fn bootstrap_setup_invalid_input() {
    run("bootstrap-setup", "invalid-input", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn bootstrap_setup_repeat() {
    run("bootstrap-setup", "repeat", false).await.unwrap();
}

#[tokio::test]
async fn bootstrap_setup_status_mutant() {
    run("bootstrap-setup", "success", true).await.unwrap();
}

#[tokio::test]
async fn bootstrap_confirm_cross_tenant() {
    run("bootstrap-confirm", "cross-tenant", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn bootstrap_confirm_invalid_input() {
    run("bootstrap-confirm", "invalid-input", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn bootstrap_confirm_repeat() {
    run("bootstrap-confirm", "repeat", false).await.unwrap();
}

#[tokio::test]
async fn bootstrap_confirm_status_mutant() {
    run("bootstrap-confirm", "success", true).await.unwrap();
}

struct Fault {
    table: &'static str,
    event: &'static str,
    predicate: String,
}
fn fault_plan(route: &str, kind: &str, user: i64) -> Option<Fault> {
    let (table, event, predicate) = match kind {
        "fault-staging" => (
            "totp_pending_enrollments",
            "INSERT OR UPDATE",
            format!("NEW.user_id={user}"),
        ),
        "fault-binding" => (
            "mfa_reauth_step_ups",
            "UPDATE",
            format!("NEW.user_id={user} AND NEW.target_ref IS NOT NULL"),
        ),
        "fault-audit" => ("admin_audit_log", "INSERT", format!("NEW.user_id={user}")),
        "fault-counter" => (
            "users",
            "UPDATE",
            format!("NEW.id={user} AND NEW.totp_failed_attempts>OLD.totp_failed_attempts"),
        ),
        "fault-reset" => (
            "users",
            "UPDATE",
            format!("NEW.id={user} AND OLD.totp_failed_attempts=2 AND NEW.totp_failed_attempts=0"),
        ),
        "fault-anchor" => ("oauth_tokens", "INSERT", format!("NEW.user_id={user}")),
        "fault-stepup-store" => (
            "totp_removal_step_ups",
            "INSERT",
            format!("NEW.user_id={user}"),
        ),
        "fault-stepup-clear" => (
            "totp_removal_step_ups",
            "DELETE",
            format!("OLD.user_id={user}"),
        ),
        _ => return None,
    };
    let _ = route;
    Some(Fault {
        table,
        event,
        predicate,
    })
}
async fn install_fault(c: &tokio_postgres::Client, fault: &Fault) -> Result<(), Err> {
    c.batch_execute(&format!("CREATE FUNCTION gofree_idmfa1_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF {} THEN RAISE EXCEPTION 'gofree-idmfa1 injected statement failure'; END IF; IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF; END$$;CREATE TRIGGER gofree_idmfa1_fault BEFORE {} ON {} FOR EACH ROW EXECUTE FUNCTION gofree_idmfa1_fault()",fault.predicate,fault.event,fault.table)).await?;
    Ok(())
}
async fn remove_fault(c: &tokio_postgres::Client, fault: &Fault) -> Result<(), Err> {
    c.batch_execute(&format!("DROP TRIGGER IF EXISTS gofree_idmfa1_fault ON {};DROP FUNCTION IF EXISTS gofree_idmfa1_fault()",fault.table)).await?;
    Ok(())
}

#[tokio::test]
async fn edge_verify_wrong_type() {
    run("verify", "wrong-type", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_expired_token() {
    run("verify", "expired-token", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_bad_code() {
    run("verify", "bad-code", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_near_lock() {
    run("verify", "near-lock", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_locked() {
    run("verify", "locked", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_replayed() {
    run("verify", "replayed", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_rolling_replay() {
    run("verify", "rolling-replay", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_corrupt_secret() {
    run("verify", "corrupt-secret", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_secret_whitespace() {
    run("verify", "secret-whitespace", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_revoked_challenge() {
    run("verify", "revoked-challenge", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_not_enabled() {
    run("verify", "not-enabled", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_disabled() {
    run("verify", "disabled", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_json_type() {
    run("verify", "json-type", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_malformed() {
    run("verify", "malformed", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_oversized() {
    run("verify", "oversized", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_trailing() {
    run("verify", "trailing", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_folded() {
    run("verify", "folded", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_fault_counter() {
    run("verify", "fault-counter", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_fault_reset() {
    run("verify", "fault-reset", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_fault_anchor() {
    run("verify", "fault-anchor", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_legacy_amr() {
    run("verify", "legacy-amr", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_stale_credential() {
    run("verify", "stale-credential", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_malformed_amr() {
    run("verify", "malformed-amr", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_malformed_fence() {
    run("verify", "malformed-fence", false).await.unwrap();
}

#[tokio::test]
async fn edge_verify_identity_stale() {
    run("verify", "identity-stale", false).await.unwrap();
}

#[tokio::test]
async fn edge_setup_no_grant() {
    run("setup", "no-grant", false).await.unwrap();
}

#[tokio::test]
async fn edge_setup_proof_session() {
    run("setup", "proof-session", false).await.unwrap();
}

#[tokio::test]
async fn edge_setup_proof_expired() {
    run("setup", "proof-expired", false).await.unwrap();
}

#[tokio::test]
async fn edge_setup_proof_generation() {
    run("setup", "proof-generation", false).await.unwrap();
}

#[tokio::test]
async fn edge_setup_proof_operation() {
    run("setup", "proof-operation", false).await.unwrap();
}

#[tokio::test]
async fn edge_setup_proof_family() {
    run("setup", "proof-family", false).await.unwrap();
}

#[tokio::test]
async fn edge_setup_bound_dead() {
    run("setup", "bound-dead", false).await.unwrap();
}

#[tokio::test]
async fn edge_setup_revoked_challenge() {
    run("setup", "revoked-challenge", false).await.unwrap();
}

#[tokio::test]
async fn edge_setup_impersonated() {
    run("setup", "impersonated", false).await.unwrap();
}

#[tokio::test]
async fn edge_setup_unauthenticated() {
    run("setup", "unauthenticated", false).await.unwrap();
}

#[tokio::test]
async fn edge_setup_fault_staging() {
    run("setup", "fault-staging", false).await.unwrap();
}

#[tokio::test]
async fn edge_setup_fault_binding() {
    run("setup", "fault-binding", false).await.unwrap();
}

#[tokio::test]
async fn edge_setup_fault_audit() {
    run("setup", "fault-audit", false).await.unwrap();
}

#[tokio::test]
async fn edge_confirm_bad_code() {
    run("confirm", "bad-code", false).await.unwrap();
}

#[tokio::test]
async fn edge_confirm_no_grant() {
    run("confirm", "no-grant", false).await.unwrap();
}

#[tokio::test]
async fn edge_confirm_proof_session() {
    run("confirm", "proof-session", false).await.unwrap();
}

#[tokio::test]
async fn edge_confirm_proof_expired() {
    run("confirm", "proof-expired", false).await.unwrap();
}

#[tokio::test]
async fn edge_confirm_proof_generation() {
    run("confirm", "proof-generation", false).await.unwrap();
}

#[tokio::test]
async fn edge_confirm_proof_operation() {
    run("confirm", "proof-operation", false).await.unwrap();
}

#[tokio::test]
async fn edge_confirm_proof_family() {
    run("confirm", "proof-family", false).await.unwrap();
}

#[tokio::test]
async fn edge_confirm_pending_expired() {
    run("confirm", "pending-expired", false).await.unwrap();
}

#[tokio::test]
async fn edge_confirm_pending_session() {
    run("confirm", "pending-session", false).await.unwrap();
}

#[tokio::test]
async fn edge_confirm_pending_missing() {
    run("confirm", "pending-missing", false).await.unwrap();
}

#[tokio::test]
async fn edge_confirm_pending_corrupt() {
    run("confirm", "pending-corrupt", false).await.unwrap();
}

#[tokio::test]
async fn edge_confirm_revoked_challenge() {
    run("confirm", "revoked-challenge", false).await.unwrap();
}

#[tokio::test]
async fn edge_confirm_impersonated() {
    run("confirm", "impersonated", false).await.unwrap();
}

#[tokio::test]
async fn edge_confirm_fault_audit() {
    run("confirm", "fault-audit", false).await.unwrap();
}

#[tokio::test]
async fn subtree_success() {
    run("subtree", "success", false).await.unwrap();
}
#[tokio::test]
async fn subtree_cross_tenant() {
    run("subtree", "cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn subtree_invalid_input() {
    run("subtree", "invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn subtree_status_mutant() {
    run("subtree", "success", true).await.unwrap();
}

#[tokio::test]
async fn edge_bootstrap_setup_wrong_type() {
    run("bootstrap-setup", "wrong-type", false).await.unwrap();
}

#[tokio::test]
async fn edge_bootstrap_setup_expired_token() {
    run("bootstrap-setup", "expired-token", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_setup_no_grant() {
    run("bootstrap-setup", "no-grant", false).await.unwrap();
}

#[tokio::test]
async fn edge_bootstrap_setup_proof_generation() {
    run("bootstrap-setup", "proof-generation", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_setup_bound_dead() {
    run("bootstrap-setup", "bound-dead", false).await.unwrap();
}

#[tokio::test]
async fn edge_bootstrap_setup_revoked_challenge() {
    run("bootstrap-setup", "revoked-challenge", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_setup_optional_policy() {
    run("bootstrap-setup", "optional-policy", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_setup_disabled() {
    run("bootstrap-setup", "disabled", false).await.unwrap();
}

#[tokio::test]
async fn edge_bootstrap_setup_impersonated() {
    run("bootstrap-setup", "impersonated", false).await.unwrap();
}

#[tokio::test]
async fn edge_bootstrap_setup_stale_credential() {
    run("bootstrap-setup", "stale-credential", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_setup_identity_stale() {
    run("bootstrap-setup", "identity-stale", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_setup_fault_staging() {
    run("bootstrap-setup", "fault-staging", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_setup_fault_binding() {
    run("bootstrap-setup", "fault-binding", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_bad_code() {
    run("bootstrap-confirm", "bad-code", false).await.unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_near_lock() {
    run("bootstrap-confirm", "near-lock", false).await.unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_locked() {
    run("bootstrap-confirm", "locked", false).await.unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_no_grant() {
    run("bootstrap-confirm", "no-grant", false).await.unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_proof_session() {
    run("bootstrap-confirm", "proof-session", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_proof_generation() {
    run("bootstrap-confirm", "proof-generation", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_proof_operation() {
    run("bootstrap-confirm", "proof-operation", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_pending_expired() {
    run("bootstrap-confirm", "pending-expired", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_pending_session() {
    run("bootstrap-confirm", "pending-session", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_pending_missing() {
    run("bootstrap-confirm", "pending-missing", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_pending_corrupt() {
    run("bootstrap-confirm", "pending-corrupt", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_revoked_challenge() {
    run("bootstrap-confirm", "revoked-challenge", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_optional_policy() {
    run("bootstrap-confirm", "optional-policy", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_disabled() {
    run("bootstrap-confirm", "disabled", false).await.unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_impersonated() {
    run("bootstrap-confirm", "impersonated", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_stale_credential() {
    run("bootstrap-confirm", "stale-credential", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_identity_stale() {
    run("bootstrap-confirm", "identity-stale", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_fault_audit() {
    run("bootstrap-confirm", "fault-audit", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_bootstrap_confirm_fault_anchor() {
    run("bootstrap-confirm", "fault-anchor", false)
        .await
        .unwrap();
}

#[tokio::test]
async fn edge_setup_oversized() {
    run("setup", "oversized", false).await.unwrap();
}
#[tokio::test]
async fn edge_confirm_oversized() {
    run("confirm", "oversized", false).await.unwrap();
}
#[tokio::test]
async fn edge_bootstrap_setup_oversized() {
    run("bootstrap-setup", "oversized", false).await.unwrap();
}

#[tokio::test]
async fn mutant_pending_revocation_gap_restores_go_bug() {
    run_security("verify","revoked-challenge",false,true).await.unwrap();
}

#[tokio::test]
async fn edge_verify_elapsed_code_replay(){run("verify","elapsed-code-replay",false).await.unwrap();}

#[tokio::test]
async fn mutant_elapsed_totp_replay_restores_go_bug(){run_security("verify","elapsed-code-replay",false,true).await.unwrap();}
#[tokio::test]
async fn mutant_legacy_totp_counter_gap_restores_go_bug(){run_security("verify","rolling-replay",false,true).await.unwrap();}
#[tokio::test]
async fn guest_verify_ok() { run("verify", "guest", false).await.unwrap(); }
#[tokio::test]
async fn guest_verify_scope_503() { run("verify", "guest-scope-unavailable", false).await.unwrap(); }
#[tokio::test]
async fn guest_verify_acct_500() { run("verify", "guest-account-type-unavailable", false).await.unwrap(); }
#[tokio::test]
async fn guest_bootstrap_confirm_ok() { run("bootstrap-confirm", "guest", false).await.unwrap(); }
#[tokio::test]
async fn guest_login_totp_challenge() { run("login-totp", "guest", false).await.unwrap(); }
