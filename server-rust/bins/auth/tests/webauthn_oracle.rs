//! Frozen-Go WebAuthn HTTP and committed-effect oracle.
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
static NULL_AUDIT_FLOOR: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
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
    inventory["routes"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["listener"] == "auth" || r["path"] == "/auth/webauthn/");
    if record.is_some() {
        for r in inventory["routes"].as_array_mut().unwrap().iter_mut() {
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
        .header("host", "auth.idmfa2.test")
        .header("user-agent", "IDMFA2 oracle");
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
        if name == "set-cookie" && resp.headers().get_all(name).iter().count() > 1 {
            hs.insert(
                name.into(),
                json!(resp
                    .headers()
                    .get_all(name)
                    .iter()
                    .map(|h| h.to_str().unwrap())
                    .collect::<Vec<_>>()),
            );
        } else if let Some(v) = resp.headers().get(name) {
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

fn corpus() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/identity-webauthn/goldens")
}
async fn run(route: &str, kind: &str, mutant: bool) -> Result<(), Err> {
    run_security(route,kind,mutant,false).await
}
async fn run_security(route: &str, kind: &str, mutant: bool, bug: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDMFA2").expect("assigned DB required");
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    let secure_sql=include_str!("../../../../mailserver/sql/reducers/rust_identity_webauthn_login_claim.sql");
    if bug {
        assert!(std::env::var("GOFREE_RECORD_UPSTREAM").is_err());
        let start=secure_sql.find("    -- SECURITY-ASSERTION-BEGIN").unwrap();
        let end=secure_sql.find("    -- SECURITY-ASSERTION-END").unwrap()+"    -- SECURITY-ASSERTION-END".len();
        let mut restored=secure_sql.to_owned();restored.replace_range(start..end,"");c.batch_execute(&restored).await?;
    }
    common::signing_key(&c).await;
    let saved_rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    let receipts = common::receipt_ids(&c).await;
    let null_floor: i64 = c
        .query_one("SELECT COALESCE(max(id),0) FROM auth_event_log", &[])
        .await?
        .get(0);
    NULL_AUDIT_FLOOR.store(null_floor, std::sync::atomic::Ordering::SeqCst);
    let a = fixture::account(&c, "idmfa2-actor").await?;
    let b = fixture::account(&c, "idmfa2-foreign").await?;
    for (uid, id, name, uv) in [
        (a.user, b"actor-credential".as_slice(), "My key", true),
        (b.user, b"foreign-credential".as_slice(), "Foreign", false),
    ] {
        c.execute("INSERT INTO passkey_credentials(id,user_id,public_key,attestation_type,sign_count,device_name,created_at,uv_capable) VALUES($1,$2,'\\xa0','none',7,$3,'2026-10-01T02:03:04Z',$4)",&[&id,&uid,&name,&uv]).await?;
    }
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    if matches!(route, "register-begin" | "register-finish" | "revoke") {
        use sha2::{Digest, Sha256};
        let hash = format!("{:x}", Sha256::digest(b"idmfa2-proof"));
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,proving_factor_id,bound_factor_generation,token_scope,expires_at) VALUES($1,$2,'idmfa2-actor','webauthn.register','webauthn_uv',$3,0,'session',now()+interval '5 minutes')",&[&hash,&a.user,&b"actor-credential".as_slice()]).await?;
    }
    if route == "revoke" {
        c.execute("UPDATE mfa_reauth_step_ups SET operation='webauthn.revoke',target_ref='YWN0b3ItY3JlZGVudGlhbA' WHERE user_id=$1",&[&a.user]).await?;
        match kind {
            "generation" => {
                c.execute(
                    "UPDATE mfa_reauth_step_ups SET bound_factor_generation=1 WHERE user_id=$1",
                    &[&a.user],
                )
                .await?;
            }
            "wrong-target" => {
                c.execute("UPDATE mfa_reauth_step_ups SET target_ref='Zm9yZWlnbi1jcmVkZW50aWFs' WHERE user_id=$1",&[&a.user]).await?;
            }
            "missing-target" => {
                c.execute(
                    "UPDATE mfa_reauth_step_ups SET target_ref='bWlzc2luZw' WHERE user_id=$1",
                    &[&a.user],
                )
                .await?;
            }
            "proving-revoked" => {
                c.execute(
                    "UPDATE passkey_credentials SET revoked_at=now() WHERE user_id=$1",
                    &[&a.user],
                )
                .await?;
            }
            "cleanup" => {
                c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,proving_factor_id,bound_factor_generation,token_scope,expires_at) SELECT 'other-proof',user_id,'other-session','webauthn.register','webauthn_uv',proving_factor_id,0,'session',now()+interval '5 minutes' FROM mfa_reauth_step_ups WHERE user_id=$1",&[&a.user]).await?;
            }
            _ => {}
        }
    }
    if route == "register-begin" {
        if kind == "generation" {
            c.execute(
                "UPDATE mfa_reauth_step_ups SET bound_factor_generation=1 WHERE user_id=$1",
                &[&a.user],
            )
            .await?;
        }
        if kind == "bound-dead" {
            c.execute(
                "UPDATE mfa_reauth_step_ups SET target_ref='dead-ceremony' WHERE user_id=$1",
                &[&a.user],
            )
            .await?;
        }
    }
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    if route == "login-finish" {
        cfg.signing_alg = "ES256".into();
        if kind.starts_with("pending-push"){cfg.vapid_private_key="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into();}
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
    let fault = if kind.starts_with("fault-") {
        Some(match kind {
            "fault-audit" => (
                "admin_audit_log",
                "INSERT",
                format!("NEW.user_id={}", a.user),
            ),
            "fault-generation" => (
                "users",
                "UPDATE",
                format!(
                    "NEW.id={} AND NEW.factor_generation<>OLD.factor_generation",
                    a.user
                ),
            ),
            "fault-credential" => (
                "passkey_credentials",
                "INSERT",
                format!("NEW.user_id={}", a.user),
            ),
            "fault-grant" => (
                "mfa_reauth_step_ups",
                "DELETE",
                format!("OLD.user_id={}", a.user),
            ),
            "fault-bind" => (
                "mfa_reauth_step_ups",
                "UPDATE",
                format!("NEW.user_id={}", a.user),
            ),
            "fault-write" => (
                "passkey_credentials",
                "UPDATE",
                format!("NEW.user_id={}", a.user),
            ),
            _ => unreachable!(),
        })
    } else {
        None
    };
    let result=async {
        use base64::Engine;
        let vectors:Value=serde_json::from_str(if kind.starts_with("packed-"){include_str!("../../../tests/conformance/identity-webauthn/packed-vectors.json")}else if kind=="safetynet"{include_str!("../../../tests/conformance/identity-webauthn/safetynet-vectors.json")}else if kind=="backup-eligible"{include_str!("../../../tests/conformance/identity-webauthn/backup-vectors.json")}else{include_str!("../../../tests/conformance/identity-webauthn/vectors.json")})?;
        let index=match kind.strip_prefix("packed-").unwrap_or(kind){"es384"=>1,"es512"=>2,"rs256"=>3,"eddsa"=>4,"ps256"=>5,"ps384"=>6,"ps512"=>7,_=>0};
        let vector=&vectors["cases"][index];
        if route=="login-finish" {
            if kind.starts_with("pending-push") {
                c.execute("UPDATE users SET push_mfa_enabled=true,totp_enabled=$2 WHERE id=$1",&[&a.user,&(!kind.contains("only"))]).await?;
                if kind.ends_with("limit") {for n in 0u8..3 {c.execute("INSERT INTO push_mfa_challenges(user_id,nonce,challenge_code,session_id,expires_at) VALUES($1,$2,'42','preseed',now()+interval '2 minutes')",&[&a.user,&vec![n;32]]).await?;}}
            }
            if kind=="pending-totp"{c.execute("UPDATE users SET totp_enabled=true WHERE id=$1",&[&a.user]).await?;}
            let id=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(vector["id"].as_str().unwrap())?;
            let handle=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(vector["handle"].as_str().unwrap())?;
            c.execute("DELETE FROM passkey_credentials WHERE user_id=$1",&[&a.user]).await?;
            c.execute("UPDATE users SET webauthn_user_handle=$2 WHERE id=$1",&[&a.user,&handle]).await?;
            if kind!="success"{c.execute("UPDATE users SET webauthn_user_handle=$2 WHERE id=$1",&[&b.user,&vec![3u8;32]]).await?;}
            if kind=="decimal-handle"{c.execute("UPDATE users SET webauthn_user_handle=''::bytea WHERE id=$1",&[&a.user]).await?;}
            c.execute("INSERT INTO passkey_credentials(id,user_id,public_key,attestation_type,sign_count,device_name,created_at,uv_capable) VALUES($1,$2,$3,'none',7,'My key','2026-10-01T02:03:04Z',true)",&[&id,&a.user,&unhex(vector["key"].as_str().unwrap())]).await?;
        }
        let mode=match kind{"counter-regression"=>"regression","zero-count"=>"zero",_=>"success"};
        let mut assertion=vector["assertions"][mode]["request"].clone();
        if kind=="decimal-handle"{assertion["response"]["userHandle"]=json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(a.user.to_string()));}
        if matches!(kind,"wrong-challenge"|"wrong-origin"){
            let bytes=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(assertion["response"]["clientDataJSON"].as_str().unwrap())?;
            let mut data:Value=serde_json::from_slice(&bytes)?;data[if kind=="wrong-origin"{"origin"}else{"challenge"}]=json!("wrong");
            assertion["response"]["clientDataJSON"]=json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data.to_string()));
        }
        let assertion=assertion.to_string();
        let mut registration=vector["registration"].clone();
        if kind=="body-proof"{registration["reauth_token"]=json!("idmfa2-proof");}
        if kind=="no-uv"{
            use serde_cbor_2::Value as C;
            let bytes=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(registration["response"]["attestationObject"].as_str().unwrap())?;
            let mut att:C=serde_cbor_2::from_slice(&bytes)?;
            if let C::Map(m)=&mut att{if let Some(C::Bytes(b))=m.get_mut(&C::Text("authData".into())){b[32]&=!4;}}
            registration["response"]["attestationObject"]=json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_cbor_2::to_vec(&att)?));
        }
        if matches!(kind,"malformed-key"|"extensions"|"compound"){
            use serde_cbor_2::Value as C;
            let bytes=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(registration["response"]["attestationObject"].as_str().unwrap())?;
            let mut att:C=serde_cbor_2::from_slice(&bytes)?;
            if let C::Map(m)=&mut att{
                if kind=="compound"{
                    m.insert(C::Text("fmt".into()),C::Text("compound".into()));
                    let empty=C::Map(Default::default());
                    let sub=C::Map([(C::Text("fmt".into()),C::Text("packed".into())),(C::Text("attStmt".into()),empty)].into_iter().collect());
                    m.insert(C::Text("attStmt".into()),C::Map([(C::Text("attStmt".into()),C::Array(vec![sub.clone(),sub]))].into_iter().collect()));
                }else if let Some(C::Bytes(b))=m.get_mut(&C::Text("authData".into())){
                    if kind=="extensions"{b[32]|=0x80;b.extend_from_slice(&[0xa1,0x61,b'x',0xf5]);}
                    else{let n=u16::from_be_bytes(b[53..55].try_into().unwrap())as usize;b.truncate(55+n);let key=C::Map([(C::Integer(1),C::Integer(2)),(C::Integer(3),C::Integer(-7)),(C::Integer(-1),C::Integer(1)),(C::Integer(-2),C::Bytes(Vec::new())),(C::Integer(-3),C::Bytes(Vec::new()))].into_iter().collect());b.extend_from_slice(&serde_cbor_2::to_vec(&key)?);}
                }
            }
            registration["response"]["attestationObject"]=json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_cbor_2::to_vec(&att)?));
        }
        if kind.starts_with("cbor-"){
            use serde_cbor_2::Value as C;
            let mut bytes=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(registration["response"]["attestationObject"].as_str().unwrap())?;
            match kind {
                "cbor-duplicate"=>{assert_eq!(bytes[0],0xa3);bytes[0]=0xa4;bytes.extend_from_slice(&serde_cbor_2::to_vec(&C::Text("fmt".into()))?);bytes.extend_from_slice(&serde_cbor_2::to_vec(&C::Text("none".into()))?);},
                "cbor-indefinite"=>{bytes[0]=0xbf;bytes.push(0xff);},
                "cbor-tag"=>{bytes.insert(0,0xc0);},
                "cbor-indefinite-bytes"=>{
                    let C::Map(m)=serde_cbor_2::from_slice::<C>(&bytes)? else{unreachable!()};
                    bytes=vec![0xa3];
                    for (key,value)in m{let indefinite=key==C::Text("authData".into());bytes.extend_from_slice(&serde_cbor_2::to_vec(&key)?);if indefinite{bytes.push(0x5f);}bytes.extend_from_slice(&serde_cbor_2::to_vec(&value)?);if indefinite{bytes.push(0xff);}}
                },
                "cbor-duplicate-key"=>{
                    let mut m: C=serde_cbor_2::from_slice(&bytes)?;
                    if let C::Map(m)=&mut m{if let Some(C::Bytes(auth))=m.get_mut(&C::Text("authData".into())){let n=55+u16::from_be_bytes(auth[53..55].try_into().unwrap())as usize;assert_eq!(auth[n],0xa5);auth[n]=0xa6;auth.extend_from_slice(&[3,0x26]);}}
                    bytes=serde_cbor_2::to_vec(&m)?;
                },_=>unreachable!()
            }
            registration["response"]["attestationObject"]=json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes));
        }
        let registration=registration.to_string();
        if route=="register-finish"{
            use sha2::{Digest,Sha256};
            let handle=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(vector["handle"].as_str().unwrap())?;
            c.execute("UPDATE users SET webauthn_user_handle=$2 WHERE id=$1",&[&a.user,&handle]).await?;
            c.execute("UPDATE passkey_credentials SET public_key=$2 WHERE user_id=$1",&[&a.user,&unhex(vector["key"].as_str().unwrap())]).await?;
            let hash=format!("{:x}",Sha256::digest(vector["challenge"].as_str().unwrap().as_bytes()));
            c.execute("UPDATE mfa_reauth_step_ups SET target_ref=$2 WHERE user_id=$1",&[&a.user,&hash]).await?;
            c.execute("INSERT INTO webauthn_ceremonies(challenge_hash,user_id,kind,operation,target_ref,session_jti,token_scope,expires_at) VALUES($1,$2,'registration','webauthn.register',$1,'idmfa2-actor','session',now()+interval '5 minutes')",&[&hash,&a.user]).await?;
            match kind {
                "generation"=>{c.execute("UPDATE mfa_reauth_step_ups SET bound_factor_generation=1 WHERE user_id=$1",&[&a.user]).await?;},
                "proving-revoked"=>{c.execute("UPDATE passkey_credentials SET revoked_at=now() WHERE user_id=$1",&[&a.user]).await?;},
                "expired-ceremony"=>{c.execute("UPDATE webauthn_ceremonies SET expires_at=now()-interval '1 second' WHERE user_id=$1",&[&a.user]).await?;},
                "collision"|"replace"=>{
                    let owner=if kind=="collision"{b.user}else{a.user};
                    let id=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(vector["id"].as_str().unwrap())?;
                    c.execute("INSERT INTO passkey_credentials(id,user_id,public_key,attestation_type,sign_count,device_name,created_at,uv_capable) VALUES($1,$2,'\\xa0','legacy-type',3,'Existing','2026-10-01T02:03:04Z',false)",&[&id,&owner]).await?;
                },_=>{}
            }
        }
        let cookie_codec=setjoin_identity::webauthn::CookieCipher::new(keys["secret"].as_str().unwrap().as_bytes());
        let mut session=json!({"challenge":vector["challenge"],"rpId":"localhost","user_id":base64::engine::general_purpose::STANDARD.encode(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(vector["handle"].as_str().unwrap())?),"allowed_credentials":[base64::engine::general_purpose::STANDARD.encode(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(vector["id"].as_str().unwrap())?)],"expires":"0001-01-01T00:00:00Z"});
        if kind=="decimal-handle"{session["user_id"]=json!(base64::engine::general_purpose::STANDARD.encode(a.user.to_string()));}
        let mut cookies=format!("wa_login_sess={}; wa_login_uid={}",cookie_codec.seal(session.to_string().as_bytes())?,cookie_codec.seal((if kind=="cross-tenant"{b.user}else{a.user}).to_string().as_bytes())?);
        if route=="register-finish"{
            session.as_object_mut().unwrap().remove("allowed_credentials");
            session["credParams"]=json!([-7,-35,-36,-257,-258,-259,-37,-38,-39,-8].iter().map(|alg|json!({"type":"public-key","alg":alg})).collect::<Vec<_>>());
            cookies=format!("wa_reg_sess={}",cookie_codec.seal(session.to_string().as_bytes())?);
        }
        if kind=="quoted-cookie"{cookies=cookies.split("; ").map(|c|{let(n,v)=c.split_once('=').unwrap();format!("{n}=\"{v}\"")}).collect::<Vec<_>>().join("; ");}
        let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let uid=if kind=="cross-tenant" {b.user}else{a.user};
        let claims=json!({"uid":uid,"email":"actor@idmfa2.test","typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600,"jti":"idmfa2-actor"});
        let token=setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&claims.to_string());
        let authorization=format!("Bearer {token}");
        let authorization=if matches!(kind,"unauthenticated"|"oversized-unauthenticated") || kind=="invalid-input" && route=="list" {"Bearer malformed"}else{&authorization};
        let actor_email:String=c.query_one("SELECT email FROM users WHERE id=$1",&[&a.user]).await?.get(0);
        let begin_path=if kind=="invalid-input"{String::from("/auth/webauthn/login/begin?email=missing%40idmfa2.test")}else{format!("/auth/webauthn/login/begin?email={actor_email}")};
        let encoded_id=match kind{"noncanonical-id"=>"YWN0b3ItY3JlZGVudGlhbB","escaped-id"=>"%59WN0b3ItY3JlZGVudGlhbA","invalid-input" if route=="revoke"=>"!","missing-target"=>"bWlzc2luZw",_=>"YWN0b3ItY3JlZGVudGlhbA"};
        let credential_path=format!("/auth/webauthn/credential/{encoded_id}{}",if route=="name"{"/name"}else{""});
        let (method,path,mut payload)=match route {
            "subtree"=>(if kind=="invalid-input"{"DELETE"}else if kind=="head"{"HEAD"}else{"GET"},if kind=="invalid-input"{"/auth/webauthn/login/finish"}else{"/auth/webauthn/unknown"},""),
            "list"=>("GET","/auth/webauthn/credentials",""),
            "login-begin"=>("GET",begin_path.as_str(),""),
            "login-finish"=>("POST","/auth/webauthn/login/finish",assertion.as_str()),
            "register-begin"=>("GET","/auth/webauthn/register/begin",if kind=="body-proof"{r#"{"reauth_token":"idmfa2-proof"}"#}else{""}),
            "register-finish"=>("POST","/auth/webauthn/register/finish",registration.as_str()),
            "revoke"=>("DELETE",credential_path.as_str(),if kind=="body-proof"{r#"{"reauth_token":"idmfa2-proof"}"#}else{""}),
            "name"=>("PUT",credential_path.as_str(),r#"{"device_name":"Renamed <key>"}"#),
            _=>unreachable!()
        };
        if matches!(route,"name"|"login-finish"|"register-finish")&&kind=="invalid-input"{payload="{";}
        let oversized="x".repeat((64<<10)+1);
        if kind.starts_with("oversized"){payload=&oversized;}
        let reauth=if route=="register-begin"&&kind=="invalid-input"||matches!(kind,"body-proof"|"missing-proof"){""}else{"idmfa2-proof"};
        let mut notifications=db.listen("session_revoke").await?;
        let mut actor_notifications=db.listen(&format!("tag:{}",a.mailbox)).await?;
        let mut foreign_notifications=db.listen(&format!("tag:{}",b.mailbox)).await?;
        if let Some((table,event,predicate))=&fault{c.batch_execute(&format!("CREATE FUNCTION gofree_idmfa2_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF {predicate} THEN RAISE EXCEPTION 'gofree-idmfa2 injected statement failure'; END IF; IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF; END$$;CREATE TRIGGER gofree_idmfa2_fault BEFORE {event} ON {table} FOR EACH ROW EXECUTE FUNCTION gofree_idmfa2_fault()")).await?;}
        let push_before=if kind.starts_with("pending-push"){Some(push_rows(&c,a.user).await?)}else{None};
        let before=full_stores(&c,&a,&b).await?;
        let (status,mut headers,mut raw)=request(gw.addr,method,path,payload.into(),&[("authorization",authorization),("cookie",cookies.as_str()),("x-mfa-reauth",reauth)]).await?;
        let transport=if route=="login-begin"&&status==200{Some(begin_transport(&c,if kind=="invalid-input"{0}else{a.user},&keys,&mut headers,&mut raw).await?)}else{None};
        if route=="register-begin"&&status==200{register_begin_transport(&c,a.user,&keys,&mut headers,&mut raw).await?;}
        if kind.starts_with("pending-push")&&status==200 {
            let reply:Value=serde_json::from_str(&raw)?;
            if reply["mfa_method"]=="push" {
                let nonce=reply["nonce"].as_str().ok_or("nonce")?;
                assert_eq!(nonce.len(),64);assert!(nonce.bytes().all(|b|b.is_ascii_hexdigit()));
                let row=c.query_one("SELECT challenge_code,session_id,expires_at>now()+interval '110 seconds' AND expires_at<=now()+interval '121 seconds' FROM push_mfa_challenges WHERE user_id=$1 AND encode(nonce,'hex')=$2",&[&a.user,&nonce]).await?;
                let code:String=row.get(0);assert_eq!(code.len(),2);assert!(code.bytes().all(|b|b.is_ascii_digit()));assert!(row.get::<_,String>(1).is_empty(),"Go WebAuthn purpose is empty");assert!(row.get::<_,bool>(2));
                assert!(reply.get("code").is_none());raw=raw.replace(nonce,"<nonce>");
            }
        }
        let issued_claims=if route=="login-finish"&&status==200{Some(if kind=="pending-totp"||kind.starts_with("pending-push"){issued_pending(&a,&signature_keys,&keys,&headers,&mut raw)?}else{issued(&c,&a,&signature_keys,&keys,&mut headers,&mut raw).await?})}else{None};
        let mut actual=json!({"format":1,"go_source":"6c1a7fee2c8d147965cc84ed94ea4663488a89c7","route":format!("{method} {path}"),"case":format!("{route}-{kind}"),"observation":{"request":{"method":method,"path":path,"body":payload},"response":{"status":status,"headers":headers,"body":raw}}});
        if let Some(claims)=issued_claims{actual["observation"]["issued_claims"]=claims;}
        if let Some(transport)=transport{actual["observation"]["transport"]=transport;}
        actual["observation"]["effects"]=stores(&c,&a,&b).await?;
        let protected=(route=="login-finish"&&matches!(kind,"counter-regression"|"zero-count"|"repeat")||route=="register-finish"&&kind=="safetynet")&&record.is_none();
        let legacy_file=corpus().join(format!("{route}-{kind}.json"));
        if legacy_file.exists()&&!mutant&&!protected{golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(&legacy_file)?)?,&actual)?;}
        let registered=if route=="revoke"{"/auth/webauthn/credential/{id}"}else if route=="name"{"/auth/webauthn/credential/{id}/name"}else if route=="login-begin"{"/auth/webauthn/login/begin"}else{path};
        actual["route"]=json!(format!("{method} {registered}"));
        if route=="subtree" {actual["route"]=json!("* /auth/webauthn/");actual["observation"]["request"]["actual_method"]=json!(method);actual["observation"]["request"]["method"]=json!("*");}
        actual["observation"]["request"]["path"]=json!(if route=="subtree"{"/auth/webauthn/"}else{registered});
        actual["observation"]["request"]["actual_path"]=json!(path.replace(&actor_email,"actor@idmfa2.test"));
        if kind=="repeat" {
            let (status,mut headers,mut raw)=request(gw.addr,method,path,payload.into(),&[("authorization",authorization),("cookie",cookies.as_str()),("x-mfa-reauth",reauth)]).await?;
            if route=="login-finish"&&status==200{let repeat_claims=issued(&c,&a,&signature_keys,&keys,&mut headers,&mut raw).await?;assert_eq!(actual["observation"]["issued_claims"],repeat_claims);}
            if route=="login-begin"&&status==200{let repeat=begin_transport(&c,a.user,&keys,&mut headers,&mut raw).await?;assert_eq!(actual["observation"]["transport"],repeat);}
            actual["observation"]["repeat_response"]=json!({"status":status,"headers":headers,"body":raw});
        }
        let after=full_stores(&c,&a,&b).await?;
        actual["observation"]["effects"]=json!({"before":before,"after":after});
        if let Some(before)=push_before{actual["observation"]["push_challenges"]=json!({"before":before,"after":push_rows(&c,a.user).await?});}
        actual["observation"]["audit"]=after["admin_audit_log"].clone();
        let mut notify=Vec::new();
        for payload in notifications.drain(&c).await?{notify.push(json!({"channel":"session_revoke","payload":payload}));}
        for payload in actor_notifications.drain(&c).await?{notify.push(json!({"channel":"tag:<actor>","payload":payload}));}
        for payload in foreign_notifications.drain(&c).await?{notify.push(json!({"channel":"tag:<foreign>","payload":payload}));}
        actual["observation"]["notify"]=json!(notify);
        let file=corpus().parent().unwrap().join("qualified").join(format!("{route}-{kind}.json"));
        let rowfile=file.with_file_name(format!("{route}-{kind}-rows.json"));
        let rowdoc=json!({"format":1,"go_source":actual["go_source"],"route":actual["route"],"case":format!("{route}-{kind}-row-effects"),"effects":[{"table":"webauthn","before":before,"after":after}]});
        if record.is_some()&&!file.exists(){std::fs::create_dir_all(file.parent().unwrap())?;golden::record(&file,&actual)?;golden::record(&rowfile,&rowdoc)?;}
        let anonymous=anonymous_audit(&c,&a,&b).await?;
        let anonymous_file=file.with_file_name(format!("{route}-{kind}-anonymous.json"));
        let anonymous_doc=json!({"format":1,"go_source":actual["go_source"],"route":actual["route"],"case":format!("{route}-{kind}-anonymous-audit"),"audit":anonymous});
        if record.is_some()&&!anonymous_file.exists(){golden::record(&anonymous_file,&anonymous_doc)?;}
        if !mutant{let expected=if protected&&!bug{common::expected(&anonymous_file,true,&anonymous_doc)}else{serde_json::from_str::<Value>(&std::fs::read_to_string(anonymous_file)?)?};golden::compare(&expected,&anonymous_doc)?;}
        let mut expected:Value=if protected&&!bug{common::expected(&file,true,&actual)}else{serde_json::from_str(&std::fs::read_to_string(&file)?)?};normalize_checksums(&mut expected);
        if kind=="decimal-handle"{for doc in [&mut expected,&mut actual]{let mut request:Value=serde_json::from_str(doc["observation"]["request"]["body"].as_str().unwrap())?;request["response"]["userHandle"]=json!("<decimal-handle>");doc["observation"]["request"]["body"]=json!(request.to_string());}}
        if bug{assert!(golden::compare(&common::security_expectation(&file),&actual).is_err(),"bug-restoring mutant survived");}
        if mutant {assert!(golden::compare(&expected,&actual).unwrap_err().contains("/observation/response/status"));if route=="subtree"{println!("MUTANT-REJECTED: * /auth/webauthn/ :: status");}else{println!("MUTANT-REJECTED: {method} {registered} :: status");}}
        else {golden::compare(&expected,&actual)?;let mut expected_rows:Value=if protected&&!bug{common::expected(&rowfile,true,&rowdoc)}else{serde_json::from_str(&std::fs::read_to_string(rowfile)?)?};normalize_checksums(&mut expected_rows);golden::compare(&expected_rows,&rowdoc)?;if route=="subtree"{println!("GOLDEN-REPLAY: * /auth/webauthn/ :: {route}-{kind}");}else{println!("GOLDEN-REPLAY: {method} {registered} :: {route}-{kind}");}}
        if record.is_none(){let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));}
        Ok::<(),Err>(())
    }.await;
    if bug {c.batch_execute(secure_sql).await?;}
    if let Some((table, _, _)) = &fault {
        c.batch_execute(&format!("DROP TRIGGER IF EXISTS gofree_idmfa2_fault ON {table};DROP FUNCTION IF EXISTS gofree_idmfa2_fault()")).await?;
    }
    gw.close().await;
    auth.close().await;
    c.execute("DELETE FROM push_mfa_challenges WHERE user_id=ANY($1::bigint[])",&[&vec![a.user,b.user]]).await?;
    common::restore_receipts(&c, &receipts).await;
    if let Some(value) = saved_rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&value],
        )
        .await?;
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await?;
    }
    c.execute("DELETE FROM auth_event_log WHERE user_id=ANY($1::bigint[]) OR (id>$2 AND user_id IS NULL AND event='login_failed' AND provider='webauthn')",&[&vec![a.user,b.user],&null_floor]).await?;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    c.query_one(
        "SELECT pg_advisory_unlock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    result
}
async fn stores(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, Err> {
    let mut out = serde_json::Map::new();
    for (owner, u) in [("actor", a.user), ("foreign", b.user)] {
        let rows=c.query("SELECT encode(id,'base64'),device_name,sign_count,uv_capable,revoked_at IS NOT NULL,last_used_at IS NOT NULL FROM passkey_credentials WHERE user_id=$1 ORDER BY id",&[&u]).await?;
        out.insert(owner.into(),json!(rows.iter().map(|r|json!({"id":r.get::<_,String>(0),"name":r.get::<_,String>(1),"count":r.get::<_,i32>(2),"uv":r.get::<_,bool>(3),"revoked":r.get::<_,bool>(4),"used":r.get::<_,bool>(5)})).collect::<Vec<_>>()));
    }
    Ok(Value::Object(out))
}
#[tokio::test]
async fn list_success() {
    run("list", "success", false).await.unwrap();
}

#[tokio::test]
async fn list_cross_tenant() {
    run("list", "cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn list_invalid_input() {
    run("list", "invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn list_status_mutant() {
    run("list", "success", true).await.unwrap();
}
#[tokio::test]
async fn name_success() {
    run("name", "success", false).await.unwrap();
}

#[tokio::test]
async fn name_cross_tenant() {
    run("name", "cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn name_invalid_input() {
    run("name", "invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn name_repeat() {
    run("name", "repeat", false).await.unwrap();
}
#[tokio::test]
async fn name_status_mutant() {
    run("name", "success", true).await.unwrap();
}
async fn full_stores(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, Err> {
    let mut out = json!({});
    for table in [
        "users",
        "passkey_credentials",
        "mfa_reauth_step_ups",
        "webauthn_ceremonies",
        "admin_audit_log",
        "oauth_tokens",
        "sessions",
        "auth_event_log",
        "login_events",
        "session_revocations",
    ] {
        let column = if table == "users" { "id" } else { "user_id" };
        let sql=format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY {column},to_jsonb(t)::text),'[]')::text FROM {table} t WHERE {column}=ANY($1::bigint[])");
        let raw: String = c.query_one(&sql, &[&vec![a.user, b.user]]).await?.get(0);
        let mut rows: Value = serde_json::from_str(&raw)?;
        if table == "admin_audit_log" && !rows.as_array().unwrap().is_empty() {
            let invalid: bool = c
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM verify_audit_chain(NULL,NULL) WHERE NOT valid)",
                    &[],
                )
                .await?
                .get(0);
            assert!(
                !invalid,
                "audit chain must verify before masking generated checksums"
            );
            normalize_checksums(&mut rows);
        }
        if table != "users" {
            for row in rows.as_array_mut().unwrap() {
                if row.get("id").is_some_and(Value::is_number) {
                    row["id"] = json!("<id>");
                }
            }
        }
        if matches!(table, "oauth_tokens" | "sessions") {
            for row in rows.as_array_mut().unwrap() {
                if let Some(v) = row.get_mut("token_hash") {
                    if !v.is_null() {
                        *v = json!("<issued-token-hash>");
                    }
                }
                if let Some(v) = row.get_mut("family_id") {
                    if !v.is_null() {
                        *v = json!("<family>");
                    }
                }
                if table == "sessions" {
                    row["id"] = json!("<access-jti>");
                }
            }
        }
        normalize(&mut rows, a, b);
        out[table] = rows;
    }
    for (account, label) in [(a, "actor"), (b, "foreign")] {
        let raw: String = c
            .query_one(
                "SELECT to_jsonb(m)::text FROM mailboxes m WHERE id=$1 AND user_id=$2",
                &[&account.mailbox, &account.user],
            )
            .await?
            .get(0);
        let mut row: Value = serde_json::from_str(&raw)?;
        row.as_object_mut()
            .unwrap()
            .retain(|k, _| k.starts_with("jmap_"));
        out[format!("{label}_mailbox_state")] = row;
    }
    Ok(out)
}
fn normalize(v: &mut Value, a: &fixture::Account, b: &fixture::Account) {
    match v {
        Value::Array(v) => {
            for x in v {
                normalize(x, a, b)
            }
        }
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if matches!(k.as_str(), "user_id" | "target_id" | "id") && x.is_number() {
                    *x = if *x == a.user {
                        json!("<actor>")
                    } else if *x == b.user {
                        json!("<foreign>")
                    } else {
                        json!("<id>")
                    };
                } else if k == "domain_id" && x.is_number() {
                    *x = json!(if *x == a.domain {
                        "<actor-domain>"
                    } else {
                        "<foreign-domain>"
                    });
                } else if matches!(k.as_str(), "challenge_hash" | "target_ref")
                    && x.as_str().is_some_and(|s| s.len() == 64)
                {
                    *x = json!("<challenge-hash>");
                } else if k == "webauthn_user_handle" && x.is_string() {
                    *x = json!("<user-handle>");
                } else if (k.ends_with("_at") || k.ends_with("_until")) && x.is_string() {
                    *x = json!("<timestamp>");
                } else if matches!(k.as_str(), "email" | "username") && x.is_string() {
                    *x = json!(if x.as_str().unwrap().starts_with("idmfa2-actor@") {
                        "actor@idmfa2.test"
                    } else {
                        "foreign@idmfa2.test"
                    });
                } else {
                    normalize(x, a, b);
                }
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn login_begin_success() {
    run("login-begin", "success", false).await.unwrap();
}
async fn begin_transport(
    c: &tokio_postgres::Client,
    uid: i64,
    keys: &Value,
    headers: &mut Value,
    raw: &mut String,
) -> Result<Value, Err> {
    use base64::Engine;
    let options: Value = serde_json::from_str(raw)?;
    let challenge = options["publicKey"]["challenge"]
        .as_str()
        .ok_or("challenge absent")?
        .to_owned();
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&challenge)?
            .len(),
        32
    );
    let codec =
        setjoin_identity::webauthn::CookieCipher::new(keys["secret"].as_str().unwrap().as_bytes());
    let cookies = headers["set-cookie"]
        .as_array_mut()
        .ok_or("two cookies required")?;
    let mut session = None;
    let mut principal = None;
    for cookie in cookies {
        let text = cookie.as_str().unwrap().to_owned();
        let (name, value) = text.split(';').next().unwrap().split_once('=').unwrap();
        assert!(text.contains("Max-Age=300; HttpOnly; SameSite=Strict"));
        let plain = codec.open(value).ok_or("Go cookie failed authentication")?;
        match name {
            "wa_login_sess" => {
                session = Some(serde_json::from_slice::<Value>(&plain)?);
                *cookie = json!(text.replace(value, "<session-cookie>"));
            }
            "wa_login_uid" => {
                assert_eq!(std::str::from_utf8(&plain)?.parse::<i64>()?, uid);
                principal = Some(json!(if uid == 0 { "<decoy>" } else { "<actor>" }));
                *cookie = json!(text.replace(value, "<uid-cookie>"));
            }
            _ => return Err("unexpected cookie".into()),
        }
    }
    let mut session = session.ok_or("no session")?;
    assert_eq!(session["challenge"], challenge);
    if uid > 0 {
        let handle: Vec<u8> = c
            .query_one(
                "SELECT webauthn_user_handle FROM users WHERE id=$1",
                &[&uid],
            )
            .await?
            .get(0);
        assert_eq!(
            session["user_id"],
            base64::engine::general_purpose::STANDARD.encode(handle)
        );
        session["user_id"] = json!("<user-handle>");
    } else {
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(session["user_id"].as_str().ok_or("missing handle")?)?
                .len(),
            32
        );
        session["user_id"] = json!("<decoy-handle>");
        let id = options["publicKey"]["allowCredentials"][0]["id"]
            .as_str()
            .ok_or("decoy id")?;
        let id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(id)?;
        assert_eq!(id_bytes.len(), 32);
        assert_eq!(
            session["allowed_credentials"][0],
            base64::engine::general_purpose::STANDARD.encode(&id_bytes)
        );
        session["allowed_credentials"][0] = json!("<decoy-id>");
        *raw = raw.replace(id, "<decoy-id>");
    }
    session["challenge"] = json!("<challenge>");
    *raw = raw.replace(&challenge, "<challenge>");
    Ok(json!({"session":session,"principal":principal}))
}

#[tokio::test]
async fn login_begin_cross_tenant() {
    run("login-begin", "cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn login_begin_invalid_input() {
    run("login-begin", "invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn login_begin_repeat() {
    run("login-begin", "repeat", false).await.unwrap();
}
#[tokio::test]
async fn login_begin_status_mutant() {
    run("login-begin", "success", true).await.unwrap();
}

#[tokio::test]
async fn login_finish_success() {
    run("login-finish", "success", false).await.unwrap();
}
fn unhex(raw: &str) -> Vec<u8> {
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
        .collect()
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
        assert_eq!(proof.text("sub"), a.user.to_string());
        assert_eq!(proof.text("typ"), typ);
        if let Ok(upstream) = std::env::var("GOFREE_WEBAUTHN_SWAP_UPSTREAM") {
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
        normalized["email"] = json!("actor@idmfa2.test");
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

macro_rules! finish_case {
    ($name:ident,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            run("login-finish", $kind, false).await.unwrap();
        }
    };
}
finish_case!(login_finish_cross_tenant, "cross-tenant");
finish_case!(login_finish_invalid_input, "invalid-input");
finish_case!(login_finish_repeat, "repeat");
finish_case!(edge_login_finish_counter_regression, "counter-regression");
finish_case!(edge_login_finish_zero_count, "zero-count");
finish_case!(edge_login_finish_wrong_challenge, "wrong-challenge");
finish_case!(edge_login_finish_wrong_origin, "wrong-origin");
finish_case!(edge_login_finish_decimal_handle, "decimal-handle");
finish_case!(edge_login_finish_es384, "es384");
finish_case!(edge_login_finish_es512, "es512");
finish_case!(edge_login_finish_rs256, "rs256");
finish_case!(edge_login_finish_eddsa, "eddsa");
finish_case!(edge_login_finish_ps256, "ps256");
finish_case!(edge_login_finish_ps384, "ps384");
finish_case!(edge_login_finish_ps512, "ps512");
#[tokio::test]
async fn login_finish_status_mutant() {
    run("login-finish", "success", true).await.unwrap();
}

async fn anonymous_audit(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, Err> {
    let floor = NULL_AUDIT_FLOOR.load(std::sync::atomic::Ordering::SeqCst);
    let raw:String=c.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id),'[]')::text FROM auth_event_log t WHERE id>$1 AND user_id IS NULL AND event='login_failed' AND provider='webauthn'",&[&floor]).await?.get(0);
    let mut v: Value = serde_json::from_str(&raw)?;
    for row in v.as_array_mut().unwrap() {
        row["id"] = json!("<id>");
    }
    normalize(&mut v, a, b);
    Ok(v)
}

#[tokio::test]
async fn register_begin_success() {
    run("register-begin", "success", false).await.unwrap();
}
async fn register_begin_transport(
    c: &tokio_postgres::Client,
    uid: i64,
    keys: &Value,
    headers: &mut Value,
    raw: &mut String,
) -> Result<(), Err> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let options: Value = serde_json::from_str(raw)?;
    let challenge = options["publicKey"]["challenge"]
        .as_str()
        .ok_or("challenge")?;
    let hash = format!("{:x}", Sha256::digest(challenge.as_bytes()));
    let row=c.query_one("SELECT target_ref,session_jti,expires_at>now()+interval '290 seconds' FROM webauthn_ceremonies WHERE user_id=$1 AND challenge_hash=$2 AND kind='registration' AND operation='webauthn.register' AND token_scope='session'",&[&uid,&hash]).await?;
    assert_eq!(row.get::<_, Option<String>>(0), Some(hash.clone()));
    assert_eq!(row.get::<_, String>(1), "idmfa2-actor");
    assert!(row.get::<_, bool>(2));
    let target: Option<String> = c
        .query_one(
            "SELECT target_ref FROM mfa_reauth_step_ups WHERE user_id=$1",
            &[&uid],
        )
        .await?
        .get(0);
    assert_eq!(target, Some(hash));
    let handle: Vec<u8> = c
        .query_one(
            "SELECT webauthn_user_handle FROM users WHERE id=$1",
            &[&uid],
        )
        .await?
        .get(0);
    assert_eq!(handle.len(), 32);
    assert_eq!(
        options["publicKey"]["user"]["id"],
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&handle)
    );
    let cookie = headers["set-cookie"].as_str().ok_or("cookie")?.to_owned();
    let value = cookie.split(';').next().unwrap().split_once('=').unwrap().1;
    let codec =
        setjoin_identity::webauthn::CookieCipher::new(keys["secret"].as_str().unwrap().as_bytes());
    let session: Value =
        serde_json::from_slice(&codec.open(value).ok_or("bad encrypted session")?)?;
    assert_eq!(session["challenge"], challenge);
    assert_eq!(
        session["user_id"],
        base64::engine::general_purpose::STANDARD.encode(&handle)
    );
    headers["set-cookie"] = json!(cookie.replace(value, "<registration-cookie>"));
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&uid])
        .await?
        .get(0);
    *raw = raw
        .replace(challenge, "<challenge>")
        .replace(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(handle),
            "<user-handle>",
        )
        .replace(&email, "actor@idmfa2.test");
    Ok(())
}

macro_rules! register_begin_case {
    ($name:ident,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            run("register-begin", $kind, false).await.unwrap();
        }
    };
}
register_begin_case!(register_begin_cross_tenant, "cross-tenant");
register_begin_case!(register_begin_invalid_input, "invalid-input");
register_begin_case!(register_begin_repeat, "repeat");
register_begin_case!(edge_register_begin_generation, "generation");
register_begin_case!(edge_register_begin_bound_dead, "bound-dead");
register_begin_case!(edge_register_begin_unauthenticated, "unauthenticated");
#[tokio::test]
async fn register_begin_status_mutant() {
    run("register-begin", "success", true).await.unwrap();
}

fn normalize_checksums(value: &mut Value) {
    match value {
        Value::Array(a) => {
            for v in a {
                normalize_checksums(v)
            }
        }
        Value::Object(m) => {
            for (k, v) in m {
                if k == "checksum" && v.is_string() {
                    let s = v.as_str().unwrap();
                    if s != "<verified-checksum>" {
                        let hex = s.strip_prefix("v3:").unwrap_or(s);
                        assert_eq!(hex.len(), 64);
                        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
                    }
                    *v = json!("<verified-checksum>");
                } else {
                    normalize_checksums(v);
                }
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn register_finish_success() {
    run("register-finish", "success", false).await.unwrap();
}

macro_rules! register_finish_case {
    ($name:ident,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            run("register-finish", $kind, false).await.unwrap();
        }
    };
}
register_finish_case!(register_finish_cross_tenant, "cross-tenant");
register_finish_case!(register_finish_invalid_input, "invalid-input");
register_finish_case!(register_finish_repeat, "repeat");
register_finish_case!(edge_register_finish_generation, "generation");
register_finish_case!(edge_register_finish_proving_revoked, "proving-revoked");
register_finish_case!(edge_register_finish_expired_ceremony, "expired-ceremony");
register_finish_case!(edge_register_finish_collision, "collision");
register_finish_case!(edge_register_finish_replace, "replace");
register_finish_case!(edge_register_finish_no_uv, "no-uv");
register_finish_case!(edge_register_finish_body_proof, "body-proof");
register_finish_case!(edge_register_finish_missing_proof, "missing-proof");
register_finish_case!(edge_register_finish_es384, "es384");
register_finish_case!(edge_register_finish_es512, "es512");
register_finish_case!(edge_register_finish_rs256, "rs256");
register_finish_case!(edge_register_finish_eddsa, "eddsa");
register_finish_case!(edge_register_finish_ps256, "ps256");
register_finish_case!(edge_register_finish_ps384, "ps384");
register_finish_case!(edge_register_finish_ps512, "ps512");
#[tokio::test]
async fn register_finish_status_mutant() {
    run("register-finish", "success", true).await.unwrap();
}

#[tokio::test]
async fn revoke_success() {
    run("revoke", "success", false).await.unwrap();
}

macro_rules! revoke_case {
    ($name:ident,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            run("revoke", $kind, false).await.unwrap();
        }
    };
}
revoke_case!(revoke_cross_tenant, "cross-tenant");
revoke_case!(revoke_invalid_input, "invalid-input");
revoke_case!(revoke_repeat, "repeat");
revoke_case!(edge_revoke_generation, "generation");
revoke_case!(edge_revoke_wrong_target, "wrong-target");
revoke_case!(edge_revoke_missing_target, "missing-target");
revoke_case!(edge_revoke_proving_revoked, "proving-revoked");
revoke_case!(edge_revoke_cleanup, "cleanup");
revoke_case!(edge_revoke_body_proof, "body-proof");
#[tokio::test]
async fn revoke_status_mutant() {
    run("revoke", "success", true).await.unwrap();
}

register_finish_case!(edge_register_finish_oversized, "oversized");
register_finish_case!(
    edge_register_finish_oversized_unauthenticated,
    "oversized-unauthenticated"
);
register_begin_case!(edge_register_begin_body_proof, "body-proof");

macro_rules! subtree_case {
    ($name:ident,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            run("subtree", $kind, false).await.unwrap();
        }
    };
}
subtree_case!(subtree_success, "success");
subtree_case!(subtree_cross_tenant, "cross-tenant");
subtree_case!(subtree_invalid_input, "invalid-input");
subtree_case!(edge_subtree_head, "head");
#[tokio::test]
async fn subtree_status_mutant() {
    run("subtree", "success", true).await.unwrap();
}

register_finish_case!(edge_register_finish_packed_es256, "packed-es256");
register_finish_case!(edge_register_finish_packed_es384, "packed-es384");
register_finish_case!(edge_register_finish_packed_es512, "packed-es512");
register_finish_case!(edge_register_finish_packed_rs256, "packed-rs256");
register_finish_case!(edge_register_finish_packed_eddsa, "packed-eddsa");
register_finish_case!(edge_register_finish_packed_ps256, "packed-ps256");
register_finish_case!(edge_register_finish_packed_ps384, "packed-ps384");
register_finish_case!(edge_register_finish_packed_ps512, "packed-ps512");

register_finish_case!(edge_register_finish_safetynet, "safetynet");
register_finish_case!(edge_register_finish_malformed_key, "malformed-key");
register_finish_case!(edge_register_finish_extensions, "extensions");
register_finish_case!(edge_register_finish_compound, "compound");

finish_case!(edge_login_finish_backup_eligible, "backup-eligible");
register_finish_case!(edge_register_finish_backup_eligible, "backup-eligible");

register_finish_case!(edge_register_finish_fault_audit, "fault-audit");
register_finish_case!(edge_register_finish_fault_generation, "fault-generation");
register_finish_case!(edge_register_finish_fault_credential, "fault-credential");
register_finish_case!(edge_register_finish_fault_grant, "fault-grant");
register_begin_case!(edge_register_begin_fault_bind, "fault-bind");
revoke_case!(edge_revoke_fault_audit, "fault-audit");
revoke_case!(edge_revoke_fault_generation, "fault-generation");
revoke_case!(edge_revoke_fault_grant, "fault-grant");
finish_case!(edge_login_finish_fault_write, "fault-write");
#[tokio::test]
async fn edge_name_fault_write() {
    run("name", "fault-write", false).await.unwrap();
}

#[tokio::test]
async fn edge_name_noncanonical_id() {
    run("name", "noncanonical-id", false).await.unwrap();
}
#[tokio::test]
async fn edge_name_escaped_id() {
    run("name", "escaped-id", false).await.unwrap();
}
revoke_case!(edge_revoke_noncanonical_id, "noncanonical-id");
revoke_case!(edge_revoke_escaped_id, "escaped-id");
revoke_case!(edge_revoke_fault_write, "fault-write");

finish_case!(edge_login_finish_pending_totp, "pending-totp");
fn issued_pending(
    a: &fixture::Account,
    keys: &setjoin_authz::signing_keys::KeySet,
    fixture: &Value,
    headers: &Value,
    raw: &mut String,
) -> Result<Value, Err> {
    let reply: Value = serde_json::from_str(raw)?;
    assert_eq!(reply["mfa_required"], true);
    assert!(matches!(reply["mfa_method"].as_str(),Some("totp"|"push")));
    assert_eq!(reply["fallback"], if reply["mfa_method"]=="push"{json!(["totp","backup_codes"])}else{json!(["backup_codes"])});
    assert!(headers.get("set-cookie").is_none());
    let token = reply["mfa_token"].as_str().ok_or("pending token")?;
    let legacy = setjoin_authz::legacy_jwt::LegacyKeys::new(
        fixture["secret"].as_str().unwrap().as_bytes(),
        &["authserver-hmac-1"],
        None,
    )?;
    let proof =
        setjoin_identity::session::Session::verify(token, Some(keys), &legacy, "mailserver")
            .ok_or("invalid pending signature")?;
    assert_eq!(proof.user(), a.user);
    assert_eq!(proof.text("typ"), "mfa_pending");
    assert_eq!(proof.text("sub"), a.user.to_string());
    assert!(proof.text("email").starts_with("idmfa2-actor@oracle-"));
    assert_eq!(proof.claims()["amr"], json!(["hwk"]));
    let mut claims = Value::Object(proof.claims().clone());
    let iat = claims["iat"].as_i64().unwrap();
    assert_eq!(claims["nbf"], iat);
    assert!(
        (iat as f64
            - std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs_f64())
        .abs()
            < 10.0
    );
    assert_eq!(claims["exp"].as_i64().unwrap() - iat, 300);
    assert!(proof.text("fam").is_empty());
    claims["uid"] = json!("<actor>");
    claims["sub"] = json!("<actor>");
    claims["email"] = json!("actor@idmfa2.test");
    claims["jti"] = json!("<pending-jti>");
    claims["iat"] = json!(0);
    claims["nbf"] = json!(0);
    claims["exp"] = json!(300);
    *raw = raw.replace(token, "<mfa_token>");
    Ok(claims)
}

finish_case!(edge_login_finish_quoted_cookie, "quoted-cookie");
register_finish_case!(edge_register_finish_quoted_cookie, "quoted-cookie");

register_finish_case!(edge_register_finish_cbor_duplicate, "cbor-duplicate");
register_finish_case!(edge_register_finish_cbor_indefinite, "cbor-indefinite");
register_finish_case!(edge_register_finish_cbor_tag, "cbor-tag");
register_finish_case!(
    edge_register_finish_cbor_indefinite_bytes,
    "cbor-indefinite-bytes"
);
register_finish_case!(
    edge_register_finish_cbor_duplicate_key,
    "cbor-duplicate-key"
);

#[tokio::test]
async fn mutant_login_counter_regression_restores_go_bug(){run_security("login-finish","counter-regression",false,true).await.unwrap();}
#[tokio::test]
async fn mutant_login_assertion_replay_restores_go_bug(){run_security("login-finish","repeat",false,true).await.unwrap();}

async fn push_rows(c:&tokio_postgres::Client,user:i64)->Result<Value,Err>{
    let rows=c.query("SELECT session_id,verified_at IS NOT NULL,failed_attempts,expires_at>now() FROM push_mfa_challenges WHERE user_id=$1 ORDER BY id",&[&user]).await?;
    Ok(json!(rows.iter().map(|r|json!({"session":r.get::<_,String>(0),"verified":r.get::<_,bool>(1),"failures":r.get::<_,i32>(2),"live":r.get::<_,bool>(3)})).collect::<Vec<_>>()))
}
finish_case!(login_finish_pending_push,"pending-push");
finish_case!(login_finish_pending_push_only,"pending-push-only");
finish_case!(login_finish_pending_push_limit,"pending-push-limit");
finish_case!(login_finish_pending_push_only_limit,"pending-push-only-limit");
