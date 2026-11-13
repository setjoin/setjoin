//! #333 native Drive credential: actual front door, frozen Go wire authority.
mod common;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use common::BoxError;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    Body, BoxFuture, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use std::sync::Arc;
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
struct Server {
    addr: std::net::SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    async fn close(mut self) {
        let _ = self.stop.take().unwrap().send(());
        let _ = (&mut self.task).await;
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct StatusMutant<R>(R);
impl<R: Intercept> Intercept for StatusMutant<R> {
    fn requires_session(&self,r:&Request<Body>) -> bool {
        self.0.requires_session(r)
    }
    fn matches(&self, r: &Request<Body>) -> bool {
        self.0.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.0.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let f = self.0.handle(r, c);
        Box::pin(async move {
            let mut r = f.await;
            *r.status_mut() = hyper::StatusCode::from_u16(599).unwrap();
            r
        })
    }
}
async fn native_routes(
    exec: setjoin_pg::ScopedExecutor,
    keys: Arc<setjoin_authz::jwks::Jwks>,
    secret: &str,
    mutant: bool,
) -> RouteTable {
    let chain = Arc::new(setjoin_authz::auth_chain::Chain::default());
    chain.reload(&exec).await.unwrap();
    let route = setjoin_gateway::drive_native::NativeTokenRoute::new(
        exec.clone(),
        keys.clone(),
        "mailserver".into(),
        Some(secret),
    )
    .with_chain(Some(chain));
    let routes = if mutant {
        RouteTable::proxy_all().with(StatusMutant(route))
    } else {
        RouteTable::proxy_all().with(route)
    };
    routes.with(setjoin_gateway::drive::core::CoreRoute {
        exec: exec.clone(),
        worker: exec,
        keys,
        issuer: "mailserver".into(),
        store: None,
    })
}
async fn start(upstream: Option<std::net::SocketAddr>, routes: RouteTable) -> Server {
    let mut inv: Value = serde_json::from_str(setjoin_gateway::inventory::BUNDLED).unwrap();
    for r in inv["routes"].as_array_mut().unwrap() {
        if r["path"] == "/drive/native-token" || (upstream.is_some() && r["family"] == "F14") {
            r["state"] = json!(if upstream.is_some() { "OFF" } else { "ON" });
            r["upstream"] = json!(if upstream.is_some() {
                "go-mail"
            } else {
                "local-rust"
            });
        }
    }
    let gateway = Gateway::new(
        setjoin_gateway::Config {
            upstream: upstream.map(|a| format!("http://{a}").parse().unwrap()),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: std::time::Duration::from_secs(30),
            edge_limit: Some(setjoin_gateway::jmap::limit::EdgeLimit::for_front_door(
                setjoin_gateway::jmap::limit::Limiter::new(60000, 60),
            )),
        },
        routes,
    )
    .unwrap()
    .with_inventory(&inv.to_string())
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(gateway.serve_until(listener, async {
        let _ = rx.await;
    }));
    Server {
        addr,
        stop: Some(tx),
        task,
    }
}
#[allow(dead_code)]
async fn wire(
    addr: std::net::SocketAddr,
    path: &str,
    token: &str,
    payload: &str,
) -> Result<(u16, Value, String), BoxError> {
    wire_method(addr, "POST", path, token, payload).await
}
async fn wire_method(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    token: &str,
    payload: &str,
) -> Result<(u16, Value, String), BoxError> {
    wire_case(addr, method, path, token, payload, "").await
}
async fn wire_case(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    token: &str,
    payload: &str,
    kind: &str,
) -> Result<(u16, Value, String), BoxError> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "mail.idlogin3.test")
        .header(
            "origin",
            if kind == "csrf" {
                "https://evil.test"
            } else {
                "http://mail.idlogin3.test"
            },
        )
        .header("content-type", "application/json");
    if kind == "basic-disabled" {
        request = request.header("authorization", "Basic dXNlcjpwYXNzd29yZA==");
    } else if kind == "cookie" {
        request = request.header("cookie", format!("access_token=\"{token}\""));
    } else {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = common::send(addr, request.body(common::full(payload.to_owned()))?).await;
    let status = response.status().as_u16();
    let mut headers = serde_json::Map::new();
    for name in [
        "content-type",
        "cache-control",
        "www-authenticate",
        "x-content-type-options",
    ] {
        if let Some(v) = response.headers().get(name) {
            headers.insert(name.into(), json!(v.to_str()?));
        }
    }
    let raw = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
    Ok((status, json!(headers), raw))
}
fn observe(
    raw: &mut String,
    secret: &str,
    user: i64,
    email: &str,
    source: &Value,
    now: i64,
    source_expiry: i64,
    label: &str,
) -> Result<(Option<Value>, Option<Value>), BoxError> {
    let mut issued = None;
    let mut header = None;
    if let Ok(v) = serde_json::from_str::<Value>(&raw) {
        if let Some(token) = v["token"].as_str() {
            let verifier = setjoin_authz::legacy_jwt::LegacyKeys::new(
                secret.as_bytes(),
                &["mailserver-drive-native-1"],
                None,
            )?;
            let mut c = Value::Object(
                verifier
                    .validate(token, "mailserver", "mailserver-gateway", now as f64)
                    .ok_or("invalid scoped token signature")?,
            );
            let h: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').next().unwrap())?)?;
            if c["uid"] != user
                || c["email"] != email
                || c["typ"] != "access"
                || c["scp"] != "drive"
                || c["jti"] != source["jti"]
                || c["fam"] != source["fam"]
            {
                return Err("scoped token did not inherit the proven source".into());
            }
            let expiry = c["exp"].as_i64().ok_or("missing expiry")?;
            let iat = c["iat"].as_i64().ok_or("missing iat")?;
            if expiry != source_expiry.min(iat + 43200) || !(now..=now + 30).contains(&iat) {
                return Err("derived token outlived source or has wrong issue time".into());
            }
            let expires = v["expiresAt"].as_str().ok_or("missing expiresAt")?;
            if chrono::DateTime::parse_from_rfc3339(expires)?.timestamp() != expiry {
                return Err("wire expiry disagrees with token".into());
            }
            *raw = raw
                .replace(token, "<verified-scoped-token>")
                .replace(expires, "<timestamp>");
            c["uid"] = json!(label);
            c["email"] = json!(if label == "<foreign>" {
                "foreign@idlogin3.test"
            } else {
                "actor@idlogin3.test"
            });
            c["iat"] = json!("<timestamp>");
            if c.get("act").is_some() {
                c["act"] = json!("<acting-admin>");
            }
            c["exp"] = json!(if expiry == source_expiry {
                "<source-expiry>"
            } else {
                "<12-hour-cap>"
            });
            issued = Some(c);
            header = Some(h);
        }
    }
    Ok((issued, header))
}
async fn run(kind: &str, mutant: bool) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDLOGIN3-Drive").expect("assigned DB required");
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    let a = fixture::account(&c, "idlogin3-drive-a").await?;
    let b = fixture::account(&c, "idlogin3-drive-b").await?;
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    let (source_user, source_email, label) = if kind == "cross-tenant" {
        (
            b.user,
            c.query_one("SELECT email FROM users WHERE id=$1", &[&b.user])
                .await?
                .get::<_, String>(0),
            "<foreign>",
        )
    } else {
        (a.user, email.clone(), "<actor>")
    };
    if kind == "revoked" {
        c.execute("INSERT INTO session_revocations(user_id,scope,jti,reason,not_before,expires_at) VALUES($1,'jti','idlogin3-drive-source','fixture',now(),now()+interval '1 hour')",&[&a.user]).await?;
    }
    let basic = if kind == "basic-disabled" {
        let old = c
            .query_opt(
                "SELECT enabled FROM feature_toggles WHERE key='feature.disable_basic_auth'",
                &[],
            )
            .await?
            .map(|r| r.get::<_, bool>(0));
        c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.disable_basic_auth',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await?;
        Some(old)
    } else {
        None
    };
    let flag = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.drive'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.drive',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await?;
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let secret = f["secret"].as_str().unwrap();
    let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
    let go = common::go_oracle::start_unscoped_with_env(
        &db,
        s3,
        "gofree-idlogin3-drive",
        &[("JWT_SECRET", secret.to_owned())],
    )
    .await?;
    if mutant && go.is_some() {
        return Err("mutants cannot record".into());
    }
    let jwks = common::fake_upstream(|_| async {
        Response::builder()
            .header("content-type", "application/json")
            .body(common::full(
                include_bytes!("../../../tests/conformance/jmap/test-jwks.json").as_slice(),
            ))
            .unwrap()
    })
    .await;
    let keys = Arc::new(
        setjoin_authz::jwks::Jwks::new(format!("http://{jwks}/.well-known/jwks.json").parse()?)?
            .with_legacy_keys(setjoin_authz::legacy_jwt::LegacyKeys::new(
                secret.as_bytes(),
                &["authserver-hmac-1", "mailserver-drive-native-1"],
                None,
            )?),
    );
    let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?;
    let server = start(
        go.as_ref().map(|g| g.address),
        native_routes(exec.clone(), keys.clone(), secret, mutant).await,
    )
    .await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let source_expiry = if kind == "twelve-hour" {
        now + 86400
    } else if kind == "expired" {
        now - 1
    } else {
        now + 3600
    };
    let mut claims = json!({"uid":source_user,"email":source_email,"typ":"access","jti":"idlogin3-drive-source","fam":"33300000-0000-4000-8000-000000000001","iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"nbf":now,"exp":source_expiry,"amr":["pwd"],"acr":"aal1"});
    match kind {
        "wrong-type" => claims["typ"] = json!("refresh"),
        "reset-token" => claims["typ"] = json!("password_reset"),
        "force-change" => claims["typ"] = json!("force_pw_change"),
        "device" => claims["device"] = json!({"id":"device-fingerprint"}),
        "empty-device" => claims["device"] = json!({}),
        "actor" => claims["act"] = json!(b.user),
        "no-iat" => {
            claims.as_object_mut().unwrap().remove("iat");
        }
        "no-family" => {
            claims.as_object_mut().unwrap().remove("fam");
        }
        "no-jti" => {
            claims.as_object_mut().unwrap().remove("jti");
        }
        "other-scope" => claims["scp"] = json!("mail-attachment"),
        _ => {}
    }
    let mut token = setjoin_authz::legacy_jwt::sign_hs256(secret.as_bytes(), &claims.to_string());
    if kind == "invalid-token" {
        token = "not-a-token".into();
    }
    let payload = if kind == "invalid-input" {
        "{not-json".into()
    } else {
        json!({"user_id":if kind=="cross-tenant"{a.user}else{b.user},"lifetime":99999999})
            .to_string()
    };
    let result=async{
  if kind=="interchange" {
    // The first credential is always minted by Rust, including Go recording.
    let native=start(None,native_routes(exec.clone(),keys.clone(),secret,false).await).await;
    let(_,_,mut raw)=wire(native.addr,"/api/drive/native-token",&token,&payload).await?;
    token=serde_json::from_str::<Value>(&raw)?["token"].as_str().ok_or("Rust mint missing token")?.to_owned();
    observe(&mut raw,secret,source_user,&source_email,&claims,now,source_expiry,label)?;
    native.close().await;
  }
  let before=c.query_one("SELECT (SELECT count(*) FROM sessions WHERE user_id=ANY($1::bigint[])),(SELECT count(*) FROM oauth_tokens WHERE user_id=ANY($1::bigint[])),(SELECT jsonb_agg(to_jsonb(k))::text FROM signing_keys k)",&[&vec![a.user,b.user]]).await?;
  let first=if kind=="renewal" {
    let(status,headers,mut raw)=wire_case(server.addr,"POST","/api/drive/native-token",&token,&payload,kind).await?;
    token=serde_json::from_str::<Value>(&raw)?["token"].as_str().ok_or("first mint missing token")?.to_owned();
    let(c,h)=observe(&mut raw,secret,source_user,&source_email,&claims,now,source_expiry,label)?;
    Some(json!({"response":{"status":status,"headers":headers,"body":raw},"issued_claims":c,"issued_header":h}))
  }else{None};
  let(status,headers,mut raw)=wire_case(server.addr,"POST","/api/drive/native-token",&token,&payload,kind).await?;
  let usage=if kind=="usage" {
    let scoped=serde_json::from_str::<Value>(&raw)?["token"].as_str().ok_or("missing minted credential")?.to_owned();
    let(status,headers,body)=wire_method(server.addr,"GET","/api/drive/spaces/bad/tree",&scoped,"").await?;
    let outside=if go.is_some(){wire_method(server.addr,"GET","/api/user/quota",&scoped,"").await?.0<400}else{setjoin_authz::token::verify(&scoped,"mailserver",now as f64,&*keys).await.is_some()};
    Some(json!({"drive_response":{"status":status,"headers":headers,"body":body},"outside_scope_admitted":outside}))
  }else{None};
  let (issued,header)=observe(&mut raw,secret,source_user,&source_email,&claims,now,source_expiry,label)?;
  if !mutant && kind=="success" && status!=200{return Err(format!("Go/native tracer returned {status}: {raw}").into());}
  let after=c.query_one("SELECT (SELECT count(*) FROM sessions WHERE user_id=ANY($1::bigint[])),(SELECT count(*) FROM oauth_tokens WHERE user_id=ANY($1::bigint[])),(SELECT jsonb_agg(to_jsonb(k))::text FROM signing_keys k)",&[&vec![a.user,b.user]]).await?;
  for index in 0..2 {if before.get::<_,i64>(index)!=after.get::<_,i64>(index){return Err("mint changed session/token rows".into());}}
  if before.get::<_,Option<String>>(2)!=after.get::<_,Option<String>>(2){return Err("mint rotated signing keys".into());}
  let mut doc=json!({"format":1,"go_source":"d431c0ecdbb362809c3fdba781a395712612bf61","route":"POST /drive/native-token","case":format!("drive-native-{kind}"),"observation":{"request":{"method":"POST","path":"/drive/native-token","body":payload.replace(&format!("\"user_id\":{}",b.user),"\"user_id\":\"<foreign>\"").replace(&format!("\"user_id\":{}",a.user),"\"user_id\":\"<actor>\"")},"response":{"status":status,"headers":headers,"body":raw},"effects":[],"audit":[],"notify":[]}});
  if let Some(usage)=usage{doc["observation"]["usage"]=usage;}
  if let Some(first)=first{doc["observation"]["first_mint"]=first;}
  if let Some(c)=issued{doc["observation"]["issued_claims"]=c;doc["observation"]["issued_header"]=header.unwrap();}
  let file=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/identity-token/goldens/drive-native-{kind}.json"));
  if go.is_some()&&!file.exists(){golden::record(&file,&doc)?;}
  let expected:Value=if kind=="actor"{common::security_expected(file.parent().unwrap().parent().unwrap(),&file,&doc)}else{serde_json::from_str(&std::fs::read_to_string(file)?)?};if mutant{let error=golden::compare(&expected,&doc).err().ok_or("status mutant survived")?;if !error.contains("/observation/response/status"){return Err(format!("wrong mutant rejection: {error}").into());}println!("MUTANT-REJECTED: POST /drive/native-token :: status");}else{golden::compare(&expected,&doc)?;}
  if go.is_none(){let response=common::send(server.addr,Request::builder().uri("/_gateway/metrics").body(common::full(""))?).await;let text=String::from_utf8(common::body_bytes(response).await.to_vec())?;if !text.contains("setjoin_gateway_proxied_to_go_total 0"){return Err("native replay used Go".into());}}
  println!("GOLDEN-REPLAY: POST /drive/native-token :: drive-native-{kind}");Ok::<(),BoxError>(())
 }.await;
    server.close().await;
    drop(go);
    if let Some(on) = flag {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.drive'",
            &[&on],
        )
        .await?;
    } else {
        c.execute("DELETE FROM feature_toggles WHERE key='feature.drive'", &[])
            .await?;
    }
    c.execute(
        "DELETE FROM session_revocations WHERE user_id=ANY($1::bigint[])",
        &[&vec![a.user, b.user]],
    )
    .await?;
    if let Some(old) = basic {
        if let Some(on) = old {
            c.execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.disable_basic_auth'",
                &[&on],
            )
            .await?;
        } else {
            c.execute(
                "DELETE FROM feature_toggles WHERE key='feature.disable_basic_auth'",
                &[],
            )
            .await?;
        }
    }
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    result
}
#[tokio::test]
async fn drive_native_success() {
    run("success", false).await.unwrap();
}

#[tokio::test]
async fn drive_native_renewal() {
    run("renewal", false).await.unwrap();
}

#[tokio::test]
async fn drive_native_usage() {
    run("usage", false).await.unwrap();
}

#[tokio::test]
async fn drive_native_status_mutant() {
    run("success", true).await.unwrap();
}
#[tokio::test]
async fn drive_native_cross_tenant() {
    run("cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_invalid_input() {
    run("invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_twelve_hour() {
    run("twelve-hour", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_expired() {
    run("expired", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_wrong_type() {
    run("wrong-type", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_reset_token() {
    run("reset-token", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_force_change() {
    run("force-change", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_invalid_token() {
    run("invalid-token", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_cookie() {
    run("cookie", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_device() {
    run("device", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_empty_device() {
    run("empty-device", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_actor() {
    run("actor", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_no_iat() {
    run("no-iat", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_no_family() {
    run("no-family", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_no_jti() {
    run("no-jti", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_other_scope() {
    run("other-scope", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_revoked() {
    run("revoked", false).await.unwrap();
}
#[tokio::test]
async fn drive_native_csrf() {
    run("csrf", false).await.unwrap();
}

#[tokio::test]
async fn drive_native_interchange() {
    run("interchange", false).await.unwrap();
}

#[tokio::test]
async fn drive_native_basic_disabled() {
    run("basic-disabled", false).await.unwrap();
}
