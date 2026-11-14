//! #356a: HS256/SM2 credentials on the push seams (GET /jmap/ws,
//! GET /jmap/eventsource, GET /api/chat/presence) are verified natively.
//! Frozen Go is recorded once per CRYPTO_ALGORITHM_PROFILE; native replay has
//! no Go upstream and must report zero Go proxies. Native-only tests prove
//! revocation and live eviction for legacy tokens and a missing-key mutant.
mod common;
use common::BoxError;
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::jmap::{
    jwks::Jwks, presence::PresenceRoute, push::WebSocketRoute, sse::EventSourceRoute, JmapCommands,
};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The frozen-Go oracle's JWT_SECRET (`common/go_oracle.rs`).
const SECRET: &str = "blobs1-test-jwt-secret-for-recording";
const OTHER_SECRET: &str = "push-profiles-unrelated-secret-of-32-bytes";
/// `main.rs`'s configured HMAC kids: Go's kidHMAC and kidDriveNative.
const KIDS: [&str; 2] = ["authserver-hmac-1", "mailserver-drive-native-1"];
const PROFILES: [&str; 3] = ["standard", "hybrid", "smx"];

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Clone, Copy)]
enum Via {
    Ws,
    Sse,
    Presence,
}

fn recording() -> bool {
    std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn claims(user: i64, extra: Value) -> Value {
    let now = now();
    let mut claims = json!({"uid":user,"email":"x@test","typ":"access","jti":"push-profiles","fam":"push-profiles","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600});
    if let (Some(map), Some(more)) = (claims.as_object_mut(), extra.as_object()) {
        map.extend(more.clone());
    }
    claims
}

fn hs256_raw(secret: &[u8], header: &str, claims: &Value) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let signed = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(ring::hmac::sign(&key, signed.as_bytes()).as_ref())
    )
}

fn hs256(secret: &[u8], kid: &str, claims: &Value) -> String {
    hs256_raw(
        secret,
        &json!({"alg":"HS256","kid":kid,"typ":"JWT"}).to_string(),
        claims,
    )
}

fn unsigned(claims: &Value) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

fn identity_keys() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap()
}

/// The fixture SM2 public point as bytes (HMAC-key confusion probe).
fn sm2_point() -> Vec<u8> {
    let s = identity_keys()["sm2_point"].as_str().unwrap().to_owned();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The test JWKS ES256 public point (04 || x || y).
fn es256_point() -> Vec<u8> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let jwks: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/jmap/test-jwks.json"
    ))
    .unwrap();
    let mut point = vec![4u8];
    for c in ["x", "y"] {
        point.extend(
            URL_SAFE_NO_PAD
                .decode(jwks["keys"][0][c].as_str().unwrap())
                .unwrap(),
        );
    }
    point
}

/// SEC1 private key d = 1: a valid SM2 key that is not the configured one.
fn foreign_sm2_pem() -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut der = vec![0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
    der.extend_from_slice(&[0u8; 31]);
    der.push(1);
    format!(
        "-----BEGIN EC PRIVATE KEY-----\n{}\n-----END EC PRIVATE KEY-----\n",
        STANDARD.encode(der)
    )
}

fn cases(user: i64, pem: &str) -> Result<Vec<(&'static str, Via, String)>, BoxError> {
    let secret = SECRET.as_bytes();
    let base = claims(user, json!({}));
    let sm2 = setjoin_authz::legacy_jwt::sign_sm2(pem, &base.to_string())?;
    let mut missing_iat = base.clone();
    missing_iat
        .as_object_mut()
        .ok_or("claims object")?
        .remove("iat");
    let with = |extra: Value| hs256(secret, KIDS[0], &claims(user, extra));
    Ok(vec![
        ("ws-hs256", Via::Ws, hs256(secret, KIDS[0], &base)),
        ("ws-sm2", Via::Ws, sm2.clone()),
        ("sse-hs256", Via::Sse, hs256(secret, KIDS[0], &base)),
        ("sse-sm2", Via::Sse, sm2.clone()),
        (
            "presence-hs256",
            Via::Presence,
            hs256(secret, KIDS[0], &base),
        ),
        ("presence-sm2", Via::Presence, sm2),
        (
            "ws-hs256-drive-native-kid",
            Via::Ws,
            hs256(secret, KIDS[1], &base),
        ),
        (
            "sse-hs256-drive-native-scoped",
            Via::Sse,
            hs256(secret, KIDS[1], &claims(user, json!({"scp":"drive"}))),
        ),
        (
            "ws-hs256-retired-kid",
            Via::Ws,
            hs256(secret, "mailserver-hmac-1", &base),
        ),
        (
            "ws-hs256-wrong-secret",
            Via::Ws,
            hs256(OTHER_SECRET.as_bytes(), KIDS[0], &base),
        ),
        ("ws-alg-none", Via::Ws, unsigned(&base)),
        ("sse-hs256-expired", Via::Sse, with(json!({"exp":1}))),
        (
            "sse-hs256-refresh",
            Via::Sse,
            with(json!({"typ":"refresh"})),
        ),
        (
            "sse-hs256-guest-claim-without-row",
            Via::Sse,
            with(json!({"acct":"guest"})),
        ),
        // F3: claim separation from other first-party token types and audiences.
        (
            "sse-hs256-wrong-aud",
            Via::Sse,
            with(json!({"aud":["other-audience"]})),
        ),
        (
            "sse-hs256-wrong-iss",
            Via::Sse,
            with(json!({"iss":"other-issuer"})),
        ),
        (
            "sse-hs256-missing-iat",
            Via::Sse,
            hs256(secret, KIDS[0], &missing_iat),
        ),
        (
            "sse-hs256-mfa-pending",
            Via::Sse,
            with(json!({"typ":"mfa_pending"})),
        ),
        (
            "sse-hs256-force-pw-change",
            Via::Sse,
            with(json!({"typ":"force_pw_change"})),
        ),
        (
            "sse-hs256-password-reset",
            Via::Sse,
            with(json!({"typ":"password_reset"})),
        ),
        (
            "sse-hs256-nbf-future",
            Via::Sse,
            with(json!({"nbf":now() + 300})),
        ),
        // F4: key confusion.
        (
            "sse-sm2-foreign-key",
            Via::Sse,
            setjoin_authz::legacy_jwt::sign_sm2(&foreign_sm2_pem(), &base.to_string())?,
        ),
        (
            "ws-hs256-keyed-with-sm2-point",
            Via::Ws,
            hs256(&sm2_point(), KIDS[0], &base),
        ),
        (
            "ws-hs256-keyed-with-es256-point",
            Via::Ws,
            hs256(&es256_point(), "test-es256-1", &base),
        ),
        (
            "sse-hs256-duplicate-alg-last-hs256",
            Via::Sse,
            hs256_raw(
                secret,
                r#"{"alg":"ES256","alg":"HS256","kid":"authserver-hmac-1","typ":"JWT"}"#,
                &base,
            ),
        ),
        (
            "sse-hs256-duplicate-alg-last-es256",
            Via::Sse,
            hs256_raw(
                secret,
                r#"{"alg":"HS256","alg":"ES256","kid":"authserver-hmac-1","typ":"JWT"}"#,
                &base,
            ),
        ),
    ])
}

/// The same legacy material `main.rs` installs for a profile.
fn native_keys(profile: &str, pem: &str) -> Result<Jwks, BoxError> {
    let sm2 = matches!(profile, "smx" | "hybrid").then_some(pem);
    Ok(
        common::recovery_keys().with_legacy_keys(setjoin_authz::legacy_jwt::LegacyKeys::from_pem(
            SECRET.as_bytes(),
            &KIDS,
            sm2,
        )?),
    )
}

fn native_routes(db: &Db, keys: Jwks) -> Result<RouteTable, BoxError> {
    let commands = Arc::new(JmapCommands {
        services: None,
        exec: common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?,
        worker: None,
        keys,
        issuer: "mailserver".into(),
        denylist: None,
    });
    let ws = WebSocketRoute::new(commands, db.direct.clone());
    let presence = PresenceRoute {
        commands: ws.commands.clone(),
        registry: ws.registry.clone(),
    };
    let sse = EventSourceRoute::new(&ws);
    Ok(RouteTable::proxy_all().with(sse).with(ws).with(presence))
}

struct Served(tokio::task::AbortHandle, SocketAddr);
impl Drop for Served {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn serve(upstream: Option<SocketAddr>, routes: RouteTable) -> Result<Served, BoxError> {
    let gateway = Gateway::new(
        Config {
            upstream: upstream.map(|a| format!("http://{a}").parse().unwrap()),
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: Duration::from_secs(30),
            edge_limit: None,
        },
        routes,
    )?
    .with_inventory(include_str!("../route-inventory.json"))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(gateway.serve(listener));
    Ok(Served(server.abort_handle(), address))
}

fn kept_headers<'a>(pairs: impl Iterator<Item = (&'a str, &'a [u8])>) -> Value {
    let mut out = serde_json::Map::new();
    for (name, value) in pairs {
        if matches!(
            name,
            "date" | "content-length" | "x-request-id" | "connection" | "transfer-encoding"
        ) {
            continue;
        }
        out.insert(name.to_owned(), json!(String::from_utf8_lossy(value)));
    }
    Value::Object(out)
}

async fn ready_reply(socket: &mut Socket) -> Result<String, BoxError> {
    socket
        .send(Message::Text(r#"{"@type":"ready"}"#.into()))
        .await?;
    loop {
        match tokio::time::timeout(Duration::from_secs(10), socket.next())
            .await?
            .ok_or("socket ended")??
        {
            Message::Text(text) => return Ok(text.to_string()),
            Message::Ping(_) | Message::Pong(_) => socket.flush().await?,
            other => return Err(format!("unexpected frame {other:?}").into()),
        }
    }
}

async fn websocket(address: SocketAddr, token: &str) -> Result<Value, BoxError> {
    let mut request = format!("ws://{address}/jmap/ws").into_client_request()?;
    request
        .headers_mut()
        .insert("cookie", format!("access_token={token}").parse()?);
    let connected = tokio::time::timeout(
        Duration::from_secs(30),
        tokio_tungstenite::connect_async(request),
    )
    .await?;
    match connected {
        Ok((mut socket, response)) => {
            let status = response.status().as_u16();
            let frame = ready_reply(&mut socket).await?;
            let _ = socket.close(None).await;
            Ok(json!({"status":status,"frame":frame}))
        }
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            let body = String::from_utf8(response.body().clone().unwrap_or_default())?;
            let headers = kept_headers(
                response
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_bytes())),
            );
            Ok(json!({"status":response.status().as_u16(),"headers":headers,"body":body}))
        }
        Err(error) => Err(error.into()),
    }
}

async fn eventsource(address: SocketAddr, token: &str, mailbox: i64) -> Result<Value, BoxError> {
    let response = common::send(
        address,
        Request::builder()
            .uri(format!(
                "http://{address}/jmap/eventsource?closeafter=state"
            ))
            .header("authorization", format!("Bearer {token}"))
            .body(common::full(""))?,
    )
    .await;
    let status = response.status().as_u16();
    let headers = kept_headers(
        response
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_bytes())),
    );
    let bytes = tokio::time::timeout(Duration::from_secs(15), response.into_body().collect())
        .await??
        .to_bytes();
    let body =
        String::from_utf8(bytes.to_vec())?.replace(&format!("\"{mailbox}\""), "\"<mailbox>\"");
    Ok(json!({"status":status,"headers":headers,"body":body}))
}

async fn presence(address: SocketAddr, token: &str) -> Result<Value, BoxError> {
    let response = common::send(
        address,
        Request::builder()
            .uri(format!("http://{address}/api/chat/presence?userIds=0"))
            .header("authorization", format!("Bearer {token}"))
            .body(common::full(""))?,
    )
    .await;
    let status = response.status().as_u16();
    let headers = kept_headers(
        response
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_bytes())),
    );
    let bytes = tokio::time::timeout(Duration::from_secs(15), response.into_body().collect())
        .await??
        .to_bytes();
    Ok(json!({"status":status,"headers":headers,"body":String::from_utf8(bytes.to_vec())?}))
}

async fn assert_zero_proxy(address: SocketAddr) -> Result<(), BoxError> {
    let response = common::send(
        address,
        Request::builder()
            .uri(format!("http://{address}/_gateway/metrics"))
            .body(common::full(""))?,
    )
    .await;
    let metrics = String::from_utf8(common::body_bytes(response).await.to_vec())?;
    if !metrics.contains("setjoin_gateway_proxied_to_go_total 0\n") {
        return Err(format!("native push profile used Go: {metrics}").into());
    }
    Ok(())
}

fn corpus(profile: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/conformance/jmap/push-profiles/{profile}.json"
    ))
}

fn check(
    profile: &str,
    recording: bool,
    cases: serde_json::Map<String, Value>,
) -> Result<(), BoxError> {
    let path = corpus(profile);
    if recording {
        if path.exists() {
            return Err(format!("immutable corpus already exists: {}", path.display()).into());
        }
        setjoin_conformance::golden::record(
            &path,
            &json!({"format":1,"routes":["GET /jmap/ws","GET /jmap/eventsource","GET /api/chat/presence"],
                "profile":profile,"go_source":std::env::var("GOFREE_GO_SOURCE")?,
                "normalization":["fixture mailbox id"],"cases":cases}),
        )?;
        return Ok(());
    }
    let expected: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    setjoin_conformance::golden::compare(&expected["cases"], &Value::Object(cases))?;
    println!("GOLDEN-REPLAY: push legacy profiles :: {profile}");
    Ok(())
}

struct SecretFile(std::path::PathBuf);
impl SecretFile {
    fn sm2() -> Result<Self, BoxError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::env::temp_dir().join(format!(
            "gofree-pushprof-sm2-{}-{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        if let Ok(ledger) = std::env::var("GOFREE_RESOURCE_LEDGER") {
            writeln!(
                std::fs::OpenOptions::new().append(true).open(ledger)?,
                "Plan owned fixture SM2 PEM {} (delete on drop)",
                path.display()
            )?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(identity_keys()["sm2_pem"].as_str().unwrap().as_bytes())?;
        Ok(Self(path))
    }
}
impl Drop for SecretFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn chat_on(owner: &tokio_postgres::Client) -> Result<bool, BoxError> {
    let saved: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.chat'",
            &[],
        )
        .await?
        .get(0);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=true WHERE key='feature.chat'",
            &[],
        )
        .await?;
    Ok(saved)
}

#[tokio::test]
async fn legacy_profiles_match_frozen_go() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("push-profiles") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "pushprof").await?;
    let saved_chat = chat_on(&owner).await?;
    let result = async {
        let key = SecretFile::sm2()?;
        let pem = std::fs::read_to_string(&key.0)?;
        for profile in PROFILES {
            let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
            let go_env = vec![
                ("CRYPTO_ALGORITHM_PROFILE", profile.to_owned()),
                ("SM2_PRIVATE_KEY_FILE", "/run/pushprof-sm2.pem".to_owned()),
                (
                    "--volume",
                    format!("{}:/run/pushprof-sm2.pem:ro", key.0.display()),
                ),
            ];
            let oracle =
                common::go_oracle::start_named_with_env(&db, s3, "gofree-pushprof", &go_env)
                    .await?;
            let recording = oracle.is_some();
            let routes = if recording {
                RouteTable::proxy_all()
            } else {
                native_routes(&db, native_keys(profile, &pem)?)?
            };
            let served = serve(oracle.as_ref().map(|o| o.address), routes).await?;
            let address = served.1;
            let mut observed = serde_json::Map::new();
            for (name, via, token) in cases(account.user, &pem)? {
                let value = match via {
                    Via::Ws => websocket(address, &token).await?,
                    Via::Sse => eventsource(address, &token, account.mailbox).await?,
                    Via::Presence => presence(address, &token).await?,
                };
                observed.insert(name.to_owned(), value);
            }
            if !recording {
                assert_zero_proxy(address).await?;
            }
            drop(served);
            drop(oracle);
            check(profile, recording, observed)?;
        }
        Ok::<_, BoxError>(())
    }
    .await;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.chat'",
            &[&saved_chat],
        )
        .await?;
    fixture::remove(&owner, &account).await?;
    result
}

async fn open_websocket(address: SocketAddr, token: &str) -> Result<Socket, BoxError> {
    let mut request = format!("ws://{address}/jmap/ws").into_client_request()?;
    request
        .headers_mut()
        .insert("cookie", format!("access_token={token}").parse()?);
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await?;
    ready_reply(&mut socket).await?;
    Ok(socket)
}

async fn websocket_revoked(socket: &mut Socket) -> Result<(), BoxError> {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), socket.next()).await? {
            Some(Ok(Message::Text(text))) if text.contains("SessionRevoked") => break,
            Some(Ok(Message::Text(_) | Message::Ping(_) | Message::Pong(_))) => continue,
            other => return Err(format!("socket ended without SessionRevoked: {other:?}").into()),
        }
    }
    match tokio::time::timeout(Duration::from_secs(5), socket.next()).await? {
        None | Some(Err(_)) | Some(Ok(Message::Close(_))) => Ok(()),
        other => Err(format!("revoked socket stayed open: {other:?}").into()),
    }
}

async fn open_eventsource(
    address: SocketAddr,
    token: &str,
) -> Result<hyper::body::Incoming, BoxError> {
    let response = common::send(
        address,
        Request::builder()
            .uri(format!("http://{address}/jmap/eventsource?closeafter=no"))
            .header("authorization", format!("Bearer {token}"))
            .body(common::full(""))?,
    )
    .await;
    if response.status() != 200 {
        return Err(format!("SSE open failed: {}", response.status()).into());
    }
    let mut body = response.into_body();
    let mut buffer = Vec::new();
    while !buffer.windows(2).any(|b| b == b"\n\n") {
        let frame = tokio::time::timeout(Duration::from_secs(15), body.frame())
            .await?
            .ok_or("SSE ended before its first event")??;
        if let Ok(data) = frame.into_data() {
            buffer.extend_from_slice(&data);
        }
    }
    Ok(body)
}

async fn eventsource_ends(body: &mut hyper::body::Incoming) -> Result<(), BoxError> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match body.frame().await {
                None | Some(Err(_)) => return,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await
    .map_err(|_| "revoked SSE stream stayed open".into())
}

/// F2: revocation and live eviction for natively verified HS256 and SM2
/// (hybrid profile). Native only: the path is the ES256 one, now reached by
/// legacy tokens.
#[tokio::test]
async fn legacy_tokens_honour_revocation_and_eviction() -> Result<(), BoxError> {
    if recording() {
        return Ok(());
    }
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("push-profiles-revocation") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "pushprofrev").await?;
    let saved_chat = chat_on(&owner).await?;
    let user = account.user;
    let result = async {
        let pem = identity_keys()["sm2_pem"].as_str().unwrap().to_owned();
        let served = serve(None, native_routes(&db, native_keys("hybrid", &pem)?)?).await?;
        let address = served.1;
        let base = claims(user, json!({}));
        let tokens = [
            ("hs256", hs256(SECRET.as_bytes(), KIDS[0], &base)),
            ("sm2", setjoin_authz::legacy_jwt::sign_sm2(&pem, &base.to_string())?),
        ];
        for (alg, token) in &tokens {
            if websocket(address, token).await?["status"] != 101 {
                return Err(format!("{alg}: control handshake was not accepted").into());
            }
            for scope in ["jti", "family", "all"] {
                let jti = (scope == "jti").then_some("push-profiles");
                let family = (scope == "family").then_some("push-profiles");
                owner.execute("INSERT INTO session_revocations(user_id,scope,reason,jti,family_id,not_before,expires_at) VALUES($1,$2,'pushprof',$3,$4,now(),now()+interval '10 minutes')",&[&user,&scope,&jti,&family]).await?;
                let ws = websocket(address, token).await?;
                let sse = eventsource(address, token, account.mailbox).await?;
                let presence = presence(address, token).await?;
                owner
                    .execute("DELETE FROM session_revocations WHERE user_id=$1", &[&user])
                    .await?;
                if ws["status"] != 401
                    || ws["body"] != "invalid token\n"
                    || sse["status"] != 401
                    || sse["body"] != "invalid token\n"
                    || presence["status"] != 401
                {
                    return Err(format!(
                        "{alg} scope={scope}: revocation not honoured: {ws} {sse} {presence}"
                    )
                    .into());
                }
            }
            // An open WS and SSE stream are evicted when the revocation lands.
            let mut socket = open_websocket(address, token).await?;
            let mut stream = open_eventsource(address, token).await?;
            owner.execute("INSERT INTO session_revocations(user_id,scope,reason,jti,not_before,expires_at) VALUES($1,'jti','pushprof','push-profiles',now(),now()+interval '10 minutes')",&[&user]).await?;
            let payload = json!({"user_id":user,"scope":"jti","jti":"push-profiles"}).to_string();
            owner
                .query("SELECT pg_notify('session_revoke',$1)", &[&payload])
                .await?;
            websocket_revoked(&mut socket).await?;
            eventsource_ends(&mut stream).await?;
            owner
                .execute("DELETE FROM session_revocations WHERE user_id=$1", &[&user])
                .await?;
        }
        assert_zero_proxy(address).await?;
        drop(served);
        Ok::<_, BoxError>(())
    }
    .await;
    owner
        .execute("DELETE FROM session_revocations WHERE user_id=$1", &[&user])
        .await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.chat'",
            &[&saved_chat],
        )
        .await?;
    fixture::remove(&owner, &account).await?;
    result
}

/// Mutant: a gateway without legacy key material must fail the HS256 golden
/// (refusal, never a forward or an acceptance).
#[tokio::test]
async fn replay_rejects_a_gateway_without_legacy_keys() -> Result<(), BoxError> {
    if recording() {
        return Ok(());
    }
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("push-profiles-mutant") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "pushprofmut").await?;
    let result = async {
        let expected: Value = serde_json::from_slice(&std::fs::read(corpus("standard"))?)?;
        if expected["cases"]["ws-hs256"]["status"] != 101 {
            return Err("standard golden no longer records HS256 acceptance".into());
        }
        let served = serve(None, native_routes(&db, common::recovery_keys())?).await?;
        let token = hs256(SECRET.as_bytes(), KIDS[0], &claims(account.user, json!({})));
        let observed = websocket(served.1, &token).await?;
        assert_zero_proxy(served.1).await?;
        drop(served);
        match setjoin_conformance::golden::compare(&expected["cases"]["ws-hs256"], &observed) {
            Err(error) if observed["status"] == 401 && error.contains("/status") => {
                println!("MUTANT-REJECTED: GET /jmap/ws :: legacy keys absent");
                Ok(())
            }
            Err(error) => Err(format!("mutant failed for the wrong reason: {error}").into()),
            Ok(()) => Err("a gateway without legacy keys matched the HS256 golden".into()),
        }
    }
    .await;
    fixture::remove(&owner, &account).await?;
    result
}
