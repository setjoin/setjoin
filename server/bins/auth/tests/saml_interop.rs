//! Interop against a real IdP (#546): SimpleSAMLphp 1.x in a container named
//! `gofree-samlacs-idp-*`, removed on every path. The image is pinned by digest and used with
//! `--pull never`: when it is absent the test fails and says how to fetch it, it never skips.
//! Proves an SP-initiated link and login end to end, a replay, and an unlinked user.
#![allow(dead_code, unused_imports)]
mod common;
include!("saml_oracle/harness.rs");
#[path = "saml_oracle/flows.rs"]
mod flows;
#[path = "saml_oracle/links.rs"]
mod links;
use sha2::{Digest, Sha256};

const IMAGE: &str = "kristophjunge/test-saml-idp@sha256:02a6e56c01f94b9ba3f2151f33acedf4606ac9b7eeb62a874c5a6b032c0fa9cc";
const REG: i64 = 34602;
/// Delete the registration's identity source (and the shadow rows that reference it) instead of
/// detaching it with `provider_key=NULL`, which left orphan sources behind. A source that a link
/// still references is kept (the link cleanup runs first).
const SOURCE_CLEANUP: &str = "WITH s AS (SELECT x.id FROM identity_sources x WHERE x.provider_key = $1 AND NOT EXISTS (SELECT 1 FROM user_identity_links l WHERE l.source_id=x.id)), a AS (DELETE FROM identity_auth_shadow_hours WHERE source_id IN (SELECT id FROM s)), b AS (DELETE FROM identity_auth_shadow_link_evidence WHERE source_id IN (SELECT id FROM s)), c AS (DELETE FROM identity_shadow_divergences WHERE source_id IN (SELECT id FROM s)) DELETE FROM identity_sources WHERE id IN (SELECT id FROM s)";

struct Container(String);
impl Drop for Container {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker").args(["rm", "-f", &self.0]).output();
    }
}
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}
fn segment(entity: &str) -> String {
    use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
    const SET: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'<').add(b'>').add(b'?').add(b'`').add(b'{').add(b'}').add(b'/').add(b'%');
    utf8_percent_encode(entity, SET).to_string()
}
fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let a = text.find(start)? + start.len();
    let b = text[a..].find(end)? + a;
    Some(&text[a..b])
}
/// A minimal browser against the IdP: manual cookie jar, no automatic redirects.
struct Browser {
    http: reqwest::Client,
    jar: Vec<(String, String)>,
}
impl Browser {
    fn new() -> Self {
        Self {
            http: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
            jar: Vec::new(),
        }
    }
    async fn send(&mut self, mut req: reqwest::RequestBuilder) -> (u16, Option<String>, String) {
        if !self.jar.is_empty() {
            req = req.header("cookie", self.jar.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; "));
        }
        let resp = req.send().await.expect("IdP request");
        for c in resp.headers().get_all("set-cookie") {
            let pair = c.to_str().unwrap().split(';').next().unwrap();
            let (k, v) = pair.split_once('=').unwrap();
            self.jar.retain(|(n, _)| n != k);
            self.jar.push((k.to_owned(), v.to_owned()));
        }
        let status = resp.status().as_u16();
        let location = resp.headers().get("location").map(|v| v.to_str().unwrap().to_owned());
        (status, location, resp.text().await.unwrap())
    }
    /// Follow the SP's redirect through the IdP login and return (ACS URL, SAMLResponse, RelayState).
    async fn sign_in(&mut self, start: &str, user: &str, password: &str) -> (String, String, String) {
        let (mut status, mut location, mut body) = self.send(self.http.get(start)).await;
        let mut at = start.to_owned();
        for _ in 0..8 {
            if !matches!(status, 301 | 302 | 303) {
                break;
            }
            at = reqwest::Url::parse(&at).unwrap().join(&location.unwrap()).unwrap().to_string();
            (status, location, body) = self.send(self.http.get(&at)).await;
        }
        assert_eq!(status, 200, "IdP login page: {body}");
        let action = html_escape::decode_html_entities(between(&body, "<form action=\"", "\"").or_else(|| between(&body, "action=\"", "\"")).expect("login form")).to_string();
        let state = html_escape::decode_html_entities(between(&body, "name=\"AuthState\" value=\"", "\"").expect("AuthState")).to_string();
        let action = reqwest::Url::parse(&at).unwrap().join(&action).unwrap();
        let form = [("username", user), ("password", password), ("AuthState", state.as_str())];
        let (mut status, mut location, mut body) = self.send(self.http.post(action.clone()).form(&form)).await;
        let mut at = action.to_string();
        for _ in 0..8 {
            if !matches!(status, 301 | 302 | 303) {
                break;
            }
            at = reqwest::Url::parse(&at).unwrap().join(&location.unwrap()).unwrap().to_string();
            (status, location, body) = self.send(self.http.get(&at)).await;
        }
        assert_eq!(status, 200, "IdP response page: {body}");
        let acs = html_escape::decode_html_entities(between(&body, "<form method=\"post\" action=\"", "\"").or_else(|| between(&body, "action=\"", "\"")).expect("ACS form")).to_string();
        let response = html_escape::decode_html_entities(between(&body, "name=\"SAMLResponse\" value=\"", "\"").expect("SAMLResponse")).to_string();
        let relay = html_escape::decode_html_entities(between(&body, "name=\"RelayState\" value=\"", "\"").unwrap_or("")).to_string();
        (acs, response, relay)
    }
}
fn form(response: &str, relay: &str) -> String {
    let enc = |s: &str| percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string();
    format!("SAMLResponse={}&RelayState={}", enc(response), enc(relay))
}
fn cookies_of(r: &(u16, Value, String)) -> Vec<String> {
    r.1["set-cookie"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default()
}

#[tokio::test]
async fn simplesamlphp_sp_initiated_link_then_login_end_to_end() {
    let _serial = SERIAL.lock().await;
    let sp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sp_port = sp_listener.local_addr().unwrap().port();
    let idp_port = free_port();
    let entity = format!("http://127.0.0.1:{idp_port}/simplesaml/saml2/idp/metadata.php");
    let acs = format!("http://127.0.0.1:{sp_port}/auth/saml/{}/acs", segment(&entity));
    let name = format!("gofree-samlacs-idp-{}-{idp_port}", std::process::id());
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/identity-saml/interop/saml20-sp-remote.php");
    let started = std::process::Command::new("docker")
        .args(["run", "-d", "--pull", "never", "--name", &name, "-p", &format!("127.0.0.1:{idp_port}:8080")])
        .args(["-e", &format!("SIMPLESAMLPHP_SP_ENTITY_ID=http://127.0.0.1:{sp_port}/saml/metadata")])
        .args(["-e", &format!("SIMPLESAMLPHP_SP_ASSERTION_CONSUMER_SERVICE={acs}")])
        .args(["-e", &format!("SIMPLESAMLPHP_SP_SINGLE_LOGOUT_SERVICE=http://127.0.0.1:{sp_port}/slo")])
        .args(["-v", &format!("{}:/var/www/simplesamlphp/metadata/saml20-sp-remote.php:ro", fixture.canonicalize().unwrap().display())])
        .arg(IMAGE)
        .output()
        .expect("docker is required for the SAML interop test");
    let _container = Container(name.clone());
    assert!(
        started.status.success(),
        "cannot start the IdP container (docker pull {IMAGE} first): {}",
        String::from_utf8_lossy(&started.stderr)
    );
    let mut browser = Browser::new();
    let metadata_url = format!("http://127.0.0.1:{idp_port}/simplesaml/saml2/idp/metadata.php");
    let mut metadata = String::new();
    for _ in 0..120 {
        if let Ok(r) = browser.http.get(&metadata_url).send().await {
            if r.status() == 200 {
                metadata = r.text().await.unwrap();
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert!(!metadata.is_empty(), "the IdP container never answered");
    assert_eq!(between(&metadata, "entityID=\"", "\""), Some(entity.as_str()));
    let cert = between(&metadata, "<ds:X509Certificate>", "</ds:X509Certificate>").unwrap();
    let pem = format!("-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----\n");

    // The SP under test.
    let db = Db::for_case("SAMLACS-interop").expect("assigned disposable DB required");
    let c = db.connect().await.unwrap();
    c.query_one("SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))", &[]).await.unwrap();
    common::signing_key(&c).await;
    for (key, value) in [("feature.rate_limit", false), ("feature.identity_model_v2", true), ("feature.conditional_access", false), ("feature.device_trust_enforcement", false)] {
        c.execute("INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=excluded.enabled", &[&key, &value]).await.unwrap();
    }
    // A failed earlier run leaves fixtures behind: clear them.
    c.execute("DELETE FROM sessions WHERE id LIKE 'gofree-samlacs-%'", &[]).await.unwrap();
    for row in c.query("SELECT DISTINCT l.user_id FROM user_identity_links l JOIN identity_sources s ON s.id=l.source_id WHERE s.kind='saml' AND s.provider_key=$1", &[&format!("saml:{REG}")]).await.unwrap() {
        links::cleanup_identity(&c, row.get(0)).await.unwrap();
    }
    // The source key hashes this run's IdP entity (random port) but provider_key is unique.
    c.execute(SOURCE_CLEANUP, &[&format!("saml:{REG}")]).await.unwrap();
    c.execute("DELETE FROM saml_sp_registrations WHERE id=$1", &[&REG]).await.unwrap();
    c.execute(
        "INSERT INTO saml_sp_registrations(id,idp_entity_id,idp_metadata_url,idp_sso_url,idp_cert_enc,sp_entity_id,sp_acs_url,group_mappings) VALUES($1,$2,$3,'https://ignored.invalid/sso',pgp_sym_encrypt($4,$5),$6,'https://ignored.invalid/acs','[]')",
        &[&REG, &entity, &metadata, &pem, &flows::ENC, &format!("http://127.0.0.1:{sp_port}/saml/metadata")],
    )
    .await
    .unwrap();
    let mut config = flows::config().unwrap();
    config.issuer = "mailserver".into();
    let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap();
    let auth = Arc::new(AuthServer::load(exec, config).await.unwrap());
    let sp_addr = sp_listener.local_addr().unwrap();
    let (stop, rx) = oneshot::channel::<()>();
    let serving = tokio::spawn({
        let auth = auth.clone();
        async move {
            let mut connections = tokio::task::JoinSet::new();
            tokio::pin!(rx);
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accepted = sp_listener.accept() => {
                        let (stream, peer) = accepted.unwrap();
                        let auth = auth.clone();
                        connections.spawn(async move {
                            let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                                let auth = auth.clone();
                                req.extensions_mut().insert(setjoin_auth::ConnectionMeta { peer, tls: false });
                                async move { Ok::<_, std::convert::Infallible>(auth.handle(req.map(|b| b.map_err(std::io::Error::other).boxed())).await) }
                            });
                            let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection(hyper_util::rt::TokioIo::new(stream), service).await;
                        });
                    }
                }
            }
            connections.abort_all();
        }
    });
    let audit_base: i64 = c.query_one("SELECT coalesce(max(id),0) FROM admin_audit_log", &[]).await.unwrap().get(0);
    let account = setjoin_conformance::fixture::account(&c, "samlacs-interop").await.unwrap();
    let token = flows::access(&c, account.user, "aal2", "gofree-samlacs-interop-session").await.unwrap();
    c.execute("INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES('gofree-samlacs-interop-session',$1,$2,now()+interval '1 hour','totp')", &[&account.user, &Sha256::digest(token.as_bytes()).to_vec()]).await.unwrap();

    let login_path = format!("/auth/saml/{}/login", segment(&entity));
    let link_path = format!("/auth/saml/{}/link", segment(&entity));
    let acs_path = format!("/auth/saml/{}/acs", segment(&entity));
    let result = async {
        // 1. SP-initiated link: the signed-in user starts it; the IdP authenticates user1.
        let begun = request(sp_addr, "POST", &link_path, String::new(), &[("cookie", &format!("access_token={token}"))]).await.map_err(|e| e.to_string())?;
        assert_eq!(begun.0, 302, "link begin: {}", begun.2);
        let set = cookies_of(&begun);
        let flow = set.iter().find(|c| c.starts_with("identity_link_flow=")).ok_or("no link flow")?.split(';').next().unwrap().to_owned();
        let tracking = set.iter().find(|c| c.starts_with("saml_")).ok_or("no tracking cookie")?.split(';').next().unwrap().to_owned();
        let location = begun.1["location"].as_str().ok_or("no IdP redirect")?.to_owned();
        let (target, response, relay) = browser.sign_in(&location, "user1", "user1pass").await;
        assert_eq!(target, acs, "the IdP must post to the advertised ACS");
        assert!(target.ends_with(&acs_path));
        // A browser's POST from the IdP carries only the tracking cookie (the others are Strict).
        let posted = request(sp_addr, "POST", &acs_path, form(&response, &relay), &[("content-type", "application/x-www-form-urlencoded"), ("cookie", &tracking)]).await.map_err(|e| e.to_string())?;
        assert_eq!(posted.0, 200, "link held at the ACS: {}", posted.2);
        let next = between(&posted.2, "content=\"0;url=", "\"").ok_or("no completion URL")?.to_owned();
        let done = request(sp_addr, "GET", &next, String::new(), &[("cookie", &format!("{flow}; access_token={token}"))]).await.map_err(|e| e.to_string())?;
        assert_eq!(done.0, 303, "link completed same-site: {}", done.2);
        assert_eq!(done.1["location"], "/settings?identity=linked");
        let linked: i64 = c.query_one("SELECT count(*) FROM user_identity_links l JOIN identity_sources s ON s.id=l.source_id WHERE l.user_id=$1 AND s.kind='saml' AND l.external_subject='1' AND l.state='active'", &[&account.user]).await.map_err(|e| e.to_string())?.get(0);
        assert_eq!(linked, 1, "the NameID the IdP issued for user1 is linked");
        // 2. The same response again is a replay.
        let replay = request(sp_addr, "POST", &acs_path, form(&response, &relay), &[("content-type", "application/x-www-form-urlencoded"), ("cookie", &tracking)]).await.map_err(|e| e.to_string())?;
        assert_eq!(replay.0, 401, "replay: {}", replay.2);
        // 3. SP-initiated login as the linked user.
        let start = request(sp_addr, "GET", &login_path, String::new(), &[]).await.map_err(|e| e.to_string())?;
        assert_eq!(start.0, 302);
        let tracking = cookies_of(&start).into_iter().find(|c| c.starts_with("saml_")).unwrap().split(';').next().unwrap().to_owned();
        let location = start.1["location"].as_str().unwrap().to_owned();
        let mut second = Browser::new();
        let (_, response, relay) = second.sign_in(&location, "user1", "user1pass").await;
        let before: i64 = c.query_one("SELECT count(*) FROM sessions WHERE user_id=$1", &[&account.user]).await.map_err(|e| e.to_string())?.get(0);
        let login = request(sp_addr, "POST", &acs_path, form(&response, &relay), &[("content-type", "application/x-www-form-urlencoded"), ("cookie", &tracking)]).await.map_err(|e| e.to_string())?;
        assert_eq!(login.0, 303, "login at the ACS: {}", login.2);
        assert!(cookies_of(&login).iter().any(|c| c.starts_with("access_token=")));
        let after: i64 = c.query_one("SELECT count(*) FROM sessions WHERE user_id=$1", &[&account.user]).await.map_err(|e| e.to_string())?.get(0);
        assert_eq!(after, before + 1, "a session was minted for the linked user");
        // 4. A different IdP user (NameID 2) is not linked and is not provisioned.
        let start = request(sp_addr, "GET", &login_path, String::new(), &[]).await.map_err(|e| e.to_string())?;
        let tracking = cookies_of(&start).into_iter().find(|c| c.starts_with("saml_")).unwrap().split(';').next().unwrap().to_owned();
        let mut third = Browser::new();
        let (_, response, relay) = third.sign_in(start.1["location"].as_str().unwrap(), "user2", "user2pass").await;
        let users: i64 = c.query_one("SELECT count(*) FROM users", &[]).await.map_err(|e| e.to_string())?.get(0);
        let refused = request(sp_addr, "POST", &acs_path, form(&response, &relay), &[("content-type", "application/x-www-form-urlencoded"), ("cookie", &tracking)]).await.map_err(|e| e.to_string())?;
        assert_eq!(refused.0, 401, "{}", refused.2);
        assert_eq!(c.query_one("SELECT count(*) FROM users", &[]).await.map_err(|e| e.to_string())?.get::<_, i64>(0), users);
        let audit: Vec<String> = c.query("SELECT action FROM admin_audit_log WHERE action LIKE 'saml.acs.%' AND target_id=$1 AND id>$2 ORDER BY id", &[&REG, &audit_base]).await.map_err(|e| e.to_string())?.iter().map(|r| r.get(0)).collect();
        assert_eq!(audit, ["saml.acs.link_held", "saml.acs.success", "saml.acs.replay", "saml.acs.success", "saml.acs.refused"]);
        Ok::<(), String>(())
    }
    .await;
    // Cleanup on every path.
    let _ = stop.send(());
    let _ = serving.await;
    c.execute("DELETE FROM saml_sp_registrations WHERE id=$1", &[&REG]).await.unwrap();
    for sql in ["DELETE FROM sessions WHERE user_id=$1", "DELETE FROM identity_auth_link_elevations WHERE user_id=$1", "DELETE FROM oauth_tokens WHERE user_id=$1"] {
        c.execute(sql, &[&account.user]).await.unwrap();
    }
    links::cleanup_identity(&c, account.user).await.unwrap();
    c.execute(SOURCE_CLEANUP, &[&format!("saml:{REG}")]).await.unwrap();
    let _ = setjoin_conformance::fixture::remove(&c, &account).await;
    result.unwrap();
}
