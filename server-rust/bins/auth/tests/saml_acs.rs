//! Verified SAML ACS over HTTP (#546): SP-initiated login and link end to end through
//! the real handler against the disposable database, replay, IdP-initiated policy,
//! RelayState allow-list, provisioning, audit rows and the metadata fetch policy.
//! Mutants (`SETJOIN_SAMLACS_MUTANT`, feature `oracle-mutants`) are driven by
//! `scripts/test-samlacs-mutants.py`. Synthetic keys only.
#![allow(dead_code, unused_imports)]
mod common;
include!("saml_oracle/harness.rs");
#[path = "saml_oracle/flows.rs"]
mod flows;
#[path = "saml_oracle/links.rs"]
mod links;
#[path = "../../../crates/domains/identity/tests/saml_acs/support.rs"]
mod support;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use setjoin_conformance::fixture;
use sha2::{Digest, Sha256};
use support::*;

const REG: i64 = 34601;
const ENC: &str = flows::ENC;

#[derive(Clone)]
struct Opts {
    jit: bool,
    idp_initiated: bool,
    normalized: bool,
    cert: String,
    metadata: String,
}
impl Default for Opts {
    fn default() -> Self {
        Self {
            jit: false,
            idp_initiated: false,
            normalized: false,
            cert: rsa_idp().cert_pem.clone(),
            metadata: flows::metadata("Redirect")
                .replace("https://idp.idfed3.test", "https://idp.example.test"),
        }
    }
}
struct World {
    c: tokio_postgres::Client,
    srv: Server,
    old: Vec<(&'static str, Option<bool>)>,
    accounts: Vec<fixture::Account>,
    /// admin_audit_log is append-only: rows from earlier runs stay, so each world counts
    /// only the rows after this id.
    audit_base: i64,
}
fn acs_path() -> String {
    "/auth/saml/https:%2F%2Fidp.example.test%2Fmetadata/acs".to_owned()
}
fn login_path() -> String {
    "/auth/saml/https:%2F%2Fidp.example.test%2Fmetadata/login".to_owned()
}
impl World {
    async fn start(o: Opts) -> Result<Self, Err> {
        Self::start_with(o, None).await
    }
    async fn start_with(
        o: Opts,
        http: Option<Arc<dyn setjoin_identity::rp::Http>>,
    ) -> Result<Self, Err> {
        let db = Db::for_case("SAMLACS").expect("assigned disposable DB required");
        let c = db.connect().await?;
        c.query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await?;
        common::signing_key(&c).await;
        let mut old = Vec::new();
        for (key, value) in [
            ("feature.rate_limit", false),
            ("feature.identity_model_v2", o.normalized),
            ("feature.identity_normalized_reads", o.normalized),
            ("feature.conditional_access", false),
            ("feature.device_trust_enforcement", false),
        ] {
            old.push((
                key,
                c.query_opt("SELECT enabled FROM feature_toggles WHERE key=$1", &[&key])
                    .await?
                    .map(|r| r.get(0)),
            ));
            c.execute("INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=excluded.enabled", &[&key, &value]).await?;
        }
        // A panicking earlier run leaves fixture links behind: clear this registration's.
        c.execute("UPDATE users SET saml_name_id=NULL,saml_idp_entity_id=NULL WHERE saml_idp_entity_id IN ($1,'https://another-idp.example')", &[&IDP]).await?;
        c.execute(
            "DELETE FROM sessions WHERE id LIKE 'gofree-samlacs-%'",
            &[],
        )
        .await?;
        for row in c.query("SELECT DISTINCT l.user_id FROM user_identity_links l JOIN identity_sources s ON s.id=l.source_id WHERE s.kind='saml' AND s.provider_key=$1", &[&format!("saml:{REG}")]).await? {
            links::cleanup_identity(&c, row.get(0)).await?;
        }
        c.execute("DELETE FROM saml_sp_registrations WHERE id=$1", &[&REG])
            .await?;
        c.execute(
            "INSERT INTO saml_sp_registrations(id,idp_entity_id,idp_metadata_url,idp_sso_url,idp_cert_enc,sp_entity_id,sp_acs_url,group_mappings,jit_enabled,allow_idp_initiated) VALUES($1,$2,$3,'https://ignored.invalid/sso',pgp_sym_encrypt($4,$5),'https://sp.example.test/ignored/path','https://ignored.invalid/acs','[]',$6,$7)",
            &[&REG, &IDP, &o.metadata, &o.cert, &ENC, &o.jit, &o.idp_initiated],
        )
        .await?;
        let mut config = flows::config()?;
        config.issuer = "mailserver".into();
        let exec =
            setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap();
        let native = Arc::new(match http {
            Some(http) => AuthServer::load_with_rp_http(exec, config, http).await?,
            None => AuthServer::load(exec, config).await?,
        });
        let srv = auth_server(native, false).await;
        let audit_base: i64 = c
            .query_one("SELECT coalesce(max(id),0) FROM admin_audit_log", &[])
            .await?
            .get(0);
        Ok(Self {
            c,
            srv,
            old,
            accounts: Vec::new(),
            audit_base,
        })
    }
    async fn account(&mut self, label: &str) -> Result<fixture::Account, Err> {
        let a = fixture::account(&self.c, label).await?;
        self.accounts.push(a.clone());
        Ok(a)
    }
    async fn link_legacy(&self, user: i64, name_id: &str) -> Result<(), Err> {
        self.c
            .execute(
                "UPDATE users SET saml_name_id=$2,saml_idp_entity_id=$3 WHERE id=$1",
                &[&user, &name_id, &IDP],
            )
            .await?;
        Ok(())
    }
    async fn link_normalized(&self, user: i64, name_id: &str) -> Result<(), Err> {
        self.c
            .query_one(
                "SELECT identity_auth_link($1,$1,'saml',$2,$3,$4,'SAMLACS fixture')",
                &[&user, &IDP, &name_id, &format!("saml:{REG}")],
            )
            .await?;
        Ok(())
    }
    async fn close(self) -> Result<(), Err> {
        // A failed test body can leave a transaction open on this connection.
        let _ = self.c.batch_execute("ROLLBACK").await;
        self.srv.close().await;
        self.c
            .execute("DELETE FROM saml_sp_registrations WHERE id=$1", &[&REG])
            .await?;
        for a in &self.accounts {
            self.c
                .execute("DELETE FROM sessions WHERE user_id=$1", &[&a.user])
                .await?;
            links::cleanup_identity(&self.c, a.user).await?;
            self.c
                .execute(
                    "DELETE FROM identity_auth_link_elevations WHERE user_id=$1",
                    &[&a.user],
                )
                .await?;
            self.c
                .execute("DELETE FROM oauth_tokens WHERE user_id=$1", &[&a.user])
                .await?;
            let _ = fixture::remove(&self.c, a).await;
        }
        // The first SAML login creates the registration's identity source; leave no trace of it.
        self.c
            .execute(
                "WITH s AS (SELECT x.id FROM identity_sources x WHERE x.provider_key = $1 AND NOT EXISTS (SELECT 1 FROM user_identity_links l WHERE l.source_id=x.id)), a AS (DELETE FROM identity_auth_shadow_hours WHERE source_id IN (SELECT id FROM s)), b AS (DELETE FROM identity_auth_shadow_link_evidence WHERE source_id IN (SELECT id FROM s)), c AS (DELETE FROM identity_shadow_divergences WHERE source_id IN (SELECT id FROM s)) DELETE FROM identity_sources WHERE id IN (SELECT id FROM s)",
                &[&format!("saml:{REG}")],
            )
            .await?;
        for (key, old) in self.old {
            match old {
                Some(v) => {
                    self.c
                        .execute(
                            "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                            &[&key, &v],
                        )
                        .await?;
                }
                None => {
                    self.c
                        .execute("DELETE FROM feature_toggles WHERE key=$1", &[&key])
                        .await?;
                }
            }
        }
        Ok(())
    }
    async fn audit(&self) -> Result<Vec<String>, Err> {
        Ok(self
            .c
            .query("SELECT action FROM admin_audit_log WHERE action LIKE 'saml.acs.%' AND target_id=$1 AND id>$2 ORDER BY id", &[&REG, &self.audit_base])
            .await?
            .iter()
            .map(|r| r.get(0))
            .collect())
    }
    async fn sessions(&self, user: i64) -> Result<i64, Err> {
        Ok(self
            .c
            .query_one("SELECT count(*) FROM sessions WHERE user_id=$1", &[&user])
            .await?
            .get(0))
    }
    async fn email(&self, user: i64) -> Result<String, Err> {
        Ok(self
            .c
            .query_one("SELECT email FROM users WHERE id=$1", &[&user])
            .await?
            .get(0))
    }
    async fn users(&self) -> Result<i64, Err> {
        Ok(self
            .c
            .query_one("SELECT count(*) FROM users", &[])
            .await?
            .get(0))
    }
}

struct Started {
    relay: String,
    jwt: String,
    id: String,
    cookie: String,
}
async fn start_login(w: &World) -> Result<Started, Err> {
    let r = request(w.srv.addr, "GET", &login_path(), String::new(), &[]).await?;
    assert_eq!(r.0, 302, "login: {}", r.2);
    let cookie = r.1["set-cookie"][0]
        .as_str()
        .ok_or("no tracking cookie")?
        .to_owned();
    let (name, rest) = cookie.split_once('=').unwrap();
    let jwt = rest.split(';').next().unwrap().to_owned();
    assert!(
        cookie.contains(&format!("Path={}", acs_path())),
        "tracking cookie scoped to the ACS: {cookie}"
    );
    let relay = name.strip_prefix("saml_").unwrap().to_owned();
    let claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1).unwrap())?)?;
    Ok(Started {
        relay,
        jwt,
        id: claims["id"].as_str().unwrap().to_owned(),
        cookie: name.to_owned(),
    })
}
fn form(xml: &str, relay: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    format!(
        "SAMLResponse={}&RelayState={}",
        percent_encoding::utf8_percent_encode(
            &STANDARD.encode(xml),
            percent_encoding::NON_ALPHANUMERIC
        ),
        percent_encoding::utf8_percent_encode(relay, percent_encoding::NON_ALPHANUMERIC)
    )
}
async fn acs(
    w: &World,
    xml: &str,
    relay: &str,
    cookies: &[String],
) -> Result<(u16, Value, String), Err> {
    let cookie = cookies.join("; ");
    let mut headers = vec![("content-type", "application/x-www-form-urlencoded")];
    if !cookie.is_empty() {
        headers.push(("cookie", cookie.as_str()));
    }
    request(w.srv.addr, "POST", &acs_path(), form(xml, relay), &headers).await
}
fn answer(started: &Started, name_id: &str, assertion_id: &str) -> String {
    let o = Opts_ {
        name_id: name_id.into(),
        irt: Some(started.id.clone()),
        assertion_id: assertion_id.into(),
        ..live()
    };
    signed_assertion(&o, &SigSpec::new(rsa_idp()))
}
type Opts_ = support::Opts;
/// Assertion options on the wall clock (the handler verifies against real time).
fn live() -> support::Opts {
    let now = NOW_REAL();
    support::Opts {
        not_before: now - 30,
        not_on_or_after: now + 300,
        scd_not_on_or_after: now + 300,
        ..support::Opts::default()
    }
}
fn set_cookies(r: &(u16, Value, String)) -> Vec<String> {
    r.1["set-cookie"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
fn completion_of(page: &str) -> String {
    let start = page.find("url=").expect("completion URL") + 4;
    page[start..].split('"').next().unwrap().to_owned()
}
async fn begin_link(w: &World, user: i64, jti: &str) -> Result<(String, String, Started), Err> {
    let token = flows::access(&w.c, user, "aal2", jti).await?;
    w.c.execute("INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 hour','totp')", &[&jti, &user, &Sha256::digest(token.as_bytes()).to_vec()]).await?;
    let begun = request(w.srv.addr, "POST", &acs_path().replace("/acs", "/link"), String::new(), &[("cookie", &format!("access_token={token}"))]).await?;
    assert_eq!(begun.0, 302, "{}", begun.2);
    let cookies = set_cookies(&begun);
    let flow = cookies.iter().find(|c| c.starts_with("identity_link_flow=")).unwrap().split(';').next().unwrap().to_owned();
    let tracked = cookies.iter().find(|c| c.starts_with("saml_")).unwrap();
    let (name, rest) = tracked.split_once('=').unwrap();
    let jwt = rest.split(';').next().unwrap().to_owned();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1).unwrap())?)?;
    assert_eq!(claims["purpose"], "link");
    assert_eq!(claims["reg"], REG);
    Ok((token, flow, Started { relay: name.strip_prefix("saml_").unwrap().into(), jwt, id: claims["id"].as_str().unwrap().into(), cookie: name.into() }))
}
fn tracking(s: &Started) -> String {
    format!("{}={}", s.cookie, s.jwt)
}

// ---- SP-initiated login ---------------------------------------------------------

#[tokio::test]
async fn sp_initiated_login_mints_a_session_and_is_audited() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts::default()).await.unwrap();
    let result = async {
        let user = w.account("samlacs-alice").await?;
        w.link_legacy(user.user, "alice-subject-1").await?;
        let s = start_login(&w).await?;
        let r = acs(&w, &answer(&s, "alice-subject-1", "_a-login-1"), &s.relay, &[tracking(&s)]).await?;
        assert_eq!(r.0, 303, "{}", r.2);
        assert_eq!(r.1["location"], "/");
        let cookies = set_cookies(&r);
        assert!(cookies.iter().any(|c| c.starts_with("access_token=") && c.contains("HttpOnly")), "{cookies:?}");
        assert!(cookies.iter().any(|c| c.starts_with(&format!("{}=;", s.cookie)) && c.contains("Max-Age=0")), "tracking cookie is single-use: {cookies:?}");
        assert!(!r.2.contains("access_token"), "tokens never ride a redirect body");
        assert_eq!(w.sessions(user.user).await?, 1);
        assert_eq!(w.audit().await?, ["saml.acs.success"]);
        let actor: Option<i64> = w.c.query_one("SELECT user_id FROM admin_audit_log WHERE action='saml.acs.success' AND target_id=$1 AND id>$2", &[&REG, &w.audit_base]).await?.get(0);
        assert_eq!(actor, Some(user.user));
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

#[tokio::test]
async fn sp_initiated_login_works_on_the_normalized_identity_model() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts {
        normalized: true,
        ..Opts::default()
    })
    .await
    .unwrap();
    let result = async {
        let user = w.account("samlacs-norm").await?;
        w.link_normalized(user.user, "norm-subject").await?;
        let s = start_login(&w).await?;
        let r = acs(
            &w,
            &answer(&s, "norm-subject", "_a-norm-1"),
            &s.relay,
            &[tracking(&s)],
        )
        .await?;
        assert_eq!(r.0, 303, "{}", r.2);
        assert_eq!(w.sessions(user.user).await?, 1);
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

#[tokio::test]
async fn replays_of_an_assertion_or_of_its_request_are_refused_and_audited() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts::default()).await.unwrap();
    let result = async {
        let user = w.account("samlacs-replay").await?;
        w.link_legacy(user.user, "replay-subject").await?;
        let s = start_login(&w).await?;
        let xml = answer(&s, "replay-subject", "_a-replay-1");
        assert_eq!(acs(&w, &xml, &s.relay, &[tracking(&s)]).await?.0, 303);
        // The same message again (the browser kept the cookie).
        let again = acs(&w, &xml, &s.relay, &[tracking(&s)]).await?;
        assert_eq!(again.0, 401, "{}", again.2);
        // A different assertion answering the same request.
        let other = answer(&s, "replay-subject", "_a-replay-2");
        assert_eq!(acs(&w, &other, &s.relay, &[tracking(&s)]).await?.0, 401);
        // The same assertion presented under a fresh login's cookie fails InResponseTo.
        let s2 = start_login(&w).await?;
        assert_eq!(acs(&w, &xml, &s2.relay, &[tracking(&s2)]).await?.0, 401);
        assert_eq!(
            w.sessions(user.user).await?,
            1,
            "only the first presentation mints"
        );
        let audit = w.audit().await?;
        assert_eq!(
            audit.iter().filter(|a| *a == "saml.acs.replay").count(),
            2,
            "{audit:?}"
        );
        assert!(
            audit.contains(&"saml.acs.inresponseto".to_owned()),
            "{audit:?}"
        );
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

#[tokio::test]
async fn every_failure_class_is_audited_without_a_session() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts::default()).await.unwrap();
    let result = async {
        let user = w.account("samlacs-fail").await?;
        w.link_legacy(user.user, "fail-subject").await?;
        let users = w.users().await?;
        let mut expect = Vec::new();
        for (label, class) in [
            ("unsigned", "unsigned"),
            ("badsig", "signature"),
            ("wrongissuer", "issuer"),
            ("wrongaudience", "audience"),
            ("expired", "conditions"),
            ("wrongrecipient", "recipient"),
            ("wrongirt", "inresponseto"),
        ] {
            let s = start_login(&w).await?;
            let id = format!("_a-{label}");
            let base = support::Opts {
                name_id: "fail-subject".into(),
                irt: Some(s.id.clone()),
                assertion_id: id,
                ..live()
            };
            let spec = SigSpec::new(rsa_idp());
            let xml = match label {
                "unsigned" => unsigned(&base),
                "badsig" => signed_assertion(&base, &SigSpec::new(rsa_attacker())),
                "wrongissuer" => signed_assertion(
                    &support::Opts {
                        issuer: "https://evil.example".into(),
                        ..base
                    },
                    &spec,
                ),
                "wrongaudience" => signed_assertion(
                    &support::Opts {
                        audience: "https://other-sp.example".into(),
                        ..base
                    },
                    &spec,
                ),
                "expired" => signed_assertion(
                    &support::Opts {
                        not_on_or_after: NOW_REAL() - 3600,
                        scd_not_on_or_after: NOW_REAL() - 3600,
                        not_before: NOW_REAL() - 7200,
                        ..base
                    },
                    &spec,
                ),
                "wrongrecipient" => signed_assertion(
                    &support::Opts {
                        recipient: "https://sp.example.test/other".into(),
                        ..base
                    },
                    &spec,
                ),
                _ => signed_assertion(
                    &support::Opts {
                        irt: Some("id-not-mine".into()),
                        ..base
                    },
                    &spec,
                ),
            };
            let xml = if matches!(label, "unsigned" | "badsig") || label == "wrongirt" {
                xml
            } else {
                xml
            };
            let r = acs(&w, &xml, &s.relay, &[tracking(&s)]).await?;
            assert_eq!(r.0, 401, "{label}: {}", r.2);
            assert!(r.2.contains("SAML authentication failed"), "{label}");
            assert!(
                !r.2.contains(class),
                "the body must not explain the class: {}",
                r.2
            );
            expect.push(format!("saml.acs.{class}"));
        }
        assert_eq!(w.audit().await?, expect);
        assert_eq!(w.sessions(user.user).await?, 0);
        assert_eq!(w.users().await?, users);
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}
#[allow(non_snake_case)]
fn NOW_REAL() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[tokio::test]
async fn a_forged_tracking_cookie_is_not_a_login() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts::default()).await.unwrap();
    let result = async {
        let user = w.account("samlacs-forge").await?;
        w.link_legacy(user.user, "forge-subject").await?;
        let s = start_login(&w).await?;
        // Re-sign nothing: flip a signature byte of a genuine cookie, and send an
        // answer to a request id the attacker chose.
        let mut parts: Vec<String> = s.jwt.split('.').map(str::to_owned).collect();
        let mut sig = URL_SAFE_NO_PAD.decode(&parts[2])?;
        sig[3] ^= 1;
        parts[2] = URL_SAFE_NO_PAD.encode(sig);
        let mut claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&parts[1])?)?;
        claims["id"] = json!("id-attacker-chosen");
        parts[1] = URL_SAFE_NO_PAD.encode(claims.to_string());
        let forged = format!("{}={}", s.cookie, parts.join("."));
        let fake = Started {
            relay: s.relay.clone(),
            jwt: String::new(),
            id: "id-attacker-chosen".into(),
            cookie: s.cookie.clone(),
        };
        let r = acs(
            &w,
            &answer(&fake, "forge-subject", "_a-forge"),
            &s.relay,
            &[forged],
        )
        .await?;
        assert_eq!(r.0, 401, "{}", r.2);
        assert_eq!(w.sessions(user.user).await?, 0);
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

#[tokio::test]
async fn a_cookie_for_another_relay_state_does_not_bind() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts::default()).await.unwrap();
    let result = async {
        let user = w.account("samlacs-relay").await?;
        w.link_legacy(user.user, "relay-subject").await?;
        let s = start_login(&w).await?;
        let r = acs(
            &w,
            &answer(&s, "relay-subject", "_a-relay"),
            "some-other-relay-state",
            &[tracking(&s)],
        )
        .await?;
        assert_eq!(r.0, 401);
        assert_eq!(w.sessions(user.user).await?, 0);
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

// ---- IdP-initiated SSO and RelayState ------------------------------------------

fn unsolicited(name_id: &str, assertion_id: &str) -> String {
    let o = support::Opts {
        name_id: name_id.into(),
        irt: None,
        assertion_id: assertion_id.into(),
        ..live()
    };
    signed_assertion(&o, &SigSpec::new(rsa_idp()))
}

#[tokio::test]
async fn idp_initiated_sso_is_off_by_default() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts::default()).await.unwrap();
    let result = async {
        let user = w.account("samlacs-idpinit-off").await?;
        w.link_legacy(user.user, "idp-subject").await?;
        let r = acs(&w, &unsolicited("idp-subject", "_a-idp-off"), "/mail", &[]).await?;
        assert_eq!(r.0, 401, "{}", r.2);
        assert_eq!(w.audit().await?, ["saml.acs.idp_initiated_refused"]);
        assert_eq!(w.sessions(user.user).await?, 0);
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

#[tokio::test]
async fn idp_initiated_sso_works_when_the_registration_enables_it_and_relay_state_is_allow_listed()
{
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts {
        idp_initiated: true,
        ..Opts::default()
    })
    .await
    .unwrap();
    let result = async {
        let user = w.account("samlacs-idpinit-on").await?;
        w.link_legacy(user.user, "idp-subject").await?;
        for (n, (relay, location)) in [
            ("/mail/inbox?x=1", "/mail/inbox?x=1"),
            ("//evil.example/x", "/"),
            ("https://evil.example/", "/"),
            ("/\\evil.example", "/"),
            ("javascript:alert(1)", "/"),
            ("/auth/saml/anything/login", "/"),
            ("", "/"),
        ]
        .into_iter()
        .enumerate()
        {
            let r = acs(
                &w,
                &unsolicited("idp-subject", &format!("_a-idp-on-{n}")),
                relay,
                &[],
            )
            .await?;
            assert_eq!(r.0, 303, "{relay}: {}", r.2);
            assert_eq!(r.1["location"], location, "{relay}");
        }
        // A response that claims to answer a request is not unsolicited, cookie or not.
        let s = start_login(&w).await?;
        let r = acs(&w, &answer(&s, "idp-subject", "_a-idp-irt"), &s.relay, &[]).await?;
        assert_eq!(r.0, 401, "{}", r.2);
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

// ---- link by (registration, NameID), provisioning -------------------------------

#[tokio::test]
async fn an_unlinked_nameid_is_never_matched_by_email_and_jit_off_refuses() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts::default()).await.unwrap();
    let result = async {
        let user = w.account("samlacs-email").await?;
        let users = w.users().await?;
        let email = w.email(user.user).await?;
        // The assertion names the existing user's address, in every place it could.
        let o = support::Opts {
            name_id: email.clone(),
            attrs: vec![("email".into(), vec![email.clone()])],
            ..live()
        };
        let s = start_login(&w).await?;
        let o = support::Opts {
            irt: Some(s.id.clone()),
            ..o
        };
        let r = acs(
            &w,
            &signed_assertion(&o, &SigSpec::new(rsa_idp())),
            &s.relay,
            &[tracking(&s)],
        )
        .await?;
        assert_eq!(r.0, 401, "{}", r.2);
        assert!(r.2.contains("user not found"));
        assert_eq!(w.sessions(user.user).await?, 0);
        assert_eq!(w.users().await?, users, "no user is provisioned");
        let saml: Option<String> =
            w.c.query_one("SELECT saml_name_id FROM users WHERE id=$1", &[&user.user])
                .await?
                .get(0);
        assert_eq!(saml, None, "nothing was linked");
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

#[tokio::test]
async fn a_nameid_linked_to_one_registration_is_not_another_registrations_user() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts::default()).await.unwrap();
    let result = async {
        let user = w.account("samlacs-otheridp").await?;
        // Linked under a different IdP entity with the same NameID.
        w.c.execute("UPDATE users SET saml_name_id='shared-subject',saml_idp_entity_id='https://another-idp.example' WHERE id=$1", &[&user.user]).await?;
        let s = start_login(&w).await?;
        let r = acs(&w, &answer(&s, "shared-subject", "_a-other"), &s.relay, &[tracking(&s)]).await?;
        assert_eq!(r.0, 401, "{}", r.2);
        assert_eq!(w.sessions(user.user).await?, 0);
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

#[tokio::test]
async fn jit_follows_the_oidc_policy_and_creates_one_linked_user() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts {
        jit: true,
        normalized: true,
        ..Opts::default()
    })
    .await
    .unwrap();
    let result = async {
        let existing = w.account("samlacs-jit").await?;
        let domain = w.email(existing.user).await?.split_once('@').unwrap().1.to_owned();
        let email = format!("newbie@{domain}");
        let users = w.users().await?;
        let s = start_login(&w).await?;
        let o = support::Opts {
            name_id: "jit-subject".into(),
            irt: Some(s.id.clone()),
            attrs: vec![("email".into(), vec![email.clone()])],
            ..live()
        };
        let r = acs(&w, &signed_assertion(&o, &SigSpec::new(rsa_idp())), &s.relay, &[tracking(&s)]).await?;
        assert_eq!(r.0, 303, "{}", r.2);
        assert_eq!(w.users().await?, users + 1);
        let row = w.c.query_one("SELECT u.id,l.external_subject FROM users u JOIN user_identity_links l ON l.user_id=u.id JOIN identity_sources s ON s.id=l.source_id WHERE u.email=$1 AND s.kind='saml'", &[&email]).await?;
        assert_eq!(row.get::<_, String>(1), "jit-subject");
        let created: i64 = row.get(0);
        assert_eq!(w.sessions(created).await?, 1);
        w.c.execute("DELETE FROM sessions WHERE user_id=$1", &[&created]).await?;
        w.c.execute("DELETE FROM oauth_tokens WHERE user_id=$1", &[&created]).await?;
        links::cleanup_identity(&w.c, created).await?;
        // The JIT user and its mailbox, the way fixture::remove clears a fixture account.
        w.c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM mailbox_audit_log WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id={created}); COMMIT;")).await?;
        w.c.batch_execute(&format!("DELETE FROM message_trace WHERE details->>'mailbox_id' IN (SELECT id::text FROM mailboxes WHERE user_id={created})")).await?;
        w.c.batch_execute(&format!("BEGIN; DELETE FROM mailboxes WHERE user_id={created}; DELETE FROM users WHERE id={created}; COMMIT;")).await?;
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

#[tokio::test]
async fn an_authenticated_user_links_a_nameid_through_the_acs() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts {
        normalized: true,
        ..Opts::default()
    })
    .await
    .unwrap();
    let result = async {
        let user = w.account("samlacs-link").await?;
        let token = flows::access(&w.c, user.user, "aal2", "gofree-samlacs-session").await?;
        w.c.execute("INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES('gofree-samlacs-session',$1,$2,now()+interval '1 hour','totp')", &[&user.user, &Sha256::digest(token.as_bytes()).to_vec()]).await?;
        // Begin: the user's own session starts the flow (frozen #341 behaviour).
        let begun = request(w.srv.addr, "POST", &acs_path().replace("/acs", "/link"), String::new(), &[("cookie", &format!("access_token={token}"))]).await?;
        assert_eq!(begun.0, 302, "{}", begun.2);
        let cookies = set_cookies(&begun);
        let flow = cookies.iter().find(|c| c.starts_with("identity_link_flow=")).unwrap().split(';').next().unwrap().to_owned();
        let tracked = cookies.iter().find(|c| c.starts_with("saml_")).unwrap();
        let (name, rest) = tracked.split_once('=').unwrap();
        let jwt = rest.split(';').next().unwrap().to_owned();
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1).unwrap())?)?;
        let s = Started { relay: name.strip_prefix("saml_").unwrap().into(), jwt, id: claims["id"].as_str().unwrap().into(), cookie: name.into() };
        // Complete, as a browser does: the IdP's cross-site POST carries only the (SameSite=None)
        // tracking cookie, not the Strict flow or access cookies.
        let xml = answer(&s, "linked-subject-9", "_a-link-1");
        let r = acs(&w, &xml, &s.relay, &[tracking(&s)]).await?;
        assert_eq!(r.0, 200, "{}", r.2);
        assert!(r.1.get("location").is_none() && !set_cookies(&r).iter().any(|c| c.starts_with("access_token=")));
        let next = completion_of(&r.2);
        let n: i64 = w.c.query_one("SELECT count(*) FROM user_identity_links l JOIN identity_sources s ON s.id=l.source_id WHERE l.user_id=$1 AND s.kind='saml' AND l.external_subject='linked-subject-9'", &[&user.user]).await?.get(0);
        assert_eq!(n, 0, "nothing is linked until the same-site completion");
        // The completion request carries the Strict cookies and finishes the link.
        let done = request(w.srv.addr, "GET", &next, String::new(), &[("cookie", &format!("{flow}; access_token={token}"))]).await?;
        assert_eq!(done.0, 303, "{}", done.2);
        assert_eq!(done.1["location"], "/settings?identity=linked");
        let n: i64 = w.c.query_one("SELECT count(*) FROM user_identity_links l JOIN identity_sources s ON s.id=l.source_id WHERE l.user_id=$1 AND s.kind='saml' AND l.external_subject='linked-subject-9' AND l.state='active'", &[&user.user]).await?.get(0);
        assert_eq!(n, 1);
        assert_eq!(w.audit().await?, ["saml.acs.link_held", "saml.acs.success"]);
        // Single use: the token and the elevation are spent.
        let again = request(w.srv.addr, "GET", &next, String::new(), &[("cookie", &format!("{flow}; access_token={token}"))]).await?;
        assert_ne!(again.0, 303, "{}", again.2);
        // And the linked NameID now logs in.
        let s3 = start_login(&w).await?;
        let r3 = acs(&w, &answer(&s3, "linked-subject-9", "_a-link-3"), &s3.relay, &[tracking(&s3)]).await?;
        assert_eq!(r3.0, 303, "{}", r3.2);
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

// ---- transport shape ------------------------------------------------------------

#[tokio::test]
async fn malformed_oversized_and_ambiguous_posts_are_refused() {
    let _serial = SERIAL.lock().await;
    let w = World::start(Opts::default()).await.unwrap();
    let result = async {
        let h = [("content-type", "application/x-www-form-urlencoded")];
        let r = request(w.srv.addr, "POST", &acs_path(), "SAMLResponse=".into(), &h).await?;
        assert_eq!(r.0, 400);
        let r = request(
            w.srv.addr,
            "POST",
            &acs_path(),
            "SAMLResponse=!!!&RelayState=x".into(),
            &h,
        )
        .await?;
        assert_eq!(r.0, 400);
        let r = request(
            w.srv.addr,
            "POST",
            &acs_path(),
            "SAMLResponse=QQ%3D%3D&SAMLResponse=QQ%3D%3D".into(),
            &h,
        )
        .await?;
        assert_eq!(r.0, 400, "a repeated SAMLResponse is ambiguous");
        let r = request(
            w.srv.addr,
            "POST",
            &acs_path(),
            "SAMLResponse=QQ%3D%3D".into(),
            &[("content-type", "application/json")],
        )
        .await?;
        assert_eq!(r.0, 400);
        let big = format!("SAMLResponse={}", "A".repeat(2 << 20));
        let r = request(w.srv.addr, "POST", &acs_path(), big, &h).await?;
        assert_eq!(r.0, 413);
        let huge = format!("SAMLResponse={}", "A".repeat(5 << 20));
        let r = request(w.srv.addr, "POST", &acs_path(), huge, &h).await?;
        assert_eq!(r.0, 413);
        let r = request(w.srv.addr, "GET", &acs_path(), String::new(), &[]).await?;
        assert_eq!(r.0, 405);
        let audit = w.audit().await?;
        assert!(
            audit.iter().all(|a| a.starts_with("saml.acs.")) && audit.len() >= 6,
            "{audit:?}"
        );
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

// ---- metadata fetch policy ---------------------------------------------------------

struct Recording {
    calls: std::sync::Mutex<Vec<String>>,
    body: Vec<u8>,
}
impl setjoin_identity::rp::Http for Recording {
    fn send(&self, request: hyper::Request<Vec<u8>>) -> setjoin_identity::rp::HttpFuture<'_> {
        self.calls.lock().unwrap().push(request.uri().to_string());
        let body = self.body.clone();
        Box::pin(async move { Ok(hyper::Response::builder().status(200).body(body).unwrap()) })
    }
}

async fn metadata_registered(url: &str, body: Vec<u8>) -> (bool, Vec<String>) {
    let _serial = SERIAL.lock().await;
    let http = Arc::new(Recording {
        calls: Default::default(),
        body,
    });
    let w = World::start_with(
        Opts {
            metadata: url.into(),
            ..Opts::default()
        },
        Some(http.clone()),
    )
    .await
    .unwrap();
    let r = request(w.srv.addr, "GET", &login_path(), String::new(), &[])
        .await
        .unwrap();
    w.close().await.unwrap();
    let calls = http.calls.lock().unwrap().clone();
    (r.0 == 302, calls)
}

#[tokio::test]
async fn metadata_is_fetched_over_https_only() {
    let xml = flows::metadata("Redirect").into_bytes();
    let (ok, calls) = metadata_registered("https://idp.example.test/metadata", xml.clone()).await;
    assert!(ok && calls.len() == 1, "{calls:?}");
    let (ok, calls) = metadata_registered("http://idp.example.test/metadata", xml).await;
    assert!(!ok, "an http metadata URL must not register");
    assert!(
        calls.is_empty(),
        "no request may be sent over http: {calls:?}"
    );
}
#[tokio::test]
async fn metadata_fetch_refuses_private_literals_before_any_transport() {
    let xml = flows::metadata("Redirect").into_bytes();
    for url in [
        "https://127.0.0.1/md",
        "https://[::1]/md",
        "https://10.1.2.3/md",
        "https://169.254.169.254/latest",
    ] {
        let (ok, calls) = metadata_registered(url, xml.clone()).await;
        assert!(
            !ok && calls.is_empty(),
            "{url}: registered={ok} calls={calls:?}"
        );
    }
}
#[tokio::test]
async fn metadata_response_over_one_mebibyte_is_refused() {
    let mut big = flows::metadata("Redirect");
    big.push_str(&" ".repeat((1 << 20) + 1));
    let (ok, calls) = metadata_registered("https://idp.example.test/big", big.into_bytes()).await;
    assert_eq!(calls.len(), 1);
    assert!(!ok, "an oversized metadata document must not register");
}

// ---- the replay cache's database posture (R4) ----------------------------------------

#[tokio::test]
async fn the_replay_cache_is_worker_only_and_expires_with_the_assertion() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts::default()).await.unwrap();
    let result = async {
        let user = w.account("samlacs-ttl").await?;
        w.link_legacy(user.user, "ttl-subject").await?;
        let s = start_login(&w).await?;
        let xml = answer(&s, "ttl-subject", "_a-ttl");
        let r = acs(&w, &xml, &s.relay, &[tracking(&s)]).await?;
        assert_eq!(r.0, 303, "{}", r.2);
        // Both IDs are stored, hashed, until the assertion's NotOnOrAfter plus the skew.
        let rows = w.c.query("SELECT kind,encode(token_hash,'hex'),extract(epoch FROM expires_at)::bigint FROM saml_assertion_replay WHERE registration_id=$1 ORDER BY kind", &[&REG]).await?;
        assert_eq!(rows.len(), 2);
        let expected = |id: &str| format!("{:x}", Sha256::digest(id.as_bytes()));
        assert_eq!(rows[0].get::<_, String>(0), "assertion");
        assert_eq!(rows[0].get::<_, String>(1), expected("_a-ttl"));
        assert_eq!(rows[1].get::<_, String>(0), "request");
        assert_eq!(rows[1].get::<_, String>(1), expected(&s.id));
        let ttl = rows[0].get::<_, i64>(2);
        let want = NOW_REAL() + 300 + 120;
        assert!((ttl - want).abs() <= 5, "row expires with the assertion plus skew: {ttl} vs {want}");
        // The application credential (frozen Go's) is denied by row security: it sees no
        // row, cannot insert, and its delete reaches nothing.
        let (app, conn) = tokio_postgres::connect(&std::env::var("DB_APP_DSN")?, tokio_postgres::NoTls).await?;
        tokio::spawn(conn);
        // load-test-schema.sh (so every lane template) ends with provision-roles.sql, which
        // restates the V281 grants: the app role holds no privilege on the table, so each
        // statement is refused with 42501. Row security stays the second layer, checked
        // directly below.
        let e = app.query_one("SELECT count(*) FROM saml_assertion_replay", &[]).await.expect_err("app select");
        assert_eq!(e.code().map(|c| c.code()), Some("42501"), "{e}");
        let e = app.execute("INSERT INTO saml_assertion_replay(registration_id,kind,token_hash,expires_at) VALUES($1,'assertion',digest('x','sha256'),now())", &[&REG]).await.expect_err("app insert");
        assert_eq!(e.code().map(|c| c.code()), Some("42501"), "{e}");
        let e = app.execute("DELETE FROM saml_assertion_replay", &[]).await.expect_err("app delete");
        assert_eq!(e.code().map(|c| c.code()), Some("42501"), "{e}");
        // Row security: every policy on the table is limited to the worker role, and the
        // table forces it on.
        let policies = w.c.query("SELECT policyname, qual, with_check FROM pg_policies WHERE tablename='saml_assertion_replay'", &[]).await?;
        assert!(!policies.is_empty(), "the replay cache keeps its row-security policy");
        for p in &policies {
            let text = format!("{:?}{:?}", p.get::<_, Option<String>>(1), p.get::<_, Option<String>>(2));
            assert!(text.contains("setjoin_worker"), "policy {} is worker-only: {text}", p.get::<_, String>(0));
        }
        let rls: bool = w.c.query_one("SELECT relrowsecurity FROM pg_class WHERE oid='public.saml_assertion_replay'::regclass", &[]).await?.get(0);
        assert!(rls, "row security is enabled on the replay cache");
        let kept: i64 = w.c.query_one("SELECT count(*) FROM saml_assertion_replay WHERE registration_id=$1", &[&REG]).await?.get(0);
        assert_eq!(kept, 2, "the app role could not delete the cache");
        // The reducer is the only door, and it fails closed on bad input.
        let call = |a: i64, id: &'static str, req: Option<&'static str>| {
            let app = &app;
            async move {
                let v: String = app.query_one("SELECT rust_identity_saml_consume($1,$2,$3,$4)::text", &[&a, &id, &req, &(NOW_REAL() + 600)]).await.unwrap().get(0);
                serde_json::from_str::<Value>(&v).unwrap()["status"].as_str().unwrap().to_owned()
            }
        };
        assert_eq!(call(REG, "_direct-1", Some("id-direct-1")).await, "consumed");
        assert_eq!(call(REG, "_direct-1", None).await, "replayed");
        assert_eq!(call(REG, "_direct-2", Some("id-direct-1")).await, "replayed");
        assert_eq!(call(REG, "_direct-3", None).await, "consumed");
        assert_eq!(call(999_999, "_direct-4", None).await, "unknown_registration");
        assert_eq!(call(0, "_direct-4", None).await, "invalid");
        // Deleting the registration removes its cache.
        w.c.execute("DELETE FROM saml_sp_registrations WHERE id=$1", &[&REG]).await?;
        let left: i64 = w.c.query_one("SELECT count(*) FROM saml_assertion_replay WHERE registration_id=$1", &[&REG]).await?.get(0);
        assert_eq!(left, 0);
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

#[tokio::test]
async fn a_link_purpose_acs_without_the_strict_cookies_links_and_never_logs_in() {
    let _serial = SERIAL.lock().await;
    // JIT is ON: a login-shaped ACS would provision and sign in this unlinked NameID.
    let mut w = World::start(Opts { normalized: true, jit: true, ..Opts::default() }).await.unwrap();
    let result = async {
        let user = w.account("samlacs-browser-link").await?;
        let domain = w.email(user.user).await?.split_once('@').unwrap().1.to_owned();
        let (token, flow, s) = begin_link(&w, user.user, "gofree-samlacs-browser").await?;
        let users = w.users().await?;
        let sessions = w.sessions(user.user).await?;
        let o = support::Opts {
            name_id: "browser-subject".into(),
            irt: Some(s.id.clone()),
            attrs: vec![("email".into(), vec![format!("browser@{domain}")])],
            ..live()
        };
        let r = acs(&w, &signed_assertion(&o, &SigSpec::new(rsa_idp())), &s.relay, &[tracking(&s)]).await?;
        assert_eq!(r.0, 200, "the browser's POST must be held, not answered with a login: {}", r.2);
        assert!(!set_cookies(&r).iter().any(|c| c.starts_with("access_token=")), "no session is minted");
        assert_eq!(w.users().await?, users, "nothing is provisioned");
        assert_eq!(w.sessions(user.user).await?, sessions);
        // A completion without the Strict cookies, or by another session, links nothing.
        let next = completion_of(&r.2);
        let bare = request(w.srv.addr, "GET", &next, String::new(), &[]).await?;
        assert_eq!(bare.0, 401, "{}", bare.2);
        let other = w.account("samlacs-browser-other").await?;
        let (other_token, other_flow, _) = begin_link(&w, other.user, "gofree-samlacs-browser-2").await?;
        let users = w.users().await?;
        let stolen = request(w.srv.addr, "GET", &next, String::new(), &[("cookie", &format!("{other_flow}; access_token={other_token}"))]).await?;
        assert_ne!(stolen.0, 303, "another session's flow cannot take this assertion: {}", stolen.2);
        let n: i64 = w.c.query_one("SELECT count(*) FROM user_identity_links WHERE external_subject='browser-subject'", &[]).await?.get(0);
        assert_eq!(n, 0);
        // The session that started the link finishes it, once.
        let done = request(w.srv.addr, "GET", &next, String::new(), &[("cookie", &format!("{flow}; access_token={token}"))]).await?;
        assert_eq!(done.0, 303, "{}", done.2);
        let n: i64 = w.c.query_one("SELECT count(*) FROM user_identity_links l WHERE l.user_id=$1 AND l.external_subject='browser-subject' AND l.state='active'", &[&user.user]).await?.get(0);
        assert_eq!(n, 1);
        assert_eq!(w.users().await?, users);
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

#[tokio::test]
async fn a_login_purpose_answer_never_completes_a_link() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts { normalized: true, ..Opts::default() }).await.unwrap();
    let result = async {
        let user = w.account("samlacs-purpose").await?;
        // The browser holds a live link flow (Strict cookies) while an ordinary login answers.
        let (token, flow, _link) = begin_link(&w, user.user, "gofree-samlacs-purpose").await?;
        let s = start_login(&w).await?;
        let r = acs(&w, &answer(&s, "purpose-subject", "_a-purpose"), &s.relay, &[tracking(&s), flow, format!("access_token={token}")]).await?;
        assert_eq!(r.0, 401, "an unlinked login answer is refused: {}", r.2);
        let n: i64 = w.c.query_one("SELECT count(*) FROM user_identity_links WHERE external_subject='purpose-subject'", &[]).await?.get(0);
        assert_eq!(n, 0, "a login-purpose answer links nothing");
        // And a tracking cookie is bound to its registration and purpose: the cookie text
        // names both, and carries SameSite=None for the IdP's cross-site POST.
        let started = request(w.srv.addr, "GET", &login_path(), String::new(), &[]).await?;
        let cookie = set_cookies(&started).into_iter().find(|c| c.starts_with("saml_")).unwrap();
        assert!(cookie.contains("SameSite=None") && cookie.contains("Secure"), "{cookie}");
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

#[tokio::test]
async fn saml_jit_refuses_an_address_another_user_already_holds() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Opts { normalized: true, jit: true, ..Opts::default() }).await.unwrap();
    let result = async {
        let user = w.account("samlacs-collide").await?;
        let email = w.email(user.user).await?;
        let alias = format!("alias-{}", email);
        // An alias of the existing user, and the user's own address, are both taken.
        w.c.execute("INSERT INTO aliases(mailbox_id,domain_id,email) SELECT id,domain_id,$2 FROM mailboxes WHERE user_id=$1 AND is_primary", &[&user.user, &alias]).await?;
        let users = w.users().await?;
        for (n, address) in [email.clone(), alias.clone()].into_iter().enumerate() {
            let s = start_login(&w).await?;
            let o = support::Opts {
                name_id: format!("collide-{n}"),
                assertion_id: format!("_a-collide-{n}"),
                irt: Some(s.id.clone()),
                attrs: vec![("email".into(), vec![address])],
                ..live()
            };
            let r = acs(&w, &signed_assertion(&o, &SigSpec::new(rsa_idp())), &s.relay, &[tracking(&s)]).await?;
            assert_eq!(r.0, 409, "{} {:?}", r.2, w.audit().await?);
        }
        assert_eq!(w.users().await?, users, "no user is provisioned");
        let n: i64 = w.c.query_one("SELECT count(*) FROM user_identity_links WHERE external_subject LIKE 'collide-%'", &[]).await?.get(0);
        assert_eq!(n, 0, "and nothing is linked");
        Ok::<_, Err>(())
    }
    .await;
    w.close().await.unwrap();
    result.unwrap();
}

#[tokio::test]
async fn metadata_hostnames_that_resolve_to_private_addresses_are_refused_by_the_client() {
    let _serial = SERIAL.lock().await;
    // `localhost` is a name, not a literal: only the shared post-DNS resolver can refuse it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = accepted.clone();
    let task = tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    let w = World::start(Opts { metadata: format!("https://localhost:{port}/md"), ..Opts::default() }).await.unwrap();
    let r = request(w.srv.addr, "GET", &login_path(), String::new(), &[]).await.unwrap();
    w.close().await.unwrap();
    task.abort();
    assert_eq!(r.0, 404, "the registration must not load");
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 0, "no connection reached a private address");
}
