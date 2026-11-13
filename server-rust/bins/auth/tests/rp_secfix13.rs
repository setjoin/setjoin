#![allow(dead_code)]
//! Owner-approved OIDC relying-party follow-ups (#547, decision 2026-11-05). Each test states
//! the secure behaviour at the real front door; `scripts/test-secfix13-mutants.py` restores the
//! defect (feature `oracle-mutants`, `SETJOIN_SECFIX13_MUTANT`, or a bug-restored reducer) and
//! requires the matching test to fail.
mod common;
include!("rp_oracle/harness.rs");
#[path = "rp_oracle/flows.rs"]
mod flows;
#[path = "rp_oracle/idp.rs"]
mod idp;
#[path = "rp_oracle/link.rs"]
mod link;
#[path = "rp_oracle/observation.rs"]
mod observation;
#[path = "rp_oracle/settlement.rs"]
mod settlement;
use setjoin_conformance::fixture as fx;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../tests/conformance/identity-login/keys.json")).unwrap()
}

/// How the OIDC source is configured for a case.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// `feature.identity_model_v2` off, no source.
    Legacy,
    /// Feature on, the source serves normalized reads.
    Normalized,
    /// Feature on, the source only observes (read_mode `shadow`).
    Shadow,
}

/// What an earlier run left behind (a failed assertion, for example under a restored-bug
/// mutant, skips `finish`): the users a JIT login created, the review candidates a blocked
/// attempt records against the fixture users, then the shared fixture leftovers.
async fn purge(c: &tokio_postgres::Client) {
    for row in c
        .query("SELECT u.id,m.id FROM users u JOIN mailboxes m ON m.user_id=u.id AND m.is_primary WHERE u.email LIKE 'provisioned13@%'", &[])
        .await
        .unwrap()
    {
        let user: i64 = row.get(0);
        c.execute("DELETE FROM identity_match_candidates WHERE candidate_user_id=$1", &[&user]).await.unwrap();
        settlement::cleanup_identity(c, user).await.unwrap();
        let account = fx::Account { user, domain: 0, mailbox: row.get(1), inbox: 0, label: 0, two_labels: 0, inbox_only: 0 };
        fx::remove(c, &account).await.unwrap();
    }
    c.batch_execute("DELETE FROM identity_match_candidates WHERE candidate_user_id IN (SELECT id FROM users WHERE username LIKE 'idfed2-%@oracle-%')").await.unwrap();
    settlement::cleanup_leftovers(c).await.unwrap();
}

struct World {
    env: flows::Env,
    a: fx::Account,
    b: fx::Account,
    email: String,
    domain: String,
    receipts: Vec<String>,
    old_identity: Option<bool>,
    old_mode: Option<String>,
    mode: Mode,
    created: Vec<String>,
}
impl World {
    async fn start(mode: Mode) -> World {
        let env = flows::Env::start(false).await.unwrap();
        let c = &env.c;
        purge(c).await;
        let a = fx::account(c, "idfed2-actor").await.unwrap();
        let b = fx::account(c, "idfed2-foreign").await.unwrap();
        let receipts = common::receipt_ids(c).await;
        let old_identity = c
            .query_opt("SELECT enabled FROM feature_toggles WHERE key='feature.identity_model_v2'", &[])
            .await
            .unwrap()
            .map(|r| r.get::<_, bool>(0));
        let old_mode = c
            .query_opt("SELECT read_mode FROM identity_sources WHERE provider_key='oidc:idfed2'", &[])
            .await
            .unwrap()
            .map(|r| r.get::<_, String>(0));
        let email: String = c.query_one("SELECT email FROM users WHERE id=$1", &[&a.user]).await.unwrap().get(0);
        let domain = email.split_once('@').unwrap().1.to_owned();
        c.execute("UPDATE users SET oidc_subject='actor-subject',oidc_issuer=$2 WHERE id=$1", &[&a.user, &idp::ISSUER])
            .await
            .unwrap();
        if mode != Mode::Legacy {
            c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.identity_model_v2',true) ON CONFLICT(key) DO UPDATE SET enabled=true", &[]).await.unwrap();
            c.query_one("SELECT identity_auth_link($1,$1,'oidc',$2,'actor-subject','oidc:idfed2','IDFED2 fixture')", &[&a.user, &idp::ISSUER]).await.unwrap();
            let read_mode = if mode == Mode::Normalized { "normalized" } else { "shadow" };
            c.execute("UPDATE identity_sources SET read_mode=$1 WHERE provider_key='oidc:idfed2'", &[&read_mode]).await.unwrap();
        }
        World { env, a, b, email, domain, receipts, old_identity, old_mode, mode, created: Vec::new() }
    }
    async fn callback(&self, extra: Value) -> (u16, Value, String) {
        let response = request(self.env.gw.addr, "GET", "/auth/oidc/login?provider=idfed2", String::new(), &[]).await.unwrap();
        let (_, flow) = flows::normalize_flow(response).unwrap();
        let cookie = flow.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        let mut claims = json!({"email": self.email, "email_verified": true});
        for (k, v) in extra.as_object().unwrap() {
            claims[k] = v.clone();
        }
        let code = self.env.idp.state.code(&flow["oidc_verifier"], &flow["oidc_nonce"], claims);
        let path = setjoin_identity::oidc::query_response(
            "/auth/oidc/callback",
            &[("state", &flow["oidc_state"]), ("code", &code)],
            false,
        );
        request(self.env.gw.addr, "GET", &path, String::new(), &[("cookie", &cookie)]).await.unwrap()
    }
    async fn email_of(&self, user: i64) -> String {
        self.env.c.query_one("SELECT email FROM users WHERE id=$1", &[&user]).await.unwrap().get(0)
    }
    async fn finish(self) {
        let c = &self.env.c;
        for email in &self.created {
            if let Some(row) = c
                .query_opt("SELECT u.id,u.domain_id,m.id FROM users u JOIN mailboxes m ON m.user_id=u.id AND m.is_primary WHERE u.email=$1", &[email])
                .await
                .unwrap()
            {
                let user: i64 = row.get(0);
                settlement::cleanup_identity(c, user).await.unwrap();
                let account = fx::Account { user, domain: 0, mailbox: row.get(2), inbox: 0, label: 0, two_labels: 0, inbox_only: 0 };
                fx::remove(c, &account).await.unwrap();
            }
        }
        if self.mode != Mode::Legacy {
            if let Some(mode) = &self.old_mode {
                c.execute("UPDATE identity_sources SET read_mode=$1 WHERE provider_key='oidc:idfed2'", &[mode]).await.unwrap();
            }
            match self.old_identity {
                Some(old) => c.execute("UPDATE feature_toggles SET enabled=$1 WHERE key='feature.identity_model_v2'", &[&old]).await.unwrap(),
                None => c.execute("DELETE FROM feature_toggles WHERE key='feature.identity_model_v2'", &[]).await.unwrap(),
            };
        }
        common::restore_receipts(c, &self.receipts).await;
        c.execute("DELETE FROM identity_match_candidates WHERE candidate_user_id=ANY($1)", &[&vec![self.a.user, self.b.user]]).await.unwrap();
        settlement::cleanup_identity(c, self.a.user).await.unwrap();
        fx::remove(c, &self.a).await.unwrap();
        fx::remove(c, &self.b).await.unwrap();
        c.execute("WITH s AS (SELECT x.id FROM identity_sources x WHERE x.provider_key IN ('oidc:idfed2') AND NOT EXISTS (SELECT 1 FROM user_identity_links l WHERE l.source_id=x.id)), a AS (DELETE FROM identity_auth_shadow_hours WHERE source_id IN (SELECT id FROM s)), b AS (DELETE FROM identity_auth_shadow_link_evidence WHERE source_id IN (SELECT id FROM s)), c AS (DELETE FROM identity_shadow_divergences WHERE source_id IN (SELECT id FROM s)) DELETE FROM identity_sources WHERE id IN (SELECT id FROM s)", &[]).await.unwrap();
        self.env.close().await.unwrap();
    }
}

#[tokio::test]
async fn an_idp_asserted_address_never_rewrites_the_linked_account_email() {
    for mode in [Mode::Legacy, Mode::Normalized] {
        let _serial = SERIAL.lock().await;
        let w = World::start(mode).await;
        let moved = format!("moved@{}", w.domain);
        let (status, _, text) = w.callback(json!({"email": moved})).await;
        assert_eq!(status, 200, "{text}");
        assert_eq!(w.email_of(w.a.user).await, w.email, "the IdP moved the mailbox address of a linked account");
        let holder: i64 = w.env.c.query_one("SELECT count(*) FROM users WHERE lower(email)=lower($1)", &[&moved]).await.unwrap().get(0);
        assert_eq!(holder, 0, "no account may carry the IdP-asserted address");
        w.finish().await;
    }
}

#[tokio::test]
async fn a_jit_login_in_shadow_read_mode_creates_its_link_and_can_log_in_again() {
    let _serial = SERIAL.lock().await;
    let mut w = World::start(Mode::Shadow).await;
    w.env.configure(json!({"jit_enabled": true})).await.unwrap();
    let email = format!("provisioned13@{}", w.domain);
    w.created.push(email.clone());
    let jit = || json!({"sub": "jit-subject-13", "email": email});
    let (status, _, text) = w.callback(jit()).await;
    assert_eq!(status, 200, "a shadow-mode JIT login must succeed: {text}");
    let links: i64 = w.env.c
        .query_one("SELECT count(*) FROM user_identity_links l JOIN users u ON u.id=l.user_id WHERE u.email=$1 AND l.external_subject='jit-subject-13' AND l.state='active'", &[&email])
        .await.unwrap().get(0);
    assert_eq!(links, 1, "the created user must carry its authentication link (no orphan)");
    let (again, _, text) = w.callback(jit()).await;
    assert_eq!(again, 200, "the retry must not fail against an orphan: {text}");
    let users: i64 = w.env.c.query_one("SELECT count(*) FROM users WHERE email=$1", &[&email]).await.unwrap().get(0);
    assert_eq!(users, 1);
    w.finish().await;
}

#[tokio::test]
async fn a_jit_address_collision_is_a_conflict_not_a_server_error() {
    for mode in [Mode::Normalized, Mode::Shadow] {
        let _serial = SERIAL.lock().await;
        let w = World::start(mode).await;
        w.env.configure(json!({"jit_enabled": true})).await.unwrap();
        // A new subject asserting an address an existing person already holds.
        let (status, _, text) = w.callback(json!({"sub": "collider-13", "email": w.email})).await;
        assert_eq!(status, 409, "an address collision is a conflict, got {status}: {text}");
        assert!(text.contains("explicit account linking is required"), "{text}");
        let users: i64 = w.env.c.query_one("SELECT count(*) FROM users WHERE lower(email)=lower($1)", &[&w.email]).await.unwrap().get(0);
        assert_eq!(users, 1, "nothing is provisioned for a blocked address");
        w.finish().await;
    }
}

fn set_cookies(headers: &Value) -> Vec<String> {
    headers["set-cookie"].as_array().map(|a| a.iter().map(|v| v.as_str().unwrap().to_owned()).collect()).unwrap_or_default()
}

#[tokio::test]
async fn an_oidc_link_completes_same_site_after_the_cross_site_callback() {
    let _serial = SERIAL.lock().await;
    {
        let probe = flows::Env::start(false).await.unwrap();
        purge(&probe.c).await;
        probe.close().await.unwrap();
    }
    let env = link::Env::start().await.unwrap();
    let addr = env.base.gw.addr;
    let result = async {
        let access = format!("access_token={}", env.token);
        let response = request(addr, "POST", "/auth/oidc/link?provider=idfed2", String::new(), &[("cookie", &access)]).await?;
        assert_eq!(response.0, 302);
        // The callback is a cross-site navigation: the flow cookies must travel on it.
        for cookie in set_cookies(&response.1) {
            assert!(cookie.contains("SameSite=Lax"), "link flow cookie must be SameSite=Lax: {cookie}");
            assert!(!cookie.contains("SameSite=Strict"), "{cookie}");
        }
        let (_, flow) = flows::normalize_flow(response)?;
        assert!(flow.contains_key("identity_link_flow"));
        let cookie = flow.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        let code = env.base.idp.state.code(&flow["oidc_verifier"], &flow["oidc_nonce"], json!({"sub": "linked-subject-13", "email_verified": true}));
        let path = setjoin_identity::oidc::query_response("/auth/oidc/callback", &[("state", &flow["oidc_state"]), ("code", &code)], false);
        let before = env.effects().await?;
        // The IdP's redirect carries no SameSite=Strict `access_token` cookie.
        let held = request(addr, "GET", &path, String::new(), &[("cookie", &cookie)]).await?;
        assert_eq!(held.0, 200, "the callback must hold the assertion for the same-site step: {}", held.2);
        let next = held.2.split("url=").nth(1).and_then(|s| s.split('"').next()).ok_or("no completion url")?.to_owned();
        assert!(next.starts_with("/auth/oidc/link/complete?provider=idfed2&token="), "{next}");
        let spent = set_cookies(&held.1);
        assert!(!spent.iter().any(|c| c.starts_with("identity_link_flow=")), "the flow cookie must survive to the completion request: {spent:?}");
        assert_eq!(env.effects().await?, before, "holding links nothing and mints nothing");
        let count = |sql: &'static str| {
            let c = &env.base.c;
            let user = env.a.user;
            async move { c.query_one(sql, &[&user]).await.map(|r| r.get::<_, i64>(0)) }
        };
        assert_eq!(count("SELECT count(*) FROM user_identity_links WHERE user_id=$1 AND external_subject='linked-subject-13'").await?, 0);
        let flow_only = format!("identity_link_flow={}", flow["identity_link_flow"]);
        // Without the session the completion is refused and the token is not spent.
        let anonymous = request(addr, "GET", &next, String::new(), &[("cookie", &flow_only)]).await?;
        assert_eq!(anonymous.0, 401, "{}", anonymous.2);
        // Another user's session cannot complete this flow.
        let email_b: String = env.base.c.query_one("SELECT email FROM users WHERE id=$1", &[&env.b.user]).await?.get(0);
        let foreign = settlement::session_token(env.b.user, &email_b, "aal2").await?;
        let stolen = request(addr, "GET", &next, String::new(), &[("cookie", &format!("{flow_only}; access_token={foreign}"))]).await?;
        assert_eq!(stolen.0, 403, "{}", stolen.2);
        assert_eq!(count("SELECT count(*) FROM user_identity_links WHERE user_id=$1 AND external_subject='linked-subject-13'").await?, 0);
        // HEAD must not spend the one-use token.
        let head = request(addr, "HEAD", &next, String::new(), &[("cookie", &format!("{flow_only}; {access}"))]).await?;
        assert_eq!(head.0, 405);
        let done = request(addr, "GET", &next, String::new(), &[("cookie", &format!("{flow_only}; {access}"))]).await?;
        assert_eq!(done.0, 303, "{}", done.2);
        assert!(done.1.to_string().contains("/settings?identity=linked"), "{}", done.1);
        assert_eq!(count("SELECT count(*) FROM user_identity_links WHERE user_id=$1 AND external_subject='linked-subject-13' AND state='active'").await?, 1);
        let replay = request(addr, "GET", &next, String::new(), &[("cookie", &format!("{flow_only}; {access}"))]).await?;
        assert_ne!(replay.0, 303, "a held assertion is single use: {}", replay.2);
        Ok::<(), Err>(())
    }
    .await;
    env.close().await.unwrap();
    result.unwrap();
}
