#![allow(dead_code)]
//! Owner-approved OIDC relying-party security fixes (#530, 2026-11-06). Each
//! test states the secure behaviour; `scripts/test-secfix8-mutants.py` restores
//! the frozen-Go defect and requires the matching test to fail.
mod common;
include!("rp_oracle/harness.rs");
#[path = "rp_oracle/flows.rs"]
mod flows;
#[path = "rp_oracle/idp.rs"]
mod idp;
#[path = "rp_oracle/observation.rs"]
mod observation;
#[path = "rp_oracle/settlement.rs"]
mod settlement;
use setjoin_conformance::fixture as fx;
use setjoin_identity::rp::{Provider, Registry};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap()
}

async fn registry() -> Arc<Registry> {
    let exec = setjoin_pg::ScopedExecutor::from_dsn(&std::env::var("DB_APP_DSN").unwrap(), 4).unwrap();
    Registry::load(
        exec,
        fixture()["secret"].as_str().unwrap().as_bytes(),
        idp::http().unwrap(),
    )
    .await
}
async fn exchange(
    env: &flows::Env,
    provider: &Provider,
    extra: Value,
) -> (Result<setjoin_identity::rp::VerifiedClaims, String>, String) {
    let flow = provider.authorization().unwrap();
    let code = env.idp.state.code(&flow.verifier, &flow.nonce, extra);
    (provider.exchange(&code, &flow.verifier).await, flow.nonce)
}
fn patch(env: &flows::Env, doc: Value) {
    *env.idp.state.discovery.lock().unwrap() = doc;
}
async fn library<F, Fut>(f: F)
where
    F: FnOnce(flows::Env) -> Fut,
    Fut: std::future::Future<Output = Result<(), Err>>,
{
    let _serial = SERIAL.lock().await;
    let env = flows::Env::start(false).await.unwrap();
    f(env).await.unwrap();
}

#[tokio::test]
async fn discovered_token_and_jwks_endpoints_must_be_https() {
    library(|env| async move {
        assert!(registry().await.provider("idfed2").is_some(), "control: https endpoints load");
        for key in ["token_endpoint", "jwks_uri"] {
            patch(&env, json!({key: "http://idp.idfed2.test:19440/plain"}));
            assert!(
                registry().await.provider("idfed2").is_none(),
                "a plain-http {key} must refuse the provider"
            );
        }
        patch(&env, json!({}));
        env.close().await
    })
    .await;
}

#[tokio::test]
async fn id_token_alg_is_pinned_to_the_discovery_list_asymmetric_only() {
    library(|env| async move {
        patch(&env, json!({"id_token_signing_alg_values_supported": ["ES256"]}));
        let provider = registry().await.provider("idfed2").expect("ES256 provider loads");
        let (claims, _) = exchange(&env, &provider, json!({"email_verified": true})).await;
        assert!(claims.is_err(), "an RS256 token must not pass a provider that advertises only ES256");
        patch(&env, json!({"id_token_signing_alg_values_supported": ["RS256"]}));
        let provider = registry().await.provider("idfed2").unwrap();
        let (claims, _) = exchange(&env, &provider, json!({"email_verified": true})).await;
        assert!(claims.is_ok(), "control: the advertised algorithm verifies");
        for symmetric in [json!(["HS256"]), json!(["none"]), json!(["HS512", "none"])] {
            patch(&env, json!({"id_token_signing_alg_values_supported": symmetric}));
            assert!(
                registry().await.provider("idfed2").is_none(),
                "a provider with no asymmetric algorithm must be refused: {symmetric}"
            );
        }
        patch(&env, json!({}));
        let provider = registry().await.provider("idfed2").unwrap();
        let (claims, _) = exchange(&env, &provider, json!({"email_verified": true})).await;
        assert!(claims.is_ok(), "control: an absent list defaults to RS256 (OIDC Discovery 3)");
        env.close().await
    })
    .await;
}

#[test]
fn only_asymmetric_advertised_algorithms_survive() {
    let names = |v: &[&str]| {
        let list: Vec<String> = v.iter().map(|s| s.to_string()).collect();
        setjoin_identity::rp::id_token_algs(Some(&list)).len()
    };
    assert_eq!(names(&["HS256", "HS384", "HS512", "none"]), 0);
    assert_eq!(names(&["RS256", "HS256", "ES256", "PS384", "bogus"]), 3);
    assert_eq!(setjoin_identity::rp::id_token_algs(None).len(), 1);
}

#[tokio::test]
async fn idp_response_bodies_are_capped() {
    library(|env| async move {
        let provider = registry().await.provider("idfed2").unwrap();
        let (claims, _) = exchange(&env, &provider, json!({"email_verified": true})).await;
        assert!(claims.is_ok(), "control: a normal token response is accepted");
        let (claims, _) = exchange(&env, &provider, json!({"email_verified": true, "_oracle_pad": 2_000_000})).await;
        assert!(claims.is_err(), "a 2 MB token response must be refused");
        patch(&env, json!({"padding": "a".repeat(2_000_000)}));
        assert!(registry().await.provider("idfed2").is_none(), "a 2 MB discovery document must be refused");
        patch(&env, json!({}));
        env.close().await
    })
    .await;
}

#[tokio::test]
async fn only_the_verified_email_claim_is_an_email() {
    library(|env| async move {
        let provider = registry().await.provider("idfed2").unwrap();
        let victim = json!("victim@idfed2.test");
        let (claims, nonce) = exchange(
            &env,
            &provider,
            json!({"email": null, "email_verified": true, "preferred_username": victim, "upn": victim}),
        )
        .await;
        let denied = claims.unwrap().assertion(Some(&nonce), &provider).err();
        assert_eq!(denied, Some("no email in ID token"), "preferred_username/upn must not become the email");
        let (claims, nonce) = exchange(
            &env,
            &provider,
            json!({"email": "actor@idfed2.test", "email_verified": true, "preferred_username": victim, "upn": victim}),
        )
        .await;
        assert!(claims.unwrap().assertion(Some(&nonce), &provider).is_ok(), "control: a verified email still works");
        env.close().await
    })
    .await;
}

#[tokio::test]
async fn an_empty_or_missing_nonce_never_matches() {
    library(|env| async move {
        let provider = registry().await.provider("idfed2").unwrap();
        let (claims, nonce) = exchange(&env, &provider, json!({"email_verified": true, "nonce": ""})).await;
        let claims = claims.unwrap();
        assert!(!claims.nonce_matches(Some("")), "empty cookie against an empty claim");
        assert!(!claims.nonce_matches(None));
        assert!(!claims.nonce_matches(Some(&nonce)));
        let (claims, _) = exchange(&env, &provider, json!({"email_verified": true, "nonce": null})).await;
        let claims = claims.unwrap();
        assert!(!claims.nonce_matches(Some("")), "empty cookie against a nonce-less token");
        let (claims, nonce) = exchange(&env, &provider, json!({"email_verified": true})).await;
        assert!(claims.unwrap().nonce_matches(Some(&nonce)), "control: the real nonce matches");
        env.close().await
    })
    .await;
}

struct World {
    env: flows::Env,
    a: fx::Account,
    b: fx::Account,
    email: String,
    receipts: Vec<String>,
    group: Option<i64>,
    old_identity: Option<bool>,
    old_mode: Option<String>,
    normalized: bool,
}
impl World {
    async fn start(normalized: bool, groups: bool) -> World {
        let env = flows::Env::start(false).await.unwrap();
        let c = &env.c;
        // A failed assertion (for example under a restored-bug mutant) skips `finish`: drop what
        // an earlier run left on the fixture mailboxes before the shared leftover cleanup.
        c.batch_execute(
            "DELETE FROM sso_distribution_group_provenance WHERE mailbox_id IN (SELECT m.id FROM mailboxes m JOIN users u ON u.id=m.user_id WHERE u.username LIKE 'idfed2-%@oracle-%'); \
             DELETE FROM distribution_group_members WHERE mailbox_id IN (SELECT m.id FROM mailboxes m JOIN users u ON u.id=m.user_id WHERE u.username LIKE 'idfed2-%@oracle-%'); \
             DELETE FROM distribution_groups WHERE mailbox_id IN (SELECT m.id FROM mailboxes m JOIN users u ON u.id=m.user_id WHERE u.username LIKE 'idfed2-%@oracle-%')",
        )
        .await
        .unwrap();
        settlement::cleanup_leftovers(c).await.unwrap();
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
        c.execute("UPDATE users SET oidc_subject='actor-subject',oidc_issuer=$2 WHERE id=$1", &[&a.user, &idp::ISSUER])
            .await
            .unwrap();
        let mut group = None;
        if groups {
            let g: i64 = c
                .query_one("INSERT INTO distribution_groups(mailbox_id) VALUES($1) RETURNING id", &[&b.mailbox])
                .await
                .unwrap()
                .get(0);
            group = Some(g);
            env.configure(json!({"group_mappings":[{"idp_group":"engineering","distribution_group_id":g}]}))
                .await
                .unwrap();
        }
        if normalized {
            c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.identity_model_v2',true) ON CONFLICT(key) DO UPDATE SET enabled=true", &[]).await.unwrap();
            c.query_one("SELECT identity_auth_link($1,$1,'oidc',$2,'actor-subject','oidc:idfed2','IDFED2 fixture')", &[&a.user, &idp::ISSUER]).await.unwrap();
            c.execute("UPDATE identity_sources SET read_mode='normalized' WHERE provider_key='oidc:idfed2'", &[]).await.unwrap();
        }
        World { env, a, b, email, receipts, group, old_identity, old_mode, normalized }
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
    async fn finish(self) {
        let c = &self.env.c;
        if self.normalized {
            if let Some(mode) = &self.old_mode {
                c.execute("UPDATE identity_sources SET read_mode=$1 WHERE provider_key='oidc:idfed2'", &[mode]).await.unwrap();
            }
            match self.old_identity {
                Some(old) => c.execute("UPDATE feature_toggles SET enabled=$1 WHERE key='feature.identity_model_v2'", &[&old]).await.unwrap(),
                None => c.execute("DELETE FROM feature_toggles WHERE key='feature.identity_model_v2'", &[]).await.unwrap(),
            };
        }
        common::restore_receipts(c, &self.receipts).await;
        if let Some(g) = self.group {
            c.execute("DELETE FROM distribution_groups WHERE id=$1", &[&g]).await.unwrap();
        }
        settlement::cleanup_identity(c, self.a.user).await.unwrap();
        fx::remove(c, &self.a).await.unwrap();
        fx::remove(c, &self.b).await.unwrap();
        c.execute("WITH s AS (SELECT x.id FROM identity_sources x WHERE x.provider_key IN ('oidc:idfed2') AND NOT EXISTS (SELECT 1 FROM user_identity_links l WHERE l.source_id=x.id)), a AS (DELETE FROM identity_auth_shadow_hours WHERE source_id IN (SELECT id FROM s)), b AS (DELETE FROM identity_auth_shadow_link_evidence WHERE source_id IN (SELECT id FROM s)), c AS (DELETE FROM identity_shadow_divergences WHERE source_id IN (SELECT id FROM s)) DELETE FROM identity_sources WHERE id IN (SELECT id FROM s)", &[]).await.unwrap();
        self.env.close().await.unwrap();
    }
}

#[tokio::test]
async fn the_first_group_grant_records_provider_provenance_so_an_idp_removal_revokes_it() {
    let _serial = SERIAL.lock().await;
    let w = World::start(false, true).await;
    let g = w.group.unwrap();
    let probe = || async {
        let row = w.env.c.query_one(
            "SELECT EXISTS(SELECT 1 FROM distribution_group_members WHERE mailbox_id=$1 AND group_id=$2),EXISTS(SELECT 1 FROM sso_distribution_group_provenance WHERE mailbox_id=$1 AND group_id=$2 AND provider_key='oidc:idfed2')",
            &[&w.a.mailbox, &g],
        ).await.unwrap();
        (row.get::<_, bool>(0), row.get::<_, bool>(1))
    };
    let first = w.callback(json!({})).await;
    assert_eq!(first.0, 200, "{}", first.2);
    assert_eq!(probe().await, (true, true), "the first grant must carry provenance");
    let second = w.callback(json!({"groups": []})).await;
    assert_eq!(second.0, 200, "{}", second.2);
    assert_eq!(probe().await, (false, false), "the IdP no longer asserts the group: the grant is revoked");
    w.finish().await;
}

#[tokio::test]
async fn a_successful_callback_clears_the_flow_cookies_normalized_or_not() {
    for normalized in [false, true] {
        let _serial = SERIAL.lock().await;
        let w = World::start(normalized, false).await;
        let (status, headers, text) = w.callback(json!({})).await;
        assert_eq!(status, 200, "{text}");
        let cookies = headers["set-cookie"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_owned()).collect::<Vec<_>>();
        for name in ["oidc_state", "oidc_verifier", "oidc_nonce", "oidc_provider"] {
            assert!(
                cookies.iter().any(|c| c.starts_with(&format!("{name}=;")) && c.contains("Max-Age=0")),
                "normalized={normalized}: {name} must be cleared on success: {cookies:?}"
            );
        }
        w.finish().await;
    }
}
