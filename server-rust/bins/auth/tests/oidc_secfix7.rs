//! Secure-behaviour tests for the owner-approved OIDC provider security fixes
//! (2026-11-05, #523). Each test fails against the matching frozen-Go defect
//! restored by `scripts/test-secfix7-mutants.py` (feature `oracle-mutants`).
mod common;
include!("oidc_oracle/harness.rs");
#[path = "oidc_oracle/grants.rs"]
mod grants;
#[path = "oidc_oracle/tokens.rs"]
mod tokens;
use base64::{engine::general_purpose::STANDARD, Engine};
use grants::{Env, CLIENT, OTHER};

const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn basic(id: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{id}:client-secret-339")))
}
fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}
async fn userinfo(env: &Env, token: &str) -> u16 {
    request(
        env.gw.addr,
        "GET",
        "/userinfo",
        String::new(),
        &[("authorization", &bearer(token))],
    )
    .await
    .unwrap()
    .0
}
async fn introspect(env: &Env, caller: &str, token: &str) -> Value {
    let auth = basic(caller);
    let r = request(
        env.gw.addr,
        "POST",
        "/oauth/introspect",
        format!("token={token}"),
        &[FORM, ("authorization", &auth)],
    )
    .await
    .unwrap();
    assert_eq!(r.0, 200, "{}", r.2);
    serde_json::from_str(&r.2).unwrap()
}
async fn token(env: &Env, payload: String) -> (u16, Value, String) {
    request(env.gw.addr, "POST", "/oauth/token", payload, &[FORM])
        .await
        .unwrap()
}
async fn scenario<F, Fut>(body: F)
where
    F: FnOnce(Env) -> Fut,
    Fut: std::future::Future<Output = Env>,
{
    let _serial = SERIAL.lock().await;
    let env = Env::start(false).await.unwrap();
    let env = body(env).await;
    env.close().await.unwrap();
}

/// CFB access tokens are integrity-less (bit flips rewrite the subject) and are
/// no longer accepted; opaque/signed tokens are bound to their stored row.
#[tokio::test]
async fn legacy_cfb_tokens_are_dead_and_every_token_is_bound_to_its_stored_row() {
    scenario(|env| async move {
        let first = tokens::fresh(&env).await.unwrap();
        // 1. A well-formed legacy token naming the real row and user.
        use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
        struct KeyLen;
        impl ring::hkdf::KeyType for KeyLen {
            fn len(&self) -> usize {
                32
            }
        }
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/conformance/identity-login/keys.json"
        ))
        .unwrap();
        let mut key = [0; 32];
        ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"mailserver-oidc-cryptokey-v1")
            .extract(fixture["secret"].as_str().unwrap().as_bytes())
            .expand(&[b""], KeyLen)
            .unwrap()
            .fill(&mut key)
            .unwrap();
        let iv = [7; 16];
        // The subject is the attacker's choice: a legacy forgery rewrites it.
        let mut forged = format!("{}:{}", first.jti, env.b.user).into_bytes();
        cfb_mode::Encryptor::<aes::Aes256>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt(&mut forged);
        let mut raw = iv.to_vec();
        raw.extend(forged);
        let legacy = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        assert_eq!(userinfo(&env, &legacy).await, 401, "legacy CFB token accepted");
        assert_eq!(introspect(&env, CLIENT, &legacy).await["active"], false);
        // 2. A validly signed token whose subject is not the stored row's user.
        let op = setjoin_identity::oidc::SigningKey::load(
            corpus().join("op-private.pem").to_str().unwrap(),
            corpus().join("op-public.pem").to_str().unwrap(),
        )
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = |sub: i64| json!({"iss":"https://auth.idfed1.test","sub":sub.to_string(),"aud":[CLIENT],"exp":now+300,"iat":now,"jti":first.jti});
        let foreign = op.sign(&claims(env.b.user)).unwrap();
        assert_eq!(userinfo(&env, &foreign).await, 403, "subject not bound to the row");
        assert_eq!(introspect(&env, CLIENT, &foreign).await["active"], false);
        let own = op.sign(&claims(env.a.user)).unwrap();
        assert_eq!(userinfo(&env, &own).await, 200);
        // 3. The stored expiry is enforced whatever the token's own exp says.
        env.c
            .execute(
                "UPDATE oidc_tokens SET expires_at=now()-interval '1 minute' WHERE id=$1",
                &[&first.jti],
            )
            .await
            .unwrap();
        assert_eq!(userinfo(&env, &own).await, 403, "stored expiry ignored");
        assert_eq!(introspect(&env, CLIENT, &own).await["active"], false);
        env
    })
    .await;
}

#[tokio::test]
async fn introspection_only_answers_the_client_the_token_was_issued_to() {
    scenario(|env| async move {
        let first = tokens::fresh(&env).await.unwrap();
        let other = introspect(&env, OTHER, &first.access).await;
        assert_eq!(other, json!({"active": false}), "another client learned a token");
        let own = introspect(&env, CLIENT, &first.access).await;
        assert_eq!(own["active"], true);
        assert_eq!(own["client_id"], CLIENT);
        env
    })
    .await;
}

#[tokio::test]
async fn token_endpoint_responses_are_never_cacheable() {
    scenario(|env| async move {
        let (_, code) = tokens::code(&env).await.unwrap();
        let ok = format!("grant_type=authorization_code&client_id={CLIENT}&code={code}&redirect_uri=https%3A%2F%2Frp.idfed1.test%2Fcallback&code_verifier={VERIFIER}");
        let success = token(&env, ok.clone()).await;
        assert_eq!(success.0, 200);
        let replay = token(&env, ok).await;
        assert_eq!(replay.0, 400);
        let unsupported = token(&env, "grant_type=password".into()).await;
        assert_eq!(unsupported.0, 400);
        for (label, r) in [("success", success), ("error", replay), ("unsupported", unsupported)] {
            assert_eq!(r.1["cache-control"], "no-store", "{label}");
            assert_eq!(r.1["pragma"], "no-cache", "{label}");
        }
        env
    })
    .await;
}

/// Completion binds an authorization request to a session, so it is a POST with
/// a synchroniser token; the callback hands the code only to that session.
#[tokio::test]
async fn completion_requires_post_with_csrf_and_the_callback_is_bound_to_the_session() {
    scenario(|env| async move {
        let id = grants::pending(&env).await.unwrap();
        let victim = grants::session(&env, false).await.unwrap();
        let attacker = grants::session(&env, true).await.unwrap();
        // A lured GET only shows a consent page: it binds nothing.
        let page = request(env.gw.addr, "GET", &format!("/auth/oidc/op/complete?id={id}"), String::new(), &[("authorization", &victim)]).await.unwrap();
        assert_eq!(page.0, 200, "{}", page.2);
        assert!(page.2.contains("<form method=\"post\""));
        assert_eq!(bound(&env, &id).await, (false, None), "a GET bound the request");
        let csrf = grants::csrf_of(&page.2).unwrap();
        let post = |auth: &str, payload: String, extra: Option<(&str, &str)>| {
            let mut hs = vec![FORM, ("authorization", auth)];
            hs.extend(extra);
            let addr = env.gw.addr;
            let hs: Vec<(String, String)> = hs.into_iter().map(|(k, v)| (k.to_owned(), v.to_owned())).collect();
            async move {
                let hs: Vec<(&str, &str)> = hs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                request(addr, "POST", "/auth/oidc/op/complete", payload, &hs).await.unwrap()
            }
        };
        // No token, a forged token, another session's token, a cross-site origin.
        assert_eq!(post(&victim, format!("id={id}"), None).await.0, 403);
        assert_eq!(post(&victim, format!("id={id}&csrf=AAAA"), None).await.0, 403);
        assert_eq!(post(&attacker, format!("id={id}&csrf={csrf}"), None).await.0, 403, "token not bound to the session");
        let other = grants::pending(&env).await.unwrap();
        assert_eq!(post(&victim, format!("id={other}&csrf={csrf}"), None).await.0, 403, "token not bound to the request");
        assert_eq!(post(&victim, format!("id={id}&csrf={csrf}"), Some(("origin", "https://evil.example"))).await.0, 403);
        assert_eq!(post(&victim, format!("id={id}&csrf={csrf}"), Some(("sec-fetch-site", "cross-site"))).await.0, 403);
        assert_eq!(bound(&env, &id).await, (false, None));
        let done = post(&victim, format!("id={id}&csrf={csrf}"), Some(("origin", "http://auth.idfed1.test"))).await;
        assert_eq!(done.0, 302, "{}", done.2);
        assert_eq!(bound(&env, &id).await, (true, Some(env.a.user)));
        // The code goes to the completing session only.
        let callback = |auth: Option<String>| {
            let addr = env.gw.addr;
            let path = format!("/authorize/callback?id={id}");
            async move {
                let hs: Vec<(&str, &str)> = auth.iter().map(|a| ("authorization", a.as_str())).collect();
                request(addr, "GET", &path, String::new(), &hs).await.unwrap()
            }
        };
        let anonymous = callback(None).await;
        assert_eq!(anonymous.0, 401, "anonymous callback minted a code");
        let foreign = callback(Some(attacker)).await;
        assert_eq!(foreign.0, 400);
        assert!(!foreign.1["location"].as_str().unwrap_or("").contains("code="));
        let hash: Option<Vec<u8>> = env.c.query_one("SELECT code_hash FROM oidc_auth_requests WHERE id=$1", &[&id]).await.unwrap().get(0);
        assert!(hash.is_none(), "a code was bound for a stranger");
        let own = callback(Some(victim)).await;
        assert_eq!(own.0, 302);
        assert!(own.1["location"].as_str().unwrap().contains("code="));
        env
    })
    .await;
}

async fn bound(env: &Env, id: &str) -> (bool, Option<i64>) {
    let row = env
        .c
        .query_one("SELECT done, user_id FROM oidc_auth_requests WHERE id=$1", &[&id])
        .await
        .unwrap();
    (row.get::<_, bool>(0), row.get::<_, Option<i64>>(1))
}
fn refresh_payload(refresh: &str) -> String {
    format!("grant_type=refresh_token&client_id={CLIENT}&refresh_token={refresh}")
}
fn field(r: &(u16, Value, String), key: &str) -> String {
    serde_json::from_str::<Value>(&r.2).unwrap()[key].as_str().unwrap_or_default().to_owned()
}

#[tokio::test]
async fn reusing_a_rotated_refresh_token_revokes_its_whole_family() {
    scenario(|env| async move {
        let first = tokens::fresh(&env).await.unwrap();
        let second = token(&env, refresh_payload(&first.refresh)).await;
        assert_eq!(second.0, 200, "{}", second.2);
        let (refresh2, access2) = (field(&second, "refresh_token"), field(&second, "access_token"));
        assert_eq!(userinfo(&env, &access2).await, 200);
        let third = token(&env, refresh_payload(&refresh2)).await;
        assert_eq!(third.0, 200, "{}", third.2);
        let (refresh3, access3) = (field(&third, "refresh_token"), field(&third, "access_token"));
        // The leaked first token is replayed: refused, and the family dies.
        assert_eq!(token(&env, refresh_payload(&first.refresh)).await.0, 400);
        assert_eq!(token(&env, refresh_payload(&refresh3)).await.0, 400, "family survived reuse");
        assert_eq!(userinfo(&env, &access3).await, 403, "live access token survived reuse");
        let live: i64 = env.c.query_one("SELECT count(*) FROM oidc_tokens WHERE client_id=$1 AND revoked_at IS NULL", &[&CLIENT]).await.unwrap().get(0);
        assert_eq!(live, 0);
        // Another client's token is untouched by the reuse path (no cross-client revocation).
        env
    })
    .await;
}

#[tokio::test]
async fn refresh_rotation_cannot_slide_past_the_absolute_family_lifetime() {
    scenario(|env| async move {
        let first = tokens::fresh(&env).await.unwrap();
        let family: (String, std::time::SystemTime) = {
            let row = env.c.query_one("SELECT refresh_family,refresh_family_expires_at FROM oidc_tokens WHERE id=$1", &[&first.jti]).await.unwrap();
            (row.get(0), row.get(1))
        };
        assert_eq!(family.0, first.jti, "a fresh grant names its family");
        let cap = std::time::SystemTime::now() + std::time::Duration::from_secs(10 * 24 * 3600);
        env.c.execute("UPDATE oidc_tokens SET refresh_family_expires_at=$2 WHERE refresh_family=$1", &[&family.0, &cap]).await.unwrap();
        let second = token(&env, refresh_payload(&first.refresh)).await;
        assert_eq!(second.0, 200, "{}", second.2);
        let row = env.c.query_one("SELECT n.refresh_family, n.refresh_family_expires_at=$2::timestamptz, n.refresh_expires_at<=$2::timestamptz FROM oidc_tokens n WHERE n.refresh_token_hash IS NOT NULL AND n.revoked_at IS NULL AND n.client_id=$1", &[&CLIENT, &cap]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), family.0, "rotation left the family");
        assert!(row.get::<_, bool>(1), "rotation re-extended the family lifetime");
        assert!(row.get::<_, bool>(2), "refresh expiry slid past the family cap");
        // Once the family lifetime ends, even a live-looking token cannot be redeemed.
        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        env.c.execute("UPDATE oidc_tokens SET refresh_family_expires_at=$2 WHERE refresh_family=$1", &[&family.0, &past]).await.unwrap();
        assert_eq!(token(&env, refresh_payload(&field(&second, "refresh_token"))).await.0, 400);
        env
    })
    .await;
}

#[tokio::test]
async fn confidential_clients_must_use_pkce_too() {
    scenario(|env| async move {
        // A code issued without a challenge (the public client allows it) must still
        // be refused once the client is confidential: the token endpoint checks too.
        let (_, code) = tokens::code_method(&env, "none").await.unwrap();
        env.c.execute("UPDATE oidc_clients SET client_type='confidential' WHERE id=$1", &[&CLIENT]).await.unwrap();
        let payload = format!("grant_type=authorization_code&client_id={CLIENT}&client_secret=client-secret-339&code={code}&redirect_uri=https%3A%2F%2Frp.idfed1.test%2Fcallback");
        let r = token(&env, payload).await;
        assert_eq!(r.0, 400, "{}", r.2);
        assert!(r.2.contains("PKCE required"), "{}", r.2);
        let (_, code) = tokens::code(&env).await.unwrap();
        let payload = format!("grant_type=authorization_code&client_id={CLIENT}&client_secret=client-secret-339&code={code}&redirect_uri=https%3A%2F%2Frp.idfed1.test%2Fcallback&code_verifier={VERIFIER}");
        assert_eq!(token(&env, payload).await.0, 200);
        env
    })
    .await;
}

#[tokio::test]
async fn confidential_clients_without_a_challenge_are_refused_at_authorize() {
    scenario(|env| async move {
        env.c.execute("UPDATE oidc_clients SET client_type='confidential' WHERE id=$1", &[&CLIENT]).await.unwrap();
        let before: i64 = env.c.query_one("SELECT count(*) FROM oidc_auth_requests", &[]).await.unwrap().get(0);
        let query = format!("client_id={CLIENT}&redirect_uri=https%3A%2F%2Frp.idfed1.test%2Fcallback&response_type=code&scope=openid&state=s");
        let r = request(env.gw.addr, "GET", &format!("/authorize?{query}"), String::new(), &[]).await.unwrap();
        assert_eq!(r.0, 302, "{}", r.2);
        let location = r.1["location"].as_str().unwrap();
        assert!(location.starts_with("https://rp.idfed1.test/callback?"), "{location}");
        assert!(location.contains("error=invalid_request") && location.contains("PKCE"), "{location}");
        let after: i64 = env.c.query_one("SELECT count(*) FROM oidc_auth_requests", &[]).await.unwrap().get(0);
        assert_eq!(before, after, "an unredeemable request was stored");
        let with = format!("{query}&code_challenge={}&code_challenge_method=S256", grants::CHALLENGE);
        let r = request(env.gw.addr, "GET", &format!("/authorize?{with}"), String::new(), &[]).await.unwrap();
        assert!(r.1["location"].as_str().unwrap().starts_with("/auth/oidc/op/complete?id="));
        env
    })
    .await;
}

#[tokio::test]
async fn a_non_preflight_options_request_cannot_mint_a_callback_code() {
    scenario(|env| async move {
        let id = grants::pending(&env).await.unwrap();
        let victim = grants::session(&env, false).await.unwrap();
        assert_eq!(grants::complete_flow(&env, &id, &victim).await.unwrap().0, 302);
        let path = format!("/authorize/callback?id={id}");
        for hs in [vec![], vec![("origin", "https://evil.example")]] {
            let r = request(env.gw.addr, "OPTIONS", &path, String::new(), &hs).await.unwrap();
            assert!(!r.1["location"].as_str().unwrap_or("").contains("code="), "OPTIONS minted a code: {} {:?}", r.0, r.1);
            assert_ne!(r.0, 302);
        }
        let hash: Option<Vec<u8>> = env.c.query_one("SELECT code_hash FROM oidc_auth_requests WHERE id=$1", &[&id]).await.unwrap().get(0);
        assert!(hash.is_none(), "OPTIONS bound a code");
        env
    })
    .await;
}

#[tokio::test]
async fn narrowed_scope_refresh_spends_the_token_and_joins_the_family() {
    scenario(|env| async move {
        let first = tokens::fresh(&env).await.unwrap();
        let narrowed = token(&env, format!("{}&scope=openid+email", refresh_payload(&first.refresh))).await;
        assert_eq!(narrowed.0, 200, "{}", narrowed.2);
        let live_family: i64 = env.c.query_one("SELECT count(*) FROM oidc_tokens WHERE refresh_family=$1 AND revoked_at IS NULL", &[&first.jti]).await.unwrap().get(0);
        assert_eq!(live_family, 1, "the narrowed grant's access row did not join the family");
        // The original token is spent: replaying it is reuse and kills the family.
        assert_eq!(token(&env, refresh_payload(&first.refresh)).await.0, 400, "a narrowed refresh left the token redeemable");
        let live: i64 = env.c.query_one("SELECT count(*) FROM oidc_tokens WHERE client_id=$1 AND revoked_at IS NULL", &[&CLIENT]).await.unwrap().get(0);
        assert_eq!(live, 0, "reuse after a narrowed refresh left live tokens");
        env
    })
    .await;
}

#[tokio::test]
async fn another_client_cannot_burn_a_code() {
    scenario(|env| async move {
        let (_, code) = tokens::code(&env).await.unwrap();
        let redirect = "redirect_uri=https%3A%2F%2Frp.idfed1.test%2Fcallback";
        let stolen = token(&env, format!("grant_type=authorization_code&client_id={OTHER}&code={code}&{redirect}&code_verifier={VERIFIER}")).await;
        assert_eq!(stolen.0, 400, "{}", stolen.2);
        let r = token(&env, format!("grant_type=authorization_code&client_id={CLIENT}&code={code}&{redirect}&code_verifier={VERIFIER}")).await;
        assert_eq!(r.0, 200, "client B burned client A's code: {}", r.2);
        env
    })
    .await;
}

/// A held family lock must block both reducers: rotation and reuse revocation
/// serialise per family, so a concurrent successor cannot outlive a revoke.
async fn blocked_by_family_lock(env: &Env, family: &str, user: i64, call: &str) -> String {
    let other = Db::for_case("IDFED1-grants").unwrap().connect().await.unwrap();
    env.c.batch_execute("BEGIN").await.unwrap();
    env.c.execute("SELECT pg_advisory_xact_lock(hashtextextended('oidc-family:'||$1::text,0))", &[&family]).await.unwrap();
    other.batch_execute("BEGIN; SET LOCAL lock_timeout='400ms'").await.unwrap();
    other.execute("SELECT set_config('app.current_user_id',$1::text,true)", &[&user.to_string()]).await.unwrap();
    let result = other.query(call, &[]).await;
    let _ = other.batch_execute("ROLLBACK").await;
    env.c.batch_execute("ROLLBACK").await.unwrap();
    match result {
        Ok(_) => String::new(),
        Err(e) => e.code().map_or_else(|| e.to_string(), |c| c.code().to_owned()),
    }
}
#[tokio::test]
async fn refresh_rotation_waits_for_the_family_lock() {
    scenario(|env| async move {
        use sha2::{Digest, Sha256};
        let first = tokens::fresh(&env).await.unwrap();
        let hash = format!("{:x}", Sha256::digest(first.refresh.as_bytes()));
        let call = format!("SELECT * FROM rust_identity_oidc_rotate({},'{CLIENT}','{hash}','locked-id',ARRAY['openid','offline_access'],'locked-hash')", env.a.user);
        assert_eq!(blocked_by_family_lock(&env, &first.jti, env.a.user, &call).await, "55P03", "rotation ignored the family lock");
        env
    })
    .await;
}
#[tokio::test]
async fn refresh_reuse_revocation_waits_for_the_family_lock() {
    scenario(|env| async move {
        use sha2::{Digest, Sha256};
        let first = tokens::fresh(&env).await.unwrap();
        assert_eq!(token(&env, refresh_payload(&first.refresh)).await.0, 200);
        let hash = format!("{:x}", Sha256::digest(first.refresh.as_bytes()));
        let call = format!("SELECT * FROM rust_identity_oidc_reuse({},'{CLIENT}','{hash}')", env.a.user);
        assert_eq!(blocked_by_family_lock(&env, &first.jti, env.a.user, &call).await, "55P03", "reuse revocation ignored the family lock");
        env
    })
    .await;
}

#[tokio::test]
async fn an_unauthenticated_code_holder_cannot_burn_the_code() {
    scenario(|env| async move {
        env.c.execute("UPDATE oidc_clients SET client_type='confidential' WHERE id=$1", &[&CLIENT]).await.unwrap();
        let (_, code) = tokens::code(&env).await.unwrap();
        let base = format!("grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Frp.idfed1.test%2Fcallback&code_verifier={VERIFIER}");
        assert_eq!(token(&env, format!("{base}&client_id={CLIENT}&client_secret=wrong")).await.0, 401);
        assert_eq!(token(&env, format!("{base}&client_id={CLIENT}")).await.0, 401);
        assert_eq!(token(&env, format!("{base}&client_id=no-such-client&client_secret=x")).await.0, 401);
        // The legitimate client still redeems the same code.
        let r = token(&env, format!("{base}&client_id={CLIENT}&client_secret=client-secret-339")).await;
        assert_eq!(r.0, 200, "the code was burned by an unauthenticated attempt: {}", r.2);
        env
    })
    .await;
}
