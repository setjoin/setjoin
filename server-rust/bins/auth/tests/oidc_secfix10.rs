//! Secure-behaviour tests for #525 (owner-approved security fix 2026-11-05): every
//! credential-keyed `oidc_tokens` lookup of the Rust OP goes through a worker-owned reducer
//! that derives the user from the credential. RLS on the table is staged for the Go-deletion
//! ticket (mailserver/sql/staged/), so these tests prove the reducer call itself: with
//! EXECUTE revoked from the app role the flow must fail, and it works with it granted. Each
//! fails against the matching direct-SELECT mutant restored by
//! `scripts/test-secfix10-mutants.py` (feature `oracle-mutants`, `SETJOIN_SECFIX10_MUTANT`).
mod common;
include!("oidc_oracle/harness.rs");
#[path = "oidc_oracle/grants.rs"]
mod grants;
#[path = "oidc_oracle/tokens.rs"]
mod tokens;
use grants::{Env, CLIENT};

const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");

async fn scenario<F, Fut>(body: F)
where
    F: FnOnce(Env) -> Fut,
    Fut: std::future::Future<Output = Env>,
{
    let _serial = SERIAL.lock().await;
    let env = Env::start(false).await.unwrap();
    for f in [ANCHOR, OWNER, TARGET] {
        reducer(&env, f, true).await;
    }
    let env = body(env).await;
    env.close().await.unwrap();
}
const ANCHOR: &str = "rust_identity_oidc_refresh_anchor(text)";
const OWNER: &str = "rust_identity_oidc_token_owner(text)";
const TARGET: &str = "rust_identity_oidc_revoke_target(text,text,text)";
/// Grant or withdraw the request role's EXECUTE on one lookup reducer.
async fn reducer(env: &Env, signature: &str, on: bool) {
    let sql = if on {
        format!("GRANT EXECUTE ON FUNCTION {signature} TO setjoin_app")
    } else {
        format!("REVOKE EXECUTE ON FUNCTION {signature} FROM setjoin_app")
    };
    env.c.batch_execute(&sql).await.unwrap();
}
async fn post(env: &Env, path: &str, payload: String) -> (u16, Value, String) {
    request(env.gw.addr, "POST", path, payload, &[FORM])
        .await
        .unwrap()
}
async fn userinfo(env: &Env, token: &str) -> u16 {
    request(
        env.gw.addr,
        "GET",
        "/userinfo",
        String::new(),
        &[("authorization", &format!("Bearer {token}"))],
    )
    .await
    .unwrap()
    .0
}
async fn live_rows(env: &Env) -> i64 {
    env.c
        .query_one(
            "SELECT count(*) FROM oidc_tokens WHERE client_id=$1 AND revoked_at IS NULL",
            &[&CLIENT],
        )
        .await
        .unwrap()
        .get(0)
}

/// The refresh grant finds the row's owner through `rust_identity_oidc_refresh_anchor`.
#[tokio::test]
async fn the_refresh_grant_derives_its_user_from_the_presented_hash() {
    scenario(|env| async move {
        let first = tokens::fresh(&env).await.unwrap();
        let r = post(
            &env,
            "/oauth/token",
            format!("grant_type=refresh_token&client_id={CLIENT}&refresh_token={}", first.refresh),
        )
        .await;
        assert_eq!(r.0, 200, "refresh grant under RLS: {}", r.2);
        let issued: Value = serde_json::from_str(&r.2).unwrap();
        assert_eq!(userinfo(&env, issued["access_token"].as_str().unwrap()).await, 200);
        let owner: i64 = env
            .c
            .query_one("SELECT user_id FROM oidc_tokens WHERE refresh_token_hash IS NOT NULL AND revoked_at IS NULL AND client_id=$1", &[&CLIENT])
            .await
            .unwrap()
            .get(0);
        assert_eq!(owner, env.a.user, "the successor belongs to the credential's user");
        // Without the reducer the grant has no way to find its user.
        let second = tokens::fresh(&env).await.unwrap();
        reducer(&env, ANCHOR, false).await;
        let r = post(&env, "/oauth/token", format!("grant_type=refresh_token&client_id={CLIENT}&refresh_token={}", second.refresh)).await;
        reducer(&env, ANCHOR, true).await;
        assert_ne!(r.0, 200, "the refresh grant did not use rust_identity_oidc_refresh_anchor");
        env
    })
    .await;
}

/// UserInfo and introspection resolve the stored row's owner through
/// `rust_identity_oidc_token_owner`.
#[tokio::test]
async fn userinfo_and_introspection_derive_the_owner_from_the_token_row() {
    scenario(|env| async move {
        let first = tokens::fresh(&env).await.unwrap();
        assert_eq!(userinfo(&env, &first.access).await, 200, "userinfo under RLS");
        let basic = {
            use base64::{engine::general_purpose::STANDARD, Engine};
            format!("Basic {}", STANDARD.encode(format!("{CLIENT}:client-secret-339")))
        };
        let r = request(
            env.gw.addr,
            "POST",
            "/oauth/introspect",
            format!("token={}", first.access),
            &[FORM, ("authorization", &basic)],
        )
        .await
        .unwrap();
        assert_eq!(r.0, 200, "{}", r.2);
        let body: Value = serde_json::from_str(&r.2).unwrap();
        assert_eq!(body["active"], true, "introspection under RLS: {}", r.2);
        assert_eq!(body["sub"], env.a.user.to_string());
        reducer(&env, OWNER, false).await;
        let off = userinfo(&env, &first.access).await;
        reducer(&env, OWNER, true).await;
        assert_ne!(off, 200, "UserInfo did not use rust_identity_oidc_token_owner");
        env
    })
    .await;
}

/// Revocation (by access token and by refresh token) finds the owner through
/// `rust_identity_oidc_revoke_target` and revokes under that user's scope.
#[tokio::test]
async fn revocation_derives_the_owner_from_the_presented_credential() {
    scenario(|env| async move {
        let first = tokens::fresh(&env).await.unwrap();
        assert_eq!(live_rows(&env).await, 1);
        let r = post(&env, "/revoke", format!("client_id={CLIENT}&token={}", first.access)).await;
        assert_eq!(r.0, 200, "{}", r.2);
        assert_eq!(live_rows(&env).await, 0, "access-token revocation did not revoke the row");
        let second = tokens::fresh(&env).await.unwrap();
        assert_eq!(live_rows(&env).await, 1);
        let r = post(&env, "/revoke", format!("client_id={CLIENT}&token={}", second.refresh)).await;
        assert_eq!(r.0, 200, "{}", r.2);
        assert_eq!(live_rows(&env).await, 0, "refresh-token revocation did not revoke the row");
        let third = tokens::fresh(&env).await.unwrap();
        reducer(&env, TARGET, false).await;
        post(&env, "/revoke", format!("client_id={CLIENT}&token={}", third.access)).await;
        reducer(&env, TARGET, true).await;
        assert_eq!(live_rows(&env).await, 1, "revocation did not use rust_identity_oidc_revoke_target");
        env
    })
    .await;
}
