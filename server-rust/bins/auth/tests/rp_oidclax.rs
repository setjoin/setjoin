#![allow(dead_code)]
//! Owner-approved functional fix (#548, decision 2026-11-09): the four OIDC login flow cookies are
//! SameSite=Lax so the IdP's cross-site redirect to the callback carries them.
//! `scripts/test-oidclax-mutants.py` restores Strict (feature `oracle-mutants`,
//! `SETJOIN_OIDCLAX_MUTANT`) and requires this test to fail.
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


const FLOW: [&str; 4] = ["oidc_state", "oidc_nonce", "oidc_provider", "oidc_verifier"];

fn set_cookies(headers: &Value) -> Vec<String> {
    headers["set-cookie"].as_array().map(|a| a.iter().map(|v| v.as_str().unwrap().to_owned()).collect()).unwrap_or_default()
}

/// A browser sends the IdP's cross-site top-level GET with Lax-eligible cookies only: every
/// SameSite=Strict cookie (the session `access_token`) is withheld.
fn browser_cookies(set: &[String]) -> String {
    set.iter()
        .filter(|c| !c.contains("SameSite=Strict"))
        .map(|c| c.split(';').next().unwrap().to_owned())
        .collect::<Vec<_>>()
        .join("; ")
}

#[tokio::test]
async fn a_cross_site_idp_redirect_carrying_only_lax_cookies_completes_the_login() {
    let _serial = SERIAL.lock().await;
    let env = flows::Env::start(false).await.unwrap();
    // A failed assertion (a restored-bug mutant) skips the cleanup below: clear what it left.
    settlement::cleanup_leftovers(&env.c).await.unwrap();
    let a = fx::account(&env.c, "idfed2-actor").await.unwrap();
    let result = async {
        let email: String = env.c.query_one("SELECT email FROM users WHERE id=$1", &[&a.user]).await?.get(0);
        env.c.execute("UPDATE users SET oidc_subject='actor-subject',oidc_issuer=$2 WHERE id=$1", &[&a.user, &idp::ISSUER]).await?;
        let login = request(env.gw.addr, "GET", "/auth/oidc/login?provider=idfed2", String::new(), &[]).await?;
        assert_eq!(login.0, 302);
        let set = set_cookies(&login.1);
        for name in FLOW {
            let cookie = set.iter().find(|c| c.starts_with(&format!("{name}="))).ok_or(format!("{name} not set"))?;
            assert!(cookie.contains("SameSite=Lax") && !cookie.contains("SameSite=Strict"), "login flow cookie must be SameSite=Lax: {cookie}");
            assert!(cookie.contains("HttpOnly") && cookie.contains("Max-Age=600"), "{cookie}");
        }
        let (_, flow) = flows::normalize_flow(login)?;
        let code = env.idp.state.code(&flow["oidc_verifier"], &flow["oidc_nonce"], json!({"email": email, "email_verified": true}));
        let path = setjoin_identity::oidc::query_response("/auth/oidc/callback", &[("state", &flow["oidc_state"]), ("code", &code)], false);
        let cookie = browser_cookies(&set);
        assert!(!cookie.contains("access_token"), "{cookie}");
        let done = request(env.gw.addr, "GET", &path, String::new(), &[("cookie", &cookie)]).await?;
        assert_eq!(done.0, 200, "the cross-site callback must complete the login: {}", done.2);
        assert!(done.2.contains("access_token"), "{}", done.2);
        // The single-use flow cookies are cleared with the same Lax attribute they were set
        // with (consistency; browsers store any SameSite value on a top-level navigation response).
        let after = set_cookies(&done.1);
        for name in FLOW {
            let clear = after.iter().find(|c| c.starts_with(&format!("{name}=;"))).ok_or(format!("{name} not cleared"))?;
            assert!(clear.contains("SameSite=Lax") && !clear.contains("SameSite=Strict"), "flow clear must be SameSite=Lax: {clear}");
        }
        Ok::<(), Err>(())
    }
    .await;
    let c = &env.c;
    let cleanup = async {
        settlement::cleanup_identity(c, a.user).await.unwrap();
        fx::remove(c, &a).await.unwrap();
    };
    cleanup.await;
    env.close().await.unwrap();
    result.unwrap();
}
