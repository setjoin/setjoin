//! Frozen-Go OIDC OP HTTP oracle.
mod common;
include!("oidc_oracle/harness.rs");
async fn public(route: &str, kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDFED1").expect("assigned DB required");
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    cfg.dsn = db.dsn.clone();
    cfg.oidc_enabled = true;
    cfg.oidc_hostname = "auth.idfed1.test".into();
    cfg.oidc_private_key = corpus().join("op-private.pem").to_str().unwrap().into();
    cfg.oidc_public_key = corpus().join("op-public.pem").to_str().unwrap().into();
    let server = auth_server(
        Arc::new(
            AuthServer::load(
                setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
                    .unwrap(),
                cfg,
            )
            .await?,
        ),
        mutant,
    )
    .await;
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none());
    let gw = gateway(server.addr, record.clone()).await;
    let path = match route {
        "discovery" => "/.well-known/openid-configuration",
        "metadata" => "/.well-known/oauth-authorization-server",
        _ => "/keys",
    };
    let method = if kind == "preflight" {
        "OPTIONS"
    } else if kind == "post" {
        "POST"
    } else if kind == "head" {
        "HEAD"
    } else {
        "GET"
    };
    let hs = if kind == "cors" {
        vec![("origin", "https://auth.idfed1.test")]
    } else if kind == "cors-denied" {
        vec![("origin", "https://foreign.invalid")]
    } else if kind == "preflight" {
        vec![
            ("origin", "https://auth.idfed1.test"),
            ("access-control-request-method", "POST"),
            (
                "access-control-request-headers",
                "authorization,content-type",
            ),
        ]
    } else if kind == "cross-tenant" {
        vec![("authorization", "Bearer foreign"), ("x-user-id", "9999")]
    } else if kind == "invalid-input" {
        vec![("authorization", "Bearer broken")]
    } else {
        vec![]
    };
    let response = request(
        gw.addr,
        method,
        path,
        if kind == "invalid-input" {
            "{".into()
        } else {
            String::new()
        },
        &hs,
    )
    .await?;
    if !mutant {
        assert_eq!(
            response.0,
            if kind == "preflight" { 204 } else { 200 },
            "public OP endpoint"
        );
    }
    let actual = json!({"format":1,"go_source":SOURCE,"route":format!("* {}",if route=="discovery"{"/.well-known/"}else{path}),"case":format!("{route}-{kind}"),"observation":{"request":{"method":method,"path":path},"response":{"status":response.0,"headers":response.1,"body":response.2},"audit":[],"notify":[],"effects":[]}});
    let p = corpus()
        .join("goldens")
        .join(format!("{route}-{kind}.json"));
    let result = (|| -> Result<(), Err> {
        if record.is_some() && !p.exists() {
            golden::record(&p, &actual)?;
        }
        let observation = grants::observe(
            record.is_some(),
            &p,
            &actual,
            &Value::Null,
            &Value::Null,
            mutant,
        );
        let expected: Value = serde_json::from_slice(&std::fs::read(&p)?)?;
        if mutant {
            assert!(golden::compare(&expected, &actual)
                .unwrap_err()
                .contains("/observation/response/status"));
        } else {
            observation?;
            golden::compare(&expected, &actual)?;
        }
        Ok(())
    })();
    let (_, _, metrics) = request(gw.addr, "GET", "/_gateway/metrics", String::new(), &[]).await?;
    if record.is_none() {
        assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));
    }
    gw.close().await;
    server.close().await;
    result
}
#[tokio::test]
async fn discovery_success() {
    public("discovery", "success", false).await.unwrap();
}
#[tokio::test]
async fn discovery_cross_tenant() {
    public("discovery", "cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn discovery_invalid_input() {
    public("discovery", "invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn discovery_status_mutant() {
    public("discovery", "success", true).await.unwrap();
}
#[tokio::test]
async fn keys_success() {
    public("keys", "success", false).await.unwrap();
}
#[tokio::test]
async fn keys_cross_tenant() {
    public("keys", "cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn keys_invalid_input() {
    public("keys", "invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn keys_status_mutant() {
    public("keys", "success", true).await.unwrap();
}

#[tokio::test]
async fn metadata_success() {
    public("metadata", "success", false).await.unwrap();
}
#[tokio::test]
async fn metadata_cross_tenant() {
    public("metadata", "cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn metadata_invalid_input() {
    public("metadata", "invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn metadata_status_mutant() {
    public("metadata", "success", true).await.unwrap();
}
#[tokio::test]
async fn discovery_head() {
    public("discovery", "head", false).await.unwrap();
}
#[tokio::test]
async fn discovery_post() {
    public("discovery", "post", false).await.unwrap();
}

#[tokio::test]
async fn keys_cors() {
    public("keys", "cors", false).await.unwrap();
}
#[tokio::test]
async fn keys_cors_denied() {
    public("keys", "cors-denied", false).await.unwrap();
}
#[tokio::test]
async fn keys_preflight() {
    public("keys", "preflight", false).await.unwrap();
}

#[path = "oidc_oracle/grants.rs"]
mod grants;

macro_rules! authorize_case {
    ($name:ident,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            grants::authorize($kind, false).await.unwrap();
        }
    };
}
authorize_case!(authorize_success, "success");
authorize_case!(authorize_cross_tenant, "cross-tenant");
authorize_case!(authorize_invalid_input, "invalid-input");
authorize_case!(authorize_bad_response_type, "bad-response-type");
authorize_case!(authorize_absent_scope, "absent-scope");
authorize_case!(authorize_empty_scope, "missing-scope");
authorize_case!(authorize_unknown_scope, "unknown-scope");
#[tokio::test]
async fn authorize_status_mutant() {
    let e = grants::authorize("success", true).await.unwrap_err();
    assert!(e.to_string().contains("/observation/response/status"));
    println!("MUTANT-REJECTED: * /authorize :: status");
}

#[tokio::test]
async fn complete_success() {
    grants::complete("success", false).await.unwrap();
}

macro_rules! complete_case {
    ($name:ident,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            grants::complete($kind, false).await.unwrap();
        }
    };
}
complete_case!(complete_cross_tenant, "cross-tenant");
complete_case!(complete_invalid_input, "invalid-input");
complete_case!(complete_repeat, "repeat");
complete_case!(complete_anonymous, "anonymous");
complete_case!(complete_head, "head");
#[tokio::test]
async fn complete_status_mutant() {
    let e = grants::complete("success", true).await.unwrap_err();
    assert!(e.to_string().contains("/observation/response/status"));
    println!("MUTANT-REJECTED: GET /auth/oidc/op/complete :: status");
}
#[tokio::test]
async fn callback_success() {
    grants::callback("success", false).await.unwrap();
}

macro_rules! callback_case {
    ($name:ident,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            grants::callback($kind, false).await.unwrap();
        }
    };
}
callback_case!(callback_cross_tenant, "cross-tenant");
callback_case!(callback_invalid_input, "invalid-input");
callback_case!(callback_repeat, "repeat");
#[tokio::test]
async fn callback_status_mutant() {
    let e = grants::callback("success", true).await.unwrap_err();
    assert!(e.to_string().contains("/observation/response/status"));
    println!("MUTANT-REJECTED: * /authorize/callback :: status");
}

#[path = "oidc_oracle/tokens.rs"]
mod tokens;
#[tokio::test]
async fn token_success() {
    tokens::exchange("success", false).await.unwrap();
}

macro_rules! token_case {
    ($name:ident,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            tokens::exchange($kind, false).await.unwrap();
        }
    };
}
token_case!(token_cross_tenant, "cross-tenant");
token_case!(token_invalid_input, "invalid-input");
token_case!(token_repeat, "repeat");
token_case!(token_pkce_wrong, "pkce-wrong");
token_case!(token_pkce_missing, "pkce-missing");
token_case!(token_redirect_mismatch, "redirect-mismatch");
token_case!(token_confidential, "confidential");
token_case!(token_wrong_secret, "wrong-secret");
#[tokio::test]
async fn token_status_mutant() {
    let e = tokens::exchange("success", true).await.unwrap_err();
    assert!(e.to_string().contains("/observation/response/status"));
    println!("MUTANT-REJECTED: * /oauth/ authorization-code :: status");
}

#[tokio::test]
async fn refresh_success() {
    tokens::refresh("success", false).await.unwrap();
}

macro_rules! refresh_case {
    ($name:ident,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            tokens::refresh($kind, false).await.unwrap();
        }
    };
}
refresh_case!(refresh_cross_tenant, "cross-tenant");
refresh_case!(refresh_invalid_input, "invalid-input");
refresh_case!(refresh_repeat, "repeat");
refresh_case!(refresh_scope_widen, "scope-widen");
refresh_case!(refresh_scope_narrow, "scope-narrow");
#[tokio::test]
async fn refresh_status_mutant() {
    let e = tokens::refresh("success", true).await.unwrap_err();
    assert!(e.to_string().contains("/observation/response/status"));
    println!("MUTANT-REJECTED: * /oauth/ refresh-token :: status");
}
macro_rules! consumer_case {
    ($name:ident,$route:literal,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            tokens::consumer($route, $kind, false).await.unwrap();
        }
    };
}
macro_rules! consumer_mutant {
    ($name:ident,$route:literal) => {
        #[tokio::test]
        async fn $name() {
            let e = tokens::consumer($route, "success", true).await.unwrap_err();
            assert!(e.to_string().contains("/observation/response/status"));
        }
    };
}
consumer_case!(userinfo_success, "userinfo", "success");
consumer_case!(userinfo_cross_tenant, "userinfo", "cross-tenant");
consumer_case!(userinfo_invalid_input, "userinfo", "invalid-input");
consumer_mutant!(userinfo_status_mutant, "userinfo");
consumer_case!(introspect_success, "introspect", "success");
consumer_case!(introspect_cross_tenant, "introspect", "cross-tenant");
consumer_case!(introspect_invalid_input, "introspect", "invalid-input");
consumer_mutant!(introspect_status_mutant, "introspect");
consumer_case!(revoke_success, "revoke", "success");
consumer_case!(revoke_cross_tenant, "revoke", "cross-tenant");
consumer_case!(revoke_invalid_input, "revoke", "invalid-input");
consumer_mutant!(revoke_status_mutant, "revoke");
consumer_case!(end_session_success, "end_session", "success");
consumer_case!(end_session_cross_tenant, "end_session", "cross-tenant");
consumer_case!(end_session_invalid_input, "end_session", "invalid-input");
consumer_mutant!(end_session_status_mutant, "end_session");

authorize_case!(authorize_repeat, "repeat");
consumer_case!(revoke_repeat, "revoke", "repeat");
consumer_case!(end_session_repeat, "end_session", "repeat");
#[path = "oidc_oracle/mux.rs"]
mod mux;
#[tokio::test]
async fn well_known_mux_success() {
    mux::run("well_known_mux", "success", false).await.unwrap();
}
#[tokio::test]
async fn well_known_mux_cross_tenant() {
    mux::run("well_known_mux", "cross-tenant", false)
        .await
        .unwrap();
}
#[tokio::test]
async fn well_known_mux_invalid_input() {
    mux::run("well_known_mux", "invalid-input", false)
        .await
        .unwrap();
}
#[tokio::test]
async fn well_known_mux_status_mutant() {
    let e = mux::run("well_known_mux", "success", true)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("/observation/response/status"));
}
#[tokio::test]
async fn authorize_mux_success() {
    mux::run("authorize_mux", "success", false).await.unwrap();
}
#[tokio::test]
async fn authorize_mux_cross_tenant() {
    mux::run("authorize_mux", "cross-tenant", false)
        .await
        .unwrap();
}
#[tokio::test]
async fn authorize_mux_invalid_input() {
    mux::run("authorize_mux", "invalid-input", false)
        .await
        .unwrap();
}
#[tokio::test]
async fn authorize_mux_status_mutant() {
    let e = mux::run("authorize_mux", "success", true)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("/observation/response/status"));
}
#[tokio::test]
async fn oauth_mux_success() {
    mux::run("oauth_mux", "success", false).await.unwrap();
}
#[tokio::test]
async fn oauth_mux_cross_tenant() {
    mux::run("oauth_mux", "cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn oauth_mux_invalid_input() {
    mux::run("oauth_mux", "invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn oauth_mux_status_mutant() {
    let e = mux::run("oauth_mux", "success", true).await.unwrap_err();
    assert!(e.to_string().contains("/observation/response/status"));
}
#[tokio::test]
async fn oauth_namespace_success() {
    mux::run("oauth_namespace", "success", false).await.unwrap();
}
#[tokio::test]
async fn oauth_namespace_cross_tenant() {
    mux::run("oauth_namespace", "cross-tenant", false)
        .await
        .unwrap();
}
#[tokio::test]
async fn oauth_namespace_invalid_input() {
    mux::run("oauth_namespace", "invalid-input", false)
        .await
        .unwrap();
}
#[tokio::test]
async fn oauth_namespace_status_mutant() {
    let e = mux::run("oauth_namespace", "success", true)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("/observation/response/status"));
}
authorize_case!(authorize_duplicate_client, "duplicate-client");
authorize_case!(authorize_prompt_mixed, "prompt-mixed");
authorize_case!(authorize_prompt_none, "prompt-none");
authorize_case!(authorize_max_age_invalid, "max-age-invalid");
authorize_case!(authorize_invalid_hint, "invalid-hint");
authorize_case!(authorize_request_object, "request-object");
authorize_case!(authorize_loopback, "loopback");

consumer_case!(userinfo_legacy, "userinfo", "legacy");
consumer_case!(introspect_legacy, "introspect", "legacy");
consumer_case!(revoke_legacy, "revoke", "legacy");
token_case!(token_pkce_plain, "pkce-plain");
token_case!(token_pkce_absent, "pkce-absent");
token_case!(token_confidential_basic, "confidential-basic");
token_case!(token_mixed_auth, "mixed-auth");

#[tokio::test]
async fn keys_head() {
    public("keys", "head", false).await.unwrap();
}
#[tokio::test]
async fn metadata_head() {
    public("metadata", "head", false).await.unwrap();
}
#[tokio::test]
async fn gateway_oauth_mux_success() {
    mux::run("gateway_oauth_mux", "success", false)
        .await
        .unwrap();
}
#[tokio::test]
async fn gateway_oauth_mux_cross_tenant() {
    mux::run("gateway_oauth_mux", "cross-tenant", false)
        .await
        .unwrap();
}
#[tokio::test]
async fn gateway_oauth_mux_invalid_input() {
    mux::run("gateway_oauth_mux", "invalid-input", false)
        .await
        .unwrap();
}
#[tokio::test]
async fn gateway_oauth_mux_status_mutant() {
    let e = mux::run("gateway_oauth_mux", "success", true)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("/observation/response/status"));
}

token_case!(token_access_statement, "access-statement");
token_case!(token_attach_statement, "attach-statement");
refresh_case!(refresh_attach_statement, "attach-statement");
consumer_case!(revoke_statement_failure, "revoke", "statement-failure");
consumer_case!(revoke_invalid_statement, "revoke", "invalid-statement");
consumer_case!(
    end_session_statement_failure,
    "end_session",
    "statement-failure"
);

authorize_case!(authorize_public_remote_http, "public-remote-http");
authorize_case!(authorize_confidential_custom, "confidential-custom");

consumer_case!(introspect_post_secret, "introspect", "post-secret");

authorize_case!(authorize_malformed_form, "malformed-form");
token_case!(token_malformed_form, "malformed-form");
token_case!(token_invalid_basic, "invalid-basic");

#[test]
fn recorded_go_tokens_verify_with_the_unchanged_op_key(){
 use base64::{Engine,engine::general_purpose::URL_SAFE_NO_PAD as B64};use sha2::{Digest,Sha256};
 let fixture:Value=serde_json::from_slice(&std::fs::read(corpus().join("interop-go-tokens.json")).unwrap()).unwrap();assert_eq!(fixture["go_source"],SOURCE);
 let key=setjoin_identity::oidc::SigningKey::load(corpus().join("op-private.pem").to_str().unwrap(),corpus().join("op-public.pem").to_str().unwrap()).unwrap();
 let access=fixture["access"].as_str().unwrap();let id=fixture["id"].as_str().unwrap();let ac=key.verify(access).unwrap();let ic=key.verify(id).unwrap();
 for c in [&ac,&ic]{assert_eq!(c["iss"],fixture["issuer"]);assert_eq!(c["aud"],json!([grants::CLIENT]));assert!(c["sub"].as_str().unwrap().parse::<i64>().unwrap()>0);assert!((299..=301).contains(&(c["exp"].as_i64().unwrap()-c["iat"].as_i64().unwrap())));}
 assert_eq!(ic["sub"],ac["sub"]);assert_eq!(ic["at_hash"],B64.encode(&Sha256::digest(access.as_bytes())[..16]));
 let first_party:Value=serde_json::from_str(include_str!("../../../tests/conformance/identity-login/keys.json")).unwrap();let legacy=setjoin_authz::legacy_jwt::LegacyKeys::new(first_party["secret"].as_str().unwrap().as_bytes(),&["authserver-hmac-1"],None).unwrap();
 assert!(setjoin_identity::session::Session::verify(access,None,&legacy,"mailserver").is_none());assert!(setjoin_identity::session::Session::verify(id,None,&legacy,"mailserver").is_none());
}

#[tokio::test]
async fn bundled_inventory_serves_op_with_go_upstreams_unset(){
 let _serial=SERIAL.lock().await;let mut env=grants::Env::start(false).await.unwrap();
 let front=gateway_mode(env.auth.addr,None,true,None).await;let original=std::mem::replace(&mut env.gw,front);original.close().await;
 let result=async{
  let issued=tokens::fresh(&env).await?;
  for path in ["/.well-known/openid-configuration","/.well-known/oauth-authorization-server","/keys"]{let r=request(env.gw.addr,"GET",path,String::new(),&[]).await?;if r.0!=200{return Err(format!("bundled public path {path}: {} {}",r.0,r.2).into());}}
  let r=request(env.gw.addr,"GET","/userinfo",String::new(),&[("authorization",&format!("Bearer {}",issued.access))]).await?;if r.0!=200{return Err("bundled userinfo failed".into());}
  for path in ["/oauth","/oauth/unknown","/authorize/unknown"]{if request(env.gw.addr,"GET",path,String::new(),&[]).await?.0!=404{return Err(format!("bundled namespace {path} failed").into());}}
  let r=request(env.gw.addr,"POST","/revoke",format!("client_id={}&token={}",grants::CLIENT,issued.access),&[("content-type","application/x-www-form-urlencoded")]).await?;if r.0!=200{return Err("bundled revocation failed".into());}
  let r=request(env.gw.addr,"GET","/userinfo",String::new(),&[("authorization",&format!("Bearer {}",issued.access))]).await?;if r.0!=403{return Err("revoked OP token remained usable".into());}
  Ok::<(),Err>(())
 }.await;env.close().await.unwrap();result.unwrap();
}
