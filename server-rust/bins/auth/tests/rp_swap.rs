//! Live first-party access/refresh swap, plus Go-free immutable signature replay.
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
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap()
}
async fn fresh(env: &flows::Env, addr: std::net::SocketAddr, email: &str) -> Result<Value, Err> {
    let response = request(
        addr,
        "GET",
        "/auth/oidc/login?provider=idfed2",
        String::new(),
        &[],
    )
    .await?;
    let (_, flow) = flows::normalize_flow(response)?;
    let code = env.idp.state.code(
        &flow["oidc_verifier"],
        &flow["oidc_nonce"],
        json!({"email":email,"email_verified":true}),
    );
    let cookie = flow
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let path = setjoin_identity::oidc::query_response(
        "/auth/oidc/callback",
        &[("state", &flow["oidc_state"]), ("code", &code)],
        false,
    );
    let response = request(addr, "GET", &path, String::new(), &[("cookie", &cookie)]).await?;
    if response.0 != 200 {
        return Err(format!("swap callback {} {}", response.0, response.2).into());
    }
    Ok(serde_json::from_str(&response.2)?)
}
#[tokio::test]
async fn first_party_tokens_survive_the_rp_process_swap() {
    use setjoin_conformance::fixture;
    let _serial = SERIAL.lock().await;
    let env = flows::Env::start(false).await.unwrap();
    settlement::cleanup_leftovers(&env.c).await.unwrap();
    let a = fixture::account(&env.c, "idfed2-actor").await.unwrap();
    let receipts = common::receipt_ids(&env.c).await;
    let result=async{
        let email:String=env.c.query_one("SELECT email FROM users WHERE id=$1",&[&a.user]).await?.get(0);
        env.c.execute("UPDATE users SET oidc_subject='actor-subject',oidc_issuer=$2 WHERE id=$1",&[&a.user,&idp::ISSUER]).await?;
        let native=fresh(&env,env.gw.addr,&email).await?;
        let path=corpus().join("interop-go-tokens.json");
        if let Ok(upstream)=std::env::var("GOFREE_SWAP_UPSTREAM"){
            let go:hyper::Uri=upstream.parse()?;let addr:std::net::SocketAddr=format!("{}:{}",go.host().unwrap(),go.port_u16().unwrap()).parse()?;
            let ready:String=env.c.query_one("SELECT value->>'name' FROM system_config WHERE key='oidc_provider_zz_idfed2_ready_config'",&[]).await?.get(0);
            let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(15);
            loop{let r=request(addr,"GET",&format!("/auth/oidc/login?provider={ready}"),String::new(),&[]).await?;if r.0==302{break;}if tokio::time::Instant::now()>deadline{return Err("Go RP cache did not load swap fixture".into());}tokio::time::sleep(std::time::Duration::from_millis(20)).await;}
            let go_me=request(addr,"GET","/auth/me",String::new(),&[("authorization",&format!("Bearer {}",native["access_token"].as_str().unwrap()))]).await?;
            let go_refresh=request(addr,"POST","/auth/refresh",json!({"refresh_token":native["refresh_token"]}).to_string(),&[]).await?;
            let go=fresh(&env,addr,&email).await?;
            let rust_me=request(env.gw.addr,"GET","/auth/me",String::new(),&[("authorization",&format!("Bearer {}",go["access_token"].as_str().unwrap()))]).await?;
            let rust_refresh=request(env.gw.addr,"POST","/auth/refresh",json!({"refresh_token":go["refresh_token"]}).to_string(),&[]).await?;
            for (which,r) in [("Go access",go_me),("Go refresh",go_refresh),("Rust access",rust_me),("Rust refresh",rust_refresh)]{if r.0!=200{return Err(format!("{which} swap refusal {} {}",r.0,r.2).into());}}
            let vector=json!({"format":1,"go_source":SOURCE,"access":go["access_token"],"refresh":go["refresh_token"],"go_accepts_rust_access":200,"go_accepts_rust_refresh":200,"rust_accepts_go_access":200,"rust_accepts_go_refresh":200});
            if !path.exists(){setjoin_conformance::golden::record(&path,&vector)?;}
            println!("RP-SWAP: Go/Rust accept each other's ES256 access and refresh credentials without key rotation");
        }
        let vector:Value=serde_json::from_slice(&std::fs::read(path)?)?;
        let exec=setjoin_pg::ScopedExecutor::from_dsn(&std::env::var("DB_APP_DSN")?,4).unwrap();
        let keys=setjoin_authz::signing_keys::KeySet::load(&exec,fixture()["secret"].as_str().unwrap().as_bytes(),setjoin_config_secret::CryptoProfile::Standard).await?;
        for kind in ["access","refresh"]{
            use base64::Engine;
            let token=vector[kind].as_str().ok_or("missing Go swap artifact")?;
            let raw:Value=serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token.split('.').nth(1).ok_or("bad JWT")?)?)?;
            let when=raw["iat"].as_f64().ok_or("missing recorded issuance time")?+0.5;
            let claims=keys.validate(token,"mailserver",when).ok_or("frozen Go first-party signature/profile no longer verifies")?;
            if claims.get("typ").and_then(Value::as_str)!=Some(kind){return Err("swap token profile changed".into());}
        }
        for key in ["go_accepts_rust_access","go_accepts_rust_refresh","rust_accepts_go_access","rust_accepts_go_refresh"]{if vector[key]!=200{return Err("recorded swap was refused".into());}}
        Ok::<(),Err>(())
    }.await;
    common::restore_receipts(&env.c, &receipts).await;
    settlement::cleanup_identity(&env.c, a.user).await.unwrap();
    fixture::remove(&env.c, &a).await.unwrap();
    env.close().await.unwrap();
    result.unwrap();
}
