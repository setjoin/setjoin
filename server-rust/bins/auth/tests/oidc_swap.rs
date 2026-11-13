//! Live frozen-Go/native OP swap. Run explicitly with the assigned recorder;
//! ordinary oidc_oracle qualification has both Go upstreams unset.
mod common;
include!("oidc_oracle/harness.rs");
#[path = "oidc_oracle/grants.rs"]
mod grants;
#[path = "oidc_oracle/tokens.rs"]
mod tokens;
#[tokio::test]
async fn tokens_verify_across_the_go_rust_swap() {
    let Ok(upstream)=std::env::var("GOFREE_SWAP_UPSTREAM") else{
        let _serial=SERIAL.lock().await;let env=grants::Env::start(false).await.unwrap();
        let result=async{
            let vector:Value=serde_json::from_slice(&std::fs::read(corpus().join("interop-go-tokens.json"))?)?;
            let key=setjoin_identity::oidc::SigningKey::load(corpus().join("op-private.pem").to_str().unwrap(),corpus().join("op-public.pem").to_str().unwrap())?;
            for kind in ["access","id"]{let claims=key.verify(vector[kind].as_str().ok_or("missing Go artifact")?).ok_or("Go signature no longer verifies")?;if claims["iss"]!=vector["issuer"]{return Err("Go issuer changed".into());}}
            let native=tokens::fresh(&env).await?;let r=request(env.gw.addr,"GET","/userinfo",String::new(),&[("authorization",&format!("Bearer {}",native.access))]).await?;if r.0!=200{return Err("native replay failed".into());}Ok::<(),Err>(())
        }.await;env.close().await.unwrap();result.unwrap();return;
    };
    let go: hyper::Uri = upstream.parse().unwrap();
    let addr: std::net::SocketAddr = format!("{}:{}", go.host().unwrap(), go.port_u16().unwrap())
        .parse()
        .unwrap();
    let _serial = SERIAL.lock().await;
    let mut env = grants::Env::start(false).await.unwrap();
    let result=async{
  let rust=tokens::fresh(&env).await?;
  let response=request(addr,"GET","/userinfo",String::new(),&[("authorization",&format!("Bearer {}",rust.access))]).await?;
  if response.0!=200{return Err(format!("Go rejected Rust OP JWT: {} {}",response.0,response.2).into());}
  let response=request(addr,"POST","/end_session",format!("client_id={}&id_token_hint={}",grants::CLIENT,rust.id),&[("content-type","application/x-www-form-urlencoded")]).await?;
  if response.0!=302{return Err("Go rejected Rust OP ID token".into());}
  let bridge=gateway(env.auth.addr,Some(upstream)).await;
  let native_gateway=std::mem::replace(&mut env.gw,bridge);
  let go_token=tokens::fresh(&env).await?;
  let bridge=std::mem::replace(&mut env.gw,native_gateway);bridge.close().await;
  let response=request(env.gw.addr,"GET","/userinfo",String::new(),&[("authorization",&format!("Bearer {}",go_token.access))]).await?;
  if response.0!=200{return Err(format!("Rust rejected Go OP JWT: {} {}",response.0,response.2).into());}
  let response=request(env.gw.addr,"POST","/end_session",format!("client_id={}&id_token_hint={}",grants::CLIENT,go_token.id),&[("content-type","application/x-www-form-urlencoded")]).await?;
  if response.0!=302{return Err("Rust rejected Go OP ID token".into());}
  let path=corpus().join("interop-go-tokens.json");if !path.exists(){golden::record(&path,&json!({"format":1,"go_source":SOURCE,"issuer":"https://auth.idfed1.test","access":go_token.access,"id":go_token.id}))?;}
  println!("OP-SWAP: Rust->Go and Go->Rust RS256 access and ID credentials accepted without rotation or session reset");
  Ok::<(),Err>(())
 }.await;
    env.close().await.unwrap();
    result.unwrap();
}
