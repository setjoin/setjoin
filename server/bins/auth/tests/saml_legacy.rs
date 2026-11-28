//! Existing Go RSA1024 SP key custody; no key generation/rotation in production.
mod common;
include!("saml_oracle/harness.rs");
#[path = "saml_oracle/flows.rs"]
mod flows;
#[tokio::test]
async fn existing_go_legacy_rsa_key_keeps_working() {
    let _serial = SERIAL.lock().await;
    let env = flows::Env::start(false).await.unwrap();
    let result=async{
        let mut cfg=flows::config()?;
        cfg.saml_cert_file=corpus().join("legacy-sp-cert.pem").display().to_string();
        cfg.saml_key_file=corpus().join("legacy-sp-key.pem").display().to_string();
        let exec=setjoin_pg::ScopedExecutor::from_dsn(&std::env::var("DB_APP_DSN")?,4).map_err(|e|e.0)?;
        let auth=auth_server(Arc::new(AuthServer::load(exec,cfg).await?),false).await;let gw=gateway(auth.addr,None).await;
        let response=request(if env.recording{env.gw.addr}else{gw.addr},"GET","/auth/saml/idfed3/login",String::new(),&[]).await;
        let session=request(if env.recording{env.gw.addr}else{gw.addr},"GET","/auth/saml/idfed3/login",String::new(),&[("cookie",&format!("token={}",include_str!("../../../tests/conformance/identity-saml/legacy-session.jwt").trim()))]).await;
        let metrics=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await;
        gw.close().await;auth.close().await;let response=response?;let session=session?;
        if !env.recording&&!metrics?.2.contains("setjoin_gateway_proxied_to_go_total 0"){return Err("legacy replay proxied to Go".into());}
        if response.0!=302{return Err(format!("legacy SP key refused: {} {}",response.0,response.2).into());}
        let normalized=flows::normalize_for(response,include_bytes!("../../../tests/conformance/identity-saml/legacy-sp-public.der"),include_bytes!("../../../tests/conformance/identity-saml/legacy-sp-cert.pem"),true)?;
        let actual=json!({"format":1,"go_source":SOURCE,"route":"GET /auth/saml/{idp}/login","case":"legacy-rsa1024","observation":{"request":{"method":"GET","path":"/auth/saml/idfed3/login"},"response":normalized,"effects":[],"audit":[],"notify":[]}});
        let path=corpus().join("legacy-rsa1024.json");
        if env.recording&&!path.exists(){setjoin_conformance::golden::record(&path,&actual)?;}
        setjoin_conformance::golden::compare(&flows::expected_for(&path,&actual)?,&actual)?;
        let actual=json!({"format":1,"go_source":SOURCE,"route":"GET /auth/saml/{idp}/login","case":"legacy-rsa1024-session","observation":{"request":{"method":"GET","path":"/auth/saml/idfed3/login","cookie":"_existing_legacy_sp_session"},"response":{"status":session.0,"headers":session.1,"body":session.2},"effects":[],"audit":[],"notify":[]}});
        let path=corpus().join("legacy-rsa1024-session.json");
        if env.recording&&!path.exists(){setjoin_conformance::golden::record(&path,&actual)?;}
        setjoin_conformance::golden::compare(&serde_json::from_slice(&std::fs::read(path)?)?,&actual)?;
        Ok::<(),Err>(())
    }.await;
    env.close().await.unwrap();
    result.unwrap();
}
