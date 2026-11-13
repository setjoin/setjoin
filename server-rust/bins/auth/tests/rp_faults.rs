//! Real PostgreSQL COMMIT cuts at the RP publishing commands; fresh proof lookup.
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
#[path = "common/webauthn_commit.rs"]
mod wire;
use setjoin_conformance::fixture;
struct Proxy(tokio::task::JoinHandle<std::io::Result<wire::CommitCut>>);
impl Drop for Proxy {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap()
}
async fn assertion(
    env: &flows::Env,
    subject: &str,
    email: &str,
) -> Result<setjoin_identity::rp::Assertion, Err> {
    let exec = setjoin_pg::ScopedExecutor::from_dsn(&std::env::var("DB_APP_DSN")?, 4).unwrap();
    let registry = setjoin_identity::rp::Registry::load(
        exec,
        fixture()["secret"].as_str().unwrap().as_bytes(),
        idp::http()?,
    )
    .await;
    let provider = registry
        .provider("idfed2")
        .ok_or("fresh provider unavailable")?;
    let flow = provider.authorization()?;
    let code = env.idp.state.code(
        &flow.verifier,
        &flow.nonce,
        json!({"sub":subject,"email":email,"email_verified":true}),
    );
    Ok(provider
        .exchange(&code, &flow.verifier)
        .await?
        .assertion(Some(&flow.nonce), &provider)?)
}
async fn lost(kind: &str, cut: wire::CommitCut) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = flows::Env::start(false).await?;
    settlement::cleanup_leftovers(&env.c).await?;
    let a = fixture::account(&env.c, "idfed2-actor").await?;
    let b = fixture::account(&env.c, "idfed2-foreign").await?;
    let receipts = common::receipt_ids(&env.c).await;
    let normalized = kind == "normalized-mint";
    let old_mode = env
        .c
        .query_opt(
            "SELECT read_mode FROM identity_sources WHERE provider_key='oidc:idfed2'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, String>(0));
    let result=async{
        let email:String=env.c.query_one("SELECT email FROM users WHERE id=$1",&[&a.user]).await?.get(0);
        let other:String=env.c.query_one("SELECT email FROM users WHERE id=$1",&[&b.user]).await?.get(0);
        env.c.execute("UPDATE users SET oidc_subject='actor-subject',oidc_issuer=$2 WHERE id=$1",&[&a.user,&idp::ISSUER]).await?;
        env.c.execute("UPDATE users SET oidc_subject='foreign-subject',oidc_issuer=$2 WHERE id=$1",&[&b.user,&idp::ISSUER]).await?;
        if normalized{
            env.c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.identity_model_v2',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await?;
            env.c.query_one("SELECT identity_auth_link($1,$1,'oidc',$2,'actor-subject','oidc:idfed2','IDFED2 commit fixture')",&[&a.user,&idp::ISSUER]).await?;
            env.c.execute("UPDATE identity_sources SET read_mode='normalized' WHERE provider_key='oidc:idfed2'",&[]).await?;
        }
        let response=request(env.gw.addr,"GET","/auth/oidc/login?provider=idfed2",String::new(),&[]).await?;let (_,flow)=flows::normalize_flow(response)?;
        let cookie=flow.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        let new_email=format!("changed@{}",email.split_once('@').unwrap().1);
        let code=env.idp.state.code(&flow["oidc_verifier"],&flow["oidc_nonce"],json!({"email":new_email,"email_verified":true}));
        let db=Db::for_case("IDFED2-commit").unwrap();let marker=match kind{"settle"=>"rp-settle",_=>"rp-mint"};
        let work=kind=="settle"||normalized;
        let (dsn,task)=wire::multiplex_commit_cut_proxy(if work{&db.dsn}else{db.app.as_deref().unwrap_or(&db.dsn)},cut,marker).await;let mut proxy=Proxy(task);
        let mut cfg=Config::for_secret(fixture()["secret"].as_str().unwrap().into());cfg.signing_alg="ES256".into();cfg.dsn=db.dsn.clone();cfg.direct_dsn=db.dsn.clone();cfg.worker_dsn=Some(if work{dsn.clone()}else{db.dsn.clone()});cfg.oidc_rp_enabled=true;
        let duration=std::time::Duration::from_secs(3);
        let exec=setjoin_pg::ScopedExecutor::from_dsn_with(if work{db.app.as_deref().unwrap_or(&db.dsn)}else{&dsn},4,setjoin_pg::Timeouts{pool_wait:duration,create:duration,statement:duration}).map_err(|e|e.0)?;
        let auth=auth_server(Arc::new(AuthServer::load_with_rp_http(exec,cfg,idp::http()?).await?),false).await;let gw=gateway(auth.addr,None).await;
        let path=setjoin_identity::oidc::query_response("/auth/oidc/callback",&[("state",&flow["oidc_state"]),("code",&code)],false);
        let response=request(gw.addr,"GET",&path,String::new(),&[("cookie",&cookie)]).await;
        gw.close().await;auth.close().await;let response=response?;
        if tokio::time::timeout(std::time::Duration::from_secs(10),&mut proxy.0).await???!=cut{return Err("wrong COMMIT cut".into());}
        if response.0!=503||response.2.contains("access_token")||response.2.contains("refresh_token")||response.1.get("location").is_some()||flows::cookies(&response.1).contains_key("access_token"){return Err(format!("unknown commit published success/credentials: {} {}",response.0,response.2).into());}
        let operation=setjoin_contracts::ids::OperationId(*uuid::Uuid::parse_str(response.1["x-operation-id"].as_str().ok_or("missing operation ID")?)?.as_bytes());
        let clean=setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?;let worker=setjoin_pg::ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?;
        let kind=if kind=="settle"{setjoin_identity::rp::Operation::Settle}else{setjoin_identity::rp::Operation::Mint};
        let fresh=assertion(&env,"actor-subject",&email).await?;let foreign=assertion(&env,"foreign-subject",&other).await?;
        let committed=cut==wire::CommitCut::AfterCommit;
        if setjoin_identity::rp::lookup_assertion(&clean,&worker,&fresh,operation,kind).await.map_err(|e|e.message)?!=committed{return Err("fresh assertion lookup disagrees with COMMIT".into());}
        if setjoin_identity::rp::lookup_assertion(&clean,&worker,&foreign,operation,kind).await.unwrap_or(false){return Err("foreign assertion observed receipt".into());}
        let row=env.c.query_one("SELECT email,(SELECT count(*) FROM oauth_tokens WHERE user_id=$1),(SELECT count(*) FROM sessions WHERE user_id=$1),(SELECT count(*) FROM login_events WHERE user_id=$1) FROM users WHERE id=$1",&[&a.user]).await?;
        // The IdP-asserted address never rewrites the account (#547), committed or not.
        let expected_email=&email;
        if row.get::<_,String>(0)!=*expected_email||row.get::<_,i64>(1)!=if marker=="rp-mint"&&committed{1}else{0}||row.get::<_,i64>(2)!=i64::from(normalized)||row.get::<_,i64>(3)!=i64::from(normalized){return Err("commit fence/tail effects differ".into());}
        env.c.execute("UPDATE users SET enabled=false WHERE id=$1",&[&a.user]).await?;
        if setjoin_identity::rp::lookup_assertion(&clean,&worker,&fresh,operation,kind).await.is_ok(){return Err("disabled assertion observed receipt".into());}
        env.c.execute("UPDATE users SET enabled=true WHERE id=$1",&[&a.user]).await?;
        println!("RP-COMMIT: {marker} {cut:?} withheld credentials; fresh owner-only lookup verified");Ok::<(),Err>(())
    }.await;
    if normalized {
        env.c
            .execute(
                "UPDATE feature_toggles SET enabled=false WHERE key='feature.identity_model_v2'",
                &[],
            )
            .await?;
        if let Some(mode) = &old_mode {
            env.c
                .execute(
                    "UPDATE identity_sources SET read_mode=$1 WHERE provider_key='oidc:idfed2'",
                    &[&mode],
                )
                .await?;
        }
    }
    common::restore_receipts(&env.c, &receipts).await;
    settlement::cleanup_identity(&env.c, a.user).await?;
    fixture::remove(&env.c, &a).await?;
    fixture::remove(&env.c, &b).await?;
    // Any settled OIDC login creates the source, not only the normalized variants: remove it
    // (once unlinked) so no later suite sees a leftover identity source.
    env.c
        .execute(
            "WITH s AS (SELECT x.id FROM identity_sources x WHERE x.provider_key IN ('oidc:idfed2') AND NOT EXISTS (SELECT 1 FROM user_identity_links l WHERE l.source_id=x.id)), a AS (DELETE FROM identity_auth_shadow_hours WHERE source_id IN (SELECT id FROM s)), b AS (DELETE FROM identity_auth_shadow_link_evidence WHERE source_id IN (SELECT id FROM s)), c AS (DELETE FROM identity_shadow_divergences WHERE source_id IN (SELECT id FROM s)) DELETE FROM identity_sources WHERE id IN (SELECT id FROM s)",
            &[],
        )
        .await?;
    env.close().await?;
    result
}
#[tokio::test]
async fn settle_before_commit() {
    lost("settle", wire::CommitCut::BeforeCommit).await.unwrap();
}
#[tokio::test]
async fn settle_after_commit() {
    lost("settle", wire::CommitCut::AfterCommit).await.unwrap();
}
#[tokio::test]
async fn mint_before_commit() {
    lost("mint", wire::CommitCut::BeforeCommit).await.unwrap();
}
#[tokio::test]
async fn mint_after_commit() {
    lost("mint", wire::CommitCut::AfterCommit).await.unwrap();
}

#[tokio::test]
async fn normalized_mint_before_commit() {
    lost("normalized-mint", wire::CommitCut::BeforeCommit)
        .await
        .unwrap();
}
#[tokio::test]
async fn normalized_mint_after_commit() {
    lost("normalized-mint", wire::CommitCut::AfterCommit)
        .await
        .unwrap();
}
#[path = "rp_oracle/link.rs"]
mod link;
async fn lost_link(kind: &str, cut: wire::CommitCut) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = link::Env::start().await?;
    let result=async{
        let mut cookie=format!("access_token={}",env.token);let mut method="POST";let mut path="/auth/oidc/link?provider=idfed2".to_owned();
        let marker=if kind=="begin"{"rp-link-begin"}else{"rp-link-finish"};
        if kind=="finish"{
            let response=request(env.base.gw.addr,"POST",&path,String::new(),&[("cookie",&cookie)]).await?;
            if response.0!=302{return Err("fault link setup failed".into());}
            let (_,mut flow)=flows::normalize_flow(response)?;flow.insert("access_token".into(),env.token.clone());
            let code=env.base.idp.state.code(&flow["oidc_verifier"],&flow["oidc_nonce"],json!({"sub":"fault-linked-subject","email_verified":true}));
            cookie=flow.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; ");
            method="GET";path=setjoin_identity::oidc::query_response("/auth/oidc/callback",&[("state",&flow["oidc_state"]),("code",&code)],false);
        }
        let db=Db::for_case("IDFED2-link-commit").unwrap();let mut listener=db.listen("identity_link").await?;
        let (dsn,task)=wire::multiplex_commit_cut_proxy(&db.dsn,cut,marker).await;let mut proxy=Proxy(task);
        let mut cfg=Config::for_secret(fixture()["secret"].as_str().unwrap().into());cfg.signing_alg="ES256".into();cfg.dsn=db.dsn.clone();cfg.direct_dsn=db.dsn.clone();cfg.worker_dsn=Some(dsn);cfg.oidc_rp_enabled=true;
        let exec=setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?;
        let auth=auth_server(Arc::new(AuthServer::load_with_rp_http(exec,cfg,idp::http()?).await?),false).await;let gw=gateway(auth.addr,None).await;
        let response=request(gw.addr,method,&path,String::new(),&[("cookie",&cookie)]).await;
        gw.close().await;auth.close().await;let response=response?;
        if tokio::time::timeout(std::time::Duration::from_secs(10),&mut proxy.0).await???!=cut{return Err("wrong link COMMIT cut".into());}
        if response.0!=503||response.1.get("location").is_some()||flows::cookies(&response.1).get("identity_link_flow").is_some_and(|v|!v.is_empty())||flows::cookies(&response.1).get("oidc_verifier").is_some_and(|v|!v.is_empty()){return Err("unknown link commit published flow or success".into());}
        let operation=setjoin_contracts::ids::OperationId(*uuid::Uuid::parse_str(response.1["x-operation-id"].as_str().ok_or("missing link operation ID")?)?.as_bytes());
        let clean=setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?;
        let keys=setjoin_authz::signing_keys::KeySet::load(&clean,fixture()["secret"].as_str().unwrap().as_bytes(),setjoin_config_secret::CryptoProfile::Standard).await?;
        let legacy=setjoin_authz::legacy_jwt::LegacyKeys::from_pem(fixture()["secret"].as_str().unwrap().as_bytes(),&["authserver-hmac-1"],None).map_err(str::to_owned)?;
        let proof=setjoin_identity::session::Session::verify(&env.token,Some(&keys),&legacy,"mailserver").ok_or("fresh link session verification")?;
        let operation_kind=if kind=="begin"{setjoin_identity::rp::Operation::LinkBegin}else{setjoin_identity::rp::Operation::LinkFinish};
        let committed=cut==wire::CommitCut::AfterCommit;
        if setjoin_identity::rp::lookup_session(&clean,&proof,operation,operation_kind).await.map_err(|e|e.message)?!=committed{return Err("link receipt disagrees with COMMIT".into());}
        let email:String=env.base.c.query_one("SELECT email FROM users WHERE id=$1",&[&env.b.user]).await?.get(0);let raw=settlement::session_token(env.b.user,&email,"aal2").await?;
        let foreign=setjoin_identity::session::Session::verify(&raw,Some(&keys),&legacy,"mailserver").ok_or("foreign signature verification")?;
        if setjoin_identity::rp::lookup_session(&clean,&foreign,operation,operation_kind).await.unwrap_or(false){return Err("foreign link principal observed receipt".into());}
        let effects=env.effects().await?;
        let expected_links=if kind=="finish"&&committed{1}else{0};let expected_elevations=if kind=="finish"||committed{1}else{0};
        if effects["actor_identity"]["links"].as_array().unwrap().len()!=expected_links||effects["store"]["actor_elevations"].as_array().unwrap().len()!=expected_elevations{return Err(format!("link commit effects differ: {effects}").into());}
        if kind=="finish"&&effects["store"]["actor_elevations"][0]!=committed{return Err("elevation consumption split from link".into());}
        let notify=listener.drain(&env.base.c).await?;if notify.len()!=expected_links{return Err("link NOTIFY escaped its commit".into());}
        env.base.c.execute("INSERT INTO session_revocations(user_id,scope,jti,reason,not_before,expires_at) VALUES($1,'jti','idfed2-session','IDFED2 fixture',now(),now()+interval '1 hour')",&[&env.a.user]).await?;
        if setjoin_identity::rp::lookup_session(&clean,&proof,operation,operation_kind).await.is_ok(){return Err("revoked link session retained receipt authority".into());}
        env.base.c.execute("DELETE FROM session_revocations WHERE user_id=$1 AND scope='jti' AND jti='idfed2-session'",&[&env.a.user]).await?;
        env.base.c.execute("UPDATE users SET enabled=false WHERE id=$1",&[&env.a.user]).await?;
        if setjoin_identity::rp::lookup_session(&clean,&proof,operation,operation_kind).await.is_ok(){return Err("disabled link user retained receipt authority".into());}
        env.base.c.execute("UPDATE users SET enabled=true WHERE id=$1",&[&env.a.user]).await?;
        println!("RP-COMMIT: {marker} {cut:?} withheld publication; live owner-only lookup and atomic effects verified");Ok::<(),Err>(())
    }.await;
    env.close().await?;
    result
}
#[tokio::test]
async fn link_begin_before_commit() {
    lost_link("begin", wire::CommitCut::BeforeCommit)
        .await
        .unwrap();
}
#[tokio::test]
async fn link_begin_after_commit() {
    lost_link("begin", wire::CommitCut::AfterCommit)
        .await
        .unwrap();
}
#[tokio::test]
async fn link_finish_before_commit() {
    lost_link("finish", wire::CommitCut::BeforeCommit)
        .await
        .unwrap();
}
#[tokio::test]
async fn link_finish_after_commit() {
    lost_link("finish", wire::CommitCut::AfterCommit)
        .await
        .unwrap();
}
