//! Real PostgreSQL cuts before/after COMMIT, through the public auth/front door.
mod common;
include!("saml_oracle/harness.rs");
#[path = "saml_oracle/flows.rs"]
mod flows;
#[path = "saml_oracle/links.rs"]
mod links;
#[path = "common/webauthn_commit.rs"]
mod wire;
struct Proxy(tokio::task::JoinHandle<std::io::Result<wire::CommitCut>>);
impl Drop for Proxy {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn proof(
    exec: &setjoin_pg::ScopedExecutor,
    raw: &str,
) -> Result<setjoin_identity::session::Session, Err> {
    let secret = flows::fixture()["secret"].as_str().unwrap().to_owned();
    let keys = setjoin_authz::signing_keys::KeySet::load(
        exec,
        secret.as_bytes(),
        setjoin_config_secret::CryptoProfile::Standard,
    )
    .await?;
    let legacy = setjoin_authz::legacy_jwt::LegacyKeys::from_pem(
        secret.as_bytes(),
        &["authserver-hmac-1"],
        None,
    )
    .map_err(str::to_owned)?;
    setjoin_identity::session::Session::verify(raw, Some(&keys), &legacy, "mailserver")
        .ok_or("fresh signature verification failed".into())
}
async fn lost(unlink: bool, cut: wire::CommitCut) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = links::Env::start().await?;
    let result=async{
        let db=Db::for_case("IDFED3-commit").unwrap();let marker=if unlink{"identity-unlink"}else{"saml-link-begin"};
        let mut listener=db.listen("identity_link").await?;
        let (dsn,task)=wire::multiplex_commit_cut_proxy(&db.dsn,cut,marker).await;let mut proxy=Proxy(task);
        let mut cfg=flows::config()?;cfg.worker_dsn=Some(dsn);
        let exec=setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?;
        let auth=auth_server(Arc::new(AuthServer::load(exec,cfg).await?),false).await;let gw=gateway(auth.addr,None).await;
        let path=if unlink{format!("/auth/identity-links/{}",env.link)}else{"/auth/saml/idfed3/link".into()};
        let response=request(gw.addr,if unlink{"DELETE"}else{"POST"},&path,if unlink{"{\"reason\":\"IDFED3 commit\"}".into()}else{String::new()},&[("cookie",&format!("access_token={}",env.token))]).await;
        gw.close().await;auth.close().await;let response=response?;
        if tokio::time::timeout(std::time::Duration::from_secs(10),&mut proxy.0).await???!=cut{return Err("wrong COMMIT cut".into());}
        if response.0!=503||response.1.get("location").is_some()||response.1.get("set-cookie").is_some()||response.2.contains("unlinked\": true"){return Err("UNKNOWN published success or cookies".into());}
        let operation=setjoin_contracts::ids::OperationId(*uuid::Uuid::parse_str(response.1["x-operation-id"].as_str().ok_or("missing operation ID")?)?.as_bytes());
        let clean=setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?;
        let old=proof(&clean,&env.token).await?;let committed=cut==wire::CommitCut::AfterCommit;
        let kind=if unlink{setjoin_identity::rp::Operation::Unlink}else{setjoin_identity::rp::Operation::SamlLinkBegin};
        if unlink&&committed&&setjoin_identity::rp::lookup_session(&clean,&old,operation,kind).await.is_ok(){return Err("revoked original session retained receipt authority".into());}
        let raw=if unlink&&committed{
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            let raw=flows::access_age(&env.base.c,env.a.user,"aal2","gofree-idfed3-fresh",0).await?;
            use sha2::{Digest,Sha256};env.base.c.execute("INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES('gofree-idfed3-fresh',$1,$2,now()+interval '1 hour','totp')",&[&env.a.user,&Sha256::digest(raw.as_bytes()).to_vec()]).await?;raw
        }else{env.token.clone()};
        let fresh=proof(&clean,&raw).await?;
        if setjoin_identity::rp::lookup_session(&clean,&fresh,operation,kind).await.map_err(|e|e.message)?!=committed{return Err("owner receipt disagrees with COMMIT".into());}
        let foreign=proof(&clean,&env.other).await?;
        if setjoin_identity::rp::lookup_session(&clean,&foreign,operation,kind).await.unwrap_or(false){return Err("foreign principal observed receipt".into());}
        let effects=env.effects().await?;
        if unlink {
            if effects["actor"]["links"][0]["state"]!=if committed{"detached"}else{"active"}||effects["actor"]["revocations"].as_array().unwrap().len()!=usize::from(committed){return Err("unlink effects split from receipt".into());}
        }else if effects["actor"]["elevations"].as_array().unwrap().len()!=usize::from(committed){return Err("elevation split from receipt".into());}
        if listener.drain(&env.base.c).await?.len()!=usize::from(unlink&&committed){return Err("NOTIFY escaped COMMIT".into());}
        env.base.c.execute("UPDATE users SET enabled=false WHERE id=$1",&[&env.a.user]).await?;
        let disabled=setjoin_identity::rp::lookup_session(&clean,&fresh,operation,kind).await;
        env.base.c.execute("UPDATE users SET enabled=true WHERE id=$1",&[&env.a.user]).await?;
        if disabled.is_ok(){return Err("disabled user retained receipt authority".into());}
        println!("SAML-COMMIT: {marker} {cut:?}: withheld publication; live owner-only lookup and atomic effects verified");Ok::<(),Err>(())
    }.await;
    env.close().await?;
    result
}
#[tokio::test]
async fn link_before_commit() {
    lost(false, wire::CommitCut::BeforeCommit).await.unwrap();
}
#[tokio::test]
async fn link_after_commit() {
    lost(false, wire::CommitCut::AfterCommit).await.unwrap();
}
#[tokio::test]
async fn unlink_before_commit() {
    lost(true, wire::CommitCut::BeforeCommit).await.unwrap();
}
#[tokio::test]
async fn unlink_after_commit() {
    lost(true, wire::CommitCut::AfterCommit).await.unwrap();
}
