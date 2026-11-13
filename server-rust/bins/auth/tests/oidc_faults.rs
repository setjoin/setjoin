//! HTTP publication under actual PostgreSQL COMMIT wire loss.
mod common;
include!("oidc_oracle/harness.rs");
#[path = "oidc_oracle/grants.rs"]
mod grants;
#[path = "oidc_oracle/tokens.rs"]
mod tokens;
#[path = "common/webauthn_commit.rs"]
mod wire;
struct Proxy(tokio::task::JoinHandle<std::io::Result<wire::CommitCut>>);
impl Drop for Proxy {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn lost(kind: &str, cut: wire::CommitCut) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = grants::Env::start(false).await?;
    let result=async{
  let session=grants::session(&env,false).await?;
  let mut headers=vec![("content-type","application/x-www-form-urlencoded")];let mut method="POST";let mut path="/oauth/token".to_owned();let payload;
  let marker;let operation_kind;
  match kind{
   "authorize"=>{method="GET";path=format!("/authorize?client_id={}&redirect_uri=https%3A%2F%2Frp.idfed1.test%2Fcallback&response_type=code&scope=openid",grants::CLIENT);payload=String::new();marker="oidc-authorize";operation_kind=None;},
   "complete"|"code"=>{
    let id=grants::pending(&env).await?;method="GET";
    if kind=="complete"{let page=request(env.gw.addr,"GET",&format!("/auth/oidc/op/complete?id={id}"),String::new(),&[("authorization",&session)]).await?;let csrf=grants::csrf_of(&page.2).ok_or("completion page")?;path="/auth/oidc/op/complete".to_owned();method="POST";payload=format!("id={id}&csrf={csrf}");headers.push(("authorization",session.as_str()));marker="oidc-complete";operation_kind=Some(setjoin_identity::oidc::Operation::Complete);}
    else{payload=String::new();let r=grants::complete_flow(&env,&id,&session).await?;if r.0!=302{return Err("callback fault setup".into());}path=format!("/authorize/callback?id={id}");headers.push(("authorization",session.as_str()));marker="oidc-code";operation_kind=Some(setjoin_identity::oidc::Operation::Code);}
   },
   "consume"|"access"|"attach"=>{
    let(_,code)=tokens::code(&env).await?;payload=format!("grant_type=authorization_code&client_id={}&code={code}&redirect_uri=https%3A%2F%2Frp.idfed1.test%2Fcallback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",grants::CLIENT);
    (marker,operation_kind)=match kind{"consume"=>("oidc-consume",Some(setjoin_identity::oidc::Operation::Consume)),"access"=>("oidc-access",Some(setjoin_identity::oidc::Operation::Access)),_=>("oidc-refresh-attach",Some(setjoin_identity::oidc::Operation::RefreshAttach))};
   },
   _=>{let fresh=tokens::fresh(&env).await?;
    match kind{
     "rotate"=>{payload=format!("grant_type=refresh_token&client_id={}&refresh_token={}",grants::CLIENT,fresh.refresh);marker="oidc-rotate";operation_kind=Some(setjoin_identity::oidc::Operation::Rotate);},
     "revoke"=>{path="/revoke".into();payload=format!("client_id={}&token={}",grants::CLIENT,fresh.access);marker="oidc-revoke";operation_kind=Some(setjoin_identity::oidc::Operation::Revoke);},
     _=>{path="/end_session".into();payload=format!("client_id={}&id_token_hint={}",grants::CLIENT,fresh.id);marker="oidc-end-session";operation_kind=Some(setjoin_identity::oidc::Operation::EndSession);},
    }
   }
  }
  let db=Db::for_case("IDFED1-commit").unwrap();let (dsn,task)=wire::multiplex_commit_cut_proxy(db.app.as_deref().unwrap_or(&db.dsn),cut,marker).await;let mut proxy=Proxy(task);
  let fixture:Value=serde_json::from_str(include_str!("../../../tests/conformance/identity-login/keys.json"))?;
  let mut cfg=Config::for_secret(fixture["secret"].as_str().unwrap().into());cfg.dsn=db.dsn.clone();cfg.oidc_enabled=true;cfg.oidc_hostname="auth.idfed1.test".into();cfg.oidc_private_key=corpus().join("op-private.pem").to_str().unwrap().into();cfg.oidc_public_key=corpus().join("op-public.pem").to_str().unwrap().into();
  let duration=std::time::Duration::from_secs(3);let exec=setjoin_pg::ScopedExecutor::from_dsn_with(&dsn,4,setjoin_pg::Timeouts{pool_wait:duration,create:duration,statement:duration}).map_err(|e|e.0)?;
  let auth=auth_server(Arc::new(AuthServer::load(exec,cfg).await?),false).await;let gw=gateway(auth.addr,None).await;
  let response=request(gw.addr,method,&path,payload,&headers).await;
  gw.close().await;auth.close().await;let response=response?;
  let observed=tokio::time::timeout(std::time::Duration::from_secs(10),&mut proxy.0).await???;if observed!=cut{return Err("wrong COMMIT cut".into());}
  if response.2.contains("access_token")||response.2.contains("refresh_token")||response.1["location"].as_str().is_some_and(|s|s.contains("code=")){return Err("OIDC credential escaped an unknown COMMIT".into());}
  let id=response.1["x-operation-id"].as_str().ok_or_else(||format!("missing unknown operation: {} {}",response.0,response.2))?;let operation=setjoin_contracts::ids::OperationId(*uuid::Uuid::parse_str(id)?.as_bytes());
  let clean=setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),2).map_err(|e|e.0)?;let committed=cut==wire::CommitCut::AfterCommit;
  if let Some(kind)=operation_kind{
   let legacy=setjoin_authz::legacy_jwt::LegacyKeys::new(fixture["secret"].as_str().unwrap().as_bytes(),&["authserver-hmac-1"],None)?;
   let proof=setjoin_identity::session::Session::verify(session.strip_prefix("Bearer ").unwrap(),None,&legacy,"mailserver").ok_or("fresh session verification")?;
   if setjoin_identity::oidc::lookup_operation(&clean,&proof,operation,kind).await.map_err(|e|e.message)?!=committed{return Err("OIDC receipt disagrees with COMMIT".into());}
   let foreign=grants::session(&env,true).await?;let foreign=setjoin_identity::session::Session::verify(foreign.strip_prefix("Bearer ").unwrap(),None,&legacy,"mailserver").ok_or("foreign proof")?;
   if setjoin_identity::oidc::lookup_operation(&clean,&foreign,operation,kind).await.map_err(|e|e.message)?{return Err("foreign user observed OIDC receipt".into());}
   env.c.execute("UPDATE users SET enabled=false WHERE id=$1",&[&env.a.user]).await?;
   if setjoin_identity::oidc::lookup_operation(&clean,&proof,operation,kind).await.is_ok(){return Err("disabled user retained receipt authority".into());}
   env.c.execute("UPDATE users SET enabled=true WHERE id=$1",&[&env.a.user]).await?;
  }else{
   if setjoin_identity::oidc::lookup_authorization(&clean,grants::CLIENT,operation).await.map_err(|e|e.message)?!=committed{return Err("authorization receipt disagrees with COMMIT".into());}
   if setjoin_identity::oidc::lookup_authorization(&clean,grants::OTHER,operation).await.map_err(|e|e.message)?{return Err("foreign client observed authorization receipt".into());}
   env.c.execute("UPDATE oidc_clients SET enabled=false WHERE id=$1",&[&grants::CLIENT]).await?;
   if setjoin_identity::oidc::lookup_authorization(&clean,grants::CLIENT,operation).await.is_ok(){return Err("disabled client retained receipt authority".into());}
  }
  let n: i64=env.c.query_one("SELECT count(*) FROM oidc_tokens WHERE client_id=$1",&[&grants::CLIENT]).await?.get(0);
  let expected=match kind{"authorize"|"complete"|"code"|"consume"=>0,"access"=>i64::from(committed),"rotate"=>1+i64::from(committed),_=>1};if n!=expected{return Err(format!("{kind} leaked/lost token anchors: {n}, expected{expected}").into());}
  if matches!(kind,"rotate"|"revoke"|"end") {let n:i64=env.c.query_one("SELECT count(*) FROM oidc_tokens WHERE client_id=$1 AND revoked_at IS NOT NULL",&[&grants::CLIENT]).await?.get(0);if n!=i64::from(committed){return Err("revocation escaped the publishing transaction".into());}}
  Ok::<(),Err>(())
 }.await;
    env.close().await?;
    result
}
macro_rules! cut {
    ($name:ident,$kind:literal,$cut:ident) => {
        #[tokio::test]
        async fn $name() {
            lost($kind, wire::CommitCut::$cut).await.unwrap();
        }
    };
}
cut!(authorize_before_commit, "authorize", BeforeCommit);
cut!(authorize_after_commit, "authorize", AfterCommit);
cut!(complete_before_commit, "complete", BeforeCommit);
cut!(complete_after_commit, "complete", AfterCommit);
cut!(code_before_commit, "code", BeforeCommit);
cut!(code_after_commit, "code", AfterCommit);
cut!(consume_before_commit, "consume", BeforeCommit);
cut!(consume_after_commit, "consume", AfterCommit);
cut!(access_before_commit, "access", BeforeCommit);
cut!(access_after_commit, "access", AfterCommit);
cut!(attach_before_commit, "attach", BeforeCommit);
cut!(attach_after_commit, "attach", AfterCommit);
cut!(rotate_before_commit, "rotate", BeforeCommit);
cut!(rotate_after_commit, "rotate", AfterCommit);
cut!(revoke_before_commit, "revoke", BeforeCommit);
cut!(revoke_after_commit, "revoke", AfterCommit);
cut!(end_before_commit, "end", BeforeCommit);
cut!(end_after_commit, "end", AfterCommit);
