//! Real PostgreSQL COMMIT cuts, fresh proof lookup and failed reads during RP completion.
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
#[path = "common/revoke.rs"]
mod revoke;
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
) -> Result<(setjoin_identity::rp::Assertion, Arc<setjoin_identity::rp::Provider>), Err> {
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
    let verified = provider
        .exchange(&code, &flow.verifier)
        .await?
        .assertion(Some(&flow.nonce), &provider)?;
    Ok((verified, provider))
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
        let (fresh,_)=assertion(&env,"actor-subject",&email).await?;let (foreign,_)=assertion(&env,"foreign-subject",&other).await?;
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
    // #431: shared oidc:idfed2 source rows are left for the throwaway CI database; the sweep
    // is provider-wide and would remove other cases' rows.
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

/// Fable 353-2: no N7 case may run against a replaced is_guest_account. Restore
/// from the reducer source, or fail hard.
async fn guest_function_pristine(c: &tokio_postgres::Client) -> Result<(), Err> {
    async fn def(c: &tokio_postgres::Client) -> Result<String, tokio_postgres::Error> {
        c.query_one(
            "SELECT pg_get_functiondef('is_guest_account(bigint)'::regprocedure)",
            &[],
        )
        .await
        .map(|r| r.get::<_, String>(0))
    }
    let ok = |d: &str| {
        d.contains("SECURITY DEFINER")
            && d.contains("public.guest_accounts")
            && !d.contains("gofree_")
    };
    if ok(&def(c).await?) {
        return Ok(());
    }
    c.batch_execute(include_str!(
        "../../../../mailserver/sql/reducers/guest_account.sql"
    ))
    .await?;
    c.batch_execute("DROP SEQUENCE IF EXISTS gofree_idmfa1_guest_calls; DROP SEQUENCE IF EXISTS gofree_guest353_calls").await?;
    if ok(&def(c).await?) {
        Ok(())
    } else {
        Err("is_guest_account is not pristine after restore; refusing to run".into())
    }
}
/// Replaces is_guest_account with a counting function; `branch` runs after the
/// call number is stored in `n` (1-based).
async fn install_counting_guest(c: &tokio_postgres::Client, branch: &str) -> Result<(), Err> {
    c.batch_execute("DROP SEQUENCE IF EXISTS gofree_guest353_calls;CREATE SEQUENCE gofree_guest353_calls;GRANT USAGE ON SEQUENCE gofree_guest353_calls TO setjoin_app").await?;
    c.batch_execute(&format!("CREATE OR REPLACE FUNCTION is_guest_account(p_user_id bigint) RETURNS boolean LANGUAGE plpgsql AS $$DECLARE n bigint; BEGIN n := nextval('gofree_guest353_calls'); {branch} END$$")).await?;
    Ok(())
}
fn jwt_claims(token: &str) -> Result<Value, Err> {
    use base64::Engine;
    let segment = token.split('.').nth(1).ok_or("jwt without payload")?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(segment)?;
    Ok(serde_json::from_slice(&raw)?)
}
/// One OIDC SSO completion for an existing member; returns the callback response.
async fn sso_once(
    env: &flows::Env,
    email: &str,
    subject: &str,
) -> Result<(u16, Value, String), Err> {
    let response = request(
        env.gw.addr,
        "GET",
        "/auth/oidc/login?provider=idfed2",
        String::new(),
        &[],
    )
    .await?;
    let (_, flow) = flows::normalize_flow(response)?;
    let cookie = flow
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let code = env.idp.state.code(
        &flow["oidc_verifier"],
        &flow["oidc_nonce"],
        json!({"sub":subject,"email":email,"email_verified":true}),
    );
    let path = setjoin_identity::oidc::query_response(
        "/auth/oidc/callback",
        &[("state", &flow["oidc_state"]), ("code", &code)],
        false,
    );
    request(env.gw.addr, "GET", &path, String::new(), &[("cookie", &cookie)]).await
}
async fn sso_effects(c: &tokio_postgres::Client, user: i64) -> Result<(i64, i64), Err> {
    let r = c
        .query_one(
            "SELECT (SELECT count(*) FROM oauth_tokens WHERE user_id=$1),(SELECT count(*) FROM sessions WHERE user_id=$1)",
            &[&user],
        )
        .await?;
    Ok((r.get(0), r.get(1)))
}
/// Combines a case result with a cleanup result: the case error is kept (the
/// cleanup error is appended); a cleanup error alone fails a passing case.
fn settle(case: Result<(), Err>, cleanup: Result<(), Err>) -> Result<(), Err> {
    match (case, cleanup) {
        (Ok(()), c) => c,
        (Err(e), Ok(())) => Err(e),
        (Err(e), Err(c)) => Err(format!("{e}; cleanup also failed: {c}").into()),
    }
}
/// N7 (#353): SSO completion for a member carries no `acct`; a guest row seen
/// only at the mint-time admission lookup is refused with 503.
async fn n7_sso_guest_scope() -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = flows::Env::start(false).await?;
    guest_function_pristine(&env.c).await?;
    settlement::cleanup_leftovers(&env.c).await?;
    // Receipts this case writes are all family F21 (rp-settle/rp-mint commands:
    // crates/domains/identity/src/rp/account.rs:300,507); restore that family only.
    let receipts = common::receipt_ids(&env.c).await;
    let a = fixture::account(&env.c, "guest353-n7-member").await?;
    let result = async {
        let email: String = env
            .c
            .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
            .await?
            .get(0);
        env.c.execute("UPDATE users SET oidc_subject='guest353-n7-subject',oidc_issuer=$2 WHERE id=$1", &[&a.user, &idp::ISSUER]).await?;
        // (i) member SSO, counting function that never says guest: learn k.
        install_counting_guest(&env.c, "RETURN false;").await?;
        let before = sso_effects(&env.c, a.user).await?;
        let (status, headers, raw) = sso_once(&env, &email, "guest353-n7-subject").await?;
        if status != 302 && status != 200 {
            return Err(format!("member SSO status {status}: {raw}").into());
        }
        let jar = flows::cookies(&headers);
        let access = jar.get("access_token").filter(|v| !v.is_empty()).ok_or("member SSO set no access cookie")?;
        if jwt_claims(access)?.get("acct").is_some() {
            return Err("member SSO access token must not carry acct".into());
        }
        let after = sso_effects(&env.c, a.user).await?;
        if after.0 != before.0 + 1 {
            return Err(format!("member SSO should add one oauth_tokens row: {before:?} -> {after:?}").into());
        }
        let k: i64 = env.c.query_one("SELECT last_value FROM gofree_guest353_calls", &[]).await?.get(0);
        if k < 1 {
            return Err("member SSO never called is_guest_account".into());
        }
        // (ii) race: false until the k-th (mint-time) lookup, which says guest.
        install_counting_guest(&env.c, &format!("RETURN n = {k};")).await?;
        let before = sso_effects(&env.c, a.user).await?;
        let (status, headers, raw) = sso_once(&env, &email, "guest353-n7-subject").await?;
        if status != 503 || !raw.contains("conditional access context unavailable") {
            return Err(format!("race: want 503 conditional access context unavailable, got {status} {raw}").into());
        }
        if raw.contains("access_token") || raw.contains("refresh_token") || headers.get("location").is_some() || flows::cookies(&headers).get("access_token").is_some_and(|v| !v.is_empty()) {
            return Err("race: refused SSO leaked credentials".into());
        }
        let after = sso_effects(&env.c, a.user).await?;
        if after != before {
            return Err(format!("race: refused SSO left rows: {before:?} -> {after:?}").into());
        }
        let calls: i64 = env.c.query_one("SELECT last_value FROM gofree_guest353_calls", &[]).await?.get(0);
        if calls != k {
            return Err(format!("race: expected {k} lookups, saw {calls}").into());
        }
        Ok::<(), Err>(())
    }
    .await;
    let pristine = guest_function_pristine(&env.c).await;
    let identity = settlement::cleanup_identity(&env.c, a.user).await;
    let removed = fixture::remove(&env.c, &a).await;
    // Non-panicking receipt restore (common::restore_receipts unwraps) so teardown always settles.
    let receipts_restored = env
        .c
        .execute("DELETE FROM rust_operation_receipts WHERE family='F21' AND operation_id::text<>ALL($1::text[])", &[&receipts])
        .await
        .map(|_| ());
    // #431: shared oidc:idfed2 source rows are left for the throwaway CI database; the sweep
    // is provider-wide and would remove other cases' rows.
    let closed = env.close().await;
    let cleanup = pristine
        .and(identity)
        .and(removed.map_err(|e| -> Err { e.into() }))
        .and(receipts_restored.map_err(|e| -> Err { e.into() }))
        .and(closed);
    settle(result, cleanup)
}
#[tokio::test]
async fn n7_sso_refuses_guest_rows_at_mint() {
    n7_sso_guest_scope().await.unwrap();
}

/// #454: SSO completion with a failing risk read answers 500 'token issue failed' before any
/// token is signed or stored; the same login succeeds once the read works again. Cleanup runs
/// on every path: each step is aggregated, and only rows this test created are removed.
async fn failclosed_sso_risk() -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = flows::Env::start(false).await?;
    let mut saved: Option<String> = None;
    let mut account: Option<fixture::Account> = None;
    let result: Result<(), Err> = async {
        settlement::cleanup_leftovers(&env.c).await?;
        let db = Db::for_case("IDFED2-failclosed").ok_or("assigned DB required")?;
        let app = setjoin_pg::ScopedExecutor::from_dsn(
            db.app.as_deref().ok_or("DB_APP_DSN required")?,
            2,
        )
        .map_err(|e| e.0)?;
        saved = Some(
            env.c
                .query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key='feature.user_risk'", &[])
                .await?
                .try_get(0)?,
        );
        let a = fixture::account(&env.c, "failclosed-rp-member").await?;
        let user = a.user;
        account = Some(a);
        let email: String = env
            .c
            .query_one("SELECT email FROM users WHERE id=$1", &[&user])
            .await?
            .try_get(0)?;
        env.c
            .execute(
                "UPDATE users SET oidc_subject='failclosed-rp-subject',oidc_issuer=$2 WHERE id=$1",
                &[&user, &idp::ISSUER],
            )
            .await?;
        env.c
            .execute(
                "INSERT INTO feature_toggles(key,enabled) VALUES('feature.user_risk',true) ON CONFLICT(key) DO UPDATE SET enabled=true",
                &[],
            )
            .await?;
        let before = sso_effects(&env.c, user).await?;
        let guard = revoke::table(&db.dsn, &env.c, &app, "user_risk").await?;
        let (status, headers, raw) = sso_once(&env, &email, "failclosed-rp-subject").await?;
        guard.restore(&env.c).await?;
        let after = sso_effects(&env.c, user).await?;
        if status != 500 || !raw.contains("token issue failed") {
            return Err(format!("want 500 token issue failed, got {status}: {raw}").into());
        }
        if raw.contains("access_token") || raw.contains("refresh_token") || headers.get("location").is_some() || flows::cookies(&headers).get("access_token").is_some_and(|v| !v.is_empty()) {
            return Err("refused SSO leaked credentials".into());
        }
        if after != before {
            return Err(format!("refused SSO left token/session rows: {before:?} -> {after:?}").into());
        }
        let (status, headers, raw) = sso_once(&env, &email, "failclosed-rp-subject").await?;
        if status != 302 && status != 200 {
            return Err(format!("control SSO status {status}: {raw}").into());
        }
        flows::cookies(&headers).get("access_token").filter(|v| !v.is_empty()).ok_or("control SSO set no access cookie")?;
        Ok(())
    }
    .await;

    // Cleanup: every step runs, failures aggregate, and nothing is short-circuited.
    let mut cleanup: Result<(), Err> = Ok(());
    if let Some(saved) = &saved {
        let flag: Result<(), Err> = async {
            env.c.execute("DELETE FROM feature_toggles WHERE key='feature.user_risk'", &[]).await?;
            env.c.execute("INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)", &[saved]).await?;
            Ok(())
        }
        .await;
        cleanup = settle(cleanup, flag);
    }
    if let Some(a) = &account {
        cleanup = settle(cleanup, settlement::cleanup_identity(&env.c, a.user).await);
    }
    if let Some(a) = &account {
        let removed: Result<(), Err> = fixture::remove(&env.c, a).await.map(|_| ()).map_err(Into::into);
        cleanup = settle(cleanup, removed);
    }
    // Residue rows (SSO receipts, identity sources and their evidence, login events) are left
    // for the throwaway CI database (#431).
    let closed = env.close().await;
    cleanup = settle(cleanup, closed);
    settle(result, cleanup)
}
#[tokio::test]
async fn failclosed_454_sso_risk_fault_issues_no_token() {
    failclosed_sso_risk().await.unwrap();
}

#[tokio::test]
async fn identity_model_flag_fault_refuses_jit_before_any_account_write() -> Result<(), Err> {
    use setjoin_identity::rp::Lookup;

    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDFED2-flag-fault").ok_or("assigned DB required")?;
    let app = setjoin_pg::ScopedExecutor::from_dsn(
        db.app.as_deref().ok_or("DB_APP_DSN required")?,
        2,
    )
    .map_err(|e| e.0)?;
    let worker = setjoin_pg::ScopedExecutor::from_dsn(&db.dsn, 2).map_err(|e| e.0)?;
    let env = flows::Env::start(false).await?;
    let mut account = None;
    let mut jit_identity = None;
    let result: Result<(), Err> = async {
        let a = account.insert(fixture::account(&env.c, "rp-flag-fault").await?);
        let email: String = env.c
            .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
            .await?
            .try_get(0)?;
        let (_, domain) = email.split_once('@').ok_or("fixture email has no domain")?;
        let subject = uuid::Uuid::new_v4().to_string();
        env.c.execute(
            "UPDATE users SET oidc_subject=$2,oidc_issuer=$3 WHERE id=$1",
            &[&a.user, &subject, &idp::ISSUER],
        ).await?;
        let (existing, provider) = assertion(&env, &subject, &email).await?;
        let Lookup::Existing(resolution) =
            existing.resolve(&app, &worker).await.map_err(|e| e.message)?
        else {
            return Err("control account did not resolve".into());
        };

        let jit_email = format!("jit@{domain}");
        let jit_subject = uuid::Uuid::new_v4().to_string();
        let (jit, _) = assertion(&env, &jit_subject, &jit_email).await?;
        jit_identity = Some((jit_email, jit_subject));
        env.c.execute(
            "UPDATE feature_toggles SET enabled=true WHERE key='feature.identity_model_v2'",
            &[],
        ).await?;
        // This legacy account has no normalized link, so re-reading the enabled flag would
        // send it into normalized reconciliation and refuse settlement.
        let after_toggle = existing.settle(&app, &worker, &*provider, &resolution, false).await;
        let guard = revoke::table(&db.dsn, &env.c, &app, "feature_toggles").await?;
        // Settlement of an admitted account uses the flag captured before the revoke.
        let settled = existing.settle(&app, &worker, &*provider, &resolution, false).await;
        let outcome: Result<(), Err> = match jit.resolve(&app, &worker).await {
            Err(e) if e.message == "normalized identity resolution unavailable" => Ok(()),
            Err(e) => Err(format!("unexpected resolution failure: {}", e.message).into()),
            Ok(Lookup::Missing(miss)) => {
                // Follow the callback's JIT path if resolution incorrectly allows it.
                if let Ok(created) = miss.create(&app, &worker).await {
                    let _ = jit.settle(&app, &worker, &*provider, &created, false).await;
                }
                Err("flag fault allowed legacy JIT resolution".into())
            }
            Ok(Lookup::Existing(_)) => Err("flag fault admitted an account".into()),
        };
        guard.restore(&env.c).await?;
        after_toggle.map_err(|e| e.message)?;
        let completion = settled.map_err(|e| e.message)?;
        if completion.user() != a.user {
            return Err("settlement changed the resolved account".into());
        }
        outcome
    }
    .await;

    let mut cleanup = Ok(());
    if let (Some(a), Some((email, subject))) = (&account, &jit_identity) {
        let jit_cleanup: Result<(), Err> = async {
            if let Some(row) = env.c.query_opt(
                "SELECT u.id,COALESCE(m.id,0) FROM users u LEFT JOIN mailboxes m ON m.user_id=u.id AND m.is_primary WHERE u.domain_id=$1 AND u.email=$2 AND u.oidc_subject=$3 AND u.oidc_issuer=$4",
                &[&a.domain, email, subject, &idp::ISSUER],
            ).await? {
                let mut created = a.clone();
                created.user = row.try_get(0)?;
                created.mailbox = row.try_get(1)?;
                created.domain = 0;
                fixture::remove(&env.c, &created).await?;
                return Err("flag fault created a JIT account".into());
            }
            Ok(())
        }.await;
        cleanup = settle(cleanup, jit_cleanup);
    }
    if let Some(a) = &account {
        cleanup = settle(cleanup, fixture::remove(&env.c, a).await);
    }
    cleanup = settle(cleanup, env.close().await);
    settle(result, cleanup)
}

#[tokio::test]
async fn failclosed_454_legacy_lookup_faults_refuse_jit() -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDFED2-legacy-lookup-fault").ok_or("assigned DB required")?;
    let app = setjoin_pg::ScopedExecutor::from_dsn(
        db.app.as_deref().ok_or("DB_APP_DSN required")?,
        2,
    )
    .map_err(|e| e.0)?;
    let env = flows::Env::configured(false, idp::ISSUER, json!({"jit_enabled":true})).await?;
    let mut account = None;
    let responses = async {
        let a = account.insert(fixture::account(&env.c, "rp-legacy-lookup-fault").await?);
        let email: String = env.c
            .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
            .await?
            .try_get(0)?;
        let linked = uuid::Uuid::new_v4().to_string();
        let unlinked = uuid::Uuid::new_v4().to_string();
        env.c.execute(
            "UPDATE users SET oidc_subject=$2,oidc_issuer=$3 WHERE id=$1",
            &[&a.user, &linked, &idp::ISSUER],
        ).await?;

        // Keep the address lookup readable. Otherwise its failure could hide a regression
        // in the exact-link lookup, which would fall through to address matching.
        let guard = revoke::revoke(
            &db.dsn,
            &env.c,
            &app,
            "users",
            "REVOKE SELECT ON users FROM setjoin_app; GRANT SELECT (id, enabled, email, ad_upn) ON users TO setjoin_app",
            "REVOKE SELECT (id, enabled, email, ad_upn) ON users FROM setjoin_app; GRANT SELECT ON users TO setjoin_app",
            "SELECT oidc_subject FROM users LIMIT 1",
        ).await?;
        let exact = sso_once(&env, &email, &linked).await;
        guard.restore(&env.c).await?;
        drop(guard);

        // The unlinked subject misses the exact lookup and reaches the address lookup.
        let address_control = sso_once(&env, &email, &unlinked).await?;
        let guard = revoke::table(&db.dsn, &env.c, &app, "aliases").await?;
        let address = sso_once(&env, &email, &unlinked).await;
        guard.restore(&env.c).await?;
        Ok::<_, Err>((exact?, address_control, address?))
    }
    .await;

    let mut cleanup = Ok(());
    if let Some(a) = &account {
        let jit_cleanup: Result<(), Err> = async {
            let rows = env.c.query(
                "SELECT u.id,COALESCE(m.id,0) FROM users u LEFT JOIN mailboxes m ON m.user_id=u.id AND m.is_primary WHERE u.domain_id=$1 AND u.id<>$2",
                &[&a.domain, &a.user],
            ).await?;
            let mut removed = Ok(());
            for row in &rows {
                let mut created = a.clone();
                created.user = row.try_get(0)?;
                created.mailbox = row.try_get(1)?;
                created.domain = 0;
                removed = settle(removed, fixture::remove(&env.c, &created).await);
            }
            if rows.is_empty() {
                Ok(())
            } else {
                settle(Err("legacy lookup fault created a JIT account".into()), removed)
            }
        }
        .await;
        cleanup = settle(cleanup, jit_cleanup);
        cleanup = settle(cleanup, fixture::remove(&env.c, a).await);
    }
    cleanup = settle(cleanup, env.close().await);

    let result = responses.and_then(|(exact, address_control, address)| {
        if address_control.0 != 409
            || !address_control.2.contains("explicit account linking is required")
        {
            return Err(format!("address control expected 409, got {}", address_control.0).into());
        }
        for (lookup, (status, headers, raw)) in [("exact-link", exact), ("address", address)] {
            if status != 503 || !raw.contains("normalized identity resolution unavailable") {
                return Err(
                    format!("{lookup} lookup fault expected resolution 503, got {status}").into(),
                );
            }
            let cookies = flows::cookies(&headers);
            if headers.get("location").is_some()
                || raw.contains("access_token")
                || raw.contains("refresh_token")
                || ["access_token", "refresh_token"]
                    .iter()
                    .any(|name| cookies.get(*name).is_some_and(|v| !v.is_empty()))
            {
                return Err(format!("{lookup} lookup fault published credentials or a redirect").into());
            }
        }
        Ok(())
    });
    settle(result, cleanup)
}
