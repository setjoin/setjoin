//! Authenticated explicit linking, including the one-use live-session elevation.
use super::*;
use setjoin_conformance::{fixture, golden};
use sha2::{Digest, Sha256};
pub(super) struct Env {
    pub base: flows::Env,
    pub a: fixture::Account,
    pub b: fixture::Account,
    pub token: String,
    old: Option<bool>,
    receipts: Vec<String>,
}
impl Env {
    pub(super) async fn start() -> Result<Self, Err> {
        let base = flows::Env::start(false).await?;
        settlement::cleanup_leftovers(&base.c).await?;
        base.c
            .execute("DELETE FROM sessions WHERE id='idfed2-session'", &[])
            .await?;
        let a = fixture::account(&base.c, "idfed2-actor").await?;
        let b = fixture::account(&base.c, "idfed2-foreign").await?;
        let old = base
            .c
            .query_opt(
                "SELECT enabled FROM feature_toggles WHERE key='feature.identity_model_v2'",
                &[],
            )
            .await?
            .map(|r| r.get(0));
        base.c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.identity_model_v2',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await?;
        let email: String = base
            .c
            .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
            .await?
            .get(0);
        let token = settlement::session_token(a.user, &email, "aal2").await?;
        let hash = Sha256::digest(token.as_bytes()).to_vec();
        base.c.execute("INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES('idfed2-session',$1,$2,now()+interval '1 hour','totp')",&[&a.user,&hash]).await?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let r = request(
                base.gw.addr,
                "POST",
                "/auth/oidc/link?provider=missing",
                String::new(),
                &[("cookie", &format!("access_token={token}"))],
            )
            .await?;
            if !base.recording || r.0 == 400 {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                return Err(format!("identity toggle stale {} {}", r.0, r.2).into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let receipts = common::receipt_ids(&base.c).await;
        Ok(Self {
            base,
            a,
            b,
            token,
            old,
            receipts,
        })
    }
    pub(super) async fn close(self) -> Result<(), Err> {
        self.base
            .c
            .execute("DELETE FROM sessions WHERE id='idfed2-session'", &[])
            .await?;
        common::restore_receipts(&self.base.c, &self.receipts).await;
        match self.old {
            Some(old) => {
                self.base.c.execute("UPDATE feature_toggles SET enabled=$1 WHERE key='feature.identity_model_v2'",&[&old]).await?;
            }
            None => {
                self.base
                    .c
                    .execute(
                        "DELETE FROM feature_toggles WHERE key='feature.identity_model_v2'",
                        &[],
                    )
                    .await?;
            }
        }
        settlement::cleanup_identity(&self.base.c, self.a.user).await?;
        settlement::cleanup_identity(&self.base.c, self.b.user).await?;
        fixture::remove(&self.base.c, &self.a).await?;
        fixture::remove(&self.base.c, &self.b).await?;
        self.base.close().await
    }
    pub(super) async fn effects(&self) -> Result<Value, Err> {
        let row=self.base.c.query_one("SELECT jsonb_build_object('actor_elevations',(SELECT coalesce(jsonb_agg(consumed_at IS NOT NULL ORDER BY created_at),'[]') FROM identity_auth_link_elevations WHERE user_id=$1),'foreign_elevations',(SELECT count(*) FROM identity_auth_link_elevations WHERE user_id=$2),'actor_sessions',(SELECT count(*) FROM sessions WHERE user_id=$1),'actor_anchors',(SELECT count(*) FROM oauth_tokens WHERE user_id=$1),'foreign_anchors',(SELECT count(*) FROM oauth_tokens WHERE user_id=$2))::text",&[&self.a.user,&self.b.user]).await?;
        Ok(
            json!({"store":serde_json::from_str::<Value>(&row.get::<_,String>(0))?,"actor_identity":settlement::identity_effects(&self.base.c,self.a.user).await?,"foreign_identity":settlement::identity_effects(&self.base.c,self.b.user).await?}),
        )
    }
}
pub async fn begin(kind: &str) -> Result<(), Err> {
    begin_variant(kind, false).await
}
pub async fn begin_variant(kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = Env::start().await?;
    let result=async{
        if kind=="repeat"{let first=request(env.base.gw.addr,"POST","/auth/oidc/link?provider=idfed2",String::new(),&[("cookie",&format!("access_token={}",env.token))]).await?;if first.0!=302{return Err("repeat link setup failed".into());}}
        let before=env.effects().await?;
        let query=if kind=="invalid-input"{"provider=missing"}else{"provider=idfed2"};
        let cookie=format!("access_token={}",env.token);
        let headers=if kind=="no-session"{vec![]}else{vec![("cookie",cookie.as_str())]};
        let payload=if kind=="cross-tenant"{json!({"user_id":env.b.user}).to_string()}else{"{".into()};
        if mutant{env.base.mutation.store(true,std::sync::atomic::Ordering::SeqCst);}
        let response=request(env.base.gw.addr,"POST",&format!("/auth/oidc/link?{query}"),payload,&headers).await?;
        let (mut response,cookies)=flows::normalize_flow(response)?;
        let mut claim=Value::Null;
        if let Some(sealed)=cookies.get("identity_link_flow"){
            claim=link_claims(sealed,&env)?;
            response=serde_json::from_str(&serde_json::to_string(&response)?.replace(sealed,"_sealed_link_flow"))?;
        }
        let actual=json!({"format":1,"go_source":SOURCE,"route":"POST /auth/oidc/link","case":format!("link-{kind}"),"observation":{"request":{"method":"POST","path":"/auth/oidc/link","query":query,"cookie":if kind=="no-session"{""}else{"_access"},"body":if kind=="cross-tenant"{"{\"user_id\":\"_foreign\"}"}else{"{"}},"response":response,"flow":claim,"effects":{"before":before,"after":env.effects().await?},"audit":[],"notify":[]}});
        if mutant{
            let expected:Value=serde_json::from_slice(&std::fs::read(corpus().join("goldens/link-success.json"))?)?;
            let error=golden::compare(&expected,&actual).expect_err("link status mutant survived");
            if !error.contains("/observation/response/status"){return Err(error.into());}
            super::observation::compare(&actual,true)?;
            println!("MUTANT-REJECTED: POST /auth/oidc/link :: status");return Ok(());
        }
        observe(&env,&format!("link-{kind}"),&actual)?;
        let expected=match kind{"invalid-input"=>400,"no-session"=>401,_=>302};
        if actual["observation"]["response"]["status"]!=expected{return Err(format!("link begin wrong status {actual}").into());}
        println!("GOLDEN-REPLAY: POST /auth/oidc/link :: link-{kind}");Ok::<(),Err>(())
    }.await;
    env.close().await?;
    result
}
fn link_claims(sealed: &str, env: &Env) -> Result<Value, Err> {
    let plain = setjoin_identity::webauthn::CookieCipher::new(
        fixture()["secret"].as_str().unwrap().as_bytes(),
    )
    .open(sealed)
    .ok_or("link cookie cannot open")?;
    let mut v: Value = serde_json::from_slice(&plain)?;
    let hash = format!("{:x}", Sha256::digest(env.token.as_bytes()));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    if v["userId"] != env.a.user
        || v["kind"] != "oidc"
        || v["providerKey"] != "oidc:idfed2"
        || v["sessionJti"] != "idfed2-session"
        || v["sessionHash"] != hash
        || v["expiresAt"]
            .as_i64()
            .is_none_or(|t| !(595..=600).contains(&(t - now)))
        || uuid::Uuid::parse_str(v["flowId"].as_str().ok_or("flow id missing")?).is_err()
    {
        return Err("link cookie authority differs".into());
    }
    v["userId"] = json!("_actor");
    v["flowId"] = json!("_flow");
    v["sessionHash"] = json!("_session_hash");
    v["expiresAt"] = json!(600);
    Ok(v)
}
fn observe(env: &Env, name: &str, actual: &Value) -> Result<(), Err> {
    let path = corpus().join("goldens").join(format!("{name}.json"));
    if env.base.recording && !path.exists() {
        golden::record(&path, actual)?;
    }
    // A baseline pinned in divergences.json (owner-approved security fix, #547) compares with
    // its reviewed expectation.
    let expected = super::observation::expected_for(&path, actual)?;
    golden::compare(&expected, actual)?;
    super::observation::replay(actual, env.base.recording)?;
    Ok(())
}
pub async fn callback(kind: &str) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = Env::start().await?;
    let result=async{
        let access=format!("access_token={}",env.token);
        let response=request(env.base.gw.addr,"POST","/auth/oidc/link?provider=idfed2",String::new(),&[("cookie",&access)]).await?;
        let (_,mut flow)=flows::normalize_flow(response)?;
        if !flow.contains_key("identity_link_flow"){return Err("link flow did not start".into());}
        if kind=="foreign-subject"{env.base.c.query_one("SELECT identity_auth_link($1,$1,'oidc',$2,'linked-subject','oidc:idfed2','IDFED2 foreign fixture')",&[&env.b.user,&idp::ISSUER]).await?;}
        if kind=="revoked-elevation"{env.base.c.execute("INSERT INTO session_revocations(user_id,scope,jti,reason,not_before,expires_at) VALUES($1,'jti','idfed2-session','IDFED2 fixture',now(),now()+interval '1 hour')",&[&env.a.user]).await?;}
        if kind=="mapping-failure"{env.base.configure(json!({"group_mappings":[{"idp_group":"engineering","department_id":-1}]})).await?;}
        if kind=="bad-flow"{flow.insert("identity_link_flow".into(),"invalid".into());}
        if kind=="inactive-session"{env.base.c.execute("DELETE FROM sessions WHERE id='idfed2-session'",&[]).await?;}
        if kind!="no-session"{
            let token=if kind=="cross-session"{
                let email:String=env.base.c.query_one("SELECT email FROM users WHERE id=$1",&[&env.b.user]).await?.get(0);
                settlement::session_token(env.b.user,&email,"aal2").await?
            }else{env.token.clone()};flow.insert("access_token".into(),token);
        }
        let cookie=flow.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        let mut code=env.base.idp.state.code(&flow["oidc_verifier"],&flow["oidc_nonce"],json!({"sub":"linked-subject","email_verified":true}));
        if kind=="replay"{
            let path=setjoin_identity::oidc::query_response("/auth/oidc/callback",&[("state",&flow["oidc_state"]),("code",&code)],false);
            let first=request(env.base.gw.addr,"GET",&path,String::new(),&[("cookie",&cookie)]).await?;
            if first.0!=303{return Err("replay setup did not link".into());}
            code=env.base.idp.state.code(&flow["oidc_verifier"],&flow["oidc_nonce"],json!({"sub":"linked-subject","email_verified":true}));
        }
        let before=env.effects().await?;
        let db=Db::for_case("IDFED2-link-notify").unwrap();let mut listener=db.listen("identity_link").await?;
        env.base.idp.state.calls.lock().unwrap().clear();
        let path=setjoin_identity::oidc::query_response("/auth/oidc/callback",&[("state",&flow["oidc_state"]),("code",&code)],false);
        let mut response=request(env.base.gw.addr,"GET",&path,String::new(),&[("cookie",&cookie)]).await?;
        // A held link completion carries a random one-time token (#547); normalize it.
        if let Some(at)=response.2.find("token=") {
            let end=|from:usize|response.2[from..].find(|c:char|!(c.is_ascii_alphanumeric()||c=='-'||c=='_')).map_or(response.2.len(),|n|from+n);
            let tokens:Vec<String>=response.2.match_indices("token=").map(|(i,_)|response.2[i+6..end(i+6)].to_owned()).collect();
            let _=at;
            for token in tokens {response.2=response.2.replace(&token,"_token");}
        }
        let mut notify=Vec::new();
        for raw in listener.drain(&env.base.c).await?{
            let mut value:Value=serde_json::from_str(&raw)?;
            if value["userId"]!=env.a.user.to_string(){return Err("foreign link notification".into());}
            value["userId"]=json!("_actor");notify.push(json!({"channel":"identity_link","payload":value}));
        }
        let actual=json!({"format":1,"go_source":SOURCE,"route":"GET /auth/oidc/callback","case":format!("callback-link-{kind}"),"observation":{"request":{"method":"GET","path":"/auth/oidc/callback","query":"code=_code&state=_state","cookie":"_bound-link-flow"},"response":{"status":response.0,"headers":response.1,"body":response.2},"effects":{"before":before,"after":env.effects().await?},"audit":[],"notify":notify,"outbound":env.base.idp.state.calls.lock().unwrap().clone()}});
        observe(&env,&format!("callback-link-{kind}"),&actual)?;
        let expected=match kind{"bad-flow"=>400,"no-session"=>200,"inactive-session"=>401,"cross-session"=>403,"mapping-failure"|"replay"|"revoked-elevation"|"foreign-subject"=>409,_=>303};
        if response.0!=expected{return Err(format!("link callback wrong status {actual}").into());}
        println!("GOLDEN-REPLAY: GET /auth/oidc/callback :: callback-link-{kind}");Ok::<(),Err>(())
    }.await;
    env.close().await?;
    result
}
