//! Complete first-party token/session effect observations at the callback seam.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use setjoin_conformance::{fixture, golden};
use sha2::{Digest, Sha256};

pub async fn run(kind: &str) -> Result<(), Err> {
    run_variant(kind, false).await
}
pub async fn run_variant(kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = flows::Env::start(false).await?;
    cleanup_leftovers(&env.c).await?;
    let a = fixture::account(&env.c, "idfed2-actor").await?;
    let b = fixture::account(&env.c, "idfed2-foreign").await?;
    let mut created = None;
    let mut group = None;
    let mut department = None;
    let old_identity = env
        .c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.identity_model_v2'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    let old_mode = env
        .c
        .query_opt(
            "SELECT read_mode FROM identity_sources WHERE provider_key='oidc:idfed2'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, String>(0));
    let receipts = common::receipt_ids(&env.c).await;
    let result=async{
        let mut email:String=env.c.query_one("SELECT email FROM users WHERE id=$1",&[&a.user]).await?.get(0);
        env.c.execute("UPDATE users SET oidc_subject='actor-subject',oidc_issuer=$2 WHERE id=$1",&[&a.user,&idp::ISSUER]).await?;
        if kind=="jit-create"{env.c.execute("UPDATE users SET oidc_subject=NULL,oidc_issuer=NULL WHERE id=$1",&[&a.user]).await?;}
        if kind=="address-collision"{env.c.execute("UPDATE users SET oidc_subject=NULL,oidc_issuer=NULL WHERE id=$1",&[&a.user]).await?;}
        if kind=="disabled"{env.c.execute("UPDATE users SET enabled=false WHERE id=$1",&[&a.user]).await?;}
        if kind.starts_with("jit"){
            let domain=env.c.query_one("SELECT name FROM domains WHERE id=$1",&[&a.domain]).await?.get::<_,String>(0);
            email=format!("provisioned@{domain}");
            env.configure(json!({"jit_enabled":true})).await?;
        }
        if kind.starts_with("groups-"){
            let g:i64=env.c.query_one("INSERT INTO distribution_groups(mailbox_id) VALUES($1) RETURNING id",&[&b.mailbox]).await?.get(0);group=Some(g);
            let d:i64=env.c.query_one("INSERT INTO departments(name,path,ldap_ou) VALUES('IDFED2','idfed2/','OU=idfed2') RETURNING id",&[]).await?.get(0);department=Some(d);
            if matches!(kind,"groups-remove"|"groups-absent"){
                env.c.execute("INSERT INTO distribution_group_members(group_id,mailbox_id,source) VALUES($1,$2,'sso')",&[&g,&a.mailbox]).await?;
                env.c.execute("INSERT INTO sso_distribution_group_provenance(provider_key,group_id,mailbox_id) VALUES('oidc:idfed2',$1,$2)",&[&g,&a.mailbox]).await?;
            }
            env.configure(json!({"group_claim":if kind=="groups-absent"{"absent"}else{"groups"},"group_mappings":[{"idp_group":"engineering","distribution_group_id":g,"admin_role":"auditor","department_id":if kind=="groups-failure"{-1}else{d}}]})).await?;
        }
        if kind.starts_with("normalized"){
            env.c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.identity_model_v2',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await?;
            env.c.query_one("SELECT identity_auth_link($1,$1,'oidc',$2,'actor-subject','oidc:idfed2','IDFED2 fixture')",&[&a.user,&idp::ISSUER]).await?;
            env.c.execute("UPDATE identity_sources SET read_mode='normalized' WHERE provider_key='oidc:idfed2'",&[]).await?;
            if env.recording{
                let token=session_token(a.user,&email,"aal2").await?;
                let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(10);
                loop{
                    let r=request(env.gw.addr,"POST","/auth/oidc/link?provider=missing",String::new(),&[("authorization",&format!("Bearer {token}"))]).await?;
                    if r.0==400{break;}
                    if tokio::time::Instant::now()>deadline{return Err(format!("Go identity toggle did not rearm: {} {}",r.0,r.2).into());}
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }
            if kind=="normalized-stale"{
                env.c.batch_execute(&format!("CREATE FUNCTION gofree_idfed2_fence_change() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN UPDATE user_identity_links SET generation=generation+1 WHERE user_id=NEW.id;RETURN NEW;END;$$; CREATE TRIGGER gofree_idfed2_fence_change AFTER UPDATE OF email ON users FOR EACH ROW WHEN(NEW.id={}) EXECUTE FUNCTION gofree_idfed2_fence_change();",a.user)).await?;
            }
        }
        let mut before=effects(&env.c,a.user,b.user).await?;
        let map_before=if group.is_some(){mapping_effects(&env.c,a.user,a.mailbox,group.unwrap(),&email).await?}else{Value::Null};
        let identity_before=if kind.starts_with("normalized"){identity_effects(&env.c,a.user).await?}else{Value::Null};
        let response=request(env.gw.addr,"GET","/auth/oidc/login?provider=idfed2",String::new(),&[]).await?;
        let (_,flow)=flows::normalize_flow(response)?;
        let cookie=flow.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        let mut extra=json!({"email":email,"email_verified":true});
        if kind=="normalized-stale"{extra["email"]=json!(format!("renamed@{}",email.split_once('@').unwrap().1));}
        if kind=="groups-remove"{extra["groups"]=json!([]);}
        if kind=="groups-failure"{extra["email"]=json!(format!("updated@{}",email.split_once('@').unwrap().1));}
        if kind=="profile-invalid"{extra["email"]=json!("not-an-address");}
        if kind=="profile-conflict"{extra["email"]=json!(env.c.query_one("SELECT email FROM users WHERE id=$1",&[&b.user]).await?.get::<_,String>(0));}

        let code=env.idp.state.code(&flow["oidc_verifier"],&flow["oidc_nonce"],extra);
        env.idp.state.calls.lock().unwrap().clear();
        let path=setjoin_identity::oidc::query_response("/auth/oidc/callback",&[("state",&flow["oidc_state"]),("code",&code)],false);
        let foreign=b.user.to_string();
        let mut request_headers=vec![("cookie",cookie.as_str())];
        if kind=="cross-tenant"{request_headers.push(("x-user-id",&foreign));request_headers.push(("authorization","Bearer foreign"));}
        if kind=="repeat"{
            let first=request(env.gw.addr,"GET",&path,String::new(),&request_headers).await?;
            if first.0!=200{return Err(format!("repeat setup did not mint: {} {}",first.0,first.2).into());}
            before=effects(&env.c,a.user,b.user).await?;env.idp.state.calls.lock().unwrap().clear();
        }
        if mutant{env.mutation.store(true,std::sync::atomic::Ordering::SeqCst);}
        let response=request(env.gw.addr,"GET",&path,String::new(),&request_headers).await?;
        let mut actor=a.user;
        if kind.starts_with("jit")&&response.0==200{
            // The asserted address no longer rewrites a linked account (#547): `jit` signs the
            // existing actor in, so no row carries the asserted address.
            actor=env.c.query_opt("SELECT id FROM users WHERE email=$1",&[&email]).await?.map_or(a.user,|r|r.get(0));
            if kind=="jit-create"&&actor==a.user{return Err("JIT did not create a distinct principal".into());}
            let mailbox=env.c.query_one("SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary",&[&actor]).await?.get(0);
            let mut row=a.clone();row.user=actor;row.mailbox=mailbox;row.domain=0;if actor!=a.user{created=Some(row);}
        }
        let mut claims=Value::Null;
        let mut headers=response.1;let mut text=response.2;
        if response.0==200||mutant {
            let tokens:Value=serde_json::from_str(&text)?;
            let access=tokens["access_token"].as_str().ok_or("missing access")?;
            let refresh=tokens["refresh_token"].as_str().ok_or("missing refresh")?;
            let exec=setjoin_pg::ScopedExecutor::from_dsn(&std::env::var("DB_APP_DSN")?,4).unwrap();
            let keys=setjoin_authz::signing_keys::KeySet::load(&exec,fixture()["secret"].as_str().unwrap().as_bytes(),setjoin_config_secret::CryptoProfile::Standard).await?;
            let legacy=setjoin_authz::legacy_jwt::LegacyKeys::from_pem(fixture()["secret"].as_str().unwrap().as_bytes(),&["authserver-hmac-1"],None).map_err(|e|e.to_owned())?;
            let mut all=json!({});
            for(name,token)in [("access",access),("refresh",refresh)]{
                let verified=setjoin_identity::session::Session::verify(token,Some(&keys),&legacy,"mailserver").ok_or("first-party signature/profile failed")?;
                let header:Value=serde_json::from_slice(&B64.decode(token.split('.').next().unwrap())?)?;
                if header["alg"]!="ES256"||header["kid"]!=fixture()["kid"]||verified.user()!=actor||verified.text("typ")!=name{return Err("first-party principal/profile differs".into());}
                all[name]=Value::Object(verified.claims().clone());
            }
            if all["access"]["fam"]!=all["refresh"]["fam"]{return Err("family link differs".into());}
            let hash=Sha256::digest(refresh.as_bytes()).to_vec();
            let row=env.c.query_one("SELECT family_id::text FROM oauth_tokens WHERE user_id=$1 AND token_hash=$2 AND token_type='refresh'",&[&actor,&hash]).await?;
            if row.get::<_,String>(0)!=all["refresh"]["fam"].as_str().unwrap(){return Err("persisted anchor differs".into());}
            let hash=Sha256::digest(access.as_bytes()).to_vec();
            let row=env.c.query_one("SELECT id FROM sessions WHERE user_id=$1 AND token_hash=$2",&[&actor,&hash]).await?;
            if row.get::<_,String>(0)!=all["access"]["jti"].as_str().unwrap(){return Err("session/access binding differs".into());}
            for name in ["access","refresh"]{
                let v=&mut all[name];
                let now=v["iat"].as_i64().ok_or("missing iat")?;
                let exp=v["exp"].as_i64().ok_or("missing exp")?;
                if v["nbf"]!=now||exp-now!=if name=="access"{3600}else{2592000}{return Err("token lifetime differs".into());}
                v["uid"]=json!("_actor");v["sub"]=json!("_actor");v["email"]=json!("_email");v["iat"]=json!("_now");v["nbf"]=json!("_now");v["exp"]=json!(exp-now);v["fam"]=json!("_family");v["jti"]=json!(format!("_{name}_jti"));
            }
            claims=all;
            text=text.replace(access,"_access").replace(refresh,"_refresh");
            let h=serde_json::to_string(&headers)?.replace(access,"_access");headers=serde_json::from_str(&h)?;
        }
        let mut after=effects(&env.c,actor,b.user).await?;
        if kind.starts_with("groups-")&&after["actor"]["department"].is_number(){after["actor"]["department"]=json!("_department");}
        if kind.starts_with("jit"){after["provisioned"]=json!(actor!=a.user);}

        let mut actual=json!({"format":1,"go_source":SOURCE,"route":"GET /auth/oidc/callback","case":format!("callback-{kind}"),"observation":{"request":{"method":"GET","path":"/auth/oidc/callback","query":"code=_code&state=_state","cookie":"_bound-flow"},"response":{"status":response.0,"headers":headers,"body":text},"claims":claims,"effects":{"before":before,"after":after},"audit":[],"notify":[],"outbound":env.idp.state.calls.lock().unwrap().clone()}});
        if kind.starts_with("normalized"){actual["observation"]["identity"]=json!({"before":identity_before,"after":identity_effects(&env.c,a.user).await?});}
        if let Some(g)=group{actual["observation"]["mapping"]=json!({"before":map_before,"after":mapping_effects(&env.c,a.user,a.mailbox,g,&email).await?});}
        let path=corpus().join("goldens").join(format!("callback-{kind}.json"));
        if env.recording&&!path.exists(){golden::record(&path,&actual)?;}
        let expected=super::observation::expected_for(&path,&actual)?;
        if mutant{
            let error=golden::compare(&expected,&actual).expect_err("callback status mutant survived");
            if !error.contains("/observation/response/status"){return Err(error.into());}
            super::observation::compare(&actual,true)?;
            println!("MUTANT-REJECTED: GET /auth/oidc/callback :: status");return Ok(());
        }
        golden::compare(&expected,&actual)?;
        super::observation::replay(&actual,env.recording)?;
        if actual["observation"]["response"]["status"]!=match kind{"address-collision"|"profile-invalid"|"groups-failure"=>409,"disabled"|"repeat"=>401,_=>200}{return Err(format!("SSO did not succeed: {actual}").into());}
        println!("GOLDEN-REPLAY: GET /auth/oidc/callback :: callback-{kind}");Ok::<(),Err>(())
    }.await;
    env.c.batch_execute("DROP TRIGGER IF EXISTS gofree_idfed2_fence_change ON users;DROP FUNCTION IF EXISTS gofree_idfed2_fence_change()").await?;
    if kind.starts_with("normalized") {
        if let Some(mode) = &old_mode {
            env.c
                .execute(
                    "UPDATE identity_sources SET read_mode=$1 WHERE provider_key='oidc:idfed2'",
                    &[&mode],
                )
                .await?;
        }
        if let Some(old) = old_identity {
            env.c
                .execute(
                    "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.identity_model_v2'",
                    &[&old],
                )
                .await?;
        } else {
            env.c
                .execute(
                    "DELETE FROM feature_toggles WHERE key='feature.identity_model_v2'",
                    &[],
                )
                .await?;
        }
    }
    common::restore_receipts(&env.c, &receipts).await;
    if let Some(g) = group {
        env.c
            .execute("DELETE FROM distribution_groups WHERE id=$1", &[&g])
            .await?;
    }
    if let Some(row) = created {
        fixture::remove(&env.c, &row).await?;
    }
    cleanup_identity(&env.c, a.user).await?;
    fixture::remove(&env.c, &a).await?;
    fixture::remove(&env.c, &b).await?;
    if let Some(d) = department {
        env.c
            .execute("DELETE FROM departments WHERE id=$1", &[&d])
            .await?;
    }
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
async fn effects(c: &tokio_postgres::Client, a: i64, b: i64) -> Result<Value, Err> {
    let mut all = json!({});
    for (name, user) in [("actor", a), ("foreign", b)] {
        let row=c.query_one("SELECT jsonb_build_object('enabled',u.enabled,'subject',u.oidc_subject,'issuer',u.oidc_issuer,'department',u.department_id,'anchors',(SELECT count(*) FROM oauth_tokens WHERE user_id=u.id),'sessions',(SELECT count(*) FROM sessions WHERE user_id=u.id),'auth_events',(SELECT coalesce(jsonb_agg(jsonb_build_object('event',event,'provider',provider) ORDER BY id),'[]') FROM auth_event_log WHERE user_id=u.id),'signins',(SELECT coalesce(jsonb_agg(jsonb_build_object('success',success,'method',auth_method,'client',client,'protocol',protocol) ORDER BY id),'[]') FROM login_events WHERE user_id=u.id))::text FROM users u WHERE id=$1",&[&user]).await?;
        all[name] = serde_json::from_str::<Value>(&row.get::<_, String>(0))?;
    }
    Ok(all)
}

async fn mapping_effects(
    c: &tokio_postgres::Client,
    user: i64,
    mailbox: i64,
    group: i64,
    email: &str,
) -> Result<Value, Err> {
    let row=c.query_one("SELECT jsonb_build_object('membership',EXISTS(SELECT 1 FROM distribution_group_members WHERE mailbox_id=$2 AND group_id=$3),'provenance',EXISTS(SELECT 1 FROM sso_distribution_group_provenance WHERE mailbox_id=$2 AND group_id=$3 AND provider_key='oidc:idfed2'),'roles',(SELECT coalesce(jsonb_agg(role_group_id ORDER BY role_group_id),'[]') FROM admin_role_assignments WHERE user_id=$1),'role_provenance',(SELECT count(*) FROM sso_admin_role_provenance p JOIN admin_role_assignments a ON a.id=p.assignment_id WHERE a.user_id=$1 AND p.provider_key='oidc:idfed2'),'original_email',EXISTS(SELECT 1 FROM users WHERE id=$1 AND email=$4))::text",&[&user,&mailbox,&group,&email]).await?;
    Ok(serde_json::from_str(&row.get::<_, String>(0))?)
}

pub(super) async fn session_token(user: i64, email: &str, acr: &str) -> Result<String, Err> {
    let exec = setjoin_pg::ScopedExecutor::from_dsn(&std::env::var("DB_APP_DSN")?, 4).unwrap();
    let keys = setjoin_authz::signing_keys::KeySet::load(
        &exec,
        fixture()["secret"].as_str().unwrap().as_bytes(),
        setjoin_config_secret::CryptoProfile::Standard,
    )
    .await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    keys.sign(&json!({"uid":user,"email":email,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-60,"nbf":now-60,"exp":now+3600,"jti":"idfed2-session","fam":"idfed2-family","acr":acr,"amr":["pwd","otp"]}).to_string()).map_err(Into::into)
}
pub(super) async fn identity_effects(c: &tokio_postgres::Client, user: i64) -> Result<Value, Err> {
    let row=c.query_one("SELECT jsonb_build_object('links',(SELECT coalesce(jsonb_agg(jsonb_build_object('state',state,'generation',generation,'subject',external_subject) ORDER BY id),'[]') FROM user_identity_links WHERE user_id=$1),'events',(SELECT coalesce(jsonb_agg(action ORDER BY id),'[]') FROM identity_link_events WHERE user_id=$1),'grants',(SELECT count(*) FROM identity_entitlement_grants WHERE user_id=$1 AND revoked_at IS NULL))::text",&[&user]).await?;
    Ok(serde_json::from_str(&row.get::<_, String>(0))?)
}

pub(super) async fn cleanup_identity(c: &tokio_postgres::Client, user: i64) -> Result<(), Err> {
    c.batch_execute(
        "BEGIN;ALTER TABLE identity_link_events DISABLE TRIGGER identity_link_events_append_only",
    )
    .await?;
    for sql in [
        "DELETE FROM identity_auth_shadow_link_evidence WHERE user_id=$1",
        "DELETE FROM identity_shadow_divergences WHERE user_id=$1",
        "DELETE FROM identity_read_cohort WHERE user_id=$1",
        "DELETE FROM identity_entitlement_grants WHERE user_id=$1",
        "DELETE FROM identity_attribute_authority WHERE user_id=$1",
        "DELETE FROM user_lifecycle_authorities WHERE user_id=$1",
        "DELETE FROM identity_link_events WHERE user_id=$1",
        "DELETE FROM user_identity_links WHERE user_id=$1",
    ] {
        c.execute(sql, &[&user]).await?;
    }
    c.batch_execute(
        "ALTER TABLE identity_link_events ENABLE TRIGGER identity_link_events_append_only;COMMIT",
    )
    .await?;
    Ok(())
}
pub(super) async fn cleanup_leftovers(c: &tokio_postgres::Client) -> Result<(), Err> {
    let rows=c.query("SELECT u.id,u.domain_id,m.id FROM users u JOIN mailboxes m ON m.user_id=u.id AND m.is_primary WHERE u.username LIKE 'idfed2-actor@oracle-%' OR u.username LIKE 'idfed2-foreign@oracle-%'",&[]).await?;
    for r in rows {
        let user = r.get(0);
        cleanup_identity(c, user).await?;
        let a = fixture::Account {
            user,
            domain: r.get(1),
            mailbox: r.get(2),
            inbox: 0,
            label: 0,
            two_labels: 0,
            inbox_only: 0,
        };
        fixture::remove(c, &a).await?;
    }
    Ok(())
}
