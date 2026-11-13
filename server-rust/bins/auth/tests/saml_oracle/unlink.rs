use super::*;
use setjoin_conformance::{golden, harness::Db};
pub async fn run(kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let mut env = links::Env::variant(mutant).await?;
    let result=async {
        // Additional live first-party anchors and source grants make the owned
        // revocation and foreign preservation observable at the effect seam.
        for (user,link,label) in [(env.a.user,env.link,"actor"),(env.b.user,env.foreign_link,"foreign")] {
            env.base.c.execute("INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at) VALUES($1,digest($2,'sha256'),'refresh',now()+interval '1 hour')",&[&user,&format!("idfed3-{label}-refresh")]).await?;
            env.base.c.execute("INSERT INTO identity_entitlement_grants(user_id,target_kind,target_id,entitlement_kind,entitlement_id,provenance_kind,source_id,link_id,source_object) SELECT $1,'person',$1,'admin_role_group',8,'source',source_id,id,'IDFED3 source grant' FROM user_identity_links WHERE id=$2 AND user_id=$1",&[&user,&link]).await?;
        }
        let db=Db::for_case("IDFED3-unlink").unwrap();
        if kind=="repeat" {
            let r=request(env.base.gw.addr,"DELETE",&format!("/auth/identity-links/{}",env.link),"{\"reason\":\"IDFED3 unlink\"}".into(),&[("cookie",&format!("access_token={}",env.token))]).await?;
            if r.0!=200{return Err(format!("repeat unlink setup failed {} {}",r.0,r.2).into());}
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            env.token=flows::access_age(&env.base.c,env.a.user,"aal2","gofree-idfed3-retry",0).await?;
            use sha2::{Digest,Sha256};
            env.base.c.execute("INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES('gofree-idfed3-retry',$1,$2,now()+interval '1 hour','totp')",&[&env.a.user,&Sha256::digest(env.token.as_bytes()).to_vec()]).await?;
        }
        let mut revoke=db.listen("session_revoke").await?;let mut identity=db.listen("identity_link").await?;
        let before=env.effects().await?;
        let audit_before:i64=env.base.c.query_one("SELECT coalesce(max(id),0) FROM admin_audit_log WHERE action='revoke_user_sessions' AND target_type='user' AND target_id=ANY($1::bigint[])",&[&vec![env.a.user,env.b.user]]).await?.get(0);
        let id=if kind=="cross-tenant"{env.foreign_link.to_string()}else if kind=="invalid-input"{"not-an-id".into()}else{env.link.to_string()};
        let path=format!("/auth/identity-links/{id}");
        let token=if kind=="invalid-owner"{
            let exec=setjoin_pg::ScopedExecutor::from_dsn(&std::env::var("DB_APP_DSN")?,4).map_err(|e|e.0)?;
            let keys=setjoin_authz::signing_keys::KeySet::load(&exec,flows::fixture()["secret"].as_str().unwrap().as_bytes(),setjoin_config_secret::CryptoProfile::Standard).await?;
            let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            keys.sign(&json!({"uid":0,"email":"invalid-owner@idfed3.test","typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-60,"nbf":now-60,"exp":now+3600,"jti":"gofree-idfed3-invalid-owner","fam":"idfed3-family","acr":"aal2","amr":["pwd","otp"]}).to_string())?
        }else if kind=="aal1"{flows::access(&env.base.c,env.a.user,"aal1","gofree-idfed3-session-a").await?}else{env.token.clone()};
        let cookie=format!("access_token={token}");let mut headers=if kind=="no-session"{Vec::new()}else{vec![("cookie",cookie.as_str())]};
        if kind=="csrf"{headers.push(("origin","https://foreign.idfed3.test"));headers.push(("sec-fetch-site","cross-site"));}
        let payload=if kind=="malformed"{"{bad".into()}else if kind=="empty-reason"{"{\"reason\":\"\"}".into()}else if kind=="oversized"{format!("{{\"reason\":\"{}\"}}","x".repeat(17<<10))}else if kind=="trailing-large"{format!("{{\"ReAsOn\":\"IDFED3 unlink\"}}{}","x".repeat(20<<10))}else{"{\"reason\":\"IDFED3 unlink\"}".into()};
        let response=request(env.base.gw.addr,"DELETE",&path,payload.clone(),&headers).await?;
        if mutant && response.0!=599{return Err("unlink wire mutant missed native handler".into());}
        let after=env.effects().await?;
        let mut notifications=Vec::new();
        for (channel,values) in [("session_revoke",revoke.drain(&env.base.c).await?),("identity_link",identity.drain(&env.base.c).await?)] {
            for text in values {let mut payload:Value=serde_json::from_str(&text)?;normalize_dynamic(&mut payload,&env)?;notifications.push(json!({"channel":channel,"payload":payload}));}
        }
        let audit=audit(&env,audit_before).await?;
        let mut response_body=response.2;
        if response.0==200||mutant {
            if let Ok(value)=serde_json::from_str::<Value>(&response_body) {
                if let Some(event)=value["evictionEventId"].as_str(){uuid::Uuid::parse_str(event)?;response_body=response_body.replace(event,"_eviction_event");}
            }
        }
        if let Ok(value)=serde_json::from_str::<Value>(&response_body) {
            if value["instance"]==path {response_body=response_body.replace(&format!("\"instance\":\"{path}\""),&format!("\"instance\":\"/auth/identity-links/{}\"",if kind=="cross-tenant"{"_foreign_link"}else{"_actor_link"}));}
        }
        response_body=response_body.replace(&format!("\"linkId\": \"{}\"",env.link),"\"linkId\": \"_actor_link\"").replace(&format!("\"linkId\": \"{}\"",env.foreign_link),"\"linkId\": \"_foreign_link\"");
        let status=match kind{"cross-tenant"|"invalid-owner"=>409,"invalid-input"|"malformed"|"empty-reason"|"oversized"=>400,"no-session"=>401,"aal1"|"csrf"=>403,_=>200};
        if env.base.recording&&response.0!=status{return Err(format!("unexpected Go unlink status {} {}",response.0,response_body).into());}
        let actual=json!({"format":1,"go_source":SOURCE,"route":"DELETE /auth/identity-links/{id}","case":format!("unlink-{kind}"),"observation":{"request":{"method":"DELETE","path":if kind=="invalid-input"{"/auth/identity-links/not-an-id"}else if kind=="cross-tenant"{"/auth/identity-links/_foreign_link"}else{"/auth/identity-links/_actor_link"},"body":payload},"response":{"status":response.0,"headers":response.1,"body":response_body},"effects":{"before":before,"after":after},"audit":audit,"notify":notifications,"outbound":[]}});
        if mutant {
            let expected:Value=flows::expected_for(&corpus().join("goldens/unlink-success.json"),&actual)?;
            let error=golden::compare(&expected,&actual).expect_err("unlink wire status mutant survived");if !error.contains("/observation/response/status"){return Err(error.into());}
            flows::qualified_compare(&actual,true)?;Ok(())
        }else{flows::check(&format!("unlink-{kind}"),&actual,env.base.recording)}
    }.await;
    env.close().await?;
    result
}
pub fn normalize_dynamic(value: &mut Value, env: &links::Env) -> Result<(), Err> {
    match value {
        Value::Array(values) => {
            for value in values {
                normalize_dynamic(value, env)?;
            }
        }
        Value::Object(map) => {
            if map.contains_key("not_before") && map.contains_key("expires_at") {
                let a = chrono::DateTime::parse_from_rfc3339(
                    map["not_before"]
                        .as_str()
                        .ok_or("revocation time missing")?,
                )?;
                let b = chrono::DateTime::parse_from_rfc3339(
                    map["expires_at"]
                        .as_str()
                        .ok_or("revocation expiry missing")?,
                )?;
                if (b - a).num_seconds() != 31 * 86400 {
                    return Err("revocation retention differs".into());
                }
            }
            for key in ["user_id", "userId", "target_id", "created_by"] {
                if let Some(v) = map.get_mut(key) {
                    if *v == env.a.user || v.as_str() == Some(&env.a.user.to_string()) {
                        *v = json!("_actor");
                    } else if *v == env.b.user || v.as_str() == Some(&env.b.user.to_string()) {
                        *v = json!("_foreign");
                    }
                }
            }
            if let Some(id) = map.get_mut("id").filter(|v| v.is_number()) {
                *id = json!("_id");
            }
            for key in ["occurred_at", "created_at", "not_before", "expires_at"] {
                if let Some(v) = map.get_mut(key).filter(|v| !v.is_null()) {
                    chrono::DateTime::parse_from_rfc3339(
                        v.as_str().ok_or("invalid recorded timestamp")?,
                    )?;
                    *v = json!("_timestamp");
                }
            }
            for value in map.values_mut() {
                if value.as_str() != Some("_timestamp") {
                    normalize_dynamic(value, env)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}
async fn audit(env: &links::Env, before: i64) -> Result<Value, Err> {
    let ids = vec![env.a.user, env.b.user];
    let valid:bool=env.base.c.query_one("SELECT coalesce(bool_and(valid),true) FROM verify_audit_chain((SELECT min(id) FROM admin_audit_log WHERE action='revoke_user_sessions' AND target_type='user' AND target_id=ANY($1::bigint[]) AND id>$2),(SELECT max(id) FROM admin_audit_log WHERE action='revoke_user_sessions' AND target_type='user' AND target_id=ANY($1::bigint[]) AND id>$2))",&[&ids,&before]).await?.get(0);
    if !valid {
        return Err("invalid committed audit chain".into());
    }
    let raw:String=env.base.c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)-'checksum' ORDER BY id),'[]')::text FROM admin_audit_log t WHERE action='revoke_user_sessions' AND target_type='user' AND target_id=ANY($1::bigint[]) AND id>$2",&[&ids,&before]).await?.get(0);
    let mut rows: Value = serde_json::from_str(&raw)?;
    normalize_dynamic(&mut rows, env)?;
    Ok(rows)
}
