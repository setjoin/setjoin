use super::*;
use sha2::{Digest, Sha256};
pub async fn run(kind: &str) -> Result<(), Err> {
    variant(kind, false).await
}
pub async fn variant(kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = links::Env::variant(mutant).await?;
    let result=async{
        if kind=="inactive-session"{env.base.c.execute("DELETE FROM sessions WHERE user_id=$1",&[&env.a.user]).await?;}
        if kind=="repeat" {let r=request(env.base.gw.addr,"POST","/auth/saml/idfed3/link",String::new(),&[("cookie",&format!("access_token={}",env.token))]).await?;if r.0!=302{return Err("repeat link setup failed".into());}}
        let before=env.effects().await?;
        let path=if kind=="invalid-input"{"/auth/saml/missing/link"}else{"/auth/saml/idfed3/link"};
        let token=match kind{"aal1"=>flows::access(&env.base.c,env.a.user,"aal1","gofree-idfed3-session-a").await?,"stale"=>flows::access_age(&env.base.c,env.a.user,"aal2","gofree-idfed3-session-a",600).await?,_=>env.token.clone()};
        let mut cookie=format!("access_token={token}");if kind=="sp-session"{cookie.push_str(&format!("; token={}",flows::sp_session("https://auth.idfed3.test")?));}
        let bearer=format!("Bearer {}",if kind=="cross-session"{&env.other}else{&token});
        let mut headers=if matches!(kind,"no-session"|"bearer-only"){Vec::new()}else{vec![("cookie",cookie.as_str())]};
        if matches!(kind,"cross-session"|"bearer-only"){headers.push(("authorization",bearer.as_str()));}
        if kind=="csrf"{headers.push(("origin","https://foreign.idfed3.test"));headers.push(("sec-fetch-site","cross-site"));}
        let payload=if kind=="cross-tenant"{json!({"user_id":env.b.user}).to_string()}else{"{".into()};
        let response=request(env.base.gw.addr,"POST",path,payload,&headers).await?;
        if mutant && response.0!=599{return Err("link wire mutant did not reach native handler".into());}
        let (response,flow)=normalize(response,&env).await?;
        if env.base.recording && response["status"]!=match kind{"invalid-input"=>404,"no-session"=>401,"aal1"|"stale"|"bearer-only"|"csrf"=>403,"inactive-session"|"cross-session"=>503,_=>302}{return Err(format!("unexpected Go link result {response}").into());}
        let actual=json!({"format":1,"go_source":SOURCE,"route":"POST /auth/saml/{idp}/link","case":format!("link-{kind}"),"observation":{"request":{"method":"POST","path":path,"body":if kind=="cross-tenant"{"{\"user_id\":\"_foreign\"}"}else{"{"},"cookie":"_actor_access"},"response":response,"flow":flow,"effects":{"before":before,"after":env.effects().await?},"audit":[],"notify":[],"outbound":[]}});
        if mutant {
            let expected:Value=flows::expected_for(&corpus().join("goldens/link-success.json"),&actual)?;
            let error=setjoin_conformance::golden::compare(&expected,&actual).expect_err("link wire status mutant survived");if !error.contains("/observation/response/status"){return Err(error.into());}
            flows::qualified_compare(&actual,true)?;Ok(())
        }else{flows::check(&format!("link-{kind}"),&actual,env.base.recording)}
    }.await;
    env.close().await?;
    result
}
pub async fn normalize(
    response: (u16, Value, String),
    env: &links::Env,
) -> Result<(Value, Value), Err> {
    let cookies = response.1["set-cookie"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let tracked = cookies
        .iter()
        .find(|v| v.as_str().is_some_and(|s| s.starts_with("saml_")))
        .cloned();
    let flow = cookies.iter().filter_map(Value::as_str).find_map(|s| {
        s.strip_prefix("identity_link_flow=")
            .map(|s| s.split(';').next().unwrap())
    });
    let mut normalized = if let Some(tracked) = &tracked {
        let mut bare = response.clone();
        bare.1["set-cookie"] = json!([tracked]);
        flows::normalize(bare)?
    } else {
        json!({"status":response.0,"headers":response.1,"body":response.2})
    };
    let mut claims = Value::Null;
    if let Some(sealed) = flow {
        let plain = setjoin_identity::webauthn::CookieCipher::new(
            flows::fixture()["secret"].as_str().unwrap().as_bytes(),
        )
        .open(sealed)
        .ok_or("link flow cannot open")?;
        let mut value: Value = serde_json::from_slice(&plain)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let hash = format!("{:x}", Sha256::digest(env.token.as_bytes()));
        if value["userId"] != env.a.user
            || value["kind"] != "saml"
            || value["providerKey"] != "saml:34101"
            || value["sessionJti"] != "gofree-idfed3-session-a"
            || value["sessionHash"] != hash
            || value["expiresAt"]
                .as_i64()
                .is_none_or(|t| !(595..=600).contains(&(t - now)))
        {
            return Err("link authority binding differs".into());
        }
        let id = value["flowId"].as_str().ok_or("missing flow ID")?;
        uuid::Uuid::parse_str(id)?;
        let rows=env.base.c.query("SELECT user_id,session_jti,encode(session_hash,'hex'),kind,provider_key,extract(epoch FROM expires_at)::bigint,consumed_at IS NULL FROM identity_auth_link_elevations WHERE flow_id=$1::text::uuid",&[&id]).await?;
        if rows.len() != 1 {
            return Err("published link flow lacks committed elevation".into());
        }
        let row = &rows[0];
        if row.get::<_, i64>(0) != env.a.user
            || row.get::<_, String>(1) != "gofree-idfed3-session-a"
            || row.get::<_, String>(2) != hash
            || row.get::<_, String>(3) != "saml"
            || row.get::<_, String>(4) != "saml:34101"
            || Some(row.get::<_, i64>(5)) != value["expiresAt"].as_i64()
            || !row.get::<_, bool>(6)
        {
            return Err("committed link elevation differs from cookie".into());
        }
        value["userId"] = json!("_actor");
        value["flowId"] = json!("_flow");
        value["sessionHash"] = json!("_session_hash");
        value["expiresAt"] = json!(600);
        claims = value;
    }
    if !cookies.is_empty() {
        let normalized_tracking = normalized["headers"]["set-cookie"][0].clone();
        normalized["headers"]["set-cookie"] = Value::Array(
            cookies
                .iter()
                .map(|v| {
                    let raw = v.as_str().unwrap();
                    if let Some(sealed) = flow.filter(|_| raw.starts_with("identity_link_flow=")) {
                        json!(raw.replace(sealed, "_sealed_link_flow"))
                    } else if tracked.as_ref() == Some(v) {
                        normalized_tracking.clone()
                    } else {
                        v.clone()
                    }
                })
                .collect(),
        );
    }
    Ok((normalized, claims))
}
