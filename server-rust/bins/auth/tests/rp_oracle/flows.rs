use super::*;
use setjoin_conformance::golden;
pub(super) struct Env {
    pub c: tokio_postgres::Client,
    pub gw: Server,
    pub mutation: Arc<std::sync::atomic::AtomicBool>,
    listener: Option<setjoin_identity::rp::Listener>,
    auth: Server,
    pub idp: idp::Idp,
    old: Option<(String, bool)>,
    old_rate: Option<bool>,
    old_identity: Option<bool>,
    old_sentinel: Option<(String, bool)>,
    pub recording: bool,
}
const CONFIG: &str = "oidc_provider_idfed2_config";
impl Env {
    pub async fn start(mutant: bool) -> Result<Self, Err> {
        Self::issuer(mutant, idp::ISSUER).await
    }
    pub async fn issuer(mutant: bool, issuer: &str) -> Result<Self, Err> {
        Self::configured(mutant, issuer, json!({})).await
    }
    pub async fn configured(mutant: bool, issuer: &str, extra: Value) -> Result<Self, Err> {
        let db = Db::for_case("IDFED2-rp").expect("assigned DB required");
        let c = db.connect().await?;
        c.query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await?;
        common::signing_key(&c).await;
        let old_rate = c
            .query_opt(
                "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
                &[],
            )
            .await?
            .map(|r| r.get(0));
        c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
        let old_identity = c
            .query_opt(
                "SELECT enabled FROM feature_toggles WHERE key='feature.identity_model_v2'",
                &[],
            )
            .await?
            .map(|r| r.get::<_, bool>(0));
        c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.identity_model_v2',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
        let idp = idp::Idp::start().await?;
        let old = c
            .query_opt(
                "SELECT value::text,encrypted FROM system_config WHERE key=$1",
                &[&CONFIG],
            )
            .await?
            .map(|r| (r.get(0), r.get(1)));
        let mut doc = json!({"name":"idfed2","provider_url":issuer,"client_id":idp::CLIENT,"client_secret":"","redirect_url":idp::REDIRECT,"enabled":true,"jit_enabled":false,"group_claim":"groups","group_mappings":[]});
        if let Some(extra) = extra.as_object() {
            for (k, v) in extra {
                doc[k] = v.clone();
            }
        }
        let doc = doc.to_string();
        c.execute("INSERT INTO system_config(key,value,encrypted) VALUES($1,$2::text::jsonb,false) ON CONFLICT(key) DO UPDATE SET value=excluded.value,encrypted=false",&[&CONFIG,&doc]).await?;
        let sentinel_key = "oidc_provider_zz_idfed2_ready_config";
        let old_sentinel = c
            .query_opt(
                "SELECT value::text,encrypted FROM system_config WHERE key=$1",
                &[&sentinel_key],
            )
            .await?
            .map(|r| (r.get(0), r.get(1)));
        let sentinel_name = format!("idfed2-ready-{}", uuid::Uuid::new_v4());
        let mut sentinel: Value = serde_json::from_str(&doc)?;
        sentinel["name"] = json!(sentinel_name);
        sentinel["provider_url"] = json!(idp::ISSUER);
        c.execute("INSERT INTO system_config(key,value,encrypted) VALUES($1,$2::text::jsonb,false) ON CONFLICT(key) DO UPDATE SET value=excluded.value,encrypted=false",&[&sentinel_key,&sentinel.to_string()]).await?;
        let mut cfg = Config::for_secret(fixture()["secret"].as_str().unwrap().into());
        cfg.signing_alg = "ES256".into();
        cfg.dsn = db.dsn.clone();
        cfg.direct_dsn = db.dsn.clone();
        cfg.oidc_rp_enabled = true;
        let native = Arc::new(
            AuthServer::load_with_rp_http(
                setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
                    .unwrap(),
                cfg,
                idp::http()?,
            )
            .await?,
        );
        let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
        let recording = record.is_some();
        assert!(!mutant || !recording);
        let listener = if recording {
            None
        } else {
            native.start_rp_listener("oidc_rp", "oidc_rp").await?
        };
        let mutation = Arc::new(std::sync::atomic::AtomicBool::new(mutant));
        let auth = auth_server_armed(native, mutation.clone()).await;
        let gw = gateway_mode(auth.addr, record, true).await;
        if recording {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
            loop {
                let response = request(
                    gw.addr,
                    "GET",
                    &format!("/auth/oidc/login?provider={sentinel_name}"),
                    String::new(),
                    &[],
                )
                .await?;
                if response.0 == 302 {
                    break;
                }
                if tokio::time::Instant::now() > deadline {
                    return Err(
                        format!("Go provider never loaded: {} {}", response.0, response.2).into(),
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
        Ok(Self {
            c,
            gw,
            auth,
            idp,
            old,
            old_rate,
            old_identity,
            old_sentinel,
            recording,
            listener,
            mutation,
        })
    }
    pub async fn configure(&self, extra: Value) -> Result<(), Err> {
        self.c.execute("UPDATE system_config SET value=value||$1::text::jsonb WHERE key='oidc_provider_idfed2_config'",&[&extra.to_string()]).await?;
        let name = format!("idfed2-ready-{}", uuid::Uuid::new_v4());
        self.c.execute("UPDATE system_config SET value=jsonb_set(value,'{name}',to_jsonb($1::text)) WHERE key='oidc_provider_zz_idfed2_ready_config'",&[&name]).await?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if request(
                self.gw.addr,
                "GET",
                &format!("/auth/oidc/login?provider={name}"),
                String::new(),
                &[],
            )
            .await?
            .0 == 302
            {
                return Ok(());
            }
            if tokio::time::Instant::now() > deadline {
                return Err("provider reconfigure did not settle".into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
    pub async fn close(self) -> Result<(), Err> {
        let metrics = request(self.gw.addr, "GET", "/_gateway/metrics", String::new(), &[]).await?;
        drop(self.listener);
        self.gw.close().await;
        self.auth.close().await;
        self.idp.close().await;
        match self.old {
            Some((value, encrypted)) => {
                self.c
                    .execute(
                        "UPDATE system_config SET value=$2::text::jsonb,encrypted=$3 WHERE key=$1",
                        &[&CONFIG, &value, &encrypted],
                    )
                    .await?;
            }
            None => {
                self.c
                    .execute("DELETE FROM system_config WHERE key=$1", &[&CONFIG])
                    .await?;
            }
        }
        let sentinel_key = "oidc_provider_zz_idfed2_ready_config";
        match self.old_sentinel {
            Some((value, encrypted)) => {
                self.c
                    .execute(
                        "UPDATE system_config SET value=$2::text::jsonb,encrypted=$3 WHERE key=$1",
                        &[&sentinel_key, &value, &encrypted],
                    )
                    .await?;
            }
            None => {
                self.c
                    .execute("DELETE FROM system_config WHERE key=$1", &[&sentinel_key])
                    .await?;
            }
        }
        match self.old_identity {
            Some(old) => {
                self.c.execute("UPDATE feature_toggles SET enabled=$1 WHERE key='feature.identity_model_v2'",&[&old]).await?;
            }
            None => {
                self.c
                    .execute(
                        "DELETE FROM feature_toggles WHERE key='feature.identity_model_v2'",
                        &[],
                    )
                    .await?;
            }
        }
        if let Some(old) = self.old_rate {
            self.c
                .execute(
                    "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
                    &[&old],
                )
                .await?;
        } else {
            self.c
                .execute(
                    "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
                    &[],
                )
                .await?;
        }
        if !self.recording && !metrics.2.contains("setjoin_gateway_proxied_to_go_total 0") {
            return Err("native RP contacted Go".into());
        }
        super::observation::regeneration_guard();
        Ok(())
    }
}
pub(super) fn cookies(headers: &Value) -> std::collections::BTreeMap<String, String> {
    headers["set-cookie"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| {
            let (key, value) = v.as_str()?.split(';').next()?.split_once('=')?;
            Some((key.into(), value.into()))
        })
        .collect()
}
pub(super) fn normalize_flow(
    response: (u16, Value, String),
) -> Result<(Value, std::collections::BTreeMap<String, String>), Err> {
    use base64::{
        engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
        Engine,
    };
    use sha2::{Digest, Sha256};
    let mut headers = response.1;
    let values = cookies(&headers);
    if response.0 != 302 {
        return Ok((
            json!({"status":response.0,"headers":headers,"body":response.2}),
            values,
        ));
    }
    let location = headers["location"]
        .as_str()
        .ok_or("missing RP redirect")?
        .to_owned();
    let query =
        setjoin_identity::issuance::query(location.split_once('?').ok_or("missing IdP query")?.1);
    let get = |key: &str| values.get(key).ok_or("missing flow cookie");
    let state = get("oidc_state")?;
    let nonce = get("oidc_nonce")?;
    let verifier = get("oidc_verifier")?;
    if URL_SAFE.decode(state)?.len() != 16
        || URL_SAFE.decode(nonce)?.len() != 16
        || URL_SAFE_NO_PAD.decode(verifier)?.len() != 32
    {
        return Err("flow entropy shape differs from Go".into());
    }
    if query.get("state") != Some(state)
        || query.get("nonce") != Some(nonce)
        || query.get("code_challenge")
            != Some(&URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())))
    {
        return Err("cookie/redirect/PKCE binding failed".into());
    }
    let challenge = query["code_challenge"].clone();
    let mut text =
        serde_json::to_string(&json!({"status":response.0,"headers":headers,"body":response.2}))?;
    for (raw, placeholder) in [
        (state, "_state"),
        (nonce, "_nonce"),
        (verifier, "_verifier"),
        (&challenge, "_challenge"),
    ] {
        let encoded = setjoin_identity::oidc::query_response("", &[("x", raw)], false)
            .strip_prefix("?x=")
            .unwrap()
            .to_owned();
        text = text
            .replace(&encoded, placeholder)
            .replace(raw, placeholder);
    }
    headers = serde_json::from_str::<Value>(&text)?;
    Ok((headers, values))
}
pub(super) async fn login(kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = Env::start(mutant).await?;
    let result=async{
        let method=if kind=="head"{"HEAD"}else{"GET"};
        let query=if kind=="invalid-input"{"provider=missing"}else{"provider=idfed2"};
        let headers=if kind=="cross-tenant"{vec![("authorization","Bearer foreign"),("x-user-id","9999")]}else{vec![]};
        let response=request(env.gw.addr,method,&format!("/auth/oidc/login?{query}"),if kind=="invalid-input"{"{".into()}else{String::new()},&headers).await?;
        let (response,_)=normalize_flow(response)?;
        let actual=json!({"format":1,"go_source":SOURCE,"route":"GET /auth/oidc/login","case":format!("login-{kind}"),"observation":{"request":{"method":method,"path":"/auth/oidc/login","query":query},"response":response,"effects":[],"audit":[],"notify":[]}});
        let expected_status=if kind=="invalid-input"{400}else{302};
        if !mutant&&actual["observation"]["response"]["status"]!=expected_status{return Err(format!("login status: {}",actual["observation"]["response"]).into());}
        let path=corpus().join("goldens").join(format!("login-{kind}.json"));
        if env.recording&&!path.exists(){std::fs::create_dir_all(path.parent().unwrap())?;golden::record(&path,&actual)?;}
        // #548: the login flow cookies are Lax; the pinned divergence supplies the reviewed expectation.
        let expected:Value=if mutant{super::observation::pinned_for(&path)?}else{super::observation::expected_for(&path,&actual)?};
        if mutant{
            let error=golden::compare(&expected,&actual).expect_err("HTTP status mutant escaped");
            if !error.contains("/observation/response/status"){return Err(error.into());}
            println!("MUTANT-REJECTED: GET /auth/oidc/login :: status");
        }else{golden::compare(&expected,&actual)?;}
        if mutant{super::observation::compare(&actual,true)?;}else{super::observation::replay(&actual,env.recording)?;}
        println!("GOLDEN-REPLAY: GET /auth/oidc/login :: login-{kind}");Ok::<(),Err>(())
    }.await;
    env.close().await?;
    result
}

pub(super) async fn callback_guard(kind: &str) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = Env::start(false).await?;
    let result=async{
        env.idp.state.calls.lock().unwrap().clear();
        let query=if kind=="redirect-mismatch"{"state=foreign-flow&code=invalid&redirect_uri=https%3A%2F%2Fforeign.test%2Fcallback"}else{"state=foreign-flow&code=invalid"};
        let cookie=match kind{
            "missing-verifier"=>"oidc_state=foreign-flow",
            "bad-verifier"=>"oidc_state=foreign-flow; oidc_verifier=short",
            "missing-provider"=>"oidc_state=foreign-flow; oidc_verifier=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            "unknown-provider"=>"oidc_state=foreign-flow; oidc_verifier=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG; oidc_provider=missing",
            "redirect-mismatch"=>"oidc_state=foreign-flow; oidc_verifier=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG; oidc_provider=idfed2",
            _=>""};
        let headers=if cookie.is_empty(){vec![]}else{vec![("cookie",cookie)]};
        let response=request(env.gw.addr,"GET",&format!("/auth/oidc/callback?{query}"),String::new(),&headers).await?;
        let calls=env.idp.state.calls.lock().unwrap().clone();
        let mut actual=json!({"format":1,"go_source":SOURCE,"route":"GET /auth/oidc/callback","case":format!("callback-{kind}"),"observation":{"request":{"method":"GET","path":"/auth/oidc/callback","query":query},"response":{"status":response.0,"headers":response.1,"body":response.2},"effects":[],"audit":[],"notify":[],"outbound":calls}});
        if !cookie.is_empty(){actual["observation"]["request"]["cookie"]=json!(cookie);}
        if actual["observation"]["response"]["status"]!=400{return Err(format!("callback flow state status: {}",actual["observation"]["response"]).into());}
        let path=corpus().join("goldens").join(format!("callback-{kind}.json"));
        if env.recording&&!path.exists(){golden::record(&path,&actual)?;}
        let expected=super::observation::expected_for(&path,&actual)?;
        golden::compare(&expected,&actual)?;
        super::observation::replay(&actual,env.recording)?;
        println!("GOLDEN-REPLAY: GET /auth/oidc/callback :: callback-{kind}");Ok::<(),Err>(())
    }.await;
    env.close().await?;
    result
}

pub(super) async fn token_claims(kind: &str) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = Env::start(false).await?;
    let result=async{
        if kind=="client-secret"{
            use base64::Engine;
            let sealed=setjoin_config_secret::seal_column(b"rp secret+&/340",fixture()["secret"].as_str().unwrap().as_bytes(),setjoin_config_secret::CryptoProfile::Standard)?;
            env.configure(json!({"client_secret":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sealed)})).await?;
        }
        let response=request(env.gw.addr,"GET","/auth/oidc/login?provider=idfed2",String::new(),&[]).await?;
        let (_,flow)=normalize_flow(response)?;
        let mut sent=flow.clone();
        if kind=="pkce-mismatch"{sent.insert("oidc_verifier".into(),"b".repeat(43));}
        if kind=="missing-nonce-cookie"{sent.remove("oidc_nonce");}
        let cookie=sent.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        let mut extra=json!({"email_verified":false});
        let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        match kind{
            "no-email"=>{extra["email_verified"]=json!(true);extra["email"]=json!("");},
            "unknown-user"=>extra["email_verified"]=json!(true),
            "invalid-groups"=>{extra["email_verified"]=json!(true);extra["groups"]=json!([1]);},
            "bad-nonce"=>extra["nonce"]=json!("foreign-nonce"),
            "bad-signature"=>extra["_oracle_bad_signature"]=json!(true),
            "bad-issuer"=>extra["iss"]=json!("https://foreign.idfed2.test"),
            "bad-audience"=>extra["aud"]=json!("foreign-client"),
            "multi-audience-no-azp"=>extra["aud"]=json!([idp::CLIENT,"foreign-client"]),
            "multi-audience-azp"=>{extra["aud"]=json!([idp::CLIENT,"foreign-client"]);extra["azp"]=json!(idp::CLIENT);},
            "bad-azp"=>extra["azp"]=json!("foreign-client"),
            "expired"=>extra["exp"]=json!(1),
            "future-iat"=>{extra["iat"]=json!(now+3600);extra["exp"]=json!(now+7200);},
            "bad-at-hash"=>extra["at_hash"]=json!("incorrect"),
            "valid-at-hash"=>{use sha2::{Digest,Sha256};use base64::Engine;extra["at_hash"]=json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&Sha256::digest(b"upstream-access")[..16]));},
            _=>{},
        }
        let code=env.idp.state.code(&flow["oidc_verifier"],&flow["oidc_nonce"],extra);
        env.idp.state.calls.lock().unwrap().clear();
        let path=setjoin_identity::oidc::query_response("/auth/oidc/callback",&[("state",&flow["oidc_state"]),("code",&code)],false);
        let response=request(env.gw.addr,"GET",&path,String::new(),&[("cookie",&cookie)]).await?;
        let calls=env.idp.state.calls.lock().unwrap().clone();
        let actual=json!({"format":1,"go_source":SOURCE,"route":"GET /auth/oidc/callback","case":format!("callback-{kind}"),"observation":{"request":{"method":"GET","path":"/auth/oidc/callback","query":"code=_code&state=_state","cookie":"_bound-flow"},"response":{"status":response.0,"headers":response.1,"body":response.2},"effects":[],"audit":[],"notify":[],"outbound":calls}});
        let expected_status=if matches!(kind,"bad-nonce"|"missing-nonce-cookie"|"no-email"){400}else if matches!(kind,"unverified-email"|"multi-audience-azp"|"valid-at-hash"|"client-secret"){403}else{401};
        if actual["observation"]["response"]["status"]!=expected_status{return Err(format!("callback claims status: {}",actual["observation"]["response"]).into());}
        let path=corpus().join("goldens").join(format!("callback-{kind}.json"));
        if env.recording&&!path.exists(){golden::record(&path,&actual)?;}
        let expected=super::observation::expected_for(&path,&actual)?;
        golden::compare(&expected,&actual)?;
        super::observation::replay(&actual,env.recording)?;
        println!("GOLDEN-REPLAY: GET /auth/oidc/callback :: callback-{kind}");Ok::<(),Err>(())
    }.await;
    env.close().await?;
    result
}
