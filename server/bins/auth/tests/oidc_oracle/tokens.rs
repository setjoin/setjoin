//! OP token wire, signature and durable credential bindings.
use super::grants::{check_code, code_hash, parse_time, session, Env, CLIENT, OTHER};
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use sha2::{Digest, Sha256};
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
pub(super) async fn code(env: &Env) -> Result<(String, String), Err> {
    code_method(env, "S256").await
}
pub(super) async fn code_method(env: &Env, method: &str) -> Result<(String, String), Err> {
    let id = super::grants::pending_method(env, method).await?;
    let auth = session(env, false).await?;
    let r = super::grants::complete_flow(env, &id, &auth).await?;
    if r.0 != 302 {
        return Err(format!("token setup completion failed: {} {}", r.0, r.2).into());
    }
    let r = request(
        env.gw.addr,
        "GET",
        &format!("/authorize/callback?id={id}"),
        String::new(),
        &[("authorization", &auth)],
    )
    .await?;
    let fields = setjoin_identity::issuance::query(
        r.1["location"]
            .as_str()
            .and_then(|s| s.split_once('?'))
            .ok_or("token setup has no code Location")?
            .1,
    );
    let code = fields.get("code").ok_or("token setup has no code")?.clone();
    check_code(&code, &id)?;
    Ok((id, code))
}
fn jwt(token: &str) -> Result<(Value, Value), Err> {
    let fixed: Value = serde_json::from_str(&std::fs::read_to_string(
        corpus().join("goldens/keys-success.json"),
    )?)?;
    let key: Value =
        serde_json::from_str(fixed["observation"]["response"]["body"].as_str().unwrap())?;
    let key = &key["keys"][0];
    let p: Vec<_> = token.split('.').collect();
    if p.len() != 3 {
        return Err("not a signed OP JWT".into());
    }
    let header: Value = serde_json::from_slice(&B64.decode(p[0])?)?;
    if header["alg"] != "RS256" || header["kid"] != key["kid"] || header["typ"] != "JWT" {
        return Err("OP JWT signing profile".into());
    }
    ring::signature::RsaPublicKeyComponents {
        n: B64.decode(key["n"].as_str().unwrap())?,
        e: B64.decode(key["e"].as_str().unwrap())?,
    }
    .verify(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        format!("{}.{}", p[0], p[1]).as_bytes(),
        &B64.decode(p[2])?,
    )
    .map_err(|_| "OP JWT signature differs from Go's immutable public key")?;
    Ok((header, serde_json::from_slice(&B64.decode(p[1])?)?))
}
pub(super) struct Issued {
    pub(super) access: String,
    pub(super) id: String,
    pub(super) refresh: String,
    pub(super) jti: String,
    proof: Value,
    index: usize,
}
impl Issued {
    async fn parse(
        env: &Env,
        raw: &str,
        code: &str,
        start: i64,
        end: i64,
        index: usize,
    ) -> Result<Self, Err> {
        let wire: Value = serde_json::from_str(raw)?;
        let access = wire["access_token"]
            .as_str()
            .ok_or("missing access token")?
            .to_owned();
        let id = wire["id_token"]
            .as_str()
            .ok_or("missing ID token")?
            .to_owned();
        let refresh = wire["refresh_token"].as_str().unwrap_or("").to_owned();
        let (ah, mut ac) = jwt(&access)?;
        let (ih, mut ic) = jwt(&id)?;
        let uid = env.a.user.to_string();
        let email: String = env
            .c
            .query_one("SELECT email FROM users WHERE id=$1", &[&env.a.user])
            .await?
            .get(0);
        for c in [&mut ac, &mut ic] {
            if c["iss"] != "https://auth.idfed1.test"
                || c["sub"] != uid
                || c["client_id"] != CLIENT
                || c["aud"] != json!([CLIENT])
            {
                return Err(format!("OP principal/issuer/audience: {c}").into());
            }
            let exp = c["exp"].as_i64().ok_or("missing OP expiry")?;
            let iat = c["iat"].as_i64().ok_or("missing OP iat")?;
            if !(start + 299..=end + 301).contains(&exp) || !(start - 1..=end + 1).contains(&iat) {
                return Err("OP five-minute lifetime outside the request clock window".into());
            }
            c["exp"] = json!("_mint+300s");
            c["iat"] = json!("_mint");
            if let Some(nbf) = c.get("nbf") {
                if nbf.as_i64() != Some(iat) {
                    return Err("OP nbf differs from issuance".into());
                }
                c["nbf"] = json!("_mint");
            }
            c["sub"] = json!("_actor");
            if c["email"] == email {
                c["email"] = json!("_actor-email");
            }
        }
        let jti = ac["jti"].as_str().ok_or("access has no jti")?.to_owned();
        if jti.len() != 32 || !jti.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("OP access ID is not Go hex16".into());
        }
        ac["jti"] = json!(format!("_access{index}"));
        if ic["at_hash"] != B64.encode(&Sha256::digest(access.as_bytes())[..16]) {
            return Err("ID token does not bind access artifact".into());
        }
        ic["at_hash"] = json!(format!("_access{index}-hash"));
        if code.is_empty() {
            if ic.get("c_hash").is_some() {
                return Err("refresh ID token has an unexpected code hash".into());
            }
        } else {
            if ic["c_hash"] != B64.encode(&Sha256::digest(code.as_bytes())[..16]) {
                return Err("ID token does not bind code artifact".into());
            }
            ic["c_hash"] = json!("_code1-hash");
        }
        let row=env.c.query_one("SELECT user_id,subject,refresh_token_hash FROM oidc_tokens WHERE id=$1 AND client_id=$2 AND user_id=$3",&[&jti,&CLIENT,&env.a.user]).await?;
        if row.get::<_, i64>(0) != env.a.user || row.get::<_, String>(1) != uid {
            return Err("OP anchor owner differs from the signed subject".into());
        }
        let (_, raw_claims) = jwt(&access)?;
        let expiry: std::time::SystemTime = env
            .c
            .query_one(
                "SELECT expires_at FROM oidc_tokens WHERE id=$1 AND user_id=$2",
                &[&jti, &env.a.user],
            )
            .await?
            .get(0);
        if expiry.duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64
            != raw_claims["exp"].as_i64().unwrap()
        {
            return Err("OP JWT expiry differs from durable anchor".into());
        }
        if refresh.is_empty() {
            if row.get::<_, Option<String>>(2).is_some() {
                return Err("unexpected durable refresh secret".into());
            }
        } else if refresh.len() != 64
            || !refresh.bytes().all(|b| b.is_ascii_hexdigit())
            || row.get::<_, Option<String>>(2)
                != Some(format!("{:x}", Sha256::digest(refresh.as_bytes())))
        {
            return Err("OP refresh secret/hash format or binding".into());
        }
        let validity = wire["expires_in"].as_i64().ok_or("no token validity")?;
        let remaining = raw_claims["exp"].as_i64().unwrap() - end;
        if !(remaining - 1..=remaining + 2).contains(&validity) || validity > 300 {
            return Err("wire validity differs from signed expiry".into());
        }
        Ok(Self {
            access,
            id,
            refresh,
            jti,
            index,
            proof: json!({"access":{"header":ah,"claims":ac},"id":{"header":ih,"claims":ic}}),
        })
    }
    fn body(&self, raw: &str) -> String {
        let mut wire = raw
            .replace(&self.access, &format!("_access{}", self.index))
            .replace(&self.id, &format!("_id{}", self.index));
        if !self.refresh.is_empty() {
            wire = wire.replace(&self.refresh, &format!("_refresh{}", self.index));
        }
        if let Ok(v) = serde_json::from_str::<Value>(raw) {
            if let Some(n) = v["expires_in"].as_i64() {
                wire = wire.replace(
                    &format!("\"expires_in\":{n}"),
                    "\"expires_in\":\"_access-validity\"",
                );
            }
        }
        wire
    }
}
// refresh_family* are Rust-only columns (#523), asserted by oidc_secfix7, not Go-observable.
async fn token_rows(env: &Env, issued: Option<&Issued>) -> Result<Value, Err> {
    token_rows_many(env, &issued.into_iter().collect::<Vec<_>>()).await
}
async fn token_rows_many(env: &Env, issued: &[&Issued]) -> Result<Value, Err> {
    let raw:String=env.c.query_one("SELECT coalesce(jsonb_agg((to_jsonb(t)-'refresh_family'-'refresh_family_expires_at') ORDER BY t.created_at,t.id),'[]')::text FROM oidc_tokens t WHERE client_id=ANY($1::text[])",&[&vec![CLIENT,OTHER]]).await?.get(0);
    let mut rows: Value = serde_json::from_str(&raw)?;
    for r in rows.as_array_mut().unwrap() {
        if r["user_id"] != env.a.user || r["subject"] != env.a.user.to_string() {
            return Err("OP token escaped actor scope".into());
        }
        r["user_id"] = json!("_actor");
        r["subject"] = json!("_actor");
        if let Some(i) = issued.iter().find(|i| r["id"] == i.jti) {
            r["id"] = json!(format!("_access{}", i.index));
            if !i.refresh.is_empty() {
                if r["refresh_token_hash"] != format!("{:x}", Sha256::digest(i.refresh.as_bytes()))
                {
                    return Err("unexpected refresh hash".into());
                }
                r["refresh_token_hash"] = json!(format!("_refresh{}-sha256", i.index));
            } else if !r["refresh_token_hash"].is_null() {
                return Err("unexpected refresh attachment".into());
            }
        } else {
            return Err("unpublished OP token row".into());
        }
        if !r["revoked_at"].is_null() {
            parse_time(&r["revoked_at"])?;
            r["revoked_at"] = json!("_revoked");
        }
        let created = parse_time(&r["created_at"])?;
        let expires = parse_time(&r["expires_at"])?;
        if !(240..=302).contains(&(expires - created)) {
            return Err("OP access anchor TTL".into());
        }
        r["created_at"] = json!("_created");
        r["expires_at"] = json!("_created+300s");
        if !r["refresh_expires_at"].is_null() {
            let expiry = parse_time(&r["refresh_expires_at"])?;
            if !(2591998..=2592032).contains(&(expiry - created)) {
                return Err("OP refresh anchor TTL".into());
            }
            r["refresh_expires_at"] = json!("_created+30d");
        }
    }
    Ok(rows)
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
pub(super) async fn exchange(kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = Env::start(false).await?;
    let result=async{
  if matches!(kind,"confidential"|"wrong-secret"|"confidential-basic"|"mixed-auth"){env.c.execute("UPDATE oidc_clients SET client_type='confidential' WHERE id=$1",&[&CLIENT]).await?;}
  let (id,code)=code_method(&env,match kind{"pkce-plain"=>"plain","pkce-absent"=>"none",_=>"S256"}).await?;
  if kind=="access-statement"{env.fail_writes("insert").await?;}if kind=="attach-statement"{env.fail_writes("attach").await?;}
  let original_payload=format!("grant_type=authorization_code&client_id={CLIENT}&code={code}&redirect_uri=https%3A%2F%2Frp.idfed1.test%2Fcallback&code_verifier={VERIFIER}");
  let mut prior=None;
  if kind=="repeat"{
   let start=now();let r=request(env.gw.addr,"POST","/oauth/token",original_payload.clone(),&[("content-type","application/x-www-form-urlencoded")]).await?;
   prior=Some(Issued::parse(&env,&r.2,&code,start,now(),1).await?);
  }
  let mut before=env.stores(&[id.clone()]).await?;code_hash(&mut before,&code)?;let before_tokens=token_rows(&env,prior.as_ref()).await?;
  let mut payload=original_payload;
  match kind {
   "cross-tenant"=>payload=payload.replace(&format!("client_id={CLIENT}"),&format!("client_id={OTHER}")),
   "malformed-form"=>payload=payload.replace(&format!("code={code}"),"code=%ZZ"),
   "invalid-input"=>payload=payload.replace(&format!("code={code}"),"code=missing-code"),
   "pkce-wrong"=>payload=payload.replace(VERIFIER,"wrong-verifier"),
   "pkce-missing"|"pkce-absent"=>payload=payload.replace(&format!("&code_verifier={VERIFIER}"),""),
   "redirect-mismatch"=>payload=payload.replace("rp.idfed1.test","foreign.idfed1.test"),
   "confidential"=>payload.push_str("&client_secret=client-secret-339"),
   "mixed-auth"=>payload.push_str("&client_secret=client-secret-339"),
   "wrong-secret"=>payload.push_str("&client_secret=wrong"),
   _=>{},
  }
  let basic=format!("Basic {}",base64::engine::general_purpose::STANDARD.encode(if kind=="invalid-basic"{format!("{CLIENT}:%ZZ")}else{format!("{CLIENT}:client-secret-339")}));
  let mut headers=vec![("content-type","application/x-www-form-urlencoded")];if matches!(kind,"confidential-basic"|"mixed-auth"|"invalid-basic"){headers.push(("authorization",basic.as_str()));}
  env.status_mutation.store(mutant,std::sync::atomic::Ordering::SeqCst);let start=now();
  let response=request(env.gw.addr,"POST","/oauth/token",payload.clone(),&headers).await?;let end=now();
  let expected_status=match kind{"success"|"confidential"|"pkce-plain"|"confidential-basic"=>200,"wrong-secret"|"invalid-basic"=>401,"access-statement"|"attach-statement"=>500,_=>400};
  if !mutant&&response.0!=expected_status{return Err(format!("token expected{expected_status}, got{} {}",response.0,response.2).into());}
  let issued=if expected_status==200{Some(Issued::parse(&env,&response.2,&code,start,end,1).await?)}else{None};
  let mut after=env.stores(&[id.clone()]).await?;code_hash(&mut after,&code)?;let diagnostic=if kind=="attach-statement"{Some(Issued{access:String::new(),id:String::new(),refresh:String::new(),jti:env.c.query_one("SELECT id FROM oidc_tokens WHERE client_id=$1",&[&CLIENT]).await?.get(0),proof:Value::Null,index:1})}else{None};
  let rows=token_rows(&env,issued.as_ref().or(prior.as_ref()).or(diagnostic.as_ref())).await?;
  let actual=json!({"format":1,"go_source":SOURCE,"route":"* /oauth/ authorization-code","case":format!("token-{kind}"),"observation":{"request":{"method":"*","path":"/oauth/","wire_method":"POST","wire_path":"/oauth/token","body":payload.replace(&code,"_code1")},"response":{"status":response.0,"headers":response.1,"body":issued.as_ref().map_or(response.2.clone(),|i|i.body(&response.2))},"issued":issued.as_ref().map_or(Value::Null,|i|i.proof.clone()),"effects":[{"table":"oidc_auth_requests","before":before["requests"],"after":after["requests"]},{"table":"oidc_tokens","before":before_tokens,"after":rows},{"table":"auth_attempts","before":before["attempts"],"after":after["attempts"]}],"audit":[],"notify":[]}});
  let file=corpus().join("goldens").join(format!("token-{kind}.json"));if env.recording&&!file.exists(){golden::record(&file,&actual)?;}
  super::grants::observe(env.recording,&file,&actual,&before,&after,mutant)?;
  println!("GOLDEN-REPLAY: * /oauth/ authorization-code :: token-{kind}");Ok::<(),Err>(())
 }.await;
    env.close().await?;
    result
}

pub(super) async fn fresh(env: &Env) -> Result<Issued, Err> {
    let (_, code) = code(env).await?;
    let payload=format!("grant_type=authorization_code&client_id={CLIENT}&code={code}&redirect_uri=https%3A%2F%2Frp.idfed1.test%2Fcallback&code_verifier={VERIFIER}");
    let start = now();
    let r = request(
        env.gw.addr,
        "POST",
        "/oauth/token",
        payload,
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await?;
    if r.0 != 200 {
        return Err(format!("fresh token setup {} {}", r.0, r.2).into());
    }
    Issued::parse(env, &r.2, &code, start, now(), 1).await
}
pub(super) async fn refresh(kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = Env::start(false).await?;
    let result=async{
  let first=fresh(&env).await?;
  if kind=="attach-statement"{env.fail_writes("attach").await?;}
  let mut prior=None;
  if kind=="repeat"{let start=now();let r=request(env.gw.addr,"POST","/oauth/token",format!("grant_type=refresh_token&client_id={CLIENT}&refresh_token={}",first.refresh),&[("content-type","application/x-www-form-urlencoded")]).await?;prior=Some(Issued::parse(&env,&r.2,"",start,now(),2).await?);}
  let before=env.stores(&[]).await?;let before_tokens=token_rows_many(&env,&[Some(&first),prior.as_ref()].into_iter().flatten().collect::<Vec<_>>()).await?;
  let mut payload=format!("grant_type=refresh_token&client_id={CLIENT}&refresh_token={}",first.refresh);
  if kind=="cross-tenant"{payload=payload.replace(CLIENT,OTHER);}if kind=="invalid-input"{payload=payload.replace(&first.refresh,"bad-refresh");}if kind=="scope-widen"{payload.push_str("&scope=openid+admin");}if kind=="scope-narrow"{payload.push_str("&scope=openid+email");}
  env.status_mutation.store(mutant,std::sync::atomic::Ordering::SeqCst);let start=now();
  let response=request(env.gw.addr,"POST","/oauth/token",payload.clone(),&[("content-type","application/x-www-form-urlencoded")]).await?;let end=now();
  let expected_status=if matches!(kind,"success"|"scope-narrow"){200}else if kind=="attach-statement"{500}else{400};
  if !mutant&&response.0!=expected_status{return Err(format!("refresh expected{expected_status}, got{} {}",response.0,response.2).into());}
  let issued=if expected_status==200{Some(Issued::parse(&env,&response.2,"",start,end,2).await?)}else{None};
  let after=env.stores(&[]).await?;let rows=token_rows_many(&env,&[Some(&first),issued.as_ref().or(prior.as_ref())].into_iter().flatten().collect::<Vec<_>>()).await?;
  let actual=json!({"format":1,"go_source":SOURCE,"route":"* /oauth/ refresh-token","case":format!("refresh-{kind}"),"observation":{"request":{"method":"*","path":"/oauth/","wire_method":"POST","wire_path":"/oauth/token","body":payload.replace(&first.refresh,"_refresh1")},"response":{"status":response.0,"headers":response.1,"body":issued.as_ref().map_or(response.2.clone(),|i|i.body(&response.2))},"issued":issued.as_ref().map_or(Value::Null,|i|i.proof.clone()),"effects":[{"table":"oidc_auth_requests","before":before["requests"],"after":after["requests"]},{"table":"oidc_tokens","before":before_tokens,"after":rows},{"table":"auth_attempts","before":before["attempts"],"after":after["attempts"]}],"audit":[],"notify":[]}});
  let file=corpus().join("goldens").join(format!("refresh-{kind}.json"));if env.recording&&!file.exists(){golden::record(&file,&actual)?;}
  super::grants::observe(env.recording,&file,&actual,&before,&after,mutant)?;
  println!("GOLDEN-REPLAY: * /oauth/ refresh-token :: refresh-{kind}");Ok::<(),Err>(())
 }.await;
    env.close().await?;
    result
}

pub(super) async fn consumer(route: &str, kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = Env::start(false).await?;
    let result=async{
  let first=fresh(&env).await?;
  if kind=="repeat" {let(path,payload)=if route=="revoke"{("/revoke",format!("token={}&client_id={CLIENT}",first.access))}else{("/end_session",format!("id_token_hint={}&client_id={CLIENT}",first.id))};let r=request(env.gw.addr,"POST",path,payload,&[("content-type","application/x-www-form-urlencoded")]).await?;if !matches!(r.0,200|302){return Err("consumer repeat setup".into());}}
  let before=env.stores(&[]).await?;let before_tokens=token_rows(&env,Some(&first)).await?;
  let legacy=if kind=="legacy"{
   use cfb_mode::cipher::{AsyncStreamCipher,KeyIvInit};struct KeyLen;impl ring::hkdf::KeyType for KeyLen{fn len(&self)->usize{32}}
   let fixture:Value=serde_json::from_str(include_str!("../../../../tests/conformance/identity-login/keys.json"))?;let mut key=[0;32];ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256,b"mailserver-oidc-cryptokey-v1").extract(fixture["secret"].as_str().unwrap().as_bytes()).expand(&[b""],KeyLen).map_err(|_|"fixture HKDF")?.fill(&mut key).map_err(|_|"fixture key")?;
   let iv=[7;16];let mut encrypted=format!("{}:{}",first.jti,env.a.user).into_bytes();cfb_mode::Encryptor::<aes::Aes256>::new_from_slices(&key,&iv).map_err(|_|"fixture CFB")?.encrypt(&mut encrypted);let mut raw=iv.to_vec();raw.extend(encrypted);Some(B64.encode(raw))
  }else{None};
  if kind=="statement-failure"{env.fail_writes("revoke").await?;}if kind=="invalid-statement"{env.fail_writes("statement").await?;}
  let other=kind=="cross-tenant";let bad=matches!(kind,"invalid-input"|"invalid-statement");let token=if bad{"invalid-token"}else{legacy.as_deref().unwrap_or(&first.access)};
  let basic=format!("Basic {}",base64::engine::general_purpose::STANDARD.encode(format!("{}:client-secret-339",if other{OTHER}else{CLIENT})));
  let bearer=if other{session(&env,true).await?}else{format!("Bearer {token}")};
  let path=if route=="introspect"{"/oauth/introspect".to_owned()}else{format!("/{route}")};
  let mut payload=match route{"userinfo"=>String::new(),"end_session"=>format!("id_token_hint={}&client_id={}",if bad{"invalid-token"}else{&first.id},if other{OTHER}else{CLIENT}),_=>format!("token={token}&client_id={}",if other{OTHER}else{CLIENT})};
  if kind=="post-secret"{payload.push_str("&client_secret=client-secret-339");}
  let method=if route=="userinfo"{"GET"}else{"POST"};let mut headers=vec![("content-type","application/x-www-form-urlencoded")];if route=="userinfo"{headers.push(("authorization",bearer.as_str()));}if route=="introspect"&&kind!="post-secret"{headers.push(("authorization",basic.as_str()));}
  env.status_mutation.store(mutant,std::sync::atomic::Ordering::SeqCst);
  let response=request(env.gw.addr,method,&path,payload.clone(),&headers).await?;
  let after=env.stores(&[]).await?;let rows=token_rows(&env,Some(&first)).await?;
  let email:String=env.c.query_one("SELECT email FROM users WHERE id=$1",&[&env.a.user]).await?.get(0);
  let response_body=response.2.replace(&env.a.user.to_string(),"_actor").replace(&email,"_actor-email");
  let mut request_body=if legacy.is_some(){payload.replace(token,"_legacy-access1")}else{payload.clone()};request_body=request_body.replace(&first.access,"_access1").replace(&first.id,"_id1");if !first.refresh.is_empty(){request_body=request_body.replace(&first.refresh,"_refresh1");}
  let route_key=if route=="introspect"{"* /oauth/ introspection".to_owned()}else{format!("* /{route}")};
  let actual=json!({"format":1,"go_source":SOURCE,"route":route_key,"case":format!("{route}-{kind}"),"observation":{"request":{"method":"*","path":if route=="introspect"{"/oauth/"}else{&path},"wire_method":method,"wire_path":path,"body":request_body},"response":{"status":response.0,"headers":response.1,"body":response_body},"effects":[{"table":"oidc_auth_requests","before":before["requests"],"after":after["requests"]},{"table":"oidc_tokens","before":before_tokens,"after":rows},{"table":"auth_attempts","before":before["attempts"],"after":after["attempts"]}],"audit":[],"notify":[]}});
  let file=corpus().join("goldens").join(format!("{route}-{kind}.json"));if env.recording&&!file.exists(){golden::record(&file,&actual)?;}
  super::grants::observe(env.recording,&file,&actual,&before,&after,mutant)?;println!("GOLDEN-REPLAY: {route_key} :: {route}-{kind}");Ok::<(),Err>(())
 }.await;
    env.close().await?;
    result
}
