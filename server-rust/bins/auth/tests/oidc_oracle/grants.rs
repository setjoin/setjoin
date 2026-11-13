//! HTTP capabilities and complete owned store observations for OP grants.
use super::*;
use setjoin_conformance::fixture::{self, Account};
pub(super) const CLIENT: &str = "idfed1-client";
pub(super) const OTHER: &str = "idfed1-other";
pub(super) const REDIRECT: &str = "https://rp.idfed1.test/callback";
pub(super) const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
pub(super) struct Env {
    pub(super) c: tokio_postgres::Client,
    pub(super) a: Account,
    pub(super) b: Account,
    pub(super) old_rate: Option<bool>,
    pub(super) gw: Server,
    pub(super) auth: Server,
    pub(super) recording: bool,
    pub(super) attempts: i64,
    pub(super) receipts: Vec<String>,
    pub(super) listeners: Vec<tokio::sync::Mutex<setjoin_conformance::harness::Listener>>,
    pub(super) audit_watermark: i64,
    pub(super) status_mutation: Arc<std::sync::atomic::AtomicBool>,
}
impl Env {
    pub(super) async fn start(_mutant: bool) -> Result<Self, Err> {
        let db = Db::for_case("IDFED1-grants").expect("assigned DB required");
        let c = db.connect().await?;
        c.query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await?;
        common::signing_key(&c).await;
        // A failing (or mutant-restored) test panics past its own teardown: start clean.
        for table in [
            "DELETE FROM oidc_tokens WHERE client_id=ANY($1::text[])",
            "DELETE FROM oidc_auth_requests WHERE client_id=ANY($1::text[])",
            "DELETE FROM oidc_clients WHERE id=ANY($1::text[])",
        ] {
            c.execute(table, &[&vec![CLIENT, OTHER]]).await?;
        }
        let old_rate = c
            .query_opt(
                "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
                &[],
            )
            .await?
            .map(|r| r.get(0));
        c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
        let a = fixture::account(&c, "idfed1-actor").await?;
        let b = fixture::account(&c, "idfed1-foreign").await?;
        let mut listeners = Vec::new();
        for channel in [
            "session_revoke".to_owned(),
            format!("tag:{}", a.mailbox),
            format!("tag:{}", b.mailbox),
        ] {
            listeners.push(tokio::sync::Mutex::new(db.listen(&channel).await?));
        }
        let audit_watermark = c
            .query_one("SELECT coalesce(max(id),0) FROM admin_audit_log", &[])
            .await?
            .get(0);
        let hash = bcrypt::hash("client-secret-339", 4)?;
        for id in [CLIENT, OTHER] {
            c.execute("INSERT INTO oidc_clients(id,name,secret,redirect_uris,grant_types,scopes,client_type) VALUES($1,$1,$2,$3,ARRAY['authorization_code','refresh_token'],ARRAY['openid','email','profile','offline_access'],'public')",&[&id,&hash,&vec![REDIRECT]]).await?;
        }
        let receipts = common::receipt_ids(&c).await;
        let attempts = c
            .query_one("SELECT coalesce(max(id),0) FROM auth_attempts", &[])
            .await?
            .get(0);
        let keys: Value = serde_json::from_str(include_str!(
            "../../../../tests/conformance/identity-login/keys.json"
        ))?;
        let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
        cfg.dsn = db.dsn.clone();
        cfg.oidc_enabled = true;
        cfg.oidc_hostname = "auth.idfed1.test".into();
        cfg.oidc_private_key = corpus().join("op-private.pem").to_str().unwrap().into();
        cfg.oidc_public_key = corpus().join("op-public.pem").to_str().unwrap().into();
        let status_mutation = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let auth = auth_server_armed(
            Arc::new(
                AuthServer::load(
                    setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
                        .unwrap(),
                    cfg,
                )
                .await?,
            ),
            status_mutation.clone(),
        )
        .await;
        let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
        let recording = record.is_some();
        let gw = gateway(auth.addr, record).await;
        Ok(Self {
            c,
            a,
            b,
            old_rate,
            listeners,
            audit_watermark,
            gw,
            auth,
            recording,
            attempts,
            receipts,
            status_mutation,
        })
    }
    pub(super) async fn fail_writes(&self, mode: &str) -> Result<(), Err> {
        let clause=match mode{"insert"=>"BEFORE INSERT ON oidc_tokens FOR EACH ROW", "attach"=>"BEFORE UPDATE ON oidc_tokens FOR EACH ROW WHEN (NEW.refresh_token_hash IS NOT NULL AND OLD.refresh_token_hash IS NULL)","revoke"=>"BEFORE UPDATE ON oidc_tokens FOR EACH ROW WHEN (NEW.revoked_at IS NOT NULL)","statement"=>"BEFORE UPDATE ON oidc_tokens FOR EACH STATEMENT",_=>return Err("unknown test fault".into())};
        self.c.batch_execute(&format!("CREATE FUNCTION gofree_idfed1_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF TG_LEVEL='STATEMENT' OR NEW.client_id='idfed1-client' THEN RAISE EXCEPTION 'injected OP {mode} failure'; END IF; RETURN NEW; END;$$;CREATE TRIGGER gofree_idfed1_fault {clause} EXECUTE FUNCTION gofree_idfed1_fault();")).await?;
        Ok(())
    }
    pub(super) async fn close(self) -> Result<(), Err> {
        let metrics = request(self.gw.addr, "GET", "/_gateway/metrics", String::new(), &[]).await;
        self.gw.close().await;
        self.auth.close().await;
        self.c.batch_execute("DROP TRIGGER IF EXISTS gofree_idfed1_fault ON oidc_tokens;DROP FUNCTION IF EXISTS gofree_idfed1_fault()").await?;
        self.c
            .execute(
                "DELETE FROM oidc_auth_requests WHERE client_id=ANY($1::text[])",
                &[&vec![CLIENT, OTHER]],
            )
            .await?;
        self.c
            .execute(
                "DELETE FROM oidc_tokens WHERE client_id=ANY($1::text[])",
                &[&vec![CLIENT, OTHER]],
            )
            .await?;
        self.c
            .execute(
                "DELETE FROM oidc_clients WHERE id=ANY($1::text[])",
                &[&vec![CLIENT, OTHER]],
            )
            .await?;
        self.c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM auth_attempts WHERE id>{} AND protocol='http' AND source_ip='127.0.0.1'::inet;COMMIT",self.attempts)).await?;
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
        common::restore_receipts(&self.c, &self.receipts).await;
        fixture::remove(&self.c, &self.a).await?;
        fixture::remove(&self.c, &self.b).await?;
        if !self.recording && !metrics?.2.contains("setjoin_gateway_proxied_to_go_total 0") {
            return Err("native OP used a Go upstream".into());
        }
        Ok(())
    }
    pub(super) async fn stores(&self, ids: &[String]) -> Result<Value, Err> {
        let reqs:String=self.c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.created_at,r.id),'[]')::text FROM oidc_auth_requests r WHERE client_id=ANY($1::text[])",&[&vec![CLIENT,OTHER]]).await?.get(0);
        let attempts:String=self.c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')::text FROM auth_attempts t WHERE id>$1 AND protocol='http' AND source_ip='127.0.0.1'::inet",&[&self.attempts]).await?.get(0);
        let mut reqs: Value = serde_json::from_str(&reqs)?;
        let mut attempts: Value = serde_json::from_str(&attempts)?;
        for row in reqs.as_array_mut().unwrap() {
            let created = parse_time(&row["created_at"])?;
            let expiry = parse_time(&row["expires_at"])?;
            if !(598..=602).contains(&(expiry - created)) {
                return Err("authorization request TTL".into());
            }
            if let Some(uid) = row["user_id"].as_i64() {
                row["user_id"] = if uid == self.a.user {
                    json!("_actor")
                } else if uid == self.b.user {
                    json!("_foreign")
                } else {
                    return Err("unknown authorization owner".into());
                };
            }
            row["created_at"] = json!("_created");
            row["expires_at"] = json!("_created+600s");
            for (i, id) in ids.iter().enumerate() {
                if row["id"] == *id {
                    row["id"] = json!(format!("_request{}", i + 1));
                }
            }
        }
        for (i, row) in attempts.as_array_mut().unwrap().iter_mut().enumerate() {
            for key in ["created_at", "attempted_at", "occurred_at"] {
                if row.get(key).is_some() {
                    parse_time(&row[key])?;
                    row[key] = json!("_attempt-time");
                }
            }
            row["id"] = json!(format!("_attempt{}", i + 1));
        }
        let audit:String=self.c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]')::text FROM admin_audit_log a WHERE id>$1",&[&self.audit_watermark]).await?.get(0);
        let mut notifications = Vec::new();
        for listener in &self.listeners {
            notifications.extend(listener.lock().await.drain(&self.c).await?);
        }
        if audit != "[]" || !notifications.is_empty() {
            return Err(format!("unexpected OP audit/notify: {audit} {notifications:?}").into());
        }
        let mut state = serde_json::Map::new();
        for (label, mailbox) in [("actor", self.a.mailbox), ("foreign", self.b.mailbox)] {
            let raw: Value = serde_json::from_str(
                &self
                    .c
                    .query_one(
                        "SELECT to_jsonb(m)::text FROM mailboxes m WHERE id=$1",
                        &[&mailbox],
                    )
                    .await?
                    .get::<_, String>(0),
            )?;
            state.insert(
                label.into(),
                Value::Object(
                    raw.as_object()
                        .unwrap()
                        .iter()
                        .filter(|(k, _)| k.starts_with("jmap_") && k.ends_with("_state"))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                ),
            );
        }
        Ok(json!({"requests":reqs,"attempts":attempts,"state":state}))
    }
}
pub(super) fn parse_time(v: &Value) -> Result<i64, Err> {
    Ok(
        chrono::DateTime::parse_from_rfc3339(v.as_str().ok_or("timestamp not a string")?)?
            .timestamp(),
    )
}
pub(super) async fn authorize(kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = Env::start(mutant).await?;
    let result=async {
  let mut query=format!("client_id={CLIENT}&redirect_uri=https%3A%2F%2Frp.idfed1.test%2Fcallback&response_type=code&scope=openid+email+profile+offline_access&state=state-339&nonce=nonce-339&code_challenge={CHALLENGE}&code_challenge_method=S256");
  if kind=="unknown-scope"{query=query.replace("scope=openid+email+profile+offline_access","scope=openid+unregistered");}
  if kind=="invalid-input"{query.clear();}
  if kind=="cross-tenant"{query=query.replace("rp.idfed1.test","foreign.idfed1.test");}
  if kind=="absent-scope"{query=query.replace("&scope=openid+email+profile+offline_access","");}
  if kind=="missing-scope"{query=query.replace("scope=openid+email+profile+offline_access","scope=");}
  if kind=="bad-response-type"{query=query.replace("response_type=code","response_type=token");}
  if kind=="malformed-form"{query.push_str("&bad=%ZZ");}
  if kind=="duplicate-client"{query=format!("client_id=wrong&{query}");}
  if kind=="prompt-mixed"{query.push_str("&prompt=none+login");}
  if kind=="prompt-none"{query.push_str("&prompt=none");}
  if kind=="max-age-invalid"{query.push_str("&max_age=-1");}
  if kind=="invalid-hint"{query.push_str("&id_token_hint=bad-hint");}
  if kind=="request-object"{query.push_str("&request=unsupported-object");}
  if kind=="loopback"{env.c.execute("UPDATE oidc_clients SET redirect_uris=ARRAY['http://127.0.0.1:9999/callback'] WHERE id=$1",&[&CLIENT]).await?;query=query.replace("https%3A%2F%2Frp.idfed1.test%2Fcallback","http%3A%2F%2Flocalhost%3A47113%2Fcallback");}

  if kind=="public-remote-http"{env.c.execute("UPDATE oidc_clients SET redirect_uris=ARRAY['http://remote.idfed1.test/callback'] WHERE id=$1",&[&CLIENT]).await?;query=query.replace("https%3A%2F%2Frp.idfed1.test%2Fcallback","http%3A%2F%2Fremote.idfed1.test%2Fcallback");}
  if kind=="confidential-custom"{env.c.execute("UPDATE oidc_clients SET client_type='confidential',redirect_uris=ARRAY['com.idfed1:/callback'] WHERE id=$1",&[&CLIENT]).await?;query=query.replace("https%3A%2F%2Frp.idfed1.test%2Fcallback","com.idfed1%3A%2Fcallback");}
  let path=format!("/authorize?{query}");
  let prior=if kind=="repeat"{Some(pending(&env).await?)}else{None};
  let mut before=env.stores(&prior.clone().into_iter().collect::<Vec<_>>()).await?;if prior.is_some(){for r in before["requests"].as_array_mut().unwrap(){r["id"]=json!("_request2");}}
  env.status_mutation.store(mutant,std::sync::atomic::Ordering::SeqCst);
  let response=request(env.gw.addr,"GET",&path,String::new(),&[]).await?;
  if !mutant && response.0!=if matches!(kind,"invalid-input"|"cross-tenant"|"max-age-invalid"|"malformed-form"|"public-remote-http"|"confidential-custom"){400}else{302}{return Err(format!("authorization expected302, got{}",response.0).into());}
  let location=response.1["location"].as_str().unwrap_or("").to_owned();
  let id=if !location.starts_with("/auth/oidc/op/complete?id="){String::new()}else{
   if !location.starts_with("/auth/oidc/op/complete?id="){return Err("missing login handoff".into());}
   let id=location.split("id=").nth(1).ok_or("missing request id")?.to_owned();if id.len()!=32{return Err("request ID length".into());}id
  };
  let mut ids=if id.is_empty(){vec![]}else{vec![id.clone()]};ids.extend(prior);let after=env.stores(&ids).await?;
  let response_body=if id.is_empty(){response.2}else{response.2.replace(&id,"_request1")};let mut headers=response.1;if !location.is_empty(){headers["location"]=json!(if id.is_empty(){location}else{location.replace(&id,"_request1")});}
  let actual=json!({"format":1,"go_source":SOURCE,"route":"* /authorize","case":format!("authorize-{kind}"),"observation":{"request":{"method":"*","path":"/authorize","wire_method":"GET","query":query},"response":{"status":response.0,"headers":headers,"body":response_body},"effects":[{"table":"oidc_auth_requests","before":before["requests"],"after":after["requests"]},{"table":"auth_attempts","before":before["attempts"],"after":after["attempts"]}],"audit":[],"notify":[]}});
  let file=corpus().join("goldens").join(format!("authorize-{kind}-v2.json"));
  if env.recording&&!file.exists(){golden::record(&file,&actual)?;}
  observe(env.recording,&file,&actual,&before,&after,mutant)?;println!("GOLDEN-REPLAY: * /authorize :: authorize-{kind}");
  Ok::<(),Err>(())
 }.await;
    let cleanup = env.close().await;
    cleanup?;
    result
}

pub(super) async fn pending(env: &Env) -> Result<String, Err> {
    pending_method(env, "S256").await
}
pub(super) async fn pending_method(env: &Env, method: &str) -> Result<String, Err> {
    let mut query=format!("client_id={CLIENT}&redirect_uri=https%3A%2F%2Frp.idfed1.test%2Fcallback&response_type=code&scope=openid+email+profile+offline_access&state=state-339&nonce=nonce-339&code_challenge={CHALLENGE}&code_challenge_method=S256");
    if method == "none" {
        query = query.replace(
            &format!("&code_challenge={CHALLENGE}&code_challenge_method=S256"),
            "",
        );
    } else {
        query = query.replace(
            "code_challenge_method=S256",
            &format!("code_challenge_method={method}"),
        );
    }
    let r = request(
        env.gw.addr,
        "GET",
        &format!("/authorize?{query}"),
        String::new(),
        &[],
    )
    .await?;
    if r.0 != 302 {
        return Err(format!("authorization setup: {} {}", r.0, r.2).into());
    }
    Ok(r.1["location"]
        .as_str()
        .and_then(|s| s.strip_prefix("/auth/oidc/op/complete?id="))
        .ok_or("authorization setup did not return a request")?
        .into())
}
pub(super) async fn session(env: &Env, foreign: bool) -> Result<String, Err> {
    let uid = if foreign { env.b.user } else { env.a.user };
    let email: String = env
        .c
        .query_one("SELECT email FROM users WHERE id=$1", &[&uid])
        .await?
        .get(0);
    let keys: Value = serde_json::from_str(include_str!(
        "../../../../tests/conformance/identity-login/keys.json"
    ))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let claims = json!({"uid":uid,"email":email,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-60,"exp":now+3600,"jti":if foreign{"foreign-session-339"}else{"actor-session-339"},"fam":"family-339","auth_time":1700000000,"acr":"aal2","amr":["pwd","user","swk"]});
    Ok(format!(
        "Bearer {}",
        setjoin_authz::legacy_jwt::sign_hs256(
            keys["secret"].as_str().unwrap().as_bytes(),
            &claims.to_string()
        )
    ))
}
/// Owner-approved security fix 2026-11-05 (#523): completion is GET (consent page
/// carrying a synchroniser token) then POST. Returns the POST response, or the
/// GET response when no page was served.
pub(super) fn csrf_of(page: &str) -> Option<String> {
    let rest = page.split("name=\"csrf\" value=\"").nth(1)?;
    Some(rest.split('"').next()?.to_owned())
}
pub(super) async fn complete_flow(
    env: &Env,
    id: &str,
    auth: &str,
) -> Result<(u16, Value, String), Err> {
    let page = request(
        env.gw.addr,
        "GET",
        &format!("/auth/oidc/op/complete?id={id}"),
        String::new(),
        &[("authorization", auth)],
    )
    .await?;
    if page.0 != 200 {
        return Ok(page);
    }
    let csrf = csrf_of(&page.2).ok_or("completion page has no csrf token")?;
    request(
        env.gw.addr,
        "POST",
        "/auth/oidc/op/complete",
        format!("id={id}&csrf={csrf}"),
        &[
            ("authorization", auth),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
    )
    .await
}
pub(super) async fn complete(kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = Env::start(false).await?;
    let result=async {
  let id=pending(&env).await?;let actor=session(&env,false).await?;
  if matches!(kind,"cross-tenant"|"repeat"){
   let r=complete_flow(&env,&id,&actor).await?;
   if r.0!=302{return Err("initial completion failed".into());}
  }
  let before=env.stores(&[id.clone()]).await?;
  let auth=if kind=="cross-tenant"{session(&env,true).await?}else{actor};
  let path=if kind=="anonymous"{format!("/auth/oidc/op/complete?id={id}")}else if kind=="invalid-input"{format!("/auth/oidc/op/complete?user_id={}",env.b.user)}else{format!("/auth/oidc/op/complete?id={id}&user_id={}",env.b.user)};
  let hs=if kind=="anonymous"{vec![]}else{vec![("authorization",auth.as_str())]};
  let method=if kind=="head"{"HEAD"}else{"GET"};
  env.status_mutation.store(mutant,std::sync::atomic::Ordering::SeqCst);
  let response=request(env.gw.addr,method,&path,String::new(),&hs).await?;
  let expected_status=if matches!(kind,"cross-tenant"|"repeat"|"invalid-input"){400}else if matches!(kind,"success"|"head"){200}else{302};
  if !mutant && response.0!=expected_status{return Err(format!("completion expected{expected_status}, got{} {}",response.0,response.2).into());}
  let after=env.stores(&[id.clone()]).await?;
  let mut headers=response.1;if let Some(s)=headers["location"].as_str(){headers["location"]=json!(s.replace(&id,"_request1"));}
  let actor_email:String=env.c.query_one("SELECT email FROM users WHERE id=$1",&[&env.a.user]).await?.get(0);
  let mut page_body=response.2.replace(&id,"_request1").replace(&actor_email,"_actor-email");if let Some(csrf)=csrf_of(&page_body){page_body=page_body.replace(&csrf,"_csrf");}
  let mut actual=json!({"format":1,"go_source":SOURCE,"route":"GET /auth/oidc/op/complete","case":format!("complete-{kind}"),"observation":{"request":{"method":"GET","path":"/auth/oidc/op/complete","query":if kind=="anonymous"{"id=_request1"}else if kind=="invalid-input"{"user_id=_foreign"}else{"id=_request1&user_id=_foreign"},"credential":if kind=="cross-tenant"{"_foreign-session"}else if kind=="anonymous"{"_anonymous"}else{"_actor-session"}},"response":{"status":response.0,"headers":headers,"body":page_body},"effects":[{"table":"oidc_auth_requests","before":before["requests"],"after":after["requests"]},{"table":"auth_attempts","before":before["attempts"],"after":after["attempts"]}],"audit":[],"notify":[]}});
  if kind!="success"{actual["observation"]["request"]["wire_method"]=json!(method);}
  let file=corpus().join("goldens").join(format!("complete-{kind}.json"));if env.recording&&!file.exists(){golden::record(&file,&actual)?;}
  observe(env.recording,&file,&actual,&before,&after,mutant)?;
  println!("GOLDEN-REPLAY: GET /auth/oidc/op/complete :: complete-{kind}");
  Ok::<(),Err>(())
 }.await;
    env.close().await?;
    result
}

pub(super) fn check_code(code: &str, id: &str) -> Result<(), Err> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    let parts: Vec<_> = code.split('.').collect();
    if parts.len() != 5 {
        return Err("authorization code is not Go's compact JWE".into());
    }
    let h: Value = serde_json::from_slice(&B64.decode(parts[0])?)?;
    if h["alg"] != "A256GCMKW" || h["enc"] != "A256GCM" || h["kid"] != "authserver-enc-1" {
        return Err("authorization JWE profile".into());
    }
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/conformance/identity-login/keys.json"
    ))?;
    struct Len;
    impl ring::hkdf::KeyType for Len {
        fn len(&self) -> usize {
            32
        }
    }
    let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"mailserver-oidc-cryptokey-v1");
    let prk = salt.extract(fixture["secret"].as_str().unwrap().as_bytes());
    let mut kek = [0; 32];
    prk.expand(&[b""], Len)
        .map_err(|_| "HKDF")?
        .fill(&mut kek)
        .map_err(|_| "HKDF")?;
    let open = |key: &[u8], iv: Vec<u8>, aad: &[u8], mut data: Vec<u8>| -> Result<Vec<u8>, Err> {
        let key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key).map_err(|_| "AES key")?,
        );
        Ok(key
            .open_in_place(
                ring::aead::Nonce::try_assume_unique_for_key(&iv).map_err(|_| "AES nonce")?,
                ring::aead::Aad::from(aad),
                &mut data,
            )
            .map_err(|_| "JWE authentication")?
            .to_vec())
    };
    let mut wrapped = B64.decode(parts[1])?;
    wrapped.extend(B64.decode(h["tag"].as_str().ok_or("wrap tag")?)?);
    let cek = open(
        &kek,
        B64.decode(h["iv"].as_str().ok_or("wrap IV")?)?,
        b"",
        wrapped,
    )?;
    let mut cipher = B64.decode(parts[3])?;
    cipher.extend(B64.decode(parts[4])?);
    if open(&cek, B64.decode(parts[2])?, parts[0].as_bytes(), cipher)? != id.as_bytes() {
        return Err("code encrypts another request".into());
    }
    Ok(())
}
pub(super) fn code_hash(rows: &mut Value, code: &str) -> Result<(), Err> {
    use sha2::{Digest, Sha256};
    let expected = format!("\\x{:x}", Sha256::digest(code.as_bytes()));
    for r in rows["requests"].as_array_mut().unwrap() {
        if !r["code_hash"].is_null() {
            if r["code_hash"] != expected {
                return Err(
                    "stored authorization code hash does not bind the returned code".into(),
                );
            }
            r["code_hash"] = json!("_code1-sha256");
        }
    }
    Ok(())
}
pub(super) async fn callback(kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = Env::start(false).await?;
    let result=async{
  let id=pending(&env).await?;let auth=session(&env,false).await?;
  if kind!="cross-tenant"{
   let completed=complete_flow(&env,&id,&auth).await?;
   if completed.0!=302{return Err("callback setup completion failed".into());}
  }
  let mut prior=None;
  if kind=="repeat"{
   let first=request(env.gw.addr,"GET",&format!("/authorize/callback?id={id}"),String::new(),&[("authorization",&auth)]).await?;
   let location=first.1["location"].as_str().ok_or("no initial code Location")?;
   let fields=setjoin_identity::issuance::query(location.split_once('?').ok_or("no initial code query")?.1);
   let code=fields.get("code").ok_or("no initial code")?.clone();check_code(&code,&id)?;prior=Some(code);
  }
  let mut before=env.stores(&[id.clone()]).await?;if let Some(code)=&prior{code_hash(&mut before,code)?;}
  let path=if kind=="invalid-input"{"/authorize/callback".to_owned()}else{format!("/authorize/callback?id={id}")};
  env.status_mutation.store(mutant,std::sync::atomic::Ordering::SeqCst);
  let response=request(env.gw.addr,"GET",&path,String::new(),&[("authorization",&auth)]).await?;
  let expected_status=if matches!(kind,"invalid-input"|"cross-tenant"){400}else{302};
  if !mutant&&response.0!=expected_status{return Err(format!("callback expected{expected_status}, got{} {}",response.0,response.2).into());}
  let location=response.1["location"].as_str().unwrap_or("").to_owned();
  let fields=setjoin_identity::issuance::query(location.split_once('?').map_or("",|v|v.1));
  let code=fields.get("code").cloned();
  if kind=="success"&&code.is_none(){return Err("callback did not return a code".into());}
  if let Some(code)=&code{check_code(code,&id)?;}
  let mut after=env.stores(&[id.clone()]).await?;if let Some(code)=code.as_ref().or(prior.as_ref()){code_hash(&mut after,code)?;}
  let normalize=|raw:String|code.as_ref().map_or(raw.clone(),|code|raw.replace(code,"_code1"));
  let mut headers=response.1;if !location.is_empty(){headers["location"]=json!(normalize(location));}
  let actual=json!({"format":1,"go_source":SOURCE,"route":"* /authorize/callback","case":format!("callback-{kind}"),"observation":{"request":{"method":"*","path":"/authorize/callback","wire_method":"GET","query":if kind=="invalid-input"{""}else{"id=_request1"}},"response":{"status":response.0,"headers":headers,"body":normalize(response.2)},"effects":[{"table":"oidc_auth_requests","before":before["requests"],"after":after["requests"]},{"table":"auth_attempts","before":before["attempts"],"after":after["attempts"]}],"audit":[],"notify":[]}});
  let file=corpus().join("goldens").join(format!("callback-{kind}.json"));if env.recording&&!file.exists(){golden::record(&file,&actual)?;}
  observe(env.recording,&file,&actual,&before,&after,mutant)?;
  println!("GOLDEN-REPLAY: * /authorize/callback :: callback-{kind}");Ok::<(),Err>(())
 }.await;
    env.close().await?;
    result
}

/// Immutable qualification wrappers retain the actual wire method/path while
/// naming every inventory mount which routes to the exercised OP handler.
pub(super) fn qualify(actual: &Value) -> Vec<Value> {
    let key = actual["route"].as_str().unwrap();
    let targets: Vec<(&str, &str)> = match key {
        "* /.well-known/" => vec![("* /.well-known/ discovery", "/.well-known/")],
        "* /.well-known/oauth-authorization-server" => vec![(
            "GET /.well-known/oauth-authorization-server",
            "/.well-known/oauth-authorization-server",
        )],
        "* /oauth/ authorization-code" => vec![
            ("* /oauth/ authorization-code", "/oauth/"),
            ("* /oauth/token authorization-code", "/oauth/token"),
        ],
        "* /oauth/ refresh-token" => vec![
            ("* /oauth/ refresh-token", "/oauth/"),
            ("* /oauth/token refresh-token", "/oauth/token"),
        ],
        "* /oauth/ introspection" => vec![
            ("* /oauth/ introspection", "/oauth/"),
            ("* /oauth/introspect", "/oauth/introspect"),
        ],
        "* /keys" => vec![("* /keys", "/keys"), ("GET /keys", "/keys")],
        _ => vec![(
            key,
            actual["observation"]["request"]["path"].as_str().unwrap(),
        )],
    };
    let mut out = Vec::new();
    for (key, path) in targets {
        let wire=actual["observation"]["request"].get("wire_method").unwrap_or(&actual["observation"]["request"]["method"]).as_str().unwrap_or("");
        if key.starts_with("GET ")&&!matches!(wire,"GET"|"HEAD"){continue;}
        let mut v = actual.clone();
        let r = &mut v["observation"]["request"];
        if r.get("wire_method").is_none() {
            r["wire_method"] = r["method"].clone();
        }
        if r.get("wire_path").is_none() {
            r["wire_path"] = r["path"].clone();
        }
        r["method"] = json!(key.split(' ').next().unwrap());
        r["path"] = json!(path);
        v["route"] = json!(key);
        out.push(v);
    }
    if key == "* /.well-known/" && matches!(actual["observation"]["request"]["method"].as_str(),Some("GET"|"HEAD")) {
        let mut v = out[0].clone();
        v["route"] = json!("GET /.well-known/openid-configuration");
        v["observation"]["request"]["method"] = json!("GET");
        v["observation"]["request"]["path"] = json!("/.well-known/openid-configuration");
        out.push(v);
    }
    out
}
pub(super) fn qualified_name(v: &Value) -> String {
    format!(
        "{}--{}.json",
        v["route"]
            .as_str()
            .unwrap()
            .replace(['*', '/', '.', ' '], "_")
            .trim_matches('_'),
        v["case"].as_str().unwrap()
    )
}
/// Reviewed security expectation for a recorded Go baseline (owner-approved
/// security fixes 2026-11-05, #523). Go captures stay hash-pinned and are never
/// rewritten; `divergences.json` names each baseline whose expected document is
/// the authored `security/<file>`. `SECFIX7_WRITE_SECURITY=1` writes/updates
/// those expectations (and their divergence entries) from the actual document
/// for diff review, only where it differs from the baseline.
pub(super) fn expected_for(baseline: &std::path::Path, actual: &Value) -> Result<Value, Err> {
    use sha2::{Digest, Sha256};
    let family = corpus();
    let relative = baseline.strip_prefix(&family)?.to_str().unwrap().to_owned();
    let list = family.join("divergences.json");
    let mut entries: Vec<Value> = if list.exists() {
        serde_json::from_slice(&std::fs::read(&list)?)?
    } else {
        Vec::new()
    };
    let base: Value = serde_json::from_slice(&std::fs::read(baseline)?)?;
    let name = baseline.file_name().unwrap().to_str().unwrap().to_owned();
    let expectation = family.join("security").join(&name);
    if std::env::var("SECFIX7_WRITE_SECURITY").as_deref() == Ok("1")
        && golden::compare(&base, actual).is_err()
    {
        std::fs::create_dir_all(expectation.parent().unwrap())?;
        std::fs::write(&expectation, serde_json::to_string_pretty(actual)? + "\n")?;
        let entry = json!({"baseline":relative,"sha256":format!("{:x}",Sha256::digest(std::fs::read(baseline)?)),"expectation":format!("security/{name}"),"reason":"owner-approved security fix 2026-11-05 (#523): UNREVIEWED","reviewer":"owner 2026-11-05","reviewed":true});
        match entries.iter_mut().find(|e| e["baseline"] == relative) {
            Some(e) => {
                e["sha256"] = entry["sha256"].clone();
            }
            None => entries.push(entry),
        }
        entries.sort_by(|a, b| a["baseline"].as_str().cmp(&b["baseline"].as_str()));
        std::fs::write(&list, serde_json::to_string_pretty(&entries)? + "\n")?;
    }
    let Some(entry) = entries.iter().find(|e| e["baseline"] == relative) else {
        return Ok(base);
    };
    assert_eq!(entry["reviewed"], true);
    assert!(entry["reason"]
        .as_str()
        .unwrap()
        .contains("owner-approved security fix 2026-11-05"));
    assert!(!entry["reason"].as_str().unwrap().contains("UNREVIEWED") || std::env::var("SECFIX7_WRITE_SECURITY").is_ok());
    assert_eq!(
        entry["sha256"],
        format!("{:x}", Sha256::digest(std::fs::read(baseline)?)),
        "{relative}: the Go capture changed"
    );
    Ok(serde_json::from_slice(&std::fs::read(
        family.join(entry["expectation"].as_str().unwrap()),
    )?)?)
}
pub(super) fn observe(
    recording: bool,
    file: &std::path::Path,
    actual: &Value,
    before: &Value,
    after: &Value,
    mutant: bool,
) -> Result<(), Err> {
    for value in qualify(actual) {
        let path = corpus().join("qualified").join(qualified_name(&value));
        let mut rows = value["observation"]["effects"].as_array().unwrap().clone();
        rows.push(json!({"table":"mailboxes.jmap_*_state","before":before["state"],"after":after["state"]}));
        let companion = json!({"format":1,"go_source":SOURCE,"route":value["route"],"case":format!("{}-row-effects",value["case"].as_str().unwrap()),"effects":rows});
        let row_path = path.with_file_name(format!(
            "{}-rows.json",
            path.file_stem().unwrap().to_str().unwrap()
        ));
        if recording {
            std::fs::create_dir_all(path.parent().unwrap())?;
            if !path.exists() {
                golden::record(&path, &value)?;
            }
            if !row_path.exists() {
                golden::record(&row_path, &companion)?;
            }
        }
        let expected = expected_for(&path, &value)?;
        let row_expected = expected_for(&row_path, &companion)?;
        let result = golden::compare(&expected, &value);
        if mutant {
            if result
                .as_ref()
                .is_err_and(|e| e.contains("/observation/response/status"))
            {
                println!(
                    "MUTANT-REJECTED: {} :: status",
                    value["route"].as_str().unwrap()
                );
            } else {
                return Err("status mutant survived qualification".into());
            }
        } else {
            result?;
            golden::compare(&row_expected, &companion)?;
            println!(
                "GOLDEN-REPLAY: {} :: {}",
                value["route"].as_str().unwrap(),
                value["case"].as_str().unwrap()
            );
        }
    }
    let expected = expected_for(file, actual)?;
    golden::compare(&expected, actual)?;
    Ok(())
}
