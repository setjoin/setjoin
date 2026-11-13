use super::*;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use setjoin_conformance::golden;
use std::io::Read;
pub const ENC: &str = "idfed3-test-encryption-key-at-least-32-bytes";
pub const ENTITY: &str = "idfed3";
pub fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap()
}
pub fn metadata(binding: &str) -> String {
    format!("<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://idp.idfed3.test\"><IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-{binding}\" Location=\"https://idp.idfed3.test/sso\"/></IDPSSODescriptor></EntityDescriptor>")
}
pub fn config() -> Result<Config, Err> {
    let path = corpus();
    let fields = vec![
        ("SETJOIN_CONFIG", None),
        (
            "JWT_SECRET",
            Some(fixture()["secret"].as_str().unwrap().to_owned()),
        ),
        ("JWT_SIGNING_ALG", Some("ES256".into())),
        ("CRYPTO_ALGORITHM_PROFILE", Some("standard".into())),
        ("SAML_ENABLED", Some("true".into())),
        (
            "SAML_CERT_FILE",
            Some(path.join("sp-cert.pem").display().to_string()),
        ),
        (
            "SAML_KEY_FILE",
            Some(path.join("sp-key.pem").display().to_string()),
        ),
        ("DB_ENCRYPTION_KEY", Some(ENC.into())),
        ("AUTHSERVER_GO_UPSTREAM", None),
    ];
    let before: Vec<_> = fields
        .iter()
        .map(|(k, _)| (*k, std::env::var_os(k)))
        .collect();
    for (k, v) in &fields {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
    let result = Config::from_env();
    for (k, v) in before {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
    result.map_err(Into::into)
}
pub struct Env {
    pub c: tokio_postgres::Client,
    pub native: Arc<AuthServer>,
    pub gw: Server,
    auth: Server,
    pub recording: bool,
    old: Vec<(&'static str, Option<bool>)>,
}
impl Env {
    pub async fn start(mutant: bool) -> Result<Self, Err> {
        Self::binding(mutant, "Redirect").await
    }
    pub async fn binding(mutant: bool, binding: &str) -> Result<Self, Err> {
        Self::configured(mutant, binding, ENTITY).await
    }
    pub async fn configured(mutant: bool, binding: &str, entity: &str) -> Result<Self, Err> {
        Self::mode(mutant, binding, entity, false).await
    }
    pub async fn mode(
        mutant: bool,
        binding: &str,
        entity: &str,
        public: bool,
    ) -> Result<Self, Err> {
        let db = Db::for_case("IDFED3-saml").expect("assigned DB required");
        let c = db.connect().await?;
        c.query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await?;
        common::signing_key(&c).await;
        let mut old = Vec::new();
        for (key, value) in [
            ("feature.rate_limit", false),
            ("feature.identity_model_v2", false),
        ] {
            old.push((
                key,
                c.query_opt("SELECT enabled FROM feature_toggles WHERE key=$1", &[&key])
                    .await?
                    .map(|r| r.get(0)),
            ));
            c.execute("INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=excluded.enabled",&[&key,&value]).await?;
        }
        c.execute(
            "DELETE FROM saml_sp_registrations WHERE id IN (34101,34102)",
            &[],
        )
        .await?;
        c.execute("INSERT INTO saml_sp_registrations(id,idp_entity_id,idp_metadata_url,idp_sso_url,idp_cert_enc,sp_entity_id,sp_acs_url,group_mappings) VALUES(34101,$1,$2,'https://ignored.invalid/sso',pgp_sym_encrypt('unused-cert',$3),'https://auth.idfed3.test/ignored/path','https://ignored.invalid/acs','[]')",&[&entity,&metadata(binding),&ENC]).await?;
        c.execute(
            "SELECT pg_notify('config_changed','{\"key\":\"saml_sp\"}')",
            &[],
        )
        .await?;
        let native = Arc::new(
            AuthServer::load(
                setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
                    .unwrap(),
                config()?,
            )
            .await?,
        );
        let auth = auth_server(native.clone(), mutant).await;
        let record = std::env::var("GOFREE_RECORD_UPSTREAM")
            .ok()
            .filter(|v| !v.is_empty());
        let recording = record.is_some();
        let gw = gateway_mode(auth.addr, record, public).await;
        if recording {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                let r = request(
                    gw.addr,
                    "GET",
                    &format!("/auth/saml/{}/login", encoded_idp(entity)),
                    String::new(),
                    &[],
                )
                .await?;
                if r.0 == if binding == "Redirect" { 302 } else { 200 } {
                    break;
                }
                if tokio::time::Instant::now() > deadline {
                    return Err(format!("Go SAML snapshot not ready: {} {}", r.0, r.2).into());
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
        Ok(Self {
            native,
            c,
            gw,
            auth,
            recording,
            old,
        })
    }
    pub async fn close(self) -> Result<(), Err> {
        let metrics = if !self.recording {
            request(self.gw.addr, "GET", "/_gateway/metrics", String::new(), &[])
                .await
                .map(|r| r.2.contains("setjoin_gateway_proxied_to_go_total 0"))
        } else {
            Ok(true)
        };
        self.gw.close().await;
        self.auth.close().await;
        self.c
            .execute(
                "DELETE FROM saml_sp_registrations WHERE id IN (34101,34102)",
                &[],
            )
            .await?;
        // A SAML login creates the registration's identity source; leave no trace of it.
        self.c
            .execute(
                "WITH s AS (SELECT x.id FROM identity_sources x WHERE x.provider_key IN ('saml:34101','saml:34102') AND NOT EXISTS (SELECT 1 FROM user_identity_links l WHERE l.source_id=x.id)), a AS (DELETE FROM identity_auth_shadow_hours WHERE source_id IN (SELECT id FROM s)), b AS (DELETE FROM identity_auth_shadow_link_evidence WHERE source_id IN (SELECT id FROM s)), c AS (DELETE FROM identity_shadow_divergences WHERE source_id IN (SELECT id FROM s)) DELETE FROM identity_sources WHERE id IN (SELECT id FROM s)",
                &[],
            )
            .await?;
        for (key, old) in self.old {
            match old {
                Some(v) => {
                    self.c
                        .execute(
                            "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                            &[&key, &v],
                        )
                        .await?;
                }
                None => {
                    self.c
                        .execute("DELETE FROM feature_toggles WHERE key=$1", &[&key])
                        .await?;
                }
            }
        }
        self.c
            .execute(
                "SELECT pg_notify('config_changed','{\"key\":\"saml_sp\"}')",
                &[],
            )
            .await?;
        if !metrics? {
            return Err("SAML replay proxied to Go".into());
        }
        observation::regeneration_guard();
        Ok(())
    }
}
pub fn attribute<'a>(xml: &'a str, name: &str) -> Result<&'a str, Err> {
    let start = xml
        .find(&format!(" {name}=\""))
        .ok_or("missing AuthnRequest attribute")?
        + name.len()
        + 3;
    Ok(xml[start..]
        .split_once('"')
        .ok_or("unterminated XML attribute")?
        .0)
}
pub fn normalize(response: (u16, Value, String)) -> Result<Value, Err> {
    normalize_for(
        response,
        include_bytes!("../../../../tests/conformance/identity-saml/sp-public.der"),
        include_bytes!("../../../../tests/conformance/identity-saml/sp-cert.pem"),
        false,
    )
}
pub fn normalize_for(
    mut response: (u16, Value, String),
    public: &[u8],
    certificate: &[u8],
    legacy: bool,
) -> Result<Value, Err> {
    let verify_signature = |input: &[u8], signature: &[u8]| -> Result<(), Err> {
        let algorithm = if legacy {
            &ring::signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
        } else {
            &ring::signature::RSA_PKCS1_2048_8192_SHA256
        };
        ring::signature::UnparsedPublicKey::new(algorithm, public)
            .verify(input, signature)
            .map_err(|_| "SAML signature invalid".into())
    };
    if response.1.get("set-cookie").is_none() {
        return Ok(json!({"status":response.0,"headers":response.1,"body":response.2}));
    }
    let cookie = response.1["set-cookie"][0]
        .as_str()
        .ok_or("missing tracking cookie")?
        .to_owned();
    let (name, token) = cookie
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .ok_or("invalid cookie")?;
    let relay = name.strip_prefix("saml_").ok_or("wrong cookie")?;
    if URL_SAFE_NO_PAD.decode(relay)?.len() != 42 {
        return Err("tracking entropy differs".into());
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid tracking JWT".into());
    }
    verify_signature(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &URL_SAFE_NO_PAD.decode(parts[2])?,
    )?;
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    if header != json!({"alg":"RS256","typ":"JWT"}) {
        return Err("tracking JWT header differs".into());
    }
    let mut claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    let id = claims["id"]
        .as_str()
        .ok_or("missing request ID")?
        .to_owned();
    if id.len() != 43 || !id.starts_with("id-") || !id[3..].bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("request entropy differs".into());
    }
    let iat = claims["iat"].as_i64().ok_or("missing issued-at")?;
    if claims["exp"].as_i64() != Some(iat + 90) || claims["nbf"] != iat || claims["sub"] != relay {
        return Err("tracking binding/lifetime differs".into());
    }
    let mut xml = String::new();
    if response.1.get("location").is_some() {
        let location = response.1["location"]
            .as_str()
            .ok_or("missing redirect")?
            .to_owned();
        let query = location.split_once('?').ok_or("missing request query")?.1;
        let (signed, signature) = query
            .rsplit_once("&Signature=")
            .ok_or("unsigned redirect")?;
        let decoded = setjoin_identity::issuance::query(query);
        if decoded["RelayState"] != relay
            || decoded["SigAlg"] != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        {
            return Err("redirect binding differs".into());
        }
        let sig = setjoin_identity::issuance::query(&format!("s={signature}"))["s"].clone();
        verify_signature(signed.as_bytes(), &STANDARD.decode(sig)?)?;
        let compressed = STANDARD.decode(&decoded["SAMLRequest"])?;
        flate2::read::DeflateDecoder::new(compressed.as_slice()).read_to_string(&mut xml)?;
        let base = location.split_once('?').unwrap().0;
        response.1["location"] = json!(format!(
            "{base}?SAMLRequest=_request&RelayState=_relay&SigAlg={}&Signature=_signature",
            decoded["SigAlg"]
        ));
    } else {
        let prefix = "name=\"SAMLRequest\" value=\"";
        let start = response.2.find(prefix).ok_or("missing POST request")? + prefix.len();
        let encoded = response.2[start..]
            .split_once('"')
            .ok_or("POST value quote")?
            .0
            .to_owned();
        xml = String::from_utf8(
            STANDARD.decode(html_escape::decode_html_entities(&encoded).as_bytes())?,
        )?;
        let mut manager = bergshamra_keys::KeysManager::new();
        manager.add_key(bergshamra_keys::loader::load_x509_cert_pem(certificate)?);
        let ctx = bergshamra_dsig::DsigContext::new(manager)
            .with_trusted_keys_only(true)
            .with_strict_verification(true);
        let checked = bergshamra_dsig::verify::verify(&ctx, &xml)?;
        if !checked.is_valid() || checked.has_unverified_references() {
            return Err("POST XML signature invalid".into());
        }
        if let bergshamra_dsig::verify::VerifyResult::Valid { references, .. } = checked {
            if references.len() != 1
                || references[0].uri != format!("#{id}")
                || !references[0].digest_verified
            {
                return Err("POST reference differs".into());
            }
        }
        for name in ["DigestValue", "SignatureValue"] {
            let open = format!("<ds:{name}>");
            let close = format!("</ds:{name}>");
            let start = xml.find(&open).ok_or("signature field absent")? + open.len();
            let end = start + xml[start..].find(&close).ok_or("signature field close")?;
            xml.replace_range(
                start..end,
                if name == "DigestValue" {
                    "_digest"
                } else {
                    "_signature"
                },
            );
        }
        response.2 = response
            .2
            .replace(&encoded, "_request")
            .replace(relay, "_relay");
    }
    if attribute(&xml, "ID")? != id {
        return Err("request/cookie identity mismatch".into());
    }
    let instant = attribute(&xml, "IssueInstant")?.to_owned();
    if (chrono::DateTime::parse_from_rfc3339(&instant)?.timestamp() - iat).abs() > 1 {
        return Err("request/cookie instant mismatch".into());
    }
    if claims["flow"].is_string() {
        claims["flow"] = json!("_flow");
    }
    claims["id"] = json!("_request");
    claims["sub"] = json!("_relay");
    for k in ["iat", "nbf", "exp"] {
        claims[k] = json!(format!("_{k}"));
    }
    response.1["set-cookie"][0] =
        json!(cookie.replace(&format!("{name}={token}"), "saml__relay=_tracked"));
    Ok(
        json!({"status":response.0,"headers":response.1,"body":response.2,"authn_request":xml.replace(&id,"_request").replace(&instant,"_instant"),"tracked":claims}),
    )
}
#[path = "observation.rs"]
mod observation;
pub fn expected_for(baseline: &std::path::Path, actual: &Value) -> Result<Value, Err> {
    observation::expected_for(baseline, actual)
}
pub fn qualified_compare(actual: &Value, mutant: bool) -> Result<(), Err> {
    observation::compare(actual, mutant)
}
pub fn check(name: &str, actual: &Value, recording: bool) -> Result<(), Err> {
    let path = corpus().join("goldens").join(format!("{name}.json"));
    if recording && !path.exists() {
        golden::record(&path, actual)?;
    }
    golden::compare(&observation::expected_for(&path, actual)?, actual)?;
    if !recording {
        qualified_compare(actual, false)?;
    }
    Ok(())
}
pub async fn login(kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let entity = if kind == "encoded" {
        "https://idp.idfed3.test/path"
    } else {
        ENTITY
    };
    let path = format!(
        "/auth/saml/{}/login",
        encoded_idp(if kind == "invalid-input" {
            "missing"
        } else {
            entity
        })
    );
    let env = Env::configured(
        mutant,
        if kind == "post" { "POST" } else { "Redirect" },
        entity,
    )
    .await?;
    let foreign = if kind == "cross-tenant" {
        Some(setjoin_conformance::fixture::account(&env.c, "idfed3-foreign-public").await?)
    } else {
        None
    };
    let result=async{
        let cookie=if kind=="session"{format!("token={}",sp_session("https://auth.idfed3.test")?)}else if kind=="foreign-session"{format!("token={}",sp_session("https://foreign.idfed3.test")?)}else if kind=="invalid-session"{let token=sp_session("https://auth.idfed3.test")?;let p:Vec<_>=token.split('.').collect();let mut sig=URL_SAFE_NO_PAD.decode(p[2])?;sig[0]^=1;format!("token={}.{}.{}",p[0],p[1],URL_SAFE_NO_PAD.encode(sig))}else if let Some(foreign)=&foreign{format!("access_token={}",access(&env.c,foreign.user,"aal2","idfed3-public").await?)}else{String::new()};
        let headers=if cookie.is_empty(){Vec::new()}else{vec![("cookie",cookie.as_str())]};
        let response=request(env.gw.addr,"GET",&path,String::new(),&headers).await?;
        if env.recording && response.0!=if kind=="invalid-input"{404}else if kind=="post"{200}else{302} {return Err(format!("Go login expected binding success, got {} {}",response.0,response.2).into());}
        let actual=json!({"format":1,"go_source":SOURCE,"route":"GET /auth/saml/{idp}/login","case":format!("login-{kind}"),"observation":{"request":{"method":"GET","path":path},"response":normalize(response)?,"effects":[],"audit":[],"notify":[],"outbound":[]}});
        if mutant {
            let expected:Value=expected_for(&corpus().join("goldens/login-success.json"),&actual)?;
            let error=golden::compare(&expected,&actual).expect_err("login HTTP status mutant escaped");
            if !error.contains("/observation/response/status"){return Err(error.into());}
            qualified_compare(&actual,true)?;
        }else{check(&format!("login-{kind}"),&actual,env.recording)?;}
        if !env.recording {
            let r=request(env.gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;
            if !r.2.contains("setjoin_gateway_proxied_to_go_total 0") {return Err("SAML replay proxied to Go".into());}
        }
        Ok(())
    }.await;
    if let Some(foreign) = foreign {
        setjoin_conformance::fixture::remove(&env.c, &foreign).await?;
    }
    env.close().await?;
    result
}

fn encoded_idp(entity: &str) -> String {
    percent_encoding::utf8_percent_encode(entity, percent_encoding::NON_ALPHANUMERIC).to_string()
}

pub fn sp_session(audience: &str) -> Result<String, Err> {
    let pem = include_str!("../../../../tests/conformance/identity-saml/sp-key.pem");
    let der = STANDARD.decode(
        pem.lines()
            .filter(|l| !l.starts_with("---"))
            .collect::<String>(),
    )?;
    let key = ring::signature::RsaKeyPair::from_pkcs8(&der).map_err(|_| "fixture SP key")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let claims = json!({"iss":"https://auth.idfed3.test","aud":audience,"sub":"existing@idfed3.test","iat":now-60,"nbf":now-60,"exp":now+3600,"saml-session":true,"attr":{"memberOf":["users"]}});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        input.as_bytes(),
        &mut signature,
    )
    .map_err(|_| "fixture SP signature")?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

pub async fn public(group: &str, kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = Env::mode(mutant, "Redirect", ENTITY, matches!(group, "mux" | "alias")).await?;
    let foreign = if kind == "cross-tenant" {
        Some(setjoin_conformance::fixture::account(&env.c, "idfed3-foreign-public").await?)
    } else {
        None
    };
    let result=async{
        let entity=if kind=="invalid-input"{"missing"}else{ENTITY};
        let (method,path,route)=match group {
            "acs"=>("POST",format!("/auth/saml/{entity}/acs"),"POST /auth/saml/{idp}/acs"),
            "metadata"=>("GET",format!("/auth/saml/{entity}/metadata"),"GET /auth/saml/{idp}/metadata"),
            "alias"=>("GET",format!("/auth/saml/{entity}/link"),"GET /auth/saml/{idp}/link"),
            _=>("PATCH",if kind=="invalid-input"{"/auth/saml/idfed3/missing".into()}else{"/auth/saml/idfed3/login".into()},"* /auth/saml/ mux")
        };
        let xml=if kind=="wrapping"{"<Response xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\"><Assertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"idfed3-repeated\"/><Assertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"idfed3-repeated\"/></Response>"}else{"<Response xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"idfed3-response\"><Assertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"idfed3-repeated\"><Issuer>https://idp.idfed3.test</Issuer><Subject><NameID>actor@idfed3.test</NameID></Subject></Assertion></Response>"};
        let payload=if group=="acs" {format!("SAMLResponse={}",percent_encoding::utf8_percent_encode(&STANDARD.encode(xml),percent_encoding::NON_ALPHANUMERIC))}else{String::new()};
        let cookie=if let Some(f)=&foreign {format!("access_token={}",access(&env.c,f.user,"aal2","idfed3-public").await?)}else{String::new()};
        let mut headers=vec![("content-type","application/x-www-form-urlencoded")];if !cookie.is_empty(){headers.push(("cookie",cookie.as_str()));}
        let before=public_effects(&env.c).await?;
        if kind=="repeat" {request(env.gw.addr,method,&path,payload.clone(),&headers).await?;}
        let response=request(env.gw.addr,method,&path,payload.clone(),&headers).await?;
        let actual=json!({"format":1,"go_source":SOURCE,"route":route,"case":format!("{group}-{kind}"),"observation":{"request":{"method":method,"path":path,"body":payload},"response":{"status":response.0,"headers":response.1,"body":response.2},"effects":{"before":before,"after":public_effects(&env.c).await?},"audit":[],"notify":[],"outbound":[]}});
        if mutant {
            let expected:Value=expected_for(&corpus().join("goldens").join(format!("{group}-success.json")),&actual)?;
            let error=golden::compare(&expected,&actual).expect_err("wire status mutant survived");
            if !error.contains("/observation/response/status"){return Err(error.into());}
            qualified_compare(&actual,true)?;Ok(())
        } else {
            check(&format!("{group}-{kind}"),&actual,env.recording)
        }
    }.await;
    if let Some(foreign) = foreign {
        setjoin_conformance::fixture::remove(&env.c, &foreign).await?;
    }
    env.close().await?;
    result
}
async fn public_effects(c: &tokio_postgres::Client) -> Result<Value, Err> {
    // Owner-only black-box effect observer on this ticket's disposable DB.
    let r=c.query_one("SELECT jsonb_build_object('assertions',(SELECT coalesce(jsonb_agg(assertion_id ORDER BY assertion_id),'[]') FROM used_saml_assertions WHERE assertion_id LIKE 'idfed3-%'),'users',(SELECT count(*) FROM users WHERE saml_idp_entity_id='idfed3'),'sessions',(SELECT count(*) FROM sessions WHERE auth_method='saml'),'tokens',(SELECT count(*) FROM oauth_tokens t JOIN users u ON u.id=t.user_id WHERE u.saml_idp_entity_id='idfed3'))::text",&[]).await?;
    Ok(serde_json::from_str(&r.get::<_, String>(0))?)
}

pub async fn access_age(
    c: &tokio_postgres::Client,
    user: i64,
    acr: &str,
    jti: &str,
    age: u64,
) -> Result<String, Err> {
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&user])
        .await?
        .get(0);
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
    keys.sign(&json!({"uid":user,"email":email,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-age,"nbf":now-age,"exp":now+3600,"jti":jti,"fam":"idfed3-family","acr":acr,"amr":["pwd","otp"]}).to_string()).map_err(Into::into)
}

pub async fn access(
    c: &tokio_postgres::Client,
    user: i64,
    acr: &str,
    jti: &str,
) -> Result<String, Err> {
    access_age(c, user, acr, jti, 60).await
}
