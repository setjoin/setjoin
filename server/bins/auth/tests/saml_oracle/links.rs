//! Established-session HTTP seam and committed owned identity effects.
use super::*;
use setjoin_conformance::{fixture, golden};
use sha2::{Digest, Sha256};
pub struct Env {
    pub base: flows::Env,
    pub a: fixture::Account,
    pub b: fixture::Account,
    pub token: String,
    pub other: String,
    pub link: i64,
    pub foreign_link: i64,
    receipts: Vec<String>,
}
impl Env {
    pub async fn start() -> Result<Self, Err> {
        Self::variant(false).await
    }
    pub async fn variant(mutant: bool) -> Result<Self, Err> {
        let base = flows::Env::start(mutant).await?;
        let a = fixture::account(&base.c, "idfed3-actor").await?;
        let b = fixture::account(&base.c, "idfed3-foreign").await?;
        let token = flows::access(&base.c, a.user, "aal2", "gofree-idfed3-session-a").await?;
        let other = flows::access(&base.c, b.user, "aal2", "gofree-idfed3-session-b").await?;
        for (user, jti, token) in [
            (a.user, "gofree-idfed3-session-a", &token),
            (b.user, "gofree-idfed3-session-b", &other),
        ] {
            base.c.execute("INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 hour','totp')",&[&jti,&user,&Sha256::digest(token.as_bytes()).to_vec()]).await?;
        }
        base.c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.identity_model_v2',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await?;
        let mut ids = Vec::new();
        for (user, subject) in [
            (a.user, "idfed3-actor-subject"),
            (b.user, "idfed3-foreign-subject"),
        ] {
            let row=base.c.query_one("SELECT identity_auth_link($1,$1,'saml','idfed3',$2,'saml:34101','IDFED3 fixture')->>'linkId'",&[&user,&subject]).await?;
            ids.push(row.get::<_, String>(0).parse()?);
        }
        base.c.execute("UPDATE user_identity_links SET first_seen_at='2026-10-30T00:00:00.123456Z',last_seen_at='2026-10-30T00:00:00.123456Z' WHERE user_id IN ($1,$2)",&[&a.user,&b.user]).await?;
        if base.recording {
            let probe = flows::access(&base.c, a.user, "aal1", "gofree-idfed3-probe").await?;
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                let r = request(
                    base.gw.addr,
                    "POST",
                    "/auth/saml/idfed3/link",
                    String::new(),
                    &[("authorization", &format!("Bearer {probe}"))],
                )
                .await?;
                if r.0 == 403 {
                    break;
                }
                if tokio::time::Instant::now() > deadline {
                    return Err(format!("Go identity feature not ready: {} {}", r.0, r.2).into());
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
        let receipts = common::receipt_ids(&base.c).await;
        Ok(Self {
            base,
            a,
            b,
            token,
            other,
            link: ids[0],
            foreign_link: ids[1],
            receipts,
        })
    }
    pub async fn close(self) -> Result<(), Err> {
        for user in [self.a.user, self.b.user] {
            self.base
                .c
                .execute("DELETE FROM sessions WHERE user_id=$1", &[&user])
                .await?;
            self.base
                .c
                .execute(
                    "DELETE FROM identity_auth_link_elevations WHERE user_id=$1",
                    &[&user],
                )
                .await?;
            self.base
                .c
                .execute(
                    "DELETE FROM identity_session_eviction_intents WHERE user_id=$1",
                    &[&user],
                )
                .await?;
            self.base
                .c
                .execute(
                    "DELETE FROM oauth_tokens WHERE user_id=$1 OR revoked_by=$1",
                    &[&user],
                )
                .await?;
            cleanup_identity(&self.base.c, user).await?;
        }
        common::restore_receipts(&self.base.c, &self.receipts).await;
        fixture::remove(&self.base.c, &self.a).await?;
        fixture::remove(&self.base.c, &self.b).await?;
        self.base.close().await
    }
    pub async fn effects(&self) -> Result<Value, Err> {
        let mut result = serde_json::Map::new();
        for (name, user, token) in [
            ("actor", self.a.user, &self.token),
            ("foreign", self.b.user, &self.other),
        ] {
            let row=self.base.c.query_one("SELECT jsonb_build_object('user',(SELECT jsonb_build_object('saml_name_id',saml_name_id,'saml_idp_entity_id',saml_idp_entity_id,'enabled',enabled,'password_set',password_hash IS NOT NULL AND password_hash<>'') FROM users WHERE id=$1),'links',(SELECT coalesce(jsonb_agg(jsonb_build_object('subject',external_subject,'state',state,'generation',generation,'purposes',purposes,'method',link_method,'detached_reason',detached_reason,'detached_by_owner',detached_by=$1) ORDER BY id),'[]') FROM user_identity_links WHERE user_id=$1),'elevations',(SELECT coalesce(jsonb_agg(jsonb_build_object('kind',kind,'provider',provider_key,'jti',session_jti,'hash_bound',session_hash=digest($2,'sha256'),'consumed',consumed_at IS NOT NULL) ORDER BY created_at,flow_id),'[]') FROM identity_auth_link_elevations WHERE user_id=$1),'sessions',(SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'hash_bound',token_hash=digest($2,'sha256'),'method',auth_method) ORDER BY id),'[]') FROM sessions WHERE user_id=$1),'tokens',(SELECT coalesce(jsonb_agg(jsonb_build_object('type',token_type,'revoked',revoked_at IS NOT NULL,'revoked_by_owner',revoked_by=$1) ORDER BY id),'[]') FROM oauth_tokens WHERE user_id=$1),'revocations',(SELECT coalesce(jsonb_agg(jsonb_build_object('scope',scope,'jti',jti,'family',family_id,'reason',reason,'created_by_owner',created_by=$1) ORDER BY id),'[]') FROM session_revocations WHERE user_id=$1),'events',(SELECT coalesce(jsonb_agg(jsonb_build_object('action',action,'reason',reason,'metadata',metadata,'actor_is_owner',actor_user_id=$1,'before_digest',before_digest IS NOT NULL,'after_digest',after_digest IS NOT NULL) ORDER BY id),'[]') FROM identity_link_events WHERE user_id=$1),'grants',(SELECT coalesce(jsonb_agg(jsonb_build_object('target',target_kind,'kind',entitlement_kind,'provenance',provenance_kind,'revoked',revoked_at IS NOT NULL,'generation',generation) ORDER BY id),'[]') FROM identity_entitlement_grants WHERE user_id=$1),'ws',(SELECT count(*) FROM ws_subscriptions WHERE user_id=$1),'evictions',(SELECT coalesce(jsonb_agg(jsonb_build_object('room',room_name,'reason',reason,'identity_bound',identity='u:'||$1::text,'attempt_count',attempt_count,'completed',completed_at IS NOT NULL) ORDER BY id),'[]') FROM identity_session_eviction_intents WHERE user_id=$1))::text",&[&user,&token.as_str()]).await?;
            result.insert(name.into(), serde_json::from_str(&row.get::<_, String>(0))?);
        }
        Ok(Value::Object(result))
    }
}
pub async fn cleanup_identity(c: &tokio_postgres::Client, user: i64) -> Result<(), Err> {
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
pub async fn list(kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = Env::start().await?;
    let result=async {
        let path=if kind=="cross-tenant"{format!("/auth/identity-links?user_id={}",env.b.user)}else{"/auth/identity-links".into()};
        if kind=="infinity" {env.base.c.execute("UPDATE user_identity_links SET last_seen_at='infinity' WHERE id=$1 AND user_id=$2",&[&env.link,&env.a.user]).await?;}
        let before=env.effects().await?;
        let native=if mutant {
            let native=Arc::new(AuthServer::load(setjoin_pg::ScopedExecutor::from_dsn(&std::env::var("DB_APP_DSN")?,4).unwrap(),flows::config()?).await?);
            Some(auth_server(native,true).await)
        }else{None};
        let mutant_gw=if let Some(auth)=&native{Some(gateway(auth.addr,None).await)}else{None};
        let addr=mutant_gw.as_ref().map_or(env.base.gw.addr,|g|g.addr);
        let cookie=format!("access_token={}",if kind=="invalid-input"{"invalid-token"}else{&env.token});
        let response=request(addr,"GET",&path,String::new(),&[("cookie",&cookie)]).await;
        if let Some(gw)=mutant_gw{gw.close().await;}if let Some(auth)=native{auth.close().await;}let response=response?;
        let text=response.2.replace(&format!("\"id\":\"{}\"",env.link),"\"id\":\"_actor_link\"").replace(&format!("\"id\":\"{}\"",env.foreign_link),"\"id\":\"_foreign_link\"");
        let actual=json!({"format":1,"go_source":SOURCE,"route":"GET /auth/identity-links","case":format!("list-{kind}"),"observation":{"request":{"method":"GET","path":"/auth/identity-links","query":if kind=="cross-tenant"{"user_id=_foreign"}else{""},"cookie":if kind=="invalid-input"{"_invalid"}else{"_actor_access"}},"response":{"status":response.0,"headers":response.1,"body":text},"effects":{"before":before,"after":env.effects().await?},"audit":[],"notify":[],"outbound":[]}});
        if mutant {
            let expected:Value=flows::expected_for(&corpus().join("goldens/list-success.json"),&actual)?;let error=golden::compare(&expected,&actual).expect_err("list wire status mutant survived");if !error.contains("/observation/response/status"){return Err(error.into());}flows::qualified_compare(&actual,true)?;Ok(())
        }else{flows::check(&format!("list-{kind}"),&actual,env.base.recording)}
    }.await;
    env.close().await?;
    result
}
