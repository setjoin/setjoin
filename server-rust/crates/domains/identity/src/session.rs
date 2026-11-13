//! Established-session proof and profile. Identity comes only from a verified JWT.
use serde_json::{json, Map, Value};
use setjoin_authz::{legacy_jwt::LegacyKeys, signing_keys::KeySet};
use setjoin_pg::{ScopedExecutor, Type};

pub struct Session {
    claims: Map<String, Value>,
    hash: Vec<u8>,
}
impl Session {
    pub fn verify(
        token: &str,
        keys: Option<&KeySet>,
        legacy: &LegacyKeys,
        issuer: &str,
    ) -> Option<Self> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs_f64();
        let claims = keys
            .and_then(|k| k.validate(token, issuer, now))
            .or_else(|| legacy.validate(token, issuer, "mailserver-gateway", now))?;
        for key in ["uid", "act", "domain"] {
            if claims
                .get(key)
                .is_some_and(|v| !v.is_null() && v.as_i64().is_none())
            {
                return None;
            }
        }
        for key in ["email", "typ", "jti", "fam", "acct"] {
            if claims
                .get(key)
                .is_some_and(|v| !v.is_null() && !v.is_string())
            {
                return None;
            }
        }
        if claims
            .get("admin")
            .is_some_and(|v| !v.is_null() && !v.is_boolean())
        {
            return None;
        }
        use sha2::{Digest, Sha256};
        Some(Self {
            claims,
            hash: Sha256::digest(token.as_bytes()).to_vec(),
        })
    }
    pub(crate) fn token_hash(&self) -> &[u8] {
        &self.hash
    }
    pub fn user(&self) -> i64 {
        self.claims.get("uid").and_then(Value::as_i64).unwrap_or(0)
    }
    pub fn text(&self, key: &str) -> &str {
        self.claims.get(key).and_then(Value::as_str).unwrap_or("")
    }
    pub fn claims(&self) -> &Map<String, Value> {
        &self.claims
    }
    pub fn bound(&self) -> bool {
        self.claims
            .get("cnf")
            .and_then(|v| v.get("jkt"))
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
    }
    /// Opaque commit metadata only, under a freshly verified refresh credential
    /// and the same user/operation lock. A revoked/disabled proof is an error,
    /// never a false claim that an operation was absent.
    pub async fn lookup_refresh(
        &self,
        exec: &ScopedExecutor,
        operation: setjoin_contracts::ids::OperationId,
    ) -> Result<bool, setjoin_pg::StatementFailure> {
        let invalid = || setjoin_pg::StatementFailure {
            sqlstate: None,
            hint: None,
            message: "refresh lookup authority unavailable".into(),
        };
        if self.text("typ") != "refresh" {
            return Err(invalid());
        }
        let user = setjoin_contracts::ids::ActorId::new(self.user()).map_err(|_| invalid())?;
        let op = uuid::Uuid::from_bytes(operation.0).to_string();
        let result=exec.run_user_command(user,operation,"SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=$3::text::uuid AND family='F21' AND command='refresh') WHERE EXISTS(SELECT 1 FROM users u JOIN oauth_tokens o ON o.user_id=u.id WHERE u.id=$1 AND u.enabled AND o.user_id=$1 AND o.token_hash=$2 AND o.revoked_at IS NULL AND o.expires_at>now() AND identity_transition_admission_allowed(u.id))",&[(&self.user(),Type::INT8),(&self.hash,Type::BYTEA),(&op,Type::TEXT)],|r|r.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await;
        match result {
            setjoin_pg::CommandOutcome::Committed(v) => Ok(v),
            _ => Err(invalid()),
        }
    }
    pub async fn risk(&self, exec: &ScopedExecutor) -> Option<Value> {
        if !super::login::enabled(exec, "feature.user_risk")
            .await
            .unwrap_or(false)
        {
            return None;
        }
        let rows = exec
            .read_user_scoped(
                setjoin_contracts::ids::ActorId::new(self.user()).ok()?,
                "SELECT score,level,signals::text FROM user_risk WHERE user_id=$1",
                &[(&self.user(), Type::INT8)],
            )
            .await
            .ok()?;
        let r = rows.first()?;
        let level: String = r.get(1);
        if level.is_empty() || level == "none" {
            return None;
        }
        let signals: Value = serde_json::from_str(&r.get::<_, String>(2)).unwrap_or(Value::Null);
        Some(
            json!({"user_score":r.get::<_,i32>(0),"level":level,"requires_mfa":level=="medium"||level=="high","signals":signals}),
        )
    }
    pub async fn refresh(
        &self,
        exec: &ScopedExecutor,
        hash: &[u8],
        expected: Option<&Value>,
        new_hash: Option<&[u8]>,
        expiry: i64,
        family: &str,
        operation: setjoin_contracts::ids::OperationId,
    ) -> setjoin_pg::CommandOutcome<Value, setjoin_pg::StatementFailure> {
        let Ok(actor) = setjoin_contracts::ids::ActorId::new(self.user()) else {
            return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable);
        };
        let expected = expected.map(Value::to_string);
        let claim_family = self.text("fam");
        let write = expected.is_some();
        let user = self.user();
        exec.run_user_command_with_tail(actor,operation,"SELECT rust_identity_refresh($1,$2,$3,$4::text::jsonb,$5,$6,$7::text::uuid)::text",&[(&self.user(),Type::INT8),(&hash,Type::BYTEA),(&claim_family,Type::TEXT),(&expected,Type::TEXT),(&new_hash,Type::BYTEA),(&expiry,Type::INT8),(&family,Type::TEXT)],|rows|{let raw:String=rows[0].get(0);serde_json::from_str(&raw).map_err(|_|setjoin_pg::StatementFailure{sqlstate:None,hint:None,message:"refresh result".into()})},|value:&Value|{
            let record=write && value["status"]=="mint";let email=value["email"].as_str().unwrap_or("").to_owned();
            async move {if record {let _=exec.protocol_statement("INSERT INTO auth_event_log(user_id,event,provider,email) VALUES($1,'login','jwt',NULLIF($2,''))",&[(&user,Type::INT8),(&email,Type::TEXT)]).await;}}
        }).await
    }
    pub async fn revoke(
        &self,
        exec: &ScopedExecutor,
        operation: setjoin_contracts::ids::OperationId,
    ) -> setjoin_pg::CommandOutcome<i64, setjoin_pg::StatementFailure> {
        let Ok(actor) = setjoin_contracts::ids::ActorId::new(self.user()) else {
            return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable);
        };
        exec.run_user_command(
            actor,
            operation,
            "SELECT revoke_user_sessions($1,'all','token_revoke_all',NULL,NULL,NULL)",
            &[(&self.user(), Type::INT8)],
            |rows| {
                rows[0]
                    .try_get(0)
                    .map_err(|_| setjoin_pg::StatementFailure {
                        sqlstate: None,
                        hint: None,
                        message: "revocation result".into(),
                    })
            },
        )
        .await
    }
    pub async fn me(&self, exec: &ScopedExecutor) -> Result<Value, &'static str> {
        let user = self.user();
        let rows=exec.read("SELECT EXISTS(SELECT 1 FROM admin_role_assignments ara WHERE ara.user_id=u.id AND (ara.expires_at IS NULL OR ara.expires_at>now())),EXISTS(SELECT 1 FROM mailboxes WHERE user_id=u.id AND is_primary=true LIMIT 1),COALESCE(u.totp_enabled,false),(to_jsonb(u.totp_enabled_at AT TIME ZONE 'UTC')#>>'{}'),COALESCE(u.display_name,''),u.email FROM users u WHERE u.id=$1",&[(&user,Type::INT8)]).await.map_err(|_|"profile lookup failed")?;
        let r = rows.first().ok_or("profile lookup failed")?;
        let delegates=exec.read("SELECT mb.id,mb.email,md.permission FROM mailbox_delegates md JOIN mailboxes mb ON mb.id=md.mailbox_id WHERE md.user_id=$1 AND md.permission IN ('send_as','full_access') AND mb.enabled=true ORDER BY lower(mb.email),mb.id",&[(&user,Type::INT8)]).await.unwrap_or_default().iter().map(|r|json!({"id":r.get::<_,i64>(0),"email":r.get::<_,String>(1),"permission":r.get::<_,String>(2)})).collect::<Vec<_>>();
        let aliases=exec.read("SELECT a.email FROM aliases a JOIN mailboxes m ON m.id=a.mailbox_id JOIN users u ON u.id=m.user_id WHERE m.user_id=$1 AND m.is_primary=true AND m.enabled=true AND lower(a.email)<>lower(u.email) ORDER BY lower(a.email),a.id",&[(&user,Type::INT8)]).await.unwrap_or_default().iter().map(|r|json!({"email":r.get::<_,String>(0)})).collect::<Vec<_>>();
        let guest = exec
            .read("SELECT is_guest_account($1)", &[(&user, Type::INT8)])
            .await
            .map_err(|_| "account type lookup failed")?[0]
            .get::<_, bool>(0);
        let at: Option<String> = r.get(3);
        let mut out = json!({"user_id":user,"email":r.get::<_,String>(5),"display_name":r.get::<_,String>(4),"is_admin":r.get::<_,bool>(0),"has_mailbox":r.get::<_,bool>(1),"totp_enabled":r.get::<_,bool>(2),"totp_enabled_at":at.map(|s|s+"Z"),"delegates":delegates,"aliases":aliases,"account_type":if guest {"guest"}else{"member"}});
        if let Some(actor) = self.claims.get("act").filter(|v| !v.is_null()) {
            out["impersonating"] = json!(true);
            out["actor_id"] = actor.clone();
        }
        Ok(out)
    }
}
