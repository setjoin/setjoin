//! Established-session proof and profile. Identity comes only from a verified JWT.
use serde_json::{json, Map, Value};
use setjoin_authz::{legacy_jwt::LegacyKeys, signing_keys::KeySet};
use setjoin_pg::{AuthDb, Type};

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
        self.bound_jkt().is_some()
    }
    pub fn bound_jkt(&self) -> Option<&str> {
        self.claims
            .get("cnf")
            .and_then(|v| v.get("jkt"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    }
    /// Opaque commit metadata only, under a freshly verified refresh credential
    /// and the same user/operation lock. A revoked/disabled proof is an error,
    /// never a false claim that an operation was absent.
    pub async fn lookup_refresh(
        &self,
        exec: &AuthDb,
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
        let result = exec
            .run_user_command_contract(
                user,
                operation,
                &crate::sql::SESSION_L92,
                &[
                    (&self.user(), Type::INT8),
                    (&self.hash, Type::BYTEA),
                    (&op, Type::TEXT),
                ],
                |r| {
                    r.first()
                        .and_then(|r| r.try_get(0).ok())
                        .ok_or_else(invalid)
                },
            )
            .await;
        match result {
            setjoin_pg::CommandOutcome::Committed(v) => Ok(v),
            _ => Err(invalid()),
        }
    }
    /// #454: a feature-flag or risk query error (also with the flag off), an invalid actor
    /// and an unreadable or unparsable stored value fail closed; only a missing row or level
    /// none/empty is "no risk claim". `user_risk.score` is smallint, read as int4.
    pub async fn risk(&self, exec: &AuthDb) -> Result<Option<Value>, setjoin_pg::StatementFailure> {
        let bad = || setjoin_pg::StatementFailure {
            sqlstate: None,
            hint: None,
            message: "user risk row".into(),
        };
        if !super::login::enabled(exec, "feature.user_risk").await? {
            return Ok(None);
        }
        let actor = setjoin_contracts::ids::ActorId::new(self.user()).map_err(|_| bad())?;
        let rows = exec
            .read_user_scoped_contract(
                actor,
                &crate::sql::LOGIN_L344,
                &[(&self.user(), Type::INT8)],
            )
            .await?;
        let Some(r) = rows.first() else {
            return Ok(None);
        };
        let level: String = r.try_get(1).map_err(|_| bad())?;
        if level.is_empty() || level == "none" {
            return Ok(None);
        }
        let score: i32 = r.try_get(0).map_err(|_| bad())?;
        let raw: String = r.try_get(2).map_err(|_| bad())?;
        let signals: Vec<String> = serde_json::from_str(&raw).map_err(|_| bad())?;
        Ok(Some(
            json!({"user_score":score,"level":level,"requires_mfa":level=="medium"||level=="high","signals":signals}),
        ))
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn refresh(
        &self,
        exec: &AuthDb,
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
        exec.run_user_command_contract_with_tail(
            actor,
            operation,
            &crate::sql::SESSION_L149,
            &[
                (&self.user(), Type::INT8),
                (&hash, Type::BYTEA),
                (&claim_family, Type::TEXT),
                (&expected, Type::TEXT),
                (&new_hash, Type::BYTEA),
                (&expiry, Type::INT8),
                (&family, Type::TEXT),
            ],
            |rows| {
                let raw: String =
                    rows.first()
                        .and_then(|r| r.try_get(0).ok())
                        .ok_or_else(|| setjoin_pg::StatementFailure {
                            sqlstate: None,
                            hint: None,
                            message: "refresh result row".into(),
                        })?;
                serde_json::from_str(&raw).map_err(|_| setjoin_pg::StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: "refresh result".into(),
                })
            },
            |value: &Value| {
                let record = write && value["status"] == "mint";
                let email = value["email"].as_str().unwrap_or("").to_owned();
                async move {
                    if record {
                        let _ = exec
                            .protocol_statement_contract(
                                &crate::sql::SESSION_L151,
                                &[(&user, Type::INT8), (&email, Type::TEXT)],
                            )
                            .await;
                    }
                }
            },
        )
        .await
    }
    pub async fn revoke(
        &self,
        exec: &AuthDb,
        operation: setjoin_contracts::ids::OperationId,
    ) -> setjoin_pg::CommandOutcome<i64, setjoin_pg::StatementFailure> {
        let Ok(actor) = setjoin_contracts::ids::ActorId::new(self.user()) else {
            return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable);
        };
        exec.run_user_command_contract(
            actor,
            operation,
            &crate::sql::ISSUANCE_L388,
            &[(&self.user(), Type::INT8)],
            |rows| {
                rows.first().and_then(|r| r.try_get(0).ok()).ok_or_else(|| {
                    setjoin_pg::StatementFailure {
                        sqlstate: None,
                        hint: None,
                        message: "revocation result".into(),
                    }
                })
            },
        )
        .await
    }
    pub async fn me(&self, exec: &AuthDb) -> Result<Value, &'static str> {
        let user = self.user();
        let rows = exec
            .read_contract(&crate::sql::SESSION_L181, &[(&user, Type::INT8)])
            .await
            .map_err(|_| "profile lookup failed")?;
        let r = rows.first().ok_or("profile lookup failed")?;
        let delegates=exec.read_contract(&crate::sql::SESSION_L183,&[(&user,Type::INT8)]).await.unwrap_or_default().iter().map(|r|-> Result<Value,&'static str>{Ok(json!({"id":r.try_get::<_,i64>(0).map_err(|_|"profile lookup failed")?,"email":r.try_get::<_,String>(1).map_err(|_|"profile lookup failed")?,"permission":r.try_get::<_,String>(2).map_err(|_|"profile lookup failed")?}))}).collect::<Result<Vec<_>,&'static str>>()?;
        let aliases = exec
            .read_contract(&crate::sql::SESSION_L184, &[(&user, Type::INT8)])
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| -> Result<Value, &'static str> {
                Ok(json!({"email":r.try_get::<_,String>(0).map_err(|_|"profile lookup failed")?}))
            })
            .collect::<Result<Vec<_>, &'static str>>()?;
        let guest = exec
            .read_contract(&crate::sql::IS_GUEST_ACCOUNT, &[(&user, Type::INT8)])
            .await
            .map_err(|_| "account type lookup failed")?
            .first()
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .ok_or("account type lookup failed")?;
        let bad_profile = "profile lookup failed";
        let is_admin: bool = r.try_get(0).map_err(|_| bad_profile)?;
        let has_mailbox: bool = r.try_get(1).map_err(|_| bad_profile)?;
        let totp_enabled: bool = r.try_get(2).map_err(|_| bad_profile)?;
        let at: Option<String> = r.try_get(3).map_err(|_| bad_profile)?;
        let display_name: String = r.try_get(4).map_err(|_| bad_profile)?;
        let email: String = r.try_get(5).map_err(|_| bad_profile)?;
        let mut out = json!({"user_id":user,"email":email,"display_name":display_name,"is_admin":is_admin,"has_mailbox":has_mailbox,"totp_enabled":totp_enabled,"totp_enabled_at":at.map(|s|s+"Z"),"delegates":delegates,"aliases":aliases,"account_type":if guest {"guest"}else{"member"}});
        if let Some(actor) = self.claims.get("act").filter(|v| !v.is_null()) {
            out["impersonating"] = json!(true);
            out["actor_id"] = actor.clone();
        }
        Ok(out)
    }
}
