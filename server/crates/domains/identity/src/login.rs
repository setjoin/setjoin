//! Password proof is the identity source here; request uid/mailbox fields are ignored.
use serde_json::{json, Value};
use setjoin_pg::{AuthDb, StatementFailure, Type};
use sha2::{Digest, Sha256};

/// Sealed proof of the exact enabled local credential version that was verified.
pub struct PasswordProof {
    user: i64,
    email: String,
    hash: String,
    pub admin: bool,
    pub totp: bool,
    pub push: bool,
    pub force_change: bool,
}
impl PasswordProof {
    pub fn user(&self) -> i64 {
        self.user
    }
    pub fn email(&self) -> &str {
        &self.email
    }
}

const DUMMY_BCRYPT: &str = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
const DUMMY_SM3: &str =
    "$sm3$100000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// The fixed hash an unknown email is verified against: the same algorithm and cost
/// the profile writes (PBKDF2-SM3 100k for smx/hybrid, bcrypt 10 otherwise), so
/// timing reveals no account under any profile.
pub fn dummy_hash(profile: setjoin_config_secret::CryptoProfile) -> &'static str {
    use setjoin_config_secret::CryptoProfile::{Hybrid, Smx};
    if matches!(profile, Smx | Hybrid)
        && !setjoin_contracts::mutants::on("login-dummy-always-bcrypt")
    {
        DUMMY_SM3
    } else {
        DUMMY_BCRYPT
    }
}

// Keep absent, disabled and unreadable credentials on the same password-cost path (#487).
async fn verify_dummy(password: &str, profile: setjoin_config_secret::CryptoProfile) {
    if !setjoin_contracts::mutants::on("login-no-dummy-hash") {
        let password = password.to_owned();
        let _ = tokio::task::spawn_blocking(move || {
            setjoin_authz::password::verify(dummy_hash(profile), &password)
        })
        .await;
    }
}

pub async fn verify(
    exec: &AuthDb,
    email: &str,
    password: &str,
    profile: setjoin_config_secret::CryptoProfile,
) -> Result<Option<PasswordProof>, StatementFailure> {
    let rows = exec
        .read_contract(&crate::sql::LOGIN_L56, &[(&email, Type::TEXT)])
        .await?;
    let Some(r) = rows.first() else {
        verify_dummy(password, profile).await;
        return Ok(None);
    };
    let invalid_proof = |_| StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid password proof row".into(),
    };
    let hash: String = match r.try_get(2) {
        Ok(hash) => hash,
        Err(err) => {
            verify_dummy(password, profile).await;
            return Err(invalid_proof(err));
        }
    };
    let password = password.to_owned();
    let stored = hash.clone();
    let valid =
        tokio::task::spawn_blocking(move || setjoin_authz::password::verify(&stored, &password))
            .await
            .unwrap_or(false);
    if !valid {
        return Ok(None);
    }
    Ok(Some(PasswordProof {
        user: r.try_get(0).map_err(invalid_proof)?,
        email: r.try_get(1).map_err(invalid_proof)?,
        hash,
        admin: r.try_get(3).map_err(invalid_proof)?,
        totp: r.try_get(4).map_err(invalid_proof)?,
        push: r.try_get(5).map_err(invalid_proof)?,
        force_change: r.try_get(6).map_err(invalid_proof)?,
    }))
}
pub async fn mfa_status(exec: &AuthDb, p: &PasswordProof) -> Result<String, StatementFailure> {
    Ok(mfa_policy(exec, p).await?["status"]
        .as_str()
        .ok_or_else(invalid)?
        .into())
}
pub async fn mfa_policy(exec: &AuthDb, p: &PasswordProof) -> Result<Value, StatementFailure> {
    let rows = exec
        .protocol_query_contract(&crate::sql::LOGIN_L96, &[(&p.user, Type::INT8)])
        .await?;
    let raw: String = rows
        .first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(invalid)?;
    let v: Value = serde_json::from_str(&raw).map_err(|_| invalid())?;
    if v.get("message")
        .is_some_and(|v| !v.is_null() && !v.is_string())
    {
        return Err(invalid());
    }
    match v["status"].as_str() {
        Some("exempt" | "enrolled" | "enrollment_required" | "optional") => Ok(v),
        _ => Err(invalid()),
    }
}
impl PasswordProof {
    pub fn credential_fence(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(self.hash.as_bytes()))
    }
}
pub async fn bootstrap_mfa_grant(
    exec: &AuthDb,
    p: &PasswordProof,
    token: &str,
    jti: &str,
) -> setjoin_pg::CommandOutcome<bool, StatementFailure> {
    let exec = exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand {
        family: "F21",
        command: "mfa-bootstrap-grant",
    });
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    exec.run_user_command_contract(
        setjoin_contracts::ids::ActorId::new(p.user).expect("password proof"),
        setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes()),
        &crate::sql::LOGIN_L112,
        &[
            (&p.user, Type::INT8),
            (&p.hash, Type::TEXT),
            (&hash, Type::TEXT),
            (&jti, Type::TEXT),
        ],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get::<_, bool>(0).ok())
                .ok_or_else(invalid)
        },
    )
    .await
}
pub async fn guest_scope(exec: &AuthDb, p: &PasswordProof) -> Result<bool, StatementFailure> {
    let rows = exec
        .protocol_query_contract(&crate::sql::IS_GUEST_ACCOUNT, &[(&p.user, Type::INT8)])
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}
#[derive(Debug)]
pub enum AdmissionFailure {
    Transition(StatementFailure),
    AccountType(StatementFailure),
}
pub async fn admission(exec: &AuthDb, p: &PasswordProof) -> Result<(bool, bool), AdmissionFailure> {
    let rows = exec
        .read_contract(&crate::sql::LOGIN_L137, &[(&p.user, Type::INT8)])
        .await
        .map_err(AdmissionFailure::Transition)?;
    let allowed = rows
        .first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
        .map_err(AdmissionFailure::Transition)?;
    if !allowed {
        return Ok((false, false));
    }
    Ok((
        true,
        guest_scope(exec, p)
            .await
            .map_err(AdmissionFailure::AccountType)?,
    ))
}
pub async fn domain_scope(
    exec: &AuthDb,
    p: &PasswordProof,
) -> Result<Option<i64>, StatementFailure> {
    if !p.admin {
        return Ok(None);
    }
    let rows = exec
        .read_contract(&crate::sql::LOGIN_L164, &[(&p.user, Type::INT8)])
        .await?;
    rows.first()
        .ok_or_else(invalid)?
        .try_get::<_, Option<i64>>(0)
        .map_err(|_| invalid())
}
pub async fn mint(
    exec: &AuthDb,
    p: &PasswordProof,
    refresh: &str,
    expiry: i64,
    family: &str,
) -> setjoin_pg::CommandOutcome<bool, StatementFailure> {
    let hash = Sha256::digest(refresh.as_bytes()).to_vec();
    let operation = setjoin_contracts::ids::OperationId(
        *uuid::Uuid::parse_str(family)
            .expect("server family UUID")
            .as_bytes(),
    );
    exec.run_user_command_contract(
        setjoin_contracts::ids::ActorId::new(p.user).expect("proven user"),
        operation,
        &crate::sql::LOGIN_L186,
        &[
            (&p.user, Type::INT8),
            (&p.hash, Type::TEXT),
            (&hash, Type::BYTEA),
            (&expiry, Type::INT8),
            (&family, Type::TEXT),
        ],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid)
        },
    )
    .await
}
/// Current-authority lookup after a lost autocommit result. Callers must
/// re-prove the credential; the family UUID is only a correlation id.
pub async fn lookup_mint(
    exec: &AuthDb,
    p: &PasswordProof,
    family: &str,
) -> Result<bool, StatementFailure> {
    let operation = setjoin_contracts::ids::OperationId(
        *uuid::Uuid::parse_str(family)
            .map_err(|_| invalid())?
            .as_bytes(),
    );
    let result = exec
        .run_user_command_contract(
            setjoin_contracts::ids::ActorId::new(p.user).map_err(|_| invalid())?,
            operation,
            &crate::sql::LOGIN_L215,
            &[
                (&p.user, Type::INT8),
                (&family, Type::TEXT),
                (&p.hash, Type::TEXT),
            ],
            |rows| {
                rows.first()
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
/// Go's independent best-effort tail writes stay independent. A failure must
/// neither undo a committed refresh family nor falsely claim a log was written.
pub async fn record_success(
    exec: &AuthDb,
    p: &PasswordProof,
    access: &str,
    jti: &str,
    expiry: i64,
    ip: &str,
    agent: &str,
) {
    let _ = exec
        .protocol_statement_contract(
            &crate::sql::LOGIN_L234,
            &[
                (&p.user, Type::INT8),
                (&p.email, Type::TEXT),
                (&ip, Type::TEXT),
            ],
        )
        .await;
    let _ = exec
        .protocol_statement_contract(
            &crate::sql::LOGIN_L237,
            &[(&Some(p.user), Type::INT8), (&ip, Type::TEXT)],
        )
        .await;
    let hash = Sha256::digest(access.as_bytes()).to_vec();
    let _ = exec
        .protocol_statement_contract(
            &crate::sql::LOGIN_L242,
            &[
                (&jti, Type::TEXT),
                (&p.user, Type::INT8),
                (&hash, Type::BYTEA),
                (&expiry, Type::INT8),
                (&ip, Type::TEXT),
                (&agent, Type::TEXT),
            ],
        )
        .await;
}
pub async fn record_failure(exec: &AuthDb, email: &str, ip: &str) {
    let rows = exec
        .read_contract(&crate::sql::LOGIN_L247, &[(&email, Type::TEXT)])
        .await;
    let user: Option<i64> = rows.ok().and_then(|rows| rows.first()?.try_get(0).ok());
    // verifyPassword logs no user id, even for a known user's wrong password.
    let details = if user.is_none() {
        Some(r#"{"reason":"user_not_found"}"#)
    } else {
        None
    };
    let _ = exec
        .protocol_statement_contract(
            &crate::sql::LOGIN_L258,
            &[
                (&email, Type::TEXT),
                (&ip, Type::TEXT),
                (&details, Type::TEXT),
            ],
        )
        .await;
    let _ = exec
        .protocol_statement_contract(
            &crate::sql::LOGIN_L261,
            &[(&user, Type::INT8), (&ip, Type::TEXT)],
        )
        .await;
}
/// Default-OFF feature controls; a failed lookup stays unresolved.
pub async fn enabled(exec: &AuthDb, key: &str) -> Result<bool, StatementFailure> {
    let rows = exec
        .read_contract(&crate::sql::LOGIN_L270, &[(&key, Type::TEXT)])
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}
#[allow(clippy::too_many_arguments)]
pub fn claims(
    p: &PasswordProof,
    typ: &str,
    jti: &str,
    family: &str,
    issuer: &str,
    now: i64,
    expiry: i64,
    domain: Option<i64>,
) -> Value {
    let mut c = json!({"uid":p.user,"email":p.email,"typ":typ,"iss":issuer,"sub":p.user.to_string(),"aud":["mailserver-gateway"],"exp":now+expiry,"nbf":now,"iat":now});
    if !jti.is_empty() {
        c["jti"] = json!(jti);
    }
    if !family.is_empty() {
        c["fam"] = json!(family);
    }
    if typ == "access" {
        c["acr"] = json!("aal1");
        c["amr"] = json!(["pwd"]);
        if p.admin {
            c["admin"] = json!(true);
        }
        if let Some(d) = domain {
            c["domain"] = json!(d);
        }
    }
    c
}
pub(crate) fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid MFA status".into(),
    }
}

pub fn random_jti() -> Result<String, String> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "random jti failed")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
/// #454: a feature-flag or risk query error (also with the flag off), an invalid actor and
/// an unreadable or unparsable stored value fail closed (no panicking decode); only a missing
/// row or level none/empty is "no risk claim". `user_risk.score` is smallint, read as int4.
pub async fn risk(exec: &AuthDb, p: &PasswordProof) -> Result<Option<Value>, StatementFailure> {
    risk_for_user(exec, p.user).await
}

/// Read-only risk lookup for a verified user id (shared with #454 fail-closed tests).
pub async fn risk_for_user(exec: &AuthDb, user: i64) -> Result<Option<Value>, StatementFailure> {
    let bad = || StatementFailure {
        sqlstate: None,
        hint: None,
        message: "user risk row".into(),
    };
    if !enabled(exec, "feature.user_risk").await? {
        return Ok(None);
    }
    let actor = setjoin_contracts::ids::ActorId::new(user).map_err(|_| bad())?;
    let rows = exec
        .read_user_scoped_contract(actor, &crate::sql::LOGIN_L344, &[(&user, Type::INT8)])
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
