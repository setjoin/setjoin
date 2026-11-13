//! Password proof is the identity source here; request uid/mailbox fields are ignored.
use serde_json::{json, Value};
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};
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
const DUMMY_SM3: &str = "$sm3$100000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// The fixed hash an unknown email is verified against: the same algorithm and cost
/// the profile writes (PBKDF2-SM3 100k for smx/hybrid, bcrypt 10 otherwise), so
/// timing reveals no account under any profile.
pub fn dummy_hash(profile: setjoin_config_secret::CryptoProfile) -> &'static str {
    use setjoin_config_secret::CryptoProfile::{Hybrid, Smx};
    if matches!(profile, Smx | Hybrid) && !setjoin_contracts::mutants::on("login-dummy-always-bcrypt") {
        DUMMY_SM3
    } else {
        DUMMY_BCRYPT
    }
}

pub async fn verify(
    exec: &ScopedExecutor,
    email: &str,
    password: &str,
    profile: setjoin_config_secret::CryptoProfile,
) -> Result<Option<PasswordProof>, StatementFailure> {
    let rows=exec.read("SELECT id,email,password_hash,EXISTS(SELECT 1 FROM admin_role_assignments ara WHERE ara.user_id=users.id AND (ara.expires_at IS NULL OR ara.expires_at>now())), COALESCE(totp_enabled,false),COALESCE(push_mfa_enabled,false),COALESCE(must_change_password,false) FROM users WHERE lower(email)=lower($1) AND enabled=true",&[(&email,Type::TEXT)]).await?;
    let Some(r) = rows.first() else {
        // Owner-approved security fix 2026-11-05 (#487): an unknown or disabled
        // email costs the same password hash as a known one, so response timing
        // does not reveal which accounts exist.
        if !setjoin_contracts::mutants::on("login-no-dummy-hash") {
            let password = password.to_owned();
            let _ = tokio::task::spawn_blocking(move || {
                setjoin_authz::password::verify(dummy_hash(profile), &password)
            })
            .await;
        }
        return Ok(None);
    };
    let hash: String = r.get(2);
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
        user: r.get(0),
        email: r.get(1),
        hash,
        admin: r.get(3),
        totp: r.get(4),
        push: r.get(5),
        force_change: r.get(6),
    }))
}
pub async fn mfa_status(exec:&ScopedExecutor,p:&PasswordProof)->Result<String,StatementFailure>{
    Ok(mfa_policy(exec,p).await?["status"].as_str().ok_or_else(invalid)?.into())
}
pub async fn mfa_policy(exec:&ScopedExecutor,p:&PasswordProof)->Result<Value,StatementFailure>{
    let rows=exec.read("SELECT mfa_status($1)::text",&[(&p.user,Type::INT8)]).await?;
    let v:Value=serde_json::from_str(&rows[0].get::<_,String>(0)).map_err(|_|invalid())?;
    if v.get("message").is_some_and(|v|!v.is_null()&&!v.is_string()){return Err(invalid())}
    match v["status"].as_str(){Some("exempt"|"enrolled"|"enrollment_required"|"optional")=>Ok(v),_=>Err(invalid())}
}
impl PasswordProof {
    pub fn credential_fence(&self)->String{
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(self.hash.as_bytes()))
    }
}
pub async fn bootstrap_mfa_grant(exec:&ScopedExecutor,p:&PasswordProof,token:&str,jti:&str)->setjoin_pg::CommandOutcome<bool,StatementFailure>{
    let exec=exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F21",command:"mfa-bootstrap-grant"});
    let hash=format!("{:x}",Sha256::digest(token.as_bytes()));
    exec.run_user_command(setjoin_contracts::ids::ActorId::new(p.user).expect("password proof"),setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes()),
        "SELECT rust_identity_mfa_bootstrap_grant($1,$2,$3,$4)",
        &[(&p.user,Type::INT8),(&p.hash,Type::TEXT),(&hash,Type::TEXT),(&jti,Type::TEXT)],|rows|Ok(rows[0].get(0))).await
}
pub async fn guest_scope(
    exec: &ScopedExecutor,
    p: &PasswordProof,
) -> Result<bool, StatementFailure> {
    let rows = exec
        .read("SELECT is_guest_account($1)", &[(&p.user, Type::INT8)])
        .await?;
    Ok(rows[0].get(0))
}
#[derive(Debug)]
pub enum AdmissionFailure {
    Transition(StatementFailure),
    AccountType(StatementFailure),
}
pub async fn admission(
    exec: &ScopedExecutor,
    p: &PasswordProof,
) -> Result<(bool, bool), AdmissionFailure> {
    let rows = exec
        .read(
            "SELECT identity_transition_admission_allowed($1)",
            &[(&p.user, Type::INT8)],
        )
        .await
        .map_err(AdmissionFailure::Transition)?;
    if !rows[0].get::<_, bool>(0) {
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
    exec: &ScopedExecutor,
    p: &PasswordProof,
) -> Result<Option<i64>, StatementFailure> {
    if !p.admin {
        return Ok(None);
    }
    let rows=exec.read("SELECT MIN(COALESCE(ra.domain_override,rg.domain_scope)) FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$1 AND COALESCE(ra.domain_override,rg.domain_scope) IS NOT NULL AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)",&[(&p.user,Type::INT8)]).await?;
    Ok(rows[0].get(0))
}
pub async fn mint(
    exec: &ScopedExecutor,
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
    exec.run_user_command(
        setjoin_contracts::ids::ActorId::new(p.user).expect("proven user"),
        operation,
        "SELECT rust_identity_login_mint($1,$2,$3,$4,$5::text::uuid)",
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
    exec: &ScopedExecutor,
    p: &PasswordProof,
    family: &str,
) -> Result<bool, StatementFailure> {
    let operation = setjoin_contracts::ids::OperationId(
        *uuid::Uuid::parse_str(family)
            .map_err(|_| invalid())?
            .as_bytes(),
    );
    let result=exec.run_user_command(setjoin_contracts::ids::ActorId::new(p.user).map_err(|_|invalid())?,operation,
        "SELECT EXISTS(SELECT 1 FROM oauth_tokens o JOIN users u ON u.id=o.user_id WHERE o.user_id=$1 AND o.family_id=$2::text::uuid AND u.enabled AND u.password_hash=$3 AND o.revoked_at IS NULL AND o.expires_at>now())",
        &[(&p.user,Type::INT8),(&family,Type::TEXT),(&p.hash,Type::TEXT)],
        |rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await;
    match result {
        setjoin_pg::CommandOutcome::Committed(v) => Ok(v),
        _ => Err(invalid()),
    }
}
/// Go's independent best-effort tail writes stay independent. A failure must
/// neither undo a committed refresh family nor falsely claim a log was written.
pub async fn record_success(
    exec: &ScopedExecutor,
    p: &PasswordProof,
    access: &str,
    jti: &str,
    expiry: i64,
    ip: &str,
    agent: &str,
) {
    let _=exec.protocol_statement("INSERT INTO auth_event_log(user_id,event,provider,email,ip_address) VALUES($1,'login','jwt',NULLIF($2,''),NULLIF($3,'')::inet)",&[(&p.user,Type::INT8),(&p.email,Type::TEXT),(&ip,Type::TEXT)]).await;
    let _ = exec
        .read(
            "SELECT rust_identity_signin_record($1,true,$2)",
            &[(&Some(p.user), Type::INT8), (&ip, Type::TEXT)],
        )
        .await;
    let hash = Sha256::digest(access.as_bytes()).to_vec();
    let _=exec.protocol_statement("INSERT INTO sessions(id,user_id,token_hash,expires_at,ip,user_agent,auth_method) VALUES($1,$2,$3,now()+make_interval(secs=>$4),NULLIF($5,'')::inet,$6,'password') ON CONFLICT(id) DO NOTHING",&[(&jti,Type::TEXT),(&p.user,Type::INT8),(&hash,Type::BYTEA),(&expiry,Type::INT8),(&ip,Type::TEXT),(&agent,Type::TEXT)]).await;
}
pub async fn record_failure(exec: &ScopedExecutor, email: &str, ip: &str) {
    let rows = exec
        .read(
            "SELECT id FROM users WHERE lower(email)=lower($1) AND enabled=true",
            &[(&email, Type::TEXT)],
        )
        .await;
    let user: Option<i64> = rows.as_ref().ok().and_then(|r| r.first()).map(|r| r.get(0));
    // verifyPassword logs no user id, even for a known user's wrong password.
    let details = if user.is_none() {
        Some(r#"{"reason":"user_not_found"}"#)
    } else {
        None
    };
    let _=exec.protocol_statement("INSERT INTO auth_event_log(user_id,event,provider,email,ip_address,details) VALUES(NULL,'login_failed','bcrypt',NULLIF($1,''),NULLIF($2,'')::inet,$3::text::jsonb)",&[(&email,Type::TEXT),(&ip,Type::TEXT),(&details,Type::TEXT)]).await;
    let _ = exec
        .read(
            "SELECT rust_identity_signin_record($1,false,$2)",
            &[(&user, Type::INT8), (&ip, Type::TEXT)],
        )
        .await;
}
/// Default-OFF feature controls; a failed lookup stays unresolved.
pub async fn enabled(exec: &ScopedExecutor, key: &str) -> Result<bool, StatementFailure> {
    let rows = exec
        .read(
            "SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key=$1),false)",
            &[(&key, Type::TEXT)],
        )
        .await?;
    Ok(rows[0].get(0))
}
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
fn invalid() -> StatementFailure {
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
pub async fn risk(exec: &ScopedExecutor, p: &PasswordProof) -> Option<Value> {
    if !enabled(exec, "feature.user_risk").await.unwrap_or(false) {
        return None;
    }
    let rows = exec
        .read_user_scoped(
            setjoin_contracts::ids::ActorId::new(p.user).ok()?,
            "SELECT score,level,signals::text FROM user_risk WHERE user_id=$1",
            &[(&p.user, Type::INT8)],
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
