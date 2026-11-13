//! TOTP authority accepts only the signature-verified session principal.
use crate::session::Session;
use setjoin_contracts::ids::{ActorId, OperationId};
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};
use sha2::{Digest, Sha256};

/// Code-owned lookup categories; request JSON never supplies receipt names.
#[derive(Clone, Copy)]
pub enum Operation {
    Remove,
    Cycle,
    Begin,
    Setup,
    Confirm,
    BootstrapSetup,
    BootstrapConfirm,
    BootstrapGrant,
    Mint,
    PasswordGrant,
    TotpGrant,
    BackupGenerate,
    BackupConsume,
    NativeRegister,
    PushHarvest,
    PushApprove,
    PushSend,
    WebauthnPossessionBegin,
    WebauthnPossessionFinish,
    RecoveryBudget,
    RecoveryPush,
}
impl Operation {
    fn command(self) -> &'static str {
        match self {
            Self::Remove => "mfa-remove",
            Self::Cycle => "mfa-cycle",
            Self::Begin => "mfa-begin",
            Self::Setup => "mfa-setup",
            Self::Confirm => "mfa-confirm",
            Self::BootstrapSetup => "mfa-bootstrap-setup",
            Self::BootstrapConfirm => "mfa-bootstrap-confirm",
            Self::BootstrapGrant => "mfa-bootstrap-grant",
            Self::Mint => "mfa-mint",
            Self::RecoveryBudget => "mfa-recovery-budget",
            Self::RecoveryPush => "mfa-recovery-push",
            Self::PasswordGrant => "mfa-password-grant",
            Self::TotpGrant => "mfa-totp-grant",
            Self::BackupGenerate => "mfa-backup-generate",
            Self::BackupConsume => "mfa-backup-consume",
            Self::NativeRegister => "mfa-native-register",
            Self::PushHarvest => "mfa-push-harvest",
            Self::PushApprove => "mfa-push-approve",
            Self::PushSend => "mfa-push-send",
            Self::WebauthnPossessionBegin => "mfa-webauthn-possession-begin",
            Self::WebauthnPossessionFinish => "mfa-webauthn-possession-finish",

        }
    }
}
fn receipted(exec: &ScopedExecutor, operation: Operation) -> ScopedExecutor {
    exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand {
        family: "F21",
        command: operation.command(),
    })
}
/// Fresh verified authority, durable revocation and current enabled identity
/// precede actor-bound receipt lookup under the original user/operation lock.
pub async fn lookup_operation(
    exec: &ScopedExecutor,
    session: &Session,
    operation: OperationId,
    kind: Operation,
) -> Result<bool, StatementFailure> {
    let invalid = || StatementFailure {
        sqlstate: None,
        hint: None,
        message: "TOTP lookup authority unavailable".into(),
    };
    if !matches!(session.text("typ"), "access" | "mfa_pending") || session.bound() {
        return Err(invalid());
    }
    let actor = ActorId::new(session.user()).map_err(|_| invalid())?;
    let op = setjoin_pg::operation_hex(operation);
    let claims = serde_json::Value::Object(session.claims().clone()).to_string();
    let result=exec.run_user_command(actor,operation,
        "SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=substr(encode(digest($2::text || ':' || $1::text,'sha256'),'hex'),1,32)::uuid AND family='F21' AND command=$3) WHERE EXISTS(SELECT 1 FROM users u WHERE u.id=$1 AND u.enabled AND identity_transition_admission_allowed(u.id) AND (COALESCE($4::text::jsonb->>'credential_fence','')='' OR rtrim(translate(encode(digest(u.password_hash,'sha256'),'base64'),'+/','-_'),'=')=$4::text::jsonb->>'credential_fence')) AND NOT EXISTS(SELECT 1 FROM session_revocations WHERE user_id=$1 AND (expires_at IS NULL OR expires_at>now()) AND ((scope='jti' AND jti=COALESCE($4::text::jsonb->>'jti','')) OR (scope='family' AND family_id=COALESCE($4::text::jsonb->>'fam','')) OR (scope='all' AND to_timestamp(COALESCE(($4::text::jsonb->>'iat')::double precision,0))<=not_before)))",
        &[(&session.user(),Type::INT8),(&op,Type::TEXT),(&kind.command(),Type::TEXT),(&claims,Type::TEXT)],
        |rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await;
    match result {
        CommandOutcome::Committed(found) => Ok(found),
        _ => Err(invalid()),
    }
}

pub async fn remove(
    exec: &ScopedExecutor,
    session: &Session,
    token: &str,
    ip: &str,
) -> CommandOutcome<String, StatementFailure> {
    let exec = receipted(exec, Operation::Remove);
    let user = session.user();
    let Ok(actor) = ActorId::new(user) else {
        return CommandOutcome::Committed("invalid".into());
    };
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    exec.run_user_command(
        actor,
        OperationId(*uuid::Uuid::new_v4().as_bytes()),
        "SELECT rust_identity_totp_remove($1,$2,$3,$4)",
        &[
            (&user, Type::INT8),
            (&session.text("jti"), Type::TEXT),
            (&hash, Type::TEXT),
            (&ip, Type::TEXT),
        ],
        |rows| Ok(rows[0].get(0)),
    )
    .await
}
pub async fn audit(exec: &ScopedExecutor, session: &Session, ip: &str, action: &str, notes: &str) {
    let user = session.user();
    let Ok(actor) = ActorId::new(user) else {
        return;
    };
    let _=exec.run_user_command(actor,OperationId(*uuid::Uuid::new_v4().as_bytes()),
        "INSERT INTO admin_audit_log(user_id,ip,action,target_type,target_id,notes) VALUES($1,$2::text::inet,$3,'user',$1,NULLIF($4,''))",
        &[(&user,Type::INT8),(&ip,Type::TEXT),(&action,Type::TEXT),(&notes,Type::TEXT)],|_|Ok(())).await;
}

/// RFC 4226/6238 framing over ring's audited HMAC. Go uses SHA-1, six digits,
/// a 30-second period and all three windows, including for malformed codes.
fn secret_key(secret: &str) -> Option<Vec<u8>> {
    // Frozen Go pads before simple Unicode uppercasing, accepts unused bits,
    // and ignores CR/LF. The maintained codec still validates the encoding.
    let secret = secret.trim();
    let mut padded = secret.to_owned();
    if secret.len() % 8 != 0 {
        padded.extend(std::iter::repeat_n('=', 8 - secret.len() % 8));
    }
    let padded: String = padded
        .chars()
        .map(|c| {
            let mut upper = c.to_uppercase();
            let first = upper.next().unwrap();
            if upper.next().is_none() {
                first
            } else {
                c
            }
        })
        .collect();
    static LEGACY_BASE32: std::sync::OnceLock<data_encoding::Encoding> = std::sync::OnceLock::new();
    let codec = LEGACY_BASE32.get_or_init(|| {
        let mut spec = data_encoding::BASE32.specification();
        spec.check_trailing_bits = false;
        spec.ignore = "\r\n".into();
        spec.encoding().expect("fixed Go base32 profile")
    });
    codec.decode(padded.as_bytes()).ok()
}
pub fn code(secret: &str, unix: i64) -> Option<String> {
    let key = secret_key(secret)?;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key);
    let counter = (unix / 30) as u64;
    let tag = ring::hmac::sign(&key, &counter.to_be_bytes());
    let mac = tag.as_ref();
    let at = (mac[19] & 15) as usize;
    let binary = u32::from_be_bytes(mac[at..at + 4].try_into().ok()?) & 0x7fff_ffff;
    Some(format!("{:06}", binary % 1_000_000))
}
pub fn validate(presented: &str, secret: &str, unix: i64) -> bool {
    use subtle::ConstantTimeEq;
    let mut matched = subtle::Choice::from(0);
    for offset in [-30, 0, 30] {
        if let Some(expected) = code(secret, unix + offset) {
            matched |= presented.as_bytes().ct_eq(expected.as_bytes());
        }
    }
    bool::from(matched)
}

/// Return the highest matching counter, so a rare adjacent-code collision also
/// cannot replay a previously accepted value. Library constant-time selection
/// retains the fixed three-window verification work.
pub(crate) fn counter_proof(presented:&str,secret:&str,unix:i64)->Option<(i64,Vec<u8>)>{
    use subtle::{ConstantTimeEq,ConditionallySelectable};
    let mut found=subtle::Choice::from(0);let mut counter=0u64;
    for offset in [-30,0,30]{
        if let Some(expected)=code(secret,unix+offset){
            let hit=presented.as_bytes().ct_eq(expected.as_bytes());
            counter=u64::conditional_select(&counter,&(((unix+offset)/30) as u64),hit);
            found|=hit;
        }
    }
    if !bool::from(found){return None;}
    Some((counter as i64,Sha256::digest(secret_key(secret)?).to_vec()))
}


pub async fn cycle(
    exec: &ScopedExecutor,
    session: &Session,
    presented: &str,
) -> CommandOutcome<String, StatementFailure> {
    cycle_for(exec, session.user(), presented).await
}

/// Recovery can call this only after its server-side credential lookup.
pub(crate) async fn cycle_for(
    exec: &ScopedExecutor,
    user: i64,
    presented: &str,
) -> CommandOutcome<String, StatementFailure> {
    let exec = receipted(exec, Operation::Cycle);
    let Ok(actor) = ActorId::new(user) else {
        return CommandOutcome::Committed("invalid".into());
    };
    exec.run_user_proof_command(
        actor,
        OperationId(*uuid::Uuid::new_v4().as_bytes()),
        "SELECT * FROM rust_identity_totp_cycle_read($1)",
        &[(&user, Type::INT8)],
        |rows| {
            let outcome: String = rows[0].get(0);
            if outcome != "evaluate" {
                return Ok(
                    setjoin_pg::ProvenStatement::new("SELECT $1::text").bind(outcome, Type::TEXT)
                );
            }
            let secret: Option<String> = rows[0].get(1);
            let Some(secret) = secret else {
                return Ok(setjoin_pg::ProvenStatement::new(
                    "SELECT 'bookkeeping'::text",
                ));
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let proof=counter_proof(presented,&secret,now);
            let counter=proof.as_ref().map(|p|p.0);let factor=proof.map(|p|p.1);
            let valid=counter.is_some();
            Ok(
                setjoin_pg::ProvenStatement::new("SELECT rust_identity_totp_cycle($1,$2,$3,$4)")
                    .bind(user, Type::INT8)
                    .bind(valid, Type::BOOL).bind(counter,Type::INT8).bind(factor,Type::BYTEA),
            )
        },
        |rows| Ok(rows[0].get(0)),
    )
    .await
}

#[derive(Debug)]
pub enum Failure {
    Reply(u16, &'static str, Option<&'static str>),
    Unknown(OperationId),
}
fn internal() -> Failure {
    Failure::Reply(500, "totp removal failed", None)
}
async fn unit_command(
    exec: &ScopedExecutor,
    user: i64,
    sql: &'static str,
    params: &[setjoin_pg::Param<'_>],
) -> Result<(), Failure> {
    let exec = receipted(exec, Operation::Begin);
    let actor = ActorId::new(user).map_err(|_| internal())?;
    match exec
        .run_user_command(
            actor,
            OperationId(*uuid::Uuid::new_v4().as_bytes()),
            sql,
            params,
            |_| Ok(()),
        )
        .await
    {
        CommandOutcome::Committed(()) => Ok(()),
        CommandOutcome::Unknown { operation } => Err(Failure::Unknown(operation)),
        _ => Err(internal()),
    }
}
pub async fn begin(
    exec: &ScopedExecutor,
    session: &Session,
    password: &str,
    presented: &str,
) -> Result<String, Failure> {
    let user = session.user();
    let rows=exec.read("SELECT COALESCE(totp_enabled,false),COALESCE(totp_backup_codes_enc,'{}') FROM users WHERE id=$1",&[(&user,Type::INT8)]).await.map_err(|_|internal())?;
    let row = rows.first().ok_or_else(internal)?;
    if !row.get::<_, bool>(0) {
        return Err(Failure::Reply(
            409,
            "TOTP is not enabled",
            Some("totp not enabled"),
        ));
    }
    let backups: Vec<String> = row.get(1);
    let hashes = exec
        .read(
            "SELECT password_hash FROM users WHERE id=$1",
            &[(&user, Type::INT8)],
        )
        .await
        .map_err(|_| internal())?;
    let hash: String = hashes.first().ok_or_else(internal)?.get(0);
    let password = password.to_owned();
    if !tokio::task::spawn_blocking(move || setjoin_authz::password::verify(&hash, &password))
        .await
        .unwrap_or(false)
    {
        return Err(Failure::Reply(
            403,
            "invalid password",
            Some("invalid password"),
        ));
    }
    let outcome = match cycle(exec, session, presented).await {
        CommandOutcome::Committed(s) => s,
        CommandOutcome::Unknown { operation } => return Err(Failure::Unknown(operation)),
        _ => return Err(internal()),
    };
    match outcome.as_str() {
        "accepted" => {}
        "locked" => {
            return Err(Failure::Reply(
                429,
                "account locked due to too many TOTP failures",
                Some("account locked"),
            ))
        }
        "invalid" => {
            let mut accepted = false;
            if !backups.is_empty() {
                let rows = exec
                    .read(
                        "SELECT totp_backup_codes_enc FROM users WHERE id=$1",
                        &[(&user, Type::INT8)],
                    )
                    .await
                    .map_err(|_| internal())?;
                let hashes: Option<Vec<String>> = rows.first().ok_or_else(internal)?.get(0);
                let code = presented.to_owned();
                accepted = tokio::task::spawn_blocking(move || {
                    hashes
                        .unwrap_or_default()
                        .iter()
                        .any(|h| bcrypt::verify(&code, h).unwrap_or(false))
                })
                .await
                .unwrap_or(false);
            }
            if !accepted {
                return Err(Failure::Reply(401, "invalid code", Some("invalid code")));
            }
        }
        _ => return Err(internal()),
    }
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| internal())?;
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    // Frozen Go deliberately commits cleanup separately from insertion. A later
    // storage failure must not resurrect the prior step-up (ARCH-029).
    unit_command(
        exec,
        user,
        "DELETE FROM totp_removal_step_ups WHERE user_id=$1",
        &[(&user, Type::INT8)],
    )
    .await?;
    unit_command(exec,user,"INSERT INTO totp_removal_step_ups(token_hash,user_id,session_jti,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')",&[(&hash,Type::TEXT),(&user,Type::INT8),(&session.text("jti"),Type::TEXT)]).await?;
    Ok(token)
}

pub async fn setup(
    exec: &ScopedExecutor,
    session: &Session,
    token: &str,
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    stage(exec, session, token, false).await
}
pub async fn bootstrap_setup(
    exec: &ScopedExecutor,
    session: &Session,
    token: &str,
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    stage(exec, session, token, true).await
}
async fn stage(
    exec: &ScopedExecutor,
    session: &Session,
    token: &str,
    bootstrap: bool,
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let exec = receipted(
        exec,
        if bootstrap {
            Operation::BootstrapSetup
        } else {
            Operation::Setup
        },
    );
    use ring::rand::SecureRandom;
    let user = session.user();
    let Ok(actor) = ActorId::new(user) else {
        return CommandOutcome::Committed(serde_json::json!({"status":"internal"}));
    };
    let mut bytes = [0u8; 32];
    if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
        return CommandOutcome::Committed(serde_json::json!({"status":"setup_failed"}));
    }
    let secret = data_encoding::BASE32_NOPAD.encode(&bytes);
    let claims = serde_json::Value::Object(session.claims().clone()).to_string();
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    exec.run_user_command(
        actor,
        OperationId(*uuid::Uuid::new_v4().as_bytes()),
        if bootstrap {
            "SELECT rust_identity_totp_bootstrap_setup($1,$2::text::jsonb,$3,$4)::text"
        } else {
            "SELECT rust_identity_totp_setup($1,$2::text::jsonb,$3,$4)::text"
        },
        &[
            (&user, Type::INT8),
            (&claims, Type::TEXT),
            (&hash, Type::TEXT),
            (&secret, Type::TEXT),
        ],
        |rows| {
            serde_json::from_str(&rows[0].get::<_, String>(0)).map_err(|_| StatementFailure {
                sqlstate: None,
                hint: None,
                message: "TOTP setup result".into(),
            })
        },
    )
    .await
}
/// Go net/url escaping for an opaque URI path segment or query member.
fn escape(text: &str, query: bool) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || (!query && b"$&+:=@".contains(&b)) {
            out.push(b as char);
        } else if query && b == b' ' {
            out.push('+');
        } else {
            out += &format!("%{b:02X}");
        }
    }
    out
}
pub fn provisioning_uri(secret: &str, email: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={secret}&issuer={}&algorithm=SHA1&digits=6&period=30",
        escape(issuer, false),
        escape(email, false),
        escape(issuer, true)
    )
}

fn json_row(rows: &[setjoin_pg::Row]) -> Result<serde_json::Value, StatementFailure> {
    serde_json::from_str(&rows[0].get::<_, String>(0)).map_err(|_| StatementFailure {
        sqlstate: None,
        hint: None,
        message: "TOTP result".into(),
    })
}
pub async fn confirm(
    exec: &ScopedExecutor,
    session: &Session,
    token: &str,
    enrollment: &str,
    presented: &str,
    ip: &str,
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let exec = receipted(exec, Operation::Confirm);
    let user = session.user();
    let Ok(actor) = ActorId::new(user) else {
        return CommandOutcome::Committed(serde_json::json!({"status":"internal"}));
    };
    let claims = serde_json::Value::Object(session.claims().clone()).to_string();
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    exec.run_user_proof_command(
        actor,
        OperationId(*uuid::Uuid::new_v4().as_bytes()),
        "SELECT rust_identity_totp_confirm_read($1,$2::text::jsonb,$3,$4,$5)::text",
        &[
            (&user, Type::INT8),
            (&claims, Type::TEXT),
            (&hash, Type::TEXT),
            (&enrollment, Type::TEXT),
            (&ip, Type::TEXT),
        ],
        |rows| {
            let result = json_row(rows)?;
            if result["status"] != "ready" {
                return Ok(setjoin_pg::ProvenStatement::new("SELECT $1::text")
                    .bind(result.to_string(), Type::TEXT));
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let Some((counter,factor))=counter_proof(presented,result["secret"].as_str().unwrap_or(""),now) else {
                return Ok(setjoin_pg::ProvenStatement::new(
                    "SELECT '{\"status\":\"invalid_code\"}'::text",
                ));
            };
            Ok(setjoin_pg::ProvenStatement::new(
                "SELECT rust_identity_totp_confirm($1,$2::text::jsonb,$3,$4,$5,$6,$7)::text",
            )
            .bind(user, Type::INT8)
            .bind(claims.clone(), Type::TEXT)
            .bind(hash.clone(), Type::TEXT)
            .bind(enrollment.to_owned(), Type::TEXT)
            .bind(ip.to_owned(), Type::TEXT).bind(counter,Type::INT8).bind(factor,Type::BYTEA))
        },
        json_row,
    )
    .await
}

/// Enabled completion principal resolved by the verified pending JWT's uid.
#[derive(Clone)]
pub struct CompletionUser {
    pub(crate) user: i64,
    pub(crate) email: String,
    pub(crate) admin: bool,
}
impl CompletionUser {
    pub fn user(&self) -> i64 {
        self.user
    }
    pub async fn load(
        exec: &ScopedExecutor,
        pending: &Session,
    ) -> Result<Option<Self>, StatementFailure> {
        let user = pending.user();
        let rows=exec.read("SELECT email,EXISTS(SELECT 1 FROM admin_role_assignments ara WHERE ara.user_id=u.id AND (ara.expires_at IS NULL OR ara.expires_at>now())) FROM users u WHERE u.id=$1 AND u.enabled",&[(&user,Type::INT8)]).await?;
        Ok(rows.first().map(|r| Self {
            user,
            email: r.get(0),
            admin: r.get(1),
        }))
    }
    pub async fn scope(&self, exec: &ScopedExecutor) -> Result<Option<i64>, StatementFailure> {
        if !self.admin {
            return Ok(None);
        }
        let rows=exec.read("SELECT MIN(COALESCE(ra.domain_override,rg.domain_scope)) FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$1 AND COALESCE(ra.domain_override,rg.domain_scope) IS NOT NULL AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)",&[(&self.user,Type::INT8)]).await?;
        Ok(rows[0].get(0))
    }
    pub async fn admission(
        &self,
        exec: &ScopedExecutor,
    ) -> Result<(bool, bool), crate::login::AdmissionFailure> {
        let rows = exec
            .read(
                "SELECT identity_transition_admission_allowed($1)",
                &[(&self.user, Type::INT8)],
            )
            .await
            .map_err(crate::login::AdmissionFailure::Transition)?;
        if !rows[0].get::<_, bool>(0) {
            return Ok((false, false));
        }
        let rows = exec
            .read("SELECT is_guest_account($1)", &[(&self.user, Type::INT8)])
            .await
            .map_err(crate::login::AdmissionFailure::AccountType)?;
        Ok((true, rows[0].get(0)))
    }
    pub fn claims(
        &self,
        typ: &str,
        jti: &str,
        family: &str,
        issuer: &str,
        now: i64,
        expiry: i64,
        scope: Option<i64>,
        factors: &[String],
    ) -> serde_json::Value {
        use serde_json::json;
        let mut out = json!({"uid":self.user,"email":self.email,"typ":typ,"jti":jti,"fam":family,"iss":issuer,"sub":self.user.to_string(),"aud":["mailserver-gateway"],"iat":now,"nbf":now,"exp":now+expiry});
        if typ == "access" {
            let mut methods: std::collections::BTreeSet<String> =
                factors.iter().filter(|s| !s.is_empty()).cloned().collect();
            let multi = methods
                .iter()
                .filter(|s| !matches!(s.as_str(), "mfa" | "user"))
                .count()
                >= 2;
            if multi {
                methods.insert("mfa".into());
            }
            out["acr"] = json!(if multi { "aal2" } else { "aal1" });
            out["amr"] = json!(methods);
            if self.admin {
                out["admin"] = json!(true);
            }
            if let Some(scope) = scope {
                out["domain"] = json!(scope);
            }
        }
        out
    }
    pub async fn risk(&self, exec: &ScopedExecutor) -> Option<serde_json::Value> {
        use serde_json::{json, Value};
        if !crate::login::enabled(exec, "feature.user_risk")
            .await
            .unwrap_or(false)
        {
            return None;
        }
        let rows = exec
            .read_user_scoped(
                ActorId::new(self.user).ok()?,
                "SELECT score,level,signals::text FROM user_risk WHERE user_id=$1",
                &[(&self.user, Type::INT8)],
            )
            .await
            .ok()?;
        let row = rows.first()?;
        let level: String = row.get(1);
        if level.is_empty() || level == "none" {
            return None;
        }
        let signals: Value = serde_json::from_str(&row.get::<_, String>(2)).ok()?;
        Some(
            json!({"user_score":row.get::<_,i32>(0),"level":level,"requires_mfa":level=="medium"||level=="high","signals":signals}),
        )
    }
    pub async fn record(
        &self,
        exec: &ScopedExecutor,
        access: &str,
        jti: &str,
        expiry: i64,
        ip: &str,
        agent: &str,
        factors: &[String],
    ) {
        let method = match factors.first().map(String::as_str) {
            Some("hwk") => "webauthn",
            Some("swk") => "push",
            Some("otp") => "totp",
            _ => "password",
        };
        let _=exec.protocol_statement("INSERT INTO auth_event_log(user_id,event,provider,email,ip_address) VALUES($1,'login','jwt',NULLIF($2,''),NULLIF($3,'')::inet)",&[(&self.user,Type::INT8),(&self.email,Type::TEXT),(&ip,Type::TEXT)]).await;
        if let Ok(actor) = ActorId::new(self.user) {
            let _=exec.run_user_command(actor,OperationId(*uuid::Uuid::new_v4().as_bytes()),"INSERT INTO login_events(user_id,device_fingerprint,device_name,platform,source_ip,location,success,fail_reason,client,protocol,auth_method,session_id,correlation_id,occurred_at) VALUES($1,NULL,NULL,NULL,NULLIF($2,'')::inet,NULL,true,NULL,'web','http',$3,NULL,NULL,now())",&[(&self.user,Type::INT8),(&ip,Type::TEXT),(&method,Type::TEXT)],|_|Ok(())).await;
        }
        let hash = Sha256::digest(access.as_bytes()).to_vec();
        let _=exec.protocol_statement("INSERT INTO sessions(id,user_id,token_hash,expires_at,ip,user_agent,auth_method) VALUES($1,$2,$3,now()+make_interval(secs=>$4),NULLIF($5,'')::inet,$6,$7) ON CONFLICT(id) DO NOTHING",&[(&jti,Type::TEXT),(&self.user,Type::INT8),(&hash,Type::BYTEA),(&expiry,Type::INT8),(&ip,Type::TEXT),(&agent,Type::TEXT),(&method,Type::TEXT)]).await;
    }
}
pub fn factors(pending: &Session) -> Vec<String> {
    let mut methods: Vec<String> = pending
        .claims()
        .get("amr")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let legacy = methods.is_empty();
    methods.push("otp".into());
    if legacy {
        methods.push("pwd".into());
    }
    methods
}
pub async fn mint(
    exec: &ScopedExecutor,
    pending: &Session,
    refresh: &str,
    expiry: i64,
    family: &str,
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let exec = receipted(exec, Operation::Mint);
    let user = pending.user();
    let Ok(actor) = ActorId::new(user) else {
        return CommandOutcome::Committed(serde_json::json!({"status":"identity_changed"}));
    };
    let claims = serde_json::Value::Object(pending.claims().clone()).to_string();
    let hash = Sha256::digest(refresh.as_bytes()).to_vec();
    exec.run_user_command(
        actor,
        OperationId(
            *uuid::Uuid::parse_str(family)
                .expect("server family")
                .as_bytes(),
        ),
        "SELECT rust_identity_mfa_mint($1,$2::text::jsonb,$3,$4,$5::text::uuid)::text",
        &[
            (&user, Type::INT8),
            (&claims, Type::TEXT),
            (&hash, Type::BYTEA),
            (&expiry, Type::INT8),
            (&family, Type::TEXT),
        ],
        json_row,
    )
    .await
}

pub struct MfaAnchor {
    pub refresh: String,
    pub lifetime: i64,
}
#[allow(clippy::too_many_arguments)]
pub async fn bootstrap_confirm<P, PF, F, FF>(
    exec: &ScopedExecutor,
    pending: &Session,
    token: &str,
    enrollment: &str,
    presented: &str,
    ip: &str,
    prepare: P,
    tail: F,
) -> CommandOutcome<serde_json::Value, StatementFailure>
where
    P: FnOnce(String) -> PF,
    PF: std::future::Future<Output = Result<MfaAnchor, serde_json::Value>>,
    F: FnOnce(&serde_json::Value) -> FF,
    FF: std::future::Future<Output = ()>,
{
    let exec = receipted(exec, Operation::BootstrapConfirm);
    let user = pending.user();
    let Ok(actor) = ActorId::new(user) else {
        return CommandOutcome::Committed(serde_json::json!({"status":"confirm_failed"}));
    };
    let operation = uuid::Uuid::new_v4();
    let family = operation.to_string();
    let claims = serde_json::Value::Object(pending.claims().clone()).to_string();
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    let final_claims = &claims;
    let final_hash = &hash;
    exec.run_user_async_proof_command_with_tail(actor,OperationId(*operation.as_bytes()),
        "SELECT rust_identity_totp_bootstrap_read($1,$2::text::jsonb,$3,$4,$5)::text",
        &[(&user,Type::INT8),(&claims,Type::TEXT),(&hash,Type::TEXT),(&enrollment,Type::TEXT),(&ip,Type::TEXT)],
        |rows|{let read=json_row(rows);async move {
            let result=read?;
            if result["status"]!="ready"{return Ok(setjoin_pg::ProvenStatement::new("SELECT $1::text").bind(result.to_string(),Type::TEXT));}
            let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
            let Some((counter,factor))=counter_proof(presented,result["secret"].as_str().unwrap_or(""),now)else{return Ok(setjoin_pg::ProvenStatement::new("SELECT rust_identity_totp_bootstrap_fail($1)::text").bind(user,Type::INT8));};
            if result["user_enabled"]!=true{return Ok(setjoin_pg::ProvenStatement::new("SELECT '{\"status\":\"state_changed\"}'::text"));}
            let anchor=match prepare(family.clone()).await{Ok(a)=>a,Err(v)=>return Ok(setjoin_pg::ProvenStatement::new("SELECT $1::text").bind(v.to_string(),Type::TEXT))};
            let refresh_hash=Sha256::digest(anchor.refresh.as_bytes()).to_vec();
            Ok(setjoin_pg::ProvenStatement::new("SELECT rust_identity_totp_bootstrap_confirm($1,$2::text::jsonb,$3,$4,$5,$6,$7,$8::text::uuid,$9,$10)::text")
                .bind(user,Type::INT8).bind(final_claims.to_string(),Type::TEXT).bind(final_hash.to_string(),Type::TEXT).bind(enrollment.to_owned(),Type::TEXT).bind(ip.to_owned(),Type::TEXT)
                .bind(refresh_hash,Type::BYTEA).bind(anchor.lifetime,Type::INT8).bind(family,Type::TEXT).bind(counter,Type::INT8).bind(factor,Type::BYTEA))
        }},json_row,tail).await
}
