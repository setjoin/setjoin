//! Push MFA formats. Cryptographic operations stay in audited crates.
use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use p256::elliptic_curve::sec1::ToSec1Point;

/// Frozen authserver derives the browser's public VAPID key at startup.
pub fn vapid_public_key(private: &str) -> Option<String> {
    let bytes = URL_SAFE
        .decode(private.replace(['\r', '\n'], ""))
        .or_else(|_| URL_SAFE_NO_PAD.decode(private.replace(['\r', '\n'], "")))
        .ok()?;
    let secret = p256::SecretKey::from_slice(&bytes).ok()?;
    Some(URL_SAFE_NO_PAD.encode(secret.public_key().to_sec1_point(false).as_bytes()))
}

/// Password proof and the grant write share one retained transaction and user fence.
pub async fn password_grant(
    exec: &setjoin_pg::ScopedExecutor,
    session: &crate::session::Session,
    password: &str,
    operation: &str,
    target: Option<String>,
) -> setjoin_pg::CommandOutcome<serde_json::Value, setjoin_pg::StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::{ProvenStatement, Type};
    use sha2::{Digest, Sha256};
    let Ok(actor) = ActorId::new(session.user()) else {
        return setjoin_pg::CommandOutcome::Committed(serde_json::json!({"status":"internal"}));
    };
    // Go uses 32 random bytes represented as 64 lower-case hexadecimal digits.
    let (Ok(first), Ok(second)) = (crate::login::random_jti(), crate::login::random_jti()) else {
        return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable);
    };
    let token = format!("{first}{second}");
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    let claims = serde_json::Value::Object(session.claims().clone()).to_string();
    let user = session.user();
    let exec = exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand {
        family: "F21",
        command: "mfa-password-grant",
    });
    exec.run_user_proof_command(
        actor,
        OperationId(*uuid::Uuid::new_v4().as_bytes()),
        "SELECT rust_identity_possession_read($1,$2::text::jsonb)::text",
        &[(&user, Type::INT8), (&claims, Type::TEXT)],
        |rows| {
            let value: serde_json::Value =
                serde_json::from_str(&rows[0].get::<_, String>(0)).expect("reducer JSON");
            if value["status"] != "ready" {
                return Ok(
                    ProvenStatement::new("SELECT $1::text").bind(value.to_string(), Type::TEXT)
                );
            }
            let valid =
                setjoin_authz::password::verify(value["hash"].as_str().unwrap_or(""), password);
            Ok(ProvenStatement::new(
                "SELECT rust_identity_possession_issue($1,$2::text::jsonb,$3,$4,$5,$6)::text",
            )
            .bind(user, Type::INT8)
            .bind(claims.clone(), Type::TEXT)
            .bind(operation.to_owned(), Type::TEXT)
            .bind(target, Type::TEXT)
            .bind(hash, Type::TEXT)
            .bind(valid, Type::BOOL))
        },
        |rows| {
            let mut value: serde_json::Value =
                serde_json::from_str(&rows[0].get::<_, String>(0)).expect("reducer JSON");
            if value["status"] == "issued" {
                value["token"] = serde_json::json!(token);
            }
            Ok(value)
        },
    )
    .await
}

/// TOTP proof and the grant write share one retained transaction and user fence.
pub async fn totp_grant(
    exec: &setjoin_pg::ScopedExecutor,
    session: &crate::session::Session,
    code: &str,
    operation: &str,
    target: Option<String>,
) -> setjoin_pg::CommandOutcome<serde_json::Value, setjoin_pg::StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::{ProvenStatement, Type};
    use sha2::{Digest, Sha256};
    let Ok(actor) = ActorId::new(session.user()) else {
        return setjoin_pg::CommandOutcome::Committed(serde_json::json!({"status":"internal"}));
    };
    // Go uses 32 random bytes represented as 64 lower-case hexadecimal digits.
    let (Ok(first), Ok(second)) = (crate::login::random_jti(), crate::login::random_jti()) else {
        return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable);
    };
    let token = format!("{first}{second}");
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    let claims = serde_json::Value::Object(session.claims().clone()).to_string();
    let user = session.user();
    let exec = exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand {
        family: "F21",
        command: "mfa-totp-grant",
    });
    exec.run_user_proof_command(
        actor,
        OperationId(*uuid::Uuid::new_v4().as_bytes()),
        "SELECT rust_identity_possession_totp_read($1,$2::text::jsonb)::text",
        &[(&user, Type::INT8), (&claims, Type::TEXT)],
        |rows| {
            let value: serde_json::Value =
                serde_json::from_str(&rows[0].get::<_, String>(0)).expect("reducer JSON");
            if value["status"] != "ready" {
                return Ok(
                    ProvenStatement::new("SELECT $1::text").bind(value.to_string(), Type::TEXT)
                );
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let proof=crate::totp::counter_proof(code,value["secret"].as_str().unwrap_or(""),now);
            let counter=proof.as_ref().map(|p|p.0);let factor=proof.map(|p|p.1);let valid=counter.is_some();
            Ok(ProvenStatement::new(
                "SELECT rust_identity_possession_totp_issue($1,$2::text::jsonb,$3,$4,$5,$6,$7,$8)::text",
            )
            .bind(user, Type::INT8)
            .bind(claims.clone(), Type::TEXT)
            .bind(operation.to_owned(), Type::TEXT)
            .bind(target, Type::TEXT)
            .bind(hash, Type::TEXT)
            .bind(valid, Type::BOOL).bind(counter,Type::INT8).bind(factor,Type::BYTEA))
        },
        |rows| {
            let mut value: serde_json::Value =
                serde_json::from_str(&rows[0].get::<_, String>(0)).expect("reducer JSON");
            if value["status"] == "issued" {
                value["token"] = serde_json::json!(token);
            }
            Ok(value)
        },
    )
    .await
}

/// Recovery code generation consumes the proved tuple before hashing, in one transaction.
pub async fn generate_backups(
    exec: &setjoin_pg::ScopedExecutor,
    session: &crate::session::Session,
    proof: &str,
    ip: &str,
) -> setjoin_pg::CommandOutcome<serde_json::Value, setjoin_pg::StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::{CommandOutcome, ProvenStatement, Rejection, StatementFailure, Type};
    use sha2::{Digest, Sha256};
    let failure = || StatementFailure {
        sqlstate: None,
        hint: Some("backup_generation_failed".into()),
        message: "backup code generation failed".into(),
    };
    let Ok(actor) = ActorId::new(session.user()) else {
        return CommandOutcome::Committed(serde_json::json!({"status":"internal"}));
    };
    let user = session.user();
    let claims = serde_json::Value::Object(session.claims().clone()).to_string();
    let hash = (!proof.is_empty()).then(|| format!("{:x}", Sha256::digest(proof.as_bytes())));
    let generated = std::sync::Mutex::new(Vec::<String>::new());
    let slot = &generated;
    let ready = std::sync::atomic::AtomicBool::new(false);
    let stage = &ready;
    let exec = exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand {
        family: "F21",
        command: "mfa-backup-generate",
    });
    let outcome=exec.run_user_async_proof_command_with_tail(actor,OperationId(*uuid::Uuid::new_v4().as_bytes()),
  "SELECT rust_identity_possession_consume($1,$2::text::jsonb,$3,'recovery.regenerate',false,NULL)::text",
  &[(&user,Type::INT8),(&claims,Type::TEXT),(&hash,Type::TEXT)],
  |rows|{let value:serde_json::Value=serde_json::from_str(&rows[0].get::<_,String>(0)).expect("reducer JSON");async move{
   if value["status"]!="ready"{return Ok(ProvenStatement::new("SELECT $1::text").bind(value.to_string(),Type::TEXT));}
   stage.store(true,std::sync::atomic::Ordering::Relaxed);
   let (codes,hashes)=tokio::task::spawn_blocking(||->Result<_,()>{
    use ring::rand::SecureRandom;let mut codes=Vec::with_capacity(10);let mut hashes=Vec::with_capacity(10);
    for _ in 0..10{let mut bytes=[0;4];ring::rand::SystemRandom::new().fill(&mut bytes).map_err(|_|())?;
     let code=bytes.iter().map(|b|format!("{b:02x}")).collect::<String>();
     let hash=bcrypt::hash_with_result(&code,10).map_err(|_|())?.format_for_version(bcrypt::Version::TwoA);codes.push(code);hashes.push(hash);
    }Ok((codes,hashes))
   }).await.map_err(|_|failure())?.map_err(|_|failure())?;
   *slot.lock().unwrap()=codes;
   Ok(ProvenStatement::new("SELECT rust_identity_backup_generate($1,$2,$3)::text").bind(user,Type::INT8).bind(hashes,Type::TEXT_ARRAY).bind(ip.to_owned(),Type::TEXT))
  }},
  |rows|{let mut value:serde_json::Value=serde_json::from_str(&rows[0].get::<_,String>(0)).expect("reducer JSON");
   if value["status"]=="generated"{value["codes"]=serde_json::json!(*generated.lock().unwrap());}Ok(value)
  },|_|async{}).await;
    match outcome {
        CommandOutcome::RolledBack(_) if ready.load(std::sync::atomic::Ordering::Relaxed) => {
            CommandOutcome::RolledBack(Rejection::Statement(failure()))
        }
        other => other,
    }
}

/// Frozen backup-code CAS: read/verify independently, then atomically claim the owned hash.
pub async fn consume_backup(
    exec: &setjoin_pg::ScopedExecutor,
    pending: &crate::session::Session,
    code: &str,
) -> setjoin_pg::CommandOutcome<bool, setjoin_pg::StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::{CommandOutcome, Rejection, StatementFailure, Type};
    let Ok(actor) = ActorId::new(pending.user()) else {
        return CommandOutcome::RolledBack(Rejection::Unavailable);
    };
    let rows = match exec
        .read_user_scoped(
            actor,
            "SELECT totp_backup_codes_enc FROM users WHERE id=$1",
            &[(&pending.user(), Type::INT8)],
        )
        .await
    {
        Ok(rows) => rows,
        Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
    };
    let Some(row) = rows.first() else {
        return CommandOutcome::RolledBack(Rejection::Unavailable);
    };
    let hashes: Option<Vec<String>> = row.get(0);
    let code = code.to_owned();
    let matched = tokio::task::spawn_blocking(move || {
        hashes
            .unwrap_or_default()
            .into_iter()
            .find(|hash| bcrypt::verify(&code, hash).unwrap_or(false))
    })
    .await;
    let hash = match matched {
        Ok(Some(hash)) => hash,
        Ok(None) => return CommandOutcome::Committed(false),
        Err(_) => {
            return CommandOutcome::RolledBack(Rejection::Statement(StatementFailure {
                sqlstate: None,
                hint: None,
                message: "backup verification unavailable".into(),
            }))
        }
    };
    let exec = exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand {
        family: "F21",
        command: "mfa-backup-consume",
    });
    exec.run_user_command(actor,OperationId(*uuid::Uuid::new_v4().as_bytes()),
  "UPDATE users SET totp_backup_codes_enc=array_remove(totp_backup_codes_enc,$2) WHERE id=$1 AND $2=ANY(totp_backup_codes_enc) RETURNING id",
  &[(&pending.user(),Type::INT8),(&hash,Type::TEXT)],|rows|Ok(!rows.is_empty())).await
}

/// Frozen native device key admission: hex, then uncompressed on-curve P-256.
pub fn native_key(text: &str) -> Result<Vec<u8>, &'static str> {
    if text.is_empty() {
        return Err("device_public_key is required for native providers");
    }
    let bytes = data_encoding::HEXLOWER_PERMISSIVE
        .decode(text.as_bytes())
        .map_err(|_| "device_public_key must be hex-encoded")?;
    if bytes.len() != 65 || bytes[0] != 4 || p256::PublicKey::from_sec1_bytes(&bytes).is_err() {
        return Err("device_public_key must be an uncompressed P-256 public key");
    }
    Ok(bytes)
}
/// The sealed access proof alone supplies the native approval-device owner.
#[allow(clippy::too_many_arguments)]
pub async fn register_native(
    exec: &setjoin_pg::ScopedExecutor,
    proof: &crate::issuance::SessionProof,
    token: &str,
    provider: &str,
    delivery_token: &str,
    key: Vec<u8>,
    name: &str,
    ip: &str,
) -> setjoin_pg::CommandOutcome<serde_json::Value, setjoin_pg::StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::{CommandOutcome, Type};
    use sha2::{Digest, Sha256};
    let user = proof.user();
    let actor = ActorId::new(user).expect("sealed session");
    let claims = serde_json::Value::Object(proof.claims().clone()).to_string();
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    let receipted = exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand {
        family: "F21",
        command: "mfa-native-register",
    });
    let outcome = receipted
        .run_user_command(
            actor,
            OperationId(*uuid::Uuid::new_v4().as_bytes()),
            "SELECT rust_identity_native_register($1,$2::text::jsonb,$3,$4,$5,$6,$7,$8)::text",
            &[
                (&user, Type::INT8),
                (&claims, Type::TEXT),
                (&hash, Type::TEXT),
                (&provider, Type::TEXT),
                (&delivery_token, Type::TEXT),
                (&key, Type::BYTEA),
                (&name, Type::TEXT),
                (&ip, Type::TEXT),
            ],
            |rows| {
                Ok(
                    serde_json::from_str::<serde_json::Value>(&rows[0].get::<_, String>(0))
                        .expect("reducer JSON"),
                )
            },
        )
        .await;
    if let CommandOutcome::Committed(value) = &outcome {
        if value["status"] == "reauth" {
            let notes =
                if value["notes"] == "possession proof refused: proving factor no longer live" {
                    "possession proof refused: proving factor no longer live"
                } else {
                    "native device register without a valid possession proof"
                };
            let _=exec.run_user_command(actor,OperationId(*uuid::Uuid::new_v4().as_bytes()),
   "INSERT INTO admin_audit_log(user_id,ip,action,target_type,target_id,notes) VALUES($1,$2::text::inet,'mfa_reauth_refused','user',$1,$3)",
   &[(&user,Type::INT8),(&ip,Type::TEXT),(&notes,Type::TEXT)],|_|Ok(())).await;
        }
    }
    outcome
}

/// An approved nonce can be harvested only by its exact initiating signed token.
/// The claim commits independently before session issuance, as frozen Go does.
pub async fn harvest(
    exec: &setjoin_pg::ScopedExecutor,
    pending: &crate::session::Session,
    nonce: &str,
    token: &str,
) -> setjoin_pg::CommandOutcome<bool, setjoin_pg::StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::{CommandOutcome, Type};
    let user = pending.user();
    let approved=exec.read("SELECT approved_at IS NOT NULL FROM push_mfa_challenges WHERE nonce=decode($1,'hex') AND user_id=$2 ORDER BY created_at DESC LIMIT 1",&[(&nonce,Type::TEXT),(&user,Type::INT8)]).await;
    if !approved.is_ok_and(|rows| rows.first().is_some_and(|r| r.get::<_, bool>(0))) {
        return CommandOutcome::Committed(false);
    }
    let exec = exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand {
        family: "F21",
        command: "mfa-push-harvest",
    });
    exec.run_user_command(ActorId::new(user).expect("signed pending principal"),OperationId(*uuid::Uuid::new_v4().as_bytes()),
     "UPDATE push_mfa_challenges SET session_id=NULL WHERE nonce=decode($1,'hex') AND user_id=$2 AND session_id=$3 AND approved_at IS NOT NULL AND expires_at>now() RETURNING true",
     &[(&nonce,Type::TEXT),(&user,Type::INT8),(&token,Type::TEXT)],|rows|Ok(!rows.is_empty())).await
}

/// Go preserves the pending AMR, appends the completed factors, then legacy pwd.
pub fn approval_factors(pending: &crate::session::Session) -> Vec<String> {
    let mut factors = pending
        .claims()
        .get("amr")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let legacy = factors.is_empty();
    factors.extend(["swk".into(), "user".into()]);
    if legacy {
        factors.push("pwd".into());
    }
    factors
}

pub struct Approval {
    pub nonce: String,
    pub code: String,
    pub device: i64,
    pub decision: String,
    pub issued: i64,
    pub expires: i64,
    pub signature: String,
}
impl Approval {
    pub fn nonce_bytes(&self) -> Option<Vec<u8>> {
        data_encoding::HEXLOWER_PERMISSIVE
            .decode(self.nonce.as_bytes())
            .ok()
            .filter(|b| b.len() == 32)
    }
    pub fn canonical(&self, user: i64, session: &str) -> Vec<u8> {
        serde_json::json!({"code":self.code,"decision":self.decision,"device_id":self.device,"expires_at":self.expires,"issued_at":self.issued,"nonce":self.nonce,"protocol":"setjoin.push-approval.v1","session_id":session,"user_id":user}).to_string().replace('&',"\\u0026").replace('<',"\\u003c").replace('>',"\\u003e").replace('\u{2028}',"\\u2028").replace('\u{2029}',"\\u2029").into_bytes()
    }
}
pub fn verify_approval(key: &[u8], canonical: &[u8], signature: &str) -> bool {
    use base64::{
        alphabet,
        engine::{general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig},
    };
    if key.len() != 65 || key[0] != 4 {
        return false;
    }
    let codec = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    let Ok(raw) = codec.decode(signature.replace(['\r', '\n'], "")) else {
        return false;
    };
    raw.len() == 64
        && ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, key)
            .verify(canonical, &raw)
            .is_ok()
}
/// Preauth capability lookup resolves a possible owner only; the locked callback
/// authenticates the device signature before the reducer can approve any row.
pub async fn approve(
    exec: &setjoin_pg::ScopedExecutor,
    assertion: &Approval,
) -> setjoin_pg::CommandOutcome<String, setjoin_pg::StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::{CommandOutcome, ProvenStatement, Type};
    use subtle::ConstantTimeEq;
    let invalid = || CommandOutcome::Committed("invalid".to_owned());
    let Some(nonce) = assertion.nonce_bytes() else {
        return invalid();
    };
    let rows=exec.read("SELECT c.user_id FROM push_mfa_challenges c JOIN push_devices d ON d.user_id=c.user_id AND d.id=$2 WHERE c.nonce=$1 AND c.verified_at IS NULL AND c.expires_at>now() AND d.revoked_at IS NULL AND d.device_public_key IS NOT NULL ORDER BY c.created_at DESC LIMIT 1",&[(&nonce,Type::BYTEA),(&assertion.device,Type::INT8)]).await;
    let Some(user) = rows
        .ok()
        .and_then(|r| r.first().map(|r| r.get::<_, i64>(0)))
    else {
        return invalid();
    };
    let Ok(actor) = ActorId::new(user) else {
        return invalid();
    };
    let exec = exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand {
        family: "F21",
        command: "mfa-push-approve",
    });
    exec.run_user_proof_command(
        actor,
        OperationId(*uuid::Uuid::new_v4().as_bytes()),
        "SELECT rust_identity_push_approval_read($1,$2,$3)::text",
        &[
            (&user, Type::INT8),
            (&nonce, Type::BYTEA),
            (&assertion.device, Type::INT8),
        ],
        |rows| {
            let value: serde_json::Value =
                serde_json::from_str(&rows[0].get::<_, String>(0)).expect("reducer JSON");
            if value["status"] != "ready" {
                return Ok(ProvenStatement::new("SELECT 'invalid'::text"));
            }
            let id = value["id"].as_i64().expect("challenge id");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let key = data_encoding::HEXLOWER_PERMISSIVE
                .decode(value["key"].as_str().unwrap_or("").as_bytes())
                .unwrap_or_default();
            let result = if value["failures"].as_i64().unwrap_or(0) >= 3 {
                "burn"
            } else if assertion.issued < now - 120
                || assertion.issued > now + 30
                || assertion.expires <= now
                || assertion.expires > value["expires"].as_i64().unwrap_or(0)
                || assertion
                    .expires
                    .checked_sub(assertion.issued)
                    .is_none_or(|d| d > 120)
                || !verify_approval(
                    &key,
                    &assertion.canonical(user, value["session"].as_str().unwrap_or("")),
                    &assertion.signature,
                )
            {
                "invalid"
            } else if !bool::from(
                value["code"]
                    .as_str()
                    .unwrap_or("")
                    .as_bytes()
                    .ct_eq(assertion.code.as_bytes()),
            ) {
                "wrong"
            } else {
                "accepted"
            };
            Ok(
                ProvenStatement::new("SELECT rust_identity_push_approval_finish($1,$2,$3)")
                    .bind(user, Type::INT8)
                    .bind(id, Type::INT8)
                    .bind(result.to_owned(), Type::TEXT),
            )
        },
        |rows| Ok(rows[0].get::<_, String>(0)),
    )
    .await
}

/// Go's process-local fixed-window ten-events/five-minutes budget.
#[derive(Default)]
pub struct IpBudget(std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, u32)>>);
impl IpBudget {
    pub fn allow(&self, ip: &str) -> bool {
        if ip.is_empty() {
            return true;
        }
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(300);
        let mut hits = self.0.lock().expect("IP budget lock");
        if let Some((start, count)) = hits.get_mut(ip) {
            if now.duration_since(*start) < window {
                if *count >= 10 {
                    return false;
                }
                *count += 1;
                return true;
            }
        }
        hits.retain(|_, (start, _)| now.duration_since(*start) < window);
        hits.insert(ip.to_owned(), (now, 1));
        true
    }
}
pub struct Challenge {
    pub(super) user: i64,
    pub(super) code: String,
    pub(super) nonce: String,
    pub(super) session: String,
    pub(super) expires: i64,
}
impl Challenge {
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
}
pub enum Generated {
    Limited,
    Created(Challenge),
}
/// Only a signed pending principal or a proved password can mint a login challenge.
pub async fn generate_pending(
    exec: &setjoin_pg::ScopedExecutor,
    pending: &crate::session::Session,
    token: &str,
) -> setjoin_pg::CommandOutcome<Generated, setjoin_pg::StatementFailure> {
    generate_for(exec, pending.user(), token).await
}
pub async fn generate_login(
    exec: &setjoin_pg::ScopedExecutor,
    proof: &crate::login::PasswordProof,
    token: &str,
) -> setjoin_pg::CommandOutcome<Generated, setjoin_pg::StatementFailure> {
    generate_for(exec, proof.user(), token).await
}
pub(super) async fn generate_for(
    exec: &setjoin_pg::ScopedExecutor,
    user: i64,
    session: &str,
) -> setjoin_pg::CommandOutcome<Generated, setjoin_pg::StatementFailure> {
    use rand::{Rng, RngExt, SeedableRng};
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::{CommandOutcome, Rejection, Type};
    // These are separate transactions in frozen Go; do not invent serialization.
    let count=exec.read("SELECT count(*) FROM push_mfa_challenges WHERE user_id=$1 AND created_at>now()-interval '5 minutes'",&[(&user,Type::INT8)]).await;
    let count = match count {
        Ok(rows) => rows[0].get::<_, i64>(0),
        Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
    };
    if count >= 3 {
        return CommandOutcome::Committed(Generated::Limited);
    }
    let Ok(mut rng) = rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng) else {
        return CommandOutcome::RolledBack(Rejection::Unavailable);
    };
    let code = format!("{:02}", rng.random_range(0u32..100));
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let hex = data_encoding::HEXLOWER.encode(&nonce);
    let deadline = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
        + 120.;
    let Ok(actor) = ActorId::new(user) else {
        return CommandOutcome::RolledBack(Rejection::Unavailable);
    };
    let exec = exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand {
        family: "F21",
        command: "mfa-push-send",
    });
    let result=exec.run_user_command(actor,OperationId(*uuid::Uuid::new_v4().as_bytes()),"INSERT INTO push_mfa_challenges(user_id,challenge_code,nonce,session_id,expires_at) VALUES($1,$2,$3,$4,to_timestamp($5))",&[(&user,Type::INT8),(&code,Type::TEXT),(&nonce.as_slice(),Type::BYTEA),(&session,Type::TEXT),(&deadline,Type::FLOAT8)],|_|Ok(())).await;
    match result {
        CommandOutcome::Committed(()) => CommandOutcome::Committed(Generated::Created(Challenge {
            user,
            code,
            nonce: hex,
            session: session.to_owned(),
            expires: deadline as i64,
        })),
        CommandOutcome::Unknown { operation } => CommandOutcome::Unknown { operation },
        CommandOutcome::RolledBack(e) => CommandOutcome::RolledBack(e),
    }
}
