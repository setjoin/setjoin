//! Frozen-Go guest invitation acceptance (#342), authserver/internal/handlers/guest_invite.go.
//! Canonical reducers own every lock, lifecycle check and write; this module selects
//! the executor scope, hashes the credential and decodes verdicts.
use crate::password::{
    common_password_digest, password_was_used, COMMON_PASSWORD_ERROR, REUSED_PASSWORD_ERROR,
};
use serde_json::Value;
use setjoin_config_secret::CryptoProfile;
use setjoin_contracts::ids::{ActorId, OperationId};
use setjoin_pg::{
    AuthDb, CommandOutcome, ProvenContract, ReceiptCommand, Rejection, Row, StatementFailure, Type,
};
use sha2::{Digest, Sha256};

const REJECT: &str = "guest invite terminal reject";
const INVALID: &str = "guest invite password refused";
/// Go's pwhash.PasswordMaxBytes; longer passwords are never bound or hashed.
pub const PASSWORD_MAX_BYTES: usize = 72;

/// One settled transaction: Reject/Invalid are reported only after ROLLBACK was
/// acknowledged or the connection discarded (an elapsed link: after its COMMIT).
#[derive(Debug)]
pub enum Outcome<T> {
    Done(T),
    Reject,
    Invalid(String),
    Failed,
    Unknown(OperationId),
}

#[derive(Debug)]
pub struct Disclosure {
    pub org_name: String,
    pub invited_email: String,
    pub channels: Vec<String>,
    pub locality: String,
    pub addendum: String,
    pub version: String,
    pub expires_at: String,
}

#[derive(Debug)]
pub struct Accepted {
    pub invited_email: String,
}

/// Go's guestInviteTokenHash: lowercase hex SHA-256 of the raw token bytes.
pub fn token_hash(raw: &[u8]) -> String {
    Sha256::digest(raw)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn marker(message: &str, hint: Option<String>) -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        message: message.into(),
        hint,
    }
}

fn verdict(rows: &[Row]) -> Value {
    rows.first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null)
}

fn settle<T>(outcome: CommandOutcome<Option<T>, StatementFailure>) -> Outcome<T> {
    match outcome {
        CommandOutcome::Committed(Some(v)) => Outcome::Done(v),
        CommandOutcome::Committed(None) => Outcome::Reject,
        CommandOutcome::RolledBack(Rejection::Statement(f))
            if f.sqlstate.is_none() && f.message == REJECT =>
        {
            Outcome::Reject
        }
        CommandOutcome::RolledBack(Rejection::Statement(f))
            if f.sqlstate.is_none() && f.message == INVALID =>
        {
            Outcome::Invalid(f.hint.unwrap_or_default())
        }
        CommandOutcome::Unknown { operation } => Outcome::Unknown(operation),
        _ => Outcome::Failed,
    }
}

/// Go's unlocked id discovery; FORCE RLS without BYPASSRLS yields no row (uniform 401).
async fn discover(worker: &AuthDb, hash: &str) -> Result<Option<i64>, ()> {
    worker
        .read_contract(&crate::sql::GUEST_INVITE_L94, &[(&hash, Type::TEXT)])
        .await
        .map(|rows| rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()))
        .map_err(|_| ())
}

/// Startup posture check: BYPASSRLS worker credential and installed reducers.
pub async fn readiness(worker: &AuthDb) -> Result<(), String> {
    let rows = worker
        .read_contract(&crate::sql::GUEST_INVITE_L105, &[])
        .await
        .map_err(|e| format!("readiness query failed: {}", e.message))?;
    let r = rows
        .first()
        .ok_or_else(|| "readiness query returned no row".to_string())?;
    let bypass: bool = r
        .try_get(0)
        .map_err(|_| "readiness query returned an invalid row".to_string())?;
    let reducers: bool = r
        .try_get(1)
        .map_err(|_| "readiness query returned an invalid row".to_string())?;
    match (bypass, reducers) {
        (true, true) => Ok(()),
        (false, _) => Err(
            "worker credential lacks BYPASSRLS; every invite token will be refused (401)".into(),
        ),
        (_, false) => {
            Err("rust_guest_invite_* reducers are not installed; acceptance returns 500".into())
        }
    }
}

/// GET: one user-scoped transaction (no receipt); a terminal verdict rolls back.
pub async fn disclosure(worker: &AuthDb, raw_token: &[u8]) -> Outcome<Disclosure> {
    let hash = token_hash(raw_token);
    let guest = match discover(worker, &hash).await {
        Ok(Some(g)) => g,
        Ok(None) => return Outcome::Reject,
        Err(()) => return Outcome::Failed,
    };
    let Ok(actor) = ActorId::new(guest) else {
        return Outcome::Reject;
    };
    settle(
        worker
            .run_user_command_contract(
                actor,
                OperationId(*uuid::Uuid::new_v4().as_bytes()),
                &crate::sql::GUEST_INVITE_L147,
                &[(&guest, Type::INT8), (&hash, Type::TEXT)],
                |rows| {
                    let v = verdict(rows);
                    if v["status"] != "ok" {
                        return Err(marker(REJECT, None));
                    }
                    let text = |k: &str| v[k].as_str().unwrap_or("").to_owned();
                    Ok(Some(Disclosure {
                        org_name: text("org_name"),
                        invited_email: text("invited_email"),
                        channels: v["channels"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|c| c.as_str().map(str::to_owned))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        locality: text("locality"),
                        addendum: text("addendum"),
                        version: text("disclosure_version"),
                        expires_at: text("expires_at"),
                    }))
                },
            )
            .await,
    )
}

/// POST: discovery selects the scope. The read reducer locks and checks policy.
/// Rust checks history and hashes under those locks before the finishing write.
pub async fn accept(
    worker: &AuthDb,
    raw_token: &str,
    password: &str,
    profile: CryptoProfile,
    ip: Option<String>,
    operation: OperationId,
) -> Outcome<Accepted> {
    let hash = token_hash(raw_token.as_bytes());
    let guest = match discover(worker, &hash).await {
        Ok(Some(g)) => g,
        Ok(None) => return Outcome::Reject,
        Err(()) => return Outcome::Failed,
    };
    let Ok(actor) = ActorId::new(guest) else {
        return Outcome::Reject;
    };
    let too_long = password.len() > PASSWORD_MAX_BYTES;
    // PostgreSQL TEXT cannot carry NUL; never bind it (Go fails at its later bind).
    let invalid_text = password.contains('\0');
    let bound: Option<&str> = (!too_long && !invalid_text).then_some(password);
    let digest = bound.map(common_password_digest);
    let candidate = bound.unwrap_or("").to_owned();
    let token = hash.clone();
    let worker = worker.clone().with_user_receipt(ReceiptCommand {
        family: "F21",
        command: "guest_invite_accept",
    });
    settle(
        worker
            .run_user_async_proof_command_contract_with_tail(
                actor,
                operation,
                &crate::sql::GUEST_INVITE_L209,
                &[
                    (&guest, Type::INT8),
                    (&hash, Type::TEXT),
                    (&bound, Type::TEXT),
                    (&too_long, Type::BOOL),
                    (&invalid_text, Type::BOOL),
                    (&digest, Type::BYTEA),
                ],
                move |rows: &[Row]| {
                    let mut v = verdict(rows);
                    let invite = v["invite_id"].as_i64();
                    let status = v["status"].as_str().unwrap_or("reject").to_owned();
                    let error = v["error"].as_str().unwrap_or("").to_owned();
                    async move {
                        match (status.as_str(), invite) {
                            ("ready", Some(invite)) => {
                                let history: Vec<String> =
                                    serde_json::from_value(v["history"].take())
                                        .map_err(|_| marker("guest invite history result", None))?;
                                let hashed = tokio::task::spawn_blocking(move || {
                                    if password_was_used(&history, &candidate) {
                                        return Err(marker(
                                            INVALID,
                                            Some(REUSED_PASSWORD_ERROR.into()),
                                        ));
                                    }
                                    setjoin_authz::password::hash(&candidate, profile)
                                        .map_err(|_| marker("guest invite hash failed", None))
                                })
                                .await
                                .map_err(|_| marker("guest invite hash task failed", None))??;
                                Ok(ProvenContract::new(&crate::sql::GUEST_INVITE_L237)
                                    .bind(guest, Type::INT8)
                                    .bind(invite, Type::INT8)
                                    .bind(token, Type::TEXT)
                                    .bind(hashed, Type::TEXT)
                                    .bind(ip, Type::TEXT))
                            }
                            ("expired", _) => Ok(ProvenContract::new(&crate::sql::ECHO_TEXT)
                                .bind(r#"{"status":"expired"}"#.to_owned(), Type::TEXT)),
                            ("invalid", _) => Err(marker(INVALID, Some(error))),
                            ("common", _) => {
                                Err(marker(INVALID, Some(COMMON_PASSWORD_ERROR.into())))
                            }
                            _ => Err(marker(REJECT, None)),
                        }
                    }
                },
                |rows| {
                    let v = verdict(rows);
                    match v["status"].as_str() {
                        Some("accepted") => Ok(Some(Accepted {
                            invited_email: v["invited_email"].as_str().unwrap_or("").to_owned(),
                        })),
                        Some("expired") => Ok(None),
                        _ => Err(marker("guest invite finish result", None)),
                    }
                },
                |_| std::future::ready(()),
            )
            .await,
    )
}
