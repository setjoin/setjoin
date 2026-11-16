//! Frozen-Go guest invitation acceptance (#342), authserver/internal/handlers/guest_invite.go.
//! Canonical reducers own every lock, lifecycle check and write; this module selects
//! the executor scope, hashes the credential and decodes verdicts.
use serde_json::Value;
use setjoin_config_secret::CryptoProfile;
use setjoin_contracts::ids::{ActorId, OperationId};
use setjoin_pg::{
    CommandOutcome, ProvenStatement, ReceiptCommand, Rejection, Row, ScopedExecutor,
    StatementFailure, Type,
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
async fn discover(worker: &ScopedExecutor, hash: &str) -> Result<Option<i64>, ()> {
    worker
        .read(
            "SELECT guest_user_id FROM guest_invites WHERE token_hash=$1",
            &[(&hash, Type::TEXT)],
        )
        .await
        .map(|rows| rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()))
        .map_err(|_| ())
}

/// Startup posture check: BYPASSRLS worker credential and installed reducers.
pub async fn readiness(worker: &ScopedExecutor) -> Result<(), String> {
    let rows = worker.read(
        "SELECT COALESCE((SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname=current_user),false), \
         to_regprocedure('rust_guest_invite_disclosure(bigint,text)') IS NOT NULL \
         AND to_regprocedure('rust_guest_invite_accept_read(bigint,text,text,boolean,boolean)') IS NOT NULL \
         AND to_regprocedure('rust_guest_invite_accept_finish(bigint,bigint,text,text,inet)') IS NOT NULL",
        &[],
    ).await.map_err(|e| format!("readiness query failed: {}", e.message))?;
    let (bypass, reducers): (bool, bool) = (rows[0].get(0), rows[0].get(1));
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
pub async fn disclosure(worker: &ScopedExecutor, raw_token: &[u8]) -> Outcome<Disclosure> {
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
            .run_user_command(
                actor,
                OperationId(*uuid::Uuid::new_v4().as_bytes()),
                "SELECT rust_guest_invite_disclosure($1,$2)::text",
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

/// POST: discovery selects the scope; the read reducer locks and decides; the
/// password is hashed under those locks before the one finishing write.
pub async fn accept(
    worker: &ScopedExecutor,
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
    let candidate = bound.unwrap_or("").to_owned();
    let token = hash.clone();
    let worker = worker.clone().with_user_receipt(ReceiptCommand {
        family: "F21",
        command: "guest_invite_accept",
    });
    settle(worker.run_user_async_proof_command_with_tail(
        actor, operation,
        "SELECT rust_guest_invite_accept_read($1,$2,$3,$4,$5)::text",
        &[
            (&guest, Type::INT8),
            (&hash, Type::TEXT),
            (&bound, Type::TEXT),
            (&too_long, Type::BOOL),
            (&invalid_text, Type::BOOL),
        ],
        move |rows: &[Row]| {
            let v = verdict(rows);
            let invite = v["invite_id"].as_i64();
            let status = v["status"].as_str().unwrap_or("reject").to_owned();
            let error = v["error"].as_str().unwrap_or("").to_owned();
            async move {
                match (status.as_str(), invite) {
                    ("ready", Some(invite)) => {
                        let hashed = tokio::task::spawn_blocking(move || setjoin_authz::password::hash(&candidate, profile))
                            .await.map_err(|_| marker("guest invite hash task failed", None))?
                            .map_err(|_| marker("guest invite hash failed", None))?;
                        Ok(ProvenStatement::new("SELECT rust_guest_invite_accept_finish($1,$2,$3,$4,$5::text::inet)::text")
                            .bind(guest, Type::INT8).bind(invite, Type::INT8).bind(token, Type::TEXT)
                            .bind(hashed, Type::TEXT).bind(ip, Type::TEXT))
                    }
                    ("expired", _) => Ok(ProvenStatement::new("SELECT $1::text").bind(r#"{"status":"expired"}"#.to_owned(), Type::TEXT)),
                    ("invalid", _) => Err(marker(INVALID, Some(error))),
                    _ => Err(marker(REJECT, None)),
                }
            }
        },
        |rows| {
            let v = verdict(rows);
            match v["status"].as_str() {
                Some("accepted") => Ok(Some(Accepted { invited_email: v["invited_email"].as_str().unwrap_or("").to_owned() })),
                Some("expired") => Ok(None),
                _ => Err(marker("guest invite finish result", None)),
            }
        },
        |_| std::future::ready(()),
    ).await)
}
