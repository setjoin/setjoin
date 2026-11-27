//! Frozen local credential updates. HTTP maps these domain results byte-for-byte.
use crate::session::Session;
use serde_json::{json, Value};
use setjoin_config_secret::CryptoProfile;
use setjoin_pg::{AuthDb, CommandOutcome, Type};
use sha2::{Digest, Sha256};

pub(crate) const COMMON_PASSWORD_ERROR: &str =
    "This password is too common and easily guessed. Please choose a stronger password.";
pub(crate) const REUSED_PASSWORD_ERROR: &str =
    "This password was used recently. Please choose a new one.";

pub(crate) fn common_password_digest(password: &str) -> Vec<u8> {
    Sha256::digest(setjoin_authz::address::lower(password.trim()).as_bytes()).to_vec()
}

pub(crate) fn password_was_used(hashes: &[String], candidate: &str) -> bool {
    hashes
        .iter()
        .any(|hash| setjoin_authz::password::verify(hash, candidate))
}

#[derive(Debug)]
pub enum Failure {
    Reply(u16, String),
    Unknown(setjoin_contracts::ids::OperationId),
}
fn reply(status: u16, detail: impl Into<String>) -> Failure {
    Failure::Reply(status, detail.into())
}
async fn check_policy(exec: &AuthDb, new: &str, admin: bool) -> Result<(), Failure> {
    let rows = exec
        .read_contract(
            &crate::sql::PASSWORD_L34,
            &[(&new, Type::TEXT), (&admin, Type::BOOL)],
        )
        .await
        .map_err(|_| reply(500, "internal error"))?;
    let raw: String = rows
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(|| reply(500, "internal error"))?;
    let value: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    if value["valid"] == true {
        Ok(())
    } else {
        Err(reply(400, value["error"].as_str().unwrap_or("")))
    }
}
#[allow(clippy::too_many_arguments)]
async fn write(
    exec: &AuthDb,
    proof: &Session,
    email: &str,
    old_hash: &str,
    history: &Value,
    new_hash: &str,
    depth: i32,
    reset: bool,
    operation: setjoin_contracts::ids::OperationId,
) -> Result<String, Failure> {
    let actor = setjoin_contracts::ids::ActorId::new(proof.user())
        .map_err(|_| reply(500, "internal error"))?;
    let history = history.to_string();
    match exec
        .run_user_command_contract(
            actor,
            operation,
            &crate::sql::PASSWORD_L68,
            &[
                (&proof.user(), Type::INT8),
                (&email, Type::TEXT),
                (&old_hash, Type::TEXT),
                (&history, Type::TEXT),
                (&new_hash, Type::TEXT),
                (&depth, Type::INT4),
                (&reset, Type::BOOL),
            ],
            |rows| {
                let raw: String =
                    rows.first()
                        .and_then(|r| r.try_get(0).ok())
                        .ok_or_else(|| setjoin_pg::StatementFailure {
                            sqlstate: None,
                            hint: None,
                            message: "password result row".into(),
                        })?;
                serde_json::from_str::<Value>(&raw).map_err(|_| setjoin_pg::StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: "password result".into(),
                })
            },
        )
        .await
    {
        CommandOutcome::Committed(v) => Ok(v["status"].as_str().unwrap_or("internal").into()),
        CommandOutcome::Unknown { operation } => Err(Failure::Unknown(operation)),
        _ => Err(reply(500, "internal error")),
    }
}
pub async fn change(
    exec: &AuthDb,
    proof: &Session,
    old: &str,
    new: &str,
    profile: CryptoProfile,
    operation: setjoin_contracts::ids::OperationId,
) -> Result<(), Failure> {
    if old == new {
        return Err(reply(400, "New password must differ from current password"));
    }
    check_policy(
        exec,
        new,
        proof
            .claims()
            .get("admin")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
    .await?;
    let actor = setjoin_contracts::ids::ActorId::new(proof.user())
        .map_err(|_| reply(403, "invalid current password"))?;
    let hash = common_password_digest(new);
    // #454: a query error, an unreadable or a missing flag fails closed as an internal
    // fault, never as "not common" (frozen Go proceeds on a failed lookup).
    let common = match exec
        .read_user_scoped_contract(actor, &crate::sql::PASSWORD_L127, &[(&hash, Type::BYTEA)])
        .await
    {
        Ok(rows) => match rows.first().map(|r| r.try_get::<_, bool>(0)) {
            Some(Ok(flag)) => flag,
            _ => return Err(reply(500, "internal error")),
        },
        Err(_) => return Err(reply(500, "internal error")),
    };
    if common {
        return Err(reply(400, COMMON_PASSWORD_ERROR));
    }
    let raw_email = setjoin_authz::address::lower(proof.text("email"));
    let lower = setjoin_authz::address::lower(new);
    if let Some((local, domain)) = raw_email.split_once('@') {
        if (!local.is_empty() && lower.contains(local))
            || (!domain.is_empty() && lower.contains(domain))
        {
            return Err(reply(
                400,
                "Password must not contain your email address or name.",
            ));
        }
    }
    let canonical = setjoin_authz::address::canonical(proof.text("email"));
    let email = canonical.as_str();
    // A query error, a missing row or an unreadable depth is the 500 internal fault; the
    // SQL already COALESCEs an absent setting to 5, so a decode error never falls back to 5.
    let depth = match exec.read_contract(&crate::sql::PASSWORD_L157, &[]).await {
        Ok(rows) => match rows.first().map(|r| r.try_get::<_, i32>(0)) {
            Some(Ok(n)) => n,
            _ => return Err(reply(500, "internal error")),
        },
        Err(_) => return Err(reply(500, "internal error")),
    };
    let depth = if depth > 0 { depth } else { 5 };
    for _ in 0..4 {
        if exec
            .protocol_query_contract(&crate::sql::PASSWORD_L168, &[(&proof.user(), Type::INT8)])
            .await
            .is_err()
        {
            return Err(reply(503, "credential update fence unavailable"));
        }
        let by_email = setjoin_contracts::mutants::on("password-keyed-on-email");
        // Owner-approved security fix 2026-11-05 (#490): the credential row
        // is the signed uid's, never whichever row the signed email names.
        let rows = if by_email {
            exec.read_contract(
                &crate::sql::PASSWORD_L182,
                &[(&proof.user(), Type::INT8), (&email, Type::TEXT)],
            )
            .await
        } else {
            exec.read_user_scoped_contract(
                actor,
                &crate::sql::PASSWORD_L184,
                &[(&proof.user(), Type::INT8), (&email, Type::TEXT)],
            )
            .await
        }
        .map_err(|_| reply(403, "invalid current password"))?;
        let stored: String = rows
            .first()
            .ok_or_else(|| reply(403, "invalid current password"))?
            .try_get(0)
            .map_err(|_| reply(500, "internal error"))?;
        let candidate = old.to_owned();
        let compare = stored.clone();
        if !tokio::task::spawn_blocking(move || {
            setjoin_authz::password::verify(&compare, &candidate)
        })
        .await
        .unwrap_or(false)
        {
            return Err(reply(403, "invalid current password"));
        }
        let hashes: Vec<String> = exec
            .read_user_scoped_contract(
                actor,
                &crate::sql::PASSWORD_L205,
                &[(&proof.user(), Type::INT8), (&depth, Type::INT4)],
            )
            .await
            .map_err(|_| reply(500, "token revocation failed"))?
            .iter()
            .map(|r| r.try_get(0))
            .collect::<Result<Vec<String>, _>>()
            .map_err(|_| reply(500, "token revocation failed"))?;
        let history = json!(hashes);
        let candidate = new.to_owned();
        let (reused, new_hash) = tokio::task::spawn_blocking(move || {
            let reused = password_was_used(&hashes, &candidate);
            (reused, setjoin_authz::password::hash(&candidate, profile))
        })
        .await
        .map_err(|_| reply(500, "internal error"))?;
        if reused {
            return Err(reply(400, REUSED_PASSWORD_ERROR));
        }
        let new_hash = new_hash.map_err(|_| reply(500, "internal error"))?;
        match write(
            exec, proof, email, &stored, &history, &new_hash, depth, false, operation,
        )
        .await?
        .as_str()
        {
            "ok" => return Ok(()),
            "retry" => continue,
            "invalid-current" => return Err(reply(403, "invalid current password")),
            "fence-failed" => return Err(reply(503, "credential update fence unavailable")),
            "revoke-failed" => return Err(reply(500, "token revocation failed")),
            _ => return Err(reply(500, "internal error")),
        }
    }
    Err(reply(500, "internal error"))
}

pub async fn reset(
    exec: &AuthDb,
    proof: &Session,
    new: &str,
    profile: CryptoProfile,
    operation: setjoin_contracts::ids::OperationId,
) -> Result<(), Failure> {
    let actor = setjoin_contracts::ids::ActorId::new(proof.user())
        .map_err(|_| reply(500, "internal error"))?;
    let hash = proof
        .token_hash()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    // Frozen Go consumes the token BEFORE policy/user/fence checks. This is
    // intentionally a separate committed statement, including failed resets.
    match exec
        .run_user_command_contract(
            actor,
            operation,
            &crate::sql::PASSWORD_L251,
            &[(&hash, Type::TEXT)],
            |rows| Ok(!rows.is_empty()),
        )
        .await
    {
        CommandOutcome::Committed(true) => {}
        CommandOutcome::Committed(false) => {
            return Err(reply(401, "invalid or expired reset token"))
        }
        CommandOutcome::Unknown { operation } => return Err(Failure::Unknown(operation)),
        _ => return Err(reply(500, "internal error")),
    }
    let rows = exec
        .read_contract(&crate::sql::PASSWORD_L254, &[(&proof.user(), Type::INT8)])
        .await
        .map_err(|_| reply(401, "user not found"))?;
    let admin = rows
        .first()
        .ok_or_else(|| reply(401, "user not found"))?
        .try_get::<_, bool>(0)
        .map_err(|_| reply(500, "internal error"))?;
    check_policy(exec, new, admin).await?;
    // Preserve Go's fence error priority before hashing, then recheck in SQL.
    if exec
        .protocol_query_contract(&crate::sql::PASSWORD_L168, &[(&proof.user(), Type::INT8)])
        .await
        .is_err()
    {
        return Err(reply(503, "credential update fence unavailable"));
    }
    let password = new.to_owned();
    let hash =
        tokio::task::spawn_blocking(move || setjoin_authz::password::hash(&password, profile))
            .await
            .map_err(|_| reply(500, "internal error"))?
            .map_err(|_| reply(500, "internal error"))?;
    match write(
        exec,
        proof,
        proof.text("email"),
        "",
        &json!([]),
        &hash,
        0,
        true,
        operation,
    )
    .await?
    .as_str()
    {
        "ok" => Ok(()),
        "fence-failed" => Err(reply(503, "credential update fence unavailable")),
        _ => Err(reply(500, "internal error")),
    }
}
