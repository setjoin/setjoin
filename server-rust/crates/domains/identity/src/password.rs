//! Frozen local credential updates. HTTP maps these domain results byte-for-byte.
use crate::session::Session;
use serde_json::{json, Value};
use setjoin_config_secret::CryptoProfile;
use setjoin_pg::{CommandOutcome, ScopedExecutor, Type};
#[derive(Debug)]
pub enum Failure {
    Reply(u16, String),
    Unknown(setjoin_contracts::ids::OperationId),
}
fn reply(status: u16, detail: impl Into<String>) -> Failure {
    Failure::Reply(status, detail.into())
}
async fn check_policy(exec: &ScopedExecutor, new: &str, admin: bool) -> Result<(), Failure> {
    let rows = exec
        .read(
            "SELECT validate_password($1,$2)::text",
            &[(&new, Type::TEXT), (&admin, Type::BOOL)],
        )
        .await
        .map_err(|_| reply(500, "internal error"))?;
    let value: Value = serde_json::from_str(&rows[0].get::<_, String>(0)).unwrap_or(Value::Null);
    if value["valid"] == true {
        Ok(())
    } else {
        Err(reply(400, value["error"].as_str().unwrap_or("")))
    }
}
async fn write(
    exec: &ScopedExecutor,
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
        .run_user_command(
            actor,
            operation,
            "SELECT rust_identity_password_write($1,$2,$3,$4::text::jsonb,$5,$6,$7)::text",
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
                let raw: String = rows[0].get(0);
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
    exec: &ScopedExecutor,
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
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(setjoin_authz::address::lower(new.trim()).as_bytes()).to_vec();
    if exec
        .read(
            "SELECT EXISTS(SELECT 1 FROM common_passwords WHERE password_hash=$1)",
            &[(&hash, Type::BYTEA)],
        )
        .await
        .is_ok_and(|r| r[0].get::<_, bool>(0))
    {
        return Err(reply(
            400,
            "This password is too common and easily guessed. Please choose a stronger password.",
        ));
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
    let depth=exec.read("SELECT COALESCE((SELECT (value->>0)::INT FROM system_config WHERE key='password_history_depth'),5)",&[]).await.ok().and_then(|r|r[0].try_get::<_,i32>(0).ok()).filter(|n|*n>0).unwrap_or(5);
    for _ in 0..4 {
        if exec
            .read(
                "SELECT identity_auth_local_mint_fence($1)",
                &[(&proof.user(), Type::INT8)],
            )
            .await
            .is_err()
        {
            return Err(reply(503, "credential update fence unavailable"));
        }
        let by_email = setjoin_contracts::mutants::on("password-keyed-on-email");
        let rows = exec
            .read(
                // Owner-approved security fix 2026-11-05 (#490): the credential row
                // is the signed uid's, never whichever row the signed email names.
                if by_email {
                    "SELECT password_hash FROM users WHERE email=$2 AND $1>0"
                } else {
                    "SELECT password_hash FROM users WHERE id=$1 AND $2::text IS NOT NULL"
                },
                &[(&proof.user(), Type::INT8), (&email, Type::TEXT)],
            )
            .await
            .map_err(|_| reply(403, "invalid current password"))?;
        let stored: String = rows
            .first()
            .ok_or_else(|| reply(403, "invalid current password"))?
            .get(0);
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
        let hashes:Vec<String>=exec.read("SELECT password_hash FROM password_history WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2",&[(&proof.user(),Type::INT8),(&depth,Type::INT4)]).await.map_err(|_|reply(500,"token revocation failed"))?.iter().map(|r|r.get(0)).collect();
        let history = json!(hashes);
        let candidate = new.to_owned();
        let (reused, new_hash) = tokio::task::spawn_blocking(move || {
            let reused = hashes
                .iter()
                .any(|h| setjoin_authz::password::verify(h, &candidate));
            (reused, setjoin_authz::password::hash(&candidate, profile))
        })
        .await
        .map_err(|_| reply(500, "internal error"))?;
        if reused {
            return Err(reply(
                400,
                "This password was used recently. Please choose a new one.",
            ));
        }
        let new_hash = new_hash.map_err(|_| reply(500, "internal error"))?;
        match write(
            exec, proof, &email, &stored, &history, &new_hash, depth, false, operation,
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
    exec: &ScopedExecutor,
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
    match exec.run_user_command(actor,operation,"INSERT INTO used_password_reset_tokens(token_hash) VALUES($1) ON CONFLICT DO NOTHING RETURNING true",&[(&hash,Type::TEXT)],|rows|Ok(!rows.is_empty())).await {
        CommandOutcome::Committed(true)=>{},CommandOutcome::Committed(false)=>return Err(reply(401,"invalid or expired reset token")),CommandOutcome::Unknown{operation}=>return Err(Failure::Unknown(operation)),_=>return Err(reply(500,"internal error")),
    }
    let rows=exec.read("SELECT EXISTS(SELECT 1 FROM admin_role_assignments ara WHERE ara.user_id=users.id AND (ara.expires_at IS NULL OR ara.expires_at>now())) FROM users WHERE id=$1",&[(&proof.user(),Type::INT8)]).await.map_err(|_|reply(401,"user not found"))?;
    let admin = rows
        .first()
        .ok_or_else(|| reply(401, "user not found"))?
        .get::<_, bool>(0);
    check_policy(exec, new, admin).await?;
    // Preserve Go's fence error priority before hashing, then recheck in SQL.
    if exec
        .read(
            "SELECT identity_auth_local_mint_fence($1)",
            &[(&proof.user(), Type::INT8)],
        )
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
