//! Mailserver-local F21 self-service queries. The verified context is the owner;
//! HTTP input can never construct it. Contract: ../SELF_SERVICE.md.
use crate::issuance::object;
use serde_json::json;
use setjoin_authz::AuthContext;
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};

/// pgx/time.Time JSON: UTC, with fractional seconds trimmed as Go does.
fn timestamp(column: &str) -> String {
    format!("to_char({column} AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || CASE WHEN date_part('microseconds', {column} AT TIME ZONE 'UTC')::bigint % 1000000 = 0 THEN '' ELSE regexp_replace(to_char({column} AT TIME ZONE 'UTC','.US'),'0+$','') END || 'Z'")
}

/// Public certificate metadata only; the SELECT never reads private_key_enc.
pub struct UserCertificate {
    pub id: i64,
    pub label: String,
    pub pem: String,
    pub is_default: bool,
}

/// Parse independently of the uploaded certificate, as frozen Go does. Key
/// decoding/validation belongs to OpenSSL; no private arithmetic is implemented.
pub fn smime_private_key_parses(der: &[u8]) -> bool {
    use openssl::{nid::Nid, pkey::{Id, PKey}};
    let Ok(key) = PKey::private_key_from_der(der) else { return false; };
    match key.id() {
        Id::RSA => key.rsa().and_then(|rsa| rsa.check_key()).unwrap_or(false),
        Id::EC => key.ec_key().ok().is_some_and(|ec| matches!(ec.group().curve_name(),
            Some(Nid::SECP224R1 | Nid::X9_62_PRIME256V1 | Nid::SECP384R1 | Nid::SECP521R1))),
        Id::ED25519 | Id::X25519 => true,
        _ => false,
    }
}

/// Frozen Go's whole upload transaction: one owned upsert. The key is encrypted
/// by pgcrypto under the executor's trusted configuration GUC, never a body key.
#[allow(clippy::too_many_arguments)]
pub async fn user_certificate_store(
    exec: &ScopedExecutor, actor: &AuthContext, label: &str, cert: &str,
    key: &str, before: i64, after: i64, operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::ReceiptCommand;
    let user = actor.user_id();
    exec.clone().with_user_receipt(ReceiptCommand { family: "F21", command: "self-service.cert.store" })
        .run_user_command(ActorId::new(user).expect("verified actor"), OperationId(operation),
            "INSERT INTO user_smime_certs(user_id,label,cert_pem,private_key_enc,issued_at,expires_at,is_default) \
             VALUES($1,$2,$3,pgp_sym_encrypt($4::text,current_setting('app.encryption_key')),to_timestamp($5::bigint),to_timestamp($6::bigint), \
             NOT EXISTS(SELECT 1 FROM user_smime_certs WHERE user_id=$1)) \
             ON CONFLICT(user_id,label) DO UPDATE SET cert_pem=EXCLUDED.cert_pem,private_key_enc=EXCLUDED.private_key_enc, \
             issued_at=EXCLUDED.issued_at,expires_at=EXCLUDED.expires_at \
             WHERE user_smime_certs.user_id=$1 AND user_smime_certs.label=$2",
            &[(&user,Type::INT8),(&label,Type::TEXT),(&cert,Type::TEXT),(&key,Type::TEXT),(&before,Type::INT8),(&after,Type::INT8)],
            |_| Ok(())).await
}

/// The reducer owns delete + survivor promotion as one atomic transaction.
/// Failed phase verdicts abort this outer transaction too, leaving no receipt.
pub async fn user_certificate_delete(
    exec: &ScopedExecutor, actor: &AuthContext, id: i64, operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::ReceiptCommand;
    let user = actor.user_id();
    exec.clone().with_user_receipt(ReceiptCommand { family: "F21", command: "self-service.cert.delete" })
        .run_user_command(ActorId::new(user).expect("verified actor"), OperationId(operation),
            "SELECT rust_identity_smime_cert_delete($1,$2)",
            &[(&user,Type::INT8),(&id,Type::INT8)],
            |rows| {
                let phase = rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).unwrap_or_else(|| "delete".into());
                if phase == "ok" { Ok(()) } else { Err(StatementFailure { sqlstate: None, message: phase, hint: None }) }
            }).await
}

pub async fn user_certificate_default(
    exec: &ScopedExecutor, actor: &AuthContext, id: i64, operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::ReceiptCommand;
    let user = actor.user_id();
    exec.clone().with_user_receipt(ReceiptCommand { family: "F21", command: "self-service.cert.default" })
        .run_user_command(ActorId::new(user).expect("verified actor"), OperationId(operation),
            "SELECT rust_identity_smime_cert_default($1,$2)",
            &[(&user,Type::INT8),(&id,Type::INT8)],
            |rows| {
                let phase = rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).unwrap_or_else(|| "lookup".into());
                if phase == "ok" { Ok(()) } else { Err(StatementFailure { sqlstate: None, message: phase, hint: None }) }
            }).await
}

pub async fn user_certificates(exec: &ScopedExecutor, actor: &AuthContext) -> Result<Vec<UserCertificate>, StatementFailure> {
    let user = actor.user_id();
    let result = exec.read_iterated(
        "SELECT id,label,cert_pem,is_default FROM user_smime_certs WHERE user_id=$1 ORDER BY is_default DESC,created_at DESC",
        &[(&user, Type::INT8)],
    ).await;
    let rows = match result {
        Ok(rows) => rows,
        // Go ignores pgx's deferred permission failure and encodes a nil list.
        Err(error) if error.sqlstate.as_deref() == Some("42501") => Vec::new(),
        Err(error) => return Err(error),
    };
    Ok(rows.iter().filter_map(|row| Some(UserCertificate {
        id: row.try_get(0).ok()?, label: row.try_get(1).ok()?,
        pem: row.try_get(2).ok()?, is_default: row.try_get(3).ok()?,
    })).collect())
}

/// Recipient metadata is user-owned; the PEM is used only for the capability hint.
pub struct RecipientCertificate {
    pub id: i64,
    pub email: String,
    pub label: String,
    pub source: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub fingerprint: String,
    pub pem: String,
}

pub async fn recipient_certificates(exec: &ScopedExecutor, actor: &AuthContext) -> Result<Vec<RecipientCertificate>, StatementFailure> {
    let user = actor.user_id();
    let result = exec.read_iterated(
        "SELECT id,email,COALESCE(label,''),source,         to_char(NULLIF(not_before,'0001-01-01T00:00:00Z'::timestamptz) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),         to_char(NULLIF(not_after,'0001-01-01T00:00:00Z'::timestamptz) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),         fingerprint,cert_pem FROM recipient_smime_certs WHERE owner_user_id=$1 ORDER BY last_seen DESC",
        &[(&user,Type::INT8)],
    ).await;
    let rows = match result {
        Ok(rows) => rows,
        // Frozen pgx surfaces this at Rows.Next; Go omits Rows.Err.
        Err(error) if error.sqlstate.as_deref() == Some("42501") => Vec::new(),
        Err(error) => return Err(error),
    };
    Ok(rows.iter().filter_map(|r| Some(RecipientCertificate {
        id:r.try_get(0).ok()?, email:r.try_get(1).ok()?, label:r.try_get(2).ok()?, source:r.try_get(3).ok()?,
        before:r.try_get(4).ok()?, after:r.try_get(5).ok()?, fingerprint:r.try_get(6).ok()?, pem:r.try_get(7).ok()?,
    })).collect())
}

/// Single owned dedup upsert; Go preserves original PEM/dates/first_seen on conflict.
#[allow(clippy::too_many_arguments)]
pub async fn recipient_certificate_store(
    exec: &ScopedExecutor, actor: &AuthContext, email: &str, cert: &str,
    fingerprint: &str, before: i64, after: i64, label: &str, operation: [u8;16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    use setjoin_contracts::ids::{ActorId,OperationId};
    use setjoin_pg::ReceiptCommand;
    let user=actor.user_id();
    exec.clone().with_user_receipt(ReceiptCommand {family:"F21",command:"self-service.recipient.store"})
        .run_user_command(ActorId::new(user).expect("verified actor"),OperationId(operation),
            "INSERT INTO recipient_smime_certs(owner_user_id,email,cert_pem,fingerprint,not_before,not_after,source,label,first_seen,last_seen)              VALUES($1,$2,$3,$4,to_timestamp($5::bigint),to_timestamp($6::bigint),'imported',$7,now(),now())              ON CONFLICT ON CONSTRAINT recipient_smime_certs_dedup_key DO UPDATE SET last_seen=now(),source='imported',              label=COALESCE(NULLIF($7,''),recipient_smime_certs.label) WHERE recipient_smime_certs.owner_user_id=$1",
            &[(&user,Type::INT8),(&email,Type::TEXT),(&cert,Type::TEXT),(&fingerprint,Type::TEXT),(&before,Type::INT8),(&after,Type::INT8),(&label,Type::TEXT)],
            |_|Ok(())).await
}

/// One ownership-scoped DELETE; a missing row aborts the infrastructure receipt.
pub async fn recipient_certificate_delete(
    exec: &ScopedExecutor, actor: &AuthContext, id: i64, operation: [u8;16],
) -> setjoin_pg::CommandOutcome<(),StatementFailure> {
    use setjoin_contracts::ids::{ActorId,OperationId};
    use setjoin_pg::ReceiptCommand;
    let user=actor.user_id();
    exec.clone().with_user_receipt(ReceiptCommand {family:"F21",command:"self-service.recipient.delete"})
        .run_user_command(ActorId::new(user).expect("verified actor"),OperationId(operation),
            "WITH d AS (DELETE FROM recipient_smime_certs WHERE id=$2 AND owner_user_id=$1 RETURNING id) SELECT EXISTS(SELECT 1 FROM d)",
            &[(&user,Type::INT8),(&id,Type::INT8)],
            |rows| match rows.first().and_then(|r|r.try_get::<_,bool>(0).ok()) {
                Some(true)=>Ok(()),
                other=>Err(StatementFailure {sqlstate:None,hint:None,message:if other==Some(false) {"not-found"}else{"invalid delete result"}.into()}),
            }).await
}

/// Frozen Go's latest non-completed job. Every lookup remains actor-owned;
/// any query/scan error is the status:none projection, as in QueryRow.Scan.
pub async fn migration_status(exec:&ScopedExecutor,actor:&AuthContext)->Option<String> {
    let user=actor.user_id();
    let rows=exec.read_iterated(
        "SELECT id,source_type,status,conflict_strategy,progress::text,error_log::text,         to_char(started_at,'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),         to_char(completed_at,'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),         to_char(created_at,'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')          FROM migration_jobs WHERE user_id=$1 AND status!='completed' ORDER BY created_at DESC LIMIT 1",
        &[(&user,Type::INT8)]).await.ok()?;
    let row=rows.first()?;
    let id:i64=row.try_get(0).ok()?;
    let source:String=row.try_get(1).ok()?;
    let status:String=row.try_get(2).ok()?;
    let strategy:String=row.try_get(3).ok()?;
    let progress:Option<String>=row.try_get(4).ok()?;
    let errors:Option<String>=row.try_get(5).ok()?;
    let started:Option<String>=row.try_get(6).ok()?;
    let completed:Option<String>=row.try_get(7).ok()?;
    let created:String=row.try_get(8).ok()?;
    let quoted=|value:serde_json::Value| compact_raw(&value.to_string());
    Some(format!("{{\"completed_at\":{},\"conflict_strategy\":{},\"created_at\":{},\"error_log\":{},\"id\":{},\"progress\":{},\"source_type\":{},\"started_at\":{},\"status\":{}}}\n",
        quoted(json!(completed)),quoted(json!(strategy)),quoted(json!(created)),compact_raw(errors.as_deref().unwrap_or("null")),id,
        compact_raw(progress.as_deref().unwrap_or("null")),quoted(json!(source)),quoted(json!(started)),quoted(json!(status))))
}

/// One owned history deletion; FK cascades remain inside the same transaction.
pub async fn migration_history_delete(exec:&ScopedExecutor,actor:&AuthContext,operation:[u8;16])->setjoin_pg::CommandOutcome<i64,StatementFailure> {
    use setjoin_contracts::ids::{ActorId,OperationId};
    use setjoin_pg::ReceiptCommand;
    let user=actor.user_id();
    exec.clone().with_user_receipt(ReceiptCommand {family:"F21",command:"self-service.migration.delete"})
        .run_user_command(ActorId::new(user).expect("verified actor"),OperationId(operation),
            "WITH d AS (DELETE FROM migration_jobs WHERE user_id=$1 AND status IN ('completed','cancelled','failed') RETURNING id) SELECT count(*)::bigint FROM d",
            &[(&user,Type::INT8)],
            |rows|rows.first().and_then(|r|r.try_get::<_,i64>(0).ok()).ok_or_else(||StatementFailure {sqlstate:None,hint:None,message:"invalid history delete result".into()})).await
}

/// Frozen self-service start accepts any owned mailbox, including non-primary.
pub async fn migration_mailbox(exec:&ScopedExecutor,actor:&AuthContext)->Option<i64> {
    let user=actor.user_id();
    exec.read_iterated("SELECT id FROM mailboxes WHERE user_id=$1 LIMIT 1",&[(&user,Type::INT8)]).await.ok()?.first()?.try_get(0).ok()
}

/// Control lookup errors project as no job, matching frozen Go's QueryRow.
pub async fn migration_cancel_job(exec:&ScopedExecutor,actor:&AuthContext)->Option<i64> {
    let user=actor.user_id();
    exec.read_iterated("SELECT id FROM migration_jobs WHERE user_id=$1 AND status IN ('pending','testing','fetching','importing','paused') ORDER BY created_at DESC LIMIT 1",&[(&user,Type::INT8)]).await.ok()?.first()?.try_get(0).ok()
}

pub async fn migration_pause_job(exec:&ScopedExecutor,actor:&AuthContext)->Option<i64> {
    let user=actor.user_id();
    exec.read_iterated("SELECT id FROM migration_jobs WHERE user_id=$1 AND status IN ('fetching','importing') ORDER BY created_at DESC LIMIT 1",&[(&user,Type::INT8)]).await.ok()?.first()?.try_get(0).ok()
}

pub async fn migration_paused_job(exec:&ScopedExecutor,actor:&AuthContext)->Option<i64> {
    let user=actor.user_id();
    exec.read_iterated("SELECT id FROM migration_jobs WHERE user_id=$1 AND status='paused' ORDER BY created_at DESC LIMIT 1",&[(&user,Type::INT8)]).await.ok()?.first()?.try_get(0).ok()
}

/// Upload accepts any job phase, but only an actor-owned job.
pub async fn migration_job_owned(exec:&ScopedExecutor,actor:&AuthContext,job:i64)->bool {
    let user=actor.user_id();
    exec.read_iterated("SELECT id FROM migration_jobs WHERE user_id=$1 AND id=$2",&[(&user,Type::INT8),(&job,Type::INT8)]).await.is_ok_and(|rows|!rows.is_empty())
}

pub async fn migration_job_insert(exec:&ScopedExecutor,actor:&AuthContext,source:&str,config:Option<&[u8]>,mailbox:i64,strategy:&str,operation:[u8;16])->setjoin_pg::CommandOutcome<i64,StatementFailure> {
    use setjoin_contracts::ids::{ActorId,OperationId};
    use setjoin_pg::ReceiptCommand;
    let user=actor.user_id();
    exec.clone().with_user_receipt(ReceiptCommand {family:"F21",command:"self-service.migration.start"})
        .run_user_command(ActorId::new(user).expect("verified actor"),OperationId(operation),
            "INSERT INTO migration_jobs(user_id,source_type,source_config_enc,target_mailbox_id,conflict_strategy,status)              SELECT $1,$2,$3,$4,$5,'pending' WHERE EXISTS(SELECT 1 FROM mailboxes WHERE id=$4 AND user_id=$1) RETURNING id",
            &[(&user,Type::INT8),(&source,Type::TEXT),(&config,Type::BYTEA),(&mailbox,Type::INT8),(&strategy,Type::TEXT)],
            |rows|rows.first().and_then(|r|r.try_get::<_,i64>(0).ok()).ok_or_else(||StatementFailure {sqlstate:None,hint:None,message:"invalid migration insert result".into()})).await
}

/// Go's per-user webhook subscription ceiling (`maxUserWebhookSubscriptions`).
pub const MAX_WEBHOOK_SUBSCRIPTIONS_PER_USER: i64 = 20;

/// `requireWebhookCap` count: the caller's own rows, read on the request pool
/// before the handler decodes the body. Failure is fail-closed (503).
pub async fn webhook_count(exec: &ScopedExecutor, actor: &AuthContext) -> Result<i64, StatementFailure> {
    let user = actor.user_id();
    let rows = exec.read_scoped(
        &actor.database_scope(),
        "SELECT count(*) FROM webhook_subscriptions WHERE user_id = $1",
        &[(&user, Type::INT8)],
    ).await?;
    rows.first().and_then(|r| r.try_get(0).ok()).ok_or_else(|| StatementFailure {
        sqlstate: None, message: "missing webhook count".into(), hint: None,
    })
}

/// Self-service subscriptions expose metadata only. The creator comes from the
/// verified session; Go skips scan failures and ignores deferred iteration errors.
pub async fn webhooks(exec: &ScopedExecutor, actor: &AuthContext) -> Result<String, StatementFailure> {
    let sql = format!(
        "SELECT id,url,event_types::text,scope,is_active,{},{} FROM webhook_subscriptions \
         WHERE user_id=$1 ORDER BY created_at DESC",
        timestamp("created_at"), timestamp("updated_at")
    );
    let user = actor.user_id();
    let rows = match exec.read_iterated(&sql, &[(&user, Type::INT8)]).await {
        Ok(rows) => rows,
        // pgx exposes the permission failure at Rows.Next, which this frozen
        // list handler never checks. Our driver may receive it before metadata.
        Err(error) if error.sqlstate.as_deref() == Some("42501") => Vec::new(),
        Err(error) => return Err(error),
    };
    let values = rows.iter().filter_map(|row| {
        let types: String = row.try_get(2).ok()?;
        // json.Unmarshal into []string keeps a nil slice for non-arrays and
        // zero-value elements when a stored element is not a string.
        let types = match serde_json::from_str::<serde_json::Value>(&types).ok()? {
            serde_json::Value::Array(xs) => json!(xs.iter().map(|x| x.as_str().unwrap_or("")).collect::<Vec<_>>()),
            _ => serde_json::Value::Null,
        };
        Some(object(&[
            ("id", json!(row.try_get::<_, i64>(0).ok()?)),
            ("url", json!(row.try_get::<_, String>(1).ok()?)),
            ("eventTypes", types),
            ("scope", json!(row.try_get::<_, String>(3).ok()?)),
            ("isActive", json!(row.try_get::<_, bool>(4).ok()?)),
            ("createdAt", json!(row.try_get::<_, String>(5).ok()?)),
            ("updatedAt", json!(row.try_get::<_, String>(6).ok()?)),
        ]))
    }).collect::<Vec<_>>();
    Ok(format!("[{}]\n", values.join(",")))
}

/// Go's whole webhook-create transaction is one INSERT. Only the caller's
/// verified user id supplies ownership; plaintext signing material stays out of
/// SQL. The adapter releases it only after this receipted explicit COMMIT.
#[allow(clippy::too_many_arguments)]
pub async fn webhook_create(
    exec: &ScopedExecutor, actor: &AuthContext, url: &str, events: &str,
    sealed: &[u8], key: &str, operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::ReceiptCommand;
    let user = actor.user_id();
    exec.clone().with_user_receipt(ReceiptCommand {
        family: "F21", command: "self-service.webhook.create",
    }).run_user_command(
        ActorId::new(user).expect("verified actor"), OperationId(operation),
        "INSERT INTO webhook_subscriptions(user_id,url,event_types,scope,secret_enc,secret_key_id) \
         VALUES($1,$2,$3::text::jsonb,'self',$4,$5) RETURNING id",
        &[(&user, Type::INT8), (&url, Type::TEXT), (&events, Type::TEXT),
          (&sealed, Type::BYTEA), (&key, Type::TEXT)],
        |rows| rows.first().and_then(|r| r.try_get(0).ok()).ok_or_else(|| StatementFailure {
            sqlstate: None, message: "missing webhook insert result".into(), hint: None,
        }),
    ).await
}

/// One owned DELETE, matching Go's complete transaction. The controller retains
/// Go's swallowed-error404, while an uncertain COMMIT remains an unknown outcome.
pub async fn webhook_delete(
    exec: &ScopedExecutor, actor: &AuthContext, id: i64, operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<bool, StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::ReceiptCommand;
    let user = actor.user_id();
    exec.clone().with_user_receipt(ReceiptCommand {
        family: "F21", command: "self-service.webhook.delete",
    }).run_user_command(
        ActorId::new(user).expect("verified actor"), OperationId(operation),
        "DELETE FROM webhook_subscriptions WHERE id=$2 AND user_id=$1 RETURNING id",
        &[(&user, Type::INT8), (&id, Type::INT8)], |rows| Ok(!rows.is_empty()),
    ).await
}

/// The authenticated user's active app passwords; no raw token or stored hash.
/// Frozen Go skips row-scan failures and ignores deferred iteration errors.
pub async fn app_passwords(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let sql = format!(
        "SELECT id,name,{},{},{} FROM app_passwords \
         WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC",
        timestamp("created_at"),
        timestamp("last_used_at"),
        timestamp("expires_at")
    );
    let user = actor.user_id();
    let rows = exec.read_iterated(&sql, &[(&user, Type::INT8)]).await?;
    let values = rows
        .iter()
        .filter_map(|row| {
            let id: i64 = row.try_get(0).ok()?;
            let name: String = row.try_get(1).ok()?;
            let created: String = row.try_get(2).ok()?;
            let used: Option<String> = row.try_get(3).ok()?;
            let expires: Option<String> = row.try_get(4).ok()?;
            let mut fields = vec![
                ("id", json!(id)),
                ("name", json!(name)),
                ("createdAt", json!(created)),
            ];
            if let Some(used) = used {
                fields.push(("lastUsedAt", json!(used)));
            }
            if let Some(expires) = expires {
                fields.push(("expiresAt", json!(expires)));
            }
            Some(object(&fields))
        })
        .collect::<Vec<_>>();
    Ok(format!("[{}]\n", values.join(",")))
}

/// Go's one-statement app-password creation. The plaintext is released only
/// after explicit COMMIT; the database stores its SHA-256 digest and owner.
/// Outer Err is entropy failure, before any database write.
pub async fn app_password_create(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &str,
    label: &str,
    operation: [u8; 16],
) -> Result<setjoin_pg::CommandOutcome<String, StatementFailure>, ()> {
    use ring::rand::SecureRandom;
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::{CommandOutcome, ReceiptCommand};
    use sha2::{Digest, Sha256};
    let mut random = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| ())?;
    let token = format!(
        "mail-ap-{}",
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    let user = actor.user_id();
    let outcome = exec
        .clone()
        .with_user_receipt(ReceiptCommand {
            family: "F21",
            command: "self-service.app.create",
        })
        .run_user_command(
            ActorId::new(user).expect("verified actor"),
            OperationId(operation),
            "INSERT INTO app_passwords(user_id,name,label,token_hash) VALUES($1,$2,$3,$4)",
            &[
                (&user, Type::INT8),
                (&name, Type::TEXT),
                (&label, Type::TEXT),
                (&hash, Type::TEXT),
            ],
            |_| Ok(()),
        )
        .await;
    Ok(match outcome {
        CommandOutcome::Committed(()) => CommandOutcome::Committed(token),
        CommandOutcome::RolledBack(error) => CommandOutcome::RolledBack(error),
        CommandOutcome::Unknown { operation } => CommandOutcome::Unknown { operation },
    })
}

/// Soft-revoke only a live credential owned by the authenticated user.
/// A committed no-op is Go's404; an uncertain transaction is never success.
pub async fn app_password_revoke(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<bool, StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::ReceiptCommand;
    let user = actor.user_id();
    exec.clone()
        .with_user_receipt(ReceiptCommand {
            family: "F21",
            command: "self-service.app.revoke",
        })
        .run_user_command(
            ActorId::new(user).expect("verified actor"),
            OperationId(operation),
            "UPDATE app_passwords SET revoked_at=now() WHERE id=$2 AND user_id=$1 AND revoked_at IS NULL RETURNING id",
            &[(&user, Type::INT8), (&id, Type::INT8)],
            |rows| Ok(!rows.is_empty()),
        )
        .await
}

/// Registered default-enabled compose switches. Go caches these shared rows;
/// a missing row uses its compiled default, and a failed advisory read is OFF.
pub async fn advisory_enabled(exec: &ScopedExecutor, key: &str) -> bool {
    exec.read(
        "SELECT enabled FROM feature_toggles WHERE key=$1",
        &[(&key, Type::TEXT)],
    )
    .await
    .ok()
    .map(|rows| rows.first().map_or(true, |row| row.get(0)))
    .unwrap_or(false)
}

/// Resolve the account slot from the verified actor, never a body mailbox ID.
pub async fn primary_mailbox(exec: &ScopedExecutor, actor: &AuthContext) -> Option<i64> {
    let user = actor.user_id();
    exec.read_scoped(
        &actor.database_scope(),
        "SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary=TRUE LIMIT 1",
        &[(&user, Type::INT8)],
    )
    .await
    .ok()?
    .first()?
    .try_get(0)
    .ok()
}

/// Read-only DLP advisory: the existing reducer is the send-time policy seam.
pub async fn dlp_check(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    mailbox: i64,
    recipients: &str,
    subject: &str,
    text: &str,
    html: &str,
) -> Option<String> {
    exec.read_scoped(
        &mailbox_scope(actor, mailbox),
        "SELECT dlp_evaluate_draft($1,$2::text::jsonb,$3,$4,$5)::text",
        &[
            (&mailbox, Type::INT8),
            (&recipients, Type::TEXT),
            (&subject, Type::TEXT),
            (&text, Type::TEXT),
            (&html, Type::TEXT),
        ],
    )
    .await
    .ok()?
    .first()?
    .try_get(0)
    .ok()
}

/// `encoding/json` compacts RawMessage without sorting its nested object keys.
/// Input comes from PostgreSQL JSONB, so token validation belongs to PostgreSQL.
fn compact_raw(raw: &str) -> String {
    let (mut quoted, mut escaped) = (false, false);
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if quoted {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
            out.push(ch);
        } else if !matches!(ch, ' ' | '\t' | '\r' | '\n') {
            out.push(ch);
        }
    }
    out.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// The target is selected only after the HTTP permission gate. Every read
/// repeats the verified actor/domain reach, including the profile projection.
/// Frozen Go independently substitutes [] on chart errors and null on profile error.
pub async fn org_chart(exec: &ScopedExecutor, actor: &AuthContext, target: i64) -> Option<String> {
    let user = actor.user_id();
    let params: &[setjoin_pg::Param<'_>] = &[(&user, Type::INT8), (&target, Type::INT8)];
    let allowed=exec.read("SELECT EXISTS(SELECT 1 FROM users a JOIN users t ON t.domain_id=a.domain_id WHERE a.id=$1 AND t.id=$2)",params)
        .await.ok()?.first()?.try_get::<_,bool>(0).ok()?;
    if !allowed {
        return None;
    }
    let mut values = Vec::new();
    for (sql,default) in [
        ("SELECT org_chart_managers($2)::text WHERE EXISTS(SELECT 1 FROM users a JOIN users t ON t.domain_id=a.domain_id WHERE a.id=$1 AND t.id=$2)","[]"),
        ("SELECT org_chart_reports($2,3)::text WHERE EXISTS(SELECT 1 FROM users a JOIN users t ON t.domain_id=a.domain_id WHERE a.id=$1 AND t.id=$2)","[]"),
        ("SELECT jsonb_build_object('id',u.id::text,'email',u.email,'displayName',u.display_name,'firstName',u.first_name,'lastName',u.last_name,'jobTitle',u.job_title,'department',d.name,'avatar',CASE WHEN u.avatar_sha256 IS NOT NULL THEN jsonb_build_object('blobId',u.avatar_sha256) END)::text FROM users u JOIN users a ON a.domain_id=u.domain_id LEFT JOIN departments d ON d.id=u.department_id WHERE a.id=$1 AND u.id=$2","null"),
    ] {
        let value=exec.read(sql,params).await.ok().and_then(|rows|rows.first().and_then(|r|r.try_get::<_,String>(0).ok())).unwrap_or_else(||default.into());
        values.push(compact_raw(&value));
    }
    Some(format!(
        "{{\"managers\":{},\"reports\":{},\"user\":{}}}\n",
        values[0], values[1], values[2]
    ))
}

/// Only server-resolved, actor-owned mailbox IDs enter this scope constructor.
fn mailbox_scope(actor: &AuthContext, mailbox: i64) -> setjoin_pg::MailboxAuthContext {
    use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
    setjoin_pg::MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified actor"),
        MailboxId::new(mailbox).expect("owned primary mailbox"),
        Generation(1),
    )
}

/// Compose warnings are advisory. Preserve Go's warning-group order, duplicate
/// recipients, per-user preference, dates-only OOO seam and swallowed read errors.
pub async fn mailtips(
    exec: &ScopedExecutor,
    worker: &ScopedExecutor,
    actor: &AuthContext,
    recipients: &str,
    from: &str,
) -> String {
    use std::collections::{HashMap, HashSet};
    let mut warnings = Vec::new();
    if recipients.is_empty() && from.is_empty() {
        return "{\"warnings\":[]}\n".into();
    }
    let clean = recipients
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if clean.len() > 25 {
        warnings.push(json!({"type":"large_audience","message":format!("Your message will be sent to {} recipients",clean.len()),"count":clean.len()}));
    }
    if !clean.is_empty() {
        let user = actor.user_id();
        let external = advisory_enabled(exec, "feature.external_sender_warn").await
            && exec
                .read(
                    "SELECT COALESCE(external_sender_warning,TRUE) FROM users WHERE id=$1",
                    &[(&user, Type::INT8)],
                )
                .await
                .ok()
                .and_then(|rows| rows.first().map(|r| r.get::<_, bool>(0)))
                .unwrap_or(false);
        if external {
            // Go ranges a map: ordering between distinct domains is unspecified.
            let mut groups = HashMap::<String, Vec<&str>>::new();
            for recipient in &clean {
                if let Some((_, domain)) = recipient.split_once('@') {
                    groups
                        .entry(setjoin_authz::address::lower(domain))
                        .or_default()
                        .push(recipient);
                }
            }
            if !groups.is_empty() {
                let names = groups.keys().cloned().collect::<Vec<_>>();
                let local = exec
                    .read_iterated(
                        "SELECT name FROM domains WHERE name=ANY($1)",
                        &[(&names, Type::TEXT_ARRAY)],
                    )
                    .await
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|r| r.try_get::<_, String>(0).ok())
                    .collect::<HashSet<_>>();
                for (domain, recipients) in groups {
                    if !local.contains(&domain) {
                        for recipient in recipients {
                            warnings.push(json!({"type":"external_recipient","recipient":recipient,"domain":domain}));
                        }
                    }
                }
            }
        }
        if let Some(mailbox) = primary_mailbox(exec, actor).await {
            let emails = json!(clean).to_string();
            if let Ok(rows) = exec
                .read_scoped(
                    &mailbox_scope(actor, mailbox),
                    "SELECT recipients_ooo_status($1,$2::text::jsonb)::text",
                    &[(&mailbox, Type::INT8), (&emails, Type::TEXT)],
                )
                .await
            {
                if let Some(raw) = rows.first().and_then(|r| r.try_get::<_, String>(0).ok()) {
                    #[derive(serde::Deserialize)]
                    struct Ooo {
                        #[serde(default)]
                        email: Option<String>,
                        until: Option<String>,
                    }
                    if let Ok(rows) = serde_json::from_str::<Vec<Ooo>>(&raw) {
                        for row in rows {
                            warnings.push(json!({"type":"ooo","recipient":row.email.unwrap_or_default(),"until":row.until}));
                        }
                    }
                }
            }
        }
    }
    if !from.is_empty() {
        let user = actor.user_id();
        // Delegate-side rows belong to another mailbox; the authenticated user
        // is the delegate predicate, on the dedicated BYPASSRLS credential.
        let allowed=worker.read("SELECT EXISTS(SELECT 1 FROM mailbox_delegates md JOIN mailboxes mb ON mb.id=md.mailbox_id WHERE md.user_id=$1 AND mb.email=$2 AND md.permission IN ('send_as','full_access'))",
            &[(&user,Type::INT8),(&from,Type::TEXT)]).await.ok().and_then(|rows|rows.first().map(|r|r.get::<_,bool>(0))).unwrap_or(false);
        if !allowed && from != actor.email() {
            warnings.push(json!({"type":"no_send_as","message":format!("You don't have permission to send as {from}"),"from":from}));
        }
    }
    object(&[("warnings", json!(warnings))]) + "\n"
}

/// Mailbox-keyed MDN publication. Policy, message ownership, deduplication and
/// queue/receipt writes remain in the existing send_read_receipt transaction.
pub async fn read_receipt(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    message: i64,
    consent: bool,
    operation: [u8; 16],
) -> Option<setjoin_pg::CommandOutcome<String, StatementFailure>> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let mailbox = primary_mailbox(exec, actor).await?;
    let auth = mailbox_scope(actor, mailbox);
    let email = actor.email();
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(
            Sha256::digest(format!("{message}:{consent}:{email}").as_bytes()).into(),
        ),
        command: (),
    };
    Some(setjoin_pg::run_receipted_command(exec,
        setjoin_pg::ReceiptCommand{family:"F21",command:"self-service.read-receipt"},
        &envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
        "SELECT send_read_receipt($1::bigint,$4::bigint,$5::text,$6::boolean)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[(&message,Type::INT8),(&email,Type::TEXT),(&consent,Type::BOOL)],
        |rows|rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).ok_or_else(||StatementFailure{sqlstate:None,hint:None,message:"invalid read-receipt result".into()}),
    ).await)
}
