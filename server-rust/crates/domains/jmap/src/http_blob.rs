//! JMAP HTTP blob authority. Account selectors never supply the actor identity.
use setjoin_contracts::command::CommandEnvelope;
use setjoin_pg::{
    CommandOutcome, MailboxAuthContext, ReceiptCommand, ScopedExecutor, StatementFailure, Type,
    run_receipted_command,
};

pub async fn account_read(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    account: i64,
) -> Result<bool, StatementFailure> {
    setjoin_authz::mailbox::can_read(exec, auth, account).await
}

pub async fn account_upload(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    envelope: &CommandEnvelope<()>,
    hash: &str,
    reference: &str,
    size: i64,
    content_type: &str,
    grace: i32,
    quota: i64,
) -> CommandOutcome<String, StatementFailure> {
    run_receipted_command(exec,ReceiptCommand{family:"jmap",command:"blob.upload"},envelope,auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
        "SELECT blob_upload_account($2,$4,$5,$6,$7,$8,$9)::text WHERE $1::bigint>0 AND $3::text<>''",&[(&hash,Type::TEXT),(&reference,Type::TEXT),(&size,Type::INT8),(&content_type,Type::TEXT),(&grace,Type::INT4),(&quota,Type::INT8)],
        |rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(||StatementFailure{hint:None,sqlstate:None,message:"missing upload accounting".into()})).await
}

pub async fn metadata(
    exec: &ScopedExecutor,
    hash: &str,
) -> Result<Option<(i64, String)>, StatementFailure> {
    let rows=exec.read("SELECT size_bytes,COALESCE(content_type,'application/octet-stream') FROM blobs WHERE sha256=$1",&[(&hash,Type::TEXT)]).await?;
    Ok(rows.first().map(|r| (r.get(0), r.get(1))))
}
pub async fn download_allowed(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    account: &str,
    hash: &str,
) -> Result<bool, StatementFailure> {
    let delegated = if let Some(account) = account
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0 && *n != auth.mailbox().get())
    {
        if account_read(exec, auth, account).await.unwrap_or(false) {
            account
        } else {
            0
        }
    } else {
        0
    };
    let user = auth.actor().get();
    let rows=exec.read("SELECT EXISTS(SELECT 1 FROM message_attachments ma JOIN messages m ON m.id=ma.message_id JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE ma.blob_sha256=$1 AND (mb.user_id=$2 OR mb.id=$3))",&[(&hash,Type::TEXT),(&user,Type::INT8),(&delegated,Type::INT8)]).await?;
    Ok(rows.first().is_some_and(|r| r.get(0)))
}

/// Raw recovery is a GET with server-global continuity writes. Account scope
/// has passed Go's primary/delegate admission before this scoped reducer.
pub async fn recovery_context(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    envelope: &CommandEnvelope<()>,
    message: i64,
    boot: &str,
) -> CommandOutcome<String, StatementFailure> {
    run_receipted_command(exec,ReceiptCommand{family:"jmap",command:"recovery.raw"},envelope,auth,std::time::Instant::now()+std::time::Duration::from_secs(10),
        "SELECT continuity_recovery_receipt_context($1,ARRAY[$4],$5::text::uuid)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[(&message,Type::INT8),(&boot,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(||StatementFailure{hint:None,sqlstate:None,message:"missing recovery context".into()})).await
}

pub async fn transfer_device(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    fingerprint: &str,
    platform: &str,
) -> Result<Option<i64>, StatementFailure> {
    if fingerprint.is_empty() || !matches!(platform, "desktop" | "ios" | "android") {
        return Ok(None);
    }
    let user = auth.actor().get();
    let rows=exec.read("SELECT id FROM user_devices WHERE user_id=$1 AND fingerprint_hash=sha256($2::text::bytea) AND platform=$3 AND NOT wipe_requested ORDER BY id ASC LIMIT 1",&[(&user,Type::INT8),(&fingerprint,Type::TEXT),(&platform,Type::TEXT)]).await?;
    Ok(rows.first().map(|r| r.get(0)))
}
pub async fn transfer_policy(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    device: i64,
) -> Result<String, StatementFailure> {
    let mailbox = auth.mailbox().get();
    let rows = exec
        .read(
            "SELECT offline_effective_policy_snapshot($1,$2)::text",
            &[(&mailbox, Type::INT8), (&device, Type::INT8)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "missing transfer policy".into(),
        })
}
