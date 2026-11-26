//! JMAP HTTP blob authority. Account selectors never supply the actor identity.
use setjoin_authz::principals::{ReadCapability, TxFactory, UserPrincipal};
use setjoin_contracts::command::CommandEnvelope;
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, StatementFailure};

use crate::sql;

/// Check whether `user` has read access to `account` (own primary mailbox or
/// any mail delegate grant on `account`).
pub async fn account_read(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    primary_mailbox: Option<i64>,
    account: i64,
) -> Result<bool, StatementFailure> {
    if primary_mailbox == Some(account) {
        return Ok(true);
    }
    if account <= 0 {
        return Ok(false);
    }
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &sql::HTTP_BLOB_ACCOUNT_READ, &[&account, &uid])
        .await?;
    Ok(rows
        .first()
        .is_some_and(|r| r.try_get::<_, bool>(0).unwrap_or(false)))
}

#[allow(clippy::too_many_arguments)]
pub async fn account_upload(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    envelope: &CommandEnvelope<()>,
    hash: &str,
    reference: &str,
    size: i64,
    content_type: &str,
    grace: i32,
    quota: i64,
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            envelope,
            std::time::Instant::now() + std::time::Duration::from_secs(30),
            &sql::HTTP_BLOB_ACCOUNT_UPLOAD,
            &[
                &uid,
                &hash,
                &reference,
                &size,
                &content_type,
                &grace,
                &quota,
            ],
            Some(ReceiptCommand {
                family: "jmap",
                command: "blob.upload",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(|| StatementFailure {
                        hint: None,
                        sqlstate: None,
                        message: "missing upload accounting".into(),
                    })
            },
        )
        .await
}

pub async fn metadata(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    hash: &str,
) -> Result<Option<(i64, String)>, StatementFailure> {
    let rows = tx_factory
        .run_user_read_contract(user, &sql::HTTP_BLOB_METADATA, &[&hash])
        .await?;
    Ok(rows
        .first()
        .and_then(|r| Some((r.try_get(0).ok()?, r.try_get(1).ok()?))))
}

/// Decode rows produced by [`crate::sql::HTTP_BLOB_DOWNLOAD_ALLOWED`].
pub fn decode_download_allowed(rows: &[Row]) -> bool {
    rows.first()
        .is_some_and(|r| r.try_get::<_, bool>(0).unwrap_or(false))
}

/// Raw recovery is a GET with server-global continuity writes. Runs via
/// [`TxFactory::run_mailbox_audited_read_contract`] strictly from a verified
/// [`ReadCapability`].
pub async fn recovery_context(
    tx_factory: &TxFactory,
    read: &ReadCapability,
    envelope: &CommandEnvelope<()>,
    message: i64,
    boot: &str,
) -> CommandOutcome<String, StatementFailure> {
    let mailbox = read.mailbox().get();
    tx_factory
        .run_mailbox_audited_read_contract(
            read,
            envelope,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
            &sql::HTTP_BLOB_RECOVERY_CONTEXT,
            &[&mailbox, &message, &boot],
            Some(ReceiptCommand {
                family: "jmap",
                command: "recovery.raw",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(|| StatementFailure {
                        hint: None,
                        sqlstate: None,
                        message: "missing recovery context".into(),
                    })
            },
        )
        .await
}

/// Issue continuity receipt context for `Email/recoveryReceipt` (`1..=64` IDs).
/// Commits and releases the database transaction before callers read S3 or sign.
pub async fn recovery_receipt_contexts(
    tx_factory: &TxFactory,
    read: &ReadCapability,
    envelope: &CommandEnvelope<()>,
    ids: &[i64],
    boot: &str,
) -> CommandOutcome<String, StatementFailure> {
    let mailbox = read.mailbox().get();
    let ids = ids.to_vec();
    tx_factory
        .run_mailbox_audited_read_contract(
            read,
            envelope,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
            &sql::HTTP_BLOB_RECOVERY_RECEIPT_CONTEXTS,
            &[&mailbox, &ids, &boot],
            Some(ReceiptCommand {
                family: "jmap",
                command: "recovery.receipt",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(|| StatementFailure {
                        hint: None,
                        sqlstate: None,
                        message: "missing recovery receipt context".into(),
                    })
            },
        )
        .await
}

pub async fn transfer_device(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    fingerprint: &str,
    platform: &str,
) -> Result<Option<i64>, StatementFailure> {
    if fingerprint.is_empty() || !matches!(platform, "desktop" | "ios" | "android") {
        return Ok(None);
    }
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(
            user,
            &sql::HTTP_BLOB_TRANSFER_DEVICE,
            &[&uid, &fingerprint, &platform],
        )
        .await?;
    Ok(rows.first().and_then(|r| r.try_get(0).ok()))
}

pub async fn transfer_policy(
    tx_factory: &TxFactory,
    read: &ReadCapability,
    device: i64,
) -> Result<String, StatementFailure> {
    let mailbox = read.mailbox().get();
    let rows = tx_factory
        .run_mailbox_read_contract(read, &sql::HTTP_BLOB_TRANSFER_POLICY, &[&mailbox, &device])
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "missing transfer policy".into(),
        })
}
