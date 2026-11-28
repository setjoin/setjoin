//! Blob and recovery-upload family contracts.
#![forbid(unsafe_code)]

pub mod sql;
pub use sql::SQL_CONTRACTS;

use setjoin_authz::principals::{TxFactory, UserPrincipal};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{Digest, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, StatementFailure};
use sha2::{Digest as _, Sha256};

fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}

fn envelope(user: &UserPrincipal, operation: [u8; 16], payload: &str) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: AuthorityKey {
            actor: user.user(),
            scope: ResourceScope::User(user.user()),
            generation: user.generation(),
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(payload.as_bytes()).into()),
        command: (),
    }
}

/// Go's UUID parser accepts canonical, compact, braced and URN spellings.
/// Zero UUIDs are rejected by the recovery HTTP boundary.
pub fn recovery_uuid(value: &str) -> Option<String> {
    if !value.is_ascii() {
        return None;
    }
    let value = if value.len() == 45 && value[..9].eq_ignore_ascii_case("urn:uuid:") {
        &value[9..]
    } else if value.len() == 38 && value.starts_with('{') && value.ends_with('}') {
        &value[1..37]
    } else {
        value
    };
    let compact = if value.len() == 36 {
        if [8, 13, 18, 23]
            .iter()
            .any(|&at| value.as_bytes()[at] != b'-')
        {
            return None;
        }
        value.replace('-', "")
    } else if value.len() == 32 {
        value.to_owned()
    } else {
        return None;
    };
    if !compact.bytes().all(|b| b.is_ascii_hexdigit()) || compact.bytes().all(|b| b == b'0') {
        return None;
    }
    let compact = compact.to_ascii_lowercase();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &compact[..8],
        &compact[8..12],
        &compact[12..16],
        &compact[16..20],
        &compact[20..]
    ))
}

/// Call Go's existing atomic abort reducer. The authenticated actor is the
/// reducer's ownership predicate; the URL supplies only the target identifier.
/// Chunk rows intentionally survive for the cleanup worker, exactly as in Go.
pub async fn abort_upload(
    factory: &TxFactory,
    user: &UserPrincipal,
    session: &str,
    operation: [u8; 16],
) -> CommandOutcome<Vec<String>, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(user, operation, &format!("recovery.abort:{session}"));
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::ABORT_UPLOAD,
            &[&actor, &session],
            Some(ReceiptCommand {
                family: "F16",
                command: "mail_recovery_upload_abort",
            }),
            |rows| {
                let invalid = || StatementFailure {
                    hint: None,
                    sqlstate: None,
                    message: "invalid recovery abort result".into(),
                };
                let raw: String = rows
                    .first()
                    .ok_or_else(invalid)?
                    .try_get(0)
                    .map_err(|_| invalid())?;
                let value: serde_json::Value = serde_json::from_str(&raw).map_err(|_| invalid())?;
                value["objectKeys"]
                    .as_array()
                    .ok_or_else(invalid)?
                    .iter()
                    .map(|key| key.as_str().map(str::to_owned).ok_or_else(invalid))
                    .collect()
            },
        )
        .await
}

/// Go's consent reducer owns the locked artifact, current affected-user or
/// full-delegate authorization, idempotent consent timestamp and core audit.
pub async fn fork_consent(
    factory: &TxFactory,
    user: &UserPrincipal,
    artifact: &str,
    device: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(
        user,
        operation,
        &format!("recovery.fork:{artifact}:{device}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::FORK_CONSENT,
            &[&actor, &artifact, &device],
            Some(ReceiptCommand {
                family: "F16",
                command: "mail_recovery_fork_consent",
            }),
            |rows| {
                rows.first()
                    .and_then(|row| row.try_get(0).ok())
                    .ok_or_else(|| StatementFailure {
                        hint: None,
                        sqlstate: None,
                        message: "invalid fork consent result".into(),
                    })
            },
        )
        .await
}

pub struct UploadItem {
    pub incident: String,
    pub next_offset: i64,
    pub size: i64,
    pub available: bool,
}

pub fn decode_upload_item(rows: &[Row]) -> Option<UploadItem> {
    rows.first().map(|row| UploadItem {
        incident: row.get(0),
        next_offset: row.get(1),
        size: row.get(2),
        available: row.get(3),
    })
}

pub struct ExistingChunk {
    pub size: i32,
    pub digest: String,
    pub key: String,
}

pub fn decode_existing_chunk(rows: &[Row]) -> Option<ExistingChunk> {
    rows.first().map(|row| ExistingChunk {
        size: row.get(0),
        digest: row.get(1),
        key: row.get(2),
    })
}

pub struct ChunkRecord<'a> {
    pub session: &'a str,
    pub item: &'a str,
    pub start: i64,
    pub size: i32,
    pub digest: &'a str,
    pub key: &'a str,
}

/// Existing reducer commits the exact chunk row and both acknowledged offsets.
pub async fn record_chunk(
    factory: &TxFactory,
    user: &UserPrincipal,
    chunk: ChunkRecord<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(
        user,
        operation,
        &format!(
            "recovery.chunk:{}:{}:{}:{}:{}:{}",
            chunk.session, chunk.item, chunk.start, chunk.size, chunk.digest, chunk.key
        ),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::RECORD_CHUNK,
            &[
                &actor,
                &chunk.session,
                &chunk.item,
                &chunk.start,
                &chunk.size,
                &chunk.digest,
                &chunk.key,
            ],
            Some(ReceiptCommand {
                family: "F16",
                command: "mail_recovery_upload_chunk_record",
            }),
            |rows| {
                rows.first()
                    .and_then(|row| row.try_get(0).ok())
                    .ok_or_else(|| StatementFailure {
                        hint: None,
                        sqlstate: None,
                        message: "invalid chunk record result".into(),
                    })
            },
        )
        .await
}

/// Inclusive byte offsets and declared full size of a recovery upload chunk.
#[derive(Debug, PartialEq, Eq)]
pub struct ChunkRange {
    pub start: i64,
    pub end: i64,
    pub total: i64,
}

impl ChunkRange {
    /// Go permits at most 256 KiB per recovery upload chunk.
    pub fn fits_chunk_limit(&self) -> bool {
        self.start >= 0
            && self
                .end
                .checked_sub(self.start)
                .is_some_and(|size| (0..256 * 1024).contains(&size))
    }
}

/// Parse the canonical Content-Range syntax accepted by Go's recovery handler.
pub fn parse_chunk_range(value: &str) -> Option<ChunkRange> {
    let (bounds, total) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (start, end) = bounds.split_once('-')?;
    let decimal = |s: &str| {
        let n = s.parse::<i64>().ok()?;
        (n >= 0 && n.to_string() == s).then_some(n)
    };
    let (start, end, total) = (decimal(start)?, decimal(end)?, decimal(total)?);
    (start <= end && end < total).then_some(ChunkRange { start, end, total })
}

/// Lists recovery incidents visible to the verified caller using the SECURITY
/// DEFINER reducer. Request data cannot supply the user identity.
pub async fn user_incidents(
    factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let user_id = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::USER_INCIDENTS, &[&user_id])
        .await?;
    let row = rows.first().ok_or_else(|| StatementFailure {
        hint: None,
        sqlstate: None,
        message: "recovery incident list returned no row".into(),
    })?;
    row.try_get(0).map_err(|error| StatementFailure {
        hint: None,
        sqlstate: None,
        message: error.to_string(),
    })
}

pub fn decode_blob_owned(rows: &[Row]) -> Result<bool, StatementFailure> {
    rows.first()
        .and_then(|row| row.try_get(0).ok())
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "blob ownership returned no boolean".into(),
        })
}

pub struct ItemCommit {
    pub digest: String,
    pub size: i64,
    pub role: String,
    pub status: String,
    pub object_ref: String,
}

pub fn decode_item_for_commit(rows: &[Row]) -> Option<ItemCommit> {
    rows.first().map(|row| ItemCommit {
        digest: row.get(0),
        size: row.get(1),
        role: row.get(2),
        status: row.get(3),
        object_ref: row.get(4),
    })
}

pub struct QuarantineChunk {
    pub start: i64,
    pub size: i32,
    pub digest: String,
    pub key: String,
}

pub fn decode_item_chunks(rows: &[Row]) -> Vec<QuarantineChunk> {
    rows.iter()
        .map(|row| QuarantineChunk {
            start: row.get(0),
            size: row.get(1),
            digest: row.get(2),
            key: row.get(3),
        })
        .collect()
}

pub async fn verify_item(
    factory: &TxFactory,
    user: &UserPrincipal,
    session: &str,
    item: &str,
    object_ref: &str,
    staging_key: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(
        user,
        operation,
        &format!("recovery.verify:{session}:{item}:{object_ref}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::VERIFY_ITEM,
            &[&actor, &session, &item, &object_ref, &staging_key],
            Some(ReceiptCommand {
                family: "F16",
                command: "mail_recovery_upload_item_verify",
            }),
            |rows| {
                rows.first()
                    .and_then(|row| row.try_get(0).ok())
                    .ok_or_else(|| StatementFailure {
                        hint: None,
                        sqlstate: None,
                        message: "invalid item verification result".into(),
                    })
            },
        )
        .await
}

/// The frozen PUT transaction: admission, caller charge, GC reactivation, and
/// durable staging promote recovery (#243/#550/#551).
#[allow(clippy::too_many_arguments)]
pub async fn account_upload(
    factory: &TxFactory,
    user: &UserPrincipal,
    hash: &str,
    reference: &str,
    size: i64,
    content_type: &str,
    staging_key: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(
        user,
        operation,
        &format!("blob.put:{hash}:{size}:{content_type}"),
    );
    let grace: i32 = std::env::var("BLOB_RECLAIM_GRACE_MINUTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(1440);
    let quota: i64 = std::env::var("BLOB_USER_QUOTA_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::ACCOUNT_UPLOAD,
            &[
                &actor,
                &hash,
                &reference,
                &size,
                &content_type,
                &grace,
                &quota,
                &staging_key,
            ],
            Some(ReceiptCommand {
                family: "F16",
                command: "blob_upload_account",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(|| StatementFailure {
                        hint: None,
                        sqlstate: None,
                        message: "invalid blob accounting result".into(),
                    })
            },
        )
        .await
}

/// Cancels a pending `blob.promote_recover` item iff still unleased and matching
/// `(hash, staging_key)`. Returns `true` when safe for caller to delete staging.
pub async fn complete_promote_recover(
    factory: &TxFactory,
    user: &UserPrincipal,
    work_item_id: i64,
    hash: &str,
    staging_key: &str,
    operation: [u8; 16],
) -> Result<bool, StatementFailure> {
    let env = envelope(
        user,
        operation,
        &format!("blob.promote_recover.complete:{work_item_id}:{hash}"),
    );
    match factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::COMPLETE_PROMOTE_RECOVER,
            &[&work_item_id, &hash, &staging_key],
            None,
            |rows| {
                Ok(rows
                    .first()
                    .and_then(|r| r.try_get::<_, bool>(0).ok())
                    .unwrap_or(false))
            },
        )
        .await
    {
        CommandOutcome::Committed(done) => Ok(done),
        CommandOutcome::RolledBack(_) | CommandOutcome::Unknown { .. } => Ok(false),
    }
}

pub fn decode_attachment_metadata(rows: &[Row]) -> Option<(i64, String)> {
    rows.first().map(|r| (r.get(0), r.get(1)))
}

pub struct BeginUpload<'a> {
    pub session: &'a str,
    pub incident: &'a str,
    pub mailbox: i64,
    pub device: &'a str,
    pub artifact: &'a str,
    pub eligibility: &'a str,
    pub receipt: &'a str,
    pub inventory: &'a str,
    pub consented: String,
    pub idempotency: &'a str,
}

/// Existing reducer locks admission budgets and atomically reserves all items.
pub async fn begin_upload(
    factory: &TxFactory,
    user: &UserPrincipal,
    offer: BeginUpload<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(
        user,
        operation,
        &format!("recovery.begin:{}:{}", offer.session, offer.receipt),
    );
    let consented = offer.consented;
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::BEGIN_UPLOAD,
            &[
                &actor,
                &offer.session,
                &offer.incident,
                &offer.mailbox,
                &offer.device,
                &offer.artifact,
                &offer.eligibility,
                &offer.receipt,
                &offer.inventory,
                &consented,
                &offer.idempotency,
            ],
            Some(ReceiptCommand {
                family: "F16",
                command: "mail_recovery_upload_begin",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(|| StatementFailure {
                        hint: None,
                        sqlstate: None,
                        message: "invalid recovery begin result".into(),
                    })
            },
        )
        .await
}

pub struct FinalizeItem {
    pub reference: Option<String>,
    pub size: i64,
    pub eligibility: String,
    pub status: String,
}

pub fn decode_finalize_item(rows: &[Row]) -> Option<FinalizeItem> {
    rows.first().map(|r| FinalizeItem {
        reference: r.get(0),
        size: r.get(1),
        eligibility: r.get(2),
        status: r.get(3),
    })
}

pub fn decode_replay_finalize(rows: &[Row]) -> Option<String> {
    rows.first().map(|r| r.get(0))
}

pub struct Quarantine<'a> {
    pub session: &'a str,
    pub artifact: &'a str,
    pub parsed: &'a str,
    pub malware: &'a str,
    pub rejection: Option<&'a str>,
}

pub async fn quarantine(
    factory: &TxFactory,
    user: &UserPrincipal,
    offer: Quarantine<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(
        user,
        operation,
        &format!("recovery.finalize:{}:{}", offer.session, offer.parsed),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::QUARANTINE,
            &[
                &actor,
                &offer.session,
                &offer.artifact,
                &offer.parsed,
                &offer.malware,
                &offer.rejection,
            ],
            Some(ReceiptCommand {
                family: "F16",
                command: "mail_recovery_artifact_quarantine",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(|| StatementFailure {
                        hint: None,
                        sqlstate: None,
                        message: "invalid recovery quarantine result".into(),
                    })
            },
        )
        .await
}
