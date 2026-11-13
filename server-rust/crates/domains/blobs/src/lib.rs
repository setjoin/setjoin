//! Blob and recovery-upload family contracts.
#![forbid(unsafe_code)]

use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId, OperationId},
};
use setjoin_pg::{CommandOutcome, MailboxAuthContext, StatementFailure, Type};
use sha2::{Digest as _, Sha256};

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
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    session: &str,
    operation: [u8; 16],
) -> CommandOutcome<Vec<String>, StatementFailure> {
    // AuthContext is sealed and contains positive, database-derived identities.
    let auth = MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified actor"),
        MailboxId::new(actor.mailbox_id()).expect("authenticated mailbox"),
        Generation(1),
    );
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("recovery.abort:{session}")).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec, setjoin_pg::ReceiptCommand{family:"F16",command:"mail_recovery_upload_abort"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
        "SELECT mail_recovery_upload_abort($2,$4::text::uuid)::text WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",
        &[(&session,Type::TEXT)], |rows| {
            let invalid = ||StatementFailure{hint: None,sqlstate:None,message:"invalid recovery abort result".into()};
            let raw: String = rows.first().ok_or_else(invalid)?.try_get(0).map_err(|_|invalid())?;
            let value: serde_json::Value = serde_json::from_str(&raw).map_err(|_|invalid())?;
            value["objectKeys"].as_array().ok_or_else(invalid)?.iter()
                .map(|key|key.as_str().map(str::to_owned).ok_or_else(invalid)).collect()
        }).await
}

/// Go's consent reducer owns the locked artifact, current affected-user or
/// full-delegate authorization, idempotent consent timestamp and core audit.
pub async fn fork_consent(
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    artifact: &str,
    device: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified actor"),
        MailboxId::new(actor.mailbox_id()).expect("authenticated mailbox"),
        Generation(1),
    );
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("recovery.fork:{artifact}:{device}")).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec, setjoin_pg::ReceiptCommand{family:"F16",command:"mail_recovery_fork_consent"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
        "SELECT mail_recovery_fork_consent($2,$4::text::uuid,$5::text::uuid)::text WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",
        &[(&artifact,Type::TEXT),(&device,Type::TEXT)],|rows| {
            rows.first().and_then(|row|row.try_get(0).ok()).ok_or_else(||StatementFailure{hint: None,sqlstate:None,message:"invalid fork consent result".into()})
        }).await
}

pub struct UploadItem {
    pub incident: String,
    pub next_offset: i64,
    pub size: i64,
    pub available: bool,
}

/// Go's byte-plane preflight, always scoped to the sealed uploading actor.
pub async fn upload_item(
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    session: &str,
    item: &str,
) -> Result<Option<UploadItem>, StatementFailure> {
    let user = actor.user_id();
    let rows=exec.read("SELECT s.incident_id::text,i.next_offset,i.declared_size,(s.status='uploading' AND i.status='uploading' AND s.expires_at>clock_timestamp()) FROM mail_recovery_upload_sessions s JOIN mail_recovery_upload_items i ON i.session_id=s.id WHERE s.id=$1::text::uuid AND s.uploading_user_id=$2 AND i.item_id=$3",
        &[(&session,Type::TEXT),(&user,Type::INT8),(&item,Type::TEXT)]).await?;
    Ok(rows.first().map(|row| UploadItem {
        incident: row.get(0),
        next_offset: row.get(1),
        size: row.get(2),
        available: row.get(3),
    }))
}

pub struct ExistingChunk {
    pub size: i32,
    pub digest: String,
    pub key: String,
}

pub async fn chunk_at(
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    session: &str,
    item: &str,
    start: i64,
) -> Result<Option<ExistingChunk>, StatementFailure> {
    let user = actor.user_id();
    let rows=exec.read("SELECT c.size_bytes,encode(c.sha256,'hex'),c.object_key FROM mail_recovery_upload_chunks c JOIN mail_recovery_upload_sessions s ON s.id=c.session_id WHERE c.session_id=$1::text::uuid AND s.uploading_user_id=$2 AND c.item_id=$3 AND c.start_offset=$4",
        &[(&session,Type::TEXT),(&user,Type::INT8),(&item,Type::TEXT),(&start,Type::INT8)]).await?;
    Ok(rows.first().map(|row| ExistingChunk {
        size: row.get(0),
        digest: row.get(1),
        key: row.get(2),
    }))
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
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    chunk: ChunkRecord<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified actor"),
        MailboxId::new(actor.mailbox_id()).expect("authenticated mailbox"),
        Generation(1),
    );
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(
            Sha256::digest(format!(
                "recovery.chunk:{}:{}:{}:{}:{}:{}",
                chunk.session, chunk.item, chunk.start, chunk.size, chunk.digest, chunk.key
            ))
            .into(),
        ),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec, setjoin_pg::ReceiptCommand{family:"F16",command:"mail_recovery_upload_chunk_record"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
        "SELECT mail_recovery_upload_chunk_record($2,$4::text::uuid,$5,$6,$7,$8,$9)::text WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",
        &[(&chunk.session,Type::TEXT),(&chunk.item,Type::TEXT),(&chunk.start,Type::INT8),(&chunk.size,Type::INT4),(&chunk.digest,Type::TEXT),(&chunk.key,Type::TEXT)],|rows| {
            rows.first().and_then(|row|row.try_get(0).ok()).ok_or_else(||StatementFailure{hint: None,sqlstate:None,message:"invalid chunk record result".into()})
        }).await
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

/// Lists recovery incidents visible to the verified caller using Go's
/// worker-credential reducer. Request data cannot supply the user identity.
pub async fn user_incidents(
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
) -> Result<String, setjoin_pg::StatementFailure> {
    let user_id = actor.user_id();
    let rows = exec
        .read(
            "SELECT mail_recovery_user_incident_list($1)::text",
            &[(&user_id, setjoin_pg::Type::INT8)],
        )
        .await?;
    let row = rows.first().ok_or_else(|| setjoin_pg::StatementFailure {
        hint: None,
        sqlstate: None,
        message: "recovery incident list returned no row".into(),
    })?;
    row.try_get(0)
        .map_err(|error| setjoin_pg::StatementFailure {
            hint: None,
            sqlstate: None,
            message: error.to_string(),
        })
}

/// Go's attachment/expense-receipt visibility, scoped to the verified actor.
pub async fn blob_owned(
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    hash: &str,
) -> Result<bool, setjoin_pg::StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read(
            "SELECT EXISTS (SELECT 1 FROM message_attachments ma \
         JOIN messages m ON m.id=ma.message_id AND m.received_at=ma.received_at \
         JOIN mailboxes mb ON mb.id=m.mailbox_id \
         WHERE ma.blob_sha256=$1 AND mb.user_id=$2) \
         OR EXISTS (SELECT 1 FROM hr_expense_receipts her \
         JOIN approval_requests ar ON ar.id=her.approval_request_id \
         WHERE her.blob_sha256=$1 AND (ar.requester_user_id=$2 \
         OR (ar.approver_kind='user' AND ar.approver_ref=$2) \
         OR (ar.approver_kind='role_group' AND EXISTS(SELECT 1 FROM admin_role_assignments ara \
             WHERE ara.role_group_id=ar.approver_ref AND ara.user_id=$2 \
             AND (ara.expires_at IS NULL OR ara.expires_at>now()) \
             AND admin_assignment_active(ara.eligible,ara.activated_until))) \
         OR EXISTS(SELECT 1 FROM admin_role_assignments sa \
             WHERE sa.role_group_id=1 AND sa.user_id=$2 \
             AND (sa.expires_at IS NULL OR sa.expires_at>now()) \
             AND admin_assignment_active(sa.eligible,sa.activated_until))))",
            &[
                (&hash, setjoin_pg::Type::TEXT),
                (&user, setjoin_pg::Type::INT8),
            ],
        )
        .await?;
    rows.first()
        .and_then(|row| row.try_get(0).ok())
        .ok_or_else(|| setjoin_pg::StatementFailure {
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

/// A verified replay remains available for quarantined sessions, as Go does.
pub async fn item_for_commit(
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    session: &str,
    item: &str,
) -> Result<Option<ItemCommit>, StatementFailure> {
    let user = actor.user_id();
    let rows=exec.read("SELECT encode(i.sha256,'hex'),i.declared_size,i.role,i.status,COALESCE(i.object_ref,'') FROM mail_recovery_upload_sessions s JOIN mail_recovery_upload_items i ON i.session_id=s.id WHERE s.id=$1::text::uuid AND s.uploading_user_id=$2 AND i.item_id=$3 AND s.status IN ('uploading','quarantined')",
        &[(&session,Type::TEXT),(&user,Type::INT8),(&item,Type::TEXT)]).await?;
    Ok(rows.first().map(|row| ItemCommit {
        digest: row.get(0),
        size: row.get(1),
        role: row.get(2),
        status: row.get(3),
        object_ref: row.get(4),
    }))
}

pub struct QuarantineChunk {
    pub start: i64,
    pub size: i32,
    pub digest: String,
    pub key: String,
}

pub async fn item_chunks(
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    session: &str,
    item: &str,
) -> Result<Vec<QuarantineChunk>, StatementFailure> {
    let user = actor.user_id();
    let rows=exec.read("SELECT c.start_offset,c.size_bytes,encode(c.sha256,'hex'),c.object_key FROM mail_recovery_upload_chunks c JOIN mail_recovery_upload_sessions s ON s.id=c.session_id WHERE c.session_id=$1::text::uuid AND s.uploading_user_id=$2 AND c.item_id=$3 ORDER BY c.start_offset",
        &[(&session,Type::TEXT),(&user,Type::INT8),(&item,Type::TEXT)]).await?;
    Ok(rows
        .iter()
        .map(|row| QuarantineChunk {
            start: row.get(0),
            size: row.get(1),
            digest: row.get(2),
            key: row.get(3),
        })
        .collect())
}

pub async fn verify_item(
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    session: &str,
    item: &str,
    object_ref: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified actor"),
        MailboxId::new(actor.mailbox_id()).expect("authenticated mailbox"),
        Generation(1),
    );
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(
            Sha256::digest(format!("recovery.verify:{session}:{item}:{object_ref}")).into(),
        ),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec, setjoin_pg::ReceiptCommand{family:"F16",command:"mail_recovery_upload_item_verify"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),"SELECT mail_recovery_upload_item_verify($2,$4::text::uuid,$5,$6)::text WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&session,Type::TEXT),(&item,Type::TEXT),(&object_ref,Type::TEXT)],|rows|rows.first().and_then(|row|row.try_get(0).ok()).ok_or_else(||StatementFailure{hint: None,sqlstate:None,message:"invalid item verification result".into()})).await
}

/// The frozen PUT transaction: admission, caller charge and reclamation arming.
pub async fn account_upload(
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    hash: &str,
    reference: &str,
    size: i64,
    content_type: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified actor"),
        MailboxId::new(actor.mailbox_id()).expect("authenticated mailbox"),
        Generation(1),
    );
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(
            Sha256::digest(format!("blob.put:{hash}:{size}:{content_type}")).into(),
        ),
        command: (),
    };
    let grace: i32 = std::env::var("BLOB_RECLAIM_GRACE_MINUTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(1440);
    let quota: i64 = std::env::var("BLOB_USER_QUOTA_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    setjoin_pg::run_receipted_command(exec, setjoin_pg::ReceiptCommand{family:"F16",command:"blob_upload_account"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
        "SELECT blob_upload_account($2,$4,$5,$6,$7,$8,$9)::text WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",
        &[(&hash,Type::TEXT),(&reference,Type::TEXT),(&size,Type::INT8),(&content_type,Type::TEXT),(&grace,Type::INT4),(&quota,Type::INT8)],
        |rows| rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(||StatementFailure{hint: None,sqlstate:None,message:"invalid blob accounting result".into()})).await
}

/// Attachment-transfer metadata only after the actor-owned or freshly admitted delegate attachment join.
/// The optional delegated mailbox has passed shared can_read for this sealed
/// actor in the current request; zero retains Go's own-mailboxes-only arm.
pub async fn attachment_metadata(
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    hash: &str,
    delegated: i64,
) -> Result<Option<(i64, String)>, StatementFailure> {
    let user = actor.user_id();
    let rows=exec.read("SELECT b.size_bytes,COALESCE(b.content_type,'application/octet-stream') FROM blobs b WHERE b.sha256=$1 AND b.size_bytes BETWEEN 0 AND 8589934592 AND EXISTS(SELECT 1 FROM message_attachments ma JOIN messages m ON m.id=ma.message_id JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE ma.blob_sha256=b.sha256 AND (mb.user_id=$2 OR mb.id=$3))",&[(&hash,Type::TEXT),(&user,Type::INT8),(&delegated,Type::INT8)]).await?;
    Ok(rows.first().map(|r| (r.get(0), r.get(1))))
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
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    offer: BeginUpload<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified actor"),
        MailboxId::new(actor.mailbox_id()).expect("authenticated mailbox"),
        Generation(1),
    );
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(
            Sha256::digest(format!(
                "recovery.begin:{}:{}",
                offer.session, offer.receipt
            ))
            .into(),
        ),
        command: (),
    };
    // Timestamp is parsed at the protocol boundary and sent as canonical text, so
    // the family need not link the driver's chrono adapter.
    let consented = offer.consented;
    setjoin_pg::run_receipted_command(exec, setjoin_pg::ReceiptCommand{family:"F16",command:"mail_recovery_upload_begin"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
 "SELECT mail_recovery_upload_begin($2,$4::text::uuid,$5::text::uuid,$6,$7::text::uuid,$8,$9,$10::text::jsonb,$11::text::jsonb,$12::text::timestamptz,$13::text::uuid)::text WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",
 &[(&offer.session,Type::TEXT),(&offer.incident,Type::TEXT),(&offer.mailbox,Type::INT8),(&offer.device,Type::TEXT),(&offer.artifact,Type::TEXT),(&offer.eligibility,Type::TEXT),(&offer.receipt,Type::TEXT),(&offer.inventory,Type::TEXT),(&consented,Type::TEXT),(&offer.idempotency,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(||StatementFailure{hint: None,sqlstate:None,message:"invalid recovery begin result".into()})).await
}

pub struct FinalizeItem {
    pub reference: Option<String>,
    pub size: i64,
    pub eligibility: String,
    pub status: String,
}
pub async fn finalize_item(
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    session: &str,
) -> Result<Option<FinalizeItem>, StatementFailure> {
    let user = actor.user_id();
    let rows=exec.read("SELECT i.object_ref,i.declared_size,s.eligibility,s.status FROM mail_recovery_upload_sessions s JOIN mail_recovery_upload_items i ON i.session_id=s.id AND i.role='raw' WHERE s.id=$1::text::uuid AND s.uploading_user_id=$2",&[(&session,Type::TEXT),(&user,Type::INT8)]).await?;
    Ok(rows.first().map(|r| FinalizeItem {
        reference: r.get(0),
        size: r.get(1),
        eligibility: r.get(2),
        status: r.get(3),
    }))
}
pub async fn replay_finalize(
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    session: &str,
) -> Result<Option<String>, StatementFailure> {
    let user = actor.user_id();
    let rows=exec.read("SELECT jsonb_build_object('id',id,'status',status,'replayed',true)::text FROM (SELECT a.id,a.status FROM mail_recovery_quarantine_artifacts a JOIN mail_recovery_upload_sessions s ON s.id=a.session_id WHERE s.id=$1::text::uuid AND s.uploading_user_id=$2 UNION ALL SELECT l.quarantine_id,CASE WHEN s.status='deduplicated' THEN 'deduplicated' ELSE l.outcome END FROM mail_recovery_upload_sessions s JOIN mail_recovery_ledger l ON l.artifact_identity=s.artifact_identity WHERE s.id=$1::text::uuid AND s.uploading_user_id=$2 AND s.status='deduplicated') replay LIMIT 1",&[(&session,Type::TEXT),(&user,Type::INT8)]).await?;
    Ok(rows.first().map(|r| r.get(0)))
}
pub struct Quarantine<'a> {
    pub session: &'a str,
    pub artifact: &'a str,
    pub parsed: &'a str,
    pub malware: &'a str,
    pub rejection: Option<&'a str>,
}
pub async fn quarantine(
    exec: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    offer: Quarantine<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified actor"),
        MailboxId::new(actor.mailbox_id()).expect("authenticated mailbox"),
        Generation(1),
    );
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(
            Sha256::digest(format!(
                "recovery.finalize:{}:{}",
                offer.session, offer.parsed
            ))
            .into(),
        ),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec, setjoin_pg::ReceiptCommand{family:"F16",command:"mail_recovery_artifact_quarantine"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),"SELECT mail_recovery_artifact_quarantine($2,$4::text::uuid,$5::text::uuid,$6::text::jsonb,$7,$8)::text WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&offer.session,Type::TEXT),(&offer.artifact,Type::TEXT),(&offer.parsed,Type::TEXT),(&offer.malware,Type::TEXT),(&offer.rejection,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(||StatementFailure{hint: None,sqlstate:None,message:"invalid recovery quarantine result".into()})).await
}
