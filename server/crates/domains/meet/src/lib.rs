//! Meet and RTC (F13) reducers. The verified user is the only authority; the
//! LiveKit SFU, Egress and ASR sidecars are peripherals and never stored here.
#![forbid(unsafe_code)]

pub mod sql;
pub use sql::SQL_CONTRACTS;

use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{Digest, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, StatementFailure, ToSql};
use setjoin_sql_catalog::SqlContract;
use sha2::{Digest as _, Sha256};

fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}

fn envelope(user: &UserPrincipal, operation: [u8; 16], name: &str) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: AuthorityKey {
            actor: user.user(),
            scope: ResourceScope::User(user.user()),
            generation: user.generation(),
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(name.as_bytes()).into()),
        command: (),
    }
}

fn invalid_result() -> StatementFailure {
    StatementFailure {
        hint: None,
        sqlstate: None,
        message: "invalid meet reducer result".into(),
    }
}

fn void(rows: Vec<Row>) -> Result<(), StatementFailure> {
    if rows.is_empty() {
        Err(invalid_result())
    } else {
        Ok(())
    }
}

/// Decode column 0 of the first row as `String`.
pub fn decode_text0(rows: &[Row]) -> Result<String, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(invalid_result)
}

fn text0(rows: Vec<Row>) -> Result<String, StatementFailure> {
    decode_text0(&rows)
}

/// Go's per-request `feature.meet` gate; an absent row reads OFF.
pub async fn enabled(factory: &TxFactory) -> Result<bool, StatementFailure> {
    let rows = factory.run_public_read_contract(&sql::ENABLED, &[]).await?;
    Ok(rows
        .first()
        .is_some_and(|r| r.try_get::<_, bool>(0).unwrap_or(false)))
}

/// Go's `FeatureFlags` resolution for a key the registry knows: the stored
/// row wins, else the registry default.
pub async fn flag(factory: &TxFactory, key: &str, default: bool) -> Result<bool, StatementFailure> {
    let rows = factory
        .run_public_read_contract(&sql::FLAG, &[&key, &default])
        .await?;
    Ok(rows
        .first()
        .map_or(default, |r| r.try_get::<_, bool>(0).unwrap_or(default)))
}

/// Go's RequireApp entitlement; the HTTP adapter emits its denial and independent audit.
pub async fn entitled(factory: &TxFactory, user: &UserPrincipal) -> Result<bool, StatementFailure> {
    let uid = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::ENTITLED, &[&uid])
        .await?;
    Ok(rows
        .first()
        .is_some_and(|r| r.try_get::<_, bool>(0).unwrap_or(false)))
}

pub async fn list(factory: &TxFactory, user: &UserPrincipal) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    decode_text0(
        &factory
            .run_user_read_contract(user, &sql::LIST, &[&uid])
            .await?,
    )
}

pub async fn get(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    decode_text0(
        &factory
            .run_user_read_contract(user, &sql::GET, &[&uid, &id])
            .await?,
    )
}

pub async fn by_slug(
    factory: &TxFactory,
    user: &UserPrincipal,
    slug: &str,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    decode_text0(
        &factory
            .run_user_read_contract(user, &sql::BY_SLUG, &[&uid, &slug])
            .await?,
    )
}

#[allow(clippy::too_many_arguments)]
async fn mutate<T, D>(
    factory: &TxFactory,
    user: &UserPrincipal,
    operation: [u8; 16],
    name: &'static str,
    contract: &'static SqlContract,
    values: &[&(dyn ToSql + Sync)],
    decode: D,
) -> CommandOutcome<T, StatementFailure>
where
    D: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
{
    let env = envelope(user, operation, name);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            contract,
            values,
            Some(ReceiptCommand {
                family: "F13",
                command: name,
            }),
            decode,
        )
        .await
}

pub struct NewMeeting {
    pub title: String,
    pub start: Option<String>,
    pub end: Option<String>,
    pub chat_channel: Option<i64>,
    pub calendar_event: Option<i64>,
    pub guest_allowed: Option<bool>,
}

/// Times arrive as validated RFC 3339 text; the reducer sees the same instants.
pub async fn create(
    factory: &TxFactory,
    user: &UserPrincipal,
    m: &NewMeeting,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_create",
        &sql::CREATE,
        &[
            &uid,
            &m.title,
            &m.start,
            &m.end,
            &m.chat_channel,
            &m.calendar_event,
            &m.guest_allowed,
        ],
        text0,
    )
    .await
}

pub async fn lock(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    locked: bool,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_lock",
        &sql::LOCK,
        &[&uid, &id, &locked],
        void,
    )
    .await
}

pub async fn set_guest_allowed(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    allowed: bool,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_set_guest_allowed",
        &sql::SET_GUEST_ALLOWED,
        &[&uid, &id, &allowed],
        void,
    )
    .await
}

pub async fn set_role(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    identity: &str,
    role: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_set_role",
        &sql::SET_ROLE,
        &[&uid, &id, &identity, &role],
        void,
    )
    .await
}

// ---- sub-router-a (#286): join/kick/end, lobby, breakouts.

/// `meeting_join` then `meeting_get` in one transaction (Go's one scoped tx):
/// the grant spec and the meeting envelope, both as JSON text. Two statements,
/// because `meeting_get` is STABLE and would not see the join's own writes
/// inside a single statement's snapshot.
pub async fn join(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<(String, String), StatementFailure> {
    let uid = user.user().get();
    let env = envelope(user, operation, "meeting_join");
    factory
        .run_user_effect_write(
            user,
            ReceiptCommand {
                family: "F13",
                command: "meeting_join",
            },
            &env,
            deadline(),
            async move |tx| {
                let spec = tx.query_contract(&sql::JOIN, &[&uid, &id]).await?;
                let meeting = tx.query_contract(&sql::GET, &[&uid, &id]).await?;
                Ok((decode_text0(&spec)?, decode_text0(&meeting)?))
            },
        )
        .await
}

/// Returns the room the target was in (main or an open breakout child).
pub async fn kick(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    identity: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_kick",
        &sql::KICK,
        &[&uid, &id, &identity],
        text0,
    )
    .await
}

/// Returns the parent room name.
pub async fn end(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_end",
        &sql::END,
        &[&uid, &id],
        text0,
    )
    .await
}

/// Egress ids `meeting_end` just moved to `stopping` (Go reads them after the
/// reducer commits; the user GUC scopes the rows, an error reads as none).
pub async fn stopping_egress_ids(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
) -> Result<Vec<String>, StatementFailure> {
    column(factory, user, &sql::STOPPING_EGRESS_IDS, id).await
}

/// Child rooms still open, or closed within 24 h (the worker owns older ones).
pub async fn breakout_rooms(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
) -> Result<Vec<String>, StatementFailure> {
    column(factory, user, &sql::BREAKOUT_ROOMS, id).await
}

async fn column(
    factory: &TxFactory,
    user: &UserPrincipal,
    contract: &'static SqlContract,
    id: i64,
) -> Result<Vec<String>, StatementFailure> {
    Ok(factory
        .run_user_read_contract(user, contract, &[&id])
        .await?
        .iter()
        .filter_map(|r| r.try_get::<_, String>(0).ok())
        .collect())
}

/// The knock lookup: slug and display name of the meeting for the caller.
pub async fn knock_lookup(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
) -> Result<Option<(String, String)>, StatementFailure> {
    let uid = user.user().get();
    let no_slug: Option<String> = None;
    Ok(factory
        .run_user_read_contract(user, &sql::KNOCK_LOOKUP, &[&id, &uid, &no_slug])
        .await?
        .first()
        .and_then(|r| Some((r.try_get(0).ok()?, r.try_get(1).ok()?))))
}

pub async fn knock_create(
    factory: &TxFactory,
    user: &UserPrincipal,
    slug: &str,
    name: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_join_request_create",
        &sql::KNOCK_CREATE,
        &[&slug, &name, &uid],
        text0,
    )
    .await
}

pub async fn admit(
    factory: &TxFactory,
    user: &UserPrincipal,
    request: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_admit",
        &sql::ADMIT,
        &[&uid, &request],
        text0,
    )
    .await
}

pub async fn deny(
    factory: &TxFactory,
    user: &UserPrincipal,
    request: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_deny",
        &sql::DENY,
        &[&uid, &request],
        void,
    )
    .await
}

pub async fn breakout_open(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    count: i64,
    titles: &Option<Vec<String>>,
    auto_assign: bool,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_breakout_open",
        &sql::BREAKOUT_OPEN,
        &[&uid, &id, &count, titles, &auto_assign],
        text0,
    )
    .await
}

pub async fn breakout_assign(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    target: i64,
    breakout: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_breakout_assign",
        &sql::BREAKOUT_ASSIGN,
        &[&uid, &id, &target, &breakout],
        text0,
    )
    .await
}

pub async fn breakout_close(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_breakout_close",
        &sql::BREAKOUT_CLOSE,
        &[&uid, &id],
        text0,
    )
    .await
}

pub async fn breakout_join(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    breakout: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_breakout_join",
        &sql::BREAKOUT_JOIN,
        &[&uid, &id, &breakout],
        text0,
    )
    .await
}

// ---- sub-router-b (#287): recording, captions, presentation, annotation.

/// The meeting's room name, read with the caller's scope (Go's
/// `roomNameForMeeting`). A missing row is an error.
pub async fn room_name(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
) -> Result<String, StatementFailure> {
    decode_text0(
        &factory
            .run_user_read_contract(user, &sql::ROOM_NAME, &[&id])
            .await?,
    )
}

/// `meeting_recording_start`: the committed fact before any Egress call.
pub async fn recording_start(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_recording_start",
        &sql::RECORDING_START,
        &[&uid, &id],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

/// `meeting_recording_bind_egress` (success: egress id and staging key; failure:
/// the reason, which rolls the banner back).
pub async fn recording_bind(
    factory: &TxFactory,
    user: &UserPrincipal,
    recording: i64,
    bound: Option<(&str, &str)>,
    reason: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let (egress, key) = (bound.map(|b| b.0), bound.map(|b| b.1));
    let ok = bound.is_some();
    mutate(
        factory,
        user,
        operation,
        "meeting_recording_bind_egress",
        &sql::RECORDING_BIND,
        &[&recording, &egress, &key, &ok, &reason],
        void,
    )
    .await
}

/// `meeting_recording_stop`: `{recordingId, egressId}` as JSON text.
pub async fn recording_stop(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_recording_stop",
        &sql::RECORDING_STOP,
        &[&uid, &id],
        text0,
    )
    .await
}

/// `meeting_captions_set`: the bot grant spec as JSON text, or `None` when the
/// flag was already as requested.
pub async fn captions_set(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    on: bool,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_captions_set",
        &sql::CAPTIONS_SET,
        &[&uid, &id, &on],
        |rows| {
            rows.first()
                .ok_or_else(invalid_result)?
                .try_get::<_, Option<String>>(0)
                .map_err(|_| invalid_result())
        },
    )
    .await
}

/// One presentation reducer call returning its committed fact as JSON text.
async fn presentation(
    factory: &TxFactory,
    user: &UserPrincipal,
    operation: [u8; 16],
    name: &'static str,
    contract: &'static SqlContract,
    values: &[&(dyn ToSql + Sync)],
) -> CommandOutcome<String, StatementFailure> {
    mutate(factory, user, operation, name, contract, values, text0).await
}

pub async fn presentation_prepare(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    node: i64,
    version: i64,
    digest: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_presentation_prepare",
        &sql::PRESENTATION_PREPARE,
        &[&uid, &id, &node, &version, &digest],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

macro_rules! verb {
    ($fn:ident, $name:literal, $contract:ident, $extra:ident: $ty:ty) => {
        pub async fn $fn(
            factory: &TxFactory,
            user: &UserPrincipal,
            id: i64,
            pid: i64,
            $extra: $ty,
            operation: [u8; 16],
        ) -> CommandOutcome<String, StatementFailure> {
            let uid = user.user().get();
            presentation(
                factory,
                user,
                operation,
                $name,
                &sql::$contract,
                &[&uid, &id, &pid, &$extra],
            )
            .await
        }
    };
}

verb!(
    presentation_ready,
    "meeting_presentation_ready",
    PRESENTATION_READY,
    digest: Option<&str>
);
verb!(
    presentation_start,
    "meeting_presentation_start",
    PRESENTATION_START,
    generation: Option<i64>
);
verb!(
    presentation_recover,
    "meeting_presentation_recover",
    PRESENTATION_RECOVER,
    generation: Option<i64>
);
verb!(
    presentation_end,
    "meeting_presentation_end",
    PRESENTATION_END,
    generation: Option<i64>
);
verb!(
    presentation_revoke,
    "meeting_presentation_revoke",
    PRESENTATION_REVOKE,
    reason: Option<&str>
);

#[allow(clippy::too_many_arguments)]
pub async fn presentation_page(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    pid: i64,
    generation: i64,
    seq: i64,
    page: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    presentation(
        factory,
        user,
        operation,
        "meeting_presentation_page",
        &sql::PRESENTATION_PAGE,
        &[&uid, &id, &pid, &generation, &seq, &page],
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn presentation_presenter(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    pid: i64,
    target: i64,
    takeover: bool,
    generation: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    presentation(
        factory,
        user,
        operation,
        "meeting_presentation_presenter",
        &sql::PRESENTATION_PRESENTER,
        &[&uid, &id, &pid, &target, &takeover, &generation],
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn presentation_source(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    pid: i64,
    node: i64,
    version: i64,
    digest: &str,
    generation: Option<i64>,
    seq: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    presentation(
        factory,
        user,
        operation,
        "meeting_presentation_source_switch",
        &sql::PRESENTATION_SOURCE,
        &[&uid, &id, &pid, &node, &version, &digest, &generation, &seq],
    )
    .await
}

pub async fn presentation_degrade(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    pid: i64,
    generation: Option<i64>,
    reason: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    presentation(
        factory,
        user,
        operation,
        "meeting_presentation_degrade",
        &sql::PRESENTATION_DEGRADE,
        &[&uid, &id, &pid, &generation, &reason],
    )
    .await
}

/// A snapshot commit (`Some(text)`) or a clear (`None`).
#[allow(clippy::too_many_arguments)]
pub async fn presentation_annotation(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    pid: i64,
    generation: i64,
    seq: i64,
    snapshot: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    let clear = snapshot.is_none();
    let bytes: Option<i64> = snapshot.map(|s| s.len() as i64);
    presentation(
        factory,
        user,
        operation,
        "meeting_presentation_annotation_commit",
        &sql::PRESENTATION_ANNOTATION,
        &[
            &uid,
            &id,
            &pid,
            &generation,
            &seq,
            &clear,
            &snapshot,
            &bytes,
        ],
    )
    .await
}

/// The authorized checkpoint read.
pub async fn presentation_checkpoint(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    pid: i64,
) -> Result<String, StatementFailure> {
    presentation_read(factory, user, &sql::PRESENTATION_CHECKPOINT, id, pid).await
}

/// The authorized read of the current committed annotation snapshot.
pub async fn presentation_annotation_read(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    pid: i64,
) -> Result<String, StatementFailure> {
    presentation_read(factory, user, &sql::PRESENTATION_ANNOTATION_READ, id, pid).await
}

async fn presentation_read(
    factory: &TxFactory,
    user: &UserPrincipal,
    contract: &'static SqlContract,
    id: i64,
    pid: i64,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    decode_text0(
        &factory
            .run_user_read_contract(user, contract, &[&uid, &id, &pid])
            .await?,
    )
}

// ---- sub-router-c (#288): local capture, semantic reads, admin registry.

/// `meeting_local_capture_lease_acquire`: the committed lease as JSON text. The
/// reducer commits the `local_registered` recording and banner before the lease.
#[allow(clippy::too_many_arguments)]
pub async fn local_lease_acquire(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    device: &str,
    surfaces: &str,
    producer: &str,
    seconds: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_local_capture_lease_acquire",
        &sql::LOCAL_LEASE_ACQUIRE,
        &[&uid, &id, &device, &surfaces, &producer, &seconds],
        text0,
    )
    .await
}

/// `meeting_local_capture_lease_heartbeat`: the stop fact the device consumes.
#[allow(clippy::too_many_arguments)]
pub async fn local_lease_heartbeat(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    recording: i64,
    generation: i64,
    seq: i64,
    state: &str,
    disk_free: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_local_capture_lease_heartbeat",
        &sql::LOCAL_LEASE_HEARTBEAT,
        &[&uid, &id, &recording, &generation, &seq, &state, &disk_free],
        text0,
    )
    .await
}

/// `meeting_local_capture_lease_stop`: owner or host/cohost stops lease and recording.
pub async fn local_lease_stop(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    recording: i64,
    generation: Option<i64>,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_local_capture_lease_stop",
        &sql::LOCAL_LEASE_STOP,
        &[&uid, &id, &recording, &generation, &reason],
        text0,
    )
    .await
}

/// `meeting_local_capture_register`: the exact received descriptor bytes, which
/// the reducer re-derives segment by segment in the same transaction.
pub async fn local_register(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    recording: i64,
    descriptor: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meeting_local_capture_register",
        &sql::LOCAL_REGISTER,
        &[&uid, &id, &recording, &descriptor],
        text0,
    )
    .await
}

/// The authorized `.sjrec` package projection.
pub async fn semantic_package(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    recording: i64,
) -> Result<String, StatementFailure> {
    presentation_read(factory, user, &sql::SEMANTIC_PACKAGE, id, recording).await
}

/// The deterministic replay feed.
pub async fn semantic_replay(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    recording: i64,
) -> Result<String, StatementFailure> {
    presentation_read(factory, user, &sql::SEMANTIC_REPLAY, id, recording).await
}

/// One row of the admin recordings registry, every column already text.
pub struct RegistryRow {
    pub id: i64,
    pub meeting: i64,
    pub title: String,
    pub state: String,
    pub started_by: i64,
    pub started_at: String,
    pub stopped_at: Option<String>,
    pub duration_ms: Option<i64>,
    pub size_bytes: Option<i64>,
    pub file_node: Option<i64>,
    pub version: Option<i64>,
    pub error: Option<String>,
}

/// Go's registry read: the RBAC-proved cross-tenant admin read (`BYPASSRLS`,
/// the admin sees every meeting), newest first, at most 200 rows. Authorization
/// is the caller's `drive.view` proof; no per-user filter belongs here.
pub async fn registry_list(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    state: Option<&str>,
    meeting: Option<i64>,
) -> Result<Vec<RegistryRow>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::REGISTRY_LIST, &[&state, &meeting])
        .await?;
    rows.iter()
        .map(|r| {
            Ok(RegistryRow {
                id: r.try_get(0).map_err(|_| invalid_result())?,
                meeting: r.try_get(1).map_err(|_| invalid_result())?,
                title: r.try_get(2).map_err(|_| invalid_result())?,
                state: r.try_get(3).map_err(|_| invalid_result())?,
                started_by: r.try_get(4).map_err(|_| invalid_result())?,
                started_at: r.try_get(5).map_err(|_| invalid_result())?,
                stopped_at: r.try_get(6).map_err(|_| invalid_result())?,
                duration_ms: r.try_get(7).map_err(|_| invalid_result())?,
                size_bytes: r.try_get(8).map_err(|_| invalid_result())?,
                file_node: r.try_get(9).map_err(|_| invalid_result())?,
                version: r.try_get(10).map_err(|_| invalid_result())?,
                error: r.try_get(11).map_err(|_| invalid_result())?,
            })
        })
        .collect()
}

/// Go's best-effort audited read: `audit_write` as the caller, tier core.
pub async fn registry_audit(
    factory: &TxFactory,
    user: &UserPrincipal,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "meet_recordings_list",
        &sql::REGISTRY_AUDIT,
        &[&uid, &ip],
        |rows| {
            if rows.len() == 1 {
                Ok(())
            } else {
                Err(invalid_result())
            }
        },
    )
    .await
}

/// Best-effort durable console-denial audit row (`audit_write`, tier core).
pub async fn console_denied(
    factory: &TxFactory,
    user: &UserPrincipal,
    before: &str,
    path: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    mutate(
        factory,
        user,
        operation,
        "console.denied",
        &sql::CONSOLE_DENIED,
        &[&before, &path],
        |rows| {
            if rows.len() == 1 {
                Ok(())
            } else {
                Err(invalid_result())
            }
        },
    )
    .await
}
