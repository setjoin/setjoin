//! Meet and RTC (F13) reducers. The verified user is the only authority; the
//! LiveKit SFU, Egress and ASR sidecars are peripherals and never stored here.
use setjoin_authz::AuthContext;
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, StatementFailure, Type};

fn scope(actor: &AuthContext) -> MailboxAuthContext {
    actor.database_scope()
}

/// Go's per-request `feature.meet` gate; an absent row reads OFF.
pub async fn enabled(exec: &ScopedExecutor) -> Result<bool, StatementFailure> {
    Ok(exec
        .read(
            "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.meet'),false)",
            &[],
        )
        .await?[0]
        .get(0))
}

/// Go's RequireApp entitlement; the HTTP adapter emits its denial and independent audit.
pub async fn entitled(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<bool, StatementFailure> {
    let user = actor.user_id();
    Ok(exec
        .read(
            "SELECT check_user_app_entitlement($1,'meet')",
            &[(&user, Type::INT8)],
        )
        .await?[0]
        .get(0))
}

pub async fn list(exec: &ScopedExecutor, actor: &AuthContext) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    Ok(exec
        .read_scoped(
            &scope(actor),
            "SELECT meeting_list($1)::text",
            &[(&user, Type::INT8)],
        )
        .await?[0]
        .get(0))
}

pub async fn get(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    Ok(exec
        .read_scoped(
            &scope(actor),
            "SELECT meeting_get($1,$2)::text",
            &[(&user, Type::INT8), (&id, Type::INT8)],
        )
        .await?[0]
        .get(0))
}

pub async fn by_slug(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    slug: &str,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    Ok(exec
        .read_scoped(
            &scope(actor),
            "SELECT meeting_get_by_slug($1,$2)::text",
            &[(&user, Type::INT8), (&slug, Type::TEXT)],
        )
        .await?[0]
        .get(0))
}

async fn mutate<T, D>(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    operation: [u8; 16],
    name: &'static str,
    sql: &'static str,
    params: &[setjoin_pg::Param<'_>],
    decode: D,
) -> setjoin_pg::CommandOutcome<T, StatementFailure>
where
    D: FnOnce(&[setjoin_pg::Row]) -> Result<T, StatementFailure>,
{
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(name.as_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F13",
            command: name,
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        sql,
        params,
        decode,
    )
    .await
}

fn invalid_result() -> StatementFailure {
    StatementFailure {
        hint: None,
        sqlstate: None,
        message: "invalid meet reducer result".into(),
    }
}

fn void(rows: &[setjoin_pg::Row]) -> Result<(), StatementFailure> {
    if rows.is_empty() {
        Err(invalid_result())
    } else {
        Ok(())
    }
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    m: &NewMeeting,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_create",
        "SELECT meeting_create($2,$4,$5::text::timestamptz,$6::text::timestamptz,$7,$8,$9)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&m.title, Type::TEXT),
            (&m.start, Type::TEXT),
            (&m.end, Type::TEXT),
            (&m.chat_channel, Type::INT8),
            (&m.calendar_event, Type::INT8),
            (&m.guest_allowed, Type::BOOL),
        ],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

pub async fn lock(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    locked: bool,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_lock",
        "SELECT meeting_lock($2,$4,$5) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8), (&locked, Type::BOOL)],
        void,
    )
    .await
}

pub async fn set_guest_allowed(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    allowed: bool,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_set_guest_allowed",
        "SELECT meeting_set_guest_allowed($2,$4,$5) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8), (&allowed, Type::BOOL)],
        void,
    )
    .await
}

pub async fn set_role(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    identity: &str,
    role: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_set_role",
        "SELECT meeting_set_role($2,$4,$5,$6) WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&id, Type::INT8),
            (&identity, Type::TEXT),
            (&role, Type::TEXT),
        ],
        void,
    )
    .await
}

// ---- sub-router-a (#286): join/kick/end, lobby, breakouts, public lobby, webhook facts.

/// Go's `FeatureFlags` resolution for a key the registry knows: the stored
/// row wins, else the registry default.
pub async fn flag(
    exec: &ScopedExecutor,
    key: &str,
    default: bool,
) -> Result<bool, StatementFailure> {
    Ok(exec
        .read(
            "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key=$1),$2)",
            &[(&key, Type::TEXT), (&default, Type::BOOL)],
        )
        .await?[0]
        .get(0))
}

fn text0(rows: &[setjoin_pg::Row]) -> Result<String, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(invalid_result)
}

/// `meeting_join` then `meeting_get` in one transaction (Go's one scoped tx):
/// the grant spec and the meeting envelope, both as JSON text. Two statements,
/// because `meeting_get` is STABLE and would not see the join's own writes
/// inside a single statement's snapshot.
pub async fn join(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(String, String), StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let user = actor.user_id();
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(b"meeting_join").into()),
        command: (),
    };
    setjoin_pg::command::run_receipted_effect(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F13",
            command: "meeting_join",
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        async move |tx: &mut setjoin_pg::ScopedTx| {
            let spec = tx
                .query(
                    "SELECT meeting_join($1,$2)::text",
                    &[(&user, Type::INT8), (&id, Type::INT8)],
                )
                .await?;
            let meeting = tx
                .query(
                    "SELECT meeting_get($1,$2)::text",
                    &[(&user, Type::INT8), (&id, Type::INT8)],
                )
                .await?;
            let cell = |rows: &[setjoin_pg::Row]| -> Result<String, StatementFailure> {
                rows.first()
                    .ok_or_else(invalid_result)?
                    .try_get(0)
                    .map_err(|_| invalid_result())
            };
            Ok((cell(&spec)?, cell(&meeting)?))
        },
    )
    .await
}

/// Returns the room the target was in (main or an open breakout child).
pub async fn kick(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    identity: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_kick",
        "SELECT meeting_kick($2,$4,$5)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8), (&identity, Type::TEXT)],
        text0,
    )
    .await
}

/// Returns the parent room name.
pub async fn end(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_end",
        "SELECT meeting_end($2,$4)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8)],
        text0,
    )
    .await
}

/// Egress ids `meeting_end` just moved to `stopping` (Go reads them after the
/// reducer commits; the user GUC scopes the rows, an error reads as none).
pub async fn stopping_egress_ids(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
) -> Result<Vec<String>, StatementFailure> {
    column(
        exec,
        actor,
        "SELECT egress_id FROM meeting_recordings WHERE meeting_id = $1 AND state = 'stopping' AND egress_id IS NOT NULL",
        id,
    )
    .await
}

/// Child rooms still open, or closed within 24 h (the worker owns older ones).
pub async fn breakout_rooms(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
) -> Result<Vec<String>, StatementFailure> {
    column(
        exec,
        actor,
        "SELECT room_name::text FROM meeting_breakouts WHERE meeting_id = $1 AND (state = 'open' OR closed_at > now() - interval '24 hours')",
        id,
    )
    .await
}

async fn column(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    sql: &'static str,
    id: i64,
) -> Result<Vec<String>, StatementFailure> {
    Ok(exec
        .read_scoped(&scope(actor), sql, &[(&id, Type::INT8)])
        .await?
        .iter()
        .filter_map(|r| r.try_get::<_, String>(0).ok())
        .collect())
}

/// The knock lookup: slug and display name of the meeting for the caller.
pub async fn knock_lookup(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
) -> Result<Option<(String, String)>, StatementFailure> {
    let user = actor.user_id();
    let no_slug: Option<String> = None;
    Ok(exec
        .read_scoped(
            &scope(actor),
            "SELECT m.slug, COALESCE(u.display_name, u.email) FROM meetings m, users u WHERE m.id = $1 AND u.id = $2 AND ($3::text IS NULL OR m.slug = $3)",
            &[(&id, Type::INT8), (&user, Type::INT8), (&no_slug, Type::TEXT)],
        )
        .await?
        .first()
        .and_then(|r| Some((r.try_get(0).ok()?, r.try_get(1).ok()?))))
}

pub async fn knock_create(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    slug: &str,
    name: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_join_request_create",
        "SELECT meeting_join_request_create($4,$5,$2)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[(&slug, Type::TEXT), (&name, Type::TEXT)],
        text0,
    )
    .await
}

pub async fn admit(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    request: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_admit",
        "SELECT meeting_admit($2,$4)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[(&request, Type::INT8)],
        text0,
    )
    .await
}

pub async fn deny(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    request: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_deny",
        "SELECT meeting_deny($2,$4) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&request, Type::INT8)],
        void,
    )
    .await
}

pub async fn breakout_open(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    count: i64,
    titles: &Option<Vec<String>>,
    auto_assign: bool,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_breakout_open",
        "SELECT meeting_breakout_open($2,$4,$5::bigint::int,$6,$7)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&id, Type::INT8),
            (&count, Type::INT8),
            (titles, Type::TEXT_ARRAY),
            (&auto_assign, Type::BOOL),
        ],
        text0,
    )
    .await
}

pub async fn breakout_assign(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    target: i64,
    breakout: Option<i64>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_breakout_assign",
        "SELECT meeting_breakout_assign($2,$4,$5,$6)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&id, Type::INT8),
            (&target, Type::INT8),
            (&breakout, Type::INT8),
        ],
        text0,
    )
    .await
}

pub async fn breakout_close(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_breakout_close",
        "SELECT meeting_breakout_close($2,$4)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8)],
        text0,
    )
    .await
}

pub async fn breakout_join(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    breakout: Option<i64>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_breakout_join",
        "SELECT meeting_breakout_join($2,$4,$5)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8), (&breakout, Type::INT8)],
        text0,
    )
    .await
}

// The unauthenticated surface has no caller identity: these SECURITY DEFINER
// reducers self-scope by slug and secret, and run as one autocommit statement
// exactly as Go's pool call does. They carry no mailbox or receipt.

/// `meeting_join_request_create(slug, name)` for a guest, JSON text.
pub async fn public_create(
    exec: &ScopedExecutor,
    slug: &str,
    display_name: &str,
) -> Result<String, StatementFailure> {
    text0(
        &exec
            .read(
                "SELECT meeting_join_request_create($1,$2)::text",
                &[(&slug, Type::TEXT), (&display_name, Type::TEXT)],
            )
            .await?,
    )
}

pub async fn public_poll(
    exec: &ScopedExecutor,
    slug: &str,
    request: i64,
    secret: &str,
) -> Result<String, StatementFailure> {
    text0(
        &exec
            .read(
                "SELECT meeting_join_request_poll($1,$2,$3)::text",
                &[
                    (&slug, Type::TEXT),
                    (&request, Type::INT8),
                    (&secret, Type::TEXT),
                ],
            )
            .await?,
    )
}

/// A LiveKit participant/room fact; facts never authorize (DES-011).
pub async fn participant_event(
    exec: &ScopedExecutor,
    room: &str,
    event: &str,
    identity: &Option<String>,
) -> Result<(), StatementFailure> {
    exec.read(
        "SELECT meeting_participant_event($1::text::uuid,$2,$3)",
        &[
            (&room, Type::TEXT),
            (&event, Type::TEXT),
            (identity, Type::TEXT),
        ],
    )
    .await
    .map(|_| ())
}

/// An Egress fact for the recording state machine.
pub async fn recording_event(
    exec: &ScopedExecutor,
    room: &str,
    egress_id: &str,
    event: &str,
    info: &str,
) -> Result<(), StatementFailure> {
    exec.read(
        "SELECT meeting_recording_event($1::text::uuid,$2,$3,$4::text::jsonb)",
        &[
            (&room, Type::TEXT),
            (&egress_id, Type::TEXT),
            (&event, Type::TEXT),
            (&info, Type::TEXT),
        ],
    )
    .await
    .map(|_| ())
}

// ---- sub-router-b (#287): recording, captions, presentation, annotation.

/// The meeting's room name, read with the caller's scope (Go's
/// `roomNameForMeeting`). A missing row is an error.
pub async fn room_name(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
) -> Result<String, StatementFailure> {
    text0(
        &exec
            .read_scoped(
                &scope(actor),
                "SELECT room_name::text FROM meetings WHERE id = $1",
                &[(&id, Type::INT8)],
            )
            .await?,
    )
}

/// `meeting_recording_start`: the committed fact before any Egress call.
pub async fn recording_start(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_recording_start",
        "SELECT meeting_recording_start($2,$4) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8)],
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    recording: i64,
    bound: Option<(&str, &str)>,
    reason: Option<&str>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    let (egress, key) = (bound.map(|b| b.0), bound.map(|b| b.1));
    let ok = bound.is_some();
    mutate(
        exec,
        actor,
        operation,
        "meeting_recording_bind_egress",
        "SELECT meeting_recording_bind_egress($4,$5,$6,$7,$8) WHERE $2::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[
            (&recording, Type::INT8),
            (&egress, Type::TEXT),
            (&key, Type::TEXT),
            (&ok, Type::BOOL),
            (&reason, Type::TEXT),
        ],
        void,
    )
    .await
}

/// `meeting_recording_stop`: `{recordingId, egressId}` as JSON text.
pub async fn recording_stop(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_recording_stop",
        "SELECT meeting_recording_stop($2,$4)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8)],
        text0,
    )
    .await
}

/// `meeting_captions_set`: the bot grant spec as JSON text, or `None` when the
/// flag was already as requested.
pub async fn captions_set(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    on: bool,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<Option<String>, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_captions_set",
        "SELECT meeting_captions_set($2,$4,$5)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8), (&on, Type::BOOL)],
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    operation: [u8; 16],
    name: &'static str,
    sql: &'static str,
    params: &[setjoin_pg::Param<'_>],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(exec, actor, operation, name, sql, params, text0).await
}

pub async fn presentation_prepare(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    node: i64,
    version: i64,
    digest: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_presentation_prepare",
        "SELECT meeting_presentation_prepare($2,$4,$5,$6,$7) WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&id, Type::INT8),
            (&node, Type::INT8),
            (&version, Type::INT8),
            (&digest, Type::TEXT),
        ],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

macro_rules! verb {
    ($fn:ident, $name:literal, $extra:ident: $ty:ty, $pg:expr, $sql:literal) => {
        pub async fn $fn(
            exec: &ScopedExecutor,
            actor: &AuthContext,
            id: i64,
            pid: i64,
            $extra: $ty,
            operation: [u8; 16],
        ) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
            presentation(
                exec,
                actor,
                operation,
                $name,
                concat!(
                    "SELECT ",
                    $sql,
                    "::text WHERE $2::bigint>0 AND $3::text<>''"
                ),
                &[(&id, Type::INT8), (&pid, Type::INT8), (&$extra, $pg)],
            )
            .await
        }
    };
}

verb!(presentation_ready, "meeting_presentation_ready", digest: Option<&str>, Type::TEXT,
    "meeting_presentation_ready($2,$4,$5,$6)");
verb!(presentation_start, "meeting_presentation_start", generation: Option<i64>, Type::INT8,
    "meeting_presentation_start($2,$4,$5,$6)");
verb!(presentation_recover, "meeting_presentation_recover", generation: Option<i64>, Type::INT8,
    "meeting_presentation_recover($2,$4,$5,$6)");
verb!(presentation_end, "meeting_presentation_end", generation: Option<i64>, Type::INT8,
    "meeting_presentation_end($2,$4,$5,$6)");
verb!(presentation_revoke, "meeting_presentation_revoke", reason: Option<&str>, Type::TEXT,
    "meeting_presentation_revoke($2,$4,$5,$6)");

pub async fn presentation_page(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    pid: i64,
    generation: i64,
    seq: i64,
    page: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    presentation(
        exec,
        actor,
        operation,
        "meeting_presentation_page",
        "SELECT meeting_presentation_page($2,$4,$5,$6,$7,$8::bigint::int)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&id, Type::INT8),
            (&pid, Type::INT8),
            (&generation, Type::INT8),
            (&seq, Type::INT8),
            (&page, Type::INT8),
        ],
    )
    .await
}

pub async fn presentation_presenter(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    pid: i64,
    target: i64,
    takeover: bool,
    generation: Option<i64>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    presentation(
        exec,
        actor,
        operation,
        "meeting_presentation_presenter",
        "SELECT meeting_presentation_presenter($2,$4,$5,$6,$7,$8)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&id, Type::INT8),
            (&pid, Type::INT8),
            (&target, Type::INT8),
            (&takeover, Type::BOOL),
            (&generation, Type::INT8),
        ],
    )
    .await
}

pub async fn presentation_source(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    pid: i64,
    node: i64,
    version: i64,
    digest: &str,
    generation: Option<i64>,
    seq: Option<i64>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    presentation(
        exec,
        actor,
        operation,
        "meeting_presentation_source_switch",
        "SELECT meeting_presentation_source_switch($2,$4,$5,$6,$7,$8,$9,$10)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&id, Type::INT8),
            (&pid, Type::INT8),
            (&node, Type::INT8),
            (&version, Type::INT8),
            (&digest, Type::TEXT),
            (&generation, Type::INT8),
            (&seq, Type::INT8),
        ],
    )
    .await
}

pub async fn presentation_degrade(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    pid: i64,
    generation: Option<i64>,
    reason: Option<&str>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    presentation(
        exec,
        actor,
        operation,
        "meeting_presentation_degrade",
        "SELECT meeting_presentation_degrade($2,$4,$5,$6,$7)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&id, Type::INT8),
            (&pid, Type::INT8),
            (&generation, Type::INT8),
            (&reason, Type::TEXT),
        ],
    )
    .await
}

/// A snapshot commit (`Some(text)`) or a clear (`None`).
pub async fn presentation_annotation(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    pid: i64,
    generation: i64,
    seq: i64,
    snapshot: Option<&str>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let clear = snapshot.is_none();
    let bytes: Option<i64> = snapshot.map(|s| s.len() as i64);
    presentation(
        exec,
        actor,
        operation,
        "meeting_presentation_annotation_commit",
        "SELECT meeting_presentation_annotation_commit($2,$4,$5,$6,$7,$8,$9,$10::bigint::int)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&id, Type::INT8),
            (&pid, Type::INT8),
            (&generation, Type::INT8),
            (&seq, Type::INT8),
            (&clear, Type::BOOL),
            (&snapshot, Type::TEXT),
            (&bytes, Type::INT8),
        ],
    )
    .await
}

/// The authorized checkpoint read.
pub async fn presentation_checkpoint(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    pid: i64,
) -> Result<String, StatementFailure> {
    presentation_read(
        exec,
        actor,
        "SELECT meeting_presentation_checkpoint($1,$2,$3)::text",
        id,
        pid,
    )
    .await
}

/// The authorized read of the current committed annotation snapshot.
pub async fn presentation_annotation_read(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    pid: i64,
) -> Result<String, StatementFailure> {
    presentation_read(
        exec,
        actor,
        "SELECT meeting_presentation_annotation_read($1,$2,$3)::text",
        id,
        pid,
    )
    .await
}

async fn presentation_read(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    sql: &'static str,
    id: i64,
    pid: i64,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    text0(
        &exec
            .read_scoped(
                &scope(actor),
                sql,
                &[(&user, Type::INT8), (&id, Type::INT8), (&pid, Type::INT8)],
            )
            .await?,
    )
}

// ---- sub-router-c (#288): local capture, semantic reads, admin registry.

/// `meeting_local_capture_lease_acquire`: the committed lease as JSON text. The
/// reducer commits the `local_registered` recording and banner before the lease.
pub async fn local_lease_acquire(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    device: &str,
    surfaces: &str,
    producer: &str,
    seconds: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_local_capture_lease_acquire",
        "SELECT meeting_local_capture_lease_acquire($2,$4,$5,$6::text::jsonb,$7::text::jsonb,$8::bigint::int)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&id, Type::INT8),
            (&device, Type::TEXT),
            (&surfaces, Type::TEXT),
            (&producer, Type::TEXT),
            (&seconds, Type::INT8),
        ],
        text0,
    )
    .await
}

/// `meeting_local_capture_lease_heartbeat`: the stop fact the device consumes.
pub async fn local_lease_heartbeat(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    recording: i64,
    generation: i64,
    seq: i64,
    state: &str,
    disk_free: Option<i64>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_local_capture_lease_heartbeat",
        "SELECT meeting_local_capture_lease_heartbeat($2,$4,$5,$6,$7,$8,$9)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&id, Type::INT8),
            (&recording, Type::INT8),
            (&generation, Type::INT8),
            (&seq, Type::INT8),
            (&state, Type::TEXT),
            (&disk_free, Type::INT8),
        ],
        text0,
    )
    .await
}

/// `meeting_local_capture_lease_stop`: owner or host/cohost stops lease and recording.
pub async fn local_lease_stop(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    recording: i64,
    generation: Option<i64>,
    reason: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_local_capture_lease_stop",
        "SELECT meeting_local_capture_lease_stop($2,$4,$5,$6,$7)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&id, Type::INT8),
            (&recording, Type::INT8),
            (&generation, Type::INT8),
            (&reason, Type::TEXT),
        ],
        text0,
    )
    .await
}

/// `meeting_local_capture_register`: the exact received descriptor bytes, which
/// the reducer re-derives segment by segment in the same transaction.
pub async fn local_register(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    recording: i64,
    descriptor: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meeting_local_capture_register",
        "SELECT meeting_local_capture_register($2,$4,$5,$6::text::jsonb)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&id, Type::INT8),
            (&recording, Type::INT8),
            (&descriptor, Type::TEXT),
        ],
        text0,
    )
    .await
}

/// The authorized `.sjrec` package projection.
pub async fn semantic_package(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    recording: i64,
) -> Result<String, StatementFailure> {
    presentation_read(
        exec,
        actor,
        "SELECT meeting_semantic_package_read($1,$2,$3)::text",
        id,
        recording,
    )
    .await
}

/// The deterministic replay feed.
pub async fn semantic_replay(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    recording: i64,
) -> Result<String, StatementFailure> {
    presentation_read(
        exec,
        actor,
        "SELECT meeting_semantic_replay_read($1,$2,$3)::text",
        id,
        recording,
    )
    .await
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

/// Go's registry read: the worker credential (BYPASSRLS, the admin sees every
/// meeting), newest first, at most 200 rows. Authorization is the caller's
/// `drive.view` check; no per-user filter belongs here.
pub async fn registry_list(
    worker: &ScopedExecutor,
    state: Option<&str>,
    meeting: Option<i64>,
) -> Result<Vec<RegistryRow>, StatementFailure> {
    let rows = worker
        .read(
            "SELECT r.id::bigint, r.meeting_id::bigint, m.title::text, r.state::text, r.started_by::bigint, \
             to_char(r.started_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
             to_char(r.stopped_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
             r.duration_ms::bigint, r.size_bytes::bigint, r.file_node_id::bigint, r.version_id::bigint, r.error::text \
             FROM meeting_recordings r JOIN meetings m ON m.id = r.meeting_id \
             WHERE ($1::text IS NULL OR r.state = $1) AND ($2::bigint IS NULL OR r.meeting_id = $2) \
             ORDER BY r.id DESC LIMIT 200",
            &[(&state, Type::TEXT), (&meeting, Type::INT8)],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| RegistryRow {
            id: r.get(0),
            meeting: r.get(1),
            title: r.get(2),
            state: r.get(3),
            started_by: r.get(4),
            started_at: r.get(5),
            stopped_at: r.get(6),
            duration_ms: r.get(7),
            size_bytes: r.get(8),
            file_node: r.get(9),
            version: r.get(10),
            error: r.get(11),
        })
        .collect())
}

/// Go's best-effort audited read: `audit_write` as the caller, tier core.
pub async fn registry_audit(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "meet_recordings_list",
        "SELECT count(*)::bigint FROM (SELECT audit_write($2,'meet_recordings_list','meeting_recording',NULL,NULL,NULL,NULLIF($4::text,'')::inet,'','core') WHERE $2::bigint>0 AND $3::text<>'') w",
        &[(&ip, Type::TEXT)],
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
