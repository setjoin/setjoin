//! Static typed SQL contract catalog for `setjoin-meet` (F13).
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};

pub const ENABLED: SqlContract = SqlContract {
    id: "meet.enabled",
    domain: "meet",
    sql: "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.meet'),false)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FLAG: SqlContract = SqlContract {
    id: "meet.flag",
    domain: "meet",
    sql: "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key=$1),$2)",
    params: &[Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ENTITLED: SqlContract = SqlContract {
    id: "meet.entitled",
    domain: "meet",
    sql: "SELECT check_user_app_entitlement($1,'meet')",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LIST: SqlContract = SqlContract {
    id: "meet.list",
    domain: "meet",
    sql: "SELECT meeting_list($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const GET: SqlContract = SqlContract {
    id: "meet.get",
    domain: "meet",
    sql: "SELECT meeting_get($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BY_SLUG: SqlContract = SqlContract {
    id: "meet.by_slug",
    domain: "meet",
    sql: "SELECT meeting_get_by_slug($1,$2)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CREATE: SqlContract = SqlContract {
    id: "meet.create",
    domain: "meet",
    sql: "SELECT meeting_create($1,$2,$3::text::timestamptz,$4::text::timestamptz,$5,$6,$7)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOCK: SqlContract = SqlContract {
    id: "meet.lock",
    domain: "meet",
    sql: "SELECT meeting_lock($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SET_GUEST_ALLOWED: SqlContract = SqlContract {
    id: "meet.set_guest_allowed",
    domain: "meet",
    sql: "SELECT meeting_set_guest_allowed($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SET_ROLE: SqlContract = SqlContract {
    id: "meet.set_role",
    domain: "meet",
    sql: "SELECT meeting_set_role($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const JOIN: SqlContract = SqlContract {
    id: "meet.join",
    domain: "meet",
    sql: "SELECT meeting_join($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const KICK: SqlContract = SqlContract {
    id: "meet.kick",
    domain: "meet",
    sql: "SELECT meeting_kick($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const END: SqlContract = SqlContract {
    id: "meet.end",
    domain: "meet",
    sql: "SELECT meeting_end($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const STOPPING_EGRESS_IDS: SqlContract = SqlContract {
    id: "meet.stopping_egress_ids",
    domain: "meet",
    sql: "SELECT egress_id FROM meeting_recordings WHERE meeting_id = $1 AND state = 'stopping' AND egress_id IS NOT NULL",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("egress_id", Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BREAKOUT_ROOMS: SqlContract = SqlContract {
    id: "meet.breakout_rooms",
    domain: "meet",
    sql: "SELECT room_name::text FROM meeting_breakouts WHERE meeting_id = $1 AND (state = 'open' OR closed_at > now() - interval '24 hours')",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const KNOCK_LOOKUP: SqlContract = SqlContract {
    id: "meet.knock_lookup",
    domain: "meet",
    sql: "SELECT m.slug, COALESCE(u.display_name, u.email) FROM meetings m, users u WHERE m.id = $1 AND u.id = $2 AND ($3::text IS NULL OR m.slug = $3)",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[
        ColumnSpec::named("slug", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const KNOCK_CREATE: SqlContract = SqlContract {
    id: "meet.knock_create",
    domain: "meet",
    sql: "SELECT meeting_join_request_create($1,$2,$3)::text",
    params: &[Type::TEXT, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIT: SqlContract = SqlContract {
    id: "meet.admit",
    domain: "meet",
    sql: "SELECT meeting_admit($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DENY: SqlContract = SqlContract {
    id: "meet.deny",
    domain: "meet",
    sql: "SELECT meeting_deny($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BREAKOUT_OPEN: SqlContract = SqlContract {
    id: "meet.breakout_open",
    domain: "meet",
    sql: "SELECT meeting_breakout_open($1,$2,$3::bigint::int,$4,$5)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT_ARRAY,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BREAKOUT_ASSIGN: SqlContract = SqlContract {
    id: "meet.breakout_assign",
    domain: "meet",
    sql: "SELECT meeting_breakout_assign($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BREAKOUT_CLOSE: SqlContract = SqlContract {
    id: "meet.breakout_close",
    domain: "meet",
    sql: "SELECT meeting_breakout_close($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BREAKOUT_JOIN: SqlContract = SqlContract {
    id: "meet.breakout_join",
    domain: "meet",
    sql: "SELECT meeting_breakout_join($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUBLIC_CREATE: SqlContract = SqlContract {
    id: "meet.public_create",
    domain: "meet",
    sql: "SELECT meeting_join_request_create($1,$2)::text",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUBLIC_POLL: SqlContract = SqlContract {
    id: "meet.public_poll",
    domain: "meet",
    sql: "SELECT meeting_join_request_poll($1,$2,$3)::text",
    params: &[Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PARTICIPANT_EVENT: SqlContract = SqlContract {
    id: "meet.participant_event",
    domain: "meet",
    sql: "SELECT meeting_participant_event($1::text::uuid,$2,$3)",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RECORDING_EVENT: SqlContract = SqlContract {
    id: "meet.recording_event",
    domain: "meet",
    sql: "SELECT meeting_recording_event($1::text::uuid,$2,$3,$4::text::jsonb)",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ROOM_NAME: SqlContract = SqlContract {
    id: "meet.room_name",
    domain: "meet",
    sql: "SELECT room_name::text FROM meetings WHERE id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RECORDING_START: SqlContract = SqlContract {
    id: "meet.recording_start",
    domain: "meet",
    sql: "SELECT meeting_recording_start($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RECORDING_BIND: SqlContract = SqlContract {
    id: "meet.recording_bind",
    domain: "meet",
    sql: "SELECT meeting_recording_bind_egress($1,$2,$3,$4,$5)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::BOOL, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RECORDING_STOP: SqlContract = SqlContract {
    id: "meet.recording_stop",
    domain: "meet",
    sql: "SELECT meeting_recording_stop($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CAPTIONS_SET: SqlContract = SqlContract {
    id: "meet.captions_set",
    domain: "meet",
    sql: "SELECT meeting_captions_set($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRESENTATION_PREPARE: SqlContract = SqlContract {
    id: "meet.presentation_prepare",
    domain: "meet",
    sql: "SELECT meeting_presentation_prepare($1,$2,$3,$4,$5)",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRESENTATION_READY: SqlContract = SqlContract {
    id: "meet.presentation_ready",
    domain: "meet",
    sql: "SELECT meeting_presentation_ready($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRESENTATION_START: SqlContract = SqlContract {
    id: "meet.presentation_start",
    domain: "meet",
    sql: "SELECT meeting_presentation_start($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRESENTATION_RECOVER: SqlContract = SqlContract {
    id: "meet.presentation_recover",
    domain: "meet",
    sql: "SELECT meeting_presentation_recover($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRESENTATION_END: SqlContract = SqlContract {
    id: "meet.presentation_end",
    domain: "meet",
    sql: "SELECT meeting_presentation_end($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRESENTATION_REVOKE: SqlContract = SqlContract {
    id: "meet.presentation_revoke",
    domain: "meet",
    sql: "SELECT meeting_presentation_revoke($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRESENTATION_PAGE: SqlContract = SqlContract {
    id: "meet.presentation_page",
    domain: "meet",
    sql: "SELECT meeting_presentation_page($1,$2,$3,$4,$5,$6::bigint::int)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRESENTATION_PRESENTER: SqlContract = SqlContract {
    id: "meet.presentation_presenter",
    domain: "meet",
    sql: "SELECT meeting_presentation_presenter($1,$2,$3,$4,$5,$6)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::BOOL,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRESENTATION_SOURCE: SqlContract = SqlContract {
    id: "meet.presentation_source",
    domain: "meet",
    sql: "SELECT meeting_presentation_source_switch($1,$2,$3,$4,$5,$6,$7,$8)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRESENTATION_DEGRADE: SqlContract = SqlContract {
    id: "meet.presentation_degrade",
    domain: "meet",
    sql: "SELECT meeting_presentation_degrade($1,$2,$3,$4,$5)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRESENTATION_ANNOTATION: SqlContract = SqlContract {
    id: "meet.presentation_annotation",
    domain: "meet",
    sql:
        "SELECT meeting_presentation_annotation_commit($1,$2,$3,$4,$5,$6,$7,$8::bigint::int)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::BOOL,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRESENTATION_CHECKPOINT: SqlContract = SqlContract {
    id: "meet.presentation_checkpoint",
    domain: "meet",
    sql: "SELECT meeting_presentation_checkpoint($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRESENTATION_ANNOTATION_READ: SqlContract = SqlContract {
    id: "meet.presentation_annotation_read",
    domain: "meet",
    sql: "SELECT meeting_presentation_annotation_read($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOCAL_LEASE_ACQUIRE: SqlContract = SqlContract {
    id: "meet.local_lease_acquire",
    domain: "meet",
    sql: "SELECT meeting_local_capture_lease_acquire($1,$2,$3,$4::text::jsonb,$5::text::jsonb,$6::bigint::int)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOCAL_LEASE_HEARTBEAT: SqlContract = SqlContract {
    id: "meet.local_lease_heartbeat",
    domain: "meet",
    sql: "SELECT meeting_local_capture_lease_heartbeat($1,$2,$3,$4,$5,$6,$7)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOCAL_LEASE_STOP: SqlContract = SqlContract {
    id: "meet.local_lease_stop",
    domain: "meet",
    sql: "SELECT meeting_local_capture_lease_stop($1,$2,$3,$4,$5)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOCAL_REGISTER: SqlContract = SqlContract {
    id: "meet.local_register",
    domain: "meet",
    sql: "SELECT meeting_local_capture_register($1,$2,$3,$4::text::jsonb)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SEMANTIC_PACKAGE: SqlContract = SqlContract {
    id: "meet.semantic_package",
    domain: "meet",
    sql: "SELECT meeting_semantic_package_read($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SEMANTIC_REPLAY: SqlContract = SqlContract {
    id: "meet.semantic_replay",
    domain: "meet",
    sql: "SELECT meeting_semantic_replay_read($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REGISTRY_LIST: SqlContract = SqlContract {
    id: "meet.registry_list",
    domain: "meet",
    sql: "SELECT r.id::bigint, r.meeting_id::bigint, m.title::text, r.state::text, r.started_by::bigint, \
          to_char(r.started_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
          to_char(r.stopped_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
          r.duration_ms::bigint, r.size_bytes::bigint, r.file_node_id::bigint, r.version_id::bigint, r.error::text \
          FROM meeting_recordings r JOIN meetings m ON m.id = r.meeting_id \
          WHERE ($1::text IS NULL OR r.state = $1) AND ($2::bigint IS NULL OR r.meeting_id = $2) \
          ORDER BY r.id DESC LIMIT 200",
    params: &[Type::TEXT, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("meeting_id", Type::INT8),
        ColumnSpec::named("title", Type::TEXT),
        ColumnSpec::named("state", Type::TEXT),
        ColumnSpec::named("started_by", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("duration_ms", Type::INT8),
        ColumnSpec::named("size_bytes", Type::INT8),
        ColumnSpec::named("file_node_id", Type::INT8),
        ColumnSpec::named("version_id", Type::INT8),
        ColumnSpec::named("error", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REGISTRY_AUDIT: SqlContract = SqlContract {
    id: "meet.registry_audit",
    domain: "meet",
    sql: "SELECT audit_write($1,'meet_recordings_list','meeting_recording',NULL,NULL,NULL,NULLIF($2::text,'')::inet,'','core')",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONSOLE_DENIED: SqlContract = SqlContract {
    id: "meet.console_denied",
    domain: "meet",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    ENABLED,
    FLAG,
    ENTITLED,
    LIST,
    GET,
    BY_SLUG,
    CREATE,
    LOCK,
    SET_GUEST_ALLOWED,
    SET_ROLE,
    JOIN,
    KICK,
    END,
    STOPPING_EGRESS_IDS,
    BREAKOUT_ROOMS,
    KNOCK_LOOKUP,
    KNOCK_CREATE,
    ADMIT,
    DENY,
    BREAKOUT_OPEN,
    BREAKOUT_ASSIGN,
    BREAKOUT_CLOSE,
    BREAKOUT_JOIN,
    PUBLIC_CREATE,
    PUBLIC_POLL,
    PARTICIPANT_EVENT,
    RECORDING_EVENT,
    ROOM_NAME,
    RECORDING_START,
    RECORDING_BIND,
    RECORDING_STOP,
    CAPTIONS_SET,
    PRESENTATION_PREPARE,
    PRESENTATION_READY,
    PRESENTATION_START,
    PRESENTATION_RECOVER,
    PRESENTATION_END,
    PRESENTATION_REVOKE,
    PRESENTATION_PAGE,
    PRESENTATION_PRESENTER,
    PRESENTATION_SOURCE,
    PRESENTATION_DEGRADE,
    PRESENTATION_ANNOTATION,
    PRESENTATION_CHECKPOINT,
    PRESENTATION_ANNOTATION_READ,
    LOCAL_LEASE_ACQUIRE,
    LOCAL_LEASE_HEARTBEAT,
    LOCAL_LEASE_STOP,
    LOCAL_REGISTER,
    SEMANTIC_PACKAGE,
    SEMANTIC_REPLAY,
    REGISTRY_LIST,
    REGISTRY_AUDIT,
    CONSOLE_DENIED,
];
