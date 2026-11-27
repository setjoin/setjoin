//! Static typed SQL contract catalog for `setjoin-chat` (F12).
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};

// ---------------------------------------------------------------------------
// Feature toggles (public pre-scope reads)
// ---------------------------------------------------------------------------

pub const COMPLIANCE_ENABLED: SqlContract = SqlContract {
    id: "chat.compliance_enabled",
    domain: "chat",
    sql: "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.chat_compliance'),false)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHAT_ENABLED: SqlContract = SqlContract {
    id: "chat.enabled",
    domain: "chat",
    sql: "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.chat'),false)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DRIVE_ENABLED: SqlContract = SqlContract {
    id: "chat.drive_enabled",
    domain: "chat",
    sql: "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.drive'),false)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FEDERATION_ENABLED: SqlContract = SqlContract {
    id: "chat.federation_enabled",
    domain: "chat",
    sql: "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.federation'),false)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UNFURL_ENABLED: SqlContract = SqlContract {
    id: "chat.unfurl_enabled",
    domain: "chat",
    sql: "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='chat.unfurl'),false)",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---------------------------------------------------------------------------
// Compliance administration (F12 golden-routes)
// ---------------------------------------------------------------------------

pub const CONSOLE_DENIED: SqlContract = SqlContract {
    id: "chat.console_denied",
    domain: "chat",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_READ: SqlContract = SqlContract {
    id: "chat.audit_read",
    domain: "chat",
    sql: "SELECT audit_write($1,$2,'chat_channel',$3,NULL,NULL,$4::text::inet,'','core')",
    params: &[Type::INT8, Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHANNEL_SET_HOLD: SqlContract = SqlContract {
    id: "chat.channel_set_hold",
    domain: "chat",
    sql: "SELECT chat_channel_set_hold($1,$2,$3,$4) \
          WHERE EXISTS(SELECT 1 FROM admin_role_assignments ra \
            JOIN admin_role_groups rg ON rg.id=ra.role_group_id \
           WHERE ra.user_id=$1 AND 'chat.compliance_manage'=ANY(rg.permissions) \
             AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
             AND admin_assignment_active(ra.eligible,ra.activated_until))",
    params: &[Type::INT8, Type::INT8, Type::BOOL, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHANNEL_SET_RETENTION: SqlContract = SqlContract {
    id: "chat.channel_set_retention",
    domain: "chat",
    sql: "SELECT chat_channel_set_retention($1,$2,$3) \
          WHERE EXISTS(SELECT 1 FROM admin_role_assignments ra \
            JOIN admin_role_groups rg ON rg.id=ra.role_group_id \
           WHERE ra.user_id=$1 AND 'chat.compliance_manage'=ANY(rg.permissions) \
             AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
             AND admin_assignment_active(ra.eligible,ra.activated_until))",
    params: &[Type::INT8, Type::INT8, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CLASSIFICATION_KNOBS: SqlContract = SqlContract {
    id: "chat.classification_knobs",
    domain: "chat",
    sql: "WITH changed AS (\
            UPDATE chat_channels SET retention_days=$2,worm_mode=$3 \
             WHERE id=$1 \
               AND EXISTS(SELECT 1 FROM admin_role_assignments ra \
                 JOIN admin_role_groups rg ON rg.id=ra.role_group_id \
                WHERE ra.user_id=$4 AND 'chat.compliance_manage'=ANY(rg.permissions) \
                  AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
                  AND admin_assignment_active(ra.eligible,ra.activated_until)) \
             RETURNING id\
          ) \
          SELECT (SELECT count(*) FROM changed) \
           WHERE EXISTS(SELECT 1 FROM admin_role_assignments ra \
             JOIN admin_role_groups rg ON rg.id=ra.role_group_id \
            WHERE ra.user_id=$4 AND 'chat.compliance_manage'=ANY(rg.permissions) \
              AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
              AND admin_assignment_active(ra.eligible,ra.activated_until))",
    params: &[Type::INT8, Type::INT4, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHANNEL_SET_CLASSIFICATION: SqlContract = SqlContract {
    id: "chat.channel_set_classification",
    domain: "chat",
    sql: "SELECT chat_channel_set_classification($1,$2,$3) \
          WHERE EXISTS(SELECT 1 FROM admin_role_assignments ra \
            JOIN admin_role_groups rg ON rg.id=ra.role_group_id \
           WHERE ra.user_id=$1 AND 'chat.compliance_manage'=ANY(rg.permissions) \
             AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
             AND admin_assignment_active(ra.eligible,ra.activated_until))",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LIST_CHANNELS: SqlContract = SqlContract {
    id: "chat.list_channels",
    domain: "chat",
    sql: "SELECT c.id, c.kind, c.name, \
                 c.classification, c.retention_days, c.worm_mode, \
                 chat_hold_active(c.id) AS legal_hold, \
                 c.legal_hold_reason, c.last_purged_seq, \
                 chat_effective_retention(c.id) AS effective_retention_days, \
                 (SELECT count(*) FROM chat_channel_members m WHERE m.channel_id = c.id) AS member_count, \
                 (SELECT count(*) FROM chat_case_hold_channels hc \
                    JOIN chat_case_holds h ON h.id = hc.hold_id AND h.released_at IS NULL \
                   WHERE hc.channel_id = c.id) AS case_hold_count, \
                 COALESCE((\
                   SELECT jsonb_agg(jsonb_build_object('userId', u.id, \
                                                       'displayName', u.display_name, \
                                                       'email', u.email) \
                                    ORDER BY u.display_name) \
                     FROM (SELECT m2.user_id FROM chat_channel_members m2 \
                            WHERE m2.channel_id = c.id ORDER BY m2.user_id LIMIT 8) lim \
                     JOIN users u ON u.id = lim.user_id\
                 ), '[]'::jsonb)::text AS participants \
            FROM chat_channels c \
           WHERE ($1::bigint IS NULL OR EXISTS (SELECT 1 FROM chat_channel_members m3 \
                                                 WHERE m3.channel_id = c.id AND m3.user_id = $1)) \
             AND ($2::text IS NULL OR c.name ILIKE '%'||$2||'%' \
                  OR EXISTS (SELECT 1 FROM chat_channel_members m4 JOIN users u2 ON u2.id = m4.user_id \
                              WHERE m4.channel_id = c.id \
                                AND (u2.email ILIKE '%'||$2||'%' OR u2.display_name ILIKE '%'||$2||'%'))) \
             AND EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id \
                         WHERE ra.user_id=$5 \
                           AND (rg.permissions && ARRAY['chat.compliance_view','chat.compliance_manage']) \
                           AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
                           AND admin_assignment_active(ra.eligible,ra.activated_until)) \
           ORDER BY c.id \
           LIMIT $3 OFFSET $4",
    params: &[Type::INT8, Type::TEXT, Type::INT8, Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("kind", Type::TEXT),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("classification", Type::TEXT),
        ColumnSpec::named("retention_days", Type::INT4),
        ColumnSpec::named("worm_mode", Type::TEXT),
        ColumnSpec::named("legal_hold", Type::BOOL),
        ColumnSpec::named("legal_hold_reason", Type::TEXT),
        ColumnSpec::named("last_purged_seq", Type::INT8),
        ColumnSpec::named("effective_retention_days", Type::INT4),
        ColumnSpec::named("member_count", Type::INT8),
        ColumnSpec::named("case_hold_count", Type::INT8),
        ColumnSpec::named("participants", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_LIST: SqlContract = SqlContract {
    id: "chat.audit_list",
    domain: "chat",
    sql: "SELECT id,\
                 to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),\
                 user_id,\
                 COALESCE(ip::text,''),\
                 action,\
                 target_type,\
                 target_id,\
                 before_state::text,\
                 after_state::text,\
                 notes \
            FROM chat_audit_log \
           WHERE channel_id=$1 \
             AND ($2::bigint IS NULL OR id<$2) \
             AND EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id \
                         WHERE ra.user_id=$4 \
                           AND (rg.permissions && ARRAY['chat.compliance_view','chat.compliance_manage']) \
                           AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
                           AND admin_assignment_active(ra.eligible,ra.activated_until)) \
           ORDER BY id DESC LIMIT $3",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("user_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("action", Type::TEXT),
        ColumnSpec::named("target_type", Type::TEXT),
        ColumnSpec::named("target_id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("notes", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VERIFY_CHAIN: SqlContract = SqlContract {
    id: "chat.verify_chain",
    domain: "chat",
    sql: "SELECT row_id,valid FROM verify_chat_audit_chain($1) \
           WHERE EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id \
                         WHERE ra.user_id=$2 \
                           AND (rg.permissions && ARRAY['chat.compliance_view','chat.compliance_manage']) \
                           AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
                           AND admin_assignment_active(ra.eligible,ra.activated_until))",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("row_id", Type::INT8),
        ColumnSpec::named("valid", Type::BOOL),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VERIFY_HMAC_KEY: SqlContract = SqlContract {
    id: "chat.verify_hmac_key",
    domain: "chat",
    sql: "SELECT coalesce(current_setting('app.audit_hmac_key',true),'')<>'' \
           WHERE EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id \
                         WHERE ra.user_id=$1 \
                           AND (rg.permissions && ARRAY['chat.compliance_view','chat.compliance_manage']) \
                           AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
                           AND admin_assignment_active(ra.eligible,ra.activated_until))",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VERIFY_NOTARY: SqlContract = SqlContract {
    id: "chat.verify_notary",
    domain: "chat",
    sql: "SELECT (after_state->'heads'->$1::text)::text \
            FROM admin_audit_log \
           WHERE action='chat.chain_notary' \
             AND EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id \
                         WHERE ra.user_id=$2 \
                           AND (rg.permissions && ARRAY['chat.compliance_view','chat.compliance_manage']) \
                           AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
                           AND admin_assignment_active(ra.eligible,ra.activated_until)) \
           ORDER BY id DESC LIMIT 1",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VERIFY_LIVE_HEAD: SqlContract = SqlContract {
    id: "chat.verify_live_head",
    domain: "chat",
    sql: "SELECT id,after_state->>'_checksum' \
            FROM chat_audit_log \
           WHERE channel_id=$1 \
             AND EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id \
                         WHERE ra.user_id=$2 \
                           AND (rg.permissions && ARRAY['chat.compliance_view','chat.compliance_manage']) \
                           AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
                           AND admin_assignment_active(ra.eligible,ra.activated_until)) \
           ORDER BY id DESC LIMIT 1",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VERIFY_NOTARY_MATCH: SqlContract = SqlContract {
    id: "chat.verify_notary_match",
    domain: "chat",
    sql: "SELECT after_state->>'_checksum' \
            FROM chat_audit_log \
           WHERE channel_id=$1 AND id=$2 \
             AND EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id \
                         WHERE ra.user_id=$3 \
                           AND (rg.permissions && ARRAY['chat.compliance_view','chat.compliance_manage']) \
                           AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
                           AND admin_assignment_active(ra.eligible,ra.activated_until))",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VERIFY_ANCHORS: SqlContract = SqlContract {
    id: "chat.verify_anchors",
    domain: "chat",
    sql: "SELECT anchor_id,id_from,id_to,valid,reconciled_from_purge,revisions_unchained \
            FROM chat_chain_anchor_verify($1) \
           WHERE EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id \
                         WHERE ra.user_id=$2 \
                           AND (rg.permissions && ARRAY['chat.compliance_view','chat.compliance_manage']) \
                           AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
                           AND admin_assignment_active(ra.eligible,ra.activated_until))",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("anchor_id", Type::INT8),
        ColumnSpec::named("id_from", Type::INT8),
        ColumnSpec::named("id_to", Type::INT8),
        ColumnSpec::named("valid", Type::BOOL),
        ColumnSpec::named("reconciled_from_purge", Type::INT4),
        ColumnSpec::named("revisions_unchained", Type::INT4),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---------------------------------------------------------------------------
// User channels (F12 sub-router-a)
// ---------------------------------------------------------------------------

pub const BROWSE_CHANNELS: SqlContract = SqlContract {
    id: "chat.browse_channels",
    domain: "chat",
    sql: "SELECT chat_browse_channels($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONVERSATION_LIST: SqlContract = SqlContract {
    id: "chat.conversation_list",
    domain: "chat",
    sql: "SELECT chat_conversation_list($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHANNEL_ROSTER: SqlContract = SqlContract {
    id: "chat.channel_roster",
    domain: "chat",
    sql: "SELECT chat_channel_roster($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MENTION_SEARCH: SqlContract = SqlContract {
    id: "chat.mention_search",
    domain: "chat",
    sql: "SELECT chat_mention_search($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PINS_LIST: SqlContract = SqlContract {
    id: "chat.pins_list",
    domain: "chat",
    sql: "SELECT chat_pins_list($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHANNEL_READERS: SqlContract = SqlContract {
    id: "chat.channel_readers",
    domain: "chat",
    sql: "SELECT chat_channel_readers($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MESSAGES_LIST: SqlContract = SqlContract {
    id: "chat.messages_list",
    domain: "chat",
    sql: "SELECT chat_messages_list($1,$2,$3,$4::bigint::integer,$5)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MESSAGES_SINCE: SqlContract = SqlContract {
    id: "chat.messages_since",
    domain: "chat",
    sql: "SELECT chat_messages_since($1,$2,$3)::text,\
          coalesce((SELECT change_seq FROM chat_channels c \
                     WHERE c.id=$2 AND EXISTS(SELECT 1 FROM chat_channel_members m \
                                               WHERE m.channel_id=c.id AND m.user_id=$1)),0)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHANNEL_CREATE: SqlContract = SqlContract {
    id: "chat.channel_create",
    domain: "chat",
    sql: "SELECT chat_channel_create($1,$2,$3,$4)",
    params: &[Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHANNEL_JOIN: SqlContract = SqlContract {
    id: "chat.channel_join",
    domain: "chat",
    sql: "SELECT chat_channel_join($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TYPING_SIGNAL: SqlContract = SqlContract {
    id: "chat.typing_signal",
    domain: "chat",
    sql: "SELECT chat_typing_signal($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MARK_READ: SqlContract = SqlContract {
    id: "chat.mark_read",
    domain: "chat",
    sql: "SELECT chat_mark_read($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MEMBER_SET_NOTIF: SqlContract = SqlContract {
    id: "chat.member_set_notif",
    domain: "chat",
    sql: "SELECT chat_member_set_notif($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MEMBER_ADD: SqlContract = SqlContract {
    id: "chat.member_add",
    domain: "chat",
    sql: "SELECT chat_member_add($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHANNEL_UPDATE: SqlContract = SqlContract {
    id: "chat.channel_update",
    domain: "chat",
    sql: "SELECT chat_channel_update($1,$2,$3,$4,$5,$6,$7)",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MEMBER_REMOVE: SqlContract = SqlContract {
    id: "chat.member_remove",
    domain: "chat",
    sql: "SELECT chat_member_remove($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DM_OPEN: SqlContract = SqlContract {
    id: "chat.dm_open",
    domain: "chat",
    sql: "SELECT chat_dm_open($1,$2)",
    params: &[Type::INT8, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPACE_ENSURE: SqlContract = SqlContract {
    id: "chat.space_ensure",
    domain: "chat",
    sql: "SELECT chat_space_ensure($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const GUEST_PREVIEW: SqlContract = SqlContract {
    id: "chat.guest_preview",
    domain: "chat",
    sql: "SELECT chat_guest_preview($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MESSAGE_SEND: SqlContract = SqlContract {
    id: "chat.message_send",
    domain: "chat",
    sql: "SELECT chat_message_send($1,$2,$3,$4,$5,$6,$7::text::jsonb,$8,$9::text::jsonb)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::INT8_ARRAY,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLL_CREATE: SqlContract = SqlContract {
    id: "chat.poll_create",
    domain: "chat",
    sql: "SELECT chat_poll_create($1,$2,$3,$4,$5,$6::text::timestamptz)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT_ARRAY,
        Type::BOOL,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCHEDULE_MESSAGE: SqlContract = SqlContract {
    id: "chat.schedule_message",
    domain: "chat",
    sql: "SELECT jsonb_build_object('actionId',chat_schedule_message($1,$2,$3,$4,$5,$6,$7::text::timestamptz))::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::INT8_ARRAY,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FEDERATION_DM_ENSURE: SqlContract = SqlContract {
    id: "chat.federation_dm_ensure",
    domain: "chat",
    sql: "SELECT federation_dm_ensure($1,$2)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FEDERATION_ROOM_CREATE: SqlContract = SqlContract {
    id: "chat.federation_room_create",
    domain: "chat",
    sql: "SELECT jsonb_build_object('roomId',federation_room_create($1,$2,$3))::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FEDERATION_ROOM_ROSTER: SqlContract = SqlContract {
    id: "chat.federation_room_roster",
    domain: "chat",
    sql: "SELECT federation_room_roster($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FEDERATION_ROOM_INVITE: SqlContract = SqlContract {
    id: "chat.federation_room_invite",
    domain: "chat",
    sql: "SELECT federation_room_invite($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FEDERATION_ROOM_REMOVE: SqlContract = SqlContract {
    id: "chat.federation_room_remove",
    domain: "chat",
    sql: "SELECT federation_room_remove($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---------------------------------------------------------------------------
// End-user members & unfurl (F12 sub-router-b)
// ---------------------------------------------------------------------------

pub const APP_ENTITLED: SqlContract = SqlContract {
    id: "chat.app_entitled",
    domain: "chat",
    sql: "SELECT check_user_app_entitlement($1,'chat')",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SAVES_LIST: SqlContract = SqlContract {
    id: "chat.saves_list",
    domain: "chat",
    sql: "SELECT chat_saves_list($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SAVE_TOGGLE: SqlContract = SqlContract {
    id: "chat.save_toggle",
    domain: "chat",
    sql: "SELECT to_jsonb(chat_save_toggle($1,$2))::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const THREAD_LIST: SqlContract = SqlContract {
    id: "chat.thread_list",
    domain: "chat",
    sql: "SELECT chat_thread_list($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MY_THREADS: SqlContract = SqlContract {
    id: "chat.my_threads",
    domain: "chat",
    sql: "SELECT chat_my_threads($1,$2::bigint::integer)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SEARCH: SqlContract = SqlContract {
    id: "chat.search",
    domain: "chat",
    sql: "SELECT chat_search($1,$2,$3,$4,$5,$6,$7)::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MESSAGE_EDIT: SqlContract = SqlContract {
    id: "chat.message_edit",
    domain: "chat",
    sql: "SELECT to_jsonb(chat_message_edit($1,$2,$3))::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const MESSAGE_DELETE: SqlContract = SqlContract {
    id: "chat.message_delete",
    domain: "chat",
    sql: "SELECT to_jsonb(chat_message_delete($1,$2))::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REACTION_TOGGLE: SqlContract = SqlContract {
    id: "chat.reaction_toggle",
    domain: "chat",
    sql: "SELECT to_jsonb(chat_reaction_toggle($1,$2,$3))::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PIN_TOGGLE: SqlContract = SqlContract {
    id: "chat.pin_toggle",
    domain: "chat",
    sql: "SELECT to_jsonb(chat_pin_toggle($1,$2))::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TRANSLATE_EGRESS: SqlContract = SqlContract {
    id: "chat.translate_egress",
    domain: "chat",
    sql: "SELECT 'null'::text FROM (SELECT chat_access_audit($1,$2,'translate.egress','message',$3,NULL,$4::text::jsonb,NULL,NULL)) effect",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCHEDULED_LIST: SqlContract = SqlContract {
    id: "chat.scheduled_list",
    domain: "chat",
    sql: "SELECT chat_scheduled_list($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SCHEDULED_CANCEL: SqlContract = SqlContract {
    id: "chat.scheduled_cancel",
    domain: "chat",
    sql: "SELECT 'null'::text FROM (SELECT chat_scheduled_cancel($1,$2::text::uuid)) effect",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLL_VOTE: SqlContract = SqlContract {
    id: "chat.poll_vote",
    domain: "chat",
    sql: "SELECT 'null'::text FROM (SELECT chat_poll_vote($1,$2,$3)) effect",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLL_CLOSE: SqlContract = SqlContract {
    id: "chat.poll_close",
    domain: "chat",
    sql: "SELECT 'null'::text FROM (SELECT chat_poll_close($1,$2)) effect",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const POLL_RESULTS: SqlContract = SqlContract {
    id: "chat.poll_results",
    domain: "chat",
    sql: "SELECT chat_poll_results($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IMAGE_TYPE: SqlContract = SqlContract {
    id: "chat.image_type",
    domain: "chat",
    sql: "SELECT content_type FROM blobs WHERE sha256=$1 AND chat_link_preview_image_owner($1)",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::named("content_type", Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const APP_BLOCKED: SqlContract = SqlContract {
    id: "chat.app_blocked",
    domain: "chat",
    sql: "SELECT 'null'::text FROM (SELECT audit_write($1,'app_blocked','app',NULL,NULL,NULL,$2::text::inet,'chat','routine')) effect",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UNFURL_LOOKUP: SqlContract = SqlContract {
    id: "chat.unfurl_lookup",
    domain: "chat",
    sql: "SELECT chat_link_preview_lookup($1)::text",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UNFURL_APPLY: SqlContract = SqlContract {
    id: "chat.unfurl_apply",
    domain: "chat",
    sql: "SELECT 'null'::text FROM (SELECT chat_message_unfurl_apply($1,$2)) effect",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UNFURL_CLAIM: SqlContract = SqlContract {
    id: "chat.unfurl_claim",
    domain: "chat",
    sql: "SELECT to_jsonb(chat_link_preview_claim($1,$2))::text",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UNFURL_WRITE: SqlContract = SqlContract {
    id: "chat.unfurl_write",
    domain: "chat",
    sql: "SELECT 'null'::text FROM (SELECT chat_link_preview_cache_write($1,$2,$3,$4,$5)) effect",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UNFURL_BLOB: SqlContract = SqlContract {
    id: "chat.unfurl_blob",
    domain: "chat",
    sql: "SELECT 'null'::text FROM (SELECT blob_gc_register_and_reactivate($1,$2,$3,$4)) effect",
    params: &[Type::TEXT, Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    COMPLIANCE_ENABLED,
    CHAT_ENABLED,
    DRIVE_ENABLED,
    FEDERATION_ENABLED,
    UNFURL_ENABLED,
    CONSOLE_DENIED,
    AUDIT_READ,
    CHANNEL_SET_HOLD,
    CHANNEL_SET_RETENTION,
    CLASSIFICATION_KNOBS,
    CHANNEL_SET_CLASSIFICATION,
    LIST_CHANNELS,
    AUDIT_LIST,
    VERIFY_CHAIN,
    VERIFY_HMAC_KEY,
    VERIFY_NOTARY,
    VERIFY_LIVE_HEAD,
    VERIFY_NOTARY_MATCH,
    VERIFY_ANCHORS,
    BROWSE_CHANNELS,
    CONVERSATION_LIST,
    CHANNEL_ROSTER,
    MENTION_SEARCH,
    PINS_LIST,
    CHANNEL_READERS,
    MESSAGES_LIST,
    MESSAGES_SINCE,
    CHANNEL_CREATE,
    CHANNEL_JOIN,
    TYPING_SIGNAL,
    MARK_READ,
    MEMBER_SET_NOTIF,
    MEMBER_ADD,
    CHANNEL_UPDATE,
    MEMBER_REMOVE,
    DM_OPEN,
    SPACE_ENSURE,
    GUEST_PREVIEW,
    MESSAGE_SEND,
    POLL_CREATE,
    SCHEDULE_MESSAGE,
    FEDERATION_DM_ENSURE,
    FEDERATION_ROOM_CREATE,
    FEDERATION_ROOM_ROSTER,
    FEDERATION_ROOM_INVITE,
    FEDERATION_ROOM_REMOVE,
    APP_ENTITLED,
    SAVES_LIST,
    SAVE_TOGGLE,
    THREAD_LIST,
    MY_THREADS,
    SEARCH,
    MESSAGE_EDIT,
    MESSAGE_DELETE,
    REACTION_TOGGLE,
    PIN_TOGGLE,
    TRANSLATE_EGRESS,
    SCHEDULED_LIST,
    SCHEDULED_CANCEL,
    POLL_VOTE,
    POLL_CLOSE,
    POLL_RESULTS,
    IMAGE_TYPE,
    APP_BLOCKED,
    UNFURL_LOOKUP,
    UNFURL_APPLY,
    UNFURL_CLAIM,
    UNFURL_WRITE,
    UNFURL_BLOB,
];
