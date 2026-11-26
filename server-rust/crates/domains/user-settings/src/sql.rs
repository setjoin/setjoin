//! Static typed SQL contract catalog for `setjoin-user-settings` (F19).
use setjoin_sql_catalog::{
    pg_go_utc_time, pg_rfc3339, ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type,
};

macro_rules! rfc3339_fmt {
    () => {
        "'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'"
    };
}

pub const PROFILE_UPDATE: SqlContract = SqlContract {
    id: "user_settings.profile_update",
    domain: "user-settings",
    sql: "WITH written AS (UPDATE users SET display_name = $2::text, updated_at = now() WHERE id = $1::bigint RETURNING 1) \
          SELECT count(*)::bigint FROM written",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const QUOTA_GET: SqlContract = SqlContract {
    id: "user_settings.quota_get",
    domain: "user-settings",
    sql: "SELECT COALESCE(SUM(used_bytes), 0)::text, COALESCE(SUM(quota_bytes), 0)::text \
          FROM mailboxes WHERE user_id = $1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IMAP_GET: SqlContract = SqlContract {
    id: "user_settings.imap_get",
    domain: "user-settings",
    sql: "SELECT COALESCE(expose_all, FALSE), COALESCE(show_subscribed_only, TRUE), \
          COALESCE(exposed_tag_ids, '{}'), COALESCE(folder_separator, '/') \
          FROM user_imap_settings WHERE user_id = $1",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::INT8_ARRAY),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const IMAP_PUT: SqlContract = SqlContract {
    id: "user_settings.imap_put",
    domain: "user-settings",
    sql: "INSERT INTO user_imap_settings (user_id, expose_all, show_subscribed_only, exposed_tag_ids, folder_separator) \
          VALUES ($1::bigint, $2::boolean, $3::boolean, $4::bigint[], $5::text) \
          ON CONFLICT (user_id) DO UPDATE SET \
            expose_all = COALESCE($2::boolean, user_imap_settings.expose_all), \
            show_subscribed_only = COALESCE($3::boolean, user_imap_settings.show_subscribed_only), \
            exposed_tag_ids = CASE WHEN $4::BIGINT[] IS NOT NULL THEN $4::bigint[] ELSE user_imap_settings.exposed_tag_ids END, \
            folder_separator = COALESCE($5::text, user_imap_settings.folder_separator) \
          RETURNING 1",
    params: &[
        Type::INT8,
        Type::BOOL,
        Type::BOOL,
        Type::INT8_ARRAY,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VIEW_PREFS_GET: SqlContract = SqlContract {
    id: "user_settings.view_prefs_get",
    domain: "user-settings",
    sql: "SELECT view_prefs::text FROM users WHERE id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VIEW_PREFS_PUT: SqlContract = SqlContract {
    id: "user_settings.view_prefs_put",
    domain: "user-settings",
    sql: "WITH written AS (UPDATE users SET view_prefs = $2::text::jsonb WHERE id = $1::bigint RETURNING 1) \
          SELECT count(*)::bigint FROM written",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UNDO_DELAY_PUT: SqlContract = SqlContract {
    id: "user_settings.undo_delay_put",
    domain: "user-settings",
    sql: "SELECT rust_settings_undo_delay_put($1, $2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const NEWSLETTER_PUT: SqlContract = SqlContract {
    id: "user_settings.newsletter_put",
    domain: "user-settings",
    sql: "WITH written AS (UPDATE users SET view_prefs = COALESCE(view_prefs, '{}'::jsonb) || $2::text::jsonb \
          WHERE id = $1::bigint RETURNING 1) \
          SELECT count(*)::bigint FROM written",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SIGNATURE_LIST: SqlContract = SqlContract {
    id: "user_settings.signature_list",
    domain: "user-settings",
    sql: concat!(
        "SELECT id, alias_email, signature_html, signature_text, is_default, default_for, ",
        pg_rfc3339!("created_at"),
        ", ",
        pg_rfc3339!("updated_at"),
        " FROM user_signatures WHERE user_id = $1 ORDER BY alias_email"
    ),
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("alias_email", Type::TEXT),
        ColumnSpec::named("signature_html", Type::TEXT),
        ColumnSpec::named("signature_text", Type::TEXT),
        ColumnSpec::named("is_default", Type::BOOL),
        ColumnSpec::named("default_for", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SIGNATURE_OTHERS: SqlContract = SqlContract {
    id: "user_settings.signature_others",
    domain: "user-settings",
    sql: "SELECT COUNT(*)::bigint FROM user_signatures WHERE user_id = $1 AND alias_email <> $2",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SIGNATURE_PUT: SqlContract = SqlContract {
    id: "user_settings.signature_put",
    domain: "user-settings",
    sql: "SELECT rust_settings_signature_put($1, $2, $3, $4, $5, $6)",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SIGNATURE_DELETE: SqlContract = SqlContract {
    id: "user_settings.signature_delete",
    domain: "user-settings",
    sql:
        "WITH gone AS (DELETE FROM user_signatures WHERE id = $2::bigint AND user_id = $1::bigint \
          RETURNING 1) SELECT count(*)::bigint FROM gone",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const NOTIFICATION_GET: SqlContract = SqlContract {
    id: "user_settings.notification_get",
    domain: "user-settings",
    sql: "SELECT device_fingerprint::text, push_enabled, push_sound, stop_push_when_desktop_online, \
          to_char(dnd_start, 'HH24:MI:SS.US'), to_char(dnd_end, 'HH24:MI:SS.US'), dnd_days::int4, mail_notifications, calendar_reminders, \
          task_reminders, read_receipt_policy, chat_notifications \
          FROM user_notification_prefs WHERE user_id = $1 ORDER BY device_fingerprint NULLS FIRST",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("push_enabled", Type::BOOL),
        ColumnSpec::named("push_sound", Type::TEXT),
        ColumnSpec::named("stop_push_when_desktop_online", Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::INT4),
        ColumnSpec::named("mail_notifications", Type::TEXT),
        ColumnSpec::named("calendar_reminders", Type::BOOL),
        ColumnSpec::named("task_reminders", Type::BOOL),
        ColumnSpec::named("read_receipt_policy", Type::TEXT),
        ColumnSpec::named("chat_notifications", Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const NOTIFICATION_PUT: SqlContract = SqlContract {
    id: "user_settings.notification_put",
    domain: "user-settings",
    sql: "INSERT INTO user_notification_prefs \
            (user_id, device_fingerprint, push_enabled, push_sound, stop_push_when_desktop_online, \
             dnd_start, dnd_end, dnd_days, mail_notifications, calendar_reminders, task_reminders, \
             read_receipt_policy, chat_notifications, updated_at) \
          VALUES ($1::bigint, $2::text::uuid, $3::boolean, $4::text, $5::boolean, $6::text::time, $7::text::time, \
                 $8::bigint::smallint, $9::text, $10::boolean, $11::boolean, \
                 COALESCE(NULLIF($12::text, ''), 'ask'), COALESCE(NULLIF($13::text, ''), 'all'), now()) \
          ON CONFLICT (user_id, device_fingerprint) DO UPDATE SET \
             push_enabled = $3::boolean, push_sound = $4::text, stop_push_when_desktop_online = $5::boolean, \
             dnd_start = $6::text::time, dnd_end = $7::text::time, dnd_days = $8::bigint::smallint, \
             mail_notifications = $9::text, calendar_reminders = $10::boolean, task_reminders = $11::boolean, \
             read_receipt_policy = COALESCE(NULLIF($12::text, ''), user_notification_prefs.read_receipt_policy), \
             chat_notifications = COALESCE(NULLIF($13::text, ''), user_notification_prefs.chat_notifications), \
             updated_at = now() \
          RETURNING 1",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
        Type::TEXT,
        Type::BOOL,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::BOOL,
        Type::BOOL,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VIP_GET: SqlContract = SqlContract {
    id: "user_settings.vip_get",
    domain: "user-settings",
    sql: "SELECT rust_vip_senders_list($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VIP_PUT: SqlContract = SqlContract {
    id: "user_settings.vip_put",
    domain: "user-settings",
    sql: "SELECT rust_vip_sender_set($1::bigint, $2::text, $3::boolean)::text",
    params: &[Type::INT8, Type::TEXT, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRIMARY_MAILBOX: SqlContract = SqlContract {
    id: "user_settings.primary_mailbox",
    domain: "user-settings",
    sql: "SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VACATION_GET: SqlContract = SqlContract {
    id: "user_settings.vacation_get",
    domain: "user-settings",
    sql: "SELECT enabled, subject, body_text, body_html, body_external, body_external_html, \
          to_char(start_date, 'YYYY-MM-DD'), to_char(end_date, 'YYYY-MM-DD'), external_audience \
          FROM get_vacation($1)",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("enabled", Type::BOOL),
        ColumnSpec::named("subject", Type::TEXT),
        ColumnSpec::named("body_text", Type::TEXT),
        ColumnSpec::named("body_html", Type::TEXT),
        ColumnSpec::named("body_external", Type::TEXT),
        ColumnSpec::named("body_external_html", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("external_audience", Type::TEXT),
    ],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VACATION_PUT: SqlContract = SqlContract {
    id: "user_settings.vacation_put",
    domain: "user-settings",
    sql: "SELECT set_vacation($1::bigint, \
          $2::boolean, $3::text, $4::text, $5::text, $6::text, $7::text, $8::text::date, $9::text::date, $10::text)::text",
    params: &[
        Type::INT8,
        Type::BOOL,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DELEGATION_GET: SqlContract = SqlContract {
    id: "user_settings.delegation_get",
    domain: "user-settings",
    sql: "SELECT d.delegate_user_id, u.display_name, u.email, \
          to_char(d.starts_at, 'YYYY-MM-DD\"T\"HH24:MI'), to_char(d.ends_at, 'YYYY-MM-DD\"T\"HH24:MI') \
          FROM get_approval_delegation($1) d JOIN users u ON u.id = d.delegate_user_id",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("delegate_user_id", Type::INT8),
        ColumnSpec::named("display_name", Type::TEXT),
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DELEGATION_PUT: SqlContract = SqlContract {
    id: "user_settings.delegation_put",
    domain: "user-settings",
    sql: "SELECT set_approval_delegation($1::bigint, $2::bigint, $3::text::timestamptz, $4::text::timestamptz)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSIONS_LIST: SqlContract = SqlContract {
    id: "user_settings.sessions_list",
    domain: "user-settings",
    sql: concat!(
        "SELECT id, kind, client_id, device, location, to_char(last_used_at AT TIME ZONE 'UTC', ",
        rfc3339_fmt!(),
        "), auth_method, current FROM ( \
         SELECT id::text AS id, 'oauth' AS kind, COALESCE(client_id,'') AS client_id, '' AS device, '' AS location, \
                COALESCE(last_used_at, issued_at) AS last_used_at, COALESCE(last_used_protocol,'') AS auth_method, false AS current \
           FROM oauth_tokens \
          WHERE user_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) \
            AND previous_token_hash IS NULL AND token_type IN ('refresh','xoauth2','app_password') \
         UNION ALL \
         SELECT id, 'web', '', COALESCE(user_agent,''), COALESCE(host(ip),''), last_seen_at, COALESCE(auth_method,''), (id = $2) \
           FROM sessions WHERE user_id = $1 AND expires_at > now() \
         ) u ORDER BY u.last_used_at DESC NULLS LAST"
    ),
    params: &[Type::INT8, Type::TEXT],
    columns: &[
        ColumnSpec::named("id", Type::TEXT),
        ColumnSpec::named("kind", Type::TEXT),
        ColumnSpec::named("client_id", Type::TEXT),
        ColumnSpec::named("device", Type::TEXT),
        ColumnSpec::named("location", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("auth_method", Type::TEXT),
        ColumnSpec::named("current", Type::BOOL),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DEVICES_LIST: SqlContract = SqlContract {
    id: "user_settings.devices_list",
    domain: "user-settings",
    sql: concat!(
        "SELECT dr.device_hash, COALESCE(dev.device_name, NULLIF(dr.user_agent, ''), dr.device_hash), \
         COALESCE(dev.platform, ''), ",
        pg_go_utc_time!("dr.last_seen"),
        ", dr.trust_tier, ",
        pg_go_utc_time!("dr.first_seen"),
        " FROM device_registry dr LEFT JOIN devices dev ON dev.user_id = dr.user_id AND dev.fingerprint = dr.device_fingerprint::text \
         WHERE dr.user_id = $1 ORDER BY dr.last_seen DESC"
    ),
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("device_hash", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("trust_tier", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareExplainAndRlsDenyProbe,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_HISTORY: SqlContract = SqlContract {
    id: "user_settings.login_history",
    domain: "user-settings",
    sql: concat!(
        "SELECT id, to_char(occurred_at AT TIME ZONE 'UTC', ",
        rfc3339_fmt!(),
        "), COALESCE(host(source_ip), ''), COALESCE(location, ''), \
         COALESCE(device_name, ''), COALESCE(platform, ''), COALESCE(client, ''), COALESCE(protocol, ''), COALESCE(auth_method, ''), \
         success, COALESCE(fail_reason, ''), (session_id IS NOT NULL AND session_id = $4), COUNT(*) OVER () \
         FROM login_events WHERE user_id = $1 AND ($5 = '' OR success = ($5 = 'success')) \
         ORDER BY occurred_at DESC LIMIT $2 OFFSET $3"
    ),
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("success", Type::BOOL),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::INT8),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareExplainAndRlsDenyProbe,
    audit: SqlAuditPosture::Standard,
};

pub const LOGIN_HISTORY_SUMMARY: SqlContract = SqlContract {
    id: "user_settings.login_history_summary",
    domain: "user-settings",
    sql: concat!(
        "SELECT COUNT(*)::bigint, COUNT(DISTINCT location)::bigint, COALESCE(to_char(MIN(occurred_at), ",
        rfc3339_fmt!(),
        "), '') \
         FROM login_events WHERE user_id = $1 AND success = false AND occurred_at > now() - interval '7 days'"
    ),
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareExplainAndRlsDenyProbe,
    audit: SqlAuditPosture::Standard,
};

pub const SECURITY_SCORE_TOTP: SqlContract = SqlContract {
    id: "user_settings.security_score_totp",
    domain: "user-settings",
    sql: "SELECT totp_enabled FROM users WHERE id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("totp_enabled", Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SECURITY_SCORE_BACKUP_CODES: SqlContract = SqlContract {
    id: "user_settings.security_score_backup_codes",
    domain: "user-settings",
    sql: "SELECT COALESCE(array_length(totp_backup_codes_enc, 1), 0) FROM users WHERE id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SECURITY_SCORE_FAILED_LOGINS: SqlContract = SqlContract {
    id: "user_settings.security_score_failed_logins",
    domain: "user-settings",
    sql: "SELECT COUNT(*)::bigint FROM login_events WHERE user_id = $1 AND success = false AND occurred_at > now() - INTERVAL '7 days'",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareExplainAndRlsDenyProbe,
    audit: SqlAuditPosture::Standard,
};

pub const SECURITY_SCORE_DEVICE_COUNT: SqlContract = SqlContract {
    id: "user_settings.security_score_device_count",
    domain: "user-settings",
    sql: "SELECT COUNT(*)::bigint FROM device_registry WHERE user_id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareExplainAndRlsDenyProbe,
    audit: SqlAuditPosture::Standard,
};

pub const SESSION_REVOKE_ONE: SqlContract = SqlContract {
    id: "user_settings.session_revoke_one",
    domain: "user-settings",
    sql: "SELECT rust_session_revoke_one($1, $2)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SESSIONS_REVOKE_ALL: SqlContract = SqlContract {
    id: "user_settings.sessions_revoke_all",
    domain: "user-settings",
    sql: "SELECT rust_sessions_revoke_all($1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SECURE_ACCOUNT_SELF: SqlContract = SqlContract {
    id: "user_settings.secure_account_self",
    domain: "user-settings",
    sql: "SELECT rust_secure_account_self($1, $2)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SYNC_TOGGLES: SqlContract = SqlContract {
    id: "user_settings.sync_toggles",
    domain: "user-settings",
    sql: "SELECT \
          COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.offline_mail'), false), \
          COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.connectivity_aware_sync'), false), \
          COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.biometric_unlock'), false), \
          COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.windows_sso_unlock'), false)",
    params: &[],
    columns: &[
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::BOOL),
        ColumnSpec::unnamed(Type::BOOL),
    ],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SYNC_DEVICE: SqlContract = SqlContract {
    id: "user_settings.sync_device",
    domain: "user-settings",
    sql: "SELECT id FROM user_devices WHERE user_id = $1 AND fingerprint_hash = sha256($2::bytea) ORDER BY id ASC LIMIT 1",
    params: &[Type::INT8, Type::BYTEA],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SYNC_CAPABILITIES: SqlContract = SqlContract {
    id: "user_settings.sync_capabilities",
    domain: "user-settings",
    sql: "SELECT effective_capabilities($1, $2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SYNC_PUT: SqlContract = SqlContract {
    id: "user_settings.sync_put",
    domain: "user-settings",
    sql: "SELECT rust_offline_device_set_preferences($1::bigint, \
          $2::bigint, $3::boolean, $4::int, $5::boolean, $6::text, $7::text)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::BOOL,
        Type::INT4,
        Type::BOOL,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    PROFILE_UPDATE,
    QUOTA_GET,
    IMAP_GET,
    IMAP_PUT,
    VIEW_PREFS_GET,
    VIEW_PREFS_PUT,
    UNDO_DELAY_PUT,
    NEWSLETTER_PUT,
    SIGNATURE_LIST,
    SIGNATURE_OTHERS,
    SIGNATURE_PUT,
    SIGNATURE_DELETE,
    NOTIFICATION_GET,
    NOTIFICATION_PUT,
    VIP_GET,
    VIP_PUT,
    PRIMARY_MAILBOX,
    VACATION_GET,
    VACATION_PUT,
    DELEGATION_GET,
    DELEGATION_PUT,
    SESSIONS_LIST,
    DEVICES_LIST,
    LOGIN_HISTORY,
    LOGIN_HISTORY_SUMMARY,
    SECURITY_SCORE_TOTP,
    SECURITY_SCORE_BACKUP_CODES,
    SECURITY_SCORE_FAILED_LOGINS,
    SECURITY_SCORE_DEVICE_COUNT,
    SESSION_REVOKE_ONE,
    SESSIONS_REVOKE_ALL,
    SECURE_ACCOUNT_SELF,
    SYNC_TOGGLES,
    SYNC_DEVICE,
    SYNC_CAPABILITIES,
    SYNC_PUT,
];
