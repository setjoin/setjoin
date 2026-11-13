//! Slice `settings-b` (#307): `/user/notification-preferences`, `/user/vip-senders`,
//! `/user/automatic-replies` and `/user/approval-delegation` (GET and PUT each).
//!
//! Every PUT is Go's whole transaction as ONE statement: an upsert (notification preferences)
//! or one call of an existing reducer (`vip_sender_set`, `set_vacation`,
//! `set_approval_delegation`), so each runs as one receipted statement with the verified user
//! (or that user's primary mailbox) taken from the sealed context inside the same statement
//! (R1-R3). No new reducer is needed. Business errors keep Go's mapping: the adapter turns the
//! reducer SQLSTATE into Go's fixed 400 body, every other failure is Go's 500 `database error`.
use super::{command, deadline, done, envelope, invalid, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, Row, ScopedExecutor, StatementFailure, Type};

// ---- notification preferences ----

/// `validReadReceiptPolicy`.
pub fn valid_read_receipt_policy(v: &str) -> bool {
    matches!(v, "ask" | "always" | "never")
}
/// `validChatNotifications`.
pub fn valid_chat_notifications(v: &str) -> bool {
    matches!(v, "all" | "mentions" | "off")
}

/// `github.com/google/uuid.Parse`: 36 bytes, `urn:uuid:`-prefixed, braced (the closing byte is
/// not checked) or 32 plain hex digits. Returns the canonical lower-case text.
pub fn go_uuid(raw: &str) -> Option<String> {
    let b = raw.as_bytes();
    let (text, plain): (&[u8], bool) = match b.len() {
        36 => (b, false),
        45 if b[..9].eq_ignore_ascii_case(b"urn:uuid:") => (&b[9..], false),
        38 => (&b[1..], false),
        32 => (b, true),
        _ => return None,
    };
    let mut hex = Vec::with_capacity(32);
    if plain {
        for c in text {
            hex.push(*c);
        }
    } else {
        if [8, 13, 18, 23].iter().any(|i| text[*i] != b'-') {
            return None;
        }
        for (i, c) in text.iter().take(36).enumerate() {
            if ![8, 13, 18, 23].contains(&i) {
                hex.push(*c);
            }
        }
    }
    if hex.len() != 32 || !hex.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let l = String::from_utf8(hex).ok()?.to_ascii_lowercase();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &l[..8],
        &l[8..12],
        &l[12..16],
        &l[16..20],
        &l[20..]
    ))
}

/// `GET /user/notification-preferences`: Go skips a row whose scan fails (a NULL in a column
/// it scans into a plain bool, string or int) and answers `[]` for none.
pub async fn notification_get(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT device_fingerprint::text, push_enabled, push_sound, stop_push_when_desktop_online, \
             to_char(dnd_start, 'HH24:MI:SS.US'), to_char(dnd_end, 'HH24:MI:SS.US'), dnd_days::int4, mail_notifications, calendar_reminders, \
             task_reminders, read_receipt_policy, chat_notifications \
             FROM user_notification_prefs WHERE user_id = $1 ORDER BY device_fingerprint NULLS FIRST",
            &[(&user, Type::INT8)],
        )
        .await?;
    let render = |r: &Row| -> Option<String> {
        let mut out = String::from("{");
        if let Some(fp) = r.try_get::<_, Option<String>>(0).ok()? {
            out += &format!("\"device_fingerprint\":{},", s(&fp));
        }
        out += &format!(
            "\"push_enabled\":{},\"push_sound\":{},\"stop_push_when_desktop_online\":{},",
            r.try_get::<_, bool>(1).ok()?,
            s(&r.try_get::<_, String>(2).ok()?),
            r.try_get::<_, bool>(3).ok()?
        );
        for (index, key) in [(4, "dnd_start"), (5, "dnd_end")] {
            if let Some(t) = r.try_get::<_, Option<String>>(index).ok()? {
                out += &format!("\"{key}\":{},", s(&t));
            }
        }
        out += &format!(
            "\"dnd_days\":{},\"mail_notifications\":{},\"calendar_reminders\":{},\"task_reminders\":{},\"read_receipt_policy\":{},\"chat_notifications\":{}}}",
            r.try_get::<_, i32>(6).ok()?,
            s(&r.try_get::<_, String>(7).ok()?),
            r.try_get::<_, bool>(8).ok()?,
            r.try_get::<_, bool>(9).ok()?,
            s(&r.try_get::<_, String>(10).ok()?),
            s(&r.try_get::<_, String>(11).ok()?)
        );
        Some(out)
    };
    let items: Vec<String> = rows.iter().filter_map(render).collect();
    Ok(done(format!("{{\"preferences\":[{}]}}", items.join(","))))
}

/// The decoded PUT body (`fingerprint` already parsed to canonical text).
#[derive(Default)]
pub struct NotificationPut {
    pub fingerprint: Option<String>,
    pub push_enabled: bool,
    pub push_sound: String,
    pub stop_push_when_desktop_online: bool,
    pub dnd_start: Option<String>,
    pub dnd_end: Option<String>,
    pub dnd_days: i64,
    pub mail_notifications: String,
    pub calendar_reminders: bool,
    pub task_reminders: bool,
    pub read_receipt_policy: String,
    pub chat_notifications: String,
}

/// Go's single upsert (an empty policy keeps the stored value, defaults on insert).
pub async fn notification_put(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    b: &NotificationPut,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    let payload = format!(
        "notification.put:{:?}:{}:{}:{:?}:{:?}:{}",
        b.fingerprint, b.push_enabled, b.push_sound, b.dnd_start, b.dnd_end, b.dnd_days
    );
    setjoin_pg::run_receipted_command(
        exec,
        command("notification.put"),
        &envelope(&auth, operation, &payload),
        &auth,
        deadline(),
        "INSERT INTO user_notification_prefs \
            (user_id, device_fingerprint, push_enabled, push_sound, stop_push_when_desktop_online, \
             dnd_start, dnd_end, dnd_days, mail_notifications, calendar_reminders, task_reminders, \
             read_receipt_policy, chat_notifications, updated_at) \
         SELECT $2::bigint, $4::text::uuid, $5::boolean, $6::text, $7::boolean, $8::text::time, $9::text::time, \
                $10::bigint::smallint, $11::text, $12::boolean, $13::boolean, \
                COALESCE(NULLIF($14::text, ''), 'ask'), COALESCE(NULLIF($15::text, ''), 'all'), now() \
         WHERE $1::bigint > 0 AND $3::text <> '' \
         ON CONFLICT (user_id, device_fingerprint) DO UPDATE SET \
            push_enabled = $5::boolean, push_sound = $6::text, stop_push_when_desktop_online = $7::boolean, \
            dnd_start = $8::text::time, dnd_end = $9::text::time, dnd_days = $10::bigint::smallint, \
            mail_notifications = $11::text, calendar_reminders = $12::boolean, task_reminders = $13::boolean, \
            read_receipt_policy = COALESCE(NULLIF($14::text, ''), user_notification_prefs.read_receipt_policy), \
            chat_notifications = COALESCE(NULLIF($15::text, ''), user_notification_prefs.chat_notifications), \
            updated_at = now() \
         RETURNING 1",
        &[
            (&b.fingerprint, Type::TEXT),
            (&b.push_enabled, Type::BOOL),
            (&b.push_sound, Type::TEXT),
            (&b.stop_push_when_desktop_online, Type::BOOL),
            (&b.dnd_start, Type::TEXT),
            (&b.dnd_end, Type::TEXT),
            (&b.dnd_days, Type::INT8),
            (&b.mail_notifications, Type::TEXT),
            (&b.calendar_reminders, Type::BOOL),
            (&b.task_reminders, Type::BOOL),
            (&b.read_receipt_policy, Type::TEXT),
            (&b.chat_notifications, Type::TEXT),
        ],
        |rows| {
            if rows.len() == 1 {
                Ok(())
            } else {
                Err(invalid())
            }
        },
    )
    .await
}

pub fn saved_body() -> String {
    done("{\"status\":\"saved\"}".into())
}

// ---- VIP senders ----

/// `GET /user/vip-senders`: `vip_senders_list` is the user's own list (R1).
pub async fn vip_get(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT rust_vip_senders_list($1)::text",
            &[(&user, Type::INT8)],
        )
        .await?;
    let raw: String = rows
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)?;
    let list: Vec<String> = serde_json::from_str(&raw).unwrap_or_default();
    Ok(done(format!(
        "{{\"senders\":[{}]}}",
        list.iter().map(|t| s(t)).collect::<Vec<_>>().join(",")
    )))
}

/// Go's `SELECT vip_sender_set($1, $2, $3)`.
pub async fn vip_put(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    email: &str,
    vip: bool,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("vip.put"),
        &envelope(&auth, operation, &format!("vip.put:{email}:{vip}")),
        &auth,
        deadline(),
        "SELECT rust_vip_sender_set($2::bigint, $4::text, $5::boolean)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&email, Type::TEXT), (&vip, Type::BOOL)],
        |rows| rows.first().map(|_| ()).ok_or_else(invalid),
    )
    .await
}

// ---- automatic replies ----

/// `identity.ResolvePrimaryMailbox`: `None` for no primary mailbox or any read error.
pub async fn primary_mailbox(exec: &ScopedExecutor, actor: &AuthContext) -> Option<i64> {
    let user = actor.user_id();
    exec.read_scoped(
        &scope(actor),
        "SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1",
        &[(&user, Type::INT8)],
    )
    .await
    .ok()?
    .first()?
    .try_get(0)
    .ok()
}

pub const VACATION_DEFAULT: &str = "{\"enabled\":false,\"subject\":\"\",\"body_internal\":\"\",\"body_internal_html\":\"\",\"body_external\":\"\",\"body_external_html\":\"\",\"start_date\":null,\"end_date\":null,\"external_audience\":\"all\"}";

fn opt_text(value: Option<String>) -> String {
    value.map_or("null".into(), |t| s(&t))
}

/// `GET /user/automatic-replies`. Go scans NULLs of an absent row into plain fields, so
/// the failure is its generic 500: `Err` is that failure.
pub async fn vacation_get(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT enabled, subject, body_text, body_html, body_external, body_external_html, \
             to_char(start_date, 'YYYY-MM-DD'), to_char(end_date, 'YYYY-MM-DD'), external_audience \
             FROM get_vacation((SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1))",
            &[(&user, Type::INT8)],
        )
        .await?;
    let Some(r) = rows.first() else {
        return Ok(done(VACATION_DEFAULT.into()));
    };
    let text = |i| r.try_get::<_, Option<String>>(i).map_err(|_| invalid());
    let plain = |i| -> Result<String, StatementFailure> {
        r.try_get::<_, String>(i).map_err(|_| invalid())
    };
    let enabled: bool = r.try_get(0).map_err(|_| invalid())?;
    let (subject, body, audience) = (plain(1)?, plain(2)?, plain(8)?);
    Ok(done(format!(
        "{{\"enabled\":{enabled},\"subject\":{},\"body_internal\":{},\"body_internal_html\":{},\"body_external\":{},\"body_external_html\":{},\"start_date\":{},\"end_date\":{},\"external_audience\":{}}}",
        s(&subject),
        s(&body),
        s(&text(3)?.unwrap_or_default()),
        s(&text(4)?.unwrap_or_default()),
        s(&text(5)?.unwrap_or_default()),
        opt_text(text(6)?),
        opt_text(text(7)?),
        s(&audience)
    )))
}

pub struct VacationPut {
    pub enabled: bool,
    pub subject: String,
    pub body_internal: String,
    pub body_internal_html: String,
    pub body_external: String,
    pub body_external_html: String,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub external_audience: String,
}

/// `valid_external_audience`.
pub fn valid_external_audience(v: &str) -> bool {
    matches!(v, "all" | "contacts" | "none")
}

/// Go's `SELECT set_vacation(...)` on the caller's primary mailbox.
pub async fn vacation_put(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    b: &VacationPut,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    let payload = format!(
        "vacation.put:{}:{}:{:?}:{:?}:{}",
        b.enabled, b.subject, b.start_date, b.end_date, b.external_audience
    );
    setjoin_pg::run_receipted_command(
        exec,
        command("vacation.put"),
        &envelope(&auth, operation, &payload),
        &auth,
        deadline(),
        "SELECT set_vacation((SELECT id FROM mailboxes WHERE user_id = $2::bigint AND is_primary = TRUE LIMIT 1), \
         $4::boolean, $5::text, $6::text, $7::text, $8::text, $9::text, $10::text::date, $11::text::date, $12::text)::text \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&b.enabled, Type::BOOL),
            (&b.subject, Type::TEXT),
            (&b.body_internal, Type::TEXT),
            (&b.body_internal_html, Type::TEXT),
            (&b.body_external, Type::TEXT),
            (&b.body_external_html, Type::TEXT),
            (&b.start_date, Type::TEXT),
            (&b.end_date, Type::TEXT),
            (&b.external_audience, Type::TEXT),
        ],
        |rows| rows.first().map(|_| ()).ok_or_else(invalid),
    )
    .await
}

// ---- approval delegation ----

pub const DELEGATION_DEFAULT: &str = "{\"enabled\":false,\"delegate_user_id\":0,\"delegate_name\":\"\",\"delegate_email\":\"\",\"starts_at\":null,\"ends_at\":null}";

/// `GET /user/approval-delegation`: the caller's own entrust joined to its delegate.
pub async fn delegation_get(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT d.delegate_user_id, u.display_name, u.email, \
             to_char(d.starts_at, 'YYYY-MM-DD\"T\"HH24:MI'), to_char(d.ends_at, 'YYYY-MM-DD\"T\"HH24:MI') \
             FROM get_approval_delegation($1) d JOIN users u ON u.id = d.delegate_user_id",
            &[(&user, Type::INT8)],
        )
        .await?;
    let Some(r) = rows.first() else {
        return Ok(done(DELEGATION_DEFAULT.into()));
    };
    let bad = |_| invalid();
    let id: i64 = r.try_get(0).map_err(bad)?;
    let name: String = r.try_get(1).map_err(bad)?;
    let email: String = r.try_get(2).map_err(bad)?;
    let starts: Option<String> = r.try_get(3).map_err(bad)?;
    let ends: Option<String> = r.try_get(4).map_err(bad)?;
    Ok(done(format!(
        "{{\"enabled\":true,\"delegate_user_id\":{id},\"delegate_name\":{},\"delegate_email\":{},\"starts_at\":{},\"ends_at\":{}}}",
        s(&name),
        s(&email),
        opt_text(starts),
        opt_text(ends)
    )))
}

/// Go's `SELECT set_approval_delegation(...)`: `delegate` `None` clears the entrust.
pub async fn delegation_put(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    delegate: Option<i64>,
    starts: &Option<String>,
    ends: &Option<String>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("delegation.put"),
        &envelope(
            &auth,
            operation,
            &format!("delegation.put:{delegate:?}:{starts:?}:{ends:?}"),
        ),
        &auth,
        deadline(),
        "SELECT set_approval_delegation($2::bigint, $4::bigint, $5::text::timestamptz, $6::text::timestamptz)::text \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&delegate, Type::INT8),
            (starts, Type::TEXT),
            (ends, Type::TEXT),
        ],
        |rows| rows.first().map(|_| ()).ok_or_else(invalid),
    )
    .await
}
