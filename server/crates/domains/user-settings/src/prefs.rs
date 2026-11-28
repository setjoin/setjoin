//! Slice `settings-b` (#307): `/user/notification-preferences`, `/user/vip-senders`,
//! `/user/automatic-replies` and `/user/approval-delegation` (GET and PUT each).
use super::{command, deadline, done, invalid, mailbox_envelope, s, user_envelope};
use setjoin_authz::principals::{MutateCapability, ReadCapability, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, Row, StatementFailure};

// ---- notification preferences ----

pub fn valid_read_receipt_policy(v: &str) -> bool {
    matches!(v, "ask" | "always" | "never")
}
pub fn valid_chat_notifications(v: &str) -> bool {
    matches!(v, "all" | "mentions" | "off")
}

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

pub async fn notification_get(
    factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &crate::sql::NOTIFICATION_GET, &[&uid])
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

pub async fn notification_put(
    factory: &TxFactory,
    user: &UserPrincipal,
    b: &NotificationPut,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    let payload = format!(
        "notification.put:{:?}:{}:{}:{:?}:{:?}:{}",
        b.fingerprint, b.push_enabled, b.push_sound, b.dnd_start, b.dnd_end, b.dnd_days
    );
    let env = user_envelope(user, operation, &payload);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::NOTIFICATION_PUT,
            &[
                &uid,
                &b.fingerprint,
                &b.push_enabled,
                &b.push_sound,
                &b.stop_push_when_desktop_online,
                &b.dnd_start,
                &b.dnd_end,
                &b.dnd_days,
                &b.mail_notifications,
                &b.calendar_reminders,
                &b.task_reminders,
                &b.read_receipt_policy,
                &b.chat_notifications,
            ],
            Some(command("notification.put")),
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

pub async fn vip_get(
    factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &crate::sql::VIP_GET, &[&uid])
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

pub async fn vip_put(
    factory: &TxFactory,
    user: &UserPrincipal,
    email: &str,
    vip: bool,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    let env = user_envelope(user, operation, &format!("vip.put:{email}:{vip}"));
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::VIP_PUT,
            &[&uid, &email, &vip],
            Some(command("vip.put")),
            |rows| rows.first().map(|_| ()).ok_or_else(invalid),
        )
        .await
}

// ---- automatic replies ----

pub async fn primary_mailbox(factory: &TxFactory, user: &UserPrincipal) -> Option<i64> {
    let uid = user.user().get();
    factory
        .run_user_read_contract(user, &crate::sql::PRIMARY_MAILBOX, &[&uid])
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

/// `GET /user/automatic-replies` (mailbox-scoped under Wave A `FORCE RLS` on `vacation_settings`).
pub async fn vacation_get(
    factory: &TxFactory,
    cap: &ReadCapability,
) -> Result<String, StatementFailure> {
    let mb = cap.mailbox().get();
    let rows = factory
        .run_mailbox_read_contract(cap, &crate::sql::VACATION_GET, &[&mb])
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

pub fn valid_external_audience(v: &str) -> bool {
    matches!(v, "all" | "contacts" | "none")
}

/// Go's `SELECT set_vacation(...)` on the caller's primary mailbox.
pub async fn vacation_put(
    factory: &TxFactory,
    cap: &MutateCapability,
    b: &VacationPut,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let mb = cap.mailbox().get();
    let payload = format!(
        "vacation.put:{}:{}:{:?}:{:?}:{}",
        b.enabled, b.subject, b.start_date, b.end_date, b.external_audience
    );
    let env = mailbox_envelope(cap, operation, &payload);
    factory
        .run_mailbox_write_contract_pipelined(
            cap,
            &env,
            deadline(),
            &crate::sql::VACATION_PUT,
            &[
                &mb,
                &b.enabled,
                &b.subject,
                &b.body_internal,
                &b.body_internal_html,
                &b.body_external,
                &b.body_external_html,
                &b.start_date,
                &b.end_date,
                &b.external_audience,
            ],
            Some(command("vacation.put")),
            |rows| rows.first().map(|_| ()).ok_or_else(invalid),
        )
        .await
}

// ---- approval delegation ----

pub const DELEGATION_DEFAULT: &str = "{\"enabled\":false,\"delegate_user_id\":0,\"delegate_name\":\"\",\"delegate_email\":\"\",\"starts_at\":null,\"ends_at\":null}";

pub fn parse_delegation_get(rows: &[Row]) -> Result<String, StatementFailure> {
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

pub async fn delegation_get(
    factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &crate::sql::DELEGATION_GET, &[&uid])
        .await?;
    parse_delegation_get(&rows)
}

pub async fn delegation_put(
    factory: &TxFactory,
    user: &UserPrincipal,
    delegate: Option<i64>,
    starts: &Option<String>,
    ends: &Option<String>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    let env = user_envelope(
        user,
        operation,
        &format!("delegation.put:{delegate:?}:{starts:?}:{ends:?}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::DELEGATION_PUT,
            &[&uid, &delegate, starts, ends],
            Some(command("delegation.put")),
            |rows| rows.first().map(|_| ()).ok_or_else(invalid),
        )
        .await
}
