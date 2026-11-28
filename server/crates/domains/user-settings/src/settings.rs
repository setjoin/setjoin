//! Slice `settings` (#306): `/settings/*` routes.
use super::{command, deadline, done, first_i64, go_marshal, invalid, s, user_envelope};
use serde_json::Value;
use setjoin_authz::principals::{TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, Row, StatementFailure};
use std::collections::BTreeMap;

/// Go's `status: ok` document (`json.NewEncoder(w).Encode` after `WriteHeader(200)`).
pub fn ok_body() -> String {
    done("{\"status\":\"ok\"}".into())
}

// ---- GET/PUT /settings/imap ----

/// Go answers defaults for ANY read or scan error, not only a missing row.
pub async fn imap_get(factory: &TxFactory, user: &UserPrincipal) -> String {
    let uid = user.user().get();
    let row = factory
        .run_user_read_contract(user, &crate::sql::IMAP_GET, &[&uid])
        .await
        .ok()
        .and_then(|rows| rows.into_iter().next());
    let parsed = row.and_then(|r| {
        Some((
            r.try_get::<_, bool>(0).ok()?,
            r.try_get::<_, bool>(1).ok()?,
            r.try_get::<_, Vec<i64>>(2).ok()?,
            r.try_get::<_, String>(3).ok()?,
        ))
    });
    let (all, subscribed, ids, separator) = parsed.unwrap_or((false, true, vec![], "/".into()));
    done(format!(
        "{{\"exposeAll\":{all},\"exposedTagIds\":[{}],\"folderSeparator\":{},\"showSubscribedOnly\":{subscribed}}}",
        ids.iter().map(i64::to_string).collect::<Vec<_>>().join(","),
        s(&separator)
    ))
}

/// The decoded PUT body; `None` is Go's nil pointer or nil slice (bound as SQL NULL).
#[derive(Default)]
pub struct ImapPut {
    pub expose_all: Option<bool>,
    pub show_subscribed_only: Option<bool>,
    pub exposed_tag_ids: Option<Vec<i64>>,
    pub folder_separator: Option<String>,
}

/// Go's single upsert.
pub async fn imap_put(
    factory: &TxFactory,
    user: &UserPrincipal,
    body: &ImapPut,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    let payload = format!(
        "imap:{:?}:{:?}:{:?}:{:?}",
        body.expose_all, body.show_subscribed_only, body.exposed_tag_ids, body.folder_separator
    );
    let env = user_envelope(user, operation, &payload);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::IMAP_PUT,
            &[
                &uid,
                &body.expose_all,
                &body.show_subscribed_only,
                &body.exposed_tag_ids,
                &body.folder_separator,
            ],
            Some(command("imap.put")),
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

// ---- users.view_prefs ----

async fn prefs_text(factory: &TxFactory, user: &UserPrincipal) -> Option<String> {
    let uid = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &crate::sql::VIEW_PREFS_GET, &[&uid])
        .await
        .ok()?;
    let text: Option<String> = rows.first()?.try_get(0).ok()?;
    text.filter(|t| !t.is_empty() && t != "null")
}

fn prefs_map(text: &str) -> Option<serde_json::Map<String, Value>> {
    match serde_json::from_str::<Value>(text).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

fn default_prefs() -> BTreeMap<String, Value> {
    [
        ("defaultView", Value::from("conversation")),
        ("readingPane", Value::from("right")),
        ("senderImages", Value::from(true)),
        ("extSenderWarning", Value::from(true)),
        ("smartMute", Value::from(false)),
        ("undoSendDelay", Value::from(5)),
        ("offlineWindow", Value::from("30d")),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect()
}

pub async fn view_get(factory: &TxFactory, user: &UserPrincipal) -> String {
    let mut merged = default_prefs();
    if let Some(stored) = prefs_text(factory, user).await.and_then(|t| prefs_map(&t)) {
        merged.extend(stored);
    }
    done(go_marshal(&Value::Object(merged.into_iter().collect())))
}

/// Go's `validOfflineWindow`.
pub fn valid_offline_window(value: &str) -> bool {
    matches!(value, "7d" | "30d" | "90d" | "180d" | "365d" | "all")
}

/// Go's `UPDATE users SET view_prefs = $2 WHERE id = $1`; `prefs` is the re-marshalled body.
pub async fn view_put(
    factory: &TxFactory,
    user: &UserPrincipal,
    prefs: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    let env = user_envelope(user, operation, prefs);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::VIEW_PREFS_PUT,
            &[&uid, &prefs],
            Some(command("view.put")),
            |rows| rows.first().map(|_| ()).ok_or_else(invalid),
        )
        .await
}

// ---- undo-send ----

fn go_int(f: f64) -> i64 {
    if f.is_nan() || f >= 9_223_372_036_854_775_808.0 || f < -9_223_372_036_854_775_808.0 {
        i64::MIN
    } else {
        f as i64
    }
}

pub async fn undo_get(factory: &TxFactory, user: &UserPrincipal) -> String {
    let mut delay = 5;
    if let Some(map) = prefs_text(factory, user).await.and_then(|t| prefs_map(&t)) {
        if let Some(Value::Number(n)) = map.get("undoSendDelay") {
            delay = go_int(n.as_f64().unwrap_or(0.0));
        }
    }
    done(format!("{{\"undoSendDelay\":{delay}}}"))
}

pub fn clamp_delay(requested: i64) -> i64 {
    requested.clamp(5, 30)
}

pub async fn undo_put(
    factory: &TxFactory,
    user: &UserPrincipal,
    delay: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    let env = user_envelope(user, operation, &format!("undo:{delay}"));
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::UNDO_DELAY_PUT,
            &[&uid, &delay],
            Some(command("undo.put")),
            |rows| rows.first().map(|_| ()).ok_or_else(invalid),
        )
        .await
}

pub fn undo_body(delay: i64) -> String {
    done(format!("{{\"undoSendDelay\":{delay}}}"))
}

// ---- newsletter bundles ----

pub async fn newsletter_get(factory: &TxFactory, user: &UserPrincipal) -> String {
    let (mut bundle, mut optouts) = (true, Vec::<String>::new());
    if let Some(map) = prefs_text(factory, user).await.and_then(|t| prefs_map(&t)) {
        if let Some(Value::Bool(b)) = map.get("bundleNewsletters") {
            bundle = *b;
        }
        if let Some(Value::Array(items)) = map.get("newsletterOptouts") {
            let list: Option<Vec<String>> = items
                .iter()
                .map(|v| match v {
                    Value::String(t) => Some(t.clone()),
                    Value::Null => Some(String::new()),
                    _ => None,
                })
                .collect();
            if let Some(list) = list {
                optouts = list;
            }
        }
    }
    done(format!(
        "{{\"bundleNewsletters\":{bundle},\"optedOutLists\":[{}]}}",
        optouts.iter().map(|t| s(t)).collect::<Vec<_>>().join(",")
    ))
}

pub async fn newsletter_put(
    factory: &TxFactory,
    user: &UserPrincipal,
    patch: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    let env = user_envelope(user, operation, patch);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::NEWSLETTER_PUT,
            &[&uid, &patch],
            Some(command("newsletter.put")),
            |rows| rows.first().map(|_| ()).ok_or_else(invalid),
        )
        .await
}

// ---- signatures ----

pub async fn signature_list(
    factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &crate::sql::SIGNATURE_LIST, &[&uid])
        .await?;
    let render = |r: &Row| -> Option<String> {
        Some(format!(
            "{{\"id\":{},\"alias_email\":{},\"signature_html\":{},\"signature_text\":{},\"is_default\":{},\"default_for\":{},\"created_at\":{},\"updated_at\":{}}}",
            r.try_get::<_, i64>(0).ok()?,
            s(&r.try_get::<_, String>(1).ok()?),
            s(&r.try_get::<_, String>(2).ok()?),
            s(&r.try_get::<_, String>(3).ok()?),
            r.try_get::<_, bool>(4).ok()?,
            s(&r.try_get::<_, String>(5).ok()?),
            s(&r.try_get::<_, String>(6).ok()?),
            s(&r.try_get::<_, String>(7).ok()?),
        ))
    };
    let items: Vec<String> = rows.iter().filter_map(render).collect();
    Ok(done(format!("[{}]", items.join(","))))
}

pub async fn signature_others(
    factory: &TxFactory,
    user: &UserPrincipal,
    alias: &str,
) -> Result<i64, StatementFailure> {
    let uid = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &crate::sql::SIGNATURE_OTHERS, &[&uid, &alias])
        .await?;
    first_i64(&rows)
}

pub const MAX_SIGNATURES: i64 = 100;

#[allow(clippy::too_many_arguments)]
pub async fn signature_put(
    factory: &TxFactory,
    user: &UserPrincipal,
    alias: &str,
    html: &str,
    text: &str,
    is_default: bool,
    default_for: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let uid = user.user().get();
    let env = user_envelope(
        user,
        operation,
        &format!("signature.put:{alias}:{is_default}:{default_for}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::SIGNATURE_PUT,
            &[&uid, &alias, &html, &text, &is_default, &default_for],
            Some(command("signature.put")),
            |rows| first_i64(&rows).map(|id| id >= 0),
        )
        .await
}

pub async fn signature_delete(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let uid = user.user().get();
    let env = user_envelope(user, operation, &format!("signature.delete:{id}"));
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::SIGNATURE_DELETE,
            &[&uid, &id],
            Some(command("signature.delete")),
            |rows| first_i64(&rows).map(|n| n > 0),
        )
        .await
}
