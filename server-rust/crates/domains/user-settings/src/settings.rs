//! Slice `settings` (#306): the eleven `/settings/*` routes of Go's `UserIMAPSettingsHandler`,
//! `ViewPrefsHandler`, `UndoSendHandler` (delay half), `NewsletterBundlesHandler` and
//! `SignatureHandler`.
//!
//! `users.view_prefs` is one JSONB document three handlers share. Go reads it as text and
//! decodes it into a Go map, so every number is a `float64` and every response renders in
//! sorted key order; this module does the same. Write shapes follow the statement-or-reducer
//! rule: IMAP PUT, view PUT, newsletter PUT and signature DELETE are Go's one statement (one
//! receipted Rust statement, ownership in its WHERE); undo-send PUT (read, merge, write) and
//! signature PUT (count, clear, upsert, role flip) call reducers.
use super::{command, deadline, done, envelope, first_i64, go_marshal, invalid, nano, s, scope};
use serde_json::Value;
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, Row, ScopedExecutor, StatementFailure, Type};
use std::collections::BTreeMap;

/// Go's `status: ok` document (`json.NewEncoder(w).Encode` after `WriteHeader(200)`).
pub fn ok_body() -> String {
    done("{\"status\":\"ok\"}".into())
}

// ---- GET/PUT /settings/imap ----

/// Go answers defaults for ANY read or scan error, not only a missing row.
pub async fn imap_get(exec: &ScopedExecutor, actor: &AuthContext) -> String {
    let user = actor.user_id();
    let row = exec
        .read_scoped(
            &scope(actor),
            "SELECT COALESCE(expose_all, FALSE), COALESCE(show_subscribed_only, TRUE), \
             COALESCE(exposed_tag_ids, '{}'), COALESCE(folder_separator, '/') \
             FROM user_imap_settings WHERE user_id = $1",
            &[(&user, Type::INT8)],
        )
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

/// Go's single upsert. A nil field is bound as NULL, so the INSERT half violates the table's
/// NOT NULL columns and the request fails with Go's 500 unless the body carried all four.
pub async fn imap_put(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    body: &ImapPut,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    let payload = format!(
        "imap:{:?}:{:?}:{:?}:{:?}",
        body.expose_all, body.show_subscribed_only, body.exposed_tag_ids, body.folder_separator
    );
    setjoin_pg::run_receipted_command(
        exec,
        command("imap.put"),
        &envelope(&auth, operation, &payload),
        &auth,
        deadline(),
        "INSERT INTO user_imap_settings (user_id, expose_all, show_subscribed_only, exposed_tag_ids, folder_separator) \
         SELECT $2::bigint, $4::boolean, $5::boolean, $6::bigint[], $7::text WHERE $1::bigint > 0 AND $3::text <> '' \
         ON CONFLICT (user_id) DO UPDATE SET \
           expose_all = COALESCE($4::boolean, user_imap_settings.expose_all), \
           show_subscribed_only = COALESCE($5::boolean, user_imap_settings.show_subscribed_only), \
           exposed_tag_ids = CASE WHEN $6::BIGINT[] IS NOT NULL THEN $6::bigint[] ELSE user_imap_settings.exposed_tag_ids END, \
           folder_separator = COALESCE($7::text, user_imap_settings.folder_separator) \
         RETURNING 1",
        &[
            (&body.expose_all, Type::BOOL),
            (&body.show_subscribed_only, Type::BOOL),
            (&body.exposed_tag_ids, Type::INT8_ARRAY),
            (&body.folder_separator, Type::TEXT),
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

// ---- users.view_prefs ----

/// `SELECT view_prefs FROM users WHERE id = $1` as Go reads it: `None` for any error, a NULL
/// column, an empty document or JSON `null` (every caller then takes its defaults).
async fn prefs_text(exec: &ScopedExecutor, actor: &AuthContext) -> Option<String> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT view_prefs::text FROM users WHERE id = $1",
            &[(&user, Type::INT8)],
        )
        .await
        .ok()?;
    let text: Option<String> = rows.first()?.try_get(0).ok()?;
    text.filter(|t| !t.is_empty() && t != "null")
}

/// `json.Unmarshal` into `map[string]interface{}`: `None` unless the document is an object.
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

pub async fn view_get(exec: &ScopedExecutor, actor: &AuthContext) -> String {
    let mut merged = default_prefs();
    if let Some(stored) = prefs_text(exec, actor).await.and_then(|t| prefs_map(&t)) {
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    prefs: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("view.put"),
        &envelope(&auth, operation, prefs),
        &auth,
        deadline(),
        "WITH written AS (UPDATE users SET view_prefs = $4::text::jsonb WHERE id = $2::bigint AND $1::bigint > 0 AND $3::text <> '' RETURNING 1) \
         SELECT count(*)::bigint FROM written",
        &[(&prefs, Type::TEXT)],
        |rows| rows.first().map(|_| ()).ok_or_else(invalid),
    )
    .await
}

// ---- undo-send ----

/// `int(float64)` as Go compiles it on amd64: an out-of-range value is the minimum int64.
fn go_int(f: f64) -> i64 {
    if f.is_nan() || f >= 9_223_372_036_854_775_808.0 || f < -9_223_372_036_854_775_808.0 {
        i64::MIN
    } else {
        f as i64
    }
}

pub async fn undo_get(exec: &ScopedExecutor, actor: &AuthContext) -> String {
    let mut delay = 5;
    if let Some(map) = prefs_text(exec, actor).await.and_then(|t| prefs_map(&t)) {
        if let Some(Value::Number(n)) = map.get("undoSendDelay") {
            delay = go_int(n.as_f64().unwrap_or(0.0));
        }
    }
    done(format!("{{\"undoSendDelay\":{delay}}}"))
}

/// Clamp as Go's `PutDelay` does.
pub fn clamp_delay(requested: i64) -> i64 {
    requested.clamp(5, 30)
}

/// Read, merge, write: `rust_settings_undo_delay_put` keeps Go's "other keys are preserved"
/// (a non-object document is replaced) in one transaction.
pub async fn undo_put(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    delay: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("undo.put"),
        &envelope(&auth, operation, &format!("undo:{delay}")),
        &auth,
        deadline(),
        "SELECT rust_settings_undo_delay_put($2, $4) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&delay, Type::INT8)],
        |rows| rows.first().map(|_| ()).ok_or_else(invalid),
    )
    .await
}

pub fn undo_body(delay: i64) -> String {
    done(format!("{{\"undoSendDelay\":{delay}}}"))
}

// ---- newsletter bundles ----

pub async fn newsletter_get(exec: &ScopedExecutor, actor: &AuthContext) -> String {
    let (mut bundle, mut optouts) = (true, Vec::<String>::new());
    if let Some(map) = prefs_text(exec, actor).await.and_then(|t| prefs_map(&t)) {
        if let Some(Value::Bool(b)) = map.get("bundleNewsletters") {
            bundle = *b;
        }
        if let Some(Value::Array(items)) = map.get("newsletterOptouts") {
            // []string: a null element is "", any other non-string fails the whole list.
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

/// Go's merge `COALESCE(view_prefs, '{}') || $2::jsonb`; `patch` holds only the given keys.
pub async fn newsletter_put(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    patch: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("newsletter.put"),
        &envelope(&auth, operation, patch),
        &auth,
        deadline(),
        "WITH written AS (UPDATE users SET view_prefs = COALESCE(view_prefs, '{}'::jsonb) || $4::text::jsonb \
         WHERE id = $2::bigint AND $1::bigint > 0 AND $3::text <> '' RETURNING 1) \
         SELECT count(*)::bigint FROM written",
        &[(&patch, Type::TEXT)],
        |rows| rows.first().map(|_| ()).ok_or_else(invalid),
    )
    .await
}

// ---- signatures ----

/// `GET /settings/signatures-list`: Go skips a row whose scan fails and answers `[]` for none.
pub async fn signature_list(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let sql = format!(
        "SELECT id, alias_email, signature_html, signature_text, is_default, default_for, {}, {} \
         FROM user_signatures WHERE user_id = $1 ORDER BY alias_email",
        nano("created_at"),
        nano("updated_at")
    );
    let rows = exec
        .read_scoped(&scope(actor), &sql, &[(&user, Type::INT8)])
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

/// Go's `COUNT(*)` of the user's rows under other aliases (the 100-row admission).
pub async fn signature_others(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    alias: &str,
) -> Result<i64, StatementFailure> {
    let user = actor.user_id();
    first_i64(
        &exec
            .read_scoped(
                &scope(actor),
                "SELECT COUNT(*)::bigint FROM user_signatures WHERE user_id = $1 AND alias_email <> $2",
                &[(&user, Type::INT8), (&alias, Type::TEXT)],
            )
            .await?,
    )
}

pub const MAX_SIGNATURES: i64 = 100;

/// `Ok(true)` stored, `Ok(false)` the cap refused a new alias (re-checked in the reducer).
#[allow(clippy::too_many_arguments)]
pub async fn signature_put(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    alias: &str,
    html: &str,
    text: &str,
    is_default: bool,
    default_for: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("signature.put"),
        &envelope(
            &auth,
            operation,
            &format!("signature.put:{alias}:{is_default}:{default_for}"),
        ),
        &auth,
        deadline(),
        "SELECT rust_settings_signature_put($2, $4, $5, $6, $7, $8) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&alias, Type::TEXT),
            (&html, Type::TEXT),
            (&text, Type::TEXT),
            (&is_default, Type::BOOL),
            (&default_for, Type::TEXT),
        ],
        |rows| first_i64(rows).map(|id| id >= 0),
    )
    .await
}

/// Go's `DELETE ... WHERE id = $1 AND user_id = $2`: `true` when a row went away.
pub async fn signature_delete(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("signature.delete"),
        &envelope(&auth, operation, &format!("signature.delete:{id}")),
        &auth,
        deadline(),
        "WITH gone AS (DELETE FROM user_signatures WHERE id = $4::bigint AND user_id = $2::bigint \
         AND $1::bigint > 0 AND $3::text <> '' RETURNING 1) SELECT count(*)::bigint FROM gone",
        &[(&id, Type::INT8)],
        |rows| first_i64(rows).map(|n| n > 0),
    )
    .await
}
